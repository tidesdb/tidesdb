/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* a history checker in the manner of elle (kingsbury and alvaro, pvldb 2020), over adya's
 * definitions of the isolation levels. transactions append unique elements to per-key lists and
 * read whole lists, so the final list of every key gives its version order outright, and the
 * dependency graph between committed transactions is searched for the cycles each level forbids */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define HIST_DB_DIR "." PATH_SEPARATOR "test_isolation_history_db"
#define HIST_CF     "lists"

/* the workload shape, few keys so that transactions contend */
#define HIST_KEYS          6
#define HIST_KEY_BYTES     8
#define HIST_OPS_PER_TXN   4
#define HIST_THREADS       8
#define HIST_READ_PERCENT  50
#define HIST_PERCENT       100
#define HIST_WRITE_BUFFER  (256u * 1024u)
#define HIST_COMMIT_TARGET 600

/* the fixed capacity every history is recorded into; nothing is allocated while a run records */
#define HIST_ATTEMPT_MAX (HIST_COMMIT_TARGET * 24)
#define HIST_NODE_MAX    1024
#define HIST_ELEM_MAX    (HIST_ATTEMPT_MAX * HIST_OPS_PER_TXN + 1)
#define HIST_LIST_MAX    (HIST_NODE_MAX * HIST_OPS_PER_TXN)
#define HIST_WORD_BITS   64
#define HIST_WORDS       (HIST_NODE_MAX / HIST_WORD_BITS)

/* a list's digest weighs each element by its position, so a reordered or truncated list differs */
#define HIST_DIGEST_PRIME 1099511628211ULL

/* the per-thread generator the workload draws from */
#define HIST_RNG_SEED    0x9E3779B97F4A7C15ULL
#define HIST_RNG_SHIFT_A 13
#define HIST_RNG_SHIFT_B 7
#define HIST_RNG_SHIFT_C 17

#define HIST_NO_NODE (-1)
#define HIST_NO_POS  (-1)

enum
{
    HIST_OP_READ = 1,
    HIST_OP_APPEND = 2
};

enum
{
    HIST_ABORTED = 0,
    HIST_COMMITTED = 1
};

/**
 * hist_op_t
 * one recorded operation
 * @param kind HIST_OP_READ or HIST_OP_APPEND
 * @param key the key index
 * @param elem the element an append added
 * @param len the length of the list a read saw
 * @param last the last element of the list a read saw, 0 for an empty list
 * @param digest the position-weighted digest of the list a read saw
 */
typedef struct
{
    int kind;
    int key;
    uint32_t elem;
    uint32_t len;
    uint32_t last;
    uint64_t digest;
} hist_op_t;

/**
 * hist_txn_t
 * one recorded attempt, committed or not
 * @param status HIST_COMMITTED or HIST_ABORTED
 * @param n how many operations it recorded
 * @param ops the operations in the order it issued them
 */
typedef struct
{
    int status;
    int n;
    hist_op_t ops[HIST_OPS_PER_TXN];
} hist_txn_t;

/**
 * hist_t
 * a whole history, the attempts and the final list of every key
 * @param txns the attempts, indexed by slot
 * @param next_slot the next slot an attempt takes
 * @param committed how many attempts committed
 * @param final the list of each key read after every attempt finished
 * @param final_len the length of each final list
 */
typedef struct
{
    hist_txn_t txns[HIST_ATTEMPT_MAX];
    _Atomic(int) next_slot;
    _Atomic(int) committed;
    uint32_t final[HIST_KEYS][HIST_LIST_MAX];
    uint32_t final_len[HIST_KEYS];
} hist_t;

/**
 * hist_found_t
 * the anomalies a check counted
 * @param g1a reads of an aborted attempt's element, or an aborted element in a final list
 * @param g1b reads that saw a transaction's append to a key but not its later one
 * @param lost committed appends missing from their key's final list
 * @param incompatible reads that are not a prefix of their key's final list
 * @param g0_g1c edges on a cycle with no read-write edge
 * @param g_single read-write edges closing a cycle whose other edges are all write or read edges
 * @param cycles edges on any cycle
 */
typedef struct
{
    int g1a;
    int g1b;
    int lost;
    int incompatible;
    int g0_g1c;
    int g_single;
    int cycles;
} hist_found_t;

/* the analysis scratch, sized to the node limit and reused by every check */
static int g_node_of_slot[HIST_ATTEMPT_MAX];
static int g_pos_of_elem[HIST_ELEM_MAX];
static uint64_t g_edge_w[HIST_NODE_MAX][HIST_WORDS];
static uint64_t g_edge_rw[HIST_NODE_MAX][HIST_WORDS];
static uint64_t g_reach_w[HIST_NODE_MAX][HIST_WORDS];
static uint64_t g_reach_all[HIST_NODE_MAX][HIST_WORDS];
static hist_t g_hist;

static uint64_t hist_digest(const uint32_t *list, const uint32_t len)
{
    uint64_t d = 0;
    for (uint32_t i = 0; i < len && i < HIST_LIST_MAX; i++)
        d = d * HIST_DIGEST_PRIME + (uint64_t)list[i] + 1;
    return d;
}

static uint64_t hist_rng(uint64_t *s)
{
    *s ^= *s << HIST_RNG_SHIFT_A;
    *s ^= *s >> HIST_RNG_SHIFT_B;
    *s ^= *s << HIST_RNG_SHIFT_C;
    return *s;
}

static int hist_slot_of_elem(const uint32_t elem)
{
    return (int)((elem - 1) / HIST_OPS_PER_TXN);
}

static void hist_key_name(const int key, char *out)
{
    snprintf(out, HIST_KEY_BYTES, "k%d", key);
}

/**
 * hist_read_list
 * read a key's list inside a transaction
 * @param txn the transaction
 * @param cf the family
 * @param key the key index
 * @param out receives the list, HIST_LIST_MAX elements of room
 * @param len receives its length
 * @return TDB_SUCCESS, with an absent key read as an empty list, or the error the read reported
 */
static int hist_read_list(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const int key,
                          uint32_t *out, uint32_t *len)
{
    char name[HIST_KEY_BYTES];
    hist_key_name(key, name);
    uint8_t *v = NULL;
    size_t vs = 0;
    *len = 0;
    const int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)name, strlen(name), &v, &vs);
    if (rc == TDB_ERR_NOT_FOUND) return TDB_SUCCESS;
    if (rc != TDB_SUCCESS) return rc;
    const uint32_t n = (uint32_t)(vs / sizeof(uint32_t));
    if (n > HIST_LIST_MAX)
    {
        free(v);
        return TDB_ERR_TOO_LARGE;
    }
    memcpy(out, v, (size_t)n * sizeof(uint32_t));
    *len = n;
    free(v);
    return TDB_SUCCESS;
}

/* one operation of an attempt, recorded into op; returns the first error the store reported */
static int hist_run_op(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, uint64_t *rng,
                       const uint32_t elem, hist_op_t *op)
{
    uint32_t list[HIST_LIST_MAX];
    uint32_t len = 0;
    op->key = (int)(hist_rng(rng) % HIST_KEYS);
    op->kind = hist_rng(rng) % HIST_PERCENT < HIST_READ_PERCENT ? HIST_OP_READ : HIST_OP_APPEND;
    int rc = hist_read_list(txn, cf, op->key, list, &len);
    if (rc != TDB_SUCCESS) return rc;
    if (op->kind == HIST_OP_READ)
    {
        op->len = len;
        op->last = len > 0 ? list[len - 1] : 0;
        op->digest = hist_digest(list, len);
        return TDB_SUCCESS;
    }
    if (len >= HIST_LIST_MAX) return TDB_ERR_TOO_LARGE;
    list[len] = elem;
    op->elem = elem;
    char name[HIST_KEY_BYTES];
    hist_key_name(op->key, name);
    return tidesdb_txn_put(txn, cf, (const uint8_t *)name, strlen(name), (const uint8_t *)list,
                           (size_t)(len + 1) * sizeof(uint32_t), -1);
}

/* one attempt recorded into its slot; an attempt the store refuses or fails is recorded aborted */
static void hist_run_attempt(tidesdb_t *db, tidesdb_column_family_t *cf, const int iso,
                             uint64_t *rng, const int slot)
{
    hist_txn_t *t = &g_hist.txns[slot];
    t->status = HIST_ABORTED;
    t->n = 0;
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(db, (tidesdb_isolation_level_t)iso, &txn) != TDB_SUCCESS)
        return;
    int rc = TDB_SUCCESS;
    for (int i = 0; i < HIST_OPS_PER_TXN && rc == TDB_SUCCESS; i++)
    {
        memset(&t->ops[i], 0, sizeof(t->ops[i]));
        rc = hist_run_op(txn, cf, rng, (uint32_t)(slot * HIST_OPS_PER_TXN + i + 1), &t->ops[i]);
        if (rc == TDB_SUCCESS) t->n = i + 1;
    }
    if (rc == TDB_SUCCESS) rc = tidesdb_txn_commit(txn);
    if (rc == TDB_SUCCESS)
    {
        t->status = HIST_COMMITTED;
        atomic_fetch_add(&g_hist.committed, 1);
    }
    else
        (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
}

/**
 * hist_worker_t
 * what one recording thread runs against
 * @param db the database
 * @param cf the family the lists live in
 * @param iso the isolation level every attempt begins at
 * @param seed the thread's generator seed
 */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int iso;
    uint64_t seed;
} hist_worker_t;

static void *hist_worker(void *arg)
{
    hist_worker_t *w = (hist_worker_t *)arg;
    uint64_t rng = w->seed;
    for (int i = 0; i < HIST_ATTEMPT_MAX; i++)
    {
        if (atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET) break;
        const int slot = atomic_fetch_add(&g_hist.next_slot, 1);
        if (slot >= HIST_ATTEMPT_MAX) break;
        hist_run_attempt(w->db, w->cf, w->iso, &rng, slot);
    }
    return NULL;
}

/* read every key's final list once every attempt has finished */
static int hist_read_final(tidesdb_t *db, tidesdb_column_family_t *cf)
{
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn) != TDB_SUCCESS)
        return TDB_ERR_UNKNOWN;
    int rc = TDB_SUCCESS;
    for (int k = 0; k < HIST_KEYS && rc == TDB_SUCCESS; k++)
        rc = hist_read_list(txn, cf, k, g_hist.final[k], &g_hist.final_len[k]);
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    return rc;
}

/* record one history at a level against a fresh database */
static void hist_record(const int iso)
{
    memset(&g_hist, 0, sizeof(g_hist));
    (void)remove_directory(HIST_DB_DIR);
    char path[] = HIST_DB_DIR;
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = path;
    cfg.memtable_write_buffer_size = HIST_WRITE_BUFFER;
    cfg.log_level = TDB_LOG_WARN;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, HIST_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, HIST_CF);
    ASSERT_TRUE(cf != NULL);

    pthread_t th[HIST_THREADS];
    hist_worker_t w[HIST_THREADS];
    for (int i = 0; i < HIST_THREADS; i++)
    {
        w[i] = (hist_worker_t){.db = db, .cf = cf, .iso = iso, .seed = HIST_RNG_SEED + (uint64_t)i};
        ASSERT_EQ(pthread_create(&th[i], NULL, hist_worker, &w[i]), 0);
    }
    for (int i = 0; i < HIST_THREADS; i++) ASSERT_EQ(pthread_join(th[i], NULL), 0);
    ASSERT_EQ(hist_read_final(db, cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(HIST_DB_DIR);
}

static int hist_slots_recorded(void)
{
    const int n = atomic_load(&g_hist.next_slot);
    return n < HIST_ATTEMPT_MAX ? n : HIST_ATTEMPT_MAX;
}

/* number the committed attempts as graph nodes and place every element in its key's final list */
static int hist_index(hist_found_t *f)
{
    const int slots = hist_slots_recorded();
    int nodes = 0;
    for (int s = 0; s < HIST_ATTEMPT_MAX; s++) g_node_of_slot[s] = HIST_NO_NODE;
    for (int s = 0; s < slots; s++)
        if (g_hist.txns[s].status == HIST_COMMITTED && nodes < HIST_NODE_MAX)
            g_node_of_slot[s] = nodes++;
    for (int e = 0; e < HIST_ELEM_MAX; e++) g_pos_of_elem[e] = HIST_NO_POS;
    for (int k = 0; k < HIST_KEYS; k++)
        for (uint32_t i = 0; i < g_hist.final_len[k]; i++)
        {
            const uint32_t e = g_hist.final[k][i];
            if (e == 0 || e >= HIST_ELEM_MAX || g_pos_of_elem[e] != HIST_NO_POS)
            {
                f->incompatible++;
                continue;
            }
            g_pos_of_elem[e] = (int)i;
            if (g_hist.txns[hist_slot_of_elem(e)].status != HIST_COMMITTED) f->g1a++;
        }
    return nodes;
}

/* whether the attempt at slot appended to key after its operation at index op */
static int hist_appends_later(const int slot, const int op, const int key)
{
    const hist_txn_t *t = &g_hist.txns[slot];
    for (int i = op + 1; i < t->n && i < HIST_OPS_PER_TXN; i++)
        if (t->ops[i].kind == HIST_OP_APPEND && t->ops[i].key == key) return 1;
    return 0;
}

/* the element of an attempt at the op that appended it */
static int hist_op_of_elem(const uint32_t elem)
{
    return (int)((elem - 1) % HIST_OPS_PER_TXN);
}

/* reads of aborted and intermediate states, which need no version order */
static void hist_check_reads(hist_found_t *f)
{
    const int slots = hist_slots_recorded();
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        if (t->status != HIST_COMMITTED) continue;
        for (int i = 0; i < t->n && i < HIST_OPS_PER_TXN; i++)
        {
            const hist_op_t *op = &t->ops[i];
            if (op->kind != HIST_OP_READ || op->len == 0 || op->last >= HIST_ELEM_MAX) continue;
            const int w = hist_slot_of_elem(op->last);
            if (w == s) continue;
            if (g_hist.txns[w].status != HIST_COMMITTED)
                f->g1a++;
            else if (hist_appends_later(w, hist_op_of_elem(op->last), op->key))
                f->g1b++;
        }
    }
}

static void hist_set(uint64_t (*m)[HIST_WORDS], const int from, const int to)
{
    m[from][to / HIST_WORD_BITS] |= 1ULL << (to % HIST_WORD_BITS);
}

static int hist_has(uint64_t (*m)[HIST_WORDS], const int from, const int to)
{
    return (m[from][to / HIST_WORD_BITS] >> (to % HIST_WORD_BITS)) & 1ULL;
}

/* the node of the attempt that appended elem, HIST_NO_NODE when it did not commit */
static int hist_writer_node(const uint32_t elem)
{
    if (elem == 0 || elem >= HIST_ELEM_MAX) return HIST_NO_NODE;
    return g_node_of_slot[hist_slot_of_elem(elem)];
}

/* write-write edges along every final list, and the committed appends the lists lost */
static void hist_edges_from_lists(hist_found_t *f)
{
    for (int k = 0; k < HIST_KEYS; k++)
        for (uint32_t i = 1; i < g_hist.final_len[k]; i++)
        {
            const int a = hist_writer_node(g_hist.final[k][i - 1]);
            const int b = hist_writer_node(g_hist.final[k][i]);
            if (a != HIST_NO_NODE && b != HIST_NO_NODE && a != b) hist_set(g_edge_w, a, b);
        }
    const int slots = hist_slots_recorded();
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        if (t->status != HIST_COMMITTED) continue;
        for (int i = 0; i < t->n && i < HIST_OPS_PER_TXN; i++)
            if (t->ops[i].kind == HIST_OP_APPEND && g_pos_of_elem[t->ops[i].elem] == HIST_NO_POS)
                f->lost++;
    }
}

/* write-read and read-write edges from one committed read, or the read counted incompatible */
static void hist_edges_from_read(hist_found_t *f, const int node, const hist_op_t *op)
{
    const uint32_t flen = g_hist.final_len[op->key];
    const uint32_t *fl = g_hist.final[op->key];
    if (op->len > flen ||
        (op->len > 0 && (fl[op->len - 1] != op->last || hist_digest(fl, op->len) != op->digest)))
    {
        f->incompatible++;
        return;
    }
    const int w = op->len > 0 ? hist_writer_node(op->last) : HIST_NO_NODE;
    if (w != HIST_NO_NODE && w != node) hist_set(g_edge_w, w, node);
    const int next = op->len < flen ? hist_writer_node(fl[op->len]) : HIST_NO_NODE;
    if (next != HIST_NO_NODE && next != node) hist_set(g_edge_rw, node, next);
}

/* every edge of the dependency graph between committed attempts */
static void hist_build_graph(hist_found_t *f)
{
    memset(g_edge_w, 0, sizeof(g_edge_w));
    memset(g_edge_rw, 0, sizeof(g_edge_rw));
    hist_edges_from_lists(f);
    const int slots = hist_slots_recorded();
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        const int node = g_node_of_slot[s];
        if (t->status != HIST_COMMITTED || node == HIST_NO_NODE) continue;
        for (int i = 0; i < t->n && i < HIST_OPS_PER_TXN; i++)
            if (t->ops[i].kind == HIST_OP_READ) hist_edges_from_read(f, node, &t->ops[i]);
    }
}

/* the transitive closure of a relation over n nodes, by warshall over bit rows */
static void hist_close(uint64_t (*reach)[HIST_WORDS], const int n)
{
    const int words = (n + HIST_WORD_BITS - 1) / HIST_WORD_BITS;
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            if (hist_has(reach, i, k))
                for (int w = 0; w < words; w++) reach[i][w] |= reach[k][w];
}

/* count the edges that close a cycle of each kind the levels forbid */
static void hist_find_cycles(hist_found_t *f, const int n)
{
    memcpy(g_reach_w, g_edge_w, sizeof(g_reach_w));
    for (int i = 0; i < n; i++)
        for (int w = 0; w < HIST_WORDS; w++) g_reach_all[i][w] = g_edge_w[i][w] | g_edge_rw[i][w];
    hist_close(g_reach_w, n);
    hist_close(g_reach_all, n);
    for (int u = 0; u < n; u++)
        for (int v = 0; v < n; v++)
        {
            if (hist_has(g_edge_w, u, v) && hist_has(g_reach_w, v, u)) f->g0_g1c++;
            if (hist_has(g_edge_rw, u, v) && hist_has(g_reach_w, v, u)) f->g_single++;
            if ((hist_has(g_edge_w, u, v) || hist_has(g_edge_rw, u, v)) &&
                hist_has(g_reach_all, v, u))
                f->cycles++;
        }
}

/* every check over the history in g_hist */
static hist_found_t hist_check(void)
{
    hist_found_t f;
    memset(&f, 0, sizeof(f));
    const int n = hist_index(&f);
    hist_check_reads(&f);
    hist_build_graph(&f);
    hist_find_cycles(&f, n);
    return f;
}

static void hist_report(const char *level, const hist_found_t *f)
{
    printf(
        "  %s committed %d of %d attempts, g1a %d g1b %d lost %d incompatible %d g0/g1c %d "
        "g-single %d cycles %d\n",
        level, atomic_load(&g_hist.committed), hist_slots_recorded(), f->g1a, f->g1b, f->lost,
        f->incompatible, f->g0_g1c, f->g_single, f->cycles);
    (void)fflush(stdout);
}

/* ---- hand-built histories, one anomaly each, so every check is shown able to fail ---- */

static void hist_synthetic_reset(void)
{
    memset(&g_hist, 0, sizeof(g_hist));
}

/* add an attempt and return its slot */
static int hist_add_txn(const int status)
{
    const int slot = atomic_fetch_add(&g_hist.next_slot, 1);
    g_hist.txns[slot].status = status;
    if (status == HIST_COMMITTED) atomic_fetch_add(&g_hist.committed, 1);
    return slot;
}

/* add an append to the attempt at slot, returning the element */
static uint32_t hist_add_append(const int slot, const int key)
{
    hist_txn_t *t = &g_hist.txns[slot];
    const int i = t->n++;
    t->ops[i].kind = HIST_OP_APPEND;
    t->ops[i].key = key;
    t->ops[i].elem = (uint32_t)(slot * HIST_OPS_PER_TXN + i + 1);
    return t->ops[i].elem;
}

/* add a read to the attempt at slot that saw list */
static void hist_add_read(const int slot, const int key, const uint32_t *list, const uint32_t len)
{
    hist_txn_t *t = &g_hist.txns[slot];
    const int i = t->n++;
    t->ops[i].kind = HIST_OP_READ;
    t->ops[i].key = key;
    t->ops[i].len = len;
    t->ops[i].last = len > 0 ? list[len - 1] : 0;
    t->ops[i].digest = hist_digest(list, len);
}

static void hist_set_final(const int key, const uint32_t *list, const uint32_t len)
{
    memcpy(g_hist.final[key], list, (size_t)len * sizeof(uint32_t));
    g_hist.final_len[key] = len;
}

/* a committed read of an aborted append is g1a, and so is an aborted append in a final list */
void test_isolation_history_checker_finds_aborted_reads(void)
{
    hist_synthetic_reset();
    const int a = hist_add_txn(HIST_ABORTED);
    const uint32_t e = hist_add_append(a, 0);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &e, 1);
    hist_set_final(0, &e, 1);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g1a >= 2);
}

/* a read that saw a transaction's first append to a key but not its second is g1b */
void test_isolation_history_checker_finds_intermediate_reads(void)
{
    hist_synthetic_reset();
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t e1 = hist_add_append(w, 0);
    const uint32_t e2 = hist_add_append(w, 0);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &e1, 1);
    const uint32_t fin[] = {e1, e2};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g1b >= 1);
}

/* two writers ordered one way on one key and the other way on another make a write cycle, g0 */
void test_isolation_history_checker_finds_write_cycles(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(t1, 0), b = hist_add_append(t1, 1);
    const uint32_t c = hist_add_append(t2, 0), d = hist_add_append(t2, 1);
    const uint32_t k0[] = {a, c}, k1[] = {d, b};
    hist_set_final(0, k0, 2);
    hist_set_final(1, k1, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g0_g1c >= 1);
    ASSERT_TRUE(f.cycles >= 1);
}

/* a read that misses a write while seeing another from the same transaction is g-single */
void test_isolation_history_checker_finds_single_anti_dependency_cycles(void)
{
    hist_synthetic_reset();
    const int r = hist_add_txn(HIST_COMMITTED);
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w, 0), b = hist_add_append(w, 1);
    hist_add_read(r, 0, NULL, 0);
    hist_add_read(r, 1, &b, 1);
    hist_set_final(0, &a, 1);
    hist_set_final(1, &b, 1);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g_single >= 1);
    ASSERT_EQ(f.g0_g1c, 0);
}

/* write skew is a cycle of two read-write edges, which snapshot allows and serializable forbids */
void test_isolation_history_checker_finds_write_skew(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    hist_add_read(t1, 0, NULL, 0);
    const uint32_t x = hist_add_append(t1, 1);
    hist_add_read(t2, 1, NULL, 0);
    const uint32_t y = hist_add_append(t2, 0);
    hist_set_final(0, &y, 1);
    hist_set_final(1, &x, 1);
    const hist_found_t f = hist_check();
    ASSERT_EQ(f.g_single, 0);
    ASSERT_EQ(f.g0_g1c, 0);
    ASSERT_TRUE(f.cycles >= 1);
}

/* a read that is not a prefix of the final list, and a committed append the list lost */
void test_isolation_history_checker_finds_incompatible_orders(void)
{
    hist_synthetic_reset();
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w, 0);
    const uint32_t b = hist_add_append(w, 0);
    (void)hist_add_append(w, 1);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &b, 1);
    const uint32_t fin[] = {a, b};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.incompatible >= 1);
    ASSERT_TRUE(f.lost >= 1);
}

/* a history with no anomaly reports none */
void test_isolation_history_checker_accepts_a_serial_history(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(t1, 0);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    hist_add_read(t2, 0, &a, 1);
    const uint32_t b = hist_add_append(t2, 0);
    const uint32_t fin[] = {a, b};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible + f.g0_g1c + f.g_single + f.cycles, 0);
}

/* ---- recorded histories, one per level, checked against what the level forbids ---- */

/* read committed forbids reading aborted or intermediate states; its read-modify-write appends may
 * lose one another, which the level allows, so version order is not checked */
void test_isolation_history_read_committed_reads_only_committed_states(void)
{
    hist_record(TDB_ISOLATION_READ_COMMITTED);
    hist_found_t f;
    memset(&f, 0, sizeof(f));
    (void)hist_index(&f);
    hist_check_reads(&f);
    hist_report("read committed", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a, 0);
    ASSERT_EQ(f.g1b, 0);
}

/* snapshot forbids every cycle with fewer than two read-write edges, and lost updates */
void test_isolation_history_snapshot_forbids_g_single(void)
{
    hist_record(TDB_ISOLATION_SNAPSHOT);
    const hist_found_t f = hist_check();
    hist_report("snapshot", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.g0_g1c, 0);
    ASSERT_EQ(f.g_single, 0);
}

/* repeatable read validates every read at commit, so over point reads and writes every edge points
 * forward in commit order and the graph has no cycle at all */
void test_isolation_history_repeatable_read_is_acyclic_over_point_access(void)
{
    hist_record(TDB_ISOLATION_REPEATABLE_READ);
    const hist_found_t f = hist_check();
    hist_report("repeatable read", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

/* serializable forbids every cycle */
void test_isolation_history_serializable_is_acyclic(void)
{
    hist_record(TDB_ISOLATION_SERIALIZABLE);
    const hist_found_t f = hist_check();
    hist_report("serializable", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_isolation_history_checker_finds_aborted_reads, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_intermediate_reads, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_write_cycles, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_single_anti_dependency_cycles, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_write_skew, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_incompatible_orders, tests_passed);
    RUN_TEST(test_isolation_history_checker_accepts_a_serial_history, tests_passed);
    RUN_TEST(test_isolation_history_read_committed_reads_only_committed_states, tests_passed);
    RUN_TEST(test_isolation_history_snapshot_forbids_g_single, tests_passed);
    RUN_TEST(test_isolation_history_repeatable_read_is_acyclic_over_point_access, tests_passed);
    RUN_TEST(test_isolation_history_serializable_is_acyclic, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
