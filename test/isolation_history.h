/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TEST_ISOLATION_HISTORY_H__
#define __TIDESDB_TEST_ISOLATION_HISTORY_H__

/* a history checker in the manner of elle (kingsbury and alvaro, pvldb 2020), over adya's
 * definitions of the isolation levels. transactions append unique elements to per-key lists, read
 * and scan them, delete ranges of them, and commit in one phase or two. every append records the
 * list it extended, so the committed appends chain into each key's version order even where a
 * range delete has since removed it, and the dependency graph between committed transactions is
 * searched for the cycles each level forbids. an observation that cannot be placed exactly adds no
 * edge, so every anomaly reported is real */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "test_utils.h"

#define HIST_DB_DIR "." PATH_SEPARATOR "test_isolation_history_db"
#define HIST_CF     "lists"
#define HIST_CF_B   "lists_b"

/* the key space, the upper part of which range deletes may clear */
#define HIST_KEYS         12
#define HIST_POINT_KEYS   6
#define HIST_DELETE_FIRST 6
#define HIST_KEY_BYTES    16
#define HIST_KEY_FORMAT   "k%02d"
#define HIST_SPAN         3

/* the workload shape */
#define HIST_ACTIONS       4
#define HIST_THREADS       8
#define HIST_PERCENT       100
#define HIST_WRITE_BUFFER  (256u * 1024u)
#define HIST_COMMIT_TARGET 600
#define HIST_XID_BYTES     16
#define HIST_XID_FORMAT    "x%d"
#define HIST_IN_DOUBT_MAX  8

/* a buffer this small rotates the memtable every few commits, so flushes and compactions run
 * through the whole history and validation reads tables as well as memtables */
#define HIST_WRITE_BUFFER_SMALL (8u * 1024u)

/* the families a history may spread its keys over, the lower half of the keys in the first and the
 * upper half, which holds every deletable key, in the second */
#define HIST_FAMILIES_MAX 2

/* the levels a mixed history draws each attempt's from */
#define HIST_MIXED_LEVELS 3

/* the fewest commits a history must hold to be checked. the workers stop at the target, but how
 * many attempts reach it depends on the scheduler rather than the engine -- eight threads on two
 * cores are preempted inside their transactions, see many commits land meanwhile, and are refused
 * by validation as they should be, committing a few in a hundred -- so the attempt budget can run
 * out first, and a history of this size still exercises every check */
#define HIST_COMMIT_FLOOR (HIST_COMMIT_TARGET / 4)

/* the fixed capacity every history is recorded into; nothing is allocated while a run records */
#define HIST_OPS_MAX     (HIST_ACTIONS + HIST_SPAN * 2)
#define HIST_ATTEMPT_MAX (HIST_COMMIT_TARGET * 24)
#define HIST_NODE_MAX    1024
#define HIST_ELEM_MAX    (HIST_ATTEMPT_MAX * HIST_OPS_MAX + 1)
#define HIST_LIST_MAX    (HIST_NODE_MAX * HIST_ACTIONS)
#define HIST_WORD_BITS   64
#define HIST_WORDS       (HIST_NODE_MAX / HIST_WORD_BITS)

/* a list's digest weighs each element by its position, so a reordered or truncated list differs */
#define HIST_DIGEST_PRIME 1099511628211ULL

/* the per-thread generator the workload draws from */
#define HIST_RNG_SEED    0x9E3779B97F4A7C15ULL
#define HIST_RNG_SHIFT_A 13
#define HIST_RNG_SHIFT_B 7
#define HIST_RNG_SHIFT_C 17

#define HIST_NONE (-1)

enum
{
    HIST_OP_READ = 1,
    HIST_OP_APPEND = 2,
    HIST_OP_DELETE = 3
};

enum
{
    HIST_ABORTED = 0,
    HIST_COMMITTED = 1,
    HIST_IN_DOUBT = 2
};

/**
 * hist_mix_t
 * the share of each action a workload draws, in percent, with appends taking the rest
 * @param read point reads of one list
 * @param scan scans of HIST_SPAN keys through a range iterator
 * @param del range deletes of HIST_SPAN deletable keys, each scanning its range first
 * @param two_phase attempts that prepare and then commit or roll back the prepared transaction
 * @param keys how many keys the workload draws from
 * @param families how many families the keys are spread over, 0 or 1 for one
 * @param mixed non-zero to begin each attempt at read committed, repeatable read or serializable
 *              drawn at random, in place of the level the run names
 * @param small_buffer non-zero for HIST_WRITE_BUFFER_SMALL, so flushes and compactions run
 *                     through the history
 * @param linger_us how long a prepared attempt waits before its decision, in microseconds, the time
 *                  a coordinator takes to collect its other votes; while it waits the prepare holds
 *                  what it read against every writer
 */
typedef struct
{
    int read;
    int scan;
    int del;
    int two_phase;
    int keys;
    int families;
    int mixed;
    int small_buffer;
    int linger_us;
} hist_mix_t;

/**
 * hist_op_t
 * one recorded operation
 * @param kind HIST_OP_READ, HIST_OP_APPEND or HIST_OP_DELETE
 * @param key the key index, the first of the range for a delete
 * @param key_end one past the last key index a delete covered
 * @param elem the element an append added
 * @param len the length of the list read, by a read or by the append that extended it
 * @param last the last element of that list, 0 for an empty one
 * @param digest the position-weighted digest of that list
 */
typedef struct
{
    int kind;
    int key;
    int key_end;
    uint32_t elem;
    uint32_t len;
    uint32_t last;
    uint64_t digest;
} hist_op_t;

/**
 * hist_txn_t
 * one recorded attempt
 * @param status HIST_COMMITTED, HIST_ABORTED, or HIST_IN_DOUBT until a recovery decides it
 * @param weak non-zero for an attempt at read committed, whose level permits a read another
 *             attempt overwrites before it commits, so no read-write edge leaves it and a lost
 *             update it takes part in is not counted against it
 * @param n how many operations it recorded
 * @param ops the operations in the order it issued them
 */
typedef struct
{
    int status;
    int weak;
    int n;
    hist_op_t ops[HIST_OPS_MAX];
} hist_txn_t;

/**
 * hist_t
 * a whole history, the attempts and the final list of every key
 * @param txns the attempts, indexed by slot
 * @param next_slot the next slot an attempt takes
 * @param committed how many attempts committed
 * @param in_doubt how many prepared attempts were left undecided for a recovery
 * @param final the list of each key read after every attempt finished
 * @param final_len the length of each final list
 */
typedef struct
{
    hist_txn_t txns[HIST_ATTEMPT_MAX];
    _Atomic(int) next_slot;
    _Atomic(int) committed;
    _Atomic(int) in_doubt;
    uint32_t final[HIST_KEYS][HIST_LIST_MAX];
    uint32_t final_len[HIST_KEYS];
} hist_t;

/**
 * hist_found_t
 * the anomalies a check counted
 * @param g1a observations of an aborted attempt's element
 * @param g1b reads that saw a transaction's append to a key but not its later one
 * @param lost committed writes that overwrote the same version, a lost update
 * @param incompatible observations that are not a prefix of their key's version order
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

/* the analysis scratch, sized to the limits and reused by every check */
static int g_node_of_slot[HIST_ATTEMPT_MAX];
static int g_elem_key[HIST_ELEM_MAX];
static uint32_t g_elem_pred[HIST_ELEM_MAX];
static uint32_t g_elem_pos[HIST_ELEM_MAX];
static uint32_t g_elem_succ[HIST_ELEM_MAX];
static int g_elem_deleter[HIST_ELEM_MAX];
static int g_elem_deleter_slot[HIST_ELEM_MAX];
static uint32_t g_first[HIST_KEYS];
static int g_generations[HIST_KEYS];
static int g_strict_starts[HIST_KEYS];
static int g_deleted[HIST_KEYS];
static uint32_t g_path[HIST_LIST_MAX];
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
    return (int)((elem - 1) / HIST_OPS_MAX);
}

static int hist_op_of_elem(const uint32_t elem)
{
    return (int)((elem - 1) % HIST_OPS_MAX);
}

static int hist_slots_recorded(void)
{
    const int n = atomic_load(&g_hist.next_slot);
    return n < HIST_ATTEMPT_MAX ? n : HIST_ATTEMPT_MAX;
}

static int hist_committed_elem(const uint32_t elem)
{
    return elem > 0 && elem < HIST_ELEM_MAX &&
           g_hist.txns[hist_slot_of_elem(elem)].status == HIST_COMMITTED;
}

/* whether the attempt that appended elem ran at a level that permits a lost update */
static int hist_weak_elem(const uint32_t elem)
{
    return elem > 0 && elem < HIST_ELEM_MAX && g_hist.txns[hist_slot_of_elem(elem)].weak;
}

/* the node of the attempt that appended elem, HIST_NONE when it did not commit */
static int hist_writer_node(const uint32_t elem)
{
    if (elem == 0 || elem >= HIST_ELEM_MAX) return HIST_NONE;
    return g_node_of_slot[hist_slot_of_elem(elem)];
}

static void hist_set(uint64_t (*m)[HIST_WORDS], const int from, const int to)
{
    if (from == HIST_NONE || to == HIST_NONE || from == to) return;
    m[from][to / HIST_WORD_BITS] |= 1ULL << (to % HIST_WORD_BITS);
}

static int hist_has(uint64_t (*m)[HIST_WORDS], const int from, const int to)
{
    return (m[from][to / HIST_WORD_BITS] >> (to % HIST_WORD_BITS)) & 1ULL;
}

/* number the committed attempts, and place every committed append after the element it extended */
static int hist_index(void)
{
    const int slots = hist_slots_recorded();
    int nodes = 0;
    for (int s = 0; s < HIST_ATTEMPT_MAX; s++) g_node_of_slot[s] = HIST_NONE;
    for (int s = 0; s < slots; s++)
        if (g_hist.txns[s].status == HIST_COMMITTED && nodes < HIST_NODE_MAX)
            g_node_of_slot[s] = nodes++;
    memset(g_elem_succ, 0, sizeof(g_elem_succ));
    for (int e = 0; e < HIST_ELEM_MAX; e++)
        g_elem_key[e] = g_elem_deleter[e] = g_elem_deleter_slot[e] = HIST_NONE;
    memset(g_first, 0, sizeof(g_first));
    memset(g_generations, 0, sizeof(g_generations));
    memset(g_strict_starts, 0, sizeof(g_strict_starts));
    memset(g_deleted, 0, sizeof(g_deleted));
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        for (int i = 0; i < t->n && i < HIST_OPS_MAX && t->status == HIST_COMMITTED; i++)
        {
            const hist_op_t *op = &t->ops[i];
            if (op->kind == HIST_OP_DELETE)
                for (int k = op->key; k < op->key_end && k < HIST_KEYS; k++) g_deleted[k] = 1;
            if (op->kind != HIST_OP_APPEND) continue;
            g_elem_key[op->elem] = op->key;
            g_elem_pred[op->elem] = op->last;
            g_elem_pos[op->elem] = op->len;
        }
    }
    return nodes;
}

/* link each committed append to its predecessor, counting forks as lost updates. two appends that
 * extended the same version each read it, and whichever committed second read it after the first
 * overwrote it, so a fork between two attempts at levels forbidding a lost update is one whatever
 * else ran between them; a fork a read-committed attempt took part in may be its own, which its
 * level permits, and is not counted */
static void hist_chain(hist_found_t *f)
{
    for (uint32_t e = 1; e < HIST_ELEM_MAX; e++)
    {
        if (g_elem_key[e] == HIST_NONE) continue;
        const uint32_t p = g_elem_pred[e];
        const int k = g_elem_key[e];
        if (p == 0)
        {
            if (g_generations[k]++ == 0) g_first[k] = e;
            g_strict_starts[k] += !hist_weak_elem(e);
            continue;
        }
        if (!hist_committed_elem(p))
            f->g1a++;
        else if (g_elem_key[p] != k || g_elem_pos[p] + 1 != g_elem_pos[e])
            f->incompatible++;
        else if (g_elem_succ[p] != 0)
            f->lost += !hist_weak_elem(g_elem_succ[p]) && !hist_weak_elem(e);
        else
            g_elem_succ[p] = e;
    }
    /* a second start of a list no delete ever cleared is an append that missed the first */
    for (int k = 0; k < HIST_KEYS; k++)
        if (g_strict_starts[k] > 1 && !g_deleted[k]) f->lost += g_strict_starts[k] - 1;
}

/* the list ending at elem, collected back through the predecessors; its length, 0 if unplaceable */
static uint32_t hist_path_to(const uint32_t elem)
{
    uint32_t n = g_elem_pos[elem] + 1;
    if (n > HIST_LIST_MAX) return 0;
    uint32_t at = elem;
    for (uint32_t i = n; i > 0; i--)
    {
        if (at == 0 || g_elem_key[at] == HIST_NONE) return 0;
        g_path[i - 1] = at;
        at = g_elem_pred[at];
    }
    return at == 0 ? n : 0;
}

/* whether an observation of key k matches its version order; counts what it finds wrong */
static int hist_observation_placed(hist_found_t *f, const int k, const hist_op_t *op)
{
    if (op->len == 0) return 1;
    if (!hist_committed_elem(op->last))
    {
        f->g1a++;
        return 0;
    }
    if (g_elem_key[op->last] != k || g_elem_pos[op->last] + 1 != op->len ||
        hist_path_to(op->last) != op->len || hist_digest(g_path, op->len) != op->digest)
    {
        f->incompatible++;
        return 0;
    }
    return 1;
}

/* whether the attempt at slot appended to key after its operation at index op */
static int hist_appends_later(const int slot, const int op, const int key)
{
    const hist_txn_t *t = &g_hist.txns[slot];
    for (int i = op + 1; i < t->n && i < HIST_OPS_MAX; i++)
        if (t->ops[i].kind == HIST_OP_APPEND && t->ops[i].key == key) return 1;
    return 0;
}

/* a delete's own scan of key k just before it, the version the delete overwrote */
static const hist_op_t *hist_deleted_version(const hist_txn_t *t, const int del, const int k)
{
    for (int i = del - 1; i >= 0; i--)
        if (t->ops[i].kind == HIST_OP_READ && t->ops[i].key == k) return &t->ops[i];
    return NULL;
}

/* write-write edges along the version order, deletes included */
static void hist_edges_from_writes(hist_found_t *f)
{
    for (uint32_t e = 1; e < HIST_ELEM_MAX; e++)
        if (g_elem_succ[e] != 0)
            hist_set(g_edge_w, hist_writer_node(e), hist_writer_node(g_elem_succ[e]));
    const int slots = hist_slots_recorded();
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        if (t->status != HIST_COMMITTED) continue;
        for (int i = 0; i < t->n && i < HIST_OPS_MAX; i++)
        {
            if (t->ops[i].kind != HIST_OP_DELETE) continue;
            for (int k = t->ops[i].key; k < t->ops[i].key_end && k < HIST_KEYS; k++)
            {
                const hist_op_t *seen = hist_deleted_version(t, i, k);
                if (!seen || seen->len == 0 || !hist_committed_elem(seen->last)) continue;
                const uint32_t v = seen->last;
                if (g_elem_succ[v] != 0 || g_elem_deleter[v] != HIST_NONE)
                {
                    const int other_weak = g_elem_succ[v] != 0
                                               ? hist_weak_elem(g_elem_succ[v])
                                               : g_hist.txns[g_elem_deleter_slot[v]].weak;
                    f->lost += !t->weak && !other_weak;
                    continue;
                }
                g_elem_deleter[v] = g_node_of_slot[s];
                g_elem_deleter_slot[v] = s;
                hist_set(g_edge_w, hist_writer_node(seen->last), g_node_of_slot[s]);
            }
        }
    }
}

/* write-read and read-write edges from one committed observation of key k by node */
static void hist_edges_from_read(hist_found_t *f, const int node, const int slot, const int i)
{
    const hist_op_t *op = &g_hist.txns[slot].ops[i];
    const int k = op->key;
    /* a read committed attempt may read what another overwrites before it commits, so no read-write
     * edge leaves it; its write and write-read edges still count, since its level forbids g1c */
    const int rw = !g_hist.txns[slot].weak;
    if (!hist_observation_placed(f, k, op)) return;
    if (op->len == 0)
    {
        /* an empty list read before a key's only start, when no delete could have emptied it */
        if (rw && !g_deleted[k] && g_generations[k] == 1)
            hist_set(g_edge_rw, node, hist_writer_node(g_first[k]));
        return;
    }
    const int w = hist_writer_node(op->last);
    if (w != node && hist_appends_later(hist_slot_of_elem(op->last), hist_op_of_elem(op->last), k))
        f->g1b++;
    hist_set(g_edge_w, w, node);
    if (!rw) return;
    const uint32_t next = g_elem_succ[op->last];
    if (next != 0) hist_set(g_edge_rw, node, hist_writer_node(next));
    if (g_elem_deleter[op->last] != HIST_NONE) hist_set(g_edge_rw, node, g_elem_deleter[op->last]);
}

/* every edge of the dependency graph */
static void hist_build_graph(hist_found_t *f)
{
    memset(g_edge_w, 0, sizeof(g_edge_w));
    memset(g_edge_rw, 0, sizeof(g_edge_rw));
    hist_edges_from_writes(f);
    const int slots = hist_slots_recorded();
    for (int s = 0; s < slots; s++)
    {
        const hist_txn_t *t = &g_hist.txns[s];
        const int node = g_node_of_slot[s];
        if (t->status != HIST_COMMITTED || node == HIST_NONE) continue;
        for (int i = 0; i < t->n && i < HIST_OPS_MAX; i++)
            if (t->ops[i].kind == HIST_OP_READ) hist_edges_from_read(f, node, s, i);
    }
}

/* no final list holds an aborted element, and every key no delete touched ends in a list its
 * version order builds, ending at a version nothing extended. the list is followed back from its
 * end rather than forward from its start, since a read-committed attempt may fork a list, which its
 * level permits, and the final list may then be either branch */
static void hist_check_final(hist_found_t *f)
{
    for (int k = 0; k < HIST_KEYS; k++)
    {
        const uint32_t len = g_hist.final_len[k];
        for (uint32_t i = 0; i < len && i < HIST_LIST_MAX; i++)
            if (!hist_committed_elem(g_hist.final[k][i])) f->g1a++;
        if (g_deleted[k]) continue;
        if (len == 0)
        {
            f->incompatible += g_generations[k] > 0;
            continue;
        }
        const uint32_t last = g_hist.final[k][len - 1];
        if (!hist_committed_elem(last)) continue;
        if (g_elem_key[last] != k || g_elem_pos[last] + 1 != len || hist_path_to(last) != len ||
            hist_digest(g_path, len) != hist_digest(g_hist.final[k], len) || g_elem_succ[last] != 0)
            f->incompatible++;
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
    const int n = hist_index();
    hist_chain(&f);
    hist_build_graph(&f);
    hist_check_final(&f);
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

/* ---- the workload, recording into g_hist ---- */

static void hist_key_name(const int key, char *out)
{
    snprintf(out, HIST_KEY_BYTES, HIST_KEY_FORMAT, key);
}

/* the list a stored value holds, into out of HIST_LIST_MAX elements; its length, or HIST_NONE */
static int hist_decode(const uint8_t *v, const size_t vs, uint32_t *out)
{
    const size_t n = vs / sizeof(uint32_t);
    if (n > HIST_LIST_MAX || vs % sizeof(uint32_t) != 0) return HIST_NONE;
    if (n > 0) memcpy(out, v, n * sizeof(uint32_t));
    return (int)n;
}

static void hist_note_list(hist_op_t *op, const uint32_t *list, const uint32_t len)
{
    op->len = len;
    op->last = len > 0 ? list[len - 1] : 0;
    op->digest = hist_digest(list, len);
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
    const int n = hist_decode(v, vs, out);
    free(v);
    if (n == HIST_NONE) return TDB_ERR_TOO_LARGE;
    *len = (uint32_t)n;
    return TDB_SUCCESS;
}

static hist_op_t *hist_next_op(hist_txn_t *t, const int kind, const int key)
{
    hist_op_t *op = &t->ops[t->n];
    memset(op, 0, sizeof(*op));
    op->kind = kind;
    op->key = key;
    return op;
}

static int hist_do_read(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, hist_txn_t *t,
                        const int key)
{
    uint32_t list[HIST_LIST_MAX];
    uint32_t len = 0;
    hist_op_t *op = hist_next_op(t, HIST_OP_READ, key);
    const int rc = hist_read_list(txn, cf, key, list, &len);
    if (rc != TDB_SUCCESS) return rc;
    hist_note_list(op, list, len);
    t->n++;
    return TDB_SUCCESS;
}

static int hist_do_append(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, hist_txn_t *t,
                          const int slot, const int key)
{
    uint32_t list[HIST_LIST_MAX];
    uint32_t len = 0;
    hist_op_t *op = hist_next_op(t, HIST_OP_APPEND, key);
    int rc = hist_read_list(txn, cf, key, list, &len);
    if (rc != TDB_SUCCESS) return rc;
    if (len >= HIST_LIST_MAX) return TDB_ERR_TOO_LARGE;
    hist_note_list(op, list, len);
    op->elem = (uint32_t)(slot * HIST_OPS_MAX + t->n + 1);
    list[len] = op->elem;
    char name[HIST_KEY_BYTES];
    hist_key_name(key, name);
    rc = tidesdb_txn_put(txn, cf, (const uint8_t *)name, strlen(name), (const uint8_t *)list,
                         (size_t)(len + 1) * sizeof(uint32_t), -1);
    if (rc == TDB_SUCCESS) t->n++;
    return rc;
}

/* record what the iterator stands on as the list of its key, inside [lo, hi) */
static int hist_scan_step(tidesdb_iter_t *it, const int lo, const int hi, uint32_t *list,
                          hist_op_t *seen, int *present, int *past)
{
    uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    int rc = tidesdb_iter_key_value(it, &k, &ks, &v, &vs);
    if (rc != TDB_SUCCESS) return rc;
    char name[HIST_KEY_BYTES];
    hist_key_name(hi, name);
    const size_t hs = strlen(name);
    const int cmp = memcmp(k, name, ks < hs ? ks : hs);
    *past = cmp > 0 || (cmp == 0 && ks >= hs);
    for (int key = lo; key < hi && !*past; key++)
    {
        hist_key_name(key, name);
        if (strlen(name) != ks || memcmp(name, k, ks) != 0) continue;
        const int n = hist_decode(v, vs, list);
        rc = n == HIST_NONE ? TDB_ERR_TOO_LARGE : TDB_SUCCESS;
        if (n != HIST_NONE) hist_note_list(&seen[key - lo], list, (uint32_t)n);
        present[key - lo] = 1;
    }
    free(k);
    free(v);
    return rc;
}

/* scan the keys [lo, hi) through a range iterator, recording every key of the range as read, the
 * ones the scan did not return as empty. a range iterator is positioned by a seek to its lower
 * bound, and the scan steps until it stands past the upper one, so the footprint a validating
 * level records covers the whole range */
static int hist_do_scan(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, hist_txn_t *t,
                        const int lo, const int hi)
{
    char lo_name[HIST_KEY_BYTES], hi_name[HIST_KEY_BYTES];
    hist_key_name(lo, lo_name);
    hist_key_name(hi, hi_name);
    uint32_t list[HIST_LIST_MAX];
    hist_op_t seen[HIST_SPAN];
    int present[HIST_SPAN];
    memset(seen, 0, sizeof(seen));
    memset(present, 0, sizeof(present));
    tidesdb_iter_t *it = NULL;
    int rc = tidesdb_iter_new_range(txn, cf, (const uint8_t *)lo_name, strlen(lo_name),
                                    (const uint8_t *)hi_name, strlen(hi_name), &it);
    if (rc != TDB_SUCCESS) return rc;
    rc = tidesdb_iter_seek(it, (const uint8_t *)lo_name, strlen(lo_name));
    int past = 0;
    for (int step = 0; step <= HIST_SPAN && rc == TDB_SUCCESS && !past && tidesdb_iter_valid(it);
         step++)
    {
        rc = hist_scan_step(it, lo, hi, list, seen, present, &past);
        if (rc == TDB_SUCCESS && !past) rc = tidesdb_iter_next(it);
    }
    tidesdb_iter_free(it);
    if (rc != TDB_SUCCESS && rc != TDB_ERR_NOT_FOUND) return rc;
    for (int key = lo; key < hi; key++)
    {
        hist_op_t *op = hist_next_op(t, HIST_OP_READ, key);
        if (present[key - lo]) *op = seen[key - lo];
        op->kind = HIST_OP_READ;
        op->key = key;
        t->n++;
    }
    return TDB_SUCCESS;
}

/* scan the deletable keys [lo, hi), then delete them as one range */
static int hist_do_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, hist_txn_t *t,
                          const int lo, const int hi)
{
    int rc = hist_do_scan(txn, cf, t, lo, hi);
    if (rc != TDB_SUCCESS) return rc;
    char lo_name[HIST_KEY_BYTES], hi_name[HIST_KEY_BYTES];
    hist_key_name(lo, lo_name);
    hist_key_name(hi, hi_name);
    hist_op_t *op = hist_next_op(t, HIST_OP_DELETE, lo);
    op->key_end = hi;
    rc = tidesdb_txn_delete_range(txn, cf, (const uint8_t *)lo_name, strlen(lo_name),
                                  (const uint8_t *)hi_name, strlen(hi_name));
    if (rc == TDB_SUCCESS) t->n++;
    return rc;
}

/* how many families a mix spreads its keys over */
static int hist_families(const hist_mix_t *mix)
{
    return mix->families > 1 ? HIST_FAMILIES_MAX : 1;
}

/* the family a key lives in, the lower half of the keys in the first when there are two */
static int hist_family_of(const hist_mix_t *mix, const int key)
{
    return hist_families(mix) > 1 && key >= mix->keys / HIST_FAMILIES_MAX ? 1 : 0;
}

/* one drawn action; a scan or a delete that no longer fits in the attempt's record is a read. a
 * scan stays inside one family, and the deletable keys all lie in the last */
static int hist_do_action(tidesdb_txn_t *txn, tidesdb_column_family_t *const *cfs, hist_txn_t *t,
                          const int slot, const hist_mix_t *mix, uint64_t *rng)
{
    const int roll = (int)(hist_rng(rng) % HIST_PERCENT);
    const int key = (int)(hist_rng(rng) % (uint64_t)mix->keys);
    const int room = t->n + HIST_SPAN + 1 <= HIST_OPS_MAX;
    const int del_keys = mix->keys - HIST_DELETE_FIRST - HIST_SPAN + 1;
    tidesdb_column_family_t *cf = cfs[hist_family_of(mix, key)];
    if (roll < mix->scan && room)
    {
        const int span = mix->keys / hist_families(mix);
        const int base = hist_family_of(mix, key) * span;
        const int lo = base + (int)(hist_rng(rng) % (uint64_t)(span - HIST_SPAN + 1));
        return hist_do_scan(txn, cf, t, lo, lo + HIST_SPAN);
    }
    if (roll < mix->scan + mix->del && room && del_keys > 0)
    {
        const int lo = HIST_DELETE_FIRST + (int)(hist_rng(rng) % (uint64_t)del_keys);
        return hist_do_delete(txn, cfs[hist_family_of(mix, lo)], t, lo, lo + HIST_SPAN);
    }
    if (roll < mix->scan + mix->del + mix->read || t->n + 1 > HIST_OPS_MAX)
        return t->n + 1 <= HIST_OPS_MAX ? hist_do_read(txn, cf, t, key) : TDB_SUCCESS;
    return hist_do_append(txn, cf, t, slot, key);
}

/* decide an attempt in two phases, or leave it prepared for a recovery when that is still wanted */
static int hist_two_phase(tidesdb_txn_t *txn, hist_txn_t *t, const int slot, uint64_t *rng,
                          const int leave_in_doubt, const int linger_us)
{
    char xid[HIST_XID_BYTES];
    snprintf(xid, sizeof(xid), HIST_XID_FORMAT, slot);
    int rc = tidesdb_txn_prepare(txn, (const uint8_t *)xid, strlen(xid));
    if (rc != TDB_SUCCESS) return rc;
    tidesdb_txn_state_t st = TDB_TXN_STATE_ACTIVE;
    if (tidesdb_txn_state(txn, &st) != TDB_SUCCESS) return TDB_ERR_UNKNOWN;
    if (st != TDB_TXN_STATE_PREPARED)
        return st == TDB_TXN_STATE_COMMITTED ? TDB_SUCCESS : TDB_ERR_UNKNOWN;
    if (leave_in_doubt && atomic_fetch_add(&g_hist.in_doubt, 1) < HIST_IN_DOUBT_MAX)
    {
        t->status = HIST_IN_DOUBT;
        return TDB_ERR_TXN_ABORTED;
    }
    if (linger_us > 0) (void)usleep((useconds_t)linger_us);
    if (hist_rng(rng) % 2 == 0)
    {
        (void)tidesdb_txn_rollback_prepared(txn);
        return TDB_ERR_TXN_ABORTED;
    }
    return tidesdb_txn_commit_prepared(txn);
}

/**
 * hist_worker_t
 * what one recording thread runs against
 * @param db the database
 * @param cfs the families the lists live in
 * @param iso the isolation level every attempt begins at, unless the mix draws one per attempt
 * @param seed the thread's generator seed
 * @param mix the actions the attempts draw
 * @param target the committed count at which the thread stops
 * @param slot_limit the slot at which the thread stops, whatever has committed, so one run leaves
 *                   the rest of the budget to the runs after it
 * @param leave_in_doubt non-zero to leave prepared attempts undecided, up to HIST_IN_DOUBT_MAX
 */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cfs[HIST_FAMILIES_MAX];
    int iso;
    uint64_t seed;
    hist_mix_t mix;
    int target;
    int slot_limit;
    int leave_in_doubt;
} hist_worker_t;

/* one attempt recorded into its slot; an attempt the store refuses or fails is recorded aborted */
static void hist_run_attempt(const hist_worker_t *w, uint64_t *rng, const int slot)
{
    static const int levels[HIST_MIXED_LEVELS] = {
        TDB_ISOLATION_READ_COMMITTED, TDB_ISOLATION_REPEATABLE_READ, TDB_ISOLATION_SERIALIZABLE};
    const int iso = w->mix.mixed ? levels[hist_rng(rng) % HIST_MIXED_LEVELS] : w->iso;
    hist_txn_t *t = &g_hist.txns[slot];
    t->status = HIST_ABORTED;
    t->weak = iso <= TDB_ISOLATION_READ_COMMITTED;
    t->n = 0;
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(w->db, (tidesdb_isolation_level_t)iso, &txn) !=
        TDB_SUCCESS)
        return;
    int rc = TDB_SUCCESS;
    for (int i = 0; i < HIST_ACTIONS && rc == TDB_SUCCESS; i++)
        rc = hist_do_action(txn, w->cfs, t, slot, &w->mix, rng);
    if (rc == TDB_SUCCESS)
        rc = (int)(hist_rng(rng) % HIST_PERCENT) < w->mix.two_phase
                 ? hist_two_phase(txn, t, slot, rng, w->leave_in_doubt, w->mix.linger_us)
                 : tidesdb_txn_commit(txn);
    if (rc == TDB_SUCCESS)
    {
        t->status = HIST_COMMITTED;
        atomic_fetch_add(&g_hist.committed, 1);
    }
    else if (t->status != HIST_IN_DOUBT)
        (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
}

static void *hist_worker(void *arg)
{
    const hist_worker_t *w = (const hist_worker_t *)arg;
    uint64_t rng = w->seed;
    for (int i = 0; i < HIST_ATTEMPT_MAX; i++)
    {
        if (atomic_load(&g_hist.committed) >= w->target) break;
        const int slot = atomic_fetch_add(&g_hist.next_slot, 1);
        if (slot >= w->slot_limit || slot >= HIST_ATTEMPT_MAX) break;
        hist_run_attempt(w, &rng, slot);
    }
    return NULL;
}

/* open the database of a history, fresh when asked, and the families its mix spreads keys over */
static void hist_open(const int fresh, const hist_mix_t *mix, tidesdb_t **db,
                      tidesdb_column_family_t **cfs)
{
    static const char *names[HIST_FAMILIES_MAX] = {HIST_CF, HIST_CF_B};
    if (fresh) (void)remove_directory(HIST_DB_DIR);
    static char path[] = HIST_DB_DIR;
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = path;
    cfg.memtable_write_buffer_size =
        mix->small_buffer ? HIST_WRITE_BUFFER_SMALL : HIST_WRITE_BUFFER;
    cfg.log_level = TDB_LOG_WARN;
    ASSERT_EQ(tidesdb_open(&cfg, db), TDB_SUCCESS);
    for (int i = 0; i < hist_families(mix); i++)
    {
        if (fresh)
        {
            tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
            ASSERT_EQ(tidesdb_create_column_family(*db, names[i], &cc), TDB_SUCCESS);
        }
        cfs[i] = tidesdb_get_column_family(*db, names[i]);
        ASSERT_TRUE(cfs[i] != NULL);
    }
}

/* run the workers against an open database until the committed count reaches target or the slots
 * reach slot_limit */
static void hist_run(tidesdb_t *db, tidesdb_column_family_t *const *cfs, const int iso,
                     const hist_mix_t *mix, const int target, const int slot_limit,
                     const int leave_in_doubt)
{
    pthread_t th[HIST_THREADS];
    hist_worker_t w[HIST_THREADS];
    for (int i = 0; i < HIST_THREADS; i++)
    {
        w[i] =
            (hist_worker_t){.db = db,
                            .cfs = {cfs[0], cfs[hist_families(mix) - 1]},
                            .iso = iso,
                            .mix = *mix,
                            .target = target,
                            .slot_limit = slot_limit,
                            .seed = HIST_RNG_SEED + (uint64_t)(i + atomic_load(&g_hist.next_slot)),
                            .leave_in_doubt = leave_in_doubt};
        ASSERT_EQ(pthread_create(&th[i], NULL, hist_worker, &w[i]), 0);
    }
    for (int i = 0; i < HIST_THREADS; i++) ASSERT_EQ(pthread_join(th[i], NULL), 0);
}

/* read every key's final list once every attempt has finished */
static void hist_read_final(tidesdb_t *db, tidesdb_column_family_t *const *cfs,
                            const hist_mix_t *mix)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn), TDB_SUCCESS);
    for (int k = 0; k < HIST_KEYS; k++)
        ASSERT_EQ(hist_read_list(txn, cfs[hist_family_of(mix, k)], k, g_hist.final[k],
                                 &g_hist.final_len[k]),
                  TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

/* record a whole history at a level against a fresh database, without restarts */
static void hist_record(const int iso, const hist_mix_t *mix)
{
    memset(&g_hist, 0, sizeof(g_hist));
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cfs[HIST_FAMILIES_MAX] = {NULL};
    hist_open(1, mix, &db, cfs);
    hist_run(db, cfs, iso, mix, HIST_COMMIT_TARGET, HIST_ATTEMPT_MAX, 0);
    hist_read_final(db, cfs, mix);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(HIST_DB_DIR);
}

#endif /* __TIDESDB_TEST_ISOLATION_HISTORY_H__ */
