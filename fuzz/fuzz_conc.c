/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_ERR_BUSY, which is internal to the engine and not in db.h */
#include "compat.h"
#include "db.h"
#include "fuzz_model.h"

/* the concurrency harness runs several worker threads against one shared database, each owning a
 * disjoint slice of the key space keyed by a unique first byte. because no two workers ever touch
 * the same key, every worker's operation stream is deterministic and its own reference model stays
 * exact no matter how the threads interleave, while the engine's shared machinery -- the unified
 * memtable and its rotation, the write-ahead log and its staging ring, flush, compaction, the block
 * cache and the value log -- is exercised under real contention. each worker checks every read
 * against its model as it goes, and after the threads join the harness checks the whole committed
 * set once more, so a race that drops, duplicates, or corrupts a committed value is caught. there
 * is no cross-worker conflict, so the oracle needs no linearization.
 *
 * that same disjointness is an oracle for the commit path. the workers run at every isolation
 * level, and at repeatable read and above a commit claims its keys and checks them against
 * concurrent committers, so any commit refused with TDB_ERR_CONFLICT is a conflict between keys
 * nobody shares
 * -- a refusal the engine invented. a wide batch puts hundreds of keys from a key space of the
 * worker's own and commits them at once, the shape of a bulk load, so two such commits in flight
 * together carry enough keys that a table of hashed slots refused most of them; a prefix delete
 * inside a worker's own slice holds an interval the same way. both must always commit */

#define FC_WORKERS        4    /* worker threads, one disjoint key prefix each; at most 26 */
#define FC_OPS_PER_WORKER 6000 /* operations each worker runs per iteration */
#define FC_KEY_ALPHABET   5  /* distinct suffix characters, keeping the key space small and dense */
#define FC_MAX_SUFFIX     3  /* longest key suffix after the one-byte worker prefix */
#define FC_VALUE_TABLE    12 /* one in this many put values spills to the value log */
#define FC_SPILL_VLEN     1500 /* the spilled value length, above the default klog threshold */
#define FC_WRITE_BUFFER   8192 /* a small memtable so flushes fire often and race the writers */
#define FC_CF             "c0"
/* the wide key space: the worker's prefix byte, a marker no ordinary key carries, then
 * FC_WIDE_SUFFIX characters from a wider alphabet, so a batch can hold hundreds of distinct keys,
 * and a wide commit is in flight for as long as its keys take to apply */
#define FC_WIDE_MARK      'z'
#define FC_WIDE_ALPHABET  16
#define FC_WIDE_SUFFIX    3
#define FC_WIDE_KEY_LEN   (2 + FC_WIDE_SUFFIX)
#define FC_WIDE_KEY_SPACE (FC_WIDE_ALPHABET * FC_WIDE_ALPHABET * FC_WIDE_ALPHABET)
#define FC_WIDE_MIN_KEYS  128
#define FC_WIDE_MAX_KEYS  512
/* a wide batch's values stay this small: its keys are what the claims are about, and a batch of
 * hundreds of spilled values would span several memtables and sit in admission for each */
#define FC_WIDE_VALUE_MAX 8
/* one wide batch in this many op-14 turns, enough to keep two in flight together now and then
 * without the batches outweighing the rest of the stream */
#define FC_WIDE_ONE_IN 16
/* one prefix delete in this many op-15 turns. a commit carrying an interval is checked against
 * every claim in flight rather than against one chain; rare, the deletes still drive that path
 * under concurrency without it outweighing the rest of the stream */
#define FC_PREFIX_DELETE_ONE_IN 4
#define FC_STANDALONE_ITERS     30
#define FC_BUSY_RETRIES         1000 /* a busy fd reservation is retryable, never a definitive result */

#define FC_CHECK(cond, ...)                                                                \
    do                                                                                     \
    {                                                                                      \
        if (!(cond))                                                                       \
        {                                                                                  \
            fprintf(stderr, "CONC ORACLE FAIL (iteration %ld, seed %llu): ", fc_iteration, \
                    (unsigned long long)fc_iteration_seed);                                \
            fprintf(stderr, __VA_ARGS__);                                                  \
            fprintf(stderr, "\n");                                                         \
            fflush(stderr);                                                                \
            abort();                                                                       \
        }                                                                                  \
    } while (0)

/* the iteration running and the seed it runs from, named in every failure so one iteration can be
 * rerun on its own with TIDESDB_FUZZ_ONLY_SEED */
static long fc_iteration;
static uint64_t fc_iteration_seed;

/* one worker's private state; the database and column family are shared, everything else is
 * per-thread so the harness itself has no shared mutable state and races only inside the engine */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    fuzz_model_t *model;
    uint64_t rng;
    uint64_t tag; /* makes every put value distinct so a stale read is caught */
    int id;
    int nops;
    tidesdb_isolation_level_t
        isolation; /* every transaction this worker opens runs at this level */
} fc_worker_t;

/* the isolation levels the workers cycle through by id. three of the default four reserve their
 * keys at commit, so most pairs of commits in flight together are pairs of reservers, and one runs
 * at the default level so the path that reserves nothing is driven alongside them */
static const tidesdb_isolation_level_t fc_isolations[] = {
    TDB_ISOLATION_SNAPSHOT, TDB_ISOLATION_SERIALIZABLE, TDB_ISOLATION_SNAPSHOT,
    TDB_ISOLATION_READ_COMMITTED};
#define FC_ISOLATION_COUNT ((int)(sizeof(fc_isolations) / sizeof(fc_isolations[0])))

static uint64_t fc_rng(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* fill key with this worker's unique prefix byte followed by a short suffix, returning the length
 */
static size_t fc_gen_key(fc_worker_t *w, uint8_t *key)
{
    key[0] = (uint8_t)('a' + w->id);
    const size_t suffix = (size_t)(fc_rng(&w->rng) % (FC_MAX_SUFFIX + 1));
    for (size_t i = 0; i < suffix; i++)
        key[1 + i] = (uint8_t)('a' + (fc_rng(&w->rng) % FC_KEY_ALPHABET));
    return suffix + 1;
}

/* fill key with the index-th key of this worker's wide key space, so a batch that walks indices
 * puts distinct keys; indices past the space wrap */
static size_t fc_wide_key_at(const fc_worker_t *w, size_t index, uint8_t *key)
{
    key[0] = (uint8_t)('a' + w->id);
    key[1] = (uint8_t)FC_WIDE_MARK;
    index %= FC_WIDE_KEY_SPACE;
    for (size_t i = FC_WIDE_KEY_LEN - 1; i >= 2; i--)
    {
        key[i] = (uint8_t)('a' + index % FC_WIDE_ALPHABET);
        index /= FC_WIDE_ALPHABET;
    }
    return FC_WIDE_KEY_LEN;
}

/* fill value with a tag-derived byte pattern so no two puts share a value, and return its length */
static size_t fc_gen_value(fc_worker_t *w, uint8_t *val, size_t cap)
{
    const uint64_t vs = fc_rng(&w->rng);
    size_t vlen = (vs % FC_VALUE_TABLE == FC_VALUE_TABLE - 1) ? FC_SPILL_VLEN
                                                              : (size_t)(vs % FC_VALUE_TABLE) + 1;
    if (vlen > cap) vlen = cap;
    const uint64_t t = w->tag++;
    for (size_t i = 0; i < vlen; i++) val[i] = (uint8_t)(t + i);
    return vlen;
}

/* read a key through txn, retrying a busy fd reservation; returns 1 when present with the value
 * copied into val (caller frees nothing, the engine's buffer is freed here), 0 when absent */
static int fc_db_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                     size_t klen, uint8_t **out_val, size_t *out_vlen)
{
    for (int tries = 0; tries < FC_BUSY_RETRIES; tries++)
    {
        uint8_t *v = NULL;
        size_t vl = 0;
        const int rc = tidesdb_txn_get(txn, cf, key, klen, &v, &vl);
        if (rc == TDB_SUCCESS)
        {
            *out_val = v;
            *out_vlen = vl;
            return 1;
        }
        if (rc == TDB_ERR_NOT_FOUND) return 0;
        if (rc != TDB_ERR_BUSY) FC_CHECK(0, "unexpected get rc=%d", rc);
    }
    FC_CHECK(0, "get stayed busy after retries");
    return 0;
}

/* how a key the model holds and the database did not is followed up before the run aborts. it is
 * read again at read committed, where a version the watermark has passed is visible, and at read
 * uncommitted, where every applied version is, over a spread of delays. the pattern names the fault
 * -- a miss that clears is a read-path race, one that stays is a lost write, and one that only read
 * uncommitted sees is a version the watermark never reached */
#define FC_MISS_FOLLOWUPS 5
static const unsigned fc_miss_delay_us[FC_MISS_FOLLOWUPS] = {0, 1000, 10000, 100000, 1000000};

/* one follow-up read at the given isolation, returning the engine's result code */
static int fc_reread(fc_worker_t *w, tidesdb_isolation_level_t isolation, const uint8_t *key,
                     size_t klen)
{
    tidesdb_txn_t *t = NULL;
    if (tidesdb_txn_begin_with_isolation(w->db, isolation, &t) != TDB_SUCCESS) return TDB_ERR_IO;
    uint8_t *v = NULL;
    size_t vl = 0;
    const int rc = tidesdb_txn_get(t, w->cf, key, klen, &v, &vl);
    if (rc == TDB_SUCCESS) free(v);
    (void)tidesdb_txn_rollback(t);
    tidesdb_txn_free(t);
    return rc;
}

static void fc_report_miss(fc_worker_t *w, const uint8_t *key, size_t klen)
{
    for (int i = 0; i < FC_MISS_FOLLOWUPS; i++)
    {
        if (fc_miss_delay_us[i] != 0) usleep(fc_miss_delay_us[i]);
        const int rc = fc_reread(w, TDB_ISOLATION_READ_COMMITTED, key, klen);
        const int ru = fc_reread(w, TDB_ISOLATION_READ_UNCOMMITTED, key, klen);
        fprintf(stderr, "  follow-up +%u us: read committed rc=%d, read uncommitted rc=%d\n",
                fc_miss_delay_us[i], rc, ru);
    }
}

/* compare a single key's value in the database against the worker's model, under the worker's open
 * transaction when one is active (read-your-writes) or a throwaway read transaction otherwise */
static void fc_check_get(fc_worker_t *w, tidesdb_txn_t *txn)
{
    uint8_t key[1 + FC_MAX_SUFFIX];
    const size_t klen = fc_gen_key(w, key);

    const uint8_t *mv = NULL, *cvv = NULL;
    size_t mvl = 0, cvl = 0;
    const int model_present = fuzz_model_get(w->model, FC_CF, key, klen, &mv, &mvl);
    const int committed_present = fuzz_model_get_committed(w->model, FC_CF, key, klen, &cvv, &cvl);
    /* a read whose expected value comes from the open transaction's own buffer is a
     * read-your-writes read; otherwise it reads committed state, which tells the two failure modes
     * apart */
    const int ryw = txn && (model_present != committed_present || mvl != cvl ||
                            (mvl && memcmp(mv, cvv, mvl) != 0));

    tidesdb_txn_t *read = txn;
    if (!read)
        FC_CHECK(tidesdb_txn_begin_with_isolation(w->db, w->isolation, &read) == TDB_SUCCESS,
                 "read txn begin w%d", w->id);
    const uint64_t snap = tidesdb_txn_read_snapshot(read);

    uint8_t *dv = NULL;
    size_t dvl = 0;
    const int db_present = fc_db_get(read, w->cf, key, klen, &dv, &dvl);

    if (model_present && !db_present) fc_report_miss(w, key, klen);
    FC_CHECK(db_present == model_present,
             "get presence mismatch w%d key=%.*s model=%d db=%d ryw=%d open=%d isolation=%d "
             "snap=%llu",
             w->id, (int)klen, (const char *)key, model_present, db_present, ryw, txn != NULL,
             (int)w->isolation, (unsigned long long)snap);
    if (db_present)
    {
        FC_CHECK(fuzz_value_eq(dv, dvl, mv, mvl),
                 "get value mismatch w%d key=%.*s ryw=%d snap=%llu model_vlen=%zu model_v0=%u "
                 "db_vlen=%zu db_v0=%u",
                 w->id, (int)klen, (const char *)key, ryw, (unsigned long long)snap, mvl,
                 mvl ? mv[0] : 0u, dvl, dvl ? dv[0] : 0u);
        free(dv);
    }
    if (!txn)
    {
        (void)tidesdb_txn_rollback(read);
        tidesdb_txn_free(read);
    }
}

/* iterate the whole column family and check that every key belonging to this worker matches its
 * model exactly and in order, and that the worker sees all and only its committed keys; called with
 * no open transaction so the committed model is the exact expectation */
static void fc_check_iter(fc_worker_t *w)
{
    fuzz_model_kv_t *mk = NULL;
    size_t mn = 0;
    FC_CHECK(fuzz_model_scan(w->model, FC_CF, &mk, &mn), "model scan");

    tidesdb_txn_t *t = NULL;
    FC_CHECK(tidesdb_txn_begin(w->db, &t) == TDB_SUCCESS, "iter txn begin");
    tidesdb_iter_t *it = NULL;
    FC_CHECK(tidesdb_iter_new(t, w->cf, &it) == TDB_SUCCESS, "iter new");
    (void)tidesdb_iter_seek_to_first(it);

    size_t j = 0;
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        FC_CHECK(tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS, "iter read");
        if (kl > 0 && k[0] == (uint8_t)('a' + w->id))
        {
            FC_CHECK(j < mn, "iter has an extra key for w%d", w->id);
            FC_CHECK(kl == mk[j].klen && memcmp(k, mk[j].key, kl) == 0, "iter key order w%d",
                     w->id);
            FC_CHECK(fuzz_value_eq(v, vl, mk[j].val, mk[j].vlen), "iter value w%d", w->id);
            j++;
        }
        free(k);
        free(v);
        (void)tidesdb_iter_next(it);
    }
    FC_CHECK(j == mn, "iter missing keys for w%d saw %zu of %zu", w->id, j, mn);

    tidesdb_iter_free(it);
    (void)tidesdb_txn_commit(t);
    tidesdb_txn_free(t);
    free(mk);
}

/* apply a put to both the open transaction and the model; a disjoint key space means the commit
 * that follows can never conflict, so any failure here is a real fault */
static void fc_do_put(fc_worker_t *w, tidesdb_txn_t *txn)
{
    uint8_t key[1 + FC_MAX_SUFFIX], val[FC_SPILL_VLEN];
    const size_t klen = fc_gen_key(w, key);
    const size_t vlen = fc_gen_value(w, val, sizeof(val));
    FC_CHECK(tidesdb_txn_put(txn, w->cf, key, klen, val, vlen, -1) == TDB_SUCCESS, "txn put w%d",
             w->id);
    FC_CHECK(fuzz_model_put(w->model, FC_CF, key, klen, val, vlen, FUZZ_TTL_NONE), "model put w%d",
             w->id);
}

/* apply a delete to both the open transaction and the model */
static void fc_do_delete(fc_worker_t *w, tidesdb_txn_t *txn)
{
    uint8_t key[1 + FC_MAX_SUFFIX];
    const size_t klen = fc_gen_key(w, key);
    FC_CHECK(tidesdb_txn_delete(txn, w->cf, key, klen) == TDB_SUCCESS, "txn delete w%d", w->id);
    FC_CHECK(fuzz_model_delete(w->model, FC_CF, key, klen), "model delete w%d", w->id);
}

/* put a wide run of distinct keys from the worker's wide key space, so the commit that follows
 * carries a write set wide enough for its reservations to share slots with another committer's */
static void fc_do_wide_put(fc_worker_t *w, tidesdb_txn_t *txn)
{
    const size_t count =
        FC_WIDE_MIN_KEYS + (size_t)(fc_rng(&w->rng) % (FC_WIDE_MAX_KEYS - FC_WIDE_MIN_KEYS + 1));
    const size_t start = (size_t)(fc_rng(&w->rng) % FC_WIDE_KEY_SPACE);
    for (size_t i = 0; i < count; i++)
    {
        uint8_t key[FC_WIDE_KEY_LEN], val[FC_WIDE_VALUE_MAX];
        const size_t klen = fc_wide_key_at(w, start + i, key);
        const size_t vlen = fc_gen_value(w, val, sizeof(val));
        FC_CHECK(tidesdb_txn_put(txn, w->cf, key, klen, val, vlen, -1) == TDB_SUCCESS,
                 "wide put w%d", w->id);
        FC_CHECK(fuzz_model_put(w->model, FC_CF, key, klen, val, vlen, FUZZ_TTL_NONE),
                 "model wide put w%d", w->id);
    }
}

/* delete every key under the worker's prefix plus one character, in the transaction and the model;
 * at snapshot isolation and above this holds an interval rather than keys */
static void fc_do_delete_prefix(fc_worker_t *w, tidesdb_txn_t *txn)
{
    uint8_t prefix[2];
    prefix[0] = (uint8_t)('a' + w->id);
    prefix[1] = (uint8_t)('a' + (fc_rng(&w->rng) % FC_KEY_ALPHABET));
    FC_CHECK(tidesdb_txn_delete_prefix(txn, w->cf, prefix, sizeof(prefix)) == TDB_SUCCESS,
             "txn delete prefix w%d", w->id);
    FC_CHECK(fuzz_model_delete_prefix(w->model, FC_CF, prefix, sizeof(prefix)),
             "model delete prefix w%d", w->id);
}

/* open the worker's transaction at its isolation level, in the engine and the model */
static void fc_begin(fc_worker_t *w, tidesdb_txn_t **txn)
{
    FC_CHECK(tidesdb_txn_begin_with_isolation(w->db, w->isolation, txn) == TDB_SUCCESS,
             "begin w%d isolation %d", w->id, (int)w->isolation);
    fuzz_model_txn_begin(w->model);
}

/* commit the worker's transaction in the engine and the model. no worker shares a key with another,
 * so a conflict here has no writer behind it and is a fault whatever the isolation level */
static void fc_commit(fc_worker_t *w, tidesdb_txn_t **txn)
{
    const int rc = tidesdb_txn_commit(*txn);
    FC_CHECK(rc == TDB_SUCCESS, "commit w%d isolation %d rc %d, disjoint keys never conflict",
             w->id, (int)w->isolation, rc);
    fuzz_model_txn_commit(w->model);
    tidesdb_txn_free(*txn);
    *txn = NULL;
}

/* one worker thread: drive a deterministic operation stream against the shared database, keeping
 * the private model in lockstep and checking every read as it goes */
static void *fc_worker(void *arg)
{
    fc_worker_t *w = (fc_worker_t *)arg;
    tidesdb_txn_t *txn = NULL;
    for (int i = 0; i < w->nops; i++)
    {
        const uint64_t op = fc_rng(&w->rng) % 16;
        if (op <= 5) /* put */
        {
            if (!txn) fc_begin(w, &txn);
            fc_do_put(w, txn);
        }
        else if (op <= 8) /* delete */
        {
            if (!txn) fc_begin(w, &txn);
            fc_do_delete(w, txn);
        }
        else if (op <= 11) /* get, read-your-writes when a txn is open */
        {
            fc_check_get(w, txn);
        }
        else if (op == 12) /* commit */
        {
            if (txn) fc_commit(w, &txn);
        }
        else if (op == 14) /* a wide batch committed at once, the shape of a bulk load */
        {
            if (fc_rng(&w->rng) % FC_WIDE_ONE_IN == 0)
            {
                if (!txn) fc_begin(w, &txn);
                fc_do_wide_put(w, txn);
                fc_commit(w, &txn);
            }
        }
        else if (op == 15 && txn) /* now and then, an interval delete inside the own slice */
        {
            if (fc_rng(&w->rng) % FC_PREFIX_DELETE_ONE_IN == 0) fc_do_delete_prefix(w, txn);
        }
        else if (op == 13) /* rollback */
        {
            if (txn)
            {
                (void)tidesdb_txn_rollback(txn);
                fuzz_model_txn_rollback(w->model);
                tidesdb_txn_free(txn);
                txn = NULL;
            }
        }
        else if (!txn) /* iterate only against committed state, so no open txn */
        {
            fc_check_iter(w);
        }
    }
    if (txn)
    {
        (void)tidesdb_txn_rollback(txn);
        fuzz_model_txn_rollback(w->model);
        tidesdb_txn_free(txn);
    }
    return NULL;
}

/* after the workers join, check the committed set once more from the main thread: every model key
 * reads back with its value, and the whole-cf scan holds only keys some worker committed, catching
 * a race that left a phantom or lost a committed key */
static void fc_verify_final(fc_worker_t *workers, int n, tidesdb_t *db, tidesdb_column_family_t *cf)
{
    tidesdb_txn_t *t = NULL;
    FC_CHECK(tidesdb_txn_begin(db, &t) == TDB_SUCCESS, "final txn begin");

    for (int w = 0; w < n; w++)
    {
        fuzz_model_kv_t *mk = NULL;
        size_t mn = 0;
        FC_CHECK(fuzz_model_scan(workers[w].model, FC_CF, &mk, &mn), "final model scan");
        for (size_t i = 0; i < mn; i++)
        {
            uint8_t *dv = NULL;
            size_t dvl = 0;
            FC_CHECK(fc_db_get(t, cf, mk[i].key, mk[i].klen, &dv, &dvl),
                     "final lost key w%d key=%.*s", w, (int)mk[i].klen, (const char *)mk[i].key);
            FC_CHECK(fuzz_value_eq(dv, dvl, mk[i].val, mk[i].vlen),
                     "final value w%d key=%.*s model_vlen=%zu model_v0=%u db_vlen=%zu db_v0=%u", w,
                     (int)mk[i].klen, (const char *)mk[i].key, mk[i].vlen,
                     mk[i].vlen ? mk[i].val[0] : 0u, dvl, dvl ? dv[0] : 0u);
            free(dv);
        }
        free(mk);
    }

    tidesdb_iter_t *it = NULL;
    FC_CHECK(tidesdb_iter_new(t, cf, &it) == TDB_SUCCESS, "final iter");
    (void)tidesdb_iter_seek_to_first(it);
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        FC_CHECK(tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS, "final iter read");
        const int owner = kl > 0 ? (int)k[0] - 'a' : -1;
        FC_CHECK(owner >= 0 && owner < n, "final phantom key owner=%d", owner);
        const uint8_t *mv = NULL;
        size_t mvl = 0;
        FC_CHECK(fuzz_model_get(workers[owner].model, FC_CF, k, kl, &mv, &mvl),
                 "final phantom key");
        FC_CHECK(fuzz_value_eq(v, vl, mv, mvl), "final phantom value w%d", owner);
        free(k);
        free(v);
        (void)tidesdb_iter_next(it);
    }
    tidesdb_iter_free(it);
    (void)tidesdb_txn_commit(t);
    tidesdb_txn_free(t);
}

/* run one concurrency scenario end to end from a seed, aborting through FC_CHECK on any oracle
 * failure */
static void fc_run(uint64_t seed, const char *dir)
{
    (void)remove_directory(dir);
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = (char *)dir;
    cfg.memtable_write_buffer_size = FC_WRITE_BUFFER;
    cfg.memtable_sync_mode = TDB_SYNC_NONE;
    tidesdb_t *db = NULL;
    FC_CHECK(tidesdb_open(&cfg, &db) == TDB_SUCCESS, "open");
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    FC_CHECK(tidesdb_create_column_family(db, FC_CF, &cc) == TDB_SUCCESS, "create cf");
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, FC_CF);

    fc_worker_t workers[FC_WORKERS];
    pthread_t threads[FC_WORKERS];
    for (int i = 0; i < FC_WORKERS; i++)
    {
        workers[i].db = db;
        workers[i].cf = cf;
        workers[i].model = fuzz_model_create();
        FC_CHECK(workers[i].model && fuzz_model_cf_create(workers[i].model, FC_CF), "model init");
        workers[i].rng = seed ^ (0x9e3779b97f4a7c15ULL * (uint64_t)(i + 1));
        if (workers[i].rng == 0) workers[i].rng = 1;
        workers[i].tag = 0;
        workers[i].id = i;
        workers[i].nops = FC_OPS_PER_WORKER;
        workers[i].isolation = fc_isolations[i % FC_ISOLATION_COUNT];
    }

    for (int i = 0; i < FC_WORKERS; i++)
        FC_CHECK(pthread_create(&threads[i], NULL, fc_worker, &workers[i]) == 0, "thread create");
    for (int i = 0; i < FC_WORKERS; i++) pthread_join(threads[i], NULL);

    fc_verify_final(workers, FC_WORKERS, db, cf);

    for (int i = 0; i < FC_WORKERS; i++) fuzz_model_free(workers[i].model);
    (void)tidesdb_close(db);
    (void)remove_directory(dir);
}

int main(void)
{
    const char *base = getenv("TIDESDB_FUZZ_DIR");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s%sconcdb", base ? base : ".", PATH_SEPARATOR);

    const char *iters_env = getenv("TIDESDB_FUZZ_ITERS");
    const long iters = iters_env ? strtol(iters_env, NULL, 10) : FC_STANDALONE_ITERS;
    const char *seed_env = getenv("TIDESDB_FUZZ_SEED");
    uint64_t state = seed_env ? (uint64_t)strtoull(seed_env, NULL, 10) : 0x243f6a8885a308d3ULL;
    if (state == 0) state = 0x243f6a8885a308d3ULL;

    /* one iteration by its own seed, the one a failure names, so a failing run is cut down to the
     * scenario that failed rather than replayed from the start */
    const char *only_env = getenv("TIDESDB_FUZZ_ONLY_SEED");
    if (only_env)
    {
        fc_iteration = 0;
        fc_iteration_seed = (uint64_t)strtoull(only_env, NULL, 10);
        fc_run(fc_iteration_seed, dir);
        fprintf(stderr, "conc fuzz: iteration seed %llu passed\n",
                (unsigned long long)fc_iteration_seed);
        return 0;
    }

    for (long it = 0; it < iters; it++)
    {
        fc_iteration = it;
        fc_iteration_seed = fc_rng(&state);
        fc_run(fc_iteration_seed, dir);
    }
    fprintf(stderr, "conc fuzz: %ld iterations passed\n", iters);
    return 0;
}
