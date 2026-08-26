/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_internal.h"
#include "compat.h"

/* what a worker thread actually does: the key-selection helpers every workload draws through, the
 * workload bodies themselves, and the table naming them. the driver reaches this file only through
 * bench_find_workload */

static uint64_t bench_rng(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

/* the next key index this thread should touch, per the configured distribution */
static uint64_t bench_next_index(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    switch (c->dist)
    {
        case BENCH_DIST_SEQUENTIAL:
            return atomic_fetch_add_explicit(t->seq, 1, memory_order_relaxed) % c->num;
        case BENCH_DIST_ZIPFIAN:
            return bench_zipf_next(t->zipf,
                                   (double)(bench_rng(&t->rng) >> 11) / 9007199254740992.0);
        case BENCH_DIST_UNIFORM:
        default:
            return bench_rng(&t->rng) % c->num;
    }
}

/* format key index into buf as BENCH_KEY_PREFIX_BYTES big-endian bytes then zero padding, so
 * sequential indices sort and every key is exactly cfg->key_size bytes */
static void bench_make_key(const bench_config_t *c, uint64_t index, uint8_t *buf)
{
    /* the configuration is validated once at startup, but the bound is restated here so the write
     * is provably inside the caller's BENCH_MAX_KEY buffer at every call site */
    const size_t size =
        (size_t)(c->key_size > 0 && c->key_size <= BENCH_MAX_KEY ? c->key_size : BENCH_MAX_KEY);
    memset(buf, 0, size);
    const int n = c->key_size < BENCH_KEY_PREFIX_BYTES ? c->key_size : BENCH_KEY_PREFIX_BYTES;
    for (int i = 0; i < n; i++) buf[i] = (uint8_t)(index >> ((n - 1 - i) * 8));
}

/* fill val with a index-derived byte pattern so no two keys share a value and a stale read shows */
static void bench_make_value(const bench_config_t *c, uint64_t index, uint8_t *val)
{
    for (int i = 0; i < c->value_size; i++) val[i] = (uint8_t)(index + (uint64_t)i);
}

/* the column family an index maps to, round-robined so multi-cf runs spread evenly */
static tidesdb_column_family_t *bench_cf_for(bench_thread_t *t, uint64_t index)
{
    return t->cfs[t->cfg->n_cfs > 1 ? (int)(index % (uint64_t)t->cfg->n_cfs) : 0];
}

/* ===== workloads ===== */

/* longest value the bench frames on the stack; value_size is validated against this at parse time
 */
#define BENCH_MAX_VALUE 65536

/* write one committed transaction of n_ops puts, measuring the whole transaction; the keys come
 * from allocate(t) so fillseq and fillrandom differ only in that allocator, and n_ops lets the
 * mixed workloads issue single-op writes without touching shared config */
/* attempt one batch, recording why it failed rather than collapsing every cause to one code. a
 * skipped batch never reaches the write histogram, so what shrank the sample has to be visible or
 * a maximum drawn from a fraction of the commits reads as though it covered all of them */
static int bench_write_batch(bench_thread_t *t, uint64_t (*allocate)(bench_thread_t *), int n_ops)
{
    const bench_config_t *c = t->cfg;
    bench_stall_enter();
    uint8_t key[BENCH_MAX_KEY];
    uint8_t val[BENCH_MAX_VALUE];
    tidesdb_txn_t *txn = NULL;
    int rc = tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn);
    for (int i = 0; rc == TDB_SUCCESS && i < n_ops; i++)
    {
        const uint64_t idx = allocate(t);
        bench_make_key(c, idx, key);
        bench_make_value(c, idx, val);
        rc = tidesdb_txn_put(txn, bench_cf_for(t, idx), key, (size_t)c->key_size, val,
                             (size_t)c->value_size, -1);
    }
    if (rc == TDB_SUCCESS) rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);
    bench_stall_leave();

    if (rc == TDB_SUCCESS) return n_ops;
    if (rc == TDB_ERR_CONFLICT)
    {
        t->my_conflicts++;
    }
    else
    {
        t->my_write_errors++;
        const int slot = -rc;
        if (slot > 0 && slot < BENCH_ERR_TALLY_LEN) t->my_err_tally[slot]++;
    }
    return -1;
}

static uint64_t bench_alloc_seq(bench_thread_t *t)
{
    return atomic_fetch_add_explicit(t->seq, 1, memory_order_relaxed) % t->cfg->num;
}
static uint64_t bench_alloc_rand(bench_thread_t *t)
{
    return bench_next_index(t);
}

/* write this thread's even share of cfg->num keys, so the fill terminates deterministically; the
 * allocator decides the key values (a shared counter for fillseq, random for fillrandom) */
static void bench_run_fill(bench_thread_t *t, uint64_t (*allocate)(bench_thread_t *))
{
    const uint64_t per_thread = t->cfg->num / (uint64_t)t->cfg->threads + 1;
    for (uint64_t written = 0; bench_more(t, written, per_thread);
         written += (uint64_t)t->cfg->txn_ops)
    {
        struct timespec a;
        clock_gettime(CLOCK_MONOTONIC, &a);
        const int done = bench_write_batch(t, allocate, t->cfg->txn_ops);
        struct timespec b;
        clock_gettime(CLOCK_MONOTONIC, &b);
        /* a failed commit is an expected write-write conflict under a random allocator at snapshot
         * isolation, so skip the batch and keep filling rather than abandoning the thread's share
         */
        if (done < 0) continue;
        const uint64_t ns =
            (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec));
        bench_hist_record(&t->write_hist, ns);
        t->my_ops += (uint64_t)done;
        atomic_fetch_add_explicit(t->ops_done, (uint64_t)done, memory_order_relaxed);
    }
}

static void wl_fillseq(bench_thread_t *t)
{
    bench_run_fill(t, bench_alloc_seq);
}
static void wl_fillrandom(bench_thread_t *t)
{
    bench_run_fill(t, bench_alloc_rand);
}

/* read one key, offset added to the index so readmissing (offset = num) always misses */
static void bench_read_once(bench_thread_t *t, uint64_t offset)
{
    const bench_config_t *c = t->cfg;
    const uint64_t idx = bench_next_index(t) + offset;
    uint8_t key[BENCH_MAX_KEY];
    bench_make_key(c, idx, key);
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS) return;
    uint8_t *v = NULL;
    size_t vl = 0;
    const int rc = tidesdb_txn_get(txn, bench_cf_for(t, idx), key, (size_t)c->key_size, &v, &vl);
    if (rc == TDB_SUCCESS) tidesdb_free(v);
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    bench_hist_record(&t->read_hist,
                      (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)));
    t->my_ops++;
    atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
}

/* run a fixed number of reads per thread so read-only benchmarks terminate */
static void bench_run_reads(bench_thread_t *t, uint64_t offset)
{
    const uint64_t per_thread = t->cfg->num / (uint64_t)t->cfg->threads + 1;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++) bench_read_once(t, offset);
}

static void wl_readrandom(bench_thread_t *t)
{
    bench_run_reads(t, 0);
}
static void wl_readmissing(bench_thread_t *t)
{
    bench_run_reads(t, t->cfg->num);
}

/* one delete transaction of n_ops deletes, measured whole */
static void bench_delete_txn(bench_thread_t *t, int n_ops)
{
    const bench_config_t *c = t->cfg;
    uint8_t key[BENCH_MAX_KEY];
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS) return;
    int did = 0;
    for (int i = 0; i < n_ops; i++)
    {
        const uint64_t idx = bench_next_index(t);
        bench_make_key(c, idx, key);
        if (tidesdb_txn_delete(txn, bench_cf_for(t, idx), key, (size_t)c->key_size) == TDB_SUCCESS)
            did++;
    }
    if (tidesdb_txn_commit(txn) != TDB_SUCCESS) did = 0;
    tidesdb_txn_free(txn);
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    bench_hist_record(&t->write_hist,
                      (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)));
    t->my_ops += (uint64_t)did;
    atomic_fetch_add_explicit(t->ops_done, (uint64_t)(did > 0 ? did : 1), memory_order_relaxed);
}

static void wl_deleterandom(bench_thread_t *t)
{
    const uint64_t batches =
        t->cfg->num / (uint64_t)t->cfg->threads / (uint64_t)t->cfg->txn_ops + 1;
    for (uint64_t i = 0; bench_more(t, i, batches); i++) bench_delete_txn(t, t->cfg->txn_ops);
}

/* mixed read/write, each op a read with probability cfg->read_ratio else a single-put write */
static void wl_readwrite(bench_thread_t *t)
{
    const uint64_t per_thread = t->cfg->num / (uint64_t)t->cfg->threads + 1;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
    {
        if ((int)(bench_rng(&t->rng) % 100) < t->cfg->read_ratio)
        {
            bench_read_once(t, 0);
            continue;
        }
        struct timespec a;
        clock_gettime(CLOCK_MONOTONIC, &a);
        const int done = bench_write_batch(t, bench_alloc_rand, 1);
        struct timespec b;
        clock_gettime(CLOCK_MONOTONIC, &b);
        if (done > 0)
        {
            bench_hist_record(&t->write_hist, (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL +
                                                         (b.tv_nsec - a.tv_nsec)));
            t->my_ops++;
            atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
        }
    }
}

/* delete-heavy while reading -- reads at cfg->read_ratio, deletes otherwise, over the same keys */
static void wl_deletewhileread(bench_thread_t *t)
{
    const uint64_t per_thread = t->cfg->num / (uint64_t)t->cfg->threads + 1;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
    {
        if ((int)(bench_rng(&t->rng) % 100) < t->cfg->read_ratio)
            bench_read_once(t, 0);
        else
            bench_delete_txn(t, 1);
    }
}

/* range scan -- seek to a random start and iterate cfg->scan_length entries */
#define BENCH_SCANS_PER_THREAD 256 /* range-scan iterations each worker performs */

/* one scan from a random start. bounded tells the iterator the range it will read, so the merge is
 * built from the sstables that meet it rather than from every one the family holds; keys encode
 * their index big-endian, so the end of the run is the key scan_length past the start */
static void bench_scan_once(bench_thread_t *t, const int bounded)
{
    const bench_config_t *c = t->cfg;
    const uint64_t idx = bench_next_index(t);
    uint8_t key[BENCH_MAX_KEY], upper[BENCH_MAX_KEY];
    bench_make_key(c, idx, key);
    bench_make_key(c, idx + (uint64_t)c->scan_length, upper);

    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS) return;
    tidesdb_iter_t *it = NULL;
    const int opened =
        bounded ? tidesdb_iter_new_range(txn, bench_cf_for(t, idx), key, (size_t)c->key_size, upper,
                                         (size_t)c->key_size, &it)
                : tidesdb_iter_new(txn, bench_cf_for(t, idx), &it);
    if (opened == TDB_SUCCESS)
    {
        (void)tidesdb_iter_seek(it, key, (size_t)c->key_size);
        int seen = 0;
        while (seen < c->scan_length && tidesdb_iter_valid(it))
        {
            uint8_t *k = NULL, *v = NULL;
            size_t kl = 0, vl = 0;
            if (tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS)
            {
                tidesdb_free(k);
                tidesdb_free(v);
            }
            (void)tidesdb_iter_next(it);
            seen++;
        }
        tidesdb_iter_free(it);
        t->my_ops += (uint64_t)seen;
        atomic_fetch_add_explicit(t->ops_done, (uint64_t)seen, memory_order_relaxed);
    }
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    bench_hist_record(&t->read_hist,
                      (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)));
}

static void wl_scan(bench_thread_t *t)
{
    for (uint64_t s = 0; bench_more(t, s, BENCH_SCANS_PER_THREAD); s++) bench_scan_once(t, 0);
}

/* the same scan told its range up front, for measuring what the bound is worth */
static void wl_scanrange(bench_thread_t *t)
{
    for (uint64_t s = 0; bench_more(t, s, BENCH_SCANS_PER_THREAD); s++) bench_scan_once(t, 1);
}

/* the two tail bytes that place an empty probe range strictly between two adjacent written keys.
 * bench_make_key zeroes everything after the index prefix, so any non-zero tail names a key the
 * fill never writes, and 1 < 2 keeps the range non-empty as a range while holding no keys */
#define BENCH_EMPTY_PROBE_LO 0x01
#define BENCH_EMPTY_PROBE_HI 0x02

/* one bounded scan over a range holding no keys, measuring what it costs to prove a range empty.
 *
 * the range has to be *interior* to be worth measuring. a range past the last key is excluded by
 * every sstable's recorded key bounds before a block is read, which measures the pruning fast path
 * rather than the question. so the probe sits in the gap between two adjacent written keys, where
 * the bounds of every file spanning that point overlap it and none of them can be pruned -- the
 * scan must descend them all and find nothing, which is the cost a range filter would remove.
 *
 * an op here is one scan rather than one entry, since the answer is that there are no entries.
 * needs a key wider than the index prefix; without a tail there is no gap to sit in
 * @param t the worker */
static void bench_scan_empty_once(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    if (c->key_size <= BENCH_KEY_PREFIX_BYTES) return;
    const uint64_t idx = bench_next_index(t);
    uint8_t key[BENCH_MAX_KEY], upper[BENCH_MAX_KEY];
    bench_make_key(c, idx, key);
    bench_make_key(c, idx, upper);
    key[c->key_size - 1] = BENCH_EMPTY_PROBE_LO;
    upper[c->key_size - 1] = BENCH_EMPTY_PROBE_HI;

    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    bench_stall_enter();
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS)
    {
        bench_stall_leave();
        return;
    }
    tidesdb_iter_t *it = NULL;
    if (tidesdb_iter_new_range(txn, bench_cf_for(t, idx), key, (size_t)c->key_size, upper,
                               (size_t)c->key_size, &it) == TDB_SUCCESS)
    {
        /* a seek that finds nothing is the expected answer; anything found means the range was not
         * empty and the timing below is not measuring what this workload claims */
        (void)tidesdb_iter_seek(it, key, (size_t)c->key_size);
        tidesdb_iter_free(it);
    }
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    bench_stall_leave();
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    bench_hist_record(&t->read_hist,
                      (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)));
    t->my_ops++;
    atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
}

static void wl_scanempty(bench_thread_t *t)
{
    for (uint64_t s = 0; bench_more(t, s, BENCH_SCANS_PER_THREAD); s++) bench_scan_empty_once(t);
}

/* the two column families an index workload needs: rows in one, index entries in the other, which
 * is how the MariaDB plugin lays a table out -- the table's own family plus an `__idx_` family per
 * secondary index */
#define BENCH_INDEX_DATA_CF  0
#define BENCH_INDEX_INDEX_CF 1

/* an index entry's key is the indexed value followed by the primary key it points at, so entries
 * sharing a value sort together and a prefix seek finds the whole run. both halves are big-endian
 * so byte order is key order */
#define BENCH_INDEX_KEY_BYTES 16
#define BENCH_INDEX_PK_OFFSET 8

/* write the big-endian pair that makes up an index entry's key */
static void bench_make_index_key(uint64_t value, uint64_t pk, uint8_t *buf)
{
    for (int i = 0; i < BENCH_INDEX_PK_OFFSET; i++)
        buf[i] = (uint8_t)(value >> ((BENCH_INDEX_PK_OFFSET - 1 - i) * 8));
    for (int i = 0; i < BENCH_INDEX_PK_OFFSET; i++)
        buf[BENCH_INDEX_PK_OFFSET + i] = (uint8_t)(pk >> ((BENCH_INDEX_PK_OFFSET - 1 - i) * 8));
}

/* read the primary key back out of an index entry's key */
static uint64_t bench_index_key_pk(const uint8_t *key)
{
    uint64_t pk = 0;
    for (int i = 0; i < BENCH_INDEX_PK_OFFSET; i++) pk = (pk << 8) | key[BENCH_INDEX_PK_OFFSET + i];
    return pk;
}

/* one secondary-index lookup, in the shape the MariaDB plugin actually issues it.
 *
 * the plugin's index_read_secondary opens an iterator on the index family, and then for every entry
 * whose prefix matches it calls fetch_row_by_pk -- a point get on the *table's* family -- to
 * materialise the row. so a lookup returning n rows costs one iterator build plus n point gets in a
 * different family, not a scan that returns rows directly.
 *
 * modelling only the scan half, as this workload first did, leaves out where the time goes: each of
 * those point gets descends its own family's levels, and the two families have independent depths.
 * that is the ref-join shape, and it is the one a secondary-index plan drives per outer row
 *
 * an op is one lookup rather than one row, since the lookup is the unit being measured
 * @param t the worker */
static void bench_index_lookup_once(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    const uint64_t fanout = (uint64_t)c->index_fanout;
    /* pick an indexed value rather than a row, since the value is what a lookup is given */
    const uint64_t value = bench_next_index(t) / fanout;

    uint8_t lo[BENCH_INDEX_KEY_BYTES], hi[BENCH_INDEX_KEY_BYTES];
    bench_make_index_key(value, 0, lo);
    bench_make_index_key(value, UINT64_MAX, hi);

    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    bench_stall_enter();
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS)
    {
        bench_stall_leave();
        return;
    }

    tidesdb_column_family_t *data_cf = t->cfs[BENCH_INDEX_DATA_CF];
    tidesdb_column_family_t *index_cf = t->cfs[BENCH_INDEX_INDEX_CF];

    tidesdb_iter_t *it = NULL;
    if (tidesdb_iter_new_range(txn, index_cf, lo, sizeof(lo), hi, sizeof(hi), &it) == TDB_SUCCESS)
    {
        uint64_t seen = 0;
        for (tidesdb_iter_seek(it, lo, sizeof(lo)); seen < fanout && tidesdb_iter_valid(it);
             tidesdb_iter_next(it))
        {
            uint8_t *ik = NULL;
            size_t iks = 0;
            /* the key alone, not the value -- the plugin reads the pk out of the index key and the
             * entry carries nothing else it needs */
            if (tidesdb_iter_key(it, &ik, &iks) != TDB_SUCCESS) break;
            if (iks < BENCH_INDEX_KEY_BYTES)
            {
                tidesdb_free(ik);
                break;
            }
            const uint64_t pk = bench_index_key_pk(ik);
            tidesdb_free(ik);

            uint8_t dk[BENCH_MAX_KEY];
            bench_make_key(c, pk, dk);
            uint8_t *v = NULL;
            size_t vl = 0;
            if (tidesdb_txn_get(txn, data_cf, dk, (size_t)c->key_size, &v, &vl) == TDB_SUCCESS)
                tidesdb_free(v);
            seen++;
        }
        tidesdb_iter_free(it);
    }
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    bench_stall_leave();
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    bench_hist_record(&t->read_hist,
                      (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)));
    t->my_ops++;
    atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
}

/* write one row and the index entry that points at it, as a table with one secondary index does */
static void bench_index_fill_once(bench_thread_t *t, uint64_t pk)
{
    const bench_config_t *c = t->cfg;
    uint8_t dk[BENCH_MAX_KEY], ik[BENCH_INDEX_KEY_BYTES];
    bench_make_key(c, pk, dk);
    bench_make_index_key(pk / (uint64_t)c->index_fanout, pk, ik);

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) != TDB_SUCCESS) return;

    uint8_t *val = malloc((size_t)c->value_size);
    if (!val)
    {
        tidesdb_txn_free(txn);
        return;
    }
    bench_make_value(c, pk, val);

    /* both writes land in one transaction, as the plugin's row insert does -- the row and every
     * index entry pointing at it have to commit together or a lookup finds a pk with no row */
    int ok = tidesdb_txn_put(txn, t->cfs[BENCH_INDEX_DATA_CF], dk, (size_t)c->key_size, val,
                             (size_t)c->value_size, -1) == TDB_SUCCESS;
    /* a one-byte placeholder rather than an empty value, which is what the plugin stores -- the
     * index key already carries everything a lookup needs, and the engine's write path does not
     * accept a zero-length value */
    static const uint8_t index_entry_value = 0;
    ok = ok && tidesdb_txn_put(txn, t->cfs[BENCH_INDEX_INDEX_CF], ik, sizeof(ik),
                               &index_entry_value, sizeof(index_entry_value), -1) == TDB_SUCCESS;
    free(val);

    if (ok && tidesdb_txn_commit(txn) == TDB_SUCCESS)
    {
        t->my_ops++;
        atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
    }
    else
    {
        (void)tidesdb_txn_rollback(txn);
    }
    tidesdb_txn_free(txn);
}

/* build the table and its index together, so indexscan has both families to work against */
static void wl_fillindex(bench_thread_t *t)
{
    const uint64_t per_thread = t->cfg->num / (uint64_t)t->cfg->threads + 1;
    const uint64_t start = (uint64_t)t->id * per_thread;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
        bench_index_fill_once(t, (start + i) % t->cfg->num);
}

/* index lookups against a table that is being written at the same time.
 *
 * this exists because indexscan alone cannot reproduce what a live OLTP store looks like. a
 * read-only run lets compaction finish, and a finished store has an empty L1 and non-overlapping
 * runs below it, so a narrow lookup opens about one file per level however many files exist. a
 * store under continuous write load never reaches that state -- flushes keep L1 populated, and L1
 * is the tier whose files may overlap, so every lookup opens all of them.
 *
 * TPROC-C is this shape: new orders write while payments and order-status read through the customer
 * index, so the store is never quiet. --read_ratio splits the two
 * @param t the worker */
static void wl_indexmixed(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    const uint64_t per_thread = c->num / (uint64_t)c->threads + 1;
    const uint64_t start = (uint64_t)t->id * per_thread;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
    {
        if ((int)(bench_rng(&t->rng) % 100) < c->read_ratio)
            bench_index_lookup_once(t);
        else
            bench_index_fill_once(t, (start + i) % c->num);
    }
}

static void wl_indexscan(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    const uint64_t lookups = c->num / ((uint64_t)c->threads * (uint64_t)c->index_fanout) + 1;
    for (uint64_t s = 0; bench_more(t, s, lookups); s++) bench_index_lookup_once(t);
}

/* write one entry whose value is large enough to spill into the shared value log, so the write path
 * exercises the log and the read path has to resolve a reference out of it
 * @param t the worker
 * @param idx the key index to write
 * @return 1 when the commit landed, 0 otherwise
 */
static int bench_write_large(bench_thread_t *t, uint64_t idx)
{
    const bench_config_t *c = t->cfg;
    int size = c->large_value_size;
    if (size < 1) size = 1;
    if (size > BENCH_MAX_VALUE) size = BENCH_MAX_VALUE;

    uint8_t key[BENCH_MAX_KEY];
    uint8_t *val = malloc((size_t)size);
    if (!val) return 0;
    bench_make_key(c, idx, key);
    for (int i = 0; i < size; i++) val[i] = (uint8_t)(idx + (uint64_t)i);

    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    tidesdb_txn_t *txn = NULL;
    int done = 0;
    if (tidesdb_txn_begin_with_isolation(t->db, c->isolation, &txn) == TDB_SUCCESS)
    {
        if (tidesdb_txn_put(txn, bench_cf_for(t, idx), key, (size_t)c->key_size, val, (size_t)size,
                            -1) == TDB_SUCCESS &&
            tidesdb_txn_commit(txn) == TDB_SUCCESS)
            done = 1;
        tidesdb_txn_free(txn);
    }
    free(val);
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    if (done)
    {
        bench_hist_record(&t->write_hist, (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL +
                                                     (b.tv_nsec - a.tv_nsec)));
        t->my_ops++;
        atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
    }
    return done;
}

/* reads and writes mixed as readwrite does, except a share of the writes carry a value large enough
 * to spill. both storage paths are then live at once, so the value log's reclaim runs alongside the
 * ordinary compaction cycle rather than in isolation -- which is where the two interfere, since a
 * reclaim rewrites live values while merges are rewriting the keys that point at them */
static void wl_mixedlarge(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    const uint64_t per_thread = c->num / (uint64_t)c->threads + 1;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
    {
        if ((int)(bench_rng(&t->rng) % 100) < c->read_ratio)
        {
            bench_read_once(t, 0);
            continue;
        }
        if ((int)(bench_rng(&t->rng) % 100) < c->large_ratio)
        {
            (void)bench_write_large(t, bench_alloc_rand(t));
            continue;
        }
        struct timespec a;
        clock_gettime(CLOCK_MONOTONIC, &a);
        const int done = bench_write_batch(t, bench_alloc_rand, 1);
        struct timespec b;
        clock_gettime(CLOCK_MONOTONIC, &b);
        if (done > 0)
        {
            bench_hist_record(&t->write_hist, (uint64_t)((b.tv_sec - a.tv_sec) * 1000000000LL +
                                                         (b.tv_nsec - a.tv_nsec)));
            t->my_ops++;
            atomic_fetch_add_explicit(t->ops_done, 1, memory_order_relaxed);
        }
    }
}

/* deletes racing reads over spilled values. each writer lands a large value and then deletes it, so
 * the value log accumulates garbage at a known rate while readers are resolving references out of
 * it -- the shape that shows whether a reclaim interferes with reads, and whether the tombstones it
 * leaves behind change what compaction has to do */
static void wl_deletewhilereadlarge(bench_thread_t *t)
{
    const bench_config_t *c = t->cfg;
    const uint64_t per_thread = c->num / (uint64_t)c->threads + 1;
    for (uint64_t i = 0; bench_more(t, i, per_thread); i++)
    {
        if ((int)(bench_rng(&t->rng) % 100) < c->read_ratio)
        {
            bench_read_once(t, 0);
            continue;
        }
        /* written then deleted, so the garbage is this workload's own doing rather than a property
         * of however the database happened to be filled */
        const uint64_t idx = bench_next_index(t);
        if (bench_write_large(t, idx)) bench_delete_txn(t, 1);
    }
}

static const bench_workload_t BENCH_WORKLOADS[] = {
    {"fillseq", wl_fillseq},
    {"fillrandom", wl_fillrandom},
    {"readrandom", wl_readrandom},
    {"readmissing", wl_readmissing},
    {"readwrite", wl_readwrite},
    {"deleterandom", wl_deleterandom},
    {"deletewhileread", wl_deletewhileread},
    {"scan", wl_scan},
    {"scanrange", wl_scanrange},
    {"scanempty", wl_scanempty},
    {"fillindex", wl_fillindex},
    {"indexscan", wl_indexscan},
    {"indexmixed", wl_indexmixed},
    {"mixedlarge", wl_mixedlarge},
    {"deletewhilereadlarge", wl_deletewhilereadlarge},
};

const bench_workload_t *bench_find_workload(const char *name)
{
    for (size_t i = 0; i < sizeof(BENCH_WORKLOADS) / sizeof(BENCH_WORKLOADS[0]); i++)
        if (strcmp(BENCH_WORKLOADS[i].name, name) == 0) return &BENCH_WORKLOADS[i];
    return NULL;
}
