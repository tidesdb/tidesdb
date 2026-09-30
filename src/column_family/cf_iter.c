/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "cf_iter.h"

#include <stdlib.h>

#include "base/encoding/serialization.h"   /* tdb_build_prefixed_key, TDB_CF_PREFIX_SIZE */
#include "base/errors.h"                   /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "column_family/level/level_set.h" /* level_set_collect_all, level_set_overlapping */
#include "iter/merge_iter.h"
#include "iter/merge_sources.h"

/* extra slots when sizing the pin array, absorbing a concurrent rotation between the depth query
 * and the pin */
#define CF_ITER_SLACK 8

/* a bound on retries when a concurrent rotation or compaction keeps changing the source set out
 * from under the sizing query, so a pathological churn cannot spin forever */
#define CF_ITER_MAX_RETRY 8

/* every scan built here reads through the block cache. the bulk readers that deliberately bypass
 * it -- compaction -- assemble their sstable iterators directly rather than coming through here */
#define CF_ITER_USE_CACHE 1

struct cf_iter
{
    cf_t *cf;
    uint64_t snapshot;
    tidesdb_l0_t *l0;
    tidesdb_memtable_t **mts; /* pinned memtables */
    int n_mts;
    skip_list_cursor_t **cursors;   /* one per memtable */
    memtable_merge_source_t *views; /* one per memtable */
    sstable_t **ssts; /* referenced sstables, level by level, deep levels in key order */
    int *levels;      /* the level of each sstable, parallel to ssts */
    int n_ssts;
    sstable_iter_t **iters;          /* one per sstable */
    level_merge_source_t *runs;      /* one per level below L1 read as a single source */
    writeset_merge_source_t *ws_src; /* optional read-your-own-writes overlay, owned, freed here */
    merge_source_t
        *sources; /* ws overlay, then n_mts memtables, then L1 sstables and deeper levels */
    merge_iter_t *merge;
};

/* pin the L0 memtables into the iterator, growing the array if a rotation raced the sizing query */
static int cf_iter_pin_mts(cf_iter_t *it, tidesdb_l0_t *l0)
{
    int cap = 1 + (int)tidesdb_l0_queue_depth(l0) + CF_ITER_SLACK;
    for (int tries = 0; tries < CF_ITER_MAX_RETRY; tries++)
    {
        tidesdb_memtable_t **mts = malloc((size_t)cap * sizeof(*mts));
        if (!mts) return TDB_ERR_MEMORY;
        int n = 0;
        const int rc = tidesdb_l0_pin_memtables(l0, mts, cap, &n);
        if (rc == TDB_SUCCESS)
        {
            it->mts = mts;
            it->n_mts = n;
            return TDB_SUCCESS;
        }
        free(mts);
        if (rc != TDB_ERR_TOO_LARGE) return rc;
        cap = n + CF_ITER_SLACK; /* n is the needed count */
    }
    return TDB_ERR_BUSY;
}

/* reference the sstables of one level whose key range meets the bounds, appending them to the
 * iterator's array; returns the number appended, or a negative error. a level holding more
 * overlaps than the room left is reported as busy rather than silently truncated, since a missing
 * source is a key the scan never sees.
 *
 * the room left in the caller's array is the bound, not a fresh count of the level. asking the
 * level how many it holds would enter and exit the reader epoch a second time -- on a counter every
 * reader of this family shares, under a full barrier -- to learn a number the caller's own array
 * already limits. it also left a window: the count and the collect were separate layout loads, so a
 * flush landing between them made the collected set a subset of what the count had promised */
static int cf_iter_collect_level_in_range(cf_iter_t *it, cf_t *cf, int level,
                                          const cf_iter_bounds_t *bounds, int at, int room)
{
    if (room <= 0) return TDB_ERR_BUSY; /* nothing left to collect into; the caller re-sizes */

    sstable_t **slot = &it->ssts[at];
    const int got = level_set_overlapping(cf->levels, level, bounds->lower, bounds->lower_size,
                                          bounds->upper, bounds->upper_size, slot, room);
    if (got < 0) return TDB_ERR_BUSY;
    if (got > room)
    {
        /* the stored prefix was referenced and is ours to drop before reporting the growth */
        for (int i = 0; i < room; i++)
            if (sstable_unref(slot[i])) sstable_close(slot[i]);
        return TDB_ERR_BUSY;
    }
    return got;
}

/* reference only the sstables that could hold a key in the bounds, across every level */
static int cf_iter_collect_ssts_in_range(cf_iter_t *it, cf_t *cf, const cf_iter_bounds_t *bounds)
{
    for (int tries = 0; tries < CF_ITER_MAX_RETRY; tries++)
    {
        /* the whole family bounds how many can overlap, so one sizing covers every level */
        const int cap = level_set_collect_all(cf->levels, NULL, 0);
        if (cap <= 0)
        {
            it->ssts = NULL;
            it->n_ssts = 0;
            return TDB_SUCCESS;
        }
        sstable_t **arr = malloc((size_t)cap * sizeof(*arr));
        int *levels = malloc((size_t)cap * sizeof(*levels));
        if (!arr || !levels)
        {
            free(arr);
            free(levels);
            return TDB_ERR_MEMORY;
        }

        it->ssts = arr;
        int n = 0, rc = TDB_SUCCESS;
        for (int level = LEVEL_SET_L1; level <= LEVEL_SET_MAX_LEVELS && rc == TDB_SUCCESS; level++)
        {
            if (n >= cap) break; /* the family grew past the sizing; the retry below re-sizes */
            const int got = cf_iter_collect_level_in_range(it, cf, level, bounds, n, cap - n);
            if (got < 0)
                rc = got;
            else
                for (int i = 0; i < got; i++) levels[n++] = level;
        }
        if (rc == TDB_SUCCESS)
        {
            it->levels = levels;
            it->n_ssts = n;
            return TDB_SUCCESS;
        }

        for (int i = 0; i < n; i++)
            if (sstable_unref(it->ssts[i])) sstable_close(it->ssts[i]);
        free(arr);
        free(levels);
        it->ssts = NULL;
        it->n_ssts = 0;
        if (rc != TDB_ERR_BUSY) return rc;
    }
    return TDB_ERR_BUSY;
}

/* reference the column family's sstables into the iterator with the level of each, from one layout,
 * growing the arrays if a compaction raced the sizing */
static int cf_iter_collect_ssts(cf_iter_t *it, cf_t *cf)
{
    int total = level_set_snapshot(cf->levels, NULL, 0);
    for (int tries = 0; tries < CF_ITER_MAX_RETRY; tries++)
    {
        if (total <= 0)
        {
            it->ssts = NULL;
            it->n_ssts = 0;
            return TDB_SUCCESS;
        }
        level_set_snapshot_entry_t *entries = calloc((size_t)total, sizeof(*entries));
        if (!entries) return TDB_ERR_MEMORY;
        const int got = level_set_snapshot(cf->levels, entries, total);
        if (got > total)
        {
            free(entries); /* the set grew and nothing was referenced; size up and retry */
            total = got;
            continue;
        }
        sstable_t **arr = malloc((size_t)(got > 0 ? got : 1) * sizeof(*arr));
        int *levels = malloc((size_t)(got > 0 ? got : 1) * sizeof(*levels));
        if (!arr || !levels)
        {
            for (int i = 0; i < got; i++)
                if (sstable_unref(entries[i].sst)) sstable_close(entries[i].sst);
            free(entries);
            free(arr);
            free(levels);
            return TDB_ERR_MEMORY;
        }
        for (int i = 0; i < got; i++)
        {
            arr[i] = entries[i].sst;
            levels[i] = entries[i].level;
        }
        free(entries);
        it->ssts = arr;
        it->levels = levels;
        it->n_ssts = got;
        return TDB_SUCCESS;
    }
    return TDB_ERR_BUSY;
}

/* the sources the sstables make: each L1 table one of its own, since L1 tables overlap, and each
 * deeper level one for its whole run when it holds more than one table, so a seek descends only the
 * table that can hold the key. returns the number of sources written, or -1 on allocation failure
 */
static int cf_iter_table_sources(cf_iter_t *it, merge_source_t *out)
{
    if (it->n_ssts > 0)
    {
        it->runs = calloc((size_t)it->n_ssts, sizeof(*it->runs));
        if (!it->runs) return -1;
    }
    int n = 0, runs = 0;
    for (int i = 0; i < it->n_ssts;)
    {
        int end = i + 1;
        if (it->levels[i] > LEVEL_SET_L1)
            while (end < it->n_ssts && it->levels[end] == it->levels[i]) end++;
        if (end - i > 1)
            level_merge_source(&it->runs[runs++], &it->ssts[i], &it->iters[i], end - i, &out[n++]);
        else
            sstable_merge_source(it->iters[i], &out[n++]);
        i = end;
    }
    return n;
}

static int cf_iter_build(cf_iter_t *it, cf_t *cf, uint64_t snapshot)
{
    const int ws_off = it->ws_src ? 1 : 0;
    const int n = ws_off + it->n_mts + it->n_ssts;
    if (it->n_mts > 0)
    {
        it->cursors = calloc((size_t)it->n_mts, sizeof(*it->cursors));
        it->views = calloc((size_t)it->n_mts, sizeof(*it->views));
        if (!it->cursors || !it->views) return TDB_ERR_MEMORY;
    }
    if (it->n_ssts > 0)
    {
        it->iters = calloc((size_t)it->n_ssts, sizeof(*it->iters));
        if (!it->iters) return TDB_ERR_MEMORY;
    }
    it->sources = calloc((size_t)(n > 0 ? n : 1), sizeof(*it->sources));
    if (!it->sources) return TDB_ERR_MEMORY;

    if (it->ws_src) writeset_merge_source(it->ws_src, &it->sources[0]);

    for (int i = 0; i < it->n_mts; i++)
    {
        /* the cursor allocates and reads three atomics, so the only way it fails is allocation */
        if (skip_list_cursor_init(&it->cursors[i], it->mts[i]->skip_list) != 0)
            return TDB_ERR_MEMORY;
        memtable_merge_source_init(&it->views[i], it->cursors[i], it->l0, it->mts[i],
                                   (uint32_t)cf->cf_id, snapshot);
        memtable_merge_source(&it->views[i], &it->sources[ws_off + i]);
    }
    for (int i = 0; i < it->n_ssts; i++)
    {
        /* carry the sstable's own result out rather than calling every failure an i/o error. it
         * reports a reader budget it cannot honour as busy, which is retryable back pressure and
         * nothing like a read that failed, and a caller told i/o has no way to tell the two apart
         */
        const int rc = sstable_iter_new(it->ssts[i], CF_ITER_USE_CACHE, &it->iters[i]);
        if (rc != TDB_SUCCESS) return rc;
    }
    const int tables = cf_iter_table_sources(it, &it->sources[ws_off + it->n_mts]);
    if (tables < 0) return TDB_ERR_MEMORY;
    return merge_iter_new(it->sources, ws_off + it->n_mts + tables, snapshot, MERGE_ITER_RESOLVE,
                          &it->merge);
}

int cf_iter_new(cf_t *cf, tidesdb_l0_t *l0, uint64_t snapshot, writeset_merge_source_t *ws_src,
                cf_iter_t **out)
{
    return cf_iter_new_bounded(cf, l0, snapshot, ws_src, NULL, out);
}

int cf_iter_new_bounded(cf_t *cf, tidesdb_l0_t *l0, uint64_t snapshot,
                        writeset_merge_source_t *ws_src, const cf_iter_bounds_t *bounds,
                        cf_iter_t **out)
{
    if (!cf || !l0 || !out)
    {
        writeset_merge_source_free(ws_src);
        return TDB_ERR_INVALID_ARGS;
    }

    cf_iter_t *it = calloc(1, sizeof(*it));
    if (!it)
    {
        writeset_merge_source_free(ws_src);
        return TDB_ERR_MEMORY;
    }
    it->cf = cf;
    it->snapshot = snapshot;
    it->l0 = l0;
    it->ws_src = ws_src; /* owned now, freed by cf_iter_free even on the error path below */

    int rc = cf_iter_pin_mts(it, l0);
    /* both ends are needed to bound the selection; with either missing there is no range to test
     * an sstable against and every one of them stays a candidate */
    const int pruned = bounds && bounds->lower && bounds->upper;
    if (rc == TDB_SUCCESS)
        rc = pruned ? cf_iter_collect_ssts_in_range(it, cf, bounds) : cf_iter_collect_ssts(it, cf);
    if (rc == TDB_SUCCESS) rc = cf_iter_build(it, cf, snapshot);
    if (rc != TDB_SUCCESS)
    {
        cf_iter_free(it);
        return rc;
    }
    *out = it;
    return TDB_SUCCESS;
}

void cf_iter_free(cf_iter_t *it)
{
    if (!it) return;
    merge_iter_free(it->merge);
    if (it->cursors)
        for (int i = 0; i < it->n_mts; i++) skip_list_cursor_free(it->cursors[i]);
    if (it->iters)
        for (int i = 0; i < it->n_ssts; i++) sstable_iter_free(it->iters[i]);
    if (it->mts) tidesdb_l0_unpin_memtables(it->mts, it->n_mts);
    if (it->ssts)
        for (int i = 0; i < it->n_ssts; i++)
            if (sstable_unref(it->ssts[i])) sstable_close(it->ssts[i]);
    writeset_merge_source_free(it->ws_src);
    free(it->sources);
    free(it->views);
    free(it->cursors);
    free(it->iters);
    free(it->runs);
    free(it->mts);
    free(it->ssts);
    free(it->levels);
    free(it);
}

/* every positioning call filters before it returns, so a caller that only ever asks whether the
 * iterator is valid and reads it never sees a key a range tombstone deleted */
int cf_iter_seek_first(cf_iter_t *it)
{
    const int rc = merge_iter_seek_first(it->merge);
    return rc;
}
int cf_iter_seek_last(cf_iter_t *it)
{
    const int rc = merge_iter_seek_last(it->merge);
    return rc;
}
int cf_iter_seek(cf_iter_t *it, const uint8_t *key, size_t key_size)
{
    const int rc = merge_iter_seek(it->merge, key, key_size);
    return rc;
}
int cf_iter_seek_for_prev(cf_iter_t *it, const uint8_t *key, size_t key_size)
{
    const int rc = merge_iter_seek_for_prev(it->merge, key, key_size);
    return rc;
}
int cf_iter_next(cf_iter_t *it)
{
    const int rc = merge_iter_next(it->merge);
    return rc;
}
int cf_iter_prev(cf_iter_t *it)
{
    const int rc = merge_iter_prev(it->merge);
    return rc;
}
int cf_iter_valid(const cf_iter_t *it)
{
    return it && merge_iter_valid(it->merge);
}

int cf_iter_get(cf_iter_t *it, const uint8_t **key, size_t *key_size, uint64_t *seq,
                const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                uint8_t *deleted)
{
    return merge_iter_get(it->merge, key, key_size, seq, value, value_size, vlog_offset, ttl,
                          deleted);
}
