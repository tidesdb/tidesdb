/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "merge_sources.h"

/* a level below L1 is a run of sstables sorted by key with no two overlapping, so a key can live in
 * at most one of them. this source stands for the whole run and keeps one of its cursors positioned
 * at a time: a seek binary-searches the run for the one table that can hold the target and descends
 * that table alone, and a step that runs off the end of a table carries on into its neighbour. a
 * merge given each table as a source of its own descends every one of them on every seek, which is
 * what an equality lookup through a long-lived iterator paid per level */

/* whether the positioned cursor is on an entry */
static int lv_on_entry(const level_merge_source_t *s)
{
    return s->cur >= 0 && s->cur < s->n && sstable_iter_valid(s->iters[s->cur]);
}

/* note a read the positioned cursor failed, so the merge learns of it however the walk moves on */
static void lv_note_failure(level_merge_source_t *s)
{
    if (s->cur >= 0 && s->cur < s->n && sstable_iter_read_failed(s->iters[s->cur])) s->failed = 1;
}

/* position on the first entry at or after table i, stepping over tables with no entries; stops at a
 * table whose read failed rather than past it, since the keys it holds would go unseen */
static int lv_forward_from(level_merge_source_t *s, int i)
{
    for (; i < s->n; i++)
    {
        s->cur = i;
        if (sstable_iter_seek_first(s->iters[i]) == TDB_SUCCESS && sstable_iter_valid(s->iters[i]))
            return 1;
        lv_note_failure(s);
        if (s->failed) return 0;
    }
    s->cur = s->n;
    return 0;
}

/* position on the last entry at or before table i, the mirror of lv_forward_from */
static int lv_backward_from(level_merge_source_t *s, int i)
{
    for (; i >= 0; i--)
    {
        s->cur = i;
        if (sstable_iter_seek_last(s->iters[i]) == TDB_SUCCESS && sstable_iter_valid(s->iters[i]))
            return 1;
        lv_note_failure(s);
        if (s->failed) return 0;
    }
    s->cur = -1;
    return 0;
}

static int lv_first(void *ctx)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    s->failed = 0;
    return lv_forward_from(s, 0);
}

static int lv_last(void *ctx)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    s->failed = 0;
    return lv_backward_from(s, s->n - 1);
}

static int lv_next(void *ctx)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    if (!lv_on_entry(s)) return 0;
    if (sstable_iter_next(s->iters[s->cur]) == TDB_SUCCESS && sstable_iter_valid(s->iters[s->cur]))
        return 1;
    lv_note_failure(s);
    if (s->failed) return 0;
    return lv_forward_from(s, s->cur + 1);
}

static int lv_prev(void *ctx)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    if (!lv_on_entry(s)) return 0;
    if (sstable_iter_prev(s->iters[s->cur]) == TDB_SUCCESS && sstable_iter_valid(s->iters[s->cur]))
        return 1;
    lv_note_failure(s);
    if (s->failed) return 0;
    return lv_backward_from(s, s->cur - 1);
}

static int lv_valid(void *ctx)
{
    return lv_on_entry((const level_merge_source_t *)ctx);
}

/* the first table whose largest key is at or above key, the only one that can hold the first entry
 * at or after it; n when every table ends below it */
static int lv_first_ending_at_or_after(const level_merge_source_t *s, const uint8_t *key,
                                       const size_t key_size)
{
    int lo = 0, hi = s->n;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        const sstable_t *t = s->ssts[mid];
        if (tdb_key_cmp(t->max_key, t->max_key_size, key, key_size) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* the last table whose smallest key is at or below key, the only one that can hold the last entry
 * at or before it; -1 when every table starts above it */
static int lv_last_starting_at_or_before(const level_merge_source_t *s, const uint8_t *key,
                                         const size_t key_size)
{
    int lo = 0, hi = s->n;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        const sstable_t *t = s->ssts[mid];
        if (tdb_key_cmp(t->min_key, t->min_key_size, key, key_size) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo - 1;
}

static int lv_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    s->failed = 0;
    const int i = lv_first_ending_at_or_after(s, key, key_size);
    if (i >= s->n)
    {
        s->cur = s->n;
        return 0;
    }
    s->cur = i;
    if (sstable_iter_seek(s->iters[i], key, key_size) == TDB_SUCCESS &&
        sstable_iter_valid(s->iters[i]))
        return 1;
    lv_note_failure(s);
    if (s->failed) return 0;
    return lv_forward_from(s, i + 1);
}

static int lv_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    s->failed = 0;
    const int i = lv_last_starting_at_or_before(s, key, key_size);
    if (i < 0)
    {
        s->cur = -1;
        return 0;
    }
    s->cur = i;
    if (sstable_iter_seek_for_prev(s->iters[i], key, key_size) == TDB_SUCCESS &&
        sstable_iter_valid(s->iters[i]))
        return 1;
    lv_note_failure(s);
    if (s->failed) return 0;
    return lv_backward_from(s, i - 1);
}

static void lv_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                   const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                   uint8_t *deleted)
{
    const level_merge_source_t *s = (const level_merge_source_t *)ctx;
    uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    (void)sstable_iter_get(s->iters[s->cur], &k, &ks, &v, &vs, vlog_offset, seq, ttl, deleted);
    *key = k;
    *key_size = ks;
    *value = v;
    *value_size = vs;
}

static int lv_read_failed(void *ctx)
{
    level_merge_source_t *s = (level_merge_source_t *)ctx;
    lv_note_failure(s);
    return s->failed;
}

/* the newest interval any table of the run carries over the key. an interval is not bounded by the
 * keys of the table carrying it, so every table is asked, not only the one a seek would pick */
static int lv_covers(void *ctx, const uint8_t *key, size_t key_size, uint64_t snapshot,
                     uint64_t *out_seq)
{
    const level_merge_source_t *s = (const level_merge_source_t *)ctx;
    int found = 0;
    uint64_t newest = 0;
    for (int i = 0; i < s->n; i++)
    {
        const range_tombstone_set_t *intervals = sstable_iter_intervals(s->iters[i]);
        uint64_t seq = 0;
        if (!intervals ||
            range_tombstone_max_covering(intervals, key, key_size, snapshot, &seq) != 1)
            continue;
        if (!found || seq > newest) newest = seq;
        found = 1;
    }
    if (found) *out_seq = newest;
    return found;
}

void level_merge_source(level_merge_source_t *s, sstable_t *const *ssts,
                        sstable_iter_t *const *iters, const int n, merge_source_t *out)
{
    if (!s || !out) return;
    s->ssts = ssts;
    s->iters = iters;
    s->n = n;
    s->cur = -1;
    s->failed = 0;
    memset(out, 0, sizeof(*out));
    out->read_failed = lv_read_failed;
    out->first = lv_first;
    out->last = lv_last;
    out->next = lv_next;
    out->prev = lv_prev;
    out->valid = lv_valid;
    out->seek = lv_seek;
    out->seek_for_prev = lv_seek_for_prev;
    out->get = lv_get;
    out->covers = lv_covers;
    out->ctx = s;
}
