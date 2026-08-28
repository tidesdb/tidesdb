/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "cf_source.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS, TDB_ERR_NOT_FOUND, TDB_ERR_BUSY */
#include "column_family/level/level_set.h"
#include "internal/types.h" /* TDB_TTL_NONE, the deadline a delete carries */
#include "sstable/sstable.h"
#include "sstable/vlog.h"

/* how many overlapping sstables one level's scan holds on the stack before spilling to the heap;
 * L2+ runs are non-overlapping so at most one overlaps a key there, and L1's overlap depth is
 * bounded by the flush backpressure and the compaction file-count trigger, so the stack path is the
 * common one */
#define CF_SOURCE_STACK_CANDIDATES 32

/* the interval probe reads tables it is going to walk once and discard, so it stays out of the
 * block cache rather than evicting what the read path is using */
#define CF_SOURCE_RANGE_NO_CACHE 0

/* scan one level for the newest version of key visible at snapshot. on TDB_SOURCE_FOUND, best holds
 * the winning version -- with best->value still NULL and *vlog set when the value spilled, for the
 * caller to resolve. a busy or io candidate taints the level -- without reading it the max cannot
 * be trusted, so the whole level returns BUSY for the caller to retry rather than risk a stale
 * older version. */
static tidesdb_source_result_t cf_source_scan_level(cf_t *cf, int level, const uint8_t *key,
                                                    size_t key_size, uint64_t snapshot,
                                                    tidesdb_source_version_t *best, uint64_t *vlog)
{
    *best = (tidesdb_source_version_t){0};
    *vlog = 0;

    /* collect straight into a stack buffer rather than asking the level for a count first. the
     * collect reports how many overlap even when more overlap than fit, so one call gives both the
     * candidates and the size they needed -- from a single layout load.
     *
     * that is two things at once. it halves the epoch traffic this read pays per level, on a
     * counter every reader of this family shares and enters under a full barrier. and it closes the
     * window the count-then-collect pair left open, where a flush installing between the two made
     * the candidates a subset of what the count had promised and the highest sequence among them
     * was not the highest that existed */
    sstable_t *stackbuf[CF_SOURCE_STACK_CANDIDATES];
    sstable_t **cands = stackbuf;
    int cap = CF_SOURCE_STACK_CANDIDATES;
    int n = level_set_overlapping(cf->levels, level, key, key_size, key, key_size, cands, cap);
    if (n <= 0) return TDB_SOURCE_NOT_FOUND;

    int busy = 0;
    if (n > cap)
    {
        /* more overlapped than the stack held. the prefix that was stored carries a reference
         * apiece, so release those before collecting again into a buffer sized from what this load
         * reported */
        for (int i = 0; i < cap; i++)
            if (sstable_unref(cands[i])) sstable_close(cands[i]);

        cands = malloc((size_t)n * sizeof(*cands));
        if (!cands) return TDB_SOURCE_BUSY; /* transient allocation failure, retryable */
        cap = n;
        n = level_set_overlapping(cf->levels, level, key, key_size, key, key_size, cands, cap);

        /* the level grew again between the two loads; report it rather than answer from a subset */
        if (n > cap)
        {
            busy = 1;
            n = cap;
        }
    }
    const int stored = n;

    int found = 0;
    for (int i = 0; i < stored; i++)
    {
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t voff = 0, seq = 0;
        int64_t ttl = -1;
        uint8_t deleted = 0;
        const int rc = sstable_get_at_seq(cands[i], key, key_size, snapshot, &value, &value_size,
                                          &voff, &seq, &ttl, &deleted);
        if (rc == TDB_SUCCESS)
        {
            /* keep the highest-seq visible version across the level's overlapping sstables */
            if (!found || seq > best->seq)
            {
                free(best->value);
                best->seq = seq;
                best->value = value;
                best->value_size = value_size;
                best->ttl = ttl;
                best->deleted = deleted;
                *vlog = voff;
                found = 1;
            }
            else
                free(value);
        }
        else if (rc != TDB_ERR_NOT_FOUND)
            busy = 1; /* a busy slot or any transient read error, never a definitive miss */
    }

    for (int i = 0; i < stored; i++)
        if (sstable_unref(cands[i])) sstable_close(cands[i]);
    if (cands != stackbuf) free(cands);

    if (busy)
    {
        free(best->value);
        *best = (tidesdb_source_version_t){0};
        return TDB_SOURCE_BUSY;
    }
    return found ? TDB_SOURCE_FOUND : TDB_SOURCE_NOT_FOUND;
}

/* fill a version that says the key was deleted at seq -- what a covering range tombstone resolves
 * to, since it names no value and no expiry, only the sequence it deleted from */
static void cf_source_deleted_at(const uint64_t seq, tidesdb_source_version_t *out)
{
    out->seq = seq;
    out->value = NULL;
    out->value_size = 0;
    out->ttl = TDB_TTL_NONE;
    out->deleted = 1;
}

/* the source's point lookup walks the cf's levels top-down and returns the first level that holds a
 * visible version -- the newest, because a shallower level always carries a seq at least as high as
 * any deeper one for the same key. per-level reads are race-safe against a concurrent compaction
 * because layout swaps are atomic and compaction only moves keys downward. */
static tidesdb_source_result_t cf_source_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                             size_t key_size, uint64_t snapshot,
                                             tidesdb_source_version_t *out)
{
    (void)cf_index; /* per-cf source; the composer routes only this cf's keys here */
    cf_t *cf = (cf_t *)ctx;
    if (!cf || !key || key_size == 0 || !out) return TDB_SOURCE_NOT_FOUND;

    /* one load says which levels hold anything, so the empty ones cost nothing. asking each level
     * for its count instead costs an epoch enter and exit apiece, on a counter every reader of this
     * family shares -- and with only the first level or two populated, most of that was spent
     * confirming emptiness.
     *
     * the mask is a snapshot and each level below is scanned against the live layout, so a merge
     * that moves a table into a level this mask calls empty is skipped. that is safe when a flush
     * did it -- its keys are still in the memtable it has not retired yet, and L0 is consulted
     * before any of this -- but a compaction's keys left L0 long ago, so nothing backs them up. the
     * generation is read here and again on a miss, and a shape that moved under the walk asks the
     * caller to retry rather than reporting an absence that was never true */
    const uint64_t layout_at_entry = level_set_generation(cf->levels);
    const uint32_t occupied = level_set_occupancy(cf->levels);

    /* an interval covers a range the table carrying it need not hold a single key of, so it cannot
     * be looked for alongside the key -- it is asked of the whole family once, before the walk, and
     * whichever is newer wins. a tombstone laid after a version deletes it, and a version written
     * after a tombstone survives it. a family that has never deleted a range answers from one load
     */
    uint64_t tomb_seq = 0;
    const int covered = cf_range_tombstone_covering(cf, key, key_size, snapshot, &tomb_seq);

    for (int level = LEVEL_SET_L1; level <= LEVEL_SET_MAX_LEVELS; level++)
    {
        if (!(occupied & (1u << (level - 1)))) continue;

        tidesdb_source_version_t best;
        uint64_t vlog_id = 0;
        const tidesdb_source_result_t r =
            cf_source_scan_level(cf, level, key, key_size, snapshot, &best, &vlog_id);
        if (r == TDB_SOURCE_BUSY) return TDB_SOURCE_BUSY;
        if (r == TDB_SOURCE_NOT_FOUND) continue;

        if (covered && tomb_seq > best.seq)
        {
            free(best.value);
            cf_source_deleted_at(tomb_seq, out);
            return TDB_SOURCE_FOUND;
        }

        /* a live spilled value comes back as a vlog id to resolve; a tombstone carries no value */
        if (!best.deleted && best.value == NULL && vlog_id != 0)
        {
            uint8_t *resolved = NULL;
            size_t resolved_len = 0;
            if (vlog_read(cf->vlog, vlog_id, &resolved, &resolved_len) != VLOG_OK)
                return TDB_SOURCE_BUSY;
            best.value = resolved;
            best.value_size = resolved_len;
        }
        *out = best;
        return TDB_SOURCE_FOUND;
    }

    /* no level held the key, but a tombstone covering it still answers -- and answering is what
     * stops the read falling through to a source that would report it absent for a different reason
     */
    if (covered)
    {
        cf_source_deleted_at(tomb_seq, out);
        return TDB_SOURCE_FOUND;
    }

    /* nothing held it, which is only trustworthy if the shape stood still while it was looked for
     */
    if (level_set_generation(cf->levels) != layout_at_entry) return TDB_SOURCE_BUSY;
    return TDB_SOURCE_NOT_FOUND;
}

/* the conflict-probe scan of one level. an sstable whose newest sequence is at or below the floor
 * cannot hold a conflicting version, so it is skipped on its footer metadata alone rather than
 * descending its btree. skipping one is safe even when it does hold the key, because the only
 * question here is whether a newer version exists anywhere, and a skipped sstable answers no */
static tidesdb_source_result_t cf_source_newer_in_level(cf_t *cf, int level, const uint8_t *key,
                                                        size_t key_size, uint64_t seq_floor,
                                                        int *newer)
{
    /* one layout load for both the candidates and the size they needed, as in cf_source_scan_level
     * -- this probe runs once per written key on every commit above read committed, so its share of
     * the epoch traffic is paid by every write */
    sstable_t *stackbuf[CF_SOURCE_STACK_CANDIDATES];
    sstable_t **cands = stackbuf;
    int cap = CF_SOURCE_STACK_CANDIDATES;
    int n = level_set_overlapping(cf->levels, level, key, key_size, key, key_size, cands, cap);
    if (n <= 0) return TDB_SOURCE_NOT_FOUND;

    int busy = 0;
    if (n > cap)
    {
        for (int i = 0; i < cap; i++)
            if (sstable_unref(cands[i])) sstable_close(cands[i]);

        cands = malloc((size_t)n * sizeof(*cands));
        if (!cands) return TDB_SOURCE_BUSY;
        cap = n;
        n = level_set_overlapping(cf->levels, level, key, key_size, key, key_size, cands, cap);
        if (n > cap)
        {
            busy = 1;
            n = cap;
        }
    }
    const int stored = n;

    int found = 0;

    for (int i = 0; i < stored; i++)
    {
        if (cands[i]->max_seq <= seq_floor) continue;

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t voff = 0, seq = 0;
        int64_t ttl = -1;
        uint8_t deleted = 0;
        const int rc = sstable_get_at_seq(cands[i], key, key_size, UINT64_MAX, &value, &value_size,
                                          &voff, &seq, &ttl, &deleted);
        if (rc == TDB_SUCCESS)
        {
            free(value);
            if (seq > seq_floor)
            {
                found = 1;
                *newer = 1;
            }
        }
        else if (rc != TDB_ERR_NOT_FOUND)
            busy = 1;
    }

    for (int i = 0; i < stored; i++)
        if (sstable_unref(cands[i])) sstable_close(cands[i]);
    if (cands != stackbuf) free(cands);

    if (busy) return TDB_SOURCE_BUSY;
    return found ? TDB_SOURCE_FOUND : TDB_SOURCE_NOT_FOUND;
}

/* the source's conflict probe, walking levels top-down like the point lookup does */
/* tables one interval probe reads before it gives up; a family with more than this reports busy,
 * which a commit retries rather than reading as a clear run */
#define CF_SOURCE_RANGE_MAX_TABLES 512

/* byte-wise order over keys, the same one the tables are sorted in */
static int cf_source_key_cmp(const uint8_t *a, const size_t a_size, const uint8_t *b,
                             const size_t b_size)
{
    const size_t min_size = a_size < b_size ? a_size : b_size;
    const int c = min_size > 0 ? memcmp(a, b, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (a_size < b_size) return -1;
    if (a_size > b_size) return 1;
    return 0;
}

/**
 * cf_source_table_in_range
 * whether a table's recorded key range meets [lo, hi) at all. a table entirely outside it holds
 * nothing the probe cares about and is skipped without being opened
 * @param sst the table
 * @param lo inclusive lower bound
 * @param lo_size length of lo
 * @param hi exclusive upper bound, NULL for unbounded above
 * @param hi_size length of hi, 0 for unbounded above
 * @return non-zero when the ranges meet
 */
static int cf_source_table_in_range(const sstable_t *sst, const uint8_t *lo, const size_t lo_size,
                                    const uint8_t *hi, const size_t hi_size)
{
    if (!sst->min_key || !sst->max_key) return 1; /* no recorded range, so it cannot be ruled out */
    if (cf_source_key_cmp(sst->max_key, sst->max_key_size, lo, lo_size) < 0) return 0;
    if (hi_size > 0 && cf_source_key_cmp(sst->min_key, sst->min_key_size, hi, hi_size) >= 0)
        return 0;
    return 1;
}

/**
 * cf_source_table_range_has_newer
 * walk one table over [lo, hi) for any entry above the floor, stopping at the first
 * @param sst the table to walk
 * @param lo inclusive lower bound
 * @param lo_size length of lo
 * @param hi exclusive upper bound, NULL for unbounded above
 * @param hi_size length of hi, 0 for unbounded above
 * @param seq_floor the sequence an entry must exceed
 * @param newer out, set non-zero as soon as one is found
 * @return 0 on a complete walk, -1 when the table could not be read and the probe cannot conclude
 */
static int cf_source_table_range_has_newer(sstable_t *sst, const uint8_t *lo, const size_t lo_size,
                                           const uint8_t *hi, const size_t hi_size,
                                           const uint64_t seq_floor, int *newer)
{
    sstable_iter_t *it = NULL;
    if (sstable_iter_new(sst, CF_SOURCE_RANGE_NO_CACHE, &it) != TDB_SUCCESS) return -1;
    if (sstable_iter_seek(it, lo, lo_size) != TDB_SUCCESS)
    {
        const int failed = sstable_iter_read_failed(it);
        sstable_iter_free(it);
        return failed ? -1 : 0;
    }

    int rc = 0;
    while (!*newer && sstable_iter_valid(it))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t vlog_offset = 0, seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        if (sstable_iter_get(it, &key, &key_size, &value, &value_size, &vlog_offset, &seq, &ttl,
                             &deleted) != TDB_SUCCESS)
            break;
        if (hi_size > 0 && cf_source_key_cmp(key, key_size, hi, hi_size) >= 0) break;
        if (seq > seq_floor)
        {
            *newer = 1;
            break;
        }
        if (sstable_iter_next(it) != TDB_SUCCESS) break;
    }
    if (sstable_iter_read_failed(it)) rc = -1;
    sstable_iter_free(it);
    return rc;
}

/* the interval probe a commit runs for a range delete. a table whose newest sequence is at or
 * below the floor cannot hold anything newer wherever its keys fall, so it is ruled out on cached
 * metadata alone -- which is what keeps this off the cost of the delete it is checking */
static tidesdb_source_result_t cf_source_range_has_newer(void *ctx, uint32_t cf_index,
                                                         const uint8_t *lo, size_t lo_size,
                                                         const uint8_t *hi, size_t hi_size,
                                                         uint64_t seq_floor, int *newer)
{
    (void)cf_index; /* per-cf source; the composer routes only this cf's keys here */
    cf_t *cf = (cf_t *)ctx;
    if (!cf || !lo || !newer) return TDB_SOURCE_BUSY;
    *newer = 0;

    sstable_t **tables = malloc(CF_SOURCE_RANGE_MAX_TABLES * sizeof(*tables));
    if (!tables) return TDB_SOURCE_BUSY;

    const int n = level_set_collect_all(cf->levels, tables, CF_SOURCE_RANGE_MAX_TABLES);
    if (n > CF_SOURCE_RANGE_MAX_TABLES)
    {
        for (int i = 0; i < CF_SOURCE_RANGE_MAX_TABLES; i++)
            if (sstable_unref(tables[i])) sstable_close(tables[i]);
        free(tables);
        return TDB_SOURCE_BUSY; /* a partial view cannot clear a commit */
    }

    int held = 0;
    int failed = 0;
    for (int i = 0; i < n; i++)
    {
        if (*newer || failed) continue;
        if (tables[i]->max_seq <= seq_floor) continue; /* nothing in it can be newer */
        if (!cf_source_table_in_range(tables[i], lo, lo_size, hi, hi_size)) continue;

        held = 1;
        if (cf_source_table_range_has_newer(tables[i], lo, lo_size, hi, hi_size, seq_floor,
                                            newer) != 0)
            failed = 1;
    }
    for (int i = 0; i < n; i++)
        if (sstable_unref(tables[i])) sstable_close(tables[i]);
    free(tables);

    if (failed) return TDB_SOURCE_BUSY;
    return held ? TDB_SOURCE_FOUND : TDB_SOURCE_NOT_FOUND;
}

static tidesdb_source_result_t cf_source_has_newer(void *ctx, uint32_t cf_index, const uint8_t *key,
                                                   size_t key_size, uint64_t seq_floor, int *newer)
{
    (void)cf_index;
    cf_t *cf = (cf_t *)ctx;
    if (!cf || !key || key_size == 0 || !newer) return TDB_SOURCE_NOT_FOUND;

    /* a committed range tombstone above the floor is a newer write of this key even though it names
     * no version of it. without this a range delete and a point write inside it, committing in that
     * order from concurrent transactions, would both succeed -- the delete's own scan catches the
     * other order, and this is what catches this one. a family that has never deleted a range
     * answers from one load */
    uint64_t tomb = 0;
    if (cf_range_tombstone_covering(cf, key, key_size, UINT64_MAX, &tomb) && tomb > seq_floor)
    {
        *newer = 1;
        return TDB_SOURCE_FOUND;
    }

    /* same reason as the read scan; this probe runs once per key on every commit above read
     * committed, so its share of a write is paid by every write. and the same snapshot hazard, so
     * the same guard -- a conflict probe that missed a version because the shape moved under it
     * would clear a commit that should have been refused */
    const uint64_t layout_at_entry = level_set_generation(cf->levels);
    const uint32_t occupied = level_set_occupancy(cf->levels);

    for (int level = LEVEL_SET_L1; level <= LEVEL_SET_MAX_LEVELS; level++)
    {
        if (!(occupied & (1u << (level - 1)))) continue;

        const tidesdb_source_result_t r =
            cf_source_newer_in_level(cf, level, key, key_size, seq_floor, newer);
        if (r == TDB_SOURCE_BUSY || r == TDB_SOURCE_FOUND) return r;
    }
    if (level_set_generation(cf->levels) != layout_at_entry) return TDB_SOURCE_BUSY;
    return TDB_SOURCE_NOT_FOUND;
}

void cf_source(cf_t *cf, tidesdb_source_t *out)
{
    if (!out) return;
    out->name = "cf_sstable";
    out->get = cf_source_get;
    out->has_newer = cf_source_has_newer;
    out->range_has_newer = cf_source_range_has_newer;
    out->ctx = cf;
}
