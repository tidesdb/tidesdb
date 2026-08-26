/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/log.h"
#include "sstable/vlog.h"
#include "sstable/vlog_internal.h"

/* reclamation and the build tokens that bound it. a segment goes back to the filesystem only when
 * nothing in the index resolves into it and no build in flight could still be writing to it, and a
 * build token is how a builder says which segments those are */
int vlog_build_enter(vlog_t *v)
{
    if (!v) return -1;

    /* the segment taking appends right now, which is the lowest-numbered one this builder can land
     * a value in. the next number would name the segment after it and leave the one actually being
     * written to below the floor, unprotected */
    const uint32_t slot = atomic_load_explicit(&v->active_slot, memory_order_acquire);
    const uint64_t here = v->segments[slot].number;

    for (int i = 0; i < VLOG_MAX_BUILDERS; i++)
    {
        uint64_t free_slot = VLOG_BUILD_FLOOR_NONE;
        if (atomic_compare_exchange_strong_explicit(&v->build_floors[i], &free_slot, here,
                                                    memory_order_acq_rel, memory_order_relaxed))
            return i;
    }

    /* no slot, so this builder cannot be described individually. rather than leave it unprotected,
     * it stops reclamation entirely for as long as it runs */
    atomic_fetch_add_explicit(&v->builds_unslotted, 1, memory_order_acq_rel);
    return -1;
}

void vlog_build_lower(vlog_t *v, const int token, const uint64_t segment)
{
    if (!v || token < 0 || token >= VLOG_MAX_BUILDERS) return;

    uint64_t held = atomic_load_explicit(&v->build_floors[token], memory_order_acquire);
    while (segment < held &&
           !atomic_compare_exchange_weak_explicit(&v->build_floors[token], &held, segment,
                                                  memory_order_acq_rel, memory_order_acquire))
    {
        /* held reloaded with the live value on failure; the loop re-checks segment < held */
    }
}

int vlog_id_segment(vlog_t *v, const vlog_id_t id, uint64_t *out_segment)
{
    if (!v || !out_segment) return VLOG_ERR_INVALID;

    pthread_rwlock_rdlock(&v->index_rw);
    const size_t at = vlog_index_locate(v, id, NULL);
    const int found = at != SIZE_MAX;
    const uint32_t slot = found ? v->buckets[at].segment : 0;
    pthread_rwlock_unlock(&v->index_rw);
    if (!found) return VLOG_ERR_NOT_FOUND;

    *out_segment = v->segments[slot].number;
    return VLOG_OK;
}

void vlog_build_leave(vlog_t *v, int token)
{
    if (!v) return;
    if (token < 0 || token >= VLOG_MAX_BUILDERS)
    {
        atomic_fetch_sub_explicit(&v->builds_unslotted, 1, memory_order_acq_rel);
        return;
    }
    atomic_store_explicit(&v->build_floors[token], VLOG_BUILD_FLOOR_NONE, memory_order_release);
}

/**
 * vlog_build_floor
 * the lowest segment number any builder in flight may have written to, taken fresh so a floor left
 * by a builder that has since finished never holds a segment back
 * @param v vlog handle
 * @return the floor, or VLOG_BUILD_FLOOR_NONE when nothing is in flight
 */
static uint64_t vlog_build_floor(vlog_t *v)
{
    uint64_t floor = VLOG_BUILD_FLOOR_NONE;
    for (int i = 0; i < VLOG_MAX_BUILDERS; i++)
    {
        const uint64_t held = atomic_load_explicit(&v->build_floors[i], memory_order_acquire);
        if (held < floor) floor = held;
    }
    return floor;
}

/**
 * vlog_index_purge_segment
 * drops every index entry resolving into a segment, called as it is unlinked. the entries name
 * values nothing references, so removing them frees the map of a store's entire history of dead
 * values -- which is what kept the index growing without bound
 * @param v vlog handle
 * @param slot the segment's table slot
 */
static void vlog_index_purge_segment(vlog_t *v, uint32_t slot)
{
    pthread_rwlock_wrlock(&v->index_rw);
    for (size_t i = 0; i < v->bucket_cap; i++)
    {
        if (v->buckets[i].state != VLOG_BUCKET_OCCUPIED) continue;
        if (v->buckets[i].segment != slot) continue;
        v->used_bytes -= v->buckets[i].value_len;
        v->stored_bytes -= v->buckets[i].disk_len;
        vlog_chain_account(v, v->buckets[i].chain, -(int64_t)v->buckets[i].value_len,
                           -(int64_t)v->buckets[i].disk_len, -1);
        v->buckets[i].state = VLOG_BUCKET_DELETED;
        v->bucket_count--;
        v->bucket_tomb++;
    }
    pthread_rwlock_unlock(&v->index_rw);
}

/**
 * vlog_segment_reclaimable
 * whether a segment can be dropped outright, which needs it sealed, referenced by nothing, and out
 * of reach of every builder in flight
 * @param v vlog handle
 * @param slot the segment's table slot
 * @param active the slot currently taking appends
 * @param floor the lowest segment number any builder in flight may have written to
 * @return 1 when the segment can be unlinked, 0 otherwise
 */
static int vlog_segment_reclaimable(vlog_t *v, uint32_t slot, uint32_t active, uint64_t floor)
{
    if (slot == active) return 0;
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return 0;
    if (v->segments[slot].number >= floor) return 0;
    return atomic_load_explicit(&v->segments[slot].live_bytes, memory_order_relaxed) == 0;
}

int vlog_reclaim(vlog_t *v)
{
    if (!v) return VLOG_ERR_INVALID;

    atomic_fetch_add_explicit(&v->reclaim_calls, 1, memory_order_relaxed);

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    /* a builder that could not be described individually stops the whole pass, since there is no
     * way to say which segments it might have written to */
    if (atomic_load_explicit(&v->builds_unslotted, memory_order_acquire) > 0) return VLOG_OK;

    const uint64_t floor = vlog_build_floor(v);
    int drained = 0;

    /* counted so a pass that frees nothing can say which condition held it back, since the three
     * reasons want different fixes and the totals alone cannot tell them apart */
    uint32_t sealed = 0, empty = 0, held_by_floor = 0;
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        /* read per iteration rather than once for the pass. an appender that fills the active
         * segment rolls to a fresh one while this loop is running, so a slot hoisted before it
         * started stops naming the segment that is taking appends -- and the newly active segment,
         * which is empty until its first append lands, would then satisfy every reclaim test and be
         * unlinked out from under the writers */
        const uint32_t active = atomic_load_explicit(&v->active_slot, memory_order_acquire);

        if (i != active &&
            atomic_load_explicit(&v->segments[i].state, memory_order_acquire) == VLOG_SEG_OPEN)
        {
            sealed++;
            if (atomic_load_explicit(&v->segments[i].live_bytes, memory_order_relaxed) == 0)
            {
                empty++;
                if (v->segments[i].number >= floor) held_by_floor++;
            }
        }
        if (!vlog_segment_reclaimable(v, i, active, floor)) continue;

        /* the index is purged first. an entry left behind would resolve into a slot about to hold a
         * different file, and a read of a dead id would then return another value's bytes rather
         * than failing */
        vlog_index_purge_segment(v, i);
        if (vlog_segment_retire(v, i) != VLOG_OK) continue;

        atomic_fetch_add_explicit(&v->segments_retired, 1, memory_order_relaxed);
        drained++;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "vlog reclaim drained %d of %u sealed, %u empty, %u held by floor %llu", drained,
                  sealed, empty, held_by_floor, (unsigned long long)floor);

    if (drained > 0) atomic_fetch_add_explicit(&v->reclaim_passes, 1, memory_order_relaxed);
    return VLOG_OK;
}

int vlog_mark_drainable(vlog_t *v)
{
    if (!v) return 0;

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    int marked = 0;

    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (!vlog_segment_acquire(v, i)) continue;

        /* read per iteration, as the reclaim pass does. an appender rolling while this loop runs
         * moves the active slot, and a reading hoisted before it started would let the segment now
         * taking appends be marked -- costing the next compaction a pointless rewrite of values
         * into a segment that is still growing */
        const uint32_t active = atomic_load_explicit(&v->active_slot, memory_order_acquire);

        uint64_t size = 0;
        const uint64_t live =
            atomic_load_explicit(&v->segments[i].live_bytes, memory_order_relaxed);
        /* the segment taking appends is never marked. it is still growing, so the share of it that
         * is live says nothing yet, and rewriting values into the very segment being emptied would
         * not converge */
        const int worth = i != active && live > 0 &&
                          block_manager_get_size(vlog_segment_ensure_open(v, i), &size) == 0 &&
                          live <= size / VLOG_RECLAIM_LIVE_DIVISOR;

        atomic_store_explicit(&v->segments[i].draining, worth, memory_order_relaxed);
        if (worth) marked++;
        vlog_segment_release(v, i);
    }
    return marked;
}

int vlog_should_respill(vlog_t *v, vlog_id_t id)
{
    if (!v || id == VLOG_ID_INVALID) return 0;

    pthread_rwlock_rdlock(&v->index_rw);
    const size_t bucket = vlog_index_locate(v, id, NULL);
    const int draining = bucket != SIZE_MAX &&
                         atomic_load_explicit(&v->segments[v->buckets[bucket].segment].draining,
                                              memory_order_relaxed);
    pthread_rwlock_unlock(&v->index_rw);
    return draining;
}

int vlog_evict_idle_segments(vlog_t *v, int max)
{
    if (!v) return 0;

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    int freed = 0;
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (max > 0 && freed >= max) break;
        freed += vlog_segment_evict(v, i);
    }
    return freed;
}
