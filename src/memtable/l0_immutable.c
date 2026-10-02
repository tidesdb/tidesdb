/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"
#include "base/log.h"
#include "l0_internal.h"

/* the sealed side of L0 -- the queue of immutable memtables a flush claims, retires and releases,
 * the pins a reader takes on every memtable at once, and the reclamation that frees a retired
 * memtable once its last reader has left. the active memtable and the write path are in memtable.c
 */

/* the refcount an idle memtable sits at -- its single structural reference (the active slot or the
 * queue). reclamation frees once every transient reader reference is dropped back to this. */
#define TDB_L0_MEMTABLE_BASELINE 1

/* a reclaimer waiting out a lingering reader reference pauses this long between rechecks */
#define TDB_L0_RECLAIM_DRAIN_STALL_US 50

/* forget every abandoned sequence recorded while a memtable of this generation or an older one was
 * active; a batch that landed in none of the memtables still resident cannot be read anywhere */
static void l0_forget_aborted_through(tidesdb_l0_t *l0, const uint64_t generation)
{
    pthread_mutex_lock(&l0->aborted_lock);
    const int n = atomic_load_explicit(&l0->aborted_count, memory_order_relaxed);
    for (int i = 0; i < n; i++)
        if (l0->aborted_gens[i] <= generation)
            atomic_store_explicit(&l0->aborted_seqs[i], 0, memory_order_release);
    pthread_mutex_unlock(&l0->aborted_lock);
}

tidesdb_memtable_t *tidesdb_l0_dequeue_immutable(tidesdb_l0_t *l0)
{
    if (!l0) return NULL;
    tidesdb_memtable_t *mt = (tidesdb_memtable_t *)queue_dequeue(l0->queue);
    /* the queue just got shallower, which is the thing a blocked writer is waiting on */
    if (mt) tidesdb_l0_admit_wake(l0);
    return mt;
}

tidesdb_memtable_t *tidesdb_l0_claim_immutable(tidesdb_l0_t *l0)
{
    if (!l0) return NULL;

    /* run under the reader epoch, exactly as a read does, so a concurrent retire cannot free a
     * queued immutable between the snapshot and the claim compare-and-swap */
    tdb_epoch_enter(&l0->active_readers);
    const size_t depth = queue_size(l0->queue);
    if (depth == 0)
    {
        tdb_epoch_exit(&l0->active_readers);
        return NULL;
    }

    tidesdb_memtable_t *stack_snap[TDB_L0_IMMUTABLE_SNAP_STACK];
    void **snap =
        depth <= TDB_L0_IMMUTABLE_SNAP_STACK ? (void **)stack_snap : malloc(depth * sizeof(void *));
    if (!snap)
    {
        tdb_epoch_exit(&l0->active_readers);
        return NULL;
    }
    const size_t got = queue_snapshot(l0->queue, snap, depth);

    /* claim the oldest immutable no worker has taken yet, leaving it in the queue so readers still
     * see it until it is retired after its data reaches L1. a memtable already retired by another
     * worker is claimed, so the compare-and-swap skips it. a memtable still sitting in the active
     * slot is mid rotation -- it is in the queue for reader visibility but writers still target it,
     * so skip it until the swap makes it truly immutable, or a flush would race those writers and
     * lose their data */
    tidesdb_memtable_t *claimed = NULL;
    for (size_t i = 0; i < got && !claimed; i++)
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
        if (!mt || mt == atomic_load_explicit(&l0->active, memory_order_acquire)) continue;
        int expected = 0;
        if (atomic_compare_exchange_strong(&mt->claimed, &expected, 1)) claimed = mt;
    }
    if (snap != (void **)stack_snap) free(snap);
    tdb_epoch_exit(&l0->active_readers);
    if (claimed) atomic_fetch_add_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    return claimed;
}

/* queue_remove_if predicate matching the single memtable passed as context */
static int l0_match_memtable(void *data, void *context)
{
    return data == context;
}

void tidesdb_l0_retire_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0 || !mt) return;
    /* remove this immutable from the reader-visible queue now that its data is durable in L1, then
     * reclaim it once the readers that pinned it drain. this moves the reader-visible set exactly
     * as a rotation does, so it is published the same way -- a reader that missed the active and
     * then found this immutable already gone would otherwise report an absence it cannot stand
     * behind */
    (void)queue_remove_if(l0->queue, l0_match_memtable, mt, NULL);
    atomic_fetch_add_explicit(&l0->visible_changes, 1, memory_order_release);
    atomic_fetch_sub_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    l0_forget_aborted_through(l0, mt->generation);
    tidesdb_l0_reclaim(l0, mt);
}

void tidesdb_l0_release_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0 || !mt) return;
    atomic_fetch_sub_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    atomic_store_explicit(&mt->claimed, 0, memory_order_release);
}

void tidesdb_l0_wal_wait_stats(const tidesdb_l0_t *l0, tidesdb_l0_wal_wait_t *out)
{
    if (!out) return;
    if (!l0)
    {
        memset(out, 0, sizeof(*out));
        return;
    }
    tdb_wait_read(&l0->wal_wait, &out->count, &out->total_us, &out->max_us);
}

uint64_t tidesdb_l0_wal_bytes_written(const tidesdb_l0_t *l0)
{
    return l0 ? atomic_load_explicit(&l0->wal_bytes_written, memory_order_relaxed) : 0;
}

size_t tidesdb_l0_queue_depth(const tidesdb_l0_t *l0)
{
    if (!l0) return 0;
    return queue_size(l0->queue);
}

void tidesdb_memtable_mark_flushed(tidesdb_memtable_t *mt)
{
    if (!mt) return;
    atomic_store_explicit(&mt->flushed, 1, memory_order_release);
}

int tidesdb_l0_pin_memtables(tidesdb_l0_t *l0, tidesdb_memtable_t **out, int max, int *n_out)
{
    if (!l0 || !out || !n_out) return TDB_ERR_INVALID_ARGS;
    *n_out = 0;

    /* pin the active memtable; a rotation that keeps swapping it out is transient */
    tidesdb_memtable_t *active = NULL;
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS && !active; attempt++)
        active = l0_pin_active_read(l0);

    /* snapshot and pin the immutable queue under the reader epoch, exactly as a read does */
    const size_t depth = queue_size(l0->queue);
    tidesdb_memtable_t *stack_snap[TDB_L0_IMMUTABLE_SNAP_STACK];
    void **snap =
        depth <= TDB_L0_IMMUTABLE_SNAP_STACK ? (void **)stack_snap : malloc(depth * sizeof(void *));
    if (depth > 0 && !snap)
    {
        if (active) l0_unpin_read(active);
        return TDB_ERR_MEMORY;
    }

    int n_imm = 0;
    if (depth > 0)
    {
        tdb_epoch_enter(&l0->active_readers);
        const size_t got = queue_snapshot(l0->queue, snap, depth);
        for (size_t i = 0; i < got; i++)
        {
            tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
            if (mt && tdb_try_ref(&mt->refcount)) snap[n_imm++] = mt; /* compact the pinned ones */
        }
        tdb_epoch_exit(&l0->active_readers);
    }

    const int total = (active ? 1 : 0) + n_imm;
    if (total > max)
    {
        /* the caller under-sized out; release every pin and report the needed count for a retry */
        if (active) l0_unpin_read(active);
        for (int i = 0; i < n_imm; i++) l0_unpin_read((tidesdb_memtable_t *)snap[i]);
        if (snap != (void **)stack_snap) free(snap);
        *n_out = total;
        return TDB_ERR_TOO_LARGE;
    }

    /* newest first -- the active, then the immutables from the queue tail (newest) to head */
    int k = 0;
    if (active) out[k++] = active;
    for (int i = n_imm - 1; i >= 0; i--) out[k++] = (tidesdb_memtable_t *)snap[i];
    if (snap != (void **)stack_snap) free(snap);
    *n_out = total;
    return TDB_SUCCESS;
}

void tidesdb_l0_unpin_memtables(tidesdb_memtable_t **mts, int n)
{
    if (!mts) return;
    for (int i = 0; i < n; i++)
        if (mts[i] && tdb_unref(&mts[i]->refcount)) tidesdb_memtable_free(mts[i]);
}

/* how many times reclaim rechecks inline before handing the immutable to the pending list. the
 * common case is that the readers holding it are point reads that finish in microseconds, so a
 * short recheck frees it here and the list stays empty */
#define TDB_L0_RECLAIM_INLINE_ATTEMPTS 20

/* push a node onto the lock-free pending list */
static void l0_pending_push(tidesdb_l0_t *l0, l0_pending_node_t *node)
{
    l0_pending_node_t *head = atomic_load_explicit(&l0->pending_reclaim, memory_order_acquire);
    do
    {
        node->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&l0->pending_reclaim, (void **)&head, node,
                                                    memory_order_release, memory_order_acquire));
}

/* whether an immutable can be freed now -- no reader is inside the pin window and none holds a
 * reference beyond the structural one the queue dropped */
static int l0_reclaim_ready(const tidesdb_l0_t *l0, const tidesdb_memtable_t *mt)
{
    if (l0 && tdb_epoch_active(&l0->active_readers) > 0) return 0;
    return atomic_load_explicit(&mt->refcount, memory_order_acquire) <= TDB_L0_MEMTABLE_BASELINE;
}

void tidesdb_l0_reclaim_pending(tidesdb_l0_t *l0)
{
    if (!l0) return;
    l0_pending_node_t *cur =
        atomic_exchange_explicit(&l0->pending_reclaim, NULL, memory_order_acq_rel);
    while (cur)
    {
        l0_pending_node_t *next = cur->next;
        if (l0_reclaim_ready(l0, cur->mt))
        {
            tidesdb_memtable_free(cur->mt);
            free(cur);
        }
        else
        {
            l0_pending_push(l0, cur);
        }
        cur = next;
    }
}

void tidesdb_l0_reclaim(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!mt) return;

    /* the caller dequeued mt, so no new reader can reach it and the only question is when the
     * readers already holding it leave. this runs inside a flush install, under locks a create or
     * drop needs, so it must not wait on that unboundedly -- the reader epoch is db-global and a
     * database under continuous reads may never present a quiet instant to the thread that happens
     * to be asking. recheck briefly, and hand anything still held to the pending list for the
     * reaper to free once the readers do leave */
    for (int attempt = 0; attempt < TDB_L0_RECLAIM_INLINE_ATTEMPTS; attempt++)
    {
        if (l0_reclaim_ready(l0, mt))
        {
            tidesdb_memtable_free(mt);
            return;
        }
        usleep(TDB_L0_RECLAIM_DRAIN_STALL_US);
    }

    if (!l0)
    {
        tidesdb_memtable_free(mt);
        return;
    }

    l0_pending_node_t *node = malloc(sizeof(*node));
    if (!node)
    {
        /* nowhere to defer it to, so the old inline wait is the only option left */
        tdb_epoch_wait_drained(&l0->active_readers);
        while (atomic_load_explicit(&mt->refcount, memory_order_acquire) > TDB_L0_MEMTABLE_BASELINE)
            usleep(TDB_L0_RECLAIM_DRAIN_STALL_US);
        tidesdb_memtable_free(mt);
        return;
    }
    node->mt = mt;
    l0_pending_push(l0, node);
}
