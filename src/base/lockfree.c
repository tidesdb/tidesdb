/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "lockfree.h"

#include <stdlib.h>

#include "log.h" /* TDB_DEBUG_LOG for the one path that cannot reclaim what it was given */

/**
 * tdb_retire_node
 * one retired item on the lock-free reclamation stack
 * @param item the opaque item to reclaim
 * @param guard the epoch that must drain before item may be reclaimed
 * @param reclaim callback that reclaims item
 * @param ctx opaque context passed to reclaim
 * @param next next node in the stack
 */
struct tdb_retire_node
{
    void *item;
    tdb_epoch_t *guard;
    tdb_reclaim_fn reclaim;
    void *ctx;
    tdb_retire_node_t *next;
};

void tdb_epoch_wait_drained(tdb_epoch_t *e)
{
    while (tdb_epoch_active(e) > 0) cpu_yield();
}

int tdb_try_ref(tdb_refcount_t *rc)
{
    /* only increment from a positive count. a count of 0 means the object is being freed and must
     * not be touched; a negative count is the evicting window, waited out with escalating backoff
     * because returning 0 there would be indistinguishable from a freed object and would drop a
     * live one. */
    int old = atomic_load_explicit(rc, memory_order_acquire);
    int evict_spins = 0;
    for (;;)
    {
        if (old > 0)
        {
            if (atomic_compare_exchange_weak_explicit(rc, &old, old + 1, memory_order_acq_rel,
                                                      memory_order_acquire))
                return 1;
            /* CAS failed, old was refreshed, retry */
        }
        else if (old == 0)
        {
            return 0;
        }
        else
        {
            if (++evict_spins < TDB_REFCOUNT_DRAIN_SPIN_THRESHOLD)
                cpu_pause();
            else if (evict_spins < TDB_REFCOUNT_DRAIN_YIELD_THRESHOLD)
                cpu_yield();
            else if (evict_spins < TDB_EVICT_WAIT_MAX)
                usleep(TDB_REFCOUNT_DRAIN_SLEEP_US);
            else
                /* only reachable if a window were held far past any real close. it is a wrong
                 * answer rather than a slow one -- the one caller that reads through this reports
                 * a value it could not acquire as absent -- so the windows are kept to a couple of
                 * atomics, with the expensive part of a close outside them. widening one turns
                 * this into a live value read as missing */
                return 0;
            old = atomic_load_explicit(rc, memory_order_acquire);
        }
    }
}

int tdb_refcount_begin_evict(tdb_refcount_t *rc, int baseline)
{
    int expected = baseline;
    return atomic_compare_exchange_strong(rc, &expected, TDB_REFCOUNT_EVICTING);
}

/* push a node onto the lock-free stack head */
static void retire_push(tdb_retire_list_t *list, tdb_retire_node_t *node)
{
    tdb_retire_node_t *old_head = atomic_load_explicit(&list->head, memory_order_acquire);
    do
    {
        node->next = old_head;
    } while (!atomic_compare_exchange_weak_explicit(&list->head, &old_head, node,
                                                    memory_order_release, memory_order_acquire));
}

/* run a node's reclaim callback and free the node */
static void retire_reclaim_node(tdb_retire_node_t *node)
{
    node->reclaim(node->item, node->ctx);
    free(node);
}

void tdb_retire(tdb_retire_list_t *list, void *item, tdb_epoch_t *guard, tdb_reclaim_fn reclaim,
                void *ctx)
{
    /* brief spin for the common case of readers finishing quickly, then reclaim inline */
    for (int i = 0; i < TDB_RETIRE_SPIN_ATTEMPTS; i++)
    {
        if (tdb_epoch_active(guard) == 0)
        {
            reclaim(item, ctx);
            return;
        }
        cpu_pause();
    }

    tdb_retire_node_t *node = malloc(sizeof(*node));
    if (!node)
    {
        /* no node to defer onto, so the only way to reclaim is to wait the readers out here. that
         * wait is for a moment with no reader at all, which the guard this most often runs against
         * -- a level set, entered by every read of it -- may not have while the database is being
         * read. so it is bounded, and an item whose readers never all left together is given up on
         * rather than spun on: leaking one layout under an allocation failure costs memory, and
         * hanging the thread that was trying to free it costs the database */
        for (int i = 0; i < TDB_RETIRE_OOM_DRAIN_ATTEMPTS; i++)
        {
            if (tdb_epoch_active(guard) == 0)
            {
                reclaim(item, ctx);
                return;
            }
            cpu_yield();
        }
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "no memory to defer a reclaim and its readers did not clear, leaking it");
        return;
    }

    node->item = item;
    node->guard = guard;
    node->reclaim = reclaim;
    node->ctx = ctx;
    retire_push(list, node);
}

void tdb_retire_sweep(tdb_retire_list_t *list)
{
    tdb_retire_node_t *current = atomic_exchange_explicit(&list->head, NULL, memory_order_acq_rel);
    while (current)
    {
        tdb_retire_node_t *next = current->next;
        if (tdb_epoch_active(current->guard) == 0)
            retire_reclaim_node(current);
        else
            retire_push(list, current);
        current = next;
    }
}

void tdb_retire_drain(tdb_retire_list_t *list, tdb_retire_match_fn match, void *ctx)
{
    tdb_retire_node_t *current = atomic_exchange_explicit(&list->head, NULL, memory_order_acq_rel);
    tdb_retire_node_t *keep = NULL;

    while (current)
    {
        tdb_retire_node_t *next = current->next;
        if (!match || match(current->item, current->guard, ctx))
        {
            /* the caller contract is that the guarded readers are quiescing; spin defensively
             * rather than risk reclaiming under a straggler */
            tdb_epoch_wait_drained(current->guard);
            retire_reclaim_node(current);
        }
        else
        {
            current->next = keep;
            keep = current;
        }
        current = next;
    }

    while (keep)
    {
        tdb_retire_node_t *next = keep->next;
        retire_push(list, keep);
        keep = next;
    }
}
