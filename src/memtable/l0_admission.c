/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "base/log.h"
#include "base/waitstat.h" /* tdb_monotonic_us, for a wait bounded by real time */
#include "memtable/memtable.h"

/* the L0 side of backpressure. backpressure.c decides -- given a pressure snapshot it returns
 * admit, throttle or block -- and this reads the pressure, applies the decision on the committing
 * thread, and counts what it did. the two are apart because the policy is a pure function over
 * numbers and is tested as one, while everything here touches the live queue */

/* how long a blocked writer parks before looking again on its own. it is woken when the backlog
 * moves, so this only bounds the cost of a wake lost to the race between deciding and waiting */
#define TDB_L0_BACKPRESSURE_PARK_US 20000

/* how long a writer waits for the queue to drain before it is admitted anyway. this is wall clock
 * rather than a count of polls, because a poll does not reliably sleep for as long as it asks: on
 * windows the wait is rounded to the millisecond, so a sub-millisecond one can return at once and a
 * counted bound would expire in the time it takes to spin the loop rather than in the seconds it
 * was meant to describe */
#define TDB_L0_BACKPRESSURE_CEILING_US 2000000ull
#define TDB_L0_BACKPRESSURE_LOG_EVERY  1000

/* runs in the flush tier at which a writer starts dwelling, and at which it waits for the tier to
 * drain. the compaction trigger sits below both, so merging is already underway before ingestion is
 * slowed and well underway before it is stopped */
#define TDB_L0_TIER_SLOW_RUNS  8
#define TDB_L0_TIER_STALL_RUNS 20

/**
 * l0_admission_snapshot
 * read current L0 fill into the pressure snapshot the backpressure policy decides on
 * @param l0 the subsystem
 * @param out out -- the pressure snapshot
 */
static void l0_admission_snapshot(const tidesdb_l0_t *l0, tidesdb_l0_pressure_t *out)
{
    /* zeroed first so a field added to the snapshot later reads as unweighed rather than as
     * whatever the caller's stack held. every field this producer does weigh is assigned below, and
     * the ones it deliberately does not are left with a note saying so */
    memset(out, 0, sizeof(*out));
    out->queue_depth = (int)queue_size(l0->queue);
    out->queue_limit = l0->l0_queue_size;
    /* weighing the active memtable would cost a pinned read of the shared active slot -- three
     * contended atomics and a full barrier -- on every commit, which costs more than the pacing it
     * would buy, so admission decides on the backlog alone */
    out->active_bytes = 0;
    out->buffer_size = l0->write_buffer_size;
    out->flush_in_progress = atomic_load_explicit(&l0->flushes_in_flight, memory_order_relaxed);

    /* merge progress, which the queue cannot show: a burst can drain out of memory promptly and
     * still leave a tier of runs every later read has to merge across */
    out->tier_depth = atomic_load_explicit(&l0->tier_depth, memory_order_relaxed);
    out->tier_slow = TDB_L0_TIER_SLOW_RUNS;
    out->tier_stall = TDB_L0_TIER_STALL_RUNS;

    /* every field the policy reads has to be set here, including the ones this producer does not
     * weigh: the caller's snapshot is an uninitialised stack struct, so a field left alone is read
     * as whatever was on the stack. the staging ring is paced on the append path, which is the only
     * place holding the log pinned, so admission reports it as unweighed */
    out->wal_ring_bytes = 0;
    out->wal_lag_bytes = 0;
}

/**
 * l0_admission_note_block
 * count one writer entering the blocked wait and trace it on the first block of every sampling
 * interval, so a paced workload leaves a record without the hot path emitting a line per commit
 * @param l0 the subsystem
 * @param pressure the pressure that produced the block
 */
static void l0_admission_note_block(tidesdb_l0_t *l0, const tidesdb_l0_pressure_t *pressure)
{
    const uint64_t blocked =
        atomic_fetch_add_explicit(&l0->admits_blocked, 1, memory_order_relaxed) + 1;
    if (blocked % TDB_L0_BACKPRESSURE_LOG_EVERY == 1)
        TDB_DEBUG_LOG(TDB_LOG_TRACE, "l0 admission blocked at depth %d of %d, %d flushing",
                      pressure->queue_depth, pressure->queue_limit, pressure->flush_in_progress);
}

/**
 * l0_admission_park
 * wait for the backlog to move, or for the fallback interval, whichever comes first
 *
 * the drain is done by another thread and it says so, so this sleeps until told rather than waking
 * on a timer to find nothing changed. the timeout is a backstop, not the mechanism -- a wake that
 * arrives between this caller's decision and its wait is lost, and the cost of losing one has to be
 * one interval rather than the whole ceiling. it is far longer than the poll it replaces because it
 * is no longer how the caller learns anything, only how it bounds a lost wake
 * @param l0 the subsystem whose waiters share the condition
 */
static void l0_admission_park(tidesdb_l0_t *l0)
{
    struct timespec ts;
    tdb_wait_deadline(&ts, TDB_L0_BACKPRESSURE_PARK_US);
    pthread_mutex_lock(&l0->admit_mtx);
    (void)pthread_cond_timedwait(&l0->admit_cv, &l0->admit_mtx, &ts);
    pthread_mutex_unlock(&l0->admit_mtx);
}

void tidesdb_l0_set_tier_depth(tidesdb_l0_t *l0, const int depth)
{
    if (!l0) return;
    const int was = atomic_exchange_explicit(&l0->tier_depth, depth, memory_order_relaxed);
    /* a shallower tier is the other thing a blocked writer waits on, and the compaction that made
     * it shallower is the only one in a position to say so */
    if (depth < was) tidesdb_l0_admit_wake(l0);
}

int tidesdb_l0_admit_write(tidesdb_l0_t *l0)
{
    if (!l0) return TDB_ERR_INVALID_ARGS;

    if (!l0->backpressure) return TDB_SUCCESS;

    /* two backlogs are paced against and they fail independently: the queue of unflushed immutables
     * says whether flush keeps up, and the flush tier says whether merging does. a burst can drain
     * out of memory promptly and still leave a tier of runs every later read merges across, so an
     * empty queue is only a free admit while the tier is also shallow */
    const int tier = atomic_load_explicit(&l0->tier_depth, memory_order_relaxed);
    const int no_queue_pressure = l0->l0_queue_size <= 0 || queue_size(l0->queue) == 0;
    if (no_queue_pressure && tier < TDB_L0_TIER_SLOW_RUNS) return TDB_SUCCESS;

    uint64_t stalled_us = 0;
    int counted_block = 0;
    const uint64_t wait_started_us = tdb_monotonic_us();
    for (;;)
    {
        tidesdb_l0_pressure_t pressure;
        l0_admission_snapshot(l0, &pressure);

        const tidesdb_backpressure_decision_t decision =
            tidesdb_backpressure_decide(l0->backpressure, &pressure);
        if (decision.action == TDB_BACKPRESSURE_ADMIT) break;

        if (decision.action == TDB_BACKPRESSURE_THROTTLE)
        {
            if (decision.throttle_us > 0)
            {
                usleep((unsigned int)decision.throttle_us);
                /* measured rather than assumed, for the same reason the ceiling below is: what a
                 * sleep was asked for is not what the caller was actually held for */
                stalled_us = tdb_monotonic_us() - wait_started_us;
            }
            atomic_fetch_add_explicit(&l0->admits_throttled, 1, memory_order_relaxed);
            break;
        }

        if (!counted_block)
        {
            counted_block = 1;
            l0_admission_note_block(l0, &pressure);
        }
        l0_admission_park(l0);
        stalled_us = tdb_monotonic_us() - wait_started_us;

        /* the queue never drained inside the ceiling, so flush is not making progress; admitting
         * keeps ingestion degraded instead of hanging this writer on it forever */
        if (stalled_us >= TDB_L0_BACKPRESSURE_CEILING_US)
        {
            atomic_fetch_add_explicit(&l0->admit_ceiling_hits, 1, memory_order_relaxed);
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "l0 admission ceiling reached after %llu us at depth %d, flush is not "
                          "keeping up",
                          (unsigned long long)stalled_us, pressure.queue_depth);
            break;
        }
    }

    if (stalled_us > 0)
    {
        atomic_fetch_add_explicit(&l0->admit_stall_us, stalled_us, memory_order_relaxed);
        /* the longest single hold, which is the part a latency tail is made of; the total alone
         * cannot distinguish many short dwells from one long block */
        uint64_t seen = atomic_load_explicit(&l0->admit_max_us, memory_order_relaxed);
        while (stalled_us > seen &&
               !atomic_compare_exchange_weak_explicit(&l0->admit_max_us, &seen, stalled_us,
                                                      memory_order_release, memory_order_relaxed))
            ;
    }
    return TDB_SUCCESS;
}

void tidesdb_l0_admission_stats(const tidesdb_l0_t *l0, tidesdb_l0_admission_t *out)
{
    if (!l0 || !out) return;
    out->throttled = atomic_load_explicit(&l0->admits_throttled, memory_order_relaxed);
    out->blocked = atomic_load_explicit(&l0->admits_blocked, memory_order_relaxed);
    /* longest before total, for the reason tdb_wait_read gives -- both only rise, and an admission
     * raises the total before the longest */
    out->max_us = atomic_load_explicit(&l0->admit_max_us, memory_order_acquire);
    out->stall_us = atomic_load_explicit(&l0->admit_stall_us, memory_order_relaxed);
    out->ceiling_hits = atomic_load_explicit(&l0->admit_ceiling_hits, memory_order_relaxed);
}
