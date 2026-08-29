/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_WAITSTAT_H__
#define __TIDESDB_BASE_WAITSTAT_H__

#include "../compat.h"

/* the engine's observability counters -- where a caller waited, and what the device was asked to
 * do. a total alone cannot tell many short waits from one long one, and it is the long one a
 * latency tail is made of, so the longest is kept beside it. every field is relaxed: these are
 * reported, never decided on. */

/**
 * tdb_wait_stat_t
 * one wait point's totals
 * @field count how many times a thread waited here
 * @field total_us the summed wait
 * @field max_us the longest single wait
 */
typedef struct
{
    _Atomic(uint64_t) count;
    _Atomic(uint64_t) total_us;
    _Atomic(uint64_t) max_us;
} tdb_wait_stat_t;

/**
 * tdb_monotonic_us
 * microseconds on a monotonic clock, for measuring an interval a caller waited
 * @return the reading
 */
static inline uint64_t tdb_monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

/* nanoseconds in a microsecond and in a second, for building a deadline out of a duration */
#define TDB_NS_PER_US  1000L
#define TDB_NS_PER_SEC 1000000000L

/**
 * tdb_wait_deadline
 * an absolute deadline this many microseconds from now, for a timed condition wait
 *
 * built on whichever clock the condition variable was pinned to, which is the monotonic one
 * wherever that can be selected. the two have to agree or the deadline means nothing
 * @param ts filled with the deadline
 * @param us how far ahead to place it
 */
static inline void tdb_wait_deadline(struct timespec *ts, long us)
{
#if TDB_COND_CLOCK_SELECTABLE
    clock_gettime(CLOCK_MONOTONIC, ts);
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
    ts->tv_nsec += us * TDB_NS_PER_US;
    if (ts->tv_nsec >= TDB_NS_PER_SEC)
    {
        ts->tv_sec += ts->tv_nsec / TDB_NS_PER_SEC;
        ts->tv_nsec %= TDB_NS_PER_SEC;
    }
}

/**
 * tdb_wait_note
 * fold one observed wait into a wait point's totals
 * @param w the wait point
 * @param waited_us how long the caller was held
 */
static inline void tdb_wait_note(tdb_wait_stat_t *w, const uint64_t waited_us)
{
    atomic_fetch_add_explicit(&w->count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&w->total_us, waited_us, memory_order_relaxed);
    uint64_t seen = atomic_load_explicit(&w->max_us, memory_order_relaxed);
    while (waited_us > seen &&
           !atomic_compare_exchange_weak_explicit(&w->max_us, &seen, waited_us,
                                                  memory_order_relaxed, memory_order_relaxed))
        ;
}

/**
 * tdb_wait_read
 * copy a wait point's totals out for reporting
 * @param w the wait point
 * @param out_count out -- the wait count
 * @param out_total_us out -- the summed wait
 * @param out_max_us out -- the longest single wait
 */
static inline void tdb_wait_read(const tdb_wait_stat_t *w, uint64_t *out_count,
                                 uint64_t *out_total_us, uint64_t *out_max_us)
{
    *out_count = atomic_load_explicit(&w->count, memory_order_relaxed);
    *out_total_us = atomic_load_explicit(&w->total_us, memory_order_relaxed);
    *out_max_us = atomic_load_explicit(&w->max_us, memory_order_relaxed);
}

/**
 * tdb_io_stat_t
 * what one class of file was asked to write. bytes over total_us gives the throughput that class
 * actually achieved, which is what says whether a device is saturated or merely idle behind a
 * bottleneck somewhere else
 * @field ops writes issued
 * @field bytes bytes written
 * @field total_us the summed time inside those writes
 * @field max_us the slowest single write
 */
typedef struct
{
    _Atomic(uint64_t) ops;
    _Atomic(uint64_t) bytes;
    _Atomic(uint64_t) total_us;
    _Atomic(uint64_t) max_us;
} tdb_io_stat_t;

/**
 * tdb_io_note
 * fold one completed write into a class's totals
 * @param io the class, may be NULL for a handle no one is accounting
 * @param bytes how many bytes the write carried
 * @param elapsed_us how long it took
 */
static inline void tdb_io_note(tdb_io_stat_t *io, const uint64_t bytes, const uint64_t elapsed_us)
{
    if (!io) return;
    atomic_fetch_add_explicit(&io->ops, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&io->bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&io->total_us, elapsed_us, memory_order_relaxed);
    uint64_t seen = atomic_load_explicit(&io->max_us, memory_order_relaxed);
    while (elapsed_us > seen &&
           !atomic_compare_exchange_weak_explicit(&io->max_us, &seen, elapsed_us,
                                                  memory_order_relaxed, memory_order_relaxed))
        ;
}

/**
 * tdb_io_read
 * copy a class's totals out for reporting
 * @param io the class
 * @param out_ops out -- writes issued
 * @param out_bytes out -- bytes written
 * @param out_total_us out -- summed write time
 * @param out_max_us out -- slowest single write
 */
static inline void tdb_io_read(const tdb_io_stat_t *io, uint64_t *out_ops, uint64_t *out_bytes,
                               uint64_t *out_total_us, uint64_t *out_max_us)
{
    *out_ops = atomic_load_explicit(&io->ops, memory_order_relaxed);
    *out_bytes = atomic_load_explicit(&io->bytes, memory_order_relaxed);
    *out_total_us = atomic_load_explicit(&io->total_us, memory_order_relaxed);
    *out_max_us = atomic_load_explicit(&io->max_us, memory_order_relaxed);
}

#endif /* __TIDESDB_BASE_WAITSTAT_H__ */
