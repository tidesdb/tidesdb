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
 * latency tail is made of, so the longest is kept beside it.
 *
 * nothing here is decided on, only reported, so the counters are relaxed -- with one exception. a
 * reader compares the longest against the total it sits inside, and two relaxed publications can be
 * seen in either order, which hands that reader a longest larger than the sum containing it. the
 * longest is therefore released by the writer and acquired by the reader, at both counters. */

/**
 * tdb_wait_stat_t
 * one wait point's totals
 * @param count how many times a thread waited here
 * @param total_us the summed wait
 * @param max_us the longest single wait
 */
typedef struct
{
    _Atomic(uint64_t) count;
    _Atomic(uint64_t) total_us;
    _Atomic(uint64_t) max_us;
} tdb_wait_stat_t;

/**
 * tdb_wait_init
 * bring a wait point up at zero. worth a function rather than three stores at each site: a wait
 * point living in a malloc'd struct starts as whatever the allocator returned, and a missed field
 * does not fail a build or a read -- it surfaces as a longest wait larger than the total containing
 * it, on whichever platform's allocator happened to leave a large value there
 * @param w the wait point
 */
static inline void tdb_wait_init(tdb_wait_stat_t *w)
{
    atomic_init(&w->count, 0);
    atomic_init(&w->total_us, 0);
    atomic_init(&w->max_us, 0);
}

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

/* nanoseconds in a microsecond and in a second, and microseconds in a second, for building a
 * deadline out of a duration */
#define TDB_NS_PER_US  1000L
#define TDB_NS_PER_SEC 1000000000L
#define TDB_US_PER_SEC 1000000ull

/**
 * tdb_wait_deadline
 * an absolute deadline this many microseconds from now, for a timed condition wait
 *
 * built on whichever clock the condition variable was pinned to, which is the monotonic one
 * wherever that can be selected. the two have to agree or the deadline means nothing
 * @param ts filled with the deadline
 * @param us how far ahead to place it
 */
static inline void tdb_wait_deadline(struct timespec *ts, uint64_t us)
{
#if TDB_COND_CLOCK_SELECTABLE
    clock_gettime(CLOCK_MONOTONIC, ts);
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
    /* whole seconds are added as seconds rather than folded through the nanosecond field, which a
     * multi-second interval would overflow where long is 32 bits */
    ts->tv_sec += (time_t)(us / TDB_US_PER_SEC);
    ts->tv_nsec += (long)((us % TDB_US_PER_SEC) * TDB_NS_PER_US);
    if (ts->tv_nsec >= TDB_NS_PER_SEC)
    {
        ts->tv_sec += 1;
        ts->tv_nsec -= TDB_NS_PER_SEC;
    }
}

/**
 * tdb_cond_init_monotonic
 * initialize a condition variable on the clock tdb_wait_deadline builds its deadlines from
 *
 * the two have to agree or a timed wait means nothing, so they are settled in one place. where the
 * clock can be selected that is the monotonic one, which a wall clock step cannot move -- an ntp
 * correction or a hypervisor resuming a guest it had suspended otherwise parks every waiter until
 * an absolute time that has walked away from them, and they all wake together in a burst when it
 * finally comes round
 * @param cv the condition variable to initialize
 * @return 0 on success, non-zero on failure
 */
static inline int tdb_cond_init_monotonic(pthread_cond_t *cv)
{
#if TDB_COND_CLOCK_SELECTABLE
    pthread_condattr_t cattr;
    if (pthread_condattr_init(&cattr) != 0) return -1;
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
    const int rc = pthread_cond_init(cv, &cattr);
    pthread_condattr_destroy(&cattr);
    return rc;
#else
    return pthread_cond_init(cv, NULL);
#endif
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
    /* released, so a reader that sees this sample in the longest also sees it in the total it was
     * added to. relaxed here would let a weakly ordered machine publish the two in either order and
     * hand a reader a longest wait larger than the sum containing it */
    uint64_t seen = atomic_load_explicit(&w->max_us, memory_order_relaxed);
    while (waited_us > seen &&
           !atomic_compare_exchange_weak_explicit(&w->max_us, &seen, waited_us,
                                                  memory_order_release, memory_order_relaxed))
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
    /* the longest is read before the total, and the note above raises the total before the longest,
     * so the two can only be seen in an order that keeps total >= max. read the other way round a
     * sample landing between the two loads is counted in the longest but not yet in the total, and
     * a caller comparing them sees a longest wait larger than the sum containing it -- most easily
     * on a counter whose total is still small, where one large sample outweighs everything before
     * it */
    *out_max_us = atomic_load_explicit(&w->max_us, memory_order_acquire);
    *out_total_us = atomic_load_explicit(&w->total_us, memory_order_relaxed);
    *out_count = atomic_load_explicit(&w->count, memory_order_relaxed);
}

/**
 * tdb_io_stat_t
 * what one class of file was asked to write. bytes over total_us gives the throughput that class
 * actually achieved, which is what says whether a device is saturated or merely idle behind a
 * bottleneck somewhere else
 * @param ops writes issued
 * @param bytes bytes written
 * @param total_us the summed time inside those writes
 * @param max_us the slowest single write
 */
typedef struct
{
    _Atomic(uint64_t) ops;
    _Atomic(uint64_t) bytes;
    _Atomic(uint64_t) total_us;
    _Atomic(uint64_t) max_us;
} tdb_io_stat_t;

/**
 * tdb_io_init
 * put a class's totals at zero, so an accounting context is fully initialized by its own init
 * rather than by however its owner happened to allocate it
 * @param io the class to zero
 */
static inline void tdb_io_init(tdb_io_stat_t *io)
{
    if (!io) return;
    atomic_init(&io->ops, 0);
    atomic_init(&io->bytes, 0);
    atomic_init(&io->total_us, 0);
    atomic_init(&io->max_us, 0);
}

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
    /* released for the same reason tdb_wait_note releases its own: a reader that sees this write in
     * the slowest must also see it in the total it was added to */
    uint64_t seen = atomic_load_explicit(&io->max_us, memory_order_relaxed);
    while (elapsed_us > seen &&
           !atomic_compare_exchange_weak_explicit(&io->max_us, &seen, elapsed_us,
                                                  memory_order_release, memory_order_relaxed))
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
    /* the slowest first and acquired, the total after, so the pair can only be seen in an order
     * that keeps total >= max -- the same read tdb_wait_read makes for the same reason */
    *out_max_us = atomic_load_explicit(&io->max_us, memory_order_acquire);
    *out_total_us = atomic_load_explicit(&io->total_us, memory_order_relaxed);
    *out_ops = atomic_load_explicit(&io->ops, memory_order_relaxed);
    *out_bytes = atomic_load_explicit(&io->bytes, memory_order_relaxed);
}

#endif /* __TIDESDB_BASE_WAITSTAT_H__ */
