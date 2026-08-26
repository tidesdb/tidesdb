/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "bg_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <signal.h>
#endif

#include "log.h"

/* max stored thread-name prefix, sized to the 16-char os thread-name limit so the final
 * "<prefix>.<index>" is truncated by snprintf rather than overrunning */
#define BG_POOL_NAME_MAX 16

/**
 * bg_pool
 * a fixed worker-thread pool draining a shared queue, with its thread-lifecycle state
 * @param threads array of worker thread handles
 * @param num_threads number of threads created, the length of threads
 * @param live count of worker threads still running
 * @param queue the caller-owned work queue the workers drain
 * @param worker callback invoked per dequeued item
 * @param ctx opaque context passed to every worker call
 * @param name_prefix thread-name prefix, empty when the pool is unnamed and unmasked
 */
struct bg_pool
{
    pthread_t *threads;
    int num_threads;
    _Atomic(int) live;
    queue_t *queue;
    bg_pool_worker_fn worker;
    void *ctx;
    char name_prefix[BG_POOL_NAME_MAX];
};

/**
 * bg_pool_thread_arg
 * per-thread startup argument carrying the owning pool and this thread's index for naming
 * @param pool the owning pool
 * @param index this thread's 0-based index, used to name it
 */
typedef struct
{
    bg_pool_t *pool;
    int index;
} bg_pool_thread_arg;

#ifndef _WIN32
/* block the process timer signals on the calling thread so a blocking dequeue or syscall is not
 * restarted by an interval or profiling timer */
static void bg_pool_block_timer_signals(void)
{
    sigset_t timer_signals;
    sigemptyset(&timer_signals);
    sigaddset(&timer_signals, SIGALRM);
    sigaddset(&timer_signals, SIGVTALRM);
    sigaddset(&timer_signals, SIGPROF);
    pthread_sigmask(SIG_BLOCK, &timer_signals, NULL);
}
#endif

static void *bg_pool_thread(void *arg)
{
    bg_pool_thread_arg *targ = (bg_pool_thread_arg *)arg;
    bg_pool_t *pool = targ->pool;
    const int index = targ->index;
    free(targ);

    /* a named pool is the managed engine-worker flavor -- name the thread and mask timer signals */
    if (pool->name_prefix[0])
    {
        /* sized so "<prefix>.<index>" never truncates here; tdb_set_thread_name caps it to the os
         * thread-name limit when it is set */
        char tname[BG_POOL_NAME_MAX + 16];
        snprintf(tname, sizeof(tname), "%s.%d", pool->name_prefix, index);
        tdb_set_thread_name(tname);
#ifndef _WIN32
        bg_pool_block_timer_signals();
#endif
    }

    /* queue_dequeue_wait blocks until an item is available and returns NULL once the queue is shut
     * down, which is how a worker learns to exit. an item mid-flight finishes before the next wait
     */
    void *item;
    while ((item = queue_dequeue_wait(pool->queue)) != NULL) pool->worker(item, pool->ctx);
    atomic_fetch_sub_explicit(&pool->live, 1, memory_order_release);
    return NULL;
}

/* shared implementation behind bg_pool_start and bg_pool_start_named; a NULL or empty name_prefix
 * leaves threads unnamed and unmasked */
static bg_pool_t *bg_pool_start_impl(const int num_threads, queue_t *queue, const char *name_prefix,
                                     bg_pool_worker_fn worker, void *ctx)
{
    if (num_threads < 1 || !queue || !worker) return NULL;

    bg_pool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    pool->threads = calloc((size_t)num_threads, sizeof(pthread_t));
    if (!pool->threads)
    {
        free(pool);
        return NULL;
    }
    pool->queue = queue;
    pool->worker = worker;
    pool->ctx = ctx;
    atomic_init(&pool->live, 0);
    if (name_prefix)
    {
        strncpy(pool->name_prefix, name_prefix, BG_POOL_NAME_MAX - 1);
        pool->name_prefix[BG_POOL_NAME_MAX - 1] = '\0';
    }

    for (int i = 0; i < num_threads; i++)
    {
        bg_pool_thread_arg *targ = malloc(sizeof(*targ));
        if (targ)
        {
            targ->pool = pool;
            targ->index = i;
        }
        atomic_fetch_add_explicit(&pool->live, 1, memory_order_acq_rel);
        if (!targ || pthread_create(&pool->threads[i], NULL, bg_pool_thread, targ) != 0)
        {
            /* creation failed -- free the unused arg, undo this slot's live bump, then shut down
             * and join whatever did start so the caller never leaks a half-built pool */
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "could not start worker %d of %d for pool %s", i,
                          num_threads, pool->name_prefix[0] ? pool->name_prefix : "unnamed");
            free(targ);
            atomic_fetch_sub_explicit(&pool->live, 1, memory_order_release);
            pool->num_threads = i;
            bg_pool_stop(pool);
            return NULL;
        }
    }

    pool->num_threads = num_threads;
    return pool;
}

bg_pool_t *bg_pool_start(const int num_threads, queue_t *queue, bg_pool_worker_fn worker, void *ctx)
{
    return bg_pool_start_impl(num_threads, queue, NULL, worker, ctx);
}

bg_pool_t *bg_pool_start_named(int num_threads, queue_t *queue, const char *name_prefix,
                               bg_pool_worker_fn worker, void *ctx)
{
    return bg_pool_start_impl(num_threads, queue, name_prefix, worker, ctx);
}

void bg_pool_stop(bg_pool_t *pool)
{
    if (!pool) return;
    queue_shutdown(pool->queue);
    for (int i = 0; i < pool->num_threads; i++)
        if (pool->threads) pthread_join(pool->threads[i], NULL);
    free(pool->threads);
    free(pool);
}

int bg_pool_live_threads(const bg_pool_t *pool)
{
    return pool ? atomic_load_explicit(&pool->live, memory_order_acquire) : 0;
}
