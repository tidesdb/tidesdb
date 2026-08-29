/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "bg_ticker.h"

#include <stdlib.h>
#include <time.h>

#include "log.h"
#include "waitstat.h" /* tdb_wait_deadline and the condvar clock it pairs with */

/**
 * bg_ticker
 * a periodic background task and its thread-lifecycle state
 * @param thread the worker thread running the tick loop
 * @param active 1 while the loop should keep running, cleared by stop
 * @param mtx guards the condition-variable wait
 * @param cond signals a wake or stop to cut the interval wait short
 * @param interval_us microseconds to wait between ticks
 * @param tick the periodic callback
 * @param ctx opaque context passed to tick
 */
struct bg_ticker
{
    pthread_t thread;
    _Atomic(int) active;
    pthread_mutex_t mtx;
    pthread_cond_t cond;
    uint64_t interval_us;
    bg_ticker_fn tick;
    void *ctx;
};

static void *bg_ticker_thread(void *arg)
{
    bg_ticker_t *ticker = (bg_ticker_t *)arg;
    while (atomic_load_explicit(&ticker->active, memory_order_acquire))
    {
        ticker->tick(ticker->ctx);

        pthread_mutex_lock(&ticker->mtx);
        /* re-check under the lock so a wake or stop that raced the tick is not missed */
        if (atomic_load_explicit(&ticker->active, memory_order_acquire))
        {
            struct timespec ts;
            tdb_wait_deadline(&ts, ticker->interval_us);
            pthread_cond_timedwait(&ticker->cond, &ticker->mtx, &ts);
        }
        pthread_mutex_unlock(&ticker->mtx);
    }
    return NULL;
}

bg_ticker_t *bg_ticker_start(const uint64_t interval_us, bg_ticker_fn tick, void *ctx)
{
    if (!tick) return NULL;

    bg_ticker_t *ticker = calloc(1, sizeof(*ticker));
    if (!ticker) return NULL;
    ticker->interval_us = interval_us;
    ticker->tick = tick;
    ticker->ctx = ctx;
    atomic_init(&ticker->active, 1);
    pthread_mutex_init(&ticker->mtx, NULL);
    tdb_cond_init_monotonic(&ticker->cond);

    if (pthread_create(&ticker->thread, NULL, bg_ticker_thread, ticker) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "could not start a ticker thread on a %llu us interval",
                      (unsigned long long)interval_us);
        pthread_mutex_destroy(&ticker->mtx);
        pthread_cond_destroy(&ticker->cond);
        free(ticker);
        return NULL;
    }
    return ticker;
}

void bg_ticker_wake(bg_ticker_t *ticker)
{
    if (!ticker) return;
    pthread_mutex_lock(&ticker->mtx);
    pthread_cond_signal(&ticker->cond);
    pthread_mutex_unlock(&ticker->mtx);
}

void bg_ticker_stop(bg_ticker_t *ticker)
{
    if (!ticker) return;
    atomic_store_explicit(&ticker->active, 0, memory_order_release);
    bg_ticker_wake(ticker);
    pthread_join(ticker->thread, NULL);
    pthread_mutex_destroy(&ticker->mtx);
    pthread_cond_destroy(&ticker->cond);
    free(ticker);
}
