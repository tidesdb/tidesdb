/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "thread.h"

/**
 * tdb_thread_run
 * run the body, then report the exit. nothing in t is touched after the unlock, since the waiter
 * may release t the moment it sees finished
 * @param arg the tdb_thread_t
 * @return NULL
 */
static void *tdb_thread_run(void *arg)
{
    tdb_thread_t *t = arg;
    (void)t->fn(t->arg);
    pthread_mutex_lock(&t->mtx);
    t->finished = 1;
    pthread_cond_broadcast(&t->cv);
    pthread_mutex_unlock(&t->mtx);
    return NULL;
}

int tdb_thread_start(tdb_thread_t *t, tdb_thread_fn fn, void *arg)
{
    if (!t || !fn) return -1;
    t->fn = fn;
    t->arg = arg;
    t->finished = 0;
    if (pthread_mutex_init(&t->mtx, NULL) != 0) return -1;
    if (pthread_cond_init(&t->cv, NULL) != 0)
    {
        pthread_mutex_destroy(&t->mtx);
        return -1;
    }
    pthread_t tid;
    if (pthread_create(&tid, NULL, tdb_thread_run, t) != 0)
    {
        pthread_cond_destroy(&t->cv);
        pthread_mutex_destroy(&t->mtx);
        return -1;
    }
    (void)pthread_detach(tid);
    return 0;
}

void tdb_thread_finish(tdb_thread_t *t)
{
    if (!t) return;
    pthread_mutex_lock(&t->mtx);
    while (!t->finished) pthread_cond_wait(&t->cv, &t->mtx);
    pthread_mutex_unlock(&t->mtx);
    pthread_cond_destroy(&t->cv);
    pthread_mutex_destroy(&t->mtx);
}
