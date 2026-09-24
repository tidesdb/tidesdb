/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_THREAD_H__
#define __TIDESDB_BASE_THREAD_H__

#include "../compat.h"

/* a thread the engine starts and later waits for, without ever joining it.
 *
 * a join is how a thread absorbs the exited thread's scheduling history on netbsd, whose scheduler
 * adds the joined thread's cpu estimate to the joiner unclamped and hands a new thread its
 * creator's estimate unchanged. a thread that has joined enough hot threads then sits below the
 * priority any running thread can settle at, and so does every thread it creates, and none of them
 * runs again while a busier thread is runnable. so a thread here is detached at birth and reports
 * its own exit on a condition variable, which is what the waiter waits for */

/**
 * tdb_thread_fn
 * the body of a thread started through tdb_thread_start
 * @param arg the argument given to tdb_thread_start
 * @return ignored, the shape is kept so an existing pthread body can be started unchanged
 */
typedef void *(*tdb_thread_fn)(void *arg);

/**
 * tdb_thread_t
 * one started thread and the signal it exits on
 * @param fn the body to run
 * @param arg the body's argument
 * @param mtx guards finished and the wait on it
 * @param cv signalled once by the thread as its last act
 * @param finished 1 once the body has returned
 */
typedef struct
{
    tdb_thread_fn fn;
    void *arg;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int finished;
} tdb_thread_t;

/**
 * tdb_thread_start
 * start a detached thread running fn(arg) and arm the exit signal the caller will wait for
 * @param t the thread, owned by the caller and kept in place until tdb_thread_finish returns
 * @param fn the body to run
 * @param arg passed to fn
 * @return 0 on success, -1 when the thread could not be started, leaving t unarmed
 */
int tdb_thread_start(tdb_thread_t *t, tdb_thread_fn fn, void *arg);

/**
 * tdb_thread_finish
 * wait until the thread's body has returned, then release the signal, without joining the thread
 * @param t a thread that tdb_thread_start started
 */
void tdb_thread_finish(tdb_thread_t *t);

#endif /* __TIDESDB_BASE_THREAD_H__ */
