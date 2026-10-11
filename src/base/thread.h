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

/* a thread the engine starts and later waits for.
 *
 * the wait is a join wherever a join is safe, so once it returns the thread has exited entirely,
 * its thread-local destructors and the runtime's own teardown included. a thread still tearing down
 * may hold the allocator's locks, and a process that forks in that window hands the child those
 * locks held by a thread the child does not have, so closing a database has to mean its threads
 * are gone.
 *
 * netbsd is the exception. a join is how a thread absorbs the exited thread's scheduling history
 * there, since its scheduler adds the joined thread's cpu estimate to the joiner unclamped and
 * hands a new thread its creator's estimate unchanged. a thread that has joined enough hot threads
 * then sits below the priority any running thread can settle at, and so does every thread it
 * creates, and none of them runs again while a busier thread is runnable. so on netbsd a thread is
 * detached at birth and reports the end of its body on a condition variable, which is what the
 * waiter waits for */

/* whether threads are detached and waited for by their own signal rather than joined */
#if defined(__NetBSD__)
#define TDB_THREAD_DETACHED 1
#else
#define TDB_THREAD_DETACHED 0
#endif

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
 * @param tid the thread, joined by tdb_thread_finish unless threads are detached
 */
typedef struct
{
    tdb_thread_fn fn;
    void *arg;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int finished;
    pthread_t tid;
} tdb_thread_t;

/**
 * tdb_thread_start
 * start a thread running fn(arg) and arm the exit signal the caller will wait for
 * @param t the thread, owned by the caller and kept in place until tdb_thread_finish returns
 * @param fn the body to run
 * @param arg passed to fn
 * @return 0 on success, -1 when the thread could not be started, leaving t unarmed
 */
int tdb_thread_start(tdb_thread_t *t, tdb_thread_fn fn, void *arg);

/**
 * tdb_thread_finish
 * wait until the thread has exited, by joining it, or on netbsd until its body has returned, then
 * release the signal
 * @param t a thread that tdb_thread_start started
 */
void tdb_thread_finish(tdb_thread_t *t);

#endif /* __TIDESDB_BASE_THREAD_H__ */
