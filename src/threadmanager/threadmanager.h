/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_THREADMANAGER_H__
#define __TIDESDB_THREADMANAGER_H__

#include "../base/bg_pool.h"
#include "../base/bg_ticker.h"
#include "../compat.h"

/* maximum length of a background-process label, including the terminating nul */
#define THREADMANAGER_LABEL_MAX 48

/* one central place that owns every background process the engine runs -- the flush and compaction
 * worker pools, and the wal-sync and decomposed-reaper tickers -- each under a label so they can be
 * stopped together in reverse registration order and enumerated for observability. it owns the
 * pool/ticker handles and stops them; it does not own the queues a pool drains. */

/**
 * threadmanager_kind_t
 * whether a registered background process is a worker pool or a periodic ticker
 * @param THREADMANAGER_POOL a bg_pool worker pool
 * @param THREADMANAGER_TICKER a bg_ticker periodic task
 */
typedef enum
{
    THREADMANAGER_POOL,
    THREADMANAGER_TICKER
} threadmanager_kind_t;

/**
 * threadmanager_proc_t
 * one labeled background process managed by the registry
 * @param label human-readable name, e.g. "flush" or "reaper.deferred_free"
 * @param kind whether the handle is a pool or a ticker
 * @param handle the process itself, read as handle.pool when kind is THREADMANAGER_POOL and as
 *               handle.ticker when it is THREADMANAGER_TICKER
 */
typedef struct
{
    char label[THREADMANAGER_LABEL_MAX];
    threadmanager_kind_t kind;
    union
    {
        bg_pool_t *pool;
        bg_ticker_t *ticker;
    } handle;
} threadmanager_proc_t;

typedef struct threadmanager threadmanager_t;

/**
 * threadmanager_new
 * create an empty background-process registry
 * @return the registry, or NULL on allocation failure
 */
threadmanager_t *threadmanager_new(void);

/**
 * threadmanager_add_pool
 * register an already-started worker pool under a label
 * @param reg the registry
 * @param label process name, truncated to THREADMANAGER_LABEL_MAX-1 characters
 * @param pool the started pool to take ownership of; NULL is rejected
 * @return 0 on success, -1 on bad args or allocation failure
 */
int threadmanager_add_pool(threadmanager_t *reg, const char *label, bg_pool_t *pool);

/**
 * threadmanager_add_ticker
 * register an already-started ticker under a label
 * @param reg the registry
 * @param label process name, truncated to THREADMANAGER_LABEL_MAX-1 characters
 * @param ticker the started ticker to take ownership of; NULL is rejected
 * @return 0 on success, -1 on bad args or allocation failure
 */
int threadmanager_add_ticker(threadmanager_t *reg, const char *label, bg_ticker_t *ticker);

/**
 * threadmanager_wake
 * wake the ticker registered under label so it runs its next tick now; a no-op for a pool label or
 * an unknown label
 * @param reg the registry
 * @param label the ticker's label
 */
void threadmanager_wake(threadmanager_t *reg, const char *label);

/**
 * threadmanager_count
 * the number of registered background processes
 * @param reg the registry
 * @return the count, or 0 if reg is NULL
 */
int threadmanager_count(const threadmanager_t *reg);

/**
 * threadmanager_at
 * borrow the entry at an index for introspection (label, kind, handle)
 * @param reg the registry
 * @param index 0-based index in registration order
 * @return the entry, or NULL if the index is out of range
 */
const threadmanager_proc_t *threadmanager_at(const threadmanager_t *reg, int index);

/**
 * threadmanager_stop
 * stop the process registered under label and remove it from the registry, so the caller controls
 * teardown order at load-bearing points; threadmanager_stop_all mops up whatever remains. only the
 * first match is stopped. a no-op for an unknown label.
 * @param reg the registry
 * @param label the process to stop
 * @return 0 if a process was stopped, -1 on bad args or an unknown label
 */
int threadmanager_stop(threadmanager_t *reg, const char *label);

/**
 * threadmanager_stop_all
 * stop every remaining registered process in reverse registration order (each pool via
 * bg_pool_stop, each ticker via bg_ticker_stop), then free the registry. safe with NULL.
 * @param reg the registry to stop and free
 */
void threadmanager_stop_all(threadmanager_t *reg);

#endif /* __TIDESDB_THREADMANAGER_H__ */
