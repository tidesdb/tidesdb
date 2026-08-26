/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_BG_POOL_H__
#define __TIDESDB_BASE_BG_POOL_H__

#include "datastructures/queue.h"

/* a fixed pool of worker threads that each drain a shared work queue and hand every dequeued item
 * to a worker callback. the flush and compaction pools are instances -- the pthread
 * lifecycle (create, shutdown-signal, join, live count) lives here rather than being hand-rolled
 * per pool. the queue is caller-owned; the pool neither creates nor frees it. */
typedef struct bg_pool bg_pool_t;

/* process one dequeued item; ctx is the shared context handed to bg_pool_start */
typedef void (*bg_pool_worker_fn)(void *item, void *ctx);

/**
 * bg_pool_start
 * start num_threads worker threads, each blocking on the queue and calling worker(item, ctx) for
 * every item dequeued, until the queue is shut down
 * @param num_threads number of worker threads to start (must be >= 1)
 * @param queue the caller-owned work queue to drain
 * @param worker callback invoked per dequeued item
 * @param ctx opaque context passed to every worker call
 * @return the pool, or NULL on allocation or thread-creation failure (any started threads are
 * joined)
 */
bg_pool_t *bg_pool_start(int num_threads, queue_t *queue, bg_pool_worker_fn worker, void *ctx);

/**
 * bg_pool_start_named
 * like bg_pool_start, but each worker thread is named "<name_prefix>.<i>" for observability and
 * blocks the process timer signals (SIGALRM/SIGVTALRM/SIGPROF) so a blocking dequeue or i/o syscall
 * is not restarted by an interval or profiling timer -- the flavor every engine worker pool wants
 * @param num_threads number of worker threads to start (must be >= 1)
 * @param queue the caller-owned work queue to drain
 * @param name_prefix thread-name prefix, truncated so the final "<prefix>.<i>" fits the os name
 * limit
 * @param worker callback invoked per dequeued item
 * @param ctx opaque context passed to every worker call
 * @return the pool, or NULL on allocation or thread-creation failure (any started threads are
 * joined)
 */
bg_pool_t *bg_pool_start_named(int num_threads, queue_t *queue, const char *name_prefix,
                               bg_pool_worker_fn worker, void *ctx);

/**
 * bg_pool_stop
 * shut the queue down so blocked workers wake, join every worker thread, and free the pool. the
 * queue itself is not freed. safe to call with NULL.
 * @param pool the pool to stop
 */
void bg_pool_stop(bg_pool_t *pool);

/**
 * bg_pool_live_threads
 * the number of worker threads still running
 * @param pool the pool
 * @return live worker-thread count, 0 if pool is NULL
 */
int bg_pool_live_threads(const bg_pool_t *pool);

#endif /* __TIDESDB_BASE_BG_POOL_H__ */
