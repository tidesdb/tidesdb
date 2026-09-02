/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_MEMTABLE_BACKPRESSURE_H__
#define __TIDESDB_MEMTABLE_BACKPRESSURE_H__

#include "../compat.h"

/* pluggable write backpressure for L0. as the L0 queue of unflushed immutables fills, a writer must
 * be paced so ingestion cannot outrun the flush that drains the queue. this module is only the
 * decision -- given a snapshot of L0 pressure it returns whether a writer should proceed now, dwell
 * briefly, or block until the queue drains. the waiting itself lives in the L0 subsystem, which
 * owns the queue and the condition variable; keeping the policy a pure function makes it swappable
 * and testable without threads. the default policy admits below a high-water fraction of the queue
 * limit, throttles with a rising dwell inside the band, and blocks at the peak. */

/**
 * tidesdb_l0_pressure_t
 * a snapshot of L0 fill the backpressure policy decides on
 * @param queue_depth immutables currently sitting in the L0 queue awaiting flush
 * @param queue_limit configured peak L0 queue depth, or <= 0 for unbounded (never blocks)
 * @param buffer_size rotation threshold in bytes for the active L0 memtable
 * @param flush_in_progress non-zero while a flush is draining the queue
 * @param wal_ring_bytes capacity of the write-ahead log's staging ring, or 0 when the producer did
 * not weigh it
 * @param wal_lag_bytes bytes reserved in that ring the flush thread has not yet written. this is
 * the pressure that matters most and the queue cannot show: an appender whose ring slot still holds
 * unwritten bytes stops dead until the flush thread reaches it, so the ring is a wall rather than a
 * gradient unless a policy slows ingest before it fills
 * @param tier_depth the deepest flush tier across the families, in runs. the queue says whether
 * flush keeps up; this says whether merging does, and they fail independently -- a burst can drain
 * out of memory promptly and still leave a tier of runs every later read has to merge across
 * @param tier_slow runs at which a writer starts dwelling, or 0 to weigh the tier not at all
 * @param tier_stall runs at which a writer waits for the tier to drain
 */
typedef struct
{
    int queue_depth;
    int queue_limit;
    size_t buffer_size;
    int flush_in_progress;
    size_t wal_ring_bytes;
    size_t wal_lag_bytes;
    int tier_depth;
    int tier_slow;
    int tier_stall;
} tidesdb_l0_pressure_t;

/**
 * tidesdb_backpressure_action_t
 * what a writer should do under the current L0 pressure
 * @param TDB_BACKPRESSURE_ADMIT proceed with the write now
 * @param TDB_BACKPRESSURE_THROTTLE dwell for throttle_us then proceed
 * @param TDB_BACKPRESSURE_BLOCK wait until the L0 queue drains below the peak, then re-evaluate
 */
typedef enum
{
    TDB_BACKPRESSURE_ADMIT,
    TDB_BACKPRESSURE_THROTTLE,
    TDB_BACKPRESSURE_BLOCK
} tidesdb_backpressure_action_t;

/**
 * tidesdb_backpressure_decision_t
 * a policy's verdict for one writer
 * @param action admit, throttle, or block
 * @param throttle_us dwell time in microseconds when action is throttle, else 0
 */
typedef struct
{
    tidesdb_backpressure_action_t action;
    uint64_t throttle_us;
} tidesdb_backpressure_decision_t;

/**
 * tidesdb_backpressure_policy_fn
 * a pluggable policy -- a pure function mapping L0 pressure to a writer verdict
 * @param pressure the current L0 pressure snapshot
 * @param ctx opaque policy context supplied at construction
 * @return the verdict for a writer under this pressure
 */
typedef tidesdb_backpressure_decision_t (*tidesdb_backpressure_policy_fn)(
    const tidesdb_l0_pressure_t *pressure, void *ctx);

typedef struct tidesdb_backpressure tidesdb_backpressure_t;

/**
 * tidesdb_backpressure_new
 * create a backpressure controller bound to a policy; passing NULL policy installs the default
 * @param policy the decision policy, or NULL for tidesdb_backpressure_default_policy
 * @param ctx opaque context passed to the policy on every decision
 * @return the controller, or NULL on allocation failure
 */
tidesdb_backpressure_t *tidesdb_backpressure_new(tidesdb_backpressure_policy_fn policy, void *ctx);

/**
 * tidesdb_backpressure_free
 * free a backpressure controller
 * @param bp the controller, may be NULL
 */
void tidesdb_backpressure_free(tidesdb_backpressure_t *bp);

/**
 * tidesdb_backpressure_decide
 * ask the controller's policy what a writer should do under the given pressure; a pure query with
 * no waiting, so the L0 subsystem can drive throttle/block itself and tests can assert on the
 * verdict
 * @param bp the controller
 * @param pressure the current L0 pressure snapshot
 * @return the policy verdict, or an admit verdict if bp is NULL
 */
tidesdb_backpressure_decision_t tidesdb_backpressure_decide(const tidesdb_backpressure_t *bp,
                                                            const tidesdb_l0_pressure_t *pressure);

/**
 * tidesdb_backpressure_default_policy
 * the built-in policy: admit below the high-water fraction of the queue limit, throttle with a
 * dwell that rises as depth climbs through the band, and block at or above the peak; an unbounded
 * limit
 * (<= 0) always admits
 * @param pressure the current L0 pressure snapshot
 * @param ctx unused
 * @return the verdict for a writer under this pressure
 */
tidesdb_backpressure_decision_t tidesdb_backpressure_default_policy(
    const tidesdb_l0_pressure_t *pressure, void *ctx);

#endif /* __TIDESDB_MEMTABLE_BACKPRESSURE_H__ */
