/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "backpressure.h"

#include <stdlib.h>

/* the throttle band opens at this fraction of the queue limit -- below it writers are admitted,
 * from it up to the peak they dwell, at the peak they block */
#define TDB_BACKPRESSURE_HIGHWATER_NUM 3
#define TDB_BACKPRESSURE_HIGHWATER_DEN 4

/* per-slot dwell added for each queue slot filled inside the throttle band, so the delay rises as
 * depth climbs from the high-water mark toward the peak */
#define TDB_BACKPRESSURE_THROTTLE_STEP_US 200

/* the staging ring's throttle band: pacing starts once this fraction of the ring holds bytes the
 * flush thread has not written, and reaches the full dwell as it approaches capacity. the band
 * starts late on purpose -- opening it earlier makes ordinary commits pay the dwell to smooth a
 * stall only a few of them would ever have hit, which costs more in the tail than it saves */
#define TDB_BACKPRESSURE_RING_HIGHWATER_NUM 7
#define TDB_BACKPRESSURE_RING_HIGHWATER_DEN 8

/* the dwell at the top of that band, weighed against the wall it replaces: an appender whose ring
 * slot still holds unwritten bytes waits for a whole ring to drain, with every committer stopped
 * together, which is far longer than this dwell */
#define TDB_BACKPRESSURE_RING_MAX_DWELL_US 150

/**
 * tidesdb_backpressure
 * a backpressure controller binding a pluggable decision policy to its context
 * @param policy the decision policy invoked per query
 * @param ctx opaque context handed to the policy
 */
struct tidesdb_backpressure
{
    tidesdb_backpressure_policy_fn policy;
    void *ctx;
};

/* the flush tier's own band. the queue measures whether flush keeps up; this measures whether
 * merging does, and a burst can pass the first while failing the second -- memory drains promptly
 * and leaves a tier of runs behind that every later read has to merge across. Spooky's
 * implementation slows writers at one threshold of tier files and stalls them at a higher one for
 * exactly this, with the compaction trigger sitting below both
 * @param pressure the current pressure snapshot
 * @param decision the verdict so far, tightened in place
 */
static void tidesdb_backpressure_tier_throttle(const tidesdb_l0_pressure_t *pressure,
                                               tidesdb_backpressure_decision_t *decision)
{
    if (pressure->tier_slow <= 0 || decision->action == TDB_BACKPRESSURE_BLOCK) return;

    if (pressure->tier_stall > 0 && pressure->tier_depth >= pressure->tier_stall)
    {
        decision->action = TDB_BACKPRESSURE_BLOCK;
        decision->throttle_us = 0;
        return;
    }
    if (pressure->tier_depth < pressure->tier_slow) return;

    /* the dwell grows with how far past the slow mark the tier has run, and the larger of the two
     * bands wins so neither the queue's pressure nor the tier's is masked by the other */
    const uint64_t dwell = (uint64_t)(pressure->tier_depth - pressure->tier_slow + 1) *
                           TDB_BACKPRESSURE_THROTTLE_STEP_US;
    if (dwell > decision->throttle_us)
    {
        decision->action = TDB_BACKPRESSURE_THROTTLE;
        decision->throttle_us = dwell;
    }
}

/**
 * tidesdb_backpressure_ring_throttle
 * raise a verdict's dwell for staging-ring pressure, which the queue depth cannot show
 * @param pressure the snapshot, whose ring fields may be 0 when the producer did not weigh them
 * @param decision the verdict so far, raised in place and never lowered
 */
static void tidesdb_backpressure_ring_throttle(const tidesdb_l0_pressure_t *pressure,
                                               tidesdb_backpressure_decision_t *decision)
{
    if (pressure->wal_ring_bytes == 0 || decision->action == TDB_BACKPRESSURE_BLOCK) return;

    const size_t high = pressure->wal_ring_bytes * TDB_BACKPRESSURE_RING_HIGHWATER_NUM /
                        TDB_BACKPRESSURE_RING_HIGHWATER_DEN;
    if (pressure->wal_lag_bytes < high) return;

    /* scale the dwell across the band above the high-water mark, so pacing comes on gradually as
     * the ring fills rather than arriving all at once when it is already full */
    const size_t band = pressure->wal_ring_bytes - high;
    const size_t over = pressure->wal_lag_bytes - high;
    const uint64_t dwell =
        band > 0 ? (uint64_t)TDB_BACKPRESSURE_RING_MAX_DWELL_US * (over < band ? over : band) / band
                 : TDB_BACKPRESSURE_RING_MAX_DWELL_US;

    /* the queue may already have asked for more; never trade its verdict down for this one */
    if (dwell > decision->throttle_us)
    {
        decision->action = TDB_BACKPRESSURE_THROTTLE;
        decision->throttle_us = dwell;
    }
}

tidesdb_backpressure_decision_t tidesdb_backpressure_default_policy(
    const tidesdb_l0_pressure_t *pressure, void *ctx)
{
    (void)ctx;
    tidesdb_backpressure_decision_t decision = {TDB_BACKPRESSURE_ADMIT, 0};
    if (!pressure) return decision;

    /* an unbounded queue applies no queue backpressure, but the staging ring is bounded whatever
     * the queue is, so its band is evaluated either way rather than skipped with the queue's */
    if (pressure->queue_limit <= 0)
    {
        tidesdb_backpressure_ring_throttle(pressure, &decision);
        tidesdb_backpressure_tier_throttle(pressure, &decision);
        return decision;
    }

    if (pressure->queue_depth >= pressure->queue_limit)
    {
        decision.action = TDB_BACKPRESSURE_BLOCK;
        return decision;
    }

    /* clamp to at least one slot so a tiny limit still leaves an admit region below the band and an
     * empty queue never throttles */
    int high_water =
        pressure->queue_limit * TDB_BACKPRESSURE_HIGHWATER_NUM / TDB_BACKPRESSURE_HIGHWATER_DEN;
    if (high_water < 1) high_water = 1;
    if (pressure->queue_depth >= high_water)
    {
        const int over = pressure->queue_depth - high_water + 1;
        decision.action = TDB_BACKPRESSURE_THROTTLE;
        decision.throttle_us = (uint64_t)over * TDB_BACKPRESSURE_THROTTLE_STEP_US;
    }

    tidesdb_backpressure_ring_throttle(pressure, &decision);
    tidesdb_backpressure_tier_throttle(pressure, &decision);
    return decision;
}

tidesdb_backpressure_t *tidesdb_backpressure_new(tidesdb_backpressure_policy_fn policy, void *ctx)
{
    tidesdb_backpressure_t *bp = calloc(1, sizeof(*bp));
    if (!bp) return NULL;
    bp->policy = policy ? policy : tidesdb_backpressure_default_policy;
    bp->ctx = ctx;
    return bp;
}

void tidesdb_backpressure_free(tidesdb_backpressure_t *bp)
{
    free(bp);
}

tidesdb_backpressure_decision_t tidesdb_backpressure_decide(const tidesdb_backpressure_t *bp,
                                                            const tidesdb_l0_pressure_t *pressure)
{
    if (!bp || !bp->policy)
    {
        tidesdb_backpressure_decision_t admit = {TDB_BACKPRESSURE_ADMIT, 0};
        return admit;
    }
    return bp->policy(pressure, bp->ctx);
}
