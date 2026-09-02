/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/memtable/backpressure.h"
#include "test_utils.h"

/* a ring capacity large enough that the band above the high-water mark has room to scale, and the
 * band's start mirrored from the policy's 7/8 rule the way the queue tests mirror its 3/4 one */
#define RING_CAPACITY      (16u * 1024 * 1024)
#define RING_HIGHWATER_NUM 7
#define RING_HIGHWATER_DEN 8

static int tests_passed = 0;
static int tests_failed = 0;

static tidesdb_l0_pressure_t pressure_at(int depth, int limit)
{
    tidesdb_l0_pressure_t p = {.queue_depth = depth, .queue_limit = limit};
    return p;
}

/* a snapshot weighing only the staging ring, so the ring band can be exercised on its own */
static tidesdb_l0_pressure_t ring_pressure_at(size_t lag, size_t capacity)
{
    tidesdb_l0_pressure_t p = {.wal_ring_bytes = capacity, .wal_lag_bytes = lag};
    return p;
}

/* a snapshot weighing only the flush tier, so its band can be exercised on its own */
static tidesdb_l0_pressure_t tier_pressure_at(int depth, int slow, int stall)
{
    tidesdb_l0_pressure_t p = {.tier_depth = depth, .tier_slow = slow, .tier_stall = stall};
    return p;
}

/* high-water mark the default policy uses, mirrored from the policy's 3/4 rule, clamped to >= 1 */
static int expected_high_water(int limit)
{
    int hw = limit * 3 / 4;
    return hw < 1 ? 1 : hw;
}

/* the default response is graduated across the whole depth range for a given limit: admit below the
 * high-water mark, a strictly rising throttle dwell through the band up to the peak, then block at
 * and beyond the peak. verified for several limits including the degenerate small ones. */
void test_backpressure_graduated_curve(void)
{
    const int limits[] = {1, 2, 4, 8, 100};
    for (size_t li = 0; li < sizeof(limits) / sizeof(limits[0]); li++)
    {
        const int limit = limits[li];
        const int high_water = expected_high_water(limit);
        uint64_t prev_dwell = 0;
        int seen_throttle = 0;

        for (int depth = 0; depth < limit; depth++)
        {
            tidesdb_l0_pressure_t p = pressure_at(depth, limit);
            tidesdb_backpressure_decision_t d = tidesdb_backpressure_default_policy(&p, NULL);

            if (depth < high_water)
            {
                ASSERT_EQ(d.action, TDB_BACKPRESSURE_ADMIT);
                ASSERT_TRUE(d.throttle_us == 0);
            }
            else
            {
                /* inside the band: throttle, strictly rising each slot toward the peak */
                ASSERT_EQ(d.action, TDB_BACKPRESSURE_THROTTLE);
                ASSERT_TRUE(d.throttle_us > 0);
                if (seen_throttle) ASSERT_TRUE(d.throttle_us > prev_dwell);
                prev_dwell = d.throttle_us;
                seen_throttle = 1;
            }
        }

        /* at and beyond the peak: block */
        tidesdb_l0_pressure_t peak = pressure_at(limit, limit);
        ASSERT_EQ(tidesdb_backpressure_default_policy(&peak, NULL).action, TDB_BACKPRESSURE_BLOCK);
        tidesdb_l0_pressure_t over = pressure_at(limit * 4 + 3, limit);
        ASSERT_EQ(tidesdb_backpressure_default_policy(&over, NULL).action, TDB_BACKPRESSURE_BLOCK);

        /* every non-trivial limit leaves an admit region below the band and at least one throttle
         * slot, so the response is genuinely graduated and not a straight admit-to-block cliff */
        ASSERT_TRUE(high_water >= 1);
        if (limit >= 2) ASSERT_TRUE(seen_throttle);
    }

    /* an unbounded limit never applies backpressure at any depth */
    tidesdb_l0_pressure_t unbounded = pressure_at(1000000, 0);
    ASSERT_EQ(tidesdb_backpressure_default_policy(&unbounded, NULL).action, TDB_BACKPRESSURE_ADMIT);
}

/* a controller built with NULL policy installs the default; decide delegates to it */
void test_backpressure_controller_default(void)
{
    tidesdb_backpressure_t *bp = tidesdb_backpressure_new(NULL, NULL);
    ASSERT_TRUE(bp != NULL);

    tidesdb_l0_pressure_t p = pressure_at(0, 8);
    ASSERT_EQ(tidesdb_backpressure_decide(bp, &p).action, TDB_BACKPRESSURE_ADMIT);
    p = pressure_at(8, 8);
    ASSERT_EQ(tidesdb_backpressure_decide(bp, &p).action, TDB_BACKPRESSURE_BLOCK);

    tidesdb_backpressure_free(bp);
}

static _Atomic(int) g_policy_calls = 0;
static tidesdb_backpressure_decision_t always_block(const tidesdb_l0_pressure_t *pressure,
                                                    void *ctx)
{
    (void)pressure;
    atomic_fetch_add(&g_policy_calls, 1);
    tidesdb_backpressure_decision_t d = {TDB_BACKPRESSURE_BLOCK, 0};
    if (ctx) d.throttle_us = *(uint64_t *)ctx;
    return d;
}

/* the policy is pluggable -- a custom policy and its context drive every decision */
void test_backpressure_pluggable_policy(void)
{
    atomic_store(&g_policy_calls, 0);
    uint64_t marker = 42;
    tidesdb_backpressure_t *bp = tidesdb_backpressure_new(always_block, &marker);
    ASSERT_TRUE(bp != NULL);

    tidesdb_l0_pressure_t p = pressure_at(0, 8); /* would ADMIT under the default */
    tidesdb_backpressure_decision_t d = tidesdb_backpressure_decide(bp, &p);
    ASSERT_EQ(d.action, TDB_BACKPRESSURE_BLOCK);
    ASSERT_TRUE(d.throttle_us == marker);
    ASSERT_EQ(atomic_load(&g_policy_calls), 1);

    tidesdb_backpressure_free(bp);
}

/* a NULL controller decides admit and NULL-free is a no-op */
void test_backpressure_null_safe(void)
{
    tidesdb_l0_pressure_t p = pressure_at(100, 8);
    ASSERT_EQ(tidesdb_backpressure_decide(NULL, &p).action, TDB_BACKPRESSURE_ADMIT);
    tidesdb_backpressure_free(NULL);
    ASSERT_TRUE(1);
}

/* an unbounded queue never throttles, but a filling staging ring must -- it is the pressure the
 * queue cannot show, and the one an appender collides with */
void test_ring_below_highwater_admits(void)
{
    const tidesdb_l0_pressure_t p = ring_pressure_at(RING_CAPACITY / 2, RING_CAPACITY);
    const tidesdb_backpressure_decision_t d = tidesdb_backpressure_default_policy(&p, NULL);
    ASSERT_EQ((int)d.action, (int)TDB_BACKPRESSURE_ADMIT);
    ASSERT_EQ((int)d.throttle_us, 0);
}

/* the dwell rises across the band rather than arriving all at once at the top */
void test_ring_throttle_is_graduated(void)
{
    const size_t high = RING_CAPACITY * RING_HIGHWATER_NUM / RING_HIGHWATER_DEN;
    const size_t band = RING_CAPACITY - high;

    const tidesdb_l0_pressure_t low = ring_pressure_at(high + band / 4, RING_CAPACITY);
    const tidesdb_l0_pressure_t mid = ring_pressure_at(high + band / 2, RING_CAPACITY);
    const tidesdb_l0_pressure_t full = ring_pressure_at(RING_CAPACITY, RING_CAPACITY);

    const tidesdb_backpressure_decision_t dl = tidesdb_backpressure_default_policy(&low, NULL);
    const tidesdb_backpressure_decision_t dm = tidesdb_backpressure_default_policy(&mid, NULL);
    const tidesdb_backpressure_decision_t df = tidesdb_backpressure_default_policy(&full, NULL);

    ASSERT_EQ((int)dl.action, (int)TDB_BACKPRESSURE_THROTTLE);
    ASSERT_TRUE(dl.throttle_us > 0);
    ASSERT_TRUE(dm.throttle_us > dl.throttle_us);
    ASSERT_TRUE(df.throttle_us > dm.throttle_us);
}

/* a lag past capacity cannot ask for more than the band's maximum */
void test_ring_throttle_is_capped(void)
{
    const tidesdb_l0_pressure_t full = ring_pressure_at(RING_CAPACITY, RING_CAPACITY);
    const tidesdb_l0_pressure_t over = ring_pressure_at(RING_CAPACITY * 4, RING_CAPACITY);
    const tidesdb_backpressure_decision_t df = tidesdb_backpressure_default_policy(&full, NULL);
    const tidesdb_backpressure_decision_t dov = tidesdb_backpressure_default_policy(&over, NULL);
    ASSERT_EQ((int)dov.throttle_us, (int)df.throttle_us);
}

/* a producer that did not weigh the ring leaves the verdict to the queue alone */
void test_ring_unweighed_is_ignored(void)
{
    const tidesdb_l0_pressure_t p = ring_pressure_at(0, 0);
    const tidesdb_backpressure_decision_t d = tidesdb_backpressure_default_policy(&p, NULL);
    ASSERT_EQ((int)d.action, (int)TDB_BACKPRESSURE_ADMIT);
}

/* a blocking queue verdict is never traded down to a dwell by ring pressure */
void test_ring_never_lowers_a_block(void)
{
    tidesdb_l0_pressure_t p = pressure_at(8, 8);
    p.wal_ring_bytes = RING_CAPACITY;
    p.wal_lag_bytes = RING_CAPACITY;
    const tidesdb_backpressure_decision_t d = tidesdb_backpressure_default_policy(&p, NULL);
    ASSERT_EQ((int)d.action, (int)TDB_BACKPRESSURE_BLOCK);
}

/* the queue says whether flush keeps up; the tier says whether merging does, and they fail
 * independently -- a burst can drain out of memory promptly and still leave a tier of runs every
 * later read has to merge across. so ingestion is paced against the tier too: dwelling once it runs
 * past the slow mark, waiting once it reaches the stall mark, and admitting freely below both */
void test_tier_band_paces_against_merge_progress(void)
{
    tidesdb_backpressure_t *bp = tidesdb_backpressure_new(NULL, NULL);
    ASSERT_TRUE(bp != NULL);

    const int slow = 8, stall = 20;

    /* below the slow mark the tier costs a writer nothing */
    tidesdb_l0_pressure_t p = tier_pressure_at(slow - 1, slow, stall);
    ASSERT_EQ((int)tidesdb_backpressure_decide(bp, &p).action, (int)TDB_BACKPRESSURE_ADMIT);

    /* at and past it the dwell grows with the depth */
    p = tier_pressure_at(slow, slow, stall);
    tidesdb_backpressure_decision_t d1 = tidesdb_backpressure_decide(bp, &p);
    ASSERT_EQ((int)d1.action, (int)TDB_BACKPRESSURE_THROTTLE);
    ASSERT_TRUE(d1.throttle_us > 0);

    p = tier_pressure_at(slow + 4, slow, stall);
    const tidesdb_backpressure_decision_t d2 = tidesdb_backpressure_decide(bp, &p);
    ASSERT_EQ((int)d2.action, (int)TDB_BACKPRESSURE_THROTTLE);
    ASSERT_TRUE(d2.throttle_us > d1.throttle_us);

    /* at the stall mark the writer waits for the tier to drain rather than dwelling further */
    p = tier_pressure_at(stall, slow, stall);
    ASSERT_EQ((int)tidesdb_backpressure_decide(bp, &p).action, (int)TDB_BACKPRESSURE_BLOCK);

    /* and a policy told to weigh no tier ignores it however deep it runs */
    p = tier_pressure_at(stall * 2, 0, 0);
    ASSERT_EQ((int)tidesdb_backpressure_decide(bp, &p).action, (int)TDB_BACKPRESSURE_ADMIT);

    tidesdb_backpressure_free(bp);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_backpressure_graduated_curve, tests_passed);
    RUN_TEST(test_backpressure_controller_default, tests_passed);
    RUN_TEST(test_backpressure_pluggable_policy, tests_passed);
    RUN_TEST(test_backpressure_null_safe, tests_passed);
    RUN_TEST(test_ring_below_highwater_admits, tests_passed);
    RUN_TEST(test_ring_throttle_is_graduated, tests_passed);
    RUN_TEST(test_ring_throttle_is_capped, tests_passed);
    RUN_TEST(test_tier_band_paces_against_merge_progress, tests_passed);
    RUN_TEST(test_ring_unweighed_is_ignored, tests_passed);
    RUN_TEST(test_ring_never_lowers_a_block, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
