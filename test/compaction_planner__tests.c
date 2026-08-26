/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/compaction/compaction_planner.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a config with size ratio 10, dividing level one below the largest, and a base L1 capacity of 100
 */
static compaction_planner_config_t cfg(void)
{
    compaction_planner_config_t c;
    memset(&c, 0, sizeof(c));
    c.size_ratio = 10;
    c.dividing_level_offset = 1;
    c.min_levels = 3;
    c.l1_file_count_trigger = 4;
    c.tombstone_density_trigger = 0.5;
    c.base_capacity = 100;
    return c;
}

/* the largest level keeps a geometric capacity while smaller levels are restricted to the largest
 * level's data size, tightening durable space-amplification */
void test_planner_capacities(void)
{
    compaction_state_t st;
    memset(&st, 0, sizeof(st));
    st.num_levels = 3;
    st.size[0] = 20;   /* L1 */
    st.size[1] = 300;  /* L2 */
    st.size[2] = 5000; /* L3, the largest */
    const compaction_planner_config_t c = cfg();

    uint64_t caps[LEVEL_SET_MAX_LEVELS];
    compaction_planner_capacities(&st, &c, caps);

    /* C_3 = base * T^2 = 100 * 100 = 10000 (geometric) */
    ASSERT_EQ((int)caps[2], 10000);
    /* C_2 = N_L / T^(3-2) = 5000 / 10 = 500 */
    ASSERT_EQ((int)caps[1], 500);
    /* C_1 = N_L / T^(3-1) = 5000 / 100 = 50 */
    ASSERT_EQ((int)caps[0], 50);
}

/* the dividing level is num_levels - 1 - offset, clamped into range */
void test_planner_dividing_level(void)
{
    compaction_state_t st;
    memset(&st, 0, sizeof(st));
    compaction_planner_config_t c = cfg();

    st.num_levels = 4; /* X = 4 - 1 - 1 = 2 */
    ASSERT_EQ(compaction_planner_dividing_level(&st, &c), 2);

    c.dividing_level_offset = 0; /* X = 4 - 1 - 0 = 3 = L-1 */
    ASSERT_EQ(compaction_planner_dividing_level(&st, &c), 3);

    st.num_levels = 1; /* fewer than two levels -> no dividing level */
    ASSERT_EQ(compaction_planner_dividing_level(&st, &c), 0);
}

/* the target is the smallest level that can hold the cumulative data at and below it */
void test_planner_target_level(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0; /* X = L-1 so the search spans levels 1..L-1 */

    compaction_state_t st;
    memset(&st, 0, sizeof(st));
    st.num_levels = 3;
    st.size[2] = 5000; /* caps: C1=50, C2=500, C3=10000 */

    /* L1 tiny, L2 empty. L1's own capacity would hold it, but L1 is the tier every flush lands in
     * and a merge that targets it writes the tier back into itself -- the data never descends and
     * L1 grows a run per flush. the merge goes to the shallowest level below the tier instead */
    st.size[0] = 20;
    st.size[1] = 0;
    uint64_t caps[LEVEL_SET_MAX_LEVELS];
    compaction_planner_capacities(&st, &c, caps);
    ASSERT_EQ(compaction_planner_target_level(&st, &c, caps), 2);

    /* L1 overflows its own tiny cap but L1+L2 fit in L2 (60+400=460 <= 500), target is L2 */
    st.size[0] = 60;
    st.size[1] = 400;
    compaction_planner_capacities(&st, &c, caps);
    ASSERT_EQ(compaction_planner_target_level(&st, &c, caps), 2);
}

/* runs sitting in the flush tier, past any sane file-count trigger */
#define PLANNER_TIER_RUNS 8

/* the shape a young family spends its whole load phase in: the flush tier plus one level below it,
 * with the tier over its file trigger. the merge has to move data down. targeting the tier itself
 * consolidates its files and leaves them exactly where they were, so the tier keeps growing a run
 * per flush and a scan of any range opens every one of them -- which is the read collapse, arrived
 * at without a single trigger failing to fire */
void test_planner_merge_always_leaves_the_flush_tier(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0;

    compaction_state_t st;
    memset(&st, 0, sizeof(st));
    st.num_levels = 2;
    st.size[0] = 40; /* the flush tier, past its trigger */
    st.size[1] = 900;
    st.file_count[0] = 8;

    uint64_t caps[LEVEL_SET_MAX_LEVELS];
    compaction_planner_capacities(&st, &c, caps);
    ASSERT_TRUE(compaction_planner_triggered(&st, &c, caps));
    ASSERT_TRUE(compaction_planner_target_level(&st, &c, caps) > 1);

    /* and the job the plan emits carries that target, so the merge actually promotes */
    /* the plan derives its own state from the snapshot, so the tier's file count has to be real
     * here rather than asserted above -- eight runs in the tier, one level beneath it */
    compaction_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    compaction_sstable_info_t files[PLANNER_TIER_RUNS + 1];
    memset(files, 0, sizeof(files));
    for (int i = 0; i < PLANNER_TIER_RUNS; i++)
    {
        files[i].id = (uint64_t)i + 1;
        files[i].level = 1;
        files[i].size = 40 / PLANNER_TIER_RUNS;
    }
    files[PLANNER_TIER_RUNS].id = PLANNER_TIER_RUNS + 1;
    files[PLANNER_TIER_RUNS].level = 2;
    files[PLANNER_TIER_RUNS].size = 900;
    snap.sstables = files;
    snap.n_sstables = PLANNER_TIER_RUNS + 1;
    snap.num_levels = 2;

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_TRUE(plan != NULL);
    ASSERT_TRUE(compaction_plan_job_count(plan) > 0);
    const compaction_job_t *job = compaction_plan_job(plan, 0);
    ASSERT_TRUE(job != NULL);
    ASSERT_TRUE(job->target_level > 1);
    compaction_plan_free(plan);
}

/* the L1 file-count trigger and a level reaching capacity both make a compaction due */
void test_planner_triggered(void)
{
    const compaction_planner_config_t c = cfg();
    compaction_state_t st;
    memset(&st, 0, sizeof(st));
    st.num_levels = 3;
    st.size[2] = 5000;
    uint64_t caps[LEVEL_SET_MAX_LEVELS];

    /* nothing over capacity and L1 under its file trigger -> not due */
    st.size[0] = 10;
    st.file_count[0] = 3;
    compaction_planner_capacities(&st, &c, caps);
    ASSERT_EQ(compaction_planner_triggered(&st, &c, caps), 0);

    /* L1 file count reaches the trigger -> due */
    st.file_count[0] = 4;
    ASSERT_EQ(compaction_planner_triggered(&st, &c, caps), 1);

    /* L1 under the file trigger but L2 over its capacity (600 >= C2 500) -> due */
    st.file_count[0] = 2;
    st.size[1] = 600;
    compaction_planner_capacities(&st, &c, caps);
    ASSERT_EQ(compaction_planner_triggered(&st, &c, caps), 1);
}

/* build one snapshot sstable entry */
static compaction_sstable_info_t sst(uint64_t id, int level, uint64_t size, const char *min,
                                     const char *max)
{
    compaction_sstable_info_t s;
    memset(&s, 0, sizeof(s));
    s.id = id;
    s.level = level;
    s.size = size;
    s.min_key = (const uint8_t *)min;
    s.min_key_size = strlen(min);
    s.max_key = (const uint8_t *)max;
    s.max_key_size = strlen(max);
    return s;
}

/* nothing over capacity and L1 under its file trigger yields an empty plan */
void test_plan_not_triggered(void)
{
    const compaction_planner_config_t c = cfg();
    const compaction_sstable_info_t ssts[] = {sst(1, 1, 10, "a", "z"), sst(2, 3, 5000, "a", "z")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 2, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 0);
    compaction_plan_free(plan);
}

/* a single-level tree over its file trigger grows: one job merging L1 into a new L2 */
void test_plan_grow(void)
{
    const compaction_planner_config_t c = cfg(); /* l1_file_count_trigger = 4 */
    const compaction_sstable_info_t ssts[] = {sst(1, 1, 10, "a", "c"), sst(2, 1, 10, "d", "f"),
                                              sst(3, 1, 10, "g", "i"), sst(4, 1, 10, "j", "l")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 4, .num_levels = 1};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 1);
    const compaction_job_t *j = compaction_plan_job(plan, 0);
    ASSERT_EQ(j->target_level, 2);
    ASSERT_EQ((int)j->split, (int)COMPACTION_SPLIT_NONE);
    ASSERT_EQ(j->n_inputs, 4);
    ASSERT_EQ(j->is_largest_level, 1);
    compaction_plan_free(plan);
}

/* a tree that grew under load and then had most of its data deleted must shed the levels it no
 * longer needs, or every read keeps paying for levels holding almost nothing. the threshold is a
 * size ratio below the capacity that would grow it, and that gap is what stops a family oscillating
 * between depths as it crosses the boundary */
void test_plan_sheds_a_level_when_the_largest_empties(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0;
    c.min_levels = 1;

    /* three levels, and the largest holds far less than a T-th of its own capacity */
    const compaction_sstable_info_t ssts[] = {sst(1, 1, 5, "a", "z"), sst(2, 2, 40, "a", "z"),
                                              sst(3, 3, 1, "a", "z")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 3, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 1);
    const compaction_job_t *j = compaction_plan_job(plan, 0);

    /* the merge lands one level up, and takes that level's files with it so the level it writes to
     * is left holding one run rather than two that overlap */
    ASSERT_EQ(j->target_level, 2);
    ASSERT_EQ(j->n_inputs, 2);
    compaction_plan_free(plan);
}

/* the floor a family was configured with is honoured, so a tree already at its minimum depth stays
 * there however little the largest level holds */
void test_plan_does_not_shed_below_min_levels(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0;
    c.min_levels = 3;

    const compaction_sstable_info_t ssts[] = {sst(1, 1, 5, "a", "z"), sst(2, 2, 40, "a", "z"),
                                              sst(3, 3, 1, "a", "z")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 3, .num_levels = 3};

    /* nothing else is due in this shape either -- no level is at capacity and the tier is under its
     * file trigger -- so the floor holding means the plan comes back empty. a plan with a job in it
     * is the shrink the floor was supposed to prevent */
    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 0);
    compaction_plan_free(plan);
}

/* Spooky sizes the tree to the data: when the largest level reaches its capacity a new level is
 * added, keeping the level count near log_T(N/B). without it a family stops deepening -- every
 * merge lands in the level it already occupies, the dividing level collapses onto the flush tier,
 * and the tier accumulates a run per flush with nowhere to drain to */
void test_plan_grows_a_level_when_the_largest_is_full(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0;

    /* caps at base=100, T=10: C1 tracks the largest level's data, C2 = 1000. L2 is the largest and
     * sits at its capacity, so the merge has to land in a level that does not exist yet */
    const compaction_sstable_info_t ssts[] = {sst(1, 1, 20, "a", "z"), sst(2, 2, 1000, "a", "z")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 2, .num_levels = 2};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 1);
    const compaction_job_t *j = compaction_plan_job(plan, 0);
    ASSERT_EQ(j->target_level, 3);
    compaction_plan_free(plan);
}

/* when the small levels merge into the dividing level, one job splits its output by the largest
 * level's boundaries */
void test_plan_dividing(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0; /* X = num_levels - 1 = 2 */
    /* caps at N_L=10000, T=10, base=100: C1=100, C2=1000, C3=10000 */
    const compaction_sstable_info_t ssts[] = {
        sst(1, 1, 150, "a", "z"),   /* L1 over its cap (100) -> triggered */
        sst(2, 2, 50, "a", "z"),    /* L2 well under its cap (1000) -> not partitioned */
        sst(3, 3, 5000, "a", "l"),  /* L3 file 1 */
        sst(4, 3, 5000, "m", "z")}; /* L3 file 2 -> one boundary at "m" */
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 4, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 1);
    const compaction_job_t *j = compaction_plan_job(plan, 0);
    ASSERT_EQ(j->target_level, 2); /* the dividing level X */
    ASSERT_EQ((int)j->split, (int)COMPACTION_SPLIT_BOUNDARIES);
    ASSERT_EQ(j->n_boundaries, 1);
    ASSERT_TRUE(memcmp(j->boundaries[0], "m", 1) == 0);
    ASSERT_EQ(j->n_inputs, 2); /* L1 and L2 */
    compaction_plan_free(plan);
}

/* the output cap is a fraction of the largest level's data, and is withheld entirely while that
 * fraction would be too small to be a sensible file size */
void test_plan_output_file_max(void)
{
    compaction_planner_config_t c = cfg(); /* T = 10 */
    c.dividing_level_offset = 0;

    /* a largest level of 100 MiB gives a cap of 10 MiB */
    const uint64_t large = 100u * 1024u * 1024u;
    const compaction_sstable_info_t big[] = {sst(1, 1, large, "a", "z"), sst(2, 2, 50, "a", "z"),
                                             sst(3, 3, large / 2, "a", "l"),
                                             sst(4, 3, large / 2, "m", "z")};
    const compaction_snapshot_t snap = {.sstables = big, .n_sstables = 4, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_TRUE(compaction_plan_job_count(plan) > 0);
    ASSERT_EQ((int)compaction_plan_job(plan, 0)->file_max, (int)(large / 10));
    compaction_plan_free(plan);

    /* a tiny tree would derive a cap of a few bytes, so it gets none */
    const compaction_sstable_info_t small[] = {sst(1, 1, 150, "a", "z"), sst(2, 2, 50, "a", "z"),
                                               sst(3, 3, 5000, "a", "l"),
                                               sst(4, 3, 5000, "m", "z")};
    const compaction_snapshot_t tiny = {.sstables = small, .n_sstables = 4, .num_levels = 3};

    plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&tiny, &c, &plan), TDB_SUCCESS);
    ASSERT_TRUE(compaction_plan_job_count(plan) > 0);
    ASSERT_EQ((int)compaction_plan_job(plan, 0)->file_max, 0);
    compaction_plan_free(plan);
}

/* when the dividing level is full, one job per largest-level partition merges into the largest
 * level */
/* whether every sstable id appears in at most one job's inputs across the whole plan; a partitioned
 * merge must not share an input between jobs, since the executor removes a job's inputs atomically
 * and a later job would then find the shared input gone, skip, and drop a tombstone without the
 * older versions it shadows */
static int plan_inputs_disjoint(const compaction_plan_t *plan)
{
    const int n = compaction_plan_job_count(plan);
    for (int a = 0; a < n; a++)
    {
        const compaction_job_t *ja = compaction_plan_job(plan, a);
        for (int b = a + 1; b < n; b++)
        {
            const compaction_job_t *jb = compaction_plan_job(plan, b);
            for (int i = 0; i < ja->n_inputs; i++)
                for (int k = 0; k < jb->n_inputs; k++)
                    if (ja->input_ids[i] == jb->input_ids[k]) return 0;
        }
    }
    return 1;
}

/* a partitioned merge whose inputs each sit inside one boundary partition fans out into one job per
 * partition. this is Spooky's partitioned merge proper -- one group of perfectly overlapping files
 * at a time -- so the jobs share no input, may run concurrently, and each costs one partition of
 * transient space rather than the whole of the levels it spans */
void test_plan_partitioned(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0; /* X = 2 */
    /* L2 is over its cap (1000), so X is full and the merge is partitioned into L3 */
    const compaction_sstable_info_t ssts[] = {
        sst(1, 1, 10, "a", "z"),    /* small L1 */
        sst(2, 2, 600, "a", "l"),   /* L2 file overlapping partition 0 */
        sst(3, 2, 600, "m", "z"),   /* L2 file overlapping partition 1 */
        sst(4, 3, 5000, "a", "l"),  /* L3 file 1 -> partition 0 */
        sst(5, 3, 5000, "m", "z")}; /* L3 file 2 -> partition 1 */
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 5, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 2); /* one per partition */
    for (int i = 0; i < 2; i++)
    {
        const compaction_job_t *j = compaction_plan_job(plan, i);
        ASSERT_EQ(j->target_level, 3); /* into the largest level */
        ASSERT_EQ((int)j->split, (int)COMPACTION_SPLIT_BOUNDARIES);
        ASSERT_EQ(j->is_largest_level, 1);
        ASSERT_EQ(j->n_inputs, 2);     /* one L2 and one L3 file, no L1 */
        ASSERT_EQ(j->n_boundaries, 1); /* split at the second L3 file's min-key */
        ASSERT_TRUE(memcmp(j->boundaries[0], "m", 1) == 0);
    }
    /* the whole point: nothing is shared, so the jobs may run at the same time */
    ASSERT_TRUE(plan_inputs_disjoint(plan));
    compaction_plan_free(plan);
}

/* a partitioned merge whose dividing level holds a file spanning every largest-level partition must
 * not split into per-partition jobs sharing that file, or only the first could run and a deleted
 * key at the largest level would resurrect. the plan is one job over every input */
void test_plan_partitioned_spanning_input(void)
{
    compaction_planner_config_t c = cfg();
    c.dividing_level_offset = 0; /* X = 1, the dividing level, is L1 */
    c.min_levels = 1;
    c.base_capacity = 100;
    /* L1 (X) is over its cap of n_largest/T = 100, and its single file spans both L2 partitions */
    const compaction_sstable_info_t ssts[] = {
        sst(1, 1, 150, "a", "z"),  /* the spanning dividing-level file */
        sst(2, 2, 500, "a", "l"),  /* largest-level partition 0 */
        sst(3, 2, 500, "m", "z")}; /* largest-level partition 1 */
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 3, .num_levels = 2};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan), 1);
    const compaction_job_t *j = compaction_plan_job(plan, 0);
    ASSERT_EQ(j->target_level, 2);
    ASSERT_EQ(j->is_largest_level, 1);
    ASSERT_EQ(j->n_inputs, 3); /* the spanning L1 file and both L2 files, together in one merge */
    ASSERT_TRUE(plan_inputs_disjoint(plan));
    compaction_plan_free(plan);
}

/* an sstable dense in tombstones makes a compaction due even when no level is over capacity */
void test_plan_tombstone_density(void)
{
    compaction_planner_config_t c = cfg();
    c.tombstone_density_trigger = 0.5;
    c.tombstone_density_min_entries = 10;

    /* nothing over capacity and L1 under its file trigger, but L2's file is 60% tombstones */
    compaction_sstable_info_t dense = sst(2, 2, 50, "a", "z");
    dense.entry_count = 100;
    dense.tombstone_count = 60;
    const compaction_sstable_info_t ssts[] = {sst(1, 1, 10, "a", "z"), dense,
                                              sst(3, 3, 5000, "a", "z")};
    const compaction_snapshot_t snap = {.sstables = ssts, .n_sstables = 3, .num_levels = 3};

    compaction_plan_t *plan = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap, &c, &plan), TDB_SUCCESS);
    ASSERT_TRUE(compaction_plan_job_count(plan) >= 1); /* the density made it due */
    compaction_plan_free(plan);

    /* below the entry floor, the same density does not trigger */
    compaction_sstable_info_t small = sst(2, 2, 50, "a", "z");
    small.entry_count = 5;
    small.tombstone_count = 4;
    const compaction_sstable_info_t under[] = {sst(1, 1, 10, "a", "z"), small,
                                               sst(3, 3, 5000, "a", "z")};
    const compaction_snapshot_t snap2 = {.sstables = under, .n_sstables = 3, .num_levels = 3};
    compaction_plan_t *plan2 = NULL;
    ASSERT_EQ(compaction_planner_plan(&snap2, &c, &plan2), TDB_SUCCESS);
    ASSERT_EQ(compaction_plan_job_count(plan2), 0);
    compaction_plan_free(plan2);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_planner_capacities, tests_passed);
    RUN_TEST(test_planner_dividing_level, tests_passed);
    RUN_TEST(test_planner_target_level, tests_passed);
    RUN_TEST(test_planner_merge_always_leaves_the_flush_tier, tests_passed);
    RUN_TEST(test_plan_sheds_a_level_when_the_largest_empties, tests_passed);
    RUN_TEST(test_plan_does_not_shed_below_min_levels, tests_passed);
    RUN_TEST(test_planner_triggered, tests_passed);
    RUN_TEST(test_plan_tombstone_density, tests_passed);
    RUN_TEST(test_plan_not_triggered, tests_passed);
    RUN_TEST(test_plan_grow, tests_passed);
    RUN_TEST(test_plan_grows_a_level_when_the_largest_is_full, tests_passed);
    RUN_TEST(test_plan_dividing, tests_passed);
    RUN_TEST(test_plan_output_file_max, tests_passed);
    RUN_TEST(test_plan_partitioned, tests_passed);
    RUN_TEST(test_plan_partitioned_spanning_input, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
