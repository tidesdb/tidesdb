/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* histories whose attempts each begin at a level of their own, over keys spread across two
 * families, and histories that flush and compact while they run, each attempt checked against what
 * its own level forbids */
#include "isolation_history.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the mixed workload, in percent of actions and of attempts */
#define HIST_MIXED_READ_PERCENT      25
#define HIST_MIXED_SCAN_PERCENT      15
#define HIST_MIXED_DELETE_PERCENT    10
#define HIST_MIXED_TWO_PHASE_PERCENT 30

/* how long each prepare waits for its decision, long enough that writers at every level meet it */
#define HIST_MIXED_LINGER_US 200

static const hist_mix_t g_mixed = {.read = HIST_MIXED_READ_PERCENT,
                                   .scan = HIST_MIXED_SCAN_PERCENT,
                                   .del = HIST_MIXED_DELETE_PERCENT,
                                   .two_phase = HIST_MIXED_TWO_PHASE_PERCENT,
                                   .keys = HIST_KEYS,
                                   .families = HIST_FAMILIES_MAX,
                                   .mixed = 1,
                                   .linger_us = HIST_MIXED_LINGER_US};

/* nothing any level forbids: no aborted or intermediate read, no lost update between strict
 * attempts, no read outside the version order, and no cycle through a strict attempt's read-write
 * edge or through write and write-read edges alone */
static void hist_assert_each_level_kept(const char *what, const hist_found_t *f)
{
    hist_report(what, f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f->g1a + f->g1b + f->lost + f->incompatible, 0);
    ASSERT_EQ(f->cycles, 0);
}

/* read committed, repeatable read and serializable attempts together, a third each, over two
 * families. a read-committed writer that changed what an undecided strict prepare read, and then
 * wrote before it on another key, would close a cycle through the prepare's read */
void test_isolation_history_mixed_levels_each_keep_their_own(void)
{
    hist_record(TDB_ISOLATION_SERIALIZABLE, &g_mixed);
    const hist_found_t f = hist_check();
    hist_assert_each_level_kept("mixed levels", &f);
}

/* the same history with a memtable a few commits deep, so tables are flushed, and merged where the
 * runner keeps up, under validation and scans, and the probes answer from tables as well as
 * memtables */
void test_isolation_history_mixed_levels_across_flushes_and_compactions(void)
{
    hist_mix_t mix = g_mixed;
    mix.small_buffer = 1;
    memset(&g_hist, 0, sizeof(g_hist));
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cfs[HIST_FAMILIES_MAX] = {NULL};
    hist_open(1, &mix, &db, cfs);
    hist_run(db, cfs, TDB_ISOLATION_SERIALIZABLE, &mix, HIST_COMMIT_TARGET, HIST_ATTEMPT_MAX, 0);
    uint64_t flushed = 0, compactions = 0;
    for (int i = 0; i < HIST_FAMILIES_MAX; i++)
    {
        tidesdb_cf_stats_t st;
        ASSERT_EQ(tidesdb_get_cf_stats(cfs[i], &st), TDB_SUCCESS);
        flushed += st.flush_bytes_written;
        compactions += st.compaction_count;
    }
    hist_read_final(db, cfs, &mix);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(HIST_DB_DIR);

    const hist_found_t f = hist_check();
    printf("  %llu bytes flushed, %llu compactions\n", (unsigned long long)flushed,
           (unsigned long long)compactions);
    /* a flush during the history is what puts tables under validation, so it is required. whether a
     * compaction also finishes inside it depends on how fast the runner syncs -- on one whose sync
     * is slow the history can end before the first merge does -- so the count is reported rather
     * than asserted */
    ASSERT_TRUE(flushed > 0);
    hist_assert_each_level_kept("mixed levels across flushes and compactions", &f);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_isolation_history_mixed_levels_each_keep_their_own, tests_passed);
    RUN_TEST(test_isolation_history_mixed_levels_across_flushes_and_compactions, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
