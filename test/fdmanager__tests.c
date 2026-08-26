/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/fdmanager/fdmanager.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_FDM_FILE "." PATH_SEPARATOR "test_fdmanager.bm"

void test_fd_manager_init_destroy(void)
{
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 128), 0);
    ASSERT_EQ(fd_manager_open_total(&fdm), 0);
    ASSERT_EQ(fdm.max_open, 128);
    fd_manager_destroy(&fdm);
    ASSERT_EQ(fd_manager_init(NULL, 128), -1);
}

void test_fd_manager_note_open_close(void)
{
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 64), 0);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_SSTABLE_KLOG), 3);
    fd_manager_note_close(&fdm, FD_LABEL_SSTABLE_KLOG);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_SSTABLE_KLOG), 2);
    fd_manager_destroy(&fdm);
}

/* counts are kept per label and the total sums them; each label has a stable name */
void test_fd_manager_labels(void)
{
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 64), 0);

    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    fd_manager_note_open(&fdm, FD_LABEL_WAL_LOG);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_SSTABLE_KLOG), 2);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_WAL_LOG), 1);
    ASSERT_EQ(fd_manager_open_total(&fdm), 3); /* summed across labels */

    /* closing one label leaves the other untouched */
    fd_manager_note_close(&fdm, FD_LABEL_WAL_LOG);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_WAL_LOG), 0);
    ASSERT_EQ(fd_manager_open_count(&fdm, FD_LABEL_SSTABLE_KLOG), 2);
    ASSERT_EQ(fd_manager_open_total(&fdm), 2);

    ASSERT_TRUE(strcmp(fd_manager_label_name(FD_LABEL_SSTABLE_KLOG), "sstable_klog") == 0);
    ASSERT_TRUE(strcmp(fd_manager_label_name(FD_LABEL_WAL_LOG), "wal_log") == 0);

    fd_manager_destroy(&fdm);
}

void test_fd_manager_open_budget(void)
{
    fd_manager_t fdm;

    /* unlimited cap -> INT_MAX budget */
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);
    ASSERT_EQ(fd_manager_open_budget(&fdm), INT_MAX);
    fd_manager_destroy(&fdm);

    /* 128 cap: reserve = 128/8 = 16 (>= MIN 16), budget = 128 - 16 = 112 */
    ASSERT_EQ(fd_manager_init(&fdm, 128), 0);
    ASSERT_EQ(fd_manager_open_budget(&fdm), 112);
    fd_manager_destroy(&fdm);

    /* 8 cap: reserve floors to MIN 16 but caps at max/2 = 4, so budget = 8 - 4 = 4 */
    ASSERT_EQ(fd_manager_init(&fdm, 8), 0);
    ASSERT_EQ(fd_manager_open_budget(&fdm), 4);
    fd_manager_destroy(&fdm);
}

void test_fd_manager_reader_budget(void)
{
    fd_manager_t fdm;

    /* an already-open file is never gated, even when full, and the total spans labels */
    ASSERT_EQ(fd_manager_init(&fdm, 2), 0);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);
    fd_manager_note_open(&fdm, FD_LABEL_WAL_LOG);
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 1), 1);
    /* a new open at the cap is refused (ceiling gate off, so only total < max_open decides) */
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 0), 0);
    fd_manager_note_close(&fdm, FD_LABEL_WAL_LOG);
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 0), 1);
    fd_manager_destroy(&fdm);

    /* unlimited cap never gates a new open */
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 0), 1);
    fd_manager_destroy(&fdm);
}

/* the slowest the gate may take, as a multiple of its own bound. generous because the wait is
 * built from usleep and a loaded machine oversleeps; the property under test is that it terminates
 * at all, not that it is punctual */
#define TEST_FDM_WAIT_SLACK 4

/* elapsed microseconds since start on the monotonic clock */
static uint64_t test_fdm_elapsed_us(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)((now.tv_sec - start->tv_sec) * 1000000LL +
                      (now.tv_nsec - start->tv_nsec) / 1000LL);
}

/* the reader gate waits descriptor pressure out instead of reporting it, because the caller's only
 * remedy is to sleep and ask again. that wait has to be bounded: a ceiling exhausted by something
 * outside the database must make a read fail, not hang. nothing else in the suite drives the gate
 * to its bound, so the timing is measured here rather than assumed -- an unbounded retry loop still
 * returns the right code and would pass every other test in this file */
void test_fd_manager_reader_gate_wait_is_bounded(void)
{
    /* the two bounds are one property, not two: a reader that gave up sooner than an opener would
     * fail on a shortage the opener was about to clear */
    _Static_assert(TDB_FD_BUDGET_MAX_RECHECKS == TDB_BM_OPEN_EMFILE_MAX_RETRIES,
                   "reader-gate rechecks and EMFILE retries must share one bound");

    const uint64_t bound_us =
        (uint64_t)TDB_FD_BUDGET_MAX_RECHECKS * (uint64_t)TDB_FD_BUDGET_RECHECK_STALL_US;

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 1), 0);
    fd_manager_note_open(&fdm, FD_LABEL_SSTABLE_KLOG);

    /* nothing will free a descriptor here -- there is no reaper registered and the count never
     * falls -- so the gate exhausts every recheck and then reports the pressure */
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 0), 0);
    const uint64_t waited_us = test_fdm_elapsed_us(&start);

    /* it really waited, rather than refusing on the first look */
    ASSERT_TRUE(waited_us >= bound_us);
    /* and it stopped waiting, rather than retrying until the pressure cleared */
    ASSERT_TRUE(waited_us < bound_us * TEST_FDM_WAIT_SLACK);

    /* a read of an already-open file is never gated, so it pays none of that */
    clock_gettime(CLOCK_MONOTONIC, &start);
    ASSERT_EQ(fd_manager_reader_budget_ok(&fdm, 1), 1);
    ASSERT_TRUE(test_fdm_elapsed_us(&start) < TDB_FD_BUDGET_RECHECK_STALL_US);

    fd_manager_destroy(&fdm);
}

void test_fd_manager_bm_open(void)
{
    remove(TEST_FDM_FILE);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 128), 0);

    block_manager_t *bm = NULL;
    ASSERT_EQ(fd_manager_bm_open(&fdm, &bm, TEST_FDM_FILE, BLOCK_MANAGER_SYNC_NONE), 0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_EQ(block_manager_close(bm), 0);

    fd_manager_destroy(&fdm);
    remove(TEST_FDM_FILE);
}

/* the budget the engine actually runs with is cut to fit the process open-file ceiling. the
 * arithmetic is pure so it can be asked every question here rather than through whatever ceiling
 * the machine running the suite happens to have -- fd_manager_init itself takes what it is given,
 * which is what keeps the budget tests above answerable at all */
void test_fd_manager_budget_for_process(void)
{
    /* no real ceiling to fit, so the configured cap stands whatever it is */
    ASSERT_EQ(fd_manager_budget_for_process(4096, 0), 4096);
    ASSERT_EQ(fd_manager_budget_for_process(4096, -1), 4096);

    /* unlimited is the caller saying they sized the process themselves */
    ASSERT_EQ(fd_manager_budget_for_process(0, 1024), 0);

    /* room to spare, so nothing is taken away */
    ASSERT_EQ(fd_manager_budget_for_process(128, 1024), 128);
    ASSERT_EQ(fd_manager_budget_for_process(960, 1024), 960);

    /* the default pairing: a 1024 cap against the usual 1024 POSIX ceiling leaves nothing for the
     * manifest, stdio or a temporary, so it comes down by the untracked reserve */
    ASSERT_EQ(fd_manager_budget_for_process(1024, 1024), 1024 - TDB_FD_RESERVE_UNTRACKED);

    /* exactly at the boundary is still a fit */
    ASSERT_EQ(fd_manager_budget_for_process(1024 - TDB_FD_RESERVE_UNTRACKED, 1024),
              1024 - TDB_FD_RESERVE_UNTRACKED);

    /* a ceiling too low to leave the reserve at all stops at the floor rather than going to zero,
     * which would read as unlimited, or negative, which is nonsense */
    ASSERT_EQ(fd_manager_budget_for_process(1024, 64), TDB_FD_BUDGET_MIN);
    ASSERT_EQ(fd_manager_budget_for_process(1024, 8), TDB_FD_BUDGET_MIN);
    ASSERT_TRUE(fd_manager_budget_for_process(1024, 8) > 0);

    /* and a cap already below the floor is never raised to it */
    ASSERT_EQ(fd_manager_budget_for_process(4, 64), 4);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_fd_manager_init_destroy, tests_passed);
    RUN_TEST(test_fd_manager_note_open_close, tests_passed);
    RUN_TEST(test_fd_manager_labels, tests_passed);
    RUN_TEST(test_fd_manager_budget_for_process, tests_passed);
    RUN_TEST(test_fd_manager_open_budget, tests_passed);
    RUN_TEST(test_fd_manager_reader_budget, tests_passed);
    RUN_TEST(test_fd_manager_reader_gate_wait_is_bounded, tests_passed);
    RUN_TEST(test_fd_manager_bm_open, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
