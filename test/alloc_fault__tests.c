/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "../include/db.h"
#include "../src/base/alloc_fault.h"
#include "../src/range_tombstone/range_tombstone.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* an allocation refused is the one failure a caller cannot arrange from outside, so the unwind that
 * follows it -- the partial structure freed, the lock dropped, the handle not published -- is the
 * least travelled code in the engine. this walks it: run the same small workload again and again,
 * refusing a different allocation each time, and require that whatever the engine does about it, it
 * never loses what it already acknowledged and never leaves a database that cannot be opened.
 *
 * the count is global and the flush and compaction threads allocate too, so a given n is not
 * guaranteed to be the same call site from run to run. that makes this a broad walk rather than a
 * reproducible index, which is the right trade -- the paths are what matter, not their numbering.
 * run it under the address sanitizer, where a leaked partial structure fails the round rather than
 * passing quietly. */

#define AF_DIR "." PATH_SEPARATOR "test_alloc_fault_db"
/* two families rather than one, so a single flush demuxes the shared memtable into two outputs. the
 * install loop's unwind -- returning the build reference of a family that already landed when a
 * later one cannot -- has no second family to fail on when the workload writes to only one */
#define AF_CF_COUNT 2
static const char *const AF_CF_NAMES[AF_CF_COUNT] = {"cf0", "cf1"};
/* small enough that one round is quick, since the sweep runs hundreds of them */
#define AF_KEYS    4
#define AF_VAL_LEN 64
/* how far the sweep goes. this is an opt-in developer build, never part of an ordinary test run, so
 * the budget here is minutes rather than the milliseconds the default suite is held to. most rounds
 * are quick, and the workload deliberately avoids the one call that is not -- see af_workload */
#define AF_SWEEP_CAP 512

static tidesdb_config_t af_config(char *dir)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = dir;
    /* one worker each, so the background threads add as little to the count as they can */
    cfg.num_flush_threads = 1;
    cfg.num_compaction_threads = 1;
    return cfg;
}

/* the workload one round runs. every call may fail, and none of them being checked into an assert
 * is the point -- what a round proves is what survives, not that any particular step succeeded.
 * which keys committed is recorded per key rather than as a count, because a refused allocation can
 * take one write and leave the next one working, so the survivors are not a prefix
 * @param committed receives one flag per key, set for each commit that returned success
 * @return nothing; failure anywhere is an expected outcome
 */
static void af_workload(int *committed)
{
    memset(committed, 0, sizeof(int) * AF_KEYS);
    char dir[] = AF_DIR;
    tidesdb_config_t cfg = af_config(dir);
    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS || !db) return;

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    tidesdb_column_family_t *cfs[AF_CF_COUNT] = {0};
    for (int f = 0; f < AF_CF_COUNT; f++)
        if (tidesdb_create_column_family(db, AF_CF_NAMES[f], &cc) == TDB_SUCCESS)
            cfs[f] = tidesdb_get_column_family(db, AF_CF_NAMES[f]);

    uint8_t val[AF_VAL_LEN];
    memset(val, 'v', sizeof(val));
    for (int i = 0; i < AF_KEYS; i++)
    {
        /* alternated so both families carry keys in the same memtable generation */
        tidesdb_column_family_t *cf = cfs[i % AF_CF_COUNT];
        if (!cf) continue;
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) continue;
        const int put =
            tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), val, sizeof(val), -1);
        if (put == TDB_SUCCESS && tidesdb_txn_commit(txn) == TDB_SUCCESS) committed[i] = 1;
        tidesdb_txn_free(txn);
    }

    /* close rather than an explicit flush. a flush whose allocation was the refused one leaves the
     * immutable queued for a retry this quiet workload never triggers, so tidesdb_flush_memtable
     * would sit out its full documented wait before reporting contention -- a minute per round, for
     * no more coverage than the close already gives, since the close drains the queue itself */
    (void)tidesdb_close(db);
}

/* reopen with the injector disarmed and require every commit the round acknowledged. a refused
 * allocation may cost a write that never returned, and may cost the whole round, but it may never
 * cost one the caller was told had landed */
static void af_require_committed(const int *committed, const int n_keys)
{
    alloc_fault_arm(0);
    char dir[] = AF_DIR;
    tidesdb_config_t cfg = af_config(dir);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    tidesdb_column_family_t *cfs[AF_CF_COUNT] = {0};
    for (int f = 0; f < AF_CF_COUNT; f++) cfs[f] = tidesdb_get_column_family(db, AF_CF_NAMES[f]);

    for (int i = 0; i < n_keys; i++)
    {
        tidesdb_column_family_t *cf = cfs[i % AF_CF_COUNT];
        if (!cf)
        {
            /* no family means its create never landed, so nothing on it was ever acknowledged */
            ASSERT_EQ(committed[i], 0);
            continue;
        }
        if (!committed[i]) continue;
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        uint8_t *v = NULL;
        size_t vs = 0;
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        const int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key), &v, &vs);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "acknowledged key %s lost after a refused allocation, rc=%d\n", key,
                    rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        free(v);
        (void)tidesdb_txn_rollback(txn);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
}

/* refusing any single allocation must leave a database that still opens and still owes back every
 * commit it acknowledged, however far through the workload the refusal landed */
void test_alloc_failure_leaves_an_openable_database(void)
{
    /* measure first, with nothing armed, so the sweep knows how far the workload actually reaches
     */
    (void)remove_directory(AF_DIR);
    alloc_fault_arm(0);
    int committed[AF_KEYS];
    af_workload(committed);
    const uint64_t reach = alloc_fault_count();
    ASSERT_TRUE(reach > 0);
    /* an unarmed round must do the whole workload, or the sweep below proves nothing */
    for (int i = 0; i < AF_KEYS; i++) ASSERT_EQ(committed[i], 1);
    af_require_committed(committed, AF_KEYS);

    const uint64_t sweep = reach < AF_SWEEP_CAP ? reach : AF_SWEEP_CAP;
    /* say what was covered and what was not, so a run that stops short of the workload's reach says
     * so rather than looking like it swept everything */
    printf("allocation sweep: workload reaches %llu allocations, refusing 1..%llu\n",
           (unsigned long long)reach, (unsigned long long)sweep);
    fflush(stdout);
    for (uint64_t nth = 1; nth <= sweep; nth++)
    {
        (void)remove_directory(AF_DIR);
        alloc_fault_arm(nth);
        af_workload(committed);
        af_require_committed(committed, AF_KEYS);
    }
    alloc_fault_arm(0);
    (void)remove_directory(AF_DIR);
}

/* overlapping, nested, adjacent and unbounded in one sequence, so the fragmentation rebuild takes
 * every arm it has and allocates on each of them */
#define AF_RT_ADDS 6
static const char *const AF_RT_LO[AF_RT_ADDS] = {"b", "a", "d", "c", "m", "a"};
static const char *const AF_RT_HI[AF_RT_ADDS] = {"d", "z", "f", "e", NULL, "c"};

/* lay the tombstones down one at a time, requiring of each that it either worked or reported the
 * refusal, and that a refusal left the fragments already there exactly as they were
 * @param set the set to build into
 */
static void af_rt_build(range_tombstone_set_t *set)
{
    for (int i = 0; i < AF_RT_ADDS; i++)
    {
        const size_t before = range_tombstone_set_count(set);
        const size_t hi_size = AF_RT_HI[i] ? strlen(AF_RT_HI[i]) : RT_UNBOUNDED_ABOVE;
        const int rc =
            range_tombstone_set_add(set, (const uint8_t *)AF_RT_LO[i], strlen(AF_RT_LO[i]),
                                    (const uint8_t *)AF_RT_HI[i], hi_size, (uint64_t)i + 1);
        ASSERT_TRUE(rc == TDB_SUCCESS || rc == TDB_ERR_MEMORY);

        /* the rebuild happens in fresh storage and is swapped in whole, so a refusal anywhere in it
         * owes back the set that was there before, not a half-built one */
        if (rc != TDB_SUCCESS) ASSERT_EQ(range_tombstone_set_count(set), before);
    }
}

/* the fragmentation rebuild allocates once per fragment and once per bound, and a clone allocates
 * again over the result. refusing each of those in turn is the only way those unwinds ever run, and
 * under the address sanitizer a partial one that leaked fails the round rather than passing quietly
 */
void test_alloc_failure_leaves_a_range_tombstone_set_intact(void)
{
    alloc_fault_arm(0);
    range_tombstone_set_t *measure = range_tombstone_set_new();
    ASSERT_TRUE(measure != NULL);
    af_rt_build(measure);
    range_tombstone_set_free(range_tombstone_set_clone(measure));
    const uint64_t reach = alloc_fault_count();
    ASSERT_TRUE(reach > 0);

    /* an unarmed round has to reach every add, or refusing one of them proves nothing */
    ASSERT_TRUE(range_tombstone_set_count(measure) > 0);
    range_tombstone_set_free(measure);

    printf("range tombstone sweep: build reaches %llu allocations, refusing each\n",
           (unsigned long long)reach);
    fflush(stdout);

    for (uint64_t nth = 1; nth <= reach; nth++)
    {
        alloc_fault_arm(nth);
        range_tombstone_set_t *set = range_tombstone_set_new();
        if (set)
        {
            af_rt_build(set);
            /* a clone that cannot finish owes nothing back but the memory it took */
            range_tombstone_set_free(range_tombstone_set_clone(set));
        }
        range_tombstone_set_free(set);
    }
    alloc_fault_arm(0);
}

/* the compaction round: values big enough that the buffer rotates every few writes, so the flushes
 * leave a merge real inputs, and a low trigger so one is due by the time the workload asks for it
 */
#define AF_COMPACT_KEYS       16
#define AF_COMPACT_VAL_LEN    1024
#define AF_COMPACT_BUFFER     (4u * 1024)
#define AF_COMPACT_L1_TRIGGER 2
#define AF_COMPACT_RETRIES    8
/* a round here does far more than the plain one, so the sweep is shorter; the install is reached
 * early enough in a round that the interesting allocations sit well inside this */
#define AF_COMPACT_SWEEP_CAP 400

/* the same shape as af_workload, but sized to produce several L1 runs and then merge them. the
 * install is where a refused allocation used to matter most: it names the outputs and unnames the
 * inputs in one batch, and a caller that gave up partway left those records in the manifest's
 * pending buffer for the next commit to carry -- inputs durably disowned, replacement never named,
 * and the orphan sweep unlinking their files on the next open
 * @param committed receives one flag per key, set for each commit that returned success
 */
static void af_compact_workload(int *committed)
{
    memset(committed, 0, sizeof(int) * AF_COMPACT_KEYS);
    char dir[] = AF_DIR;
    tidesdb_config_t cfg = af_config(dir);
    cfg.memtable_write_buffer_size = AF_COMPACT_BUFFER;
    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS || !db) return;

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    cc.l1_file_count_trigger = AF_COMPACT_L1_TRIGGER;
    tidesdb_column_family_t *cfs[AF_CF_COUNT] = {0};
    for (int f = 0; f < AF_CF_COUNT; f++)
        if (tidesdb_create_column_family(db, AF_CF_NAMES[f], &cc) == TDB_SUCCESS)
            cfs[f] = tidesdb_get_column_family(db, AF_CF_NAMES[f]);

    uint8_t val[AF_COMPACT_VAL_LEN];
    memset(val, 'v', sizeof(val));
    for (int i = 0; i < AF_COMPACT_KEYS; i++)
    {
        tidesdb_column_family_t *cf = cfs[i % AF_CF_COUNT];
        if (!cf) continue;
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) continue;
        const int put =
            tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), val, sizeof(val), -1);
        if (put == TDB_SUCCESS && tidesdb_txn_commit(txn) == TDB_SUCCESS) committed[i] = 1;
        tidesdb_txn_free(txn);
    }

    /* a merge the scheduler may already be running reports locked, so this retries a few times
     * rather than treating contention as the answer. every result is fine -- what the round proves
     * is what survives, not that the merge ran */
    for (int f = 0; f < AF_CF_COUNT; f++)
    {
        if (!cfs[f]) continue;
        for (int attempt = 0; attempt < AF_COMPACT_RETRIES; attempt++)
            if (tidesdb_compact(db, cfs[f]) != TDB_ERR_LOCKED) break;
    }

    (void)tidesdb_close(db);
}

/* a refused allocation anywhere in a flush-then-merge round leaves a database that still opens and
 * still owes back every commit it acknowledged. this walks the merge path, which the plain sweep
 * never reaches -- its workload writes too little to give a compaction anything to do.
 *
 * what it does not do is reach the install's own partial-failure window. the records that window
 * turns on are appended to a pending buffer that only allocates when it doubles, and a round this
 * size never gets it there, so refusing one allocation cannot land between the removals and the
 * commit. the case that window guards is pinned instead by
 * test_manifest_an_abandoned_half_batch_lands_on_the_next_commit, which shows what an abandoned
 * half-batch does to the next commit -- and therefore why the install has to put the set back
 * rather than simply return */
void test_alloc_failure_through_a_compaction_keeps_every_commit(void)
{
    (void)remove_directory(AF_DIR);
    alloc_fault_arm(0);
    int committed[AF_COMPACT_KEYS];
    af_compact_workload(committed);
    const uint64_t reach = alloc_fault_count();
    ASSERT_TRUE(reach > 0);
    for (int i = 0; i < AF_COMPACT_KEYS; i++) ASSERT_EQ(committed[i], 1);
    af_require_committed(committed, AF_COMPACT_KEYS);

    const uint64_t sweep = reach < AF_COMPACT_SWEEP_CAP ? reach : AF_COMPACT_SWEEP_CAP;
    printf("compaction sweep: workload reaches %llu allocations, refusing 1..%llu\n",
           (unsigned long long)reach, (unsigned long long)sweep);
    fflush(stdout);
    for (uint64_t nth = 1; nth <= sweep; nth++)
    {
        (void)remove_directory(AF_DIR);
        alloc_fault_arm(nth);
        af_compact_workload(committed);
        af_require_committed(committed, AF_COMPACT_KEYS);
    }
    alloc_fault_arm(0);
    (void)remove_directory(AF_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_alloc_failure_leaves_an_openable_database, tests_passed);
    RUN_TEST(test_alloc_failure_through_a_compaction_keeps_every_commit, tests_passed);
    RUN_TEST(test_alloc_failure_leaves_a_range_tombstone_set_intact, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
