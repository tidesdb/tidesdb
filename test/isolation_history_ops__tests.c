/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* histories that scan ranges through iterators, delete ranges, commit in two phases, and cross a
 * restart with prepared transactions left in doubt, each checked against what its level forbids */
#include "isolation_history.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the mixed workload, in percent of actions and of attempts */
#define HIST_OPS_READ_PERCENT      25
#define HIST_OPS_SCAN_PERCENT      15
#define HIST_OPS_DELETE_PERCENT    10
#define HIST_OPS_TWO_PHASE_PERCENT 30

/* the recovery run commits half its target before the restart and the rest after, and leaves its
 * in-doubt prepares from attempts that prepare every time */
#define HIST_RECOVERY_PHASES         2
#define HIST_RECOVERY_ALWAYS_PREPARE 100
#define HIST_RECOVERY_TRIES          (HIST_IN_DOUBT_MAX * 8)
#define HIST_RECOVERY_SEED           0xD1B54A32D192ED03ULL
/* the share of the attempt budget the run before the restart may use, so the prepares left in doubt
 * and the run after it always have slots */
#define HIST_RECOVERY_FIRST_SLOTS (HIST_ATTEMPT_MAX / 3)

static const hist_mix_t g_ops_mix = {.read = HIST_OPS_READ_PERCENT,
                                     .scan = HIST_OPS_SCAN_PERCENT,
                                     .del = HIST_OPS_DELETE_PERCENT,
                                     .two_phase = HIST_OPS_TWO_PHASE_PERCENT,
                                     .keys = HIST_KEYS};

/* read committed forbids reading aborted or intermediate states, through scans and deletes too */
void test_isolation_history_ops_read_committed_reads_only_committed_states(void)
{
    hist_record(TDB_ISOLATION_READ_COMMITTED, &g_ops_mix);
    const hist_found_t f = hist_check();
    hist_report("read committed", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f.g1a, 0);
    ASSERT_EQ(f.g1b, 0);
}

/* snapshot forbids lost updates and every cycle with fewer than two read-write edges, with range
 * deletes contending with appends under first-committer-wins */
void test_isolation_history_ops_snapshot_forbids_g_single(void)
{
    hist_record(TDB_ISOLATION_SNAPSHOT, &g_ops_mix);
    const hist_found_t f = hist_check();
    hist_report("snapshot", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.g0_g1c, 0);
    ASSERT_EQ(f.g_single, 0);
}

/* repeatable read validates what its point reads and its scans saw, so a key a scan found absent
 * cannot be inserted under it and the graph has no cycle */
void test_isolation_history_ops_repeatable_read_is_acyclic(void)
{
    hist_record(TDB_ISOLATION_REPEATABLE_READ, &g_ops_mix);
    const hist_found_t f = hist_check();
    hist_report("repeatable read", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

/* serializable forbids every cycle, phantoms through scans included */
void test_isolation_history_ops_serializable_is_acyclic(void)
{
    hist_record(TDB_ISOLATION_SERIALIZABLE, &g_ops_mix);
    const hist_found_t f = hist_check();
    hist_report("serializable", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

/* decide every prepared attempt a restart left in doubt, committing or rolling back each at
 * random, and record the decision */
static void hist_resolve_in_doubt(tidesdb_t *db, uint64_t *rng)
{
    tidesdb_prepared_txn_t found[HIST_IN_DOUBT_MAX];
    int count = 0;
    ASSERT_EQ(tidesdb_recover_prepared(db, found, HIST_IN_DOUBT_MAX, &count), TDB_SUCCESS);
    ASSERT_TRUE(count <= HIST_IN_DOUBT_MAX);
    for (int i = 0; i < count; i++)
    {
        char xid[HIST_XID_BYTES];
        const size_t n = found[i].xid_size < sizeof(xid) - 1 ? found[i].xid_size : sizeof(xid) - 1;
        memcpy(xid, found[i].xid, n);
        xid[n] = '\0';
        const int slot = atoi(xid + 1);
        ASSERT_TRUE(slot >= 0 && slot < HIST_ATTEMPT_MAX);
        ASSERT_EQ(g_hist.txns[slot].status, HIST_IN_DOUBT);
        const int commit = hist_rng(rng) % 2 == 0;
        ASSERT_EQ(commit ? tidesdb_txn_commit_prepared(found[i].txn)
                         : tidesdb_txn_rollback_prepared(found[i].txn),
                  TDB_SUCCESS);
        g_hist.txns[slot].status = commit ? HIST_COMMITTED : HIST_ABORTED;
        if (commit) atomic_fetch_add(&g_hist.committed, 1);
        tidesdb_txn_free(found[i].txn);
    }
}

/* prepare attempts one at a time until HIST_IN_DOUBT_MAX are left undecided, so they hold their
 * claims into the restart without stalling a concurrent workload behind them */
static void hist_leave_prepares_in_doubt(tidesdb_t *db, tidesdb_column_family_t *cf, const int iso)
{
    hist_worker_t w = {
        .db = db, .cfs = {cf, cf}, .iso = iso, .mix = g_ops_mix, .leave_in_doubt = 1};
    w.mix.two_phase = HIST_RECOVERY_ALWAYS_PREPARE;
    w.mix.del = 0;
    uint64_t rng = HIST_RECOVERY_SEED;
    for (int i = 0; i < HIST_RECOVERY_TRIES; i++)
    {
        if (atomic_load(&g_hist.in_doubt) >= HIST_IN_DOUBT_MAX) break;
        const int slot = atomic_fetch_add(&g_hist.next_slot, 1);
        if (slot >= HIST_ATTEMPT_MAX) break;
        hist_run_attempt(&w, &rng, slot);
    }
}

/* how many attempts are still recorded in doubt */
static int hist_count_in_doubt(void)
{
    const int slots = hist_slots_recorded();
    int n = 0;
    for (int s = 0; s < slots; s++) n += g_hist.txns[s].status == HIST_IN_DOUBT;
    return n;
}

/* a history that crosses a restart. prepares are left in doubt, the database is closed and opened
 * again, each is found by recovery and decided at random, and the workload carries on. the whole
 * history, on both sides of the restart, must be as serializable as one that never stopped */
void test_isolation_history_ops_serializable_across_a_restart_with_prepares_in_doubt(void)
{
    const int iso = TDB_ISOLATION_SERIALIZABLE;
    memset(&g_hist, 0, sizeof(g_hist));
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cfs[HIST_FAMILIES_MAX] = {NULL};
    hist_open(1, &g_ops_mix, &db, cfs);
    tidesdb_column_family_t *cf = cfs[0];
    hist_run(db, cfs, iso, &g_ops_mix, HIST_COMMIT_TARGET / HIST_RECOVERY_PHASES,
             HIST_RECOVERY_FIRST_SLOTS, 0);
    hist_leave_prepares_in_doubt(db, cf, iso);
    const int left = hist_count_in_doubt();
    ASSERT_TRUE(left > 0);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    hist_open(0, &g_ops_mix, &db, cfs);
    cf = cfs[0];
    uint64_t rng = HIST_RECOVERY_SEED;
    hist_resolve_in_doubt(db, &rng);
    ASSERT_EQ(hist_count_in_doubt(), 0);
    hist_run(db, cfs, iso, &g_ops_mix, HIST_COMMIT_TARGET, HIST_ATTEMPT_MAX, 0);
    hist_read_final(db, cfs, &g_ops_mix);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(HIST_DB_DIR);

    const hist_found_t f = hist_check();
    printf("  %d prepares left in doubt across the restart\n", left);
    hist_report("serializable across a restart", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_FLOOR);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_isolation_history_ops_read_committed_reads_only_committed_states, tests_passed);
    RUN_TEST(test_isolation_history_ops_snapshot_forbids_g_single, tests_passed);
    RUN_TEST(test_isolation_history_ops_repeatable_read_is_acyclic, tests_passed);
    RUN_TEST(test_isolation_history_ops_serializable_is_acyclic, tests_passed);
    RUN_TEST(test_isolation_history_ops_serializable_across_a_restart_with_prepares_in_doubt,
             tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
