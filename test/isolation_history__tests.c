/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* the history checker proven against hand-built histories, then point reads and appends at every
 * level checked against what each level forbids */
#include "isolation_history.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the point workload, half reads and half appends over a few keys so that transactions contend */
#define HIST_POINT_READ_PERCENT 50

static void hist_synthetic_reset(void)
{
    memset(&g_hist, 0, sizeof(g_hist));
}

/* add an attempt and return its slot */
static int hist_add_txn(const int status)
{
    const int slot = atomic_fetch_add(&g_hist.next_slot, 1);
    g_hist.txns[slot].status = status;
    if (status == HIST_COMMITTED) atomic_fetch_add(&g_hist.committed, 1);
    return slot;
}

/* add an append that extended the list it read, returning the element */
static uint32_t hist_add_append(const int slot, const int key, const uint32_t *read,
                                const uint32_t len)
{
    hist_txn_t *t = &g_hist.txns[slot];
    hist_op_t *op = hist_next_op(t, HIST_OP_APPEND, key);
    hist_note_list(op, read, len);
    op->elem = (uint32_t)(slot * HIST_OPS_MAX + t->n + 1);
    t->n++;
    return op->elem;
}

static void hist_add_read(const int slot, const int key, const uint32_t *list, const uint32_t len)
{
    hist_txn_t *t = &g_hist.txns[slot];
    hist_note_list(hist_next_op(t, HIST_OP_READ, key), list, len);
    t->n++;
}

static void hist_add_delete(const int slot, const int lo, const int hi)
{
    hist_txn_t *t = &g_hist.txns[slot];
    hist_next_op(t, HIST_OP_DELETE, lo)->key_end = hi;
    t->n++;
}

static void hist_set_final(const int key, const uint32_t *list, const uint32_t len)
{
    if (len > 0) memcpy(g_hist.final[key], list, (size_t)len * sizeof(uint32_t));
    g_hist.final_len[key] = len;
}

static int hist_total(const hist_found_t *f)
{
    return f->g1a + f->g1b + f->lost + f->incompatible + f->g0_g1c + f->g_single + f->cycles;
}

/* a committed read of an aborted append is g1a, and so is an aborted element in a final list */
void test_isolation_history_checker_finds_aborted_reads(void)
{
    hist_synthetic_reset();
    const int a = hist_add_txn(HIST_ABORTED);
    const uint32_t e = hist_add_append(a, 0, NULL, 0);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &e, 1);
    hist_set_final(0, &e, 1);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g1a >= 2);
}

/* a read that saw a transaction's first append to a key but not its second is g1b */
void test_isolation_history_checker_finds_intermediate_reads(void)
{
    hist_synthetic_reset();
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t e1 = hist_add_append(w, 0, NULL, 0);
    const uint32_t e2 = hist_add_append(w, 0, &e1, 1);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &e1, 1);
    const uint32_t fin[] = {e1, e2};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g1b >= 1);
}

/* two writers ordered one way on one key and the other way on another make a write cycle, g0 */
void test_isolation_history_checker_finds_write_cycles(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(t1, 0, NULL, 0);
    const uint32_t d = hist_add_append(t2, 1, NULL, 0);
    const uint32_t c = hist_add_append(t2, 0, &a, 1);
    const uint32_t b = hist_add_append(t1, 1, &d, 1);
    const uint32_t k0[] = {a, c}, k1[] = {d, b};
    hist_set_final(0, k0, 2);
    hist_set_final(1, k1, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g0_g1c >= 1);
    ASSERT_TRUE(f.cycles >= 1);
}

/* a read that misses a write while seeing another from the same transaction is g-single */
void test_isolation_history_checker_finds_single_anti_dependency_cycles(void)
{
    hist_synthetic_reset();
    const int r = hist_add_txn(HIST_COMMITTED);
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w, 0, NULL, 0);
    const uint32_t b = hist_add_append(w, 1, NULL, 0);
    hist_add_read(r, 0, NULL, 0);
    hist_add_read(r, 1, &b, 1);
    hist_set_final(0, &a, 1);
    hist_set_final(1, &b, 1);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g_single >= 1);
    ASSERT_EQ(f.g0_g1c, 0);
}

/* write skew is a cycle of two read-write edges, which snapshot allows and serializable forbids */
void test_isolation_history_checker_finds_write_skew(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    hist_add_read(t1, 0, NULL, 0);
    const uint32_t x = hist_add_append(t1, 1, NULL, 0);
    hist_add_read(t2, 1, NULL, 0);
    const uint32_t y = hist_add_append(t2, 0, NULL, 0);
    hist_set_final(0, &y, 1);
    hist_set_final(1, &x, 1);
    const hist_found_t f = hist_check();
    ASSERT_EQ(f.g_single, 0);
    ASSERT_EQ(f.g0_g1c, 0);
    ASSERT_TRUE(f.cycles >= 1);
}

/* two committed appends that extended the same list are a lost update, and a read placed where no
 * version of that length ends is not a prefix of the order */
void test_isolation_history_checker_finds_lost_updates(void)
{
    hist_synthetic_reset();
    const int w1 = hist_add_txn(HIST_COMMITTED);
    const int w2 = hist_add_txn(HIST_COMMITTED);
    const int w3 = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w1, 0, NULL, 0);
    const uint32_t b = hist_add_append(w2, 0, &a, 1);
    (void)hist_add_append(w3, 0, &a, 1);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, 0, &b, 1);
    const uint32_t fin[] = {a, b};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.lost >= 1);
    ASSERT_TRUE(f.incompatible >= 1);
}

/* a read of the version a range delete overwrote, beside a read of the deleter's own write, is a
 * cycle with one read-write edge */
void test_isolation_history_checker_orders_range_deletes(void)
{
    hist_synthetic_reset();
    const int w = hist_add_txn(HIST_COMMITTED);
    const int d = hist_add_txn(HIST_COMMITTED);
    const int r = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w, HIST_DELETE_FIRST, NULL, 0);
    hist_add_read(d, HIST_DELETE_FIRST, &a, 1);
    hist_add_delete(d, HIST_DELETE_FIRST, HIST_DELETE_FIRST + 1);
    const uint32_t z = hist_add_append(d, 0, NULL, 0);
    hist_add_read(r, HIST_DELETE_FIRST, &a, 1);
    hist_add_read(r, 0, &z, 1);
    hist_set_final(0, &z, 1);
    const hist_found_t f = hist_check();
    ASSERT_TRUE(f.g_single >= 1);
}

/* a list deleted and started again reads cleanly in each of its lives */
void test_isolation_history_checker_accepts_a_list_started_again(void)
{
    hist_synthetic_reset();
    const int w = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(w, HIST_DELETE_FIRST, NULL, 0);
    const int d = hist_add_txn(HIST_COMMITTED);
    hist_add_read(d, HIST_DELETE_FIRST, &a, 1);
    hist_add_delete(d, HIST_DELETE_FIRST, HIST_DELETE_FIRST + 1);
    const int w2 = hist_add_txn(HIST_COMMITTED);
    const uint32_t b = hist_add_append(w2, HIST_DELETE_FIRST, NULL, 0);
    const int r = hist_add_txn(HIST_COMMITTED);
    hist_add_read(r, HIST_DELETE_FIRST, &b, 1);
    hist_set_final(HIST_DELETE_FIRST, &b, 1);
    const hist_found_t f = hist_check();
    ASSERT_EQ(hist_total(&f), 0);
}

/* a history with no anomaly reports none */
void test_isolation_history_checker_accepts_a_serial_history(void)
{
    hist_synthetic_reset();
    const int t1 = hist_add_txn(HIST_COMMITTED);
    const uint32_t a = hist_add_append(t1, 0, NULL, 0);
    const int t2 = hist_add_txn(HIST_COMMITTED);
    hist_add_read(t2, 0, &a, 1);
    const uint32_t b = hist_add_append(t2, 0, &a, 1);
    const uint32_t fin[] = {a, b};
    hist_set_final(0, fin, 2);
    const hist_found_t f = hist_check();
    ASSERT_EQ(hist_total(&f), 0);
}

static const hist_mix_t g_point_mix = {
    .read = HIST_POINT_READ_PERCENT, .scan = 0, .del = 0, .two_phase = 0, .keys = HIST_POINT_KEYS};

/* read committed forbids reading aborted or intermediate states; its read-modify-write appends may
 * lose one another, which the level allows */
void test_isolation_history_read_committed_reads_only_committed_states(void)
{
    hist_record(TDB_ISOLATION_READ_COMMITTED, &g_point_mix);
    const hist_found_t f = hist_check();
    hist_report("read committed", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a, 0);
    ASSERT_EQ(f.g1b, 0);
}

/* snapshot forbids every cycle with fewer than two read-write edges, and lost updates */
void test_isolation_history_snapshot_forbids_g_single(void)
{
    hist_record(TDB_ISOLATION_SNAPSHOT, &g_point_mix);
    const hist_found_t f = hist_check();
    hist_report("snapshot", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.g0_g1c, 0);
    ASSERT_EQ(f.g_single, 0);
}

/* repeatable read validates every read at commit, so over point reads and writes every edge points
 * forward in commit order and the graph has no cycle at all */
void test_isolation_history_repeatable_read_is_acyclic_over_point_access(void)
{
    hist_record(TDB_ISOLATION_REPEATABLE_READ, &g_point_mix);
    const hist_found_t f = hist_check();
    hist_report("repeatable read", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

/* serializable forbids every cycle */
void test_isolation_history_serializable_is_acyclic(void)
{
    hist_record(TDB_ISOLATION_SERIALIZABLE, &g_point_mix);
    const hist_found_t f = hist_check();
    hist_report("serializable", &f);
    ASSERT_TRUE(atomic_load(&g_hist.committed) >= HIST_COMMIT_TARGET);
    ASSERT_EQ(f.g1a + f.g1b + f.lost + f.incompatible, 0);
    ASSERT_EQ(f.cycles, 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_isolation_history_checker_finds_aborted_reads, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_intermediate_reads, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_write_cycles, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_single_anti_dependency_cycles, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_write_skew, tests_passed);
    RUN_TEST(test_isolation_history_checker_finds_lost_updates, tests_passed);
    RUN_TEST(test_isolation_history_checker_orders_range_deletes, tests_passed);
    RUN_TEST(test_isolation_history_checker_accepts_a_list_started_again, tests_passed);
    RUN_TEST(test_isolation_history_checker_accepts_a_serial_history, tests_passed);
    RUN_TEST(test_isolation_history_read_committed_reads_only_committed_states, tests_passed);
    RUN_TEST(test_isolation_history_snapshot_forbids_g_single, tests_passed);
    RUN_TEST(test_isolation_history_repeatable_read_is_acyclic_over_point_access, tests_passed);
    RUN_TEST(test_isolation_history_serializable_is_acyclic, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
