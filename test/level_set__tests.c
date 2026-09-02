/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/column_family/level/level_set.h"
#include "../src/datastructures/skip_list/skip_list.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a stub sstable carrying only what the level set reads (id, min/max range, refcount); it opens no
 * files, so sstable_close frees it cleanly on the level set's last unref. created with one
 * reference that the caller transfers to the level set on install. */
static sstable_t *make_stub(uint64_t id, const char *min_key, const char *max_key)
{
    sstable_t *s = calloc(1, sizeof(sstable_t));
    if (!s) return NULL;
    s->id = id;
    s->min_key = (uint8_t *)strdup(min_key);
    s->min_key_size = strlen(min_key);
    s->max_key = (uint8_t *)strdup(max_key);
    s->max_key_size = strlen(max_key);
    atomic_init(&s->klog_bm, NULL);
    atomic_init(&s->refcount, 1);
    atomic_init(&s->last_access_time, 0);
    atomic_init(&s->marked_for_deletion, 0);
    return s;
}

/* install and hand the creation reference to the level set, so the set becomes the sole owner */
static void install_stub(level_set_t *ls, sstable_t *s, int level, uint64_t size_bytes)
{
    ASSERT_EQ(level_set_install(ls, s, level, size_bytes), 0);
    sstable_unref(s);
}

/* a read scans a level by first asking how many sstables it holds and then collecting the ones that
 * overlap its key, in two separate layout loads. a flush installing into that level between the two
 * makes the collect find more overlaps than the capacity the count sized, and a silent stop at the
 * cap hands the reader a partial candidate set. the reader then takes the highest sequence it can
 * see, which is not the highest that exists -- a missed tombstone reads as a live older value and a
 * missed sole version reads as absent. the collect has to say it truncated so the caller can retry
 */
/* an sstable whose recorded key range is missing cannot be placed against a query range. an empty
 * key sorts below every real key, so comparing against it would exclude the file from every lookup
 * and lose whatever it holds. the overlap check has to resolve the doubt toward reading the file */
void test_level_set_overlapping_includes_a_rangeless_sstable(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    install_stub(ls, make_stub(1, "a", "e"), 1, 10);

    /* a stub with no recorded range at all, as a build that failed to record one would leave it */
    sstable_t *rangeless = calloc(1, sizeof(sstable_t));
    ASSERT_TRUE(rangeless != NULL);
    rangeless->id = 2;
    atomic_init(&rangeless->klog_bm, NULL);
    atomic_init(&rangeless->refcount, 1);
    atomic_init(&rangeless->last_access_time, 0);
    atomic_init(&rangeless->marked_for_deletion, 0);
    install_stub(ls, rangeless, 1, 10);

    sstable_t *out[8];
    /* [x,z] misses the placed sstable, so only the range-less one may come back */
    int n = level_set_overlapping(ls, 1, (const uint8_t *)"x", 1, (const uint8_t *)"z", 1, out, 8);
    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)out[0]->id, 2);
    if (sstable_unref(out[0])) sstable_close(out[0]);

    level_set_free(ls);
}

/* how many disjoint runs the deep-level window test lays down; enough that a wrong window is a
 * miss rather than an off-by-one that still happens to land inside the answer */
#define LS_WINDOW_RUNS 64

/* L2 and below hold non-overlapping runs sorted by min_key, so the files meeting a range are a
 * contiguous window that two binary searches find, instead of a scan of the whole level. the window
 * has to agree with the scan it replaces for every query: one that starts too late drops a file
 * that holds the key, and a lookup then reports a present key absent. checked differentially here,
 * against a brute-force overlap over the same level, because the failure is silent */
void test_level_set_deep_level_window_matches_a_full_scan(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    /* disjoint runs at L2, installed out of order so the level set's own sort is what orders them:
     * run i covers ["k<2i>", "k<2i+1>"], leaving a gap between consecutive runs */
    char lo[LS_WINDOW_RUNS][16], hi[LS_WINDOW_RUNS][16];
    for (int i = 0; i < LS_WINDOW_RUNS; i++)
    {
        snprintf(lo[i], sizeof(lo[i]), "k%04d", i * 2);
        snprintf(hi[i], sizeof(hi[i]), "k%04d", i * 2 + 1);
    }
    for (int i = LS_WINDOW_RUNS - 1; i >= 0; i--)
        install_stub(ls, make_stub((uint64_t)(i + 1), lo[i], hi[i]), 2, 10);
    ASSERT_EQ(level_set_count(ls, 2), LS_WINDOW_RUNS);

    /* probe every boundary and every gap, as points and as spans of varying width */
    for (int a = 0; a < LS_WINDOW_RUNS * 2 + 2; a++)
    {
        for (int width = 0; width < 5; width++)
        {
            char qlo[16], qhi[16];
            snprintf(qlo, sizeof(qlo), "k%04d", a);
            snprintf(qhi, sizeof(qhi), "k%04d", a + width);

            /* what a scan of the level would answer */
            int expected = 0;
            for (int i = 0; i < LS_WINDOW_RUNS; i++)
                if (!(strcmp(hi[i], qlo) < 0 || strcmp(lo[i], qhi) > 0)) expected++;

            sstable_t *got[LS_WINDOW_RUNS];
            const int n =
                level_set_overlapping(ls, 2, (const uint8_t *)qlo, strlen(qlo),
                                      (const uint8_t *)qhi, strlen(qhi), got, LS_WINDOW_RUNS);
            ASSERT_EQ(n, expected);
            for (int i = 0; i < n; i++)
                if (sstable_unref(got[i])) sstable_close(got[i]);
        }
    }

    level_set_free(ls);
}

void test_level_set_overlapping_reports_truncation(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    /* four sstables at L1 all covering the probe key, as a tiered level legitimately can */
    install_stub(ls, make_stub(1, "a", "z"), 1, 100);
    install_stub(ls, make_stub(2, "a", "z"), 1, 100);
    install_stub(ls, make_stub(3, "a", "z"), 1, 100);
    install_stub(ls, make_stub(4, "a", "z"), 1, 100);
    ASSERT_EQ(level_set_count(ls, 1), 4);

    /* the capacity a reader sized from an earlier, smaller count */
    sstable_t *got[4];
    const int n =
        level_set_overlapping(ls, 1, (const uint8_t *)"m", 1, (const uint8_t *)"m", 1, got, 2);

    /* a caller that asked for at most 2 and got exactly 2 cannot tell a complete answer from a
     * truncated one, so the count returned has to reflect what actually overlaps */
    ASSERT_TRUE(n > 2);

    for (int i = 0; i < (n < 2 ? n : 2); i++)
        if (sstable_unref(got[i])) free(got[i]);
    level_set_free(ls);
}

void test_level_set_install_and_count(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    install_stub(ls, make_stub(1, "a", "c"), 1, 100);
    install_stub(ls, make_stub(2, "d", "f"), 1, 200);
    install_stub(ls, make_stub(3, "g", "i"), 2, 300);

    ASSERT_EQ(level_set_count(ls, 1), 2);
    ASSERT_EQ(level_set_count(ls, 2), 1);
    ASSERT_EQ(level_set_count(ls, 3), 0);
    ASSERT_EQ(level_set_count(ls, 99), 0);
    ASSERT_EQ(level_set_l1_overlap_depth(ls), 2);

    level_set_free(ls);
}

/* collecting the whole set is a two-call protocol -- ask with a NULL destination, allocate for the
 * answer, then collect -- and a flush can install into the set between the two calls, so the
 * collect can find more than the caller sized for. it has to be all or nothing there. referencing
 * the ones that fit and returning the larger total would hand back references the caller has no
 * count of and therefore never drops, which is a leak that leaves every sstable in the set pinned
 * for the life of the process while looking, from the caller's side, like a resize-and-retry it
 * handled correctly */
void test_level_set_collect_all_references_all_or_nothing(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    sstable_t *first = make_stub(1, "a", "c");
    install_stub(ls, first, 1, 100);
    install_stub(ls, make_stub(2, "d", "f"), 1, 200);
    install_stub(ls, make_stub(3, "g", "i"), 2, 300);

    /* the set holds the only reference to each until a collect adds one */
    ASSERT_EQ(atomic_load(&first->refcount), 1);

    /* the sizing call reports the total and references nothing */
    ASSERT_EQ(level_set_collect_all(ls, NULL, 0), 3);
    ASSERT_EQ(atomic_load(&first->refcount), 1);

    /* under-sized: the true total comes back, and neither the destination nor a refcount is touched
     */
    sstable_t *marker = (sstable_t *)(uintptr_t)0x1;
    sstable_t *slots[3] = {marker, marker, marker};
    ASSERT_EQ(level_set_collect_all(ls, slots, 2), 3);
    ASSERT_TRUE(slots[0] == marker && slots[1] == marker && slots[2] == marker);
    ASSERT_EQ(atomic_load(&first->refcount), 1);

    /* sized for the answer: every entry collected, each carrying one reference for the caller on
     * top of the set's own */
    ASSERT_EQ(level_set_collect_all(ls, slots, 3), 3);
    ASSERT_TRUE(slots[0] != marker && slots[1] != marker && slots[2] != marker);
    ASSERT_EQ(atomic_load(&first->refcount), 2);
    for (int i = 0; i < 3; i++) sstable_unref(slots[i]);
    ASSERT_EQ(atomic_load(&first->refcount), 1);

    level_set_free(ls);
}

void test_level_set_level_bytes(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    install_stub(ls, make_stub(1, "a", "c"), 1, 100);
    install_stub(ls, make_stub(2, "d", "f"), 1, 250);
    install_stub(ls, make_stub(3, "g", "i"), 2, 999);

    ASSERT_EQ((int)level_set_level_bytes(ls, 1), 350);
    ASSERT_EQ((int)level_set_level_bytes(ls, 2), 999);
    ASSERT_EQ((int)level_set_level_bytes(ls, 3), 0);

    level_set_free(ls);
}

void test_level_set_overlapping(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    /* L1 overlapping set */
    install_stub(ls, make_stub(1, "a", "e"), 1, 10);
    install_stub(ls, make_stub(2, "c", "g"), 1, 10);
    install_stub(ls, make_stub(3, "m", "q"), 1, 10);

    sstable_t *out[8];
    /* range [d,d] intersects [a,e] and [c,g] but not [m,q] */
    int n = level_set_overlapping(ls, 1, (const uint8_t *)"d", 1, (const uint8_t *)"d", 1, out, 8);
    ASSERT_EQ(n, 2);
    for (int i = 0; i < n; i++)
        if (sstable_unref(out[i])) sstable_close(out[i]);

    /* range [n,p] intersects only [m,q] */
    n = level_set_overlapping(ls, 1, (const uint8_t *)"n", 1, (const uint8_t *)"p", 1, out, 8);
    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)out[0]->id, 3);
    if (sstable_unref(out[0])) sstable_close(out[0]);

    /* range [x,z] intersects nothing */
    n = level_set_overlapping(ls, 1, (const uint8_t *)"x", 1, (const uint8_t *)"z", 1, out, 8);
    ASSERT_EQ(n, 0);

    level_set_free(ls);
}

void test_level_set_l2_sorted(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    /* insert L2 runs out of order; the set keeps them sorted by min_key, so a range query returns
     * the single covering run */
    install_stub(ls, make_stub(30, "m", "p"), 2, 10);
    install_stub(ls, make_stub(10, "a", "d"), 2, 10);
    install_stub(ls, make_stub(20, "f", "i"), 2, 10);

    sstable_t *out[8];
    int n = level_set_overlapping(ls, 2, (const uint8_t *)"g", 1, (const uint8_t *)"g", 1, out, 8);
    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)out[0]->id, 20);
    if (sstable_unref(out[0])) sstable_close(out[0]);

    level_set_free(ls);
}

void test_level_set_swap(void)
{
    level_set_t *ls = NULL;
    ASSERT_EQ(level_set_create(&ls), 0);

    sstable_t *a = make_stub(1, "a", "c");
    sstable_t *b = make_stub(2, "d", "f");
    install_stub(ls, a, 1, 100);
    install_stub(ls, b, 1, 100);
    ASSERT_EQ(level_set_count(ls, 1), 2);

    /* compaction merges the two L1 sstables into one L2 output */
    sstable_t *merged = make_stub(3, "a", "f");
    sstable_t *inputs[2] = {a, b};
    sstable_t *outputs[1] = {merged};
    int out_levels[1] = {2};
    uint64_t out_sizes[1] = {180};
    ASSERT_EQ(level_set_swap(ls, inputs, 2, outputs, out_levels, out_sizes, 1), 0);
    sstable_unref(merged); /* transfer the creation ref to the set */

    ASSERT_EQ(level_set_count(ls, 1), 0);
    ASSERT_EQ(level_set_count(ls, 2), 1);
    ASSERT_EQ((int)level_set_level_bytes(ls, 2), 180);

    /* a trivial move re-points the merged sstable to L3 with no input */
    sstable_t *moved[1] = {merged};
    int move_levels[1] = {3};
    uint64_t move_sizes[1] = {180};
    /* remove it from L2 and reinstall at L3 in one swap */
    sstable_t *rm[1] = {merged};
    ASSERT_EQ(level_set_swap(ls, rm, 1, moved, move_levels, move_sizes, 1), 0);
    ASSERT_EQ(level_set_count(ls, 2), 0);
    ASSERT_EQ(level_set_count(ls, 3), 1);

    level_set_free(ls);
}

/* ===== concurrent RCU: readers query while a writer churns the layout ===== */
#define LEVEL_CONCURRENT_ITERS   4000
#define LEVEL_CONCURRENT_READERS 3

static level_set_t *g_ls;
static _Atomic(int) g_stop;

static void *reader_loop(void *arg)
{
    (void)arg;
    sstable_t *out[16];
    while (!atomic_load(&g_stop))
    {
        (void)level_set_count(g_ls, 1);
        (void)level_set_level_bytes(g_ls, 1);
        int n = level_set_overlapping(g_ls, 1, (const uint8_t *)"a", 1, (const uint8_t *)"z", 1,
                                      out, 16);
        for (int i = 0; i < n; i++)
            if (sstable_unref(out[i])) sstable_close(out[i]);
    }
    return NULL;
}

void test_level_set_concurrent_readers(void)
{
    ASSERT_EQ(level_set_create(&g_ls), 0);
    atomic_init(&g_stop, 0);

    /* seed a stable L2 run so readers always find something to ref while the writer churns L1 */
    install_stub(g_ls, make_stub(100, "a", "z"), 2, 10);

    pthread_t readers[LEVEL_CONCURRENT_READERS];
    for (int i = 0; i < LEVEL_CONCURRENT_READERS; i++)
        pthread_create(&readers[i], NULL, reader_loop, NULL);

    /* writer repeatedly installs an L1 sstable then swaps it back out, so old layouts retire under
     * live readers -- the epoch must keep a retired layout alive until its readers drain */
    for (int it = 0; it < LEVEL_CONCURRENT_ITERS; it++)
    {
        sstable_t *s = make_stub(1, "a", "z");
        install_stub(g_ls, s, 1, 42);
        sstable_t *rm[1] = {s};
        ASSERT_EQ(level_set_swap(g_ls, rm, 1, NULL, NULL, NULL, 0), 0);
    }

    atomic_store(&g_stop, 1);
    for (int i = 0; i < LEVEL_CONCURRENT_READERS; i++) pthread_join(readers[i], NULL);

    level_set_free(g_ls);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_level_set_install_and_count, tests_passed);
    RUN_TEST(test_level_set_collect_all_references_all_or_nothing, tests_passed);
    RUN_TEST(test_level_set_overlapping_includes_a_rangeless_sstable, tests_passed);
    RUN_TEST(test_level_set_deep_level_window_matches_a_full_scan, tests_passed);
    RUN_TEST(test_level_set_overlapping_reports_truncation, tests_passed);
    RUN_TEST(test_level_set_level_bytes, tests_passed);
    RUN_TEST(test_level_set_overlapping, tests_passed);
    RUN_TEST(test_level_set_l2_sorted, tests_passed);
    RUN_TEST(test_level_set_swap, tests_passed);
    RUN_TEST(test_level_set_concurrent_readers, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
