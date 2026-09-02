/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/fdmanager/reaper.h"
#include "../src/sstable/sstable.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_REAPER_DIR      "." PATH_SEPARATOR "test_reaper"
#define TEST_REAPER_MODE     0755
#define TEST_REAPER_MAX_OPEN 8
#define TEST_REAPER_COUNT    6

/* build a small real sstable klog on disk under the given id, leaving the file for a reopen */
static void build_sst(uint64_t id)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.id = id;
    entry.birth_level = 1;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_REAPER_DIR, PATH_SEPARATOR, filename);

    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    memset(&config, 0, sizeof(config));
    config.target_node_size = BTREE_DEFAULT_NODE_SIZE;
    config.value_threshold = 1u << 20;
    config.enable_bloom = 1;
    config.bloom_fpr = 0.01;
    config.sync_mode = BLOCK_MANAGER_SYNC_NONE;
    config.id = id;
    config.partition = MANIFEST_NO_PARTITION;
    config.cf_name = "cf";
    config.klog_path = path;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, bm, NULL, &config), TDB_SUCCESS);
    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"k", 1, (const uint8_t *)"v", 1, 1, 0, 0),
        TDB_SUCCESS);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);
    sstable_close(sst);
}

/* open a built sstable through the fd manager and hold its klog open, so it counts as one resident
 * descriptor the reaper can reclaim */
static sstable_t *open_and_hold(uint64_t id, fd_manager_t *fdm)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.level = 1;
    entry.id = id;
    entry.partition = MANIFEST_NO_PARTITION;

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_REAPER_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, fdm, NULL, NULL),
              TDB_SUCCESS);
    ASSERT_TRUE(sstable_ensure_open(sst) != NULL);
    sstable_ref(sst);
    return sst;
}

static int klog_open(sstable_t *sst)
{
    return atomic_load_explicit(&sst->klog_bm, memory_order_acquire) != NULL;
}

/* the reaper reclaims idle klogs until the resident count is back under the open budget */
void test_reaper_evicts_to_budget(void)
{
    (void)remove_directory(TEST_REAPER_DIR);
    ASSERT_EQ(mkdir(TEST_REAPER_DIR, TEST_REAPER_MODE), 0);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, TEST_REAPER_MAX_OPEN), 0);
    const int budget = fd_manager_open_budget(&fdm);
    ASSERT_TRUE(budget < TEST_REAPER_COUNT); /* the test only makes sense over budget */

    sstable_t *ssts[TEST_REAPER_COUNT];
    for (int i = 0; i < TEST_REAPER_COUNT; i++)
    {
        build_sst((uint64_t)(500 + i));
        ssts[i] = open_and_hold((uint64_t)(500 + i), &fdm);
    }
    ASSERT_EQ(fd_manager_open_total(&fdm), TEST_REAPER_COUNT);

    const int reclaimed = fd_reaper_run(&fdm, ssts, TEST_REAPER_COUNT, NULL);
    ASSERT_EQ(reclaimed, TEST_REAPER_COUNT - budget);
    ASSERT_EQ(fd_manager_open_total(&fdm), budget);

    for (int i = 0; i < TEST_REAPER_COUNT; i++) sstable_close(ssts[i]);
    fd_manager_destroy(&fdm);
    (void)remove_directory(TEST_REAPER_DIR);
}

/* a referenced sstable is never evicted; the reaper skips it and reclaims the idle ones instead */
void test_reaper_respects_refs(void)
{
    (void)remove_directory(TEST_REAPER_DIR);
    ASSERT_EQ(mkdir(TEST_REAPER_DIR, TEST_REAPER_MODE), 0);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, TEST_REAPER_MAX_OPEN), 0);

    sstable_t *ssts[TEST_REAPER_COUNT];
    for (int i = 0; i < TEST_REAPER_COUNT; i++)
    {
        build_sst((uint64_t)(600 + i));
        ssts[i] = open_and_hold((uint64_t)(600 + i), &fdm);
    }

    /* a reader holds the coldest candidate, first in eviction order */
    sstable_ref(ssts[0]);

    (void)fd_reaper_run(&fdm, ssts, TEST_REAPER_COUNT, NULL);
    ASSERT_TRUE(klog_open(ssts[0])); /* held, so it kept its descriptor */

    if (sstable_unref(ssts[0]))
        sstable_close(ssts[0]); /* drops the extra reference, back to idle */
    for (int i = 0; i < TEST_REAPER_COUNT; i++) sstable_close(ssts[i]);
    fd_manager_destroy(&fdm);
    (void)remove_directory(TEST_REAPER_DIR);
}

/* an unlimited fd manager has no soft cap, so the reaper reclaims nothing */
void test_reaper_unlimited_noop(void)
{
    (void)remove_directory(TEST_REAPER_DIR);
    ASSERT_EQ(mkdir(TEST_REAPER_DIR, TEST_REAPER_MODE), 0);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0); /* 0 = unlimited */

    sstable_t *ssts[2];
    for (int i = 0; i < 2; i++)
    {
        build_sst((uint64_t)(700 + i));
        ssts[i] = open_and_hold((uint64_t)(700 + i), &fdm);
    }

    ASSERT_EQ(fd_reaper_run(&fdm, ssts, 2, NULL), 0);
    ASSERT_EQ(fd_manager_open_total(&fdm), 2);

    for (int i = 0; i < 2; i++) sstable_close(ssts[i]);
    fd_manager_destroy(&fdm);
    (void)remove_directory(TEST_REAPER_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_reaper_evicts_to_budget, tests_passed);
    RUN_TEST(test_reaper_respects_refs, tests_passed);
    RUN_TEST(test_reaper_unlimited_noop, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
