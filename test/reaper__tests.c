/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/column_family/level/level_set.h"
#include "../src/fdmanager/reaper.h"
#include "../src/sstable/sstable_internal.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_REAPER_DIR       "." PATH_SEPARATOR "test_reaper"
#define TEST_REAPER_MODE      0755
#define TEST_REAPER_MAX_OPEN  8
#define TEST_REAPER_COUNT     6
#define TEST_REAPER_IDLE_REFS 2

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

static void drop_sstable_ref(sstable_t *sst)
{
    if (sstable_unref(sst)) sstable_close(sst);
}

typedef struct
{
    fd_manager_t *fdm;
    sstable_t **candidates;
    sstable_t *victim;
    int calls;
    int failed;
} read_pin_probe_t;

/* force descriptor pressure while a point read or sync holds its pin, so a candidate at the former
 * caller-plus-reaper baseline proves that the new pin keeps its block manager resident */
static void reap_during_read_pin(sstable_t *sst, void *context)
{
    read_pin_probe_t *probe = context;
    probe->calls++;
    if (fd_reaper_run(probe->fdm, probe->candidates, TEST_REAPER_COUNT, NULL) != 1 ||
        !klog_open(sst) || klog_open(probe->victim))
        probe->failed = 1;
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

/* a cursor must pin a table after the layout that owned it has been retired: the reaper's candidate
 * reference and this caller's reference alone look idle after the deferred layout is reclaimed */
void test_reaper_keeps_retired_iterator_reader_resident(void)
{
    (void)remove_directory(TEST_REAPER_DIR);
    ASSERT_EQ(mkdir(TEST_REAPER_DIR, TEST_REAPER_MODE), 0);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, TEST_REAPER_MAX_OPEN), 0);
    const int budget = fd_manager_open_budget(&fdm);
    ASSERT_TRUE(budget < TEST_REAPER_COUNT);

    level_set_t *levels = NULL;
    ASSERT_EQ(level_set_create(&levels), 0);
    sstable_t *tables[TEST_REAPER_COUNT] = {0};
    sstable_t *candidates[TEST_REAPER_COUNT] = {0};
    sstable_iter_t *reader = NULL;
    sstable_t *caller_ref = NULL;

    for (int i = 0; i < TEST_REAPER_COUNT; i++)
    {
        const uint64_t id = (uint64_t)(800 + i);
        build_sst(id);
        tables[i] = open_and_hold(id, &fdm);
        drop_sstable_ref(tables[i]); /* open_and_hold's test reference is not layout ownership */
        ASSERT_EQ(level_set_install(levels, tables[i], LEVEL_SET_L1, 1), 0);
        drop_sstable_ref(tables[i]); /* transfer the open's ownership to the layout */
        tables[i] = NULL;
    }
    ASSERT_EQ(level_set_collect_all(levels, candidates, TEST_REAPER_COUNT), TEST_REAPER_COUNT);

    caller_ref = candidates[0];
    sstable_ref(caller_ref); /* the reader's source owns this table while its cursor is live */
    ASSERT_EQ(sstable_iter_new(caller_ref, 0, &reader), TDB_SUCCESS);
    ASSERT_EQ(sstable_iter_seek(reader, (const uint8_t *)"k", 1), TDB_SUCCESS);

    ASSERT_EQ(level_set_swap(levels, candidates, 1, NULL, NULL, NULL, 0), 0);
    level_set_reclaim_deferred(levels);

    ASSERT_EQ(fd_reaper_run(&fdm, candidates, TEST_REAPER_COUNT, NULL), TEST_REAPER_COUNT - budget);
    ASSERT_TRUE(klog_open(caller_ref)); /* check before using the cursor: upstream evicts this */

    uint8_t *key = NULL, *value = NULL, deleted = 0;
    size_t key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    ASSERT_EQ(sstable_iter_seek(reader, (const uint8_t *)"k", 1), TDB_SUCCESS);
    ASSERT_EQ(sstable_iter_get(reader, &key, &key_size, &value, &value_size, &vlog_offset, &seq,
                               &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ(key_size, 1);
    ASSERT_EQ(value_size, 1);
    ASSERT_EQ(key[0], 'k');
    ASSERT_EQ(value[0], 'v');
    ASSERT_FALSE(deleted);
    sstable_iter_free(reader);
    reader = NULL;

    /* point reads and checkpoints need the same short-lived pin, while their hook makes eviction
     * contend with the borrow before either path touches the klog */
    ASSERT_TRUE(sstable_ensure_open(caller_ref) != NULL);
    ASSERT_TRUE(sstable_ensure_open(candidates[1]) != NULL);
    read_pin_probe_t probe = {
        .fdm = &fdm,
        .candidates = candidates,
        .victim = candidates[1],
    };
    sstable_test_set_read_hook(reap_during_read_pin, &probe);
    key = NULL;
    value = NULL;
    ASSERT_EQ(sstable_get(caller_ref, (const uint8_t *)"k", 1, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted),
              TDB_SUCCESS);
    sstable_test_set_read_hook(NULL, NULL);
    ASSERT_EQ(probe.calls, 1);
    ASSERT_FALSE(probe.failed);
    ASSERT_EQ(value_size, 1);
    ASSERT_EQ(value[0], 'v');
    free(value);

    ASSERT_TRUE(sstable_ensure_open(candidates[1]) != NULL);
    sstable_test_set_read_hook(reap_during_read_pin, &probe);
    ASSERT_EQ(sstable_sync_klog(caller_ref), TDB_SUCCESS);
    sstable_test_set_read_hook(NULL, NULL);
    ASSERT_EQ(probe.calls, 2);
    ASSERT_FALSE(probe.failed);

    ASSERT_TRUE(sstable_ensure_open(candidates[1]) != NULL);
    ASSERT_EQ(fd_reaper_run(&fdm, candidates, TEST_REAPER_COUNT, NULL), 1);
    ASSERT_FALSE(klog_open(caller_ref)); /* all three operations released their pins */

    /* missing keys and failed opens must return the operation's pin too */
    value = NULL;
    ASSERT_EQ(sstable_get_at_seq(caller_ref, (const uint8_t *)"k", 1, 0, &value, &value_size,
                                 &vlog_offset, &seq, &ttl, &deleted),
              TDB_ERR_NOT_FOUND);
    ASSERT_EQ(atomic_load(&caller_ref->refcount), TEST_REAPER_IDLE_REFS);
    ASSERT_EQ(fd_reaper_run(&fdm, candidates, TEST_REAPER_COUNT, NULL), 1);
    ASSERT_EQ(sstable_sync_klog(caller_ref), TDB_SUCCESS); /* a nonresident klog needs no sync */
    ASSERT_EQ(atomic_load(&caller_ref->refcount), TEST_REAPER_IDLE_REFS);

    char missing_path[] = TEST_REAPER_DIR PATH_SEPARATOR "missing" PATH_SEPARATOR "table.klog";
    char *saved_path = caller_ref->klog_path;
    caller_ref->klog_path = missing_path;
    ASSERT_EQ(sstable_get(caller_ref, (const uint8_t *)"k", 1, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted),
              TDB_ERR_IO);
    ASSERT_EQ(atomic_load(&caller_ref->refcount), TEST_REAPER_IDLE_REFS);
    ASSERT_EQ(sstable_iter_new(caller_ref, 0, &reader), TDB_ERR_IO);
    ASSERT_EQ(atomic_load(&caller_ref->refcount), TEST_REAPER_IDLE_REFS);
    caller_ref->klog_path = saved_path;

    value = NULL;
    ASSERT_EQ(sstable_get(caller_ref, (const uint8_t *)"k", 1, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted),
              TDB_SUCCESS);
    free(value);
    ASSERT_EQ(fd_reaper_run(&fdm, candidates, TEST_REAPER_COUNT, NULL), 1);
    ASSERT_FALSE(klog_open(caller_ref));

    drop_sstable_ref(caller_ref);
    for (int i = 0; i < TEST_REAPER_COUNT; i++) drop_sstable_ref(candidates[i]);
    level_set_free(levels);
    fd_manager_destroy(&fdm);
    (void)remove_directory(TEST_REAPER_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_reaper_evicts_to_budget, tests_passed);
    RUN_TEST(test_reaper_respects_refs, tests_passed);
    RUN_TEST(test_reaper_unlimited_noop, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_reaper_keeps_retired_iterator_reader_resident, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
