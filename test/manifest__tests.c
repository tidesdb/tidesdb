/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../src/manifest.h"
#include "../src/tidesdb.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_MANIFEST_PATH "./test_manifest"

void test_manifest_create()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_entries, 0);
    ASSERT_EQ(manifest->capacity, MANIFEST_INITIAL_CAPACITY);
    ASSERT_EQ(manifest->sequence, 0);
    ASSERT_TRUE(manifest->entries != NULL);

    tidesdb_manifest_free(manifest);
}

void test_manifest_add_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add first sstable */
    int result = tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_EQ(manifest->entries[0].level, 1);
    ASSERT_EQ(manifest->entries[0].id, 100);
    ASSERT_EQ(manifest->entries[0].num_entries, 1000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 65536);

    /* add second sstable */
    result = tidesdb_manifest_add_sstable(manifest, 2, 200, 2000, 131072);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_EQ(manifest->entries[1].level, 2);
    ASSERT_EQ(manifest->entries[1].id, 200);

    /* add third sstable at same level as first */
    result = tidesdb_manifest_add_sstable(manifest, 1, 101, 1500, 98304);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 3);

    tidesdb_manifest_free(manifest);
}

void test_manifest_update_existing_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add sstable */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    ASSERT_EQ(manifest->num_entries, 1);

    /* update same sstable (same level and id) */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 2000, 131072);
    ASSERT_EQ(manifest->num_entries, 1);                /* should still be 1 */
    ASSERT_EQ(manifest->entries[0].num_entries, 2000);  /* updated */
    ASSERT_EQ(manifest->entries[0].size_bytes, 131072); /* updated */

    tidesdb_manifest_free(manifest);
}

void test_manifest_has_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add some sstables */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(manifest, 2, 200, 2000, 131072);
    tidesdb_manifest_add_sstable(manifest, 1, 101, 1500, 98304);

    /* check existing sstables */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 101));

    /* check non-existing sstables */
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 999));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 3, 100));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 2, 100));

    tidesdb_manifest_free(manifest);
}

void test_manifest_remove_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add sstables */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(manifest, 2, 200, 2000, 131072);
    tidesdb_manifest_add_sstable(manifest, 1, 101, 1500, 98304);
    ASSERT_EQ(manifest->num_entries, 3);

    /* remove middle entry */
    int result = tidesdb_manifest_remove_sstable(manifest, 2, 200);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 101));

    /* remove first entry */
    result = tidesdb_manifest_remove_sstable(manifest, 1, 100);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 100));

    /* try to remove non-existing entry */
    result = tidesdb_manifest_remove_sstable(manifest, 1, 999);
    ASSERT_EQ(result, -1);
    ASSERT_EQ(manifest->num_entries, 1);

    tidesdb_manifest_free(manifest);
}

void test_manifest_update_sequence()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->sequence, 0);

    tidesdb_manifest_update_sequence(manifest, 12345);
    ASSERT_EQ(manifest->sequence, 12345);

    tidesdb_manifest_update_sequence(manifest, 99999);
    ASSERT_EQ(manifest->sequence, 99999);

    tidesdb_manifest_free(manifest);
}

void test_manifest_capacity_growth()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->capacity, MANIFEST_INITIAL_CAPACITY);

    /* add more entries than initial capacity to trigger growth */
    for (int i = 0; i < MANIFEST_INITIAL_CAPACITY + 10; i++)
    {
        int result = tidesdb_manifest_add_sstable(manifest, 1, i, 1000, 65536);
        ASSERT_EQ(result, 0);
    }

    ASSERT_EQ(manifest->num_entries, MANIFEST_INITIAL_CAPACITY + 10);
    ASSERT_TRUE(manifest->capacity > MANIFEST_INITIAL_CAPACITY);

    /* verify all entries are still accessible */
    for (int i = 0; i < MANIFEST_INITIAL_CAPACITY + 10; i++)
    {
        ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, i));
    }

    tidesdb_manifest_free(manifest);
}

void test_manifest_commit_and_load()
{
    /* create and populate manifest */
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(manifest, 2, 200, 2000, 131072);
    tidesdb_manifest_add_sstable(manifest, 1, 101, 1500, 98304);
    tidesdb_manifest_update_sequence(manifest, 54321);

    /* commit to disk */
    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH);
    ASSERT_EQ(result, 0);

    /* free original manifest */
    tidesdb_manifest_free(manifest);

    /* load from disk */
    tidesdb_manifest_t *loaded = tidesdb_manifest_load(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 3);
    ASSERT_EQ(loaded->sequence, 54321);

    /* verify entries */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 101));

    /* verify entry details */
    for (int i = 0; i < loaded->num_entries; i++)
    {
        if (loaded->entries[i].level == 1 && loaded->entries[i].id == 100)
        {
            ASSERT_EQ(loaded->entries[i].num_entries, 1000);
            ASSERT_EQ(loaded->entries[i].size_bytes, 65536);
        }
        else if (loaded->entries[i].level == 2 && loaded->entries[i].id == 200)
        {
            ASSERT_EQ(loaded->entries[i].num_entries, 2000);
            ASSERT_EQ(loaded->entries[i].size_bytes, 131072);
        }
    }

    tidesdb_manifest_free(loaded);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_load_nonexistent()
{
    /* loading non-existent file should create new manifest */
    tidesdb_manifest_t *manifest = tidesdb_manifest_load("./nonexistent_manifest");
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_entries, 0);
    ASSERT_EQ(manifest->sequence, 0);

    tidesdb_manifest_free(manifest);
}

void test_manifest_atomic_commit()
{
    /* create manifest */
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);

    /* commit */
    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH);
    ASSERT_EQ(result, 0);

    tidesdb_manifest_t *loaded = tidesdb_manifest_load(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 1);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 100));

    tidesdb_manifest_free(loaded);
    tidesdb_manifest_free(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_multiple_levels()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add sstables across multiple levels */
    for (int level = 1; level <= 5; level++)
    {
        for (int id = 0; id < 3; id++)
        {
            tidesdb_manifest_add_sstable(manifest, level, id, 1000 * level, 65536 * level);
        }
    }

    ASSERT_EQ(manifest->num_entries, 15); /* 5 levels * 3 sstables */

    /* verify all entries */
    for (int level = 1; level <= 5; level++)
    {
        for (int id = 0; id < 3; id++)
        {
            ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, level, id));
        }
    }

    /* remove all from level 3 */
    for (int id = 0; id < 3; id++)
    {
        tidesdb_manifest_remove_sstable(manifest, 3, id);
    }

    ASSERT_EQ(manifest->num_entries, 12);

    /* verify level 3 entries are gone */
    for (int id = 0; id < 3; id++)
    {
        ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 3, id));
    }

    /* verify other levels still exist */
    for (int level = 1; level <= 5; level++)
    {
        if (level == 3) continue;
        for (int id = 0; id < 3; id++)
        {
            ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, level, id));
        }
    }

    tidesdb_manifest_free(manifest);
}

void test_manifest_persistence_cycle()
{
    /* simulate a full lifecycle: create, add, commit, load, modify, commit, load */

    /* cycle 1: create and commit */
    tidesdb_manifest_t *m1 = tidesdb_manifest_create();
    tidesdb_manifest_add_sstable(m1, 1, 0, 100, 1024);
    tidesdb_manifest_add_sstable(m1, 1, 1, 200, 2048);
    tidesdb_manifest_update_sequence(m1, 1000);
    ASSERT_EQ(tidesdb_manifest_commit(m1, TEST_MANIFEST_PATH), 0);
    tidesdb_manifest_free(m1);

    /* cycle 2: load, modify, commit */
    tidesdb_manifest_t *m2 = tidesdb_manifest_load(TEST_MANIFEST_PATH);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_EQ(m2->sequence, 1000);
    tidesdb_manifest_add_sstable(m2, 2, 0, 300, 4096);
    tidesdb_manifest_remove_sstable(m2, 1, 0);
    tidesdb_manifest_update_sequence(m2, 2000);
    ASSERT_EQ(tidesdb_manifest_commit(m2, TEST_MANIFEST_PATH), 0);
    tidesdb_manifest_free(m2);

    /* cycle 3: load and verify */
    tidesdb_manifest_t *m3 = tidesdb_manifest_load(TEST_MANIFEST_PATH);
    ASSERT_EQ(m3->num_entries, 2);
    ASSERT_EQ(m3->sequence, 2000);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 1, 0)); /* removed */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 1));  /* still there */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 2, 0));  /* added */
    tidesdb_manifest_free(m3);

    remove(TEST_MANIFEST_PATH);
}

void test_manifest_auto_compaction()
{
    /* create a test directory and manifest */
    mkdir("./test_manifest_dir", TDB_DIR_PERMISSIONS);

    tidesdb_manifest_t *m1 = tidesdb_manifest_create();

    /* add entries for ssts */
    tidesdb_manifest_add_sstable(m1, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(m1, 1, 101, 1500, 98304);
    tidesdb_manifest_add_sstable(m1, 2, 200, 2000, 131072);

    /* create actual sst files for some entries */
    FILE *f1 = tdb_fopen("./test_manifest_dir/L1_100.klog", "w");
    fclose(f1);
    FILE *f2 = tdb_fopen("./test_manifest_dir/L2_200.klog", "w");
    fclose(f2);
    /* intentionally do't create L1_101.klog -- its a stale entry */

    /* commit manifest */
    ASSERT_EQ(tidesdb_manifest_commit(m1, "./test_manifest_dir/manifest"), 0);
    tidesdb_manifest_free(m1);

    /* load manifest - should auto-compact and remove stale entry */
    tidesdb_manifest_t *m2 = tidesdb_manifest_load("./test_manifest_dir/manifest");
    ASSERT_TRUE(m2 != NULL);

    /* should only have 2 entries now (101 was removed) */
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 100));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 101)); /* removed */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 2, 200));

    tidesdb_manifest_free(m2);

    /* cleanup */
    remove_directory("./test_manifest_dir");
}

void test_manifest_block_compaction()
{
    /* test that manifest compacts after >100 commits */
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    ASSERT_TRUE(manifest != NULL);

    /* add initial entry */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    tidesdb_manifest_update_sequence(manifest, 0);

    /* commit 150 times to trigger compaction (threshold is 100) */
    for (int i = 0; i < 150; i++)
    {
        tidesdb_manifest_update_sequence(manifest, i);
        int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH);
        ASSERT_EQ(result, 0);
    }

    /* verify manifest can still be loaded correctly */
    tidesdb_manifest_t *loaded = tidesdb_manifest_load(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 1);
    ASSERT_EQ(loaded->sequence, 149);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 100));

    /* verify the file was compacted by checking block count
     * after compaction, should have only 1 block (the current state) */
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, TEST_MANIFEST_PATH, BLOCK_MANAGER_SYNC_NONE) == 0)
    {
        int block_count = block_manager_count_blocks(bm);
        /* should be compacted to 1 block after hitting 100+ blocks */
        ASSERT_TRUE(block_count < 100);
        block_manager_close(bm);
    }

    tidesdb_manifest_free(manifest);
    tidesdb_manifest_free(loaded);
    remove(TEST_MANIFEST_PATH);
}

int main()
{
    printf("\n" BOLDCYAN "Running Manifest Tests...\n" RESET);

    RUN_TEST(test_manifest_create, tests_passed);
    RUN_TEST(test_manifest_add_sstable, tests_passed);
    RUN_TEST(test_manifest_update_existing_sstable, tests_passed);
    RUN_TEST(test_manifest_has_sstable, tests_passed);
    RUN_TEST(test_manifest_remove_sstable, tests_passed);
    RUN_TEST(test_manifest_update_sequence, tests_passed);
    RUN_TEST(test_manifest_capacity_growth, tests_passed);
    RUN_TEST(test_manifest_commit_and_load, tests_passed);
    RUN_TEST(test_manifest_load_nonexistent, tests_passed);
    RUN_TEST(test_manifest_atomic_commit, tests_passed);
    RUN_TEST(test_manifest_multiple_levels, tests_passed);
    RUN_TEST(test_manifest_persistence_cycle, tests_passed);
    RUN_TEST(test_manifest_auto_compaction, tests_passed);
    RUN_TEST(test_manifest_block_compaction, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}