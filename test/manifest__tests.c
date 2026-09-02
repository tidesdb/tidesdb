/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/manifest/manifest.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_MANIFEST_PATH "." PATH_SEPARATOR "test_manifest"

/* octal mode passed to mkdir for the test scratch dirs (ignored on windows) */
#define TEST_MANIFEST_DIR_PERMISSIONS 0755

void test_manifest_create()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_entries, 0);
    ASSERT_EQ(manifest->capacity, MANIFEST_INITIAL_CAPACITY);
    ASSERT_EQ(manifest->sequence, 0);
    ASSERT_TRUE(manifest->entries != NULL);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_add_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add first sstable */
    int result =
        tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_EQ(manifest->entries[0].level, 1);
    ASSERT_EQ(manifest->entries[0].id, 100);
    ASSERT_EQ(manifest->entries[0].num_entries, 1000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 65536);

    /* add second sstable */
    result = tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_EQ(manifest->entries[1].level, 2);
    ASSERT_EQ(manifest->entries[1].id, 200);

    /* add third sstable at same level as first */
    result = tidesdb_manifest_add_sstable(manifest, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 3);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_update_existing_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add sstable */
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    ASSERT_EQ(manifest->num_entries, 1);

    /* update same sstable (same level and id) */
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 2000, 131072, MANIFEST_NO_PARTITION);
    ASSERT_EQ(manifest->num_entries, 1);                /* should still be 1 */
    ASSERT_EQ(manifest->entries[0].num_entries, 2000);  /* updated */
    ASSERT_EQ(manifest->entries[0].size_bytes, 131072); /* updated */

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_has_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add some sstables */
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);

    /* check existing sstables */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 101));

    /* check non-existing sstables */
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 1, 999));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 3, 100));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 2, 100));

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_remove_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add sstables */
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);
    ASSERT_EQ(manifest->num_entries, 3);

    /* remove middle entry */
    int result = tidesdb_manifest_remove_sstable(manifest, 1, 2, 200);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 101));

    /* remove first entry */
    result = tidesdb_manifest_remove_sstable(manifest, 1, 1, 100);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));

    /* try to remove non-existing entry */
    result = tidesdb_manifest_remove_sstable(manifest, 1, 1, 999);
    ASSERT_EQ(result, -1);
    ASSERT_EQ(manifest->num_entries, 1);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_update_sequence()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->sequence, 0);

    tidesdb_manifest_update_sequence(manifest, 12345);
    ASSERT_EQ(manifest->sequence, 12345);

    tidesdb_manifest_update_sequence(manifest, 99999);
    ASSERT_EQ(manifest->sequence, 99999);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_capacity_growth()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->capacity, MANIFEST_INITIAL_CAPACITY);

    /* add more entries than initial capacity to trigger growth */
    for (int i = 0; i < MANIFEST_INITIAL_CAPACITY + 10; i++)
    {
        int result =
            tidesdb_manifest_add_sstable(manifest, 1, 1, i, 1000, 65536, MANIFEST_NO_PARTITION);
        ASSERT_EQ(result, 0);
    }

    ASSERT_EQ(manifest->num_entries, MANIFEST_INITIAL_CAPACITY + 10);
    ASSERT_TRUE(manifest->capacity > MANIFEST_INITIAL_CAPACITY);

    /* verify all entries are still accessible */
    for (int i = 0; i < MANIFEST_INITIAL_CAPACITY + 10; i++)
    {
        ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, i));
    }

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_commit_and_load()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(manifest, 54321);

    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1);
    ASSERT_EQ(result, 0);

    tidesdb_manifest_close(manifest);

    /* load from disk */
    tidesdb_manifest_t *loaded = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 3);
    ASSERT_EQ(loaded->sequence, 54321);

    /* verify entries */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 1, 101));

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

    tidesdb_manifest_close(loaded);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_birth_level_persists()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 3, 500, 100, 4096, 7 /* partitioned */);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 501, 100, 4096, MANIFEST_NO_PARTITION);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *loaded = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 2);
    for (int i = 0; i < loaded->num_entries; i++)
    {
        /* a freshly added sstable is born at its level */
        ASSERT_EQ(loaded->entries[i].birth_level, loaded->entries[i].level);
        if (loaded->entries[i].id == 500) ASSERT_EQ(loaded->entries[i].partition, 7);
    }
    tidesdb_manifest_close(loaded);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_move_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 1, 900, 100, 4096, MANIFEST_NO_PARTITION);
    ASSERT_EQ(tidesdb_manifest_find_level_by_id(manifest, 1, 900), 1);

    /* move id 900 from level 1 to level 3; birth level (which names the file) stays 1 */
    ASSERT_EQ(tidesdb_manifest_move_sstable(manifest, 1, 900, 3), 0);
    ASSERT_EQ(tidesdb_manifest_find_level_by_id(manifest, 1, 900), 3);
    for (int i = 0; i < manifest->num_entries; i++)
        if (manifest->entries[i].id == 900)
        {
            ASSERT_EQ(manifest->entries[i].level, 3);
            ASSERT_EQ(manifest->entries[i].birth_level, 1);
        }
    /* moving an unknown id fails */
    ASSERT_EQ(tidesdb_manifest_move_sstable(manifest, 1, 12345, 2), -1);

    /* the MOVE replays through the append log */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(manifest);
    tidesdb_manifest_t *replayed = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(replayed != NULL);
    ASSERT_EQ(tidesdb_manifest_find_level_by_id(replayed, 1, 900), 3);
    for (int i = 0; i < replayed->num_entries; i++)
        if (replayed->entries[i].id == 900)
        {
            ASSERT_EQ(replayed->entries[i].level, 3);
            ASSERT_EQ(replayed->entries[i].birth_level, 1);
        }

    /* and folds into a rollover snapshot -- a path-change commit re-serializes every entry, so the
     * moved entry's level 3 and birth level 1 must both survive the ADD_P snapshot path (this is
     * what cold-start relies on to reconstruct the file at its birth level) */
    const char *path2 = "./test_manifest_moved.db";
    remove(path2);
    ASSERT_EQ(tidesdb_manifest_commit(replayed, path2, 1), 0);
    tidesdb_manifest_close(replayed);
    tidesdb_manifest_t *rolled = tidesdb_manifest_open(path2);
    ASSERT_TRUE(rolled != NULL);
    ASSERT_EQ(tidesdb_manifest_find_level_by_id(rolled, 1, 900), 3);
    for (int i = 0; i < rolled->num_entries; i++)
        if (rolled->entries[i].id == 900)
        {
            ASSERT_EQ(rolled->entries[i].level, 3);
            ASSERT_EQ(rolled->entries[i].birth_level, 1);
        }
    tidesdb_manifest_close(rolled);
    remove(path2);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_load_nonexistent()
{
    /* loading non-existent file should create new manifest */
    const char *test_path = "nonexistent_manifest_test";
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_entries, 0);
    ASSERT_EQ(manifest->sequence, 0);

    tidesdb_manifest_close(manifest);
    remove(test_path);
}

void test_manifest_atomic_commit()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);

    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1);
    ASSERT_EQ(result, 0);

    tidesdb_manifest_t *loaded = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 1);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 1, 100));

    tidesdb_manifest_close(loaded);
    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_multiple_levels()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add sstables across multiple levels */
    for (int level = 1; level <= 5; level++)
    {
        for (int id = 0; id < 3; id++)
        {
            tidesdb_manifest_add_sstable(manifest, 1, level, id, 1000 * level, 65536 * level,
                                         MANIFEST_NO_PARTITION);
        }
    }

    ASSERT_EQ(manifest->num_entries, 15); /* 5 levels * 3 sstables */

    /* verify all entries */
    for (int level = 1; level <= 5; level++)
    {
        for (int id = 0; id < 3; id++)
        {
            ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, level, id));
        }
    }

    /* remove all from level 3 */
    for (int id = 0; id < 3; id++)
    {
        tidesdb_manifest_remove_sstable(manifest, 1, 3, id);
    }

    ASSERT_EQ(manifest->num_entries, 12);

    /* verify level 3 entries are gone */
    for (int id = 0; id < 3; id++)
    {
        ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 3, id));
    }

    /* verify other levels still exist */
    for (int level = 1; level <= 5; level++)
    {
        if (level == 3) continue;
        for (int id = 0; id < 3; id++)
        {
            ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, level, id));
        }
    }

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_persistence_cycle()
{
    /* simulate a full lifecycle*/

    /* cycle create and commit */
    tidesdb_manifest_t *m1 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    tidesdb_manifest_add_sstable(m1, 1, 1, 0, 100, 1024, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(m1, 1, 1, 1, 200, 2048, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(m1, 1000);
    ASSERT_EQ(tidesdb_manifest_commit(m1, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(m1);

    /* cycle load, modify, commit */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_EQ(m2->sequence, 1000);
    tidesdb_manifest_add_sstable(m2, 1, 2, 0, 300, 4096, MANIFEST_NO_PARTITION);
    tidesdb_manifest_remove_sstable(m2, 1, 1, 0);
    tidesdb_manifest_update_sequence(m2, 2000);
    ASSERT_EQ(tidesdb_manifest_commit(m2, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(m2);

    /* cycle load and verify */
    tidesdb_manifest_t *m3 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_EQ(m3->num_entries, 2);
    ASSERT_EQ(m3->sequence, 2000);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 1, 1, 0)); /* removed */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 1, 1));  /* still there */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 2, 0));  /* added */
    tidesdb_manifest_close(m3);

    remove(TEST_MANIFEST_PATH);
}

void test_manifest_auto_compaction()
{
    mkdir("." PATH_SEPARATOR "test_manifest_dir", TEST_MANIFEST_DIR_PERMISSIONS);

    tidesdb_manifest_t *m1 =
        tidesdb_manifest_open("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest");

    /* add entries for ssts */
    tidesdb_manifest_add_sstable(m1, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(m1, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(m1, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);

    /* create actual sst files for some entries */
    FILE *f1 = tdb_fopen("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "L1_100.klog", "w");
    fclose(f1);
    FILE *f2 = tdb_fopen("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "L2_200.klog", "w");
    fclose(f2);
    /* intentionally don't create L1_101.klog -- its a stale entry */

    /* commit manifest */
    ASSERT_EQ(tidesdb_manifest_commit(
                  m1, "." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest", 1),
              0);
    tidesdb_manifest_close(m1);

    /* load manifest */
    tidesdb_manifest_t *m2 =
        tidesdb_manifest_open("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest");
    ASSERT_TRUE(m2 != NULL);

    /* should have all 3 entries (no auto-compaction) */
    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 2, 200));

    tidesdb_manifest_close(m2);

    remove_directory("." PATH_SEPARATOR "test_manifest_dir");
}

void test_manifest_crash_recovery()
{
    const char *crash_test_path = "." PATH_SEPARATOR "test_crash_manifest";

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m1 != NULL);

    tidesdb_manifest_add_sstable(m1, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(m1, 1, 1, 101, 1500, 98304, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(m1, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(m1, 5000);

    ASSERT_EQ(tidesdb_manifest_commit(m1, crash_test_path, 1), 0);
    tidesdb_manifest_close(m1);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_EQ(m2->sequence, 5000);

    tidesdb_manifest_add_sstable(m2, 1, 3, 300, 3000, 196608, MANIFEST_NO_PARTITION);
    tidesdb_manifest_remove_sstable(m2, 1, 1, 100);
    tidesdb_manifest_update_sequence(m2, 6000);

    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 3, 300));
    ASSERT_EQ(m2->sequence, 6000);

    tidesdb_manifest_close(m2);

    tidesdb_manifest_t *m3 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m3 != NULL);

    ASSERT_EQ(m3->num_entries, 3);
    ASSERT_EQ(m3->sequence, 5000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 2, 200));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 1, 3, 300));

    tidesdb_manifest_add_sstable(m3, 1, 3, 301, 3500, 200000, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(m3, 7000);
    ASSERT_EQ(tidesdb_manifest_commit(m3, crash_test_path, 1), 0);
    tidesdb_manifest_close(m3);

    tidesdb_manifest_t *m4 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m4 != NULL);
    ASSERT_EQ(m4->num_entries, 4);
    ASSERT_EQ(m4->sequence, 7000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 3, 301));

    tidesdb_manifest_close(m4);
    remove(crash_test_path);
}

void test_manifest_orphaned_temp_cleanup()
{
    const char *test_path = "." PATH_SEPARATOR "test_orphan_manifest";

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m1 != NULL);
    tidesdb_manifest_add_sstable(m1, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(m1, 1000);
    ASSERT_EQ(tidesdb_manifest_commit(m1, test_path, 1), 0);
    tidesdb_manifest_close(m1);

    char temp1[256], temp2[256], temp3[256];
    snprintf(temp1, sizeof(temp1), "%s.tmp.12345.9999", test_path);
    snprintf(temp2, sizeof(temp2), "%s.tmp.67890.8888", test_path);
    snprintf(temp3, sizeof(temp3), "%s.tmp.11111.7777", test_path);

    FILE *f1 = tdb_fopen(temp1, "w");
    ASSERT_TRUE(f1 != NULL);
    fprintf(f1, "7\n2000\n1,200,2000,131072\n");
    fclose(f1);

    FILE *f2 = tdb_fopen(temp2, "w");
    ASSERT_TRUE(f2 != NULL);
    fprintf(f2, "7\n3000\n1,300,3000,196608\n");
    fclose(f2);

    FILE *f3 = tdb_fopen(temp3, "w");
    ASSERT_TRUE(f3 != NULL);
    fprintf(f3, "7\n4000\n1,400,4000,262144\n");
    fclose(f3);

    ASSERT_EQ(access(temp1, F_OK), 0);
    ASSERT_EQ(access(temp2, F_OK), 0);
    ASSERT_EQ(access(temp3, F_OK), 0);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);

    /* verify original manifest data is intact */
    ASSERT_EQ(m2->num_entries, 1);
    ASSERT_EQ(m2->sequence, 1000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));

    tidesdb_manifest_close(m2);

    ASSERT_NE(access(temp1, F_OK), 0);
    ASSERT_NE(access(temp2, F_OK), 0);
    ASSERT_NE(access(temp3, F_OK), 0);

    remove(test_path);
}

typedef struct
{
    tidesdb_manifest_t *manifest;
    int thread_id;
    int operations;
} thread_data_t;

void *concurrent_add_thread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    for (int i = 0; i < data->operations; i++)
    {
        uint64_t id = data->thread_id * 1000 + i;
        tidesdb_manifest_add_sstable(data->manifest, 1, data->thread_id, id, i * 100, i * 65536,
                                     MANIFEST_NO_PARTITION);
    }
    return NULL;
}

void *concurrent_read_thread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    for (int i = 0; i < data->operations; i++)
    {
        for (int level = 0; level < 5; level++)
        {
            tidesdb_manifest_has_sstable(data->manifest, 1, level, i);
        }
    }
    return NULL;
}

void test_manifest_concurrent_operations()
{
    const char *test_path = "." PATH_SEPARATOR "test_concurrent_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    const int num_threads = 4;
    const int ops_per_thread = 50;
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads * 2);
    thread_data_t *thread_data = malloc(sizeof(thread_data_t) * num_threads * 2);
    ASSERT_TRUE(threads != NULL);
    ASSERT_TRUE(thread_data != NULL);

    /* create writer threads */
    for (int i = 0; i < num_threads; i++)
    {
        thread_data[i].manifest = manifest;
        thread_data[i].thread_id = i;
        thread_data[i].operations = ops_per_thread;
        pthread_create(&threads[i], NULL, concurrent_add_thread, &thread_data[i]);
    }

    /* create reader threads */
    for (int i = 0; i < num_threads; i++)
    {
        thread_data[num_threads + i].manifest = manifest;
        thread_data[num_threads + i].thread_id = i;
        thread_data[num_threads + i].operations = ops_per_thread;
        pthread_create(&threads[num_threads + i], NULL, concurrent_read_thread,
                       &thread_data[num_threads + i]);
    }

    /* wait for all threads */
    for (int i = 0; i < num_threads * 2; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* verify all entries were added */
    ASSERT_EQ(manifest->num_entries, num_threads * ops_per_thread);

    /* commit and verify persistence */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    /* reload and verify */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, num_threads * ops_per_thread);

    tidesdb_manifest_close(m2);
    remove(test_path);

    free(threads);
    free(thread_data);
}

void test_manifest_corrupted_recovery()
{
    const char *test_path = "." PATH_SEPARATOR "test_corrupted_manifest";

    /* a file that does not begin with a valid block-manager header cannot be a v10 log, so open
     * self-heals to a fresh empty log rather than failing (the sstables on disk are the truth) */
    FILE *f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "999\n1000\n1,100,1000,65536\n");
    fclose(f);

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m1 != NULL);
    ASSERT_EQ(m1->num_entries, 0);
    tidesdb_manifest_close(m1);
    remove(test_path);

    /* arbitrary text bytes are not a header either, so they self-heal to empty as well */
    f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "7\n2000\n1 100 1000 65536\n");
    fclose(f);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 0);
    tidesdb_manifest_close(m2);
    remove(test_path);

    /* test empty file */
    f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fclose(f);

    tidesdb_manifest_t *m4 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m4 != NULL);
    ASSERT_EQ(m4->num_entries, 0);
    tidesdb_manifest_close(m4);
    remove(test_path);
}

void test_manifest_large_stress()
{
    const char *test_path = "." PATH_SEPARATOR "test_large_manifest";

    remove(test_path);

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    const int num_entries = 10000;
    int initial_capacity = manifest->capacity;

    /* we add many entries to trigger multiple reallocations */
    for (int i = 0; i < num_entries; i++)
    {
        int level = i % 7;
        uint64_t id = i;
        uint64_t num_ents = i * 10;
        uint64_t size = i * 1024;
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, level, id, num_ents, size,
                                               MANIFEST_NO_PARTITION),
                  0);
    }

    ASSERT_EQ(manifest->num_entries, num_entries);
    ASSERT_TRUE(manifest->capacity > initial_capacity);

    /* we verify random entries (level = id % 7) */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 0 % 7, 0));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 5555 % 7, 5555));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 9999 % 7, 9999));

    /* we commit large manifest */
    tidesdb_manifest_update_sequence(manifest, 999999);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    /* we reload and verify all entries */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, num_entries);
    ASSERT_EQ(m2->sequence, 999999);

    /* we verify random entries after reload */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 0 % 7, 0));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 5555 % 7, 5555));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 9999 % 7, 9999));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 0, 99999));

    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_duplicate_id_handling()
{
    const char *test_path = "." PATH_SEPARATOR "test_duplicate_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION),
              0);
    ASSERT_EQ(manifest->num_entries, 1);

    /* we add same level+id with different values (should update, not add) */
    ASSERT_EQ(
        tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 2000, 131072, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(manifest->num_entries, 1);

    /* we verify updated values */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));
    ASSERT_EQ(manifest->entries[0].num_entries, 2000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 131072);

    /* we add multiple updates */
    for (int i = 0; i < 10; i++)
    {
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 100, i * 1000, i * 65536,
                                               MANIFEST_NO_PARTITION),
                  0);
        ASSERT_EQ(manifest->num_entries, 1);
    }

    /* we verify final update */
    ASSERT_EQ(manifest->entries[0].num_entries, 9000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 9 * 65536);

    /* we add different id on same level */
    ASSERT_EQ(
        tidesdb_manifest_add_sstable(manifest, 1, 1, 101, 5000, 200000, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(manifest->num_entries, 2);

    /* we add same id on different level (should add, not update) */
    ASSERT_EQ(
        tidesdb_manifest_add_sstable(manifest, 1, 2, 100, 3000, 150000, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(manifest->num_entries, 3);

    /* we verify all entries exist */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 2, 100));

    /* test remove non-existent */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 5, 999), -1);
    ASSERT_EQ(manifest->num_entries, 3);

    /* test remove existing */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 1, 100), 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));

    /* we commit and reload to verify persistence */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 2, 100));

    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_null_safety(void)
{
    /* tidesdb_manifest_open with NULL path */
    ASSERT_TRUE(tidesdb_manifest_open(NULL) == NULL);

    /* tidesdb_manifest_add_sstable with NULL manifest */
    ASSERT_EQ(tidesdb_manifest_add_sstable(NULL, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION),
              -1);

    /* tidesdb_manifest_remove_sstable with NULL manifest */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(NULL, 1, 1, 100), -1);

    /* tidesdb_manifest_has_sstable with NULL manifest */
    ASSERT_EQ(tidesdb_manifest_has_sstable(NULL, 1, 1, 100), 0);

    /* tidesdb_manifest_update_sequence with NULL should not crash */
    tidesdb_manifest_update_sequence(NULL, 12345);

    /* tidesdb_manifest_commit with NULL manifest */
    ASSERT_EQ(tidesdb_manifest_commit(NULL, "some_path", 1), -1);

    /* tidesdb_manifest_commit with NULL path */
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, NULL, 1), -1);
    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);

    /* tidesdb_manifest_close with NULL should not crash */
    tidesdb_manifest_close(NULL);
}

void test_manifest_commit_different_path(void)
{
    const char *path1 = "." PATH_SEPARATOR "test_manifest_path1";
    const char *path2 = "." PATH_SEPARATOR "test_manifest_path2";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(path1);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(manifest, 5000);

    /* we commit to path1 first */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, path1, 1), 0);

    /* we add more data and commit to a different path */
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(manifest, 6000);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, path2, 1), 0);

    tidesdb_manifest_close(manifest);

    /* we verify path2 has all entries */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(path2);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_EQ(m2->sequence, 6000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 2, 200));
    tidesdb_manifest_close(m2);

    /* we verify path1 still has original data */
    tidesdb_manifest_t *m1 = tidesdb_manifest_open(path1);
    ASSERT_TRUE(m1 != NULL);
    ASSERT_EQ(m1->num_entries, 1);
    ASSERT_EQ(m1->sequence, 5000);
    tidesdb_manifest_close(m1);

    remove(path1);
    remove(path2);
}

void test_manifest_corrupted_version_nonnumeric(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_nonnumeric_manifest";

    FILE *f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "abc\n1000\n1,100,1000,65536\n");
    fclose(f);

    /* a non-numeric version is not the legacy text format nor a valid binary header, so open
     * self-heals to a fresh empty log rather than failing */
    tidesdb_manifest_t *m = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m != NULL);
    ASSERT_EQ(m->num_entries, 0);
    tidesdb_manifest_close(m);

    remove(test_path);
}

void test_manifest_remove_to_zero(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    ASSERT_EQ(manifest->num_entries, 1);

    /* we remove the sole entry */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 1, 100), 0);
    ASSERT_EQ(manifest->num_entries, 0);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 1, 100));

    /* we verify we can still add after emptying */
    ASSERT_EQ(
        tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 2, 200));

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_commit_empty(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_empty_commit_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_entries, 0);

    /* we commit with zero entries */
    tidesdb_manifest_update_sequence(manifest, 42);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    /* we reload and verify */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 0);
    ASSERT_EQ(m2->sequence, 42);
    tidesdb_manifest_close(m2);

    remove(test_path);
}

void test_manifest_large_uint64_roundtrip(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_large_uint64_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    const uint64_t large_id = UINT64_MAX - 1;
    const uint64_t large_entries = UINT64_MAX / 2;
    const uint64_t large_size = UINT64_MAX;

    tidesdb_manifest_add_sstable(manifest, 1, 1, large_id, large_entries, large_size,
                                 MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(manifest, UINT64_MAX);

    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    /* we reload and verify large values survived round-trip */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 1);
    ASSERT_EQ(m2->sequence, UINT64_MAX);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, large_id));
    ASSERT_EQ(m2->entries[0].id, large_id);
    ASSERT_EQ(m2->entries[0].num_entries, large_entries);
    ASSERT_EQ(m2->entries[0].size_bytes, large_size);

    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_binary_format_roundtrip(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_binary_format_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    tidesdb_manifest_update_sequence(manifest, 4242);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    /* the committed file is the append-only block-manager log -- per-block xxhash checksums give it
     * integrity and it round-trips every field on reload */
    FILE *f = tdb_fopen(test_path, "rb");
    ASSERT_TRUE(f != NULL);
    unsigned char first = 0;
    ASSERT_TRUE(fread(&first, 1, 1, f) == 1);
    fclose(f);

    /* the reload must reproduce every field */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->sequence, 4242);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 2, 200));
    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_self_heals_on_corruption(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_corrupt_manifest_bin";

    /* build a two-commit log so there is a non-final block to corrupt */
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    tidesdb_manifest_add_sstable(manifest, 1, 1, 100, 1000, 65536, MANIFEST_NO_PARTITION);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_add_sstable(manifest, 1, 2, 200, 2000, 131072, MANIFEST_NO_PARTITION);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 1), 0);
    tidesdb_manifest_close(manifest);

    unsigned char buf[1024];
    FILE *f = tdb_fopen(test_path, "rb");
    ASSERT_TRUE(f != NULL);
    const size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_TRUE(n > 24);

    /* torn tail -- a crash mid-append leaves the final block truncated. open must not fail; the
     * sstable files (not tested here) are the ground truth that recovery reloads. */
    {
        FILE *w = tdb_fopen(test_path, "wb");
        ASSERT_TRUE(w != NULL);
        ASSERT_EQ(fwrite(buf, 1, n - 6, w), n - 6); /* cut into the last block */
        fclose(w);

        tidesdb_manifest_t *mt = tidesdb_manifest_open(test_path);
        ASSERT_TRUE(mt != NULL);
        tidesdb_manifest_close(mt);
    }

    /* unreadable manifest -- overwrite it with garbage (a corrupt header). open must self-heal to a
     * fresh usable log rather than fail (the sstable files, not tested here, are the ground truth
     * recovery reloads), and an add + commit + reopen must round-trip cleanly afterward. */
    {
        FILE *w = tdb_fopen(test_path, "wb");
        ASSERT_TRUE(w != NULL);
        const char garbage[] = "not a manifest at all -- pure garbage bytes \x01\x02\x03";
        ASSERT_EQ(fwrite(garbage, 1, sizeof(garbage), w), sizeof(garbage));
        fclose(w);

        tidesdb_manifest_t *mc = tidesdb_manifest_open(test_path);
        ASSERT_TRUE(mc != NULL);
        ASSERT_EQ(tidesdb_manifest_add_sstable(mc, 1, 5, 500, 5000, 4096, MANIFEST_NO_PARTITION),
                  0);
        ASSERT_EQ(tidesdb_manifest_commit(mc, test_path, 1), 0);
        tidesdb_manifest_close(mc);

        tidesdb_manifest_t *mc2 = tidesdb_manifest_open(test_path);
        ASSERT_TRUE(mc2 != NULL);
        ASSERT_TRUE(tidesdb_manifest_has_sstable(mc2, 1, 5, 500));
        tidesdb_manifest_close(mc2);
    }

    remove(test_path);
}

void test_manifest_cf_registry(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(manifest->num_cfs, 0);

    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "default", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 2, "users", NULL, 0), 0);
    ASSERT_EQ(manifest->num_cfs, 2);

    /* re-adding an id renames it in place rather than duplicating */
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 2, "accounts", NULL, 0), 0);
    ASSERT_EQ(manifest->num_cfs, 2);

    uint64_t id = 0;
    ASSERT_EQ(tidesdb_manifest_cf_id_by_name(manifest, "accounts", &id), 0);
    ASSERT_EQ(id, 2);
    ASSERT_EQ(tidesdb_manifest_cf_id_by_name(manifest, "users", &id), -1);
    ASSERT_EQ(tidesdb_manifest_cf_id_by_name(manifest, "default", &id), 0);
    ASSERT_EQ(id, 1);

    ASSERT_EQ(tidesdb_manifest_copy_cfs(manifest, NULL, 0), 2);
    tidesdb_manifest_cf_t got[4];
    ASSERT_EQ(tidesdb_manifest_copy_cfs(manifest, got, 4), 2);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_cf_isolation(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* the same (level, id) in two column families are distinct entries */
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 42, 10, 100, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 2, 1, 42, 20, 200, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(manifest->num_entries, 2);

    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 1, 1, 42), 1);
    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 2, 1, 42), 1);
    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 3, 1, 42), 0);

    /* removing from one cf leaves the other's entry intact */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 1, 42), 0);
    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 1, 1, 42), 0);
    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 2, 1, 42), 1);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

/* records buffered by a caller that then gave up belong to the next commit, whoever makes it. this
 * is why a caller that mutates the set and cannot finish has to put it back rather than simply
 * return -- an abandoned half-batch is not discarded, it waits, and the next commit from any path
 * at all carries it durably */
void test_manifest_an_abandoned_half_batch_lands_on_the_next_commit(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_halfbatch_manifest";
    remove(test_path);

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "kv", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 10, 100, 4096, MANIFEST_NO_PARTITION),
              0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 11, 100, 4096, MANIFEST_NO_PARTITION),
              0);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 0), 0);

    /* a caller starts replacing 10 and 11 with 12, gets one removal in, and stops there */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 1, 10), 0);

    /* somebody else's commit -- a flush, say -- now carries that removal */
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 2, 99, 1, 1, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 0), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *reloaded = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(reloaded != NULL);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(reloaded, 1, 1, 10)); /* durably gone */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(reloaded, 1, 1, 11));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(reloaded, 1, 2, 99));
    tidesdb_manifest_close(reloaded);
    remove(test_path);
}

/* comfortably past MANIFEST_INITIAL_CAPACITY, so the registry, the tombstone sets and the entry
 * array all have to grow, and enough records with it to force a rollover through the snapshot */
#define TEST_MANIFEST_GROWTH_CFS 300

/* every growable array in the set outgrows the capacity it was created with, and the whole thing
 * survives the snapshot a rollover writes. the arrays start empty or at one fixed size and double,
 * so a wrong first step reads back as a set that is short or is not there */
void test_manifest_arrays_grow_past_their_initial_capacity(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_growth_manifest";
    remove(test_path);

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    for (int i = 0; i < TEST_MANIFEST_GROWTH_CFS; i++)
    {
        char name[MANIFEST_CF_NAME_MAX];
        snprintf(name, sizeof(name), "cf%04d", i);
        const uint8_t config[] = {(uint8_t)i, (uint8_t)(i >> 8), 0xEE};
        ASSERT_EQ(tidesdb_manifest_add_cf(manifest, (uint64_t)i, name, config, sizeof(config)), 0);

        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, (uint64_t)i, 1, (uint64_t)i, 10, 100,
                                               MANIFEST_NO_PARTITION),
                  0);
    }
    ASSERT_EQ(manifest->num_cfs, TEST_MANIFEST_GROWTH_CFS);
    ASSERT_EQ(manifest->num_entries, TEST_MANIFEST_GROWTH_CFS);
    ASSERT_TRUE(manifest->cfs_capacity >= TEST_MANIFEST_GROWTH_CFS);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 0), 0);
    /* the counter resets only on a rollover, so this is what says the reload below reads a snapshot
     * rather than a log of the records that built it. each family adds one cf record and one
     * sstable record, and the commit itself one more, which is what carries the count past twice
     * the live entries */
    ASSERT_EQ(manifest->records_since_snapshot, 0);
    tidesdb_manifest_close(manifest);

    /* replayed from the snapshot the rollover left behind */
    tidesdb_manifest_t *reloaded = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(reloaded != NULL);
    ASSERT_EQ(reloaded->num_cfs, TEST_MANIFEST_GROWTH_CFS);
    ASSERT_EQ(reloaded->num_entries, TEST_MANIFEST_GROWTH_CFS);

    for (int i = 0; i < TEST_MANIFEST_GROWTH_CFS; i++)
    {
        char name[MANIFEST_CF_NAME_MAX];
        snprintf(name, sizeof(name), "cf%04d", i);
        uint64_t id = 0;
        ASSERT_EQ(tidesdb_manifest_cf_id_by_name(reloaded, name, &id), 0);
        ASSERT_EQ((int)id, i);
        ASSERT_TRUE(tidesdb_manifest_has_sstable(reloaded, (uint64_t)i, 1, (uint64_t)i));
    }

    tidesdb_manifest_close(reloaded);
    remove(test_path);
}

/* the live set the hold test builds, the commits it needs to force a rollover past the 512-record
 * bound, and how long it lets the blocked committer try before checking it made no progress */
#define TEST_MANIFEST_HOLD_ENTRIES 20
#define TEST_MANIFEST_HOLD_COMMITS 400
#define TEST_MANIFEST_HOLD_WAIT_US 50000

typedef struct
{
    tidesdb_manifest_t *manifest;
    const char *path;
    _Atomic(int) committed;
} manifest_hold_committer_t;

/* commit enough records to carry the log past its rollover bound, counting each one that lands */
static void *manifest_commit_until_rollover(void *arg)
{
    manifest_hold_committer_t *c = (manifest_hold_committer_t *)arg;
    for (int i = 0; i < TEST_MANIFEST_HOLD_COMMITS; i++)
    {
        tidesdb_manifest_add_sstable(c->manifest, 1, 1, (uint64_t)(i % TEST_MANIFEST_HOLD_ENTRIES),
                                     1000, 65536, MANIFEST_NO_PARTITION);
        tidesdb_manifest_commit(c->manifest, c->path, 0);
        atomic_fetch_add(&c->committed, 1);
    }
    return NULL;
}

/* a hold stops the log moving, which is what lets a caller measure it and then open it by name and
 * get the same bytes. a commit that carries the log past its rollover bound renames a fresh
 * snapshot over the path, so without the hold a length and the file it is applied to can belong to
 * two different files -- the second half of this asserts that rename really does happen, since a
 * hold that blocked nothing would pass the first half on its own */
void test_manifest_hold_keeps_the_log_still(void)
{
    const char *test_path = "." PATH_SEPARATOR "test_hold_manifest";
    remove(test_path);

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "kv", NULL, 0), 0);
    for (int i = 0; i < TEST_MANIFEST_HOLD_ENTRIES; i++)
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, (uint64_t)i, 1000, 65536,
                                               MANIFEST_NO_PARTITION),
                  0);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path, 0), 0);

    uint64_t held_len = 0;
    ASSERT_EQ(tidesdb_manifest_hold(manifest, &held_len), 0);
    ASSERT_TRUE(held_len > 0);
    unsigned long long held_id = 0;
    ASSERT_EQ(test_file_identity(test_path, &held_id), 0);

    manifest_hold_committer_t c = {.manifest = manifest, .path = test_path};
    atomic_init(&c.committed, 0);
    pthread_t committer;
    ASSERT_EQ(pthread_create(&committer, NULL, manifest_commit_until_rollover, &c), 0);

    /* the first commit blocks on the hold, so not one of them lands and the file the length
     * describes is still the file at the path */
    usleep(TEST_MANIFEST_HOLD_WAIT_US);
    ASSERT_EQ(atomic_load(&c.committed), 0);
    unsigned long long during_id = 0;
    ASSERT_EQ(test_file_identity(test_path, &during_id), 0);
    ASSERT_EQ((int)(during_id == held_id), 1);
    struct stat during;
    ASSERT_EQ(stat(test_path, &during), 0);
    ASSERT_EQ((long long)during.st_size, (long long)held_len);

    tidesdb_manifest_release(manifest);
    pthread_join(committer, NULL);

    /* and the commits the hold was holding back do replace the file, which is the thing a length
     * measured outside a hold would have been applied to */
    unsigned long long after_id = 0;
    ASSERT_EQ(test_file_identity(test_path, &after_id), 0);
    ASSERT_EQ(atomic_load(&c.committed), TEST_MANIFEST_HOLD_COMMITS);
    ASSERT_EQ((int)(after_id != held_id), 1);

    tidesdb_manifest_close(manifest);
    remove(test_path);
}

void test_manifest_cf_drop_cascade(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "keep", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 2, "drop", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 1, 10, 1, 1, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 2, 1, 20, 1, 1, MANIFEST_NO_PARTITION), 0);

    /* dropping cf 2 removes its cf entry and its sstables, leaving cf 1 untouched */
    ASSERT_EQ(tidesdb_manifest_drop_cf(manifest, 2), 0);
    ASSERT_EQ(manifest->num_cfs, 1);
    ASSERT_EQ(manifest->num_entries, 1);
    ASSERT_EQ(tidesdb_manifest_has_sstable(manifest, 1, 1, 10), 1);

    /* dropping an absent cf is a no-op error */
    ASSERT_EQ(tidesdb_manifest_drop_cf(manifest, 99), -1);

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_cf_persist(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "default", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 7, "metrics", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 7, 2, 55, 3, 30, MANIFEST_NO_PARTITION), 0);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(manifest);

    /* the cf registry and cf-tagged entries survive a close and reopen replay */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_cfs, 2);
    uint64_t id = 0;
    ASSERT_EQ(tidesdb_manifest_cf_id_by_name(m2, "metrics", &id), 0);
    ASSERT_EQ(id, 7);
    ASSERT_EQ(tidesdb_manifest_has_sstable(m2, 7, 2, 55), 1);
    ASSERT_EQ(tidesdb_manifest_find_level_by_id(m2, 7, 55), 2);
    tidesdb_manifest_close(m2);
    remove(TEST_MANIFEST_PATH);
}

/* a cf's opaque config blob round-trips through commit and reopen replay */
void test_manifest_cf_config_blob(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    uint8_t blob[67];
    for (int i = 0; i < (int)sizeof(blob); i++) blob[i] = (uint8_t)(i * 3 + 1);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 4, "shaped", blob, sizeof(blob)), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 5, "plain", NULL, 0), 0); /* a cf with no config */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(m2 != NULL);
    tidesdb_manifest_cf_t cfs[4];
    const int n = tidesdb_manifest_copy_cfs(m2, cfs, 4);
    ASSERT_EQ(n, 2);
    for (int i = 0; i < n; i++)
    {
        if (cfs[i].id == 4)
        {
            ASSERT_EQ((int)cfs[i].config_blob_len, (int)sizeof(blob));
            ASSERT_TRUE(memcmp(cfs[i].config_blob, blob, sizeof(blob)) == 0);
        }
        else
        {
            ASSERT_EQ((int)cfs[i].id, 5);
            ASSERT_EQ((int)cfs[i].config_blob_len, 0); /* a NULL-blob cf recovers with no config */
        }
    }
    tidesdb_manifest_close(m2);
    remove(TEST_MANIFEST_PATH);
}

/* the cf-id high-water outlives the family that set it, so dropping the largest id and reopening
 * does not hand that id out again -- a reissued id would let a dropped family's unreaped wal
 * records replay into whichever family later took it */
void test_manifest_cf_id_high_water_survives_drop(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 0, "a", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 1, "b", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 2, "c", NULL, 0), 0);
    ASSERT_EQ((int)atomic_load(&manifest->next_cf_id), 3); /* adding a family raises it */

    /* drop the largest id; the high-water must not follow it back down */
    ASSERT_EQ(tidesdb_manifest_drop_cf(manifest, 2), 0);
    ASSERT_EQ((int)atomic_load(&manifest->next_cf_id), 3);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 1), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_cfs, 2); /* only the two survivors come back */
    ASSERT_EQ((int)atomic_load(&m2->next_cf_id), 3);
    tidesdb_manifest_close(m2);
    remove(TEST_MANIFEST_PATH);
}

/* a rollover emits only the live families, so the high-water rides its own snapshot record rather
 * than being re-derived from the ids the snapshot happens to still describe */
void test_manifest_cf_id_high_water_survives_snapshot(void)
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 0, "keep", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, 9, "doomed", NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_drop_cf(manifest, 9), 0);

    /* push past the rollover threshold so the log collapses into a fresh snapshot block */
    for (int i = 0; i < MANIFEST_ROLLOVER_MIN_RECORDS + 16; i++)
    {
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 0, 1, (uint64_t)(100 + i), 1, 1,
                                               MANIFEST_NO_PARTITION),
                  0);
        ASSERT_EQ(tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH, 0), 0);
    }
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_cfs, 1);                        /* the dropped family is gone */
    ASSERT_EQ((int)atomic_load(&m2->next_cf_id), 10); /* but its id stays spent */
    tidesdb_manifest_close(m2);
    remove(TEST_MANIFEST_PATH);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_manifest_create, tests_passed);
    RUN_TEST(test_manifest_add_sstable, tests_passed);
    RUN_TEST(test_manifest_update_existing_sstable, tests_passed);
    RUN_TEST(test_manifest_has_sstable, tests_passed);
    RUN_TEST(test_manifest_remove_sstable, tests_passed);
    RUN_TEST(test_manifest_update_sequence, tests_passed);
    RUN_TEST(test_manifest_capacity_growth, tests_passed);
    RUN_TEST(test_manifest_commit_and_load, tests_passed);
    RUN_TEST(test_manifest_birth_level_persists, tests_passed);
    RUN_TEST(test_manifest_move_sstable, tests_passed);
    RUN_TEST(test_manifest_load_nonexistent, tests_passed);
    RUN_TEST(test_manifest_atomic_commit, tests_passed);
    RUN_TEST(test_manifest_multiple_levels, tests_passed);
    RUN_TEST(test_manifest_persistence_cycle, tests_passed);
    RUN_TEST(test_manifest_auto_compaction, tests_passed);
    RUN_TEST(test_manifest_crash_recovery, tests_passed);
    RUN_TEST(test_manifest_orphaned_temp_cleanup, tests_passed);
    RUN_TEST(test_manifest_concurrent_operations, tests_passed);
    RUN_TEST(test_manifest_corrupted_recovery, tests_passed);
    RUN_TEST(test_manifest_large_stress, tests_passed);
    RUN_TEST(test_manifest_duplicate_id_handling, tests_passed);
    RUN_TEST(test_manifest_null_safety, tests_passed);
    RUN_TEST(test_manifest_commit_different_path, tests_passed);
    RUN_TEST(test_manifest_corrupted_version_nonnumeric, tests_passed);
    RUN_TEST(test_manifest_remove_to_zero, tests_passed);
    RUN_TEST(test_manifest_commit_empty, tests_passed);
    RUN_TEST(test_manifest_large_uint64_roundtrip, tests_passed);
    RUN_TEST(test_manifest_binary_format_roundtrip, tests_passed);
    RUN_TEST(test_manifest_self_heals_on_corruption, tests_passed);
    RUN_TEST(test_manifest_cf_registry, tests_passed);
    RUN_TEST(test_manifest_cf_isolation, tests_passed);
    RUN_TEST(test_manifest_an_abandoned_half_batch_lands_on_the_next_commit, tests_passed);
    RUN_TEST(test_manifest_arrays_grow_past_their_initial_capacity, tests_passed);
    RUN_TEST(test_manifest_hold_keeps_the_log_still, tests_passed);
    RUN_TEST(test_manifest_cf_drop_cascade, tests_passed);
    RUN_TEST(test_manifest_cf_persist, tests_passed);
    RUN_TEST(test_manifest_cf_config_blob, tests_passed);
    RUN_TEST(test_manifest_cf_id_high_water_survives_drop, tests_passed);
    RUN_TEST(test_manifest_cf_id_high_water_survives_snapshot, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}