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

#define TEST_MANIFEST_PATH "." PATH_SEPARATOR "test_manifest"

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

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_update_existing_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    /* add sstable */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    ASSERT_EQ(manifest->num_entries, 1);

    /* update same sstable (same level and id) */
    tidesdb_manifest_add_sstable(manifest, 1, 100, 2000, 131072);
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

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_remove_sstable()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
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

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_commit_and_load()
{
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(manifest != NULL);

    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(manifest, 2, 200, 2000, 131072);
    tidesdb_manifest_add_sstable(manifest, 1, 101, 1500, 98304);
    tidesdb_manifest_update_sequence(manifest, 54321);

    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH);
    ASSERT_EQ(result, 0);

    tidesdb_manifest_close(manifest);

    /* load from disk */
    tidesdb_manifest_t *loaded = tidesdb_manifest_open(TEST_MANIFEST_PATH);
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

    tidesdb_manifest_close(loaded);
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

    tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536);

    int result = tidesdb_manifest_commit(manifest, TEST_MANIFEST_PATH);
    ASSERT_EQ(result, 0);

    tidesdb_manifest_t *loaded = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_TRUE(loaded != NULL);
    ASSERT_EQ(loaded->num_entries, 1);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(loaded, 1, 100));

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

    tidesdb_manifest_close(manifest);
    remove(TEST_MANIFEST_PATH);
}

void test_manifest_persistence_cycle()
{
    /* simulate a full lifecycle*/

    /* cycle create and commit */
    tidesdb_manifest_t *m1 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    tidesdb_manifest_add_sstable(m1, 1, 0, 100, 1024);
    tidesdb_manifest_add_sstable(m1, 1, 1, 200, 2048);
    tidesdb_manifest_update_sequence(m1, 1000);
    ASSERT_EQ(tidesdb_manifest_commit(m1, TEST_MANIFEST_PATH), 0);
    tidesdb_manifest_close(m1);

    /* cycle load, modify, commit */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_EQ(m2->sequence, 1000);
    tidesdb_manifest_add_sstable(m2, 2, 0, 300, 4096);
    tidesdb_manifest_remove_sstable(m2, 1, 0);
    tidesdb_manifest_update_sequence(m2, 2000);
    ASSERT_EQ(tidesdb_manifest_commit(m2, TEST_MANIFEST_PATH), 0);
    tidesdb_manifest_close(m2);

    /* cycle load and verify */
    tidesdb_manifest_t *m3 = tidesdb_manifest_open(TEST_MANIFEST_PATH);
    ASSERT_EQ(m3->num_entries, 2);
    ASSERT_EQ(m3->sequence, 2000);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 1, 0)); /* removed */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 1));  /* still there */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 2, 0));  /* added */
    tidesdb_manifest_close(m3);

    remove(TEST_MANIFEST_PATH);
}

void test_manifest_auto_compaction()
{
    mkdir("." PATH_SEPARATOR "test_manifest_dir", TDB_DIR_PERMISSIONS);

    tidesdb_manifest_t *m1 =
        tidesdb_manifest_open("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest");

    /* add entries for ssts */
    tidesdb_manifest_add_sstable(m1, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(m1, 1, 101, 1500, 98304);
    tidesdb_manifest_add_sstable(m1, 2, 200, 2000, 131072);

    /* create actual sst files for some entries */
    FILE *f1 = tdb_fopen("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "L1_100.klog", "w");
    fclose(f1);
    FILE *f2 = tdb_fopen("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "L2_200.klog", "w");
    fclose(f2);
    /* intentionally don't create L1_101.klog -- its a stale entry */

    /* commit manifest */
    ASSERT_EQ(tidesdb_manifest_commit(
                  m1, "." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest"),
              0);
    tidesdb_manifest_close(m1);

    /* load manifest */
    tidesdb_manifest_t *m2 =
        tidesdb_manifest_open("." PATH_SEPARATOR "test_manifest_dir" PATH_SEPARATOR "manifest");
    ASSERT_TRUE(m2 != NULL);

    /* should have all 3 entries (no auto-compaction) */
    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 2, 200));

    tidesdb_manifest_close(m2);

    remove_directory("." PATH_SEPARATOR "test_manifest_dir");
}

void test_manifest_crash_recovery()
{
    const char *crash_test_path = "." PATH_SEPARATOR "test_crash_manifest";

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m1 != NULL);

    tidesdb_manifest_add_sstable(m1, 1, 100, 1000, 65536);
    tidesdb_manifest_add_sstable(m1, 1, 101, 1500, 98304);
    tidesdb_manifest_add_sstable(m1, 2, 200, 2000, 131072);
    tidesdb_manifest_update_sequence(m1, 5000);

    ASSERT_EQ(tidesdb_manifest_commit(m1, crash_test_path), 0);
    tidesdb_manifest_close(m1);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_EQ(m2->sequence, 5000);

    tidesdb_manifest_add_sstable(m2, 3, 300, 3000, 196608);
    tidesdb_manifest_remove_sstable(m2, 1, 100);
    tidesdb_manifest_update_sequence(m2, 6000);

    ASSERT_EQ(m2->num_entries, 3);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 3, 300));
    ASSERT_EQ(m2->sequence, 6000);

    tidesdb_manifest_close(m2);

    tidesdb_manifest_t *m3 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m3 != NULL);

    ASSERT_EQ(m3->num_entries, 3);
    ASSERT_EQ(m3->sequence, 5000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 2, 200));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 3, 300));

    tidesdb_manifest_add_sstable(m3, 3, 301, 3500, 200000);
    tidesdb_manifest_update_sequence(m3, 7000);
    ASSERT_EQ(tidesdb_manifest_commit(m3, crash_test_path), 0);
    tidesdb_manifest_close(m3);

    tidesdb_manifest_t *m4 = tidesdb_manifest_open(crash_test_path);
    ASSERT_TRUE(m4 != NULL);
    ASSERT_EQ(m4->num_entries, 4);
    ASSERT_EQ(m4->sequence, 7000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m4, 3, 301));

    tidesdb_manifest_close(m4);
    remove(crash_test_path);
}

void test_manifest_orphaned_temp_cleanup()
{
    const char *test_path = "." PATH_SEPARATOR "test_orphan_manifest";

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m1 != NULL);
    tidesdb_manifest_add_sstable(m1, 1, 100, 1000, 65536);
    tidesdb_manifest_update_sequence(m1, 1000);
    ASSERT_EQ(tidesdb_manifest_commit(m1, test_path), 0);
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

    /*  simulate crash by creating orphaned temp files
     * these would be left behind if commit crashed before rename */
    /* verify temp files exist */
    ASSERT_EQ(access(temp1, F_OK), 0);
    ASSERT_EQ(access(temp2, F_OK), 0);
    ASSERT_EQ(access(temp3, F_OK), 0);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);

    /* verify original manifest data is intact */
    ASSERT_EQ(m2->num_entries, 1);
    ASSERT_EQ(m2->sequence, 1000);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 100));

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
        tidesdb_manifest_add_sstable(data->manifest, data->thread_id, id, i * 100, i * 65536);
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
            tidesdb_manifest_has_sstable(data->manifest, level, i);
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
    pthread_t threads[num_threads * 2];
    thread_data_t thread_data[num_threads * 2];

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
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path), 0);
    tidesdb_manifest_close(manifest);

    /* reload and verify */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, num_threads * ops_per_thread);

    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_corrupted_recovery()
{
    const char *test_path = "." PATH_SEPARATOR "test_corrupted_manifest";

    /* test invalid version */
    FILE *f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "999\n1000\n1,100,1000,65536\n");
    fclose(f);

    tidesdb_manifest_t *m1 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m1 == NULL);
    remove(test_path);

    /* test malformed entry (missing comma) */
    f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "7\n2000\n1 100 1000 65536\n");
    fclose(f);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 0);
    tidesdb_manifest_close(m2);
    remove(test_path);

    /* test partial valid entries */
    f = tdb_fopen(test_path, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "7\n3000\n");
    fprintf(f, "1,100,1000,65536\n");
    fprintf(f, "invalid line here\n");
    fprintf(f, "2,200,2000,131072\n");
    fprintf(f, "3,300\n");
    fprintf(f, "4,400,4000,262144\n");
    fclose(f);

    tidesdb_manifest_t *m3 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m3 != NULL);
    ASSERT_EQ(m3->sequence, 3000);
    ASSERT_EQ(m3->num_entries, 3);
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 2, 200));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m3, 4, 400));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m3, 3, 300));
    tidesdb_manifest_close(m3);
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
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, level, id, num_ents, size), 0);
    }

    ASSERT_EQ(manifest->num_entries, num_entries);
    ASSERT_TRUE(manifest->capacity > initial_capacity);

    /* we verify random entries (level = id % 7) */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 0 % 7, 0));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 5555 % 7, 5555));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 9999 % 7, 9999));

    /* we commit large manifest */
    tidesdb_manifest_update_sequence(manifest, 999999);
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path), 0);
    tidesdb_manifest_close(manifest);

    /* we reload and verify all entries */
    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, num_entries);
    ASSERT_EQ(m2->sequence, 999999);

    /* we verify random entries after reload */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 0 % 7, 0));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 5555 % 7, 5555));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 9999 % 7, 9999));
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 0, 99999));

    tidesdb_manifest_close(m2);
    remove(test_path);
}

void test_manifest_duplicate_id_handling()
{
    const char *test_path = "." PATH_SEPARATOR "test_duplicate_manifest";

    tidesdb_manifest_t *manifest = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(manifest != NULL);

    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 100, 1000, 65536), 0);
    ASSERT_EQ(manifest->num_entries, 1);

    /* we add same level+id with different values (should update, not add) */
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 100, 2000, 131072), 0);
    ASSERT_EQ(manifest->num_entries, 1);

    /* we verify updated values */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 100));
    ASSERT_EQ(manifest->entries[0].num_entries, 2000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 131072);

    /* we add multiple updates */
    for (int i = 0; i < 10; i++)
    {
        ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 100, i * 1000, i * 65536), 0);
        ASSERT_EQ(manifest->num_entries, 1);
    }

    /* we verify final update */
    ASSERT_EQ(manifest->entries[0].num_entries, 9000);
    ASSERT_EQ(manifest->entries[0].size_bytes, 9 * 65536);

    /* we add different id on same level */
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 1, 101, 5000, 200000), 0);
    ASSERT_EQ(manifest->num_entries, 2);

    /* we add same id on different level (should add, not update) */
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, 2, 100, 3000, 150000), 0);
    ASSERT_EQ(manifest->num_entries, 3);

    /* we verify all entries exist */
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(manifest, 2, 100));

    /* test remove non-existent */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 5, 999), -1);
    ASSERT_EQ(manifest->num_entries, 3);

    /* test remove existing */
    ASSERT_EQ(tidesdb_manifest_remove_sstable(manifest, 1, 100), 0);
    ASSERT_EQ(manifest->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(manifest, 1, 100));

    /* we commit and reload to verify persistence */
    ASSERT_EQ(tidesdb_manifest_commit(manifest, test_path), 0);
    tidesdb_manifest_close(manifest);

    tidesdb_manifest_t *m2 = tidesdb_manifest_open(test_path);
    ASSERT_TRUE(m2 != NULL);
    ASSERT_EQ(m2->num_entries, 2);
    ASSERT_FALSE(tidesdb_manifest_has_sstable(m2, 1, 100));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 1, 101));
    ASSERT_TRUE(tidesdb_manifest_has_sstable(m2, 2, 100));

    tidesdb_manifest_close(m2);
    remove(test_path);
}

int main()
{
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
    RUN_TEST(test_manifest_crash_recovery, tests_passed);
    RUN_TEST(test_manifest_orphaned_temp_cleanup, tests_passed);
    RUN_TEST(test_manifest_concurrent_operations, tests_passed);
    RUN_TEST(test_manifest_corrupted_recovery, tests_passed);
    RUN_TEST(test_manifest_large_stress, tests_passed);
    RUN_TEST(test_manifest_duplicate_id_handling, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}