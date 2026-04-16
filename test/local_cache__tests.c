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

#include "../src/local_cache.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_CACHE_DIR "." PATH_SEPARATOR "test_local_cache_dir"

static void create_test_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    ASSERT_TRUE(f != NULL);
    for (size_t i = 0; i < size; i++)
    {
        fputc('X', f);
    }
    fclose(f);
}

void test_local_cache_init_destroy(void)
{
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);
    ASSERT_EQ(strcmp(cache.cache_dir, TEST_CACHE_DIR), 0);
    ASSERT_EQ(cache.max_bytes, 1024 * 1024);
    ASSERT_EQ(cache.num_entries, 0);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 0);
    ASSERT_TRUE(cache.lru_head == NULL);
    ASSERT_TRUE(cache.lru_tail == NULL);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_init_unlimited(void)
{
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 0), 0);
    ASSERT_EQ(cache.max_bytes, 0);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_track_single(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path[256];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR "file_a.dat", TEST_CACHE_DIR);
    create_test_file(path, 100);

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, path), 0);
    ASSERT_EQ(cache.num_entries, 1);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 100);
    ASSERT_TRUE(cache.lru_head != NULL);
    ASSERT_TRUE(cache.lru_tail != NULL);
    ASSERT_EQ(cache.lru_head, cache.lru_tail);

    tdb_local_cache_destroy(&cache);
    remove(path);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_track_multiple(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path_a[256], path_b[256], path_c[256];
    snprintf(path_a, sizeof(path_a), "%s" PATH_SEPARATOR "a.dat", TEST_CACHE_DIR);
    snprintf(path_b, sizeof(path_b), "%s" PATH_SEPARATOR "b.dat", TEST_CACHE_DIR);
    snprintf(path_c, sizeof(path_c), "%s" PATH_SEPARATOR "c.dat", TEST_CACHE_DIR);
    create_test_file(path_a, 100);
    create_test_file(path_b, 200);
    create_test_file(path_c, 300);

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, path_a), 0);
    ASSERT_EQ(tdb_local_cache_track(&cache, path_b), 0);
    ASSERT_EQ(tdb_local_cache_track(&cache, path_c), 0);
    ASSERT_EQ(cache.num_entries, 3);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 600);

    /* most recently tracked (path_c) should be at LRU head */
    ASSERT_EQ(strcmp(cache.lru_head->path, path_c), 0);

    /* first tracked (path_a) should be at LRU tail */
    ASSERT_EQ(strcmp(cache.lru_tail->path, path_a), 0);

    tdb_local_cache_destroy(&cache);
    remove(path_a);
    remove(path_b);
    remove(path_c);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_track_duplicate(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path[256];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR "dup.dat", TEST_CACHE_DIR);
    create_test_file(path, 100);

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, path), 0);
    ASSERT_EQ(cache.num_entries, 1);

    /* tracking same file again should not add duplicate */
    ASSERT_EQ(tdb_local_cache_track(&cache, path), 0);
    ASSERT_EQ(cache.num_entries, 1);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 100);

    tdb_local_cache_destroy(&cache);
    remove(path);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_track_nonexistent(void)
{
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    /* tracking a file that doesn't exist should fail */
    ASSERT_EQ(tdb_local_cache_track(&cache, "/nonexistent/path/file.dat"), -1);
    ASSERT_EQ(cache.num_entries, 0);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_touch(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path_a[256], path_b[256], path_c[256];
    snprintf(path_a, sizeof(path_a), "%s" PATH_SEPARATOR "ta.dat", TEST_CACHE_DIR);
    snprintf(path_b, sizeof(path_b), "%s" PATH_SEPARATOR "tb.dat", TEST_CACHE_DIR);
    snprintf(path_c, sizeof(path_c), "%s" PATH_SEPARATOR "tc.dat", TEST_CACHE_DIR);
    create_test_file(path_a, 100);
    create_test_file(path_b, 200);
    create_test_file(path_c, 300);

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    tdb_local_cache_track(&cache, path_a);
    tdb_local_cache_track(&cache, path_b);
    tdb_local_cache_track(&cache, path_c);

    /* path_c is at head, path_a is at tail */
    ASSERT_EQ(strcmp(cache.lru_head->path, path_c), 0);
    ASSERT_EQ(strcmp(cache.lru_tail->path, path_a), 0);

    /* touch path_a, it should move to head */
    tdb_local_cache_touch(&cache, path_a);
    ASSERT_EQ(strcmp(cache.lru_head->path, path_a), 0);
    ASSERT_EQ(strcmp(cache.lru_tail->path, path_b), 0);
    ASSERT_EQ(cache.num_entries, 3);

    tdb_local_cache_destroy(&cache);
    remove(path_a);
    remove(path_b);
    remove(path_c);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_touch_nonexistent(void)
{
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    /* touch on untracked path should be a no-op */
    tdb_local_cache_touch(&cache, "/does/not/exist");
    ASSERT_EQ(cache.num_entries, 0);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_remove(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path_a[256], path_b[256], path_c[256];
    snprintf(path_a, sizeof(path_a), "%s" PATH_SEPARATOR "ra.dat", TEST_CACHE_DIR);
    snprintf(path_b, sizeof(path_b), "%s" PATH_SEPARATOR "rb.dat", TEST_CACHE_DIR);
    snprintf(path_c, sizeof(path_c), "%s" PATH_SEPARATOR "rc.dat", TEST_CACHE_DIR);
    create_test_file(path_a, 100);
    create_test_file(path_b, 200);
    create_test_file(path_c, 300);

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    tdb_local_cache_track(&cache, path_a);
    tdb_local_cache_track(&cache, path_b);
    tdb_local_cache_track(&cache, path_c);
    ASSERT_EQ(cache.num_entries, 3);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 600);

    /* remove middle entry */
    tdb_local_cache_remove(&cache, path_b);
    ASSERT_EQ(cache.num_entries, 2);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 400);

    /* file should still exist on disk (remove does not delete files) */
    ASSERT_EQ(access(path_b, F_OK), 0);

    /* remove head */
    tdb_local_cache_remove(&cache, path_c);
    ASSERT_EQ(cache.num_entries, 1);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 100);
    ASSERT_EQ(strcmp(cache.lru_head->path, path_a), 0);
    ASSERT_EQ(cache.lru_head, cache.lru_tail);

    /* remove last entry */
    tdb_local_cache_remove(&cache, path_a);
    ASSERT_EQ(cache.num_entries, 0);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 0);
    ASSERT_TRUE(cache.lru_head == NULL);
    ASSERT_TRUE(cache.lru_tail == NULL);

    tdb_local_cache_destroy(&cache);
    remove(path_a);
    remove(path_b);
    remove(path_c);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_remove_nonexistent(void)
{
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    /* remove on untracked path should be a no-op */
    tdb_local_cache_remove(&cache, "/does/not/exist");
    ASSERT_EQ(cache.num_entries, 0);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_eviction(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path_a[256], path_b[256], path_c[256];
    snprintf(path_a, sizeof(path_a), "%s" PATH_SEPARATOR "ev_a.dat", TEST_CACHE_DIR);
    snprintf(path_b, sizeof(path_b), "%s" PATH_SEPARATOR "ev_b.dat", TEST_CACHE_DIR);
    snprintf(path_c, sizeof(path_c), "%s" PATH_SEPARATOR "ev_c.dat", TEST_CACHE_DIR);
    create_test_file(path_a, 400);
    create_test_file(path_b, 400);
    create_test_file(path_c, 400);

    /* cache can hold 800 bytes, so 2 of the 3 files */
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 800), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, path_a), 0);
    ASSERT_EQ(tdb_local_cache_track(&cache, path_b), 0);
    ASSERT_EQ(cache.num_entries, 2);

    /* tracking path_c should evict path_a (LRU tail) */
    ASSERT_EQ(tdb_local_cache_track(&cache, path_c), 0);
    ASSERT_TRUE(cache.num_entries <= 2);
    ASSERT_TRUE(atomic_load(&cache.current_bytes) <= 800);

    /* path_a should have been evicted (deleted from disk) */
    ASSERT_NE(access(path_a, F_OK), 0);

    /* path_b and path_c should still be tracked */
    ASSERT_EQ(strcmp(cache.lru_head->path, path_c), 0);

    tdb_local_cache_destroy(&cache);
    remove(path_b);
    remove(path_c);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_eviction_unlimited(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char path_a[256], path_b[256];
    snprintf(path_a, sizeof(path_a), "%s" PATH_SEPARATOR "ul_a.dat", TEST_CACHE_DIR);
    snprintf(path_b, sizeof(path_b), "%s" PATH_SEPARATOR "ul_b.dat", TEST_CACHE_DIR);
    create_test_file(path_a, 1000);
    create_test_file(path_b, 1000);

    /* unlimited cache should never evict */
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 0), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, path_a), 0);
    ASSERT_EQ(tdb_local_cache_track(&cache, path_b), 0);
    ASSERT_EQ(cache.num_entries, 2);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 2000);

    tdb_local_cache_destroy(&cache);
    remove(path_a);
    remove(path_b);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_klog_vlog_pair_eviction(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char klog_a[256], vlog_a[256], klog_b[256];
    snprintf(klog_a, sizeof(klog_a), "%s" PATH_SEPARATOR "sst_001.klog", TEST_CACHE_DIR);
    snprintf(vlog_a, sizeof(vlog_a), "%s" PATH_SEPARATOR "sst_001.vlog", TEST_CACHE_DIR);
    snprintf(klog_b, sizeof(klog_b), "%s" PATH_SEPARATOR "sst_002.klog", TEST_CACHE_DIR);
    create_test_file(klog_a, 300);
    create_test_file(vlog_a, 300);
    create_test_file(klog_b, 300);

    /* cache can hold 600 bytes (fits klog_a + vlog_a, but not klog_b too) */
    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 600), 0);

    ASSERT_EQ(tdb_local_cache_track(&cache, klog_a), 0);
    ASSERT_EQ(tdb_local_cache_track(&cache, vlog_a), 0);
    ASSERT_EQ(cache.num_entries, 2);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 600);

    /* tracking klog_b should evict klog_a (LRU tail) and its vlog partner */
    ASSERT_EQ(tdb_local_cache_track(&cache, klog_b), 0);

    /* both klog_a and vlog_a should be evicted from disk */
    ASSERT_NE(access(klog_a, F_OK), 0);
    ASSERT_NE(access(vlog_a, F_OK), 0);

    /* only klog_b should remain */
    ASSERT_EQ(cache.num_entries, 1);
    ASSERT_EQ(atomic_load(&cache.current_bytes), 300);

    tdb_local_cache_destroy(&cache);
    remove(klog_b);
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_null_args(void)
{
    tdb_local_cache_t cache;

    /* init with NULL args */
    ASSERT_EQ(tdb_local_cache_init(NULL, TEST_CACHE_DIR, 1024), -1);
    ASSERT_EQ(tdb_local_cache_init(&cache, NULL, 1024), -1);

    /* init a valid cache for remaining NULL tests */
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024), 0);

    /* track with NULL args */
    ASSERT_EQ(tdb_local_cache_track(NULL, "path"), -1);
    ASSERT_EQ(tdb_local_cache_track(&cache, NULL), -1);

    /* touch with NULL args should not crash */
    tdb_local_cache_touch(NULL, "path");
    tdb_local_cache_touch(&cache, NULL);

    /* remove with NULL args should not crash */
    tdb_local_cache_remove(NULL, "path");
    tdb_local_cache_remove(&cache, NULL);

    /* destroy with NULL should not crash */
    tdb_local_cache_destroy(NULL);

    tdb_local_cache_destroy(&cache);
}

void test_local_cache_lru_ordering(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    char paths[5][256];
    for (int i = 0; i < 5; i++)
    {
        snprintf(paths[i], sizeof(paths[i]), "%s" PATH_SEPARATOR "lru_%d.dat", TEST_CACHE_DIR, i);
        create_test_file(paths[i], 100);
    }

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 1024 * 1024), 0);

    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(tdb_local_cache_track(&cache, paths[i]), 0);
    }

    /* LRU order should be head=4, 3, 2, 1, tail=0 */
    ASSERT_EQ(strcmp(cache.lru_head->path, paths[4]), 0);
    ASSERT_EQ(strcmp(cache.lru_tail->path, paths[0]), 0);

    /* touch paths[1], should move to head */
    tdb_local_cache_touch(&cache, paths[1]);
    ASSERT_EQ(strcmp(cache.lru_head->path, paths[1]), 0);
    ASSERT_EQ(strcmp(cache.lru_tail->path, paths[0]), 0);

    /* touch paths[0] (tail), should move to head */
    tdb_local_cache_touch(&cache, paths[0]);
    ASSERT_EQ(strcmp(cache.lru_head->path, paths[0]), 0);

    /* walk the LRU list and verify length */
    int count = 0;
    tdb_cache_entry_t *cur = cache.lru_head;
    while (cur)
    {
        count++;
        cur = cur->next;
    }
    ASSERT_EQ(count, 5);

    /* walk backwards */
    count = 0;
    cur = cache.lru_tail;
    while (cur)
    {
        count++;
        cur = cur->prev;
    }
    ASSERT_EQ(count, 5);

    tdb_local_cache_destroy(&cache);
    for (int i = 0; i < 5; i++)
    {
        remove(paths[i]);
    }
    remove_directory(TEST_CACHE_DIR);
}

void test_local_cache_many_entries(void)
{
    mkdir(TEST_CACHE_DIR, 0755);

    const int num_files = 100;
    char paths[100][256];
    for (int i = 0; i < num_files; i++)
    {
        snprintf(paths[i], sizeof(paths[i]), "%s" PATH_SEPARATOR "many_%03d.dat", TEST_CACHE_DIR,
                 i);
        create_test_file(paths[i], 50);
    }

    tdb_local_cache_t cache;
    ASSERT_EQ(tdb_local_cache_init(&cache, TEST_CACHE_DIR, 0), 0);

    for (int i = 0; i < num_files; i++)
    {
        ASSERT_EQ(tdb_local_cache_track(&cache, paths[i]), 0);
    }

    ASSERT_EQ(cache.num_entries, num_files);
    ASSERT_EQ(atomic_load(&cache.current_bytes), (size_t)(num_files * 50));

    /* remove every other entry */
    for (int i = 0; i < num_files; i += 2)
    {
        tdb_local_cache_remove(&cache, paths[i]);
    }
    ASSERT_EQ(cache.num_entries, num_files / 2);
    ASSERT_EQ(atomic_load(&cache.current_bytes), (size_t)(num_files / 2 * 50));

    tdb_local_cache_destroy(&cache);
    for (int i = 0; i < num_files; i++)
    {
        remove(paths[i]);
    }
    remove_directory(TEST_CACHE_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_local_cache_init_destroy, tests_passed);
    RUN_TEST(test_local_cache_init_unlimited, tests_passed);
    RUN_TEST(test_local_cache_track_single, tests_passed);
    RUN_TEST(test_local_cache_track_multiple, tests_passed);
    RUN_TEST(test_local_cache_track_duplicate, tests_passed);
    RUN_TEST(test_local_cache_track_nonexistent, tests_passed);
    RUN_TEST(test_local_cache_touch, tests_passed);
    RUN_TEST(test_local_cache_touch_nonexistent, tests_passed);
    RUN_TEST(test_local_cache_remove, tests_passed);
    RUN_TEST(test_local_cache_remove_nonexistent, tests_passed);
    RUN_TEST(test_local_cache_eviction, tests_passed);
    RUN_TEST(test_local_cache_eviction_unlimited, tests_passed);
    RUN_TEST(test_local_cache_klog_vlog_pair_eviction, tests_passed);
    RUN_TEST(test_local_cache_null_args, tests_passed);
    RUN_TEST(test_local_cache_lru_ordering, tests_passed);
    RUN_TEST(test_local_cache_many_entries, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
