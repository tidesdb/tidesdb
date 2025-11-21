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

#include "../src/succinct_trie.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_disk_streaming_basic()
{
    /* use NULL to let builder choose platform-appropriate temp directory */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    /* add sorted keys */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"apple", 5, 1), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"banana", 6, 2), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"cherry", 6, 3), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"date", 4, 4), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"elderberry", 10, 5), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    /* verify lookups */
    int64_t value;
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"apple", 5, &value), 0);
    ASSERT_EQ(value, 1);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"banana", 6, &value), 0);
    ASSERT_EQ(value, 2);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"cherry", 6, &value), 0);
    ASSERT_EQ(value, 3);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"date", 4, &value), 0);
    ASSERT_EQ(value, 4);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"elderberry", 10, &value), 0);
    ASSERT_EQ(value, 5);

    /* verify non-existent key */
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"fig", 3, &value), -1);

    succinct_trie_free(trie);
}

void test_disk_streaming_prefix_queries()
{
    /* test prefix queries with disk streaming */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    /* add keys with common prefixes (must be in sorted order) */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"test", 4, 1), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"tester", 6, 2), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"testing", 7, 3), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"toast", 5, 4), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    /* test exact matches */
    int64_t value;
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"test", 4, &value), 0);
    ASSERT_EQ(value, 1);

    /* test prefix matches -- should find first terminal in subtree */
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"tes", 3, &value), 0);
    ASSERT_EQ(value, 1); /* should find "test" */

    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"to", 2, &value), 0);
    ASSERT_EQ(value, 4); /* should find "toast" */

    succinct_trie_free(trie);
}

void test_disk_streaming_sorted_order_validation()
{
    /* test that unsorted keys are rejected */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"apple", 5, 1), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"cherry", 6, 3), 0);

    /* try to add out-of-order key (should fail) */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"banana", 6, 2), -1);

    succinct_trie_builder_free(builder);
}

void test_disk_streaming_large_dataset()
{
    /* test with larger dataset to verify memory efficiency */
    const int N = 10000;
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    clock_t start = clock();

    /* add keys in sorted order */
    for (int i = 0; i < N; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%07d", i);
        ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)key, strlen(key), i), 0);
    }

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    clock_t end = clock();
    double build_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf(CYAN "Built disk-streaming trie with %d entries in %f seconds\n" RESET, N, build_time);

    /* verify random lookups */
    int64_t value;
    for (int i = 0; i < 100; i++)
    {
        int idx = (i * 97) % N; /* pseudo-random indices */
        char key[32];
        snprintf(key, sizeof(key), "key_%07d", idx);
        ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)key, strlen(key), &value), 0);
        ASSERT_EQ(value, idx);
    }

    size_t trie_size = succinct_trie_get_size(trie);
    printf(YELLOW "Disk-streaming trie size: %.2f KB\n" RESET, trie_size / 1024.0);

    succinct_trie_free(trie);
}

void test_disk_streaming_common_prefix()
{
    /* test keys with long common prefixes */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"commonprefix_a", 14, 1), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"commonprefix_b", 14, 2), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"commonprefix_c", 14, 3), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"commonprefix_d", 14, 4), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    int64_t value;
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"commonprefix_a", 14, &value), 0);
    ASSERT_EQ(value, 1);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"commonprefix_d", 14, &value), 0);
    ASSERT_EQ(value, 4);

    /* test common prefix */
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"commonprefix", 12, &value), 0);
    ASSERT_EQ(value, 1); /* should find first entry */

    succinct_trie_free(trie);
}

void test_disk_streaming_single_entry()
{
    /* single entry */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"single", 6, 42), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    int64_t value;
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"single", 6, &value), 0);
    ASSERT_EQ(value, 42);

    succinct_trie_free(trie);
}

void test_disk_streaming_serialization()
{
    /* test that disk-streaming trie can be serialized/deserialized */
    succinct_trie_builder_t *builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(builder != NULL);

    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"alpha", 5, 10), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"beta", 4, 20), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"gamma", 5, 30), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);

    size_t serialized_size;
    uint8_t *serialized = succinct_trie_serialize(trie, &serialized_size);
    ASSERT_TRUE(serialized != NULL);
    ASSERT_TRUE(serialized_size > 0);

    succinct_trie_t *trie2 = succinct_trie_deserialize(serialized, serialized_size);
    ASSERT_TRUE(trie2 != NULL);

    /* verify lookups on deserialized trie */
    int64_t value;
    ASSERT_EQ(succinct_trie_prefix_get(trie2, (uint8_t *)"alpha", 5, &value), 0);
    ASSERT_EQ(value, 10);
    ASSERT_EQ(succinct_trie_prefix_get(trie2, (uint8_t *)"beta", 4, &value), 0);
    ASSERT_EQ(value, 20);
    ASSERT_EQ(succinct_trie_prefix_get(trie2, (uint8_t *)"gamma", 5, &value), 0);
    ASSERT_EQ(value, 30);

    free(serialized);
    succinct_trie_free(trie);
    succinct_trie_free(trie2);
}

void benchmark_succinct_trie()
{
    const int N = 100000;
    char **keys = malloc(sizeof(char *) * N);
    ASSERT_TRUE(keys != NULL);

    /* allocate all keys first with zero-padding for sorted order */
    for (int i = 0; i < N; i++)
    {
        keys[i] = malloc(20);
        snprintf(keys[i], 20, "key_%07d", i); /* zero-padded for lexicographic sorting */
    }

    clock_t start = clock();
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_string, NULL);
    ASSERT_TRUE(builder != NULL);

    /* add keys in sorted order (streaming mode requires sorted input) */
    for (int i = 0; i < N; i++)
    {
        ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)keys[i], strlen(keys[i]), i), 0);
    }

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_TRUE(trie != NULL);
    clock_t end = clock();
    double build_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf(CYAN "Built succinct trie with %d entries in %f seconds (memory streaming mode)\n" RESET,
           N, build_time);

    size_t total_bytes = succinct_trie_get_size(trie);

    printf(YELLOW "Trie size: %.2f MB (%zu bytes)\n" RESET, total_bytes / (1024.0 * 1024.0),
           total_bytes);

    int64_t value;
    for (int i = 0; i < 1000; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "key_%07d", i); /* must match the format used during insertion */
        ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)key, strlen(key), &value), 0);
        ASSERT_EQ(value, i);
    }

    succinct_trie_free(trie);
    for (int i = 0; i < N; i++) free(keys[i]);
    free(keys);
}

void test_succinct_trie_invalid_inputs()
{
    succinct_trie_builder_t *builder;
    succinct_trie_t *trie;
    int64_t val;

    /* NULL builder operations */
    ASSERT_EQ(succinct_trie_builder_add(NULL, (uint8_t *)"key", 3, 123), -1);

    /* NULL key */
    builder = succinct_trie_builder_new(NULL, succinct_trie_comparator_memcmp, NULL);
    ASSERT_EQ(succinct_trie_builder_add(builder, NULL, 3, 123), -1);
    succinct_trie_builder_free(builder);

    /* NULL trie operations */
    ASSERT_EQ(succinct_trie_prefix_get(NULL, (uint8_t *)"key", 3, &val), -1);

    /* NULL prefix */
    builder = succinct_trie_builder_new(NULL, succinct_trie_comparator_memcmp, NULL);
    succinct_trie_builder_add(builder, (uint8_t *)"key", 3, 123);
    trie = succinct_trie_builder_build(builder, NULL);
    ASSERT_EQ(succinct_trie_prefix_get(trie, NULL, 3, &val), -1);
    succinct_trie_free(trie);

    /* succinct_trie_free with NULL */
    succinct_trie_free(NULL);
}

void test_succinct_trie_empty()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_memcmp, NULL);
    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    int64_t val;
    /* get from empty trie */
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"nonexistent", 11, &val), -1);

    /* serialize empty trie */
    size_t size;
    uint8_t *data = succinct_trie_serialize(trie, &size);
    ASSERT_TRUE(data != NULL);

    /* deserialize and verify still empty */
    succinct_trie_t *trie2 = succinct_trie_deserialize(data, size);
    ASSERT_TRUE(trie2 != NULL);
    ASSERT_EQ(succinct_trie_prefix_get(trie2, (uint8_t *)"key", 3, &val), -1);

    free(data);
    succinct_trie_free(trie);
    succinct_trie_free(trie2);
}

void test_succinct_trie_binary_keys()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_memcmp, NULL);

    /* binary keys with null bytes - must be sorted */
    uint8_t key1[] = {0x00, 0xFF, 0x00, 0xAA};
    uint8_t key2[] = {0x00, 0xFF, 0x01, 0xBB};

    ASSERT_EQ(succinct_trie_builder_add(builder, key1, sizeof(key1), 100), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, key2, sizeof(key2), 200), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    int64_t val;
    ASSERT_EQ(succinct_trie_prefix_get(trie, key1, sizeof(key1), &val), 0);
    ASSERT_EQ(val, 100);
    ASSERT_EQ(succinct_trie_prefix_get(trie, key2, sizeof(key2), &val), 0);
    ASSERT_EQ(val, 200);

    succinct_trie_free(trie);
}

void test_succinct_trie_duplicate_keys()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_string, NULL);

    /* add same key multiple times -- only last should be kept */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"key", 3, 100), 0);
    /* second add of same key should fail (not in sorted order) */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"key", 3, 200), -1);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    int64_t val;
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"key", 3, &val), 0);
    ASSERT_EQ(val, 100);

    succinct_trie_free(trie);
}

void test_succinct_trie_long_keys()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_memcmp, NULL);

    /* very long key (1KB) */
    uint8_t long_key[1024];
    memset(long_key, 'A', sizeof(long_key));

    ASSERT_EQ(succinct_trie_builder_add(builder, long_key, sizeof(long_key), 999), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    int64_t val;
    ASSERT_EQ(succinct_trie_prefix_get(trie, long_key, sizeof(long_key), &val), 0);
    ASSERT_EQ(val, 999);

    succinct_trie_free(trie);
}

void test_succinct_trie_prefix_edge_cases()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_string, NULL);

    /* keys where one is prefix of another -- must be in sorted order */
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"a", 1, 1), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"ab", 2, 2), 0);
    ASSERT_EQ(succinct_trie_builder_add(builder, (uint8_t *)"abc", 3, 3), 0);

    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    int64_t val;
    /* prefix queries */
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"a", 1, &val), 0);
    ASSERT_EQ(val, 1);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"ab", 2, &val), 0);
    ASSERT_EQ(val, 2);
    ASSERT_EQ(succinct_trie_prefix_get(trie, (uint8_t *)"abc", 3, &val), 0);
    ASSERT_EQ(val, 3);

    succinct_trie_free(trie);
}

void test_succinct_trie_deserialize_corrupted()
{
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(NULL, succinct_trie_comparator_string, NULL);
    succinct_trie_builder_add(builder, (uint8_t *)"test", 4, 123);
    succinct_trie_t *trie = succinct_trie_builder_build(builder, NULL);

    size_t size;
    uint8_t *data = succinct_trie_serialize(trie, &size);

    /* corrupt the data */
    if (size > 4)
    {
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
    }

    /* should handle gracefully */
    succinct_trie_t *trie2 = succinct_trie_deserialize(data, size);
    /* may return NULL or corrupted trie -- just shouldn't crash */

    free(data);
    succinct_trie_free(trie);
    if (trie2) succinct_trie_free(trie2);
}

void benchmark_disk_streaming_vs_memory()
{
    const int N = 50000;
    char **keys = malloc(sizeof(char *) * N);
    ASSERT_TRUE(keys != NULL);

    for (int i = 0; i < N; i++)
    {
        keys[i] = malloc(20);
        snprintf(keys[i], 20, "key_%07d", i);
    }

    /* benchmark disk streaming */
    clock_t start = clock();
    succinct_trie_builder_t *disk_builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(disk_builder != NULL);

    for (int i = 0; i < N; i++)
    {
        ASSERT_EQ(succinct_trie_builder_add(disk_builder, (uint8_t *)keys[i], strlen(keys[i]), i),
                  0);
    }

    succinct_trie_t *disk_trie = succinct_trie_builder_build(disk_builder, NULL);
    ASSERT_TRUE(disk_trie != NULL);
    clock_t end = clock();
    double disk_time = (double)(end - start) / CLOCKS_PER_SEC;

    /* benchmark memory streaming */
    start = clock();
    succinct_trie_builder_t *mem_builder = succinct_trie_builder_new(NULL, NULL, NULL);
    ASSERT_TRUE(mem_builder != NULL);

    for (int i = 0; i < N; i++)
    {
        ASSERT_EQ(succinct_trie_builder_add(mem_builder, (uint8_t *)keys[i], strlen(keys[i]), i),
                  0);
    }

    succinct_trie_t *mem_trie = succinct_trie_builder_build(mem_builder, NULL);
    ASSERT_TRUE(mem_trie != NULL);
    end = clock();
    double mem_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf(CYAN "\n*=== Performance Comparison (%d entries) ===*\n" RESET, N);
    printf(YELLOW "Disk streaming: %.3f seconds\n" RESET, disk_time);
    printf(YELLOW "Memory streaming: %.3f seconds\n" RESET, mem_time);
    printf(YELLOW "Disk/Memory ratio: %.2fx\n" RESET, disk_time / mem_time);

    /* verify both produce same results */
    int64_t disk_val, mem_val;
    for (int i = 0; i < 100; i++)
    {
        int idx = (i * 97) % N;
        ASSERT_EQ(
            succinct_trie_prefix_get(disk_trie, (uint8_t *)keys[idx], strlen(keys[idx]), &disk_val),
            0);
        ASSERT_EQ(
            succinct_trie_prefix_get(mem_trie, (uint8_t *)keys[idx], strlen(keys[idx]), &mem_val),
            0);
        ASSERT_EQ(disk_val, mem_val);
    }

    succinct_trie_free(disk_trie);
    succinct_trie_free(mem_trie);
    for (int i = 0; i < N; i++) free(keys[i]);
    free(keys);
}

int main(void)
{
    RUN_TEST(test_disk_streaming_basic, tests_passed);
    RUN_TEST(test_disk_streaming_prefix_queries, tests_passed);
    RUN_TEST(test_disk_streaming_sorted_order_validation, tests_passed);
    RUN_TEST(test_disk_streaming_single_entry, tests_passed);
    RUN_TEST(test_disk_streaming_common_prefix, tests_passed);
    RUN_TEST(test_disk_streaming_serialization, tests_passed);
    RUN_TEST(test_disk_streaming_large_dataset, tests_passed);
    RUN_TEST(test_succinct_trie_invalid_inputs, tests_passed);
    RUN_TEST(test_succinct_trie_empty, tests_passed);
    RUN_TEST(test_succinct_trie_binary_keys, tests_passed);
    RUN_TEST(test_succinct_trie_duplicate_keys, tests_passed);
    RUN_TEST(test_succinct_trie_long_keys, tests_passed);
    RUN_TEST(test_succinct_trie_prefix_edge_cases, tests_passed);
    RUN_TEST(test_succinct_trie_deserialize_corrupted, tests_passed);
    RUN_TEST(benchmark_succinct_trie, tests_passed);
    RUN_TEST(benchmark_disk_streaming_vs_memory, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}