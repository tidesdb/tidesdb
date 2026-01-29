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

#include "../src/skip_list.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define BENCH_N 1000000 /* number of entries to write and retrieve */

/* helper macros for accessing node data */
#define NODE_KEY(node)   ((node)->key)
#define NODE_VALUE(node) (atomic_load_explicit(&(node)->versions, memory_order_acquire)->value)
#define NODE_IS_DELETED(node) \
    (VERSION_IS_DELETED(atomic_load_explicit(&(node)->versions, memory_order_acquire)))

void test_skip_list_create_node()
{
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_node_t *node =
        skip_list_create_node(1, key, sizeof(key), value, sizeof(value), -1, 0);
    ASSERT_TRUE(node != NULL);

    int test_passed = 1;
    if (memcmp(NODE_KEY(node), key, sizeof(key)) != 0) test_passed = 0;
    if (memcmp(NODE_VALUE(node), value, sizeof(value)) != 0) test_passed = 0;
    if (NODE_IS_DELETED(node)) test_passed = 0;

    /* properly free node with all its allocations */
    skip_list_free_node(node);

    ASSERT_TRUE(test_passed);
}

void test_skip_list_put_get()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_TRUE(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 1, 0) ==
                0);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    uint8_t deleted;
    int64_t ttl;
    int get_result = skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size,
                                   &ttl, &deleted);
    ASSERT_EQ(get_result, 0);
    ASSERT_TRUE(memcmp(retrieved_value, value, sizeof(value)) == 0);

    free(retrieved_value);
    skip_list_free(list);
}

void test_skip_list_destroy()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    skip_list_free(list);
}

void test_skip_list_clear()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_TRUE(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 1, 0) ==
                0);
    int result = skip_list_clear(list);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(skip_list_count_entries(list) == 0);
    (void)skip_list_free(list);
}

void test_skip_list_count_entries()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    ASSERT_TRUE(skip_list_count_entries(list) == 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_TRUE(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 1, 0) ==
                0);
    ASSERT_TRUE(skip_list_count_entries(list) == 1);

    (void)skip_list_free(list);
}

void test_skip_list_get_size()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    ASSERT_TRUE(skip_list_get_size(list) == 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_TRUE(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 1, 0) ==
                0);
    ASSERT_TRUE(skip_list_get_size(list) > 0);

    (void)skip_list_free(list);
}

void test_skip_list_cursor_init()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);
    ASSERT_EQ(cursor->list, list);
    ASSERT_EQ(cursor->current, list->header->forward[0]);

    (void)skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void test_skip_list_cursor_next()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key1, sizeof(key1), value1, sizeof(value1), -1, 1, 0) == 0);
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key2, sizeof(key2), value2, sizeof(value2), -1, 2, 0) == 0);

    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);
    ASSERT_NE(cursor->current, NULL);

    int result = skip_list_cursor_next(cursor);
    ASSERT_EQ(result, 0);
    ASSERT_NE(cursor->current, NULL);
    ASSERT_TRUE(memcmp(NODE_KEY(cursor->current), key2, sizeof(key2)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
}

void test_skip_list_cursor_prev()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key1, sizeof(key1), value1, sizeof(value1), -1, 1, 0) == 0);
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key2, sizeof(key2), value2, sizeof(value2), -1, 2, 0) == 0);

    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);
    ASSERT_NE(cursor->current, NULL);

    ASSERT_TRUE(skip_list_cursor_next(cursor) == 0);
    int result = skip_list_cursor_prev(cursor);
    ASSERT_EQ(result, 0);
    ASSERT_NE(cursor->current, NULL);
    ASSERT_TRUE(memcmp(NODE_KEY(cursor->current), key1, sizeof(key1)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
}

void benchmark_skip_list()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    const size_t key_size = 16;
    const size_t value_size = 8;

    uint8_t **keys = malloc(BENCH_N * sizeof(uint8_t *));
    uint8_t **values = malloc(BENCH_N * sizeof(uint8_t *));
    if (keys == NULL || values == NULL)
    {
        printf(RED "Failed to allocate memory for keys and values\n" RESET);
        return;
    }

    for (size_t i = 0; i < BENCH_N; i++)
    {
        keys[i] = malloc(key_size * sizeof(uint8_t));
        values[i] = malloc(value_size * sizeof(uint8_t));
        if (keys[i] == NULL || values[i] == NULL)
        {
            for (size_t j = 0; j <= i; j++)
            {
                free(keys[j]);
                free(values[j]);
            }
            free(keys);
            free(values);
            printf(RED "Failed to allocate memory for keys and values\n" RESET);
            return;
        }
    }

    for (size_t i = 0; i < BENCH_N; i++)
    {
        generate_random_key_value(keys[i], key_size, values[i], value_size);
    }

    clock_t start_write = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        ASSERT_EQ(
            skip_list_put_with_seq(list, keys[i], key_size, values[i], value_size, -1, i + 1, 0),
            0);
    }
    clock_t end_write = clock();
    double write_time = (double)(end_write - start_write) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to write %d entries: %f seconds\n" RESET, BENCH_N, write_time);

    clock_t start_read = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        uint8_t *retrieved_value;
        size_t retrieved_value_size;
        uint8_t deleted;
        int64_t ttl;

        int result = skip_list_get(list, keys[i], key_size, &retrieved_value, &retrieved_value_size,
                                   &ttl, &deleted);
        ASSERT_EQ(result, 0);
        ASSERT_EQ(memcmp(retrieved_value, values[i], value_size), 0);
        free(retrieved_value);
    }
    clock_t end_read = clock();
    double read_time = (double)(end_read - start_read) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to read and verify %d entries: %f seconds\n" RESET, BENCH_N, read_time);

    for (size_t i = 0; i < BENCH_N; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);

    (void)skip_list_free(list);
}

void benchmark_skip_list_sequential()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    const size_t key_size = 16;
    const size_t value_size = 8;

    uint8_t **keys = malloc(BENCH_N * sizeof(uint8_t *));
    uint8_t **values = malloc(BENCH_N * sizeof(uint8_t *));
    if (keys == NULL || values == NULL)
    {
        printf(RED "Failed to allocate memory\n" RESET);
        return;
    }

    for (size_t i = 0; i < BENCH_N; i++)
    {
        keys[i] = malloc(key_size);
        values[i] = malloc(value_size);
    }

    for (size_t i = 0; i < BENCH_N; i++)
    {
        memset(keys[i], 0, key_size);
        memcpy(keys[i], &i, sizeof(size_t));
        memset(values[i], (int)i, value_size);
    }

    clock_t start = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        skip_list_put_with_seq(list, keys[i], key_size, values[i], value_size, -1, i + 1, 0);
    }
    clock_t end = clock();
    double write_time = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "Sequential keys - Write time: %f seconds (%.2f M ops/sec)\n" RESET, write_time,
           BENCH_N / write_time / 1000000.0);

    start = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        uint8_t *retrieved_value;
        size_t retrieved_value_size;
        uint8_t deleted;
        int64_t ttl;
        skip_list_get(list, keys[i], key_size, &retrieved_value, &retrieved_value_size, &ttl,
                      &deleted);
        free(retrieved_value);
    }
    end = clock();
    double read_time = (double)(end - start) / CLOCKS_PER_SEC;
    printf(CYAN "Sequential keys - Read time: %f seconds (%.2f M ops/sec)\n" RESET, read_time,
           BENCH_N / read_time / 1000000.0);

    for (size_t i = 0; i < BENCH_N; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
    skip_list_free(list);
}

void test_skip_list_ttl()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    int64_t ttl = 1;

    ASSERT_TRUE(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value),
                                       time(NULL) + ttl, 1, 0) == 0);

#ifdef _WIN32
    Sleep((ttl + 1) * 1000);
#else
    sleep(ttl + 1);
#endif

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    uint8_t deleted;
    time_t retrieved_ttl;
    int result = skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size,
                               &retrieved_ttl, &deleted);

    ASSERT_EQ(result, 0);
    ASSERT_EQ(deleted, 1);

    free(retrieved_value);
    (void)skip_list_free(list);
}

void test_skip_list_cursor_functions()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    ASSERT_TRUE(list != NULL);

    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_goto_first(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_goto_last(cursor) == -1);

    (void)skip_list_cursor_free(cursor);

    uint8_t key1[] = {1};
    uint8_t value1[] = {10};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key1, sizeof(key1), value1, sizeof(value1), -1, 1, 0) == 0);

    uint8_t key2[] = {2};
    uint8_t value2[] = {20};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key2, sizeof(key2), value2, sizeof(value2), -1, 2, 0) == 0);

    uint8_t key3[] = {3};
    uint8_t value3[] = {30};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key3, sizeof(key3), value3, sizeof(value3), -1, 3, 0) == 0);

    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    ASSERT_TRUE(skip_list_cursor_goto_first(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == 1);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == 0);

    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    int64_t ttl;
    uint8_t deleted;

    ASSERT_TRUE(
        skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted) == 0);
    ASSERT_EQ(key_size, sizeof(key1));
    ASSERT_EQ(memcmp(key, key1, key_size), 0);
    ASSERT_EQ(value_size, sizeof(value1));
    ASSERT_EQ(memcmp(value, value1, value_size), 0);

    ASSERT_TRUE(skip_list_cursor_next(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == 1);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == 1);

    ASSERT_TRUE(skip_list_cursor_next(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == 1);

    ASSERT_TRUE(skip_list_cursor_goto_last(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == 1);

    ASSERT_TRUE(
        skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted) == 0);
    ASSERT_EQ(key_size, sizeof(key3));
    ASSERT_EQ(memcmp(key, key3, key_size), 0);
    ASSERT_EQ(value_size, sizeof(value3));
    ASSERT_EQ(memcmp(value, value3, value_size), 0);

    (void)skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void test_skip_list_min_max_key()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    ASSERT_TRUE(list != NULL);

    uint8_t *min_key = NULL;
    size_t min_key_size;
    uint8_t *max_key = NULL;
    size_t max_key_size;

    ASSERT_TRUE(skip_list_get_min_key(list, &min_key, &min_key_size) == -1);
    ASSERT_TRUE(skip_list_get_max_key(list, &max_key, &max_key_size) == -1);

    uint8_t key2[] = {2};
    uint8_t value2[] = {20};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key2, sizeof(key2), value2, sizeof(value2), -1, 1, 0) == 0);

    uint8_t key1[] = {1};
    uint8_t value1[] = {10};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key1, sizeof(key1), value1, sizeof(value1), -1, 2, 0) == 0);

    uint8_t key3[] = {3};
    uint8_t value3[] = {30};
    ASSERT_TRUE(
        skip_list_put_with_seq(list, key3, sizeof(key3), value3, sizeof(value3), -1, 3, 0) == 0);

    ASSERT_TRUE(skip_list_get_min_key(list, &min_key, &min_key_size) == 0);
    ASSERT_TRUE(min_key != NULL);
    ASSERT_EQ(min_key_size, sizeof(key1));
    ASSERT_EQ(memcmp(min_key, key1, min_key_size), 0);
    free(min_key);

    ASSERT_TRUE(skip_list_get_max_key(list, &max_key, &max_key_size) == 0);
    ASSERT_TRUE(max_key != NULL);
    ASSERT_EQ(max_key_size, sizeof(key3));
    ASSERT_EQ(memcmp(max_key, key3, max_key_size), 0);
    free(max_key);

    uint8_t key0[] = {0};
    uint8_t value0[] = {5};
    int64_t ttl = 1;
    ASSERT_TRUE(skip_list_put_with_seq(list, key0, sizeof(key0), value0, sizeof(value0),
                                       time(NULL) + ttl, 4, 0) == 0);

    ASSERT_TRUE(skip_list_get_min_key(list, &min_key, &min_key_size) == 0);
    ASSERT_TRUE(min_key != NULL);
    ASSERT_EQ(min_key_size, sizeof(key0));
    ASSERT_EQ(memcmp(min_key, key0, min_key_size), 0);
    free(min_key);

#ifdef _WIN32
    Sleep((ttl + 1) * 1000);
#else
    sleep(ttl + 1);
#endif

    ASSERT_TRUE(skip_list_get_min_key(list, &min_key, &min_key_size) == 0);
    ASSERT_TRUE(min_key != NULL);
    ASSERT_EQ(min_key_size, sizeof(key1));
    ASSERT_EQ(memcmp(min_key, key1, min_key_size), 0);
    free(min_key);

    skip_list_free(list);
}

void test_skip_list_cursor_seek()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }

    for (int i = 0; i <= 90; i += 10)
    {
        char key[16];
        char value[16];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);
        ASSERT_TRUE(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                           strlen(value), -1, (i / 10) + 1, 0) == 0);
    }

    /* test seek to exact key */
    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    const char *seek_key = "key_50";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek_key, strlen(seek_key)), 0);

    /* cursor should be positioned before key_50, so next() should return key_50 */
    ASSERT_TRUE(skip_list_cursor_has_next(cursor));
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_50", strlen("key_50")), 0);

    /* test seek to non-existent key (should find next key) */
    const char *seek_key2 = "key_55";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek_key2, strlen(seek_key2)), 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor));
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_60", strlen("key_60")), 0);

    /* test seek to key before all keys */
    const char *seek_key3 = "key_";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek_key3, strlen(seek_key3)), 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor));
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_00", strlen("key_00")), 0);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void test_skip_list_cursor_seek_for_prev()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }

    for (int i = 0; i <= 90; i += 10)
    {
        char key[16];
        char value[16];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);
        ASSERT_TRUE(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                           strlen(value), -1, (i / 10) + 1, 0) == 0);
    }

    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    const char *seek_key = "key_50";
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek_key, strlen(seek_key)), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_50", strlen("key_50")), 0);

    /* test seek_for_prev to non-existent key (should find previous key) */
    const char *seek_key2 = "key_55";
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek_key2, strlen(seek_key2)), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_50", strlen("key_50")), 0);

    const char *seek_key3 = "key_99";
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek_key3, strlen(seek_key3)), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_90", strlen("key_90")), 0);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

typedef struct
{
    skip_list_t *list;
    int thread_id;
    int num_ops;
    int reads_completed;
    int writes_completed;
    _Atomic(uint64_t) *shared_seq; /* shared sequence counter for concurrent tests */
} concurrent_test_ctx_t;

void *concurrent_reader(void *arg)
{
    concurrent_test_ctx_t *ctx = (concurrent_test_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "key%d", i % 10);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;
        int result = skip_list_get(ctx->list, (uint8_t *)key_buf, strlen(key_buf) + 1, &value,
                                   &value_size, &ttl, &deleted);

        if (result == 0 && value != NULL)
        {
            ASSERT_TRUE(value_size > 0);
            free(value);
        }

        ctx->reads_completed++;
    }

    return NULL;
}

void *concurrent_writer(void *arg)
{
    concurrent_test_ctx_t *ctx = (concurrent_test_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        char key_buf[32];
        char value_buf[64];
        snprintf(key_buf, sizeof(key_buf), "key%d", i % 10);
        snprintf(value_buf, sizeof(value_buf), "thread%d_value%d", ctx->thread_id, i);

        /* retry loop: if write fails due to sequence conflict, get new seq and retry */
        int result = -1;
        int retry_count = 0;
        while (result != 0 && retry_count < 100)
        {
            /* get next sequence number atomically */
            uint64_t seq = atomic_fetch_add_explicit(ctx->shared_seq, 1, memory_order_relaxed) + 1;

            result =
                skip_list_put_with_seq(ctx->list, (uint8_t *)key_buf, strlen(key_buf) + 1,
                                       (uint8_t *)value_buf, strlen(value_buf) + 1, -1, seq, 0);
            retry_count++;
        }

        /* if still failed after retries, just continue (shouldn't happen with retry logic) */
        if (result == 0)
        {
            ctx->writes_completed++;
        }
    }

    return NULL;
}

void test_skip_list_concurrent_read_write()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);
    ASSERT_TRUE(list != NULL);

    for (int i = 0; i < 10; i++)
    {
        char key_buf[32];
        char value_buf[32];
        snprintf(key_buf, sizeof(key_buf), "key%d", i);
        snprintf(value_buf, sizeof(value_buf), "initial_value%d", i);
        skip_list_put_with_seq(list, (uint8_t *)key_buf, strlen(key_buf) + 1, (uint8_t *)value_buf,
                               strlen(value_buf) + 1, -1, i + 1, 0);
    }

    const int num_readers = 4;
    const int num_writers = 1;
    const int ops_per_thread = 10000;

    pthread_t *readers = malloc(num_readers * sizeof(pthread_t));
    pthread_t *writers = malloc(num_writers * sizeof(pthread_t));
    concurrent_test_ctx_t *reader_ctx = malloc(num_readers * sizeof(concurrent_test_ctx_t));
    concurrent_test_ctx_t *writer_ctx = malloc(num_writers * sizeof(concurrent_test_ctx_t));

    /* shared atomic sequence counter starting after initial keys */
    _Atomic(uint64_t) shared_seq = 10;

    for (int i = 0; i < num_readers; i++)
    {
        reader_ctx[i].list = list;
        reader_ctx[i].thread_id = i;
        reader_ctx[i].num_ops = ops_per_thread;
        reader_ctx[i].reads_completed = 0;
        pthread_create(&readers[i], NULL, concurrent_reader, &reader_ctx[i]);
    }

    for (int i = 0; i < num_writers; i++)
    {
        writer_ctx[i].list = list;
        writer_ctx[i].thread_id = i;
        writer_ctx[i].num_ops = ops_per_thread;
        writer_ctx[i].writes_completed = 0;
        writer_ctx[i].shared_seq = &shared_seq;
        pthread_create(&writers[i], NULL, concurrent_writer, &writer_ctx[i]);
    }

    for (int i = 0; i < num_readers; i++)
    {
        pthread_join(readers[i], NULL);
        printf(YELLOW "  Reader %d completed %d reads\n" RESET, i, reader_ctx[i].reads_completed);
    }

    for (int i = 0; i < num_writers; i++)
    {
        pthread_join(writers[i], NULL);
        printf(YELLOW "  Writer %d completed %d writes\n" RESET, i, writer_ctx[i].writes_completed);
    }

    int total_reads = 0;
    int total_writes = 0;
    for (int i = 0; i < num_readers; i++) total_reads += reader_ctx[i].reads_completed;
    for (int i = 0; i < num_writers; i++) total_writes += writer_ctx[i].writes_completed;

    ASSERT_EQ(total_reads, num_readers * ops_per_thread);
    ASSERT_EQ(total_writes, num_writers * ops_per_thread);

    free(readers);
    free(writers);
    free(reader_ctx);
    free(writer_ctx);

    skip_list_free(list);
}

void test_skip_list_null_validation()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "key";
    uint8_t value[] = "value";
    uint8_t *out_value = NULL;
    size_t out_size = 0;
    uint8_t deleted = 0;
    int64_t ttl;

    /* null list */
    ASSERT_EQ(skip_list_put_with_seq(NULL, key, sizeof(key), value, sizeof(value), -1, 1, 0), -1);
    ASSERT_EQ(skip_list_get(NULL, key, sizeof(key), &out_value, &out_size, &ttl, &deleted), -1);

    /* null key */
    ASSERT_EQ(skip_list_put_with_seq(list, NULL, sizeof(key), value, sizeof(value), -1, 1, 0), -1);
    ASSERT_EQ(skip_list_get(list, NULL, sizeof(key), &out_value, &out_size, &ttl, &deleted), -1);

    /* null value on put */
    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), NULL, sizeof(value), -1, 1, 0), -1);

    /* null output pointers on get */
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), NULL, &out_size, &ttl, &deleted), -1);
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), &out_value, NULL, &ttl, &deleted), -1);

    skip_list_free(list);
}

void test_skip_list_zero_size_key()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "";
    uint8_t value[] = "value";

    /* zero-size key should fail */
    ASSERT_EQ(skip_list_put_with_seq(list, key, 0, value, sizeof(value), -1, 1, 0), -1);

    skip_list_free(list);
}

void test_skip_list_large_keys_values()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    /* test key larger than inline threshold (24 bytes) */
    uint8_t large_key[100];
    memset(large_key, 'K', sizeof(large_key));

    /* test value larger than inline threshold */
    uint8_t large_value[200];
    memset(large_value, 'V', sizeof(large_value));

    ASSERT_EQ(skip_list_put_with_seq(list, large_key, sizeof(large_key), large_value,
                                     sizeof(large_value), -1, 1, 0),
              0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;
    int64_t ttl;

    ASSERT_EQ(skip_list_get(list, large_key, sizeof(large_key), &retrieved_value, &retrieved_size,
                            &ttl, &deleted),
              0);
    ASSERT_EQ(retrieved_size, sizeof(large_value));
    ASSERT_EQ(memcmp(retrieved_value, large_value, sizeof(large_value)), 0);

    free(retrieved_value);
    skip_list_free(list);
}

void test_skip_list_duplicate_key_update()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    uint8_t value2[] = "updated_value";

    /* insert first value */
    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value1, sizeof(value1), -1, 1, 0), 0);

    /* insert second value with same key (LSM tree allows duplicates) */
    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value2, sizeof(value2), -1, 2, 0), 0);

    /* verify we get the first matching value (search finds first occurrence) */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;
    int64_t ttl;

    ASSERT_EQ(
        skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_size, &ttl, &deleted),
        0);

    /* GET should return the latest version (value2), atomic replacement, no duplicates */
    ASSERT_EQ(retrieved_size, sizeof(value2));
    ASSERT_EQ(memcmp(retrieved_value, value2, sizeof(value2)), 0);
    ASSERT_EQ(deleted, 0);

    /* count should be 1 (atomic replacement, no duplicates in memtable) */
    ASSERT_EQ(skip_list_count_entries(list), 1);

    free(retrieved_value);
    skip_list_free(list);
}

void test_skip_list_delete_operations()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "delete_me";
    uint8_t value[] = "value";

    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 1, 0), 0);
    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value, sizeof(value), -1, 2, 0), 0);

    /* get should return with deleted flag */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;
    int64_t ttl;

    int result =
        skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_size, &ttl, &deleted);

    if (result == 0 && retrieved_value != NULL)
    {
        free(retrieved_value);
    }

    /* delete non-existent key */
    uint8_t nonexistent[] = "nonexistent";
    result = skip_list_get(list, nonexistent, sizeof(nonexistent), &retrieved_value,
                           &retrieved_size, &ttl, &deleted);
    ASSERT_EQ(result, -1);

    skip_list_free(list);
}

void test_skip_list_delete_existing_keys()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                         strlen(value) + 1, -1, i + 1, 0),
                  0);
    }

    ASSERT_EQ(skip_list_count_entries(list), 100);

    /* delete every other key */
    for (int i = 0; i < 100; i += 2)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, 101 + (i / 2)), 0);
    }

    /* verify deleted keys return deleted flag */
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        int result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &ttl,
                                   &deleted);

        if (i % 2 == 0)
        {
            /* should be deleted */
            ASSERT_EQ(result, 0);
            ASSERT_EQ(deleted, 1);
        }
        else
        {
            /* should exist */
            ASSERT_EQ(result, 0);
            ASSERT_EQ(deleted, 0);
        }

        if (value) free(value);
    }

    skip_list_free(list);
}

void test_skip_list_delete_nonexistent_keys()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    /* delete non-existent keys should be no-op */
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "nonexist_%d", i);
        ASSERT_EQ(skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, i + 1), 0);
    }

    /* list should still be empty (no tombstones created) */
    ASSERT_EQ(skip_list_count_entries(list), 0);

    /* verify keys don't exist */
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "nonexist_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        int result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &ttl,
                                   &deleted);
        ASSERT_EQ(result, -1);
    }

    skip_list_free(list);
}

void test_skip_list_delete_and_reinsert()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    uint8_t value2[] = "value2";

    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value1, sizeof(value1), -1, 1, 0), 0);

    ASSERT_EQ(skip_list_delete(list, key, sizeof(key), 2), 0);

    /* verify deleted */
    uint8_t *retrieved = NULL;
    size_t size = 0;
    uint8_t deleted = 0;
    int64_t ttl;
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), &retrieved, &size, &ttl, &deleted), 0);
    ASSERT_EQ(deleted, 1);
    if (retrieved) free(retrieved);

    /* re-insert with new value */
    ASSERT_EQ(skip_list_put_with_seq(list, key, sizeof(key), value2, sizeof(value2), -1, 3, 0), 0);

    /* verify new value exists and not deleted */
    retrieved = NULL;
    size = 0;
    deleted = 0;
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), &retrieved, &size, &ttl, &deleted), 0);
    ASSERT_EQ(deleted, 0);
    ASSERT_EQ(size, sizeof(value2));
    ASSERT_TRUE(memcmp(retrieved, value2, sizeof(value2)) == 0);
    if (retrieved) free(retrieved);

    skip_list_free(list);
}

void test_skip_list_iterate_with_deletes()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                         strlen(value) + 1, -1, i + 1, 0),
                  0);
    }

    for (int i = 10; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        ASSERT_EQ(skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, 51 + i), 0);
    }

    /* iterate and count non-deleted entries */
    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    int total_count = 0;
    int deleted_count = 0;
    int active_count = 0;

    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        do
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            int64_t ttl;
            uint8_t deleted;

            ASSERT_EQ(
                skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
                0);

            total_count++;
            if (deleted)
                deleted_count++;
            else
                active_count++;

        } while (skip_list_cursor_next(cursor) == 0);
    }

    ASSERT_EQ(total_count, 50);
    ASSERT_EQ(deleted_count, 10);
    ASSERT_EQ(active_count, 40);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void *lockfree_stress_writer(void *arg)
{
    concurrent_test_ctx_t *ctx = (concurrent_test_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        /* use overlapping keys to maximize contention */
        int key_id = i % 100; /* only 100 unique keys, lots of updates */
        char key_buf[32];
        char value_buf[64];
        snprintf(key_buf, sizeof(key_buf), "key%d", key_id);
        snprintf(value_buf, sizeof(value_buf), "t%d_v%d", ctx->thread_id, i);

        /* retry loop: if write fails due to sequence conflict, get new seq and retry */
        int result = -1;
        int retry_count = 0;
        while (result != 0 && retry_count < 100)
        {
            /* get next sequence number atomically */
            uint64_t seq = atomic_fetch_add_explicit(ctx->shared_seq, 1, memory_order_relaxed) + 1;

            result =
                skip_list_put_with_seq(ctx->list, (uint8_t *)key_buf, strlen(key_buf) + 1,
                                       (uint8_t *)value_buf, strlen(value_buf) + 1, -1, seq, 0);
            retry_count++;
        }

        if (result != 0)
        {
            printf(
                RED
                "ERROR: Thread %d failed to insert key %s at iteration %d after %d retries\n" RESET,
                ctx->thread_id, key_buf, i, retry_count);
            return NULL;
        }

        ctx->writes_completed++;
    }

    return NULL;
}

void test_skip_list_concurrent_duplicate_keys()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);
    ASSERT_TRUE(list != NULL);

    const int num_writers = 8;
    const int ops_per_thread = 5000;
    const int num_unique_keys = 50; /* many threads writing to same keys */

    pthread_t *writers = malloc(num_writers * sizeof(pthread_t));
    concurrent_test_ctx_t *writer_ctx = malloc(num_writers * sizeof(concurrent_test_ctx_t));

    /* shared atomic sequence counter for all threads */
    _Atomic(uint64_t) shared_seq = 0;

    printf(YELLOW
           "  Testing concurrent duplicate key handling: %d threads, %d ops each, %d unique "
           "keys\n" RESET,
           num_writers, ops_per_thread, num_unique_keys);

    /* create writer threads that will heavily contend on the same keys */
    for (int i = 0; i < num_writers; i++)
    {
        writer_ctx[i].list = list;
        writer_ctx[i].thread_id = i;
        writer_ctx[i].num_ops = ops_per_thread;
        writer_ctx[i].writes_completed = 0;
        writer_ctx[i].shared_seq = &shared_seq;
        pthread_create(&writers[i], NULL, lockfree_stress_writer, &writer_ctx[i]);
    }

    for (int i = 0; i < num_writers; i++)
    {
        pthread_join(writers[i], NULL);
        printf(YELLOW "  Writer %d completed %d writes\n" RESET, i, writer_ctx[i].writes_completed);
    }

    int total_writes = 0;
    for (int i = 0; i < num_writers; i++)
    {
        total_writes += writer_ctx[i].writes_completed;
    }

    printf(CYAN "  Total writes attempted: %d\n" RESET, total_writes);
    ASSERT_EQ(total_writes, num_writers * ops_per_thread);

    /* verify entry count is correct (should be <= 100 unique keys) */
    int entry_count = skip_list_count_entries(list);
    printf(CYAN "  Entry count in list: %d\n" RESET, entry_count);
    ASSERT_TRUE(entry_count <= 100); /* we use key%100 in stress writer */
    ASSERT_TRUE(entry_count > 0);

    /* verify all keys are accessible and have valid data */
    int keys_found = 0;
    for (int i = 0; i < 100; i++)
    {
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "key%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        int result = skip_list_get(list, (uint8_t *)key_buf, strlen(key_buf) + 1, &value,
                                   &value_size, &ttl, &deleted);
        if (result == 0 && value != NULL && !deleted)
        {
            keys_found++;
            free(value);
        }
    }

    printf(CYAN "  Keys found: %d\n" RESET, keys_found);
    ASSERT_EQ(keys_found, entry_count); /* all entries should be findable */

    /* verify no duplicate nodes exist by iterating */
    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);

    int iterated = 0;
    char *last_key = NULL;
    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        do
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            int64_t ttl;
            uint8_t deleted;

            ASSERT_EQ(
                skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
                0);

            /* verify no duplicate keys in sequence */
            if (last_key != NULL)
            {
                ASSERT_TRUE(strcmp(last_key, (char *)key) != 0); /* keys should be unique */
                free(last_key);
            }
            last_key = malloc(key_size);
            memcpy(last_key, key, key_size);

            iterated++;
        } while (skip_list_cursor_next(cursor) == 0);
    }

    if (last_key) free(last_key);

    printf(CYAN "  Iterated entries: %d\n" RESET, iterated);
    ASSERT_EQ(iterated, entry_count); /* iteration count should match entry count */

    skip_list_cursor_free(cursor);
    free(writers);
    free(writer_ctx);
    skip_list_free(list);
}

void test_skip_list_lockfree_stress()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);
    ASSERT_TRUE(list != NULL);

    const int num_writers = 16; /* many concurrent writers */
    const int ops_per_thread = 10000;

    pthread_t *writers = malloc(num_writers * sizeof(pthread_t));
    concurrent_test_ctx_t *writer_ctx = malloc(num_writers * sizeof(concurrent_test_ctx_t));

    /* shared atomic sequence counter for all threads */
    _Atomic(uint64_t) shared_seq = 0;

    printf(YELLOW "  Starting %d writer threads, %d ops each...\n" RESET, num_writers,
           ops_per_thread);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_writers; i++)
    {
        writer_ctx[i].list = list;
        writer_ctx[i].thread_id = i;
        writer_ctx[i].num_ops = ops_per_thread;
        writer_ctx[i].writes_completed = 0;
        writer_ctx[i].shared_seq = &shared_seq;
        pthread_create(&writers[i], NULL, lockfree_stress_writer, &writer_ctx[i]);
    }

    for (int i = 0; i < num_writers; i++)
    {
        pthread_join(writers[i], NULL);
        printf(YELLOW "  Writer %d completed %d writes\n" RESET, i, writer_ctx[i].writes_completed);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    int total_writes = 0;
    for (int i = 0; i < num_writers; i++)
    {
        total_writes += writer_ctx[i].writes_completed;
    }

    printf(CYAN "  Total writes: %d in %.2f seconds (%.2f M ops/sec)\n" RESET, total_writes,
           elapsed, total_writes / elapsed / 1000000.0);

    /* verify all writes completed */
    ASSERT_EQ(total_writes, num_writers * ops_per_thread);

    /* verify list integrity, check that we can read all keys */
    printf(YELLOW "  Verifying list integrity...\n" RESET);
    int keys_found = 0;
    for (int i = 0; i < 100; i++)
    {
        char key_buf[32];
        snprintf(key_buf, sizeof(key_buf), "key%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        int result = skip_list_get(list, (uint8_t *)key_buf, strlen(key_buf) + 1, &value,
                                   &value_size, &ttl, &deleted);
        if (result == 0 && value != NULL)
        {
            keys_found++;
            free(value);
        }
    }

    printf(YELLOW "  Found %d/100 keys (some may have been deleted)\n" RESET, keys_found);
    ASSERT_TRUE(keys_found > 0); /* at least some keys should exist */

    /* verify we can iterate without crashes */
    printf(YELLOW "  Testing iteration...\n" RESET);
    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    int iterated = 0;
    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        do
        {
            iterated++;
            if (iterated > 200) /* safety limit */
                break;
        } while (skip_list_cursor_next(cursor) == 0);
    }

    printf(YELLOW "  Iterated through %d entries\n" RESET, iterated);
    skip_list_cursor_free(cursor);

    free(writers);
    free(writer_ctx);
    skip_list_free(list);
}

static uint64_t zipfian_next(uint64_t *state, uint64_t n)
{
    /* simple zipfian approximation: 80% of accesses go to 20% of keys */
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    if ((*state % 100) < 80)
    {
        /* hot keys first 20% */
        return (*state % (n / 5));
    }
    else
    {
        /* cold keys remaining 80% */
        return (n / 5) + (*state % (n - n / 5));
    }
}

void benchmark_skip_list_zipfian()
{
    skip_list_t *list = NULL;
    int result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(list != NULL);

    const int num_ops = 500000;
    const int num_unique_keys = 56000;
    uint64_t zipf_state = 12345;

    /* track unique keys accessed */
    int *key_seen = calloc(num_unique_keys, sizeof(int));
    int unique_keys_accessed = 0;

    /* zipfian writes (hot keys get updated many times) */
    printf(YELLOW "  Zipfian writes (%d ops, ~%d unique keys)...\n" RESET, num_ops,
           num_unique_keys);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_ops; i++)
    {
        uint64_t key_num = zipfian_next(&zipf_state, num_unique_keys);
        char key[32];
        snprintf(key, sizeof(key), "key_%08" PRIu64, key_num);

        char value[100];
        snprintf(value, sizeof(value), "value_%d", i);

        /* track unique keys */
        if (!key_seen[key_num])
        {
            key_seen[key_num] = 1;
            unique_keys_accessed++;
        }

        int put_result = skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1,
                                                (uint8_t *)value, strlen(value) + 1, -1, i + 1, 0);
        ASSERT_EQ(put_result, 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double write_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double write_ops_per_sec = num_ops / write_time;

    printf(CYAN "    Writes: %.2f M ops/sec (%.3f seconds)\n" RESET, write_ops_per_sec / 1e6,
           write_time);
    printf(CYAN "    Unique keys accessed: %d\n" RESET, unique_keys_accessed);
    printf(CYAN "    New inserts: %d, Updates: %d\n" RESET, unique_keys_accessed,
           num_ops - unique_keys_accessed);
    printf(CYAN "    Actual entries in skip list: %d\n" RESET, skip_list_count_entries(list));
    printf(YELLOW "    Duplicates created: %d\n" RESET,
           skip_list_count_entries(list) - unique_keys_accessed);

    free(key_seen);

    /* mixed workload (50% read, 50% write) with zipfian distribution */
    printf(YELLOW "  Zipfian mixed (50/50 read/write, %d ops)...\n" RESET, num_ops);

    zipf_state = 12345; /* reset for consistent distribution */
    clock_gettime(CLOCK_MONOTONIC, &start);

    int read_count = 0, write_count = 0;
    int read_hits = 0;

    for (int i = 0; i < num_ops; i++)
    {
        uint64_t key_num = zipfian_next(&zipf_state, num_unique_keys);
        char key[32];
        snprintf(key, sizeof(key), "key_%08" PRIu64, key_num);

        if (i % 2 == 0)
        {
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint8_t deleted = 0;
            int64_t ttl;

            int get_result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value,
                                           &value_size, &ttl, &deleted);
            if (get_result == 0 && !deleted)
            {
                read_hits++;
                free(value);
            }
            read_count++;
        }
        else
        {
            char value[100];
            snprintf(value, sizeof(value), "updated_value_%d", i);

            skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                   strlen(value) + 1, -1, num_ops + i + 1, 0);
            write_count++;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double mixed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double mixed_ops_per_sec = num_ops / mixed_time;
    double read_ops_per_sec = read_count / mixed_time;
    double mixed_write_ops_per_sec = write_count / mixed_time;

    printf(CYAN "    Mixed: %.2f M ops/sec (%.3f seconds)\n" RESET, mixed_ops_per_sec / 1e6,
           mixed_time);
    printf(CYAN "    Reads: %.2f M ops/sec (%d ops, %d hits, %.1f%% hit rate)\n" RESET,
           read_ops_per_sec / 1e6, read_count, read_hits, (read_hits * 100.0) / read_count);
    printf(CYAN "    Writes: %.2f M ops/sec (%d ops)\n" RESET, mixed_write_ops_per_sec / 1e6,
           write_count);

    /* pure reads (all hot keys) */
    printf(YELLOW "  Zipfian reads only (%d ops)...\n" RESET, num_ops);

    zipf_state = 12345;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int pure_read_hits = 0;
    for (int i = 0; i < num_ops; i++)
    {
        uint64_t key_num = zipfian_next(&zipf_state, num_unique_keys);
        char key[32];
        snprintf(key, sizeof(key), "key_%08" PRIu64, key_num);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        int get_result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size,
                                       &ttl, &deleted);
        if (get_result == 0 && !deleted)
        {
            pure_read_hits++;
            free(value);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double read_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double pure_read_ops_per_sec = num_ops / read_time;

    printf(CYAN "    Reads: %.2f M ops/sec (%.3f seconds, %d hits, %.1f%% hit rate)\n" RESET,
           pure_read_ops_per_sec / 1e6, read_time, pure_read_hits,
           (pure_read_hits * 100.0) / num_ops);

    skip_list_free(list);
}

void test_skip_list_update_patterns()
{
    skip_list_t *list = NULL;
    int result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(list != NULL);

    printf(YELLOW "  Writing version 1 for 50 keys...\n" RESET);
    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(value, sizeof(value), "version_1_value_%d", i);

        result = skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                        strlen(value) + 1, -1, i + 1, 0);
        ASSERT_EQ(result, 0);
    }

    int count_v1 = skip_list_count_entries(list);
    printf(YELLOW "    After version 1: %d entries\n" RESET, count_v1);
    ASSERT_EQ(count_v1, 50);

    /* update same keys multiple times */
    for (int version = 2; version <= 5; version++)
    {
        printf(YELLOW "  Writing version %d for 50 keys...\n" RESET, version);
        for (int i = 0; i < 50; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "update_key_%d", i);
            snprintf(value, sizeof(value), "version_%d_value_%d", version, i);

            result = skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                            strlen(value) + 1, -1, (version - 1) * 50 + i + 1, 0);
            ASSERT_EQ(result, 0);
        }

        int count = skip_list_count_entries(list);
        printf(YELLOW "    After version %d: %d entries\n" RESET, version, count);
    }

    printf(YELLOW "  Verifying all keys return version 5...\n" RESET);
    for (int i = 0; i < 50; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(expected, sizeof(expected), "version_5_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &ttl,
                               &deleted);
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(!deleted);
        ASSERT_EQ(value_size, strlen(expected) + 1);

        if (memcmp(value, expected, strlen(expected)) != 0)
        {
            printf(RED "    ERROR: key=%s expected=%s got=%s\n" RESET, key, expected,
                   (char *)value);
            ASSERT_TRUE(0);
        }

        free(value);
    }

    printf(YELLOW "    All 50 keys verified successfully!\n" RESET);

    skip_list_free(list);
}

static void test_skip_list_large_value_updates(void)
{
    skip_list_t *list = NULL;
    int result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(list != NULL);

    printf(YELLOW "  Testing large value updates (100 bytes, 10 versions)...\n" RESET);

    const int num_keys = 20;
    const int num_versions = 10;
    char large_value[100];

    for (int version = 1; version <= num_versions; version++)
    {
        for (int i = 0; i < num_keys; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "large_key_%d", i);
            snprintf(large_value, sizeof(large_value), "large_version_%d_value_%d_padding", version,
                     i);

            result = skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1,
                                            (uint8_t *)large_value, strlen(large_value) + 1, -1,
                                            (version - 1) * num_keys + i + 1, 0);
            ASSERT_EQ(result, 0);
        }

        int count = skip_list_count_entries(list);
        printf(YELLOW "    After version %d: %d entries\n" RESET, version, count);

        /* after first version, count should stay constant (in-place updates) */
        if (version > 1)
        {
            ASSERT_EQ(count, num_keys);
        }
    }

    /* verify we get the latest version for all keys */
    printf(YELLOW "  Verifying all keys return version %d...\n" RESET, num_versions);
    for (int i = 0; i < num_keys; i++)
    {
        char key[32], expected[100];
        snprintf(key, sizeof(key), "large_key_%d", i);
        snprintf(expected, sizeof(expected), "large_version_%d_value_%d_padding", num_versions, i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &ttl,
                               &deleted);
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(!deleted);
        ASSERT_EQ(value_size, strlen(expected) + 1);

        if (memcmp(value, expected, strlen(expected)) != 0)
        {
            printf(RED "    ERROR: key=%s expected=%s got=%s\n" RESET, key, expected,
                   (char *)value);
            ASSERT_TRUE(0);
        }

        free(value);
    }

    printf(CYAN "    All %d keys verified successfully!\n" RESET, num_keys);
    printf(CYAN "    Final entry count: %d (should be %d, no duplicates)\n" RESET,
           skip_list_count_entries(list), num_keys);

    skip_list_free(list);
}

void benchmark_skip_list_deletions()
{
    skip_list_t *list = NULL;
    int result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(list != NULL);

    const int num_keys = 100000;
    struct timespec start, end;

    printf(YELLOW "  Populating %d keys...\n" RESET, num_keys);
    for (int i = 0; i < num_keys; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        result = skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                        strlen(value) + 1, -1, i + 1, 0);
        ASSERT_EQ(result, 0);
    }

    printf(YELLOW "  Initial entry count: %d\n" RESET, skip_list_count_entries(list));

    /* benchmark delete existing keys */
    printf(YELLOW "  Deleting existing keys (%d ops)...\n" RESET, num_keys);
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, num_keys + i + 1);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double delete_existing_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double delete_existing_ops_per_sec = num_keys / delete_existing_time;

    printf(YELLOW "    Delete existing: %.2f M ops/sec (%.3f seconds)\n" RESET,
           delete_existing_ops_per_sec / 1e6, delete_existing_time);

    /* verify all keys are marked deleted */
    int deleted_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint8_t deleted = 0;
        int64_t ttl;

        result = skip_list_get(list, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &ttl,
                               &deleted);
        if (result == 0 && deleted)
        {
            deleted_count++;
            free(value);
        }
    }
    printf(YELLOW "    Verified %d keys marked as deleted\n" RESET, deleted_count);

    skip_list_free(list);

    /* benchmark delete non-existing keys (no-op, should be very fast) */
    const int tombstone_ops = 10000;
    printf(YELLOW "  Deleting non-existing keys (%d ops)...\n" RESET, tombstone_ops);
    result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);

    /* pre-populate some keys for realistic distribution */
    for (int i = 0; i < tombstone_ops; i += 10)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "anchor_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                               strlen(value) + 1, -1, (i / 10) + 1, 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < tombstone_ops; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "nonexist_%d", i);
        skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, (tombstone_ops / 10) + i + 1);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double delete_nonexist_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double delete_nonexist_ops_per_sec = tombstone_ops / delete_nonexist_time;

    printf(YELLOW "    Delete non-existing: %.2f M ops/sec (%.3f seconds)\n" RESET,
           delete_nonexist_ops_per_sec / 1e6, delete_nonexist_time);
    printf(YELLOW "    Tombstone count: %d\n" RESET, skip_list_count_entries(list));

    skip_list_free(list);

    /* benchmark mixed workload (50% existing, 50% non-existing) */
    printf(YELLOW "  Mixed deletions (50%% existing, 50%% non-existing, %d ops)...\n" RESET,
           num_keys);
    result = skip_list_new(&list, 12, 0.25);
    ASSERT_EQ(result, 0);

    /* populate half the keys */
    for (int i = 0; i < num_keys / 2; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "mixed_%d", i * 2);
        snprintf(value, sizeof(value), "value_%d", i * 2);

        skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                               strlen(value) + 1, -1, i + 1, 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "mixed_%d", i);
        skip_list_delete(list, (uint8_t *)key, strlen(key) + 1, (num_keys / 2) + i + 1);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double delete_mixed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double delete_mixed_ops_per_sec = num_keys / delete_mixed_time;

    printf(CYAN "    Delete mixed: %.2f M ops/sec (%.3f seconds)\n" RESET,
           delete_mixed_ops_per_sec / 1e6, delete_mixed_time);

    skip_list_free(list);
}

void test_skip_list_seek_for_prev_nonexistent()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.24f), 0);

    /* insert keys 020-029 like in the failing test */
    for (int i = 20; i < 30; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);
        ASSERT_EQ(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                         strlen(value), -1, i + 1, 0),
                  0);
    }

    skip_list_cursor_t *cursor = NULL;
    ASSERT_TRUE(skip_list_cursor_init(&cursor, list) == 0);
    ASSERT_TRUE(cursor != NULL);

    /* seek_for_prev with "key_025_5" should find "key_025" */
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)"key_025_5", 9), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(memcmp(key, "key_025", 7), 0);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

/* reverse comparator for testing */
static int reverse_memcmp_comparator(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx)
{
    (void)ctx;
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int result = memcmp(key1, key2, min_size);
    if (result != 0) return -result;      /* negate to reverse */
    if (key1_size < key2_size) return 1;  /* reverse: shorter is greater */
    if (key1_size > key2_size) return -1; /* reverse: longer is smaller */
    return 0;
}

void test_skip_list_reverse_comparator()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new_with_comparator(&list, 12, 0.25, reverse_memcmp_comparator, NULL), 0);
    ASSERT_TRUE(list != NULL);

    /* insert keys 0-9 */
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);
        ASSERT_EQ(skip_list_put_with_seq(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                         strlen(value) + 1, -1, i + 1, 0),
                  0);
    }

    /* iterate forward -- should get keys in reverse order (9, 8, 7, ..., 0) */
    skip_list_cursor_t *cursor = NULL;
    ASSERT_EQ(skip_list_cursor_init(&cursor, list), 0);
    ASSERT_EQ(skip_list_cursor_goto_first(cursor), 0);

    int expected = 9;
    while (skip_list_cursor_valid(cursor))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        ASSERT_EQ(
            skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted), 0);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%03d", expected);

        printf("  Expected: %s, Got: %s\n", expected_key, (char *)key);
        ASSERT_EQ(strcmp((char *)key, expected_key), 0);

        expected--;
        if (skip_list_cursor_next(cursor) != 0) break;
    }

    ASSERT_EQ(expected, -1); /* should have iterated through all 10 keys */

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void test_skip_list_prefix_seek_behavior()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    /* common prefixes: user:100, user:200, user:300, user:400, user:500 */
    const char *keys[] = {"user:100", "user:200", "user:300", "user:400", "user:500"};
    const char *values[] = {"alice", "bob", "charlie", "david", "eve"};
    const int num_keys = 5;

    for (int i = 0; i < num_keys; i++)
    {
        ASSERT_EQ(skip_list_put_with_seq(list, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                         (uint8_t *)values[i], strlen(values[i]) + 1, -1, i + 1, 0),
                  0);
    }

    skip_list_cursor_t *cursor = NULL;
    ASSERT_EQ(skip_list_cursor_init(&cursor, list), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    const char *seek1 = "user:150";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek1, strlen(seek1) + 1), 0);
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)key, "user:200"), 0);
    ASSERT_EQ(strcmp((char *)value, "bob"), 0);

    const char *seek2 = "user:250";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek2, strlen(seek2) + 1), 0);
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)key, "user:300"), 0);

    const char *seek3 = "user:";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek3, strlen(seek3) + 1), 0);
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)key, "user:100"), 0);

    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek3, strlen(seek3) + 1), 0);
    int count = 0;
    while (skip_list_cursor_next(cursor) == 0 && skip_list_cursor_valid(cursor) == 1)
    {
        ASSERT_EQ(
            skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted), 0);
        /* verify key starts with "user:" */
        ASSERT_EQ(strncmp((char *)key, "user:", 5), 0);
        count++;
    }
    ASSERT_EQ(count, num_keys);

    const char *seek5 = "user:350";
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek5, strlen(seek5) + 1), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)key, "user:300"), 0);
    const char *seek6 = "user:999";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek6, strlen(seek6) + 1), 0);

    int next_result = skip_list_cursor_next(cursor);
    if (next_result == 0)
    {
        ASSERT_EQ(skip_list_cursor_valid(cursor), 0);
    }

    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek6, strlen(seek6) + 1), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)key, "user:500"), 0);

    const char *seek8 = "aaa";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek8, strlen(seek8) + 1), 0);
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);
    ASSERT_EQ(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl, &deleted),
              0);

    ASSERT_EQ(strcmp((char *)key, "user:100"), 0);

    uint8_t *get_value = NULL;
    size_t get_value_size = 0;
    uint8_t get_deleted = 0;
    time_t get_ttl;
    int get_result = skip_list_get(list, (uint8_t *)seek1, strlen(seek1) + 1, &get_value,
                                   &get_value_size, &get_ttl, &get_deleted);
    ASSERT_EQ(get_result, -1);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

void test_skip_list_put_batch()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.24f), 0);

    /* we test batch put with multiple entries */
    skip_list_batch_entry_t entries[5];
    const char *keys[] = {"batch_key1", "batch_key2", "batch_key3", "batch_key4", "batch_key5"};
    const char *values[] = {"value1", "value2", "value3", "value4", "value5"};

    for (int i = 0; i < 5; i++)
    {
        entries[i].key = (const uint8_t *)keys[i];
        entries[i].key_size = strlen(keys[i]) + 1;
        entries[i].value = (const uint8_t *)values[i];
        entries[i].value_size = strlen(values[i]) + 1;
        entries[i].ttl = -1;
        entries[i].seq = (uint64_t)(i + 1);
        entries[i].deleted = 0;
    }

    int result = skip_list_put_batch(list, entries, 5);
    ASSERT_EQ(result, 5);

    /* we verify all entries are retrievable */
    for (int i = 0; i < 5; i++)
    {
        uint8_t *retrieved_value = NULL;
        size_t retrieved_value_size = 0;
        int64_t ttl;
        uint8_t deleted;
        int get_result = skip_list_get(list, (const uint8_t *)keys[i], strlen(keys[i]) + 1,
                                       &retrieved_value, &retrieved_value_size, &ttl, &deleted);
        ASSERT_EQ(get_result, 0);
        ASSERT_EQ(deleted, 0);
        ASSERT_EQ(strcmp((char *)retrieved_value, values[i]), 0);
        free(retrieved_value);
    }

    ASSERT_EQ(skip_list_count_entries(list), 5);

    skip_list_free(list);
}

void test_skip_list_put_batch_sorted()
{
    /* we test batch put with sorted keys for optimal performance */
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.24f), 0);

    const int batch_size = 100;
    skip_list_batch_entry_t *entries = malloc(batch_size * sizeof(skip_list_batch_entry_t));
    char **keys = malloc(batch_size * sizeof(char *));
    char **values = malloc(batch_size * sizeof(char *));

    /* we create sorted keys */
    for (int i = 0; i < batch_size; i++)
    {
        keys[i] = malloc(32);
        values[i] = malloc(32);
        snprintf(keys[i], 32, "sorted_key_%04d", i);
        snprintf(values[i], 32, "value_%04d", i);

        entries[i].key = (const uint8_t *)keys[i];
        entries[i].key_size = strlen(keys[i]) + 1;
        entries[i].value = (const uint8_t *)values[i];
        entries[i].value_size = strlen(values[i]) + 1;
        entries[i].ttl = -1;
        entries[i].seq = (uint64_t)(i + 1);
        entries[i].deleted = 0;
    }

    int result = skip_list_put_batch(list, entries, batch_size);
    ASSERT_EQ(result, batch_size);
    ASSERT_EQ(skip_list_count_entries(list), batch_size);

    /* we verify first, middle, and last entries */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_value_size = 0;
    int64_t ttl;
    uint8_t deleted;

    ASSERT_EQ(skip_list_get(list, (const uint8_t *)keys[0], strlen(keys[0]) + 1, &retrieved_value,
                            &retrieved_value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)retrieved_value, values[0]), 0);
    free(retrieved_value);

    ASSERT_EQ(skip_list_get(list, (const uint8_t *)keys[50], strlen(keys[50]) + 1, &retrieved_value,
                            &retrieved_value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)retrieved_value, values[50]), 0);
    free(retrieved_value);

    ASSERT_EQ(skip_list_get(list, (const uint8_t *)keys[99], strlen(keys[99]) + 1, &retrieved_value,
                            &retrieved_value_size, &ttl, &deleted),
              0);
    ASSERT_EQ(strcmp((char *)retrieved_value, values[99]), 0);
    free(retrieved_value);

    for (int i = 0; i < batch_size; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
    free(entries);
    skip_list_free(list);
}

void benchmark_skip_list_batch_vs_single()
{
    printf(BOLDWHITE "\n=== Batch vs Single Put Benchmark ===\n" RESET);

    const int num_entries = 100000;
    skip_list_batch_entry_t *entries = malloc(num_entries * sizeof(skip_list_batch_entry_t));
    char **keys = malloc(num_entries * sizeof(char *));
    char **values = malloc(num_entries * sizeof(char *));

    /* we prepare entries */
    for (int i = 0; i < num_entries; i++)
    {
        keys[i] = malloc(32);
        values[i] = malloc(64);
        snprintf(keys[i], 32, "bench_key_%08d", i);
        snprintf(values[i], 64, "bench_value_%08d", i);

        entries[i].key = (const uint8_t *)keys[i];
        entries[i].key_size = strlen(keys[i]) + 1;
        entries[i].value = (const uint8_t *)values[i];
        entries[i].value_size = strlen(values[i]) + 1;
        entries[i].ttl = -1;
        entries[i].seq = (uint64_t)(i + 1);
        entries[i].deleted = 0;
    }

    /* we benchmark single puts */
    skip_list_t *list_single = NULL;
    skip_list_new(&list_single, 12, 0.24f);

    clock_t start_single = clock();
    for (int i = 0; i < num_entries; i++)
    {
        skip_list_put_with_seq(list_single, entries[i].key, entries[i].key_size, entries[i].value,
                               entries[i].value_size, entries[i].ttl, entries[i].seq,
                               entries[i].deleted);
    }
    clock_t end_single = clock();
    double time_single = (double)(end_single - start_single) / CLOCKS_PER_SEC;

    /* we benchmark batch puts */
    skip_list_t *list_batch = NULL;
    skip_list_new(&list_batch, 12, 0.24f);

    clock_t start_batch = clock();
    skip_list_put_batch(list_batch, entries, num_entries);
    clock_t end_batch = clock();
    double time_batch = (double)(end_batch - start_batch) / CLOCKS_PER_SEC;

    printf(CYAN "Single put (%d entries): %.4f seconds (%.0f ops/sec)\n" RESET, num_entries,
           time_single, num_entries / time_single);
    printf(CYAN "Batch put (%d entries):  %.4f seconds (%.0f ops/sec)\n" RESET, num_entries,
           time_batch, num_entries / time_batch);
    printf(BOLDWHITE "Speedup: %.2fx\n" RESET, time_single / time_batch);

    ASSERT_EQ(skip_list_count_entries(list_single), num_entries);
    ASSERT_EQ(skip_list_count_entries(list_batch), num_entries);

    for (int i = 0; i < num_entries; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
    free(entries);
    skip_list_free(list_single);
    skip_list_free(list_batch);
}

int main(void)
{
    RUN_TEST(test_skip_list_create_node, tests_passed);
    RUN_TEST(test_skip_list_put_get, tests_passed);
    RUN_TEST(test_skip_list_destroy, tests_passed);
    RUN_TEST(test_skip_list_clear, tests_passed);
    RUN_TEST(test_skip_list_min_max_key, tests_passed);
    RUN_TEST(test_skip_list_count_entries, tests_passed);
    RUN_TEST(test_skip_list_get_size, tests_passed);
    RUN_TEST(test_skip_list_cursor_init, tests_passed);
    RUN_TEST(test_skip_list_cursor_next, tests_passed);
    RUN_TEST(test_skip_list_cursor_prev, tests_passed);
    RUN_TEST(test_skip_list_cursor_functions, tests_passed);
    RUN_TEST(test_skip_list_ttl, tests_passed);
    RUN_TEST(test_skip_list_cursor_seek, tests_passed);
    RUN_TEST(test_skip_list_cursor_seek_for_prev, tests_passed);
    RUN_TEST(test_skip_list_seek_for_prev_nonexistent, tests_passed);
    RUN_TEST(test_skip_list_null_validation, tests_passed);
    RUN_TEST(test_skip_list_zero_size_key, tests_passed);
    RUN_TEST(test_skip_list_large_keys_values, tests_passed);
    RUN_TEST(test_skip_list_delete_operations, tests_passed);
    RUN_TEST(test_skip_list_delete_existing_keys, tests_passed);
    RUN_TEST(test_skip_list_delete_nonexistent_keys, tests_passed);
    RUN_TEST(test_skip_list_delete_and_reinsert, tests_passed);
    RUN_TEST(test_skip_list_iterate_with_deletes, tests_passed);
    RUN_TEST(test_skip_list_large_value_updates, tests_passed);
    RUN_TEST(test_skip_list_duplicate_key_update, tests_passed);
    RUN_TEST(test_skip_list_update_patterns, tests_passed);
    RUN_TEST(test_skip_list_concurrent_read_write, tests_passed);
    RUN_TEST(test_skip_list_concurrent_duplicate_keys, tests_passed);
    RUN_TEST(test_skip_list_lockfree_stress, tests_passed);
    RUN_TEST(test_skip_list_reverse_comparator, tests_passed);
    RUN_TEST(test_skip_list_prefix_seek_behavior, tests_passed);
    RUN_TEST(test_skip_list_put_batch, tests_passed);
    RUN_TEST(test_skip_list_put_batch_sorted, tests_passed);

    RUN_TEST(benchmark_skip_list, tests_passed);
    RUN_TEST(benchmark_skip_list_sequential, tests_passed);
    RUN_TEST(benchmark_skip_list_zipfian, tests_passed);
    RUN_TEST(benchmark_skip_list_deletions, tests_passed);
    RUN_TEST(benchmark_skip_list_batch_vs_single, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}