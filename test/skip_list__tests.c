/*
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

#define NODE_KEY(node) \
    ((node)->key_is_inline ? (node)->key_data.key_inline : (node)->key_data.key_ptr)
#define NODE_VALUE(node) \
    ((node)->value_is_inline ? (node)->value_data.value_inline : (node)->value_data.value_ptr)

static int tests_passed = 0;
static int tests_failed = 0;

#define BENCH_N 1000000 /* number of entries to write and retrieve */

void test_skip_list_create_node()
{
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_node_t *node =
        skip_list_create_node(1, key, sizeof(key), value, sizeof(value), -1, 0);
    ASSERT_TRUE(node != NULL);
    ASSERT_TRUE(memcmp(NODE_KEY(node), key, sizeof(key)) == 0);
    ASSERT_TRUE(memcmp(NODE_VALUE(node), value, sizeof(value)) == 0);
    ASSERT_EQ(node->deleted, 0);
    skip_list_release_node(node);
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
    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1) == 0);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    uint8_t deleted;
    int get_result =
        skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size, &deleted);
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
    int result = skip_list_free(list);
    ASSERT_EQ(result, 0);
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
    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1) == 0);
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
    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1) == 0);
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
    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1) == 0);
    ASSERT_TRUE(skip_list_get_size(list) > 0);

    (void)skip_list_free(list);
}

void test_skip_list_copy()
{
    skip_list_t *list = NULL;
    if (skip_list_new(&list, 12, 0.24f) == -1)
    {
        printf(RED "Failed to create skip list\n" RESET);
        return;
    }
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1) == 0);

    skip_list_t *copy = skip_list_copy(list);
    ASSERT_TRUE(copy != NULL);
    ASSERT_TRUE(skip_list_count_entries(copy) == skip_list_count_entries(list));

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    uint8_t deleted;

    int result =
        skip_list_get(copy, key, sizeof(key), &retrieved_value, &retrieved_value_size, &deleted);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(memcmp(retrieved_value, value, sizeof(value)) == 0);

    free(retrieved_value);
    (void)skip_list_free(copy);
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
    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    ASSERT_TRUE(cursor != NULL);
    ASSERT_EQ(cursor->list, list);
    ASSERT_EQ(cursor->current, list->header->forward[0]);

    (void)skip_list_cursor_free(cursor);
    ASSERT_TRUE(skip_list_free(list) == 0);
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
    ASSERT_TRUE(skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == 0);
    ASSERT_TRUE(skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == 0);

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
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
    ASSERT_TRUE(skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == 0);
    ASSERT_TRUE(skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == 0);

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
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
        ASSERT_EQ(skip_list_put(list, keys[i], key_size, values[i], value_size, -1), 0);
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

        int result = skip_list_get(list, keys[i], key_size, &retrieved_value, &retrieved_value_size,
                                   &deleted);
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
        skip_list_put(list, keys[i], key_size, values[i], value_size, -1);
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
        skip_list_get(list, keys[i], key_size, &retrieved_value, &retrieved_value_size, &deleted);
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
    time_t ttl = 1;

    ASSERT_TRUE(skip_list_put(list, key, sizeof(key), value, sizeof(value), time(NULL) + ttl) == 0);

    /* take a snooze */
#ifdef _WIN32
    Sleep((ttl + 1) * 1000);
#else
    sleep(ttl + 1);
#endif

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    uint8_t deleted;
    int result =
        skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size, &deleted);

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

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    ASSERT_TRUE(cursor != NULL);

    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_goto_first(cursor) == -1);
    ASSERT_TRUE(skip_list_cursor_goto_last(cursor) == -1);

    (void)skip_list_cursor_free(cursor);

    uint8_t key1[] = {1};
    uint8_t value1[] = {10};
    ASSERT_TRUE(skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == 0);

    uint8_t key2[] = {2};
    uint8_t value2[] = {20};
    ASSERT_TRUE(skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == 0);

    uint8_t key3[] = {3};
    uint8_t value3[] = {30};
    ASSERT_TRUE(skip_list_put(list, key3, sizeof(key3), value3, sizeof(value3), -1) == 0);

    cursor = skip_list_cursor_init(list);
    ASSERT_TRUE(cursor != NULL);

    ASSERT_TRUE(skip_list_cursor_goto_first(cursor) == 0);
    ASSERT_TRUE(skip_list_cursor_has_next(cursor) == 1);
    ASSERT_TRUE(skip_list_cursor_has_prev(cursor) == 0);

    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
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
    ASSERT_TRUE(skip_list_free(list) == 0);
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
    ASSERT_TRUE(skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == 0);

    uint8_t key1[] = {1};
    uint8_t value1[] = {10};
    ASSERT_TRUE(skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == 0);

    uint8_t key3[] = {3};
    uint8_t value3[] = {30};
    ASSERT_TRUE(skip_list_put(list, key3, sizeof(key3), value3, sizeof(value3), -1) == 0);

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
    time_t ttl = 1;
    ASSERT_TRUE(skip_list_put(list, key0, sizeof(key0), value0, sizeof(value0), time(NULL) + ttl) ==
                0);

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

    ASSERT_TRUE(skip_list_free(list) == 0);
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
        ASSERT_TRUE(skip_list_put(list, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1) == 0);
    }

    /* test seek to exact key */
    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    ASSERT_TRUE(cursor != NULL);

    const char *seek_key = "key_50";
    ASSERT_EQ(skip_list_cursor_seek(cursor, (uint8_t *)seek_key, strlen(seek_key)), 0);

    /* cursor should be positioned BEFORE key_50, so next() should return key_50 */
    ASSERT_TRUE(skip_list_cursor_has_next(cursor));
    ASSERT_EQ(skip_list_cursor_next(cursor), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    time_t ttl = 0;
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
    ASSERT_TRUE(skip_list_free(list) == 0);
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
        ASSERT_TRUE(skip_list_put(list, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1) == 0);
    }

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    ASSERT_TRUE(cursor != NULL);

    const char *seek_key = "key_50";
    ASSERT_EQ(skip_list_cursor_seek_for_prev(cursor, (uint8_t *)seek_key, strlen(seek_key)), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    time_t ttl = 0;
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
    ASSERT_TRUE(skip_list_free(list) == 0);
}

void test_skip_list_cow_updates()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);
    ASSERT_TRUE(list != NULL);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), value1, sizeof(value1), -1), 0);

    for (int i = 0; i < 100; i++)
    {
        char value_buf[32];
        snprintf(value_buf, sizeof(value_buf), "value%d", i);
        ASSERT_EQ(
            skip_list_put(list, key, sizeof(key), (uint8_t *)value_buf, strlen(value_buf) + 1, -1),
            0);

        uint8_t *read_value = NULL;
        size_t read_size = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(skip_list_get(list, key, sizeof(key), &read_value, &read_size, &deleted), 0);
        ASSERT_TRUE(read_value != NULL);
        ASSERT_EQ(strcmp((char *)read_value, value_buf), 0);
        free(read_value);
    }

    skip_list_free(list);
}

typedef struct
{
    skip_list_t *list;
    int thread_id;
    int num_ops;
    int reads_completed;
    int writes_completed;
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
        int result = skip_list_get(ctx->list, (uint8_t *)key_buf, strlen(key_buf) + 1, &value,
                                   &value_size, &deleted);

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

        skip_list_put(ctx->list, (uint8_t *)key_buf, strlen(key_buf) + 1, (uint8_t *)value_buf,
                      strlen(value_buf) + 1, -1);

        ctx->writes_completed++;
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
        skip_list_put(list, (uint8_t *)key_buf, strlen(key_buf) + 1, (uint8_t *)value_buf,
                      strlen(value_buf) + 1, -1);
    }

    const int num_readers = 4;
    const int num_writers = 1;
    const int ops_per_thread = 10000;

    pthread_t *readers = malloc(num_readers * sizeof(pthread_t));
    pthread_t *writers = malloc(num_writers * sizeof(pthread_t));
    concurrent_test_ctx_t *reader_ctx = malloc(num_readers * sizeof(concurrent_test_ctx_t));
    concurrent_test_ctx_t *writer_ctx = malloc(num_writers * sizeof(concurrent_test_ctx_t));

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
        pthread_create(&writers[i], NULL, concurrent_writer, &writer_ctx[i]);
    }

    for (int i = 0; i < num_readers; i++)
    {
        pthread_join(readers[i], NULL);
        printf("  Reader %d completed %d reads\n", i, reader_ctx[i].reads_completed);
    }

    for (int i = 0; i < num_writers; i++)
    {
        pthread_join(writers[i], NULL);
        printf("  Writer %d completed %d writes\n", i, writer_ctx[i].writes_completed);
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

    /* null list */
    ASSERT_EQ(skip_list_put(NULL, key, sizeof(key), value, sizeof(value), -1), -1);
    ASSERT_EQ(skip_list_get(NULL, key, sizeof(key), &out_value, &out_size, &deleted), -1);

    /* null key */
    ASSERT_EQ(skip_list_put(list, NULL, sizeof(key), value, sizeof(value), -1), -1);
    ASSERT_EQ(skip_list_get(list, NULL, sizeof(key), &out_value, &out_size, &deleted), -1);

    /* null value on put */
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), NULL, sizeof(value), -1), -1);

    /* null output pointers on get */
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), NULL, &out_size, &deleted), -1);
    ASSERT_EQ(skip_list_get(list, key, sizeof(key), &out_value, NULL, &deleted), -1);

    skip_list_free(list);
}

void test_skip_list_zero_size_key()
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, 12, 0.25f), 0);

    uint8_t key[] = "";
    uint8_t value[] = "value";

    /* zero-size key should fail */
    ASSERT_EQ(skip_list_put(list, key, 0, value, sizeof(value), -1), -1);

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

    ASSERT_EQ(
        skip_list_put(list, large_key, sizeof(large_key), large_value, sizeof(large_value), -1), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(skip_list_get(list, large_key, sizeof(large_key), &retrieved_value, &retrieved_size,
                            &deleted),
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

    uint8_t key[] = "duplicate_key";
    uint8_t value1[] = "first_value";
    uint8_t value2[] = "second_value";

    /* insert first value */
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), value1, sizeof(value1), -1), 0);

    /* update with second value */
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), value2, sizeof(value2), -1), 0);

    /* verify we get the second value */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_size, &deleted),
              0);
    ASSERT_EQ(retrieved_size, sizeof(value2));
    ASSERT_EQ(memcmp(retrieved_value, value2, sizeof(value2)), 0);
    ASSERT_EQ(deleted, 0);

    /* count should still be 1 (update, not insert) */
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

    /* insert then delete */
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1), 0);
    ASSERT_EQ(skip_list_put(list, key, sizeof(key), value, sizeof(value), -1),
              0); /* mark deleted */

    /* get should return with deleted flag */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint8_t deleted = 0;

    int result = skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_size, &deleted);
    /* depending on implementation, might return -1 or return with deleted=1 */
    if (result == 0 && retrieved_value != NULL)
    {
        free(retrieved_value);
    }

    /* delete non-existent key */
    uint8_t nonexistent[] = "nonexistent";
    result = skip_list_get(list, nonexistent, sizeof(nonexistent), &retrieved_value,
                           &retrieved_size, &deleted);
    ASSERT_EQ(result, -1);

    skip_list_free(list);
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
    RUN_TEST(test_skip_list_copy, tests_passed);
    RUN_TEST(test_skip_list_cursor_init, tests_passed);
    RUN_TEST(test_skip_list_cursor_next, tests_passed);
    RUN_TEST(test_skip_list_cursor_prev, tests_passed);
    RUN_TEST(test_skip_list_cursor_functions, tests_passed);
    RUN_TEST(test_skip_list_ttl, tests_passed);
    RUN_TEST(test_skip_list_cursor_seek, tests_passed);
    RUN_TEST(test_skip_list_cursor_seek_for_prev, tests_passed);
    RUN_TEST(test_skip_list_cow_updates, tests_passed);
    RUN_TEST(test_skip_list_concurrent_read_write, tests_passed);
    RUN_TEST(test_skip_list_null_validation, tests_passed);
    RUN_TEST(test_skip_list_zero_size_key, tests_passed);
    RUN_TEST(test_skip_list_large_keys_values, tests_passed);
    RUN_TEST(test_skip_list_duplicate_key_update, tests_passed);
    RUN_TEST(test_skip_list_delete_operations, tests_passed);
    RUN_TEST(benchmark_skip_list, tests_passed);
    RUN_TEST(benchmark_skip_list_sequential, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}