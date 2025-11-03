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
#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "../src/skip_list.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define BENCH_N 1000000 /* number of entries to write and retrieve */

void test_skip_list_create_node()
{
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_node_t *node = skip_list_create_node(1, key, sizeof(key), value, sizeof(value), -1);
    ASSERT_TRUE(node != NULL);
    ASSERT_TRUE(memcmp(node->key, key, sizeof(key)) == 0);
    ASSERT_TRUE(memcmp(node->value, value, sizeof(value)) == 0);
    (void)skip_list_free_node(node);
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
    printf(GREEN "test_skip_list_put_get passed\n" RESET);
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
    printf(GREEN "test_skip_list_destroy passed\n" RESET);
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
    printf(GREEN "test_skip_list_clear passed\n" RESET);
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
    printf(GREEN "test_skip_list_count_entries passed\n" RESET);
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
    printf(GREEN "test_skip_list_get_size passed\n" RESET);
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
    printf(GREEN "test_skip_list_copy passed\n" RESET);
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
    printf(GREEN "test_skip_list_cursor_init passed\n" RESET);
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
    ASSERT_TRUE(memcmp(cursor->current->key, key2, sizeof(key2)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
    printf(GREEN "test_skip_list_cursor_next passed\n" RESET);
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
    ASSERT_TRUE(memcmp(cursor->current->key, key1, sizeof(key1)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
    printf(GREEN "test_skip_list_cursor_prev passed\n" RESET);
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
    printf(GREEN "test_skip_list_ttl passed\n" RESET);
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
    printf(GREEN "test_skip_list_min_max_key passed\n" RESET);
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
    RUN_TEST(benchmark_skip_list, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}