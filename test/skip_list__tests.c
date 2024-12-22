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
#include <assert.h>
#include <unistd.h>

#include "../src/skip_list.h"
#include "test_macros.h"
#include "test_utils.h"

#define BENCH_N 1000000 /* number of entries to write and retrieve */

void test_skip_list_create_node()
{
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_node_t *node = skip_list_create_node(1, key, sizeof(key), value, sizeof(value), -1);
    assert(node != NULL);
    assert(memcmp(node->key, key, sizeof(key)) == 0);
    assert(memcmp(node->value, value, sizeof(value)) == 0);
    skip_list_free_node(node);
    printf(GREEN "test_skip_list_create_node passed\n" RESET);
}

void test_skip_list_put_get()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_put(list, key, sizeof(key), value, sizeof(value), -1);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    int result = skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size);
    assert(result == 0);
    assert(memcmp(retrieved_value, value, sizeof(value)) == 0);

    free(retrieved_value);
    skip_list_free(list);
    printf(GREEN "test_skip_list_put_get passed\n" RESET);
}

void test_skip_list_destroy()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    int result = skip_list_free(list);
    assert(result == 0);
    printf(GREEN "test_skip_list_destroy passed\n" RESET);
}

void test_skip_list_clear()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_put(list, key, sizeof(key), value, sizeof(value), -1);
    int result = skip_list_clear(list);
    assert(result == 0);
    assert(skip_list_count_entries(list) == 0);
    skip_list_free(list);
    printf(GREEN "test_skip_list_clear passed\n" RESET);
}

void test_skip_list_count_entries()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    assert(skip_list_count_entries(list) == 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_put(list, key, sizeof(key), value, sizeof(value), -1);
    assert(skip_list_count_entries(list) == 1);

    skip_list_free(list);
    printf(GREEN "test_skip_list_count_entries passed\n" RESET);
}

void test_skip_list_get_size()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    assert(skip_list_get_size(list) == 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_put(list, key, sizeof(key), value, sizeof(value), -1);
    assert(skip_list_get_size(list) > 0);

    skip_list_free(list);
    printf(GREEN "test_skip_list_get_size passed\n" RESET);
}

void test_skip_list_copy()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    skip_list_put(list, key, sizeof(key), value, sizeof(value), -1);

    skip_list_t *copy = skip_list_copy(list);
    assert(copy != NULL);
    assert(skip_list_count_entries(copy) == skip_list_count_entries(list));

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    int result = skip_list_get(copy, key, sizeof(key), &retrieved_value, &retrieved_value_size);
    assert(result == 0);
    assert(memcmp(retrieved_value, value, sizeof(value)) == 0);

    free(retrieved_value);
    skip_list_free(copy);
    skip_list_free(list);
    printf(GREEN "test_skip_list_copy passed\n" RESET);
}

void test_skip_list_cursor_init()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    assert(cursor != NULL);
    assert(cursor->list == list);
    assert(cursor->current == list->header->forward[0]);

    (void)skip_list_cursor_free(cursor);
    assert(skip_list_free(list) == 0);
    printf(GREEN "test_skip_list_cursor_init passed\n" RESET);
}

void test_skip_list_cursor_next()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1);
    skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1);

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    assert(cursor != NULL);
    assert(cursor->current != NULL);

    int result = skip_list_cursor_next(cursor);
    assert(result == 0);
    assert(cursor->current != NULL);
    assert(memcmp(cursor->current->key, key2, sizeof(key2)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
    printf(GREEN "test_skip_list_cursor_next passed\n" RESET);
}

void test_skip_list_cursor_prev()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1);
    skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1);

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    assert(cursor != NULL);
    assert(cursor->current != NULL);

    skip_list_cursor_next(cursor);
    int result = skip_list_cursor_prev(cursor);
    assert(result == 0);
    assert(cursor->current != NULL);
    assert(memcmp(cursor->current->key, key1, sizeof(key1)) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
    printf(GREEN "test_skip_list_cursor_prev passed\n" RESET);
}

void benchmark_skip_list()
{
    /* random key-value pairs */
    skip_list_t *list = skip_list_new(12, 0.24f);
    const size_t key_size = 16;
    const size_t value_size = 8;

    /* allocate memory for keys and values */
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

    /* generate random key-value pairs */
    for (size_t i = 0; i < BENCH_N; i++)
    {
        generate_random_key_value(keys[i], key_size, values[i], value_size);
    }

    /* benchmark writing */
    clock_t start_write = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        skip_list_put(list, keys[i], key_size, values[i], value_size, -1);
    }
    clock_t end_write = clock();
    double write_time = (double)(end_write - start_write) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to write %d entries: %f seconds\n" RESET, BENCH_N, write_time);

    /* benchmark reading and verifying */
    clock_t start_read = clock();
    for (size_t i = 0; i < BENCH_N; i++)
    {
        uint8_t *retrieved_value;
        size_t retrieved_value_size;
        int result =
            skip_list_get(list, keys[i], key_size, &retrieved_value, &retrieved_value_size);
        assert(result == 0);
        assert(memcmp(retrieved_value, values[i], value_size) == 0);
        free(retrieved_value);
    }
    clock_t end_read = clock();
    double read_time = (double)(end_read - start_read) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to read and verify %d entries: %f seconds\n" RESET, BENCH_N, read_time);

    /* free allocated memory */
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
    skip_list_t *list = skip_list_new(12, 0.24f);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    time_t ttl = 1; /* 1 second */

    skip_list_put(list, key, sizeof(key), value, sizeof(value), time(NULL) + ttl);

    /* take a snooze */
    sleep(ttl + 1);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    int result = skip_list_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size);

    /* check if the value is a tombstone */
    assert(result == 0);
    assert(retrieved_value_size == sizeof(uint32_t));
    assert(*(uint32_t *)retrieved_value == TOMBSTONE);

    free(retrieved_value);
    skip_list_free(list);
    printf(GREEN "test_skip_list_ttl passed\n" RESET);
}

void example()
{
    skip_list_t *list = skip_list_new(12, 0.24f);
    if (list == NULL)
    {
        fprintf(stderr, "Failed to create skip list\n");
        return;
    }

    for (int i = 0; i < 10; i++)
    {
        char key[5];
        char value[5];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "val%d", i);
        if (skip_list_put(list, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                          strlen(value) + 1, -1) != 0)
        {
            fprintf(stderr, "Failed to insert key-value pair\n");
            skip_list_free(list);
            return;
        }
    }

    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    if (cursor == NULL)
    {
        fprintf(stderr, "Failed to initialize cursor\n");
        skip_list_free(list);
        return;
    }

    do
    {
        uint8_t *key;
        size_t key_size;
        uint8_t *value;
        size_t value_size;
        time_t ttl;
        if (skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl) == 0)
        {
            printf("Key: %.*s, Value: %.*s\n", (int)key_size, key, (int)value_size, value);
        }
        else
        {
            printf("Failed to get key-value pair\n");
        }
    } while (skip_list_cursor_next(cursor) == 0);

    (void)skip_list_cursor_free(cursor);
    (void)skip_list_free(list);
}

void test_skip_list_cursor_functions()
{
    /* create a new skip list */
    skip_list_t *list = skip_list_new(4, 0.5);
    assert(list != NULL);

    /* initialize cursor */
    skip_list_cursor_t *cursor = skip_list_cursor_init(list);
    assert(cursor != NULL);

    /* test cursor on empty list */
    assert(skip_list_cursor_has_next(cursor) == -1);
    assert(skip_list_cursor_has_prev(cursor) == -1);
    assert(skip_list_cursor_goto_first(cursor) == -1);
    assert(skip_list_cursor_goto_last(cursor) == -1);

    (void)skip_list_cursor_free(cursor);

    /* add entries */
    uint8_t key1[] = {1};
    uint8_t value1[] = {10};
    assert(skip_list_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == 0);

    uint8_t key2[] = {2};
    uint8_t value2[] = {20};
    assert(skip_list_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == 0);

    uint8_t key3[] = {3};
    uint8_t value3[] = {30};
    assert(skip_list_put(list, key3, sizeof(key3), value3, sizeof(value3), -1) == 0);

    /* reinitialize cursor */
    cursor = skip_list_cursor_init(list);
    assert(cursor != NULL);

    /* test cursor functionality */
    assert(skip_list_cursor_goto_first(cursor) == 0);
    assert(skip_list_cursor_has_next(cursor) == 1);
    assert(skip_list_cursor_has_prev(cursor) == 0);

    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;

    /* check first entry */
    assert(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl) == 0);
    assert(key_size == sizeof(key1));
    assert(memcmp(key, key1, key_size) == 0);
    assert(value_size == sizeof(value1));
    assert(memcmp(value, value1, value_size) == 0);

    assert(skip_list_cursor_next(cursor) == 0);
    assert(skip_list_cursor_has_next(cursor) == 1);
    assert(skip_list_cursor_has_prev(cursor) == 1);

    assert(skip_list_cursor_next(cursor) == 0);
    assert(skip_list_cursor_has_next(cursor) == 0);
    assert(skip_list_cursor_has_prev(cursor) == 1);

    /* check last entry */
    assert(skip_list_cursor_goto_last(cursor) == 0);
    assert(skip_list_cursor_has_next(cursor) == 0);
    assert(skip_list_cursor_has_prev(cursor) == 1);

    assert(skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl) == 0);
    assert(key_size == sizeof(key3));
    assert(memcmp(key, key3, key_size) == 0);
    assert(value_size == sizeof(value3));
    assert(memcmp(value, value3, value_size) == 0);

    /* clean upp */
    (void)skip_list_cursor_free(cursor);
    assert(skip_list_free(list) == 0);
}

int main(void)
{
    test_skip_list_create_node();
    test_skip_list_put_get();
    test_skip_list_destroy();
    test_skip_list_clear();
    test_skip_list_count_entries();
    test_skip_list_get_size();
    test_skip_list_copy();
    test_skip_list_cursor_init();
    test_skip_list_cursor_next();
    test_skip_list_cursor_prev();
    test_skip_list_cursor_functions();
    test_skip_list_ttl();
    benchmark_skip_list();

    return 0;
}