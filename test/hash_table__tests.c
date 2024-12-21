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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../src/hash_table.h"
#include "test_macros.h"
#include "test_utils.h"

#define BENCH_N 1000000 /* number of entries to write and retrieve */

void test_hash_table_new()
{
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);
    assert(ht != NULL);
    assert(ht->buckets != NULL);
    assert(ht->bucket_count == INITIAL_BUCKETS);
    assert(ht->count == 0);
    assert(ht->total_size == 0);
    hash_table_destroy(ht);
    printf(GREEN "test_hash_table_new passed\n" RESET);
}

void test_hash_table_put_get()
{
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);

    uint8_t key[] = "key";
    uint8_t value[] = "value";
    assert(hash_table_put(&ht, key, sizeof(key), value, sizeof(value), -1) == 0);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    assert(hash_table_get(ht, key, sizeof(key), &retrieved_value, &retrieved_value_size) == 0);
    assert(retrieved_value_size == sizeof(value));
    assert(memcmp(retrieved_value, value, retrieved_value_size) == 0);
    free(retrieved_value);

    hash_table_destroy(ht);
    printf(GREEN "test_hash_table_put_get passed\n" RESET);
}

void test_hash_table_resize()
{
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);

    for (size_t i = 0; i < INITIAL_BUCKETS * 2; i++)
    {
        uint8_t key[16];
        uint8_t value[16];
        snprintf((char *)key, sizeof(key), "key%zu", i);
        snprintf((char *)value, sizeof(value), "value%zu", i);
        assert(hash_table_put(&ht, key, sizeof(key), value, sizeof(value), -1) == 0);
    }

    assert(ht->bucket_count > INITIAL_BUCKETS);
    hash_table_destroy(ht);
    printf(GREEN "test_hash_table_resize passed\n" RESET);
}

void test_hash_table_clear()
{
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);

    uint8_t key[] = "key";
    uint8_t value[] = "value";
    assert(hash_table_put(&ht, key, sizeof(key), value, sizeof(value), -1) == 0);

    hash_table_clear(ht);
    assert(ht->count == 0);
    assert(ht->total_size == 0);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    assert(hash_table_get(ht, key, sizeof(key), &retrieved_value, &retrieved_value_size) == -1);

    hash_table_destroy(ht);
    printf(GREEN "test_hash_table_clear passed\n" RESET);
}

void test_hash_table_cursor()
{
    /* we can add more
     * here if needed */
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);

    uint8_t key[] = "key";
    uint8_t value[] = "value";
    assert(hash_table_put(&ht, key, sizeof(key), value, sizeof(value), -1) == 0);

    hash_table_cursor_t *cursor = hash_table_cursor_new(ht);
    uint8_t *retrieved_key;
    size_t retrieved_key_size;
    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    time_t retrieved_ttl;
    do
    {
        if (hash_table_cursor_get(cursor, &retrieved_key, &retrieved_key_size, &retrieved_value,
                                  &retrieved_value_size, &retrieved_ttl) == 0)
        {
            assert(retrieved_key_size == sizeof(key));
            assert(memcmp(retrieved_key, key, retrieved_key_size) == 0);
            assert(retrieved_value_size == sizeof(value));
            assert(memcmp(retrieved_value, value, retrieved_value_size) == 0);
        }
    } while (hash_table_cursor_next(cursor) == 0);

    hash_table_cursor_destroy(cursor);
    hash_table_destroy(ht);
    printf(GREEN "test_hash_table_cursor passed\n" RESET);
}

void benchmark_hash_table()
{
    /* random key-value pairs */
    hash_table_t *ht;
    assert(hash_table_new(&ht) == 0);
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
        assert(hash_table_put(&ht, keys[i], key_size, values[i], value_size, -1) == 0);
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
        int result = hash_table_get(ht, keys[i], key_size, &retrieved_value, &retrieved_value_size);
        if (result != 0)
        {
            printf(RED "Failed to retrieve key at index %zu\n" RESET, i);
            continue;
        }
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

    hash_table_destroy(ht);
}

int main(void)
{
    test_hash_table_new();
    test_hash_table_put_get();
    test_hash_table_clear();
    test_hash_table_cursor();
    test_hash_table_resize();
    benchmark_hash_table();
    return 0;
}