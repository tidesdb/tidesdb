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
    printf("test_hash_table_new passed\n");
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
    printf("test_hash_table_put_get passed\n");
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
    printf("test_hash_table_resize passed\n");
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
    printf("test_hash_table_clear passed\n");
}

void test_hash_table_cursor()
{
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
    do
    {
        if (hash_table_cursor_get(cursor, &retrieved_key, &retrieved_key_size, &retrieved_value,
                                  &retrieved_value_size) == 0)
        {
            assert(retrieved_key_size == sizeof(key));
            assert(memcmp(retrieved_key, key, retrieved_key_size) == 0);
            assert(retrieved_value_size == sizeof(value));
            assert(memcmp(retrieved_value, value, retrieved_value_size) == 0);
        }
    } while (hash_table_cursor_next(cursor) == 0);

    hash_table_cursor_destroy(cursor);
    hash_table_destroy(ht);
    printf("test_hash_table_cursor passed\n");
}

int main(void)
{
    test_hash_table_new();
    test_hash_table_put_get();
    test_hash_table_clear();
    test_hash_table_cursor();
    test_hash_table_resize();
    return 0;
}