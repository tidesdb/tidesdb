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

void test_hash_table_new()
{
    hash_table_t *ht;
    int result = hash_table_new(&ht);
    assert(result == 0);
    assert(ht != NULL);
    free(ht);
    printf(GREEN "test_hash_table_new passed\n" RESET);
}

void test_hash_table_put_get()
{
    hash_table_t *ht;
    hash_table_new(&ht);

    const char *key = "key";
    const char *value = "value";
    hash_table_put(ht, (const uint8_t *)key, strlen(key), (const uint8_t *)value, strlen(value),
                   -1);

    uint8_t *retrieved_value;
    size_t retrieved_value_size;
    int result = hash_table_get(ht, (const uint8_t *)key, strlen(key), &retrieved_value,
                                &retrieved_value_size);
    assert(result == 0);
    assert(memcmp(retrieved_value, value, retrieved_value_size) == 0);

    free(ht->buckets[bloom_filter_hash((const uint8_t *)key, strlen(key), 0) % BUCKETS]->key);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key, strlen(key), 0) % BUCKETS]->value);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key, strlen(key), 0) % BUCKETS]);
    free(ht);
    printf(GREEN "test_hash_table_put_get passed\n" RESET);
}

void test_hash_table_cursor()
{
    hash_table_t *ht;
    hash_table_new(&ht);

    const char *key1 = "key1";
    const char *value1 = "value1";
    hash_table_put(ht, (const uint8_t *)key1, strlen(key1), (const uint8_t *)value1, strlen(value1),
                   -1);

    const char *key2 = "key2";
    const char *value2 = "value2";
    hash_table_put(ht, (const uint8_t *)key2, strlen(key2), (const uint8_t *)value2, strlen(value2),
                   -1);

    hash_table_cursor_t *cursor = hash_table_cursor_new(ht);
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;

    int result = hash_table_cursor_next(cursor, &key, &key_size, &value, &value_size);
    assert(result == 0);
    assert(memcmp(key, key1, key_size) == 0 || memcmp(key, key2, key_size) == 0);

    result = hash_table_cursor_next(cursor, &key, &key_size, &value, &value_size);
    assert(result == 0);
    assert(memcmp(key, key1, key_size) == 0 || memcmp(key, key2, key_size) == 0);

    result = hash_table_cursor_next(cursor, &key, &key_size, &value, &value_size);
    assert(result == -1);

    hash_table_cursor_destroy(cursor);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]->key);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]->value);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]->key);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]->value);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]);
    free(ht);
    printf(GREEN "test_hash_table_cursor passed\n" RESET);
}

void test_hash_table_cursor_prev()
{
    hash_table_t *ht;
    hash_table_new(&ht);

    const char *key1 = "key1";
    const char *value1 = "value1";
    hash_table_put(ht, (const uint8_t *)key1, strlen(key1), (const uint8_t *)value1, strlen(value1),
                   -1);

    const char *key2 = "key2";
    const char *value2 = "value2";
    hash_table_put(ht, (const uint8_t *)key2, strlen(key2), (const uint8_t *)value2, strlen(value2),
                   -1);

    hash_table_cursor_t *cursor = hash_table_cursor_new(ht);
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;

    /* go to end of the hash table */
    while (hash_table_cursor_next(cursor, &key, &key_size, &value, &value_size) == 0)
        ;

    /* test moving cursor backwards */
    int result = hash_table_cursor_prev(cursor, &key, &key_size, &value, &value_size);
    assert(result == 0);
    assert(memcmp(key, key1, key_size) == 0 || memcmp(key, key2, key_size) == 0);

    result = hash_table_cursor_prev(cursor, &key, &key_size, &value, &value_size);
    assert(result == 0);
    assert(memcmp(key, key1, key_size) == 0 || memcmp(key, key2, key_size) == 0);

    result = hash_table_cursor_prev(cursor, &key, &key_size, &value, &value_size);
    assert(result == -1);

    hash_table_cursor_destroy(cursor);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]->key);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]->value);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key1, strlen(key1), 0) % BUCKETS]);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]->key);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]->value);
    free(ht->buckets[bloom_filter_hash((const uint8_t *)key2, strlen(key2), 0) % BUCKETS]);
    free(ht);
    printf(GREEN "test_hash_table_cursor_prev passed\n" RESET);
}

int main()
{
    test_hash_table_new();
    test_hash_table_put_get();
    test_hash_table_cursor();
    test_hash_table_cursor_prev();
    return 0;
}