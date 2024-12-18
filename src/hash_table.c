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
#include "hash_table.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

int hash_table_new(hash_table_t **ht)
{
    /* we alloc the hash table */
    *ht = malloc(sizeof(hash_table_t));
    if (*ht == NULL)
    {
        return -1;
    }

    /* we set the buckets to 0 */
    memset((*ht)->buckets, 0, sizeof((*ht)->buckets));

    /* we set the total size to 0 */
    (*ht)->total_size = 0;
    return 0;
}

void hash_table_put(hash_table_t *ht, const uint8_t *key, size_t key_size, const uint8_t *value,
                    size_t value_size, time_t ttl)
{
    size_t index = bloom_filter_hash(key, key_size, 0) % BUCKETS;

    /* we initialize the bucket */
    hash_table_bucket_t *bucket = malloc(sizeof(hash_table_bucket_t));

    /* we set the key */
    bucket->key = malloc(key_size);
    memcpy(bucket->key, key, key_size);

    bucket->key_size = key_size;

    /* we set the value */
    bucket->value = malloc(value_size);
    memcpy(bucket->value, value, value_size);
    bucket->value_size = value_size;
    bucket->ttl = ttl;

    /* we free the old bucket if it exists */
    if (ht->buckets[index] != NULL)
    {
        free(ht->buckets[index]->key);
        free(ht->buckets[index]->value);
        free(ht->buckets[index]);
    }

    ht->buckets[index] = bucket; /* we set the bucket */
    ht->total_size += key_size + value_size;
}

int hash_table_get(hash_table_t *ht, const uint8_t *key, size_t key_size, uint8_t **value,
                   size_t *value_size)
{
    size_t index = bloom_filter_hash(key, key_size, 0) % BUCKETS;
    hash_table_bucket_t *bucket = ht->buckets[index];
    if (bucket == NULL || bucket->key_size != key_size || memcmp(bucket->key, key, key_size) != 0)
    {
        return -1; /* key not found */
    }

    /* check if ttl is set and if the key has expired */
    if (bucket->ttl != -1 && time(NULL) > bucket->ttl)
    {
        *(uint32_t *)bucket->value = TOMBSTONE;
        return -1;
    }

    *value = bucket->value;
    *value_size = bucket->value_size;
    return 0;
}

hash_table_cursor_t *hash_table_cursor_new(hash_table_t *ht)
{
    hash_table_cursor_t *cursor = malloc(sizeof(hash_table_cursor_t));
    cursor->ht = ht;
    cursor->current_bucket_index = 0;
    return cursor;
}

void hash_table_cursor_reset(hash_table_cursor_t *cursor)
{
    cursor->current_bucket_index = 0;
}

int hash_table_cursor_next(hash_table_cursor_t *cursor, uint8_t **key, size_t *key_size,
                           uint8_t **value, size_t *value_size)
{
    while (cursor->current_bucket_index < BUCKETS)
    {
        /* we get the bucket */
        hash_table_bucket_t *bucket = cursor->ht->buckets[cursor->current_bucket_index++];
        /* we check if the bucket is not null and not a tombstone */
        if (bucket != NULL)
        {
            if (bucket->ttl != -1 && time(NULL) > bucket->ttl)
            {
                *(uint32_t *)bucket->value = TOMBSTONE;
                return -1;
            }

            *key = bucket->key;
            *key_size = bucket->key_size;
            *value = bucket->value;
            *value_size = bucket->value_size;
            return 0;
        }
    }
    return -1;
}

int hash_table_cursor_prev(hash_table_cursor_t *cursor, uint8_t **key, size_t *key_size,
                           uint8_t **value, size_t *value_size)
{
    while (cursor->current_bucket_index > 0)
    {
        hash_table_bucket_t *bucket = cursor->ht->buckets[--cursor->current_bucket_index];
        /* we check if the bucket is not null and not a tombstone */
        if (bucket != NULL)
        {
            if (bucket->ttl != -1 && time(NULL) > bucket->ttl)
            {
                *(uint32_t *)bucket->value = TOMBSTONE;
                return -1;
            }

            *key = bucket->key;
            *key_size = bucket->key_size;
            *value = bucket->value;
            *value_size = bucket->value_size;
            return 0;
        }
    }
    return -1;
}

void hash_table_cursor_destroy(hash_table_cursor_t *cursor)
{
    free(cursor);
}
