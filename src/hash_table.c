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

#include <stdio.h>
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

    /* we set the buckets to INITIAL_BUCKETS */
    (*ht)->buckets = malloc(INITIAL_BUCKETS * sizeof(hash_table_bucket_t *));
    if ((*ht)->buckets == NULL)
    {
        free(*ht);
        return -1;
    }

    /* we set the buckets to 0 */
    memset((*ht)->buckets, 0, INITIAL_BUCKETS * sizeof(hash_table_bucket_t *));

    /* we set the bucket count */
    (*ht)->bucket_count = INITIAL_BUCKETS;

    /* we set the count to 0 */
    (*ht)->count = 0;

    /* we set the total size to 0 */
    (*ht)->total_size = 0;
    return 0;
}

int hash_table_put(hash_table_t **ht, const uint8_t *key, size_t key_size, const uint8_t *value,
                   size_t value_size, time_t ttl)
{
    size_t index = bloom_filter_hash(key, key_size, 0) % (*ht)->bucket_count;

    /* we initialize the bucket */
    hash_table_bucket_t *bucket = malloc(sizeof(hash_table_bucket_t));
    if (bucket == NULL)
    {
        return -1;
    }

    /* we set the key */
    bucket->key = malloc(key_size);
    if (bucket->key == NULL)
    {
        free(bucket);
        return -1;
    }

    memcpy(bucket->key, key, key_size);
    bucket->key_size = key_size;

    /* we set the value */
    bucket->value = malloc(value_size);
    if (bucket->value == NULL)
    {
        free(bucket->key);
        free(bucket);
        return -1;
    }

    memcpy(bucket->value, value, value_size);
    bucket->value_size = value_size;
    bucket->ttl = ttl;

    /* we free the old bucket if it exists */
    if ((*ht)->buckets[index] != NULL)
    {
        free((*ht)->buckets[index]->key);
        free((*ht)->buckets[index]->value);
        free((*ht)->buckets[index]);
    }
    else
    {
        (*ht)->count++;
    }

    (*ht)->buckets[index] = bucket; /* we set the bucket */
    (*ht)->total_size += key_size + value_size;

    /* we check if we should resize */
    if (hash_table_should_resize(*ht))
    {
        if (hash_table_resize(ht, (*ht)->bucket_count * 2) == -1)
        {
            return -1;
        }
    }

    return 0;
}

int hash_table_resize(hash_table_t **ht, size_t new_size)
{
    /* we create a new hash table
     * with the new size and we add all buckets from the old hash table */

    hash_table_t *new_ht = malloc(sizeof(hash_table_t));
    if (*ht == NULL)
    {
        return -1;
    }

    new_ht->buckets = malloc(new_size * sizeof(hash_table_bucket_t *));
    if (new_ht->buckets == NULL)
    {
        free(new_ht);
        return -1;
    }

    /* we set the buckets to 0 */
    memset(new_ht->buckets, 0, new_size * sizeof(hash_table_bucket_t *));

    /* we set the bucket count */
    new_ht->bucket_count = new_size;

    /* we set the count to 0 */
    new_ht->count = 0;

    /* we set the total size to 0 */
    new_ht->total_size = 0;

    /* we add all the buckets from the old hash table */
    for (size_t i = 0; i < (*ht)->bucket_count; i++)
    {
        hash_table_bucket_t *bucket = (*ht)->buckets[i];
        if (bucket != NULL)
        {
            if (bucket->key == NULL || bucket->value == NULL)
            {
                continue;
            }
            (void)hash_table_put(&new_ht, bucket->key, bucket->key_size, bucket->value,
                                 bucket->value_size, bucket->ttl);
        }
    }

    /* we free the old hash table */
    hash_table_destroy(*ht);

    /* we set the new hash table */
    *ht = new_ht;

    return 0;
}

int hash_table_get(hash_table_t *ht, const uint8_t *key, size_t key_size, uint8_t **value,
                   size_t *value_size)
{
    size_t index = bloom_filter_hash(key, key_size, 0) % ht->bucket_count;
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

    *value = malloc(bucket->value_size);
    if (*value == NULL)
    {
        return -1;
    }

    /* we copy the value */
    memcpy(*value, bucket->value, bucket->value_size);

    *value_size = bucket->value_size;
    return 0;
}

hash_table_cursor_t *hash_table_cursor_new(hash_table_t *ht)
{
    hash_table_cursor_t *cursor = malloc(sizeof(hash_table_cursor_t));
    cursor->ht = ht;
    cursor->current_bucket_index = 0;
    cursor->last_bucket_index = ht->bucket_count - 1;
    return cursor;
}

void hash_table_cursor_reset(hash_table_cursor_t *cursor)
{
    cursor->current_bucket_index = 0;
}

int hash_table_cursor_next(hash_table_cursor_t *cursor)
{
    if (cursor->current_bucket_index >= cursor->ht->bucket_count)
    {
        return -1; /* we are at the end */
    }

    cursor->current_bucket_index++;
    return 0;
}

int hash_table_cursor_prev(hash_table_cursor_t *cursor)
{
    if (cursor->current_bucket_index == 0)
    {
        return -1; /* we are at the beginning */
    }

    --cursor->current_bucket_index;
    return 0;
}

int hash_table_cursor_get(hash_table_cursor_t *cursor, uint8_t **key, size_t *key_size,
                          uint8_t **value, size_t *value_size)
{
    if (cursor->current_bucket_index >= cursor->ht->bucket_count)
    {
        return -1; /* we are at the end */
    }

    if (cursor->current_bucket_index < 0)
    {
        return -1; /* we are at the beginning */
    }

    hash_table_bucket_t *bucket = cursor->ht->buckets[cursor->current_bucket_index];
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
    return -1;
}

void hash_table_cursor_destroy(hash_table_cursor_t *cursor)
{
    free(cursor);
}

int hash_table_should_resize(hash_table_t *ht)
{
    return ht->count >= (size_t)((double)ht->bucket_count * LOAD_FACTOR);
}

void hash_table_clear(hash_table_t *ht)
{
    if (ht == NULL || ht->buckets == NULL) return;

    for (size_t i = 0; i < ht->bucket_count; i++)
    {
        hash_table_bucket_t *bucket = ht->buckets[i];
        if (bucket != NULL)
        {
            free(bucket->key);
            free(bucket->value);
            free(bucket);
            ht->buckets[i] = NULL;
        }
    }
    ht->count = 0;
    ht->total_size = 0;
}

void hash_table_destroy(hash_table_t *ht)
{
    if (ht == NULL) return;

    hash_table_clear(ht);
    free(ht->buckets);
    free(ht);
}