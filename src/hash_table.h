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
#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> /* should be fine for windows, linux, and mac */

#include "bloom_filter.h" /* for bloom_filter_hash */

#define TOMBSTONE                                                                                 \
    0xDEADBEEF /* on expiration of a bucket if time to live is set we set the key's value to this \
                */
#define INITIAL_BUCKETS 1048576 /* the initial number of buckets in the hash table */

#define LOAD_FACTOR 0.50 /* The load factor of the hash table */

/**
 * hash_table_bucket_t
 * the hash table bucket structure
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time to live of the key-value pair
 */
typedef struct
{
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
} hash_table_bucket_t;

/**
 * hash_table_t
 * the hash table structure
 * @param buckets the hash table buckets
 * @param bucket_count the number of buckets
 * @param total_size the total size of hash table (keys and values) in bytes
 * @param count the number of active buckets
 */
typedef struct
{
    hash_table_bucket_t **buckets;
    size_t bucket_count;
    size_t total_size;
    size_t count;
} hash_table_t;

/**
 * hash_table_cursor_t
 * the hash table cursor structure
 * @param ht the hash table
 * @param current_bucket_index the current bucket index
 * @param last_bucket_index the last bucket index
 */
typedef struct
{
    hash_table_t *ht;
    ssize_t current_bucket_index;
    ssize_t last_bucket_index;
} hash_table_cursor_t;

/**
 * hash_table_new
 * creates a new hash table
 * @return the new hash table
 */
hash_table_t *hash_table_new();

/**
 * hash_table_put
 * puts a key-value pair into the hash table
 * @param ht the hash table to put into
 * @param key the key to put
 * @param key_size the size of the key
 * @param value the value to put
 * @param value_size the size of the value
 * @param ttl the time to live for the key-value pair. -1 if no ttl
 * @return 0 if successful, -1 if not
 */
int hash_table_put(hash_table_t **ht, const uint8_t *key, size_t key_size, const uint8_t *value,
                   size_t value_size, time_t ttl);

/**
 * hash_table_get
 * gets a value from the hash table
 * @param ht the hash table to get from
 * @param key the key to get
 * @param key_size the size of the key
 * @param value the value to get
 * @param value_size the size of the value
 * @return 0 if successful, -1 if not
 */
int hash_table_get(hash_table_t *ht, const uint8_t *key, size_t key_size, uint8_t **value,
                   size_t *value_size);

/**
 * hash_table_resize
 * resizes the hash table
 * @param ht the hash table to resize
 * @param new_size the new size of the hash table (buckets)
 * @return 0 if successful, -1 if not
 */
int hash_table_resize(hash_table_t **ht, size_t new_size);

/**
 * hash_table_should_resize
 * checks if the hash table should resize
 * @param ht the hash table to check
 * @return 1 if the hash table should resize, 0 if not
 */
int hash_table_should_resize(hash_table_t *ht);

/**
 * hash_table_free
 * free's the hash table
 * @param ht the hash table to free
 */
void hash_table_free(hash_table_t *ht);

/**
 * hash_table_clear
 * clears the hash table
 * @param ht the hash table to clear
 */
void hash_table_clear(hash_table_t *ht);

/** cursor methods */

/**
 * hash_table_cursor_init
 * creates a new hash table cursor
 * @param ht the hash table to create the cursor for
 * @return the new hash table cursor
 */
hash_table_cursor_t *hash_table_cursor_init(hash_table_t *ht);

/**
 * hash_table_cursor_reset
 * resets the hash table cursor
 * @param cursor the cursor to reset
 */
void hash_table_cursor_reset(hash_table_cursor_t *cursor);

/**
 * hash_table_cursor_next
 * moves the cursor to the next bucket
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int hash_table_cursor_next(hash_table_cursor_t *cursor);

/**
 * hash_table_cursor_prev
 * moves the cursor to the previous bucket
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int hash_table_cursor_prev(hash_table_cursor_t *cursor);

/*
 * hash_table_cursor_get
 * get's current bucket's key and value
 * @param cursor the cursor to get the key and value from
 * @param key the key to be returned
 * @param key_size the size of the key
 * @param value the value to be returned
 * @param value_size the size of the value
 * @param ttl the time to live of the key-value pair
 * @return 0 if successful, -1 if not
 */
int hash_table_cursor_get(hash_table_cursor_t *cursor, uint8_t **key, size_t *key_size,
                          uint8_t **value, size_t *value_size, time_t *ttl);

/**
 * hash_table_cursor_free
 * free's a hash table cursor
 * @param cursor the cursor to free
 */
void hash_table_cursor_free(hash_table_cursor_t *cursor);

#endif /* __HASH_TABLE_H__ */