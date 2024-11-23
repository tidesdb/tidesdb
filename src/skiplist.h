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
#ifndef SKIPLIST_H
#define SKIPLIST_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOMBSTONE \
    0xDEADBEEF  // On expiration of a node if time to live is set we set the key's value to this

typedef struct skiplist_node skiplist_node;

/*
 * skiplist_node
 * the node structure for the skiplist
 */
struct skiplist_node {
    unsigned char *key;        // the key for the node
    size_t key_size;           // the key size
    unsigned char *value;      // the value for the node
    size_t value_size;         // the value size
    time_t ttl;                // an expiration time for the node (optional)
    skiplist_node *forward[];  // the forward pointers for the node
};

/*
 * skiplist
 * the skiplist structure
 */
typedef struct {
    int level;              // the current level of the skiplist
    int max_level;          // the maximum level of the skiplist
    float probability;      // the probability of a node having a certain level
    skiplist_node *header;  // the header node of the skiplist
    size_t total_size;      // total size in bytes
    pthread_rwlock_t lock;  // read-write lock for list-level synchronization
} skiplist;

/*
 * skiplist_cursor
 * the cursor structure for the skiplist
 */
typedef struct skiplist_cursor {
    skiplist *list;          // the skiplist
    skiplist_node *current;  // the current node
} skiplist_cursor;

/* Skip list function prototypes */

/*
 * skiplist_create_node
 * create a new skiplist node
 */
skiplist_node *skiplist_create_node(int level, const unsigned char *key, size_t key_size,
                                    const unsigned char *value, size_t value_size, time_t ttl);

/*
 * skiplist_destroy_node
 * destroy a skiplist node
 */
bool skiplist_destroy_node(skiplist_node *node);

/*
 * new_skiplist
 * create a new skiplist
 */
skiplist *new_skiplist(int max_level, float probability);

/*
 * skiplist_destroy
 * destroy a skiplist
 */
int skiplist_destroy(skiplist *list);

/*
 * skiplist_random_level
 * generate a random level for a new skiplist node
 */
int skiplist_random_level(skiplist *list);

/*
 * skiplist_compare_keys
 * compares two keys
 */
int skiplist_compare_keys(const unsigned char *key1, size_t key1_size, const unsigned char *key2,
                          size_t key2_size);

/*
 * skiplist_delete
 * deletes a key value pair from skiplist
 */
bool skiplist_delete(skiplist *list, const unsigned char *key, size_t key_size);

/*
 * skiplist_put
 * put a new key-value pair into the skiplist
 */
bool skiplist_put(skiplist *list, const unsigned char *key, size_t key_size,
                  const unsigned char *value, size_t value_size, time_t ttl);

/*
 * skiplist_get
 * get a value from the skiplist
 */
bool skiplist_get(skiplist *list, const unsigned char *key, size_t key_size, unsigned char **value,
                  size_t *value_size);

/*
 * skiplist_cursor_init
 * initialize a new skiplist cursor
 */
skiplist_cursor *skiplist_cursor_init(skiplist *list);

/*
 * skiplist_cursor_next
 * move the cursor to the next node
 */
bool skiplist_cursor_next(skiplist_cursor *cursor);

/*
 * skiplist_cursor_prev
 * move the cursor to the previous node
 */
bool skiplist_cursor_prev(skiplist_cursor *cursor);

/*
 * skiplist_cursor_free
 * free the memory for the cursor
 */
void skiplist_cursor_free(skiplist_cursor *cursor);

/*
 * skiplist_clear
 * clear the skiplist
 */
int skiplist_clear(skiplist *list);

/*
 * skiplist_copy
 * copy the skiplist
 */
skiplist *skiplist_copy(skiplist *list);

/*
 * skiplist_check_and_update_ttl
 * checks if a node has expired and updates the value to TOMBSTONE
 */
bool skiplist_check_and_update_ttl(skiplist_node *node);

#endif  // SKIPLIST_H