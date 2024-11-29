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
    0xDEADBEEF /* On expiration of a node if time to live is set we set the key's value to this */

typedef struct skiplist_node skiplist_node;

/*
 * skiplist_node
 * the node structure for the skiplist
 * @param key the key for the node
 * @param key_size the key size
 * @param value the value for the node
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @param forward the forward pointers for the node
 */
struct skiplist_node
{
    uint8_t *key;       /* the key for the node */
    size_t key_size;          /* the key size */
    uint8_t *value;     /* the value for the node */
    size_t value_size;        /* the value size */
    time_t ttl;               /* an expiration time for the node (optional) */
    skiplist_node *forward[]; /* the forward pointers for the node */
};

/*
 * skiplist
 * the skiplist structure
 * @param level the current level of the skiplist
 * @param max_level the maximum level of the skiplist
 * @param probability the probability of a node having a certain level
 * @param header the header node of the skiplist
 * @param total_size the total size in bytes
 * @param lock the read-write lock for list-level synchronization
 */
typedef struct
{
    int level;             /* the current level of the skiplist  */
    int max_level;         /* the maximum level of the skiplist  */
    float probability;     /* the probability of a node having a certain level  */
    skiplist_node *header; /* the header node of the skiplist  */
    size_t total_size;     /* total size in bytes  */
    pthread_rwlock_t lock; /* read-write lock for list-level synchronization  */
} skiplist;

/*
 * skiplist_cursor
 * the cursor structure for the skiplist
 * @param list the skiplist
 * @param current the current node
 */
typedef struct
{
    skiplist *list;         /* the skiplist  */
    skiplist_node *current; /* the current node  */
} skiplist_cursor;

/* Skip list function prototypes */

/*
 * skiplist_create_node
 * create a new skiplist node
 * @param level the level of the node
 * @param key the key for the node
 * @param key_size the key size
 * @param value the value for the node
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @return the new skiplist node
 */
skiplist_node *skiplist_create_node(int level, const uint8_t *key, size_t key_size,
                                    const uint8_t *value, size_t value_size, time_t ttl);

/*
 * skiplist_destroy_node
 * destroy a skiplist node
 * @param node the node to destroy
 * @return true if the node was destroyed successfully, false otherwise
 */
bool skiplist_destroy_node(skiplist_node *node);

/*
 * new_skiplist
 * create a new skiplist
 * @param max_level the maximum level of the skiplist
 * @param probability the probability of a node having a certain level
 * @return the new skiplist
 */
skiplist *new_skiplist(int max_level, float probability);

/*
 * skiplist_destroy
 * destroy a skiplist
 * @param list the skiplist to destroy
 * @return 0 if the skiplist was destroyed successfully, -1 otherwise
 */
int skiplist_destroy(skiplist *list);

/*
 * skiplist_random_level
 * generate a random level for a new skiplist node
 * @param list the skiplist
 * @return the new level
 */
int skiplist_random_level(skiplist *list);

/*
 * skiplist_compare_keys
 * compares two keys
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @return 0 if the keys are equal, -1 if key1 is less than key2, 1 if key1 is greater than key2
 */
int skiplist_compare_keys(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                          size_t key2_size);

/*
 * skiplist_delete
 * deletes a key value pair from skiplist
 * @param list the skiplist
 * @param key the key to delete
 * @param key_size the key size
 * @return true if the key was deleted successfully, false otherwise
 */
bool skiplist_delete(skiplist *list, const uint8_t *key, size_t key_size);

/*
 * skiplist_put
 * put a new key-value pair into the skiplist
 * @param list the skiplist
 * @param key the key to put
 * @param key_size the key size
 * @param value the value to put
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @return true if the key-value pair was put successfully, false otherwise
 */
bool skiplist_put(skiplist *list, const uint8_t *key, size_t key_size,
                  const uint8_t *value, size_t value_size, time_t ttl);

/*
 * skiplist_get
 * get a value from the skiplist
 * @param list the skiplist
 * @param key the key to get
 * @param key_size the key size
 * @param value the value
 * @param value_size the value size
 * @return true if the value was retrieved successfully, false otherwise
 */
bool skiplist_get(skiplist *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size);

/*
 * skiplist_cursor_init
 * initialize a new skiplist cursor
 * @param list the skiplist
 * @return the new skiplist cursor
 */
skiplist_cursor *skiplist_cursor_init(skiplist *list);

/*
 * skiplist_cursor_next
 * move the cursor to the next node
 * @param cursor the cursor
 * @return true if the cursor was moved successfully, false otherwise
 */
bool skiplist_cursor_next(skiplist_cursor *cursor);

/*
 * skiplist_cursor_prev
 * move the cursor to the previous node
 * @param cursor the cursor
 * @return true if the cursor was moved successfully, false otherwise
 */
bool skiplist_cursor_prev(skiplist_cursor *cursor);

/*
 * skiplist_cursor_free
 * free the memory for the cursor
 * @param cursor the cursor
 * @return true if the cursor was freed successfully, false otherwise
 */
void skiplist_cursor_free(skiplist_cursor *cursor);

/*
 * skiplist_clear
 * clear the skiplist
 * @param list the skiplist
 */
int skiplist_clear(skiplist *list);

/*
 * skiplist_copy
 * copy the skiplist
 * @param list the skiplist
 * @return the copied skiplist
 */
skiplist *skiplist_copy(skiplist *list);

/*
 * skiplist_check_and_update_ttl
 * checks if a node has expired and updates the value to TOMBSTONE
 * @param node the node to check
 * @return true if the node has expired, false otherwise
 */
bool skiplist_check_and_update_ttl(skiplist_node *node);

#endif /* SKIPLIST_H */