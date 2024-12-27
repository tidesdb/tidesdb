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
#ifndef __SKIP_LIST_H__
#define __SKIP_LIST_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOMBSTONE \
    0xDEADBEEF /* On expiration of a node if time to live is set we set the key's value to this */

typedef struct skip_list_node_t skip_list_node_t; /* forward declaration */

/*
 * skip_list_node_t
 * the node structure for the skip list
 * @param key the key for the node
 * @param key_size the key size
 * @param value the value for the node
 * @param value_size the value size
 * @param ttl an expiration time for the node (-1 if no expiration)
 * @param forward the forward pointers for the node
 */
struct skip_list_node_t
{
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
    skip_list_node_t *forward[];
};

/*
 * skip_list_t
 * the skip list structure
 * @param level the current level of the skip list
 * @param max_level the maximum level of the skip list
 * @param probability the probability of a node having a certain level
 * @param header the header node of the skip list
 * @param total_size the total size in bytes of kv pairs in the skip list
 */
typedef struct
{
    int level;
    int max_level;
    float probability;
    skip_list_node_t *header;
    size_t total_size;
} skip_list_t;

/*
 * skip_list_cursor_t
 * the cursor structure for the skip list
 * @param list the skip list
 * @param current the current node
 */
typedef struct
{
    skip_list_t *list;
    skip_list_node_t *current;
} skip_list_cursor_t;

/* Skip list function prototypes */

/*
 * skip_list_create_node
 * create a new skip list node
 * @param level the level of the node
 * @param key the key for the node
 * @param key_size the key size
 * @param value the value for the node
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @return the new skip list node
 */
skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl);

/*
 * skip_list_free_node
 * free's a skip list node
 * @param node the node to free
 * @return 0 if the node was freed successfully, -1 otherwise
 */
int skip_list_free_node(skip_list_node_t *node);

/*
 * skip_list_new
 * create a new skip list
 * @param max_level the maximum level of the skip list
 * @param probability the probability of a node having a certain level
 * @return the new skip_list
 */
skip_list_t *skip_list_new(int max_level, float probability);

/*
 * skip_list_free
 * free's a skip list
 * @param list the skip list to free
 * @return 0 if the skip list was freed successfully, -1 otherwise on error
 */
int skip_list_free(skip_list_t *list);

/*
 * skip_list_random_level
 * generate a random level for a new skip list node
 * @param list the skip list
 * @return the new level
 */
int skip_list_random_level(skip_list_t *list);

/*
 * skip_list_compare_keys
 * compares two keys
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @return 0 if the keys are equal, -1 if key1 is less than key2, 1 if key1 is greater than key2
 */
int skip_list_compare_keys(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                           size_t key2_size);

/*
 * skip_list_put
 * put a new key-value pair into the skip list
 * @param list the skip list
 * @param key the key to put
 * @param key_size the key size
 * @param value the value to put
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @return 0 if the key-value pair was put successfully, -1 otherwise
 */
int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl);

/*
 * skip_list_get
 * get a value from the skip list
 * @param list the skip list
 * @param key the key to get
 * @param key_size the key size
 * @param value the value
 * @param value_size the value size
 * @return 0 if the value was retrieved successfully, -1 otherwise on error
 */
int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size);

/*
 * skip_list_cursor_init
 * initialize a new skip list cursor
 * @param list the skip list
 * @return the new skip list cursor
 */
skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list);

/*
 * skip_list_cursor_next
 * move the cursor to the next node
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_next(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_prev
 * move the cursor to the previous node
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_prev(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_get
 * get the key and value from the cursor
 * @param cursor the cursor
 * @param key the key
 * @param key_size the key size
 * @param value the value
 * @param value_size the value size
 * @param ttl the expiration time of the node
 * @return 0 if the key and value were retrieved successfully, -1 otherwise on error
 */
int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, time_t *ttl);

/*
 * skip_list_cursor_free
 * free the memory for the cursor
 * @param cursor the cursor
 */
void skip_list_cursor_free(skip_list_cursor_t *cursor);

/*
 * skip_list_clear
 * clear the skip list
 * @param list the skip list
 * @return 0 if the skip list was cleared successfully, -1 otherwise on error
 */
int skip_list_clear(skip_list_t *list);

/*
 * skip_list_copy
 * copy the skip list
 * @param list the skip list
 * @return the copied skip list
 */
skip_list_t *skip_list_copy(skip_list_t *list);

/*
 * skip_list_check_and_update_ttl
 * checks if a node has expired and updates the value to TOMBSTONE
 * @param node the node to check
 * @return 0 if the node has not expired, 1 if the node has expired
 */
int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node);

/*
 * skip_list_get_size
 * get the size of the skip list
 * @param list the skip list
 * @return the size of the skip list
 */
int skip_list_get_size(skip_list_t *list);

/*
 * skip_list_count_entries
 * count the number of entries/nodes in the skip list
 * @param list the skip list
 * @return the number of entries in the skip list
 */
int skip_list_count_entries(skip_list_t *list);

/*
 * skip_list_cursor_at_start
 * check if the cursor is at the start of the skip list
 * @param cursor the cursor
 * @return 0 or 1 if the cursor is at the start of the skip list, -1 otherwise
 */
int skip_list_cursor_at_start(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_at_end
 * check if the cursor is at the end of the skip list
 * @param cursor the cursor
 * @return 0 or 1 if the cursor is at the end of the skip list, -1 otherwise
 */
int skip_list_cursor_at_end(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_has_next
 * check if the cursor has a next node
 * @param cursor the cursor
 * @return 0 or 1 if the cursor has a next node, -1 otherwise on error
 */
int skip_list_cursor_has_next(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_has_prev
 * check if the cursor has a previous node
 * @param cursor the cursor
 * @return 0 or 1 if the cursor has a previous node, -1 otherwise on error
 */
int skip_list_cursor_has_prev(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_goto_last
 * move the cursor to the last node in the skip list
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_goto_last(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_goto_first
 * move the cursor to the first node in the skip list
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_goto_first(skip_list_cursor_t *cursor);

#endif /* __SKIP_LIST_H__ */