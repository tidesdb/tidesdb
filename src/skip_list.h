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
#include "compat.h"

/* forward declarations */
typedef struct skip_list_node_t skip_list_node_t;
typedef struct skip_list_t skip_list_t;
typedef struct skip_list_arena_t skip_list_arena_t;

/* inline threshold -- keys/values smaller than this are stored inline */
#define SKIP_LIST_INLINE_THRESHOLD 24

/* comparator function type for custom key comparison
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @param ctx optional context pointer for the comparator
 * @return 0 if keys are equal, negative if key1 < key2, positive if key1 > key2
 */
typedef int (*skip_list_comparator_fn)(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                       size_t key2_size, void *ctx);

/*
 * skip_list_arena_t
 * memory pool for efficient node allocation
 * reduces malloc overhead and improves cache locality
 * @param buffer the memory buffer
 * @param capacity total capacity of the buffer
 * @param offset current allocation offset (atomic for thread-safety)
 * @param next pointer to next arena in chain
 */
struct skip_list_arena_t
{
    uint8_t *buffer;
    size_t capacity;
    _Atomic(size_t) offset;
    skip_list_arena_t *next;
};

/* macro to access backward pointers at a specific level */
#define BACKWARD_PTR(node, lvl, max_level) (node->forward[(node)->level + (lvl)])

/*
 * skip_list_node_t
 * immutable node structure; once created, contents never change
 * nodes are reference counted for safe memory reclamation
 * optimized with inline storage for small keys/values
 * @param key_size the key size
 * @param value_size the value size
 * @param ttl an expiration time for the node (-1 if no expiration)
 * @param deleted flag indicating if the node is deleted (1 = deleted, 0 = valid)
 * @param key_is_inline flag indicating if key is stored inline (1) or as pointer (0)
 * @param value_is_inline flag indicating if value is stored inline (1) or as pointer (0)
 * @param arena_allocated flag indicating if node was allocated from arena (1) or malloc (0)
 * @param level actual level of this node (for backward pointer calculation)
 * @param ref_count reference count for safe memory reclamation
 * @param key_data union for inline or pointer storage of key
 * @param value_data union for inline or pointer storage of value
 * @param forward the forward pointers for the node (atomic for COW updates)
 */
struct skip_list_node_t
{
    size_t key_size;
    size_t value_size;
    time_t ttl;
    uint8_t deleted;
    uint8_t key_is_inline;
    uint8_t value_is_inline;
    uint8_t arena_allocated; /* 1 if allocated from arena, 0 if from malloc */
    int level;               /* actual level of this node (for backward pointer calculation) */
    ATOMIC_ALIGN(8) _Atomic(uint64_t) ref_count;
    union
    {
        uint8_t *key_ptr;
        uint8_t key_inline[SKIP_LIST_INLINE_THRESHOLD];
    } key_data;
    union
    {
        uint8_t *value_ptr;
        uint8_t value_inline[SKIP_LIST_INLINE_THRESHOLD];
    } value_data;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200)
#endif
    _Atomic(skip_list_node_t *) forward[];
#ifdef _MSC_VER
#pragma warning(pop)
#endif
};

/*
 * skip_list_t
 * the skip list structure using copy-on-write for lock-free reads
 * @param level the current level of the skip list
 * @param max_level the maximum level of the skip list
 * @param probability the probability of a node having a certain level
 * @param header the header node of the skip list (atomic pointer)
 * @param tail the tail node of the skip list (atomic pointer)
 * @param total_size the total size in bytes of kv pairs in the skip list
 * @param global_epoch current epoch for RCU memory reclamation
 * @param retired_head list of retired nodes awaiting reclamation
 * @param retired_lock mutex protecting retired nodes list
 * @param comparator custom key comparator function
 * @param comparator_ctx context pointer passed to comparator function
 * @param arena memory pool for efficient node allocation
 */
/* retired node for epoch-based RCU */
typedef struct retired_node_t
{
    skip_list_node_t *node;
    uint64_t retire_epoch;
    struct retired_node_t *next;
} retired_node_t;

typedef struct skip_list_t
{
    _Atomic(int) level;
    int max_level;
    float probability;
    _Atomic(skip_list_node_t *) header;
    _Atomic(skip_list_node_t *) tail;
    _Atomic(size_t) total_size;
    skip_list_comparator_fn comparator;
    void *comparator_ctx;
    skip_list_arena_t *arena;

    /* epoch-based RCU for safe memory reclamation */
    /* uses time-based grace period: nodes retired at epoch N are freed at epoch N+10 */
    _Atomic(uint64_t) global_epoch; /* current epoch */
    retired_node_t *retired_head;   /* list of retired nodes */
    pthread_mutex_t retired_lock;   /* protects retired list */
} skip_list_t;

/*
 * skip_list_cursor_t
 * the cursor structure for the skip list
 * cursors hold references to nodes to prevent premature deallocation
 * @param list the skip list
 * @param current the current node (with reference held)
 */
typedef struct
{
    skip_list_t *list;
    skip_list_node_t *current;
} skip_list_cursor_t;

/*** default comparator functions * * */

/**
 * skip_list_comparator_memcmp
 * default binary comparison using memcmp
 * shorter keys are considered less than longer keys
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @param ctx unused context
 * @return 0 if keys are equal, -1 if key1 < key2, 1 if key1 > key2
 */
int skip_list_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx);

/**
 * skip_list_comparator_string
 * lexicographic string comparison (keys are null-terminated C strings)
 * @param key1 the first key (null-terminated string)
 * @param key1_size the first key size (ignored, uses strlen)
 * @param key2 the second key (null-terminated string)
 * @param key2_size the second key size (ignored, uses strlen)
 * @param ctx unused context
 * @return 0 if strings are equal, -1 if key1 < key2, 1 if key1 > key2
 */
int skip_list_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx);

/**
 * skip_list_comparator_numeric
 * numeric comparison for keys containing 64-bit integers
 * interprets keys as little-endian uint64_t
 * @param key1 pointer to first uint64_t
 * @param key1_size size of first key (should be sizeof(uint64_t))
 * @param key2 pointer to second uint64_t
 * @param key2_size size of second key (should be sizeof(uint64_t))
 * @param ctx unused context
 * @return 0 if values are equal, -1 if key1 < key2, 1 if key1 > key2
 */
int skip_list_comparator_numeric(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                 size_t key2_size, void *ctx);

/*** skip list function prototypes */

/*
 * skip_list_create_node
 * create a new skip list node (immutable after creation)
 * @param level the level of the node
 * @param key the key for the node
 * @param key_size the key size
 * @param value the value for the node
 * @param value_size the value size
 * @param ttl an expiration time for the node (optional)
 * @param deleted whether this node represents a deletion
 * @return the new skip list node
 */
skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl,
                                        uint8_t deleted);

/*
 * skip_list_retain_node
 * increment reference count on a node
 * @param node the node to retain
 */
void skip_list_retain_node(skip_list_node_t *node);

/*
 * skip_list_release_node
 * decrement reference count and free if zero
 * @param node the node to release
 */
void skip_list_release_node(skip_list_node_t *node);

/*
 * skip_list_free_node
 * free's a skip list node (internal use only)
 * @param node the node to free
 * @return 0 if the node was freed successfully, -1 otherwise
 */
int skip_list_free_node(skip_list_node_t *node);

/*
 * skip_list_new
 * create a new skip list with default memcmp comparator
 * @param list the skip list to create
 * @param max_level the maximum level of the skip list
 * @param probability the probability of a node having a certain level
 * @return 0 if successful, -1 if not
 */
int skip_list_new(skip_list_t **list, int max_level, float probability);

/*
 * skip_list_new_with_comparator
 * create a new skip list with a custom comparator
 * @param list the skip list to create
 * @param max_level the maximum level of the skip list
 * @param probability the probability of a node having a certain level
 * @param comparator custom key comparison function
 * @param comparator_ctx optional context pointer passed to comparator
 * @return 0 if successful, -1 if not
 */
int skip_list_new_with_comparator(skip_list_t **list, int max_level, float probability,
                                  skip_list_comparator_fn comparator, void *comparator_ctx);

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
 * compares two keys using the skip list's comparator
 * @param list the skip list
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @return 0 if the keys are equal, negative if key1 < key2, positive if key1 > key2
 */
int skip_list_compare_keys(skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size);

/*
 * skip_list_put
 * put a new key-value pair into the skip list
 * uses copy-on-write: creates new node, readers never blocked
 * exclusive write operation (only blocks other writers)
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
 * skip_list_delete
 * mark a key as deleted in the skip list
 * uses copy-on-write: creates tombstone node, readers never blocked
 * exclusive write operation (only blocks other writers)
 * @param list the skip list
 * @param key the key to delete
 * @param key_size the key size
 * @return 0 if the key was marked as deleted successfully, -1 if key not found or on error
 */
int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size);

/*
 * skip_list_get
 * get a value from the skip list
 * lock-free read operation, never blocks or is blocked by writers
 * @param list the skip list
 * @param key the key to get
 * @param key_size the key size
 * @param value the value
 * @param value_size the value size
 * @param deleted whether the key has been deleted
 * @return 0 if the value was retrieved successfully, -1 otherwise on error
 */
int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted);

/*
 * skip_list_cursor_init
 * initialize a new skip list cursor
 * creates a snapshot of the list at current version
 * lock-free operation
 * @param list the skip list
 * @return the new skip list cursor
 */
skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list);

/*
 * skip_list_cursor_next
 * move the cursor to the next node
 * lock-free operation, never blocked by writers
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_next(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_prev
 * move the cursor to the previous node
 * lock-free operation, never blocked by writers
 * @param cursor the cursor
 * @return 0 if the cursor was moved successfully, -1 otherwise on error
 */
int skip_list_cursor_prev(skip_list_cursor_t *cursor);

/*
 * skip_list_cursor_get
 * get the key and value from the cursor
 * lock-free operation
 * @param cursor the cursor
 * @param key the key
 * @param key_size the key size
 * @param value the value
 * @param value_size the value size
 * @param ttl the expiration time of the node
 * @return 0 if the key and value were retrieved successfully, -1 otherwise on error
 */
int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, time_t *ttl, uint8_t *deleted);

/*
 * skip_list_cursor_free
 * free the memory for the cursor
 * @param cursor the cursor
 */
void skip_list_cursor_free(skip_list_cursor_t *cursor);

/*
 * skip_list_clear
 * clear the skip list
 * exclusive write operation (only blocks other writers)
 * @param list the skip list
 * @return 0 if the skip list was cleared successfully, -1 otherwise on error
 */
int skip_list_clear(skip_list_t *list);

/*
 * skip_list_copy
 * copy the skip list
 * lock-free read while creating new list
 * @param list the skip list
 * @return the copied skip list
 */
skip_list_t *skip_list_copy(skip_list_t *list);

/*
 * skip_list_check_and_update_ttl
 * checks if a node has expired
 * in copy-on-write model, expired nodes are treated as deleted during traversal
 * @param list the skip list
 * @param node the node to check
 * @return 0 if the node has not expired, 1 if the node has expired
 */
int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node);

/*
 * skip_list_get_size
 * get the size of the skip list
 * lock-free read using atomic
 * @param list the skip list
 * @return the size of the skip list
 */
int skip_list_get_size(skip_list_t *list);

/*
 * skip_list_count_entries
 * count the number of entries/nodes in the skip list
 * lock-free read operation
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

/**
 * skip_list_get_min_key
 * lock-free read operation
 * @param list the skip list
 * @param key pointer to store the key (will be allocated)
 * @param key_size pointer to store the key size
 * @return 0 on success, -1 on failure
 */
int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size);

/**
 * skip_list_get_max_key
 * lock-free read operation
 * @param list the skip list
 * @param key pointer to store the key (will be allocated)
 * @param key_size pointer to store the key size
 * @return 0 on success, -1 on failure
 */
int skip_list_get_max_key(skip_list_t *list, uint8_t **key, size_t *key_size);

/*
 * skip_list_cursor_init_at_end
 * initialize an existing cursor and position it at the end of the skip list
 * creates a snapshot of the list at current version
 * @param cursor pointer to an existing cursor to initialize
 * @param list the skip list
 * @return 0 if the cursor was initialized successfully, -1 otherwise on error
 */
int skip_list_cursor_init_at_end(skip_list_cursor_t **cursor, skip_list_t *list);

/*
 * skip_list_cursor_seek
 * positions cursor at the first node with key >= target key
 * lock-free operation, never blocked by writers
 * @param cursor the cursor to position
 * @param key the target key to seek to
 * @param key_size the size of the target key
 * @return 0 if positioned successfully, -1 if key not found or cursor at end
 */
int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size);

/*
 * skip_list_cursor_seek_for_prev
 * positions cursor at the first node with key <= target key
 * lock-free operation, never blocked by writers
 * @param cursor the cursor to position
 * @param key the target key to seek to
 * @param key_size the size of the target key
 * @return 0 if positioned successfully, -1 if key not found or cursor at start
 */
int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size);

#endif /* __SKIP_LIST_H__ */