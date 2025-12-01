/**
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
#ifndef __FIFO_H__
#define __FIFO_H__

#include "compat.h"

/* forward declarations */
typedef struct fifo_cache_t fifo_cache_t;
typedef struct fifo_entry_t fifo_entry_t;

/**
 * fifo_evict_callback_t
 * callback function called when an entry is evicted from the cache
 * @param key the key of the evicted entry
 * @param value the value of the evicted entry
 * @param user_data optional user data passed during entry insertion
 */
typedef void (*fifo_evict_callback_t)(const char *key, void *value, void *user_data);

/* entry states for lifecycle management */
typedef enum
{
    ENTRY_STATE_EMPTY = 0, /* slot is empty/available */
    ENTRY_STATE_INSERTING, /* entry is being inserted */
    ENTRY_STATE_ACTIVE,    /* entry is active and valid */
    ENTRY_STATE_UPDATING,  /* entry value is being updated */
    ENTRY_STATE_EVICTING,  /* entry is being evicted */
    ENTRY_STATE_DELETED    /* entry has been logically deleted */
} fifo_entry_state_t;

/* tagged pointer for aba prevention in hash chains */
typedef struct
{
    uintptr_t value;
} fifo_tagged_ptr_t;

/* tagged pointer bit allocation */
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
#define FIFO_TAG_BITS 16
#define FIFO_MARK_BIT ((uintptr_t)1ULL << 47) /* logical deletion mark */
#define FIFO_TAG_MASK ((uintptr_t)0xFFFF000000000000ULL)
#define FIFO_PTR_MASK ((uintptr_t)0x00007FFFFFFFFFFFULL)
#else
#define FIFO_TAG_BITS 8
#define FIFO_MARK_BIT ((uintptr_t)1UL << 23)
#define FIFO_TAG_MASK ((uintptr_t)0xFF000000UL)
#define FIFO_PTR_MASK ((uintptr_t)0x007FFFFFUL)
#endif

/* retired node for reclamation stack */
typedef struct fifo_retired_node_t
{
    fifo_entry_t *entry;
    _Atomic(struct fifo_retired_node_t *) next;
} fifo_retired_node_t;

/**
 * fifo_entry_t
 * a single entry in the fifo cache
 * @param state atomic state for lifecycle management
 * @param key the key string (immutable after insertion)
 * @param key_len length of key (immutable after insertion)
 * @param key_hash cached hash value (immutable after insertion)
 * @param value atomic pointer to value
 * @param user_data user data for callback
 * @param evict_cb eviction callback
 * @param hash_next tagged pointer to next entry in hash chain
 */
struct fifo_entry_t
{
    _Atomic(int) state;
    char *key;
    size_t key_len;
    uint64_t key_hash;
    _Atomic(void *) value;
    void *user_data;
    fifo_evict_callback_t evict_cb;
    _Atomic(fifo_tagged_ptr_t) hash_next;
};

/**
 * fifo_order_node_t
 * fifo order node for eviction queue
 * @param entry
 * @param next
 */
typedef struct fifo_order_node_t
{
    fifo_entry_t *entry;
    _Atomic(struct fifo_order_node_t *) next;
} fifo_order_node_t;

/**
 * fifo_cache_t
 * fifo cache structure
 * @param capacity maximum number of entries
 * @param size current number of active entries (atomic)
 * @param table hash table buckets (array of atomic tagged pointers)
 * @param table_size number of hash buckets
 * @param evict_head head of fifo eviction queue (oldest)
 * @param evict_tail tail of fifo eviction queue (newest)
 * @param retired_head stack head for deferred reclamation
 * @param retired_count approximate count for batch reclamation trigger
 */
struct fifo_cache_t
{
    size_t capacity;
    _Atomic(size_t) size;
    _Atomic(fifo_tagged_ptr_t) *table;
    size_t table_size;
    _Atomic(fifo_order_node_t *) evict_head;
    _Atomic(fifo_order_node_t *) evict_tail;
    _Atomic(fifo_retired_node_t *) retired_head;
    _Atomic(size_t) retired_count;
};

/**
 * fifo_cache_new
 * creates a new fifo cache
 * @param capacity maximum number of entries
 * @return pointer to new cache, or NULL on failure
 */
fifo_cache_t *fifo_cache_new(size_t capacity);

/**
 * fifo_cache_put
 * inserts or updates an entry
 * if cache is full, evicts oldest entry first
 * @param cache the cache
 * @param key the key string (will be copied)
 * @param value the value pointer
 * @param evict_cb optional eviction callback
 * @param user_data optional user data for callback
 * @return 0 on success, -1 on failure
 */
int fifo_cache_put(fifo_cache_t *cache, const char *key, void *value,
                   fifo_evict_callback_t evict_cb, void *user_data);

/**
 * fifo_cache_get
 * retrieves a value from the cache
 * @param cache the cache
 * @param key the key
 * @return the value if found and active, NULL otherwise
 */
void *fifo_cache_get(fifo_cache_t *cache, const char *key);

/**
 * fifo_cache_remove
 * removes an entry from the cache
 * @param cache the cache
 * @param key the key
 * @return 0 on success, -1 if not found
 */
int fifo_cache_remove(fifo_cache_t *cache, const char *key);

/**
 * fifo_cache_clear
 * removes all entries from the cache
 * @param cache the cache
 */
void fifo_cache_clear(fifo_cache_t *cache);

/**
 * fifo_cache_free
 * frees the cache and all entries (calls eviction callbacks)
 * @param cache the cache
 */
void fifo_cache_free(fifo_cache_t *cache);

/**
 * fifo_cache_destroy
 * frees the cache without calling eviction callbacks
 * @param cache the cache
 */
void fifo_cache_destroy(fifo_cache_t *cache);

/**
 * fifo_cache_size
 * returns approximate current size
 * @param cache the cache
 * @return number of entries
 */
size_t fifo_cache_size(fifo_cache_t *cache);

/**
 * fifo_cache_capacity
 * returns the maximum capacity
 * @param cache the cache
 * @return capacity
 */
size_t fifo_cache_capacity(fifo_cache_t *cache);

/**
 * fifo_foreach_callback_t
 * callback for iterating over entries
 * @param key the key
 * @param value the value
 * @param user_data user-provided context
 * @return 0 to continue, non-zero to stop
 */
typedef int (*fifo_foreach_callback_t)(const char *key, void *value, void *user_data);

/**
 * fifo_cache_foreach
 * iterates over all active entries
 * @param cache the cache
 * @param callback callback function
 * @param user_data user context
 * @return number of entries visited
 */
size_t fifo_cache_foreach(fifo_cache_t *cache, fifo_foreach_callback_t callback, void *user_data);

#endif /* __FIFO_H__ */