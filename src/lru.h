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
#ifndef __LRU_H__
#define __LRU_H__

#include "compat.h"

/* forward declarations */
typedef struct lru_cache_t lru_cache_t;
typedef struct lru_entry_t lru_entry_t;
typedef struct lru_hazard_pointer_t lru_hazard_pointer_t;
typedef struct lru_retired_entry_t lru_retired_entry_t;

/**
 * lru_evict_callback_t
 * callback function called when an entry is evicted from the cache
 * @param key the key of the evicted entry
 * @param value the value of the evicted entry
 * @param user_data optional user data passed during entry insertion
 */
typedef void (*lru_evict_callback_t)(const char *key, void *value, void *user_data);

/**
 * entry states for lock-free ops
 */
typedef enum
{
    LRU_ENTRY_ACTIVE = 0,   /* entry is active and valid */
    LRU_ENTRY_DELETED = 1,  /* entry marked for deletion */
    LRU_ENTRY_UPDATING = 2, /* entry is being updated */
} lru_entry_state_t;

/**
 * lru_entry_t
 * a single entry in the lru cache
 * uses atomic operations for lock-free access
 * @param key the key string (immutable after creation)
 * @param key_len the length of the key (pre-computed)
 * @param value atomic pointer to the value
 * @param user_data optional user data for callback
 * @param evict_cb eviction callback for this entry
 * @param access_count atomic counter for LRU approximation (clock algorithm)
 * @param state atomic state for lock-free deletion
 * @param ref_count atomic reference count for safe memory reclamation
 * @param hash_next atomic pointer to next entry in hash chain
 * @param retired flag indicating if entry is retired (waiting to be freed)
 */
struct lru_entry_t
{
    char *key;
    size_t key_len;
    _Atomic(void *) value;
    void *user_data;
    lru_evict_callback_t evict_cb;
    _Atomic(uint64_t) access_count;
    _Atomic(lru_entry_state_t) state;
    _Atomic(uint32_t) ref_count;
    _Atomic(lru_entry_t *) hash_next;
    _Atomic(int) retired;
};

/**
 * lru_hazard_pointer_t
 * per-thread hazard pointer record
 * each thread gets K hazard pointers to protect entries it's accessing
 */
#define LRU_HAZARDS_PER_THREAD 2
struct lru_hazard_pointer_t
{
    _Atomic(lru_entry_t *) pointers[LRU_HAZARDS_PER_THREAD];
    _Atomic(int) active; /* 1 if this record is in use by a thread */
    _Atomic(lru_hazard_pointer_t *) next;
};

/**
 * lru_retired_entry_t
 * list node for retired entries waiting to be freed
 */
struct lru_retired_entry_t
{
    lru_entry_t *entry;
    lru_retired_entry_t *next;
};

/**
 * lru_cache_t
 * lock-free LRU cache using clock algorithm for eviction
 * @param capacity maximum number of entries
 * @param size atomic current number of entries
 * @param table hash table with atomic bucket heads
 * @param table_size hash table size
 * @param clock_hand atomic index for clock algorithm sweep
 * @param entries array of entry pointers for clock algorithm
 * @param global_clock atomic global access counter
 * @param hazard_pointers atomic linked list of hazard pointer records
 * @param retired_list per-cache retired entries list (protected by simple lock for now)
 * @param retired_lock mutex for retired list
 * @param retired_count number of retired entries
 */
struct lru_cache_t
{
    size_t capacity;
    _Atomic(size_t) size;
    _Atomic(lru_entry_t *) *table;
    size_t table_size;
    _Atomic(size_t) clock_hand;
    _Atomic(lru_entry_t *) *entries;
    _Atomic(uint64_t) global_clock;

    /* hazard pointers */
    _Atomic(lru_hazard_pointer_t *) hazard_pointers;
    pthread_mutex_t retired_lock;
    lru_retired_entry_t *retired_list;
    _Atomic(size_t) retired_count;
};

/**
 * lru_cache_new
 * creates a new lock-free lru cache with the specified capacity
 * @param capacity maximum number of entries in the cache
 * @return pointer to the new cache, or NULL on failure
 */
lru_cache_t *lru_cache_new(size_t capacity);

/**
 * lru_cache_put
 * inserts or updates an entry in the cache (lock-free)
 * if the cache is full, the least recently used entry is evicted
 * @param cache the cache
 * @param key the key string (will be copied)
 * @param value the value pointer (not copied, managed by callback)
 * @param evict_cb optional eviction callback (can be NULL)
 * @param user_data optional user data to pass to the callback (can be NULL)
 * @return 0 on new insertion, 1 on update of existing entry, -1 on failure
 */
int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data);

/**
 * lru_cache_get
 * retrieves a value from the cache (lock-free)
 * updates access count for LRU tracking
 * @param cache the cache
 * @param key the key string
 * @return the value, or NULL if not found
 */
void *lru_cache_get(lru_cache_t *cache, const char *key);

/**
 * lru_cache_get_copy
 * retrieves and copies a value from the cache atomically
 * the copy_fn is called with reference held
 * @param cache the cache
 * @param key the key string
 * @param copy_fn function to copy the value, returns the copy or NULL
 * @return the copied value, or NULL if not found or copy failed
 */
void *lru_cache_get_copy(lru_cache_t *cache, const char *key, void *(*copy_fn)(void *));

/**
 * lru_cache_remove
 * removes an entry from the cache and calls its eviction callback
 * @param cache the lru cache
 * @param key the key string
 * @return 0 on success, -1 if not found
 */
int lru_cache_remove(lru_cache_t *cache, const char *key);

/**
 * lru_cache_clear
 * removes all entries from the cache, calling eviction callbacks
 * not lock-free, should only be called when no other threads are accessing
 * @param cache the lru cache
 */
void lru_cache_clear(lru_cache_t *cache);

/**
 * lru_cache_free
 * frees the cache and all its entries (calls eviction callbacks)
 * not lock-free, should only be called when no other threads are accessing
 * @param cache the lru cache
 */
void lru_cache_free(lru_cache_t *cache);

/**
 * lru_cache_destroy
 * frees the cache without calling eviction callbacks
 * use this when you want to clean up the cache but handle the values separately
 * not lock-free, should only be called when no other threads are accessing
 * @param cache the lru cache
 */
void lru_cache_destroy(lru_cache_t *cache);

/**
 * lru_cache_size
 * returns the current number of entries in the cache (atomic read)
 * @param cache the lru cache
 * @return the number of entries
 */
size_t lru_cache_size(lru_cache_t *cache);

/**
 * lru_cache_capacity
 * returns the maximum capacity of the cache
 * @param cache the lru cache
 * @return the capacity
 */
size_t lru_cache_capacity(lru_cache_t *cache);

/**
 * lru_foreach_callback_t
 * callback function for iterating over cache entries
 * @param key the key of the entry
 * @param value the value of the entry
 * @param user_data optional user data passed to lru_cache_foreach
 * @return 0 to continue iteration, non-zero to stop
 */
typedef int (*lru_foreach_callback_t)(const char *key, void *value, void *user_data);

/**
 * lru_cache_foreach
 * iterates over all entries in the cache
 * provides snapshot semantics, entries may change during iteration
 * @param cache the lru cache
 * @param callback callback function to call for each entry
 * @param user_data optional user data to pass to the callback
 * @return number of entries visited
 */
size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data);

#endif /* __LRU_H__ */