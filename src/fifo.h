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

/**
 * fifo_entry_t
 * a single entry in the fifo cache
 * @param key the key string (owned by entry)
 * @param key_len the length of the key (pre-computed)
 * @param value the value pointer (not owned, managed by callback)
 * @param user_data optional user data for callback
 * @param evict_cb eviction callback for this entry
 * @param prev previous entry in doubly linked list
 * @param next next entry in doubly linked list
 * @param hash_next next entry in hash table chain
 */
struct fifo_entry_t
{
    char *key;
    size_t key_len;
    void *value;
    void *user_data;
    fifo_evict_callback_t evict_cb;
    fifo_entry_t *prev;
    fifo_entry_t *next;
    fifo_entry_t *hash_next;
};

/**
 * fifo_cache_t
 * thread-safe FIFO cache with lock-free reads and configurable capacity
 * eviction policy is FIFO (oldest inserted entry evicted first)
 * @param capacity maximum number of entries
 * @param size current number of entries
 * @param head newest entry (most recently inserted)
 * @param tail oldest entry (evicted first when cache is full)
 * @param table hash table for O(1) lookups
 * @param table_size hash table size
 * @param lock mutex for write operations (reads are lock-free)
 */
struct fifo_cache_t
{
    size_t capacity;
    size_t size;
    fifo_entry_t *head;
    fifo_entry_t *tail;
    fifo_entry_t **table;
    size_t table_size;
    pthread_mutex_t lock;
};

/**
 * fifo_cache_new
 * creates a new fifo cache with the specified capacity
 * @param capacity maximum number of entries in the cache
 * @return pointer to the new cache, or NULL on failure
 */
fifo_cache_t *fifo_cache_new(size_t capacity);

/**
 * fifo_cache_put
 * inserts or updates an entry in the cache
 * if the cache is full, the oldest entry (FIFO) is evicted
 * @param cache the cache
 * @param key the key string (will be copied)
 * @param value the value pointer (not copied, managed by callback)
 * @param evict_cb optional eviction callback (can be NULL)
 * @param user_data optional user data to pass to the callback (can be NULL)
 * @return 0 on success, -1 on failure
 */
int fifo_cache_put(fifo_cache_t *cache, const char *key, void *value,
                   fifo_evict_callback_t evict_cb, void *user_data);

/**
 * fifo_cache_get
 * retrieves a value from the cache by key (lock-free)
 * @param cache the cache
 * @param key the key
 * @return the value if found, NULL otherwise
 */
void *fifo_cache_get(fifo_cache_t *cache, const char *key);

/**
 * fifo_cache_remove
 * removes an entry from the cache and calls its eviction callback
 * @param cache the fifo cache
 * @param key the key string
 * @return 0 on success, -1 if not found
 */
int fifo_cache_remove(fifo_cache_t *cache, const char *key);

/**
 * fifo_cache_clear
 * removes all entries from the cache, calling eviction callbacks
 * @param cache the fifo cache
 */
void fifo_cache_clear(fifo_cache_t *cache);

/**
 * fifo_cache_free
 * frees the cache and all its entries (calls eviction callbacks)
 * @param cache the fifo cache
 */
void fifo_cache_free(fifo_cache_t *cache);

/**
 * fifo_cache_destroy
 * frees the cache without calling eviction callbacks
 * use this when you want to clean up the cache but handle the values separately
 * @param cache the fifo cache
 */
void fifo_cache_destroy(fifo_cache_t *cache);

/**
 * fifo_cache_size
 * returns the current number of entries in the cache
 * @param cache the fifo cache
 * @return the number of entries
 */
size_t fifo_cache_size(fifo_cache_t *cache);

/**
 * fifo_cache_capacity
 * returns the maximum capacity of the cache
 * @param cache the fifo cache
 * @return the capacity
 */
size_t fifo_cache_capacity(fifo_cache_t *cache);

/**
 * fifo_foreach_callback_t
 * callback function for iterating over cache entries
 * @param key the key of the entry
 * @param value the value of the entry
 * @param user_data optional user data passed to fifo_cache_foreach
 * @return 0 to continue iteration, non-zero to stop
 */
typedef int (*fifo_foreach_callback_t)(const char *key, void *value, void *user_data);

/**
 * fifo_cache_foreach
 * iterates over all entries in the cache (from most to least recently used)
 * @param cache the fifo cache
 * @param callback callback function to call for each entry
 * @param user_data optional user data to pass to the callback
 * @return number of entries visited
 */
size_t fifo_cache_foreach(fifo_cache_t *cache, fifo_foreach_callback_t callback, void *user_data);

#endif /* __FIFO_H__ */
