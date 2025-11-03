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
#ifndef LRU_H
#define LRU_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/* forward declarations */
typedef struct lru_cache_t lru_cache_t;
typedef struct lru_entry_t lru_entry_t;

/*
 * lru_evict_callback_t
 * callback function called when an entry is evicted from the cache
 * @param key the key of the evicted entry
 * @param value the value of the evicted entry
 * @param user_data optional user data passed during entry insertion
 */
typedef void (*lru_evict_callback_t)(const char *key, void *value, void *user_data);

/*
 * lru_entry_t
 * represents a single entry in the LRU cache
 */
struct lru_entry_t
{
    char *key;                     /* key string (owned by entry) */
    void *value;                   /* value pointer (not owned, managed by callback) */
    void *user_data;               /* optional user data for callback */
    lru_evict_callback_t evict_cb; /* eviction callback for this entry */
    lru_entry_t *prev;             /* previous entry in doubly linked list */
    lru_entry_t *next;             /* next entry in doubly linked list */
    lru_entry_t *hash_next;        /* next entry in hash table chain */
};

/*
 * lru_cache_t
 * thread-safe LRU cache with configurable capacity
 */
struct lru_cache_t
{
    size_t capacity;      /* maximum number of entries */
    size_t size;          /* current number of entries */
    lru_entry_t *head;    /* most recently used entry */
    lru_entry_t *tail;    /* least recently used entry */
    lru_entry_t **table;  /* hash table for O(1) lookups */
    size_t table_size;    /* hash table size */
    pthread_mutex_t lock; /* mutex for thread safety */
};

/*
 * lru_cache_new
 * creates a new LRU cache with the specified capacity
 * @param capacity maximum number of entries in the cache
 * @return pointer to the new cache, or NULL on failure
 */
lru_cache_t *lru_cache_new(size_t capacity);

/*
 * lru_cache_put
 * inserts or updates an entry in the cache
 * if the cache is full, the least recently used entry is evicted
 * @param cache the LRU cache
 * @param key the key string (will be copied)
 * @param value the value pointer (not copied, managed by callback)
 * @param evict_cb callback to call when this entry is evicted (can be NULL)
 * @param user_data optional user data to pass to the callback (can be NULL)
 * @return 0 on success, -1 on failure
 */
int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data);

/*
 * lru_cache_get
 * retrieves a value from the cache and marks it as recently used
 * @param cache the LRU cache
 * @param key the key string
 * @return the value pointer, or NULL if not found
 */
void *lru_cache_get(lru_cache_t *cache, const char *key);

/*
 * lru_cache_remove
 * removes an entry from the cache and calls its eviction callback
 * @param cache the LRU cache
 * @param key the key string
 * @return 0 on success, -1 if not found
 */
int lru_cache_remove(lru_cache_t *cache, const char *key);

/*
 * lru_cache_clear
 * removes all entries from the cache, calling eviction callbacks
 * @param cache the LRU cache
 */
void lru_cache_clear(lru_cache_t *cache);

/*
 * lru_cache_free
 * frees the cache and all its entries (calls eviction callbacks)
 * @param cache the LRU cache
 */
void lru_cache_free(lru_cache_t *cache);

/*
 * lru_cache_destroy
 * frees the cache without calling eviction callbacks
 * use this when you want to clean up the cache but handle the values separately
 * @param cache the LRU cache
 */
void lru_cache_destroy(lru_cache_t *cache);

/*
 * lru_cache_size
 * returns the current number of entries in the cache
 * @param cache the LRU cache
 * @return the number of entries
 */
size_t lru_cache_size(lru_cache_t *cache);

/*
 * lru_cache_capacity
 * returns the maximum capacity of the cache
 * @param cache the LRU cache
 * @return the capacity
 */
size_t lru_cache_capacity(lru_cache_t *cache);

/*
 * lru_foreach_callback_t
 * callback function for iterating over cache entries
 * @param key the key of the entry
 * @param value the value of the entry
 * @param user_data optional user data passed to lru_cache_foreach
 * @return 0 to continue iteration, non-zero to stop
 */
typedef int (*lru_foreach_callback_t)(const char *key, void *value, void *user_data);

/*
 * lru_cache_foreach
 * iterates over all entries in the cache (from most to least recently used)
 * @param cache the LRU cache
 * @param callback callback function to call for each entry
 * @param user_data optional user data to pass to the callback
 * @return number of entries visited
 */
size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data);

#endif /* LRU_H */
