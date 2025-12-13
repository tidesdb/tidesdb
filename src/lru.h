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

/* * https://dl.acm.org/doi/pdf/10.1145/3732365.3732389 */

typedef struct lru_cache_t lru_cache_t;

/**
 * lru_evict_callback_t
 * callback function called when an entry is evicted from the cache
 * @param key the key of the evicted entry
 * @param value the value pointer (caller manages lifetime)
 * @param user_data optional user data passed during insertion
 */
typedef void (*lru_evict_callback_t)(const char *key, void *value, void *user_data);

/**
 * lru_cache_new
 * creates a new hybrid LRU/LFU cache with temperature-based promotion
 * @param lru_capacity capacity of the LRU (hot) cache
 * @param lfu_capacity capacity of the LFU (warm) cache
 * @param promotion_threshold access count threshold to promote from LRU to LFU
 * @param ttl_seconds time-to-live for LFU entries (0 = no expiration)
 * @return pointer to cache, or NULL on failure
 */
lru_cache_t *lru_cache_new(size_t lru_capacity, size_t lfu_capacity, uint32_t promotion_threshold,
                           uint32_t ttl_seconds);

/**
 * lru_cache_put
 * inserts or updates an entry in the cache
 * @param cache the cache
 * @param key the key string (will be copied)
 * @param value the value pointer (not copied, managed by callback)
 * @param evict_cb optional eviction callback (can be NULL)
 * @param user_data optional user data for callback
 * @return 0 on new insertion, 1 on update of existing entry, -1 on failure
 */
int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data);

/**
 * lru_cache_get
 * retrieves a value from the cache and updates access statistics
 * @param cache the cache
 * @param key the key string
 * @return the value, or NULL if not found
 */
void *lru_cache_get(lru_cache_t *cache, const char *key);

/**
 * lru_cache_get_n
 * retrieves a value from the cache with pre-computed key length (avoids strlen)
 * @param cache the cache
 * @param key the key string
 * @param key_len pre-computed length of key
 * @return the value, or NULL if not found
 */
void *lru_cache_get_n(lru_cache_t *cache, const char *key, size_t key_len);

/**
 * lru_cache_get_copy
 * retrieves and copies a value atomically (e.g., for acquiring references)
 * @param cache the cache
 * @param key the key string
 * @param copy_fn function to copy/acquire the value
 * @return the copied value, or NULL if not found or copy failed
 */
void *lru_cache_get_copy(lru_cache_t *cache, const char *key, void *(*copy_fn)(void *));

/**
 * lru_cache_get_copy_n
 * retrieves and copies a value with pre-computed key length (avoids strlen)
 * @param cache the cache
 * @param key the key string
 * @param key_len pre-computed length of key
 * @param copy_fn function to copy/acquire the value
 * @return the copied value, or NULL if not found or copy failed
 */
void *lru_cache_get_copy_n(lru_cache_t *cache, const char *key, size_t key_len,
                           void *(*copy_fn)(void *));

/**
 * lru_cache_remove
 * removes an entry from the cache
 * @param cache the cache
 * @param key the key string
 * @return 0 on success, -1 if not found
 */
int lru_cache_remove(lru_cache_t *cache, const char *key);

/**
 * lru_cache_clear
 * removes all entries from the cache
 * @param cache the cache
 */
void lru_cache_clear(lru_cache_t *cache);

/**
 * lru_cache_free
 * frees the cache and all entries (calls eviction callbacks)
 * @param cache the cache
 */
void lru_cache_free(lru_cache_t *cache);

/**
 * lru_cache_destroy
 * frees the cache without calling eviction callbacks
 * @param cache the cache
 */
void lru_cache_destroy(lru_cache_t *cache);

/**
 * lru_cache_size
 * returns the total number of entries in the cache
 * @param cache the cache
 * @return number of entries
 */
size_t lru_cache_size(lru_cache_t *cache);

/**
 * lru_cache_capacity
 * returns the total capacity of the cache
 * @param cache the cache
 * @return total capacity (LRU + LFU)
 */
size_t lru_cache_capacity(lru_cache_t *cache);

/**
 * lru_cache_stats
 * retrieves cache statistics
 * @param cache the cache
 * @param lru_size output: number of entries in LRU cache
 * @param lfu_size output: number of entries in LFU cache
 * @param hits output: total cache hits
 * @param misses output: total cache misses
 */
void lru_cache_stats(lru_cache_t *cache, size_t *lru_size, size_t *lfu_size, uint64_t *hits,
                     uint64_t *misses);

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
 * iterates over all entries in the cache (LRU then LFU)
 * @param cache the cache
 * @param callback callback function to call for each entry
 * @param user_data optional user data to pass to the callback
 * @return number of entries visited
 */
size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data);

#endif /* __LRU_H__ */