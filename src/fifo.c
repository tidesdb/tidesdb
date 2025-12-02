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
#include "fifo.h"

#include "xxhash.h"

/**
 * fifo_hash
 * hash function for string keys using xxhash
 * @param key the key to hash
 * @param key_len the length of the key
 * @param bucket_count the number of buckets
 * @return the bucket index
 */
static inline size_t fifo_hash(const char *key, size_t key_len, size_t bucket_count)
{
    XXH64_hash_t hash = XXH64(key, key_len, 0);
    return (size_t)(hash % bucket_count);
}

/**
 * fifo_alloc_entry
 * allocates and initializes a new cache entry
 * @param key the key string (will be copied)
 * @param key_len the length of the key
 * @param value the value pointer
 * @param evict_cb the eviction callback
 * @param user_data optional user data
 * @return the allocated entry, or NULL on failure
 */
static fifo_entry_t *fifo_alloc_entry(const char *key, size_t key_len, void *value,
                                      fifo_evict_callback_t evict_cb, void *user_data)
{
    fifo_entry_t *entry = (fifo_entry_t *)malloc(sizeof(fifo_entry_t));
    if (entry == NULL) return NULL;

    entry->key = (char *)malloc(key_len + 1);
    if (entry->key == NULL)
    {
        free(entry);
        return NULL;
    }

    memcpy(entry->key, key, key_len);
    entry->key[key_len] = '\0';
    entry->key_len = key_len;
    entry->value = value;
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    atomic_store_explicit(&entry->state, FIFO_ENTRY_ACTIVE, memory_order_relaxed);
    atomic_store_explicit(&entry->hash_next, NULL, memory_order_relaxed);

    return entry;
}

/**
 * fifo_free_entry
 * frees an entry and optionally calls its eviction callback
 * @param entry the entry to free
 * @param call_callback whether to call the eviction callback
 */
static void fifo_free_entry(fifo_entry_t *entry, int call_callback)
{
    if (entry == NULL) return;

    if (call_callback && entry->evict_cb != NULL)
    {
        entry->evict_cb(entry->key, entry->value, entry->user_data);
    }

    free(entry->key);
    free(entry);
}

/**
 * fifo_find_entry_lockfree
 * finds an entry in the hash table using lock-free traversal
 * Only returns ACTIVE entries
 * @param cache the cache
 * @param key the key to find
 * @param key_len the length of the key
 * @param bucket_idx output parameter for the bucket index
 * @return the entry if found and ACTIVE, NULL otherwise
 */
static fifo_entry_t *fifo_find_entry_lockfree(fifo_cache_t *cache, const char *key, size_t key_len,
                                              size_t *bucket_idx)
{
    size_t idx = fifo_hash(key, key_len, cache->bucket_count);
    if (bucket_idx) *bucket_idx = idx;

    fifo_entry_t *entry = atomic_load_explicit(&cache->buckets[idx].head, memory_order_acquire);

    while (entry != NULL)
    {
        int state = atomic_load_explicit(&entry->state, memory_order_acquire);
        if (state == FIFO_ENTRY_ACTIVE)
        {
            if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0)
            {
                state = atomic_load_explicit(&entry->state, memory_order_acquire);
                if (state == FIFO_ENTRY_ACTIVE)
                {
                    return entry;
                }
            }
        }
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    return NULL;
}

/**
 * fifo_add_to_bucket
 * adds an entry to a hash bucket (caller must hold bucket lock)
 * @param cache the cache
 * @param entry the entry to add
 * @param bucket_idx the bucket index
 */
static void fifo_add_to_bucket(fifo_cache_t *cache, fifo_entry_t *entry, size_t bucket_idx)
{
    fifo_entry_t *old_head =
        atomic_load_explicit(&cache->buckets[bucket_idx].head, memory_order_relaxed);
    atomic_store_explicit(&entry->hash_next, old_head, memory_order_relaxed);
    atomic_store_explicit(&cache->buckets[bucket_idx].head, entry, memory_order_release);
}

/**
 * fifo_remove_from_bucket
 * removes an entry from a hash bucket (caller must hold bucket lock)
 * The entry should already be marked as non-ACTIVE
 * @param cache the cache
 * @param entry the entry to remove
 * @param bucket_idx the bucket index
 * @return 0 on success, -1 if not found
 */
static int fifo_remove_from_bucket(fifo_cache_t *cache, fifo_entry_t *entry, size_t bucket_idx)
{
    fifo_entry_t *current =
        atomic_load_explicit(&cache->buckets[bucket_idx].head, memory_order_relaxed);
    fifo_entry_t *prev = NULL;

    while (current != NULL)
    {
        if (current == entry)
        {
            fifo_entry_t *next = atomic_load_explicit(&current->hash_next, memory_order_relaxed);
            if (prev != NULL)
            {
                atomic_store_explicit(&prev->hash_next, next, memory_order_release);
            }
            else
            {
                atomic_store_explicit(&cache->buckets[bucket_idx].head, next, memory_order_release);
            }
            return 0;
        }
        prev = current;
        current = atomic_load_explicit(&current->hash_next, memory_order_relaxed);
    }

    return -1;
}

/**
 * fifo_mark_entry
 * atomically marks an entry for removal
 * uses CAS to ensure only one thread succeeds in marking
 * @param entry the entry to mark
 * @return 1 if successfully marked, 0 if already marked/removed
 */
static int fifo_mark_entry(fifo_entry_t *entry)
{
    int expected = FIFO_ENTRY_ACTIVE;
    return atomic_compare_exchange_strong_explicit(&entry->state, &expected, FIFO_ENTRY_MARKED,
                                                   memory_order_release, memory_order_relaxed);
}

/**
 * fifo_evict_oldest
 * evicts the oldest entry from the cache using lock-free dequeue
 * @param cache the cache
 * @return 1 if an entry was evicted, 0 if cache was empty
 */
static int fifo_evict_oldest(fifo_cache_t *cache)
{
    while (1)
    {
        fifo_entry_t *entry = (fifo_entry_t *)queue_dequeue(cache->queue);
        if (entry == NULL)
        {
            return 0;
        }

        if (fifo_mark_entry(entry))
        {
            size_t bucket_idx = fifo_hash(entry->key, entry->key_len, cache->bucket_count);

            pthread_mutex_lock(&cache->buckets[bucket_idx].lock);
            fifo_remove_from_bucket(cache, entry, bucket_idx);
            pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);

            atomic_store_explicit(&entry->state, FIFO_ENTRY_REMOVED, memory_order_release);

            atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

            fifo_free_entry(entry, 1);
            return 1;
        }
    }
}

fifo_cache_t *fifo_cache_new(size_t capacity)
{
    if (capacity == 0) return NULL;

    fifo_cache_t *cache = (fifo_cache_t *)malloc(sizeof(fifo_cache_t));
    if (cache == NULL) return NULL;

    cache->capacity = capacity;
    atomic_store_explicit(&cache->size, 0, memory_order_relaxed);

    cache->queue = queue_new();
    if (cache->queue == NULL)
    {
        free(cache);
        return NULL;
    }

    cache->bucket_count = capacity * 2;
    if (cache->bucket_count < 16) cache->bucket_count = 16; /* minimum bucket count */

    cache->buckets = (fifo_bucket_t *)calloc(cache->bucket_count, sizeof(fifo_bucket_t));
    if (cache->buckets == NULL)
    {
        queue_free(cache->queue);
        free(cache);
        return NULL;
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        atomic_store_explicit(&cache->buckets[i].head, NULL, memory_order_relaxed);
        if (pthread_mutex_init(&cache->buckets[i].lock, NULL) != 0)
        {
            for (size_t j = 0; j < i; j++)
            {
                pthread_mutex_destroy(&cache->buckets[j].lock);
            }
            free(cache->buckets);
            queue_free(cache->queue);
            free(cache);
            return NULL;
        }
    }

    return cache;
}

int fifo_cache_put(fifo_cache_t *cache, const char *key, void *value,
                   fifo_evict_callback_t evict_cb, void *user_data)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    size_t bucket_idx = fifo_hash(key, key_len, cache->bucket_count);

    pthread_mutex_lock(&cache->buckets[bucket_idx].lock);

    fifo_entry_t *existing =
        atomic_load_explicit(&cache->buckets[bucket_idx].head, memory_order_relaxed);
    while (existing != NULL)
    {
        int state = atomic_load_explicit(&existing->state, memory_order_acquire);
        if (state == FIFO_ENTRY_ACTIVE && existing->key_len == key_len &&
            memcmp(existing->key, key, key_len) == 0)
        {
            if (existing->evict_cb && existing->value)
            {
                existing->evict_cb(existing->key, existing->value, existing->user_data);
            }

            existing->value = value;
            existing->evict_cb = evict_cb;
            existing->user_data = user_data;

            pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);
            return 0;
        }
        existing = atomic_load_explicit(&existing->hash_next, memory_order_relaxed);
    }

    size_t current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    while (current_size >= cache->capacity)
    {
        pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);

        if (!fifo_evict_oldest(cache))
        {
            /* Failed to evict, but size indicates full - race condition
             * Re-check size after reacquiring lock */
        }

        pthread_mutex_lock(&cache->buckets[bucket_idx].lock);
        current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    }

    fifo_entry_t *entry = fifo_alloc_entry(key, key_len, value, evict_cb, user_data);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);
        return -1;
    }

    fifo_add_to_bucket(cache, entry, bucket_idx);

    atomic_fetch_add_explicit(&cache->size, 1, memory_order_relaxed);

    pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);

    if (queue_enqueue(cache->queue, entry) != 0)
    {
        pthread_mutex_lock(&cache->buckets[bucket_idx].lock);
        atomic_store_explicit(&entry->state, FIFO_ENTRY_MARKED, memory_order_release);
        fifo_remove_from_bucket(cache, entry, bucket_idx);
        atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);
        pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);
        fifo_free_entry(entry, 0);
        return -1;
    }

    return 0;
}

void *fifo_cache_get(fifo_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return NULL;

    size_t key_len = strlen(key);

    fifo_entry_t *entry = fifo_find_entry_lockfree(cache, key, key_len, NULL);
    if (entry == NULL) return NULL;

    return entry->value;
}

int fifo_cache_remove(fifo_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    size_t bucket_idx;

    fifo_entry_t *entry = fifo_find_entry_lockfree(cache, key, key_len, &bucket_idx);
    if (entry == NULL) return -1;

    if (!fifo_mark_entry(entry))
    {
        return -1;
    }

    pthread_mutex_lock(&cache->buckets[bucket_idx].lock);
    fifo_remove_from_bucket(cache, entry, bucket_idx);
    pthread_mutex_unlock(&cache->buckets[bucket_idx].lock);

    atomic_store_explicit(&entry->state, FIFO_ENTRY_REMOVED, memory_order_release);

    atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

    fifo_free_entry(entry, 1);

    return 0;
}

void fifo_cache_clear(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_lock(&cache->buckets[i].lock);
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        fifo_entry_t *entry = atomic_load_explicit(&cache->buckets[i].head, memory_order_relaxed);
        while (entry != NULL)
        {
            fifo_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);

            int expected = FIFO_ENTRY_ACTIVE;
            if (atomic_compare_exchange_strong_explicit(&entry->state, &expected,
                                                        FIFO_ENTRY_REMOVED, memory_order_release,
                                                        memory_order_relaxed))
            {
                fifo_free_entry(entry, 1);
            }

            entry = next;
        }
        atomic_store_explicit(&cache->buckets[i].head, NULL, memory_order_release);
    }

    atomic_store_explicit(&cache->size, 0, memory_order_release);

    while (queue_dequeue(cache->queue) != NULL)
    {
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_unlock(&cache->buckets[i].lock);
    }
}

void fifo_cache_free(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    fifo_cache_clear(cache);

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_destroy(&cache->buckets[i].lock);
    }

    queue_free(cache->queue);

    free(cache->buckets);
    free(cache);
    cache = NULL;
}

void fifo_cache_destroy(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_lock(&cache->buckets[i].lock);
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        fifo_entry_t *entry = atomic_load_explicit(&cache->buckets[i].head, memory_order_relaxed);
        while (entry != NULL)
        {
            fifo_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);

            int expected = FIFO_ENTRY_ACTIVE;
            if (atomic_compare_exchange_strong_explicit(&entry->state, &expected,
                                                        FIFO_ENTRY_REMOVED, memory_order_release,
                                                        memory_order_relaxed))
            {
                fifo_free_entry(entry, 0); /* no callback */
            }

            entry = next;
        }
        atomic_store_explicit(&cache->buckets[i].head, NULL, memory_order_release);
    }

    atomic_store_explicit(&cache->size, 0, memory_order_release);

    while (queue_dequeue(cache->queue) != NULL)
    {
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_unlock(&cache->buckets[i].lock);
    }

    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        pthread_mutex_destroy(&cache->buckets[i].lock);
    }

    queue_free(cache->queue);

    free(cache->buckets);
    free(cache);
    cache = NULL;
}

size_t fifo_cache_size(fifo_cache_t *cache)
{
    if (cache == NULL) return 0;
    return atomic_load_explicit(&cache->size, memory_order_relaxed);
}

size_t fifo_cache_capacity(fifo_cache_t *cache)
{
    if (cache == NULL) return 0;
    return cache->capacity;
}

size_t fifo_cache_foreach(fifo_cache_t *cache, fifo_foreach_callback_t callback, void *user_data)
{
    if (cache == NULL || callback == NULL) return 0;

    size_t count = 0;

    /* iter through all buckets */
    for (size_t i = 0; i < cache->bucket_count; i++)
    {
        fifo_entry_t *entry = atomic_load_explicit(&cache->buckets[i].head, memory_order_acquire);

        while (entry != NULL)
        {
            int state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state == FIFO_ENTRY_ACTIVE)
            {
                int result = callback(entry->key, entry->value, user_data);
                count++;

                if (result != 0)
                {
                    return count;
                }
            }

            entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
        }
    }

    return count;
}