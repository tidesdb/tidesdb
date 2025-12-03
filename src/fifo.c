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
 * @param key_len the length of the key (pre-computed)
 * @param table_size the size of the hash table
 * @return the hash value
 */
static inline size_t fifo_hash(const char *key, size_t key_len, size_t table_size)
{
    XXH64_hash_t hash = XXH64(key, key_len, 0);
    return (size_t)(hash % table_size);
}

/**
 * fifo_find_entry
 * find entry in hash table
 * @param cache the cache to search in
 * @param key the key to search for
 * @param key_len the length of the key
 * @return the entry if found, NULL otherwise
 */
static fifo_entry_t *fifo_find_entry(fifo_cache_t *cache, const char *key, size_t key_len)
{
    size_t index = fifo_hash(key, key_len, cache->table_size);
    fifo_entry_t *entry = cache->table[index];

    /* compare length first, then memcmp */
    while (entry != NULL)
    {
        if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) return entry;
        entry = entry->hash_next;
    }

    return NULL;
}

/**
 * fifo_remove_from_table
 * remove entry from hash table
 * @param cache the cache to remove the entry from
 * @param entry the entry to remove
 */
static void fifo_remove_from_table(fifo_cache_t *cache, fifo_entry_t *entry)
{
    size_t index = fifo_hash(entry->key, entry->key_len, cache->table_size);
    fifo_entry_t *current = cache->table[index];
    fifo_entry_t *prev = NULL;

    while (current != NULL)
    {
        if (current == entry)
        {
            if (prev)
                prev->hash_next = current->hash_next;
            else
                cache->table[index] = current->hash_next;
            return;
        }
        prev = current;
        current = current->hash_next;
    }
}

/**
 * fifo_add_to_table
 * add entry to hash table
 * @param cache the cache to add the entry to
 * @param entry the entry to add
 */
static void fifo_add_to_table(fifo_cache_t *cache, fifo_entry_t *entry)
{
    size_t index = fifo_hash(entry->key, entry->key_len, cache->table_size);
    entry->hash_next = cache->table[index];
    cache->table[index] = entry;
}

/**
 * fifo_evict_fifo
 * evict oldest entry
 * @param cache the cache to evict from
 */
static void fifo_evict_fifo(fifo_cache_t *cache)
{
    if (cache->size == 0 || !cache->tail) return;
    fifo_entry_t *victim = cache->tail;

    /* remove victim from doubly linked list */
    if (victim->prev)
    {
        victim->prev->next = NULL;
        cache->tail = victim->prev;
    }
    else
    {
        /* only entry in cache */
        cache->head = NULL;
        cache->tail = NULL;
    }

    fifo_remove_from_table(cache, victim);
    if (victim->evict_cb) victim->evict_cb(victim->key, victim->value, victim->user_data);

    free(victim->key);
    free(victim);
    victim = NULL;

    cache->size--;
}

/**
 * fifo_free_entry
 * free an entry and call its eviction callback
 * @param cache the cache to free the entry from
 * @param entry the entry to free
 */
static void fifo_free_entry(fifo_cache_t *cache, fifo_entry_t *entry)
{
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        cache->head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        cache->tail = entry->prev;

    fifo_remove_from_table(cache, entry);

    if (entry->evict_cb) entry->evict_cb(entry->key, entry->value, entry->user_data);

    free(entry->key);
    free(entry);
    entry = NULL;

    cache->size--;
}

fifo_cache_t *fifo_cache_new(size_t capacity)
{
    if (capacity == 0) return NULL;

    fifo_cache_t *cache = (fifo_cache_t *)malloc(sizeof(fifo_cache_t));
    if (cache == NULL) return NULL;

    cache->capacity = capacity;
    cache->size = 0;
    cache->head = NULL;
    cache->tail = NULL;
    cache->table_size = capacity * 2;
    cache->table = (fifo_entry_t **)calloc(cache->table_size, sizeof(fifo_entry_t *));
    if (cache->table == NULL)
    {
        free(cache);
        return NULL;
    }

    if (pthread_mutex_init(&cache->lock, NULL) != 0)
    {
        free(cache->table);
        free(cache);
        cache = NULL;
        return NULL;
    }

    return cache;
}

int fifo_cache_put(fifo_cache_t *cache, const char *key, void *value,
                   fifo_evict_callback_t evict_cb, void *user_data)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    pthread_mutex_lock(&cache->lock);

    fifo_entry_t *existing = fifo_find_entry(cache, key, key_len);
    if (existing != NULL)
    {
        /* call eviction callback on old value before replacing */
        if (existing->evict_cb && existing->value)
        {
            existing->evict_cb(existing->key, existing->value, existing->user_data);
        }

        existing->value = value;
        existing->evict_cb = evict_cb;
        existing->user_data = user_data;

        pthread_mutex_unlock(&cache->lock);
        return 1; /* return 1 to indicate entry was updated, not inserted */
    }

    if (cache->size >= cache->capacity) fifo_evict_fifo(cache);

    fifo_entry_t *entry = (fifo_entry_t *)malloc(sizeof(fifo_entry_t));
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    entry->key = tdb_strdup(key);

    if (entry->key == NULL)
    {
        free(entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    entry->key_len = key_len;
    entry->value = value;
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    entry->prev = NULL;
    entry->next = cache->head;

    if (cache->head) cache->head->prev = entry;
    cache->head = entry;

    /* if list was empty, this is also the tail */
    if (cache->tail == NULL) cache->tail = entry;

    fifo_add_to_table(cache, entry);

    cache->size++;

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void *fifo_cache_get(fifo_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return NULL;

    size_t key_len = strlen(key);

    /* lock to prevent use-after-free if another thread is modifying the cache */
    pthread_mutex_lock(&cache->lock);

    fifo_entry_t *entry = fifo_find_entry(cache, key, key_len);
    void *value = entry ? entry->value : NULL;

    pthread_mutex_unlock(&cache->lock);

    return value;
}

int fifo_cache_remove(fifo_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    pthread_mutex_lock(&cache->lock);

    fifo_entry_t *entry = fifo_find_entry(cache, key, key_len);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    fifo_free_entry(cache, entry);

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void fifo_cache_clear(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    pthread_mutex_lock(&cache->lock);

    fifo_entry_t *current = cache->head;
    while (current != NULL)
    {
        fifo_entry_t *next = current->next;

        /* call eviction callback if set */
        if (current->evict_cb) current->evict_cb(current->key, current->value, current->user_data);

        free(current->key);
        free(current);
        current = next;
    }

    memset(cache->table, 0, cache->table_size * sizeof(fifo_entry_t *));

    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;

    pthread_mutex_unlock(&cache->lock);
}

void fifo_cache_free(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    fifo_cache_clear(cache);

    pthread_mutex_destroy(&cache->lock);
    free(cache->table);
    free(cache);
    cache = NULL;
}

void fifo_cache_destroy(fifo_cache_t *cache)
{
    if (cache == NULL) return;

    pthread_mutex_lock(&cache->lock);

    fifo_entry_t *current = cache->head;
    while (current != NULL)
    {
        fifo_entry_t *next = current->next;

        free(current->key);
        free(current);
        current = next;
    }

    memset(cache->table, 0, cache->table_size * sizeof(fifo_entry_t *));

    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;

    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache->table);
    free(cache);
    cache = NULL;
}

size_t fifo_cache_size(fifo_cache_t *cache)
{
    if (cache == NULL) return 0;

    pthread_mutex_lock(&cache->lock);
    size_t size = cache->size;
    pthread_mutex_unlock(&cache->lock);

    return size;
}

size_t fifo_cache_capacity(fifo_cache_t *cache)
{
    if (cache == NULL) return 0;
    return cache->capacity;
}

size_t fifo_cache_foreach(fifo_cache_t *cache, fifo_foreach_callback_t callback, void *user_data)
{
    if (cache == NULL || callback == NULL) return 0;

    pthread_mutex_lock(&cache->lock);

    size_t count = 0;
    fifo_entry_t *current = cache->head;

    /* iterate from most recently used to least recently used */
    while (current != NULL)
    {
        int result = callback(current->key, current->value, user_data);
        count++;

        /* if callback returns non-zero, stop iteration */
        if (result != 0) break;

        current = current->next;
    }

    pthread_mutex_unlock(&cache->lock);

    return count;
}