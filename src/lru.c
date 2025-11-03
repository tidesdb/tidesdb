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
#include "lru.h"

#include <stdlib.h>
#include <string.h>

#include "../external/xxhash.h"

/* hash function for string keys using xxhash */
static size_t lru_hash(const char *key, size_t table_size)
{
    XXH64_hash_t hash = XXH64(key, strlen(key), 0);
    return (size_t)(hash % table_size);
}

/* find entry in hash table */
static lru_entry_t *lru_find_entry(lru_cache_t *cache, const char *key)
{
    size_t index = lru_hash(key, cache->table_size);
    lru_entry_t *entry = cache->table[index];

    while (entry != NULL)
    {
        if (strcmp(entry->key, key) == 0) return entry;
        entry = entry->hash_next;
    }

    return NULL;
}

/* move entry to head (most recently used) */
static void lru_move_to_head(lru_cache_t *cache, lru_entry_t *entry)
{
    if (entry == cache->head) return;

    if (entry->prev) entry->prev->next = entry->next;
    if (entry->next) entry->next->prev = entry->prev;
    if (entry == cache->tail) cache->tail = entry->prev;

    /* insert at head */
    entry->prev = NULL;
    entry->next = cache->head;
    if (cache->head) cache->head->prev = entry;
    cache->head = entry;

    /* if list was empty, this is also the tail */
    if (cache->tail == NULL) cache->tail = entry;
}

/* remove entry from hash table */
static void lru_remove_from_table(lru_cache_t *cache, lru_entry_t *entry)
{
    size_t index = lru_hash(entry->key, cache->table_size);
    lru_entry_t *current = cache->table[index];
    lru_entry_t *prev = NULL;

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

/* add entry to hash table */
static void lru_add_to_table(lru_cache_t *cache, lru_entry_t *entry)
{
    size_t index = lru_hash(entry->key, cache->table_size);
    entry->hash_next = cache->table[index];
    cache->table[index] = entry;
}

/* evict least recently used entry */
static void lru_evict_lru(lru_cache_t *cache)
{
    if (cache->tail == NULL) return;

    lru_entry_t *lru = cache->tail;

    /* remove from doubly linked list */
    if (lru->prev)
        lru->prev->next = NULL;
    else
        cache->head = NULL;

    cache->tail = lru->prev;

    lru_remove_from_table(cache, lru);

    /* call eviction callback if set */
    if (lru->evict_cb) lru->evict_cb(lru->key, lru->value, lru->user_data);

    /* free entry */
    free(lru->key);
    free(lru);

    cache->size--;
}

/* free an entry and call its eviction callback */
static void lru_free_entry(lru_cache_t *cache, lru_entry_t *entry)
{
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        cache->head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        cache->tail = entry->prev;

    lru_remove_from_table(cache, entry);

    if (entry->evict_cb) entry->evict_cb(entry->key, entry->value, entry->user_data);

    free(entry->key);
    free(entry);

    cache->size--;
}

lru_cache_t *lru_cache_new(size_t capacity)
{
    if (capacity == 0) return NULL;

    lru_cache_t *cache = (lru_cache_t *)malloc(sizeof(lru_cache_t));
    if (cache == NULL) return NULL;

    cache->capacity = capacity;
    cache->size = 0;
    cache->head = NULL;
    cache->tail = NULL;

    /* hash table size is 2x capacity for better distribution */
    cache->table_size = capacity * 2;
    cache->table = (lru_entry_t **)calloc(cache->table_size, sizeof(lru_entry_t *));
    if (cache->table == NULL)
    {
        free(cache);
        return NULL;
    }

    if (pthread_mutex_init(&cache->lock, NULL) != 0)
    {
        free(cache->table);
        free(cache);
        return NULL;
    }

    return cache;
}

int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data)
{
    if (cache == NULL || key == NULL) return -1;

    pthread_mutex_lock(&cache->lock);

    lru_entry_t *existing = lru_find_entry(cache, key);
    if (existing != NULL)
    {
        existing->value = value;
        existing->evict_cb = evict_cb;
        existing->user_data = user_data;
        lru_move_to_head(cache, existing);
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }

    /* evict if at capacity */
    if (cache->size >= cache->capacity) lru_evict_lru(cache);

    /* create new entry */
    lru_entry_t *entry = (lru_entry_t *)malloc(sizeof(lru_entry_t));
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    /* use _strdup on MSVC, strdup on others */
#ifdef _MSC_VER
    entry->key = _strdup(key);
#else
    entry->key = strdup(key);
#endif
    if (entry->key == NULL)
    {
        free(entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    entry->value = value;
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    entry->prev = NULL;
    entry->next = cache->head;

    /* insert at head */
    if (cache->head) cache->head->prev = entry;
    cache->head = entry;

    /* if list was empty, this is also the tail */
    if (cache->tail == NULL) cache->tail = entry;

    /* add to hash table */
    lru_add_to_table(cache, entry);

    cache->size++;

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void *lru_cache_get(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return NULL;

    pthread_mutex_lock(&cache->lock);

    lru_entry_t *entry = lru_find_entry(cache, key);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->lock);
        return NULL;
    }

    /* move to head (mark as recently used) */
    lru_move_to_head(cache, entry);

    void *value = entry->value;
    pthread_mutex_unlock(&cache->lock);

    return value;
}

int lru_cache_remove(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return -1;

    pthread_mutex_lock(&cache->lock);

    lru_entry_t *entry = lru_find_entry(cache, key);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    lru_free_entry(cache, entry);

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void lru_cache_clear(lru_cache_t *cache)
{
    if (cache == NULL) return;

    pthread_mutex_lock(&cache->lock);

    lru_entry_t *current = cache->head;
    while (current != NULL)
    {
        lru_entry_t *next = current->next;

        /* call eviction callback if set */
        if (current->evict_cb) current->evict_cb(current->key, current->value, current->user_data);

        free(current->key);
        free(current);
        current = next;
    }

    /* clear hash table */
    memset(cache->table, 0, cache->table_size * sizeof(lru_entry_t *));

    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;

    pthread_mutex_unlock(&cache->lock);
}

void lru_cache_free(lru_cache_t *cache)
{
    if (cache == NULL) return;

    lru_cache_clear(cache);

    pthread_mutex_destroy(&cache->lock);
    free(cache->table);
    free(cache);
}

void lru_cache_destroy(lru_cache_t *cache)
{
    if (cache == NULL) return;

    pthread_mutex_lock(&cache->lock);

    lru_entry_t *current = cache->head;
    while (current != NULL)
    {
        lru_entry_t *next = current->next;

        /* free entry WITHOUT calling eviction callback */
        free(current->key);
        free(current);
        current = next;
    }

    /* clear hash table */
    memset(cache->table, 0, cache->table_size * sizeof(lru_entry_t *));

    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;

    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache->table);
    free(cache);
}

size_t lru_cache_size(lru_cache_t *cache)
{
    if (cache == NULL) return 0;

    pthread_mutex_lock(&cache->lock);
    size_t size = cache->size;
    pthread_mutex_unlock(&cache->lock);

    return size;
}

size_t lru_cache_capacity(lru_cache_t *cache)
{
    if (cache == NULL) return 0;
    return cache->capacity;
}

size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data)
{
    if (cache == NULL || callback == NULL) return 0;

    pthread_mutex_lock(&cache->lock);

    size_t count = 0;
    lru_entry_t *current = cache->head;

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
