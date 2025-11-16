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

#include "xxhash.h"

/*
 * lru_hash
 * hash function for string keys using xxhash
 * @param key the key to hash
 * @param key_len the length of the key (pre-computed)
 * @param table_size the size of the hash table
 * @return the hash value
 */
static inline size_t lru_hash(const char *key, size_t key_len, size_t table_size)
{
    XXH64_hash_t hash = XXH64(key, key_len, 0);
    return (size_t)(hash % table_size);
}

/*
 * lru_find_entry
 * find entry in hash table
 * @param cache the cache to search in
 * @param key the key to search for
 * @param key_len the length of the key
 * @return the entry if found, NULL otherwise
 */
static lru_entry_t *lru_find_entry(lru_cache_t *cache, const char *key, size_t key_len)
{
    size_t index = lru_hash(key, key_len, cache->table_size);
    lru_entry_t *entry = cache->table[index];

    /* compare length first, then memcmp */
    while (entry != NULL)
    {
        if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0) return entry;
        entry = entry->hash_next;
    }

    return NULL;
}

/*
 * lru_move_to_head
 * move entry to head (most recently used)
 * @param cache the cache to move the entry to
 * @param entry the entry to move
 */
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

/*
 * lru_remove_from_table
 * remove entry from hash table
 * @param cache the cache to remove the entry from
 * @param entry the entry to remove
 */
static void lru_remove_from_table(lru_cache_t *cache, lru_entry_t *entry)
{
    size_t index = lru_hash(entry->key, entry->key_len, cache->table_size);
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

/*
 * lru_add_to_table
 * add entry to hash table
 * @param cache the cache to add the entry to
 * @param entry the entry to add
 */
static void lru_add_to_table(lru_cache_t *cache, lru_entry_t *entry)
{
    size_t index = lru_hash(entry->key, entry->key_len, cache->table_size);
    entry->hash_next = cache->table[index];
    cache->table[index] = entry;
}

/*
 * lru_evict_lru
 * evict least frequently used entry (approximate LRU based on access_count)
 * @param cache the cache to evict from
 */
static void lru_evict_lru(lru_cache_t *cache)
{
    if (cache->size == 0) return;

    /* find entry with oldest timestamp (least recently used)
     * this is approximate LRU - we scan the list to find oldest entry */
    lru_entry_t *victim = cache->head;
    lru_entry_t *current = cache->head;
    uint64_t min_time = atomic_load(&victim->last_access_time);

    while (current != NULL)
    {
        uint64_t time = atomic_load(&current->last_access_time);
        if (time < min_time)
        {
            min_time = time;
            victim = current;
        }
        current = current->next;
    }

    /* remove victim from doubly linked list */
    if (victim->prev)
        victim->prev->next = victim->next;
    else
        cache->head = victim->next;

    if (victim->next)
        victim->next->prev = victim->prev;
    else
        cache->tail = victim->prev;

    lru_remove_from_table(cache, victim);
    if (victim->evict_cb) victim->evict_cb(victim->key, victim->value, victim->user_data);

    free(victim->key);
    free(victim);

    cache->size--;
}

/*
 * lru_free_entry
 * free an entry and call its eviction callback
 * @param cache the cache to free the entry from
 * @param entry the entry to free
 */
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
    cache->table_size = capacity * 2;
    atomic_store(&cache->timestamp_counter, 0);
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

    size_t key_len = strlen(key);
    pthread_mutex_lock(&cache->lock);

    lru_entry_t *existing = lru_find_entry(cache, key, key_len);
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
        lru_move_to_head(cache, existing);
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }

    if (cache->size >= cache->capacity) lru_evict_lru(cache);

    lru_entry_t *entry = (lru_entry_t *)malloc(sizeof(lru_entry_t));
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
    atomic_store(&entry->last_access_time, atomic_fetch_add(&cache->timestamp_counter, 1));

    if (cache->head) cache->head->prev = entry;
    cache->head = entry;

    /* if list was empty, this is also the tail */
    if (cache->tail == NULL) cache->tail = entry;

    lru_add_to_table(cache, entry);

    cache->size++;

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void *lru_cache_get(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return NULL;

    size_t key_len = strlen(key);

    /* LOCK-FREE READ: No lock needed for lookup!
     * Hash table is read-only during lookups, only modified during put/evict.
     * We rely on the write lock in put/evict to ensure consistency. */
    size_t index = lru_hash(key, key_len, cache->table_size);
    lru_entry_t *entry = cache->table[index];

    /* walk hash chain without lock */
    while (entry != NULL)
    {
        if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0)
        {
            /* found it! update timestamp atomically (lock-free) */
            atomic_store(&entry->last_access_time, atomic_fetch_add(&cache->timestamp_counter, 1));
            return entry->value;
        }
        entry = entry->hash_next;
    }

    return NULL; /* not found */
}

int lru_cache_remove(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    pthread_mutex_lock(&cache->lock);

    lru_entry_t *entry = lru_find_entry(cache, key, key_len);
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

        free(current->key);
        free(current);
        current = next;
    }

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
