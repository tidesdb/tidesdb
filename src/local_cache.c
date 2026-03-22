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
#include "local_cache.h"

#include <string.h>
#include <sys/stat.h>

int tdb_local_cache_init(tdb_local_cache_t *cache, const char *cache_dir, size_t max_bytes)
{
    if (!cache || !cache_dir) return -1;

    memset(cache, 0, sizeof(*cache));
    snprintf(cache->cache_dir, sizeof(cache->cache_dir), "%s", cache_dir);
    cache->max_bytes = max_bytes;
    atomic_init(&cache->current_bytes, 0);
    pthread_mutex_init(&cache->lock, NULL);
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    cache->num_entries = 0;

    return 0;
}

void tdb_local_cache_destroy(tdb_local_cache_t *cache)
{
    if (!cache) return;

    pthread_mutex_lock(&cache->lock);

    tdb_cache_entry_t *cur = cache->lru_head;
    while (cur)
    {
        tdb_cache_entry_t *next = cur->next;
        free(cur);
        cur = next;
    }
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    cache->num_entries = 0;
    atomic_store(&cache->current_bytes, 0);

    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
}

/**
 * cache_unlink
 * unlink an entry from the doubly-linked LRU list
 * @param cache the cache manager
 * @param entry entry to unlink (must be in the list)
 * caller must hold cache->lock
 */
static void cache_unlink(tdb_local_cache_t *cache, tdb_cache_entry_t *entry)
{
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        cache->lru_head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        cache->lru_tail = entry->prev;

    entry->prev = NULL;
    entry->next = NULL;
}

/**
 * cache_push_head
 * insert an entry at the head (most recently used) of the LRU list
 * @param cache the cache manager
 * @param entry entry to insert
 * caller must hold cache->lock
 */
static void cache_push_head(tdb_local_cache_t *cache, tdb_cache_entry_t *entry)
{
    entry->prev = NULL;
    entry->next = cache->lru_head;
    if (cache->lru_head)
        cache->lru_head->prev = entry;
    else
        cache->lru_tail = entry;
    cache->lru_head = entry;
}

/**
 * cache_find
 * find an entry by file path in the LRU list
 * @param cache the cache manager
 * @param path file path to search for
 * @return the entry if found, NULL otherwise
 * caller must hold cache->lock
 */
static tdb_cache_entry_t *cache_find(tdb_local_cache_t *cache, const char *path)
{
    tdb_cache_entry_t *cur = cache->lru_head;
    while (cur)
    {
        if (strcmp(cur->path, path) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

/**
 * cache_evict
 * evict LRU entries (from tail) until enough space is available
 * @param cache the cache manager
 * @param bytes_needed number of bytes needed for the new entry
 * caller must hold cache->lock
 */
static void cache_evict(tdb_local_cache_t *cache, size_t bytes_needed)
{
    if (cache->max_bytes == 0) return; /* unlimited */

    size_t current = atomic_load_explicit(&cache->current_bytes, memory_order_relaxed);
    while (current + bytes_needed > cache->max_bytes && cache->lru_tail)
    {
        tdb_cache_entry_t *victim = cache->lru_tail;
        cache_unlink(cache, victim);

        /* we delete the cached file from disk */
#ifdef _WIN32
        _unlink(victim->path);
#else
        unlink(victim->path);
#endif

        current -= victim->size;
        atomic_store_explicit(&cache->current_bytes, current, memory_order_relaxed);
        cache->num_entries--;
        free(victim);
    }
}

int tdb_local_cache_track(tdb_local_cache_t *cache, const char *local_path)
{
    if (!cache || !local_path) return -1;

    struct stat st;
    if (stat(local_path, &st) != 0) return -1;

    size_t file_size = (size_t)st.st_size;

    pthread_mutex_lock(&cache->lock);

    /* we check if already tracked */
    tdb_cache_entry_t *existing = cache_find(cache, local_path);
    if (existing)
    {
        /* we move to head (touch) */
        cache_unlink(cache, existing);
        cache_push_head(cache, existing);
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }

    /* we evict if needed */
    cache_evict(cache, file_size);

    tdb_cache_entry_t *entry = calloc(1, sizeof(tdb_cache_entry_t));
    if (!entry)
    {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    snprintf(entry->path, sizeof(entry->path), "%s", local_path);
    entry->size = file_size;
    cache_push_head(cache, entry);
    cache->num_entries++;
    atomic_fetch_add_explicit(&cache->current_bytes, file_size, memory_order_relaxed);

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

void tdb_local_cache_touch(tdb_local_cache_t *cache, const char *local_path)
{
    if (!cache || !local_path) return;

    pthread_mutex_lock(&cache->lock);

    tdb_cache_entry_t *entry = cache_find(cache, local_path);
    if (entry)
    {
        cache_unlink(cache, entry);
        cache_push_head(cache, entry);
    }

    pthread_mutex_unlock(&cache->lock);
}

void tdb_local_cache_remove(tdb_local_cache_t *cache, const char *local_path)
{
    if (!cache || !local_path) return;

    pthread_mutex_lock(&cache->lock);

    tdb_cache_entry_t *entry = cache_find(cache, local_path);
    if (entry)
    {
        cache_unlink(cache, entry);
        atomic_fetch_sub_explicit(&cache->current_bytes, entry->size, memory_order_relaxed);
        cache->num_entries--;
        free(entry);
    }

    pthread_mutex_unlock(&cache->lock);
}
