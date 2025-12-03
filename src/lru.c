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
#include "lru.h"

#include "xxhash.h"

/**
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

/**
 * lru_entry_acquire
 * increment reference count on entry
 * @param entry the entry to acquire
 * @return true if acquired successfully, false if entry is being deleted
 */
static inline int lru_entry_acquire(lru_entry_t *entry)
{
    uint32_t old_ref = atomic_load_explicit(&entry->ref_count, memory_order_relaxed);
    do
    {
        if (old_ref == 0) return 0; /* entry is being freed */
    } while (!atomic_compare_exchange_weak_explicit(&entry->ref_count, &old_ref, old_ref + 1,
                                                    memory_order_acquire, memory_order_relaxed));
    return 1;
}

/**
 * lru_entry_release
 * decrement reference count on entry, free if zero
 * @param entry the entry to release
 * @param call_evict whether to call eviction callback
 */
static void lru_entry_release(lru_entry_t *entry, int call_evict)
{
    uint32_t old_ref = atomic_fetch_sub_explicit(&entry->ref_count, 1, memory_order_release);
    if (old_ref == 1)
    {
        /* we were the last reference, free the entry */
        atomic_thread_fence(memory_order_acquire);

        if (call_evict && entry->evict_cb)
        {
            void *value = atomic_load_explicit(&entry->value, memory_order_relaxed);
            entry->evict_cb(entry->key, value, entry->user_data);
        }
        free(entry->key);
        free(entry);
    }
}

/**
 * lru_find_entry
 * find entry in hash table (lock-free)
 * @param cache the cache to search in
 * @param key the key to search for
 * @param key_len the length of the key
 * @return the entry if found (with ref count incremented), NULL otherwise
 */
static lru_entry_t *lru_find_entry(lru_cache_t *cache, const char *key, size_t key_len)
{
    size_t index = lru_hash(key, key_len, cache->table_size);

retry:;
    lru_entry_t *entry = atomic_load_explicit(&cache->table[index], memory_order_acquire);

    while (entry != NULL)
    {
        /* check if entry is active */
        lru_entry_state_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
        if (state == LRU_ENTRY_ACTIVE)
        {
            /* compare length first, then memcmp */
            if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0)
            {
                /* try to acquire reference */
                if (lru_entry_acquire(entry))
                {
                    /* verify state didn't change */
                    state = atomic_load_explicit(&entry->state, memory_order_acquire);
                    if (state == LRU_ENTRY_ACTIVE)
                    {
                        return entry;
                    }
                    /* state changed, release and retry */
                    lru_entry_release(entry, 0);
                    goto retry;
                }
                /* couldn't acquire, entry is being deleted, retry */
                goto retry;
            }
        }
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    return NULL;
}

/**
 * lru_find_slot
 * find an empty slot in the entries array
 * @param cache the cache
 * @return slot index, or SIZE_MAX if no slot available
 */
static size_t lru_find_slot(lru_cache_t *cache)
{
    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *entry = atomic_load_explicit(&cache->entries[i], memory_order_relaxed);
        if (entry == NULL)
        {
            return i;
        }
    }
    return SIZE_MAX;
}

/**
 * lru_evict_one
 * evict one entry using clock algorithm
 * @param cache the cache
 * @return true if an entry was evicted, false otherwise
 */
static int lru_evict_one(lru_cache_t *cache)
{
    size_t start_hand = atomic_load_explicit(&cache->clock_hand, memory_order_relaxed);
    size_t hand = start_hand;
    size_t passes = 0;
    const size_t max_passes = 3; /* limit clock sweeps */

    while (passes < max_passes)
    {
        lru_entry_t *entry = atomic_load_explicit(&cache->entries[hand], memory_order_acquire);

        if (entry != NULL)
        {
            lru_entry_state_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state == LRU_ENTRY_ACTIVE)
            {
                uint64_t access = atomic_load_explicit(&entry->access_count, memory_order_relaxed);

                if (access == 0)
                {
                    /* try to mark for deletion */
                    lru_entry_state_t expected = LRU_ENTRY_ACTIVE;
                    if (atomic_compare_exchange_strong_explicit(
                            &entry->state, &expected, LRU_ENTRY_DELETED, memory_order_acq_rel,
                            memory_order_relaxed))
                    {
                        /* successfully marked for deletion, remove from hash table */
                        size_t hash_idx = lru_hash(entry->key, entry->key_len, cache->table_size);

                        /* remove from hash chain using CAS loop */
                        lru_entry_t *prev = NULL;
                        lru_entry_t *curr =
                            atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);

                        while (curr != NULL && curr != entry)
                        {
                            prev = curr;
                            curr = atomic_load_explicit(&curr->hash_next, memory_order_acquire);
                        }

                        if (curr == entry)
                        {
                            lru_entry_t *next =
                                atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
                            if (prev == NULL)
                            {
                                atomic_store_explicit(&cache->table[hash_idx], next,
                                                      memory_order_release);
                            }
                            else
                            {
                                atomic_store_explicit(&prev->hash_next, next, memory_order_release);
                            }
                        }

                        /* clear slot in entries array */
                        atomic_store_explicit(&cache->entries[hand], NULL, memory_order_release);

                        /* decrement size */
                        atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

                        /* advance clock hand */
                        size_t next_hand = (hand + 1) % cache->capacity;
                        atomic_store_explicit(&cache->clock_hand, next_hand, memory_order_relaxed);

                        /* release entry (will free when ref count hits 0) */
                        lru_entry_release(entry, 1);

                        return 1;
                    }
                }
                else
                {
                    /* decrement access count (give it another chance) */
                    atomic_fetch_sub_explicit(&entry->access_count, 1, memory_order_relaxed);
                }
            }
        }

        /* advance hand */
        hand = (hand + 1) % cache->capacity;
        if (hand == start_hand)
        {
            passes++;
        }
    }

    return 0;
}

lru_cache_t *lru_cache_new(size_t capacity)
{
    if (capacity == 0) return NULL;

    lru_cache_t *cache = (lru_cache_t *)malloc(sizeof(lru_cache_t));
    if (cache == NULL) return NULL;

    cache->capacity = capacity;
    atomic_init(&cache->size, 0);
    cache->table_size = capacity * 2;
    atomic_init(&cache->clock_hand, 0);
    atomic_init(&cache->global_clock, 0);

    /* allocate hash table */
    cache->table =
        (_Atomic(lru_entry_t *) *)calloc(cache->table_size, sizeof(_Atomic(lru_entry_t *)));
    if (cache->table == NULL)
    {
        free(cache);
        return NULL;
    }

    /* allocate entries array for clock algorithm */
    cache->entries = (_Atomic(lru_entry_t *) *)calloc(capacity, sizeof(_Atomic(lru_entry_t *)));
    if (cache->entries == NULL)
    {
        free(cache->table);
        free(cache);
        return NULL;
    }

    /* initialize atomic pointers */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        atomic_init(&cache->table[i], NULL);
    }
    for (size_t i = 0; i < capacity; i++)
    {
        atomic_init(&cache->entries[i], NULL);
    }

    return cache;
}

int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);

    /* check if entry already exists */
    lru_entry_t *existing = lru_find_entry(cache, key, key_len);
    if (existing != NULL)
    {
        /* update existing entry */
        void *old_value = atomic_exchange_explicit(&existing->value, value, memory_order_acq_rel);

        /* call eviction callback on old value */
        if (existing->evict_cb && old_value)
        {
            existing->evict_cb(existing->key, old_value, existing->user_data);
        }

        /* update callbacks */
        existing->evict_cb = evict_cb;
        existing->user_data = user_data;

        /* bump access count */
        atomic_fetch_add_explicit(&existing->access_count, 1, memory_order_relaxed);

        lru_entry_release(existing, 0);
        return 1; /* updated */
    }

    /* need to insert new entry */
    size_t current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    while (current_size >= cache->capacity)
    {
        if (!lru_evict_one(cache))
        {
            /* couldn't evict, cache might be in bad state */
            return -1;
        }
        current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    }

    /* create new entry */
    lru_entry_t *entry = (lru_entry_t *)malloc(sizeof(lru_entry_t));
    if (entry == NULL) return -1;

    entry->key = tdb_strdup(key);
    if (entry->key == NULL)
    {
        free(entry);
        return -1;
    }

    entry->key_len = key_len;
    atomic_init(&entry->value, value);
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    atomic_init(&entry->access_count, 1); /* start with access count of 1 */
    atomic_init(&entry->state, LRU_ENTRY_ACTIVE);
    atomic_init(&entry->ref_count, 1); /* initial reference */
    atomic_init(&entry->hash_next, NULL);

    /* find a slot in entries array */
    size_t slot = lru_find_slot(cache);
    if (slot == SIZE_MAX)
    {
        /* no slot available, try evicting again */
        if (!lru_evict_one(cache))
        {
            free(entry->key);
            free(entry);
            return -1;
        }
        slot = lru_find_slot(cache);
        if (slot == SIZE_MAX)
        {
            free(entry->key);
            free(entry);
            return -1;
        }
    }

    /* add to entries array */
    lru_entry_t *expected_null = NULL;
    if (!atomic_compare_exchange_strong_explicit(&cache->entries[slot], &expected_null, entry,
                                                 memory_order_release, memory_order_relaxed))
    {
        /* slot was taken by another thread, find another */
        slot = lru_find_slot(cache);
        if (slot == SIZE_MAX)
        {
            free(entry->key);
            free(entry);
            return -1;
        }
        expected_null = NULL;
        if (!atomic_compare_exchange_strong_explicit(&cache->entries[slot], &expected_null, entry,
                                                     memory_order_release, memory_order_relaxed))
        {
            free(entry->key);
            free(entry);
            return -1;
        }
    }

    /* add to hash table */
    size_t hash_idx = lru_hash(key, key_len, cache->table_size);
    lru_entry_t *head;
    do
    {
        head = atomic_load_explicit(&cache->table[hash_idx], memory_order_relaxed);
        atomic_store_explicit(&entry->hash_next, head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&cache->table[hash_idx], &head, entry,
                                                    memory_order_release, memory_order_relaxed));

    /* increment size */
    atomic_fetch_add_explicit(&cache->size, 1, memory_order_relaxed);

    return 0; /* inserted */
}

void *lru_cache_get(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return NULL;

    size_t key_len = strlen(key);
    lru_entry_t *entry = lru_find_entry(cache, key, key_len);

    if (entry == NULL) return NULL;

    /* bump access count for LRU */
    atomic_fetch_add_explicit(&entry->access_count, 1, memory_order_relaxed);

    void *value = atomic_load_explicit(&entry->value, memory_order_acquire);

    lru_entry_release(entry, 0);

    return value;
}

void *lru_cache_get_copy(lru_cache_t *cache, const char *key, void *(*copy_fn)(void *))
{
    if (cache == NULL || key == NULL || copy_fn == NULL) return NULL;

    size_t key_len = strlen(key);
    lru_entry_t *entry = lru_find_entry(cache, key, key_len);

    if (entry == NULL) return NULL;

    /* bump access count for LRU */
    atomic_fetch_add_explicit(&entry->access_count, 1, memory_order_relaxed);

    void *value = atomic_load_explicit(&entry->value, memory_order_acquire);
    void *copy = NULL;

    if (value)
    {
        copy = copy_fn(value);
    }

    lru_entry_release(entry, 0);

    return copy;
}

int lru_cache_remove(lru_cache_t *cache, const char *key)
{
    if (cache == NULL || key == NULL) return -1;

    size_t key_len = strlen(key);
    lru_entry_t *entry = lru_find_entry(cache, key, key_len);

    if (entry == NULL) return -1;

    /* try to mark for deletion */
    lru_entry_state_t expected = LRU_ENTRY_ACTIVE;
    if (!atomic_compare_exchange_strong_explicit(&entry->state, &expected, LRU_ENTRY_DELETED,
                                                 memory_order_acq_rel, memory_order_relaxed))
    {
        /* already being deleted or updated */
        lru_entry_release(entry, 0);
        return -1;
    }

    /* remove from hash table */
    size_t hash_idx = lru_hash(key, key_len, cache->table_size);
    lru_entry_t *prev = NULL;
    lru_entry_t *curr = atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);

    while (curr != NULL && curr != entry)
    {
        prev = curr;
        curr = atomic_load_explicit(&curr->hash_next, memory_order_acquire);
    }

    if (curr == entry)
    {
        lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
        if (prev == NULL)
        {
            atomic_store_explicit(&cache->table[hash_idx], next, memory_order_release);
        }
        else
        {
            atomic_store_explicit(&prev->hash_next, next, memory_order_release);
        }
    }

    /* remove from entries array */
    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *e = atomic_load_explicit(&cache->entries[i], memory_order_relaxed);
        if (e == entry)
        {
            atomic_store_explicit(&cache->entries[i], NULL, memory_order_release);
            break;
        }
    }

    /* decrement size */
    atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

    /* release our reference (from find) */
    lru_entry_release(entry, 0);

    /* release the entry's own reference (will call eviction callback) */
    lru_entry_release(entry, 1);

    return 0;
}

void lru_cache_clear(lru_cache_t *cache)
{
    if (cache == NULL) return;

    /* not lock-free, assumes exclusive access */
    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *entry =
            atomic_exchange_explicit(&cache->entries[i], NULL, memory_order_acq_rel);
        if (entry != NULL)
        {
            atomic_store_explicit(&entry->state, LRU_ENTRY_DELETED, memory_order_release);

            if (entry->evict_cb)
            {
                void *value = atomic_load_explicit(&entry->value, memory_order_relaxed);
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            free(entry->key);
            free(entry);
        }
    }

    /* clear hash table */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        atomic_store_explicit(&cache->table[i], NULL, memory_order_release);
    }

    atomic_store_explicit(&cache->size, 0, memory_order_release);
    atomic_store_explicit(&cache->clock_hand, 0, memory_order_release);
}

void lru_cache_free(lru_cache_t *cache)
{
    if (cache == NULL) return;

    lru_cache_clear(cache);

    free(cache->table);
    free(cache->entries);
    free(cache);
}

void lru_cache_destroy(lru_cache_t *cache)
{
    if (cache == NULL) return;

    /*  not lock-free, assumes exclusive access */
    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *entry =
            atomic_exchange_explicit(&cache->entries[i], NULL, memory_order_acq_rel);
        if (entry != NULL)
        {
            /* free without calling eviction callback */
            free(entry->key);
            free(entry);
        }
    }

    /* clear hash table */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        atomic_store_explicit(&cache->table[i], NULL, memory_order_release);
    }

    free(cache->table);
    free(cache->entries);
    free(cache);
}

size_t lru_cache_size(lru_cache_t *cache)
{
    if (cache == NULL) return 0;
    return atomic_load_explicit(&cache->size, memory_order_relaxed);
}

size_t lru_cache_capacity(lru_cache_t *cache)
{
    if (cache == NULL) return 0;
    return cache->capacity;
}

size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data)
{
    if (cache == NULL || callback == NULL) return 0;

    size_t count = 0;

    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *entry = atomic_load_explicit(&cache->entries[i], memory_order_acquire);

        if (entry != NULL)
        {
            lru_entry_state_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state == LRU_ENTRY_ACTIVE)
            {
                if (lru_entry_acquire(entry))
                {
                    /* verify still active after acquiring */
                    state = atomic_load_explicit(&entry->state, memory_order_acquire);
                    if (state == LRU_ENTRY_ACTIVE)
                    {
                        void *value = atomic_load_explicit(&entry->value, memory_order_acquire);
                        int result = callback(entry->key, value, user_data);
                        count++;

                        lru_entry_release(entry, 0);

                        if (result != 0) break;
                    }
                    else
                    {
                        lru_entry_release(entry, 0);
                    }
                }
            }
        }
    }

    return count;
}