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
 * forward declarations
 */
static void lru_reclaim_retired(lru_cache_t *cache);

/**
 * thread-local hazard pointer record
 */
static THREAD_LOCAL lru_hazard_pointer_t *tls_hazard_record = NULL;

/**
 * lru_hazard_acquire
 * acquires a hazard pointer record for the current thread
 * @param cache the cache
 * @return hazard pointer record for this thread
 */
static lru_hazard_pointer_t *lru_hazard_acquire(lru_cache_t *cache)
{
    /* we check if we have a cached record and if it's still valid for this cache */
    if (tls_hazard_record != NULL)
    {
        lru_hazard_pointer_t *hp =
            atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
        while (hp != NULL)
        {
            if (hp == tls_hazard_record)
            {
                /* found it, still valid */
                return tls_hazard_record;
            }
            hp = atomic_load_explicit(&hp->next, memory_order_acquire);
        }
        /* not found, the cache was destroyed and recreated */
        tls_hazard_record = NULL;
    }

    /* we try to find an inactive record to reuse */
    lru_hazard_pointer_t *hp = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
    while (hp != NULL)
    {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(&hp->active, &expected, 1, memory_order_acq_rel,
                                                    memory_order_acquire))
        {
            /* success claimed this record */
            tls_hazard_record = hp;
            return hp;
        }
        hp = atomic_load_explicit(&hp->next, memory_order_acquire);
    }

    /* no inactive record found, allocate a new one */
    hp = (lru_hazard_pointer_t *)calloc(1, sizeof(lru_hazard_pointer_t));
    if (hp == NULL) return NULL;

    for (int i = 0; i < LRU_HAZARDS_PER_THREAD; i++)
    {
        atomic_init(&hp->pointers[i], NULL);
    }
    atomic_init(&hp->active, 1);

    /* add to the list */
    lru_hazard_pointer_t *head;
    do
    {
        head = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
        atomic_store_explicit(&hp->next, head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&cache->hazard_pointers, &head, hp,
                                                    memory_order_release, memory_order_relaxed));

    tls_hazard_record = hp;
    return hp;
}

/**
 * lru_hazard_protect
 * protects an entry pointer using a hazard pointer
 * @param hp hazard pointer record
 * @param slot which hazard pointer slot to use (0 or 1)
 * @param entry the entry to protect
 */
static inline void lru_hazard_protect(lru_hazard_pointer_t *hp, int slot, lru_entry_t *entry)
{
    atomic_store_explicit(&hp->pointers[slot], entry, memory_order_release);
}

/**
 * lru_hazard_clear
 * clears a hazard pointer slot
 * @param hp hazard pointer record
 * @param slot which hazard pointer slot to clear
 */
static inline void lru_hazard_clear(lru_hazard_pointer_t *hp, int slot)
{
    atomic_store_explicit(&hp->pointers[slot], NULL, memory_order_release);
}

/**
 * lru_hazard_scan
 * scans all hazard pointers to build a set of protected entries
 * @param cache the cache
 * @param protected output array of protected entries (caller must free)
 * @param count output count of protected entries
 */
static void lru_hazard_scan(lru_cache_t *cache, lru_entry_t ***protected, size_t *count)
{
    size_t hp_count = 0;
    lru_hazard_pointer_t *hp = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
    while (hp != NULL)
    {
        if (atomic_load_explicit(&hp->active, memory_order_acquire))
        {
            hp_count++;
        }
        hp = atomic_load_explicit(&hp->next, memory_order_acquire);
    }

    size_t max_protected = hp_count * LRU_HAZARDS_PER_THREAD;
    lru_entry_t **prot = (lru_entry_t **)malloc(max_protected * sizeof(lru_entry_t *));
    if (prot == NULL)
    {
        *protected = NULL;
        *count = 0;
        return;
    }

    /* collect all hazard pointers */
    size_t idx = 0;
    hp = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
    while (hp != NULL)
    {
        if (atomic_load_explicit(&hp->active, memory_order_acquire))
        {
            for (int i = 0; i < LRU_HAZARDS_PER_THREAD; i++)
            {
                lru_entry_t *entry = atomic_load_explicit(&hp->pointers[i], memory_order_acquire);
                if (entry != NULL)
                {
                    prot[idx++] = entry;
                }
            }
        }
        hp = atomic_load_explicit(&hp->next, memory_order_acquire);
    }

    *protected = prot;
    *count = idx;
}

/**
 * lru_is_protected
 * checks if an entry is protected by any hazard pointer
 * @param entry the entry to check
 * @param protected array of protected entries
 * @param count number of protected entries
 * @return 1 if protected, 0 otherwise
 */
static int lru_is_protected(lru_entry_t *entry, lru_entry_t **protected, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (protected[i] == entry) return 1;
    }
    return 0;
}

/**
 * lru_retire_entry
 * retires an entry for later reclamation
 * @param cache the cache
 * @param entry the entry to retire
 */
static void lru_retire_entry(lru_cache_t *cache, lru_entry_t *entry)
{
    atomic_store_explicit(&entry->retired, 1, memory_order_release);
    pthread_mutex_lock(&cache->retired_lock);

    lru_retired_entry_t *retired = (lru_retired_entry_t *)malloc(sizeof(lru_retired_entry_t));
    if (retired != NULL)
    {
        retired->entry = entry;
        retired->next = cache->retired_list;
        cache->retired_list = retired;
        atomic_fetch_add_explicit(&cache->retired_count, 1, memory_order_relaxed);
    }

    pthread_mutex_unlock(&cache->retired_lock);

    /* we try to reclaim if we have too many retired entries */
    size_t retired_count = atomic_load_explicit(&cache->retired_count, memory_order_relaxed);
    if (retired_count > cache->capacity)
    {
        lru_reclaim_retired(cache);
    }
}

/**
 * lru_reclaim_retired
 * attempts to reclaim retired entries that are no longer protected
 * @param cache the cache
 */
static void lru_reclaim_retired(lru_cache_t *cache)
{
    /* get list of protected entries */
    lru_entry_t **protected;
    size_t prot_count;
    lru_hazard_scan(cache, &protected, &prot_count);

    pthread_mutex_lock(&cache->retired_lock);

    lru_retired_entry_t *prev = NULL;
    lru_retired_entry_t *curr = cache->retired_list;
    lru_retired_entry_t *to_free_list = NULL;

    while (curr != NULL)
    {
        lru_retired_entry_t *next = curr->next;

        if (!lru_is_protected(curr->entry, protected, prot_count))
        {
            /* entry is not protected, can be freed */
            if (prev == NULL)
            {
                cache->retired_list = next;
            }
            else
            {
                prev->next = next;
            }

            /* add to free list (will free outside lock) */
            curr->next = to_free_list;
            to_free_list = curr;
            atomic_fetch_sub_explicit(&cache->retired_count, 1, memory_order_relaxed);
        }
        else
        {
            prev = curr;
        }

        curr = next;
    }

    pthread_mutex_unlock(&cache->retired_lock);

    while (to_free_list != NULL)
    {
        lru_retired_entry_t *next = to_free_list->next;
        lru_entry_t *entry = to_free_list->entry;

        if (entry->evict_cb)
        {
            void *value = atomic_load_explicit(&entry->value, memory_order_relaxed);
            if (value != NULL)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
        }

        free(entry->key);
        free(entry);
        free(to_free_list);
        to_free_list = next;
    }

    if (protected != NULL)
    {
        free(protected);
    }
}

/**
 * lru_entry_try_acquire
 * try to increment reference count on entry if it's still valid
 * Uses a CAS loop to safely increment only if ref_count > 0
 * @param entry the entry to acquire
 * @return true if acquired successfully, false if entry is being deleted (ref_count was 0)
 */
static inline int lru_entry_try_acquire(lru_entry_t *entry)
{
    uint32_t old_ref = atomic_load_explicit(&entry->ref_count, memory_order_acquire);
    do
    {
        if (old_ref == 0) return 0; /* entry is being freed or already freed */
    } while (!atomic_compare_exchange_weak_explicit(&entry->ref_count, &old_ref, old_ref + 1,
                                                    memory_order_acq_rel, memory_order_acquire));
    return 1;
}

/**
 * lru_entry_release
 * decrement reference count on entry, free if zero
 * @param entry the entry to release
 * @param call_evict whether to call eviction callback
 */
static void lru_entry_release(lru_entry_t *entry, int call_evict, lru_cache_t *cache)
{
    uint32_t old_ref = atomic_fetch_sub_explicit(&entry->ref_count, 1, memory_order_acq_rel);
    if (old_ref == 1)
    {
        /* we were the last reference, retire the entry for safe reclamation */
        atomic_thread_fence(memory_order_acquire);

        if (call_evict && entry->evict_cb)
        {
            void *value = atomic_load_explicit(&entry->value, memory_order_relaxed);
            if (value != NULL)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            /* NULL out value after calling callback */
            atomic_store_explicit(&entry->value, NULL, memory_order_release);
        }

        /* retire the entry instead of freeing immediately */
        lru_retire_entry(cache, entry);
    }
}

/**
 * lru_find_entry
 * find entry in hash table
 * @param cache the cache to search in
 * @param key the key to search for
 * @param key_len the length of the key
 * @return the entry if found (with ref count incremented), NULL otherwise
 */
static lru_entry_t *lru_find_entry(lru_cache_t *cache, const char *key, size_t key_len)
{
    size_t index = lru_hash(key, key_len, cache->table_size);
    int restart_count = 0;
    const int max_restarts = 100;

    /* acquire hazard pointer record for this thread */
    lru_hazard_pointer_t *hp = lru_hazard_acquire(cache);
    if (hp == NULL) return NULL;

restart:
    if (restart_count++ > max_restarts)
    {
        /* too much contention, give up */
        lru_hazard_clear(hp, 0);
        return NULL;
    }

    lru_entry_t *entry = atomic_load_explicit(&cache->table[index], memory_order_acquire);

    while (entry != NULL)
    {
        /* protect this entry with hazard pointer before accessing it */
        lru_hazard_protect(hp, 0, entry);

        /* mem barrier to ensure hazard pointer is visible before we access entry */
        atomic_thread_fence(memory_order_seq_cst);

        /* check if entry is retired -- if so, skip it */
        int is_retired = atomic_load_explicit(&entry->retired, memory_order_acquire);
        if (is_retired)
        {
            /* entry is retired, move to next */
            entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
            continue;
        }

        /* now try to acquire a reference */
        if (!lru_entry_try_acquire(entry))
        {
            /* entry is being freed, restart from head */
            goto restart;
        }

        /* we now hold a reference. check if the entry is still active. */
        lru_entry_state_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
        if (state == LRU_ENTRY_ACTIVE)
        {
            /* we check if this is our key */
            if (entry->key_len == key_len && memcmp(entry->key, key, key_len) == 0)
            {
                /* found it! we clear hazard pointer and return with reference held */
                lru_hazard_clear(hp, 0);
                return entry;
            }
        }

        /* not our key or not active. Move to next entry. */
        lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_acquire);

        /* rel the reference we acquired */
        lru_entry_release(entry, 0, cache);

        entry = next;
    }

    /* reached end of chain without finding the key */
    lru_hazard_clear(hp, 0);
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
            /* we try to acquire a reference before doing anything with the entry */
            if (!lru_entry_try_acquire(entry))
            {
                /* entry is being freed by another thread, skip it */
                hand = (hand + 1) % cache->capacity;
                if (hand == start_hand) passes++;
                continue;
            }

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
                        /* successfully marked for deletion */

                        /* rm from entries array first (prevents new lookups finding it here) */
                        lru_entry_t *expected_entry = entry;
                        atomic_compare_exchange_strong_explicit(
                            &cache->entries[hand], &expected_entry, NULL, memory_order_acq_rel,
                            memory_order_relaxed);

                        /* rm from hash table */
                        size_t hash_idx = lru_hash(entry->key, entry->key_len, cache->table_size);

                        /* rm from hash chain using CAS loop */
                        int removed = 0;
                        for (int attempts = 0; attempts < 100 && !removed; attempts++)
                        {
                            lru_entry_t *head =
                                atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);

                            if (head == entry)
                            {
                                /* entry is at head of chain */
                                lru_entry_t *next =
                                    atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
                                if (atomic_compare_exchange_strong_explicit(
                                        &cache->table[hash_idx], &head, next, memory_order_acq_rel,
                                        memory_order_relaxed))
                                {
                                    removed = 1;
                                }
                            }
                            else if (head != NULL)
                            {
                                /* search for entry in chain */
                                lru_entry_t *prev = head;
                                lru_entry_t *curr =
                                    atomic_load_explicit(&prev->hash_next, memory_order_acquire);
                                while (curr != NULL && curr != entry)
                                {
                                    prev = curr;
                                    curr = atomic_load_explicit(&curr->hash_next,
                                                                memory_order_acquire);
                                }
                                if (curr == entry)
                                {
                                    lru_entry_t *next = atomic_load_explicit(&entry->hash_next,
                                                                             memory_order_relaxed);
                                    lru_entry_t *expected_curr = curr;
                                    if (atomic_compare_exchange_strong_explicit(
                                            &prev->hash_next, &expected_curr, next,
                                            memory_order_acq_rel, memory_order_relaxed))
                                    {
                                        removed = 1;
                                    }
                                }
                                else
                                {
                                    /* entry not in chain (already removed by another thread) */
                                    removed = 1;
                                }
                            }
                            else
                            {
                                /* chain is empty (entry already removed) */
                                removed = 1;
                            }
                        }

                        /* decrement size */
                        atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

                        /* advance clock hand */
                        size_t next_hand = (hand + 1) % cache->capacity;
                        atomic_store_explicit(&cache->clock_hand, next_hand, memory_order_relaxed);

                        /* release our reference (from try_acquire above) */
                        lru_entry_release(entry, 0, cache);

                        /* release the entry initial reference (will free and call callback
                         * when all refs are gone) */
                        lru_entry_release(entry, 1, cache);

                        return 1;
                    }
                }
                else
                {
                    /* decrement access count (give it another chance) */
                    atomic_fetch_sub_explicit(&entry->access_count, 1, memory_order_relaxed);
                }
            }

            lru_entry_release(entry, 0, cache);
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

    cache->table =
        (_Atomic(lru_entry_t *) *)calloc(cache->table_size, sizeof(_Atomic(lru_entry_t *)));
    if (cache->table == NULL)
    {
        free(cache);
        return NULL;
    }

    cache->entries = (_Atomic(lru_entry_t *) *)calloc(capacity, sizeof(_Atomic(lru_entry_t *)));
    if (cache->entries == NULL)
    {
        free((void *)cache->table);
        free(cache);
        return NULL;
    }

    for (size_t i = 0; i < cache->table_size; i++)
    {
        atomic_init(&cache->table[i], NULL);
    }
    for (size_t i = 0; i < capacity; i++)
    {
        atomic_init(&cache->entries[i], NULL);
    }

    atomic_init(&cache->hazard_pointers, NULL);
    pthread_mutex_init(&cache->retired_lock, NULL);
    cache->retired_list = NULL;
    atomic_init(&cache->retired_count, 0);

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

        lru_entry_release(existing, 0, cache);
        return 1; /* updated */
    }

    /* need to insert new entry */
    size_t current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    while (current_size >= cache->capacity)
    {
        if (!lru_evict_one(cache))
        {
            /* couldn't evict, cache might be in bad state */
            if (evict_cb && value)
            {
                evict_cb(key, value, user_data);
            }
            return -1;
        }
        current_size = atomic_load_explicit(&cache->size, memory_order_relaxed);
    }

    lru_entry_t *entry = (lru_entry_t *)malloc(sizeof(lru_entry_t));
    if (entry == NULL)
    {
        if (evict_cb && value)
        {
            evict_cb(key, value, user_data);
        }
        return -1;
    }

    entry->key = tdb_strdup(key);
    if (entry->key == NULL)
    {
        free(entry);
        if (evict_cb && value)
        {
            evict_cb(key, value, user_data);
        }
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
    atomic_init(&entry->retired, 0); /* not retired initially */

    /* find a slot in entries array */
    size_t slot = lru_find_slot(cache);
    if (slot == SIZE_MAX)
    {
        /* no slot available, try evicting again */
        if (!lru_evict_one(cache))
        {
            /* call eviction callback before freeing to prevent value leak */
            if (entry->evict_cb && value)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            free(entry->key);
            free(entry);
            return -1;
        }
        slot = lru_find_slot(cache);
        if (slot == SIZE_MAX)
        {
            /* call eviction callback before freeing to prevent value leak */
            if (entry->evict_cb && value)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            free(entry->key);
            free(entry);
            return -1;
        }
    }

    /* add to entries array first */
    lru_entry_t *expected_null = NULL;
    if (!atomic_compare_exchange_strong_explicit(&cache->entries[slot], &expected_null, entry,
                                                 memory_order_acq_rel, memory_order_relaxed))
    {
        /* slot was taken by another thread, find another */
        slot = lru_find_slot(cache);
        if (slot == SIZE_MAX)
        {
            if (entry->evict_cb && value)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            free(entry->key);
            free(entry);
            return -1;
        }
        expected_null = NULL;
        if (!atomic_compare_exchange_strong_explicit(&cache->entries[slot], &expected_null, entry,
                                                     memory_order_acq_rel, memory_order_relaxed))
        {
            if (entry->evict_cb && value)
            {
                entry->evict_cb(entry->key, value, entry->user_data);
            }
            free(entry->key);
            free(entry);
            return -1;
        }
    }

    size_t hash_idx = lru_hash(key, key_len, cache->table_size);
    lru_entry_t *head;
    do
    {
        head = atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);
        atomic_store_explicit(&entry->hash_next, head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&cache->table[hash_idx], &head, entry,
                                                    memory_order_release, memory_order_relaxed));

    atomic_fetch_add_explicit(&cache->size, 1, memory_order_relaxed);

    lru_entry_t *curr = atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);
    while (curr != NULL)
    {
        if (curr != entry && curr->key_len == key_len && memcmp(curr->key, key, key_len) == 0)
        {
            /* found a dupe! we try acquire it to see if it's still valid */
            if (lru_entry_try_acquire(curr))
            {
                lru_entry_state_t state = atomic_load_explicit(&curr->state, memory_order_acquire);
                if (state == LRU_ENTRY_ACTIVE)
                {
                    /* theres an active duplicate. we need to remove our entry
                     * and update the existing one instead. */

                    /* mark our entry as deleted */
                    atomic_store_explicit(&entry->state, LRU_ENTRY_DELETED, memory_order_release);

                    /* remove our entry from hash chain */
                    lru_entry_t *prev = NULL;
                    lru_entry_t *scan =
                        atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);
                    while (scan != NULL && scan != entry)
                    {
                        prev = scan;
                        scan = atomic_load_explicit(&scan->hash_next, memory_order_acquire);
                    }
                    if (scan == entry)
                    {
                        lru_entry_t *next =
                            atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
                        if (prev == NULL)
                        {
                            atomic_compare_exchange_strong_explicit(&cache->table[hash_idx], &scan,
                                                                    next, memory_order_acq_rel,
                                                                    memory_order_relaxed);
                        }
                        else
                        {
                            atomic_store_explicit(&prev->hash_next, next, memory_order_release);
                        }
                    }

                    atomic_store_explicit(&cache->entries[slot], NULL, memory_order_release);

                    atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

                    /* atomically extract our value and NULL out entry->value */
                    void *our_value =
                        atomic_exchange_explicit(&entry->value, NULL, memory_order_acq_rel);

                    /* we detected a duplicate after insertion
                     * the existing entry wins, so we discard our entry and value
                     * call evict callback on our value to clean it up */
                    if (evict_cb && our_value)
                    {
                        evict_cb(key, our_value, user_data);
                    }

                    /* just bump access count on existing entry, don't update its value */
                    atomic_fetch_add_explicit(&curr->access_count, 1, memory_order_relaxed);

                    lru_entry_release(curr, 0, cache);
                    lru_entry_release(entry, 0, cache);

                    return 1; /* updated existing */
                }
                lru_entry_release(curr, 0, cache);
            }
        }
        curr = atomic_load_explicit(&curr->hash_next, memory_order_acquire);
    }

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

    lru_entry_release(entry, 0, cache);

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

    lru_entry_release(entry, 0, cache);

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
        lru_entry_release(entry, 0, cache);
        return -1;
    }

    /* remove from entries array first */
    for (size_t i = 0; i < cache->capacity; i++)
    {
        lru_entry_t *e = atomic_load_explicit(&cache->entries[i], memory_order_relaxed);
        if (e == entry)
        {
            lru_entry_t *expected_e = e;
            atomic_compare_exchange_strong_explicit(&cache->entries[i], &expected_e, NULL,
                                                    memory_order_acq_rel, memory_order_relaxed);
            break;
        }
    }

    /* remove from hash table */
    size_t hash_idx = lru_hash(key, key_len, cache->table_size);

    int removed = 0;
    for (int attempts = 0; attempts < 100 && !removed; attempts++)
    {
        lru_entry_t *head = atomic_load_explicit(&cache->table[hash_idx], memory_order_acquire);

        if (head == entry)
        {
            lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
            if (atomic_compare_exchange_strong_explicit(&cache->table[hash_idx], &head, next,
                                                        memory_order_acq_rel, memory_order_relaxed))
            {
                removed = 1;
            }
        }
        else if (head != NULL)
        {
            lru_entry_t *prev = head;
            lru_entry_t *curr = atomic_load_explicit(&prev->hash_next, memory_order_acquire);
            while (curr != NULL && curr != entry)
            {
                prev = curr;
                curr = atomic_load_explicit(&curr->hash_next, memory_order_acquire);
            }
            if (curr == entry)
            {
                lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);
                lru_entry_t *expected_curr = curr;
                if (atomic_compare_exchange_strong_explicit(&prev->hash_next, &expected_curr, next,
                                                            memory_order_acq_rel,
                                                            memory_order_relaxed))
                {
                    removed = 1;
                }
            }
            else
            {
                removed = 1; /* already removed */
            }
        }
        else
        {
            removed = 1; /* chain empty */
        }
    }

    atomic_fetch_sub_explicit(&cache->size, 1, memory_order_relaxed);

    /* release our reference (from find) */
    lru_entry_release(entry, 0, cache);

    /* release the entry's own reference (will call eviction callback when all refs gone) */
    lru_entry_release(entry, 1, cache);

    return 0;
}

void lru_cache_clear(lru_cache_t *cache)
{
    if (cache == NULL) return;

    for (size_t i = 0; i < cache->capacity; i++)
    {
        atomic_store_explicit(&cache->entries[i], NULL, memory_order_release);
    }

    for (size_t i = 0; i < cache->table_size; i++)
    {
        lru_entry_t *entry = atomic_exchange_explicit(&cache->table[i], NULL, memory_order_acq_rel);
        while (entry != NULL)
        {
            lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);

            int is_retired = atomic_load_explicit(&entry->retired, memory_order_acquire);
            if (!is_retired)
            {
                if (entry->evict_cb)
                {
                    void *value = atomic_load_explicit(&entry->value, memory_order_relaxed);
                    if (value != NULL)
                    {
                        entry->evict_cb(entry->key, value, entry->user_data);
                    }
                }
                free(entry->key);
                free(entry);
            }

            entry = next;
        }
    }

    atomic_store_explicit(&cache->size, 0, memory_order_release);
    atomic_store_explicit(&cache->clock_hand, 0, memory_order_release);
}

void lru_cache_free(lru_cache_t *cache)
{
    if (cache == NULL) return;

    lru_cache_clear(cache);

    for (int i = 0; i < 3; i++)
    {
        if (atomic_load_explicit(&cache->retired_count, memory_order_relaxed) == 0) break;
        lru_reclaim_retired(cache);
    }

    pthread_mutex_lock(&cache->retired_lock);
    lru_retired_entry_t *retired = cache->retired_list;
    while (retired != NULL)
    {
        lru_retired_entry_t *next = retired->next;
        if (retired->entry->evict_cb)
        {
            void *value = atomic_load_explicit(&retired->entry->value, memory_order_relaxed);
            if (value != NULL)
            {
                retired->entry->evict_cb(retired->entry->key, value, retired->entry->user_data);
            }
        }
        free(retired->entry->key);
        free(retired->entry);
        free(retired);
        retired = next;
    }
    cache->retired_list = NULL;
    atomic_store_explicit(&cache->retired_count, 0, memory_order_relaxed);
    pthread_mutex_unlock(&cache->retired_lock);

    lru_hazard_pointer_t *hp = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
    while (hp != NULL)
    {
        lru_hazard_pointer_t *next = atomic_load_explicit(&hp->next, memory_order_acquire);
        free(hp);
        hp = next;
    }

    pthread_mutex_destroy(&cache->retired_lock);
    free((void *)cache->table);
    free((void *)cache->entries);
    free(cache);
}

void lru_cache_destroy(lru_cache_t *cache)
{
    if (cache == NULL) return;

    /* we clear entries array first (just set to NULL, don't free yet) */
    for (size_t i = 0; i < cache->capacity; i++)
    {
        atomic_store_explicit(&cache->entries[i], NULL, memory_order_release);
    }

    /* we now iterate hash table and free all entries (without calling callbacks) */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        lru_entry_t *entry = atomic_exchange_explicit(&cache->table[i], NULL, memory_order_acq_rel);
        while (entry != NULL)
        {
            lru_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_relaxed);

            free(entry->key);
            free(entry);

            entry = next;
        }
    }

    pthread_mutex_lock(&cache->retired_lock);
    lru_retired_entry_t *retired = cache->retired_list;
    while (retired != NULL)
    {
        lru_retired_entry_t *next = retired->next;
        free(retired->entry->key);
        free(retired->entry);
        free(retired);
        retired = next;
    }
    pthread_mutex_unlock(&cache->retired_lock);

    lru_hazard_pointer_t *hp = atomic_load_explicit(&cache->hazard_pointers, memory_order_acquire);
    while (hp != NULL)
    {
        lru_hazard_pointer_t *next = atomic_load_explicit(&hp->next, memory_order_acquire);
        free(hp);
        hp = next;
    }

    pthread_mutex_destroy(&cache->retired_lock);
    free((void *)cache->table);
    free((void *)cache->entries);
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
            /* we try to acquire reference first, before checking state */
            if (lru_entry_try_acquire(entry))
            {
                /* verify still active after acquiring */
                lru_entry_state_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
                if (state == LRU_ENTRY_ACTIVE)
                {
                    void *value = atomic_load_explicit(&entry->value, memory_order_acquire);
                    int result = callback(entry->key, value, user_data);
                    count++;

                    lru_entry_release(entry, 0, cache);

                    if (result != 0) break;
                }
                else
                {
                    lru_entry_release(entry, 0, cache);
                }
            }
            /* if we couldn't acquire, entry is being freed, skip it */
        }
    }

    return count;
}