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
#include "clock_cache.h"

#include "../external/xxhash.h"

/**
 * _entry_size
 * compute total entry size
 * @param key_len key length
 * @param payload_len payload length
 * @return total entry size
 */
static inline size_t _entry_size(size_t key_len, size_t payload_len)
{
    return key_len + payload_len + sizeof(clock_cache_entry_t);
}

/**
 * _hash_to_partition
 * hash key to partition index
 * @param cache the cache
 * @param key the key
 * @param key_len the key length
 * @return partition index
 */
static inline size_t _hash_to_partition(clock_cache_t *cache, const char *key, size_t key_len)
{
    uint64_t hash = XXH3_64bits(key, key_len);
    return (size_t)(hash & cache->partition_mask);
}

/**
 * _compute_hash
 * compute full hash for key
 * @param key the key
 * @param key_len the key length
 * @return hash
 */
static inline uint64_t _compute_hash(const char *key, size_t key_len)
{
    return XXH3_64bits(key, key_len);
}

/**
 * _hash_table_insert
 * insert slot into hash index with linear probing
 * @param partition the partition
 * @param hash the hash
 * @param slot_idx the slot index
 */
static void _hash_table_insert(clock_cache_partition_t *partition, uint64_t hash, size_t slot_idx)
{
    clock_cache_entry_t *slot = &partition->slots[slot_idx];

    /* we store hash in entry for verification */
    atomic_store_explicit(&slot->cached_hash, hash, memory_order_release);

    /* we insert into hash index with linear probing */
    size_t idx = hash & partition->hash_mask;
    size_t max_probe = (partition->hash_index_size < CLOCK_CACHE_MAX_HASH_PROBE)
                           ? partition->hash_index_size
                           : CLOCK_CACHE_MAX_HASH_PROBE;
    for (size_t probe = 0; probe < max_probe; probe++)
    {
        size_t pos = (idx + probe) & partition->hash_mask;
        int32_t expected = -1;

        /* we try to claim this hash index slot */
        if (atomic_compare_exchange_strong(&partition->hash_index[pos], &expected,
                                           (int32_t)slot_idx))
        {
            return;
        }

        /* we check if this slot already points to our entry (reuse case) */
        int32_t current = atomic_load_explicit(&partition->hash_index[pos], memory_order_relaxed);
        if (current == (int32_t)slot_idx)
        {
            return; /* already indexed */
        }
    }
}

/**
 * _hash_table_remove
 * remove slot from hash index
 * @param partition the partition
 * @param hash the hash
 * @param slot_idx the slot index
 */
static void _hash_table_remove(clock_cache_partition_t *partition, uint64_t hash, size_t slot_idx)
{
    /* gotta find and clear this slot from hash index */
    size_t idx = hash & partition->hash_mask;
    for (size_t probe = 0; probe < partition->hash_index_size; probe++)
    {
        size_t pos = (idx + probe) & partition->hash_mask;
        int32_t current = atomic_load_explicit(&partition->hash_index[pos], memory_order_acquire);

        if (current == (int32_t)slot_idx)
        {
            /* clear this index entry */
            atomic_store_explicit(&partition->hash_index[pos], -1, memory_order_release);
            return;
        }

        if (current == -1)
        {
            /* empty slot, entry not in index */
            return;
        }
    }
}

/**
 * _find_entry
 * find entry using hash index for O(1) lookup
 * @param partition the partition
 * @param key the key
 * @param key_len the key length
 * @param out_index output parameter for index
 * @return the entry or NULL if not found
 */
static clock_cache_entry_t *_find_entry(clock_cache_partition_t *partition, const char *key,
                                        size_t key_len, size_t *out_index)
{
    uint64_t target_hash = _compute_hash(key, key_len);
    size_t idx = target_hash & partition->hash_mask;
    size_t max_probe = (partition->hash_index_size < CLOCK_CACHE_MAX_HASH_PROBE)
                           ? partition->hash_index_size
                           : CLOCK_CACHE_MAX_HASH_PROBE;
    for (size_t probe = 0; probe < max_probe; probe++)
    {
        size_t pos = (idx + probe) & partition->hash_mask;
        int32_t slot_idx = atomic_load_explicit(&partition->hash_index[pos], memory_order_relaxed);

        if (slot_idx == -1)
        {
            /* empty slot in index, entry not found */
            return NULL;
        }

        clock_cache_entry_t *entry = &partition->slots[slot_idx];

        /* we check state first -- relaxed is fine, we validate later */
        uint8_t state = atomic_load_explicit(&entry->state, memory_order_relaxed);
        if (state != ENTRY_VALID) continue;

        /* we check cached hash matches -- relaxed */
        uint64_t entry_hash = atomic_load_explicit(&entry->cached_hash, memory_order_relaxed);
        if (entry_hash != target_hash) continue;

        /* we load key length -- relaxed */
        size_t entry_key_len = atomic_load_explicit(&entry->key_len, memory_order_relaxed);
        if (entry_key_len != key_len) continue;

        /* now key pointer with acquire for final validation */
        char *entry_key_ptr = atomic_load_explicit(&entry->key, memory_order_acquire);
        if (!entry_key_ptr) continue;

        if (memcmp(entry_key_ptr, key, key_len) == 0)
        {
            /* state didn't change during comparison? */
            uint8_t state_after = atomic_load_explicit(&entry->state, memory_order_acquire);
            char *key_after = atomic_load_explicit(&entry->key, memory_order_acquire);

            if (state_after == ENTRY_VALID && key_after == entry_key_ptr)
            {
                /* match confirmed and entry still valid */
                if (out_index) *out_index = slot_idx;
                return entry;
            }
        }
    }

    /* if hash index lookup failed, we do linear scan of all slots */
    /* this handles rare case where hash index was full during insert */

    for (size_t i = 0; i < partition->num_slots; i++)
    {
        clock_cache_entry_t *entry = &partition->slots[i];

        uint8_t state = atomic_load_explicit(&entry->state, memory_order_relaxed);
        if (state != ENTRY_VALID) continue;

        uint64_t entry_hash = atomic_load_explicit(&entry->cached_hash, memory_order_relaxed);
        if (entry_hash != target_hash) continue;

        size_t entry_key_len = atomic_load_explicit(&entry->key_len, memory_order_relaxed);
        if (entry_key_len != key_len) continue;

        char *entry_key_ptr = atomic_load_explicit(&entry->key, memory_order_acquire);
        if (!entry_key_ptr) continue;

        if (memcmp(entry_key_ptr, key, key_len) == 0)
        {
            uint8_t state_after = atomic_load_explicit(&entry->state, memory_order_acquire);
            char *key_after = atomic_load_explicit(&entry->key, memory_order_acquire);

            if (state_after == ENTRY_VALID && key_after == entry_key_ptr)
            {
                if (out_index) *out_index = i;
                return entry;
            }
        }
    }

    return NULL;
}

/**
 * _free_entry
 * free entry contents -- lock-free with atomic state transitions
 * @param cache the cache
 * @param partition the partition
 * @param entry the entry
 */
static void _free_entry(clock_cache_t *cache, clock_cache_partition_t *partition,
                        clock_cache_entry_t *entry)
{
    (void)cache;

    /* try to claim entry for deletion using CAS */
    uint8_t expected = ENTRY_VALID;
    if (!atomic_compare_exchange_strong(&entry->state, &expected, ENTRY_DELETING))
    {
        /* someone else is deleting or entry is already empty */
        return;
    }

    /* WE WON! we own this entry now, its our precious */

    /* load pointers and sizes */
    char *key = atomic_load_explicit(&entry->key, memory_order_acquire);
    uint8_t *payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
    size_t klen = atomic_load_explicit(&entry->key_len, memory_order_acquire);

    if (!key || !payload)
    {
        /* invalid entry, just mark as empty */
        atomic_store_explicit(&entry->state, ENTRY_EMPTY, memory_order_release);
        return;
    }

    /* mark hash entry as deleted (tombstone) -- but keep back-pointer for reuse */
    uint64_t hash = _compute_hash(key, klen);
    size_t slot_idx = entry - partition->slots;
    _hash_table_remove(partition, hash, slot_idx);

    /* mem fence -- ensure all readers see deleted before we free */
    atomic_thread_fence(memory_order_seq_cst);

    free(key);
    free(payload);

    /* clear pointers atomically -- but not hash_entry, we want to reuse it */
    atomic_store_explicit(&entry->key, NULL, memory_order_release);
    atomic_store_explicit(&entry->payload, NULL, memory_order_release);
    atomic_store_explicit(&entry->key_len, 0, memory_order_release);
    atomic_store_explicit(&entry->payload_len, 0, memory_order_release);
    atomic_store_explicit(&entry->ref_bit, 0, memory_order_release);
    /** hash_entry back-pointer is not cleared -- it stays for reuse */

    /* transistion to empty state */
    atomic_store_explicit(&entry->state, ENTRY_EMPTY, memory_order_release);
}

/**
 * _clock_evict
 * clock eviction
 * @param cache the cache
 * @param partition the partition
 * @return the slot index of the evicted entry
 */
static size_t _clock_evict(clock_cache_t *cache, clock_cache_partition_t *partition)
{
    size_t iterations = 0;
    size_t max_iterations = partition->num_slots * 2;

    /* start from thread-local position to reduce contention on clock_hand */
    static THREAD_LOCAL size_t thread_hand = 0;
    if (thread_hand == 0)
    {
        thread_hand = (size_t)TDB_THREAD_ID();
        if (thread_hand == 0) thread_hand = 1; /* ensure non-zero */
    }
    size_t start_pos = thread_hand % partition->num_slots;

    while (iterations < max_iterations)
    {
        /* we use local counter with occasional sync to global clock_hand */
        size_t hand = (start_pos + iterations) % partition->num_slots;
        clock_cache_entry_t *entry = &partition->slots[hand];

        /* we check state atomically */
        uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);

        if (state == ENTRY_EMPTY)
        {
            /* found empty slot -- update thread position for next time */
            thread_hand = hand + 1;
            return hand;
        }

        if (state == ENTRY_VALID)
        {
            /* we check reference bit */
            uint8_t ref = atomic_load_explicit(&entry->ref_bit, memory_order_acquire);

            if (ref == 0)
            {
                /* found victim -- try to evict */
                _free_entry(cache, partition, entry);

                /* update thread position for next time */
                thread_hand = hand + 1;
                return hand;
            }

            /* clear reference bit atomically */
            atomic_store_explicit(&entry->ref_bit, 0, memory_order_relaxed);
        }

        iterations++;
    }

    /* try to evict at current position as a fallback*/
    size_t hand =
        atomic_load_explicit(&partition->clock_hand, memory_order_acquire) % partition->num_slots;
    clock_cache_entry_t *entry = &partition->slots[hand];
    uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);

    if (state == ENTRY_VALID)
    {
        _free_entry(cache, partition, entry);
    }

    return hand;
}

/**
 * _ensure_space
 * ensure space in partition
 * @param cache the cache
 * @param partition the partition
 * @param required_bytes the required bytes
 * @return 0 on success, -1 on failure
 */
static int _ensure_space(clock_cache_t *cache, clock_cache_partition_t *partition,
                         size_t required_bytes)
{
    /* is partition completely full? */
    size_t occupied = 0;
    for (size_t j = 0; j < partition->num_slots; j++)
    {
        uint8_t state = atomic_load_explicit(&partition->slots[j].state, memory_order_relaxed);
        if (state == ENTRY_VALID || state == ENTRY_WRITING)
        {
            occupied++;
        }
    }

    int should_check_bytes = (partition->num_slots <= CLOCK_CACHE_SMALL_PARTITION_SLOTS);

    if (should_check_bytes)
    {
        /* compute total bytes across all partitions */
        size_t total_bytes = 0;
        for (size_t i = 0; i < cache->num_partitions; i++)
        {
            clock_cache_partition_t *p = &cache->partitions[i];
            for (size_t j = 0; j < p->num_slots; j++)
            {
                uint8_t state = atomic_load_explicit(&p->slots[j].state, memory_order_relaxed);
                if (state == ENTRY_VALID)
                {
                    size_t klen = atomic_load_explicit(&p->slots[j].key_len, memory_order_relaxed);
                    size_t plen =
                        atomic_load_explicit(&p->slots[j].payload_len, memory_order_relaxed);
                    total_bytes += _entry_size(klen, plen);
                }
            }
        }

        /* evict if we would exceed byte limit */
        while (total_bytes + required_bytes > cache->max_bytes)
        {
            /* find a partition with entries to evict */
            clock_cache_partition_t *evict_partition = NULL;
            for (size_t i = 0; i < cache->num_partitions; i++)
            {
                clock_cache_partition_t *p = &cache->partitions[i];
                for (size_t j = 0; j < p->num_slots; j++)
                {
                    uint8_t state = atomic_load_explicit(&p->slots[j].state, memory_order_relaxed);
                    if (state == ENTRY_VALID)
                    {
                        evict_partition = p;
                        goto found_partition;
                    }
                }
            }
        found_partition:

            if (!evict_partition) break;

            _clock_evict(cache, evict_partition);

            /* recompute total_bytes */
            total_bytes = 0;
            for (size_t i = 0; i < cache->num_partitions; i++)
            {
                clock_cache_partition_t *p = &cache->partitions[i];
                for (size_t j = 0; j < p->num_slots; j++)
                {
                    uint8_t state = atomic_load_explicit(&p->slots[j].state, memory_order_relaxed);
                    if (state == ENTRY_VALID)
                    {
                        size_t klen =
                            atomic_load_explicit(&p->slots[j].key_len, memory_order_relaxed);
                        size_t plen =
                            atomic_load_explicit(&p->slots[j].payload_len, memory_order_relaxed);
                        total_bytes += _entry_size(klen, plen);
                    }
                }
            }
        }
    }

    /* also evict if partition is completely full */
    if (occupied >= partition->num_slots)
    {
        _clock_evict(cache, partition);
    }

    return 0;
}

void clock_cache_compute_config(size_t max_bytes, cache_config_t *config)
{
    if (!config) return;

    /* CPU count for partition sizing */
    int num_cpus = tdb_get_cpu_count();

    /* heuristic is 1-2 partitions per CPU core, capped at 128 */
    size_t num_partitions = (size_t)num_cpus * CLOCK_CACHE_PARTITIONS_PER_CPU;
    if (num_partitions < CLOCK_CACHE_MIN_PARTITIONS) num_partitions = CLOCK_CACHE_MIN_PARTITIONS;
    if (num_partitions > CLOCK_CACHE_MAX_PARTITIONS) num_partitions = CLOCK_CACHE_MAX_PARTITIONS;

    /* we round up to next power of 2 for efficient masking */
    size_t p = 1;
    while (p < num_partitions) p <<= 1;
    num_partitions = p;

    /* estimate average entry size is ~100 bytes (key + payload + overhead) */
    const size_t avg_entry_size = CLOCK_CACHE_AVG_ENTRY_SIZE;
    size_t total_entries = max_bytes / avg_entry_size;
    if (total_entries < num_partitions) total_entries = num_partitions;

    /* distribute entries across partitions */
    size_t slots_per_partition = total_entries / num_partitions;

    /* Clamp to reasonable range: 64-2048 slots per partition */
    if (slots_per_partition < CLOCK_CACHE_MIN_SLOTS_PER_PARTITION)
        slots_per_partition = CLOCK_CACHE_MIN_SLOTS_PER_PARTITION;
    if (slots_per_partition > CLOCK_CACHE_MAX_SLOTS_PER_PARTITION)
        slots_per_partition = CLOCK_CACHE_MAX_SLOTS_PER_PARTITION;

    /* Round up to next power of 2 for better memory alignment */
    size_t s = CLOCK_CACHE_MIN_SLOTS_PER_PARTITION;
    while (s < slots_per_partition) s <<= 1;
    slots_per_partition = s;

    config->max_bytes = max_bytes;
    config->num_partitions = num_partitions;
    config->slots_per_partition = slots_per_partition;
}

clock_cache_t *clock_cache_create(const cache_config_t *config)
{
    if (!config || config->num_partitions == 0 || config->slots_per_partition == 0)
    {
        return NULL;
    }

    clock_cache_t *cache = (clock_cache_t *)calloc(1, sizeof(clock_cache_t));
    if (!cache) return NULL;

    cache->num_partitions = config->num_partitions;
    cache->max_bytes = config->max_bytes;
    cache->partition_mask = config->num_partitions - 1; /* assumes power of 2 */
    atomic_store_explicit(&cache->total_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&cache->hits, 0, memory_order_relaxed);
    atomic_store_explicit(&cache->misses, 0, memory_order_relaxed);
    atomic_store_explicit(&cache->shutdown, 0, memory_order_relaxed);

    cache->partitions =
        (clock_cache_partition_t *)calloc(config->num_partitions, sizeof(clock_cache_partition_t));
    if (!cache->partitions)
    {
        free(cache);
        return NULL;
    }

    for (size_t i = 0; i < config->num_partitions; i++)
    {
        clock_cache_partition_t *partition = &cache->partitions[i];
        partition->num_slots = config->slots_per_partition;
        atomic_store_explicit(&partition->clock_hand, 0, memory_order_relaxed);
        atomic_store_explicit(&partition->occupied_count, 0, memory_order_relaxed);
        atomic_store_explicit(&partition->bytes_used, 0, memory_order_relaxed);

        /* calculate hash index size (2x slots for low collision rate) */
        partition->hash_index_size =
            config->slots_per_partition * CLOCK_CACHE_HASH_INDEX_MULTIPLIER;
        /* round up to next power of 2 */
        size_t size = 1;
        while (size < partition->hash_index_size) size <<= 1;
        partition->hash_index_size = size;
        partition->hash_mask = size - 1;

        partition->slots =
            (clock_cache_entry_t *)calloc(config->slots_per_partition, sizeof(clock_cache_entry_t));
        if (!partition->slots)
        {
            for (size_t j = 0; j < i; j++)
            {
                free(cache->partitions[j].slots);
            }
            free(cache->partitions);
            free(cache);
            return NULL;
        }

        partition->hash_index =
            (_Atomic(int32_t) *)calloc(partition->hash_index_size, sizeof(_Atomic(int32_t)));
        if (!partition->hash_index)
        {
            free(partition->slots);
            for (size_t j = 0; j < i; j++)
            {
                free(cache->partitions[j].hash_index);
                free(cache->partitions[j].slots);
            }
            free(cache->partitions);
            free(cache);
            return NULL;
        }

        /* initialize hash index to -1 (empty) */
        for (size_t j = 0; j < partition->hash_index_size; j++)
        {
            atomic_store_explicit(&partition->hash_index[j], -1, memory_order_relaxed);
        }

        /* initialize all entry states to EMPTY */
        for (size_t j = 0; j < partition->num_slots; j++)
        {
            atomic_store_explicit(&partition->slots[j].state, ENTRY_EMPTY, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].key, NULL, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].payload, NULL, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].key_len, 0, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].payload_len, 0, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].ref_bit, 0, memory_order_relaxed);
            atomic_store_explicit(&partition->slots[j].cached_hash, 0, memory_order_relaxed);
        }

        /* link partitions */
        if (i > 0)
        {
            cache->partitions[i - 1].next = partition;
        }
        partition->next = NULL;
    }

    return cache;
}

void clock_cache_destroy(clock_cache_t *cache)
{
    if (!cache) return;

    /* set shutdown flag to prevent new operations */
    atomic_store_explicit(&cache->shutdown, 1, memory_order_release);

    /* mem fence, ensure all threads see shutdown flag */
    atomic_thread_fence(memory_order_seq_cst);

    for (size_t i = 0; i < cache->num_partitions; i++)
    {
        clock_cache_partition_t *partition = &cache->partitions[i];

        /* we mark all entries as deleting first to stop new accesses */
        for (size_t j = 0; j < partition->num_slots; j++)
        {
            uint8_t state = atomic_load_explicit(&partition->slots[j].state, memory_order_acquire);
            if (state == ENTRY_VALID || state == ENTRY_WRITING)
            {
                atomic_store_explicit(&partition->slots[j].state, ENTRY_DELETING,
                                      memory_order_release);
            }
        }

        /* mem fence -- ensure all readers see DELETING state */
        atomic_thread_fence(memory_order_seq_cst);

        for (size_t j = 0; j < partition->num_slots; j++)
        {
            char *key = atomic_load_explicit(&partition->slots[j].key, memory_order_acquire);
            uint8_t *payload =
                atomic_load_explicit(&partition->slots[j].payload, memory_order_acquire);
            if (key) free(key);
            if (payload) free(payload);
        }

        free(partition->hash_index);
        free(partition->slots);
    }

    free(cache->partitions);
    free(cache);
    cache = NULL;
}

int clock_cache_put(clock_cache_t *cache, const char *key, size_t key_len, const uint8_t *payload,
                    size_t payload_len)
{
    if (!cache || !key || key_len == 0 || !payload) return -1;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return -1;

    size_t partition_idx = _hash_to_partition(cache, key, key_len);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];
    uint64_t hash = _compute_hash(key, key_len);
    size_t entry_bytes = _entry_size(key_len, payload_len);

    /* try to find and invalidate existing entry (best-effort update) */
    clock_cache_entry_t *old_entry = _find_entry(partition, key, key_len, NULL);
    if (old_entry)
    {
        /* mark old entry as deleted to avoid duplicates */
        _free_entry(cache, partition, old_entry);
    }

    if (partition->num_slots <= CLOCK_CACHE_SMALL_PARTITION_SLOTS)
    {
        _ensure_space(cache, partition, entry_bytes);
    }

    clock_cache_entry_t *entry = NULL;
    size_t slot_idx = 0;
    int max_retries = CLOCK_CACHE_MAX_PUT_RETRIES;

    for (int retry = 0; retry < max_retries; retry++)
    {
        slot_idx = _clock_evict(cache, partition);
        entry = &partition->slots[slot_idx];

        /* we try to claim slot with CAS, EMPTY --> WRITING */
        uint8_t expected = ENTRY_EMPTY;
        if (atomic_compare_exchange_strong(&entry->state, &expected, ENTRY_WRITING))
        {
            /* got it */
            break;
        }

        /* someone else claimed it, try again */
        entry = NULL;
    }

    if (!entry)
    {
        /* failed to claim slot after retries */
        return -1;
    }

    /* we own the slot now, allocate and fill */
    char *new_key = (char *)malloc(key_len);
    uint8_t *new_payload = (uint8_t *)malloc(payload_len);

    if (!new_key || !new_payload)
    {
        free(new_key);
        free(new_payload);
        atomic_store_explicit(&entry->state, ENTRY_EMPTY, memory_order_release);
        return -1;
    }

    memcpy(new_key, key, key_len);
    memcpy(new_payload, payload, payload_len);

    atomic_store_explicit(&entry->key, new_key, memory_order_release);
    atomic_store_explicit(&entry->payload, new_payload, memory_order_release);
    atomic_store_explicit(&entry->key_len, key_len, memory_order_release);
    atomic_store_explicit(&entry->payload_len, payload_len, memory_order_release);
    atomic_store_explicit(&entry->ref_bit, 1, memory_order_release);

    /* transition to valid, entry is now visible */
    atomic_store_explicit(&entry->state, ENTRY_VALID, memory_order_release);

    /* add to hash index after entry is valid */
    _hash_table_insert(partition, hash, slot_idx);

    return 0;
}

uint8_t *clock_cache_get(clock_cache_t *cache, const char *key, size_t key_len, size_t *payload_len)
{
    if (!cache || !key || key_len == 0) return NULL;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return NULL;

    size_t partition_idx = _hash_to_partition(cache, key, key_len);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];

    clock_cache_entry_t *entry = _find_entry(partition, key, key_len, NULL);

    if (!entry)
    {
        return NULL;
    }

    uint8_t *entry_payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
    size_t entry_payload_len = atomic_load_explicit(&entry->payload_len, memory_order_acquire);

    if (!entry_payload || entry_payload_len == 0)
    {
        return NULL;
    }

    uint8_t *result = (uint8_t *)malloc(entry_payload_len);
    if (!result) return NULL;

    memcpy(result, entry_payload, entry_payload_len);

    /* state didnt change during copy? */
    uint8_t final_state = atomic_load_explicit(&entry->state, memory_order_acquire);
    if (final_state != ENTRY_VALID)
    {
        /* state changed, entry being deleted */
        free(result);
        return NULL;
    }

    if (payload_len) *payload_len = entry_payload_len;

    /* set reference bit atomically */
    atomic_store_explicit(&entry->ref_bit, 1, memory_order_relaxed);

    /* skip global hit counter -- too much contention */
    return result;
}

int clock_cache_delete(clock_cache_t *cache, const char *key, size_t key_len)
{
    if (!cache || !key || key_len == 0) return -1;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return -1;

    size_t partition_idx = _hash_to_partition(cache, key, key_len);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];

    clock_cache_entry_t *entry = _find_entry(partition, key, key_len, NULL);

    if (!entry)
    {
        return -1;
    }

    _free_entry(cache, partition, entry);

    return 0;
}

void clock_cache_clear(clock_cache_t *cache)
{
    if (!cache) return;

    for (size_t i = 0; i < cache->num_partitions; i++)
    {
        clock_cache_partition_t *partition = &cache->partitions[i];

        for (size_t j = 0; j < partition->num_slots; j++)
        {
            uint8_t state = atomic_load_explicit(&partition->slots[j].state, memory_order_acquire);
            if (state == ENTRY_VALID)
            {
                _free_entry(cache, partition, &partition->slots[j]);
            }
        }
    }

    atomic_store_explicit(&cache->total_bytes, 0, memory_order_relaxed);
}

void clock_cache_get_stats(clock_cache_t *cache, clock_cache_stats_t *stats)
{
    if (!cache || !stats) return;

    size_t total_bytes = 0;
    size_t total_entries = 0;
    for (size_t i = 0; i < cache->num_partitions; i++)
    {
        clock_cache_partition_t *partition = &cache->partitions[i];
        for (size_t j = 0; j < partition->num_slots; j++)
        {
            uint8_t state = atomic_load_explicit(&partition->slots[j].state, memory_order_relaxed);
            if (state == ENTRY_VALID)
            {
                size_t klen =
                    atomic_load_explicit(&partition->slots[j].key_len, memory_order_relaxed);
                size_t plen =
                    atomic_load_explicit(&partition->slots[j].payload_len, memory_order_relaxed);
                total_bytes += _entry_size(klen, plen);
                total_entries++;
            }
        }
    }

    stats->total_bytes = total_bytes;
    stats->total_entries = total_entries;
    stats->hits = atomic_load_explicit(&cache->hits, memory_order_relaxed);
    stats->misses = atomic_load_explicit(&cache->misses, memory_order_relaxed);
    stats->num_partitions = cache->num_partitions;

    uint64_t total_accesses = stats->hits + stats->misses;
    stats->hit_rate = (total_accesses > 0) ? ((double)stats->hits / total_accesses) : 0.0;
}

size_t clock_cache_foreach_prefix(clock_cache_t *cache, const char *prefix, size_t prefix_len,
                                  clock_cache_foreach_callback_t callback, void *user_data)
{
    if (!cache || !prefix || prefix_len == 0 || !callback) return 0;

    size_t count = 0;

    /* iterate over all partitions */
    for (size_t p = 0; p < cache->num_partitions; p++)
    {
        clock_cache_partition_t *partition = &cache->partitions[p];

        /* iterate over all slots in this partition */
        for (size_t i = 0; i < partition->num_slots; i++)
        {
            clock_cache_entry_t *entry = &partition->slots[i];

            /* check if entry is valid */
            uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state != ENTRY_VALID) continue;

            /* get key atomically */
            char *key = atomic_load_explicit(&entry->key, memory_order_acquire);
            size_t key_len = atomic_load_explicit(&entry->key_len, memory_order_acquire);

            if (!key || key_len < prefix_len) continue;

            /* check prefix match */
            if (memcmp(key, prefix, prefix_len) == 0)
            {
                /* get payload atomically */
                uint8_t *payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
                size_t payload_len =
                    atomic_load_explicit(&entry->payload_len, memory_order_acquire);

                if (payload)
                {
                    /* call callback */
                    int result = callback(key, key_len, payload, payload_len, user_data);
                    count++;

                    /* stop if callback returns non-zero */
                    if (result != 0) return count;
                }
            }
        }
    }

    return count;
}
