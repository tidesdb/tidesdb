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

#define CLOCK_CACHE_PARTITION_FULL_THRESHOLD 85
#define CLOCK_CACHE_YIELD_COUNT              1
#define CLOCK_CACHE_REF_BIT                  1u
#define CLOCK_CACHE_READER_INC               2u
#define CLOCK_CACHE_REF_MASK                 ((uint8_t)(~1u & 0xFFu))
#define CLOCK_CACHE_HAS_READERS(ref)         (((ref)&CLOCK_CACHE_REF_MASK) != 0)

/**
 * entry_size
 * compute total entry size
 * @param key_len key length
 * @param payload_len payload length
 * @return total entry size
 */
static inline size_t entry_size(const size_t key_len, const size_t payload_len)
{
    return key_len + payload_len + sizeof(clock_cache_entry_t);
}

/**
 * compute_hash
 * compute full hash for key
 * @param key the key
 * @param key_len the key length
 * @return hash
 */
static inline uint64_t compute_hash(const char *key, const size_t key_len)
{
    return XXH3_64bits(key, key_len);
}

/**
 * hash_table_insert
 * insert slot into hash index with linear probing
 * @param partition the partition
 * @param hash the hash
 * @param slot_idx the slot index
 */
static void hash_table_insert(clock_cache_partition_t *partition, uint64_t hash,
                              const size_t slot_idx)
{
    clock_cache_entry_t *slot = &partition->slots[slot_idx];

    /* we store hash in entry for verification */
    atomic_store_explicit(&slot->cached_hash, hash, memory_order_release);

    /* we insert into hash index with linear probing */
    const size_t idx = hash & partition->hash_mask;
    const size_t max_probe = (partition->hash_index_size < CLOCK_CACHE_MAX_HASH_PROBE)
                                 ? partition->hash_index_size
                                 : CLOCK_CACHE_MAX_HASH_PROBE;
    for (size_t probe = 0; probe < max_probe; probe++)
    {
        const size_t pos = (idx + probe) & partition->hash_mask;
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
 * hash_table_remove
 * remove slot from hash index
 * @param partition the partition
 * @param hash the hash
 * @param slot_idx the slot index
 */
static void hash_table_remove(clock_cache_partition_t *partition, const uint64_t hash,
                              const size_t slot_idx)
{
    const size_t idx = hash & partition->hash_mask;
    for (size_t probe = 0; probe < partition->hash_index_size; probe++)
    {
        const size_t pos = (idx + probe) & partition->hash_mask;
        int32_t current = atomic_load_explicit(&partition->hash_index[pos], memory_order_acquire);

        if (current == (int32_t)slot_idx)
        {
            atomic_store_explicit(&partition->hash_index[pos], -1, memory_order_release);
            return;
        }

        if (current == -1)
        {
            return;
        }
    }
}

/**
 * try_match_entry
 * @param entry the entry
 * @param key the key
 * @param key_len the key length
 * @param target_hash the target hash
 * @return the entry or NULL if not found
 */
static clock_cache_entry_t *try_match_entry(clock_cache_entry_t *entry, const char *key,
                                            size_t key_len, uint64_t target_hash)
{
    uint8_t state = atomic_load_explicit(&entry->state, memory_order_relaxed);
    if (state != ENTRY_VALID) return NULL;

    uint64_t entry_hash = atomic_load_explicit(&entry->cached_hash, memory_order_relaxed);
    if (entry_hash != target_hash) return NULL;

    size_t entry_key_len = atomic_load_explicit(&entry->key_len, memory_order_relaxed);
    if (entry_key_len != key_len) return NULL;

    atomic_fetch_add_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);

    uint8_t state_before = atomic_load_explicit(&entry->state, memory_order_acquire);
    if (state_before != ENTRY_VALID)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    char *entry_key_ptr = atomic_load_explicit(&entry->key, memory_order_acquire);
    if (!entry_key_ptr)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    entry_hash = atomic_load_explicit(&entry->cached_hash, memory_order_acquire);
    if (entry_hash != target_hash)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    entry_key_len = atomic_load_explicit(&entry->key_len, memory_order_acquire);
    if (entry_key_len != key_len)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    uint8_t state_check = atomic_load_explicit(&entry->state, memory_order_acquire);
    if (state_check != ENTRY_VALID)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    char *key_final = atomic_load_explicit(&entry->key, memory_order_acquire);
    if (!key_final || key_final != entry_key_ptr)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    const int match = (memcmp(key_final, key, key_len) == 0);

    atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);

    if (!match) return NULL;

    uint8_t state_after = atomic_load_explicit(&entry->state, memory_order_acquire);
    char *key_after = atomic_load_explicit(&entry->key, memory_order_acquire);

    if (state_after == ENTRY_VALID && key_after == key_final)
    {
        return entry;
    }

    return NULL;
}

static clock_cache_entry_t *find_entry_with_hash(clock_cache_partition_t *partition,
                                                 const char *key, const size_t key_len,
                                                 const uint64_t target_hash)
{
    const size_t idx = target_hash & partition->hash_mask;
    const size_t max_probe = (partition->hash_index_size < CLOCK_CACHE_MAX_HASH_PROBE)
                                 ? partition->hash_index_size
                                 : CLOCK_CACHE_MAX_HASH_PROBE;
    for (size_t probe = 0; probe < max_probe; probe++)
    {
        const size_t pos = (idx + probe) & partition->hash_mask;
        int32_t slot_idx = atomic_load_explicit(&partition->hash_index[pos], memory_order_relaxed);

        if (slot_idx == -1)
        {
            /* empty slot in index, entry not found */
            return NULL;
        }

        /* prefetch next probe's hash index entry to overlap with current try_match */
        if (probe + 1 < max_probe)
        {
            const size_t next_pos = (idx + probe + 1) & partition->hash_mask;
            PREFETCH_READ(&partition->hash_index[next_pos]);
        }

        PREFETCH_READ(&partition->slots[slot_idx]);
        clock_cache_entry_t *entry = &partition->slots[slot_idx];
        clock_cache_entry_t *match = try_match_entry(entry, key, key_len, target_hash);
        if (match) return match;
    }

    /* capped linear fallback -- scan limited slots instead of O(n) full scan
     * entries that overflowed the hash index are rare; full scan is too expensive */
    const size_t fallback_limit =
        (partition->num_slots < max_probe) ? partition->num_slots : max_probe;
    for (size_t i = 0; i < fallback_limit; i++)
    {
        PREFETCH_READ(&partition->slots[i]);
        clock_cache_entry_t *entry = &partition->slots[i];
        clock_cache_entry_t *match = try_match_entry(entry, key, key_len, target_hash);
        if (match) return match;
    }

    return NULL;
}

/**
 * free_entry
 * free entry contents -- lock-free with atomic state transitions
 * @param cache the cache
 * @param partition the partition
 * @param entry the entry
 */
static void free_entry(const clock_cache_t *cache, clock_cache_partition_t *partition,
                       clock_cache_entry_t *entry)
{
    /* we try to claim entry for deletion using CAS */
    uint8_t expected = ENTRY_VALID;
    if (!atomic_compare_exchange_strong(&entry->state, &expected, ENTRY_DELETING))
    {
        /* someone else is deleting or entry is already empty */
        return;
    }

    atomic_thread_fence(memory_order_seq_cst);

    for (int i = 0; i < CLOCK_CACHE_YIELD_COUNT; i++)
    {
        sched_yield();
    }

    char *key = atomic_load_explicit(&entry->key, memory_order_acquire);
    void *payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
    const size_t klen = atomic_load_explicit(&entry->key_len, memory_order_acquire);
    const size_t plen = atomic_load_explicit(&entry->payload_len, memory_order_acquire);

    if (!key || !payload)
    {
        /* invalid entry, just mark as empty */
        atomic_store_explicit(&entry->state, ENTRY_EMPTY, memory_order_release);
        return;
    }

    /* we check if entry is being read (upper bits indicate active readers) */
    atomic_thread_fence(memory_order_acq_rel);
    uint8_t ref = atomic_load_explicit(&entry->ref_bit, memory_order_acquire);
    if (CLOCK_CACHE_HAS_READERS(ref))
    {
        /* entry is being read by active readers, revert state and abort */
        atomic_store_explicit(&entry->state, ENTRY_VALID, memory_order_release);
        return;
    }

    /* mark hash entry as deleted (tombstone) -- but keep back-pointer for reuse
     * use cached hash to avoid redundant XXH3 recomputation */
    const uint64_t hash = atomic_load_explicit(&entry->cached_hash, memory_order_relaxed);
    const size_t slot_idx = entry - partition->slots;
    hash_table_remove(partition, hash, slot_idx);

    /* mem fence -- ensure all readers see deleted before we free (acq_rel sufficient) */
    atomic_thread_fence(memory_order_acq_rel);

    atomic_store_explicit(&entry->key, NULL, memory_order_release);
    atomic_store_explicit(&entry->payload, NULL, memory_order_release);

    /* fence to ensure pointer clears are visible before we free */
    atomic_thread_fence(memory_order_seq_cst);

    /* we must re-check ref_bit after clearing pointers, a reader may have snuck in
     * between our first check and clearing pointers */
    ref = atomic_load_explicit(&entry->ref_bit, memory_order_acquire);
    if (CLOCK_CACHE_HAS_READERS(ref))
    {
        /* a reader incremented ref_bit after we started deleting
         * restore pointers and revert state, we must let the reader finish */
        atomic_store_explicit(&entry->key, key, memory_order_release);
        atomic_store_explicit(&entry->payload, payload, memory_order_release);
        atomic_store_explicit(&entry->state, ENTRY_VALID, memory_order_release);
        hash_table_insert(partition, hash, slot_idx);
        return;
    }

    if (cache->evict_callback)
    {
        cache->evict_callback(payload, plen);
    }

    free(key);
    free(payload);
    atomic_store_explicit(&entry->key_len, 0, memory_order_release);
    atomic_store_explicit(&entry->payload_len, 0, memory_order_release);
    atomic_store_explicit(&entry->ref_bit, 0, memory_order_release);

    atomic_fetch_sub_explicit(&partition->occupied_count, 1, memory_order_relaxed);

    /* transition to empty state */
    atomic_store_explicit(&entry->state, ENTRY_EMPTY, memory_order_release);
}

/**
 * clock_evict
 * clock eviction
 * @param cache the cache
 * @param partition the partition
 * @return the slot index of the evicted entry
 */
static size_t clock_evict(const clock_cache_t *cache, clock_cache_partition_t *partition)
{
    size_t iterations = 0;
    const size_t max_iterations = partition->num_slots;

    /* we start from thread-local position to reduce contention on clock_hand */
    static THREAD_LOCAL size_t thread_hand = 0;
    if (thread_hand == 0)
    {
        thread_hand = (size_t)TDB_THREAD_ID();
        if (thread_hand == 0) thread_hand = 1; /* ensure non-zero */
    }
    const size_t start_pos = thread_hand % partition->num_slots;

    while (iterations < max_iterations)
    {
        /* we use local counter with occasional sync to global clock_hand */
        const size_t hand = (start_pos + iterations) % partition->num_slots;
        clock_cache_entry_t *entry = &partition->slots[hand];
        const size_t next_hand = (hand + 1) % partition->num_slots;
        PREFETCH_READ(&partition->slots[next_hand]);

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
            /* we check reference bit and active readers */
            uint8_t ref = atomic_load_explicit(&entry->ref_bit, memory_order_acquire);
            if (CLOCK_CACHE_HAS_READERS(ref))
            {
                if (ref & CLOCK_CACHE_REF_BIT)
                {
                    atomic_fetch_and_explicit(&entry->ref_bit, CLOCK_CACHE_REF_MASK,
                                              memory_order_relaxed);
                }
                iterations++;
                continue;
            }

            if ((ref & CLOCK_CACHE_REF_BIT) == 0)
            {
                /* found victim -- try to evict */
                PREFETCH_WRITE(entry);
                free_entry(cache, partition, entry);

                /* we update thread position for next time */
                thread_hand = hand + 1;
                return hand;
            }

            atomic_fetch_and_explicit(&entry->ref_bit, CLOCK_CACHE_REF_MASK, memory_order_relaxed);
        }

        iterations++;
    }

    /* we try to evict at current position as a fallback*/
    size_t hand =
        atomic_load_explicit(&partition->clock_hand, memory_order_acquire) % partition->num_slots;
    clock_cache_entry_t *entry = &partition->slots[hand];
    PREFETCH_WRITE(entry);
    uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);

    if (state == ENTRY_VALID)
    {
        free_entry(cache, partition, entry);
    }

    return hand;
}

/**
 * ensure_space
 * ensure space in partition
 * @param cache the cache
 * @param partition the partition
 * @param required_bytes the required bytes
 * @return 0 on success, -1 on failure
 */
static int ensure_space(const clock_cache_t *cache, clock_cache_partition_t *partition,
                        const size_t required_bytes)
{
    (void)required_bytes;

    /* we use cached occupied count instead of scanning all slots */
    size_t occupied = atomic_load_explicit(&partition->occupied_count, memory_order_relaxed);

    /* if partition is getting full (>CLOCK_CACHE_PARTITION_FULL_THRESHOLD%), evict one entry  */
    size_t threshold = (partition->num_slots * CLOCK_CACHE_PARTITION_FULL_THRESHOLD) / 100;
    if (occupied >= threshold)
    {
        clock_evict(cache, partition);
    }

    return 0;
}

void clock_cache_compute_config(const size_t max_bytes, cache_config_t *config)
{
    if (!config) return;

    const int num_cpus = tdb_get_cpu_count();

    size_t num_partitions = (size_t)num_cpus * CLOCK_CACHE_PARTITIONS_PER_CPU;
    if (num_partitions < CLOCK_CACHE_MIN_PARTITIONS) num_partitions = CLOCK_CACHE_MIN_PARTITIONS;
    if (num_partitions > CLOCK_CACHE_MAX_PARTITIONS) num_partitions = CLOCK_CACHE_MAX_PARTITIONS;

    /* we round up to next power of 2 for efficient masking */
    size_t p = 1;
    while (p < num_partitions) p <<= 1;
    num_partitions = p;

    const size_t avg_entry_size = CLOCK_CACHE_AVG_ENTRY_SIZE;
    size_t total_entries = max_bytes / avg_entry_size;
    if (total_entries < num_partitions) total_entries = num_partitions;

    /* we distribute entries across partitions */
    size_t slots_per_partition = total_entries / num_partitions;

    /* we clamp to reasonable range: 64-2048 slots per partition */
    if (slots_per_partition < CLOCK_CACHE_MIN_SLOTS_PER_PARTITION)
        slots_per_partition = CLOCK_CACHE_MIN_SLOTS_PER_PARTITION;
    if (slots_per_partition > CLOCK_CACHE_MAX_SLOTS_PER_PARTITION)
        slots_per_partition = CLOCK_CACHE_MAX_SLOTS_PER_PARTITION;

    /* we round up to next power of 2 for better memory alignment */
    size_t s = CLOCK_CACHE_MIN_SLOTS_PER_PARTITION;
    while (s < slots_per_partition) s <<= 1;
    slots_per_partition = s;

    config->max_bytes = max_bytes;
    config->num_partitions = num_partitions;
    config->slots_per_partition = slots_per_partition;
    config->evict_callback = NULL; /* no callback by default */
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
    cache->evict_callback = config->evict_callback;     /* store eviction callback */
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
        atomic_store_explicit(&partition->hits, 0, memory_order_relaxed);
        atomic_store_explicit(&partition->misses, 0, memory_order_relaxed);

        /* we calculate hash index size (1.5x slots for low collision rate) */
        partition->hash_index_size =
            (config->slots_per_partition * CLOCK_CACHE_HASH_INDEX_MULTIPLIER_NUM) /
            CLOCK_CACHE_HASH_INDEX_MULTIPLIER_DEN;
        /* we round up to next power of 2 */
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
                free((void *)cache->partitions[j].hash_index);
                free(cache->partitions[j].slots);
            }
            free(cache->partitions);
            free(cache);
            return NULL;
        }

        /* we initialize hash index to -1 (which is empty) */
        for (size_t j = 0; j < partition->hash_index_size; j++)
        {
            atomic_store_explicit(&partition->hash_index[j], -1, memory_order_relaxed);
        }

        /* we initialize all entry states to EMPTY */
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

        /* we link partitions */
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
            void *payload =
                atomic_load_explicit(&partition->slots[j].payload, memory_order_acquire);
            const size_t payload_len =
                atomic_load_explicit(&partition->slots[j].payload_len, memory_order_acquire);

            if (payload && cache->evict_callback)
            {
                cache->evict_callback(payload, payload_len);
            }

            if (key) free(key);
            if (payload) free(payload);
        }

        free((void *)partition->hash_index);
        free(partition->slots);
    }

    free(cache->partitions);
    free(cache);
}

int clock_cache_put(clock_cache_t *cache, const char *key, size_t key_len, const void *payload,
                    size_t payload_len)
{
    if (!cache || !key || key_len == 0 || !payload) return -1;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return -1;

    const uint64_t hash = compute_hash(key, key_len);
    const size_t partition_idx = (size_t)(hash & cache->partition_mask);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];
    const size_t entry_bytes = entry_size(key_len, payload_len);

    /* we try to find and invalidate existing entry (best-effort update) */
    clock_cache_entry_t *old_entry = find_entry_with_hash(partition, key, key_len, hash);
    if (old_entry)
    {
        /* we mark old entry as deleted to avoid duplicates */
        free_entry(cache, partition, old_entry);
    }

    /* we always ensure space to enforce max_bytes limit */
    ensure_space(cache, partition, entry_bytes);

    clock_cache_entry_t *entry = NULL;
    size_t slot_idx = 0;
    const int max_retries = CLOCK_CACHE_MAX_PUT_RETRIES;

    for (int retry = 0; retry < max_retries; retry++)
    {
        slot_idx = clock_evict(cache, partition);
        entry = &partition->slots[slot_idx];
        PREFETCH_WRITE(entry);

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
    void *new_payload = malloc(payload_len);

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
    atomic_store_explicit(&entry->ref_bit, CLOCK_CACHE_REF_BIT, memory_order_release);

    /* we transition to valid, entry is now visible */
    atomic_store_explicit(&entry->state, ENTRY_VALID, memory_order_release);

    atomic_fetch_add_explicit(&partition->occupied_count, 1, memory_order_relaxed);

    hash_table_insert(partition, hash, slot_idx);

    return 0;
}

uint8_t *clock_cache_get(clock_cache_t *cache, const char *key, const size_t key_len,
                         size_t *payload_len)
{
    if (!cache || !key || key_len == 0) return NULL;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return NULL;

    const uint64_t hash = compute_hash(key, key_len);
    const size_t partition_idx = (size_t)(hash & cache->partition_mask);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];

    clock_cache_entry_t *entry = find_entry_with_hash(partition, key, key_len, hash);

    if (!entry)
    {
        atomic_fetch_add_explicit(&partition->misses, 1, memory_order_relaxed);
        return NULL;
    }

    /* we increment ref_bit to protect entry from eviction during read */
    atomic_fetch_add_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);

    /* we verify entry is still valid after incrementing ref_bit */
    uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
    if (state != ENTRY_VALID)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    uint8_t *entry_payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
    size_t entry_payload_len = atomic_load_explicit(&entry->payload_len, memory_order_acquire);

    if (!entry_payload || entry_payload_len == 0)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    uint8_t *result = (uint8_t *)malloc(entry_payload_len);
    if (!result)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    uint8_t *payload_recheck = atomic_load_explicit(&entry->payload, memory_order_acquire);
    if (payload_recheck != entry_payload)
    {
        /* *** cleared or changed, abort *** */
        free(result);
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    memcpy(result, entry_payload, entry_payload_len);

    atomic_fetch_or_explicit(&entry->ref_bit, CLOCK_CACHE_REF_BIT, memory_order_relaxed);
    atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);

    if (payload_len) *payload_len = entry_payload_len;

    atomic_fetch_add_explicit(&partition->hits, 1, memory_order_relaxed);
    return result;
}

const uint8_t *clock_cache_get_zero_copy(clock_cache_t *cache, const char *key,
                                         const size_t key_len, size_t *payload_len,
                                         clock_cache_entry_t **entry_out)
{
    if (!cache || !key || key_len == 0) return NULL;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return NULL;

    const uint64_t hash = compute_hash(key, key_len);
    const size_t partition_idx = (size_t)(hash & cache->partition_mask);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];

    clock_cache_entry_t *entry = find_entry_with_hash(partition, key, key_len, hash);

    if (!entry)
    {
        atomic_fetch_add_explicit(&partition->misses, 1, memory_order_relaxed);
        return NULL;
    }

    /* we increment ref_bit to protect entry from eviction during use */
    atomic_fetch_add_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);

    /* we verify entry is still valid after incrementing ref_bit */
    uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
    if (state != ENTRY_VALID)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    uint8_t *entry_payload = atomic_load_explicit(&entry->payload, memory_order_acquire);
    size_t entry_payload_len = atomic_load_explicit(&entry->payload_len, memory_order_acquire);

    if (!entry_payload || entry_payload_len == 0)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    /* we need to re-verify payload pointer hasnt been cleared by free_entry */
    uint8_t *payload_recheck = atomic_load_explicit(&entry->payload, memory_order_acquire);
    if (payload_recheck != entry_payload)
    {
        atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
        return NULL;
    }

    if (payload_len) *payload_len = entry_payload_len;
    if (entry_out) *entry_out = entry;

    atomic_fetch_or_explicit(&entry->ref_bit, CLOCK_CACHE_REF_BIT, memory_order_relaxed);

    atomic_fetch_add_explicit(&partition->hits, 1, memory_order_relaxed);
    return entry_payload;
}

void clock_cache_release(clock_cache_entry_t *entry)
{
    if (!entry) return;
    atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC, memory_order_acq_rel);
}

int clock_cache_delete(clock_cache_t *cache, const char *key, const size_t key_len)
{
    if (!cache || !key || key_len == 0) return -1;

    if (atomic_load_explicit(&cache->shutdown, memory_order_acquire)) return -1;

    const uint64_t hash = compute_hash(key, key_len);
    const size_t partition_idx = (size_t)(hash & cache->partition_mask);
    clock_cache_partition_t *partition = &cache->partitions[partition_idx];

    clock_cache_entry_t *entry = find_entry_with_hash(partition, key, key_len, hash);

    if (!entry)
    {
        return -1;
    }

    free_entry(cache, partition, entry);

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
                free_entry(cache, partition, &partition->slots[j]);
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
                const size_t klen =
                    atomic_load_explicit(&partition->slots[j].key_len, memory_order_relaxed);
                const size_t plen =
                    atomic_load_explicit(&partition->slots[j].payload_len, memory_order_relaxed);
                total_bytes += entry_size(klen, plen);
                total_entries++;
            }
        }
    }

    stats->total_bytes = total_bytes;
    stats->total_entries = total_entries;

    /* sum per-partition counters to avoid false sharing on hot path */
    uint64_t total_hits = 0;
    uint64_t total_misses = 0;
    for (size_t i = 0; i < cache->num_partitions; i++)
    {
        total_hits += atomic_load_explicit(&cache->partitions[i].hits, memory_order_relaxed);
        total_misses += atomic_load_explicit(&cache->partitions[i].misses, memory_order_relaxed);
    }
    stats->hits = total_hits;
    stats->misses = total_misses;
    stats->num_partitions = cache->num_partitions;

    const uint64_t total_accesses = stats->hits + stats->misses;
    stats->hit_rate = (total_accesses > 0) ? ((double)stats->hits / (double)total_accesses) : 0.0;
}

size_t clock_cache_foreach_prefix(clock_cache_t *cache, const char *prefix, size_t prefix_len,
                                  const clock_cache_foreach_callback_t callback, void *user_data)
{
    if (!cache || !prefix || prefix_len == 0 || !callback) return 0;

    size_t count = 0;

    for (size_t p = 0; p < cache->num_partitions; p++)
    {
        clock_cache_partition_t *partition = &cache->partitions[p];

        for (size_t i = 0; i < partition->num_slots; i++)
        {
            clock_cache_entry_t *entry = &partition->slots[i];

            /* we check if entry is valid */
            uint8_t state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state != ENTRY_VALID) continue;

            /* we increment ref_bit to protect entry during access */
            atomic_fetch_add_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                      memory_order_acq_rel);

            /* * we re-verify state after incrementing ref_bit */
            state = atomic_load_explicit(&entry->state, memory_order_acquire);
            if (state != ENTRY_VALID)
            {
                atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                          memory_order_release);
                continue;
            }

            char *key_recheck = atomic_load_explicit(&entry->key, memory_order_acquire);
            size_t key_len = atomic_load_explicit(&entry->key_len, memory_order_acquire);
            if (!key_recheck || key_len < prefix_len)
            {
                atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                          memory_order_release);
                continue;
            }

            /* we check prefix match */
            if (memcmp(key_recheck, prefix, prefix_len) == 0)
            {
                const uint8_t *payload =
                    atomic_load_explicit(&entry->payload, memory_order_acquire);
                const size_t payload_len =
                    atomic_load_explicit(&entry->payload_len, memory_order_acquire);

                if (payload)
                {
                    atomic_fetch_or_explicit(&entry->ref_bit, CLOCK_CACHE_REF_BIT,
                                             memory_order_relaxed);
                    int result = callback(key_recheck, key_len, payload, payload_len, user_data);
                    count++;

                    atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                              memory_order_release);

                    if (result != 0) return count;
                }
                else
                {
                    atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                              memory_order_release);
                }
            }
            else
            {
                atomic_fetch_sub_explicit(&entry->ref_bit, CLOCK_CACHE_READER_INC,
                                          memory_order_release);
            }
        }
    }

    return count;
}
