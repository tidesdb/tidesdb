#include "clock_cache.h"

#include "xxhash.h"

static uint64_t hash_key(const char *key, size_t key_len)
{
    return XXH64(key, key_len, 0);
}

/**
 * calculate_bucket_count
 * calculate optimal bucket count based on cache size
 * @param max_bytes maximum cache size in bytes
 * @return number of hash buckets
 */
static uint32_t calculate_bucket_count(size_t max_bytes)
{
    /* estimate maximum entries based on conservative average entry size */
    size_t estimated_max_entries = max_bytes / CACHE_ESTIMATED_ENTRY_SIZE;

    /* calculate target buckets for desired load factor */
    /* load_factor = entries / buckets, so buckets = entries / load_factor */
    size_t target_buckets = (size_t)((double)estimated_max_entries / CACHE_TARGET_LOAD_FACTOR);

    /* round up to next power of 2 for fast modulo using bitwise AND
     * power-of-2 allows -- hash % buckets = hash & (buckets - 1) */
    uint32_t buckets = CACHE_MIN_HASH_BUCKETS;
    while (buckets < target_buckets && buckets < CACHE_MAX_HASH_BUCKETS)
    {
        buckets <<= 1; /* multiply by 2 */
    }

    /* clamp to max if we exceeded it */
    if (buckets > CACHE_MAX_HASH_BUCKETS)
    {
        buckets = CACHE_MAX_HASH_BUCKETS;
    }

    return buckets;
}

/**
 * cache_entry_pool_create
 * create memory pool for cache entries
 * @param node_size size of each pool node
 * @param max_nodes maximum pool size
 * @return pointer to memory pool or NULL on failure
 */
static clock_cache_entry_pool_t *cache_entry_pool_create(size_t node_size, size_t max_nodes)
{
    clock_cache_entry_pool_t *pool = malloc(sizeof(clock_cache_entry_pool_t));
    if (!pool) return NULL;

    pool->node_size = node_size;
    pool->max_nodes = max_nodes;
    atomic_init(&pool->free_list, NULL);
    atomic_init(&pool->allocated_nodes, 0);
    atomic_init(&pool->pool_hits, 0);
    atomic_init(&pool->pool_misses, 0);

    return pool;
}

/**
 * cache_entry_pool_alloc
 * allocate entry from pool (lock-free)
 * @param pool pointer to memory pool
 * @return pointer to allocated entry or NULL on failure
 */
static void *cache_entry_pool_alloc(clock_cache_entry_pool_t *pool)
{
    if (!pool) return NULL;

    /* try to pop from free list (lock-free) */
    clock_cache_entry_pool_node_t *node;
    do
    {
        node = atomic_load_explicit(&pool->free_list, memory_order_acquire);
        if (node == NULL)
        {
            size_t current = atomic_load_explicit(&pool->allocated_nodes, memory_order_acquire);
            if (current >= pool->max_nodes)
            {
                atomic_fetch_add_explicit(&pool->pool_misses, 1, memory_order_relaxed);
                return malloc(pool->node_size);
            }

            node = malloc(sizeof(clock_cache_entry_pool_node_t) + pool->node_size);
            if (!node)
            {
                atomic_fetch_add_explicit(&pool->pool_misses, 1, memory_order_relaxed);
                return NULL;
            }

            atomic_fetch_add_explicit(&pool->allocated_nodes, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&pool->pool_hits, 1, memory_order_relaxed);
            return node->data;
        }
    } while (!atomic_compare_exchange_weak_explicit(&pool->free_list, &node, node->next,
                                                    memory_order_release, memory_order_acquire));

    /* successfully popped from free list */
    atomic_fetch_add_explicit(&pool->pool_hits, 1, memory_order_relaxed);
    return node->data;
}

/**
 * cache_entry_pool_free
 * return entry to pool (lock-free)
 * @param pool pointer to memory pool
 * @param ptr pointer to entry data
 */
static void cache_entry_pool_free(clock_cache_entry_pool_t *pool, void *ptr)
{
    if (!pool || !ptr) return;

    /* get node pointer from data pointer */
    clock_cache_entry_pool_node_t *node =
        (clock_cache_entry_pool_node_t *)((uint8_t *)ptr -
                                          offsetof(clock_cache_entry_pool_node_t, data));

    /* push to free list (lock-free) */
    clock_cache_entry_pool_node_t *old_head;
    do
    {
        old_head = atomic_load_explicit(&pool->free_list, memory_order_acquire);
        node->next = old_head;
    } while (!atomic_compare_exchange_weak_explicit(&pool->free_list, &old_head, node,
                                                    memory_order_release, memory_order_acquire));
}

/**
 * cache_entry_pool_destroy
 * destroy memory pool
 * @param pool pointer to memory pool
 */
static void cache_entry_pool_destroy(clock_cache_entry_pool_t *pool)
{
    if (!pool) return;

    /* free all nodes in free list */
    clock_cache_entry_pool_node_t *node =
        atomic_load_explicit(&pool->free_list, memory_order_acquire);
    while (node)
    {
        clock_cache_entry_pool_node_t *next = node->next;
        free(node);
        node = next;
    }

    free(pool);
}

/**
 * is_power_of_2
 * check if a number is power of 2
 * @param n number to check
 * @return 1 if power of 2, 0 otherwise
 */
static inline int is_power_of_2(uint32_t n)
{
    return n > 0 && (n & (n - 1)) == 0;
}

/**
 * hash_to_bucket
 * hash mixing function for better bucket distribution
 * @param hash hash value of the key
 * @param num_buckets number of hash buckets
 * @return bucket index
 */
static inline uint32_t hash_to_bucket(uint64_t hash, uint32_t num_buckets)
{
    /* fibonacci hashing for better distribution */
    /* multiply by golden ratio and shift to get upper bits */
    uint64_t mixed = hash * 11400714819323198485ULL;
    uint32_t h = (uint32_t)(mixed >> 32);

    if (is_power_of_2(num_buckets))
    {
        return h & (num_buckets - 1);
    }
    else
    {
        return h % num_buckets;
    }
}

/**
 * cache_entry_evict
 * eviction callback for buffer -- returns entry to pool or frees it
 * @param data pointer to entry data
 * @param ctx pointer to cache context
 */
static void cache_entry_evict(void *data, void *ctx)
{
    if (data == NULL) return;

    clock_cache_entry_t *entry = (clock_cache_entry_t *)data;
    clock_cache_t *cache = (clock_cache_t *)ctx;

    /* update current bytes */
    size_t entry_size = sizeof(clock_cache_entry_t) + entry->key_len + entry->payload_len;
    atomic_fetch_sub_explicit(&cache->current_bytes, entry_size, memory_order_relaxed);

    /* check allocation source using flag (safe - no memory access issues) */
    if (entry->from_pool && cache->entry_pool)
    {
        /* return to pool (lock-free, ~3ns) */
        cache_entry_pool_free(cache->entry_pool, entry);
    }
    else
    {
        /* was allocated with malloc, free it */
        free(entry);
    }
}

static void *eviction_thread_func(void *arg)
{
    clock_cache_t *cache = (clock_cache_t *)arg;
    uint32_t backoff_ms = cache->eviction_interval_ms;

    while (atomic_load_explicit(&cache->eviction_state, memory_order_acquire) ==
           CACHE_EVICTION_RUNNING)
    {
        /* check if eviction is needed */
        size_t current = atomic_load_explicit(&cache->current_bytes, memory_order_acquire);
        float fill_ratio = (float)current / (float)cache->max_bytes;

        if (fill_ratio >= cache->eviction_threshold)
        {
            /* CLOCK EVICTION -- sweep through slots using clock hand
             * if ref_bit == 0
                evict the entry
             * if ref_bit == 1
                give second chance (set to 0) and continue
             * this is O(n) worst case but typically much faster */

            size_t target_bytes = (size_t)(cache->max_bytes * cache->eviction_target);
            uint32_t evicted_count = 0;
            uint32_t max_sweeps = cache->num_slots * 2; /* prevent infinite loop */
            uint32_t sweeps = 0;

            while (sweeps < max_sweeps)
            {
                /* check if we've evicted enough */
                current = atomic_load_explicit(&cache->current_bytes, memory_order_acquire);
                if (current <= target_bytes) break;

                /* advance clock hand */
                uint32_t slot_id =
                    atomic_fetch_add_explicit(&cache->clock_hand, 1, memory_order_relaxed) %
                    cache->num_slots;
                sweeps++;

                /* get entry at this slot */
                clock_cache_entry_t *entry =
                    atomic_load_explicit(&cache->slots[slot_id].entry, memory_order_acquire);
                if (entry == NULL) continue; /* empty slot */

                /* check reference bit */
                uint8_t ref = atomic_load_explicit(&entry->ref_bit, memory_order_acquire);

                if (ref == 0)
                {
                    /* ref_bit is 0 -- evict this entry */
                    uint32_t bucket_idx = hash_to_bucket(entry->hash, cache->num_buckets);
                    clock_cache_hash_bucket_t *bucket = &cache->hash_table[bucket_idx];

                    /* remove from hash chain */
                    uint32_t current_slot =
                        atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
                    uint32_t prev_slot = CACHE_INVALID_SLOT_ID;

                    while (current_slot != CACHE_INVALID_SLOT_ID)
                    {
                        if (current_slot == slot_id)
                        {
                            /* found it -- update chain */
                            uint32_t next =
                                atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);

                            if (prev_slot == CACHE_INVALID_SLOT_ID)
                            {
                                /* update bucket head */
                                atomic_store_explicit(&bucket->head_slot_id, next,
                                                      memory_order_release);
                            }
                            else
                            {
                                /* update previous entry */
                                clock_cache_entry_t *prev_entry = atomic_load_explicit(
                                    &cache->slots[prev_slot].entry, memory_order_acquire);
                                if (prev_entry != NULL)
                                {
                                    atomic_store_explicit(&prev_entry->next_in_bucket, next,
                                                          memory_order_release);
                                }
                            }
                            break;
                        }

                        clock_cache_entry_t *chain_entry = atomic_load_explicit(
                            &cache->slots[current_slot].entry, memory_order_acquire);
                        if (chain_entry != NULL)
                        {
                            prev_slot = current_slot;
                            current_slot = atomic_load_explicit(&chain_entry->next_in_bucket,
                                                                memory_order_acquire);
                        }
                        else
                        {
                            break;
                        }
                    }

                    /* evict entry and free slot */
                    cache_entry_evict(entry, cache);
                    atomic_store_explicit(&cache->slots[slot_id].entry, NULL, memory_order_release);
                    atomic_fetch_sub_explicit(&cache->active_slots, 1, memory_order_relaxed);
                    evicted_count++;
                }
                else
                {
                    /* ref_bit is 1 - give second chance, clear the bit */
                    atomic_store_explicit(&entry->ref_bit, 0, memory_order_relaxed);
                }
            }

            /* reset backoff after successful eviction */
            backoff_ms = cache->eviction_interval_ms;
        }
        else
        {
            /* no eviction needed -- increase backoff */
            backoff_ms = backoff_ms * 2;
            if (backoff_ms > cache->max_backoff_ms)
            {
                backoff_ms = cache->max_backoff_ms;
            }
        }
        /* sleep with backoff */
        usleep(backoff_ms * 1000);
    }

    return NULL;
}

clock_cache_t *clock_cache_create(const cache_config_t *config)
{
    if (config == NULL || config->max_bytes == 0) return NULL;

    clock_cache_t *cache = malloc(sizeof(clock_cache_t));
    if (cache == NULL) return NULL;

    /* set configuration */
    cache->max_bytes = config->max_bytes;
    atomic_init(&cache->current_bytes, 0);

    /* calculate number of slots if not specified */
    uint32_t num_slots = config->num_slots;
    if (num_slots == 0)
    {
        /* estimate -- assume average entry is 1KB, allocate 2x for overhead */
        num_slots = (config->max_bytes / 1024) * 2;
        if (num_slots < 256) num_slots = 256;
        if (num_slots > 1000000) num_slots = 1000000;
    }

    cache->num_slots = num_slots;
    cache->slots = calloc(num_slots, sizeof(clock_cache_slot_t));
    if (cache->slots == NULL)
    {
        free(cache);
        return NULL;
    }

    for (uint32_t i = 0; i < num_slots; i++)
    {
        atomic_init(&cache->slots[i].entry, NULL);
    }

    atomic_init(&cache->next_slot, 0);
    atomic_init(&cache->active_slots, 0);
    atomic_init(&cache->clock_hand, 0);

    /* create hash table with dynamic sizing */
    if (config->num_buckets > 0)
    {
        /* user specified bucket count */
        cache->num_buckets = config->num_buckets;
    }
    else if (CACHE_DEFAULT_HASH_BUCKETS > 0)
    {
        /* use configured default */
        cache->num_buckets = CACHE_DEFAULT_HASH_BUCKETS;
    }
    else
    {
        /* auto-calculate based on cache size */
        cache->num_buckets = calculate_bucket_count(config->max_bytes);
    }

    cache->hash_table = calloc(cache->num_buckets, sizeof(clock_cache_hash_bucket_t));
    if (cache->hash_table == NULL)
    {
        free(cache->slots);
        free(cache);
        return NULL;
    }

    /* initialize hash buckets */
    for (uint32_t i = 0; i < cache->num_buckets; i++)
    {
        atomic_init(&cache->hash_table[i].head_slot_id, CACHE_INVALID_SLOT_ID);
    }

    /* create memory pool for cache entries
     * pool size = estimated max entries based on average entry size
     * node size = max entry size (entry + max key + max value)
     *
     * only enable pool for caches >= 1MB
     * small caches have too much overhead and the fixed node size causes issues */
    if (config->max_bytes >= 1024 * 1024) /* 1 MB minimum */
    {
        size_t estimated_max_entries = config->max_bytes / CACHE_ESTIMATED_ENTRY_SIZE;
        size_t max_pool_nodes = estimated_max_entries;
        size_t max_node_size =
            sizeof(clock_cache_entry_t) + 512 + 4096; /* entry + 512B key + 4KB value */

        cache->entry_pool = cache_entry_pool_create(max_node_size, max_pool_nodes);
        if (cache->entry_pool == NULL)
        {
            /* pool creation failed -- continue without pool (will use malloc) */
            cache->entry_pool = NULL;
        }
    }
    else
    {
        /* cache too small for pool -- use malloc */
        cache->entry_pool = NULL;
    }

    cache->eviction_interval_ms = config->eviction_interval_ms > 0
                                      ? config->eviction_interval_ms
                                      : CACHE_DEFAULT_EVICTION_INTERVAL_MS;
    cache->max_backoff_ms =
        config->max_backoff_ms > 0 ? config->max_backoff_ms : CACHE_DEFAULT_MAX_BACKOFF_MS;
    cache->eviction_threshold = config->eviction_threshold > 0 ? config->eviction_threshold
                                                               : CACHE_DEFAULT_EVICTION_THRESHOLD;
    cache->eviction_target =
        config->eviction_target > 0 ? config->eviction_target : CACHE_DEFAULT_EVICTION_TARGET;

    /* start eviction thread */
    atomic_init(&cache->eviction_state, CACHE_EVICTION_RUNNING);
    if (pthread_create(&cache->eviction_thread, NULL, eviction_thread_func, cache) != 0)
    {
        free(cache->hash_table);
        free(cache->slots);
        if (cache->entry_pool) cache_entry_pool_destroy(cache->entry_pool);
        free(cache);
        return NULL;
    }

    return cache;
}

void clock_cache_destroy(clock_cache_t *cache)
{
    if (cache == NULL) return;

    atomic_store_explicit(&cache->eviction_state, CACHE_EVICTION_STOPPED, memory_order_release);
    pthread_join(cache->eviction_thread, NULL);

    free(cache->hash_table);

    for (uint32_t i = 0; i < cache->num_slots; i++)
    {
        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[i].entry, memory_order_acquire);
        if (entry != NULL)
        {
            cache_entry_evict(entry, cache);
        }
    }

    free(cache->slots);

    if (cache->entry_pool)
    {
        cache_entry_pool_destroy(cache->entry_pool);
    }

    free(cache);
}

int clock_cache_put(clock_cache_t *cache, const char *key, size_t key_len, const uint8_t *payload,
                    size_t payload_len)
{
    if (cache == NULL || key == NULL || key_len == 0 || payload == NULL) return -1;

    uint64_t hash = hash_key(key, key_len);
    uint32_t bucket_idx = hash_to_bucket(hash, cache->num_buckets);
    clock_cache_hash_bucket_t *bucket = &cache->hash_table[bucket_idx];

    uint32_t current_slot = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
    while (current_slot != CACHE_INVALID_SLOT_ID)
    {
        if (current_slot >= cache->num_slots) break;

        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[current_slot].entry, memory_order_acquire);
        if (entry != NULL)
        {
            if (entry->hash == hash && entry->key_len == key_len &&
                memcmp(entry->key, key, key_len) == 0)
            {
                /* key exists -- check if we can update in place */
                if (entry->payload_len == payload_len)
                {
                    /* same size -- update in place */
                    memcpy(entry->payload, payload, payload_len);
                    atomic_store_explicit(&entry->ref_bit, 1,
                                          memory_order_relaxed); /* CLOCK -- mark as accessed */
                    return 0;
                }
                else
                {
                    /* different size -- need to delete and re-insert */
                    /* remove from hash chain first */
                    uint32_t next =
                        atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);

                    /* find and remove from chain */
                    uint32_t prev_slot = CACHE_INVALID_SLOT_ID;
                    uint32_t scan_slot =
                        atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);

                    while (scan_slot != CACHE_INVALID_SLOT_ID)
                    {
                        if (scan_slot == current_slot)
                        {
                            if (prev_slot == CACHE_INVALID_SLOT_ID)
                            {
                                /* update bucket head */
                                uint32_t expected = current_slot;
                                atomic_compare_exchange_strong_explicit(
                                    &bucket->head_slot_id, &expected, next, memory_order_release,
                                    memory_order_relaxed);
                            }
                            else
                            {
                                /* update previous entry */
                                clock_cache_entry_t *prev_entry = atomic_load_explicit(
                                    &cache->slots[prev_slot].entry, memory_order_acquire);
                                if (prev_entry != NULL)
                                {
                                    atomic_store_explicit(&prev_entry->next_in_bucket, next,
                                                          memory_order_release);
                                }
                            }
                            break;
                        }

                        clock_cache_entry_t *scan_entry = atomic_load_explicit(
                            &cache->slots[scan_slot].entry, memory_order_acquire);
                        if (scan_entry != NULL)
                        {
                            prev_slot = scan_slot;
                            scan_slot = atomic_load_explicit(&scan_entry->next_in_bucket,
                                                             memory_order_acquire);
                        }
                        else
                            break;
                    }

                    /* evict old entry and free slot */
                    cache_entry_evict(entry, cache);
                    atomic_store_explicit(&cache->slots[current_slot].entry, NULL,
                                          memory_order_release);
                    atomic_fetch_sub_explicit(&cache->active_slots, 1, memory_order_relaxed);

                    /* fall through to create new entry below */
                    break;
                }
            }

            current_slot = atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);
        }
        else
        {
            break;
        }
    }

    /* create new entry with single allocation (entry + key + payload)
     * use memory pool to avoid malloc overhead */
    size_t total_size = sizeof(clock_cache_entry_t) + key_len + payload_len;
    clock_cache_entry_t *entry;
    uint8_t from_pool = 0;

    if (cache->entry_pool && total_size <= cache->entry_pool->node_size)
    {
        /* allocate from pool (lock-free, ~5ns) */
        entry = (clock_cache_entry_t *)cache_entry_pool_alloc(cache->entry_pool);
        from_pool = 1;
    }
    else
    {
        /* fall back to malloc (~50ns) */
        entry = malloc(total_size);
        from_pool = 0;
    }

    if (entry == NULL) return -1;

    /* key and payload are stored immediately after the entry struct */
    entry->key = (uint8_t *)(entry + 1);
    entry->payload = entry->key + key_len;

    memcpy(entry->key, key, key_len);
    entry->key_len = key_len;

    memcpy(entry->payload, payload, payload_len);
    entry->payload_len = payload_len;

    entry->hash = hash;
    atomic_init(&entry->next_in_bucket, CACHE_INVALID_SLOT_ID);
    atomic_init(&entry->ref_bit, 1); /* CLOCK -- mark as recently accessed */
    entry->from_pool = from_pool;    /* track allocation source */

    uint32_t slot_id = CACHE_INVALID_SLOT_ID;
    uint32_t attempts = 0;
    uint32_t start_slot =
        atomic_fetch_add_explicit(&cache->next_slot, 1, memory_order_relaxed) % cache->num_slots;

    for (uint32_t i = 0; i < cache->num_slots && attempts < cache->num_slots; i++)
    {
        uint32_t try_slot = (start_slot + i) % cache->num_slots;
        clock_cache_entry_t *expected = NULL;

        /* we try to claim this slot with CAS */
        if (atomic_compare_exchange_weak_explicit(&cache->slots[try_slot].entry, &expected, entry,
                                                  memory_order_release, memory_order_relaxed))
        {
            slot_id = try_slot;
            atomic_fetch_add_explicit(&cache->active_slots, 1, memory_order_relaxed);
            break;
        }
        attempts++;
    }

    if (slot_id == CACHE_INVALID_SLOT_ID)
    {
        /* cache full - cleanup */
        if (from_pool && cache->entry_pool)
            cache_entry_pool_free(cache->entry_pool, entry);
        else
            free(entry);
        return -1;
    }

    /* add to hash chain with limited retries and adaptive backoff
     * this reduces CAS contention by failing fast and using randomized delays */
    uint32_t old_head;
    uint32_t backoff = CACHE_INITIAL_BACKOFF;
    uint32_t max_retries = CACHE_MAX_INSERT_RETRIES;
    uint32_t retry_count = 0;

    /* fast path -- try to claim empty bucket first (common case) */
    old_head = CACHE_INVALID_SLOT_ID;
    if (atomic_compare_exchange_strong_explicit(&bucket->head_slot_id, &old_head, slot_id,
                                                memory_order_release, memory_order_relaxed))
    {
        /* success! empty bucket claimed */
        atomic_store_explicit(&entry->next_in_bucket, CACHE_INVALID_SLOT_ID, memory_order_relaxed);
        goto insert_success;
    }

    /* slow path -- bucket has entries, need to prepend with CAS */
    while (retry_count < max_retries)
    {
        old_head = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
        atomic_store_explicit(&entry->next_in_bucket, old_head, memory_order_relaxed);

        if (atomic_compare_exchange_weak_explicit(&bucket->head_slot_id, &old_head, slot_id,
                                                  memory_order_release, memory_order_relaxed))
        {
            goto insert_success;
        }

        /* CAS failed -- adaptive backoff with randomization to reduce thundering herd */
        retry_count++;

        if (retry_count < CACHE_LOW_CONTENTION_THRESHOLD)
        {
            /* first few retries -- just pause */
            for (uint32_t i = 0; i < backoff; i++) cpu_pause();
            backoff = backoff * 2;
        }
        else if (retry_count < CACHE_MED_CONTENTION_THRESHOLD)
        {
            /* medium contention -- exponential backoff with jitter */
            uint32_t jitter = (uint32_t)rand() % backoff;
            for (uint32_t i = 0; i < (backoff + jitter); i++) cpu_pause();
            backoff = backoff * 2;
            if (backoff > CACHE_MAX_BACKOFF_PAUSES) backoff = CACHE_MAX_BACKOFF_PAUSES;
        }
        else
        {
            /* contention is wee bit high, yield to other threads */
            usleep(CACHE_HIGH_CONTENTION_SLEEP_US);
        }
    }

    /* failed after max retries -- this shouldnt happen often
     * fall back is to insert at a different position in the chain (append instead of prepend) */
    old_head = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
    if (old_head != CACHE_INVALID_SLOT_ID && old_head < cache->num_slots)
    {
        /* try to append to the end of the first entry's chain */
        clock_cache_entry_t *first_entry =
            atomic_load_explicit(&cache->slots[old_head].entry, memory_order_acquire);
        if (first_entry != NULL)
        {
            atomic_store_explicit(&entry->next_in_bucket, CACHE_INVALID_SLOT_ID,
                                  memory_order_relaxed);

            /* try to append */
            uint32_t expected_next = CACHE_INVALID_SLOT_ID;
            if (atomic_compare_exchange_strong_explicit(&first_entry->next_in_bucket,
                                                        &expected_next, slot_id,
                                                        memory_order_release, memory_order_relaxed))
            {
                goto insert_success;
            }
        }
    }

    /*just prepend with strong CAS (blocking) */
    do
    {
        old_head = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
        atomic_store_explicit(&entry->next_in_bucket, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_strong_explicit(&bucket->head_slot_id, &old_head, slot_id,
                                                      memory_order_release, memory_order_relaxed));

insert_success:

    /* update size tracking */
    size_t entry_size = sizeof(clock_cache_entry_t) + key_len + payload_len;
    atomic_fetch_add_explicit(&cache->current_bytes, entry_size, memory_order_relaxed);

    return 0;
}

uint8_t *clock_cache_get(clock_cache_t *cache, const char *key, size_t key_len, size_t *payload_len)
{
    if (cache == NULL || key == NULL || key_len == 0 || payload_len == NULL) return NULL;

    uint64_t hash = hash_key(key, key_len);
    uint32_t bucket_idx = hash_to_bucket(hash, cache->num_buckets);
    clock_cache_hash_bucket_t *bucket = &cache->hash_table[bucket_idx];

    uint32_t current_slot = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
    while (current_slot != CACHE_INVALID_SLOT_ID)
    {
        if (current_slot >= cache->num_slots) break;

        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[current_slot].entry, memory_order_acquire);
        if (entry != NULL)
        {
            /* prefetch next entry in chain to hide memory latency */
            uint32_t next_slot = atomic_load_explicit(&entry->next_in_bucket, memory_order_relaxed);
            if (next_slot != CACHE_INVALID_SLOT_ID && next_slot < cache->num_slots)
            {
                __builtin_prefetch(&cache->slots[next_slot], 0, 1); /* prefetch for read */
            }

            if (entry->hash == hash && entry->key_len == key_len &&
                memcmp(entry->key, key, key_len) == 0)
            {
                /* found -- mark as recently accessed (CLOCK) */
                atomic_store_explicit(&entry->ref_bit, 1, memory_order_relaxed);

                /* copy payload */
                uint8_t *result = malloc(entry->payload_len);
                if (result == NULL) return NULL;
                memcpy(result, entry->payload, entry->payload_len);
                *payload_len = entry->payload_len;

                return result;
            }

            current_slot = atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);
        }
        else
        {
            break;
        }
    }

    return NULL;
}

int clock_cache_delete(clock_cache_t *cache, const char *key, size_t key_len)
{
    if (cache == NULL || key == NULL || key_len == 0) return -1;

    uint64_t hash = hash_key(key, key_len);
    uint32_t bucket_idx = hash_to_bucket(hash, cache->num_buckets);
    clock_cache_hash_bucket_t *bucket = &cache->hash_table[bucket_idx];

    /* search for the entry in the hash chain */
    uint32_t current_slot = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
    uint32_t prev_slot = CACHE_INVALID_SLOT_ID;

    while (current_slot != CACHE_INVALID_SLOT_ID)
    {
        if (current_slot >= cache->num_slots) break;

        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[current_slot].entry, memory_order_acquire);
        if (entry != NULL)
        {
            if (entry->hash == hash && entry->key_len == key_len &&
                memcmp(entry->key, key, key_len) == 0)
            {
                /* found -- remove from chain using CAS */
                uint32_t next = atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);

                if (prev_slot == CACHE_INVALID_SLOT_ID)
                {
                    /* removing head of chain -- use CAS on bucket head */
                    uint32_t expected = current_slot;
                    if (!atomic_compare_exchange_strong_explicit(&bucket->head_slot_id, &expected,
                                                                 next, memory_order_release,
                                                                 memory_order_relaxed))
                    {
                        /* CAS failed -- chain was modified -- retry from beginning */
                        current_slot =
                            atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
                        prev_slot = CACHE_INVALID_SLOT_ID;
                        continue;
                    }
                }
                else
                {
                    /* removing from middle/end -- update previous entry's next pointer */
                    clock_cache_entry_t *prev_entry =
                        atomic_load_explicit(&cache->slots[prev_slot].entry, memory_order_acquire);
                    if (prev_entry != NULL)
                    {
                        uint32_t expected = current_slot;
                        if (!atomic_compare_exchange_strong_explicit(
                                &prev_entry->next_in_bucket, &expected, next, memory_order_release,
                                memory_order_relaxed))
                        {
                            /* CAS failed -- chain was modified -- retry from beginning */
                            current_slot =
                                atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
                            prev_slot = CACHE_INVALID_SLOT_ID;
                            continue;
                        }
                    }
                    else
                    {
                        /* previous entry disappeared -- retry from beginning */
                        current_slot =
                            atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
                        prev_slot = CACHE_INVALID_SLOT_ID;
                        continue;
                    }
                }

                /* successfully removed from chain -- free slot */
                cache_entry_evict(entry, cache);
                atomic_store_explicit(&cache->slots[current_slot].entry, NULL,
                                      memory_order_release);
                atomic_fetch_sub_explicit(&cache->active_slots, 1, memory_order_relaxed);

                return 0;
            }

            /* not a match -- continue to next */
            prev_slot = current_slot;
            current_slot = atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);
        }
        else
        {
            break;
        }
    }

    return -1;
}

int clock_cache_exists(clock_cache_t *cache, const char *key, size_t key_len)
{
    if (cache == NULL || key == NULL || key_len == 0) return 0;

    uint64_t hash = hash_key(key, key_len);
    uint32_t bucket_idx = hash_to_bucket(hash, cache->num_buckets);
    clock_cache_hash_bucket_t *bucket = &cache->hash_table[bucket_idx];

    /* search hash chain */
    uint32_t current_slot = atomic_load_explicit(&bucket->head_slot_id, memory_order_acquire);
    while (current_slot != CACHE_INVALID_SLOT_ID)
    {
        if (current_slot >= cache->num_slots) break;

        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[current_slot].entry, memory_order_acquire);
        if (entry != NULL)
        {
            if (entry->hash == hash && entry->key_len == key_len &&
                memcmp(entry->key, key, key_len) == 0)
            {
                return 1;
            }

            current_slot = atomic_load_explicit(&entry->next_in_bucket, memory_order_acquire);
        }
        else
        {
            break;
        }
    }

    return 0;
}

void clock_cache_clear(clock_cache_t *cache)
{
    if (cache == NULL) return;

    for (uint32_t i = 0; i < cache->num_buckets; i++)
    {
        atomic_store_explicit(&cache->hash_table[i].head_slot_id, CACHE_INVALID_SLOT_ID,
                              memory_order_release);
    }

    for (uint32_t i = 0; i < cache->num_slots; i++)
    {
        clock_cache_entry_t *entry =
            atomic_load_explicit(&cache->slots[i].entry, memory_order_acquire);
        if (entry != NULL)
        {
            cache_entry_evict(entry, cache);
            atomic_store_explicit(&cache->slots[i].entry, NULL, memory_order_release);
        }
    }

    atomic_store_explicit(&cache->active_slots, 0, memory_order_release);
}

void clock_cache_stats(clock_cache_t *cache, size_t *total_entries, size_t *total_bytes)
{
    if (cache == NULL) return;

    if (total_entries != NULL)
    {
        *total_entries = atomic_load_explicit(&cache->active_slots, memory_order_acquire);
    }

    if (total_bytes != NULL)
    {
        *total_bytes = atomic_load_explicit(&cache->current_bytes, memory_order_acquire);
    }
}

void clock_cache_stats_detailed(clock_cache_t *cache, size_t *total_entries, size_t *total_bytes,
                                uint32_t *num_buckets, float *load_factor)
{
    if (cache == NULL) return;

    size_t entries = 0;
    if (total_entries != NULL || load_factor != NULL)
    {
        entries = atomic_load_explicit(&cache->active_slots, memory_order_acquire);
        if (total_entries != NULL) *total_entries = entries;
    }

    if (total_bytes != NULL)
    {
        *total_bytes = atomic_load_explicit(&cache->current_bytes, memory_order_acquire);
    }

    if (num_buckets != NULL)
    {
        *num_buckets = cache->num_buckets;
    }

    if (load_factor != NULL)
    {
        *load_factor = cache->num_buckets > 0 ? (float)entries / (float)cache->num_buckets : 0.0f;
    }
}

void clock_cache_stats_pool(clock_cache_t *cache, size_t *pool_hits, size_t *pool_misses,
                            size_t *pool_allocated, size_t *pool_max, float *pool_hit_rate)
{
    if (cache == NULL || cache->entry_pool == NULL) return;

    size_t hits = atomic_load_explicit(&cache->entry_pool->pool_hits, memory_order_acquire);
    size_t misses = atomic_load_explicit(&cache->entry_pool->pool_misses, memory_order_acquire);
    size_t allocated =
        atomic_load_explicit(&cache->entry_pool->allocated_nodes, memory_order_acquire);

    if (pool_hits != NULL) *pool_hits = hits;
    if (pool_misses != NULL) *pool_misses = misses;
    if (pool_allocated != NULL) *pool_allocated = allocated;
    if (pool_max != NULL) *pool_max = cache->entry_pool->max_nodes;

    if (pool_hit_rate != NULL)
    {
        size_t total = hits + misses;
        *pool_hit_rate = total > 0 ? (float)hits / (float)total : 0.0f;
    }
}
