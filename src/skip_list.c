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

#include "skip_list.h"

/**
 * skip_list_compare_keys_numeric_inline
 * fast inline comparison for 8-byte numeric keys
 * @param key1 first key
 * @param key2 second key
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int skip_list_compare_keys_numeric_inline(const uint8_t *key1, const uint8_t *key2)
{
    uint64_t v1, v2;
    memcpy(&v1, key1, sizeof(uint64_t));
    memcpy(&v2, key2, sizeof(uint64_t));
    return (v1 < v2) ? -1 : (v1 > v2);
}

/**
 * skip_list_compare_keys_16_inline
 * fast inline comparison for 16-byte keys
 * @param key1 first key
 * @param key2 second key
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int skip_list_compare_keys_16_inline(const uint8_t *key1, const uint8_t *key2)
{
    /* we compare high 8 bytes first -- the most discriminating for sorted data */
    uint64_t v1_hi, v2_hi;
    memcpy(&v1_hi, key1, sizeof(uint64_t));
    memcpy(&v2_hi, key2, sizeof(uint64_t));

    if (v1_hi != v2_hi) return (v1_hi < v2_hi) ? -1 : 1;

    /* only load low bytes if high bytes are equal */
    uint64_t v1_lo, v2_lo;
    memcpy(&v1_lo, key1 + 8, sizeof(uint64_t));
    memcpy(&v2_lo, key2 + 8, sizeof(uint64_t));

    if (v1_lo != v2_lo) return (v1_lo < v2_lo) ? -1 : 1;
    return 0;
}

/**
 * skip_list_compare_keys_32_inline
 * fast inline comparison for 32-byte keys (e.g., SHA-256 hashes)
 * @param key1 first key
 * @param key2 second key
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int skip_list_compare_keys_32_inline(const uint8_t *key1, const uint8_t *key2)
{
    /* we compare 8 bytes at a time, early exit on first difference */
    uint64_t v1, v2;

    memcpy(&v1, key1, sizeof(uint64_t));
    memcpy(&v2, key2, sizeof(uint64_t));
    if (v1 != v2) return (v1 < v2) ? -1 : 1;

    memcpy(&v1, key1 + 8, sizeof(uint64_t));
    memcpy(&v2, key2 + 8, sizeof(uint64_t));
    if (v1 != v2) return (v1 < v2) ? -1 : 1;

    memcpy(&v1, key1 + 16, sizeof(uint64_t));
    memcpy(&v2, key2 + 16, sizeof(uint64_t));
    if (v1 != v2) return (v1 < v2) ? -1 : 1;

    memcpy(&v1, key1 + 24, sizeof(uint64_t));
    memcpy(&v2, key2 + 24, sizeof(uint64_t));
    if (v1 != v2) return (v1 < v2) ? -1 : 1;

    return 0;
}

/**
 * skip_list_get_latest_valid_version
 * fast path for accessing the latest valid version
 */
static inline int skip_list_version_is_invalid_with_time(skip_list_version_t *version,
                                                         int64_t current_time);

static inline skip_list_version_t *skip_list_get_latest_valid_version(skip_list_node_t *node,
                                                                      const int64_t current_time)
{
    skip_list_version_t *version = atomic_load_explicit(&node->versions, memory_order_acquire);

    if (SKIP_LIST_UNLIKELY(version == NULL)) return NULL;
    skip_list_version_t *next = atomic_load_explicit(&version->next, memory_order_relaxed);
    if (SKIP_LIST_LIKELY(next == NULL))
    {
        if (!skip_list_version_is_invalid_with_time(version, current_time))
        {
            return version;
        }
        return NULL;
    }

    while (version != NULL)
    {
        if (!skip_list_version_is_invalid_with_time(version, current_time))
        {
            return version;
        }
        version = atomic_load_explicit(&version->next, memory_order_acquire);
    }

    return NULL;
}

/**
 * skip_list_free_version
 * frees a single version
 * @param version version to free
 */
static void skip_list_free_version(skip_list_version_t *version);

/**
 * skip_list_compare_keys_inline
 * inline comparator for hot paths
 * uses cmp_type enum to avoid function pointer comparison overhead
 * @param list skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int skip_list_compare_keys_inline(const skip_list_t *list, const uint8_t *key1,
                                                const size_t key1_size, const uint8_t *key2,
                                                const size_t key2_size)
{
    /* fast path for most common case -- memcmp with equal-sized keys */
    if (SKIP_LIST_LIKELY(list->cmp_type == SKIP_LIST_CMP_MEMCMP))
    {
        if (SKIP_LIST_LIKELY(key1_size == key2_size))
        {
            /* we use switch for common key sizes to help branch predictor */
            switch (key1_size)
            {
                case 8:
                    return skip_list_compare_keys_numeric_inline(key1, key2);
                case 16:
                    return skip_list_compare_keys_16_inline(key1, key2);
                case 32:
                    return skip_list_compare_keys_32_inline(key1, key2);
                default:
                {
                    const int cmp = memcmp(key1, key2, key1_size);
                    return (cmp == 0) ? 0 : ((cmp < 0) ? -1 : 1);
                }
            }
        }
        return skip_list_comparator_memcmp(key1, key1_size, key2, key2_size, NULL);
    }

    /* slow path for other comparator types */
    switch (list->cmp_type)
    {
        case SKIP_LIST_CMP_NUMERIC:
            return skip_list_compare_keys_numeric_inline(key1, key2);

        case SKIP_LIST_CMP_STRING:
            return skip_list_comparator_string(key1, key1_size, key2, key2_size, NULL);

        case SKIP_LIST_CMP_CUSTOM:
        default:
            return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
    }
}

/**
 * skip_list_get_current_time
 * gets current time using cached time if available, otherwise syscall
 * @param list skip list (may be NULL)
 * @return current time as int64_t for consistent 64-bit handling
 */
static inline time_t skip_list_get_current_time(const skip_list_t *list)
{
#if defined(__MINGW32__) && !defined(__MINGW64__)
    /* on MinGW x86, cached time has visibility issues across threads, it seems to be a compiler bug
     ********
     */
    (void)list;
    return time(NULL);
#else
    if (list != NULL && list->cached_time != NULL)
    {
        return atomic_load_explicit(list->cached_time, memory_order_relaxed);
    }
    return time(NULL);
#endif
}

/**
 * skip_list_version_is_invalid_with_time
 * checks if version is expired or deleted using provided time
 * @param version version to check
 * @param current_time current time to use for TTL check
 * @return 1 if invalid, 0 if valid
 */
static inline int skip_list_version_is_invalid_with_time(skip_list_version_t *version,
                                                         const int64_t current_time)
{
    if (version == NULL) return 1;
    if (VERSION_IS_DELETED(version)) return 1;
    if (version->ttl > 0 && version->ttl < current_time) return 1;
    return 0;
}

/**
 * skip_list_validate_sequence
 * validates that new sequence number is greater than existing version
 * @param existing_version existing version to check against
 * @param new_seq new sequence number
 * @return 0 if valid (new_seq > existing), -1 if invalid
 */
static inline int skip_list_validate_sequence(skip_list_version_t *existing_version,
                                              uint64_t new_seq)
{
    if (existing_version != NULL)
    {
        uint64_t existing_seq = atomic_load_explicit(&existing_version->seq, memory_order_acquire);
        if (new_seq <= existing_seq) return -1;
    }
    return 0;
}

/**
 * skip_list_insert_version_cas
 * inserts a new version at the head of a version chain using CAS loop
 * @param versions_ptr pointer to atomic version list head
 * @param new_version version to insert
 * @param seq sequence number (for validation)
 * @param list skip list (for total_size update)
 * @param value_size size of new value
 * @return 0 on success, -1 on failure
 */
static int skip_list_insert_version_cas(_Atomic(skip_list_version_t *) *versions_ptr,
                                        skip_list_version_t *new_version, const uint64_t seq,
                                        skip_list_t *list, size_t value_size)
{
    skip_list_version_t *old_head;
    do
    {
        old_head = atomic_load_explicit(versions_ptr, memory_order_acquire);

        if (skip_list_validate_sequence(old_head, seq) != 0)
        {
            skip_list_free_version(new_version);
            return -1;
        }

        atomic_store_explicit(&new_version->next, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(versions_ptr, &old_head, new_version,
                                                    memory_order_release, memory_order_acquire));

    /* we update total_size, subtract old, add new */
    if (old_head && old_head->value_size > 0)
    {
        atomic_fetch_sub_explicit(&list->total_size, old_head->value_size, memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&list->total_size, value_size, memory_order_relaxed);
    return 0;
}

int skip_list_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx)
{
    (void)ctx;
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    const int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp < 0 ? -1 : 1;
    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

int skip_list_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx)
{
    (void)key1_size;
    (void)key2_size;
    (void)ctx;
    int cmp = strcmp((const char *)key1, (const char *)key2);
    return cmp == 0 ? 0 : (cmp < 0 ? -1 : 1);
}

int skip_list_comparator_numeric(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                 size_t key2_size, void *ctx)
{
    (void)key1_size;
    (void)key2_size;
    (void)ctx;
    uint64_t val1, val2;
    memcpy(&val1, key1, sizeof(uint64_t));
    memcpy(&val2, key2, sizeof(uint64_t));
    if (val1 < val2) return -1;
    if (val1 > val2) return 1;
    return 0;
}

/**
 * skip_list_create_version
 * creates a new version for a key
 * @param value value data
 * @param value_size size of value
 * @param ttl time-to-live
 * @param deleted tombstone flag
 * @param seq sequence number for MVCC
 * @return pointer to new version, NULL on failure
 */
static skip_list_version_t *skip_list_create_version(const uint8_t *value, const size_t value_size,
                                                     const int64_t ttl, const uint8_t deleted,
                                                     uint64_t seq)
{
    skip_list_version_t *version = (skip_list_version_t *)malloc(sizeof(skip_list_version_t));
    if (version == NULL) return NULL;

    if (value != NULL && value_size > 0)
    {
        version->value = (uint8_t *)malloc(value_size);
        if (version->value == NULL)
        {
            free(version);
            return NULL;
        }
        memcpy(version->value, value, value_size);
        version->value_size = value_size;
    }
    else
    {
        version->value = NULL;
        version->value_size = 0;
    }

    atomic_init(&version->flags, deleted ? SKIP_LIST_FLAG_DELETED : 0);
    atomic_init(&version->seq, seq);
    version->ttl = ttl;
    atomic_init(&version->next, NULL);
    return version;
}

/**
 * skip_list_free_version
 * frees a single version
 * @param version version to free
 */
static void skip_list_free_version(skip_list_version_t *version)
{
    if (version == NULL) return;
    if (version->value != NULL) free(version->value);
    free(version);
}

/**
 * skip_list_free_version_list
 * frees a linked list of versions
 * @param head head of version list
 */
static void skip_list_free_version_list(skip_list_version_t *head)
{
    while (head != NULL)
    {
        skip_list_version_t *next = atomic_load_explicit(&head->next, memory_order_acquire);
        skip_list_free_version(head);
        head = next;
    }
}

/**
 * skip_list_create_sentinel
 * creates a sentinel node (header or tail)
 * @param level level of the node
 * @return pointer to new sentinel node, NULL on failure
 */
static skip_list_node_t *skip_list_create_sentinel(const int level)
{
    size_t pointers_size = (level + 1) * 2 * sizeof(_Atomic(skip_list_node_t *));
    skip_list_node_t *node = (skip_list_node_t *)malloc(sizeof(skip_list_node_t) + pointers_size);
    if (node == NULL) return NULL;

    node->key = NULL;
    node->key_size = 0;
    node->level = (uint8_t)level;
    node->node_flags = SKIP_LIST_NODE_FLAG_SENTINEL;
    atomic_init(&node->versions, NULL);

    for (int i = 0; i <= level; i++)
    {
        atomic_init(&node->forward[i], NULL);
        atomic_init(&BACKWARD_PTR(node, i, level), NULL);
    }

    return node;
}

skip_list_node_t *skip_list_create_node(const int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, const size_t value_size,
                                        const int64_t ttl, const uint8_t deleted)
{
    if (key == NULL || key_size == 0) return NULL;

    size_t pointers_size = (level + 1) * 2 * sizeof(_Atomic(skip_list_node_t *));
    skip_list_node_t *node = (skip_list_node_t *)malloc(sizeof(skip_list_node_t) + pointers_size);
    if (node == NULL) return NULL;

    node->key = (uint8_t *)malloc(key_size);
    if (node->key == NULL)
    {
        free(node);
        return NULL;
    }
    memcpy(node->key, key, key_size);
    node->key_size = key_size;
    node->level = (uint8_t)level;
    node->node_flags = 0; /* not a sentinel */

    skip_list_version_t *initial_version = NULL;
    if (value != NULL || deleted)
    {
        initial_version = skip_list_create_version(value, value_size, ttl, deleted, 0);
        if (initial_version == NULL)
        {
            /* for non-tombstones, version creation failure is fatal
             * for tombstones (deleted=true), NULL version is acceptable */
            if (!deleted)
            {
                free(node->key);
                free(node);
                return NULL;
            }
        }
    }
    atomic_init(&node->versions, initial_version);

    for (int i = 0; i <= level; i++)
    {
        atomic_init(&node->forward[i], NULL);
        atomic_init(&BACKWARD_PTR(node, i, level), NULL);
    }

    return node;
}

int skip_list_free_node(skip_list_node_t *node)
{
    if (node == NULL) return -1;
    skip_list_version_t *versions = atomic_load_explicit(&node->versions, memory_order_acquire);
    skip_list_free_version_list(versions);
    if (node->key != NULL) free(node->key);
    free(node);
    return 0;
}

int skip_list_new(skip_list_t **list, const int max_level, const float probability)
{
    return skip_list_new_with_comparator(list, max_level, probability, skip_list_comparator_memcmp,
                                         NULL);
}

int skip_list_new_with_comparator(skip_list_t **list, int max_level, float probability,
                                  skip_list_comparator_fn comparator, void *comparator_ctx)
{
    return skip_list_new_with_comparator_and_cached_time(list, max_level, probability, comparator,
                                                         comparator_ctx, NULL);
}

int skip_list_new_with_comparator_and_cached_time(skip_list_t **list, const int max_level,
                                                  const float probability,
                                                  skip_list_comparator_fn comparator,
                                                  void *comparator_ctx,
                                                  _Atomic(time_t) *cached_time)
{
    if (list == NULL || max_level <= 0 || probability <= 0.0f || probability >= 1.0f) return -1;

    skip_list_t *new_list = (skip_list_t *)malloc(sizeof(skip_list_t));
    if (new_list == NULL) return -1;

    atomic_init(&new_list->level, 0);
    new_list->max_level = max_level;
    new_list->probability = probability;

    /* we determine comparator typen */
    if (comparator == skip_list_comparator_memcmp)
    {
        new_list->cmp_type = SKIP_LIST_CMP_MEMCMP;
    }
    else if (comparator == skip_list_comparator_string)
    {
        new_list->cmp_type = SKIP_LIST_CMP_STRING;
    }
    else if (comparator == skip_list_comparator_numeric)
    {
        new_list->cmp_type = SKIP_LIST_CMP_NUMERIC;
    }
    else
    {
        new_list->cmp_type = SKIP_LIST_CMP_CUSTOM;
    }

    new_list->comparator = comparator;
    new_list->comparator_ctx = comparator_ctx;
    new_list->cached_time = cached_time;

    if (cached_time != NULL)
    {
        atomic_store_explicit(cached_time, tdb_get_current_time(), memory_order_seq_cst);
    }

    atomic_init(&new_list->total_size, 0);
    atomic_init(&new_list->entry_count, 0);

    /* we create sentinel nodes with no keys -- they are identified by the sentinel flag */
    skip_list_node_t *header = skip_list_create_sentinel(max_level);
    skip_list_node_t *tail = skip_list_create_sentinel(max_level);

    if (header == NULL || tail == NULL)
    {
        if (header) skip_list_free_node(header);
        if (tail) skip_list_free_node(tail);
        free(new_list);
        return -1;
    }

    for (int i = 0; i <= max_level; i++)
    {
        atomic_store_explicit(&header->forward[i], tail, memory_order_relaxed);
        atomic_store_explicit(&BACKWARD_PTR(tail, i, max_level), header, memory_order_relaxed);
    }

    atomic_init(&new_list->header, header);
    atomic_init(&new_list->tail, tail);

    *list = new_list;
    return 0;
}

/* fast thread-local RNG for skip list level selection
 * uses xorshift64* algorithm */
static inline uint64_t skip_list_xorshift64star(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

int skip_list_random_level(const skip_list_t *list)
{
    if (list == NULL) return -1;

    /* thread-local RNG state */
    static _Thread_local uint64_t rng_state = 0;
    if (SKIP_LIST_UNLIKELY(rng_state == 0))
    {
        /** we init with thread ID + address entropy for uniqueness
         * avoids time() syscall on hot path */
        rng_state = (uint64_t)TDB_THREAD_ID() ^ ((uintptr_t)&rng_state >> 3);
        if (rng_state == 0) rng_state = 1; /* ensure non-zero */
    }

    const uint64_t rnd = skip_list_xorshift64star(&rng_state);

    /* geometric distribution via trailing zeros
     * for p=0.25, we need ~2 bits per level on average
     * TDB_CTZ64 counts trailing zeros, giving geometric distribution
     * we divide by 2 to approximate p=0.25 (each level requires ~2 zero bits) */
    const int level = TDB_CTZ64(rnd | (1ULL << 62)) >> 1;

    return level < list->max_level ? level : list->max_level;
}

int skip_list_compare_keys(const skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    if (list == NULL || key1 == NULL || key2 == NULL) return 0;
    return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
}

int skip_list_check_and_update_ttl(const skip_list_t *list, skip_list_node_t *node)
{
    if (node == NULL) return -1;
    skip_list_version_t *version = atomic_load_explicit(&node->versions, memory_order_acquire);
    if (version != NULL && version->ttl > 0 && version->ttl <= skip_list_get_current_time(list))
    {
        return 1;
    }
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, const size_t key_size, uint8_t **value,
                  size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level =
        atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

    /* we track if we found exact match at level 0 to avoid redundant comparison */
    int found_exact = 0;
    skip_list_node_t *candidate = NULL;

    /* we search from top level down with prefetching
     * use relaxed loads during traversal, acquire only at level 0 for final target */
    for (int i = max_level; i >= 0; i--)
    {
        const int mem_order = (i == 0) ? memory_order_acquire : memory_order_relaxed;
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], mem_order);

        /** we prefetch next node to reduce cache miss latency */
        if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
        {
            PREFETCH_READ(next); /* prefetch for read, high temporal locality */
            if (next->key != NULL)
            {
                PREFETCH_READ(next->key);
            }
        }

        while (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL))
        {
            const int cmp =
                skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (cmp > 0) break;
            if (cmp == 0)
            {
                /* exact match found -- at level 0 we can skip final comparison */
                if (i == 0)
                {
                    found_exact = 1;
                    candidate = next;
                }
                break;
            }
            current = next;
            next = atomic_load_explicit(&current->forward[i], mem_order);

            /** we prefetch next iteration */
            if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
            {
                PREFETCH_READ(next);
                if (next->key != NULL)
                {
                    PREFETCH_READ(next->key);
                }
            }
        }
    }

    skip_list_node_t *target;
    if (found_exact)
    {
        target = candidate;
    }
    else
    {
        target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
        if (SKIP_LIST_UNLIKELY(target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL))
            return -1;

        const int cmp =
            skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
        if (SKIP_LIST_UNLIKELY(cmp != 0)) return -1;
    }

    skip_list_version_t *head_version =
        atomic_load_explicit(&target->versions, memory_order_acquire);
    if (head_version == NULL) return -1;

    const int64_t current_time = skip_list_get_current_time(list);
    int head_invalid = skip_list_version_is_invalid_with_time(head_version, current_time);

    if (head_invalid && VERSION_IS_DELETED(head_version))
    {
        if (ttl != NULL) *ttl = head_version->ttl;
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    skip_list_version_t *version =
        head_invalid ? skip_list_get_latest_valid_version(target, current_time) : head_version;

    if (version == NULL)
    {
        if (deleted != NULL) *deleted = 1;
        if (ttl != NULL) *ttl = -1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (ttl != NULL) *ttl = version->ttl;
    if (deleted != NULL) *deleted = 0;

    if (version->value_size > 0 && version->value != NULL)
    {
        *value = (uint8_t *)malloc(version->value_size);
        if (*value == NULL) return -1;
        memcpy(*value, version->value, version->value_size);
        *value_size = version->value_size;
    }
    else
    {
        *value = NULL;
        *value_size = 0;
    }
    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, const size_t key_size,
                     const uint64_t seq)
{
    if (list == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

    /* we traverse with prefetching */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

        if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
        {
            PREFETCH_READ(next);
            if (next->key != NULL)
            {
                PREFETCH_READ(next->key);
            }
        }

        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

            if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
            {
                PREFETCH_READ(next);
                if (next->key != NULL)
                {
                    PREFETCH_READ(next->key);
                }
            }
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL) return 0;

    int cmp = skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return 0;

    skip_list_version_t *latest = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (skip_list_validate_sequence(latest, seq) != 0) return -1;

    skip_list_version_t *tombstone = skip_list_create_version(NULL, 0, -1, 1, seq);
    if (tombstone == NULL) return -1;

    skip_list_version_t *old_head;
    do
    {
        old_head = atomic_load_explicit(&target->versions, memory_order_acquire);
        if (skip_list_validate_sequence(old_head, seq) != 0)
        {
            skip_list_free_version(tombstone);
            return -1;
        }
        atomic_store_explicit(&tombstone->next, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&target->versions, &old_head, tombstone,
                                                    memory_order_release, memory_order_acquire));
    return 0;
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL && !NODE_IS_SENTINEL(current))
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);
        skip_list_free_node(current);
        current = next;
    }

    const int max_level = list->max_level;
    for (int i = 0; i <= max_level; i++)
    {
        atomic_store_explicit(&header->forward[i], tail, memory_order_release);
        atomic_store_explicit(&BACKWARD_PTR(tail, i, max_level), header, memory_order_release);
    }

    atomic_store_explicit(&list->level, 0, memory_order_release);
    atomic_store_explicit(&list->total_size, 0, memory_order_release);
    atomic_store_explicit(&list->entry_count, 0, memory_order_release);

    return 0;
}

void skip_list_free(skip_list_t *list)
{
    if (list == NULL) return;

    skip_list_clear(list);

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_free_node(header);
    skip_list_free_node(tail);

    free(list);
}

size_t skip_list_get_size(skip_list_t *list)
{
    if (list == NULL) return 0;
    return atomic_load_explicit(&list->total_size, memory_order_acquire);
}

int skip_list_count_entries(skip_list_t *list)
{
    if (list == NULL) return -1;
    return atomic_load_explicit(&list->entry_count, memory_order_acquire);
}

int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (first == NULL || NODE_IS_SENTINEL(first)) return -1;

    /* we find first valid (non-deleted, non-expired) entry */
    const int64_t current_time = skip_list_get_current_time(list);
    skip_list_node_t *current = first;
    while (current != NULL && !NODE_IS_SENTINEL(current))
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (!skip_list_version_is_invalid_with_time(version, current_time))
        {
            first = current;
            break;
        }
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    if (current == NULL || NODE_IS_SENTINEL(current)) return -1;

    *key = (uint8_t *)malloc(first->key_size);
    if (*key == NULL) return -1;
    memcpy(*key, first->key, first->key_size);
    *key_size = first->key_size;
    return 0;
}

int skip_list_get_max_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    /* O(1) access to last node using backward pointer from tail */
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current =
        atomic_load_explicit(&BACKWARD_PTR(tail, 0, tail->level), memory_order_acquire);

    if (current == NULL || NODE_IS_SENTINEL(current)) return -1;

    /* we scan backwards to find last valid (non-deleted, non-expired) entry */
    const int64_t current_time = skip_list_get_current_time(list);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    while (current != NULL && current != header)
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (!skip_list_version_is_invalid_with_time(version, current_time))
        {
            /* found valid entry */
            *key = (uint8_t *)malloc(current->key_size);
            if (*key == NULL) return -1;
            memcpy(*key, current->key, current->key_size);
            *key_size = current->key_size;
            return 0;
        }
        current =
            atomic_load_explicit(&BACKWARD_PTR(current, 0, current->level), memory_order_acquire);
    }

    return -1;
}

int skip_list_cursor_init(skip_list_cursor_t **cursor, skip_list_t *list)
{
    if (cursor == NULL || list == NULL) return -1;

    *cursor = (skip_list_cursor_t *)malloc(sizeof(skip_list_cursor_t));
    if (*cursor == NULL) return -1;

    (*cursor)->list = list;
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    (*cursor)->current = atomic_load_explicit(&header->forward[0], memory_order_acquire);
    return 0;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor != NULL) free(cursor);
}

int skip_list_cursor_valid(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    return (cursor->current != header && cursor->current != tail) ? 1 : 0;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1;

    cursor->current = atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (cursor->current == NULL || cursor->current == tail) return -1;

    /* we prefetch next node to hide memory latency during iteration */
    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_relaxed);
    if (next && !NODE_IS_SENTINEL(next))
    {
        PREFETCH_READ(next);
        PREFETCH_READ(next->key);
    }

    return 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    if (cursor->current == header) return -1;

    cursor->current = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->current->level), memory_order_acquire);
    if (cursor->current == NULL || cursor->current == header) return -1;
    return 0;
}

int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1;

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;

    skip_list_version_t *version =
        atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (ttl != NULL) *ttl = version->ttl;

    /* we check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid_with_time(version, skip_list_get_current_time(cursor->list)))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (deleted != NULL) *deleted = 0;
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}

int skip_list_cursor_get_with_seq(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size, int64_t *ttl,
                                  uint8_t *deleted, uint64_t *seq)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1;

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;

    skip_list_version_t *version =
        atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (ttl != NULL) *ttl = version->ttl;
    if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);

    /* we check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid_with_time(version, skip_list_get_current_time(cursor->list)))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (deleted != NULL) *deleted = 0;
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}

int skip_list_cursor_at_start(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);
    return (cursor->current == first) ? 1 : 0;
}

int skip_list_cursor_at_end(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    return (cursor->current == tail) ? 1 : 0;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1; /* at tail means empty or past end */
    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    return (next != NULL && next != tail) ? 1 : 0;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1; /* at tail means empty or past end */
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);
    return (cursor->current != first && cursor->current != header) ? 1 : 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;

    /* O(1) using backward pointer from tail */
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *last =
        atomic_load_explicit(&BACKWARD_PTR(tail, 0, tail->level), memory_order_acquire);

    if (last == NULL || NODE_IS_SENTINEL(last)) return -1;

    cursor->current = last;
    return 0;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);
    if (first == NULL || NODE_IS_SENTINEL(first)) return -1;
    cursor->current = first;
    return 0;
}

/**
 * skip_list_cursor_seek
 * positions cursor at the node before the first key >= target
 * @param cursor the cursor to position
 * @param key the target key to seek to
 * @param key_size size of the target key
 * @return 0 on success, -1 on failure
 *
 * after calling this function, cursor->current points to the predecessor node.
 * callers must call skip_list_cursor_next() or similar to access the actual target key.
 * this behavior allows efficient insertion and supports both exact matches and range queries.
 */
int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level =
        atomic_load_explicit(&cursor->list->level, memory_order_acquire); /* cache level */

    /* find the node before the target key */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(cursor->list, next->key, next->key_size, key,
                                                    key_size);
            if (cmp >= 0) break; /* stop before target or equal */
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    /* we position cursor at the node before target
     * caller must call skip_list_cursor_next() to access first key >= target */
    cursor->current = current;
    return 0;
}

int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key,
                                   const size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level =
        atomic_load_explicit(&cursor->list->level, memory_order_acquire); /* cache level */

    /* we find the last node with key <= target */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(cursor->list, next->key, next->key_size, key,
                                                    key_size);
            if (cmp > 0) break; /* stop when key > target */
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    /* the current is now the last node with key <= target, or header if no such key */
    if (NODE_IS_SENTINEL(current))
    {
        /* no key <= target exists, cursor is invalid */
        cursor->current = current;
        return 0;
    }

    cursor->current = current;
    return 0;
}

int skip_list_put_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size,
                           const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                           uint8_t deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || (!deleted && value == NULL)) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

    /* we use stack allocation for update array */
#define SKIP_LIST_STACK_UPDATE_SIZE 64
    skip_list_node_t *stack_update[SKIP_LIST_STACK_UPDATE_SIZE];
    skip_list_node_t **update;
    const int use_stack = (list->max_level < SKIP_LIST_STACK_UPDATE_SIZE);

    if (use_stack)
    {
        update = stack_update;
    }
    else
    {
        update = malloc((list->max_level + 1) * sizeof(skip_list_node_t *));
        if (!update) return -1;
    }

    for (int i = 0; i <= list->max_level; i++)
    {
        update[i] = header;
    }

    skip_list_node_t *current = header;

    /* we traverse with prefetching */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

        if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
        {
            PREFETCH_READ(next);
            if (next->key != NULL)
            {
                PREFETCH_READ(next->key);
            }
        }

        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

            if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
            {
                PREFETCH_READ(next);
                if (next->key != NULL)
                {
                    PREFETCH_READ(next->key);
                }
            }
        }
        update[i] = current;
    }

    skip_list_node_t *existing = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (existing != NULL && !NODE_IS_SENTINEL(existing) && existing->key != NULL)
    {
        int cmp =
            skip_list_compare_keys_inline(list, existing->key, existing->key_size, key, key_size);
        if (cmp == 0)
        {
            /* the key exists, validate sequence and add new version */
            skip_list_version_t *latest =
                atomic_load_explicit(&existing->versions, memory_order_acquire);
            if (skip_list_validate_sequence(latest, seq) != 0)
            {
                if (!use_stack) free(update);
                return -1;
            }

            const uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
            skip_list_version_t *new_version =
                skip_list_create_version(value, value_size, ttl, flags, seq);
            if (new_version == NULL)
            {
                if (!use_stack) free(update);
                return -1;
            }

            if (skip_list_insert_version_cas(&existing->versions, new_version, seq, list,
                                             value_size) != 0)
            {
                if (!use_stack) free(update);
                return -1;
            }

            if (!use_stack) free(update);
            return 0;
        }
    }

    skip_list_node_t *recheck = atomic_load_explicit(&update[0]->forward[0], memory_order_acquire);
    if (recheck != NULL && !NODE_IS_SENTINEL(recheck))
    {
        int cmp =
            skip_list_compare_keys_inline(list, recheck->key, recheck->key_size, key, key_size);
        if (cmp == 0)
        {
            skip_list_version_t *latest =
                atomic_load_explicit(&recheck->versions, memory_order_acquire);
            if (skip_list_validate_sequence(latest, seq) != 0)
            {
                if (!use_stack) free(update);
                return -1;
            }

            const uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
            skip_list_version_t *new_version =
                skip_list_create_version(value, value_size, ttl, flags, seq);
            if (new_version == NULL)
            {
                if (!use_stack) free(update);
                return -1;
            }

            if (skip_list_insert_version_cas(&recheck->versions, new_version, seq, list,
                                             value_size) != 0)
            {
                if (!use_stack) free(update);
                return -1;
            }

            if (!use_stack) free(update);
            return 0;
        }
    }

    int new_level = skip_list_random_level(list);
    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

    if (new_level > current_level)
    {
        for (int i = current_level + 1; i <= new_level; i++)
        {
            update[i] = header;
        }
        atomic_store_explicit(&list->level, new_level, memory_order_release);
    }

    skip_list_node_t *new_node = malloc(
        sizeof(skip_list_node_t) + (2 * (new_level + 1)) * sizeof(_Atomic(skip_list_node_t *)));
    if (new_node == NULL)
    {
        if (!use_stack) free(update);
        return -1;
    }

    new_node->key = malloc(key_size);
    if (new_node->key == NULL)
    {
        free(new_node);
        if (!use_stack) free(update);
        return -1;
    }
    memcpy(new_node->key, key, key_size);
    new_node->key_size = key_size;
    new_node->level = (uint8_t)new_level;
    new_node->node_flags = 0;

    const uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
    skip_list_version_t *initial_version =
        skip_list_create_version(value, value_size, ttl, flags, seq);
    if (initial_version == NULL)
    {
        free(new_node->key);
        free(new_node);
        if (!use_stack) free(update);
        return -1;
    }
    atomic_init(&new_node->versions, initial_version);

    for (int i = 0; i <= new_level; i++)
    {
        atomic_init(&new_node->forward[i], NULL);
        atomic_init(&BACKWARD_PTR(new_node, i, new_level), NULL);
    }

    skip_list_node_t *pred = update[0];
    skip_list_node_t *next_at_0;
    int cas_attempts = 0;

    while (1)
    {
        next_at_0 = atomic_load_explicit(&pred->forward[0], memory_order_acquire);

        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0) && next_at_0->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next_at_0->key, next_at_0->key_size, key,
                                                    key_size);
            if (cmp == 0)
            {
                skip_list_version_t *latest =
                    atomic_load_explicit(&next_at_0->versions, memory_order_acquire);
                if (skip_list_validate_sequence(latest, seq) != 0)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                const uint8_t version_flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
                skip_list_version_t *new_version =
                    skip_list_create_version(value, value_size, ttl, version_flags, seq);
                if (new_version == NULL)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                if (skip_list_insert_version_cas(&next_at_0->versions, new_version, seq, list,
                                                 value_size) != 0)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                skip_list_free_node(new_node);
                if (!use_stack) free(update);
                return 0;
            }
            if (cmp < 0)
            {
                pred = next_at_0;
                continue;
            }
        }

        atomic_store_explicit(&new_node->forward[0], next_at_0, memory_order_relaxed);
        if (atomic_compare_exchange_weak_explicit(&pred->forward[0], &next_at_0, new_node,
                                                  memory_order_release, memory_order_acquire))
        {
            update[0] = pred;
            break;
        }

        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0) && next_at_0->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next_at_0->key, next_at_0->key_size, key,
                                                    key_size);
            if (cmp == 0)
            {
                skip_list_version_t *latest =
                    atomic_load_explicit(&next_at_0->versions, memory_order_acquire);
                if (skip_list_validate_sequence(latest, seq) != 0)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                const uint8_t version_flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
                skip_list_version_t *new_version =
                    skip_list_create_version(value, value_size, ttl, version_flags, seq);
                if (new_version == NULL)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                if (skip_list_insert_version_cas(&next_at_0->versions, new_version, seq, list,
                                                 value_size) != 0)
                {
                    skip_list_free_node(new_node);
                    if (!use_stack) free(update);
                    return -1;
                }

                skip_list_free_node(new_node);
                if (!use_stack) free(update);
                return 0;
            }
            if (cmp < 0)
            {
                pred = next_at_0;
                continue;
            }
        }

        cas_attempts++;
        if (cas_attempts > SKIP_LIST_MAX_CAS_ATTEMPTS)
        {
            skip_list_free_node(new_node);
            if (!use_stack) free(update);
            return -1;
        }
    }

    atomic_store_explicit(&BACKWARD_PTR(new_node, 0, new_level), update[0], memory_order_release);
    skip_list_node_t *next_after_insert =
        atomic_load_explicit(&new_node->forward[0], memory_order_acquire);
    if (next_after_insert != NULL)
    {
        skip_list_node_t *expected = update[0];
        atomic_compare_exchange_strong_explicit(
            &BACKWARD_PTR(next_after_insert, 0, next_after_insert->level), &expected, new_node,
            memory_order_release, memory_order_acquire);
    }

    for (int i = 1; i <= new_level; i++)
    {
        skip_list_node_t *next;
        do
        {
            next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
            atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
        } while (!atomic_compare_exchange_weak_explicit(
            &update[i]->forward[i], &next, new_node, memory_order_release, memory_order_acquire));

        atomic_store_explicit(&BACKWARD_PTR(new_node, i, new_level), update[i],
                              memory_order_release);
        if (next != NULL)
        {
            skip_list_node_t *expected = update[i];
            atomic_compare_exchange_strong_explicit(&BACKWARD_PTR(next, i, next->level), &expected,
                                                    new_node, memory_order_release,
                                                    memory_order_acquire);
        }
    }

    atomic_fetch_add_explicit(&list->total_size, key_size + value_size, memory_order_relaxed);
    atomic_fetch_add_explicit(&list->entry_count, 1, memory_order_relaxed);

    if (!use_stack) free(update);
    return 0;
}

int skip_list_put_batch(skip_list_t *list, const skip_list_batch_entry_t *entries,
                        const size_t count)
{
    if (list == NULL || entries == NULL || count == 0) return -1;

    int success_count = 0;

    /* we use a shared update array across batch entries for efficiency
     * this avoids repeated allocation/deallocation per entry */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);

#define SKIP_LIST_STACK_UPDATE_SIZE 64
    skip_list_node_t *stack_update[SKIP_LIST_STACK_UPDATE_SIZE];
    skip_list_node_t **update;
    const int use_stack = (list->max_level < SKIP_LIST_STACK_UPDATE_SIZE);

    if (use_stack)
    {
        update = stack_update;
    }
    else
    {
        update = malloc((list->max_level + 1) * sizeof(skip_list_node_t *));
        if (!update) return -1;
    }

    for (size_t e = 0; e < count; e++)
    {
        const skip_list_batch_entry_t *entry = &entries[e];

        if (entry->key == NULL || entry->key_size == 0) continue;
        if (!entry->deleted && entry->value == NULL) continue;

        /* we initialize update array */
        for (int i = 0; i <= list->max_level; i++)
        {
            update[i] = header;
        }

        const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

        /* we always start from header for correctness
         * the sorted key optimization was causing SIGSEGV when accessing
         * forward pointers beyond node's level */
        skip_list_node_t *current = header;

        /* we traverse with prefetching */
        for (int i = max_level; i >= 0; i--)
        {
            skip_list_node_t *next =
                atomic_load_explicit(&current->forward[i], memory_order_acquire);

            if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
            {
                PREFETCH_READ(next);
                if (next->key != NULL)
                {
                    PREFETCH_READ(next->key);
                }
            }

            while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
            {
                int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, entry->key,
                                                        entry->key_size);
                if (cmp >= 0) break;
                current = next;
                next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

                if (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next)))
                {
                    PREFETCH_READ(next);
                    if (next->key != NULL)
                    {
                        PREFETCH_READ(next->key);
                    }
                }
            }
            update[i] = current;
        }

        /* we check if key exists */
        skip_list_node_t *existing =
            atomic_load_explicit(&current->forward[0], memory_order_acquire);
        if (existing != NULL && !NODE_IS_SENTINEL(existing) && existing->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, existing->key, existing->key_size,
                                                    entry->key, entry->key_size);
            if (cmp == 0)
            {
                /* key exists, add new version */
                skip_list_version_t *latest =
                    atomic_load_explicit(&existing->versions, memory_order_acquire);
                if (skip_list_validate_sequence(latest, entry->seq) != 0)
                {
                    continue; /* skip this entry */
                }

                const uint8_t flags = entry->deleted ? SKIP_LIST_FLAG_DELETED : 0;
                skip_list_version_t *new_version = skip_list_create_version(
                    entry->value, entry->value_size, entry->ttl, flags, entry->seq);
                if (new_version == NULL)
                {
                    continue;
                }

                if (skip_list_insert_version_cas(&existing->versions, new_version, entry->seq, list,
                                                 entry->value_size) == 0)
                {
                    success_count++;
                }
                continue;
            }
        }

        /* we create new node */
        int new_level = skip_list_random_level(list);
        int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

        if (new_level > current_level)
        {
            for (int i = current_level + 1; i <= new_level; i++)
            {
                update[i] = header;
            }
            atomic_store_explicit(&list->level, new_level, memory_order_release);
        }

        skip_list_node_t *new_node = malloc(
            sizeof(skip_list_node_t) + (2 * (new_level + 1)) * sizeof(_Atomic(skip_list_node_t *)));
        if (new_node == NULL)
        {
            continue;
        }

        new_node->key = malloc(entry->key_size);
        if (new_node->key == NULL)
        {
            free(new_node);
            continue;
        }
        memcpy(new_node->key, entry->key, entry->key_size);
        new_node->key_size = entry->key_size;
        new_node->level = (uint8_t)new_level;
        new_node->node_flags = 0;

        const uint8_t flags = entry->deleted ? SKIP_LIST_FLAG_DELETED : 0;
        skip_list_version_t *initial_version = skip_list_create_version(
            entry->value, entry->value_size, entry->ttl, flags, entry->seq);
        if (initial_version == NULL)
        {
            free(new_node->key);
            free(new_node);
            continue;
        }
        atomic_init(&new_node->versions, initial_version);

        for (int i = 0; i <= new_level; i++)
        {
            atomic_init(&new_node->forward[i], NULL);
            atomic_init(&BACKWARD_PTR(new_node, i, new_level), NULL);
        }

        /* we insert at level 0 with CAS */
        skip_list_node_t *pred = update[0];
        skip_list_node_t *next_at_0;
        int cas_attempts = 0;
        int inserted = 0;

        while (1)
        {
            next_at_0 = atomic_load_explicit(&pred->forward[0], memory_order_acquire);

            if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0) && next_at_0->key != NULL)
            {
                int cmp = skip_list_compare_keys_inline(list, next_at_0->key, next_at_0->key_size,
                                                        entry->key, entry->key_size);
                if (cmp == 0)
                {
                    /* concurrent insert, add version instead */
                    skip_list_version_t *latest =
                        atomic_load_explicit(&next_at_0->versions, memory_order_acquire);
                    if (skip_list_validate_sequence(latest, entry->seq) == 0)
                    {
                        const uint8_t version_flags = entry->deleted ? SKIP_LIST_FLAG_DELETED : 0;
                        skip_list_version_t *new_version = skip_list_create_version(
                            entry->value, entry->value_size, entry->ttl, version_flags, entry->seq);
                        if (new_version != NULL)
                        {
                            if (skip_list_insert_version_cas(&next_at_0->versions, new_version,
                                                             entry->seq, list,
                                                             entry->value_size) == 0)
                            {
                                success_count++;
                            }
                        }
                    }
                    skip_list_free_node(new_node);
                    new_node = NULL; /* prevent use-after-free in higher level linking */
                    inserted = 1;
                    break;
                }
                if (cmp < 0)
                {
                    pred = next_at_0;
                    continue;
                }
            }

            atomic_store_explicit(&new_node->forward[0], next_at_0, memory_order_relaxed);
            if (atomic_compare_exchange_weak_explicit(&pred->forward[0], &next_at_0, new_node,
                                                      memory_order_release, memory_order_acquire))
            {
                update[0] = pred;
                inserted = 1;
                break;
            }

            cas_attempts++;
            if (cas_attempts > SKIP_LIST_MAX_CAS_ATTEMPTS)
            {
                skip_list_free_node(new_node);
                new_node = NULL; /* prevent use-after-free in higher level linking */
                inserted = 1;    /* mark as handled to avoid double-free */
                break;
            }
        }

        if (!inserted)
        {
            skip_list_free_node(new_node);
            continue;
        }

        if (new_node != NULL && cas_attempts <= SKIP_LIST_MAX_CAS_ATTEMPTS && update[0] == pred)
        {
            /* we successfully inserted new node, link higher levels */
            atomic_store_explicit(&BACKWARD_PTR(new_node, 0, new_level), update[0],
                                  memory_order_release);
            skip_list_node_t *next_after_insert =
                atomic_load_explicit(&new_node->forward[0], memory_order_acquire);
            if (next_after_insert != NULL)
            {
                skip_list_node_t *expected = update[0];
                atomic_compare_exchange_strong_explicit(
                    &BACKWARD_PTR(next_after_insert, 0, next_after_insert->level), &expected,
                    new_node, memory_order_release, memory_order_acquire);
            }

            for (int i = 1; i <= new_level; i++)
            {
                skip_list_node_t *next;
                do
                {
                    next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
                    atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
                } while (!atomic_compare_exchange_weak_explicit(&update[i]->forward[i], &next,
                                                                new_node, memory_order_release,
                                                                memory_order_acquire));

                atomic_store_explicit(&BACKWARD_PTR(new_node, i, new_level), update[i],
                                      memory_order_release);
                if (next != NULL)
                {
                    skip_list_node_t *expected = update[i];
                    atomic_compare_exchange_strong_explicit(
                        &BACKWARD_PTR(next, i, next->level), &expected, new_node,
                        memory_order_release, memory_order_acquire);
                }
            }

            atomic_fetch_add_explicit(&list->total_size, entry->key_size + entry->value_size,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&list->entry_count, 1, memory_order_relaxed);
            success_count++;
        }
    }

    if (!use_stack) free(update);
    return success_count;
}

int skip_list_get_max_seq(skip_list_t *list, const uint8_t *key, const size_t key_size,
                          uint64_t *out_seq)
{
    if (list == NULL || key == NULL || key_size == 0 || out_seq == NULL) return -1;

    *out_seq = 0;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL) return -1;

    int cmp = skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return -1;

    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (version == NULL) return -1;

    *out_seq = atomic_load_explicit(&version->seq, memory_order_acquire);
    return 0;
}

int skip_list_get_with_seq(skip_list_t *list, const uint8_t *key, const size_t key_size,
                           uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted,
                           uint64_t *seq, uint64_t snapshot_seq,
                           skip_list_visibility_check_fn visibility_check, void *visibility_ctx)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    const int max_level =
        atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

    /* attempt to find the node */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL) return -1;

    int cmp = skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return -1;

    /* found the key, now we must find the appropriate version */
    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);

    if (snapshot_seq == UINT64_MAX)
    {
        if (version == NULL) return -1;
    }
    else
    {
        /**
         * we find the newest committed version with seq <= snapshot_seq.
         * version chain is ordered newest-to-oldest, so we return the first
         * version that passes both checks. */
        while (version != NULL)
        {
            uint64_t version_seq = atomic_load_explicit(&version->seq, memory_order_acquire);

            /* we check if version is within snapshot range */
            if (version_seq <= snapshot_seq)
            {
                /* if visibility check provided, verify this version is committed */
                if (visibility_check != NULL)
                {
                    if (visibility_check(visibility_ctx, version_seq))
                    {
                        /* found the newest committed version within snapshot -- use it */
                        break;
                    }
                    /* this version is not committed yet -- check older versions */
                }
                else
                {
                    /* no visibility check -- assume committed (for recovery, etc.) */
                    break;
                }
            }
            /* version is too new or not committed -- check next (older) version */
            version = atomic_load_explicit(&version->next, memory_order_acquire);
        }

        if (version == NULL) return -1; /* no visible version */
    }

    /* always set ttl if provided */
    if (ttl != NULL) *ttl = version->ttl;

    if (version->ttl > 0)
    {
        if (version->ttl <= skip_list_get_current_time(list))
        {
            if (deleted != NULL) *deleted = 1;
            *value = NULL;
            *value_size = 0;
            if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);
            return 0; /* return success but mark as expired/deleted */
        }
    }

    uint8_t is_deleted = VERSION_IS_DELETED(version);
    if (deleted != NULL) *deleted = is_deleted;

    /* return the value (even for tombstones, caller will check deleted flag) */
    if (!is_deleted && version->value != NULL && version->value_size > 0)
    {
        *value = malloc(version->value_size);
        if (*value == NULL) return -1;
        memcpy(*value, version->value, version->value_size);
        *value_size = version->value_size;
    }
    else
    {
        *value = NULL;
        *value_size = 0;
    }

    if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);

    return 0;
}