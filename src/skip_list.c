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
 * skip_list_free_version
 * frees a single version
 * @param version version to free
 */
static void skip_list_free_version(skip_list_version_t *version);

/**
 * skip_list_compare_keys_inline
 * inline comparator for hot paths
 * @param list skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int skip_list_compare_keys_inline(const skip_list_t *list, const uint8_t *key1,
                                                size_t key1_size, const uint8_t *key2,
                                                size_t key2_size)
{
    return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
}

/**
 * skip_list_version_is_invalid
 * checks if version is expired or deleted
 * @param version version to check
 * @return 1 if invalid, 0 if valid
 */
static inline int skip_list_version_is_invalid(skip_list_version_t *version)
{
    if (version == NULL) return 1;
    if (VERSION_IS_DELETED(version)) return 1;
    if (version->ttl > 0 && version->ttl < time(NULL)) return 1;
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
                                        skip_list_version_t *new_version, uint64_t seq,
                                        skip_list_t *list, size_t value_size)
{
    skip_list_version_t *old_head;
    do
    {
        old_head = atomic_load_explicit(versions_ptr, memory_order_acquire);

        /* validate sequence number */
        if (skip_list_validate_sequence(old_head, seq) != 0)
        {
            skip_list_free_version(new_version);
            return -1;
        }

        atomic_store_explicit(&new_version->next, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(versions_ptr, &old_head, new_version,
                                                    memory_order_release, memory_order_acquire));

    /* update total_size: subtract old, add new */
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
    int cmp = memcmp(key1, key2, min_size);
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
static skip_list_version_t *skip_list_create_version(const uint8_t *value, size_t value_size,
                                                     time_t ttl, uint8_t deleted, uint64_t seq)
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
static skip_list_node_t *skip_list_create_sentinel(int level)
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

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl,
                                        uint8_t deleted)
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

int skip_list_new(skip_list_t **list, int max_level, float probability)
{
    return skip_list_new_with_comparator(list, max_level, probability, skip_list_comparator_memcmp,
                                         NULL);
}

int skip_list_new_with_comparator(skip_list_t **list, int max_level, float probability,
                                  skip_list_comparator_fn comparator, void *comparator_ctx)
{
    if (list == NULL || max_level <= 0 || probability <= 0.0f || probability >= 1.0f) return -1;

    skip_list_t *new_list = (skip_list_t *)malloc(sizeof(skip_list_t));
    if (new_list == NULL) return -1;

    atomic_init(&new_list->level, 0);
    new_list->max_level = max_level;
    new_list->probability = probability;
    new_list->comparator = comparator;
    new_list->comparator_ctx = comparator_ctx;
    atomic_init(&new_list->total_size, 0);
    atomic_init(&new_list->entry_count, 0);

    /* create sentinel nodes with no keys -- they are identified by the sentinel flag */
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
    if (rng_state == 0)
    {
        /* initialize with thread ID + timestamp for uniqueness */
        rng_state = (uint64_t)TDB_THREAD_ID() ^ (uint64_t)time(NULL);
    }

    /* convert probability to threshold for fast comparison
     * probability range is (0.0, 1.0), we scale to [0, UINT64_MAX] */
    uint64_t threshold = (uint64_t)(list->probability * (double)UINT64_MAX);

    int level = 0;

    /* keep generating levels while random value < threshold */
    while (level < list->max_level)
    {
        uint64_t rnd = skip_list_xorshift64star(&rng_state);
        if (rnd >= threshold) break;
        level++;
    }

    return level;
}

int skip_list_compare_keys(const skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    if (list == NULL || key1 == NULL || key2 == NULL) return 0;
    return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
}

int skip_list_check_and_update_ttl(const skip_list_t *list, skip_list_node_t *node)
{
    (void)list;
    if (node == NULL) return -1;
    skip_list_version_t *version = atomic_load_explicit(&node->versions, memory_order_acquire);
    if (version != NULL && version->ttl > 0 && version->ttl < time(NULL))
    {
        return 1;
    }
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, time_t *ttl, uint8_t *deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    int max_level = atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

    /* search from top level down */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (SKIP_LIST_LIKELY(next != NULL && !NODE_IS_SENTINEL(next) && next->key != NULL))
        {
            int cmp = skip_list_compare_keys_inline(list, next->key, next->key_size, key, key_size);
            if (SKIP_LIST_UNLIKELY(cmp >= 0)) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (SKIP_LIST_UNLIKELY(target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL))
        return -1;

    int cmp = skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
    if (SKIP_LIST_UNLIKELY(cmp != 0)) return -1;

    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (version == NULL) return -1;

    /* always set ttl if provided */
    if (ttl != NULL) *ttl = version->ttl;

    /* check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid(version))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

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

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size, uint64_t seq)
{
    if (list == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    int max_level = atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

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
    if (target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL) return 0;

    int cmp = skip_list_compare_keys_inline(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return 0;

    /* check if the sequence number is greater than the latest version */
    skip_list_version_t *latest = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (skip_list_validate_sequence(latest, seq) != 0) return -1;

    skip_list_version_t *tombstone = skip_list_create_version(NULL, 0, -1, 1, seq);
    if (tombstone == NULL) return -1;

    /* use helper to insert tombstone version */
    skip_list_version_t *old_head;
    do
    {
        old_head = atomic_load_explicit(&target->versions, memory_order_acquire);

        /* re-check sequence number in case another thread added a newer version */
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

    int max_level = list->max_level;
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

    /* find first valid (non-deleted, non-expired) entry */
    skip_list_node_t *current = first;
    while (current != NULL && !NODE_IS_SENTINEL(current))
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (!skip_list_version_is_invalid(version))
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

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (current == NULL || NODE_IS_SENTINEL(current)) return -1;

    /* traverse to find last valid node before tail */
    skip_list_node_t *last = NULL;
    while (current != NULL && !NODE_IS_SENTINEL(current))
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (!skip_list_version_is_invalid(version))
        {
            last = current;
        }
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    if (last == NULL) return -1;

    *key = (uint8_t *)malloc(last->key_size);
    if (*key == NULL) return -1;
    memcpy(*key, last->key, last->key_size);
    *key_size = last->key_size;
    return 0;
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

    /* prefetch next node to hide memory latency during iteration */
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
                         uint8_t **value, size_t *value_size, time_t *ttl, uint8_t *deleted)
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

    /* check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid(version))
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
                                  uint8_t **value, size_t *value_size, time_t *ttl,
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

    /* check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid(version))
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
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (current == NULL || NODE_IS_SENTINEL(current)) return -1;

    /* traverse forward to find last node */
    skip_list_node_t *last = current;
    while (current != NULL && !NODE_IS_SENTINEL(current))
    {
        last = current;
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

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
    int max_level =
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

    /* position cursor at the node before target
     * caller must call skip_list_cursor_next() to access first key >= target */
    cursor->current = current;
    return 0;
}

int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    int max_level =
        atomic_load_explicit(&cursor->list->level, memory_order_acquire); /* cache level */

    /* find the last node with key <= target */
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

    /* current is now the last node with key <= target, or header if no such key */
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
                           const uint8_t *value, size_t value_size, time_t ttl, uint64_t seq,
                           uint8_t deleted)
{
    /* for tombstones, value can be NULL */
    if (list == NULL || key == NULL || key_size == 0 || (!deleted && value == NULL)) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    int max_level = atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

    /* we update array based on max_level to handle potential level increases */
    skip_list_node_t **update = malloc((list->max_level + 1) * sizeof(skip_list_node_t *));
    if (!update) return -1;

    /* initialize all entries to header, not just up to current level
     * this is critical because level can increase and we'll access higher indices */
    for (int i = 0; i <= list->max_level; i++)
    {
        update[i] = header;
    }

    skip_list_node_t *current = header;

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
        update[i] = current;
    }

    skip_list_node_t *existing = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (existing != NULL && !NODE_IS_SENTINEL(existing) && existing->key != NULL)
    {
        int cmp =
            skip_list_compare_keys_inline(list, existing->key, existing->key_size, key, key_size);
        if (cmp == 0)
        {
            /* key exists, validate sequence and add new version */
            skip_list_version_t *latest =
                atomic_load_explicit(&existing->versions, memory_order_acquire);
            if (skip_list_validate_sequence(latest, seq) != 0)
            {
                free(update);
                return -1;
            }

            /* add new version to version chain */
            uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
            skip_list_version_t *new_version =
                skip_list_create_version(value, value_size, ttl, flags, seq);
            if (new_version == NULL)
            {
                free(update);
                return -1;
            }

            /* use helper to insert version with CAS loop */
            if (skip_list_insert_version_cas(&existing->versions, new_version, seq, list,
                                             value_size) != 0)
            {
                free(update);
                return -1;
            }

            free(update);
            return 0; /* updated existing key, no entry_count change */
        }
    }

    /* we re-check if key was inserted by another thread while we were preparing */
    skip_list_node_t *recheck = atomic_load_explicit(&update[0]->forward[0], memory_order_acquire);
    if (recheck != NULL && !NODE_IS_SENTINEL(recheck))
    {
        int cmp =
            skip_list_compare_keys_inline(list, recheck->key, recheck->key_size, key, key_size);
        if (cmp == 0)
        {
            /* another thread inserted this key! Validate sequence and add version */
            skip_list_version_t *latest =
                atomic_load_explicit(&recheck->versions, memory_order_acquire);
            if (skip_list_validate_sequence(latest, seq) != 0)
            {
                free(update);
                return -1;
            }

            uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
            skip_list_version_t *new_version =
                skip_list_create_version(value, value_size, ttl, flags, seq);
            if (new_version == NULL)
            {
                free(update);
                return -1;
            }

            /* use helper to insert version with CAS loop */
            if (skip_list_insert_version_cas(&recheck->versions, new_version, seq, list,
                                             value_size) != 0)
            {
                free(update);
                return -1;
            }

            free(update);
            return 0;
        }
    }

    /* key doesnt exist, we create new node */
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

    /* create node with initial version containing sequence number */
    skip_list_node_t *new_node = malloc(
        sizeof(skip_list_node_t) + (2 * (new_level + 1)) * sizeof(_Atomic(skip_list_node_t *)));
    if (new_node == NULL)
    {
        free(update);
        return -1;
    }

    new_node->key = malloc(key_size);
    if (new_node->key == NULL)
    {
        free(new_node);
        free(update);
        return -1;
    }
    memcpy(new_node->key, key, key_size);
    new_node->key_size = key_size;
    new_node->level = (uint8_t)new_level;
    new_node->node_flags = 0; /* not a sentinel */

    uint8_t flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
    skip_list_version_t *initial_version =
        skip_list_create_version(value, value_size, ttl, flags, seq);
    if (initial_version == NULL)
    {
        free(new_node->key);
        free(new_node);
        free(update);
        return -1;
    }
    atomic_init(&new_node->versions, initial_version);

    for (int i = 0; i <= new_level; i++)
    {
        atomic_init(&new_node->forward[i], NULL);
        atomic_init(&BACKWARD_PTR(new_node, i, new_level), NULL);
    }

    /* we inster at level 0 first with duplicate check in CAS loop */
    skip_list_node_t *pred = update[0];
    skip_list_node_t *next_at_0;
    int cas_attempts = 0;

    while (1)
    {
        /* we load the next node from our current predecessor */
        next_at_0 = atomic_load_explicit(&pred->forward[0], memory_order_acquire);

        /* we check if the key already exists at this position */
        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0) && next_at_0->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next_at_0->key, next_at_0->key_size, key,
                                                    key_size);
            if (cmp == 0)
            {
                /* key exists, add version instead of creating new node */
                skip_list_version_t *latest =
                    atomic_load_explicit(&next_at_0->versions, memory_order_acquire);
                if (skip_list_validate_sequence(latest, seq) != 0)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                uint8_t version_flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
                skip_list_version_t *new_version =
                    skip_list_create_version(value, value_size, ttl, version_flags, seq);
                if (new_version == NULL)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                if (skip_list_insert_version_cas(&next_at_0->versions, new_version, seq, list,
                                                 value_size) != 0)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                skip_list_free_node(new_node);
                free(update);
                return 0;
            }
            else if (cmp < 0)
            {
                /* next_at_0 < key, need to advance pred forward */
                pred = next_at_0;
                continue; /* retry with new pred */
            }
            /* else cmp > 0: next_at_0 > key, correct insertion point */
        }

        /* try to insert: pred -> new_node -> next_at_0 */
        atomic_store_explicit(&new_node->forward[0], next_at_0, memory_order_relaxed);

        if (atomic_compare_exchange_weak_explicit(&pred->forward[0], &next_at_0, new_node,
                                                  memory_order_release, memory_order_acquire))
        {
            /* success! Update the update[] array for higher level insertions */
            update[0] = pred;
            break;
        }

        /* CAS failed -- next_at_0 now contains the current value of pred->forward[0]
         * we check if a node was inserted that matches our key */
        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0) && next_at_0->key != NULL)
        {
            int cmp = skip_list_compare_keys_inline(list, next_at_0->key, next_at_0->key_size, key,
                                                    key_size);
            if (cmp == 0)
            {
                /* another thread just inserted our key, add version to it */
                skip_list_version_t *latest =
                    atomic_load_explicit(&next_at_0->versions, memory_order_acquire);
                if (skip_list_validate_sequence(latest, seq) != 0)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                uint8_t version_flags = deleted ? SKIP_LIST_FLAG_DELETED : 0;
                skip_list_version_t *new_version =
                    skip_list_create_version(value, value_size, ttl, version_flags, seq);
                if (new_version == NULL)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                if (skip_list_insert_version_cas(&next_at_0->versions, new_version, seq, list,
                                                 value_size) != 0)
                {
                    skip_list_free_node(new_node);
                    free(update);
                    return -1;
                }

                skip_list_free_node(new_node);
                free(update);
                return 0;
            }
            else if (cmp < 0)
            {
                /* next_at_0 < key, advance pred */
                pred = next_at_0;
            }
            /* else cmp > 0: next_at_0 > key, retry CAS with same pred */
        }

        /* retry CAS */
        cas_attempts++;
        if (cas_attempts > SKIP_LIST_MAX_CAS_ATTEMPTS)
        {
            skip_list_free_node(new_node);
            free(update);
            return -1;
        }
    }

    /* successfully inserted at level 0, now insert at higher levels */
    for (int i = 1; i <= new_level; i++)
    {
        skip_list_node_t *next;
        do
        {
            next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
            atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
        } while (!atomic_compare_exchange_weak_explicit(
            &update[i]->forward[i], &next, new_node, memory_order_release, memory_order_acquire));
    }

    /* the re-check before insertion should have caught any duplicates
     * if we reach here, we have a unique key -- complete normal insertion */
    /* set backward pointers after successful forward linking */
    for (int i = 0; i <= new_level; i++)
    {
        atomic_store_explicit(&BACKWARD_PTR(new_node, i, new_level), update[i],
                              memory_order_release);

        skip_list_node_t *next = atomic_load_explicit(&new_node->forward[i], memory_order_acquire);
        if (next != NULL && !NODE_IS_SENTINEL(next))
        {
            skip_list_node_t *expected = update[i];
            atomic_compare_exchange_strong_explicit(&BACKWARD_PTR(next, i, next->level), &expected,
                                                    new_node, memory_order_release,
                                                    memory_order_acquire);
        }
    }

    atomic_fetch_add_explicit(&list->total_size, key_size + value_size, memory_order_relaxed);
    atomic_fetch_add_explicit(&list->entry_count, 1, memory_order_relaxed);

    free(update);
    return 0;
}

int skip_list_get_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                           size_t *value_size, time_t *ttl, uint8_t *deleted, uint64_t *seq,
                           uint64_t snapshot_seq, skip_list_visibility_check_fn visibility_check,
                           void *visibility_ctx)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = header;
    int max_level = atomic_load_explicit(&list->level, memory_order_acquire); /* cache level */

    /* find the node */
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
        /* read uncommitted: see all versions, use latest */
        if (version == NULL) return -1;
    }
    else
    {
        /**
         * find the newest committed version with seq <= snapshot_seq.
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
            /* nersion is too new or not committed -- check next (older) version */
            version = atomic_load_explicit(&version->next, memory_order_acquire);
        }

        if (version == NULL) return -1; /* no visible version */
    }

    /* always set ttl if provided */
    if (ttl != NULL) *ttl = version->ttl;

    if (version->ttl > 0 && version->ttl < time(NULL))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);
        return 0; /* return success but mark as expired/deleted */
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