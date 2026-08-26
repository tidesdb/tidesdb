/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "datastructures/skip_list/skip_list_internal.h"

/**
 * skip_list_new_full
 * build a skip list with no arena, optionally sharing a cached-time clock; keys are ordered
 * byte-wise
 * @param list out -- the new list, owned by the caller
 * @param max_level maximum level a node may reach, must be positive
 * @param probability level-promotion probability, must be in (0,1)
 * @param cached_time borrowed clock the list reads instead of time(NULL), or NULL
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
static int skip_list_new_full(skip_list_t **list, const int max_level, const float probability,
                              _Atomic(int64_t) *cached_time)
{
    if (list == NULL || max_level <= 0 || probability <= 0.0f || probability >= 1.0f) return -1;

    skip_list_t *new_list = (skip_list_t *)malloc(sizeof(skip_list_t));
    if (new_list == NULL) return -1;

    atomic_init(&new_list->level, 0);
    new_list->max_level = max_level;
    new_list->probability = probability;
    new_list->cached_time = cached_time;
    new_list->arena = NULL;

    if (cached_time != NULL)
    {
        atomic_store_explicit(cached_time, (int64_t)tdb_get_current_time(), memory_order_seq_cst);
    }

    atomic_init(&new_list->data_bytes, 0);
    atomic_init(&new_list->memory_bytes, 0);
    atomic_init(&new_list->entry_count, 0);
    atomic_init(&new_list->min_seq, UINT64_MAX);

    /* sentinel nodes carry no keys -- they are identified by the sentinel flag */
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

int skip_list_new(skip_list_t **list, const int max_level, const float probability)
{
    return skip_list_new_full(list, max_level, probability, NULL);
}

int skip_list_new_with_arena(skip_list_t **list, const int max_level, const float probability,
                             _Atomic(int64_t) *cached_time, arena_pool_t *pool)
{
    const int rc = skip_list_new_full(list, max_level, probability, cached_time);
    if (rc != 0) return rc;

    /* the skip list is written by many threads concurrently, so it needs the concurrent arena */
    (*list)->arena = arena_create_concurrent(pool);
    if ((*list)->arena == NULL)
    {
        skip_list_free(*list);
        *list = NULL;
        return -1;
    }

    return 0;
}

/* xorshift64* generator parameters -- the three shift distances and the final odd multiplier that
 * define the sequence */
#define SKIP_LIST_XORSHIFT_SHIFT_A    12
#define SKIP_LIST_XORSHIFT_SHIFT_B    25
#define SKIP_LIST_XORSHIFT_SHIFT_C    27
#define SKIP_LIST_XORSHIFT_MULTIPLIER 0x2545F4914F6CDD1DULL

/* converting a 64-bit draw to a uniform double in [0, 1) -- keep the top 53 bits (a double's
 * mantissa width) and scale by 1 / 2^53 */
#define SKIP_LIST_RANDOM_DISCARD_BITS 11
#define SKIP_LIST_RANDOM_SCALE        (1.0 / 9007199254740992.0)

/* the low bits of an 8-byte-aligned address are always zero, so shift them off when mixing an
 * address into the thread-local seed */
#define SKIP_LIST_SEED_ADDR_SHIFT 3

/**
 * skip_list_xorshift64star
 * fast thread-local RNG for skip list level selection using xorshift64* algorithm
 * @param state pointer to thread-local RNG state
 * @return pseudo-random 64-bit value
 */
static inline uint64_t skip_list_xorshift64star(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> SKIP_LIST_XORSHIFT_SHIFT_A;
    x ^= x << SKIP_LIST_XORSHIFT_SHIFT_B;
    x ^= x >> SKIP_LIST_XORSHIFT_SHIFT_C;
    *state = x;
    return x * SKIP_LIST_XORSHIFT_MULTIPLIER;
}

int skip_list_random_level(const skip_list_t *list)
{
    if (list == NULL) return -1;

    /* thread-local RNG state */
    static _Thread_local uint64_t rng_state = 0;
    if (SKIP_LIST_UNLIKELY(rng_state == 0))
    {
        /** seed with thread ID + address entropy for uniqueness
         * avoids time() syscall on hot path */
        rng_state =
            (uint64_t)TDB_THREAD_ID() ^ ((uintptr_t)&rng_state >> SKIP_LIST_SEED_ADDR_SHIFT);
        if (rng_state == 0) rng_state = 1; /* ensure non-zero */
    }

    /* geometric level distribution for the configured probability where a level is promoted
     * while a fresh uniform draw stays below p. averages ~1/(1-p) draws (~1.33 at
     * p=0.25), each a cheap xorshift + compare. */
    const double p = (double)list->probability;
    int level = 0;
    while (level < list->max_level)
    {
        const uint64_t rnd = skip_list_xorshift64star(&rng_state);
        const double u = (double)(rnd >> SKIP_LIST_RANDOM_DISCARD_BITS) * SKIP_LIST_RANDOM_SCALE;
        if (u >= p) break;
        level++;
    }

    return level;
}

int skip_list_compare_keys(const skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    if (list == NULL || key1 == NULL || key2 == NULL) return 0;
    return skip_list_key_cmp(key1, key1_size, key2, key2_size);
}

/**
 * skip_list_predecessor
 * forward-searches for the last node whose key is strictly less than `key`, or for
 * the last node in the list when key == NULL. used for reverse navigation unlike
 * the per-node backward pointers (which are maintained best-effort and can be left
 * stale by concurrent inserts, so a backward walk may skip nodes), forward[0] is the
 * linearizable structure, so this is always complete.
 * @return the predecessor node, or the header sentinel when none exists
 */
skip_list_node_t *skip_list_predecessor(const skip_list_t *list, skip_list_node_t *header,
                                        const uint8_t *key, const size_t key_size)
{
    if (key == NULL) return skip_list_descend_to_end(list, header);
    return skip_list_descend(list, header, key, key_size, SKIP_LIST_DESCEND_BELOW);
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);

    if (list->arena == NULL)
    {
        /* no arena -- walk and free each node individually */
        skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);
        while (current != NULL && !NODE_IS_SENTINEL(current))
        {
            skip_list_node_t *next =
                atomic_load_explicit(&current->forward[0], memory_order_acquire);
            (void)skip_list_free_node(current);
            current = next;
        }
    }

    const int max_level = list->max_level;
    for (int i = 0; i <= max_level; i++)
    {
        atomic_store_explicit(&header->forward[i], tail, memory_order_release);
        atomic_store_explicit(&BACKWARD_PTR(tail, i, max_level), header, memory_order_release);
    }

    /* with an arena the old nodes and versions are one bulk reclaim; once the list is relinked to
     * empty their chunks return to the pool. the sentinels are malloc'd, not arena-backed, so this
     * is safe */
    if (list->arena != NULL) arena_reset(list->arena);

    atomic_store_explicit(&list->level, 0, memory_order_release);
    atomic_store_explicit(&list->data_bytes, 0, memory_order_release);
    atomic_store_explicit(&list->memory_bytes, 0, memory_order_release);
    atomic_store_explicit(&list->entry_count, 0, memory_order_release);
    atomic_store_explicit(&list->min_seq, UINT64_MAX, memory_order_release);

    return 0;
}

void skip_list_free(skip_list_t *list)
{
    if (list == NULL) return;

    if (list->arena != NULL)
    {
        /* arena path -- destroy the arena to bulk-free every node and version, then free the two
         * sentinels, which are malloc'd rather than arena-backed */
        arena_destroy(list->arena);
        list->arena = NULL;

        skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
        skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
        (void)skip_list_free_node(header);
        (void)skip_list_free_node(tail);
    }
    else
    {
        /* no arena -- walk and free each node individually */
        (void)skip_list_clear(list);

        skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
        skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
        (void)skip_list_free_node(header);
        (void)skip_list_free_node(tail);
    }

    free(list);
}

size_t skip_list_get_data_bytes(skip_list_t *list)
{
    if (list == NULL) return 0;
    return atomic_load_explicit(&list->data_bytes, memory_order_acquire);
}

size_t skip_list_get_memory_bytes(skip_list_t *list)
{
    if (list == NULL) return 0;
    return atomic_load_explicit(&list->memory_bytes, memory_order_acquire);
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

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);

    /* forward-reseek the last node, then step back via forward search (not the
     * stale-prone backward pointers) until a valid (non-deleted, non-expired)
     * entry or the header */
    const int64_t current_time = skip_list_get_current_time(list);
    skip_list_node_t *current = skip_list_predecessor(list, header, NULL, 0);
    while (current != header && !NODE_IS_SENTINEL(current))
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (!skip_list_version_is_invalid_with_time(version, current_time))
        {
            *key = (uint8_t *)malloc(current->key_size);
            if (*key == NULL) return -1;
            memcpy(*key, current->key, current->key_size);
            *key_size = current->key_size;
            return 0;
        }
        current = skip_list_predecessor(list, header, current->key, current->key_size);
    }

    return -1;
}
