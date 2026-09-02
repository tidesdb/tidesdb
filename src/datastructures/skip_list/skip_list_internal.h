/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __SKIP_LIST_INTERNAL_H__
#define __SKIP_LIST_INTERNAL_H__

#include "base/arena.h"  /* the shared region allocator backing node and version storage */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "datastructures/skip_list/skip_list.h"

/* internal helpers shared across the skip_list translation units; not part of the public api */
int skip_list_insert_version_cas(_Atomic(skip_list_version_t *) *versions_ptr,
                                 skip_list_version_t *new_version, const uint64_t seq,
                                 skip_list_t *list, size_t data_size, size_t tail_size);
skip_list_version_t *skip_list_create_version(const skip_list_t *list, const uint8_t *value,
                                              size_t value_size, uint64_t vlog_id, int64_t ttl,
                                              uint8_t flags, uint64_t seq);
void skip_list_free_version(const skip_list_t *list, skip_list_version_t *version);
void skip_list_free_version_list(const skip_list_t *list, skip_list_version_t *head);
skip_list_node_t *skip_list_create_sentinel(const int level);
int skip_list_free_node_internal(const skip_list_t *list, skip_list_node_t *node);
skip_list_node_t *skip_list_predecessor(const skip_list_t *list, skip_list_node_t *header,
                                        const uint8_t *key, size_t key_size);
void skip_list_update_min_seq(skip_list_t *list, const uint64_t seq);

/**
 * skip_list_alloc
 * allocates memory from the arena if present, otherwise from malloc
 * @param list skip list (used to check for arena)
 * @param size number of bytes
 * @return pointer to memory, or NULL on failure
 */
static inline void *skip_list_alloc(const skip_list_t *list, size_t size)
{
    if (list != NULL && list->arena != NULL)
    {
        return arena_alloc(list->arena, size, SKIP_LIST_ARENA_ALIGNMENT);
    }
    return malloc(size);
}

/**
 * skip_list_dealloc
 * frees memory -- no-op when arena is active (bulk free on arena destroy)
 * @param list skip list (used to check for arena)
 * @param ptr pointer to free
 */
static inline void skip_list_dealloc(const skip_list_t *list, void *ptr)
{
    if (list != NULL && list->arena != NULL) return; /* no-op */
    free(ptr);
}

/* where a descent stops relative to a node whose key equals the target. a lookup and a forward seek
 * want the node before it; a backward seek wants the node itself */
#define SKIP_LIST_DESCEND_BELOW       0
#define SKIP_LIST_DESCEND_AT_OR_BELOW 1

/**
 * skip_list_descend
 * walk down the levels to the last node whose key sorts below the target. this is the first half of
 * every seek -- a point lookup finishes by hopping forward from here, a cursor positions here and
 * steps -- and it is shared rather than copied because it was copied for a while and the copies
 * drifted, one of them losing the prefetch hints the others kept.
 *
 * inline, and in the header, because it is the hottest loop in the engine and its callers live in
 * different translation units
 * @param list the list, read for its current height
 * @param header the header sentinel to start from, which a cursor may hold cached
 * @param key the key to descend toward, never NULL -- the end-of-list walk is
 *        skip_list_descend_to_end, kept apart so this loop carries no test the key rules out
 * @param key_size length of key
 * @param stop SKIP_LIST_DESCEND_BELOW to stop before a node equal to the key, which is what a
 *        lookup and a forward seek want, or SKIP_LIST_DESCEND_AT_OR_BELOW to land on it, which is
 *        what a backward seek wants
 * @return the last node ordered below the key, or header itself when no node is
 */
static inline skip_list_node_t *skip_list_descend(const skip_list_t *list, skip_list_node_t *header,
                                                  const uint8_t *key, const size_t key_size,
                                                  const int stop)
{
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *current = header;

    /* prefetch ahead of the sentinel check, so the compare below is not waiting on the load */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        if (SKIP_LIST_LIKELY(next != NULL))
        {
            PREFETCH_READ(next);
            PREFETCH_READ(next->key);
        }

        while (next != NULL && !NODE_IS_SENTINEL(next))
        {
            const int cmp = tdb_key_cmp(next->key, next->key_size, key, key_size);
            if (cmp > 0 || (cmp == 0 && stop == SKIP_LIST_DESCEND_BELOW)) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
            if (SKIP_LIST_LIKELY(next != NULL))
            {
                PREFETCH_READ(next);
                PREFETCH_READ(next->key);
            }
        }
    }
    return current;
}

/**
 * skip_list_descend_to_end
 * walk down the levels to the last node in the list, the same descent with nothing to compare
 * against. separate from skip_list_descend so neither loop carries the other's test
 * @param list the list, read for its current height
 * @param header the header sentinel to start from
 * @return the last node, or header when the list is empty
 */
static inline skip_list_node_t *skip_list_descend_to_end(const skip_list_t *list,
                                                         skip_list_node_t *header)
{
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *current = header;

    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && !NODE_IS_SENTINEL(next))
        {
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }
    return current;
}

/* stack-allocated update array size for the batch/put paths; lists taller than this
 * fall back to a heap update array. file-scope so it is defined exactly once. */
#define SKIP_LIST_STACK_UPDATE_SIZE 64

/* forward declaration; defined below */
static inline int skip_list_version_is_invalid_with_time(skip_list_version_t *version,
                                                         int64_t current_time);

/**
 * skip_list_get_latest_valid_version
 * fast path for accessing the latest valid version
 * @param node node whose version chain to scan
 * @param current_time current time for TTL validation
 * @return latest valid version, or NULL if none
 */
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
 * skip_list_get_current_time
 * gets current time using cached time if available, otherwise syscall
 * @param list skip list (may be NULL)
 * @return current time as int64_t for consistent 64-bit handling
 */
static inline int64_t skip_list_get_current_time(const skip_list_t *list)
{
#if defined(__MINGW32__) && !defined(__MINGW64__)
    /* on MinGW x86 the cached time has cross-thread visibility issues (suspected compiler bug),
     * so read the clock directly */
    (void)list;
    return (int64_t)time(NULL);
#else
    if (list != NULL && list->cached_time != NULL)
    {
        return atomic_load_explicit(list->cached_time, memory_order_relaxed);
    }
    return (int64_t)time(NULL);
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
    /* at or past the deadline, matching the point get in skip_list_read.c and the sstable read.
     * with a strict less-than an iterator kept an entry the whole of the second a get already
     * reported gone, so the two disagreed for one second on every lapsing key */
    if (version->ttl > 0 && version->ttl <= current_time) return 1;
    return 0;
}

/**
 * skip_list_validate_sequence
 * validates that new sequence number does not duplicate an existing version
 * @param existing_version existing version to check against
 * @param new_seq new sequence number
 * @return 0 if valid (new_seq != existing), -1 if duplicate
 */
static inline int skip_list_validate_sequence(skip_list_version_t *existing_version,
                                              uint64_t new_seq)
{
    if (existing_version != NULL)
    {
        uint64_t existing_seq = atomic_load_explicit(&existing_version->seq, memory_order_acquire);
        if (new_seq == existing_seq) return -1;
    }
    return 0;
}

#endif /* __SKIP_LIST_INTERNAL_H__ */
