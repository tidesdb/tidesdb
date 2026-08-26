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
 * skip_list_insert_version_cas
 * inserts a new version into a version chain maintaining descending seq order
 * handles out-of-order arrivals from concurrent transaction commits by inserting
 * at the correct position in the chain rather than only at the head
 * @param versions_ptr pointer to atomic version list head
 * @param new_version version to insert
 * @param seq sequence number (for validation)
 * @param list skip list (for the size counters)
 * @param data_size the value's logical length, which is what the data counter charges
 * @param tail_size the bytes trailing the version struct, which is the value for an inline version
 *                  and the value log id for a referenced one
 * @return 0 on success, -1 on failure (duplicate seq)
 */
int skip_list_insert_version_cas(_Atomic(skip_list_version_t *) *versions_ptr,
                                 skip_list_version_t *new_version, const uint64_t seq,
                                 skip_list_t *list, size_t data_size, size_t tail_size)
{
    skip_list_version_t *old_head;
    while (1)
    {
        old_head = atomic_load_explicit(versions_ptr, memory_order_acquire);

        if (old_head == NULL || seq > atomic_load_explicit(&old_head->seq, memory_order_acquire))
        {
            /* normal case -- new version is newest, prepend at head */
            atomic_store_explicit(&new_version->next, old_head, memory_order_relaxed);
            if (atomic_compare_exchange_weak_explicit(versions_ptr, &old_head, new_version,
                                                      memory_order_release, memory_order_acquire))
            {
                /* head prepend succeeded -- the version this one displaces from the head stays in
                 * the chain, since nothing prunes a version before the whole list is freed, so its
                 * bytes are still resident and must stay counted. accounting a prepend as an
                 * overwrite would let a key written repeatedly grow without ever moving the size
                 * the rotation threshold reads, and the memtable would never seal */
                atomic_fetch_add_explicit(&list->data_bytes, data_size, memory_order_relaxed);
                atomic_fetch_add_explicit(&list->memory_bytes, SKIP_LIST_VERSION_BYTES(tail_size),
                                          memory_order_relaxed);
                return 0;
            }
            /* CAS failed, retry from top */
            continue;
        }

        uint64_t head_seq = atomic_load_explicit(&old_head->seq, memory_order_acquire);
        if (seq == head_seq)
        {
            /* duplicate sequence -- reject */
            skip_list_free_version(list, new_version);
            return -1;
        }

        /* out-of-order arrival -- walk chain to find correct insertion point
         * chain is descending by seq, so find first node where next->seq < seq
         * then insert between current and next.
         * out-of-order inserts cannot use head CAS, so retry from the top
         * if the head changed. insertion splices into the chain. */
        skip_list_version_t *prev = old_head;
        skip_list_version_t *curr = atomic_load_explicit(&prev->next, memory_order_acquire);

        while (curr != NULL)
        {
            uint64_t curr_seq = atomic_load_explicit(&curr->seq, memory_order_acquire);
            if (seq == curr_seq)
            {
                /* duplicate in chain */
                skip_list_free_version(list, new_version);
                return -1;
            }
            if (seq > curr_seq)
            {
                break; /* insert between prev and curr */
            }
            prev = curr;
            curr = atomic_load_explicit(&prev->next, memory_order_acquire);
        }

        /* splice new_version between prev and curr */
        atomic_store_explicit(&new_version->next, curr, memory_order_relaxed);
        skip_list_version_t *expected_curr = curr;
        if (!atomic_compare_exchange_strong_explicit(&prev->next, &expected_curr, new_version,
                                                     memory_order_release, memory_order_acquire))
        {
            /* chain was modified concurrently, retry from top */
            continue;
        }

        /* successfully inserted in middle/tail -- charge the version */
        atomic_fetch_add_explicit(&list->data_bytes, data_size, memory_order_relaxed);
        atomic_fetch_add_explicit(&list->memory_bytes, SKIP_LIST_VERSION_BYTES(tail_size),
                                  memory_order_relaxed);
        return 0;
    }
}

/**
 * skip_list_create_version
 * creates a new version for a key
 * @param list skip list (for arena allocation)
 * @param value value data, NULL when the value lives in the value log
 * @param value_size size of value, the logical length either way
 * @param vlog_id the value log entry holding the value, read only when flags carry
 *                SKIP_LIST_FLAG_VLOG_REF
 * @param ttl time-to-live
 * @param flags version flags (bitmask of SKIP_LIST_FLAG_*)
 * @param seq sequence number for MVCC
 * @return pointer to new version, NULL on failure
 */
skip_list_version_t *skip_list_create_version(const skip_list_t *list, const uint8_t *value,
                                              const size_t value_size, const uint64_t vlog_id,
                                              const int64_t ttl, const uint8_t flags, uint64_t seq)
{
    /* combine version struct + whatever trails it into a single allocation, which halves the
     * malloc calls and improves cache locality. the trailer is the value bytes for an inline
     * version and the value log id for a referenced one */
    const size_t tail = skip_list_version_tail_bytes(value, value_size, flags);
    skip_list_version_t *version =
        (skip_list_version_t *)skip_list_alloc(list, sizeof(skip_list_version_t) + tail);
    if (version == NULL) return NULL;

    if (flags & SKIP_LIST_FLAG_VLOG_REF)
    {
        /* the bytes are in the value log, so the version holds the id and the logical length and
         * leaves the value pointer null. the flag is what tells a reader the two apart */
        version->value = NULL;
        version->value_size = value_size;
        memcpy((uint8_t *)version + sizeof(skip_list_version_t), &vlog_id, sizeof(vlog_id));
    }
    else if (value != NULL && value_size > 0)
    {
        version->value = (uint8_t *)(version + 1); /* value follows struct in same allocation */
        memcpy(version->value, value, value_size);
        version->value_size = value_size;
    }
    else
    {
        version->value = NULL;
        version->value_size = 0;
    }

    atomic_init(&version->flags, flags);
    atomic_init(&version->seq, seq);
    version->ttl = ttl;
    atomic_init(&version->next, NULL);
    return version;
}

/**
 * skip_list_free_version
 * frees a single version
 * @param list skip list (for arena deallocation)
 * @param version version to free
 */
void skip_list_free_version(const skip_list_t *list, skip_list_version_t *version)
{
    if (version == NULL) return;
    /* value is embedded in same allocation as version struct -- single free */
    skip_list_dealloc(list, version);
}

/**
 * skip_list_free_version_list
 * frees a linked list of versions
 * @param list skip list (for arena deallocation)
 * @param head head of version list
 */
void skip_list_free_version_list(const skip_list_t *list, skip_list_version_t *head)
{
    while (head != NULL)
    {
        skip_list_version_t *next = atomic_load_explicit(&head->next, memory_order_acquire);
        skip_list_free_version(list, head);
        head = next;
    }
}

/**
 * skip_list_create_sentinel
 * creates a sentinel node (header or tail)
 * @param level level of the node
 * @return pointer to new sentinel node, NULL on failure
 */
skip_list_node_t *skip_list_create_sentinel(const int level)
{
    size_t pointers_size = SKIP_LIST_NODE_PTR_SLOTS(level) * sizeof(_Atomic(skip_list_node_t *));
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
                                        const int64_t ttl, const uint8_t flags)
{
    if (key == NULL || key_size == 0) return NULL;

    /* combine node struct + forward/backward pointers + key into a single allocation
     * this eliminates one malloc per node and co-locates key data for cache locality */
    size_t pointers_size = SKIP_LIST_NODE_PTR_SLOTS(level) * sizeof(_Atomic(skip_list_node_t *));
    skip_list_node_t *node =
        (skip_list_node_t *)malloc(sizeof(skip_list_node_t) + pointers_size + key_size);
    if (node == NULL) return NULL;

    node->key = (uint8_t *)node + sizeof(skip_list_node_t) + pointers_size;
    memcpy(node->key, key, key_size);
    node->key_size = key_size;
    node->level = (uint8_t)level;
    node->node_flags = 0; /* not a sentinel */

    const int is_tombstone = (flags & SKIP_LIST_FLAG_DELETED) != 0;
    skip_list_version_t *initial_version = NULL;
    if (value != NULL || is_tombstone)
    {
        initial_version = skip_list_create_version(NULL, value, value_size, 0, ttl, flags, 0);
        if (initial_version == NULL)
        {
            /* for non-tombstones, version creation failure is fatal
             * for tombstones, NULL version is acceptable */
            if (!is_tombstone)
            {
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

/**
 * skip_list_free_node_internal
 * arena-aware node free -- simply no-op when arena is active
 * @param list the owning list, read for its allocator
 * @param node the node to free
 * @return 0 on success, -1 when node is NULL
 */
int skip_list_free_node_internal(const skip_list_t *list, skip_list_node_t *node)
{
    if (node == NULL) return -1;
    skip_list_version_t *versions = atomic_load_explicit(&node->versions, memory_order_acquire);
    skip_list_free_version_list(list, versions);
    /* key is embedded in same allocation as node -- single free */
    skip_list_dealloc(list, node);
    return 0;
}

int skip_list_free_node(skip_list_node_t *node)
{
    if (node == NULL) return -1;
    skip_list_version_t *versions = atomic_load_explicit(&node->versions, memory_order_acquire);

    while (versions != NULL)
    {
        skip_list_version_t *next = atomic_load_explicit(&versions->next, memory_order_acquire);
        free(versions);
        versions = next;
    }
    free(node);
    return 0;
}
