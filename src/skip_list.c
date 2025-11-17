/*
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

#define SKIP_LIST_ARENA_SIZE  (2 * 1024 * 1024) /* 2MB per arena */
#define SKIP_LIST_ARENA_ALIGN 8                 /* 8-byte alignment */

#define NODE_KEY(node) \
    (NODE_KEY_IS_INLINE(node) ? (node)->key_data.key_inline : (node)->key_data.key_ptr)
#define NODE_VALUE(node) \
    (NODE_VALUE_IS_INLINE(node) ? (node)->value_data.value_inline : (node)->value_data.value_ptr)

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
 * skip_list_arena_create
 * @param capacity the capacity of the arena
 * @return the created arena, or NULL on failure
 */
static skip_list_arena_t *skip_list_arena_create(size_t capacity)
{
    skip_list_arena_t *arena = malloc(sizeof(skip_list_arena_t));
    if (!arena) return NULL;

    arena->buffer = (uint8_t *)malloc(capacity);
    if (!arena->buffer)
    {
        free(arena);
        return NULL;
    }

    arena->capacity = capacity;
    atomic_store_explicit(&arena->offset, 0, memory_order_relaxed);
    arena->next = NULL;

    return arena;
}

/**
 * skip_list_arena_alloc
 * @param arena_ptr the pointer to the arena to allocate from
 * @param size the size to allocate
 * @return the allocated memory, or NULL on failure
 */
static void *skip_list_arena_alloc(skip_list_arena_t **arena_ptr, size_t size)
{
    if (!arena_ptr) return NULL;
    if (!*arena_ptr) return NULL;

    size = (size + SKIP_LIST_ARENA_ALIGN - 1) & ~(SKIP_LIST_ARENA_ALIGN - 1);

    /* retry allocation in case arena gets replaced by another thread */
    for (int retry = 0; retry < ARENA_ALLOC_RETRY_COUNT; retry++)
    {
        skip_list_arena_t *arena = *arena_ptr;

        /* try to allocate from current arena using CAS loop */
        while (1)
        {
            size_t old_offset = atomic_load_explicit(&arena->offset, memory_order_relaxed);
            size_t new_offset = old_offset + size;

            /* check if allocation would exceed capacity */
            if (new_offset > arena->capacity)
            {
                /* arena is full, break and retry with potentially new arena */
                break;
            }

            /* try to atomically reserve space */
            if (atomic_compare_exchange_weak_explicit(&arena->offset, &old_offset, new_offset,
                                                      memory_order_relaxed, memory_order_relaxed))
            {
                /* success */
                return arena->buffer + old_offset;
            }
            /* CAS failed, retry the inner loop */
        }

        /* arena is full, try to create a new one (only on first retry) */
        if (retry == 0)
        {
            skip_list_arena_t *new_arena = skip_list_arena_create(SKIP_LIST_ARENA_SIZE);
            if (!new_arena) return NULL;

            /* atomically update arena pointer, only one thread should succeed */
            skip_list_arena_t *expected = arena;
            new_arena->next = arena;

            /* try to swap in the new arena */
            if (atomic_compare_exchange_strong_ptr((_Atomic(void *) *)arena_ptr, (void **)&expected,
                                                   new_arena))
            {
                /* CAS succeeded, new_arena is now owned by *arena_ptr, retry allocation */
                continue;
            }
            else
            {
                /* another thread already created a new arena, free ours and retry */
                free(new_arena->buffer);
                free(new_arena);
            }
        }
        /* retry from the outer loop, arena might have been updated by another thread */
    }

    /* failed after retries */
    return NULL;
}

/**
 * skip_list_arena_free_all
 * @param arena the arena to free
 */
static void skip_list_arena_free_all(skip_list_arena_t *arena)
{
    while (arena)
    {
        skip_list_arena_t *next = arena->next;
        free(arena->buffer);
        free(arena);
        arena = next;
    }
}

skip_list_node_t *skip_list_create_node_with_arena(skip_list_arena_t **arena, int level,
                                                   const uint8_t *key, size_t key_size,
                                                   const uint8_t *value, size_t value_size,
                                                   time_t ttl, uint8_t deleted)
{
    if (level <= 0) return NULL;

    int key_inline = (key_size <= SKIP_LIST_INLINE_THRESHOLD);
    int value_inline = (value_size <= SKIP_LIST_INLINE_THRESHOLD);

    size_t pointer_array_size = (size_t)(2 * level) * sizeof(_Atomic(skip_list_node_t *));
    size_t node_size = sizeof(skip_list_node_t) + pointer_array_size;
    size_t total_size = node_size;

    if (!key_inline) total_size += key_size;
    if (!value_inline) total_size += value_size;

    skip_list_node_t *node = NULL;
    int from_arena = 0;

    if (arena && *arena)
    {
        node = (skip_list_node_t *)skip_list_arena_alloc(arena, total_size);
        if (node) from_arena = 1;
    }

    if (node == NULL)
    {
        node = (skip_list_node_t *)malloc(total_size);
        from_arena = 0;
    }

    if (node == NULL) return NULL;

    /* init all forward and backward pointers to NULL
     * forward pointers indices 0 to level-1
     * backwards pointers indices level to 2*level-1 */
    for (int i = 0; i < level * 2; i++)
    {
        atomic_store_explicit(&node->forward[i], NULL, memory_order_relaxed);
    }

    node->key_size = (uint32_t)key_size;
    node->value_size = (uint32_t)value_size;
    node->ttl = ttl;
    node->level = (uint8_t)level;
    node->_padding = 0;

    /* we build packed flags byte */
    uint8_t flags_byte = 0;
    if (deleted) flags_byte |= SKIP_LIST_FLAG_DELETED;
    if (key_inline) flags_byte |= SKIP_LIST_FLAG_KEY_INLINE;
    if (value_inline) flags_byte |= SKIP_LIST_FLAG_VALUE_INLINE;
    if (from_arena) flags_byte |= SKIP_LIST_FLAG_ARENA_ALLOC;
    atomic_store_explicit(&node->flags, flags_byte, memory_order_relaxed);

    if (key_inline)
    {
        memcpy(node->key_data.key_inline, key, key_size);
    }
    else
    {
        uint8_t *key_storage = (uint8_t *)node + node_size;
        memcpy(key_storage, key, key_size);
        node->key_data.key_ptr = key_storage;
    }

    if (value_inline)
    {
        if (node->value_size > 0) memcpy(node->value_data.value_inline, value, value_size);
    }
    else
    {
        uint8_t *value_storage = (uint8_t *)node + node_size + (key_inline ? 0 : key_size);
        memcpy(value_storage, value, value_size);
        node->value_data.value_ptr = value_storage;
    }

    return node;
}

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl,
                                        uint8_t deleted)
{
    return skip_list_create_node_with_arena(NULL, level, key, key_size, value, value_size, ttl,
                                            deleted);
}

int skip_list_free_node(skip_list_node_t *node)
{
    if (node == NULL) return -1;

    if (!NODE_IS_ARENA_ALLOC(node))
    {
        free(node);
    }
    return 0;
}

int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node)
{
    (void)list;
    if (node == NULL) return -1;

    if (node->ttl != -1 && node->ttl < time(NULL))
    {
        return 1;
    }
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
    if (max_level <= 0 || probability <= 0.0 || probability >= 1.0) return -1;
    if (comparator == NULL) return -1;

    *list = (skip_list_t *)malloc(sizeof(skip_list_t));
    if (*list == NULL) return -1;

    atomic_store_explicit(&(*list)->level, 1, memory_order_relaxed);
    (*list)->max_level = max_level;
    (*list)->probability = probability;
    atomic_store_explicit(&(*list)->total_size, 0, memory_order_relaxed);
    (*list)->comparator = comparator;
    (*list)->comparator_ctx = comparator_ctx;

    (*list)->arena = skip_list_arena_create(SKIP_LIST_ARENA_SIZE);
    if ((*list)->arena == NULL)
    {
        free(*list);
        return -1;
    }

    uint8_t header_key[1] = {0};
    uint8_t header_value[1] = {0};
    skip_list_node_t *header = skip_list_create_node_with_arena(
        &(*list)->arena, max_level * 2, header_key, 1, header_value, 1, -1, 0);

    if (header == NULL)
    {
        skip_list_arena_free_all((*list)->arena);
        free(*list);
        return -1;
    }

    atomic_store_explicit(&(*list)->header, header, memory_order_release);
    atomic_store_explicit(&(*list)->tail, header, memory_order_release);

    return 0;
}

/**
 * skip_list_random_level
 * @param list the skip list
 * @return the random level
 */
static _Thread_local uint32_t tls_rng_state = 0;

/**
 * fast_rand32
 * @return a random 32-bit integer
 */
static inline uint32_t fast_rand32(void)
{
    if (tls_rng_state == 0)
    {
        tls_rng_state = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)&tls_rng_state;
    }

    uint32_t x = tls_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    tls_rng_state = x;
    return x;
}

int skip_list_random_level(skip_list_t *list)
{
    int level = 1;
    uint32_t r = fast_rand32();

    while ((r & 3) == 0 && level < list->max_level)
    {
        level++;
        r >>= 2;
    }

    return level;
}

int skip_list_compare_keys(skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    if (list->comparator == skip_list_comparator_memcmp || list->comparator == NULL)
    {
        size_t min_size = key1_size < key2_size ? key1_size : key2_size;
        int cmp = memcmp(key1, key2, min_size);
        if (cmp != 0) return cmp < 0 ? -1 : 1;
        return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
    }

    return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
}

int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl)
{
    if (list == NULL || key == NULL || key_size == 0) return -1;

    if (value_size > 0 && value == NULL) return -1;

    skip_list_node_t *update[64];
    skip_list_node_t *new_node = NULL;

retry:
    if (new_node != NULL)
    {
        if (!NODE_IS_ARENA_ALLOC(new_node))
        {
            free(new_node);
        }
        new_node = NULL;
    }

    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    /* search for insertion position we find predecessors at each level */
    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next != NULL)
        {
            const uint8_t *next_key = NODE_KEY(next);
            int cmp = skip_list_compare_keys(list, next_key, next->key_size, key, key_size);

            if (cmp >= 0) break; /* break on exact match or greater */

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
        update[i] = x;
    }

    skip_list_node_t *existing = atomic_load_explicit(&update[0]->forward[0], memory_order_acquire);

    if (existing != NULL)
    {
        const uint8_t *existing_key = NODE_KEY(existing);

        int cmp = skip_list_compare_keys(list, existing_key, existing->key_size, key, key_size);

        if (existing->key_size == key_size && cmp == 0)
        {
            /* create new node with same level as existing to maintain structure */
            int existing_level = existing->level;
            /* use arena allocation,failed CAS attempts will waste arena space but that's
             * acceptable arena memory is reclaimed when the skip list is freed */
            skip_list_node_t *replacement = skip_list_create_node_with_arena(
                &list->arena, existing_level, key, key_size, value, value_size, ttl, 0);
            if (replacement == NULL)
            {
                /* clean up new_node if it exists before returning */
                if (new_node != NULL && !NODE_IS_ARENA_ALLOC(new_node))
                {
                    free(new_node);
                }
                return -1;
            }

            /* copy forward and backward pointers from existing node */
            for (int i = 0; i < existing_level; i++)
            {
                skip_list_node_t *next =
                    atomic_load_explicit(&existing->forward[i], memory_order_acquire);
                atomic_store_explicit(&replacement->forward[i], next, memory_order_relaxed);

                /* copy backward pointer */
                skip_list_node_t *prev = atomic_load_explicit(
                    &BACKWARD_PTR(existing, i, list->max_level), memory_order_acquire);
                atomic_store_explicit(&BACKWARD_PTR(replacement, i, list->max_level), prev,
                                      memory_order_relaxed);
            }

            /* atomically replace at level 0 using CAS */
            skip_list_node_t *expected = existing;
            if (atomic_compare_exchange_strong_explicit(&update[0]->forward[0], &expected,
                                                        replacement, memory_order_release,
                                                        memory_order_acquire))
            {
                /* successfully replaced! now we update higher levels
                 * only update levels that exist in update[] (up to current_level) */
                int max_update_level =
                    (existing_level < current_level) ? existing_level : current_level;
                for (int i = 1; i < max_update_level; i++)
                {
                    expected = existing;
                    atomic_compare_exchange_strong_explicit(&update[i]->forward[i], &expected,
                                                            replacement, memory_order_release,
                                                            memory_order_acquire);
                }

                for (int i = 0; i < existing_level; i++)
                {
                    skip_list_node_t *next =
                        atomic_load_explicit(&replacement->forward[i], memory_order_acquire);
                    if (next != NULL)
                    {
                        /* update this successor's backward pointer to point to replacement */
                        atomic_store_explicit(&BACKWARD_PTR(next, i, list->max_level), replacement,
                                              memory_order_release);
                    }
                }

                /* old node is now unreachable from the skip list structure */
                atomic_fetch_add_explicit(&list->total_size, value_size, memory_order_relaxed);
                atomic_fetch_sub_explicit(&list->total_size, existing->value_size,
                                          memory_order_relaxed);

                /* free the old node if it was malloc'd (not arena-allocated) */
                if (!NODE_IS_ARENA_ALLOC(existing))
                {
                    free(existing);
                }

                return 0;
            }
            /* CAS failed, another thread modified the list
             * set new_node to replacement so retry path cleans it up */
            new_node = replacement;
            goto retry;
        }
    }

    /* gen random level for new node */
    int level = skip_list_random_level(list);

    /* if new level is higher than current, extend the list level */
    if (level > current_level)
    {
        for (int i = current_level; i < level; i++)
        {
            update[i] = header;
        }
        /* try to update list level, if it fails, someone else updated it, that's fine */
        atomic_compare_exchange_strong_explicit(&list->level, &current_level, level,
                                                memory_order_release, memory_order_relaxed);
    }

    /* create new node using arena allocation
     * failed CAS attempts will waste arena space but that's acceptable
     * arena memory is reclaimed when the skip list is freed */
    new_node = skip_list_create_node_with_arena(&list->arena, level, key, key_size, value,
                                                value_size, ttl, 0);
    if (new_node == NULL)
    {
        /* allocation failed, nothing to clean up */
        return -1;
    }

    /* set all forward pointers atomically before making node visible
     * read the current next pointers from our predecessors */
    for (int i = 0; i < level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
    }

    /* mem barrier to ensure all forward pointers are visible */
    atomic_thread_fence(memory_order_release);

    /* now try to insert at level 0, this makes the node visible */
    skip_list_node_t *expected = atomic_load_explicit(&update[0]->forward[0], memory_order_acquire);
    skip_list_node_t *new_node_next_0 =
        atomic_load_explicit(&new_node->forward[0], memory_order_relaxed);

    /* verify our forward pointer is still correct */
    if (expected != new_node_next_0)
    {
        goto retry;
    }

    /* CAS to insert at level 0 */
    if (!atomic_compare_exchange_strong_explicit(&update[0]->forward[0], &expected, new_node,
                                                 memory_order_release, memory_order_acquire))
    {
        goto retry;
    }

    /* successfully inserted at level 0, node is now visible */
    /* try to insert at higher levels */
    for (int i = 1; i < level; i++)
    {
        expected = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        skip_list_node_t *new_node_next_i =
            atomic_load_explicit(&new_node->forward[i], memory_order_relaxed);

        /* verify our forward pointer is still correct */
        if (expected != new_node_next_i)
        {
            /* skip this level, node is still valid at lower levels */
            break;
        }

        /* try CAS, if it fails, that's OK, node is valid at lower levels */
        atomic_compare_exchange_strong_explicit(&update[i]->forward[i], &expected, new_node,
                                                memory_order_release, memory_order_acquire);
    }

    /* update backward pointer for reverse iteration */
    atomic_store_explicit(&BACKWARD_PTR(new_node, 0, list->max_level), update[0],
                          memory_order_release);

    /* update tail if we're the last node */
    if (new_node_next_0 == NULL)
    {
        atomic_store_explicit(&list->tail, new_node, memory_order_release);
    }

    atomic_fetch_add_explicit(&list->total_size, key_size + value_size, memory_order_relaxed);
    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size)
{
    if (list == NULL || key == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;
    int current_level = atomic_load_explicit(&list->level, memory_order_relaxed);

    /* search for the key */
    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next != NULL)
        {
            const uint8_t *next_key = NODE_KEY(next);
            int cmp = skip_list_compare_keys(list, next_key, next->key_size, key, key_size);

            if (cmp >= 0) break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    /* check if key found */
    if (x != NULL && skip_list_compare_keys(list, NODE_KEY(x), x->key_size, key, key_size) == 0)
    {
        /* key exists, mark it as deleted */
        uint8_t old_flags = atomic_load(&x->flags);
        atomic_store_explicit(&x->flags, old_flags | SKIP_LIST_FLAG_DELETED, memory_order_release);
        return 0;
    }

    /* key not found - no-op */
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted)
{
    if (!list || !key || !value || !value_size) return -1;
    if (key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    int current_level = atomic_load_explicit(&list->level, memory_order_relaxed);

    /* search for key using skip list levels */
    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next)
        {
            const uint8_t *next_key = NODE_KEY(next);
            int cmp = skip_list_compare_keys(list, next_key, next->key_size, key, key_size);

            if (cmp >= 0)
            {
                /* found exact match or went past it */
                if (cmp == 0 && i == 0)
                {
                    x = next;
                    goto found;
                }
                break;
            }

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    /* check level 0 forward pointer for exact match */
    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);
    if (x == NULL) return -1;

    const uint8_t *x_key = NODE_KEY(x);
    if (skip_list_compare_keys(list, x_key, x->key_size, key, key_size) != 0)
    {
        return -1;
    }

found:
{
    /* check if deleted or expired (fast path most keys are not expired) */
    uint8_t is_deleted = NODE_IS_DELETED(x);
    uint8_t is_expired = 0;
    if (x->ttl > 0) /* only check expiration if TTL is actually set */
    {
        is_expired = (time(NULL) > x->ttl) ? 1 : 0;
    }

    if (deleted != NULL) *deleted = (is_deleted || is_expired);

    *value = (uint8_t *)malloc(x->value_size);
    if (*value == NULL)
    {
        return -1;
    }

    const uint8_t *x_value = NODE_VALUE(x);
    memcpy(*value, x_value, x->value_size);
    *value_size = x->value_size;

    return 0;
}
}

skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list)
{
    if (list == NULL) return NULL;

    skip_list_cursor_t *cursor = malloc(sizeof(skip_list_cursor_t));
    if (cursor == NULL) return NULL;

    cursor->list = list;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    cursor->current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    return cursor;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (next == NULL) return -1;

    cursor->current = next;
    return 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *prev = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    if (prev == header) return -1;

    cursor->current = prev;
    return 0;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor)
    {
        free(cursor);
    }
}

int skip_list_cursor_at_start(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    return cursor->current == header;
}

int skip_list_cursor_at_end(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    return next == NULL;
}

int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, time_t *ttl, uint8_t *deleted)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    *key = NODE_KEY(cursor->current);
    *key_size = cursor->current->key_size;
    *value = NODE_VALUE(cursor->current);
    *value_size = cursor->current->value_size;
    *ttl = cursor->current->ttl;
    *deleted = NODE_IS_DELETED(cursor->current);
    return 0;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);

    return (next != NULL) ? 1 : 0;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *prev = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    return (prev != header) ? 1 : 0;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (first == NULL) return -1;

    cursor->current = first;
    return 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);

    if (tail == header) return -1;

    cursor->current = tail;
    return 0;
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);

        /* free malloc'd nodes (not arena-allocated) */
        if (!NODE_IS_ARENA_ALLOC(current))
        {
            free(current);
        }
        /* arena-allocated nodes will be freed when arena is freed */

        current = next;
    }

    for (int i = 0; i < list->max_level * 2; i++)
    {
        atomic_store_explicit(&header->forward[i], NULL, memory_order_relaxed);
    }

    atomic_store_explicit(&list->tail, header, memory_order_release);
    atomic_store_explicit(&list->level, 1, memory_order_relaxed);
    atomic_store_explicit(&list->total_size, 0, memory_order_relaxed);

    return 0;
}

int skip_list_free(skip_list_t *list)
{
    if (list == NULL) return -1;
    (void)skip_list_clear(list);
    if (list->arena) skip_list_arena_free_all(list->arena);
    free(list);
    return 0;
}

int skip_list_get_size(skip_list_t *list)
{
    if (list == NULL) return -1;

    return (int)atomic_load_explicit(&list->total_size, memory_order_acquire);
}

int skip_list_count_entries(skip_list_t *list)
{
    if (list == NULL) return -1;

    int count = 0;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL)
    {
        if (!NODE_IS_DELETED(current))
        {
            count++;
        }
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    return count;
}

int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (current == NULL) return -1;

    while (current != NULL)
    {
        /* check if expired */
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;

        if (!NODE_IS_DELETED(current) && !is_expired)
        {
            *key = (uint8_t *)malloc(current->key_size);
            if (*key == NULL) return -1;

            const uint8_t *current_key = NODE_KEY(current);
            memcpy(*key, current_key, current->key_size);
            *key_size = current->key_size;
            return 0;
        }
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    /* if we reached the end without finding a valid node */
    return -1;
}

int skip_list_get_max_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    /* if list is empty (tail is header) */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);

    if (tail == header) return -1;

    /* walk backward to find a non-deleted, non-expired key */
    skip_list_node_t *current = tail;

    while (current != header)
    {
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;

        if (!NODE_IS_DELETED(current) && !is_expired)
        {
            break;
        }

        /* move to previous node */
        current =
            atomic_load_explicit(&BACKWARD_PTR(current, 0, list->max_level), memory_order_acquire);
    }

    /* if we couldn't find a valid node */
    if (current == header) return -1;

    *key = (uint8_t *)malloc(current->key_size);
    if (*key == NULL) return -1;

    memcpy(*key, NODE_KEY(current), current->key_size);
    *key_size = current->key_size;

    return 0;
}

int skip_list_cursor_init_at_end(skip_list_cursor_t **cursor, skip_list_t *list)
{
    if (list == NULL || cursor == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);

    if (tail == header)
    {
        return -1;
    }

    /* list is not empty, safe to allocate cursor */
    if (*cursor == NULL)
    {
        *cursor = (skip_list_cursor_t *)malloc(sizeof(skip_list_cursor_t));
        if (*cursor == NULL) return -1;
    }

    (*cursor)->list = list;
    (*cursor)->current = tail;

    return 0;
}

int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || cursor->list == NULL || key == NULL) return -1;

    skip_list_t *list = cursor->list;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;
    int current_level = atomic_load_explicit(&list->level, memory_order_relaxed);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        while (next)
        {
            if (skip_list_compare_keys(list, NODE_KEY(next), next->key_size, key, key_size) >= 0)
                break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        }
    }

    cursor->current = x;
    return 0;
}

int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || cursor->list == NULL || key == NULL) return -1;

    skip_list_t *list = cursor->list;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;
    int current_level = atomic_load_explicit(&list->level, memory_order_relaxed);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        while (next)
        {
            if (skip_list_compare_keys(list, NODE_KEY(next), next->key_size, key, key_size) > 0)
                break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        }
    }

    if (x == header) return -1;

    cursor->current = x;
    return 0;
}