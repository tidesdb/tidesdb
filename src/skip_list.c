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
    ((node)->key_is_inline ? (node)->key_data.key_inline : (node)->key_data.key_ptr)
#define NODE_VALUE(node) \
    ((node)->value_is_inline ? (node)->value_data.value_inline : (node)->value_data.value_ptr)

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

/*
 * skip_list_arena_create
 * @param capacity the capacity of the arena
 * @return the created arena, or NULL on failure
 */
static skip_list_arena_t *skip_list_arena_create(size_t capacity)
{
    skip_list_arena_t *arena = (skip_list_arena_t *)malloc(sizeof(skip_list_arena_t));
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

/*
 * skip_list_arena_alloc
 * @param arena_ptr the pointer to the arena to allocate from
 * @param size the size to allocate
 * @return the allocated memory, or NULL on failure
 */
static void *skip_list_arena_alloc(skip_list_arena_t **arena_ptr, size_t size)
{
    if (!arena_ptr || !*arena_ptr) return NULL;

    size = (size + SKIP_LIST_ARENA_ALIGN - 1) & ~(SKIP_LIST_ARENA_ALIGN - 1);

    /* retry allocation in case arena gets replaced by another thread */
    for (int retry = 0; retry < 10; retry++)
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
                /* Successfully allocated */
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

            /* ytu to swap in the new arena */
            if (!__atomic_compare_exchange_n(arena_ptr, &expected, new_arena, 0, __ATOMIC_RELEASE,
                                             __ATOMIC_ACQUIRE))
            {
                /* another thread already created a new arena, free ours */
                free(new_arena->buffer);
                free(new_arena);
            }
        }
        /* retry from the outer loop, arena might have been updated by another thread */
    }

    /* failed after retries */
    return NULL;
}

/*
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

    node->key_size = key_size;
    node->value_size = value_size;
    node->ttl = ttl;
    atomic_store_explicit(&node->deleted, deleted, memory_order_relaxed);
    node->key_is_inline = key_inline;
    node->value_is_inline = value_inline;
    node->arena_allocated = from_arena;
    node->level = level;

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
        memcpy(node->value_data.value_inline, value, value_size);
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

    if (!node->arena_allocated)
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

/*
 * skip_list_random_level
 * @param list the skip list
 * @return the random level
 */
static _Thread_local uint32_t tls_rng_state = 0;

/*
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
    if (!list || !key || !value) return -1;
    if (key_size == 0) return -1;

    skip_list_node_t *update[64];
    skip_list_node_t *new_node = NULL;

retry:
    if (new_node != NULL)
    {
        skip_list_free_node(new_node);
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

            if (cmp > 0) break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
        update[i] = x;
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

    /* create new node, we use arena allocation when available */
    new_node = skip_list_create_node_with_arena(&list->arena, level, key, key_size, value,
                                                value_size, ttl, 0);
    if (new_node == NULL) return -1;

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
        /* list changed, retry */
        goto retry;
    }

    /* CAS to insert at level 0 */
    if (!atomic_compare_exchange_strong_explicit(&update[0]->forward[0], &expected, new_node,
                                                 memory_order_release, memory_order_acquire))
    {
        /* CAS failed, list changed, retry */
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
        atomic_store_explicit(&x->deleted, 1, memory_order_release);
        return 0;
    }

    uint8_t empty_value = 0;
    skip_list_node_t *tombstone =
        skip_list_create_node_with_arena(&list->arena, 1, key, key_size, &empty_value, 1, -1, 1);
    if (tombstone == NULL) return -1;

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&header->forward[i], memory_order_acquire);
        skip_list_node_t *prev = header;

        while (next != NULL)
        {
            const uint8_t *next_key = NODE_KEY(next);
            int cmp = skip_list_compare_keys(list, next_key, next->key_size, key, key_size);
            if (cmp > 0) break;
            prev = next;
            next = atomic_load_explicit(&next->forward[i], memory_order_acquire);
        }

        if (i == 0)
        {
            /* insert at level 0 */
            atomic_store_explicit(&tombstone->forward[0], next, memory_order_release);
            atomic_store_explicit(&prev->forward[0], tombstone, memory_order_release);
            atomic_store_explicit(&BACKWARD_PTR(tombstone, 0, list->max_level), prev,
                                  memory_order_release);
            if (next == NULL)
            {
                atomic_store_explicit(&list->tail, tombstone, memory_order_release);
            }
        }
    }

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

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next)
        {
            const uint8_t *next_key =
                next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;
            size_t min_size = (next->key_size < key_size) ? next->key_size : key_size;
            int cmp = memcmp(next_key, key, min_size);
            if (cmp == 0)
                cmp = (next->key_size < key_size) ? -1 : (next->key_size > key_size) ? 1 : 0;

            if (cmp >= 0) break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    if (x == NULL) return -1;

    const uint8_t *x_key = x->key_is_inline ? x->key_data.key_inline : x->key_data.key_ptr;
    if (x->key_size != key_size || memcmp(x_key, key, key_size) != 0)
    {
        return -1;
    }

    /* we find the last matching key (most recent version) */
    /* continue scanning forward at level 0 while keys match */
    skip_list_node_t *last_match = x;
    skip_list_node_t *next = atomic_load_explicit(&x->forward[0], memory_order_acquire);
    while (next != NULL)
    {
        const uint8_t *next_key = NODE_KEY(next);
        if (next->key_size == key_size && memcmp(next_key, key, key_size) == 0)
        {
            last_match = next;
            next = atomic_load_explicit(&next->forward[0], memory_order_acquire);
        }
        else
        {
            break;
        }
    }
    x = last_match;

    uint8_t is_deleted = atomic_load_explicit(&x->deleted, memory_order_acquire);
    uint8_t is_expired = 0;
    if (x->ttl != -1)
    {
        is_expired = (x->ttl < time(NULL)) ? 1 : 0;
    }

    if (deleted != NULL) *deleted = (is_deleted || is_expired);

    *value = (uint8_t *)malloc(x->value_size);
    if (*value == NULL)
    {
        return -1;
    }

    const uint8_t *x_value =
        x->value_is_inline ? x->value_data.value_inline : x->value_data.value_ptr;
    memcpy(*value, x_value, x->value_size);
    *value_size = x->value_size;

    return 0;
}

skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list)
{
    if (list == NULL) return NULL;

    skip_list_cursor_t *cursor = (skip_list_cursor_t *)malloc(sizeof(skip_list_cursor_t));
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

    /* skip forward through duplicate keys to find the most recent version */
    /** if next entry has same key, current is an old version */
    const uint8_t *current_key = cursor->current->key_is_inline
                                     ? cursor->current->key_data.key_inline
                                     : cursor->current->key_data.key_ptr;
    size_t current_key_size = cursor->current->key_size;

    while (1)
    {
        skip_list_node_t *peek_next =
            atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
        if (peek_next == NULL) break;

        const uint8_t *next_key =
            peek_next->key_is_inline ? peek_next->key_data.key_inline : peek_next->key_data.key_ptr;

        /* if next key is different, we're at the latest version */
        if (peek_next->key_size != current_key_size ||
            memcmp(next_key, current_key, current_key_size) != 0)
        {
            break;
        }

        /* same key, advance to newer version */
        cursor->current = peek_next;
    }

    return 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    /* get current key before moving */
    const uint8_t *current_key = cursor->current->key_is_inline
                                     ? cursor->current->key_data.key_inline
                                     : cursor->current->key_data.key_ptr;
    size_t current_key_size = cursor->current->key_size;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);

    /* skip backward through duplicate keys (older versions of current key) */
    while (1)
    {
        skip_list_node_t *prev = atomic_load_explicit(
            &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

        if (prev == header) return -1;

        const uint8_t *prev_key =
            prev->key_is_inline ? prev->key_data.key_inline : prev->key_data.key_ptr;

        /* if previous key is different, stop */
        if (prev->key_size != current_key_size ||
            memcmp(prev_key, current_key, current_key_size) != 0)
        {
            /* we move to this different key (which is the latest version of that key) */
            cursor->current = prev;

            /* now skip forward to find the latest version of this new key */
            const uint8_t *new_key = prev_key;
            size_t new_key_size = prev->key_size;

            while (1)
            {
                skip_list_node_t *peek_next =
                    atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
                if (peek_next == NULL) break;

                const uint8_t *next_key = peek_next->key_is_inline ? peek_next->key_data.key_inline
                                                                   : peek_next->key_data.key_ptr;

                if (peek_next->key_size != new_key_size ||
                    memcmp(next_key, new_key, new_key_size) != 0)
                {
                    break;
                }

                cursor->current = peek_next;
            }

            return 0;
        }

        /* same key as current, keep going backward */
        cursor->current = prev;
    }
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
    *deleted = atomic_load_explicit(&cursor->current->deleted, memory_order_acquire);
    return 0;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    /* skip forward past duplicates of current key to find next unique key */
    const uint8_t *current_key = cursor->current->key_is_inline
                                     ? cursor->current->key_data.key_inline
                                     : cursor->current->key_data.key_ptr;
    size_t current_key_size = cursor->current->key_size;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);

    while (next != NULL)
    {
        const uint8_t *next_key =
            next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

        /* if different key, we have a next unique key */
        if (next->key_size != current_key_size ||
            memcmp(next_key, current_key, current_key_size) != 0)
        {
            return 1;
        }

        /* same key, keep looking */
        next = atomic_load_explicit(&next->forward[0], memory_order_acquire);
    }

    return 0;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);

    /* skip backward past duplicates of current key to find previous unique key */
    const uint8_t *current_key = cursor->current->key_is_inline
                                     ? cursor->current->key_data.key_inline
                                     : cursor->current->key_data.key_ptr;
    size_t current_key_size = cursor->current->key_size;

    skip_list_node_t *prev = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    while (prev != header)
    {
        const uint8_t *prev_key =
            prev->key_is_inline ? prev->key_data.key_inline : prev->key_data.key_ptr;

        /* if different key, we have a previous unique key */
        if (prev->key_size != current_key_size ||
            memcmp(prev_key, current_key, current_key_size) != 0)
        {
            return 1;
        }

        /* same key, keep looking backward */
        prev = atomic_load_explicit(&BACKWARD_PTR(prev, 0, cursor->list->max_level),
                                    memory_order_acquire);
    }

    return 0;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (first == NULL) return -1;

    cursor->current = first;

    /* skip forward to the latest version of the first key */
    const uint8_t *first_key =
        first->key_is_inline ? first->key_data.key_inline : first->key_data.key_ptr;
    size_t first_key_size = first->key_size;

    while (1)
    {
        skip_list_node_t *next =
            atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
        if (next == NULL) break;

        const uint8_t *next_key =
            next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

        if (next->key_size != first_key_size || memcmp(next_key, first_key, first_key_size) != 0)
        {
            break;
        }

        cursor->current = next;
    }

    return 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);

    if (tail == header) return -1;

    /* tail points to the last node, which is the latest version of the last key */
    /* since we insert duplicates after existing keys */
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
        if (!current->arena_allocated)
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

    /* clear the list (frees malloc'd nodes but not arena-allocated ones) */
    if (skip_list_clear(list) != 0) return -1;

    /* free all arenas (this frees all arena-allocated nodes including header) */
    if (list->arena) skip_list_arena_free_all(list->arena);

    /* free the list structure itself */
    free(list);
    return 0;
}

skip_list_t *skip_list_copy(skip_list_t *list)
{
    if (list == NULL) return NULL;

    skip_list_t *new_list = NULL;
    if (skip_list_new_with_comparator(&new_list, list->max_level, list->probability,
                                      list->comparator, list->comparator_ctx) != 0)
        return NULL;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL)
    {
        if (!atomic_load_explicit(&current->deleted, memory_order_acquire))
        {
            (void)skip_list_put(new_list, NODE_KEY(current), current->key_size, NODE_VALUE(current),
                                current->value_size, current->ttl);
        }
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    return new_list;
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
        /* skip forward to the latest version of this key */
        const uint8_t *current_key =
            current->key_is_inline ? current->key_data.key_inline : current->key_data.key_ptr;
        size_t current_key_size = current->key_size;

        skip_list_node_t *latest = current;
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);

        while (next != NULL)
        {
            const uint8_t *next_key =
                next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

            /* if same key, advance to newer version */
            if (next->key_size == current_key_size &&
                memcmp(next_key, current_key, current_key_size) == 0)
            {
                latest = next;
                next = atomic_load_explicit(&next->forward[0], memory_order_acquire);
            }
            else
            {
                break;
            }
        }

        /* count only if the latest version is not deleted */
        if (!atomic_load_explicit(&latest->deleted, memory_order_acquire))
        {
            count++;
        }

        /* move to the next different key */
        current = atomic_load_explicit(&latest->forward[0], memory_order_acquire);
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
        /* skip forward to the latest version of this key */
        const uint8_t *current_key =
            current->key_is_inline ? current->key_data.key_inline : current->key_data.key_ptr;
        size_t current_key_size = current->key_size;

        skip_list_node_t *latest = current;
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);

        while (next != NULL)
        {
            const uint8_t *next_key =
                next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

            if (next->key_size == current_key_size &&
                memcmp(next_key, current_key, current_key_size) == 0)
            {
                latest = next;
                next = atomic_load_explicit(&next->forward[0], memory_order_acquire);
            }
            else
            {
                break;
            }
        }

        /* check if the latest version is valid */
        uint8_t is_expired = (latest->ttl != -1 && latest->ttl < time(NULL)) ? 1 : 0;
        if (!latest->deleted && !is_expired)
        {
            /* found a valid node */
            current = latest;
            break;
        }

        /* move to next different key */
        current = atomic_load_explicit(&latest->forward[0], memory_order_acquire);
    }

    /* if we reached the end without finding a valid node */
    if (current == NULL) return -1;

    *key = (uint8_t *)malloc(current->key_size);
    if (*key == NULL) return -1;

    memcpy(*key, NODE_KEY(current), current->key_size);
    *key_size = current->key_size;

    return 0;
}

int skip_list_get_max_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    /* if list is empty (tail is header) */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);

    if (tail == header) return -1;

    /* start from tail (which is the latest version of the last key) */
    /* walk backward to find a non-deleted, non-expired key */
    skip_list_node_t *current = tail;

    while (current != header)
    {
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;

        if (!current->deleted && !is_expired)
        {
            /* found a valid node (already the latest version since tail is latest) */
            break;
        }

        /* skip backward past all older versions of this key */
        const uint8_t *current_key =
            current->key_is_inline ? current->key_data.key_inline : current->key_data.key_ptr;
        size_t current_key_size = current->key_size;

        while (current != header)
        {
            skip_list_node_t *prev = atomic_load_explicit(
                &BACKWARD_PTR(current, 0, list->max_level), memory_order_acquire);
            if (prev == header) break;

            const uint8_t *prev_key =
                prev->key_is_inline ? prev->key_data.key_inline : prev->key_data.key_ptr;

            /* if different key, stop */
            if (prev->key_size != current_key_size ||
                memcmp(prev_key, current_key, current_key_size) != 0)
            {
                current = prev;
                break;
            }

            /* same key, keep going backward */
            current = prev;
        }
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

    if (*cursor == NULL)
    {
        *cursor = (skip_list_cursor_t *)malloc(sizeof(skip_list_cursor_t));
        if (*cursor == NULL) return -1;
    }

    (*cursor)->list = list;

    /* if list is empty (tail is header) */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);

    if (tail == header)
    {
        (*cursor)->current = NULL;
        return -1;
    }

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

    if (x != header)
    {
        const uint8_t *x_key = x->key_is_inline ? x->key_data.key_inline : x->key_data.key_ptr;
        size_t x_key_size = x->key_size;

        while (1)
        {
            skip_list_node_t *next =
                atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
            if (next == NULL) break;

            const uint8_t *next_key =
                next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

            if (next->key_size != x_key_size || memcmp(next_key, x_key, x_key_size) != 0)
            {
                break;
            }

            cursor->current = next;
        }
    }

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

    const uint8_t *x_key = x->key_is_inline ? x->key_data.key_inline : x->key_data.key_ptr;
    size_t x_key_size = x->key_size;

    while (1)
    {
        skip_list_node_t *next =
            atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
        if (next == NULL) break;

        const uint8_t *next_key =
            next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;

        if (next->key_size != x_key_size || memcmp(next_key, x_key, x_key_size) != 0)
        {
            break;
        }

        cursor->current = next;
    }

    return 0;
}