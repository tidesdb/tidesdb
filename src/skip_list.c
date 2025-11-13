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

static void *skip_list_arena_alloc(skip_list_arena_t **arena_ptr, size_t size)
{
    if (!arena_ptr || !*arena_ptr) return NULL;

    size = (size + SKIP_LIST_ARENA_ALIGN - 1) & ~(SKIP_LIST_ARENA_ALIGN - 1);

    skip_list_arena_t *arena = *arena_ptr;

    size_t old_offset = atomic_load_explicit(&arena->offset, memory_order_relaxed);
    if (old_offset + size <= arena->capacity)
    {
        atomic_store_explicit(&arena->offset, old_offset + size, memory_order_relaxed);
        return arena->buffer + old_offset;
    }

    skip_list_arena_t *new_arena = skip_list_arena_create(SKIP_LIST_ARENA_SIZE);
    if (!new_arena) return NULL;

    new_arena->next = arena;
    *arena_ptr = new_arena;

    atomic_store_explicit(&new_arena->offset, size, memory_order_relaxed);
    return new_arena->buffer;
}

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

    if (level <= 3)
    {
        atomic_store_explicit(&node->forward[0], NULL, memory_order_relaxed);
        if (level > 1) atomic_store_explicit(&node->forward[1], NULL, memory_order_relaxed);
        if (level > 2) atomic_store_explicit(&node->forward[2], NULL, memory_order_relaxed);
    }
    else
    {
        for (int i = 0; i < level + level; i++)
        {
            atomic_store_explicit(&node->forward[i], NULL, memory_order_relaxed);
        }
    }

    node->key_size = key_size;
    node->value_size = value_size;
    node->ttl = ttl;
    node->deleted = deleted;
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

    atomic_store_explicit(&node->ref_count, 1, memory_order_relaxed);

    return node;
}

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl,
                                        uint8_t deleted)
{
    return skip_list_create_node_with_arena(NULL, level, key, key_size, value, value_size, ttl,
                                            deleted);
}

void skip_list_retain_node(skip_list_node_t *node)
{
    if (node == NULL) return;
    atomic_fetch_add_explicit(&node->ref_count, 1, memory_order_relaxed);
}

void skip_list_release_node(skip_list_node_t *node)
{
    if (node == NULL) return;

    uint64_t old_count = atomic_fetch_sub_explicit(&node->ref_count, 1, memory_order_relaxed);

    if (old_count == 1)
    {
        skip_list_free_node(node);
    }
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

    atomic_store_explicit(&(*list)->global_epoch, 0, memory_order_relaxed);
    (*list)->retired_head = NULL;
    if (pthread_mutex_init(&(*list)->retired_lock, NULL) != 0)
    {
        skip_list_arena_free_all((*list)->arena);
        free(*list);
        return -1;
    }

    uint8_t header_key[1] = {0};
    uint8_t header_value[1] = {0};
    skip_list_node_t *header = skip_list_create_node_with_arena(
        &(*list)->arena, max_level * 2, header_key, 1, header_value, 1, -1, 0);

    if (header == NULL)
    {
        pthread_mutex_destroy(&(*list)->retired_lock);
        skip_list_arena_free_all((*list)->arena);
        free(*list);
        return -1;
    }

    atomic_store_explicit(&(*list)->header, header, memory_order_release);
    atomic_store_explicit(&(*list)->tail, header, memory_order_release);

    return 0;
}

static _Thread_local uint32_t tls_rng_state = 0;

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

static void retire_node(skip_list_t *list, skip_list_node_t *node)
{
    uint64_t current_epoch = atomic_load(&list->global_epoch);

    retired_node_t *retired = malloc(sizeof(retired_node_t));
    if (!retired)
    {
        return;
    }

    retired->node = node;
    retired->retire_epoch = current_epoch;

    pthread_mutex_lock(&list->retired_lock);
    retired->next = list->retired_head;
    list->retired_head = retired;
    pthread_mutex_unlock(&list->retired_lock);
}

static void reclaim_old_nodes(skip_list_t *list)
{
    uint64_t current_epoch = atomic_load(&list->global_epoch);

    if (current_epoch < 10) return;

    uint64_t safe_epoch = current_epoch - 10;

    pthread_mutex_lock(&list->retired_lock);

    retired_node_t **prev_ptr = &list->retired_head;
    retired_node_t *curr = list->retired_head;

    while (curr)
    {
        if (curr->retire_epoch <= safe_epoch)
        {
            retired_node_t *to_free = curr;
            *prev_ptr = curr->next;
            curr = curr->next;

            /* release the node (will free when ref count hits zero) */
            skip_list_release_node(to_free->node);
            free(to_free);
        }
        else
        {
            prev_ptr = &curr->next;
            curr = curr->next;
        }
    }

    pthread_mutex_unlock(&list->retired_lock);
}

int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl)
{
    skip_list_node_t *update[64];

    int current_level = atomic_load_explicit(&list->level, memory_order_relaxed);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        int loop_count = 0;
        while (next)
        {
            PREFETCH_READ(next);

            const uint8_t *next_key =
                next->key_is_inline ? next->key_data.key_inline : next->key_data.key_ptr;
            PREFETCH_READ(next_key);
            size_t min_size = (next->key_size < key_size) ? next->key_size : key_size;
            int cmp = memcmp(next_key, key, min_size);
            if (cmp == 0)
                cmp = (next->key_size < key_size) ? -1 : (next->key_size > key_size) ? 1 : 0;

            if (cmp >= 0) break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);

            if (++loop_count > 1000)
            {
                printf("[SKIP_LIST] ERROR: infinite loop detected at level %d, loop_count=%d\n", i,
                       loop_count);
                fflush(stdout);
                return -1;
            }
        }
        update[i] = x;
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    int key_exists = 0;
    if (x)
    {
        const uint8_t *x_key = x->key_is_inline ? x->key_data.key_inline : x->key_data.key_ptr;
        if (x->key_size == key_size)
        {
            key_exists = (memcmp(x_key, key, key_size) == 0);
        }
    }

    if (key_exists)
    {
        x->deleted = 1;
        retire_node(list, x);
    }

    int level = skip_list_random_level(list);
    if (level > current_level)
    {
        for (int i = current_level; i < level; i++)
        {
            update[i] = header;
        }
        atomic_store_explicit(&list->level, level, memory_order_relaxed);
    }

    x = skip_list_create_node_with_arena(&list->arena, level, key, key_size, value, value_size, ttl,
                                         0);
    if (x == NULL)
    {
        return -1;
    }

    for (int i = 0; i < level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        atomic_store_explicit(&x->forward[i], next, memory_order_release);
        atomic_store_explicit(&update[i]->forward[i], x, memory_order_release);
    }

    /* update backward pointers at level 0 for reverse iteration */
    skip_list_node_t *next_at_0 = atomic_load_explicit(&x->forward[0], memory_order_acquire);
    BACKWARD_PTR(x, 0, list->max_level) = update[0];
    if (next_at_0 != NULL)
    {
        BACKWARD_PTR(next_at_0, 0, list->max_level) = x;
    }
    else
    {
        /* no next node means this is the new tail */
        atomic_store_explicit(&list->tail, x, memory_order_relaxed);
    }

    atomic_fetch_add_explicit(&list->total_size, key_size + value_size, memory_order_relaxed);

    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size)
{
    if (list == NULL || key == NULL) return -1;

    skip_list_node_t *stack_update[64];
    skip_list_node_t **update;

    if (list->max_level <= 64)
    {
        update = stack_update;
    }
    else
    {
        update = (skip_list_node_t **)malloc((size_t)list->max_level * sizeof(skip_list_node_t *));
        if (update == NULL)
        {
            return -1;
        }
    }

    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        while (next)
        {
            PREFETCH_READ(next);
            PREFETCH_READ(NODE_KEY(next));

            if (skip_list_compare_keys(list, NODE_KEY(next), next->key_size, key, key_size) >= 0)
                break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        }
        update[i] = x;
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_relaxed);

    /* check if key found */
    if (x == NULL || skip_list_compare_keys(list, NODE_KEY(x), x->key_size, key, key_size) != 0)
    {
        if (list->max_level > 64) free(update);
        return -1;
    }

    if (x->deleted)
    {
        return 0;
    }

    /* create tombstone node (deleted=1) with same key */
    uint8_t tombstone_value[1] = {0};
    int level = skip_list_random_level(list);
    if (level > current_level)
    {
        for (int i = current_level; i < level; i++)
        {
            update[i] = header;
        }
        atomic_store_explicit(&list->level, level, memory_order_release);
    }

    skip_list_node_t *tombstone = skip_list_create_node_with_arena(
        &list->arena, list->max_level, key, key_size, tombstone_value, 1, -1, 1);
    if (tombstone == NULL)
    {
        if (list->max_level > 64) free(update);
        return -1;
    }

    /* copy pointers from old node at levels >= tombstone's level */
    for (int i = level; i < list->max_level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        atomic_store_explicit(&tombstone->forward[i], next, memory_order_relaxed);

        skip_list_node_t *prev =
            atomic_load_explicit(&BACKWARD_PTR(x, i, list->max_level), memory_order_acquire);
        atomic_store_explicit(&BACKWARD_PTR(tombstone, i, list->max_level), prev,
                              memory_order_relaxed);
    }

    /* atomically swap in the tombstone node */
    for (int i = 0; i < level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        if (next == x)
        {
            skip_list_node_t *x_next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
            atomic_store_explicit(&tombstone->forward[i], x_next, memory_order_release);
            atomic_store_explicit(&update[i]->forward[i], tombstone, memory_order_release);

            atomic_store_explicit(&BACKWARD_PTR(tombstone, i, list->max_level), update[i],
                                  memory_order_release);

            if (x_next != NULL)
            {
                atomic_store_explicit(&BACKWARD_PTR(x_next, i, list->max_level), tombstone,
                                      memory_order_release);
            }
        }
        else
        {
            atomic_store_explicit(&tombstone->forward[i], next, memory_order_release);
            atomic_store_explicit(&update[i]->forward[i], tombstone, memory_order_release);

            atomic_store_explicit(&BACKWARD_PTR(tombstone, i, list->max_level), update[i],
                                  memory_order_release);

            if (next != NULL)
            {
                atomic_store_explicit(&BACKWARD_PTR(next, i, list->max_level), tombstone,
                                      memory_order_release);
            }
        }
    }

    /* update any remaining higher-level pointers that point to old node */
    for (int i = level; i < current_level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        if (next == x)
        {
            skip_list_node_t *x_next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
            atomic_store_explicit(&update[i]->forward[i], x_next, memory_order_release);

            /* update backward pointer of next node if it exists */
            if (x_next != NULL)
            {
                atomic_store_explicit(&BACKWARD_PTR(x_next, i, list->max_level), update[i],
                                      memory_order_release);
            }
        }
    }

    skip_list_node_t *current_tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    if (current_tail == x)
    {
        atomic_store_explicit(&list->tail, tombstone, memory_order_release);
    }

    /* update size (subtract deleted key and value sizes) */
    size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
    atomic_store_explicit(&list->total_size, old_total - (x->key_size + x->value_size),
                          memory_order_relaxed);

    /* release reference to old node (will be freed when all readers done) */
    skip_list_release_node(x);

    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted)
{
    /* periodically reclaim old nodes (safe here since we hold references) */
    static _Thread_local int read_count = 0;
    if (++read_count >= 100)
    {
        reclaim_old_nodes(list);
        read_count = 0;
    }

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

    uint8_t is_deleted = x->deleted;
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

    if (cursor->current) skip_list_retain_node(cursor->current);

    return cursor;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (next == NULL) return -1;

    skip_list_retain_node(next);
    skip_list_release_node(cursor->current);

    cursor->current = next;
    return 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *prev = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    if (prev == header) return -1;
    skip_list_retain_node(prev);
    skip_list_release_node(cursor->current);

    cursor->current = prev;
    return 0;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor)
    {
        if (cursor->current) skip_list_release_node(cursor->current);
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
    *deleted = cursor->current->deleted;
    return 0;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    return next != NULL;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *prev = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    return prev != header;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (first == NULL) return -1;

    skip_list_retain_node(first);
    if (cursor->current) skip_list_release_node(cursor->current);

    cursor->current = first;
    return 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);

    if (tail == header) return -1;

    skip_list_retain_node(tail);
    if (cursor->current) skip_list_release_node(cursor->current);

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
        skip_list_release_node(current);
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

    if (skip_list_clear(list) != 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_release_node(header);

    retired_node_t *retired = list->retired_head;
    while (retired)
    {
        retired_node_t *next = retired->next;
        skip_list_release_node(retired->node);
        free(retired);
        retired = next;
    }

    if (list->arena) skip_list_arena_free_all(list->arena);

    pthread_mutex_destroy(&list->retired_lock);
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
        if (!current->deleted)
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
        if (!current->deleted)
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
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;
        if (current->deleted || is_expired)
        {
            current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
            continue;
        }

        /* we found a valid node */
        break;
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

    /* start from tail and find non-deleted node */
    skip_list_node_t *current = tail;

    while (current != header)
    {
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;

        if (current->deleted || is_expired)
        {
            current = atomic_load_explicit(&BACKWARD_PTR(current, 0, list->max_level),
                                           memory_order_acquire);
            continue;
        }

        /* we found a valid node */
        break;
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

    skip_list_retain_node((*cursor)->current);

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
            PREFETCH_READ(next);
            PREFETCH_READ(NODE_KEY(next));

            if (skip_list_compare_keys(list, NODE_KEY(next), next->key_size, key, key_size) >= 0)
                break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        }
    }

    skip_list_retain_node(x);
    if (cursor->current) skip_list_release_node(cursor->current);

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
            PREFETCH_READ(next);
            PREFETCH_READ(NODE_KEY(next));

            if (skip_list_compare_keys(list, NODE_KEY(next), next->key_size, key, key_size) > 0)
                break;

            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
        }
    }

    if (x == header) return -1;

    skip_list_retain_node(x);
    if (cursor->current) skip_list_release_node(cursor->current);

    cursor->current = x;
    return 0;
}