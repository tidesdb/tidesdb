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

    /* safely extract uint64_t values (little-endian) */
    memcpy(&val1, key1, sizeof(uint64_t));
    memcpy(&val2, key2, sizeof(uint64_t));

    if (val1 < val2) return -1;
    if (val1 > val2) return 1;
    return 0;
}

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl,
                                        uint8_t deleted)
{
    /* validate level to prevent overflow */
    if (level <= 0) return NULL;

    size_t pointer_array_size = (size_t)(2 * level) * sizeof(_Atomic(skip_list_node_t *));
    size_t total_size = sizeof(skip_list_node_t) + pointer_array_size;

    skip_list_node_t *node = (skip_list_node_t *)malloc(total_size);
    if (node == NULL) return NULL;

    /* zero out the entire structure including flexible array */
    memset(node, 0, total_size);

    /* allocate memory for the key */
    node->key = (uint8_t *)malloc(key_size);
    if (node->key == NULL)
    {
        free(node);
        return NULL;
    }

    memcpy(node->key, key, key_size);
    node->key_size = key_size;

    /* allocate memory for the value */
    node->value = (uint8_t *)malloc(value_size);
    if (node->value == NULL)
    {
        free(node->key);
        free(node);
        return NULL;
    }

    memcpy(node->value, value, value_size);
    node->value_size = value_size;

    /* set the TTL and deleted flag (immutable) */
    node->ttl = ttl;
    node->deleted = deleted;

    /* initialize reference count to 1 */
    atomic_store_explicit(&node->ref_count, 1, memory_order_relaxed);

    /* init forward and backward pointers to NULL */
    for (int i = 0; i < level * 2; i++)
    {
        atomic_store_explicit(&node->forward[i], NULL, memory_order_relaxed);
    }

    return node;
}

void skip_list_retain_node(skip_list_node_t *node)
{
    if (node == NULL) return;
    atomic_fetch_add_explicit(&node->ref_count, 1, memory_order_relaxed);
}

void skip_list_release_node(skip_list_node_t *node)
{
    if (node == NULL) return;

    uint64_t old_count = atomic_fetch_sub_explicit(&node->ref_count, 1, memory_order_release);

    /* if we just decremented to zero, free the node */
    if (old_count == 1)
    {
        /* acquire fence to ensure all previous operations are visible */
        atomic_thread_fence(memory_order_acquire);
        skip_list_free_node(node);
    }
}

int skip_list_free_node(skip_list_node_t *node)
{
    if (node == NULL) return -1;

    free(node->key);
    node->key = NULL;
    free(node->value);
    node->value = NULL;
    free(node);
    return 0;
}

int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node)
{
    (void)list;
    if (node == NULL) return -1;

    if (node->ttl != -1 && node->ttl < time(NULL))
    {
        return 1; /* node has expired */
    }
    return 0; /* node is valid */
}

int skip_list_new(skip_list_t **list, int max_level, float probability)
{
    return skip_list_new_with_comparator(list, max_level, probability, skip_list_comparator_memcmp,
                                         NULL);
}

int skip_list_new_with_comparator(skip_list_t **list, int max_level, float probability,
                                  skip_list_comparator_fn comparator, void *comparator_ctx)
{
    /* validate max_level and probability */
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

    if (pthread_mutex_init(&(*list)->write_lock, NULL) != 0)
    {
        free(*list);
        return -1;
    }

    uint8_t header_key[1] = {0};
    uint8_t header_value[1] = {0};
    skip_list_node_t *header =
        skip_list_create_node(max_level * 2, header_key, 1, header_value, 1, -1, 0);

    if (header == NULL)
    {
        pthread_mutex_destroy(&(*list)->write_lock);
        free(*list);
        return -1;
    }

    atomic_store_explicit(&(*list)->header, header, memory_order_release);
    atomic_store_explicit(&(*list)->tail, header, memory_order_release);

    return 0;
}

int skip_list_random_level(skip_list_t *list)
{
    int level = 1;
    float rand_max_inv = 1.0f / (float)RAND_MAX;
    while (((float)rand() * rand_max_inv) < list->probability && level < list->max_level)
        level++;  // NOLINT(cert-msc30-c,cert-msc50-cpp) - acceptable for skip list randomization

    return level;
}

int skip_list_compare_keys(skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    int cmp = list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
    /* Normalize to -1, 0, or 1 */
    return cmp == 0 ? 0 : (cmp < 0 ? -1 : 1);
}

int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl)
{
    if (list == NULL || key == NULL || value == NULL) return -1;

    /* only writers block each other, readers never blocked */
    pthread_mutex_lock(&list->write_lock);

    skip_list_node_t **update =
        (skip_list_node_t **)malloc((size_t)list->max_level * sizeof(skip_list_node_t *));
    if (update == NULL)
    {
        pthread_mutex_unlock(&list->write_lock);
        return -1;
    }

    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    /* traverse to find position */
    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
        update[i] = x;
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    /* check if key exists */
    if (x && skip_list_compare_keys(list, x->key, x->key_size, key, key_size) == 0)
    {
        /* key exists, create new node to replace it (COW) */
        int level = skip_list_random_level(list);
        if (level > current_level)
        {
            for (int i = current_level; i < level; i++)
            {
                update[i] = header;
            }
            atomic_store_explicit(&list->level, level, memory_order_release);
        }

        /* create new node with updated value */
        skip_list_node_t *new_node =
            skip_list_create_node(list->max_level, key, key_size, value, value_size, ttl, 0);
        if (new_node == NULL)
        {
            free(update);
            pthread_mutex_unlock(&list->write_lock);
            return -1;
        }

        /* copy pointers from old node at levels >= new node's level */
        for (int i = level; i < list->max_level; i++)
        {
            skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
            atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);

            skip_list_node_t *prev =
                atomic_load_explicit(&BACKWARD_PTR(x, i, list->max_level), memory_order_acquire);
            atomic_store_explicit(&BACKWARD_PTR(new_node, i, list->max_level), prev,
                                  memory_order_relaxed);
        }

        /* update pointers atomically */
        for (int i = 0; i < level; i++)
        {
            skip_list_node_t *next =
                atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
            if (next == x)
            {
                /* we're replacing the old node */
                skip_list_node_t *x_next =
                    atomic_load_explicit(&x->forward[i], memory_order_acquire);
                atomic_store_explicit(&new_node->forward[i], x_next, memory_order_release);
                atomic_store_explicit(&update[i]->forward[i], new_node, memory_order_release);

                /* update backward pointers */
                atomic_store_explicit(&BACKWARD_PTR(new_node, i, list->max_level), update[i],
                                      memory_order_release);

                if (x_next != NULL)
                {
                    atomic_store_explicit(&BACKWARD_PTR(x_next, i, list->max_level), new_node,
                                          memory_order_release);
                }
            }
            else
            {
                /* normal insertion */
                atomic_store_explicit(&new_node->forward[i], next, memory_order_release);
                atomic_store_explicit(&update[i]->forward[i], new_node, memory_order_release);

                atomic_store_explicit(&BACKWARD_PTR(new_node, i, list->max_level), update[i],
                                      memory_order_release);

                if (next != NULL)
                {
                    atomic_store_explicit(&BACKWARD_PTR(next, i, list->max_level), new_node,
                                          memory_order_release);
                }
            }
        }

        /* update any remaining higher-level pointers that point to old node */
        for (int i = level; i < current_level; i++)
        {
            skip_list_node_t *next =
                atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
            if (next == x)
            {
                /* skip over the old node at this level */
                skip_list_node_t *x_next =
                    atomic_load_explicit(&x->forward[i], memory_order_acquire);
                atomic_store_explicit(&update[i]->forward[i], x_next, memory_order_release);

                /* update backward pointer of next node if it exists */
                if (x_next != NULL)
                {
                    atomic_store_explicit(&BACKWARD_PTR(x_next, i, list->max_level), update[i],
                                          memory_order_release);
                }
            }
        }

        /* update tail if necessary */
        skip_list_node_t *current_tail = atomic_load_explicit(&list->tail, memory_order_acquire);
        if (current_tail == x ||
            (current_tail != header &&
             skip_list_compare_keys(list, new_node->key, new_node->key_size, current_tail->key,
                                    current_tail->key_size) > 0))
        {
            atomic_store_explicit(&list->tail, new_node, memory_order_release);
        }

        /* update size */
        size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
        size_t new_total = old_total - x->value_size + value_size;
        atomic_store_explicit(&list->total_size, new_total, memory_order_relaxed);

        /* old node will be freed when all references are released */
        skip_list_release_node(x);

        free(update);
        pthread_mutex_unlock(&list->write_lock);
        return 0;
    }

    /* key not found, insert new node */
    int level = skip_list_random_level(list);
    if (level > current_level)
    {
        for (int i = current_level; i < level; i++)
        {
            update[i] = header;
        }
        atomic_store_explicit(&list->level, level, memory_order_release);
    }

    x = skip_list_create_node(list->max_level, key, key_size, value, value_size, ttl, 0);
    if (x == NULL)
    {
        free(update);
        pthread_mutex_unlock(&list->write_lock);
        return -1;
    }

    /* update forward and backward pointers atomically */
    for (int i = 0; i < level; i++)
    {
        skip_list_node_t *next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
        atomic_store_explicit(&x->forward[i], next, memory_order_release);
        atomic_store_explicit(&update[i]->forward[i], x, memory_order_release);

        /* update backward pointers */
        atomic_store_explicit(&BACKWARD_PTR(x, i, list->max_level), update[i],
                              memory_order_release);

        if (next != NULL)
        {
            atomic_store_explicit(&BACKWARD_PTR(next, i, list->max_level), x, memory_order_release);
        }
    }

    /* update tail if this is the new last node */
    skip_list_node_t *current_tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    if (current_tail == header ||
        skip_list_compare_keys(list, x->key, x->key_size, current_tail->key,
                               current_tail->key_size) > 0)
    {
        atomic_store_explicit(&list->tail, x, memory_order_release);
    }

    size_t new_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
    atomic_store_explicit(&list->total_size, new_total + value_size, memory_order_relaxed);

    free(update);
    pthread_mutex_unlock(&list->write_lock);
    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size)
{
    if (list == NULL || key == NULL) return -1;

    /* only writers block each other */
    pthread_mutex_lock(&list->write_lock);

    skip_list_node_t **update =
        (skip_list_node_t **)malloc((size_t)list->max_level * sizeof(skip_list_node_t *));
    if (update == NULL)
    {
        pthread_mutex_unlock(&list->write_lock);
        return -1;
    }

    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;

    /* traverse to find position */
    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
        update[i] = x;
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    /* check if key found */
    if (x == NULL || skip_list_compare_keys(list, x->key, x->key_size, key, key_size) != 0)
    {
        free(update);
        pthread_mutex_unlock(&list->write_lock);
        return -1; /* key not found */
    }

    /* if already deleted, nothing to do */
    if (x->deleted)
    {
        free(update);
        pthread_mutex_unlock(&list->write_lock);
        return 0;
    }

    /* create tombstone node (deleted=1) with same key */
    /* tombstone keeps the key but marks deleted flag */
    uint8_t tombstone_value[1] = {0}; /* minimal value for tombstone */
    int level = skip_list_random_level(list);
    if (level > current_level)
    {
        for (int i = current_level; i < level; i++)
        {
            update[i] = header;
        }
        atomic_store_explicit(&list->level, level, memory_order_release);
    }

    skip_list_node_t *tombstone =
        skip_list_create_node(list->max_level, key, key_size, tombstone_value, 1, -1, 1);
    if (tombstone == NULL)
    {
        free(update);
        pthread_mutex_unlock(&list->write_lock);
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
            /* replacing the old node with tombstone */
            skip_list_node_t *x_next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
            atomic_store_explicit(&tombstone->forward[i], x_next, memory_order_release);
            atomic_store_explicit(&update[i]->forward[i], tombstone, memory_order_release);

            /* update backward pointers */
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
            /* normal insertion case (shouldn't happen in delete, but handle it) */
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
            /* skip over the old node at this level */
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

    /* update tail if necessary */
    skip_list_node_t *current_tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    if (current_tail == x)
    {
        atomic_store_explicit(&list->tail, tombstone, memory_order_release);
    }

    /* update size (subtract deleted value size) */
    size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
    atomic_store_explicit(&list->total_size, old_total - x->value_size, memory_order_relaxed);

    /* release reference to old node (will be freed when all readers done) */
    skip_list_release_node(x);

    free(update);
    pthread_mutex_unlock(&list->write_lock);
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted)
{
    if (list == NULL || key == NULL || value == NULL || value_size == NULL) return -1;

    /* completely lock-free read - never blocks or is blocked */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;
    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);

    /* check if key found */
    if (x == NULL || skip_list_compare_keys(list, x->key, x->key_size, key, key_size) != 0)
        return -1; /* key not found */

    /* check if node has expired or is deleted (immutable fields) */
    uint8_t is_deleted = x->deleted;
    uint8_t is_expired = (x->ttl != -1 && x->ttl < time(NULL)) ? 1 : 0;

    if (deleted != NULL) *deleted = (is_deleted || is_expired);

    /* allocate memory for value */
    *value = (uint8_t *)malloc(x->value_size);
    if (*value == NULL) return -1;

    memcpy(*value, x->value, x->value_size);
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

    /* retain reference to current node */
    if (cursor->current) skip_list_retain_node(cursor->current);

    return cursor;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (next == NULL) return -1;

    /* retain new node before releasing old */
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

    /* retain new node before releasing old */
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

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;
    *value = cursor->current->value;
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

    /* retain new node before releasing old */
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

    /* if tail is the header, the list is empty */
    if (tail == header) return -1;

    /* retain new node before releasing old */
    skip_list_retain_node(tail);
    if (cursor->current) skip_list_release_node(cursor->current);

    cursor->current = tail;
    return 0;
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    /* only writers block each other */
    pthread_mutex_lock(&list->write_lock);

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

    pthread_mutex_unlock(&list->write_lock);
    return 0;
}

int skip_list_free(skip_list_t *list)
{
    if (list == NULL) return -1;

    if (skip_list_clear(list) != 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_release_node(header);

    pthread_mutex_destroy(&list->write_lock);
    free(list);
    return 0;
}

skip_list_t *skip_list_copy(skip_list_t *list)
{
    if (list == NULL) return NULL;

    /* create a new skip list with the same max level, probability, and comparator */
    skip_list_t *new_list = NULL;
    if (skip_list_new_with_comparator(&new_list, list->max_level, list->probability,
                                      list->comparator, list->comparator_ctx) != 0)
        return NULL;

    /* lock-free read while copying */
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL)
    {
        if (!current->deleted)
        {
            (void)skip_list_put(new_list, current->key, current->key_size, current->value,
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

    /* check if the list is empty */
    if (current == NULL) return -1;

    /* skip deleted and expired nodes */
    while (current != NULL)
    {
        /* check if the node has expired */
        uint8_t is_expired = (current->ttl != -1 && current->ttl < time(NULL)) ? 1 : 0;

        /* skip this node if it's deleted or expired */
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

    /* allocate memory for the key */
    *key = (uint8_t *)malloc(current->key_size);
    if (*key == NULL) return -1;

    /* copy the key and key size */
    memcpy(*key, current->key, current->key_size);
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
        /* check if the node has expired */
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

    /* allocate and copy the key */
    *key = (uint8_t *)malloc(current->key_size);
    if (*key == NULL) return -1;

    memcpy(*key, current->key, current->key_size);
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

    /* retain reference to current node */
    skip_list_retain_node((*cursor)->current);

    return 0;
}

int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || cursor->list == NULL || key == NULL) return -1;

    skip_list_t *list = cursor->list;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *x = header;
    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
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
    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) <= 0)
        {
            x = next;
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    if (x == header) return -1;

    skip_list_retain_node(x);
    if (cursor->current) skip_list_release_node(cursor->current);

    cursor->current = x;
    return 0;
}