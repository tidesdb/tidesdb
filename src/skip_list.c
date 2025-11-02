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
    (void)ctx; /* unused */

    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp < 0 ? -1 : 1;

    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

int skip_list_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx)
{
    (void)key1_size; /* unused */
    (void)key2_size; /* unused */
    (void)ctx;       /* unused */

    int cmp = strcmp((const char *)key1, (const char *)key2);
    return cmp == 0 ? 0 : (cmp < 0 ? -1 : 1);
}

int skip_list_comparator_numeric(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                 size_t key2_size, void *ctx)
{
    (void)key1_size; /* unused */
    (void)key2_size; /* unused */
    (void)ctx;       /* unused */

    uint64_t val1, val2;

    /* safely extract uint64_t values (little-endian) */
    memcpy(&val1, key1, sizeof(uint64_t));
    memcpy(&val2, key2, sizeof(uint64_t));

    if (val1 < val2) return -1;
    if (val1 > val2) return 1;
    return 0;
}

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl)
{
    /* validate level to prevent overflow */
    if (level <= 0) return NULL;

    /* allocate memory for the node, including space for forward and backward pointers */
    skip_list_node_t *node = malloc(sizeof(skip_list_node_t) +
                                    (size_t)(2 * level) * sizeof(_Atomic(skip_list_node_t *)));
    if (node == NULL) return NULL;

    /* allocate memory for the key */
    node->key = malloc(key_size);
    if (node->key == NULL)
    {
        free(node);
        return NULL;
    }

    memcpy(node->key, key, key_size);
    node->key_size = key_size;

    /* allocate memory for the value */
    node->value = malloc(value_size);
    if (node->value == NULL)
    {
        free(node->key);
        free(node);
        return NULL;
    }

    memcpy(node->value, value, value_size);
    node->value_size = value_size;

    /* set the TTL */
    node->ttl = ttl;

    /* initialize deleted flag to 0 (not deleted) */
    atomic_store_explicit(&node->deleted, 0, memory_order_relaxed);

    /* init forward and backward pointers to NULL */
    for (int i = 0; i < level * 2; i++)
    {
        atomic_store_explicit(&node->forward[i], NULL, memory_order_relaxed);
    }

    return node;
}

int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node)
{
    if (node == NULL) return -1;

    if (node->ttl != -1 && node->ttl < time(NULL))
    {
        /* node has expired - mark it as deleted */
        uint8_t was_deleted = atomic_exchange_explicit(&node->deleted, 1, memory_order_release);

        /* only update total_size if we're the first to mark it deleted */
        if (was_deleted == 0)
        {
            size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
            atomic_store_explicit(&list->total_size, old_total - node->value_size,
                                  memory_order_relaxed);
        }

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

    *list = malloc(sizeof(skip_list_t));
    if (*list == NULL) return -1;

    atomic_store_explicit(&(*list)->level, 1, memory_order_relaxed);
    (*list)->max_level = max_level;
    (*list)->probability = probability;
    atomic_store_explicit(&(*list)->total_size, 0, memory_order_relaxed);
    atomic_store_explicit(&(*list)->version, 0, memory_order_relaxed);
    (*list)->comparator = comparator;
    (*list)->comparator_ctx = comparator_ctx;

    if (pthread_mutex_init(&(*list)->write_lock, NULL) != 0)
    {
        free(*list);
        return -1;
    }

    uint8_t header_key[1] = {0};
    uint8_t header_value[1] = {0};
    (*list)->header = skip_list_create_node(max_level * 2, header_key, 1, header_value, 1, -1);

    if ((*list)->header == NULL)
    {
        pthread_mutex_destroy(&(*list)->write_lock);
        free(*list);
        return -1;
    }

    /* we initialize tail to be the same as header for an empty list */
    atomic_store_explicit(&(*list)->tail, (*list)->header, memory_order_release);

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

    pthread_mutex_lock(&list->write_lock);

    skip_list_node_t **update = malloc((size_t)list->max_level * sizeof(skip_list_node_t *));
    if (update == NULL)
    {
        pthread_mutex_unlock(&list->write_lock);
        return -1;
    }

    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    skip_list_node_t *x = list->header;

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            (void)skip_list_check_and_update_ttl(list, x);
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
        update[i] = x;
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);
    (void)skip_list_check_and_update_ttl(list, x);

    /* x can be NULL if key not found, or valid if found */
    if (x && skip_list_compare_keys(list, x->key, x->key_size, key, key_size) ==
                 0)  // NOLINT(clang-analyzer-core.NullDereference)
    {
        /* we update existing node */
        size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
        atomic_store_explicit(&list->total_size, old_total - x->value_size, memory_order_relaxed);

        free(x->value);

        x->value = malloc(value_size);
        if (x->value == NULL)
        {
            free(update);
            pthread_mutex_unlock(&list->write_lock);
            return -1;
        }

        memcpy(x->value, value, value_size);
        x->value_size = value_size;
        x->ttl = ttl;

        /* mark node as not deleted if it was previously deleted */
        atomic_store_explicit(&x->deleted, 0, memory_order_release);

        old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
        atomic_store_explicit(&list->total_size, old_total + value_size, memory_order_relaxed);
    }
    else
    {
        int level = skip_list_random_level(list);
        current_level = atomic_load_explicit(&list->level, memory_order_acquire);

        if (level > current_level)
        {
            for (int i = current_level; i < level; i++) update[i] = list->header;

            atomic_store_explicit(&list->level, level, memory_order_release);
        }

        x = skip_list_create_node(list->max_level * 2, key, key_size, value, value_size, ttl);
        if (x == NULL)
        {
            free(update);
            pthread_mutex_unlock(&list->write_lock);
            return -1;
        }

        /* we update forward pointers atomically */
        for (int i = 0; i < level; i++)
        {
            skip_list_node_t *old_next =
                atomic_load_explicit(&update[i]->forward[i], memory_order_relaxed);
            atomic_store_explicit(&x->forward[i], old_next, memory_order_relaxed);
            atomic_store_explicit(&update[i]->forward[i], x, memory_order_release);
        }

        /* we update backward pointers */
        for (int i = 0; i < level; i++)
        {
            skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_relaxed);
            if (next != NULL)
            {
                atomic_store_explicit(&next->forward[list->max_level + i], x, memory_order_release);
            }
            atomic_store_explicit(&x->forward[list->max_level + i], update[i],
                                  memory_order_release);
        }

        /* update tail if necessary */
        skip_list_node_t *next = atomic_load_explicit(&x->forward[0], memory_order_relaxed);
        if (next == NULL)
        {
            atomic_store_explicit(&list->tail, x, memory_order_release);
        }

        /* update total size and version */
        size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
        atomic_store_explicit(&list->total_size, old_total + key_size + value_size,
                              memory_order_relaxed);

        uint64_t old_version = atomic_load_explicit(&list->version, memory_order_relaxed);
        atomic_store_explicit(&list->version, old_version + 1, memory_order_release);
    }

    free(update);

    pthread_mutex_unlock(&list->write_lock);
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted)
{
    if (list == NULL || key == NULL) return -1;

    skip_list_node_t *x = list->header;
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

    /* x can be NULL if key not found, or valid if found */
    if (x && skip_list_compare_keys(list, x->key, x->key_size, key, key_size) ==
                 0)  // NOLINT(clang-analyzer-core.NullDereference)
    {
        /* check if node has expired */
        skip_list_check_and_update_ttl(list, x);

        /* check if node is deleted */
        uint8_t is_deleted = atomic_load_explicit(&x->deleted, memory_order_acquire);
        *deleted = is_deleted;

        /* alloc new memory and copy the value to avoid double-free issues.
         * the caller is responsible for freeing the returned pointer.
         * this ensures the skip list's internal memory is not freed by the caller. */
        *value = malloc(x->value_size);
        if (*value == NULL) return -1;

        memcpy(*value, x->value, x->value_size);
        *value_size = x->value_size;
        return 0;
    }

    return -1;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size)
{
    if (list == NULL || key == NULL) return -1;

    /* acquire exclusive write lock */
    pthread_mutex_lock(&list->write_lock);

    skip_list_node_t *x = list->header;
    int current_level = atomic_load_explicit(&list->level, memory_order_acquire);

    for (int i = current_level - 1; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        while (next && skip_list_compare_keys(list, next->key, next->key_size, key, key_size) < 0)
        {
            x = next;
            (void)skip_list_check_and_update_ttl(list, x);
            next = atomic_load_explicit(&x->forward[i], memory_order_acquire);
        }
    }

    x = atomic_load_explicit(&x->forward[0], memory_order_acquire);
    (void)skip_list_check_and_update_ttl(list, x);

    /* x can be NULL if key not found, or valid if found */
    if (x && skip_list_compare_keys(list, x->key, x->key_size, key, key_size) ==
                 0)  // NOLINT(clang-analyzer-core.NullDereference)
    {
        /* mark node as deleted */
        uint8_t was_deleted = atomic_exchange_explicit(&x->deleted, 1, memory_order_release);

        /* only update total_size if we're the first to mark it deleted */
        if (was_deleted == 0)
        {
            size_t old_total = atomic_load_explicit(&list->total_size, memory_order_relaxed);
            atomic_store_explicit(&list->total_size, old_total - x->value_size,
                                  memory_order_relaxed);

            uint64_t old_version = atomic_load_explicit(&list->version, memory_order_relaxed);
            atomic_store_explicit(&list->version, old_version + 1, memory_order_release);
        }

        pthread_mutex_unlock(&list->write_lock);
        return 0;
    }

    pthread_mutex_unlock(&list->write_lock);
    return -1; /* key not found */
}

skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list)
{
    if (list == NULL) return NULL;

    skip_list_cursor_t *cursor = malloc(sizeof(skip_list_cursor_t));
    if (cursor == NULL) return NULL;

    cursor->list = list;
    cursor->snapshot_version = atomic_load_explicit(&list->version, memory_order_acquire);

    /* move cursor to the first node */
    cursor->current = atomic_load_explicit(&list->header->forward[0], memory_order_acquire);

    return cursor;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    cursor->current = atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    return cursor->current == NULL ? -1 : 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    cursor->current = atomic_load_explicit(
        &BACKWARD_PTR(cursor->current, 0, cursor->list->max_level), memory_order_acquire);

    /* if previous node is the header, return -1 */
    return cursor->current == cursor->list->header ? -1 : 0;
}

int skip_list_cursor_at_start(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    skip_list_node_t *first =
        atomic_load_explicit(&cursor->list->header->forward[0], memory_order_acquire);
    return cursor->current == first ? 1 : 0;
}

int skip_list_cursor_at_end(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;

    return cursor->current == NULL ? 1 : 0;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor != NULL) free(cursor);
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    /* acquire exclusive write lock */
    pthread_mutex_lock(&list->write_lock);

    skip_list_node_t *current =
        atomic_load_explicit(&list->header->forward[0], memory_order_acquire);

    /* free all nodes */
    while (current != NULL)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);

        if (skip_list_free_node(current) != 0)
        {
            pthread_mutex_unlock(&list->write_lock);
            return -1;
        }

        current = next;
    }

    /* reset all header forward pointers to NULL to avoid use-after-free
     * when lock-free readers try to traverse the list after clear */
    for (int i = 0; i <= list->max_level; i++)
    {
        atomic_store_explicit(&list->header->forward[i], NULL, memory_order_release);
    }

    /* reset tail to header for empty list */
    atomic_store_explicit(&list->tail, list->header, memory_order_release);

    atomic_store_explicit(&list->level, 1, memory_order_relaxed);
    atomic_store_explicit(&list->total_size, 0, memory_order_relaxed);

    /* increment version */
    uint64_t old_version = atomic_load_explicit(&list->version, memory_order_relaxed);
    atomic_store_explicit(&list->version, old_version + 1, memory_order_release);

    pthread_mutex_unlock(&list->write_lock);
    return 0;
}

int skip_list_free(skip_list_t *list)
{
    if (list == NULL) return -1;

    if (skip_list_clear(list) != 0) return -1;

    if (list->header->key != NULL) free(list->header->key);

    if (list->header->value != NULL) free(list->header->value);
    free(list->header);
    pthread_mutex_destroy(&list->write_lock);
    free(list);
    return 0;
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

skip_list_t *skip_list_copy(skip_list_t *list)
{
    if (list == NULL) return NULL;

    /* create a new skip list with the same max level, probability, and comparator */
    skip_list_t *new_list = NULL;
    if (skip_list_new_with_comparator(&new_list, list->max_level, list->probability,
                                      list->comparator, list->comparator_ctx) != 0)
        return NULL;

    /* lock-free read while copying */
    skip_list_node_t *current =
        atomic_load_explicit(&list->header->forward[0], memory_order_acquire);
    while (current != NULL)
    {
        (void)skip_list_put(new_list, current->key, current->key_size, current->value,
                            current->value_size, current->ttl);
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    return new_list;
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
    uint8_t is_deleted = atomic_load_explicit(&cursor->current->deleted, memory_order_acquire);
    *deleted = is_deleted;
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

    /*  iterate through skip list */
    skip_list_node_t *current =
        atomic_load_explicit(&list->header->forward[0], memory_order_acquire);
    while (current != NULL)
    {
        count++;
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }

    return count;
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

    return prev != cursor->list->header;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    cursor->current = atomic_load_explicit(&cursor->list->header->forward[0], memory_order_acquire);
    return cursor->current == NULL ? -1 : 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    /* we simply use the tail pointer */
    cursor->current = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);

    /* if tail is the header, the list is empty */
    return cursor->current == cursor->list->header ? -1 : 0;
}

int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    /* Lock-free read: iterate through skip list to find first non-deleted node */
    skip_list_node_t *current =
        atomic_load_explicit(&list->header->forward[0], memory_order_acquire);

    /* check if the list is empty */
    if (current == NULL) return -1;

    /* skip deleted and expired nodes */
    while (current != NULL)
    {
        /* check if the node has expired */
        skip_list_check_and_update_ttl(list, current);

        /* skip this node if it's deleted */
        uint8_t is_deleted = atomic_load_explicit(&current->deleted, memory_order_acquire);
        if (is_deleted)
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
    *key = malloc(current->key_size);
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
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    if (tail == list->header) return -1;

    /* start from tail and find non-deleted node */
    skip_list_node_t *current = tail;

    while (current != list->header)
    {
        /* check if the node has expired */
        skip_list_check_and_update_ttl(list, current);

        /* we skip deleted nodes */
        uint8_t is_deleted = atomic_load_explicit(&current->deleted, memory_order_acquire);
        if (is_deleted)
        {
            current = atomic_load_explicit(&BACKWARD_PTR(current, 0, list->max_level),
                                           memory_order_acquire);
            continue;
        }

        /* we found a valid node */
        break;
    }

    /* if we couldn't find a valid node */
    if (current == list->header) return -1;

    /* allocate and copy the key */
    *key = malloc(current->key_size);
    if (*key == NULL) return -1;

    memcpy(*key, current->key, current->key_size);
    *key_size = current->key_size;

    return 0;
}

int skip_list_cursor_init_at_end(skip_list_cursor_t **cursor, skip_list_t *list)
{
    if (list == NULL || cursor == NULL) return -1;

    /* we allocate memory for the cursor if it doesn't exist */
    if (*cursor == NULL)
    {
        *cursor = malloc(sizeof(skip_list_cursor_t));
        if (*cursor == NULL) return -1;
    }

    (*cursor)->list = list;
    (*cursor)->snapshot_version = atomic_load_explicit(&list->version, memory_order_acquire);

    /* if list is empty (tail is header) */
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    if (tail == list->header)
    {
        (*cursor)->current = NULL;
        return -1;
    }

    /* we set cursor to tail */
    (*cursor)->current = tail;

    /* we check if the node has expired */
    (void)skip_list_check_and_update_ttl(list, (*cursor)->current);

    return 0;
}