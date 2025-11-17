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

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
 * @return pointer to new version, NULL on failure
 */
static skip_list_version_t *skip_list_create_version(const uint8_t *value, size_t value_size,
                                                     time_t ttl, uint8_t deleted)
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

    skip_list_version_t *initial_version = NULL;
    if (value != NULL || deleted)
    {
        initial_version = skip_list_create_version(value, value_size, ttl, deleted);
        if (initial_version == NULL && !deleted)
        {
            free(node->key);
            free(node);
            return NULL;
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

    skip_list_node_t *header = skip_list_create_node(max_level, (uint8_t *)"\0", 1, NULL, 0, -1, 0);
    skip_list_node_t *tail = skip_list_create_node(max_level, (uint8_t *)"\xff", 1, NULL, 0, -1, 0);

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

int skip_list_random_level(skip_list_t *list)
{
    if (list == NULL) return -1;
    int level = 0;
    while ((rand() / (float)RAND_MAX) < list->probability && level < list->max_level)
    {
        level++;
    }
    return level;
}

int skip_list_compare_keys(skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size)
{
    if (list == NULL || key1 == NULL || key2 == NULL) return 0;
    return list->comparator(key1, key1_size, key2, key2_size, list->comparator_ctx);
}

int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node)
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

int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t **update = malloc((list->max_level + 1) * sizeof(skip_list_node_t *));
    if (!update) return -1;
    skip_list_node_t *current = header;

    for (int i = atomic_load_explicit(&list->level, memory_order_acquire); i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && next != tail)
        {
            int cmp = skip_list_compare_keys(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
        update[i] = current;
    }

    skip_list_node_t *existing = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (existing != NULL && existing != tail)
    {
        int cmp = skip_list_compare_keys(list, existing->key, existing->key_size, key, key_size);
        if (cmp == 0)
        {
            skip_list_version_t *new_version = skip_list_create_version(value, value_size, ttl, 0);
            if (new_version == NULL)
            {
                free(update);
                return -1;
            }

            skip_list_version_t *old_head;
            do
            {
                old_head = atomic_load_explicit(&existing->versions, memory_order_acquire);
                atomic_store_explicit(&new_version->next, old_head, memory_order_relaxed);
            } while (!atomic_compare_exchange_weak_explicit(&existing->versions, &old_head,
                                                            new_version, memory_order_release,
                                                            memory_order_acquire));
            free(update);
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

    skip_list_node_t *new_node =
        skip_list_create_node(new_level, key, key_size, value, value_size, ttl, 0);
    if (new_node == NULL)
    {
        free(update);
        return -1;
    }

    for (int i = 0; i <= new_level; i++)
    {
        skip_list_node_t *next;
        do
        {
            next = atomic_load_explicit(&update[i]->forward[i], memory_order_acquire);
            atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
        } while (!atomic_compare_exchange_weak_explicit(
            &update[i]->forward[i], &next, new_node, memory_order_release, memory_order_acquire));
    }

    /* after successful insertion, set new node's backward pointers */
    for (int i = 0; i <= new_level; i++)
    {
        /* set new node's backward pointer to predecessor */
        atomic_store_explicit(&BACKWARD_PTR(new_node, i, new_level), update[i],
                              memory_order_release);

        /* try to update successor's backward pointer using CAS */
        skip_list_node_t *next = atomic_load_explicit(&new_node->forward[i], memory_order_acquire);
        if (next != NULL && next != tail)
        {
            /* try to CAS the successor's backward pointer from update[i] to new_node */
            skip_list_node_t *expected = update[i];
            atomic_compare_exchange_strong_explicit(&BACKWARD_PTR(next, i, next->level), &expected,
                                                    new_node, memory_order_release,
                                                    memory_order_acquire);
            /* if CAS fails, another thread updated it, which is fine */
        }
    }

    size_t node_size = sizeof(skip_list_node_t) + key_size + value_size;
    atomic_fetch_add(&list->total_size, node_size);
    free(update);
    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size)
{
    if (list == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = header;

    for (int i = atomic_load_explicit(&list->level, memory_order_acquire); i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && next != tail)
        {
            int cmp = skip_list_compare_keys(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (target == NULL || target == tail) return 0;

    int cmp = skip_list_compare_keys(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return 0;

    skip_list_version_t *tombstone = skip_list_create_version(NULL, 0, -1, 1);
    if (tombstone == NULL) return -1;

    skip_list_version_t *old_head;
    do
    {
        old_head = atomic_load_explicit(&target->versions, memory_order_acquire);
        atomic_store_explicit(&tombstone->next, old_head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&target->versions, &old_head, tombstone,
                                                    memory_order_release, memory_order_acquire));
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, uint8_t *deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = header;

    for (int i = atomic_load_explicit(&list->level, memory_order_acquire); i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && next != tail)
        {
            int cmp = skip_list_compare_keys(list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (target == NULL || target == tail) return -1;

    int cmp = skip_list_compare_keys(list, target->key, target->key_size, key, key_size);
    if (cmp != 0) return -1;

    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (version->ttl > 0 && version->ttl < time(NULL))
    {
        *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (VERSION_IS_DELETED(version))
    {
        *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    *deleted = 0;
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

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    while (current != NULL && current != tail)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[0], memory_order_acquire);
        skip_list_free_node(current);
        current = next;
    }

    for (int i = 0; i <= list->max_level; i++)
    {
        atomic_store_explicit(&header->forward[i], tail, memory_order_release);
        atomic_store_explicit(&BACKWARD_PTR(tail, i, list->max_level), header,
                              memory_order_release);
    }

    atomic_store_explicit(&list->level, 0, memory_order_release);
    atomic_store_explicit(&list->total_size, 0, memory_order_release);
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

int skip_list_get_size(skip_list_t *list)
{
    if (list == NULL) return -1;
    return (int)atomic_load_explicit(&list->total_size, memory_order_acquire);
}

int skip_list_count_entries(skip_list_t *list)
{
    if (list == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    int count = 0;
    while (current != NULL && current != tail)
    {
        count++;
        current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    }
    return count;
}

int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *first = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (first == NULL || first == tail) return -1;

    skip_list_version_t *version = atomic_load_explicit(&first->versions, memory_order_acquire);
    if (version != NULL)
    {
        if (VERSION_IS_DELETED(version) || (version->ttl > 0 && version->ttl < time(NULL)))
        {
            skip_list_node_t *current = first;
            while (current != NULL && current != tail)
            {
                version = atomic_load_explicit(&current->versions, memory_order_acquire);
                if (version != NULL && !VERSION_IS_DELETED(version) &&
                    !(version->ttl > 0 && version->ttl < time(NULL)))
                {
                    first = current;
                    break;
                }
                current = atomic_load_explicit(&current->forward[0], memory_order_acquire);
            }
            if (current == NULL || current == tail) return -1;
        }
    }

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
    skip_list_node_t *tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (current == NULL || current == tail) return -1;

    /* traverse to find last node before tail */
    skip_list_node_t *last = NULL;
    while (current != NULL && current != tail)
    {
        skip_list_version_t *version =
            atomic_load_explicit(&current->versions, memory_order_acquire);
        if (version != NULL && !VERSION_IS_DELETED(version) &&
            !(version->ttl > 0 && version->ttl < time(NULL)))
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

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (cursor->current == tail) return -1;

    cursor->current = atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (cursor->current == NULL || cursor->current == tail) return -1;
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

    *ttl = version->ttl;

    if (version->ttl > 0 && version->ttl < time(NULL))
    {
        *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (VERSION_IS_DELETED(version))
    {
        *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    *deleted = 0;
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
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *current = atomic_load_explicit(&header->forward[0], memory_order_acquire);

    if (current == NULL || current == tail) return -1;

    /* traverse forward to find last node */
    skip_list_node_t *last = current;
    while (current != NULL && current != tail)
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
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    if (first == NULL || first == tail) return -1;
    cursor->current = first;
    return 0;
}

int skip_list_cursor_init_at_end(skip_list_cursor_t **cursor, skip_list_t *list)
{
    if (cursor == NULL || list == NULL) return -1;
    if (skip_list_cursor_init(cursor, list) != 0) return -1;
    return skip_list_cursor_goto_last(*cursor);
}

int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *current = header;

    /* find the node before the target key */
    for (int i = atomic_load_explicit(&cursor->list->level, memory_order_acquire); i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && next != tail)
        {
            int cmp =
                skip_list_compare_keys(cursor->list, next->key, next->key_size, key, key_size);
            if (cmp >= 0) break; /* stop before target or equal */
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    /* position cursor at the node before target */
    cursor->current = current;
    return 0;
}

int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *header = atomic_load_explicit(&cursor->list->header, memory_order_acquire);
    skip_list_node_t *tail = atomic_load_explicit(&cursor->list->tail, memory_order_acquire);
    skip_list_node_t *current = header;

    for (int i = atomic_load_explicit(&cursor->list->level, memory_order_acquire); i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        while (next != NULL && next != tail)
        {
            int cmp =
                skip_list_compare_keys(cursor->list, next->key, next->key_size, key, key_size);
            if (cmp > 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);
        }
    }

    /* if current is still header, all keys are > target, so no valid position */
    /* set cursor to header to indicate invalid position */
    cursor->current = current;
    return 0;
}
