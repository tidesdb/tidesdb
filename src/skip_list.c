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

skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, time_t ttl)
{
    /* validate level to prevent overflow */
    if (level <= 0) return NULL;

    /* allocate memory for the node, including space for forward and backward pointers */
    skip_list_node_t *node =
        malloc(sizeof(skip_list_node_t) + 2 * level * sizeof(skip_list_node_t *));
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

    /* init forward and backward pointers to NULL */
    for (int i = 0; i < level * 2; i++)
    {
        node->forward[i] = NULL;
    }

    return node;
}

int skip_list_check_and_update_ttl(skip_list_t *list, skip_list_node_t *node)
{
    if (node == NULL) return -1;

    if (node->ttl != -1 && node->ttl < time(NULL))
    {
        /* node has expired */
        list->total_size -= node->value_size; /* subtract old value size */
        free(node->value);

        node->value = malloc(4);
        if (node->value == NULL) return -1;

        *(uint32_t *)node->value = TOMBSTONE; /* directly assign the value */
        node->value_size = 4;                 /* size of TOMBSTONE */
        list->total_size += node->value_size; /* add new value size */
        return 0;
    }
    return -1;
}

int skip_list_new(skip_list_t **list, int max_level, float probability)
{
    /* validate max_level and probability */
    if (max_level <= 0 || probability <= 0.0 || probability >= 1.0) return -1;

    *list = malloc(sizeof(skip_list_t));
    if (list == NULL) return -1;

    (*list)->level = 1;
    (*list)->max_level = max_level;
    (*list)->probability = probability;
    (*list)->total_size = 0;

    uint8_t header_key[1] = {0};
    uint8_t header_value[1] = {0};
    (*list)->header = skip_list_create_node(max_level * 2, header_key, 1, header_value, 1, -1);

    if ((*list)->header == NULL)
    {
        free(list);
        return -1;
    }

    /* we initialize tail to be the same as header for an empty list */
    (*list)->tail = (*list)->header;

    return 0;
}

int skip_list_random_level(skip_list_t *list)
{
    int level = 1;
    float rand_max_inv = 1.0f / RAND_MAX;
    while ((rand() * rand_max_inv) < list->probability && level < list->max_level) level++;

    return level;
}

int skip_list_compare_keys(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                           size_t key2_size)
{
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp;

    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

int skip_list_put(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t *value,
                  size_t value_size, time_t ttl)
{
    if (list == NULL || key == NULL || value == NULL) return -1;

    skip_list_node_t **update = malloc(list->max_level * sizeof(skip_list_node_t *));
    if (update == NULL) return -1;

    skip_list_node_t *x = list->header;
    for (int i = list->level - 1; i >= 0; i--)
    {
        while (x->forward[i] && skip_list_compare_keys(x->forward[i]->key, x->forward[i]->key_size,
                                                       key, key_size) < 0)
        {
            x = x->forward[i];
            (void)skip_list_check_and_update_ttl(list, x);
        }
        update[i] = x;
    }

    x = x->forward[0];
    (void)skip_list_check_and_update_ttl(list, x);

    if (x && skip_list_compare_keys(x->key, x->key_size, key, key_size) == 0)
    {
        /* we update existing node */
        list->total_size -= x->value_size; /* sub old value size */
        free(x->value);

        x->value = malloc(value_size);
        if (x->value == NULL)
        {
            free(update);
            return -1;
        }

        memcpy(x->value, value, value_size);
        x->value_size = value_size; /* ensure value_size is set */
        x->ttl = ttl;
        list->total_size += value_size; /* add up new value size */
    }
    else
    {
        int level = skip_list_random_level(list);
        if (level > list->level)
        {
            for (int i = list->level; i < level; i++) update[i] = list->header;

            list->level = level;
        }

        x = skip_list_create_node(list->max_level * 2, key, key_size, value, value_size, ttl);
        if (x == NULL)
        {
            free(update);
            return -1;
        }

        /* we update forward pointers */
        for (int i = 0; i < level; i++)
        {
            x->forward[i] = update[i]->forward[i];
            update[i]->forward[i] = x;
        }

        /* we update backward pointers */
        for (int i = 0; i < level; i++)
        {
            if (x->forward[i] != NULL)
            {
                BACKWARD_PTR(x->forward[i], i, list->max_level) = x;
            }
            BACKWARD_PTR(x, i, list->max_level) = update[i];
        }

        /* update tail if necessary */
        if (x->forward[0] == NULL)
        {
            list->tail = x;
        }

        list->total_size += key_size + value_size + sizeof(time_t); /* add to total size */
    }

    free(update);
    return 0;
}

int skip_list_cursor_at_end(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    return cursor->current == NULL;
}

int skip_list_cursor_at_start(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    return cursor->current == cursor->list->header->forward[0];
}

int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size)
{
    if (list == NULL || key == NULL || value == NULL || value_size == NULL) return -1;

    skip_list_node_t *x = list->header;

    for (int i = list->level - 1; i >= 0; i--)
    {
        while (x->forward[i] && skip_list_compare_keys(x->forward[i]->key, x->forward[i]->key_size,
                                                       key, key_size) < 0)
        {
            x = x->forward[i];
            (void)skip_list_check_and_update_ttl(list, x);
        }
    }

    x = x->forward[0];
    (void)skip_list_check_and_update_ttl(list, x);

    if (x && skip_list_compare_keys(x->key, x->key_size, key, key_size) == 0)
    {
        /* copy the value */
        *value = malloc(x->value_size);
        if (*value == NULL)
        {
            return -1;
        }

        /* copy the value size */
        *value_size = x->value_size;

        /* copy the value */
        memcpy(*value, x->value, x->value_size);

        return 0;
    }
    return -1;
}

skip_list_cursor_t *skip_list_cursor_init(skip_list_t *list)
{
    if (list == NULL || list->header == NULL) return NULL;

    skip_list_cursor_t *cursor = malloc(sizeof(skip_list_cursor_t));
    if (cursor == NULL) return NULL;

    cursor->list = list;
    cursor->current = list->header->forward[0];
    return cursor;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    if (cursor->current != NULL && cursor->current->forward[0] != NULL)
    {
        cursor->current = cursor->current->forward[0];
        (void)skip_list_check_and_update_ttl(cursor->list, cursor->current);

        return 0;
    }

    return -1;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    /* if we're at the first node, we can't go back further */
    if (cursor->current == cursor->list->header->forward[0]) return -1;

    /* we use backward pointer to go to previous node */
    if (BACKWARD_PTR(cursor->current, 0, cursor->list->max_level) != cursor->list->header)
    {
        cursor->current = BACKWARD_PTR(cursor->current, 0, cursor->list->max_level);
        (void)skip_list_check_and_update_ttl(cursor->list, cursor->current);
        return 0;
    }

    return -1;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor != NULL) free(cursor);

    cursor = NULL;
}

int skip_list_clear(skip_list_t *list)
{
    if (list == NULL || list->header == NULL) return -1;

    skip_list_node_t *current = list->header->forward[0];
    while (current != NULL)
    {
        skip_list_node_t *next = current->forward[0];

        if (current->value != NULL)
        {
            free(current->value);
        }
        if (current->key != NULL)
        {
            free(current->key);
        }
        free(current);
        current = next;
    }

    /* reset the header node's forward and backward pointers */
    for (int i = 0; i < list->max_level * 2; i++)
    {
        list->header->forward[i] = NULL;
    }

    /* reset tail to header for empty list */
    list->tail = list->header;

    list->level = 1;
    list->total_size = 0; /* reset total size */

    return 0;
}

int skip_list_free(skip_list_t *list)
{
    if (list == NULL) return -1;

    if (skip_list_clear(list) != 0) return -1;

    if (list->header->key != NULL) free(list->header->key);

    if (list->header->value != NULL) free(list->header->value);
    free(list->header);
    free(list);
    list = NULL;
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
    node = NULL;
    return 0;
}

skip_list_t *skip_list_copy(skip_list_t *list)
{
    if (list == NULL) return NULL;

    /* create a new skip list with the same max level and probability */
    skip_list_t *new_list = NULL;
    if (skip_list_new(&new_list, list->max_level, list->probability) != 0) return NULL;

    /* iterate through the original skip list and copy each node */
    skip_list_node_t *current = list->header->forward[0];
    while (current != NULL)
    {
        (void)skip_list_put(new_list, current->key, current->key_size, current->value,
                            current->value_size, current->ttl);
        current = current->forward[0];
    }

    return new_list;
}

int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, time_t *ttl)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;
    *value = cursor->current->value;
    *value_size = cursor->current->value_size;
    *ttl = cursor->current->ttl;
    return 0;
}

int skip_list_get_size(skip_list_t *list)
{
    if (list == NULL) return -1;

    /* we simply return the total size */
    return (int)list->total_size;
}

int skip_list_count_entries(skip_list_t *list)
{
    if (list == NULL) return -1;

    int count = 0;

    /* we iterate through the skip list and count each node */
    skip_list_node_t *current = list->header->forward[0];
    while (current != NULL)
    {
        count++;
        current = current->forward[0];
    }

    return count;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    return cursor->current->forward[0] != NULL;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) return -1;

    return BACKWARD_PTR(cursor->current, 0, cursor->list->max_level) != cursor->list->header;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    cursor->current = cursor->list->header->forward[0];
    return cursor->current == NULL ? -1 : 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->list == NULL) return -1;

    /* we simply use the tail pointer */
    cursor->current = cursor->list->tail;

    /* if tail is the header, the list is empty */
    return cursor->current == cursor->list->header ? -1 : 0;
}

int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size)
{
    if (list == NULL || key == NULL || key_size == NULL) return -1;

    /* iterate through the skip list to find the first node that isn't a TOMBSTONE */
    skip_list_node_t *current = list->header->forward[0];

    /* check if the list is empty */
    if (current == NULL) return -1;

    /* skip nodes with TOMBSTONE values */
    while (current != NULL)
    {
        /* check if the node has expired */
        (void)skip_list_check_and_update_ttl(list, current);

        /* skip this node if it's a TOMBSTONE */
        if (current->value_size == 4 && *(uint32_t *)current->value == TOMBSTONE)
        {
            current = current->forward[0];
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
    if (list->tail == list->header) return -1;

    /* start from tail and find non-TOMBSTONE node */
    skip_list_node_t *current = list->tail;

    while (current != list->header)
    {
        /* check if the node has expired */
        (void)skip_list_check_and_update_ttl(list, current);

        /* we skip TOMBSTONE nodes */
        if (current->value_size == 4 && *(uint32_t *)current->value == TOMBSTONE)
        {
            current = BACKWARD_PTR(current, 0, list->max_level);
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

    /* if list is empty (tail is header) */
    if (list->tail == list->header)
    {
        (*cursor)->current = NULL;
        return -1;
    }

    /* we set cursor to tail */
    (*cursor)->current = list->tail;

    /* we heck if the node has expired */
    (void)skip_list_check_and_update_ttl(list, (*cursor)->current);

    return 0;
}