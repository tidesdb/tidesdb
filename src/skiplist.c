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
#include "skiplist.h"

skiplist_node *skiplist_create_node(int level, const unsigned char *key, size_t key_size,
                                    const unsigned char *value, size_t value_size, time_t ttl) {
    // Validate level to prevent overflow
    if (level <= 0) {
        return NULL;
    }

    // Allocate memory for the node, including space for forward pointers
    skiplist_node *node = malloc(sizeof(skiplist_node) + level * sizeof(skiplist_node *));
    if (node == NULL) {
        return NULL;
    }

    // Allocate memory for the key
    node->key = (unsigned char *)malloc(key_size);
    if (node->key == NULL) {
        free(node);
        return NULL;
    }
    memcpy(node->key, key, key_size);
    node->key_size = key_size;

    // Allocate memory for the value
    node->value = (unsigned char *)malloc(value_size);
    if (node->value == NULL) {
        free(node->key);
        free(node);
        return NULL;
    }
    memcpy(node->value, value, value_size);
    node->value_size = value_size;

    // Set the TTL
    node->ttl = ttl;

    // Initialize forward pointers to NULL
    for (int i = 0; i < level; i++) {
        node->forward[i] = NULL;
    }

    return node;
}

bool skiplist_check_and_update_ttl(skiplist_node *node) {
    if (node == NULL) {
        return false;
    }

    if (node->ttl != -1 && node->ttl < time(NULL)) {
        // Node has expired
        free(node->value);
        node->value = (unsigned char *)malloc(sizeof(TOMBSTONE));
        if (node->value == NULL) {
            return false;
        }
        *(uint32_t *)node->value = TOMBSTONE;  // Directly assign the value
        node->value_size = sizeof(TOMBSTONE);
        return true;
    }
    return false;
}

skiplist *new_skiplist(int max_level, float probability) {
    // Validate max_level and probability
    if (max_level <= 0 || probability <= 0.0 || probability >= 1.0) {
        return NULL;
    }

    skiplist *list = (skiplist *)malloc(sizeof(skiplist));
    if (list == NULL) {
        return NULL;
    }

    list->level = 1;
    list->max_level = max_level;
    list->probability = probability;
    list->total_size = 0;
    pthread_rwlock_init(&list->lock, NULL);  // Initialize read-write lock

    unsigned char header_key[1] = {0};
    unsigned char header_value[1] = {0};
    list->header = skiplist_create_node(max_level, header_key, 1, header_value, 1, -1);
    if (list->header == NULL) {
        pthread_rwlock_destroy(&list->lock);  // Destroy the read-write lock
        free(list);
        return NULL;
    }

    // We don't calculate the size of the header node because its key and values aren't actually
    // counted
    return list;
}

int skiplist_random_level(skiplist *list) {
    int level = 1;
    float rand_max_inv = 1.0f / RAND_MAX;
    while ((rand() * rand_max_inv) < list->probability && level < list->max_level) {
        level++;
    }
    return level;
}

int skiplist_compare_keys(const unsigned char *key1, size_t key1_size, const unsigned char *key2,
                          size_t key2_size) {
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) {
        return cmp;
    }
    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

bool skiplist_put(skiplist *list, const unsigned char *key, size_t key_size,
                  const unsigned char *value, size_t value_size, time_t ttl) {
    if (list == NULL || key == NULL || value == NULL) {
        return false;
    }

    pthread_rwlock_wrlock(&list->lock);  // Lock the list for writing
    skiplist_node *update[list->max_level];
    skiplist_node *x = list->header;
    for (int i = list->level - 1; i >= 0; i--) {
        while (x->forward[i] && skiplist_compare_keys(x->forward[i]->key, x->forward[i]->key_size,
                                                      key, key_size) < 0) {
            x = x->forward[i];
            skiplist_check_and_update_ttl(x);
        }
        update[i] = x;
    }
    x = x->forward[0];
    skiplist_check_and_update_ttl(x);

    if (x && skiplist_compare_keys(x->key, x->key_size, key, key_size) == 0) {
        list->total_size -= x->value_size;  // Subtract old value size
        free(x->value);
        x->value = (unsigned char *)malloc(value_size);
        if (x->value == NULL) {
            pthread_rwlock_unlock(&list->lock);  // Unlock the list
            return false;
        }
        memcpy(x->value, value, value_size);
        x->value_size = value_size;  // Ensure value_size is set
        x->ttl = ttl;
        list->total_size += value_size;  // Add new value size
    } else {
        int level = skiplist_random_level(list);
        if (level > list->level) {
            for (int i = list->level; i < level; i++) {
                update[i] = list->header;
            }
            list->level = level;
        }
        x = skiplist_create_node(level, key, key_size, value, value_size, ttl);
        if (x == NULL) {
            pthread_rwlock_unlock(&list->lock);  // Unlock the list
            return false;
        }
        for (int i = 0; i < level; i++) {
            x->forward[i] = update[i]->forward[i];
            update[i]->forward[i] = x;
        }
        list->total_size += sizeof(skiplist_node) + level * sizeof(skiplist_node *) + key_size +
                            value_size;  // Add new node size
    }
    pthread_rwlock_unlock(&list->lock);  // Unlock the list
    return true;
}

bool skiplist_delete(skiplist *list, const unsigned char *key, size_t key_size) {
    pthread_rwlock_wrlock(&list->lock);  // Lock the list for writing
    skiplist_node *update[list->max_level];
    skiplist_node *x = list->header;
    for (int i = list->level - 1; i >= 0; i--) {
        while (x->forward[i] && skiplist_compare_keys(x->forward[i]->key, x->forward[i]->key_size,
                                                      key, key_size) < 0) {
            x = x->forward[i];
            skiplist_check_and_update_ttl(x);
        }
        update[i] = x;
    }
    x = x->forward[0];
    skiplist_check_and_update_ttl(x);

    if (!x || skiplist_compare_keys(x->key, x->key_size, key, key_size) != 0) {
        pthread_rwlock_unlock(&list->lock);  // Unlock the list
        return false;
    }
    for (int i = 0; i < list->level; i++) {
        if (update[i]->forward[i] != x) {
            break;
        }
        update[i]->forward[i] = x->forward[i];
    }
    list->total_size -= sizeof(skiplist_node) + x->key_size + x->value_size +
                        list->level * sizeof(skiplist_node *);  // Subtract node size
    free(x->key);
    free(x->value);
    free(x);
    while (list->level > 1 && list->header->forward[list->level - 1] == NULL) {
        list->level--;
    }
    pthread_rwlock_unlock(&list->lock);  // Unlock the list
    return true;
}

bool skiplist_get(skiplist *list, const unsigned char *key, size_t key_size, unsigned char **value,
                  size_t *value_size) {
    if (list == NULL || key == NULL || value == NULL || value_size == NULL) {
        return false;
    }

    pthread_rwlock_rdlock(&list->lock);  // Lock the list for reading
    skiplist_node *x = list->header;
    for (int i = list->level - 1; i >= 0; i--) {
        while (x->forward[i] && skiplist_compare_keys(x->forward[i]->key, x->forward[i]->key_size,
                                                      key, key_size) < 0) {
            x = x->forward[i];
            skiplist_check_and_update_ttl(x);
        }
    }
    x = x->forward[0];
    skiplist_check_and_update_ttl(x);

    if (x && skiplist_compare_keys(x->key, x->key_size, key, key_size) == 0) {
        *value = x->value;
        *value_size = x->value_size;

        pthread_rwlock_unlock(&list->lock);  // Unlock the list
        return true;
    }
    pthread_rwlock_unlock(&list->lock);  // Unlock the list
    return false;
}

skiplist_cursor *skiplist_cursor_init(skiplist *list) {
    if (list == NULL || list->header == NULL) {
        return NULL;
    }
    skiplist_cursor *cursor = malloc(sizeof(skiplist_cursor));
    if (cursor == NULL) {
        return NULL;
    }
    cursor->list = list;
    cursor->current = list->header->forward[0];
    return cursor;
}

bool skiplist_cursor_next(skiplist_cursor *cursor) {
    if (cursor == NULL || cursor->list == NULL) {
        return false;
    }
    pthread_rwlock_rdlock(&cursor->list->lock);  // Lock the list for reading
    if (cursor->current != NULL && cursor->current->forward[0] != NULL) {
        cursor->current = cursor->current->forward[0];
        skiplist_check_and_update_ttl(cursor->current);
        pthread_rwlock_unlock(&cursor->list->lock);  // Unlock the list
        return true;
    }
    pthread_rwlock_unlock(&cursor->list->lock);  // Unlock the list
    return false;
}

bool skiplist_cursor_prev(skiplist_cursor *cursor) {
    if (cursor == NULL || cursor->list == NULL || cursor->current == NULL) {
        return false;
    }
    pthread_rwlock_rdlock(&cursor->list->lock);  // Lock the list for reading
    skiplist_node *x = cursor->list->header;
    skiplist_node *prev = NULL;
    while (x->forward[0] && x->forward[0] != cursor->current) {
        prev = x->forward[0];
        x = x->forward[0];
        skiplist_check_and_update_ttl(x);
    }
    if (prev != NULL) {
        cursor->current = prev;
        skiplist_check_and_update_ttl(cursor->current);
        pthread_rwlock_unlock(&cursor->list->lock);  // Unlock the list
        return true;
    }
    pthread_rwlock_unlock(&cursor->list->lock);  // Unlock the list
    return false;
}

void skiplist_cursor_free(skiplist_cursor *cursor) {
    if (cursor != NULL) {
        free(cursor);
    }
}

int skiplist_clear(skiplist *list) {
    if (list == NULL || list->header == NULL) {
        return -1;
    }

    if (pthread_rwlock_wrlock(&list->lock) != 0) {  // Lock the list for writing
        return -1;
    }

    skiplist_node *current = list->header->forward[0];
    while (current != NULL) {
        skiplist_node *next = current->forward[0];
        free(current->key);
        free(current->value);
        free(current);
        current = next;
    }

    // Reset the header node's forward pointers
    for (int i = 0; i < list->max_level; i++) {
        list->header->forward[i] = NULL;
    }

    list->level = 1;
    list->total_size = 0;  // Reset total size

    if (pthread_rwlock_unlock(&list->lock) != 0) {  // Unlock the list
        return -1;
    }
    return 0;
}

int skiplist_destroy(skiplist *list) {
    if (list == NULL) {
        return -1;
    }
    if (skiplist_clear(list) != 0) {
        return -1;
    }
    if (pthread_rwlock_destroy(&list->lock) != 0) {
        return -1;
    }
    free(list->header->key);
    free(list->header->value);
    free(list->header);
    free(list);
    return 0;
}

bool skiplist_destroy_node(skiplist_node *node) {
    if (node == NULL) {
        return false;
    }
    free(node->key);
    free(node->value);
    free(node);
    return true;
}

skiplist *skiplist_copy(skiplist *list) {
    if (list == NULL) {
        return NULL;
    }

    // Create a new skiplist with the same max level and probability
    skiplist *new_list = new_skiplist(list->max_level, list->probability);
    if (new_list == NULL) {
        return NULL;
    }

    // Lock the original skiplist for reading
    pthread_rwlock_rdlock(&list->lock);

    // Iterate through the original skiplist and copy each node
    skiplist_node *current = list->header->forward[0];
    while (current != NULL) {
        skiplist_put(new_list, current->key, current->key_size, current->value, current->value_size,
                     current->ttl);
        current = current->forward[0];
    }

    // Unlock the original skiplist
    pthread_rwlock_unlock(&list->lock);

    return new_list;
}