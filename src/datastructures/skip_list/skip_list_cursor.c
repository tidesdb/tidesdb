/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "datastructures/skip_list/skip_list_internal.h"

int skip_list_cursor_init(skip_list_cursor_t **cursor, skip_list_t *list)
{
    if (cursor == NULL || list == NULL) return -1;

    *cursor = (skip_list_cursor_t *)malloc(sizeof(skip_list_cursor_t));
    if (*cursor == NULL) return -1;

    (*cursor)->list = list;
    (*cursor)->cached_header = atomic_load_explicit(&list->header, memory_order_acquire);
    (*cursor)->cached_tail = atomic_load_explicit(&list->tail, memory_order_acquire);
    (*cursor)->current =
        atomic_load_explicit(&(*cursor)->cached_header->forward[0], memory_order_acquire);
    (*cursor)->current_version = NULL;
    return 0;
}

void skip_list_cursor_free(skip_list_cursor_t *cursor)
{
    if (cursor != NULL) free(cursor);
}

int skip_list_cursor_valid(const skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    return (cursor->current != cursor->cached_header && cursor->current != cursor->cached_tail) ? 1
                                                                                                : 0;
}

int skip_list_cursor_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_tail) return -1;

    cursor->current = atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    cursor->current_version = NULL;
    if (cursor->current == NULL || cursor->current == cursor->cached_tail) return -1;

    /* prefetch next node, its key, and its version to hide memory latency.
     * acquire (not relaxed) -- next is dereferenced below (NODE_IS_SENTINEL,
     * ->key) so it must synchronize with the release-CAS that published it */
    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (next && !NODE_IS_SENTINEL(next))
    {
        PREFETCH_READ(next);
        PREFETCH_READ(next->key);
    }
    /* prefetch version for the current node -- cursor_get needs it */
    PREFETCH_READ(&cursor->current->versions);

    return 0;
}

int skip_list_cursor_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_header) return -1;

    skip_list_node_t *cur = cursor->current;

    /* the backward pointer is a HINT, trusted only when the forward
     * list confirms it -- H is cur's true predecessor iff H->forward[0] == cur, and
     * forward[0] is the linearizable source of truth. this keeps reverse steps O(1)
     * when the hint is fresh (the common case) while a stale/NULL backward pointer,
     * which a concurrent insert can leave behind, falls through to the reseek. */
    skip_list_node_t *hint =
        atomic_load_explicit(&BACKWARD_PTR(cur, 0, cur->level), memory_order_acquire);
    if (hint != NULL && atomic_load_explicit(&hint->forward[0], memory_order_acquire) == cur)
    {
        cursor->current = hint;
        cursor->current_version = NULL;
        if (hint == cursor->cached_header) return -1;
        PREFETCH_READ(&hint->versions);
        return 0;
    }

    /* slow path -- forward-reseek the predecessor (always complete). when cur is the
     * tail, the predecessor of "+infinity" is the last node (key == NULL). */
    skip_list_node_t *pred =
        (cur == cursor->cached_tail)
            ? skip_list_predecessor(cursor->list, cursor->cached_header, NULL, 0)
            : skip_list_predecessor(cursor->list, cursor->cached_header, cur->key, cur->key_size);

    cursor->current = pred;
    cursor->current_version = NULL;
    if (pred == cursor->cached_header) return -1;

    PREFETCH_READ(&pred->versions);
    return 0;
}

int skip_list_cursor_advance_in_node(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_header || cursor->current == cursor->cached_tail)
        return -1;

    /* if no version was selected yet, the next-older sits behind the head; otherwise
     * walk the chain pointer from the version currently parked on */
    skip_list_version_t *cur =
        cursor->current_version
            ? cursor->current_version
            : atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (cur == NULL) return -1;

    skip_list_version_t *next_older = atomic_load_explicit(&cur->next, memory_order_acquire);
    if (next_older == NULL) return -1;

    cursor->current_version = next_older;
    return 0;
}

int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (cursor == NULL || cursor->current == NULL) return -1;

    /* both sentinels, as skip_list_cursor_valid rejects both. a seek that found nothing at or below
     * its target parks on the header, which has no key to hand back -- it also has no version,
     * which is what stopped this short before the sentinel was named here */
    if (cursor->current == cursor->cached_tail || cursor->current == cursor->cached_header)
        return -1;

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;

    skip_list_version_t *version =
        cursor->current_version
            ? cursor->current_version
            : atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (ttl != NULL) *ttl = version->ttl;

    /* check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid_with_time(version, skip_list_get_current_time(cursor->list)))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (deleted != NULL) *deleted = 0;
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}

int skip_list_cursor_get_with_seq(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size, uint64_t *vlog_id,
                                  int64_t *ttl, uint8_t *deleted, uint64_t *seq)
{
    if (vlog_id != NULL) *vlog_id = 0;
    if (cursor == NULL || cursor->current == NULL) return -1;

    /* both sentinels, as skip_list_cursor_valid rejects both. a seek that found nothing at or below
     * its target parks on the header, which has no key to hand back -- it also has no version,
     * which is what stopped this short before the sentinel was named here */
    if (cursor->current == cursor->cached_tail || cursor->current == cursor->cached_header)
        return -1;

    *key = cursor->current->key;
    *key_size = cursor->current->key_size;

    skip_list_version_t *version =
        cursor->current_version
            ? cursor->current_version
            : atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (ttl != NULL) *ttl = version->ttl;
    if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);

    /* *deleted returns the version flag bits (SKIP_LIST_FLAG_*) so callers can
     * see single-delete and not just plain tombstone.  the low bit is always set
     * when the caller should treat this entry as a tombstone (tombstone or
     * expired ttl), matching the old bool-like contract for existing callers. */
    const uint8_t version_flags = atomic_load_explicit(&version->flags, memory_order_acquire);

    /* check if version is invalid (expired or deleted) */
    if (skip_list_version_is_invalid_with_time(version, skip_list_get_current_time(cursor->list)))
    {
        if (deleted != NULL)
        {
            *deleted = SKIP_LIST_FLAG_DELETED | (version_flags & SKIP_LIST_FLAG_SINGLE_DELETE);
        }
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (deleted != NULL) *deleted = 0;
    *value = version->value;
    *value_size = version->value_size;
    /* a referenced value leaves *value NULL with the logical length in *value_size, so a caller
     * that did not ask for the id would read it as an empty value. the id is reported here rather
     * than left to a separate call for exactly that reason */
    if (vlog_id != NULL) *vlog_id = skip_list_version_vlog_id(version);
    return 0;
}

int skip_list_cursor_next_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                              uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_tail) return -1;

    /* advance to next node */
    cursor->current = atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    cursor->current_version = NULL;
    if (cursor->current == NULL || cursor->current == cursor->cached_tail) return -1;

    /* prefetch next node for the next call to this function.
     * acquire (not relaxed) -- next is dereferenced below so it must
     * synchronize with the release-CAS that published it */
    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    if (next && !NODE_IS_SENTINEL(next))
    {
        PREFETCH_READ(next);
        PREFETCH_READ(next->key);
        PREFETCH_READ(&next->versions);
    }

    /* inline get -- no redundant sentinel/NULL checks */
    *key = cursor->current->key;
    *key_size = cursor->current->key_size;

    skip_list_version_t *version =
        atomic_load_explicit(&cursor->current->versions, memory_order_acquire);
    if (version == NULL) return -1;

    if (ttl != NULL) *ttl = version->ttl;

    if (skip_list_version_is_invalid_with_time(version, skip_list_get_current_time(cursor->list)))
    {
        if (deleted != NULL) *deleted = 1;
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    if (deleted != NULL) *deleted = 0;
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}

int skip_list_cursor_has_next(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_tail) return -1;
    skip_list_node_t *next =
        atomic_load_explicit(&cursor->current->forward[0], memory_order_acquire);
    return (next != NULL && next != cursor->cached_tail) ? 1 : 0;
}

int skip_list_cursor_has_prev(skip_list_cursor_t *cursor)
{
    if (cursor == NULL || cursor->current == NULL) return -1;
    if (cursor->current == cursor->cached_tail) return -1;
    skip_list_node_t *first =
        atomic_load_explicit(&cursor->cached_header->forward[0], memory_order_acquire);
    return (cursor->current != first && cursor->current != cursor->cached_header) ? 1 : 0;
}

int skip_list_cursor_goto_last(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;

    /* fast verified hint where the last node L satisfies L->forward[0] == tail.
     * trust the tail's backward pointer only when forward confirms it; otherwise
     * forward-reseek the last node (predecessor of "+infinity"). */
    skip_list_node_t *tail = cursor->cached_tail;
    skip_list_node_t *last =
        atomic_load_explicit(&BACKWARD_PTR(tail, 0, tail->level), memory_order_acquire);
    if (last == NULL || last == cursor->cached_header ||
        atomic_load_explicit(&last->forward[0], memory_order_acquire) != tail)
    {
        last = skip_list_predecessor(cursor->list, cursor->cached_header, NULL, 0);
    }

    if (last == cursor->cached_header || NODE_IS_SENTINEL(last)) return -1;

    cursor->current = last;
    cursor->current_version = NULL;
    return 0;
}

int skip_list_cursor_goto_first(skip_list_cursor_t *cursor)
{
    if (cursor == NULL) return -1;
    skip_list_node_t *first =
        atomic_load_explicit(&cursor->cached_header->forward[0], memory_order_acquire);
    if (first == NULL || NODE_IS_SENTINEL(first)) return -1;
    cursor->current = first;
    cursor->current_version = NULL;
    return 0;
}

/**
 * skip_list_cursor_seek
 * positions cursor at the node before the first key >= target
 * @param cursor the cursor to position
 * @param key the target key to seek to
 * @param key_size size of the target key
 * @return 0 on success, -1 on failure
 *
 * after calling this function, cursor->current points to the predecessor node.
 * callers must call skip_list_cursor_next() or similar to access the actual target key.
 * this behavior allows efficient insertion and supports both exact matches and range queries.
 */
int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, const size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *current = skip_list_descend(cursor->list, cursor->cached_header, key,
                                                  key_size, SKIP_LIST_DESCEND_BELOW);

    /* position cursor at the node before target
     * caller must call skip_list_cursor_next() to access first key >= target */
    cursor->current = current;
    cursor->current_version = NULL;
    return 0;
}

int skip_list_cursor_seek_ge(skip_list_cursor_t *cursor, const uint8_t *key, const size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *current = skip_list_descend(cursor->list, cursor->cached_header, key,
                                                  key_size, SKIP_LIST_DESCEND_BELOW);

    /* land directly on the first entry >= target rather than parking before it and
     * leaving a separate next() to read forward[0]. a concurrent put can splice a node
     * whose key is < target into forward[0] in that window, so a seek+next pair can
     * return a key below target; re-reading forward[0] until past target closes it.
     * once current points at a node >= target, later sub-target inserts splice in before
     * it and do not move the cursor. */
    for (;;)
    {
        skip_list_node_t *nx = atomic_load_explicit(&current->forward[0], memory_order_acquire);
        if (nx == NULL || NODE_IS_SENTINEL(nx))
        {
            cursor->current = nx;
            cursor->current_version = NULL;
            return -1;
        }
        if (tdb_key_cmp(nx->key, nx->key_size, key, key_size) >= 0)
        {
            cursor->current = nx;
            cursor->current_version = NULL;
            return 0;
        }
        current = nx;
    }
}

int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key,
                                   const size_t key_size)
{
    if (cursor == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *current = skip_list_descend(cursor->list, cursor->cached_header, key,
                                                  key_size, SKIP_LIST_DESCEND_AT_OR_BELOW);

    /* the current is now the last node with key <= target, or header if no such key */
    if (NODE_IS_SENTINEL(current))
    {
        /* no key <= target exists, cursor is invalid */
        cursor->current = current;
        cursor->current_version = NULL;
        return 0;
    }

    cursor->current = current;
    cursor->current_version = NULL;
    return 0;
}
