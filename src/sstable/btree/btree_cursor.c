/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable/btree/btree_internal.h"

int btree_cursor_init(btree_cursor_t **cursor, btree_t *tree)
{
    if (!cursor || !tree) return -1;

    btree_cursor_t *c = calloc(1, sizeof(btree_cursor_t));
    if (!c) return -1;

    c->tree = tree;
    c->current_node = NULL;
    c->current_index = -1;
    c->current_leaf_offset = -1;
    c->at_end = 0;
    c->at_begin = 0;
    c->current_pin = NULL;

    /* left unpositioned: a cursor that placed itself on the first leaf would read and pin a node
     * that almost no caller wants. a merge source is seeked to the range it will read before
     * anything is drawn from it, and a scan of the whole tree asks for the first leaf explicitly --
     * so positioning here meant loading a leaf, materializing every key in it, and releasing it
     * again on the very next call, once per sstable the scan opened.
     *
     * the unpositioned state is the one the cursor already models: valid reports 0, next goes to
     * the first entry and prev to the last, and seek descends from the root regardless */
    *cursor = c;
    return 0;
}

int btree_cursor_goto_first(btree_cursor_t *cursor)
{
    if (!cursor || !cursor->tree) return -1;

    cursor->read_error = 0;

    if (cursor->current_node)
    {
        btree_node_done(cursor->current_node, cursor->current_pin);
        cursor->current_node = NULL;
    }

    if (cursor->tree->first_leaf_offset < 0)
    {
        cursor->at_end = 1;
        return -1;
    }

    cursor->current_leaf_offset = cursor->tree->first_leaf_offset;
    if (btree_node_read_cached(cursor->tree, cursor->current_leaf_offset, &cursor->current_node,
                               &cursor->current_pin) != 0)
    {
        /* the tree has a first leaf but it could not load -- a transient failure, not empty */
        cursor->read_error = 1;
        return -1;
    }

    cursor->current_index = 0;
    cursor->at_end = (cursor->current_node->num_entries == 0);
    cursor->at_begin = 0;
    return cursor->at_end ? -1 : 0;
}

int btree_cursor_goto_last(btree_cursor_t *cursor)
{
    if (!cursor || !cursor->tree) return -1;

    cursor->read_error = 0;

    if (cursor->current_node)
    {
        btree_node_done(cursor->current_node, cursor->current_pin);
        cursor->current_node = NULL;
    }

    if (cursor->tree->last_leaf_offset < 0)
    {
        cursor->at_end = 1;
        return -1;
    }

    cursor->current_leaf_offset = cursor->tree->last_leaf_offset;
    if (btree_node_read_cached(cursor->tree, cursor->current_leaf_offset, &cursor->current_node,
                               &cursor->current_pin) != 0)
    {
        /* the tree has a last leaf but it could not load -- a transient failure, not empty */
        cursor->read_error = 1;
        return -1;
    }

    cursor->current_index = (int32_t)cursor->current_node->num_entries - 1;
    cursor->at_end = (cursor->current_index < 0);
    cursor->at_begin = 0;
    return cursor->at_end ? -1 : 0;
}

int btree_cursor_next(btree_cursor_t *cursor)
{
    if (!cursor || cursor->at_end) return -1;

    cursor->read_error = 0;

    if (!cursor->current_node)
    {
        return btree_cursor_goto_first(cursor);
    }

    cursor->current_index++;

    if ((uint32_t)cursor->current_index >= cursor->current_node->num_entries)
    {
        const int64_t next_leaf_offset = cursor->current_node->next_offset;

        if (next_leaf_offset < 0)
        {
            cursor->at_end = 1;
            return -1;
        }

        btree_node_done(cursor->current_node, cursor->current_pin);
        cursor->current_node = NULL;

        cursor->current_leaf_offset = next_leaf_offset;
        if (btree_node_read_cached(cursor->tree, cursor->current_leaf_offset, &cursor->current_node,
                                   &cursor->current_pin) != 0)
        {
            /* the next leaf exists (next_offset >= 0) but it could not load -- a transient cache
             * miss + reload failure under memory/fd pressure, not a real end. flag it so a merge
             * source aborts instead of silently dropping every remaining entry. */
            cursor->read_error = 1;
            cursor->at_end = 1;
            return -1;
        }

        cursor->current_index = 0;

        if (cursor->current_node->num_entries == 0)
        {
            cursor->at_end = 1;
            return -1;
        }
    }

    return 0;
}

int btree_cursor_prev(btree_cursor_t *cursor)
{
    if (!cursor) return -1;

    cursor->read_error = 0;

    if (!cursor->current_node)
    {
        return btree_cursor_goto_last(cursor);
    }

    cursor->current_index--;

    if (cursor->current_index < 0)
    {
        const int64_t prev_leaf_offset = cursor->current_node->prev_offset;

        if (prev_leaf_offset < 0)
        {
            /* reached beginning */
            cursor->current_index = -1;
            cursor->at_begin = 1;
            return -1;
        }

        btree_node_done(cursor->current_node, cursor->current_pin);
        cursor->current_node = NULL;

        cursor->current_leaf_offset = prev_leaf_offset;
        if (btree_node_read_cached(cursor->tree, cursor->current_leaf_offset, &cursor->current_node,
                                   &cursor->current_pin) != 0)
        {
            /* prev leaf exists but could not be loaded -- a transient failure, not the begin */
            cursor->read_error = 1;
            cursor->at_begin = 1;
            return -1;
        }

        cursor->current_index = (int32_t)cursor->current_node->num_entries - 1;

        if (cursor->current_index < 0)
        {
            cursor->at_begin = 1;
            return -1;
        }
    }

    return 0;
}

int btree_cursor_seek(btree_cursor_t *cursor, const uint8_t *key, const size_t key_size)
{
    if (!cursor || !cursor->tree || !key || key_size == 0) return -1;

    cursor->read_error = 0;

    if (cursor->current_node)
    {
        btree_node_done(cursor->current_node, cursor->current_pin);
    }
    /* clear the pin too, not just the node -- the descend below reacquires through local variables
     * and only writes current_pin back on success, so a failed or empty seek that left a stale pin
     * here would release it a second time on the next node_done, dropping a shared cached node's
     * refcount early and freeing it under another cursor */
    cursor->current_node = NULL;
    cursor->current_pin = NULL;

    if (cursor->tree->root_offset < 0)
    {
        cursor->at_end = 1;
        return -1;
    }

    btree_node_t *node = NULL;
    cache_entry_t *pin = NULL;
    if (btree_descend_to_leaf(cursor->tree, key, key_size, &node, &pin) != 0)
    {
        /* the tree has a root but a node could not be loaded -- transient, not an absent key */
        cursor->read_error = 1;
        return -1;
    }

    /* lower_bound -- leftmost index whose key is >= the search key. same-key versions are stored
     * newest-first (key asc, seq desc), so landing on the first equal entry positions the cursor on
     * the newest version (e.g. a tombstone). an exact-match break could land mid-run on an older
     * version and let a deleted key surface its older put through a seeking iterator. */
    int32_t lo = 0;
    int32_t hi = (int32_t)node->num_entries;
    while (lo < hi)
    {
        const int32_t mid = lo + (hi - lo) / 2;
        const int cmp = btree_key_cmp(key, key_size, node->keys[mid], node->key_sizes[mid]);
        if (cmp <= 0)
        {
            hi = mid;
        }
        else
        {
            lo = mid + 1;
        }
    }
    int32_t found_idx = lo;

    if ((uint32_t)found_idx >= node->num_entries)
    {
        if (node->next_offset >= 0)
        {
            const int64_t next_off = node->next_offset;
            btree_node_done(node, pin);
            if (btree_node_read_cached(cursor->tree, next_off, &node, &pin) != 0)
            {
                /* the following leaf exists but could not be loaded -- a transient failure */
                cursor->read_error = 1;
                cursor->at_end = 1;
                return -1;
            }
            found_idx = 0;
        }
        else
        {
            btree_node_done(node, pin);
            cursor->at_end = 1;
            return -1;
        }
    }

    cursor->current_node = node;
    cursor->current_pin = pin;
    cursor->current_index = found_idx;
    cursor->current_leaf_offset = node->block_offset;
    cursor->at_end = 0;
    cursor->at_begin = 0;
    return 0;
}

int btree_cursor_seek_for_prev(btree_cursor_t *cursor, const uint8_t *key, const size_t key_size)
{
    if (!cursor || !cursor->tree || !key || key_size == 0) return -1;

    if (btree_cursor_seek(cursor, key, key_size) != 0)
    {
        return btree_cursor_goto_last(cursor);
    }

    const int cmp = btree_key_cmp(key, key_size, cursor->current_node->keys[cursor->current_index],
                                  cursor->current_node->key_sizes[cursor->current_index]);

    if (cmp < 0)
    {
        return btree_cursor_prev(cursor);
    }

    return 0;
}

int btree_cursor_valid(btree_cursor_t *cursor)
{
    if (!cursor) return -1;
    if (cursor->at_end) return 0;
    if (!cursor->current_node) return 0;
    if (cursor->current_index < 0) return 0;
    if ((uint32_t)cursor->current_index >= cursor->current_node->num_entries) return 0;
    return 1;
}

int btree_cursor_read_failed(const btree_cursor_t *cursor)
{
    return cursor ? cursor->read_error : 0;
}

int btree_cursor_get(btree_cursor_t *cursor, uint8_t **key, size_t *key_size, uint8_t **value,
                     size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                     uint8_t *deleted)
{
    if (!cursor || !cursor->current_node) return -1;
    if (cursor->current_index < 0 ||
        (uint32_t)cursor->current_index >= cursor->current_node->num_entries)
    {
        return -1;
    }

    const uint32_t idx = (uint32_t)cursor->current_index;
    const btree_entry_t *entry = &cursor->current_node->entries[idx];

    if (key) *key = cursor->current_node->keys[idx];
    if (key_size) *key_size = cursor->current_node->key_sizes[idx];
    if (value) *value = cursor->current_node->values[idx];
    if (value_size) *value_size = entry->value_size;
    if (vlog_offset) *vlog_offset = entry->vlog_offset;
    if (seq) *seq = entry->seq;
    if (ttl) *ttl = entry->ttl;
    /* deleted returns the persisted tombstone/single-delete bits so compaction can distinguish a
     * single-delete from a regular one. the low bit is BTREE_ENTRY_FLAG_TOMBSTONE, so a caller that
     * only asks whether the entry is deleted can test it as a boolean */
    if (deleted)
        *deleted = entry->flags & (BTREE_ENTRY_FLAG_TOMBSTONE | BTREE_ENTRY_FLAG_SINGLE_DELETE);

    return 0;
}

int btree_cursor_has_next(btree_cursor_t *cursor)
{
    if (!cursor) return -1;
    if (cursor->at_end) return 0;
    if (!cursor->current_node) return 1;

    if ((uint32_t)(cursor->current_index + 1) < cursor->current_node->num_entries)
    {
        return 1;
    }

    return (cursor->current_node->next_offset >= 0) ? 1 : 0;
}

int btree_cursor_has_prev(btree_cursor_t *cursor)
{
    if (!cursor) return -1;
    if (!cursor->current_node) return 0;

    if (cursor->current_index > 0)
    {
        return 1;
    }

    return (cursor->current_node->prev_offset >= 0) ? 1 : 0;
}

void btree_cursor_free(btree_cursor_t *cursor)
{
    if (!cursor) return;
    btree_node_done(cursor->current_node, cursor->current_pin);
    free(cursor);
}
