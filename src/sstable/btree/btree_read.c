/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "sstable/btree/btree_internal.h"

int btree_open(btree_t **tree, block_manager_t *bm, const btree_config_t *config,
               const int64_t root_offset, const int64_t first_leaf_offset,
               const int64_t last_leaf_offset)
{
    if (!tree || !bm || !config) return -1;

    btree_t *t = calloc(1, sizeof(btree_t));
    if (!t) return -1;

    t->bm = bm;
    t->config = *config;
    t->root_offset = root_offset;
    t->first_leaf_offset = first_leaf_offset;
    t->last_leaf_offset = last_leaf_offset;

    *tree = t;
    return 0;
}

int btree_get_at_seq(btree_t *tree, const uint8_t *key, const size_t key_size,
                     const uint64_t seq_ceiling, uint8_t **value, size_t *value_size,
                     uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl, uint8_t *deleted)
{
    if (!tree || !key || key_size == 0) return -1;

    if (tree->root_offset < 0) return -1;

    cache_entry_t *pin = NULL;
    btree_node_t *node = NULL;
    /* a descend failure is a node that could not be loaded, never a genuine absence -- absence is
     * decided by the leaf scan below -- so report it as transient for the caller to retry */
    if (btree_descend_to_leaf(tree, key, key_size, &node, &pin) != 0) return BTREE_READ_TRANSIENT;

    /* lower_bound -- leftmost index whose key is >= the search key */
    int32_t lo = 0;
    int32_t hi = (int32_t)node->num_entries;
    while (lo < hi)
    {
        const int32_t mid = lo + (hi - lo) / 2;
        const int cmp = tdb_key_cmp(key, key_size, node->keys[mid], node->key_sizes[mid]);
        if (cmp <= 0)
        {
            hi = mid;
        }
        else
        {
            lo = mid + 1;
        }
    }

    /* scan the run of entries that share the search key, keeping the highest
     * seq that does not exceed seq_ceiling. a key may have several versions --
     * a flush or compaction retains a version chain -- and they all live in
     * this one leaf, so the resolved version is the one visible at the
     * caller's snapshot. */
    int32_t found_idx = -1;
    for (int32_t i = lo; i < (int32_t)node->num_entries; i++)
    {
        if (tdb_key_cmp(key, key_size, node->keys[i], node->key_sizes[i]) != 0)
        {
            break;
        }
        const uint64_t entry_seq = node->entries[i].seq;
        if (entry_seq > seq_ceiling) continue;
        if (found_idx < 0 || entry_seq > node->entries[found_idx].seq)
        {
            found_idx = i;
        }
    }

    if (found_idx < 0)
    {
        btree_node_done(node, pin);
        return -1;
    }

    const btree_entry_t *entry = &node->entries[found_idx];

    if (value && value_size)
    {
        if (entry->vlog_offset == 0 && node->values[found_idx])
        {
            *value = malloc(entry->value_size);
            /* a failed copy cannot be reported as success. callers tell an inline value from a
             * spilled one by vlog_offset, so a null value at offset zero reads back as an empty
             * value rather than as the failure it is -- report it as transient so the read retries
             * instead of resolving to the wrong bytes */
            if (!*value && entry->value_size > 0)
            {
                btree_node_done(node, pin);
                return BTREE_READ_TRANSIENT;
            }
            if (*value) memcpy(*value, node->values[found_idx], entry->value_size);
            *value_size = entry->value_size;
        }
        else
        {
            *value = NULL;
            *value_size = entry->value_size;
        }
    }

    if (vlog_offset) *vlog_offset = entry->vlog_offset;
    if (seq) *seq = entry->seq;
    if (ttl) *ttl = entry->ttl;
    /* deleted returns the persisted tombstone/single-delete bits so compaction can distinguish a
     * single-delete from a regular one. the low bit is BTREE_ENTRY_FLAG_TOMBSTONE, so a caller that
     * only asks whether the entry is deleted can test it as a boolean */
    if (deleted)
        *deleted = entry->flags & (BTREE_ENTRY_FLAG_TOMBSTONE | BTREE_ENTRY_FLAG_SINGLE_DELETE);

    btree_node_done(node, pin);
    return 0;
}

int btree_get(btree_t *tree, const uint8_t *key, const size_t key_size, uint8_t **value,
              size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
              uint8_t *deleted)
{
    return btree_get_at_seq(tree, key, key_size, UINT64_MAX, value, value_size, vlog_offset, seq,
                            ttl, deleted);
}

uint64_t btree_get_entry_count(const btree_t *tree)
{
    return tree ? tree->entry_count : 0;
}

int btree_get_min_key(btree_t *tree, uint8_t **key, size_t *key_size)
{
    if (!tree || !key || !key_size) return -1;
    if (!tree->min_key) return -1;

    *key = malloc(tree->min_key_size);
    if (!*key) return -1;
    memcpy(*key, tree->min_key, tree->min_key_size);
    *key_size = tree->min_key_size;
    return 0;
}

int btree_get_max_key(btree_t *tree, uint8_t **key, size_t *key_size)
{
    if (!tree || !key || !key_size) return -1;
    if (!tree->max_key) return -1;

    *key = malloc(tree->max_key_size);
    if (!*key) return -1;
    memcpy(*key, tree->max_key, tree->max_key_size);
    *key_size = tree->max_key_size;
    return 0;
}

uint64_t btree_get_max_seq(const btree_t *tree)
{
    return tree ? tree->max_seq : 0;
}

int btree_get_stats(const btree_t *tree, btree_stats_t *stats)
{
    if (!tree || !stats) return -1;

    stats->entry_count = tree->entry_count;
    stats->node_count = tree->node_count;
    stats->height = tree->height;

    /* get serialized size from block manager if available */
    stats->serialized_size = 0;
    if (tree->bm)
    {
        uint64_t size;
        if (block_manager_get_size(tree->bm, &size) == 0)
        {
            stats->serialized_size = size;
        }
    }

    return 0;
}

void btree_free(btree_t *tree)
{
    if (!tree) return;
    free(tree->min_key);
    free(tree->max_key);
    free(tree);
}

void btree_set_node_cache(btree_t *tree, cache_t *cache, const uint64_t cache_key_prefix)
{
    if (tree)
    {
        tree->node_cache = cache;
        tree->cache_key_prefix = cache_key_prefix;
    }
}

int btree_hold_root(btree_t *tree, btree_node_t **root, cache_entry_t **pin)
{
    if (!tree || !root || !pin) return -1;
    *root = NULL;
    *pin = NULL;
    if (!tree->node_cache || tree->root_offset < 0) return -1;

    btree_node_t *node = NULL;
    cache_entry_t *held = NULL;
    if (btree_node_read_cached(tree, tree->root_offset, &node, &held) != 0) return -1;

    if (!held || node->type != BTREE_NODE_INTERNAL)
    {
        btree_node_done(node, held);
        return -1;
    }

    *root = node;
    *pin = held;
    return 0;
}

void btree_set_borrowed_root(btree_t *tree, btree_node_t *root)
{
    if (tree) tree->borrowed_root = root;
}
