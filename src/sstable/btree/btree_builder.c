/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/errors.h" /* TDB_SUCCESS from the encoding stage runners */
#include "base/log.h"
#include "sstable/btree/btree_internal.h"

/**
 * btree_pending_leaf_create
 * creates a new pending leaf for building during tree construction
 * @return new pending leaf or NULL on failure
 */
static btree_pending_leaf_t *btree_pending_leaf_create(void)
{
    btree_pending_leaf_t *leaf = calloc(1, sizeof(btree_pending_leaf_t));
    if (!leaf) return NULL;

    leaf->capacity = BTREE_PENDING_LEAF_INITIAL_CAP;
    leaf->entries = calloc(leaf->capacity, sizeof(btree_entry_t));
    leaf->keys = calloc(leaf->capacity, sizeof(uint8_t *));
    leaf->values = calloc(leaf->capacity, sizeof(uint8_t *));

    if (!leaf->entries || !leaf->keys || !leaf->values)
    {
        free(leaf->entries);
        free(leaf->keys);
        free(leaf->values);
        free(leaf);
        return NULL;
    }

    return leaf;
}

/**
 * btree_pending_leaf_free
 * frees a pending leaf and all associated memory
 * @param leaf the pending leaf to free
 */
static void btree_pending_leaf_free(btree_pending_leaf_t *leaf)
{
    if (!leaf) return;

    for (uint32_t i = 0; i < leaf->num_entries; i++)
    {
        free(leaf->keys[i]);
        free(leaf->values[i]);
    }

    free(leaf->entries);
    free(leaf->keys);
    free(leaf->values);
    free(leaf->first_key);
    free(leaf->last_key);
    free(leaf);
}

/**
 * btree_pending_leaf_add
 * adds an entry to a pending leaf during tree construction
 * @param leaf the pending leaf to add to
 * @param key key data
 * @param key_size size of key
 * @param value value data (may be NULL if vlog_offset > 0)
 * @param value_size size of value
 * @param vlog_offset offset in value log (0 for inline values)
 * @param seq sequence number
 * @param ttl time-to-live (0 = no expiry)
 * @param flags entry flags (tombstone, etc.)
 * @return 0 on success, -1 on failure
 */
static int btree_pending_leaf_add(btree_pending_leaf_t *leaf, const uint8_t *key,
                                  const size_t key_size, const uint8_t *value,
                                  const size_t value_size, const uint64_t vlog_offset,
                                  const uint64_t seq, const int64_t ttl, const uint8_t flags)
{
    if (leaf->num_entries >= leaf->capacity)
    {
        const uint32_t new_capacity = leaf->capacity * 2;
        btree_entry_t *new_entries = realloc(leaf->entries, new_capacity * sizeof(btree_entry_t));
        uint8_t **new_keys = realloc(leaf->keys, new_capacity * sizeof(uint8_t *));
        uint8_t **new_values = realloc(leaf->values, new_capacity * sizeof(uint8_t *));

        if (!new_entries || !new_keys || !new_values)
        {
            return -1;
        }

        leaf->entries = new_entries;
        leaf->keys = new_keys;
        leaf->values = new_values;
        leaf->capacity = new_capacity;

        for (uint32_t i = leaf->num_entries; i < new_capacity; i++)
        {
            leaf->keys[i] = NULL;
            leaf->values[i] = NULL;
        }
    }

    const uint32_t idx = leaf->num_entries;

    leaf->keys[idx] = malloc(key_size);
    if (!leaf->keys[idx]) return -1;
    memcpy(leaf->keys[idx], key, key_size);

    if (vlog_offset == 0 && value && value_size > 0)
    {
        leaf->values[idx] = malloc(value_size);
        if (!leaf->values[idx])
        {
            free(leaf->keys[idx]);
            leaf->keys[idx] = NULL;
            return -1;
        }
        memcpy(leaf->values[idx], value, value_size);
    }
    else
    {
        leaf->values[idx] = NULL;
    }

    leaf->entries[idx].key_size = (uint32_t)key_size;
    leaf->entries[idx].value_size = (uint32_t)value_size;
    leaf->entries[idx].vlog_offset = vlog_offset;
    leaf->entries[idx].seq = seq;
    leaf->entries[idx].ttl = ttl;
    leaf->entries[idx].flags = flags;

    /* first_key/last_key must succeed in that an empty first_key corrupts the internal-node
     * separator and a stale last_key breaks the same-key-run flush guard in btree_builder_add. on
     * failure undo this entry (num_entries is not yet incremented, so free its key/value here) and
     * fail the add. */
    if (leaf->num_entries == 0)
    {
        leaf->first_key = malloc(key_size);
        if (!leaf->first_key)
        {
            free(leaf->keys[idx]);
            leaf->keys[idx] = NULL;
            free(leaf->values[idx]);
            leaf->values[idx] = NULL;
            return -1;
        }
        memcpy(leaf->first_key, key, key_size);
        leaf->first_key_size = key_size;
    }

    free(leaf->last_key);
    leaf->last_key = malloc(key_size);
    if (!leaf->last_key)
    {
        leaf->last_key_size = 0;
        free(leaf->keys[idx]);
        leaf->keys[idx] = NULL;
        free(leaf->values[idx]);
        leaf->values[idx] = NULL;
        return -1;
    }
    memcpy(leaf->last_key, key, key_size);
    leaf->last_key_size = key_size;

    leaf->current_size += key_size + (vlog_offset == 0 ? value_size : 0) + sizeof(btree_entry_t);
    leaf->num_entries++;

    return 0;
}

int btree_builder_new(btree_builder_t **builder, block_manager_t *bm, const btree_config_t *config)
{
    if (!builder || !bm || !config) return -1;

    btree_builder_t *b = calloc(1, sizeof(btree_builder_t));
    if (!b) return -1;

    b->bm = bm;
    b->config = *config;

    if (b->config.target_node_size == 0)
    {
        b->config.target_node_size = BTREE_DEFAULT_NODE_SIZE;
    }

    b->current_leaf = btree_pending_leaf_create();
    if (!b->current_leaf)
    {
        free(b);
        return -1;
    }

    b->first_leaf_offset = -1;
    b->last_leaf_offset = -1;
    b->prev_leaf_offset = -1;

    b->leaf_offsets_capacity = 256;
    b->leaf_offsets = calloc(b->leaf_offsets_capacity, sizeof(int64_t));
    if (!b->leaf_offsets)
    {
        btree_pending_leaf_free(b->current_leaf);
        free(b);
        return -1;
    }

    b->level_entries_capacity = 256;
    b->level_entries = calloc(b->level_entries_capacity, sizeof(btree_level_entry_t));
    if (!b->level_entries)
    {
        free(b->leaf_offsets);
        btree_pending_leaf_free(b->current_leaf);
        free(b);
        return -1;
    }

    /* uncompressed leaves are staged before compression. with compression on,
     * stage them in a temp file so the klog receives only the final compressed
     * leaves -- staging them in the klog would leave the discarded uncompressed
     * copies behind as permanent dead weight. with compression off the first
     * write is already final, so stage straight into the klog. */
    b->leaf_bm = bm;
    if (b->config.codec_count > 0)
    {
        /* sizeof the suffix literal already includes its null terminator, so this
         * holds a full-length file_path plus the suffix without truncation */
        char tmp_path[MAX_FILE_PATH_LENGTH + sizeof(BTREE_LEAF_STAGE_SUFFIX)];
        snprintf(tmp_path, sizeof(tmp_path), "%s" BTREE_LEAF_STAGE_SUFFIX, bm->file_path);
        block_manager_t *tmp_bm = NULL;
        if (block_manager_open(&tmp_bm, tmp_path, BLOCK_MANAGER_SYNC_NONE) == 0 &&
            block_manager_truncate(tmp_bm) == 0)
        {
            b->leaf_bm = tmp_bm;
        }
        else if (tmp_bm)
        {
            /* temp file unavailable -- fall back to staging in the klog so the
             * build still succeeds (correctness over space) */
            (void)block_manager_close(tmp_bm);
        }
    }

    *builder = b;
    return 0;
}

/**
 * btree_builder_flush_leaf
 * flushes the current pending leaf to storage
 * @param builder the builder instance
 * @return 0 on success, -1 on failure
 */
static int btree_builder_flush_leaf(btree_builder_t *builder)
{
    if (!builder || !builder->current_leaf || builder->current_leaf->num_entries == 0)
    {
        return 0;
    }

    uint8_t *serialized = NULL;
    size_t serialized_size = 0;

    if (btree_leaf_serialize(builder->current_leaf, builder->prev_leaf_offset, -1, &serialized,
                             &serialized_size) != 0)
    {
        return -1;
    }

    /**** leaf nodes are written without compression during build phase
     ***  because next_offset links are backpatched after all leaves are written.
     **   compression is applied during the backpatch phase after patching.
     *    from_buffer transfers ownership and avoids redundant malloc+memcpy */
    block_manager_block_t *block =
        block_manager_block_create_from_buffer(serialized_size, serialized);

    if (!block) return -1;

    const int64_t offset = block_manager_block_write(builder->leaf_bm, block);
    block_manager_block_free(block);

    if (offset < 0) return -1;

    /* track leaf offset for bidirectional linking */
    if (builder->num_leaf_offsets >= builder->leaf_offsets_capacity)
    {
        const uint32_t new_cap = builder->leaf_offsets_capacity * 2;
        int64_t *new_offsets = realloc(builder->leaf_offsets, new_cap * sizeof(int64_t));
        if (!new_offsets) return -1;
        builder->leaf_offsets = new_offsets;
        builder->leaf_offsets_capacity = new_cap;
    }
    builder->leaf_offsets[builder->num_leaf_offsets++] = offset;

    if (builder->first_leaf_offset < 0)
    {
        builder->first_leaf_offset = offset;
    }
    builder->last_leaf_offset = offset;

    if (builder->num_level_entries >= builder->level_entries_capacity)
    {
        const uint32_t new_cap = builder->level_entries_capacity * 2;
        btree_level_entry_t *new_entries =
            realloc(builder->level_entries, new_cap * sizeof(btree_level_entry_t));
        if (!new_entries) return -1;
        builder->level_entries = new_entries;
        builder->level_entries_capacity = new_cap;
    }

    btree_level_entry_t *entry = &builder->level_entries[builder->num_level_entries];
    entry->key = malloc(builder->current_leaf->first_key_size);
    if (!entry->key) return -1;
    memcpy(entry->key, builder->current_leaf->first_key, builder->current_leaf->first_key_size);
    entry->key_size = builder->current_leaf->first_key_size;
    entry->child_offset = offset;
    builder->num_level_entries++;

    builder->prev_leaf_offset = offset;
    builder->node_count++;

    btree_pending_leaf_free(builder->current_leaf);
    builder->current_leaf = btree_pending_leaf_create();

    return builder->current_leaf ? 0 : -1;
}

int btree_builder_add(btree_builder_t *builder, const uint8_t *key, const size_t key_size,
                      const uint8_t *value, const size_t value_size, const uint64_t vlog_offset,
                      const uint64_t seq, const int64_t ttl, const uint8_t entry_flags)
{
    if (!builder || !key || key_size == 0) return -1;
    /* the node format records both lengths in a u32, so one that does not fit is refused here
     * rather than silently truncated into a file that reads back as a different entry. the value
     * log turns the same case away for a separated value; an inline one is caught here */
    if (key_size > UINT32_MAX || value_size > UINT32_MAX) return -1;

    uint8_t flags = entry_flags & (BTREE_ENTRY_FLAG_TOMBSTONE | BTREE_ENTRY_FLAG_SINGLE_DELETE);
    if (ttl != 0) flags |= BTREE_ENTRY_FLAG_HAS_TTL;
    if (vlog_offset > 0) flags |= BTREE_ENTRY_FLAG_VLOG_REF;

    /* flush the full leaf before adding -- but never across a run of entries
     * that share a key. a key's versions must all stay within one leaf so
     * internal-node routing lands on the single leaf holding them and btree_get
     * can resolve the whole run. */
    if (builder->current_leaf->current_size >= builder->config.target_node_size &&
        builder->current_leaf->num_entries >= BTREE_MIN_ENTRIES_PER_LEAF)
    {
        const btree_pending_leaf_t *cur = builder->current_leaf;
        const int same_key_as_last = cur->last_key != NULL && cur->last_key_size == key_size &&
                                     memcmp(cur->last_key, key, key_size) == 0;
        if (!same_key_as_last && btree_builder_flush_leaf(builder) != 0)
        {
            return -1;
        }
    }

    if (btree_pending_leaf_add(builder->current_leaf, key, key_size, value, value_size, vlog_offset,
                               seq, ttl, flags) != 0)
    {
        return -1;
    }

    /* this pair becomes the sstable's key range in the footer, and overlap checks compare against
     * it to decide which files a lookup consults. a missing range reads as an empty one, which
     * sorts below every real key and hides the whole sstable from those checks, so a failure here
     * fails the build rather than publishing a file no query would reach */
    if (builder->min_key == NULL)
    {
        builder->min_key = malloc(key_size);
        if (!builder->min_key) return -1;
        memcpy(builder->min_key, key, key_size);
        builder->min_key_size = key_size;
    }

    free(builder->max_key);
    builder->max_key = malloc(key_size);
    if (!builder->max_key)
    {
        builder->max_key_size = 0;
        return -1;
    }
    memcpy(builder->max_key, key, key_size);
    builder->max_key_size = key_size;

    if (seq > builder->max_seq)
    {
        builder->max_seq = seq;
    }

    builder->entry_count++;
    return 0;
}

/**
 * btree_free_level
 * free one built level and every separator key it owns
 * @param level the level array, may be NULL
 * @param count the number of entries holding a key
 */
static void btree_free_level(btree_level_entry_t *level, uint32_t count)
{
    for (uint32_t j = 0; j < count; j++) free(level[j].key);
    free(level);
}

/**
 * btree_write_internal_node
 * serialize one internal node over a run of children, compress it when the build is compressing,
 * and write it out. an internal node carries the same block header as a leaf so there is a single
 * node format, with both sibling links unused
 * @param builder the builder instance
 * @param children the run of child entries this node routes to
 * @param count the number of children in the run
 * @return the offset the node was written at, or -1 on a serialize, allocation, or write failure
 */
static int64_t btree_write_internal_node(btree_builder_t *builder,
                                         const btree_level_entry_t *children, uint32_t count)
{
    uint8_t *serialized = NULL;
    size_t serialized_size = 0;
    if (btree_internal_serialize(children, count, &serialized, &serialized_size) != 0) return -1;

    const uint8_t *final_data = serialized;
    size_t final_size = serialized_size;
    uint8_t *block_with_header = NULL;

    if (builder->config.codec_count > 0)
    {
        size_t compressed_size = 0;
        uint8_t *compressed = NULL;
        if (tidesdb_encoding_stages_encode(builder->config.codec, builder->config.codec_count,
                                           serialized, serialized_size, &compressed,
                                           &compressed_size) != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "node encode failed, %d stages, %zu bytes",
                          builder->config.codec_count, serialized_size);
            compressed = NULL;
        }
        if (compressed)
        {
            /* a reader decodes from the sstable's encoding pipeline rather than per block, so
             * writing the uncompressed bytes instead would be misread. without this buffer there is
             * no correct block to write, so fail the build rather than emit one whose length and
             * contents disagree */
            block_with_header = malloc(BTREE_COMPRESSED_NODE_HEADER_SIZE + compressed_size);
            if (!block_with_header)
            {
                free(compressed);
                free(serialized);
                return -1;
            }
            encode_uint32_le_compat(block_with_header, (uint32_t)serialized_size);
            encode_int64_le_compat(block_with_header + BTREE_COMPRESSED_NODE_PREV_OFF,
                                   BTREE_LEAF_LINK_NONE);
            encode_int64_le_compat(block_with_header + BTREE_COMPRESSED_NODE_NEXT_OFF,
                                   BTREE_LEAF_LINK_NONE);
            memcpy(block_with_header + BTREE_COMPRESSED_NODE_HEADER_SIZE, compressed,
                   compressed_size);
            final_data = block_with_header;
            final_size = BTREE_COMPRESSED_NODE_HEADER_SIZE + compressed_size;
            free(compressed);
        }
    }

    block_manager_block_t *block = block_manager_block_create(final_size, final_data);
    free(serialized);
    free(block_with_header);
    if (!block) return -1;

    const int64_t offset = block_manager_block_write(builder->bm, block);
    block_manager_block_free(block);
    return offset;
}

/**
 * btree_build_one_level
 * build the internal level directly above a level, one node per fanout-sized run of its entries
 * @param builder the builder instance
 * @param current the level being covered
 * @param current_count the number of entries in current
 * @param out_count receives the number of entries in the level built
 * @return the level built, owned by the caller, or NULL on failure
 */
static btree_level_entry_t *btree_build_one_level(btree_builder_t *builder,
                                                  const btree_level_entry_t *current,
                                                  uint32_t current_count, uint32_t *out_count)
{
    const uint32_t next_capacity = (current_count / BTREE_DEFAULT_FANOUT) + 1;
    btree_level_entry_t *next_level = calloc(next_capacity, sizeof(btree_level_entry_t));
    if (!next_level) return NULL;

    uint32_t next_count = 0;
    for (uint32_t i = 0; i < current_count;)
    {
        uint32_t node_entries = BTREE_DEFAULT_FANOUT;
        if (i + node_entries > current_count) node_entries = current_count - i;

        const int64_t offset = btree_write_internal_node(builder, &current[i], node_entries);
        if (offset < 0)
        {
            btree_free_level(next_level, next_count);
            return NULL;
        }

        /* this key becomes the separator the level above routes on, so a null one would send every
         * lookup for that subtree down the wrong child. fail the build instead */
        next_level[next_count].key = malloc(current[i].key_size);
        if (!next_level[next_count].key)
        {
            btree_free_level(next_level, next_count);
            return NULL;
        }
        memcpy(next_level[next_count].key, current[i].key, current[i].key_size);
        next_level[next_count].key_size = current[i].key_size;
        next_level[next_count].child_offset = offset;
        next_count++;

        builder->node_count++;
        i += node_entries;
    }

    *out_count = next_count;
    return next_level;
}

/**
 * btree_builder_build_internal_levels
 * builds internal node levels from leaf level entries
 * @param builder the builder instance
 * @param root_offset output parameter for the root node offset
 * @return 0 on success, -1 on failure
 */
static int btree_builder_build_internal_levels(btree_builder_t *builder, int64_t *root_offset)
{
    if (builder->num_level_entries == 0)
    {
        builder->height = 1;
        *root_offset = -1;
        return 0;
    }

    if (builder->num_level_entries == 1)
    {
        builder->height = 1; /* a single leaf is the whole tree */
        *root_offset = builder->level_entries[0].child_offset;
        return 0;
    }

    btree_level_entry_t *current_level = builder->level_entries;
    uint32_t current_count = builder->num_level_entries;
    uint32_t internal_levels = 0;

    /* each pass of the loop builds one internal level above the one below it */
    while (current_count > 1)
    {
        uint32_t next_count = 0;
        btree_level_entry_t *next_level =
            btree_build_one_level(builder, current_level, current_count, &next_count);

        /* the leaf level is the builder's own array and outlives this call; every level above it
         * was built here and is freed as the build climbs past it */
        if (current_level != builder->level_entries) btree_free_level(current_level, current_count);
        if (!next_level) return -1;

        current_level = next_level;
        current_count = next_count;
        internal_levels++;
    }

    builder->height = 1 + internal_levels;
    *root_offset = current_level[0].child_offset;

    if (current_level != builder->level_entries) btree_free_level(current_level, current_count);
    return 0;
}

/**
 * btree_backpatch_one_leaf
 * write one uncompressed leaf's next-sibling offset in place and refresh the block checksum over it
 * @param builder the builder instance
 * @param leaf_offset the file offset of the leaf's block
 * @param next_leaf_offset the offset the leaf's next link should carry
 * @return 0 on success, -1 on a read or write failure
 */
static int btree_backpatch_one_leaf(btree_builder_t *builder, int64_t leaf_offset,
                                    int64_t next_leaf_offset)
{
    block_manager_cursor_t cursor;
    cursor.bm = builder->leaf_bm;
    cursor.current_pos = (uint64_t)leaf_offset;
    cursor.block_size_valid = 0;

    block_manager_block_t *block = block_manager_cursor_read(&cursor);
    if (!block) return -1;

    /* walk to the next_offset field -- type(1) + num_entries(varint) + prev_offset(8) */
    uint8_t *block_data = (uint8_t *)block->data;
    size_t off = BTREE_NODE_TYPE_BYTES;
    uint64_t num_entries;
    /* bounded like the read path, even though these are bytes this builder wrote moments ago. a
     * decode that cannot run off the end whatever it is handed is one less thing to have to reason
     * about, and the bound costs nothing here */
    const size_t adv =
        btree_varint_decode_bounded(block_data + off, block_data + block->size, &num_entries);
    if (adv == 0 || off + adv + BTREE_LEAF_LINK_BYTES > block->size)
    {
        block_manager_block_free(block);
        return -1;
    }
    off += adv;
    off += BTREE_LEAF_LINK_BYTES;

    /* patch the next-sibling offset little-endian, matching the serializer and the deserializer.
     * the same encoded bytes feed both the in-memory checksum recompute below and the disk write,
     * so the stored checksum covers exactly the bytes on disk. */
    uint8_t next_off_le[BTREE_LEAF_LINK_BYTES];
    encode_int64_le_compat(next_off_le, next_leaf_offset);
    memcpy(block_data + off, next_off_le, sizeof(next_off_le));

    uint8_t checksum_bytes[BLOCK_MANAGER_CHECKSUM_LENGTH];
    encode_uint32_le_compat(checksum_bytes, block_manager_checksum(block->data, block->size));

    int rc = block_manager_write_at(builder->leaf_bm, leaf_offset + BLOCK_MANAGER_SIZE_FIELD_SIZE,
                                    checksum_bytes, sizeof(checksum_bytes));
    if (rc == 0)
        rc = block_manager_write_at(builder->leaf_bm,
                                    leaf_offset + (int64_t)(BLOCK_MANAGER_BLOCK_HEADER_SIZE + off),
                                    next_off_le, sizeof(next_off_le));

    block_manager_block_free(block);
    return rc;
}

/**
 * btree_compress_one_leaf
 * compress one staged leaf and write it to the tree's own block manager, with both sibling links
 * left as placeholders for the patch pass. the links live in the block header rather than the
 * compressed payload so they can be patched later without decompressing
 * @param builder the builder instance
 * @param src_offset the staged leaf's offset in the leaf block manager
 * @param out_offset receives the offset the compressed leaf was written at
 * @return 0 on success, -1 on a read, compression, allocation, or write failure
 */
static int btree_compress_one_leaf(btree_builder_t *builder, int64_t src_offset,
                                   int64_t *out_offset)
{
    block_manager_cursor_t cursor;
    cursor.bm = builder->leaf_bm;
    cursor.current_pos = (uint64_t)src_offset;
    cursor.block_size_valid = 0;

    block_manager_block_t *block = block_manager_cursor_read(&cursor);
    if (!block) return -1;

    size_t compressed_size = 0;
    uint8_t *compressed = NULL;
    if (tidesdb_encoding_stages_encode(builder->config.codec, builder->config.codec_count,
                                       block->data, block->size, &compressed,
                                       &compressed_size) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "block encode failed, %d stages, %zu bytes",
                      builder->config.codec_count, block->size);
        compressed = NULL;
    }
    const uint32_t original_size = (uint32_t)block->size;
    block_manager_block_free(block);
    if (!compressed) return -1;

    const size_t total_size = BTREE_COMPRESSED_NODE_HEADER_SIZE + compressed_size;
    uint8_t *block_data = malloc(total_size);
    if (!block_data)
    {
        free(compressed);
        return -1;
    }
    encode_uint32_le_compat(block_data, original_size);
    encode_int64_le_compat(block_data + BTREE_COMPRESSED_NODE_PREV_OFF, BTREE_LEAF_LINK_NONE);
    encode_int64_le_compat(block_data + BTREE_COMPRESSED_NODE_NEXT_OFF, BTREE_LEAF_LINK_NONE);
    memcpy(block_data + BTREE_COMPRESSED_NODE_HEADER_SIZE, compressed, compressed_size);
    free(compressed);

    block_manager_block_t *new_block = block_manager_block_create(total_size, block_data);
    free(block_data);
    if (!new_block) return -1;

    const int64_t new_offset = block_manager_block_write(builder->bm, new_block);
    block_manager_block_free(new_block);
    if (new_offset < 0) return -1;

    *out_offset = new_offset;
    return 0;
}

/**
 * btree_patch_compressed_links
 * fill in both sibling links in every compressed leaf's header now that all of their offsets are
 * known, refreshing each block's checksum over the patched bytes. the links are read back
 * little-endian by the node reader, so they are patched little-endian rather than in host order
 * @param builder the builder instance
 * @param new_offsets the offset each leaf was written at, in leaf order
 * @return 0 on success, -1 on a write failure
 */
static int btree_patch_compressed_links(btree_builder_t *builder, const int64_t *new_offsets)
{
    for (uint32_t i = 0; i < builder->num_leaf_offsets; i++)
    {
        const int64_t prev_leaf = (i == 0) ? BTREE_LEAF_LINK_NONE : new_offsets[i - 1];
        const int64_t next_leaf =
            (i + 1 < builder->num_leaf_offsets) ? new_offsets[i + 1] : BTREE_LEAF_LINK_NONE;

        uint8_t link_le[BTREE_LEAF_LINK_BYTES];
        encode_int64_le_compat(link_le, prev_leaf);
        if (block_manager_write_at(
                builder->bm,
                new_offsets[i] + BLOCK_MANAGER_BLOCK_HEADER_SIZE + BTREE_COMPRESSED_NODE_PREV_OFF,
                link_le, sizeof(link_le)) != 0)
            return -1;

        encode_int64_le_compat(link_le, next_leaf);
        if (block_manager_write_at(
                builder->bm,
                new_offsets[i] + BLOCK_MANAGER_BLOCK_HEADER_SIZE + BTREE_COMPRESSED_NODE_NEXT_OFF,
                link_le, sizeof(link_le)) != 0)
            return -1;

        if (block_manager_update_checksum(builder->bm, new_offsets[i]) != 0) return -1;
    }
    return 0;
}

/**
 * btree_builder_compress_leaves
 * move every staged leaf into the tree's block manager compressed, then relink them at their new
 * locations and repoint the builder's leaf and level-entry offsets there
 * @param builder the builder instance
 * @return 0 on success, -1 on an allocation, compression, or write failure
 */
static int btree_builder_compress_leaves(btree_builder_t *builder)
{
    /* a tree with no leaves has nothing to move, and the tail of this function reads the first and
     * last entries of the offset array unconditionally -- so an empty builder would index a
     * zero-length allocation. the only caller returns early on zero leaves, which is why this has
     * never fired, but the safety of this function should not depend on reading its caller */
    if (builder->num_leaf_offsets == 0) return 0;

    int64_t *new_offsets = malloc(builder->num_leaf_offsets * sizeof(int64_t));
    if (!new_offsets) return -1;

    for (uint32_t i = 0; i < builder->num_leaf_offsets; i++)
    {
        if (btree_compress_one_leaf(builder, builder->leaf_offsets[i], &new_offsets[i]) != 0)
        {
            free(new_offsets);
            return -1;
        }
    }

    if (btree_patch_compressed_links(builder, new_offsets) != 0)
    {
        free(new_offsets);
        return -1;
    }

    for (uint32_t i = 0; i < builder->num_leaf_offsets; i++)
        builder->leaf_offsets[i] = new_offsets[i];
    for (uint32_t i = 0; i < builder->num_level_entries && i < builder->num_leaf_offsets; i++)
        builder->level_entries[i].child_offset = new_offsets[i];

    builder->first_leaf_offset = new_offsets[0];
    builder->last_leaf_offset = new_offsets[builder->num_leaf_offsets - 1];

    free(new_offsets);
    return 0;
}

static int btree_builder_backpatch_leaf_links(btree_builder_t *builder)
{
    if (!builder || builder->num_leaf_offsets == 0) return 0;

    /* the leaves are still uncompressed here, so each next link is patched in place; only a run of
     * two or more leaves has anything to link */
    for (uint32_t i = 0; i + 1 < builder->num_leaf_offsets; i++)
        if (btree_backpatch_one_leaf(builder, builder->leaf_offsets[i],
                                     builder->leaf_offsets[i + 1]) != 0)
            return -1;

    if (builder->config.codec_count > 0) return btree_builder_compress_leaves(builder);

    return 0;
}

int btree_builder_finish(btree_builder_t *builder, btree_t **tree)
{
    if (!builder || !tree) return -1;

    if (builder->current_leaf && builder->current_leaf->num_entries > 0)
    {
        if (btree_builder_flush_leaf(builder) != 0)
        {
            return -1;
        }
    }

    if (btree_builder_backpatch_leaf_links(builder) != 0)
    {
        return -1;
    }

    int64_t root_offset = -1;
    if (btree_builder_build_internal_levels(builder, &root_offset) != 0)
    {
        return -1;
    }

    btree_t *t = calloc(1, sizeof(btree_t));
    if (!t) return -1;

    t->bm = builder->bm;
    t->config = builder->config;
    t->root_offset = root_offset;
    t->first_leaf_offset = builder->first_leaf_offset;
    t->last_leaf_offset = builder->last_leaf_offset;
    t->entry_count = builder->entry_count;
    t->node_count = builder->node_count;
    t->max_seq = builder->max_seq;
    t->height = builder->height ? builder->height : 1;

    if (builder->min_key)
    {
        t->min_key = builder->min_key;
        t->min_key_size = builder->min_key_size;
        builder->min_key = NULL;
    }

    if (builder->max_key)
    {
        t->max_key = builder->max_key;
        t->max_key_size = builder->max_key_size;
        builder->max_key = NULL;
    }

    *tree = t;
    return 0;
}

void btree_builder_free(btree_builder_t *builder)
{
    if (!builder) return;

    /* drop the temp leaf-staging file (only created when compression is on) */
    if (builder->leaf_bm && builder->leaf_bm != builder->bm)
    {
        char tmp_path[MAX_FILE_PATH_LENGTH];
        snprintf(tmp_path, sizeof(tmp_path), "%s", builder->leaf_bm->file_path);
        (void)block_manager_close(builder->leaf_bm);
        remove(tmp_path);
    }

    btree_pending_leaf_free(builder->current_leaf);

    free(builder->leaf_offsets);

    if (builder->level_entries)
    {
        for (uint32_t i = 0; i < builder->num_level_entries; i++)
        {
            free(builder->level_entries[i].key);
        }
        free(builder->level_entries);
    }

    free(builder->min_key);
    free(builder->max_key);
    free(builder);
}
