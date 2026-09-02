/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/errors.h" /* TDB_SUCCESS from the encoding stage runners */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "base/log.h"
#include "sstable/btree/btree_internal.h"

/* every read in the two decoders below is bounds-checked against data_size -- on-disk node bytes
 * are untrusted, so a malformed or truncated node must be rejected rather than over-read. on a
 * violation the caller destroys the arena, so a failed read just returns -1. the macros need
 * data, data_size, off and end in scope, which both decoders provide. */
#define BT_NEED(want)                                                       \
    do                                                                      \
    {                                                                       \
        if (off > data_size || (size_t)(want) > data_size - off) return -1; \
    } while (0)
#define BT_VARINT(dst)                                                           \
    do                                                                           \
    {                                                                            \
        const size_t _vn = btree_varint_decode_bounded(data + off, end, &(dst)); \
        if (_vn == 0) return -1;                                                 \
        off += _vn;                                                              \
    } while (0)
#define BT_SVARINT(dst)                                                                 \
    do                                                                                  \
    {                                                                                   \
        const size_t _vn = btree_signed_varint_decode_bounded(data + off, end, &(dst)); \
        if (_vn == 0) return -1;                                                        \
        off += _vn;                                                                     \
    } while (0)

/**
 * btree_align_up
 * round a size up to the arena's alignment, so the arrays carved out of one allocation each start
 * on an aligned boundary
 * @param n the size to round
 * @return n rounded up to a multiple of BTREE_ARENA_ALIGNMENT
 */
static inline size_t btree_align_up(size_t n)
{
    return (n + (BTREE_ARENA_ALIGNMENT - 1)) & ~(size_t)(BTREE_ARENA_ALIGNMENT - 1);
}

/**
 * btree_leaf_scratch_t
 * the per-entry arrays a leaf decode fills while walking the node and drops when it is done; they
 * describe where each key's bytes are rather than holding them
 * @param key_offsets each key's suffix position, relative to the start of the keys section
 * @param prefix_lens how many leading bytes each key shares with the one before it
 * @param suffix_lens how many bytes each key stores for itself
 */
typedef struct
{
    uint16_t *key_offsets;
    size_t *prefix_lens;
    size_t *suffix_lens;
} btree_leaf_scratch_t;

/**
 * btree_leaf_alloc_arrays
 * carve the node's metadata arrays and the decode's scratch arrays out of the arena in two
 * allocations, rejecting an entry count the node is too small to hold before sizing anything by it
 * @param n the node being built, with num_entries already set
 * @param off the offset the indirection table starts at
 * @param data_size length of the encoded node
 * @param arena the arena every array is carved from
 * @param scratch receives the scratch arrays
 * @return 0 on success, -1 when the count is not credible or the arena is exhausted
 */
static int btree_leaf_alloc_arrays(btree_node_t *n, const size_t off, const size_t data_size,
                                   arena_t *arena, btree_leaf_scratch_t *scratch)
{
    const uint32_t ne = n->num_entries;

    /* the indirection table alone needs two bytes per entry -- reject an ne that can't fit before
     * allocating ne-sized arrays. the bound is compared by division rather than multiplying, so it
     * still holds where size_t is 32 bits and ne * 2 would wrap */
    if (off > data_size || (size_t)ne > (data_size - off) / BTREE_KEY_OFFSET_BYTES) return -1;

    /* the metadata arrays are all sized from ne, so reject a count whose combined allocation would
     * wrap size_t before any of it is computed */
    const size_t meta_per_entry =
        sizeof(btree_entry_t) + sizeof(uint8_t *) + sizeof(size_t) + sizeof(uint8_t *);
    if ((size_t)ne > SIZE_MAX / meta_per_entry) return -1;

    /* single arena alloc for all 4 metadata arrays */
    const size_t entries_sz = ne * sizeof(btree_entry_t);
    const size_t keys_ptr_sz = ne * sizeof(uint8_t *);
    const size_t key_sizes_sz = ne * sizeof(size_t);
    const size_t values_ptr_sz = ne * sizeof(uint8_t *);
    uint8_t *meta_buf =
        arena_alloc(arena, entries_sz + keys_ptr_sz + key_sizes_sz + values_ptr_sz, 0);
    if (!meta_buf) return -1;

    /* through void *, which is what says the alignment is established rather than assumed. the
     * arena hands back a maximally aligned block, and every offset below is a whole number of
     * pointers or size_ts into it, so each array starts where its type requires. casting straight
     * from uint8_t * is what a compiler cannot see that through */
    n->entries = (btree_entry_t *)(void *)meta_buf;
    n->keys = (uint8_t **)(void *)(meta_buf + entries_sz);
    n->key_sizes = (size_t *)(void *)(meta_buf + entries_sz + keys_ptr_sz);
    n->values = (uint8_t **)(void *)(meta_buf + entries_sz + keys_ptr_sz + key_sizes_sz);

    /* only values needs zeroing (sparse -- vlog entries have no inline value) */
    memset(n->values, 0, values_ptr_sz);

    /* single arena alloc for all 3 temp arrays, with the offsets array padded so the size_t arrays
     * after it start aligned */
    const size_t offsets_sz = btree_align_up(ne * sizeof(uint16_t));
    const size_t lens_sz = ne * sizeof(size_t);
    uint8_t *temp_buf = arena_alloc(arena, offsets_sz + lens_sz + lens_sz, 0);
    if (!temp_buf) return -1;

    scratch->key_offsets = (uint16_t *)(void *)temp_buf;
    scratch->prefix_lens = (size_t *)(void *)(temp_buf + offsets_sz);
    scratch->suffix_lens = (size_t *)(void *)(temp_buf + offsets_sz + lens_sz);
    return 0;
}

/**
 * btree_leaf_decode_entries
 * read the key indirection table and every entry's metadata, leaving the offset at the keys section
 * @param n the node being built, with its arrays allocated
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param offp the offset the table starts at, advanced past the metadata
 * @param scratch the scratch arrays, filled with each key's layout
 * @return 0 on success, -1 when the bytes do not decode
 */
static int btree_leaf_decode_entries(btree_node_t *n, const uint8_t *data, const size_t data_size,
                                     size_t *offp, const btree_leaf_scratch_t *scratch)
{
    const uint8_t *const end = data + data_size;
    const uint32_t ne = n->num_entries;
    size_t off = *offp;

    /* the indirection table is stored little-endian, bounded by the entry-count check already made
     */
    for (uint32_t i = 0; i < ne; i++)
    {
        scratch->key_offsets[i] = (uint16_t)(data[off] | (data[off + 1] << 8));
        off += BTREE_KEY_OFFSET_BYTES;
    }

    uint64_t base_seq;
    BT_VARINT(base_seq);

    for (uint32_t i = 0; i < ne; i++)
    {
        uint64_t prefix_len, suffix_len, value_size, vlog_offset;
        int64_t seq_delta, ttl;

        BT_VARINT(prefix_len);
        BT_VARINT(suffix_len);
        BT_VARINT(value_size);
        BT_VARINT(vlog_offset);
        BT_SVARINT(seq_delta);
        BT_SVARINT(ttl);
        BT_NEED(1); /* flags byte */

        /* both lengths must fit uint32, the width the entry records them in; a larger one is a
         * corrupt node, and truncating it into the field would decode the entry as a shorter value
         * that every later bound then agrees with. prefix can't exceed the previous key's length
         * either, since the prefix is copied from it during reconstruction */
        const uint64_t key_size = prefix_len + suffix_len;
        if (key_size > UINT32_MAX || value_size > UINT32_MAX) return -1;
        if (i == 0 ? (prefix_len != 0) : (prefix_len > n->entries[i - 1].key_size)) return -1;

        scratch->prefix_lens[i] = (size_t)prefix_len;
        scratch->suffix_lens[i] = (size_t)suffix_len;
        n->entries[i].key_size = (uint32_t)key_size;
        n->entries[i].value_size = (uint32_t)value_size;
        n->entries[i].vlog_offset = vlog_offset;
        n->entries[i].seq = base_seq + (uint64_t)seq_delta;
        n->entries[i].ttl = ttl;
        n->entries[i].flags = data[off++];
        n->key_sizes[i] = n->entries[i].key_size;
    }

    *offp = off;
    return 0;
}

/**
 * btree_leaf_rebuild_keys
 * rebuild every key from its shared prefix and its stored suffix, leaving the offset past the keys
 * section
 * @param n the node being built, with its entry metadata decoded
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param offp the offset the keys section starts at, advanced past it
 * @param arena the arena the key bytes are carved from
 * @param scratch the decoded key layout
 * @return 0 on success, -1 when the keys section does not fit the node
 */
static int btree_leaf_rebuild_keys(btree_node_t *n, const uint8_t *data, const size_t data_size,
                                   size_t *offp, arena_t *arena,
                                   const btree_leaf_scratch_t *scratch)
{
    const uint32_t ne = n->num_entries;
    size_t off = *offp;

    /* the suffixes are stored verbatim in the keys section that follows, so their total has to fit
     * what is left of the buffer. this also bounds every reconstructed key size, since a key is its
     * prefix (taken from the key before it) plus its own suffix -- without it a single corrupt
     * suffix length sizes the allocation below in the gigabytes, which the per-key bounds check
     * would only reject after the memory was asked for */
    size_t total_suffix_bytes = 0;
    for (uint32_t i = 0; i < ne; i++)
    {
        total_suffix_bytes += scratch->suffix_lens[i];
        if (off > data_size || total_suffix_bytes > data_size - off) return -1;
    }

    /* single arena alloc for all key data, then carve up with pointers. prefix compression lets a
     * reconstructed key exceed the bytes it was stored in, so this total is larger than the keys
     * section; the overflow check keeps a corrupt node from wrapping it into an undersized buffer
     */
    size_t total_key_bytes = 0;
    for (uint32_t i = 0; i < ne; i++)
    {
        const size_t padded = btree_align_up(n->entries[i].key_size);
        if (total_key_bytes > SIZE_MAX - padded) return -1;
        total_key_bytes += padded;
    }

    uint8_t *key_buf = arena_alloc(arena, total_key_bytes, 0);
    if (!key_buf) return -1;

    const size_t keys_start = off;
    size_t key_buf_off = 0;
    for (uint32_t i = 0; i < ne; i++)
    {
        n->keys[i] = key_buf + key_buf_off;

        /* copy prefix from previous key (prefix_len validated <= prev key_size) */
        if (i > 0 && scratch->prefix_lens[i] > 0)
            memcpy(n->keys[i], n->keys[i - 1], scratch->prefix_lens[i]);

        /* copy suffix from serialized data -- the suffix region must lie entirely within the node
         */
        const size_t suffix_pos = keys_start + scratch->key_offsets[i];
        if (suffix_pos > data_size || scratch->suffix_lens[i] > data_size - suffix_pos) return -1;
        memcpy(n->keys[i] + scratch->prefix_lens[i], data + suffix_pos, scratch->suffix_lens[i]);

        key_buf_off += btree_align_up(n->entries[i].key_size);
        off += scratch->suffix_lens[i];
    }

    if (off > data_size) return -1; /* keys section overran the node */
    *offp = off;
    return 0;
}

/**
 * btree_leaf_decode_values
 * copy the inline values into the arena and point each entry that has one at its bytes; an entry
 * whose value lives in the value log has none here
 * @param n the node being built, with its keys rebuilt
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param offp the offset the values section starts at, advanced past it
 * @param arena the arena the value bytes are carved from
 * @return 0 on success, -1 when the values section does not fit the node
 */
static int btree_leaf_decode_values(btree_node_t *n, const uint8_t *data, const size_t data_size,
                                    size_t *offp, arena_t *arena)
{
    const uint32_t ne = n->num_entries;
    size_t off = *offp;

    size_t total_inline_bytes = 0;
    for (uint32_t i = 0; i < ne; i++)
    {
        if (n->entries[i].vlog_offset == 0 && n->entries[i].value_size > 0)
        {
            total_inline_bytes += n->entries[i].value_size;
            if (total_inline_bytes > data_size) return -1; /* cap + overflow guard */
        }
    }

    if (total_inline_bytes > 0)
    {
        BT_NEED(total_inline_bytes);
        uint8_t *val_buf = arena_alloc(arena, total_inline_bytes, 0);
        if (!val_buf) return -1;
        memcpy(val_buf, data + off, total_inline_bytes);

        size_t val_off = 0;
        for (uint32_t i = 0; i < ne; i++)
        {
            if (n->entries[i].vlog_offset == 0 && n->entries[i].value_size > 0)
            {
                n->values[i] = val_buf + val_off;
                val_off += n->entries[i].value_size;
            }
        }
    }

    *offp = off + total_inline_bytes;
    return 0;
}

/**
 * btree_decode_leaf
 * decode a leaf node body into the arena, picking up after the type and entry count
 * @param n the node being built, with type and num_entries already set
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param off the offset just past the entry count
 * @param arena the arena every array is carved from
 * @return 0 on success, -1 when the bytes do not decode
 */
static int btree_decode_leaf(btree_node_t *n, const uint8_t *data, const size_t data_size,
                             size_t off, arena_t *arena)
{
    BT_NEED(BTREE_LEAF_LINK_BYTES * 2);
    n->prev_offset = decode_int64_le_compat(data + off);
    off += BTREE_LEAF_LINK_BYTES;
    n->next_offset = decode_int64_le_compat(data + off);
    off += BTREE_LEAF_LINK_BYTES;

    if (n->num_entries == 0) return 0;

    btree_leaf_scratch_t scratch;
    if (btree_leaf_alloc_arrays(n, off, data_size, arena, &scratch) != 0) return -1;
    if (btree_leaf_decode_entries(n, data, data_size, &off, &scratch) != 0) return -1;
    if (btree_leaf_rebuild_keys(n, data, data_size, &off, arena, &scratch) != 0) return -1;
    return btree_leaf_decode_values(n, data, data_size, &off, arena);
}

/**
 * btree_decode_internal
 * decode an internal node body into the arena, picking up after the type and key count
 * @param n the node being built, with type and num_entries already set
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param off the offset just past the key count
 * @param arena the arena every array is carved from
 * @return 0 on success, -1 when the bytes do not decode
 */
static int btree_decode_internal(btree_node_t *n, const uint8_t *data, const size_t data_size,
                                 size_t off, arena_t *arena)
{
    const uint8_t *const end = data + data_size;
    const uint32_t num_keys = n->num_entries;

    /* each child contributes at least a one-byte delta varint and each separator at least a
     * one-byte size varint, so a count that exceeds the bytes left is corrupt. rejecting it
     * here also keeps num_children below from wrapping to zero, which would leave a
     * zero-length child array that the descent would still index */
    if (off > data_size || (size_t)num_keys >= data_size - off) return -1;

    const uint32_t num_children = num_keys + 1;

    /* the arrays below are sized from num_children, so reject a count whose combined
     * allocation would wrap size_t before any of it is computed */
    const size_t internal_per_entry = sizeof(int64_t) + sizeof(uint8_t *) + sizeof(size_t);
    if ((size_t)num_children > SIZE_MAX / internal_per_entry) return -1;

    /* single arena alloc for child_offsets + keys ptrs + key_sizes */
    const size_t child_sz = num_children * sizeof(int64_t);
    const size_t ikeys_ptr_sz = num_keys * sizeof(uint8_t *);
    const size_t ikey_sizes_sz = num_keys * sizeof(size_t);
    const size_t internal_total = child_sz + ikeys_ptr_sz + ikey_sizes_sz;
    uint8_t *ibuf = arena_alloc(arena, internal_total, 0);
    if (!ibuf) return -1;

    n->child_offsets = (int64_t *)(void *)ibuf;
    n->keys = (num_keys > 0) ? (uint8_t **)(void *)(ibuf + child_sz) : NULL;
    n->key_sizes = (num_keys > 0) ? (size_t *)(void *)(ibuf + child_sz + ikeys_ptr_sz) : NULL;

    BT_NEED(8);
    int64_t base_offset = decode_int64_le_compat(data + off);
    off += 8;

    /* decode delta-encoded child offsets */
    int64_t prev_offset = base_offset;
    for (uint32_t i = 0; i < num_children; i++)
    {
        int64_t delta;
        BT_SVARINT(delta);
        /* corrupt deltas can carry this sum past the range of a signed 64-bit integer, where
         * the overflow would be undefined rather than merely wrong. accumulate through unsigned
         * so the wrap is defined; an offset that ends up nonsensical fails when the child is
         * read, which is the transient path the descent already handles */
        const int64_t child = (int64_t)((uint64_t)prev_offset + (uint64_t)delta);
        n->child_offsets[i] = child;
        prev_offset = child;
    }

    /* read key sizes (varint) */
    for (uint32_t i = 0; i < num_keys; i++)
    {
        uint64_t key_size;
        BT_VARINT(key_size);
        if (key_size > UINT32_MAX) return -1;
        n->key_sizes[i] = (size_t)key_size;
    }

    /* single arena alloc for all separator key data */
    size_t total_ikey_bytes = 0;
    size_t raw_ikey_bytes = 0;
    for (uint32_t i = 0; i < num_keys; i++)
    {
        const size_t padded = (n->key_sizes[i] + 7) & ~(size_t)7;
        if (total_ikey_bytes > SIZE_MAX - padded) return -1;
        total_ikey_bytes += padded;
        if (raw_ikey_bytes > SIZE_MAX - n->key_sizes[i]) return -1;
        raw_ikey_bytes += n->key_sizes[i];
    }

    /* separator keys are stored verbatim, so every one of those bytes has to be present in what
     * is left of the buffer. without this a corrupt size drives an arena allocation orders of
     * magnitude larger than the node could hold, which the per-key bounds check below would
     * only catch after the memory was already asked for */
    if (off > data_size || raw_ikey_bytes > data_size - off) return -1;

    if (total_ikey_bytes > 0)
    {
        uint8_t *ikey_buf = arena_alloc(arena, total_ikey_bytes, 0);
        if (!ikey_buf) return -1;

        size_t ikey_off = 0;
        for (uint32_t i = 0; i < num_keys; i++)
        {
            n->keys[i] = ikey_buf + ikey_off;
            BT_NEED(n->key_sizes[i]);
            memcpy(n->keys[i], data + off, n->key_sizes[i]);
            off += n->key_sizes[i];
            ikey_off += (n->key_sizes[i] + 7) & ~(size_t)7;
        }
    }
    return 0;
}

#undef BT_NEED
#undef BT_VARINT
#undef BT_SVARINT

/**
 * btree_node_deserialize_arena
 * deserializes a node from optimized format using arena allocation
 * all memory is allocated from the arena for O(1) bulk deallocation
 * @param data node bytes
 * @param data_size node size
 * @param node output parameter for deserialized node
 * @param arena arena allocator to use
 * @return 0 on success, -1 on failure
 */
static int btree_node_deserialize_arena(const uint8_t *data, const size_t data_size,
                                        btree_node_t **node, arena_t *arena)
{
    if (!data || data_size < 2 || !node || !arena) return -1;

    btree_node_t *n = arena_alloc(arena, sizeof(btree_node_t), 0);
    if (!n) return -1;
    memset(n, 0, sizeof(btree_node_t));
    n->arena = arena;

    size_t off = 0;
    n->type = data[off++]; /* data_size >= 2 guarantees this byte */

    /* only these two kinds have a decode. any other value would leave the entry count set from
     * the input while the key, value and child arrays stayed null, and a reader binary-searches
     * those arrays against that count, so a node like that reads as valid and dereferences null */
    if (n->type != BTREE_NODE_LEAF && n->type != BTREE_NODE_INTERNAL) return -1;

    uint64_t entry_count;
    const size_t vn = btree_varint_decode_bounded(data + off, data + data_size, &entry_count);
    if (vn == 0) return -1;
    off += vn;
    if (entry_count > UINT32_MAX) return -1;
    n->num_entries = (uint32_t)entry_count;

    const int rc = n->type == BTREE_NODE_LEAF
                       ? btree_decode_leaf(n, data, data_size, off, arena)
                       : btree_decode_internal(n, data, data_size, off, arena);
    if (rc != 0) return rc;

    *node = n;
    return 0;
}

#ifdef TDB_TEST_INTERNALS
int btree_node_deserialize_direct(const uint8_t *data, size_t data_size, btree_node_t **node,
                                  arena_t *arena)
{
    return btree_node_deserialize_arena(data, data_size, node, arena);
}
#endif

void btree_node_free(btree_node_t *node)
{
    if (!node) return;

    /* for arena-allocated nodes destroy the arena for O(1) bulk deallocation
     * for uncached nodes only -- a cached node is released through btree_node_done, which drops the
     * cache pin and leaves the free to the cache's own reclaim */
    if (node->arena)
    {
        arena_destroy(node->arena);
        return;
    }

    if (node->keys)
    {
        for (uint32_t i = 0; i < node->num_entries; i++)
        {
            free(node->keys[i]);
        }
        free(node->keys);
    }

    if (node->values)
    {
        for (uint32_t i = 0; i < node->num_entries; i++)
        {
            free(node->values[i]);
        }
        free(node->values);
    }

    free(node->entries);
    free(node->key_sizes);
    free(node->child_offsets);
    free(node);
}

/**
 * btree_node_cache_reclaim
 * the cache's per-entry reclaim for a cached node; frees the node and its arena once the last
 * reference to it drops, on whichever thread drops it
 * @param payload the cached node
 * @param ctx unused
 */
static void btree_node_cache_reclaim(void *payload, void *ctx)
{
    (void)ctx;
    btree_node_free((btree_node_t *)payload);
}

/**
 * btree_node_decode_block
 * run a stored node's bytes back through the encoding chain that wrote them, restoring the leaf
 * links the encoder lifted out into the plaintext header
 * @param block_data the block as it sits on disk, laid out
 *                   [original_size:4][prev_offset:8][next_offset:8][encoded]
 * @param block_size the block's length in bytes
 * @param codec the encoding chain the node was written with
 * @param codec_count how many stages codec holds
 * @param offset the node's file offset, for the log lines
 * @param out receives the freshly allocated plaintext, the caller's to free
 * @param out_size receives the plaintext length
 * @return 0 on success, -1 when the chain failed or produced a length the header disagrees with
 */
static int btree_node_decode_block(const uint8_t *block_data, const uint32_t block_size,
                                   const tidesdb_encoding_stage_t *codec, const int codec_count,
                                   const int64_t offset, uint8_t **out, size_t *out_size)
{
    const uint32_t original_size = decode_uint32_le_compat(block_data);
    const int64_t header_prev_offset =
        decode_int64_le_compat(block_data + BTREE_COMPRESSED_NODE_PREV_OFF);
    const int64_t header_next_offset =
        decode_int64_le_compat(block_data + BTREE_COMPRESSED_NODE_NEXT_OFF);
    const uint8_t *encoded = block_data + BTREE_COMPRESSED_NODE_HEADER_SIZE;
    const size_t encoded_size = block_size - BTREE_COMPRESSED_NODE_HEADER_SIZE;

    uint8_t *plain = NULL;
    size_t plain_size = 0;
    if (tidesdb_encoding_stages_decode(codec, codec_count, encoded, encoded_size, &plain,
                                       &plain_size) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "node decode failed at offset %lld, %d stages, %zu bytes",
                      (long long)offset, codec_count, encoded_size);
        return -1;
    }
    if (plain_size != original_size)
    {
        /* a chain that decodes but yields the wrong length means the bytes came out of a
         * different pipeline than the one recorded, not that the stored bytes are damaged */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "node decode length mismatch at offset %lld, got %zu want %u",
                      (long long)offset, plain_size, original_size);
        free(plain);
        return -1;
    }

    /* only leaves carry sibling links, and the encoder kept them in the plaintext header so a
     * rewrite can repoint them without re-encoding. bound the varint and the 16-byte patch against
     * the buffer -- its size comes from the on-disk header, so a corrupt node could otherwise drive
     * an out-of-range write. a node that does not fit is left unpatched; the bounded deserializer
     * rejects it */
    if (plain_size >= 1 && plain[0] == BTREE_NODE_LEAF)
    {
        size_t pos = 1;
        uint64_t num_entries;
        const size_t adv =
            btree_varint_decode_bounded(plain + pos, plain + plain_size, &num_entries);
        if (adv > 0 && pos + adv + BTREE_LEAF_LINK_PATCH_BYTES <= plain_size)
        {
            pos += adv;
            encode_int64_le_compat(plain + pos, header_prev_offset);
            encode_int64_le_compat(plain + pos + BTREE_LEAF_LINK_BYTES, header_next_offset);
        }
    }

    *out = plain;
    *out_size = plain_size;
    return 0;
}

int btree_node_read_with_codec(block_manager_t *bm, const int64_t offset, btree_node_t **node,
                               const tidesdb_encoding_stage_t *codec, const int codec_count,
                               arena_pool_t *pool, const uint32_t node_size_hint)
{
    if (!bm || offset < 0 || !node) return -1;

    /* borrow the verified block rather than take an owned copy -- deserialization copies what it
     * keeps into the node's arena, so nothing here outlives the read. the hint asks for the whole
     * node in the first pread, since a node built to a target size a little over the block
     * manager's default guess would otherwise cost a second syscall on every descent */
    uint32_t block_size = 0;
    const uint8_t *block_data_ptr = block_manager_borrow_block_data_at_offset(
        bm, (uint64_t)offset, node_size_hint, &block_size);
    if (!block_data_ptr) return -1;

    const uint8_t *data = block_data_ptr;
    size_t data_size = block_size;
    uint8_t *decompressed = NULL;

    if (codec_count > 0 && block_size > BTREE_COMPRESSED_NODE_HEADER_SIZE)
    {
        if (btree_node_decode_block(block_data_ptr, block_size, codec, codec_count, offset,
                                    &decompressed, &data_size) != 0)
            return -1;
        data = decompressed;
    }

    /* one arena per node rather than the N+7 separate allocations the deserialized form would
     * otherwise take, so btree_node_free releases the whole node by destroying it */
    arena_t *arena = arena_create(pool);
    if (!arena)
    {
        free(decompressed);
        return -1;
    }

    const int result = btree_node_deserialize_arena(data, data_size, node, arena);
    if (result == 0)
    {
        (*node)->block_offset = offset;
    }
    else
    {
        arena_destroy(arena);
    }

    free(decompressed);
    return result;
}

/**
 * btree_node_read_cached
 * read a node, going through the node cache when the tree has one; the cache stores the
 * deserialized node keyed by (cache_key_prefix, offset), a hit returns the pinned node and a miss
 * reads, parses, and inserts it. the returned pin must be passed to btree_node_done, which releases
 * the cache reference; a direct read (no cache) returns a NULL pin and btree_node_done frees the
 * node
 * @param tree btree instance
 * @param offset node offset in the file
 * @param node out -- the node on success
 * @param pin out -- the cache pin on a cache hit, or NULL on a direct read
 * @return 0 on success, -1 on failure
 */
int btree_node_read_cached(btree_t *tree, const int64_t offset, btree_node_t **node,
                           cache_entry_t **pin)
{
    if (!tree || !tree->bm || offset < 0 || !node || !pin) return -1;
    *pin = NULL;

    if (!tree->node_cache)
        return btree_node_read_with_codec(tree->bm, offset, node, tree->config.codec,
                                          tree->config.codec_count, tree->config.arena_pool,
                                          (uint32_t)tree->config.target_node_size);

    void *payload = NULL;
    if (cache_get(tree->node_cache, tree->cache_key_prefix, (uint64_t)offset, &payload, NULL, pin))
    {
        *node = (btree_node_t *)payload;
        return 0;
    }

    /* miss -- read and parse the node, then insert it. cache_put takes ownership of the node, or on
     * a concurrent duplicate insert or a full cache reclaims it, so re-get to pin whichever copy
     * won */
    btree_node_t *fresh = NULL;
    if (btree_node_read_with_codec(tree->bm, offset, &fresh, tree->config.codec,
                                   tree->config.codec_count, tree->config.arena_pool,
                                   (uint32_t)tree->config.target_node_size) != 0)
        return -1;

    /* what the arena reserved, not what the node used. the node's chunk is rounded up to the
     * pool's chunk size and stays held for as long as the cache keeps the node, so charging the
     * used figure lets the cache hold several times the budget it was given */
    const size_t cost =
        sizeof(btree_node_t) + (fresh->arena ? arena_bytes_reserved(fresh->arena) : 0);
    (void)cache_put(tree->node_cache, tree->cache_key_prefix, (uint64_t)offset, fresh, 0, cost,
                    btree_node_cache_reclaim, NULL, NULL);

    if (cache_get(tree->node_cache, tree->cache_key_prefix, (uint64_t)offset, &payload, NULL, pin))
    {
        *node = (btree_node_t *)payload;
        return 0;
    }

    /* the just-inserted node was evicted before this get, rare; fall back to a direct owned read */
    return btree_node_read_with_codec(tree->bm, offset, node, tree->config.codec,
                                      tree->config.codec_count, tree->config.arena_pool,
                                      (uint32_t)tree->config.target_node_size);
}

int btree_descend_to_leaf(btree_t *tree, const uint8_t *key, const size_t key_size,
                          btree_node_t **out_node, cache_entry_t **out_pin)
{
    cache_entry_t *pin = NULL;
    btree_node_t *node = tree->borrowed_root;

    /* the borrowed root carries no pin of this tree's, so it must not be released on the way down.
     * only an internal node is ever borrowed, so the loop below always moves off it before the leaf
     * is handed back and the caller's release covers only what this descent pinned */
    int borrowed = node != NULL;
    if (!borrowed && btree_node_read_cached(tree, tree->root_offset, &node, &pin) != 0) return -1;

    while (node->type == BTREE_NODE_INTERNAL)
    {
        /* binary search for the child index -- find the largest i where key >= keys[i], then
         * child_idx = i + 1 (child_idx = 0 when key < keys[0]). separator keys are strictly
         * increasing and the builder never splits a key's run across leaves, so a key's whole run
         * lives in the one child this routes to. */
        uint32_t child_idx = 0;
        if (node->num_entries > 0)
        {
            int32_t lo = 0;
            int32_t hi = (int32_t)node->num_entries - 1;
            while (lo <= hi)
            {
                const int32_t mid = lo + (hi - lo) / 2;
                const int cmp = tdb_key_cmp(key, key_size, node->keys[mid], node->key_sizes[mid]);
                if (cmp < 0)
                {
                    hi = mid - 1;
                }
                else
                {
                    lo = mid + 1;
                }
            }
            child_idx = (uint32_t)lo;
        }

        const int64_t child_offset = node->child_offsets[child_idx];
        if (!borrowed) btree_node_done(node, pin);
        borrowed = 0;

        if (btree_node_read_cached(tree, child_offset, &node, &pin) != 0) return -1;
    }

    *out_node = node;
    *out_pin = pin;
    return 0;
}
