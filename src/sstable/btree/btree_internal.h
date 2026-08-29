/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BTREE_INTERNAL_H__
#define __BTREE_INTERNAL_H__

#include <inttypes.h>

#include "base/encoding/compress.h"
#include "base/encoding/serialization.h" /* TDB_SSTABLE_KLOG_STAGE_EXT */
#include "sstable/btree/btree.h"
#include "xxhash.h"

#define BTREE_ARENA_ALIGNMENT 8

/* initial entry capacity of a pending leaf during btree construction; the array doubles
 * on overflow so this only sets the smallest meaningful allocation */
#define BTREE_PENDING_LEAF_INITIAL_CAP 64

/* small malloc safety pads added on top of the precomputed est_size in the leaf and
 * internal-node serializers, to absorb any conservative undercount without realloc */
#define BTREE_LEAF_SERIALIZE_SAFETY_PAD     64
#define BTREE_INTERNAL_SERIALIZE_SAFETY_PAD 32

/* fixed-size empty-leaf encoding -- type byte, num_entries=0 varint, prev/next int64 */
#define BTREE_LEAF_EMPTY_BUF_SIZE 32

/* suffix for the temp file uncompressed leaves are staged into before compression */
#define BTREE_LEAF_STAGE_SUFFIX TDB_SSTABLE_KLOG_STAGE_EXT

/* a leaf's sibling links are int64 file offsets, and BTREE_LEAF_LINK_NONE means there is no sibling
 */
#define BTREE_LEAF_LINK_BYTES 8
#define BTREE_LEAF_LINK_NONE  (-1)

/* the two links are rewritten as a pair, so a patch site needs room for both */
#define BTREE_LEAF_LINK_PATCH_BYTES (2 * BTREE_LEAF_LINK_BYTES)

/* the sign-bit shift a zigzag encoding folds a 64-bit signed value with */
#define BTREE_ZIGZAG_SIGN_SHIFT 63

/* the per-entry flags byte in a serialized leaf */
#define BTREE_ENTRY_FLAGS_BYTES 1

/* the node type tag leading a serialized node, and the width of one key indirection table slot */
#define BTREE_NODE_TYPE_BYTES  1
#define BTREE_KEY_OFFSET_BYTES 2

/* the encoded-node block layout written by btree_write_internal_node and btree_compress_one_leaf,
 * repointed by btree_patch_compressed_links, and read back by btree_node_read_with_codec, as
 * [original_size:u32][prev_offset:i64][next_offset:i64][encoded_data]. the sibling links stay in
 * plaintext ahead of the encoded body so a rewrite can repoint a leaf without decoding it. the
 * offsets are derived from the field widths rather than written out, so widening a field moves
 * every one of them together */
#define BTREE_COMPRESSED_NODE_ORIGINAL_SIZE_BYTES 4
#define BTREE_COMPRESSED_NODE_PREV_OFF            BTREE_COMPRESSED_NODE_ORIGINAL_SIZE_BYTES
#define BTREE_COMPRESSED_NODE_NEXT_OFF            (BTREE_COMPRESSED_NODE_PREV_OFF + BTREE_LEAF_LINK_BYTES)
#define BTREE_COMPRESSED_NODE_HEADER_SIZE         (BTREE_COMPRESSED_NODE_NEXT_OFF + BTREE_LEAF_LINK_BYTES)

/**
 * varint encoding utilities
 * uses LEB128-style encoding -- 7 bits per byte, high bit = continuation
 */

/**
 * btree_varint_size
 * returns the size of a varint encoding for a given value
 * @param val the value to encode
 * @return the size of the varint encoding
 */
static inline size_t btree_varint_size(const uint64_t val)
{
    if (val < (1ULL << 7)) return 1;
    if (val < (1ULL << 14)) return 2;
    if (val < (1ULL << 21)) return 3;
    if (val < (1ULL << 28)) return 4;
    if (val < (1ULL << 35)) return 5;
    if (val < (1ULL << 42)) return 6;
    if (val < (1ULL << 49)) return 7;
    if (val < (1ULL << 56)) return 8;
    if (val < (1ULL << 63)) return 9;
    return 10;
}

/**
 * btree_varint_encode
 * encodes a varint value into a buffer
 * @param buf the buffer to encode into
 * @param val the value to encode
 * @return the number of bytes encoded
 */
static inline size_t btree_varint_encode(uint8_t *buf, uint64_t val)
{
    size_t i = 0;
    while (val >= 0x80)
    {
        buf[i++] = (uint8_t)(val | 0x80);
        val >>= 7;
    }
    buf[i++] = (uint8_t)val;
    return i;
}

/**
 * btree_varint_decode
 * decodes a varint value from a buffer
 * @param buf the buffer to decode from
 * @param val the value to decode
 * @return the number of bytes decoded
 */
static inline size_t btree_varint_decode(const uint8_t *buf, uint64_t *val)
{
    uint64_t result = 0;
    size_t shift = 0;
    /* a 64-bit varint is at most 10 bytes -- stop after the terminating byte or 10 bytes, never
     * reading an 11th (the old form broke at i==10 then still read buf[10]) */
    for (size_t i = 0; i < 10; i++)
    {
        const uint8_t b = buf[i];
        result |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80))
        {
            *val = result;
            return i + 1;
        }
        shift += 7;
    }
    *val = result;
    return 10;
}

/**
 * btree_signed_varint_encode
 * encodes a signed integer using zigzag encoding then varint
 * @param buf the buffer to encode into
 * @param val the signed value to encode
 * @return the number of bytes encoded
 */
static inline size_t btree_signed_varint_encode(uint8_t *buf, const int64_t val)
{
    const uint64_t uval = ((uint64_t)val << 1) ^ (uint64_t)(val >> 63);
    return btree_varint_encode(buf, uval);
}

/* bounded LEB128 decode for parsing on-disk (untrusted) node bytes -- a thin adapter over the
 * canonical decoder in compat.h that keeps this module's bytes-consumed convention. returns bytes
 * consumed, or 0 on truncation / overlong encoding so the caller can reject a malformed node. */
static inline size_t btree_varint_decode_bounded(const uint8_t *buf, const uint8_t *end,
                                                 uint64_t *val)
{
    const uint8_t *next = decode_varint64_safe(buf, end, val);
    return next ? (size_t)(next - buf) : 0;
}

static inline size_t btree_signed_varint_decode_bounded(const uint8_t *buf, const uint8_t *end,
                                                        int64_t *val)
{
    uint64_t uval;
    const size_t n = btree_varint_decode_bounded(buf, end, &uval);
    if (n == 0) return 0;
    *val = (int64_t)((uval >> 1) ^ (~(uval & 1) + 1));
    return n;
}

/**
 * btree_compute_prefix_len
 * computes the common prefix length between two keys
 * @param key1 first key data
 * @param len1 length of first key
 * @param key2 second key data
 * @param len2 length of second key
 * @return the number of common prefix bytes
 */
static inline size_t btree_compute_prefix_len(const uint8_t *key1, const size_t len1,
                                              const uint8_t *key2, const size_t len2)
{
    const size_t min_len = (len1 < len2) ? len1 : len2;
    size_t prefix_len = 0;
    while (prefix_len < min_len && key1[prefix_len] == key2[prefix_len])
    {
        prefix_len++;
    }
    return prefix_len;
}

/**
 * btree_key_cmp
 * total byte-wise order over keys -- the shared prefix decides, otherwise the shorter key sorts
 * first
 * @param key1 first key
 * @param key1_size size of the first key in bytes
 * @param key2 second key
 * @param key2_size size of the second key in bytes
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static inline int btree_key_cmp(const uint8_t *key1, const size_t key1_size, const uint8_t *key2,
                                const size_t key2_size)
{
    const size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    const int c = min_size > 0 ? memcmp(key1, key2, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

/**
 * btree_pending_leaf_t
 * a leaf node being built during tree construction
 * @entries array of entry metadata
 * @keys array of key pointers
 * @values array of value pointers
 * @num_entries current number of entries
 * @capacity maximum capacity of arrays
 * @current_size current serialized size estimate
 * @first_key first key in this leaf (for separator)
 * @first_key_size size of first key
 * @last_key last key in this leaf
 * @last_key_size size of last key
 */
typedef struct btree_pending_leaf_t
{
    btree_entry_t *entries;
    uint8_t **keys;
    uint8_t **values;
    uint32_t num_entries;
    uint32_t capacity;
    size_t current_size;
    uint8_t *first_key;
    size_t first_key_size;
    uint8_t *last_key;
    size_t last_key_size;
} btree_pending_leaf_t;

/**
 * btree_level_entry_t
 * entry for building internal nodes (separator key + child offset)
 * @key separator key data
 * @key_size size of separator key
 * @child_offset offset of child node in storage
 */
typedef struct btree_level_entry_t
{
    uint8_t *key;
    size_t key_size;
    int64_t child_offset;
} btree_level_entry_t;

/**
 * btree_builder_t
 * builder state for constructing B+tree from sorted data
 * @bm block manager for storage
 * @leaf_bm where uncompressed leaves stage -- a temp file when compression is on, so the real klog
 * never keeps the discarded pre-compression copies
 * @config btree configuration
 * @current_leaf leaf node currently being built
 * @first_leaf_offset offset of first leaf in tree
 * @last_leaf_offset offset of last leaf in tree
 * @prev_leaf_offset offset of previously written leaf
 * @leaf_offsets array of all leaf offsets for backpatching
 * @num_leaf_offsets number of leaf offsets
 * @leaf_offsets_capacity capacity of leaf_offsets array
 * @level_entries entries for building internal nodes
 * @num_level_entries number of level entries
 * @level_entries_capacity capacity of level_entries array
 * @entry_count total number of entries added
 * @node_count total number of nodes written
 * @max_seq maximum sequence number seen
 * @height levels the finished tree has, counted as the internal levels are built
 * @min_key minimum key in tree
 * @min_key_size size of minimum key
 * @max_key maximum key in tree
 * @max_key_size size of maximum key
 */
struct btree_builder_t
{
    block_manager_t *bm;
    block_manager_t *leaf_bm;
    btree_config_t config;

    btree_pending_leaf_t *current_leaf;
    int64_t first_leaf_offset;
    int64_t last_leaf_offset;
    int64_t prev_leaf_offset;

    int64_t *leaf_offsets;
    uint32_t num_leaf_offsets;
    uint32_t leaf_offsets_capacity;

    btree_level_entry_t *level_entries;
    uint32_t num_level_entries;
    uint32_t level_entries_capacity;

    uint64_t entry_count;
    uint64_t node_count;
    uint64_t max_seq;
    uint32_t height;

    uint8_t *min_key;
    size_t min_key_size;
    uint8_t *max_key;
    size_t max_key_size;
};

/**
 * btree_node_done
 * finish with a node from btree_node_read_cached; release the cache pin on a cache hit, or free the
 * node on a direct read
 * @param node the node, may be NULL
 * @param pin the cache pin, or NULL when the node came from a direct read
 */
static inline void btree_node_done(btree_node_t *node, cache_entry_t *pin)
{
    if (pin)
        cache_release(pin);
    else if (node)
        btree_node_free(node);
}

/* helpers shared across the btree translation units; not part of the public api */
int btree_leaf_serialize(const btree_pending_leaf_t *leaf, const int64_t prev_offset,
                         const int64_t next_offset, uint8_t **out, size_t *out_size);
int btree_internal_serialize(const btree_level_entry_t *entries, const uint32_t num_entries,
                             uint8_t **out, size_t *out_size);
int btree_descend_to_leaf(btree_t *tree, const uint8_t *key, const size_t key_size,
                          btree_node_t **out_node, cache_entry_t **out_pin);
int btree_node_read_cached(btree_t *tree, const int64_t offset, btree_node_t **node,
                           cache_entry_t **pin);

#ifdef TDB_TEST_INTERNALS
/**
 * btree_node_deserialize_direct
 * decode a node straight from a buffer, for the decoder fuzz target only
 * on the real read path these bytes arrive from the block manager, which verifies an xxHash32 over
 * them first, so a mutated file is rejected before the decoder ever sees it. a fuzzer working
 * through that path would only ever exercise the checksum, which is why this door exists
 * @param data the encoded node bytes, untrusted
 * @param data_size length of data
 * @param node out -- the decoded node on success, owning arena
 * @param arena the arena the node is decoded into, destroyed by the caller on failure
 * @return 0 on success, -1 when the bytes do not decode
 */
int btree_node_deserialize_direct(const uint8_t *data, size_t data_size, btree_node_t **node,
                                  arena_t *arena);
#endif

#endif /* __BTREE_INTERNAL_H__ */
