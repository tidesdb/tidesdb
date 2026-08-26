/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable/btree/btree_internal.h"

/* writing a node out. a leaf is laid down prefix-compressed with an indirection table over the key
 * suffixes, and its sequences delta encoded against the smallest in the node, so ordered keys with
 * nearby sequences cost close to nothing per entry. the decode side that reads all of this back
 * lives in btree_node.c, beside the node cache it fills. */

static int btree_serialize_empty_leaf(const int64_t prev_offset, const int64_t next_offset,
                                      uint8_t **out, size_t *out_size)
{
    uint8_t *buffer = malloc(BTREE_LEAF_EMPTY_BUF_SIZE);
    if (!buffer) return -1;

    size_t off = 0;
    buffer[off++] = BTREE_NODE_LEAF;
    off += btree_varint_encode(buffer + off, 0);
    encode_int64_le_compat(buffer + off, prev_offset);
    off += BTREE_LEAF_LINK_BYTES;
    encode_int64_le_compat(buffer + off, next_offset);
    off += BTREE_LEAF_LINK_BYTES;

    *out = buffer;
    *out_size = off;
    return 0;
}

/**
 * btree_zigzag
 * map a signed value onto an unsigned one that keeps small magnitudes short under varint encoding,
 * matching what btree_signed_varint_encode writes
 * @param v the signed value
 * @return the zigzag encoding of v
 */
static inline uint64_t btree_zigzag(int64_t v)
{
    return ((uint64_t)v << 1) ^ (uint64_t)(v >> (BTREE_ZIGZAG_SIGN_SHIFT));
}

/**
 * btree_leaf_key_splits
 * split every key into the prefix it shares with the key before it and the suffix only it holds,
 * which is what the leaf actually stores
 * @param leaf the pending leaf, whose keys are already in order
 * @param prefix_lens receives each key's shared prefix length
 * @param suffix_lens receives each key's own suffix length
 */
static void btree_leaf_key_splits(const btree_pending_leaf_t *leaf, size_t *prefix_lens,
                                  size_t *suffix_lens)
{
    /* first key has no prefix compression */
    prefix_lens[0] = 0;
    suffix_lens[0] = leaf->entries[0].key_size;

    for (uint32_t i = 1; i < leaf->num_entries; i++)
    {
        prefix_lens[i] = btree_compute_prefix_len(leaf->keys[i - 1], leaf->entries[i - 1].key_size,
                                                  leaf->keys[i], leaf->entries[i].key_size);
        suffix_lens[i] = leaf->entries[i].key_size - prefix_lens[i];
    }
}

/**
 * btree_leaf_base_seq
 * the sequence every entry's own is stored as a delta from, taken as the smallest in the leaf so
 * the deltas stay small and positive
 * @param leaf the pending leaf
 * @return the base sequence
 */
static uint64_t btree_leaf_base_seq(const btree_pending_leaf_t *leaf)
{
    uint64_t base_seq = leaf->entries[0].seq;
    for (uint32_t i = 1; i < leaf->num_entries; i++)
        if (leaf->entries[i].seq < base_seq) base_seq = leaf->entries[i].seq;
    return base_seq;
}

/**
 * btree_leaf_estimate_size
 * size the buffer the encoded leaf needs, by adding up what each field will occupy
 * @param leaf the pending leaf
 * @param prefix_lens each key's shared prefix length
 * @param suffix_lens each key's own suffix length
 * @param base_seq the sequence the entry sequences are delta encoded against
 * @return the number of bytes the encoding needs, before the safety pad
 */
static size_t btree_leaf_estimate_size(const btree_pending_leaf_t *leaf, const size_t *prefix_lens,
                                       const size_t *suffix_lens, uint64_t base_seq)
{
    size_t est_size = BTREE_NODE_TYPE_BYTES;
    est_size += btree_varint_size(leaf->num_entries);
    est_size += BTREE_LEAF_LINK_BYTES * 2;                  /* prev/next offsets */
    est_size += leaf->num_entries * BTREE_KEY_OFFSET_BYTES; /* key indirection table */
    est_size += btree_varint_size(base_seq);

    size_t keys_total = 0;
    size_t values_total = 0;
    for (uint32_t i = 0; i < leaf->num_entries; i++)
    {
        est_size += btree_varint_size(prefix_lens[i]);
        est_size += btree_varint_size(suffix_lens[i]);
        est_size += btree_varint_size(leaf->entries[i].value_size);
        est_size += btree_varint_size(leaf->entries[i].vlog_offset);
        est_size += btree_varint_size(btree_zigzag((int64_t)(leaf->entries[i].seq - base_seq)));
        est_size += btree_varint_size(btree_zigzag(leaf->entries[i].ttl));
        est_size += BTREE_ENTRY_FLAGS_BYTES;
        keys_total += suffix_lens[i];
        if (leaf->entries[i].vlog_offset == 0 && leaf->values[i])
            values_total += leaf->entries[i].value_size;
    }
    return est_size + keys_total + values_total;
}

/**
 * btree_leaf_encode
 * write the leaf into the sized buffer -- header, the key indirection table filled in as the keys
 * are laid down, entry metadata, the key suffixes, then the inline values
 * @param leaf the pending leaf
 * @param prev_offset offset of the previous leaf node
 * @param next_offset offset of the next leaf node
 * @param base_seq the sequence the entry sequences are delta encoded against
 * @param prefix_lens each key's shared prefix length
 * @param suffix_lens each key's own suffix length
 * @param buffer the destination, sized by btree_leaf_estimate_size
 * @param out_off receives the encoded length
 * @return 0 on success, -1 when the keys section outgrew what an offset slot can address
 */
static int btree_leaf_encode(const btree_pending_leaf_t *leaf, const int64_t prev_offset,
                             const int64_t next_offset, uint64_t base_seq,
                             const size_t *prefix_lens, const size_t *suffix_lens, uint8_t *buffer,
                             size_t *out_off)
{
    size_t off = 0;
    buffer[off++] = BTREE_NODE_LEAF;
    off += btree_varint_encode(buffer + off, leaf->num_entries);
    encode_int64_le_compat(buffer + off, prev_offset);
    off += BTREE_LEAF_LINK_BYTES;
    encode_int64_le_compat(buffer + off, next_offset);
    off += BTREE_LEAF_LINK_BYTES;

    /* key indirection table placeholder -- filled while writing keys */
    const size_t indirection_table_pos = off;
    off += leaf->num_entries * BTREE_KEY_OFFSET_BYTES;

    off += btree_varint_encode(buffer + off, base_seq);

    for (uint32_t i = 0; i < leaf->num_entries; i++)
    {
        off += btree_varint_encode(buffer + off, prefix_lens[i]);
        off += btree_varint_encode(buffer + off, suffix_lens[i]);
        off += btree_varint_encode(buffer + off, leaf->entries[i].value_size);
        off += btree_varint_encode(buffer + off, leaf->entries[i].vlog_offset);
        off += btree_signed_varint_encode(buffer + off, (int64_t)(leaf->entries[i].seq - base_seq));
        off += btree_signed_varint_encode(buffer + off, leaf->entries[i].ttl);
        buffer[off++] = leaf->entries[i].flags;
    }

    /* keys, prefix-compressed so only the suffix is stored */
    const size_t keys_start = off;
    for (uint32_t i = 0; i < leaf->num_entries; i++)
    {
        /* the offset slot is a little-endian uint16, so a keys section past 64KB would wrap it and
         * deserialization would read from the wrong place */
        const size_t raw_off = off - keys_start;
        if (raw_off > UINT16_MAX) return -1;

        const uint16_t key_off = (uint16_t)raw_off;
        buffer[indirection_table_pos + i * BTREE_KEY_OFFSET_BYTES] = (uint8_t)(key_off & 0xFF);
        buffer[indirection_table_pos + i * BTREE_KEY_OFFSET_BYTES + 1] =
            (uint8_t)((key_off >> 8) & 0xFF);
        memcpy(buffer + off, leaf->keys[i] + prefix_lens[i], suffix_lens[i]);
        off += suffix_lens[i];
    }

    for (uint32_t i = 0; i < leaf->num_entries; i++)
    {
        if (leaf->entries[i].vlog_offset == 0 && leaf->values[i])
        {
            memcpy(buffer + off, leaf->values[i], leaf->entries[i].value_size);
            off += leaf->entries[i].value_size;
        }
    }

    *out_off = off;
    return 0;
}

/**
 * btree_leaf_serialize
 * serializes a leaf node with optimized format:
 * -- varint encoding for sizes and metadata
 * -- prefix compression for keys
 * -- key indirection table for O(1) access
 * -- delta encoding for sequence numbers
 *
 * format:
 * [type:1][num_entries:varint][prev_offset:8][next_offset:8]
 * [key_offsets_table: num_entries * 2 bytes] -- offset from keys_start to each key
 * [base_seq:varint][entries: prefix_len:varint, suffix_len:varint, value_size:varint,
 *                           vlog_offset:varint, seq_delta:signed_varint, ttl:signed_varint,
 * flags:1] [keys: prefix-compressed][values]
 *
 * @param leaf the pending leaf to serialize
 * @param prev_offset offset of previous leaf node (-1 if first)
 * @param next_offset offset of next leaf node (-1 if last)
 * @param out output buffer (caller must free)
 * @param out_size output size of serialized data
 * @return 0 on success, -1 on failure
 */
int btree_leaf_serialize(const btree_pending_leaf_t *leaf, const int64_t prev_offset,
                         const int64_t next_offset, uint8_t **out, size_t *out_size)
{
    if (!leaf || !out || !out_size) return -1;
    if (leaf->num_entries == 0)
        return btree_serialize_empty_leaf(prev_offset, next_offset, out, out_size);

    size_t *prefix_lens = malloc(leaf->num_entries * sizeof(size_t));
    size_t *suffix_lens = malloc(leaf->num_entries * sizeof(size_t));
    if (!prefix_lens || !suffix_lens)
    {
        free(prefix_lens);
        free(suffix_lens);
        return -1;
    }

    btree_leaf_key_splits(leaf, prefix_lens, suffix_lens);
    const uint64_t base_seq = btree_leaf_base_seq(leaf);
    const size_t est_size = btree_leaf_estimate_size(leaf, prefix_lens, suffix_lens, base_seq);

    uint8_t *buffer = malloc(est_size + BTREE_LEAF_SERIALIZE_SAFETY_PAD);
    size_t off = 0;
    const int rc = buffer ? btree_leaf_encode(leaf, prev_offset, next_offset, base_seq, prefix_lens,
                                              suffix_lens, buffer, &off)
                          : -1;
    free(prefix_lens);
    free(suffix_lens);
    if (rc != 0)
    {
        free(buffer);
        return -1;
    }

    *out = buffer;
    *out_size = off;
    return 0;
}
/**
 * btree_internal_serialize
 * serializes an internal node with optimized format:
 * -- varint encoding for counts and key sizes
 * -- delta encoding for child offsets
 * -- separator keys stored uncompressed
 *
 * format:
 * [type:1][num_keys:varint][base_offset:8][child_offset_deltas:signed_varint*N]
 * [key_sizes:varint*(N-1)][keys:full]
 *
 * @param entries internal node entries
 * @param num_entries number of entries
 * @param out output parameter for serialized node
 * @param out_size output parameter for serialized node size
 * @return 0 on success, -1 on failure
 */
int btree_internal_serialize(const btree_level_entry_t *entries, const uint32_t num_entries,
                             uint8_t **out, size_t *out_size)
{
    if (!entries || num_entries == 0 || !out || !out_size) return -1;

    const uint32_t num_keys = (num_entries > 1) ? num_entries - 1 : 0;
    const uint32_t num_children = num_entries;

    /* estimate size needed */
    size_t est_size = 1;                     /* type */
    est_size += btree_varint_size(num_keys); /* num_keys */
    est_size += 8;                           /* base_offset */
    est_size += num_children * 10;           /* child offset deltas (worst case) */

    size_t keys_size = 0;
    for (uint32_t i = 1; i < num_entries; i++)
    {
        est_size += btree_varint_size(entries[i].key_size);
        keys_size += entries[i].key_size;
    }
    est_size += keys_size;

    uint8_t *buffer = malloc(est_size + BTREE_INTERNAL_SERIALIZE_SAFETY_PAD);
    if (!buffer) return -1;

    size_t off = 0;

    buffer[off++] = BTREE_NODE_INTERNAL;
    off += btree_varint_encode(buffer + off, num_keys);

    /* base offset is the first child offset */
    const int64_t base_offset = entries[0].child_offset;
    encode_int64_le_compat(buffer + off, base_offset);
    off += 8;

    /* child offset deltas */
    int64_t prev_offset = base_offset;
    for (uint32_t i = 0; i < num_children; i++)
    {
        const int64_t delta = entries[i].child_offset - prev_offset;
        off += btree_signed_varint_encode(buffer + off, delta);
        prev_offset = entries[i].child_offset;
    }

    /* separator key sizes (varint) */
    for (uint32_t i = 1; i < num_entries; i++)
    {
        off += btree_varint_encode(buffer + off, entries[i].key_size);
    }

    for (uint32_t i = 1; i < num_entries; i++)
    {
        memcpy(buffer + off, entries[i].key, entries[i].key_size);
        off += entries[i].key_size;
    }

    *out = buffer;
    *out_size = off;
    return 0;
}
