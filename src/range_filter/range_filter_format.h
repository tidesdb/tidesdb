/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_FORMAT_H__
#define __RANGE_FILTER_FORMAT_H__
#include "compat.h"
#include "range_filter/range_filter_bits.h"
#include "range_filter/range_filter_codec.h"
#include "range_filter/range_filter_infix.h"

/* a filter on disk is a directory and its partitions, every integer little-endian.
 *
 * the directory is the part a reader keeps resident. it holds a magic, a format version, the
 * filter's widths and key count, the coder's model, every sample, and the partition table.
 *
 *   4 magic "TDRF", 4 version, 4 flags, 1 sample bits, 1 quotient bits, 1 remainder bits,
 *   1 reserved, 8 key count, 4 model size and the model, 4 sample count and per sample 4 bit count
 *   and its bits packed most significant first, 4 partition count and per partition 8 offset,
 *   4 size, 4 first gap
 *
 * a partition holds the stores of a contiguous run of gaps and is fetched on demand, the way a
 * bloom partition is, so the stores live in the block cache rather than in the reader.
 *
 *   4 gap count, 4 byte offset per gap and one past the last, then the stores
 *
 * a store is its slot count and then three bitmaps as whole 8-byte words, the quotients, the run
 * ends and the remainders.
 *
 * every count and offset is checked against the bytes that hold it, and a filter failing any check
 * is treated as absent, which costs the pruning it would have done and never a key */

/* the directory's magic, "TDRF" */
#define RANGE_FILTER_DIR_MAGIC 0x54445246u

/* the directory's format version, moved only when this layout changes */
#define RANGE_FILTER_FORMAT_VERSION 10u

/**
 * range_filter_part_t
 * where one partition lies and which gaps it holds
 * @param offset the offset the write sink reported for it
 * @param size its length in bytes
 * @param first_gap the first gap it holds, the rest following in order
 */
typedef struct
{
    uint64_t offset;
    uint32_t size;
    uint32_t first_gap;
} range_filter_part_t;

/**
 * range_filter_dir_t
 * a directory, written from a builder's state or read back with everything it points at owned
 * @param sample_bits the sample interval as a power of two
 * @param q_bits the quotient width of every store
 * @param r_bits the remainder width of every store
 * @param n_keys how many keys the filter was built from
 * @param codec the coder, owned once read back and left NULL when writing
 * @param samples the samples, ascending
 * @param n_samples how many
 * @param parts the partition table, ordered by first gap
 * @param n_parts how many partitions
 */
typedef struct
{
    unsigned sample_bits;
    unsigned q_bits;
    unsigned r_bits;
    uint64_t n_keys;
    range_filter_codec_t *codec;
    range_filter_bits_t *samples;
    size_t n_samples;
    range_filter_part_t *parts;
    size_t n_parts;
} range_filter_dir_t;

/**
 * range_filter_dir_encode
 * write a directory
 * @param d the directory, its codec left out
 * @param model the serialized model
 * @param model_size its length
 * @param out out -- a heap buffer the caller frees
 * @param out_size out -- its length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_TOO_LARGE or TDB_ERR_MEMORY
 */
int range_filter_dir_encode(const range_filter_dir_t *d, const uint8_t *model, size_t model_size,
                            uint8_t **out, size_t *out_size);

/**
 * range_filter_dir_decode
 * read a directory back, checking every field and that the samples rise
 * @param data the directory bytes
 * @param size their length
 * @param out the directory, owning its codec, samples and partitions, released with the call below
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION or TDB_ERR_MEMORY
 */
int range_filter_dir_decode(const uint8_t *data, size_t size, range_filter_dir_t *out);

/**
 * range_filter_dir_release
 * release what a read directory owns and leave it empty
 * @param d the directory
 */
void range_filter_dir_release(range_filter_dir_t *d);

/**
 * range_filter_store_encoded_size
 * the bytes a store takes on disk
 * @param s the store
 * @return the size
 */
size_t range_filter_store_encoded_size(const range_filter_infix_store_t *s);

/**
 * range_filter_store_encode
 * write a store into exactly range_filter_store_encoded_size bytes
 * @param s the store
 * @param out where to write
 */
void range_filter_store_encode(const range_filter_infix_store_t *s, uint8_t *out);

/**
 * range_filter_store_decode
 * read a store back, checking that its bitmaps agree with each other and with its slot count
 * @param data the store bytes
 * @param size their length
 * @param q_bits the directory's quotient width
 * @param r_bits the directory's remainder width
 * @param max_n the most slots a gap can hold
 * @param out the store, released with range_filter_infix_store_free
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION or TDB_ERR_MEMORY
 */
int range_filter_store_decode(const uint8_t *data, size_t size, unsigned q_bits, unsigned r_bits,
                              uint32_t max_n, range_filter_infix_store_t *out);

/**
 * range_filter_part_encode
 * assemble a partition from its stores laid end to end
 * @param stores the stores' bytes
 * @param offsets each store's start in them and, last, their total, n_gaps + 1 entries
 * @param n_gaps how many stores
 * @param out out -- a heap buffer the caller frees
 * @param out_size out -- its length
 * @return TDB_SUCCESS, TDB_ERR_TOO_LARGE or TDB_ERR_MEMORY
 */
int range_filter_part_encode(const uint8_t *stores, const uint32_t *offsets, uint32_t n_gaps,
                             uint8_t **out, size_t *out_size);

/**
 * range_filter_part_gap
 * find one gap's store inside a partition, checking the partition's table on the way
 * @param data the partition bytes
 * @param size their length
 * @param index the gap's position within the partition
 * @param store out -- the store's bytes
 * @param store_size out -- their length
 * @return TDB_SUCCESS, or TDB_ERR_CORRUPTION when the table does not fit the bytes or holds no such
 *         gap
 */
int range_filter_part_gap(const uint8_t *data, size_t size, uint32_t index, const uint8_t **store,
                          size_t *store_size);

#endif /* __RANGE_FILTER_FORMAT_H__ */
