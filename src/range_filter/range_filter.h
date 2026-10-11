/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_H__
#define __RANGE_FILTER_H__
#include "compat.h"
#include "range_filter/range_filter_codec.h"

/* a range filter answers whether a key range might hold a key, never answering no for a range that
 * does. it follows Diva (Eslami, Bercea, Dayan), built once from a sorted run of keys.
 *
 * every key is first encoded by the order-preserving entropy coder. every T-th encoded key, and
 * the last, is kept whole as a sample. the keys between two adjacent samples are cut down to a
 * fixed-width infix each. the bits the two samples share are dropped, since every key between them
 * shares them too. so is the run after their first difference where the lower sample holds 1s and
 * the upper 0s, since a key between them has that run fixed by its own first differing bit. what is
 * left is that bit and the next bits up to the infix width. the infixes of a gap go into an infix
 * store, which is exact over them.
 *
 * a query encodes its endpoints the same way. a sample inside the range answers yes. otherwise the
 * range lies inside one gap, its endpoints are cut down to infixes against that gap's samples, and
 * the gap's store answers. cutting is monotone, so every key in the range has an infix between the
 * endpoints' infixes, and no key in range is ever missed. a false positive is a key outside the
 * range whose infix collides with one inside it */

/* the default sample interval as a power of two, the paper's T of 1024 */
#define RANGE_FILTER_DEFAULT_SAMPLE_BITS 10

/* the widest sample interval accepted, as a power of two */
#define RANGE_FILTER_MAX_SAMPLE_BITS 16

/* the store bytes a streamed partition is closed at, near a bloom partition's size so the two
 * page through the block cache alike */
#define RANGE_FILTER_DEFAULT_PARTITION_BYTES 65536

/* a run's model is held to at most one part in this many of its filter's own bytes */
#define RANGE_FILTER_MODEL_SHARE 8

/* the most contexts a model is given however large its run */
#define RANGE_FILTER_MAX_CONTEXTS 512

typedef struct range_filter range_filter_t;
typedef struct range_filter_builder range_filter_builder_t;

/**
 * range_filter_write_fn
 * persist a finished blob, a partition or the directory, and report where it landed
 * @param ctx caller context
 * @param data the blob
 * @param size its length
 * @param out_offset receives the offset a fetch will be handed to read it back
 * @return 0 on success, non-zero to fail the build
 */
typedef int (*range_filter_write_fn)(void *ctx, const uint8_t *data, size_t size,
                                     uint64_t *out_offset);

/**
 * range_filter_fetch_fn
 * fetch a blob written earlier, valid until it is released
 * @param ctx caller context
 * @param offset the offset the write sink reported
 * @param size the blob's length
 * @param out_data receives size readable bytes
 * @param out_pin receives a handle for the release, or NULL when none is needed
 * @return 0 on success, non-zero on failure, which a query answers as may-contain
 */
typedef int (*range_filter_fetch_fn)(void *ctx, uint64_t offset, uint32_t size,
                                     const uint8_t **out_data, void **out_pin);

/**
 * range_filter_release_fn
 * release a fetched blob, never called for a NULL pin
 * @param ctx caller context
 * @param pin the handle the fetch produced
 */
typedef void (*range_filter_release_fn)(void *ctx, void *pin);

/**
 * range_filter_builder_new
 * start building a filter. the false positive rate is about 2 / 2^r_bits on well-behaved keys,
 * and the filter costs about r_bits + 2 bits per key
 * @param codec the coder every key is encoded through, borrowed, and it must outlive the filter
 * @param sample_bits the sample interval T as a power of two, 1 to RANGE_FILTER_MAX_SAMPLE_BITS
 * @param r_bits the remainder width, 1 to RANGE_FILTER_INFIX_MAX_R_BITS
 * @param out out -- the builder on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int range_filter_builder_new(const range_filter_codec_t *codec, unsigned sample_bits,
                             unsigned r_bits, range_filter_builder_t **out);

/**
 * range_filter_builder_add
 * add the next key, which must sort strictly after the one before it
 * @param b the builder
 * @param key the key bytes
 * @param key_size the key length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS for a key out of order, or TDB_ERR_MEMORY
 */
int range_filter_builder_add(range_filter_builder_t *b, const uint8_t *key, size_t key_size);

/**
 * range_filter_builder_finish
 * finish a filter built in memory and release the builder, whatever the outcome
 * @param b the builder, consumed, refused when it was streaming
 * @param out out -- the filter on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int range_filter_builder_finish(range_filter_builder_t *b, range_filter_t **out);

/**
 * range_filter_builder_stream
 * send the filter to a sink instead of keeping it. each gap's store is encoded into a partition as
 * the gap closes, so the builder holds the filter in its compact on-disk form rather than as
 * searchable stores. the partitions go out together at the finish, followed by the directory, so a
 * sink that also takes a table's data blocks keeps those contiguous, as the bloom's partitions do.
 * called before the first key
 * @param b the builder
 * @param write_fn the sink for partitions and, at the end, the directory
 * @param write_ctx its context
 * @param partition_bytes the store bytes a partition closes at, 0 for the default
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS once keys were added, or TDB_ERR_MEMORY
 */
int range_filter_builder_stream(range_filter_builder_t *b, range_filter_write_fn write_fn,
                                void *write_ctx, size_t partition_bytes);

/**
 * range_filter_builder_finish_stream
 * finish a streaming build, writing every partition and then the directory, and release the
 * builder whatever the outcome
 * @param b the builder, consumed
 * @param dir_offset out -- where the directory landed
 * @param dir_size out -- its length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO when the sink failed, TDB_ERR_TOO_LARGE or
 *         TDB_ERR_MEMORY
 */
int range_filter_builder_finish_stream(range_filter_builder_t *b, uint64_t *dir_offset,
                                       uint32_t *dir_size);

/**
 * range_filter_remainder_bits
 * the remainder width that holds a filter to a false-positive rate on uniformly spread keys, the
 * rate being about 2 / 2^r
 * @param fpr the rate, in (0, 1)
 * @return the width, 1 to RANGE_FILTER_INFIX_MAX_R_BITS
 */
unsigned range_filter_remainder_bits(double fpr);

/**
 * range_filter_context_budget
 * how many contexts a run's model may have, so the model a reader keeps loaded stays a small share
 * of the filter it serves, and a small run gets few or none
 * @param n_keys the keys in the run
 * @param r_bits the remainder width
 * @return the budget, 0 to RANGE_FILTER_MAX_CONTEXTS
 */
int range_filter_context_budget(uint64_t n_keys, unsigned r_bits);

/**
 * range_filter_builder_free
 * abandon a builder without finishing it
 * @param b the builder, or NULL
 */
void range_filter_builder_free(range_filter_builder_t *b);

/**
 * range_filter_may_contain
 * whether [lo, hi] might hold a key the filter was built from. it answers 1 for every range that
 * does, and for an error too, since only a definite 0 lets a caller skip the run
 * @param f the filter
 * @param lo the low key, inclusive
 * @param lo_size its length
 * @param hi the high key, inclusive
 * @param hi_size its length
 * @return 0 when the range is certainly empty, 1 otherwise
 */
int range_filter_may_contain(const range_filter_t *f, const uint8_t *lo, size_t lo_size,
                             const uint8_t *hi, size_t hi_size);

/**
 * range_filter_size_bits
 * the bits the filter's samples and stores occupy, the figure a bits-per-key budget is held to
 * @param f the filter
 * @return the size in bits
 */
uint64_t range_filter_size_bits(const range_filter_t *f);

/**
 * range_filter_key_count
 * how many keys the filter was built from
 * @param f the filter
 * @return the count
 */
uint64_t range_filter_key_count(const range_filter_t *f);

/**
 * range_filter_free
 * release a filter
 * @param f the filter, or NULL
 */
void range_filter_free(range_filter_t *f);

#endif /* __RANGE_FILTER_H__ */
