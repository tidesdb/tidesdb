/**
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
#ifndef __BLOCKED_INDEX_H__
#define __BLOCKED_INDEX_H__
#include "compat.h"

/**
 * a per-sstable index over klog blocks, split into range partitions so its resident cost is bounded
 * by the block cache rather than by the amount of data.
 *
 * klog blocks are grouped, in sorted write order, into partitions. each partition is a leaf holding
 * the full first-key and file offset of its blocks, serialized to its own blob in the block-managed
 * file. only a small directory of partition first-keys stays resident; the leaves are fetched on
 * demand and are meant to live in the block cache. leaves are accumulated as they fill and written
 * together when the build is finalized, so the aux region lands after the sstable's klog data and
 * its data blocks stay contiguous. a leaf holds only block first-keys, so this stays far smaller
 * than the entry count even while buffered.
 *
 * each leaf holds full first-keys, so a lookup routes to exactly one candidate block. a point
 * lookup reads that block and searches within it; an iterator seeks to it and scans from there, and
 * can size a range from the block ordinals of its two ends. block first-keys must be strictly
 * increasing, which holds when a klog block boundary always falls on a key boundary (a key's data
 * never spans two blocks).
 *
 * the writer is single-threaded and blocks must be added in ascending first-key order. once built,
 * a reader is read-only and may be queried concurrently by any number of threads.
 */

/* default number of klog blocks described by one leaf before rollover. a leaf is fetched whole per
 * lookup, so this trades leaf size against directory size; the default keeps a leaf near tens of
 * KiB for typical key sizes */
#define TDB_BLOCKED_INDEX_DEFAULT_BLOCKS_PER_PARTITION 4096

/**
 * blocked_index_write_fn
 * persist a finalized blob (a leaf, or the directory) and report where it landed. the builder calls
 * this for each accumulated leaf and then the directory when it is finalized. the returned offset
 * is opaque to the builder and is handed back to the reader's fetch to locate the same blob.
 * @param ctx caller context
 * @param data blob bytes
 * @param size blob length
 * @param out_offset receives the durable offset the blob was written at
 * @return 0 on success, non-zero to abort the build
 */
typedef int (*blocked_index_write_fn)(void *ctx, const uint8_t *data, size_t size,
                                      uint64_t *out_offset);

/**
 * blocked_index_fetch_fn
 * fetch a previously written blob for reading. on success *out_data points at exactly `size`
 * readable bytes valid until release is called with *out_pin (which may be NULL when the buffer
 * needs no pin). the intended production implementation is a block-cache lookup that faults the
 * blob in on a miss and returns a pinned handle.
 * @param ctx caller context
 * @param offset blob offset reported earlier by the write sink
 * @param size blob length to fetch
 * @param out_data receives a readable buffer of `size` bytes valid until release
 * @param out_pin receives a pin handle to pass to release, or NULL when none is needed
 * @return 0 on success, non-zero on failure
 */
typedef int (*blocked_index_fetch_fn)(void *ctx, uint64_t offset, uint32_t size,
                                      const uint8_t **out_data, void **out_pin);

/**
 * blocked_index_release_fn
 * release a pin returned by fetch. never called for a NULL pin.
 * @param ctx caller context
 * @param pin the pin handle fetch produced
 */
typedef void (*blocked_index_release_fn)(void *ctx, void *pin);

/**
 * blocked_index_comparator_fn
 * total order over keys, matching tidesdb_comparator_fn. used to route a key to its partition and
 * to its block within the leaf.
 * @param key1 first key
 * @param key1_size first key length
 * @param key2 second key
 * @param key2_size second key length
 * @param ctx comparator context
 * @return negative, zero, or positive as key1 orders before, equal to, or after key2
 */
typedef int (*blocked_index_comparator_fn)(const uint8_t *key1, size_t key1_size,
                                           const uint8_t *key2, size_t key2_size, void *ctx);

typedef struct blocked_index_builder blocked_index_builder_t;
typedef struct blocked_index_reader blocked_index_reader_t;

/**
 * blocked_index_builder_new
 * open a builder. blocks are added in ascending first-key order; each leaf is serialized as it
 * fills and all leaves are written via write_fn when the builder is finalized.
 * @param out receives the builder
 * @param blocks_per_partition klog blocks per leaf before rollover; 0 selects the default
 * @param write_fn sink for finalized leaf and directory blobs
 * @param write_ctx context passed to write_fn
 * @return 0 on success, non-zero on invalid arguments or allocation failure
 */
int blocked_index_builder_new(blocked_index_builder_t **out, uint32_t blocks_per_partition,
                              blocked_index_write_fn write_fn, void *write_ctx);

/**
 * blocked_index_builder_add
 * record the next klog block. first-keys must be strictly increasing.
 * @param b the builder, or NULL to make this a no-op (the index is disabled)
 * @param first_key the block's first key
 * @param first_key_size the block's first key length
 * @param block_offset the block's file offset
 * @return 0 on success (or when b is NULL), non-zero on an allocation failure
 */
int blocked_index_builder_add(blocked_index_builder_t *b, const uint8_t *first_key,
                              size_t first_key_size, uint64_t block_offset);

/**
 * blocked_index_builder_finish
 * finalize the trailing leaf, then serialize and write the directory. the directory's location and
 * the total block count are returned for the sstable footer to record and hand to
 * blocked_index_reader_open later. a build that added no blocks writes an empty directory.
 * @param b the builder
 * @param out_dir_offset receives the directory blob offset
 * @param out_dir_size receives the directory blob size
 * @param out_total_blocks receives the total number of blocks added (may be NULL)
 * @return 0 on success, non-zero on a write or allocation failure
 */
int blocked_index_builder_finish(blocked_index_builder_t *b, uint64_t *out_dir_offset,
                                 uint32_t *out_dir_size, uint64_t *out_total_blocks);

/**
 * blocked_index_builder_free
 * release the builder. safe on NULL.
 * @param b the builder
 */
void blocked_index_builder_free(blocked_index_builder_t *b);

/**
 * blocked_index_reader_open
 * open a reader over a built index, loading only the directory (one fetch at dir_offset). the
 * comparator and fetch callbacks are retained and used per lookup. an empty directory yields a
 * reader whose lookups all report not-found, which sends the caller to a full scan.
 * @param out receives the reader
 * @param dir_offset directory blob offset from builder_finish
 * @param dir_size directory blob size from builder_finish
 * @param cmp key order used to route a lookup
 * @param cmp_ctx context passed to cmp
 * @param fetch_fn source for the directory and leaf blobs
 * @param release_fn releases fetch pins
 * @param cb_ctx context passed to fetch_fn and release_fn
 * @return 0 on success, non-zero on a fetch or allocation failure
 */
int blocked_index_reader_open(blocked_index_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                              blocked_index_comparator_fn cmp, void *cmp_ctx,
                              blocked_index_fetch_fn fetch_fn, blocked_index_release_fn release_fn,
                              void *cb_ctx);

/**
 * blocked_index_reader_find
 * locate the klog block whose range covers the key -- the block with the greatest first-key not
 * greater than the key.
 * @param r the reader
 * @param key the lookup key
 * @param key_size the key length
 * @param out_block_offset receives the file offset of the covering block
 * @param out_block_ordinal receives the covering block's 0-based ordinal across the sstable, so an
 *        iterator can size a range as the ordinal span of its ends; may be NULL
 * @return 1 if a covering block was found, 0 if the key sorts before every block (a definite miss),
 *         negative on a fetch or decode error (the caller should fall back to a full scan)
 */
int blocked_index_reader_find(blocked_index_reader_t *r, const uint8_t *key, size_t key_size,
                              uint64_t *out_block_offset, uint64_t *out_block_ordinal);

/**
 * blocked_index_reader_resident_bytes
 * bytes the reader keeps resident (the directory). the leaves are not counted -- they live in the
 * fetch backing store (the block cache).
 * @param r the reader
 * @return resident byte count, or 0 when r is NULL
 */
size_t blocked_index_reader_resident_bytes(const blocked_index_reader_t *r);

/**
 * blocked_index_reader_free
 * release the reader. safe on NULL.
 * @param r the reader
 */
void blocked_index_reader_free(blocked_index_reader_t *r);

#endif /* __BLOCKED_INDEX_H__ */
