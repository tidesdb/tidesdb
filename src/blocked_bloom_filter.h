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
#ifndef __BLOCKED_BLOOM_FILTER_H__
#define __BLOCKED_BLOOM_FILTER_H__
#include "bloom_filter.h"
#include "compat.h"

/**
 * a per-sstable bloom filter, split into range partitions so its resident cost is bounded by the
 * block cache rather than by the entry count.
 *
 * the key space is split, in sorted write order, into range partitions. each partition is an
 * ordinary bloom_filter_t over its range, serialized to its own blob in the sstable's block-managed
 * file. only a small directory of partition first-keys stays resident; the partition blobs are
 * fetched on demand and are meant to live in the block cache. partitions are accumulated as they
 * fill and written together when the build is finalized, so the aux region lands after the
 * sstable's klog data and its data blocks stay contiguous.
 *
 * the directory holds each partition's full first-key, so routing a query to its partition is exact
 * and the filter never reports a false negative.
 *
 * the writer is single-threaded and keys must arrive in non-decreasing comparator order. once
 * built, a reader is read-only and may be queried concurrently by any number of threads.
 */

/* default number of keys per partition before rollover. at fpr 0.01 a partition holds roughly
 * 1.2 bytes of filter per key, so the default keeps each partition blob around 80 KiB -- large
 * enough to amortize the per-partition header, small enough to page and evict cheaply */
#define TDB_BLOCKED_BLOOM_DEFAULT_PARTITION_ENTRIES 65536

/**
 * blocked_bloom_write_fn
 * persist a finalized blob (a partition, or the directory) and report where it landed. the builder
 * calls this for each accumulated partition and then the directory when it is finalized. the
 * returned offset is opaque to the builder and is handed back to the reader's fetch to locate the
 * same blob.
 * @param ctx caller context
 * @param data blob bytes
 * @param size blob length
 * @param out_offset receives the durable offset the blob was written at
 * @return 0 on success, non-zero to abort the build
 */
typedef int (*blocked_bloom_write_fn)(void *ctx, const uint8_t *data, size_t size,
                                      uint64_t *out_offset);

/**
 * blocked_bloom_fetch_fn
 * fetch a previously written blob for reading. on success *out_data points at exactly `size`
 * readable bytes that stay valid until release is called with *out_pin (which may be NULL when
 * the buffer needs no pin, e.g. a test backing store). the intended production implementation
 * is a block-cache lookup that faults the blob in on a miss and returns a pinned handle.
 * @param ctx caller context
 * @param offset blob offset reported earlier by the write sink
 * @param size blob length to fetch
 * @param out_data receives a readable buffer of `size` bytes valid until release
 * @param out_pin receives a pin handle to pass to release, or NULL when none is needed
 * @return 0 on success, non-zero on failure (a failure is treated as may-be-present)
 */
typedef int (*blocked_bloom_fetch_fn)(void *ctx, uint64_t offset, uint32_t size,
                                      const uint8_t **out_data, void **out_pin);

/**
 * blocked_bloom_release_fn
 * release a pin returned by fetch. never called for a NULL pin.
 * @param ctx caller context
 * @param pin the pin handle fetch produced
 */
typedef void (*blocked_bloom_release_fn)(void *ctx, void *pin);

/**
 * blocked_bloom_comparator_fn
 * total order over keys, matching tidesdb_comparator_fn. used only to route a query key to its
 * partition; the partition bloom itself hashes raw key bytes.
 * @param key1 first key
 * @param key1_size first key length
 * @param key2 second key
 * @param key2_size second key length
 * @param ctx comparator context
 * @return negative, zero, or positive as key1 orders before, equal to, or after key2
 */
typedef int (*blocked_bloom_comparator_fn)(const uint8_t *key1, size_t key1_size,
                                           const uint8_t *key2, size_t key2_size, void *ctx);

typedef struct blocked_bloom_builder blocked_bloom_builder_t;
typedef struct blocked_bloom_reader blocked_bloom_reader_t;

/**
 * blocked_bloom_builder_new
 * open a builder. keys are added in non-decreasing comparator order; each partition is serialized
 * as it fills and all partitions are written via write_fn when the builder is finalized.
 * @param out receives the builder
 * @param fpr per-partition target false-positive rate, in (0, 1)
 * @param partition_entries keys per partition before rollover; 0 selects the default
 * @param write_fn sink for finalized partition and directory blobs
 * @param write_ctx context passed to write_fn
 * @return 0 on success, non-zero on invalid arguments or allocation failure
 */
int blocked_bloom_builder_new(blocked_bloom_builder_t **out, double fpr, uint32_t partition_entries,
                              blocked_bloom_write_fn write_fn, void *write_ctx);

/**
 * blocked_bloom_builder_add
 * add the next key. keys must be non-decreasing under the order the reader will use.
 * @param b the builder, or NULL to make this a no-op (the filter is disabled)
 * @param key the key to add
 * @param key_size the key length
 * @return 0 on success (or when b is NULL), non-zero on an allocation failure
 */
int blocked_bloom_builder_add(blocked_bloom_builder_t *b, const uint8_t *key, size_t key_size);

/**
 * blocked_bloom_builder_finish
 * finalize the trailing partition, then serialize and write the directory. the directory's
 * location and the total key count are returned for the sstable footer to record and hand to
 * blocked_bloom_reader_open later. a build that added no keys writes an empty directory.
 * @param out_dir_offset receives the directory blob offset
 * @param out_dir_size receives the directory blob size
 * @param out_total_entries receives the total number of keys added (may be NULL)
 * @return 0 on success, non-zero on a write or allocation failure
 */
int blocked_bloom_builder_finish(blocked_bloom_builder_t *b, uint64_t *out_dir_offset,
                                 uint32_t *out_dir_size, uint64_t *out_total_entries);

/**
 * blocked_bloom_builder_free
 * release the builder. safe on NULL.
 * @param b the builder
 */
void blocked_bloom_builder_free(blocked_bloom_builder_t *b);

/**
 * blocked_bloom_reader_open
 * open a reader over a built filter, loading only the directory (one fetch at dir_offset). the
 * comparator and fetch callbacks are retained and used per query. an empty directory
 * (dir_size describing zero partitions) yields a reader whose queries all return may-present,
 * which is the safe answer when no filter was built.
 * @param out receives the reader
 * @param dir_offset directory blob offset from builder_finish
 * @param dir_size directory blob size from builder_finish
 * @param cmp key order used to route a query to its partition
 * @param cmp_ctx context passed to cmp
 * @param fetch_fn source for the directory and partition blobs
 * @param release_fn releases fetch pins
 * @param cb_ctx context passed to fetch_fn and release_fn
 * @return 0 on success, non-zero on a fetch or allocation failure
 */
int blocked_bloom_reader_open(blocked_bloom_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                              blocked_bloom_comparator_fn cmp, void *cmp_ctx,
                              blocked_bloom_fetch_fn fetch_fn, blocked_bloom_release_fn release_fn,
                              void *cb_ctx);

/**
 * blocked_bloom_reader_maybe_contains
 * route the key to its partition and probe that partition's bloom.
 * @param r the reader
 * @param key the key to test
 * @param key_size the key length
 * @return 1 if the key may be present, 0 if it is definitely absent, negative on a fetch or
 *         decode error (callers must treat a negative result as may-be-present)
 */
int blocked_bloom_reader_maybe_contains(blocked_bloom_reader_t *r, const uint8_t *key,
                                        size_t key_size);

/**
 * blocked_bloom_reader_resident_bytes
 * bytes the reader keeps resident (the directory). the partition blobs are not counted -- they
 * live in the fetch backing store (the block cache).
 * @param r the reader
 * @return resident byte count, or 0 when r is NULL
 */
size_t blocked_bloom_reader_resident_bytes(const blocked_bloom_reader_t *r);

/**
 * blocked_bloom_reader_free
 * release the reader. safe on NULL.
 * @param r the reader
 */
void blocked_bloom_reader_free(blocked_bloom_reader_t *r);

#endif /* __BLOCKED_BLOOM_FILTER_H__ */
