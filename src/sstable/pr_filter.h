/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PR_FILTER_H__
#define __PR_FILTER_H__
#include "compat.h"
#include "sstable/bloom_filter.h"

/**
 * pr_filter -- a partition-range filter: a per-sstable bloom filter, split into range partitions so
 * its resident cost is bounded by the block cache rather than by the entry count.
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
 * the writer is single-threaded and keys must arrive in non-decreasing byte order. once
 * built, a reader is read-only and may be queried concurrently by any number of threads.
 */

/* default number of keys per partition before rollover. at fpr 0.01 a partition holds roughly
 * 1.2 bytes of filter per key, so the default keeps each partition blob around 80 KiB -- large
 * enough to amortize the per-partition header, small enough to page and evict cheaply */
#define TDB_PR_FILTER_DEFAULT_PARTITION_ENTRIES 65536

/**
 * pr_filter_write_fn
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
typedef int (*pr_filter_write_fn)(void *ctx, const uint8_t *data, size_t size,
                                  uint64_t *out_offset);

/**
 * pr_filter_fetch_fn
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
typedef int (*pr_filter_fetch_fn)(void *ctx, uint64_t offset, uint32_t size,
                                  const uint8_t **out_data, void **out_pin);

/**
 * pr_filter_release_fn
 * release a pin returned by fetch. never called for a NULL pin.
 * @param ctx caller context
 * @param pin the pin handle fetch produced
 */
typedef void (*pr_filter_release_fn)(void *ctx, void *pin);

typedef struct pr_filter_builder pr_filter_builder_t;
typedef struct pr_filter_reader pr_filter_reader_t;

/**
 * pr_filter_builder_new
 * open a builder. keys are added in non-decreasing byte order; each partition is serialized
 * as it fills and all partitions are written via write_fn when the builder is finalized.
 * @param out receives the builder
 * @param fpr per-partition target false-positive rate, in (0, 1)
 * @param partition_entries keys per partition before rollover; 0 selects the default
 * @param write_fn sink for finalized partition and directory blobs
 * @param write_ctx context passed to write_fn
 * @return 0 on success, non-zero on invalid arguments or allocation failure
 */
int pr_filter_builder_new(pr_filter_builder_t **out, double fpr, uint32_t partition_entries,
                          pr_filter_write_fn write_fn, void *write_ctx);

/**
 * pr_filter_builder_add
 * add the next key. keys must be non-decreasing under the order the reader will use.
 * @param b the builder, or NULL to make this a no-op (the filter is disabled)
 * @param key the key to add
 * @param key_size the key length
 * @return 0 on success (or when b is NULL), non-zero on an allocation failure
 */
int pr_filter_builder_add(pr_filter_builder_t *b, const uint8_t *key, size_t key_size);

/**
 * pr_filter_builder_finish
 * finalize the trailing partition, then serialize and write the directory. the directory's
 * location and the total key count are returned for the sstable footer to record and hand to
 * pr_filter_reader_open later. a build that added no keys writes an empty directory.
 * @param b the builder
 * @param out_dir_offset receives the directory blob offset
 * @param out_dir_size receives the directory blob size
 * @param out_total_entries receives the total number of keys added (may be NULL)
 * @return 0 on success, non-zero on a write or allocation failure
 */
int pr_filter_builder_finish(pr_filter_builder_t *b, uint64_t *out_dir_offset,
                             uint32_t *out_dir_size, uint64_t *out_total_entries);

/**
 * pr_filter_builder_free
 * release the builder. safe on NULL.
 * @param b the builder
 */
void pr_filter_builder_free(pr_filter_builder_t *b);

/**
 * pr_filter_reader_open
 * open a reader over a built filter, loading only the directory (one fetch at dir_offset). the
 * fetch callbacks are retained and used per query, and a query routes to its partition by the same
 * byte order the rest of the engine uses. an empty directory (dir_size describing zero partitions)
 * yields a reader whose queries all return may-present, which is the safe answer when no filter was
 * built.
 * @param out receives the reader
 * @param dir_offset directory blob offset from builder_finish
 * @param dir_size directory blob size from builder_finish
 * @param fetch_fn source for the directory and partition blobs
 * @param release_fn releases fetch pins
 * @param cb_ctx context passed to fetch_fn and release_fn
 * @return 0 on success, non-zero on a fetch or allocation failure
 */
int pr_filter_reader_open(pr_filter_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                          pr_filter_fetch_fn fetch_fn, pr_filter_release_fn release_fn,
                          void *cb_ctx);

/**
 * pr_filter_reader_maybe_contains
 * route the key to its partition and probe that partition's bloom.
 * @param r the reader
 * @param key the key to test
 * @param key_size the key length
 * @return 1 if the key may be present, 0 if it is definitely absent, negative on a fetch or
 *         decode error (callers must treat a negative result as may-be-present)
 */
int pr_filter_reader_maybe_contains(pr_filter_reader_t *r, const uint8_t *key, size_t key_size);

/**
 * pr_filter_reader_resident_bytes
 * bytes the reader keeps resident (the directory). the partition blobs are not counted -- they
 * live in the fetch backing store (the block cache).
 * @param r the reader
 * @return resident byte count, or 0 when r is NULL
 */
size_t pr_filter_reader_resident_bytes(const pr_filter_reader_t *r);

/**
 * pr_filter_reader_free
 * release the reader. safe on NULL.
 * @param r the reader
 */
void pr_filter_reader_free(pr_filter_reader_t *r);

#endif /* __PR_FILTER_H__ */
