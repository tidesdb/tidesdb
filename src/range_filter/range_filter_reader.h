/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_READER_H__
#define __RANGE_FILTER_READER_H__
#include "compat.h"
#include "range_filter/range_filter.h"

/* a reader answers range queries over a filter written by a streaming build. it keeps the
 * directory resident, the model, the samples and the partition table, and fetches the one partition
 * a query lands in, so the stores live wherever the fetch keeps them, the block cache in an
 * sstable. a reader never changes once opened and may be queried by any number of threads */

typedef struct range_filter_reader range_filter_reader_t;

/**
 * range_filter_reader_open
 * open a reader, fetching and checking the directory
 * @param out out -- the reader on success, NULL on failure
 * @param dir_offset where the directory was written
 * @param dir_size its length
 * @param fetch_fn the source of the directory and the partitions
 * @param release_fn releases what fetch_fn pinned
 * @param ctx context for both
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO when the directory could not be fetched,
 *         TDB_ERR_CORRUPTION when it does not check out, or TDB_ERR_MEMORY
 */
int range_filter_reader_open(range_filter_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                             range_filter_fetch_fn fetch_fn, range_filter_release_fn release_fn,
                             void *ctx);

/**
 * range_filter_reader_may_contain
 * whether [lo, hi] might hold a key the filter was built from, answering 1 for any failure along
 * the way, since only a definite 0 lets a caller skip the run
 * @param r the reader
 * @param lo the low key, inclusive
 * @param lo_size its length
 * @param hi the high key, inclusive
 * @param hi_size its length
 * @return 0 when the range is certainly empty, 1 otherwise
 */
int range_filter_reader_may_contain(const range_filter_reader_t *r, const uint8_t *lo,
                                    size_t lo_size, const uint8_t *hi, size_t hi_size);

/**
 * range_filter_reader_key_count
 * how many keys the filter was built from
 * @param r the reader
 * @return the count, 0 for NULL
 */
uint64_t range_filter_reader_key_count(const range_filter_reader_t *r);

/**
 * range_filter_reader_resident_bytes
 * the memory the reader holds, its model, samples and partition table, not the partitions
 * @param r the reader
 * @return the bytes, 0 for NULL
 */
size_t range_filter_reader_resident_bytes(const range_filter_reader_t *r);

/**
 * range_filter_reader_free
 * release a reader
 * @param r the reader, or NULL
 */
void range_filter_reader_free(range_filter_reader_t *r);

#endif /* __RANGE_FILTER_READER_H__ */
