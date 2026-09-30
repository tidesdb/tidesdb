/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_READSET_H__
#define __TIDESDB_TXN_READSET_H__

#include "../compat.h"

/* a transaction's read footprint -- the cf-namespaced keys it has read, each with the highest
 * sequence it observed, and the intervals its scans covered, each with the snapshot it scanned at.
 * repeatable-read and serializable record their reads here so commit can validate that none changed
 * under them, against the store and against the commits in flight, and a prepare at those levels
 * claims the keys. a repeated read of the same key keeps the higher observed sequence rather than
 * appending, so the keys stay bounded by distinct keys; a scan appends its interval once, when the
 * iterator that made it is freed. */

typedef struct tidesdb_readset tidesdb_readset_t;

/**
 * tidesdb_readset_entry_t
 * a read-only view of one recorded read, key pointing into the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param seq the highest sequence observed for this key
 */
typedef struct
{
    uint32_t cf_index;
    const uint8_t *key;
    size_t key_size;
    uint64_t seq;
} tidesdb_readset_entry_t;

/**
 * tidesdb_readset_range_t
 * a read-only view of one interval a scan covered, bounds pointing into the read set
 * @param cf_index the column family's prefix index
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, NULL when the scan ran to the end of the family
 * @param hi_size length of hi, 0 when open above
 * @param seq the snapshot the scan read at; a version inside the interval above it is a phantom
 */
typedef struct
{
    uint32_t cf_index;
    const uint8_t *lo;
    size_t lo_size;
    const uint8_t *hi;
    size_t hi_size;
    uint64_t seq;
} tidesdb_readset_range_t;

/**
 * tidesdb_readset_create
 * create an empty read set
 * @return the read set, or NULL on allocation failure
 */
tidesdb_readset_t *tidesdb_readset_create(void);

/**
 * tidesdb_readset_free
 * free the read set and its recorded keys and intervals
 * @param rs the read set, may be NULL
 */
void tidesdb_readset_free(tidesdb_readset_t *rs);

/**
 * tidesdb_readset_record
 * record a read of a cf-namespaced key at the observed sequence, keeping the higher sequence if the
 * key was already read, under the write lock
 * @param rs the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key (must be > 0)
 * @param seq the sequence observed for this read
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS / TDB_ERR_MEMORY
 */
int tidesdb_readset_record(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                           size_t key_size, uint64_t seq);

/**
 * tidesdb_readset_record_range
 * record the interval a scan covered, at the snapshot it scanned at; the bounds are copied
 * @param rs the read set
 * @param cf_index the column family's prefix index
 * @param lo the inclusive lower bound (must be non-empty; a bound below every key is one zero byte)
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for a scan that ran to the end
 * @param hi_size length of hi
 * @param seq the snapshot the scan read at
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS / TDB_ERR_MEMORY
 */
int tidesdb_readset_record_range(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *lo,
                                 size_t lo_size, const uint8_t *hi, size_t hi_size, uint64_t seq);

/**
 * tidesdb_readset_count
 * the number of distinct recorded reads; an owner-side read
 * @param rs the read set
 * @return the count, or 0 if rs is NULL
 */
int tidesdb_readset_count(const tidesdb_readset_t *rs);

/**
 * tidesdb_readset_at
 * borrow the recorded read at an index for commit-time validation; an owner-side read
 * @param rs the read set
 * @param index 0-based index
 * @param out receives the entry view
 * @return 1 if the index was in range, 0 otherwise
 */
int tidesdb_readset_at(const tidesdb_readset_t *rs, int index, tidesdb_readset_entry_t *out);

/**
 * tidesdb_readset_range_count
 * the number of recorded scan intervals; an owner-side read
 * @param rs the read set
 * @return the count, or 0 if rs is NULL
 */
int tidesdb_readset_range_count(const tidesdb_readset_t *rs);

/**
 * tidesdb_readset_range_at
 * borrow the recorded scan interval at an index for commit-time validation; an owner-side read
 * @param rs the read set
 * @param index 0-based index
 * @param out receives the interval view
 * @return 1 if the index was in range, 0 otherwise
 */
int tidesdb_readset_range_at(const tidesdb_readset_t *rs, int index, tidesdb_readset_range_t *out);

/**
 * tidesdb_readset_mem_bytes
 * the approximate heap the read set holds, for per-txn memory accounting
 * @param rs the read set
 * @return the byte estimate, or 0 if rs is NULL
 */
int64_t tidesdb_readset_mem_bytes(const tidesdb_readset_t *rs);

#endif /* __TIDESDB_TXN_READSET_H__ */
