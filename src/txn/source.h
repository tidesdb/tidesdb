/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_SOURCE_H__
#define __TIDESDB_TXN_SOURCE_H__

#include "../compat.h"

/* the pluggable read data-source abstraction. a transaction read of a given column family fans out
 * across, newest-first: the transaction's own uncommitted write buffer (read-your-own-writes); the
 * shared db-level L0 active memtable and then the L0 queue of immutables (both prefix-namespaced,
 * so one L0 serves every cf); and finally that column family's own L1+ sstable levels. the db-level
 * clock/block cache serves every cf's L1+ block reads and sits under the sstable source, not as a
 * source in this priority stack. this interface lets any of them be plugged in without the read
 * core knowing their internals. a source reports the highest-seq version of a key it holds that is
 * visible at the reader's snapshot. the composer consults the ordered stack newest-first and
 * returns the first hit: because a newer LSM tier always carries a sequence at least as high as any
 * older tier for the same key, the first snapshot-visible hit in that order is the globally newest
 * visible version. new source kinds extend the read path just by joining the stack. */

/**
 * tidesdb_source_result_t
 * the outcome of consulting one source for a key
 * @param TDB_SOURCE_NOT_FOUND the source holds no version of the key visible at the snapshot
 * @param TDB_SOURCE_FOUND the source holds a visible version, returned in the out version
 * @param TDB_SOURCE_BUSY the source is transiently unavailable (e.g. layout moved mid-scan); retry
 */
typedef enum
{
    TDB_SOURCE_NOT_FOUND = 0,
    TDB_SOURCE_FOUND = 1,
    TDB_SOURCE_BUSY = 2
} tidesdb_source_result_t;

/**
 * tidesdb_source_version_t
 * a version of a key returned by a source
 * @param seq the version's commit sequence number
 * @param value malloc'd copy of the value on a live hit (caller frees), NULL for a tombstone
 * @param value_size length of value, 0 for a tombstone
 * @param ttl the entry's expiry time, or -1 for none
 * @param deleted 1 when the version is a tombstone, else 0
 */
typedef struct
{
    uint64_t seq;
    uint8_t *value;
    size_t value_size;
    int64_t ttl;
    int deleted;
} tidesdb_source_version_t;

/**
 * tidesdb_source_get_fn
 * point lookup a source implements: find the highest-seq version of key (under cf_index) visible at
 * snapshot in this source, filling out on a hit
 * @param ctx the source's own context
 * @param cf_index the column family's prefix index
 * @param key the key bytes (unprefixed)
 * @param key_size length of key
 * @param snapshot the reader's snapshot sequence
 * @param out receives the version on TDB_SOURCE_FOUND
 * @return the source result
 */
typedef tidesdb_source_result_t (*tidesdb_source_get_fn)(void *ctx, uint32_t cf_index,
                                                         const uint8_t *key, size_t key_size,
                                                         uint64_t snapshot,
                                                         tidesdb_source_version_t *out);

/**
 * tidesdb_source_has_newer_fn
 * report whether this source holds the key at a sequence above seq_floor, without materializing the
 * value. a conflict check only needs that one bit, and a source able to answer it from metadata
 * skips the work a full lookup would do. a source that cannot answer cheaply leaves the slot NULL
 * and the stack falls back to a full get
 * @param ctx the source's own context
 * @param cf_index the column family's prefix index
 * @param key the key bytes (unprefixed)
 * @param key_size length of key
 * @param seq_floor the sequence a version must exceed to count as newer
 * @param newer out, set non-zero when the found version is above seq_floor
 * @return TDB_SOURCE_FOUND with newer set when this source holds the key, TDB_SOURCE_NOT_FOUND when
 *         it does not, or TDB_SOURCE_BUSY when transiently unavailable
 */
typedef tidesdb_source_result_t (*tidesdb_source_has_newer_fn)(void *ctx, uint32_t cf_index,
                                                               const uint8_t *key, size_t key_size,
                                                               uint64_t seq_floor, int *newer);

/**
 * tidesdb_source_range_has_newer_fn
 * report whether this source holds any key in [lo, hi) at a sequence above seq_floor. what a commit
 * asks on behalf of a range delete, which writes an interval and so has no one key to probe. a
 * source able to rule a whole table out on its recorded newest sequence does so without reading it
 *
 * unlike the single-key probe there is no per-key fallback for a source that leaves this NULL, so a
 * stack missing an implementation cannot answer at all and reports busy rather than a false clear
 * @param ctx the source's own context
 * @param cf_index the column family's prefix index
 * @param lo inclusive lower bound (unprefixed)
 * @param lo_size length of lo
 * @param hi exclusive upper bound (unprefixed), or NULL with hi_size 0 for unbounded above
 * @param hi_size length of hi, 0 for unbounded above
 * @param seq_floor the sequence a version must exceed to count as newer
 * @param newer out, set non-zero as soon as one is found
 * @return TDB_SOURCE_FOUND with newer set, TDB_SOURCE_NOT_FOUND when the source holds nothing in
 *         the range, or TDB_SOURCE_BUSY when transiently unavailable
 */
typedef tidesdb_source_result_t (*tidesdb_source_range_has_newer_fn)(
    void *ctx, uint32_t cf_index, const uint8_t *lo, size_t lo_size, const uint8_t *hi,
    size_t hi_size, uint64_t seq_floor, int *newer);

/**
 * tidesdb_source_t
 * one pluggable read source in a transaction's source stack
 * @param name a short label for stats and debugging
 * @param get the source's point-lookup function
 * @param has_newer the source's newer-version probe, optional; NULL falls back to a full get
 * @param range_has_newer the source's interval probe, for a commit checking a range delete. a NULL
 *        slot cannot be stood in for, so the stack reports busy rather than clearing the commit
 * @param ctx opaque context passed to get
 */
typedef struct
{
    const char *name;
    tidesdb_source_get_fn get;
    tidesdb_source_has_newer_fn has_newer;
    tidesdb_source_range_has_newer_fn range_has_newer;
    void *ctx;
} tidesdb_source_t;

/**
 * tidesdb_source_stack_has_newer
 * walk the stack newest-first and report whether any source holds the key above seq_floor. the
 * first source holding the key decides, since a shallower source always carries a sequence at least
 * as high as a deeper one for the same key
 * @param sources the source stack, ordered newest-first
 * @param count number of sources
 * @param cf_index the column family's prefix index
 * @param key the key bytes (unprefixed)
 * @param key_size length of key
 * @param seq_floor the sequence a version must exceed to count as newer
 * @param newer out, set non-zero when a newer version exists
 * @return TDB_SOURCE_FOUND or TDB_SOURCE_NOT_FOUND with newer set, or TDB_SOURCE_BUSY
 */
tidesdb_source_result_t tidesdb_source_stack_has_newer(const tidesdb_source_t *sources, int count,
                                                       uint32_t cf_index, const uint8_t *key,
                                                       size_t key_size, uint64_t seq_floor,
                                                       int *newer);

/**
 * tidesdb_source_stack_range_has_newer
 * ask every source whether any key in [lo, hi) sits above seq_floor. every one is asked, not just
 * the first holding something -- a newer key in the interval can be in any of them, and unlike a
 * point probe a shallower source says nothing about what a deeper one holds elsewhere in the range
 * @param sources the source stack
 * @param count number of sources
 * @param cf_index the column family's prefix index
 * @param lo inclusive lower bound (unprefixed)
 * @param lo_size length of lo
 * @param hi exclusive upper bound (unprefixed), or NULL with hi_size 0 for unbounded above
 * @param hi_size length of hi, 0 for unbounded above
 * @param seq_floor the sequence a version must exceed to count as newer
 * @param newer out, set non-zero when any source holds one
 * @return TDB_SOURCE_FOUND or TDB_SOURCE_NOT_FOUND with newer set, or TDB_SOURCE_BUSY when a source
 *         could not answer -- including one that implements no interval probe at all
 */
tidesdb_source_result_t tidesdb_source_stack_range_has_newer(const tidesdb_source_t *sources,
                                                             int count, uint32_t cf_index,
                                                             const uint8_t *lo, size_t lo_size,
                                                             const uint8_t *hi, size_t hi_size,
                                                             uint64_t seq_floor, int *newer);

/**
 * tidesdb_source_stack_get
 * consult an ordered, newest-first stack of sources and return the first hit; a BUSY from any
 * source short-circuits (the caller retries) rather than falling through to an older source and
 * risking a stale read
 * @param sources the source stack, ordered newest-first (write buffer first, then L0, then
 * sstables)
 * @param count number of sources
 * @param cf_index the column family's prefix index
 * @param key the key bytes (unprefixed)
 * @param key_size length of key
 * @param snapshot the reader's snapshot sequence
 * @param out receives the winning version on TDB_SOURCE_FOUND (caller frees out->value)
 * @return TDB_SOURCE_FOUND with out set, TDB_SOURCE_NOT_FOUND if no source has the key, or
 *         TDB_SOURCE_BUSY if a source was transiently unavailable
 */
tidesdb_source_result_t tidesdb_source_stack_get(const tidesdb_source_t *sources, int count,
                                                 uint32_t cf_index, const uint8_t *key,
                                                 size_t key_size, uint64_t snapshot,
                                                 tidesdb_source_version_t *out);

#endif /* __TIDESDB_TXN_SOURCE_H__ */
