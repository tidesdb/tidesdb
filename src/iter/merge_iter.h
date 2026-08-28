/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_MERGE_ITER_H__
#define __TIDESDB_MERGE_ITER_H__

#include "compat.h"

/* merge_iter folds several sorted, versioned key streams -- the L0 memtables and a column family's
 * sstables -- into one ordered stream at a snapshot. each source yields entries byte-ordered by
 * key, and the merge resolves each key to its newest version at or below the snapshot, dropping the
 * older versions and hiding a key whose newest version is a tombstone. a compaction wants none of
 * that and asks for MERGE_ITER_RAW instead, taking every version and applying its own retention.
 * it is generic over the source interface, so it composes real cursors or stub streams and is
 * unit-testable with neither a memtable nor an sstable. it is bidirectional; a direction change
 * re-seeks the sources around the current key so the flip never drops or repeats an entry. */

/**
 * merge_source_t
 * one sorted, versioned key stream the merge folds in, as a small bidirectional cursor interface.
 * entries are byte-ordered by key; several versions of one key appear adjacent. the key and value a
 * get returns stay valid only until the next positioning call on that source
 * @param first position at the first entry; returns 1 if there is one, 0 if the stream is empty
 * @param last position at the last entry; returns 1 if there is one, 0 if the stream is empty
 * @param next advance to the next entry; returns 1 if positioned, 0 at the end
 * @param prev step back to the previous entry; returns 1 if positioned, 0 before the start
 * @param valid returns 1 when the source is positioned on an entry, 0 otherwise
 * @param seek position at the first entry whose key is greater than or equal to the target; returns
 * 1 if positioned, 0 if none qualifies
 * @param seek_for_prev position at the last entry whose key is less than or equal to the target;
 *        returns 1 if positioned, 0 if none qualifies
 * @param get read the current entry; value is NULL with a non-zero vlog_offset when the value
 * spilled
 * @param read_failed whether the source stopped because it could not read rather than because it
 * ran out. a source that cannot read reports itself invalid, which is indistinguishable from
 * exhaustion, and the merge would drop the rest of its entries without it. NULL for a source that
 * reads from memory and cannot fail this way
 * @param covers the newest interval tombstone this source holds that covers a key, at or below the
 * snapshot. asked of every source rather than only the one the key came from, since an interval in
 * one source deletes keys held by another -- and asked here, inside the merge, so the sources the
 * walk reads and the intervals it honours are the same set. a source holding no intervals leaves
 * this NULL
 * @param ctx the source's own context, passed to every call
 */
typedef struct
{
    int (*first)(void *ctx);
    int (*last)(void *ctx);
    int (*next)(void *ctx);
    int (*prev)(void *ctx);
    int (*valid)(void *ctx);
    int (*seek)(void *ctx, const uint8_t *key, size_t key_size);
    int (*seek_for_prev)(void *ctx, const uint8_t *key, size_t key_size);
    void (*get)(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                uint8_t *deleted);
    int (*read_failed)(void *ctx);
    int (*covers)(void *ctx, const uint8_t *key, size_t key_size, uint64_t snapshot,
                  uint64_t *out_seq);
    void *ctx;
} merge_source_t;

typedef struct merge_iter merge_iter_t;

/* merge_iter_new flags */

/* the default -- resolve each key to its newest visible version and hide deleted keys, which is
 * what a read wants. named so a call site states what it asks for rather than passing a bare
 * zero */
#define MERGE_ITER_RESOLVE 0x0

/* yield every version of every key (key ascending, then sequence descending) with no snapshot
 * resolution and no tombstone hiding; a compaction merge consumes this and applies its own MVCC
 * retention and tombstone GC. raw mode is forward-only. */
#define MERGE_ITER_RAW 0x2

/**
 * merge_iter_new
 * build a merge iterator over a set of sources at a snapshot; the sources array is borrowed and
 * must outlive the iterator. the iterator starts unpositioned; seek it before reading
 * @param sources the sources to fold, borrowed
 * @param n_sources the number of sources
 * @param snapshot the snapshot sequence; only versions at or below it are visible (UINT64_MAX =
 * latest); ignored in raw mode, which yields every version
 * @param flags MERGE_ITER_RESOLVE for a read, or MERGE_ITER_RAW for a compaction
 * @param out out -- the iterator on success, owned by the caller (freed by merge_iter_free)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int merge_iter_new(const merge_source_t *sources, int n_sources, uint64_t snapshot, int flags,
                   merge_iter_t **out);

/**
 * merge_iter_free
 * free the iterator and its buffers; the borrowed sources are untouched. safe on NULL
 * @param it the iterator, may be NULL
 */
void merge_iter_free(merge_iter_t *it);

/**
 * merge_iter_seek_first / merge_iter_seek_last
 * position at the smallest or largest visible key
 * @param it the iterator
 * @return TDB_SUCCESS if positioned on a key, TDB_ERR_NOT_FOUND if the merged stream is empty
 */
int merge_iter_seek_first(merge_iter_t *it);
int merge_iter_seek_last(merge_iter_t *it);

/**
 * merge_iter_seek
 * position at the smallest visible key greater than or equal to the target
 * @param it the iterator
 * @param key the target key
 * @param key_size length of key
 * @return TDB_SUCCESS if positioned, TDB_ERR_NOT_FOUND if no visible key qualifies,
 * TDB_ERR_INVALID_ARGS
 */
int merge_iter_seek(merge_iter_t *it, const uint8_t *key, size_t key_size);

/**
 * merge_iter_seek_for_prev
 * position at the largest visible key less than or equal to the target
 * @param it the iterator
 * @param key the target key
 * @param key_size length of key
 * @return TDB_SUCCESS if positioned, TDB_ERR_NOT_FOUND if no visible key qualifies,
 * TDB_ERR_INVALID_ARGS
 */
int merge_iter_seek_for_prev(merge_iter_t *it, const uint8_t *key, size_t key_size);

/**
 * merge_iter_next / merge_iter_prev
 * advance to the next visible key or step back to the previous one; a change of direction re-seeks
 * the sources around the current key
 * @param it the iterator
 * @return TDB_SUCCESS if positioned on a key, TDB_ERR_NOT_FOUND at the corresponding end
 */
int merge_iter_next(merge_iter_t *it);
int merge_iter_prev(merge_iter_t *it);

/**
 * merge_iter_valid
 * report whether the iterator is positioned on a key
 * @param it the iterator
 * @return 1 when positioned, 0 otherwise
 */
int merge_iter_valid(const merge_iter_t *it);

/**
 * merge_iter_get
 * read the resolved entry at the current position; the key and value stay valid until the iterator
 * moves. a value large enough to have spilled comes back as a vlog offset for the caller to resolve
 * @param it the iterator
 * @param key out -- the key, do not free
 * @param key_size out -- key length
 * @param seq out -- the resolved version's sequence
 * @param value out -- the value, do not free (NULL when spilled)
 * @param value_size out -- the value's logical length, whether it is inline or spilled
 * @param vlog_offset out -- the vlog offset to resolve, or 0 when inline
 * @param ttl out -- the entry's expiry, or -1 for none
 * @param deleted out -- non-zero when the entry is a tombstone, which only a raw scan ever sees
 * @return TDB_SUCCESS, or TDB_ERR_NOT_FOUND when the iterator is not positioned
 */
int merge_iter_get(merge_iter_t *it, const uint8_t **key, size_t *key_size, uint64_t *seq,
                   const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                   uint8_t *deleted);

#endif /* __TIDESDB_MERGE_ITER_H__ */
