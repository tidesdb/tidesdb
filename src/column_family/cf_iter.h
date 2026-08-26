/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_CF_ITER_H__
#define __TIDESDB_CF_ITER_H__

#include "column_family/column_family.h"
#include "memtable/memtable.h"

/* cf_iter is one column family's snapshot iterator -- the merge_iter wired to live sources. it pins
 * the L0 memtables and the family's sstables, opens a cursor over each, folds them with merge_iter
 * at a snapshot, and drops every pin when freed. it composes the modules and takes no engine, so a
 * test drives it over a real memtable and level set. a read hides tombstones; a compaction scan
 * emits them, which also bypasses the block cache so a bulk scan does not pollute it. keys are
 * byte-ordered. */

typedef struct cf_iter cf_iter_t;

/* the read-your-own-writes overlay, forward-declared; built by the engine from a transaction's
 * write set and handed to cf_iter_new, which takes ownership */
typedef struct writeset_merge_source writeset_merge_source_t;

/**
 * cf_iter_bounds_t
 * the key range a scan will stay inside, so the merge is built from the sstables whose own range
 * meets it rather than from every sstable the family holds
 * @field lower range start, inclusive
 * @field lower_size size of lower in bytes
 * @field upper range end, inclusive for the purpose of selecting sources, so a caller with an
 * exclusive end may pass it unchanged and at worst keep one source it does not read from
 * @field upper_size size of upper in bytes
 */
typedef struct
{
    const uint8_t *lower;
    size_t lower_size;
    const uint8_t *upper;
    size_t upper_size;
} cf_iter_bounds_t;

/**
 * cf_iter_new
 * open a snapshot iterator over a column family, pinning its memtables and sstables for the
 * iterator's lifetime. the iterator starts unpositioned; seek it before reading
 * @param cf the column family, whose id is also its L0 prefix index and whose level set is scanned
 * @param l0 the shared L0 subsystem to pin the memtables from
 * @param snapshot the snapshot sequence; only versions at or below it are visible (UINT64_MAX =
 * latest)
 * @param ws_src an optional read-your-own-writes overlay of a transaction's buffered writes, folded
 * as the newest source so a scan inside the transaction sees its own rows; NULL for none. owned by
 * the iterator and freed by cf_iter_free even when this call fails
 * @param out out -- the iterator on success, owned by the caller (freed by cf_iter_free)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_MEMORY, or TDB_ERR_IO on a cursor open failure
 */
int cf_iter_new(cf_t *cf, tidesdb_l0_t *l0, uint64_t snapshot, writeset_merge_source_t *ws_src,
                cf_iter_t **out);

/**
 * cf_iter_new_bounded
 * as cf_iter_new, but told the range the caller will read, which is what lets the merge leave out
 * the sstables that cannot hold a key in it
 *
 * an sstable outside the range contributes nothing to the answer, yet an unbounded iterator still
 * opens a cursor into it, descends it on every seek and compares its head on every advance -- so a
 * scan of a narrow band costs what the whole family costs, and enough concurrent scans of narrow
 * bands saturate the machine. results are defined only inside the range: a caller that seeks or
 * walks outside it may miss keys the pruned-away sstables hold
 * @param cf the column family
 * @param l0 the shared L0 whose memtables are pinned into the iterator
 * @param snapshot the sequence ceiling versions are resolved against
 * @param ws_src optional write-set overlay, owned by the iterator on every path
 * @param bounds the range the caller will read, or NULL for an iterator over the whole family
 * @param out out -- the iterator on success
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL cf, l0 or out, TDB_ERR_BUSY when the
 * descriptor budget or a moving level set left a source unopenable, or TDB_ERR_MEMORY
 */
int cf_iter_new_bounded(cf_t *cf, tidesdb_l0_t *l0, uint64_t snapshot,
                        writeset_merge_source_t *ws_src, const cf_iter_bounds_t *bounds,
                        cf_iter_t **out);

/**
 * cf_iter_free
 * free the iterator, closing every cursor and dropping every memtable and sstable pin. safe on NULL
 * @param it the iterator, may be NULL
 */
void cf_iter_free(cf_iter_t *it);

/**
 * cf_iter_seek_first / cf_iter_seek_last / cf_iter_seek / cf_iter_seek_for_prev / cf_iter_next /
 * cf_iter_prev / cf_iter_valid / cf_iter_get
 * position and read the merged stream; these delegate to the underlying merge_iter. get returns the
 * value inline, or a vlog offset for the caller to resolve against the db-global value log
 * @param it the iterator, first argument to every one of them
 * @return for the positioning calls and get, TDB_SUCCESS when positioned on an entry,
 *         TDB_ERR_NOT_FOUND when the stream has no entry there, TDB_ERR_INVALID_ARGS on a NULL
 *         iterator, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION from a source read;
 *         cf_iter_valid instead returns 1 when positioned and 0 otherwise
 */
int cf_iter_seek_first(cf_iter_t *it);
int cf_iter_seek_last(cf_iter_t *it);
int cf_iter_seek(cf_iter_t *it, const uint8_t *key, size_t key_size);
int cf_iter_seek_for_prev(cf_iter_t *it, const uint8_t *key, size_t key_size);
int cf_iter_next(cf_iter_t *it);
int cf_iter_prev(cf_iter_t *it);
int cf_iter_valid(const cf_iter_t *it);
int cf_iter_get(cf_iter_t *it, const uint8_t **key, size_t *key_size, uint64_t *seq,
                const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                uint8_t *deleted);

#endif /* __TIDESDB_CF_ITER_H__ */
