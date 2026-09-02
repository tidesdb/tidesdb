/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_LEVEL_SET_H__
#define __TIDESDB_LEVEL_SET_H__

#include "sstable/sstable.h"

/* the number of sstable levels a column family keeps; levels are 1-based (L1..LN) at the api, so a
 * level argument is validated to 1..LEVEL_SET_MAX_LEVELS and stored at index level-1. */
#define LEVEL_SET_MAX_LEVELS 8

/* the first sstable level, whose flush outputs may overlap in key range */
#define LEVEL_SET_L1 1

/**
 * level_set_t
 * the per-column-family, in-memory structure organizing open sstables into tiers. L1 is an
 * overlapping set (flush outputs), L2+ are non-overlapping runs kept sorted by min_key. it is pure
 * in-memory -- it holds no manifest handle and performs no durable work; the cf module populates it
 * at open and the flush/compaction orchestrator drives its mutations. reads are lock-free against a
 * concurrent swap via an epoch-guarded immutable layout; the layout holds a reference on every
 * sstable so a table stays live while any reader's epoch is open.
 */
typedef struct level_set level_set_t;

/**
 * level_live_layouts
 * how many level layouts are allocated and not yet reclaimed, for a teardown balance check
 * @return the live layout count
 */
int64_t level_live_layouts(void);

/**
 * level_set_create
 * create an empty level set (keys are ordered byte-wise)
 * @param out out -- the new level set on success, owned by the caller
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int level_set_create(level_set_t **out);

/**
 * level_set_free
 * free the level set and drop the layout's reference on every sstable it holds; the caller must
 * ensure no other thread is still reading
 * @param ls the level set, may be NULL
 */
void level_set_free(level_set_t *ls);

/**
 * level_set_reclaim_deferred
 * reclaim any superseded layouts whose reader epoch has drained -- the deferred-free work a swap
 * under an active reader could not do inline. safe to call periodically from a background reaper;
 * concurrent with reads and swaps
 * @param ls the level set, may be NULL
 */
void level_set_reclaim_deferred(level_set_t *ls);

/**
 * level_set_install
 * add one open sstable at a level, publishing a new layout. the level set takes a reference on the
 * sstable. used for a flush L1 add and for the per-entry rebuild at cf open.
 * @param ls the level set
 * @param sst the open sstable, referenced by the set for its lifetime in the set
 * @param level 1-based level (LEVEL_SET_L1..LEVEL_SET_MAX_LEVELS)
 * @param size_bytes the sstable's on-disk size, used by level-byte triggers
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int level_set_install(level_set_t *ls, sstable_t *sst, int level, uint64_t size_bytes);

/**
 * level_set_swap
 * publish a new layout with the input sstables removed and the output sstables installed, in one
 * atomic step -- a compaction result, or a trivial move expressed as an output at a new level. the
 * set references each output and drops its reference on each input; a removed sstable is reclaimed
 * once no reader still holds the old layout. this is in-memory only; the orchestrator has already
 * committed the manifest.
 * @param ls the level set
 * @param inputs sstables to remove (matched by identity), may be NULL when n_inputs is 0
 * @param n_inputs number of inputs
 * @param outputs sstables to install, may be NULL when n_outputs is 0
 * @param out_levels 1-based target level of each output, parallel to outputs
 * @param out_sizes on-disk size of each output, parallel to outputs
 * @param n_outputs number of outputs
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int level_set_swap(level_set_t *ls, sstable_t *const *inputs, int n_inputs,
                   sstable_t *const *outputs, const int *out_levels, const uint64_t *out_sizes,
                   int n_outputs);

/**
 * level_set_count
 * the number of sstables at a level
 * @param ls the level set
 * @param level 1-based level
 * @return the count, or 0 for an out-of-range level
 */
int level_set_count(level_set_t *ls, int level);

/**
 * level_set_level_bytes
 * the summed on-disk size of every sstable at a level, the input to a level-size compaction trigger
 * @param ls the level set
 * @param level 1-based level
 * @return the total bytes, or 0 for an out-of-range level
 */
uint64_t level_set_level_bytes(level_set_t *ls, int level);

/**
 * level_set_l1_overlap_depth
 * the L1 sstable count, which is the overlap depth a point read pays there since every L1 file may
 * hold the key. the compaction scheduler takes the deepest across the families each tick and
 * publishes it as the tier depth write admission slows and stalls on, so this is one of the two
 * signals ingestion paces against -- the immutable queue is the other
 * @param ls the level set
 * @return the number of sstables at L1
 */
int level_set_l1_overlap_depth(level_set_t *ls);

/**
 * level_set_overlapping
 * collect the sstables at a level whose [min_key, max_key] range intersects [min_key, max_key], the
 * candidates a read or a compaction must consider. each returned sstable is referenced for the
 * caller, who drops it with sstable_unref.
 * @param ls the level set
 * @param level 1-based level
 * @param min_key low end of the query range (inclusive)
 * @param min_key_size size of min_key
 * @param max_key high end of the query range (inclusive)
 * @param max_key_size size of max_key
 * @param out destination array receiving referenced sstables, filled up to max_out
 * @param max_out capacity of out
 * @return how many sstables overlap the range, which may exceed max_out when out was too small --
 *         only the first max_out are written and referenced, and a caller that gets more than it
 *         asked for is holding a partial answer it must not treat as complete. -1 on a bad argument
 */
int level_set_overlapping(level_set_t *ls, int level, const uint8_t *min_key, size_t min_key_size,
                          const uint8_t *max_key, size_t max_key_size, sstable_t **out,
                          int max_out);

/**
 * level_set_collect_all
 * reference every sstable across all levels for a full snapshot scan; the caller drops each with
 * sstable_unref. atomic against the layout, so the caller queries the count with a NULL out,
 * allocates, then collects -- the set can move in between, and what comes back is the count at
 * collect time rather than the one the array was sized from
 * @param ls the level set
 * @param out destination array, or NULL to query the total
 * @param max capacity of out
 * @return the number of sstables at collect time. above max nothing is referenced or copied, so the
 *         caller can size up and retry owing nothing. at or below max every entry written is
 *         referenced -- a caller that treats a count differing from its own as a failure still owns
 *         those references and must drop them before it retries
 */
int level_set_collect_all(level_set_t *ls, sstable_t **out, int max);

/**
 * level_set_snapshot_entry_t
 * one sstable in a full snapshot, the referenced handle paired with the level and on-disk size the
 * layout records -- the two facts the handle itself does not carry
 * @param sst the referenced open sstable, dropped by the caller with sstable_unref
 * @param level the 1-based level the sstable sits at
 * @param size_bytes its on-disk size in bytes
 */
typedef struct
{
    sstable_t *sst;
    int level;
    uint64_t size_bytes;
} level_set_snapshot_entry_t;

/**
 * level_set_snapshot
 * reference every sstable across all levels with its level and on-disk size, the per-sstable input
 * a compaction planner folds into level aggregates. query the total with a NULL out, size up, then
 * collect -- the set can move in between, so what comes back is the count at collect time and not
 * necessarily the one the array was sized from
 * @param ls the level set
 * @param out destination array, or NULL to query the total
 * @param max capacity of out
 * @return the number of sstables at collect time. above max nothing is referenced or copied, so the
 *         caller owes nothing. at or below max the fill is complete and every entry it wrote is
 *         referenced -- a caller that treats a count differing from its own as a failure still owns
 *         those references and must drop them. releasing across the whole zeroed array and skipping
 *         NULL entries is correct either way, and is the only form that cannot leak
 */
int level_set_snapshot(level_set_t *ls, level_set_snapshot_entry_t *out, int max);

/**
 * level_set_generation
 * a counter bumped every time a new layout is published, so a caller that plans against the level
 * set can tell whether anything changed since it last looked without walking it
 * @param ls the level set
 * @return the current generation, or 0 for a null set
 */
uint64_t level_set_generation(const level_set_t *ls);

/**
 * level_set_occupancy
 * a bitmask of which levels hold at least one sstable, bit i for level i+1. one plain atomic load,
 * where asking each level for its count costs an epoch enter and exit apiece -- so a caller that
 * walks every level to find the few that are populated should consult this first
 * @param ls the level set
 * @return the mask, or 0 for a null or empty set
 */
uint32_t level_set_occupancy(const level_set_t *ls);

/**
 * level_set_interval_tables
 * how many of the set's sstables carry range tombstones, republished with the layout. an interval
 * covers a range the table carrying it need not hold a single key of, so the only way to ask the
 * family what covers a key is to ask every table -- and every point read and every conflict probe
 * asks. this is the one load that lets a family which has never deleted a range skip that walk
 * @param ls the level set
 * @return the number of sstables carrying at least one interval, or 0 for a null set
 */
uint32_t level_set_interval_tables(const level_set_t *ls);

#endif /* __TIDESDB_LEVEL_SET_H__ */
