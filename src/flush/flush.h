/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FLUSH_H__
#define __TIDESDB_FLUSH_H__

#include "column_family/column_family.h"
#include "manifest/manifest.h"
#include "memtable/memtable.h"

/* flush turns one sealed immutable memtable into per-column-family L1 sstables. the immutable's
 * shared skip_list is sorted by the 4-byte cf-index prefix then the key, so a single ordered pass
 * streams the entries out one column family at a time -- a demux, never a rebuild. each column
 * family's run builds one sstable; all of an immutable's outputs are recorded in one atomic
 * manifest commit, then installed into the level sets and the immutable is reclaimed. flush takes a
 * narrow context, not the engine, so many immutables (across or within a column family) flush
 * concurrently by running flush_immutable on separate threads. keys are byte-ordered throughout. */

/**
 * flush_ctx_t
 * the shared, read-only context a flush runs against; the engine builds one and the flush pool
 * reuses it across immutables
 * @param l0 the L0 subsystem, for reclaiming an immutable once its data is durable in L1
 * @param cfs the column family registry indexed by cf-index; a NULL slot is a dropped family whose
 *            entries are discarded
 * @param n_cfs the length of cfs
 * @param manifest the db-level manifest every output sstable is recorded in
 * @param manifest_path the path the manifest commits to
 * @param next_sstable_id the db-global sstable id allocator, fetch-added per output
 * @param fdm the db-global descriptor budget, for releasing a flushed immutable's WAL descriptor,
 * or NULL when the immutables carry no WAL
 * @param sync_mode the block-manager sync mode driving the klog and manifest durability barriers
 * @param gc_floor the oldest sequence any live snapshot can still read. a memtable holds a version
 *                 chain per key and this is what decides how much of it reaches L1 -- every version
 *                 above the floor survives, plus the newest at or below it. with no reader
 *                 registered the floor is UINT64_MAX and only the newest version of each key is
 *                 written, which is what a flush has always done
 * @param on_flush optional hook fired once per column family that received an L1 segment, after the
 *                 install commits, so the engine can consider that cf for compaction; may be NULL
 * @param on_flush_ctx opaque context passed to on_flush
 * @param wal_generation_pinned asked whether an undecided prepare's record lives in the generation
 * being retired, or NULL when two-phase commit is not in play. a prepared batch lives only in its
 * own log until phase two decides it, so that one generation is closed but kept rather than
 * unlinked. asking per generation rather than testing a database-wide count is what stops one slow
 * coordinator pinning every log ever written
 * @param on_wal_retained fired with the path and generation of a log the pin above kept, so the
 *                        engine can unlink
 *                        it once nothing is in doubt. a retained log that is never swept would
 *                        outlive the log holding its decision and come back as a false in-doubt
 *                        transaction; may be NULL
 * @param on_wal_retained_ctx opaque context passed to on_wal_retained
 */
typedef struct
{
    tidesdb_l0_t *l0;
    cf_t *const *cfs;
    int n_cfs;
    tidesdb_manifest_t *manifest;
    const char *manifest_path;
    _Atomic(uint64_t) *next_sstable_id;
    fd_manager_t *fdm;
    int sync_mode;
    size_t value_threshold;
    uint64_t gc_floor;
    void (*on_flush)(void *ctx, uint64_t cf_id);
    void *on_flush_ctx;
    int (*wal_generation_pinned)(void *ctx, uint64_t generation);
    void (*on_wal_retained)(void *ctx, const char *path, uint64_t generation);
    void *on_wal_retained_ctx;
} flush_ctx_t;

/**
 * flush_immutable
 * flush one dequeued immutable to L1 in a single call -- demux its skip_list into per-column-family
 * sstables, record them in one atomic manifest commit, install them into the level sets, then mark
 * the immutable flushed and reclaim it. on any failure before the commit the built sstables are
 * closed and the immutable is left for a retry, its data still durable in its WAL.
 *
 * the engine does not use this. it runs flush_build and flush_install separately so many immutables
 * build at once while only the install is ordered by ticket, and so the registry lock is held
 * across neither the wait nor the build alone. this is the equivalent single-threaded path, kept
 * because it is what the flush tests drive and what makes the two halves' contract legible
 * @param fx the flush context
 * @param immutable the dequeued immutable memtable, owned by this call on success
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a klog or manifest failure,
 * TDB_ERR_MEMORY, or TDB_ERR_CORRUPTION on a malformed skip_list key
 */
int flush_immutable(const flush_ctx_t *fx, tidesdb_memtable_t *immutable);

/**
 * flush_job_t
 * one immutable's built-but-not-installed sstables, produced by flush_build and consumed by
 * flush_install, so the costly build runs off any lock while only the install is ordered
 */
typedef struct flush_job flush_job_t;

/**
 * flush_build
 * demux the immutable into per-column-family L1 sstables on disk, holding their build references,
 * without touching the manifest or the level sets; thread-safe, so many immutables build at once.
 * on success the job must be handed to flush_install or discarded with flush_job_free
 * @param fx the flush context
 * @param immutable the dequeued immutable memtable, borrowed until flush_install retires it
 * @param out_job out -- the built job on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a klog failure, TDB_ERR_MEMORY, or
 * TDB_ERR_CORRUPTION on a malformed skip_list key
 */
int flush_build(const flush_ctx_t *fx, tidesdb_memtable_t *immutable, flush_job_t **out_job);

/**
 * flush_install
 * record a built job's sstables in one atomic manifest commit, install them into the level sets,
 * then mark the immutable flushed and reclaim it; consumes the job. call in the immutables'
 * generation order so no sstable lands newer than what remains in L0. on a commit failure the
 * immutable is left for a retry, its data still durable in its WAL
 * @param fx the flush context
 * @param job the built job from flush_build, freed by this call
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_IO on a manifest failure
 */
int flush_install(const flush_ctx_t *fx, flush_job_t *job);

/**
 * flush_job_rebind
 * re-resolve a built job's column-family pointers from a freshly read registry, for a caller that
 * released the registry lock between the build and the install. an output whose family is no longer
 * present was dropped in the gap, and is discarded rather than installed
 * @param job the built job from flush_build
 * @param cfs the column families indexed by cf id, entries may be NULL
 * @param n_cfs the length of cfs
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS
 */
int flush_job_rebind(flush_job_t *job, cf_t *const *cfs, int n_cfs);

/**
 * flush_job_free
 * discard a built-but-not-installed job, closing its sstables and freeing it, for shutdown or a
 * build that will not be installed
 * @param job the job, may be NULL
 */
void flush_job_free(flush_job_t *job);

#endif /* __TIDESDB_FLUSH_H__ */
