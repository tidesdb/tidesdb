/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_COMPACTION_EXEC_H__
#define __TIDESDB_COMPACTION_EXEC_H__

#include "column_family/column_family.h"
#include "compaction_job.h"
#include "manifest/manifest.h"

/* compaction_exec runs one compaction job against a column family. it resolves the job's input ids
 * to the live level set, raw-merges them, writes the output through the sstable builder applying
 * MVCC retention and tombstone GC and carrying spilled values forward by their vlog id, commits one
 * manifest batch, and swaps the level set. it takes a narrow context, never the engine, so it is
 * driven directly in a test. a job whose inputs a raced compaction already removed is skipped, not
 * an error. */

/**
 * compaction_ctx_t
 * the context an executor runs a job against; the engine builds one per compaction, a test builds
 * one over a real cf
 * @param cf the column family being compacted, whose level set, dir, vlog, cache, fdm, and config
 * are borrowed
 * @param manifest the db-level manifest the output and input changes are recorded in
 * @param manifest_path the path the manifest commits to
 * @param next_sstable_id the db-global sstable id allocator, fetch-added per output
 * @param gc_floor the oldest sequence any active snapshot can still read; versions at or below it
 *                 collapse to their newest, and a tombstone at the largest level below it is
 * dropped
 * @param sync_mode the block-manager sync mode driving the klog and manifest durability barriers
 * @param value_threshold the database's value separation size, which a family that keeps its values
 *                        inline raises out of reach rather than switching off -- see
 *                        cf_config_value_threshold, which resolves the two
 * @param max_subdivisions the most threads one job may split its key range across, or 0 or 1 to run
 * every merge on the calling thread alone
 */
typedef struct
{
    cf_t *cf;
    tidesdb_manifest_t *manifest;
    const char *manifest_path;
    _Atomic(uint64_t) *next_sstable_id;
    uint64_t gc_floor;
    int sync_mode;
    size_t value_threshold;
    int max_subdivisions;
} compaction_ctx_t;

/**
 * compaction_exec
 * run one compaction job -- merge its inputs into the target level, commit the manifest batch, and
 * swap the level set
 * @param cx the compaction context
 * @param job the job to run
 * @return TDB_SUCCESS on completion or on a job skipped because its inputs are gone,
 * TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a klog or manifest failure, TDB_ERR_MEMORY, or
 * TDB_ERR_CORRUPTION on a bad read
 */
int compaction_exec(const compaction_ctx_t *cx, const compaction_job_t *job);

#endif /* __TIDESDB_COMPACTION_EXEC_H__ */
