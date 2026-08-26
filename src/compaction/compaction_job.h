/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_COMPACTION_JOB_H__
#define __TIDESDB_COMPACTION_JOB_H__

#include "compat.h"

/* a compaction job is the plain descriptor the deterministic planner emits and the executor runs.
 * it names the input sstables, the level they merge into, and how the output is split. one Spooky
 * step can emit several disjoint jobs (a partitioned merge is one job per partition). the
 * descriptor holds no handles, only ids, so it can be queued and validated against the live level
 * set at execution. */

/* how a merge splits its output across files */
typedef enum
{
    COMPACTION_SPLIT_NONE,      /* outputs are not aligned to anything */
    COMPACTION_SPLIT_BOUNDARIES /* roll at the largest level's file boundaries, so an output
                                 * overlaps at most one file above */
} compaction_split_t;

/**
 * compaction_job_t
 * one merge unit: the inputs, the target level, and the split policy. the input_ids array is
 * borrowed and must outlive the job
 * @param input_ids the sstable ids to merge, from any levels below or at the target
 * @param n_inputs the number of inputs
 * @param target_level the 1-based level the merged output lands at
 * @param is_largest_level non-zero when the target is the largest live level, so the executor may
 * GC tombstones at or below the GC floor
 * @param split how outputs align across files
 * @param file_max roll to a new output once one reaches this many klog bytes, or 0 for no cap;
 * independent of split, so a partitioned merge caps the size of each partition's output too
 * @param boundaries the split-point keys for COMPACTION_SPLIT_BOUNDARIES, sorted ascending; a new
 *                   output starts at the first key reaching each boundary, so each output overlaps
 * at most one file at the next level. borrowed, must outlive the job
 * @param boundary_sizes the length of each boundary key, parallel to boundaries
 * @param n_boundaries the number of boundaries
 * @param may_subdivide the executor may split this job's key range across threads. set only when
 * the plan emitted this job alone -- a plan that emitted several already runs them at once, and
 * subdividing those too would multiply the two. an unaligned merge is the case this exists for: its
 * inputs span partitions so the planner could not split it, yet its output still rolls at the same
 * boundaries, so the ranges between them are independent
 */
typedef struct
{
    const uint64_t *input_ids;
    int n_inputs;
    int target_level;
    int is_largest_level;
    compaction_split_t split;
    uint64_t file_max;
    const uint8_t *const *boundaries;
    const size_t *boundary_sizes;
    int n_boundaries;
    int may_subdivide;
} compaction_job_t;

#endif /* __TIDESDB_COMPACTION_JOB_H__ */
