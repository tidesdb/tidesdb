/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_COMPACTION_INTERNAL_H__
#define __TIDESDB_COMPACTION_INTERNAL_H__

#include "compaction_exec.h"
#include "range_tombstone/range_tombstone.h"
#include "sstable/sstable.h"

/* what the merge and the commit sides of a compaction share, which nothing outside the module sees
 */

/* how many output slots to grow the sink's array by at a time */
#define CE_OUTPUTS_GROW 8

/* how many sstables one level of the base-tombstone sibling scan inspects; a level that fills this
 * many leaves the rest of the level unread, so absence is unproven and the tombstone is kept */
#define CE_TOMB_SIBLING_MAX 64

/* the output-building sink: the current in-progress output plus the finished ones, so a merge can
 * roll to a new file at a boundary or a size cap without the write loop knowing the details */
typedef struct
{
    const compaction_ctx_t *cx;
    sstable_t **outputs;
    uint64_t *sizes;
    int n_outputs;
    int cap_outputs;

    block_manager_t *cur_bm;
    sstable_builder_t *cur_builder;
    int cur_open;
    int cur_partition;
    const range_tombstone_set_t *carried;
} ce_sink_t;

/**
 * ce_commit
 * record the outputs and the removed inputs in one manifest batch, then swap the level set, rolling
 * the catalogue back when a step fails so it never names outputs nothing installed
 * @param cx the compaction context
 * @param job the job, whose target level the outputs are catalogued at
 * @param inputs the resolved input sstables
 * @param in_sizes the on-disk size each input's entry recorded
 * @param n_inputs the number of inputs
 * @param sink the outputs
 * @return TDB_SUCCESS, TDB_ERR_IO when the manifest could not be updated, or TDB_ERR_MEMORY
 */
int ce_commit(const compaction_ctx_t *cx, const compaction_job_t *job, sstable_t *const *inputs,
              const uint64_t *in_sizes, int n_inputs, ce_sink_t *sink);

/**
 * ce_union_intervals
 * the union of the intervals this merge's inputs carry, for its outputs to carry in their place
 *
 * an interval lives as long as a table holding it. the inputs are retired by this merge, so what
 * they carried has to reach what replaces them or every delete they held is lost with their files.
 * one this merge has finished the work of is left behind instead, which is the only thing that
 * bounds what a table accumulates. carrying none and failing to carry them are reported apart,
 * since this merge deletes the files its inputs live in, so an interval that does not reach the
 * output is not delayed but gone, and the keys it covered come back
 * @param cx the compaction context, for the family and the reclamation floor
 * @param job the job being run, for its input ids and whether it writes the largest level
 * @param inputs the tables being merged
 * @param n_inputs how many
 * @param out receives a set the caller frees, or NULL when no input carries any
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the union could not be built
 */
int ce_union_intervals(const compaction_ctx_t *cx, const compaction_job_t *job,
                       sstable_t *const *inputs, int n_inputs, range_tombstone_set_t **out);

#endif /* __TIDESDB_COMPACTION_INTERNAL_H__ */
