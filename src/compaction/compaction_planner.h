/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_COMPACTION_PLANNER_H__
#define __TIDESDB_COMPACTION_PLANNER_H__

#include "column_family/level/level_set.h" /* LEVEL_SET_MAX_LEVELS */
#include "compaction_job.h"
#include "compat.h"

/* the planner is the pure, deterministic core of Spooky compaction. given only a snapshot of the
 * level sizes and counts and the cf config, it computes the DCA capacities, the dividing level, the
 * target of the next merge, and whether any trigger is due -- no IO, no handles, no clock, so the
 * same snapshot always yields the same answer. these decisions feed the job generation. levels are
 * 1-based; the arrays index them at level-1. */

/* the aggregate level state the decisions run over */
typedef struct
{
    uint64_t size[LEVEL_SET_MAX_LEVELS]; /* N_i, bytes at level i, index 0 = L1 */
    int file_count[LEVEL_SET_MAX_LEVELS];
    int num_levels; /* the largest live level, also the live level count */
} compaction_state_t;

/* an output is never capped below this, so a young tree does not split into many tiny files */
#define CE_MIN_OUTPUT_FILE_MAX_BYTES (1024 * 1024)

/**
 * compaction_planner_output_file_max
 * the cap on a single output file, a fraction of the largest level's data so that a file a later
 * merge must rewrite stays proportional to the level holding it. a young tree whose largest level
 * is nearly empty would derive a cap of a few hundred bytes and split every entry into its own
 * file, so a cap below CE_MIN_OUTPUT_FILE_MAX_BYTES is reported as no cap
 * @param largest_level_bytes N_L, the bytes held by the largest live level
 * @param size_ratio T, the level size ratio
 * @return the cap in klog bytes, or 0 for no cap
 */
uint64_t compaction_planner_output_file_max(uint64_t largest_level_bytes, uint64_t size_ratio);

/* the planner's slice of the cf config */
typedef struct
{
    uint64_t size_ratio;       /* T, the level size ratio */
    int dividing_level_offset; /* selects the dividing level X = num_levels - 1 - offset */
    int min_levels;            /* the cf never shrinks below this many levels (clamped to >= 1) */
    int l1_file_count_trigger; /* L1 file count at or above which a compaction is due */
    double tombstone_density_trigger; /* tombstone fraction at or above which an sstable is due */
    uint64_t
        tombstone_density_min_entries; /* an sstable is judged by density only past this size */
    uint64_t base_capacity;            /* C_1, the L1 capacity in bytes */
    int force; /* plan a merge even when no trigger is due, for a manual compaction */
} compaction_planner_config_t;

/**
 * compaction_planner_capacities
 * compute the DCA capacities C_1..C_L into caps (index 0 = C_1): the largest level's capacity is
 * the geometric base * T^(L-1), and every smaller level is restricted to N_L / T^(L-i) so durable
 * space-amplification stays bounded
 * @param st the level state
 * @param cfg the config
 * @param caps out -- capacities C_1..C_L at indices 0..num_levels-1
 */
void compaction_planner_capacities(const compaction_state_t *st,
                                   const compaction_planner_config_t *cfg, uint64_t *caps);

/**
 * compaction_planner_dividing_level
 * the dividing level X, the smallest level whose merges partition their output by the largest
 * level's boundaries, clamped to the range 1..num_levels-1
 * @param st the level state
 * @param cfg the config
 * @return X, a 1-based level, or 0 when there are fewer than two levels
 */
int compaction_planner_dividing_level(const compaction_state_t *st,
                                      const compaction_planner_config_t *cfg);

/**
 * compaction_planner_target_level
 * the target level of the next small-level merge: the smallest level q in 1..X whose capacity can
 * accommodate the cumulative data at levels 1..q, so merging them there would not overflow it. this
 * is the accommodating level (C_q >= cumulative), following Spooky's prose rather than its inverted
 * pseudocode; when none in range accommodates, the dividing level X is returned
 * @param st the level state
 * @param cfg the config
 * @param caps the capacities from compaction_planner_capacities
 * @return the target level, a 1-based level in 1..X
 */
int compaction_planner_target_level(const compaction_state_t *st,
                                    const compaction_planner_config_t *cfg, const uint64_t *caps);

/**
 * compaction_planner_triggered
 * whether a compaction is due: the L1 tier has reached its file-count trigger, or some level has
 * reached its capacity
 * @param st the level state
 * @param cfg the config
 * @param caps the capacities from compaction_planner_capacities
 * @return 1 when a compaction is due, 0 otherwise
 */
int compaction_planner_triggered(const compaction_state_t *st,
                                 const compaction_planner_config_t *cfg, const uint64_t *caps);

/* ===== job generation ===== */

/**
 * compaction_sstable_info_t
 * one sstable in the level snapshot the job generation reads; the key pointers are borrowed only
 * for the duration of the plan call, which copies what it keeps
 * @param id the sstable id
 * @param level the 1-based level it currently sits at
 * @param size its on-disk size in bytes
 * @param min_key its smallest key
 * @param min_key_size length of min_key
 * @param max_key its largest key
 * @param max_key_size length of max_key
 * @param entry_count total entries
 * @param tombstone_count tombstone entries
 */
typedef struct
{
    uint64_t id;
    int level;
    uint64_t size;
    const uint8_t *min_key;
    size_t min_key_size;
    const uint8_t *max_key;
    size_t max_key_size;
    uint64_t entry_count;
    uint64_t tombstone_count;
} compaction_sstable_info_t;

/**
 * compaction_snapshot_t
 * the level snapshot the job generation reads
 * @param sstables the sstables across all levels, in any order
 * @param n_sstables the number of sstables
 * @param num_levels the largest live level, the live level count
 */
typedef struct
{
    const compaction_sstable_info_t *sstables;
    int n_sstables;
    int num_levels;
} compaction_snapshot_t;

typedef struct compaction_plan compaction_plan_t;

/**
 * compaction_planner_plan
 * produce the jobs the current snapshot calls for -- an empty plan when nothing is due, one job for
 * a full preemptive or dividing merge into the target level, or one job per partition for a
 * partitioned merge draining the dividing level. deterministic: the same snapshot always yields the
 * same plan
 * @param snap the level snapshot
 * @param cfg the config
 * @param out out -- the plan on success, owned by the caller (freed by compaction_plan_free)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int compaction_planner_plan(const compaction_snapshot_t *snap,
                            const compaction_planner_config_t *cfg, compaction_plan_t **out);

/**
 * compaction_plan_job_count
 * the number of jobs in the plan
 * @param plan the plan
 * @return the job count, or 0 when plan is NULL
 */
int compaction_plan_job_count(const compaction_plan_t *plan);

/**
 * compaction_plan_job
 * borrow the job at an index; the job and its arrays live until compaction_plan_free
 * @param plan the plan
 * @param index the job index
 * @return the job, or NULL when out of range
 */
const compaction_job_t *compaction_plan_job(const compaction_plan_t *plan, int index);

/**
 * compaction_plan_free
 * free the plan and every array its jobs reference; safe on NULL
 * @param plan the plan, may be NULL
 */
void compaction_plan_free(compaction_plan_t *plan);

#endif /* __TIDESDB_COMPACTION_PLANNER_H__ */
