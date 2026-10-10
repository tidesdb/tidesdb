/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "compaction_planner.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */

/* the shallowest tree Spooky's structure can exist in: the flush tier plus one level for merges to
 * land in. below this the dividing level would be the tier itself */
#define CE_MIN_TREE_LEVELS 2

/* the level every flush lands in, and the shallowest level a merge may write its output to. a
 * merge always reads the flush tier and always moves the data below it */
#define CE_FLUSH_TIER_LEVEL         1
#define CE_FIRST_MERGE_TARGET_LEVEL 2

/* T raised to a non-negative power, saturating at UINT64_MAX so a deep tree never wraps */
static uint64_t ce_pow(uint64_t base, int exp)
{
    uint64_t result = 1;
    for (int i = 0; i < exp; i++)
    {
        if (base != 0 && result > UINT64_MAX / base) return UINT64_MAX;
        result *= base;
    }
    return result;
}

void compaction_planner_capacities(const compaction_state_t *st,
                                   const compaction_planner_config_t *cfg, uint64_t *caps)
{
    const int l = st->num_levels;
    if (l <= 0) return;
    const uint64_t n_largest = st->size[l - 1];
    for (int i = 1; i <= l; i++)
    {
        if (i == l) /* the largest level keeps a geometric capacity C_L = base * T^(L-1) */
            caps[i - 1] = cfg->base_capacity * ce_pow(cfg->size_ratio, l - 1);
        else
        {
            /* DCA restricts a smaller level to a fraction of the largest level's data */
            const uint64_t divisor = ce_pow(cfg->size_ratio, l - i);
            caps[i - 1] = divisor == 0 ? 0 : n_largest / divisor;
        }
    }
}

int compaction_planner_dividing_level(const compaction_state_t *st,
                                      const compaction_planner_config_t *cfg)
{
    if (st->num_levels < 2) return 0;
    int x = st->num_levels - 1 - cfg->dividing_level_offset;
    if (x < 1) x = 1;
    if (x > st->num_levels - 1) x = st->num_levels - 1;
    return x;
}

int compaction_planner_target_level(const compaction_state_t *st,
                                    const compaction_planner_config_t *cfg, const uint64_t *caps)
{
    const int x = compaction_planner_dividing_level(st, cfg);
    if (x < 1) return st->num_levels; /* degenerate single-level tree */

    /* the smallest level whose capacity can hold everything at and below it, so merging there would
     * not overflow; if none in range can, the dividing level absorbs the merge.
     *
     * the search starts below the flush tier. L1 is where every flush lands, so a merge that
     * targets it reads the tier and writes it straight back: the files are consolidated but the
     * data never leaves, and L1 keeps growing one run per flush until some other trigger promotes
     * it. Spooky's preemptive merge picks a level in 1..L-1 and folds the flush tier into it -- the
     * tier is always an input and never the destination */
    uint64_t cumulative = st->size[CE_FLUSH_TIER_LEVEL - 1];
    for (int q = CE_FIRST_MERGE_TARGET_LEVEL; q <= x; q++)
    {
        cumulative += st->size[q - 1];
        if (caps[q - 1] >= cumulative) return q;
    }
    return x > CE_FIRST_MERGE_TARGET_LEVEL ? x : CE_FIRST_MERGE_TARGET_LEVEL;
}

int compaction_planner_triggered(const compaction_state_t *st,
                                 const compaction_planner_config_t *cfg, const uint64_t *caps)
{
    /* the L1 tier is due once it holds too many overlapping files */
    if (cfg->l1_file_count_trigger > 0 && st->file_count[0] >= cfg->l1_file_count_trigger) return 1;

    /* any level that has reached its capacity is due */
    for (int i = 1; i <= st->num_levels; i++)
        if (caps[i - 1] > 0 && st->size[i - 1] >= caps[i - 1]) return 1;

    return 0;
}

/* ===== job generation ===== */

/* how many job slots to grow the plan by at a time */
#define CE_PLAN_GROW 4

/* the plan owns its jobs and every array they reference so a single free tears it all down */
struct compaction_plan
{
    compaction_job_t *jobs;
    int n_jobs;
    int cap_jobs;
    uint64_t **id_arrays; /* one input_ids array per job, freed on plan free */
    int n_id_arrays;
    const uint8_t **boundary_keys; /* shared boundary pointers into boundary_bytes */
    size_t *boundary_sizes;
    uint8_t *boundary_bytes;
    int n_boundaries;
};

/* fold the per-sstable snapshot into the aggregate the decisions read */
static void ce_aggregate(const compaction_snapshot_t *snap, compaction_state_t *st)
{
    memset(st, 0, sizeof(*st));
    st->num_levels = snap->num_levels;
    for (int i = 0; i < snap->n_sstables; i++)
    {
        const int lv = snap->sstables[i].level;
        if (lv < 1 || lv > LEVEL_SET_MAX_LEVELS) continue;
        st->size[lv - 1] += snap->sstables[i].size;
        st->file_count[lv - 1]++;
    }
}

/* copy a run of input ids into the plan and hand back the owned array for a job to reference */
static uint64_t *ce_plan_keep_ids(compaction_plan_t *p, const uint64_t *ids, int n)
{
    uint64_t **grown = realloc(p->id_arrays, (size_t)(p->n_id_arrays + 1) * sizeof(*grown));
    if (!grown) return NULL;
    p->id_arrays = grown;
    uint64_t *copy = malloc((size_t)n * sizeof(*copy));
    if (!copy) return NULL;
    memcpy(copy, ids, (size_t)n * sizeof(*copy));
    p->id_arrays[p->n_id_arrays++] = copy;
    return copy;
}

/* append a job to the plan */
static int ce_plan_add(compaction_plan_t *p, const compaction_job_t *job)
{
    if (p->n_jobs == p->cap_jobs)
    {
        const int cap = p->cap_jobs + CE_PLAN_GROW;
        compaction_job_t *grown = realloc(p->jobs, (size_t)cap * sizeof(*grown));
        if (!grown) return TDB_ERR_MEMORY;
        p->jobs = grown;
        p->cap_jobs = cap;
    }
    p->jobs[p->n_jobs++] = *job;
    return TDB_SUCCESS;
}

/* collect the ids of every sstable at levels lo..hi into out, returning the count */
static int ce_ids_in_range(const compaction_snapshot_t *snap, int lo, int hi, uint64_t *out)
{
    int n = 0;
    for (int i = 0; i < snap->n_sstables; i++)
        if (snap->sstables[i].level >= lo && snap->sstables[i].level <= hi)
            out[n++] = snap->sstables[i].id;
    return n;
}

/* copy the largest level's file min-keys (past the first) into the plan as the partition
 * boundaries; output files split at these so each overlaps at most one largest-level file */
static int ce_plan_boundaries(compaction_plan_t *p, const compaction_snapshot_t *snap, int largest)
{
    /* gather the largest level's min-keys, sorted ascending by a simple insertion into an index
     * list */
    if (snap->n_sstables == 0) return TDB_SUCCESS;
    int *idx = malloc((size_t)snap->n_sstables * sizeof(*idx));
    if (!idx) return TDB_ERR_MEMORY;
    int count = 0;
    for (int i = 0; i < snap->n_sstables; i++)
        if (snap->sstables[i].level == largest) idx[count++] = i;
    for (int i = 1; i < count; i++)
        for (int j = i; j > 0; j--)
        {
            const compaction_sstable_info_t *a = &snap->sstables[idx[j]];
            const compaction_sstable_info_t *b = &snap->sstables[idx[j - 1]];
            const size_t n = a->min_key_size < b->min_key_size ? a->min_key_size : b->min_key_size;
            /* an sstable carrying nothing but an interval tombstone has no key to name, so its
             * bound is a null pointer of no length. memcmp declares both pointers non-null whatever
             * the count, and two keys sharing a prefix of nothing are equal over it, which is what
             * the size comparison below then settles */
            const int c = n ? memcmp(a->min_key, b->min_key, n) : 0;
            if (c < 0 || (c == 0 && a->min_key_size < b->min_key_size))
            {
                const int t = idx[j];
                idx[j] = idx[j - 1];
                idx[j - 1] = t;
            }
        }

    /* boundaries are the min-keys of files 2..count, so partition 0 holds the first file's range */
    p->n_boundaries = count > 1 ? count - 1 : 0;
    if (p->n_boundaries == 0)
    {
        free(idx);
        return TDB_SUCCESS;
    }

    size_t total = 0;
    for (int i = 1; i < count; i++) total += snap->sstables[idx[i]].min_key_size;
    /* an sstable carrying nothing but an interval tombstone has no key to name a boundary with, so
     * the bytes they need together can come to nothing. a zero-byte request may hand back NULL,
     * which the check below would take for exhaustion, so it always asks for something */
    p->boundary_bytes = malloc(total > 0 ? total : 1);
    p->boundary_keys = malloc((size_t)p->n_boundaries * sizeof(*p->boundary_keys));
    p->boundary_sizes = malloc((size_t)p->n_boundaries * sizeof(*p->boundary_sizes));
    if (!p->boundary_bytes || !p->boundary_keys || !p->boundary_sizes)
    {
        free(idx);
        return TDB_ERR_MEMORY;
    }

    size_t off = 0;
    for (int i = 1; i < count; i++)
    {
        const compaction_sstable_info_t *s = &snap->sstables[idx[i]];
        /* memcpy declares both pointers non-null whatever the length, and a boundary of no bytes
         * has none to name it with */
        if (s->min_key_size) memcpy(p->boundary_bytes + off, s->min_key, s->min_key_size);
        p->boundary_keys[i - 1] = p->boundary_bytes + off;
        p->boundary_sizes[i - 1] = s->min_key_size;
        off += s->min_key_size;
    }
    free(idx);
    return TDB_SUCCESS;
}

/* emit a single-output merge of levels 1..target into target */
uint64_t compaction_planner_output_file_max(uint64_t largest_level_bytes, uint64_t size_ratio)
{
    if (size_ratio == 0) return 0;
    const uint64_t cap = largest_level_bytes / size_ratio;
    return cap >= CE_MIN_OUTPUT_FILE_MAX_BYTES ? cap : 0;
}

static int ce_emit_simple(compaction_plan_t *p, const compaction_snapshot_t *snap, int target,
                          compaction_split_t split, uint64_t file_max)
{
    if (snap->n_sstables == 0) return TDB_SUCCESS;
    uint64_t *ids = malloc((size_t)snap->n_sstables * sizeof(*ids));
    if (!ids) return TDB_ERR_MEMORY;

    /* a merge into the target reads every level at and below it */
    const int hi = target <= snap->num_levels ? target : snap->num_levels;
    const int cnt = ce_ids_in_range(snap, 1, hi, ids);
    if (cnt == 0)
    {
        free(ids);
        return TDB_SUCCESS;
    }

    uint64_t *kept = ce_plan_keep_ids(p, ids, cnt);
    free(ids);
    if (!kept) return TDB_ERR_MEMORY;

    compaction_job_t job = {0};
    job.input_ids = kept;
    job.n_inputs = cnt;
    job.target_level = target;
    job.is_largest_level = target >= snap->num_levels;
    job.split = split;
    job.file_max = file_max;
    if (split == COMPACTION_SPLIT_BOUNDARIES)
    {
        job.boundaries = p->boundary_keys;
        job.boundary_sizes = p->boundary_sizes;
        job.n_boundaries = p->n_boundaries;
    }
    return ce_plan_add(p, &job);
}

/* the boundary partition a key falls in -- the count of boundaries at or below it */
static int ce_partition_of_key(const compaction_plan_t *p, const uint8_t *key, size_t key_size)
{
    int part = 0;
    while (part < p->n_boundaries &&
           tdb_key_cmp(key, key_size, p->boundary_keys[part], p->boundary_sizes[part]) >= 0)
        part++;
    return part;
}

/* whether every input in the merge range sits wholly inside one boundary partition, which is what
 * makes per-partition jobs disjoint. the largest level is partitioned to these boundaries by
 * construction and a dividing merge writes its output the same way, so this holds once the levels
 * above have been through one -- but a run flushed straight into the tier spans whatever its
 * memtable held, so it has to be checked rather than assumed */
static int ce_inputs_align_to_boundaries(const compaction_plan_t *p,
                                         const compaction_snapshot_t *snap, int x, int z)
{
    if (p->n_boundaries == 0) return 0;
    for (int i = 0; i < snap->n_sstables; i++)
    {
        const compaction_sstable_info_t *s = &snap->sstables[i];
        if (s->level < x || s->level > z) continue;
        if (!s->min_key || !s->max_key) return 0;
        if (ce_partition_of_key(p, s->min_key, s->min_key_size) !=
            ce_partition_of_key(p, s->max_key, s->max_key_size))
            return 0;
    }
    return 1;
}

/* emit one job per boundary partition, each holding only the inputs that fall inside it. this is
 * Spooky's partitioned merge proper -- one group of perfectly overlapping files at a time -- so the
 * jobs are disjoint by construction and may run at once, and a merge's transient space cost is one
 * partition rather than the whole of the levels it spans */
static int ce_emit_partition_jobs(compaction_plan_t *p, const compaction_snapshot_t *snap, int x,
                                  int z, uint64_t file_max)
{
    uint64_t *ids = malloc((size_t)snap->n_sstables * sizeof(*ids));
    if (!ids) return TDB_ERR_MEMORY;

    int rc = TDB_SUCCESS;
    for (int part = 0; part <= p->n_boundaries && rc == TDB_SUCCESS; part++)
    {
        int cnt = 0;
        int above = 0;
        for (int i = 0; i < snap->n_sstables; i++)
        {
            const compaction_sstable_info_t *s = &snap->sstables[i];
            if (s->level < x || s->level > z) continue;
            if (ce_partition_of_key(p, s->min_key, s->min_key_size) != part) continue;
            ids[cnt++] = s->id;
            if (s->level < z) above++;
        }
        /* a partition with nothing above the target has nothing to move, and rewriting what is
         * already there would be work for no consolidation. one file above it is still a move the
         * merge exists to make -- into an empty level that is every partition, and skipping them
         * plans nothing while the dividing level stays over its capacity for good */
        if (above == 0) continue;

        uint64_t *kept = ce_plan_keep_ids(p, ids, cnt);
        if (!kept)
        {
            rc = TDB_ERR_MEMORY;
            break;
        }
        compaction_job_t job = {0};
        job.input_ids = kept;
        job.n_inputs = cnt;
        job.target_level = z;
        job.is_largest_level = z >= snap->num_levels;
        job.split = COMPACTION_SPLIT_BOUNDARIES;
        job.file_max = file_max;
        job.boundaries = p->boundary_keys;
        job.boundary_sizes = p->boundary_sizes;
        job.n_boundaries = p->n_boundaries;
        rc = ce_plan_add(p, &job);
    }
    free(ids);
    return rc;
}

/* emit one merge of levels X..z whose output is split at the largest level's boundaries, so each
 * output file aligns to one largest-level file's range. every input is read in one job, which keeps
 * each key's whole version chain in a single merge; per-partition jobs would instead share any
 * spanning lower-level input, and since the executor removes a job's inputs atomically only the
 * first partition could run -- the rest would find the shared input gone and skip, dropping a
 * largest-level tombstone without the older versions it shadows and resurrecting the deleted key */
static int ce_emit_partitioned(compaction_plan_t *p, const compaction_snapshot_t *snap, int x,
                               int z, uint64_t file_max)
{
    if (snap->n_sstables == 0) return TDB_SUCCESS;

    /* when every input sits inside one partition the merge fans out into disjoint jobs that may run
     * concurrently. otherwise it stays one job over the whole range: per-partition jobs would share
     * an input spanning several of them, and since the executor removes a job's inputs atomically
     * only the first would run -- the rest would find the shared input gone and skip, dropping a
     * largest-level tombstone without the older versions it shadows */
    if (ce_inputs_align_to_boundaries(p, snap, x, z))
        return ce_emit_partition_jobs(p, snap, x, z, file_max);

    uint64_t *ids = malloc((size_t)snap->n_sstables * sizeof(*ids));
    if (!ids) return TDB_ERR_MEMORY;
    const int cnt = ce_ids_in_range(snap, x, z, ids);
    if (cnt == 0)
    {
        free(ids);
        return TDB_SUCCESS;
    }
    uint64_t *kept = ce_plan_keep_ids(p, ids, cnt);
    free(ids);
    if (!kept) return TDB_ERR_MEMORY;

    compaction_job_t job = {0};
    job.input_ids = kept;
    job.n_inputs = cnt;
    job.target_level = z;
    job.is_largest_level = z >= snap->num_levels;
    job.split = COMPACTION_SPLIT_BOUNDARIES;
    job.file_max = file_max;
    job.boundaries = p->boundary_keys;
    job.boundary_sizes = p->boundary_sizes;
    job.n_boundaries = p->n_boundaries;
    return ce_plan_add(p, &job);
}

/* the target level of a partitioned merge: the smallest level in X+1..L that can hold the
 * cumulative data across X..z. when not even the largest can, the merge lands in a new level below
 * it, which is how a tree of three or more levels deepens -- landing in the largest regardless
 * would leave it over its capacity for good, and every later dividing merge would rewrite the
 * whole of it */
static int ce_partitioned_target(const compaction_state_t *st, int x, const uint64_t *caps)
{
    uint64_t cumulative = st->size[x - 1];
    for (int z = x + 1; z <= st->num_levels; z++)
    {
        cumulative += st->size[z - 1];
        if (caps[z - 1] >= cumulative) return z;
    }
    return st->num_levels < LEVEL_SET_MAX_LEVELS ? st->num_levels + 1 : st->num_levels;
}

/* whether the tree should shed a level: its largest holds less than a size ratio's worth of the
 * capacity the level above would have as the largest, so the data now belongs one level up and
 * would sit there a whole size ratio below the point that grows it again.
 *
 * the gap is the hysteresis that stops a tree oscillating between depths. a level is added when the
 * largest reaches its capacity C_L, so the new largest starts out holding about C_L, which is
 * C_(L+1) / T. shedding at a T-th of the new largest's own capacity would therefore shed at the
 * very size the level was added at, and a growth merge that dropped any garbage at all would be
 * undone by the next plan, two whole rewrites for nothing.
 *
 * without it a tree that grew under load and then had most of its data deleted stays as deep as it
 * ever was, so every read keeps paying for levels that hold almost nothing
 * @param st the aggregate level state
 * @param cfg the family's planner configuration
 * @param caps the level capacities
 * @return non-zero when a level should be removed
 */
static int ce_shrink_due(const compaction_state_t *st, const compaction_planner_config_t *cfg,
                         const uint64_t *caps)
{
    if (cfg->size_ratio == 0) return 0;

    /* the floor the family was configured with, and never below the depth Spooky's structure needs
     * -- a flush tier plus a level for merges to land in */
    int floor_levels = cfg->min_levels > CE_MIN_TREE_LEVELS ? cfg->min_levels : CE_MIN_TREE_LEVELS;
    if (st->num_levels <= floor_levels) return 0;

    const uint64_t threshold = caps[st->num_levels - 1] / cfg->size_ratio / cfg->size_ratio;
    return threshold > 0 && st->size[st->num_levels - 1] < threshold;
}

/* merge the largest level and the one above it into a single run one level up, which removes the
 * deepest level. both are inputs because levels below the flush tier hold non-overlapping runs --
 * moving the largest level's files into a level that already holds files would leave two runs
 * overlapping at one level, and a read there would have to consult both */
static int ce_emit_shrink(compaction_plan_t *p, const compaction_snapshot_t *snap,
                          uint64_t file_max)
{
    const int largest = snap->num_levels;
    if (largest < CE_MIN_TREE_LEVELS + 1 || snap->n_sstables == 0) return TDB_SUCCESS;

    uint64_t *ids = malloc((size_t)snap->n_sstables * sizeof(*ids));
    if (!ids) return TDB_ERR_MEMORY;
    const int cnt = ce_ids_in_range(snap, largest - 1, largest, ids);
    if (cnt == 0)
    {
        free(ids);
        return TDB_SUCCESS;
    }
    uint64_t *kept = ce_plan_keep_ids(p, ids, cnt);
    free(ids);
    if (!kept) return TDB_ERR_MEMORY;

    compaction_job_t job = {0};
    job.input_ids = kept;
    job.n_inputs = cnt;
    job.target_level = largest - 1;
    /* the target becomes the deepest level once this lands, but the merge does not include every
     * sstable that could hold a key, so it does not claim the standing of one that does */
    job.is_largest_level = 0;
    job.split = COMPACTION_SPLIT_NONE;
    job.file_max = file_max;
    return ce_plan_add(p, &job);
}

/* the fraction of an sstable's entries that are tombstones, or zero when it is too small to judge
 */
static double ce_density(const compaction_sstable_info_t *s, const compaction_planner_config_t *cfg)
{
    if (cfg->tombstone_density_trigger <= 0.0) return 0.0;
    if (s->entry_count < cfg->tombstone_density_min_entries || s->entry_count == 0) return 0.0;
    const double density = (double)s->tombstone_count / (double)s->entry_count;
    return density >= cfg->tombstone_density_trigger ? density : 0.0;
}

/* whether a file in the flush tier is dense enough in tombstones to be worth merging. any merge
 * the tier is part of moves it below, so the ordinary plan serves */
static int ce_tier_density_due(const compaction_snapshot_t *snap,
                               const compaction_planner_config_t *cfg)
{
    for (int i = 0; i < snap->n_sstables; i++)
        if (snap->sstables[i].level == CE_FLUSH_TIER_LEVEL &&
            ce_density(&snap->sstables[i], cfg) > 0)
            return 1;
    return 0;
}

/* whether a table sits between the flush tier and the largest level dense enough in tombstones to
 * move down. a table at the largest level is left out, since a tombstone it still holds is one its
 * own merge could not drop -- a reader below the floor or a sibling reaching into its key -- and
 * rewriting it alone would keep the same tombstones and be planned again on the next pass. the next
 * merge into the largest level rewrites it anyway */
static int ce_mid_table_dense(const compaction_snapshot_t *snap, int i,
                              const compaction_planner_config_t *cfg)
{
    const compaction_sstable_info_t *s = &snap->sstables[i];
    return s->level > CE_FLUSH_TIER_LEVEL && s->level < snap->num_levels && ce_density(s, cfg) > 0;
}

/* whether any table is dense enough to move down */
static int ce_any_mid_table_dense(const compaction_snapshot_t *snap,
                                  const compaction_planner_config_t *cfg)
{
    for (int i = 0; i < snap->n_sstables; i++)
        if (ce_mid_table_dense(snap, i, cfg)) return 1;
    return 0;
}

/* whether two key ranges meet. a table that records no bounds holds only an interval and is taken
 * to meet everything, so a merge built from this includes it rather than leaving it behind */
static int ce_ranges_meet(const compaction_sstable_info_t *a, const compaction_sstable_info_t *b)
{
    if (!a->min_key || !a->max_key || !b->min_key || !b->max_key) return 1;
    return tdb_key_cmp(a->min_key, a->min_key_size, b->max_key, b->max_key_size) <= 0 &&
           tdb_key_cmp(b->min_key, b->min_key_size, a->max_key, a->max_key_size) <= 0;
}

/* gather a dense table and every table one level down that its range meets into ids, returning the
 * count, or 0 when any of them is already an input of a job in this plan. taken marks the tables
 * earlier jobs claimed, so the jobs a plan emits share no input and may run at once */
static int ce_density_inputs(const compaction_snapshot_t *snap, int dense, const uint8_t *taken,
                             uint64_t *ids)
{
    const compaction_sstable_info_t *d = &snap->sstables[dense];
    if (taken[dense]) return 0;
    int cnt = 0;
    ids[cnt++] = d->id;
    for (int i = 0; i < snap->n_sstables; i++)
    {
        if (snap->sstables[i].level != d->level + 1 || !ce_ranges_meet(d, &snap->sstables[i]))
            continue;
        if (taken[i]) return 0;
        ids[cnt++] = snap->sstables[i].id;
    }
    return cnt;
}

/* mark every table a job just claimed, so no later job in the plan takes it as well */
static void ce_density_take(const compaction_snapshot_t *snap, const uint64_t *ids, int cnt,
                            uint8_t *taken)
{
    for (int i = 0; i < snap->n_sstables; i++)
        for (int k = 0; k < cnt; k++)
            if (snap->sstables[i].id == ids[k]) taken[i] = 1;
}

/* merge one table dense in tombstones one level down, together with every table there its range
 * meets. a tombstone drops only at the largest level, so writing the table back into its own level
 * would keep each one, leave the table exactly as dense, and plan the same merge on every pass.
 * moving it down is progress each time, and the tombstones drop once it reaches the largest level.
 *
 * the level below is a non-overlapping run, and every table there that meets the moving table's
 * range is taken, so the outputs replace exactly the span they cover and the run stays
 * non-overlapping. the tables left at the dense table's level do not meet its range, and everything
 * shallower is newer, so deeper stays older for every key */
static int ce_emit_density_job(compaction_plan_t *p, const compaction_snapshot_t *snap, int target,
                               const uint64_t *ids, int cnt, int x, uint64_t file_max)
{
    uint64_t *kept = ce_plan_keep_ids(p, ids, cnt);
    if (!kept) return TDB_ERR_MEMORY;

    compaction_job_t job = {0};
    job.input_ids = kept;
    job.n_inputs = cnt;
    job.target_level = target;
    job.is_largest_level = target >= snap->num_levels;
    job.split = target >= x ? COMPACTION_SPLIT_BOUNDARIES : COMPACTION_SPLIT_NONE;
    job.file_max = file_max;
    if (job.split == COMPACTION_SPLIT_BOUNDARIES)
    {
        job.boundaries = p->boundary_keys;
        job.boundary_sizes = p->boundary_sizes;
        job.n_boundaries = p->n_boundaries;
    }
    return ce_plan_add(p, &job);
}

/* move every dense table down that can move without sharing an input, one job each. a store that
 * deleted most of its data has a dense table in most partitions, and moving them one plan at a time
 * would take a scheduler pass per table to give back what the deletes freed. tables are taken
 * shallowest first, so a dense table whose level below is itself moving waits for the next plan
 * rather than racing it */
static int ce_emit_density(compaction_plan_t *p, const compaction_snapshot_t *snap,
                           const compaction_planner_config_t *cfg, int x, uint64_t file_max)
{
    uint64_t *ids = malloc((size_t)snap->n_sstables * sizeof(*ids));
    uint8_t *taken = calloc((size_t)snap->n_sstables, sizeof(*taken));
    if (!ids || !taken)
    {
        free(ids);
        free(taken);
        return TDB_ERR_MEMORY;
    }

    int rc = TDB_SUCCESS;
    for (int level = CE_FLUSH_TIER_LEVEL + 1; level < snap->num_levels && rc == TDB_SUCCESS;
         level++)
        for (int i = 0; i < snap->n_sstables && rc == TDB_SUCCESS; i++)
        {
            if (snap->sstables[i].level != level) continue;
            if (!ce_mid_table_dense(snap, i, cfg)) continue;
            const int cnt = ce_density_inputs(snap, i, taken, ids);
            if (cnt == 0) continue;
            ce_density_take(snap, ids, cnt, taken);
            rc = ce_emit_density_job(p, snap, level + 1, ids, cnt, x, file_max);
        }

    free(ids);
    free(taken);
    return rc;
}

/* whether a merge of every level down to target would carry anything into it from above */
static int ce_moves_into(const compaction_snapshot_t *snap, int target)
{
    for (int i = 0; i < snap->n_sstables; i++)
        if (snap->sstables[i].level >= CE_FLUSH_TIER_LEVEL && snap->sstables[i].level < target)
            return 1;
    return 0;
}

/* the merge to plan when the ordinary one would move nothing. a merge with nothing above its target
 * reads that level and writes it straight back -- the same data in the same place, and planned
 * again on the next pass if a trigger made it due, since nothing it did changes what the trigger
 * sees. so the shallowest level holding anything moves down instead, into the smallest level below
 * that can hold it, which is the dividing merge's choice made from that level.
 *
 * when the largest level is the only one holding anything there is nowhere below to move to. it
 * grows into a new level if it is over its capacity, and a forced pass rewrites it in place, which
 * is what collects the versions and tombstones below the floor -- a caller asked for that pass, so
 * it is not repeated unless asked again */
static int ce_plan_descent(compaction_plan_t *p, const compaction_snapshot_t *snap,
                           const compaction_planner_config_t *cfg, const compaction_state_t *st,
                           const uint64_t *caps, uint64_t file_max)
{
    const int largest = st->num_levels;
    int shallowest = 0;
    for (int lv = CE_FLUSH_TIER_LEVEL; lv <= largest && shallowest == 0; lv++)
        if (st->file_count[lv - 1] > 0) shallowest = lv;
    if (shallowest == 0) return TDB_SUCCESS;

    if (shallowest < largest)
        return ce_emit_partitioned(p, snap, shallowest, ce_partitioned_target(st, shallowest, caps),
                                   file_max);
    if (largest < LEVEL_SET_MAX_LEVELS && caps[largest - 1] > 0 &&
        st->size[largest - 1] >= caps[largest - 1])
        return ce_emit_partitioned(p, snap, largest, largest + 1, file_max);
    if (cfg->force) return ce_emit_simple(p, snap, largest, COMPACTION_SPLIT_BOUNDARIES, file_max);
    return TDB_SUCCESS;
}

/* plan the merge a trigger made due -- the tier into a new level for a single-level tree, a
 * partitioned merge when the dividing level is full, else a merge of the small levels into the
 * smallest that holds them */
static int ce_plan_due(compaction_plan_t *p, const compaction_snapshot_t *snap,
                       const compaction_planner_config_t *cfg, const compaction_state_t *st,
                       const uint64_t *caps, uint64_t file_max)
{
    int rc = ce_plan_boundaries(p, snap, st->num_levels);
    if (rc != TDB_SUCCESS) return rc;

    /* a single-level tree grows: consolidate the L1 tier into one run at the new L2 */
    if (st->num_levels < CE_MIN_TREE_LEVELS)
        return ce_emit_simple(p, snap, st->num_levels + 1, COMPACTION_SPLIT_NONE, file_max);

    const int x = compaction_planner_dividing_level(st, cfg);
    if (x >= 1 && caps[x - 1] > 0 && st->size[x - 1] >= caps[x - 1])
        return ce_emit_partitioned(p, snap, x, ce_partitioned_target(st, x, caps), file_max);

    int target = compaction_planner_target_level(st, cfg, caps);
    /* the tree evolves with the data it holds. when the merge would land in the largest level and
     * that level is already at its capacity, it lands one level deeper instead, which is Spooky
     * adding a level -- the step that keeps the level count at about log_T(N/B) and that dynamic
     * capacity adaptation exists to bound the space cost of. without it a family stops deepening,
     * the dividing level collapses onto the flush tier, and the tier grows a run per flush with
     * nowhere to drain to. this is the two-level case, where the target can be the largest level;
     * a deeper tree grows through the partitioned merge's target instead */
    if (target == st->num_levels && st->num_levels < LEVEL_SET_MAX_LEVELS &&
        caps[st->num_levels - 1] > 0 && st->size[st->num_levels - 1] >= caps[st->num_levels - 1])
        target = st->num_levels + 1;
    if (!ce_moves_into(snap, target)) return ce_plan_descent(p, snap, cfg, st, caps, file_max);
    return ce_emit_simple(p, snap, target,
                          target == x ? COMPACTION_SPLIT_BOUNDARIES : COMPACTION_SPLIT_NONE,
                          file_max);
}

int compaction_planner_plan(const compaction_snapshot_t *snap,
                            const compaction_planner_config_t *cfg, compaction_plan_t **out)
{
    if (!snap || !cfg || !out) return TDB_ERR_INVALID_ARGS;

    compaction_plan_t *p = calloc(1, sizeof(*p));
    if (!p) return TDB_ERR_MEMORY;

    compaction_state_t st;
    ce_aggregate(snap, &st);
    uint64_t caps[LEVEL_SET_MAX_LEVELS];
    compaction_planner_capacities(&st, cfg, caps);
    const uint64_t file_max = st.num_levels > 0 ? compaction_planner_output_file_max(
                                                      st.size[st.num_levels - 1], cfg->size_ratio)
                                                : 0;

    int rc = TDB_SUCCESS;
    /* shedding a level is judged on its own, not behind the backlog triggers: a family that had
     * most of its data deleted has no level at capacity and nothing overdue, which is exactly the
     * state an over-deep tree gets stuck in */
    const int shrink = ce_shrink_due(&st, cfg, caps);
    if (shrink)
    {
        rc = ce_emit_shrink(p, snap, file_max);
        if (rc != TDB_SUCCESS)
        {
            compaction_plan_free(p);
            return rc;
        }
        *out = p;
        return TDB_SUCCESS;
    }

    if (cfg->force || compaction_planner_triggered(&st, cfg, caps) ||
        ce_tier_density_due(snap, cfg))
    {
        rc = ce_plan_due(p, snap, cfg, &st, caps, file_max);
    }
    else
    {
        /* density alone, below the flush tier, moves each dense table one level down */
        if (ce_any_mid_table_dense(snap, cfg))
        {
            rc = ce_plan_boundaries(p, snap, st.num_levels);
            if (rc == TDB_SUCCESS)
                rc = ce_emit_density(p, snap, cfg, compaction_planner_dividing_level(&st, cfg),
                                     file_max);
        }
    }

    if (rc != TDB_SUCCESS)
    {
        compaction_plan_free(p);
        return rc;
    }

    /* a lone job carries the whole step, so the executor may spread its key range across threads.
     * a plan that emitted several is already spread -- those jobs are disjoint and run at once, and
     * letting each subdivide as well would multiply the thread count by the partition count */
    if (p->n_jobs == 1 && p->jobs[0].n_boundaries > 0) p->jobs[0].may_subdivide = 1;

    *out = p;
    return TDB_SUCCESS;
}

int compaction_plan_job_count(const compaction_plan_t *plan)
{
    return plan ? plan->n_jobs : 0;
}

const compaction_job_t *compaction_plan_job(const compaction_plan_t *plan, int index)
{
    if (!plan || index < 0 || index >= plan->n_jobs) return NULL;
    return &plan->jobs[index];
}

void compaction_plan_free(compaction_plan_t *plan)
{
    if (!plan) return;
    for (int i = 0; i < plan->n_id_arrays; i++) free(plan->id_arrays[i]);
    free(plan->id_arrays);
    free(plan->jobs);
    free(plan->boundary_keys);
    free(plan->boundary_sizes);
    free(plan->boundary_bytes);
    free(plan);
}
