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

/* byte-wise key order with a length tiebreak, matching the engine's memcmp ordering */
static int ce_key_cmp(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size)
{
    const size_t n = a_size < b_size ? a_size : b_size;
    /* a partition boundary is the min-key of an sstable, and one carrying nothing but an interval
     * tombstone has no key to name it with */
    const int c = n > 0 ? memcmp(a, b, n) : 0;
    if (c != 0) return c;
    if (a_size < b_size) return -1;
    return a_size > b_size ? 1 : 0;
}

/* the boundary partition a key falls in -- the count of boundaries at or below it */
static int ce_partition_of_key(const compaction_plan_t *p, const uint8_t *key, size_t key_size)
{
    int part = 0;
    while (part < p->n_boundaries &&
           ce_key_cmp(key, key_size, p->boundary_keys[part], p->boundary_sizes[part]) >= 0)
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
        for (int i = 0; i < snap->n_sstables; i++)
        {
            const compaction_sstable_info_t *s = &snap->sstables[i];
            if (s->level < x || s->level > z) continue;
            if (ce_partition_of_key(p, s->min_key, s->min_key_size) != part) continue;
            ids[cnt++] = s->id;
        }
        /* a partition holding one file has nothing to merge with, and rewriting it alone would be
         * work for no consolidation */
        if (cnt < 2) continue;

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
 * cumulative data across X..z, else the largest level */
static int ce_partitioned_target(const compaction_state_t *st, int x, const uint64_t *caps)
{
    uint64_t cumulative = st->size[x - 1];
    for (int z = x + 1; z <= st->num_levels; z++)
    {
        cumulative += st->size[z - 1];
        if (caps[z - 1] >= cumulative) return z;
    }
    return st->num_levels;
}

/* whether the tree should shed a level: its largest has shrunk to less than a size ratio's worth of
 * its own capacity, so the data now belongs one level up. the gap between this and the growth
 * condition -- growth at the capacity, shrink at a T-th of it -- is the hysteresis that stops a
 * tree oscillating between depths as it crosses a boundary.
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

    const uint64_t cap = caps[st->num_levels - 1];
    return cap > 0 && st->size[st->num_levels - 1] < cap / cfg->size_ratio;
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

/* whether any sstable is dense enough in tombstones to be worth rewriting on its own */
static int ce_density_due(const compaction_snapshot_t *snap, const compaction_planner_config_t *cfg)
{
    if (cfg->tombstone_density_trigger <= 0.0) return 0;
    for (int i = 0; i < snap->n_sstables; i++)
    {
        const compaction_sstable_info_t *s = &snap->sstables[i];
        if (s->entry_count < cfg->tombstone_density_min_entries || s->entry_count == 0) continue;
        if ((double)s->tombstone_count / (double)s->entry_count >= cfg->tombstone_density_trigger)
            return 1;
    }
    return 0;
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

    if (cfg->force || compaction_planner_triggered(&st, cfg, caps) || ce_density_due(snap, cfg))
    {
        rc = ce_plan_boundaries(p, snap, st.num_levels);

        if (rc == TDB_SUCCESS && st.num_levels < CE_MIN_TREE_LEVELS)
        {
            /* a single-level tree grows: consolidate the L1 tier into one run at the new L2 */
            rc = ce_emit_simple(p, snap, st.num_levels + 1, COMPACTION_SPLIT_NONE, file_max);
        }
        else if (rc == TDB_SUCCESS)
        {
            const int x = compaction_planner_dividing_level(&st, cfg);
            if (x >= 1 && caps[x - 1] > 0 && st.size[x - 1] >= caps[x - 1])
            {
                const int z = ce_partitioned_target(&st, x, caps);
                rc = ce_emit_partitioned(p, snap, x, z, file_max);
            }
            else
            {
                int target = compaction_planner_target_level(&st, cfg, caps);
                /* the tree evolves with the data it holds. when the merge would land in the largest
                 * level and that level is already at its capacity, it lands one level deeper
                 * instead, which is Spooky adding a level -- the step that keeps the level count at
                 * about log_T(N/B) and that dynamic capacity adaptation exists to bound the space
                 * cost of. without it a family stops deepening, the dividing level collapses onto
                 * the flush tier, and the tier grows a run per flush with nowhere to drain to */
                if (target == st.num_levels && st.num_levels < LEVEL_SET_MAX_LEVELS &&
                    caps[st.num_levels - 1] > 0 &&
                    st.size[st.num_levels - 1] >= caps[st.num_levels - 1])
                    target = st.num_levels + 1;
                rc = ce_emit_simple(
                    p, snap, target,
                    target == x ? COMPACTION_SPLIT_BOUNDARIES : COMPACTION_SPLIT_NONE, file_max);
            }
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
