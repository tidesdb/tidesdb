/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "base/bg_pool.h"
#include "base/errors.h"
#include "base/log.h"
#include "column_family/level/level_set.h"
#include "compaction/compaction_exec.h"
#include "compaction/compaction_job.h"
#include "compaction/compaction_planner.h"
#include "compat.h" /* usleep */
#include "engine/engine.h"
#include "io/block_manager.h"
#include "memtable/memtable.h" /* tidesdb_l0_queue_depth */
#include "sstable/sstable.h"

/* the compaction scheduler. a backstop ticker plans each column family from a snapshot of its level
 * set, leaving the pure planner to decide whether anything is due, enqueues the jobs that come
 * back, and a worker pool runs them through compaction_exec at the current gc floor. a per-cf
 * compacting flag caps each family at one compaction in flight, which also gives a drop something
 * to wait on. a flush wakes the ticker for responsiveness; the interval is the starvation backstop.
 */

/* the threadmanager labels and the backstop interval */
#define ENGINE_COMPACTION_POOL_LABEL  "compaction"
#define ENGINE_COMPACTION_SCHED_LABEL "reaper.compaction_backstop"
#define ENGINE_COMPACTION_INTERVAL_US 1000000 /* replan every second even without a flush wake */

/* a value-log reclaim is enqueued once a compaction has dropped at least this many estimated value
 * bytes, so a tiny log is left alone whatever share of it is dead */
#define ENGINE_VLOG_GC_MIN_DEAD_BYTES (4 * 1024 * 1024)

/* the kind of unit dequeued from the compaction queue: a per-cf merge, or a db-global value-log
 * reclaim */
typedef enum
{
    ENGINE_WORK_COMPACTION = 0,
    ENGINE_WORK_VLOG_GC
} engine_work_kind_t;

/* one plan's jobs, shared by the work units that run them. a plan whose jobs are disjoint is
 * enqueued as one unit per job so the pool runs them at once rather than one worker walking them in
 * turn -- a family with several partitions to merge otherwise drains at the rate of a single thread
 * while the rest of the pool idles. the last job to finish owns the teardown: it frees the plan and
 * releases the family's claim, so neither happens while another job is still reading them */
typedef struct
{
    compaction_plan_t *plan;
    cf_t *cf;
    _Atomic(int) remaining;
} engine_job_group_t;

/* a unit of queued work -- a compaction runs one job of its group against cf; a value log reclaim
 * carries neither and reclaims the db-global vlog */
typedef struct
{
    engine_work_kind_t kind;
    cf_t *cf;
    engine_job_group_t *group;
    int job_index;
} engine_compaction_work_t;

/* pay one job's share of a group and tear it down when the last is out. both the worker that ran a
 * job and a unit discarded by a drain go through here, or a drain would leave the plan leaked and
 * the family claimed for the life of the process */
static void engine_job_group_release(engine_job_group_t *group)
{
    if (!group) return;
    if (atomic_fetch_sub_explicit(&group->remaining, 1, memory_order_acq_rel) != 1) return;
    compaction_plan_free(group->plan);
    atomic_store_explicit(&group->cf->compacting, 0, memory_order_release);
    free(group);
}

/* fold the cf config into the planner config; the L1 base capacity is one flush's worth of data.
 * force plans a merge even when no trigger is due, for a manual compaction */
static compaction_planner_config_t engine_planner_config(const tidesdb_t *db, const cf_t *cf,
                                                         int force)
{
    compaction_planner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* one snapshot for every knob, so a plan is made against a single configuration rather than a
     * mix of the one before a reconfigure and the one after */
    tidesdb_column_family_config_t cc;
    cf_config_get(cf, &cc);
    cfg.size_ratio = cc.level_size_ratio;
    cfg.dividing_level_offset = cc.dividing_level_offset;
    cfg.min_levels = cc.min_levels;
    cfg.l1_file_count_trigger = cc.l1_file_count_trigger;
    cfg.tombstone_density_trigger = cc.tombstone_density_trigger;
    cfg.tombstone_density_min_entries = cc.tombstone_density_min_entries;
    cfg.base_capacity = db->config.memtable_write_buffer_size;
    cfg.force = force;
    return cfg;
}

/* snapshot the cf's level set, fold it into a planner snapshot, and produce its plan (which may
 * hold no jobs). the snapshot references are dropped here; the plan copied what it keeps. out_rc,
 * when given, distinguishes why no plan came back, since a caller that reports the failure must not
 * describe contention as an allocation failure */
static compaction_plan_t *engine_plan_cf(const tidesdb_t *db, cf_t *cf, int force, int *out_rc)
{
    if (out_rc) *out_rc = TDB_SUCCESS;
    const int total = level_set_snapshot(cf->levels, NULL, 0);
    level_set_snapshot_entry_t *refs = calloc(total ? (size_t)total : 1, sizeof(*refs));
    compaction_sstable_info_t *info = calloc(total ? (size_t)total : 1, sizeof(*info));
    if (!refs || !info)
    {
        free(refs);
        free(info);
        if (out_rc) *out_rc = TDB_ERR_MEMORY;
        return NULL;
    }
    if (total > 0 && level_set_snapshot(cf->levels, refs, total) != total)
    {
        /* a layout that grew past the array referenced nothing, but one that shrank referenced what
         * it did fill -- and those references are this call's to drop. leaking them here pins every
         * sstable the family held at that instant for the life of the process, so a superseded one
         * can never be closed and its file never unlinked. the entries are zeroed, so the ones a
         * grow left untouched are skipped */
        for (int i = 0; i < total; i++)
            if (refs[i].sst && sstable_unref(refs[i].sst)) sstable_close(refs[i].sst);
        free(refs);
        free(info);
        /* the layout moved between sizing and filling, so this is transient contention and a later
         * pass plans cleanly */
        if (out_rc) *out_rc = TDB_ERR_LOCKED;
        return NULL;
    }

    int num_levels = 0;
    for (int i = 0; i < total; i++)
    {
        const sstable_t *s = refs[i].sst;
        info[i].id = s->id;
        info[i].level = refs[i].level;
        info[i].size = refs[i].size_bytes;
        info[i].min_key = s->min_key;
        info[i].min_key_size = s->min_key_size;
        info[i].max_key = s->max_key;
        info[i].max_key_size = s->max_key_size;
        info[i].entry_count = s->distinct_key_count;
        info[i].tombstone_count = s->tombstone_count;
        if (refs[i].level > num_levels) num_levels = refs[i].level;
    }

    const compaction_snapshot_t snap = {
        .sstables = info, .n_sstables = total, .num_levels = num_levels};
    const compaction_planner_config_t cfg = engine_planner_config(db, cf, force);
    compaction_plan_t *plan = NULL;
    const int prc = compaction_planner_plan(&snap, &cfg, &plan);
    if (prc != TDB_SUCCESS)
    {
        plan = NULL;
        if (out_rc) *out_rc = prc;
    }

    for (int i = 0; i < total; i++)
        if (sstable_unref(refs[i].sst)) sstable_close(refs[i].sst);
    free(refs);
    free(info);
    return plan;
}

/* queue a value-log reclaim when enough dead bytes have accumulated; defined below, declared here
 * because the scheduler tick asks for one too */
static void engine_maybe_enqueue_vlog_gc(tidesdb_t *db);

/* plan a cf already claimed for compaction (its compacting flag is set): enqueue the plan when it
 * has jobs, otherwise release the claim so a later tick can reconsider it */
static void engine_schedule_claimed_cf(tidesdb_t *db, cf_t *cf)
{
    /* a plan is a pure function of the level set's shape and the family's configuration, so a
     * family whose layout has not moved since the last tick would produce the very same plan.
     * planning it again means referencing and releasing every sstable it owns and copying their
     * metadata, once a second, for every family -- a cost that grows with the database and buys
     * nothing. the generation moves on every published layout, and a configuration update resets
     * it, so the two inputs that could change a plan both force a fresh one */
    const uint64_t generation = level_set_generation(cf->levels);
    const uint64_t gc_floor = tidesdb_txn_registry_min_snapshot(db->txn_registry);
    if (generation == cf->planned_generation && gc_floor == cf->planned_gc_floor)
    {
        atomic_store_explicit(&cf->compacting, 0, memory_order_release);
        return;
    }

    /* the backstop scheduler has no caller to report to and simply retries on the next tick, so the
     * reason a plan did not come back is not needed here */
    compaction_plan_t *plan = engine_plan_cf(db, cf, 0, NULL);
    const int n = plan ? compaction_plan_job_count(plan) : 0;

    /* the memo means this shape, at this floor, produced nothing worth doing -- so it is recorded
     * only when the plan really came back empty. a plan that produced jobs is deliberately left
     * unrecorded: if they run, the layout moves and the memo would not have applied anyway, and if
     * they fail the layout does not move, so recording it here would retire the family from
     * scheduling until something else wrote to it. on an idle database that is forever.
     *
     * the emptiness is read from the job count directly. deriving it from whether an allocation
     * succeeded would mean a failed malloc memoized a family that did have work, which is that same
     * permanent retirement reached through a path nothing would report */
    if (plan && n == 0)
    {
        cf->planned_generation = generation;
        cf->planned_gc_floor = gc_floor;
        TDB_DEBUG_LOG(TDB_LOG_TRACE, "compaction planned nothing for cf %s at generation %llu",
                      cf->name, (unsigned long long)generation);
    }
    if (n > 0)
    {
        engine_job_group_t *group = malloc(sizeof(*group));
        if (group)
        {
            group->plan = plan;
            group->cf = cf;
            atomic_init(&group->remaining, n);

            /* enqueued after the group is fully built, so a worker that dequeues the first unit
             * never reads a half-initialized group */
            int queued = 0;
            for (int i = 0; i < n; i++)
            {
                engine_compaction_work_t *unit = malloc(sizeof(*unit));
                if (!unit) break;
                unit->kind = ENGINE_WORK_COMPACTION;
                unit->cf = cf;
                unit->group = group;
                unit->job_index = i;
                if (queue_enqueue(db->compaction_queue, unit) != 0)
                {
                    free(unit);
                    break;
                }
                queued++;
            }
            if (queued == n) return;

            /* some units never made it onto the queue, so their share of the count would never be
             * paid and the teardown would never run. pay each missing one off here rather than
             * storing the total: a worker can already have finished a queued unit, and a store
             * would discard that decrement, leaving a count nothing can drive to zero -- the plan
             * leaked and the family claimed for the life of the process. releasing instead lands
             * on exactly n payments however the two sides interleave, and whichever pays last
             * tears the group down */
            for (int i = queued; i < n; i++) engine_job_group_release(group);
            return;
        }
    }
    compaction_plan_free(plan);
    atomic_store_explicit(&cf->compacting, 0, memory_order_release);
}

/* the backstop scheduler tick: claim each idle cf (compacting 0->1) against a borrowed view, then
 * plan each once the borrow is given back. the claim is what protects the cf from being freed by a
 * concurrent drop, which waits the flag out */
static void engine_compaction_scheduler_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;

    /* the tick already scans the live transactions for its own gc floor, so publishing the answer
     * here costs nothing and gives the commit path a minimum it can read with one load. a commit
     * cannot run the scan itself -- it would be every registry shard, once per written key */
    tidesdb_txn_registry_publish_min_snapshot(db->txn_registry);

    cf_t **live = NULL;
    int n = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &live, &n);
    cf_t **claimed = n ? malloc((size_t)n * sizeof(*claimed)) : NULL;
    int nc = 0;
    int deepest_tier = 0;
    for (int i = 0; i < n; i++)
    {
        cf_t *cf = live[i];
        /* the deepest tier across the families, whether or not this tick claims them. it is the
         * signal ingestion paces against, so it has to reflect every family and not just the ones
         * that happened to be idle */
        const int depth = level_set_l1_overlap_depth(cf->levels);
        if (depth > deepest_tier) deepest_tier = depth;
        if (!claimed) continue;
        int expected = 0;
        if (atomic_compare_exchange_strong(&cf->compacting, &expected, 1)) claimed[nc++] = cf;
    }
    cf_registry_view_leave(db->cfs, view);

    /* published every tick, so a tier that drains releases the writers it was slowing */
    tidesdb_l0_set_tier_depth(db->l0, deepest_tier);

    for (int i = 0; i < nc; i++) engine_schedule_claimed_cf(db, claimed[i]);
    free(claimed);

    /* asking here as well as at a worker's tail. dead bytes only accumulate inside a merge, so the
     * tail covers the ordinary case; this catches the round where the threshold was already met but
     * the enqueue did not happen -- a lost claim or a failed allocation -- which would otherwise
     * wait on a further compaction that an idle database never runs. two atomic loads under the
     * threshold, and claimed by a compare-exchange, so a tick with nothing due is free */
    engine_maybe_enqueue_vlog_gc(db);
}

/* run a single merge job against the cf at the current gc floor; shared by the background worker,
 * the synchronous compact, and the range compact */
static int engine_exec_job(tidesdb_t *db, cf_t *cf, const compaction_job_t *job)
{
    const compaction_ctx_t cx = {.cf = cf,
                                 .manifest = db->manifest,
                                 .manifest_path = db->manifest->path,
                                 .next_sstable_id = &db->next_sstable_id,
                                 .gc_floor = engine_take_gc_floor(db),
                                 .sync_mode = engine_sstable_bm_sync(db),
                                 .value_threshold = db->config.value_separation_threshold,
                                 /* a lone job may spread its ranges over as many threads as the
                                  * pool has workers. it is the only job of its plan and its family
                                  * holds the claim, so nothing else of this family is running --
                                  * the pool is not oversubscribed by handing it that many */
                                 .max_subdivisions = db->config.num_compaction_threads};

    /* held across the swap, not just the build. a merge that re-spills a value writes it before the
     * table naming it is installed, and a reclaim landing in that window would find the segment it
     * went into referenced by nothing */
    const int build_token = vlog_build_enter(db->vlog);
    const int rc = compaction_exec(&cx, job);
    vlog_build_leave(db->vlog, build_token);
    return rc;
}

/* how many times a family's level set is re-sampled before the pass gives up. a snapshot loses to
 * an install or a compaction swap, both of which are brief, so a handful of tries clears it */
#define ENGINE_VLOG_SNAPSHOT_ATTEMPTS 8

/* restate what one family's installed tables hold in the value log; a family whose level set moved
 * under the snapshot is reported so the caller abandons the pass rather than reclaim against a
 * liveness total missing a whole family's references */
static int engine_vlog_note_cf(cf_t *cf, vlog_t *vlog)
{
    /* the snapshot is all or nothing, and a family that gained a table between the sizing query and
     * the fill references none of them. that is ordinary under a write load rather than an error,
     * so it is retried at the size just reported. giving up instead abandoned the whole pass --
     * with several families flushing and compacting, one of them was always mid-change, and
     * reclamation never ran at all */
    for (int attempt = 0; attempt < ENGINE_VLOG_SNAPSHOT_ATTEMPTS; attempt++)
    {
        const int total = level_set_snapshot(cf->levels, NULL, 0);
        if (total <= 0) return TDB_SUCCESS;

        level_set_snapshot_entry_t *all = calloc((size_t)total, sizeof(*all));
        if (!all) return TDB_ERR_MEMORY;

        if (level_set_snapshot(cf->levels, all, total) != total)
        {
            /* as in the planner, a layout that grew past the array referenced nothing, but one that
             * shrank referenced what it did fill, and those are this call's to drop before the
             * retry sizes itself again. the entries are zeroed, so a grow leaves nothing to drop */
            for (int i = 0; i < total; i++)
                if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
            free(all);
            continue;
        }

        for (int i = 0; i < total; i++)
        {
            const sstable_t *sst = all[i].sst;
            if (!sst) continue;
            for (uint32_t r = 0; r < sst->vlog_ref_count; r++)
                vlog_live_add(vlog, sst->vlog_refs[r].segment, sst->vlog_refs[r].bytes,
                              sst->vlog_refs[r].count);
        }

        for (int i = 0; i < total; i++)
            if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
        free(all);
        return TDB_SUCCESS;
    }

    /* a family that would not hold still is still a family whose references went uncounted, and
     * reclaiming against that loses data, so the pass is abandoned rather than run short */
    TDB_DEBUG_LOG(TDB_LOG_WARN, "value log liveness gave up on cf %s after %d attempts", cf->name,
                  (int)ENGINE_VLOG_SNAPSHOT_ATTEMPTS);
    return TDB_ERR_BUSY;
}

/* count every value a staged prepared batch still names, so a reclaim sees them as live */
static void engine_vlog_note_prepared(tidesdb_t *db)
{
    if (!db->prepared) return;

    const int n = tdb_prepare_stage_count(db->prepared);
    for (int i = 0; i < n; i++)
    {
        const tdb_prepared_record_t *rec = tdb_prepare_stage_at(db->prepared, i);
        if (!rec) continue;
        for (int e = 0; e < rec->count; e++)
        {
            if (!(rec->entries[e].flags & TDB_WAL_ENTRY_VLOG_REF)) continue;
            uint64_t segment = 0, bytes = 0;
            if (vlog_segment_of(db->vlog, rec->entries[e].vlog_id, &segment, &bytes) == VLOG_OK)
                vlog_live_add(db->vlog, segment, bytes, 1);
        }
    }
}

void engine_vlog_gc(tidesdb_t *db)
{
    if (!db || !db->vlog) return;

    /* liveness is restated from the tables installed right now rather than adjusted as they come
     * and go. every sstable already records which segments its separated values live in, so this
     * reads no file and touches no key -- deriving the same answer by scanning every key of every
     * table would not finish on a store large enough to need reclaiming */
    vlog_live_reset(db->vlog);

    int rc = TDB_SUCCESS;
    cf_t **live = NULL;
    int ncf = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &live, &ncf);
    for (int i = 0; i < ncf && rc == TDB_SUCCESS; i++)
    {
        cf_t *cf = live[i];
        if (cf) rc = engine_vlog_note_cf(cf, db->vlog);
    }
    cf_registry_view_leave(db->cfs, view);

    /* a staged prepare's values are held by no table and no memtable -- its entries enter neither
     * until phase two decides it and the decision is applied -- so counting only what the families
     * hold reads their segments as empty and drops them out from under a batch that still names
     * them. a floor alone is not enough here: it is taken when the batch is staged and given back
     * when it is decided, and the apply that hands the values to a memtable comes after that */
    engine_vlog_note_prepared(db);

    /* an incomplete restatement must never drive a reclaim. a family whose references went
     * uncounted leaves the segments it holds looking empty, and dropping one of those loses every
     * value in it */
    if (rc != TDB_SUCCESS) return;

    (void)vlog_reclaim(db->vlog);

    /* what is left is the segments that are mostly but not entirely dead, which the store cannot
     * empty on its own. marking them makes the next compaction carrying one of their values rewrite
     * it instead of carrying the reference, so they fall to zero through work already scheduled and
     * are then dropped by a later pass at no cost */
    (void)vlog_mark_drainable(db->vlog);
}

/* enqueue a db-global value-log reclaim when enough of the store is no longer referenced; claims
 * vlog_gc_active so only one is ever queued or running */
static void engine_maybe_enqueue_vlog_gc(tidesdb_t *db)
{
    if (!db->vlog) return;

    vlog_stats_t vs;
    if (vlog_get_stats(db->vlog, &vs) != VLOG_OK) return;

    /* nothing has sealed, so the only segment is the one taking appends and it is never a
     * candidate */
    if (vs.segment_count < 2) return;
    if (vs.file_size < ENGINE_VLOG_GC_MIN_DEAD_BYTES) return;

    /* measured, not estimated. what a pass would actually free is the difference between the file
     * and what is still referenced, which the store already knows exactly and for free -- so it is
     * what decides, rather than a running count of what compactions believed they dropped. an
     * estimate that is reset per enqueue cannot describe a log that failed to shrink, and a log
     * that fails to shrink is precisely the one that must keep qualifying */
    const uint64_t dead = vs.file_size > vs.live_bytes ? vs.file_size - vs.live_bytes : 0;

    /* a segment's worth of garbage, not a share of the whole store. a bar set as a fraction of the
     * file demands more garbage the larger the log grows, so a store that is falling behind asks
     * for more before it will act -- the same shape that stalled the estimate this replaced. what
     * a pass can actually free is a whole segment, so that is what makes one worth running, and it
     * stays the same bar at any store size */
    if (dead < db->config.vlog_segment_size) return;

    int expected = 0;
    if (!atomic_compare_exchange_strong(&db->vlog_gc_active, &expected, 1)) return;

    engine_compaction_work_t *w = malloc(sizeof(*w));
    if (w)
    {
        w->kind = ENGINE_WORK_VLOG_GC;
        w->cf = NULL;
        w->group = NULL;
        w->job_index = 0;
        if (queue_enqueue(db->compaction_queue, w) == 0) return;
        free(w);
    }
    atomic_store_explicit(&db->vlog_gc_active, 0, memory_order_release);
}

/* the compaction worker: run a value-log reclaim, or run every job in a planned unit at the current
 * gc floor and then consider queuing a reclaim; frees the unit and releases the cf claim either way
 */
static void engine_compaction_worker(void *item, void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    engine_compaction_work_t *w = (engine_compaction_work_t *)item;
    if (!w) return;

    if (w->kind == ENGINE_WORK_VLOG_GC)
    {
        engine_vlog_gc(db);
        atomic_store_explicit(&db->vlog_gc_active, 0, memory_order_release);
        free(w);
        return;
    }

    engine_job_group_t *group = w->group;
    if (engine_exec_job(db, w->cf, compaction_plan_job(group->plan, w->job_index)) != TDB_SUCCESS)
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "compaction job failed for cf %s", w->cf->name);
    free(w);

    /* the last job out frees the plan and releases the claim, so a family stays claimed for as long
     * as any of its jobs is still running and a drop waiting on the flag waits for all of them */
    engine_job_group_release(group);

    engine_maybe_enqueue_vlog_gc(db);
}

int engine_compaction_init(tidesdb_t *db)
{
    db->compaction_queue = queue_new();
    if (!db->compaction_queue) return TDB_ERR_MEMORY;

    bg_pool_t *pool =
        bg_pool_start_named(db->config.num_compaction_threads, db->compaction_queue,
                            ENGINE_COMPACTION_POOL_LABEL, engine_compaction_worker, db);
    if (!pool || threadmanager_add_pool(db->threads, ENGINE_COMPACTION_POOL_LABEL, pool) != 0)
    {
        if (pool) bg_pool_stop(pool);
        return TDB_ERR_MEMORY;
    }

    db->compaction_scheduler =
        bg_ticker_start(ENGINE_COMPACTION_INTERVAL_US, engine_compaction_scheduler_tick, db);
    if (!db->compaction_scheduler ||
        threadmanager_add_ticker(db->threads, ENGINE_COMPACTION_SCHED_LABEL,
                                 db->compaction_scheduler) != 0)
    {
        if (db->compaction_scheduler) bg_ticker_stop(db->compaction_scheduler);
        db->compaction_scheduler = NULL;
        return TDB_ERR_MEMORY;
    }
    return TDB_SUCCESS;
}

void engine_compaction_wake(tidesdb_t *db)
{
    /* a flush retiring during close must not wake the scheduler, whose ticker the thread manager
     * has already stopped and freed by the time the drain flushes the last immutables; closing is
     * set before that teardown, so it fences the wake off the dangling pointer */
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;
    if (db->compaction_scheduler) bg_ticker_wake(db->compaction_scheduler);
}

/* queue_free_with_data callback: free a queued work unit and its plan */
static void engine_compaction_work_free(void *item)
{
    engine_compaction_work_t *w = (engine_compaction_work_t *)item;
    if (!w) return;
    engine_job_group_release(w->group);
    free(w);
}

void engine_compaction_drain(tidesdb_t *db)
{
    if (db->compaction_queue)
        queue_free_with_data(db->compaction_queue, engine_compaction_work_free);
    db->compaction_queue = NULL;
}

int engine_is_compacting(cf_t *cf)
{
    if (!cf) return 0;
    return atomic_load_explicit(&cf->compacting, memory_order_acquire) != 0;
}

/* claim the cf for a synchronous compaction, or report it already busy; the claim also blocks the
 * scheduler and a drop from touching the cf while the merge runs */
int engine_compact(tidesdb_t *db, cf_t *cf)
{
    if (!db || !cf) return TDB_ERR_INVALID_ARGS;

    int expected = 0;
    if (!atomic_compare_exchange_strong(&cf->compacting, &expected, 1)) return TDB_ERR_LOCKED;

    int prc = TDB_SUCCESS;
    compaction_plan_t *plan = engine_plan_cf(db, cf, 1, &prc);
    int rc = plan ? TDB_SUCCESS : prc;
    if (plan)
    {
        const int n = compaction_plan_job_count(plan);
        for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
            rc = engine_exec_job(db, cf, compaction_plan_job(plan, i));
        compaction_plan_free(plan);
    }
    atomic_store_explicit(&cf->compacting, 0, memory_order_release);
    return rc;
}

/* byte-wise key order, shorter key first on a shared prefix -- the memcmp-only ordering the engine
 * uses */
static int engine_key_cmp(const uint8_t *a, size_t as, const uint8_t *b, size_t bs)
{
    const size_t m = as < bs ? as : bs;
    const int c = m ? memcmp(a, b, m) : 0;
    if (c != 0) return c;
    return as < bs ? -1 : (as > bs ? 1 : 0);
}

/* whether an sstable's key span meets the half-open query range, either endpoint NULL for unbounded
 */
static int engine_sst_in_range(const sstable_t *s, const uint8_t *start, size_t ss,
                               const uint8_t *end, size_t es)
{
    if (start && engine_key_cmp(s->max_key, s->max_key_size, start, ss) < 0) return 0;
    if (end && engine_key_cmp(s->min_key, s->min_key_size, end, es) >= 0) return 0;
    return 1;
}

/* expand a seed selection to its overlap closure -- keep including any sstable whose key span meets
 * the union span of the already-included ones, so the merged output cannot overlap a run left
 * behind. the union span grows through umin/umax; the pass count is bounded because each pass that
 * grows adds at least one sstable */
static void engine_range_closure(const level_set_snapshot_entry_t *all, int total, char *included,
                                 const uint8_t **umin, size_t *umin_sz, const uint8_t **umax,
                                 size_t *umax_sz)
{
    for (int pass = 0; pass < total; pass++)
    {
        int grew = 0;
        for (int i = 0; i < total; i++)
        {
            const sstable_t *s = all[i].sst;
            if (included[i] || !s) continue;
            if (engine_key_cmp(s->max_key, s->max_key_size, *umin, *umin_sz) < 0) continue;
            if (engine_key_cmp(s->min_key, s->min_key_size, *umax, *umax_sz) > 0) continue;
            included[i] = 1;
            grew = 1;
            if (engine_key_cmp(s->min_key, s->min_key_size, *umin, *umin_sz) < 0)
            {
                *umin = s->min_key;
                *umin_sz = s->min_key_size;
            }
            if (engine_key_cmp(s->max_key, s->max_key_size, *umax, *umax_sz) > 0)
            {
                *umax = s->max_key;
                *umax_sz = s->max_key_size;
            }
        }
        if (!grew) break;
    }
}

/* seed the selection from the query range and record the union span and largest live level; returns
 * the number of seeds */
static int engine_range_seed(const level_set_snapshot_entry_t *all, int total, char *included,
                             const uint8_t *start, size_t ss, const uint8_t *end, size_t es,
                             const uint8_t **umin, size_t *umin_sz, const uint8_t **umax,
                             size_t *umax_sz, int *max_level)
{
    int seeds = 0;
    *max_level = 0;
    for (int i = 0; i < total; i++)
    {
        const sstable_t *s = all[i].sst;
        if (!s) continue;
        if (all[i].level > *max_level) *max_level = all[i].level;
        if (!engine_sst_in_range(s, start, ss, end, es)) continue;
        included[i] = 1;
        if (seeds == 0 || engine_key_cmp(s->min_key, s->min_key_size, *umin, *umin_sz) < 0)
        {
            *umin = s->min_key;
            *umin_sz = s->min_key_size;
        }
        if (seeds == 0 || engine_key_cmp(s->max_key, s->max_key_size, *umax, *umax_sz) > 0)
        {
            *umax = s->max_key;
            *umax_sz = s->max_key_size;
        }
        seeds++;
    }
    return seeds;
}

/* the count walks the merged stream, so it is bounded to keep a plan-time call from turning into a
 * scan. a range whose metadata says it holds more than this is reported from that metadata instead
 */
#define ENGINE_RANGE_WALK_CAP 1024

/* count live keys in [key_a, key_b) by stepping the merged stream. walking rather than adding a
 * memtable figure to an sstable one is what makes the answer trustworthy -- the merge resolves a
 * key present in both to a single version and hides tombstones, so a hot key that was flushed and
 * then rewritten counts once instead of twice. returns the count, and sets hit_cap when it stopped
 * early
 */
/* bytes of a key read as a number when placing it inside an sstable's key span. eight is past what
 * a linear interpolation can meaningfully resolve, and the read starts where the file's own bounds
 * diverge so a shared prefix does not consume all of them */
#define ENGINE_RANGE_KEY_SCALE_BYTES 8

/**
 * engine_key_divergence
 * the first byte position at which two keys differ, which is where an interpolation between them
 * starts to carry information
 * @param a first key
 * @param a_size size of a in bytes
 * @param b second key
 * @param b_size size of b in bytes
 * @return the index of the first differing byte, or the shorter length when one is a prefix
 */
static size_t engine_key_divergence(const uint8_t *a, size_t a_size, const uint8_t *b,
                                    size_t b_size)
{
    const size_t n = a_size < b_size ? a_size : b_size;
    size_t i = 0;
    while (i < n && a[i] == b[i]) i++;
    return i;
}

/**
 * engine_key_scalar
 * read a key as a big-endian number from a byte offset, treating bytes past its end as zero so keys
 * of different lengths compare on the same scale
 * @param key the key
 * @param key_size size of key in bytes
 * @param offset the byte to start reading at
 * @return the key's numeric position
 */
static uint64_t engine_key_scalar(const uint8_t *key, size_t key_size, size_t offset)
{
    uint64_t v = 0;
    for (size_t i = 0; i < ENGINE_RANGE_KEY_SCALE_BYTES; i++)
    {
        const size_t at = offset + i;
        v = (v << 8) | (uint64_t)(at < key_size ? key[at] : 0);
    }
    return v;
}

/**
 * engine_range_share
 * what fraction of an sstable's keys a range plausibly covers, by interpolating both against the
 * file's own recorded bounds
 *
 * counting an overlapping file's keys whole is what makes a narrow range read as the whole store:
 * a file written from an interleaved memtable spans the entire key space, so every range meets it
 * and every range is told it holds everything. interpolating assumes the keys are spread evenly
 * inside the file, which is rough -- but being within an order of magnitude is what a planner
 * needs, and it is also what keeps a narrow range under the cap where it gets counted exactly
 * instead
 * @param s the sstable, whose min and max keys bound the interpolation
 * @param key_a range start
 * @param key_a_size size of key_a in bytes
 * @param key_b range end
 * @param key_b_size size of key_b in bytes
 * @return a fraction in [0,1]; 1 when the file's span is too narrow to resolve
 */
static double engine_range_share(const sstable_t *s, const uint8_t *key_a, size_t key_a_size,
                                 const uint8_t *key_b, size_t key_b_size)
{
    if (!s->min_key || !s->max_key) return 1.0;

    const size_t at =
        engine_key_divergence(s->min_key, s->min_key_size, s->max_key, s->max_key_size);
    const uint64_t lo = engine_key_scalar(s->min_key, s->min_key_size, at);
    const uint64_t hi = engine_key_scalar(s->max_key, s->max_key_size, at);
    if (hi <= lo) return 1.0;

    const uint64_t a = engine_key_scalar(key_a, key_a_size, at);
    const uint64_t b = engine_key_scalar(key_b, key_b_size, at);
    const uint64_t from = a > lo ? a : lo;
    const uint64_t to = b < hi ? b : hi;
    if (to <= from) return 0.0;
    return (double)(to - from) / (double)(hi - lo);
}

static uint64_t engine_range_walk_keys(tidesdb_t *db, cf_t *cf, const uint8_t *key_a,
                                       size_t key_a_size, const uint8_t *key_b, size_t key_b_size,
                                       int *hit_cap)
{
    *hit_cap = 0;
    /* the walk stays inside the range it was asked about, so the merge is built from the sstables
     * that meet it rather than from every one the family holds -- a plan-time estimate that opened
     * the whole family would cost more than the query it is estimating for */
    const cf_iter_bounds_t bounds = {
        .lower = key_a, .lower_size = key_a_size, .upper = key_b, .upper_size = key_b_size};
    cf_iter_t *it = NULL;
    if (cf_iter_new_bounded(cf, db->l0, tidesdb_mvcc_current_seq(db->clock), NULL, &bounds, &it) !=
        TDB_SUCCESS)
        return 0;

    uint64_t counted = 0;
    if (cf_iter_seek(it, key_a, key_a_size) == TDB_SUCCESS)
    {
        while (cf_iter_valid(it))
        {
            const uint8_t *k = NULL;
            const uint8_t *v = NULL;
            size_t ks = 0, vs = 0;
            uint64_t seq = 0, voff = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            if (cf_iter_get(it, &k, &ks, &seq, &v, &vs, &voff, &ttl, &deleted) != TDB_SUCCESS)
                break;

            /* the end bound is exclusive, and a key equal to it on its shared prefix but no shorter
             * is already past the range */
            const size_t cmp_len = ks < key_b_size ? ks : key_b_size;
            const int c = memcmp(k, key_b, cmp_len);
            if (c > 0 || (c == 0 && ks >= key_b_size)) break;

            counted++;
            if (counted >= ENGINE_RANGE_WALK_CAP)
            {
                *hit_cap = 1;
                break;
            }
            if (cf_iter_next(it) != TDB_SUCCESS) break;
        }
    }
    cf_iter_free(it);
    return counted;
}

int engine_range_stats(tidesdb_t *db, cf_t *cf, const uint8_t *key_a, size_t key_a_size,
                       const uint8_t *key_b, size_t key_b_size, tidesdb_range_stats_t *out)
{
    if (!db || !cf || !key_a || !key_b || !out) return TDB_ERR_INVALID_ARGS;
    out->sstables_overlapping = 0;
    out->estimated_keys = 0;
    out->keys_exact = 0;

    /* one snapshot serves both figures, so the overlap count and the key estimate describe the same
     * layout instant rather than two moments a caller cannot tell apart */
    const int total = level_set_snapshot(cf->levels, NULL, 0);
    if (total < 0) return TDB_ERR_INVALID_ARGS;

    uint64_t ceiling = 0;
    if (total > 0)
    {
        level_set_snapshot_entry_t *all = calloc((size_t)total, sizeof(*all));
        if (!all) return TDB_ERR_MEMORY;
        if (level_set_snapshot(cf->levels, all, total) != total)
        {
            /* as in the planner, a shrink referenced what it filled and those are ours to drop */
            for (int i = 0; i < total; i++)
                if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
            free(all);
            /* the layout moved mid-scan; this reaches a public caller, so it reports locked rather
             * than the engine-internal contention code */
            return TDB_ERR_LOCKED;
        }

        for (int i = 0; i < total; i++)
        {
            const sstable_t *s = all[i].sst;
            if (!s || !engine_sst_in_range(s, key_a, key_a_size, key_b, key_b_size)) continue;
            out->sstables_overlapping++;
            /* distinct_key_count counts tombstoned keys too, and a deleted key is not one the
             * caller will see, so the live remainder is what the range draws from */
            const uint64_t live = s->distinct_key_count > s->tombstone_count
                                      ? s->distinct_key_count - s->tombstone_count
                                      : 0;
            /* only the share of the file the range actually covers, so a file spanning the whole
             * key space does not report the whole key space for a narrow band */
            uint64_t part = (uint64_t)((double)live *
                                       engine_range_share(s, key_a, key_a_size, key_b, key_b_size));
            /* the ranges do overlap, so a file holding anything holds at least one key of it even
             * where the interpolation rounds its share away */
            if (live > 0 && part == 0) part = 1;
            ceiling += part;
        }

        for (int i = 0; i < total; i++)
            if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
        free(all);
    }

    /* the metadata pass gates the walk. a range no sstable could fill past the cap is cheap to
     * count exactly, and one that could is reported from metadata without walking at all, so the
     * call costs no more than the overlap count for the wide ranges where walking would hurt. the
     * memtable can hold keys no sstable knows about, so a range the sstables think empty is still
     * walked rather than reported as zero */
    if (ceiling < ENGINE_RANGE_WALK_CAP)
    {
        int hit_cap = 0;
        const uint64_t counted =
            engine_range_walk_keys(db, cf, key_a, key_a_size, key_b, key_b_size, &hit_cap);
        out->estimated_keys = counted;
        out->keys_exact = !hit_cap;
        return TDB_SUCCESS;
    }

    out->estimated_keys = ceiling;
    out->keys_exact = 0;
    return TDB_SUCCESS;
}

int engine_compact_range(tidesdb_t *db, cf_t *cf, const uint8_t *start, size_t start_size,
                         const uint8_t *end, size_t end_size)
{
    if (!db || !cf || (!start && !end)) return TDB_ERR_INVALID_ARGS;

    int expected = 0;
    if (!atomic_compare_exchange_strong(&cf->compacting, &expected, 1)) return TDB_ERR_LOCKED;

    tidesdb_column_family_config_t cc;
    cf_config_get(cf, &cc);

    const int total = level_set_snapshot(cf->levels, NULL, 0);
    level_set_snapshot_entry_t *all = calloc(total ? (size_t)total : 1, sizeof(*all));
    char *included = calloc(total ? (size_t)total : 1, 1);
    uint64_t *ids = calloc(total ? (size_t)total : 1, sizeof(*ids));
    int rc = (all && included && ids) ? TDB_SUCCESS : TDB_ERR_MEMORY;
    /* as in engine_range_stats, a layout that moved mid-scan reports locked to a public caller */
    if (rc == TDB_SUCCESS && total > 0 && level_set_snapshot(cf->levels, all, total) != total)
        rc = TDB_ERR_LOCKED;

    if (rc == TDB_SUCCESS)
    {
        const uint8_t *umin = NULL, *umax = NULL;
        size_t umin_sz = 0, umax_sz = 0;
        int max_level = 0;
        const int seeds = engine_range_seed(all, total, included, start, start_size, end, end_size,
                                            &umin, &umin_sz, &umax, &umax_sz, &max_level);
        if (seeds > 0)
        {
            engine_range_closure(all, total, included, &umin, &umin_sz, &umax, &umax_sz);
            int n_in = 0, target = 0;
            for (int i = 0; i < total; i++)
                if (included[i])
                {
                    ids[n_in++] = all[i].sst->id;
                    if (all[i].level > target) target = all[i].level;
                }
            if (n_in >= 2)
            {
                const compaction_job_t job = {
                    .input_ids = ids,
                    .n_inputs = n_in,
                    .target_level = target,
                    .is_largest_level = target == max_level,
                    .split = COMPACTION_SPLIT_NONE,
                    .file_max = compaction_planner_output_file_max(
                        level_set_level_bytes(cf->levels, max_level), cc.level_size_ratio),
                    .boundaries = NULL,
                    .boundary_sizes = NULL,
                    .n_boundaries = 0};
                rc = engine_exec_job(db, cf, &job);
            }
        }
    }

    for (int i = 0; i < total; i++)
        if (all && all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
    free(all);
    free(included);
    free(ids);
    atomic_store_explicit(&cf->compacting, 0, memory_order_release);
    return rc;
}
