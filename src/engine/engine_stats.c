/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"
#include "cache/cache.h"
#include "column_family/level/level_set.h"
#include "datastructures/queue.h"
#include "engine.h"
#include "fdmanager/fdmanager.h"
#include "memtable/memtable.h"
#include "sstable/sstable.h"
#include "sstable/vlog.h"
#include "txn/mvcc.h"
#include "txn/registry.h"
#include "txn/txn.h"

/* db.h sizes its per-level stat arrays to TDB_MAX_LEVELS, which must match the level set's own cap
 * so every live level maps to a valid array slot */
_Static_assert(TDB_MAX_LEVELS == LEVEL_SET_MAX_LEVELS,
               "public per-level stat arrays must match the level set level cap");

/* retries for the size-up race when the level set grows between the count query and the collect */
#define ENGINE_STATS_SNAPSHOT_RETRIES 8

/* the per-family byte and height sums a stats pass folds before turning them into averages */
typedef struct
{
    uint64_t total_key_bytes;
    uint64_t total_value_bytes;
    uint64_t btree_height_sum;
    int btree_sampled;
} cf_stats_accum_t;

/* reference every sstable in the family with its level and size; on success out owns the array
 * (freed by engine_stats_release) and count is the number referenced. an empty family yields count
 * 0 */
static int engine_stats_snapshot(level_set_t *ls, level_set_snapshot_entry_t **out, int *count)
{
    *out = NULL;
    *count = 0;
    int total = level_set_snapshot(ls, NULL, 0);
    if (total <= 0) return total == 0 ? TDB_SUCCESS : TDB_ERR_INVALID_ARGS;

    for (int tries = 0; tries < ENGINE_STATS_SNAPSHOT_RETRIES; tries++)
    {
        level_set_snapshot_entry_t *all = malloc((size_t)total * sizeof(*all));
        if (!all) return TDB_ERR_MEMORY;
        const int got = level_set_snapshot(ls, all, total);
        if (got <= total)
        {
            *out = all;
            *count = got;
            return TDB_SUCCESS;
        }
        free(all);
        total = got;
    }
    /* the layout kept growing past every retry; this result reaches a public caller, so it reports
     * locked rather than the engine-internal contention code */
    return TDB_ERR_LOCKED;
}

/* drop the references a snapshot took, closing any sstable whose last reference this releases */
static void engine_stats_release(level_set_snapshot_entry_t *all, int count)
{
    for (int i = 0; i < count; i++)
        if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
    free(all);
}

/* fold one snapshot's sstables into the per-level arrays, the running totals, the worst tombstone
 * density, and the btree structure counters, all read straight from the sstables' cached footer
 * fields so no klog is opened */
static void engine_cf_fold(const level_set_snapshot_entry_t *all, int count,
                           tidesdb_cf_stats_t *out, cf_stats_accum_t *acc)
{
    for (int i = 0; i < count; i++)
    {
        sstable_t *sst = all[i].sst;
        if (!sst) continue;
        const int lvl = all[i].level;
        if (lvl >= LEVEL_SET_L1 && lvl <= TDB_MAX_LEVELS)
        {
            const int idx = lvl - 1;
            out->level_sizes[idx] += all[i].size_bytes;
            out->level_num_sstables[idx] += 1;
            out->level_key_counts[idx] += sst->distinct_key_count;
            out->level_tombstone_counts[idx] += sst->tombstone_count;
            if (lvl > out->num_levels) out->num_levels = lvl;
        }

        out->total_keys += sst->distinct_key_count;
        out->total_tombstones += sst->tombstone_count;
        /* the key log's own bytes, and only those. adding the summed value length on top counts
         * every inline value twice, since a value under the family's spill threshold is already
         * inside the key log this measures -- and for a workload whose values all stay inline that
         * doubles the figure. what the shared value log holds is db-level and reported there, so a
         * family's size is its key logs */
        out->total_data_size += all[i].size_bytes;
        acc->total_key_bytes += sst->total_key_bytes;
        acc->total_value_bytes += sst->total_value_bytes;

        out->btree_total_nodes += sst->btree_node_count;
        if (sst->btree_height > out->btree_max_height) out->btree_max_height = sst->btree_height;
        acc->btree_height_sum += sst->btree_height;
        acc->btree_sampled += 1;

        if (sst->distinct_key_count > 0)
        {
            const double density = (double)sst->tombstone_count / (double)sst->distinct_key_count;
            if (density > out->max_sst_density)
            {
                out->max_sst_density = density;
                out->max_sst_density_level = lvl;
            }
        }
    }
}

/* turn the folded sums into the per-key averages, the ratios, and the point-lookup read
 * amplification */
static void engine_cf_finalize(tidesdb_cf_stats_t *out, const cf_stats_accum_t *acc)
{
    if (out->total_keys > 0)
    {
        out->avg_key_size = (double)acc->total_key_bytes / (double)out->total_keys;
        out->avg_value_size = (double)acc->total_value_bytes / (double)out->total_keys;
        out->tombstone_ratio = (double)out->total_tombstones / (double)out->total_keys;
    }
    if (acc->btree_sampled > 0)
        out->btree_avg_height = (double)acc->btree_height_sum / (double)acc->btree_sampled;

    /* a point lookup probes every overlapping L1 sstable, then at most one sorted run per level
     * below */
    double read_amp = (double)out->level_num_sstables[LEVEL_SET_L1 - 1];
    for (int lvl = LEVEL_SET_L1 + 1; lvl <= TDB_MAX_LEVELS; lvl++)
        if (out->level_num_sstables[lvl - 1] > 0) read_amp += 1.0;
    out->read_amp = read_amp;
}

/* copy the family's cumulative byte and count counters into the stats struct */
static void engine_cf_copy_counters(const cf_t *cf, tidesdb_cf_stats_t *out)
{
    out->wal_bytes_written = atomic_load_explicit(&cf->wal_bytes_written, memory_order_relaxed);
    out->flush_bytes_written = atomic_load_explicit(&cf->flush_bytes_written, memory_order_relaxed);
    out->compaction_bytes_written =
        atomic_load_explicit(&cf->compaction_bytes_written, memory_order_relaxed);
    out->compaction_bytes_read =
        atomic_load_explicit(&cf->compaction_bytes_read, memory_order_relaxed);
    out->user_bytes_written = atomic_load_explicit(&cf->user_bytes_written, memory_order_relaxed);
    out->compaction_count = atomic_load_explicit(&cf->compaction_count, memory_order_relaxed);
}

int engine_get_cf_stats(cf_t *cf, tidesdb_cf_stats_t *out)
{
    if (!cf || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    cf_config_get(cf, &out->config);

    level_set_snapshot_entry_t *all = NULL;
    int count = 0;
    const int rc = engine_stats_snapshot(cf->levels, &all, &count);
    if (rc != TDB_SUCCESS) return rc;

    cf_stats_accum_t acc = {0};
    engine_cf_fold(all, count, out, &acc);
    engine_stats_release(all, count);

    engine_cf_finalize(out, &acc);
    engine_cf_copy_counters(cf, out);
    /* the counter can dip transiently negative if a flush's decrement is observed before the
     * matching apply increment, so clamp it to a sane unsigned figure */
    const int64_t unflushed = atomic_load_explicit(&cf->unflushed_key_count, memory_order_relaxed);
    out->unflushed_key_count = unflushed > 0 ? (uint64_t)unflushed : 0;
    return TDB_SUCCESS;
}

int engine_cf_estimate_cardinality(cf_t *cf, uint64_t *out_estimate)
{
    if (!cf || !out_estimate) return TDB_ERR_INVALID_ARGS;

    level_set_snapshot_entry_t *all = NULL;
    int count = 0;
    const int rc = engine_stats_snapshot(cf->levels, &all, &count);
    if (rc != TDB_SUCCESS) return rc;

    uint64_t estimate = 0;
    for (int i = 0; i < count; i++)
        if (all[i].sst) estimate += all[i].sst->distinct_key_count;
    engine_stats_release(all, count);

    *out_estimate = estimate;
    return TDB_SUCCESS;
}

/* sum the cross-family byte and count counters and the live sstable footprint under the registry
 * read lock, so no family is added or dropped mid-walk */
static void engine_db_fold_cfs(tidesdb_t *db, tidesdb_db_stats_t *out)
{
    cf_registry_rdlock(db->cfs);
    const int n = cf_registry_count_locked(db->cfs);
    out->num_column_families = n;
    for (int i = 0; i < n; i++)
    {
        cf_t *cf = cf_registry_at_locked(db->cfs, i);
        if (!cf) continue;
        out->flush_count += atomic_load_explicit(&cf->flush_count, memory_order_relaxed);
        out->flush_bytes_written +=
            atomic_load_explicit(&cf->flush_bytes_written, memory_order_relaxed);
        out->compaction_count += atomic_load_explicit(&cf->compaction_count, memory_order_relaxed);
        out->compaction_bytes_written +=
            atomic_load_explicit(&cf->compaction_bytes_written, memory_order_relaxed);
        out->compaction_bytes_read +=
            atomic_load_explicit(&cf->compaction_bytes_read, memory_order_relaxed);

        out->user_bytes_written +=
            atomic_load_explicit(&cf->user_bytes_written, memory_order_relaxed);
        for (int lvl = LEVEL_SET_L1; lvl <= TDB_MAX_LEVELS; lvl++)
        {
            out->total_sstable_count += level_set_count(cf->levels, lvl);
            out->total_data_size_bytes += level_set_level_bytes(cf->levels, lvl);
        }
    }
    cf_registry_rdunlock(db->cfs);
}

/* accumulate one live transaction into the db stats */
static int engine_db_txn_stat_visit(tdb_txn_t *txn, void *ctx)
{
    tidesdb_db_stats_t *out = (tidesdb_db_stats_t *)ctx;
    if (txn)
    {
        out->active_txn_count++;
        out->txn_memory_bytes += tdb_txn_mem_bytes(txn);
    }
    return 0; /* every transaction, no early stop */
}

/* sum the live transactions and the heap they hold, over one consistent view of the registry */
static void engine_db_txn_stats(tidesdb_t *db, tidesdb_db_stats_t *out)
{
    (void)tidesdb_txn_registry_for_each(db->txn_registry, engine_db_txn_stat_visit, out);
}

/* copy the shared value log's space accounting into the db stats */
static void engine_db_vlog_stats(tidesdb_t *db, tidesdb_db_stats_t *out)
{
    vlog_stats_t vs;
    memset(&vs, 0, sizeof(vs));
    if (db->vlog && vlog_get_stats(db->vlog, &vs) == VLOG_OK)
    {
        out->vlog_file_size = vs.file_size;
        out->vlog_value_count = vs.value_count;
        out->vlog_used_bytes = vs.used_bytes;
        out->vlog_stored_bytes = vs.stored_bytes;
        out->vlog_live_bytes = vs.live_bytes;
        out->vlog_segment_count = vs.segment_count;
        out->vlog_bytes_written = vs.bytes_written;
        out->vlog_dead_bytes = vs.dead_bytes;
        out->vlog_reclaim_calls = vs.reclaim_calls;
        out->vlog_reclaim_passes = vs.reclaim_passes;
        out->vlog_segments_retired = vs.segments_retired;
        out->vlog_segments_drainable = vs.segments_drainable;
    }
}

/**
 * engine_chain_slot
 * the accounting slot for a pipeline, creating it on first sight
 * @param out the entries being filled
 * @param count how many are in use, raised when a new chain is seen
 * @param max capacity of out
 * @param ids the pipeline's codec ids
 * @param id_count how many ids
 * @return the slot, or NULL when out is full
 */
static tidesdb_encoding_stats_t *engine_chain_slot(tidesdb_encoding_stats_t *out, size_t *count,
                                                   size_t max, const uint8_t *ids, int id_count)
{
    for (size_t i = 0; i < *count; i++)
    {
        if (out[i].id_count != id_count) continue;
        if (memcmp(out[i].ids, ids, (size_t)id_count) == 0) return &out[i];
    }
    if (*count >= max) return NULL;

    tidesdb_encoding_stats_t *e = &out[*count];
    memset(e, 0, sizeof(*e));
    e->id_count = id_count;
    if (id_count > 0) memcpy(e->ids, ids, (size_t)id_count);
    (*count)++;
    return e;
}

int engine_get_klog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                   size_t *out_count)
{
    if (!db || !out || !out_count || max == 0) return TDB_ERR_INVALID_ARGS;
    *out_count = 0;

    cf_registry_rdlock(db->cfs);
    const int ncf = cf_registry_count_locked(db->cfs);
    for (int i = 0; i < ncf; i++)
    {
        cf_t *cf = cf_registry_at_locked(db->cfs, i);
        if (!cf) continue;

        const int total = level_set_snapshot(cf->levels, NULL, 0);
        if (total <= 0) continue;
        level_set_snapshot_entry_t *all = calloc((size_t)total, sizeof(*all));
        if (!all) continue;

        if (level_set_snapshot(cf->levels, all, total) == total)
        {
            for (int j = 0; j < total; j++)
            {
                const sstable_t *sst = all[j].sst;
                if (!sst) continue;

                /* the pipeline the table was written with, from its own footer, not the family's
                 * current configuration -- a table older than a codec change still describes what
                 * encoded it */
                tidesdb_encoding_stats_t *e = engine_chain_slot(
                    out, out_count, max, sst->encoding_pipeline, sst->encoding_count);
                if (!e) continue;
                e->logical_bytes += sst->klog_logical_bytes;
                e->stored_bytes += all[j].size_bytes;
                e->item_count++;
            }
        }
        for (int j = 0; j < total; j++)
            if (all[j].sst && sstable_unref(all[j].sst)) sstable_close(all[j].sst);
        free(all);
    }
    cf_registry_rdunlock(db->cfs);
    return TDB_SUCCESS;
}

int engine_get_vlog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                   size_t *out_count)
{
    if (!db || !out || !out_count || max == 0) return TDB_ERR_INVALID_ARGS;
    *out_count = 0;
    if (!db->vlog) return TDB_SUCCESS;

    vlog_chain_stats_t chains[VLOG_MAX_CHAINS];
    size_t n = 0;
    if (vlog_get_chain_stats(db->vlog, chains, VLOG_MAX_CHAINS, &n) != VLOG_OK)
        return TDB_ERR_INVALID_ARGS;

    for (size_t i = 0; i < n && i < max; i++)
    {
        memset(&out[i], 0, sizeof(out[i]));
        out[i].id_count = chains[i].id_count;
        memcpy(out[i].ids, chains[i].ids, sizeof(out[i].ids));
        out[i].logical_bytes = chains[i].used_bytes;
        out[i].stored_bytes = chains[i].stored_bytes;
        out[i].item_count = chains[i].value_count;
        (*out_count)++;
    }
    return TDB_SUCCESS;
}

int engine_get_db_stats(tidesdb_t *db, tidesdb_db_stats_t *out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));

    engine_db_fold_cfs(db, out);

    const size_t queued = tidesdb_l0_queue_depth(db->l0);
    out->immutable_memtable_count = (int)queued;
    out->is_flushing = queued > 0 ? 1 : 0;
    out->memtable_bytes = tidesdb_l0_active_bytes(db->l0);
    out->wal_bytes_written = tidesdb_l0_wal_bytes_written(db->l0);
    out->compaction_pending_count = (int)queue_size(db->compaction_queue);
    out->num_open_sstables = fd_manager_open_count(&db->fdm, FD_LABEL_SSTABLE_KLOG);
    out->global_seq = tidesdb_mvcc_current_seq(db->clock);
    out->min_snapshot_seq = tidesdb_txn_registry_min_snapshot(db->txn_registry);
    out->next_cf_index = (uint32_t)cf_registry_next_cf_id(db->cfs);
    out->wal_generation = atomic_load_explicit(&db->wal_generation, memory_order_relaxed);

    tidesdb_l0_admission_t admission = {0};
    tidesdb_l0_admission_stats(db->l0, &admission);
    out->writes_throttled = admission.throttled;
    out->writes_blocked = admission.blocked;
    out->write_stall_us = admission.stall_us;
    out->write_stall_ceiling_hits = admission.ceiling_hits;

    engine_db_txn_stats(db, out);
    engine_db_vlog_stats(db, out);
    return TDB_SUCCESS;
}

int engine_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));

    if (!db->cache) return TDB_SUCCESS; /* the db runs without a cache, enabled stays 0 */

    cache_stats_t cs;
    memset(&cs, 0, sizeof(cs));
    cache_get_stats(db->cache, &cs);

    out->enabled = 1;
    out->total_entries = cs.entries;
    out->total_bytes = cs.bytes_used;
    out->hits = cs.hits;
    out->misses = cs.misses;
    out->num_partitions = cs.shard_count;
    const uint64_t lookups = cs.hits + cs.misses;
    out->hit_rate = lookups ? (double)cs.hits / (double)lookups : 0.0;
    return TDB_SUCCESS;
}

const char *tidesdb_stall_reason_name(const tidesdb_stall_reason_t reason)
{
    switch (reason)
    {
        case TDB_STALL_WAL_APPEND:
            return "wal_append";
        case TDB_STALL_ROTATE_LOCK:
            return "rotate_lock";
        case TDB_STALL_ROTATE_WORK:
            return "rotate_work";
        case TDB_STALL_ADMISSION:
            return "admission";
        case TDB_STALL_COUNT:
        default:
            return "unknown";
    }
}

int engine_get_stall_stats(tidesdb_t *db, tidesdb_stall_stats_t *out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));

    tidesdb_l0_wal_wait_t wal;
    tidesdb_l0_wal_wait_stats(db->l0, &wal);
    out->reasons[TDB_STALL_WAL_APPEND].count = wal.count;
    out->reasons[TDB_STALL_WAL_APPEND].total_us = wal.total_us;
    out->reasons[TDB_STALL_WAL_APPEND].max_us = wal.max_us;

    tdb_wait_read(&db->rotate_lock_wait, &out->reasons[TDB_STALL_ROTATE_LOCK].count,
                  &out->reasons[TDB_STALL_ROTATE_LOCK].total_us,
                  &out->reasons[TDB_STALL_ROTATE_LOCK].max_us);
    tdb_wait_read(&db->rotate_work_wait, &out->reasons[TDB_STALL_ROTATE_WORK].count,
                  &out->reasons[TDB_STALL_ROTATE_WORK].total_us,
                  &out->reasons[TDB_STALL_ROTATE_WORK].max_us);

    tidesdb_l0_admission_t adm;
    tidesdb_l0_admission_stats(db->l0, &adm);
    out->reasons[TDB_STALL_ADMISSION].count = adm.throttled + adm.blocked;
    out->reasons[TDB_STALL_ADMISSION].total_us = adm.stall_us;
    out->reasons[TDB_STALL_ADMISSION].max_us = adm.max_us;
    return TDB_SUCCESS;
}

const char *tidesdb_io_class_name(const tidesdb_io_class_t cls)
{
    switch (cls)
    {
        case TDB_IO_SSTABLE:
            return "sstable";
        case TDB_IO_WAL:
            return "wal";
        case TDB_IO_COUNT:
        default:
            return "unknown";
    }
}

/* the public class order and the descriptor manager's label order are independent, so the mapping
 * is written out rather than assumed */
static fd_manager_label_t engine_io_label(const tidesdb_io_class_t cls)
{
    return cls == TDB_IO_WAL ? FD_LABEL_WAL_LOG : FD_LABEL_SSTABLE_KLOG;
}

int engine_get_io_stats(tidesdb_t *db, tidesdb_io_stats_t *out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < TDB_IO_COUNT; i++)
        fd_manager_io_stats(&db->fdm, engine_io_label((tidesdb_io_class_t)i), &out->classes[i].ops,
                            &out->classes[i].bytes, &out->classes[i].total_us,
                            &out->classes[i].max_us);
    return TDB_SUCCESS;
}
