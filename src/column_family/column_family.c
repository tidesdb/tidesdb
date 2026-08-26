/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "column_family/column_family.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h"     /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h"        /* TDB_DEBUG_LOG for the recovery self-heal notice */
#include "compat.h"          /* PATH_SEPARATOR */
#include "sstable/sstable.h" /* sstable_open_from_manifest for rebuilding the level set */

/* whether cf_load_entries may self-heal past an unreadable sstable: strict fails on any load error,
 * self-heal skips an unreadable L1 segment on crash recovery since its data replays from the WAL */
#define CF_LOAD_STRICT    0
#define CF_LOAD_SELF_HEAL 1

/* the directory a family's key logs live in, which is the database directory itself -- a family
 * has none of its own, and each of its key logs carries the family id in its own filename. that is
 * what makes a rename a change of name and nothing else: no path an open sstable recorded is
 * invalidated, so nothing has to be moved, drained, or rebuilt.
 * @param dst destination buffer for the path
 * @param cap capacity of dst
 * @param db_dir the database directory
 * @return 0, or -1 if the path would not fit */
static int cf_dir_path(char *dst, const size_t cap, const char *db_dir)
{
    const int n = snprintf(dst, cap, "%s", db_dir);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/* open every manifest sstable entry belonging to this family and install it at its recorded level.
 * when self_heal is set (crash recovery), an L1 segment that will not load is skipped rather than
 * failing the open, since a torn flush output's data is still in its WAL generation and replay
 * re-applies it; a deeper level is a compaction output whose inputs are already gone, so it has no
 * WAL to fall back on and a torn one fails loudly. outside recovery every entry must load */
static int cf_load_entries(cf_t *cf, tidesdb_manifest_t *manifest, const int sync_mode,
                           const int self_heal)
{
    const int count = tidesdb_manifest_copy_entries(manifest, cf->cf_id, NULL, 0);
    if (count <= 0) return count == 0 ? 0 : -1;

    tidesdb_manifest_entry_t *entries = malloc((size_t)count * sizeof(*entries));
    if (!entries) return -1;

    const int got = tidesdb_manifest_copy_entries(manifest, cf->cf_id, entries, count);
    int result = 0;
    for (int i = 0; i < got && result == 0; i++)
    {
        sstable_t *sst = NULL;
        if (sstable_open_from_manifest(&sst, cf->dir, cf->name, &entries[i], sync_mode,
                                       cf->encodings, cf->cache, cf->fdm, cf->arena_pool,
                                       cf->now) != TDB_SUCCESS)
        {
            if (self_heal && entries[i].level == LEVEL_SET_L1)
            {
                TDB_DEBUG_LOG(TDB_LOG_WARN,
                              "cf %s skipping unreadable l1 sstable %llu on recovery, its data "
                              "replays from the wal",
                              cf->name, (unsigned long long)entries[i].id);
                continue;
            }
            result = -1;
            break;
        }
        if (level_set_install(cf->levels, sst, entries[i].level, entries[i].size_bytes) != 0)
        {
            sstable_close(sst);
            result = -1;
            break;
        }
        /* the level set took its own reference; drop the open reference so its last unref frees it
         */
        if (sstable_unref(sst)) sstable_close(sst);
    }
    free(entries);
    return result;
}

/* rebuild the family's range tombstone set from the block the manifest holds for it. a family that
 * never had one loads nothing and keeps the empty set every read short-circuits on
 * @param cf the column family
 * @param manifest the db-level manifest to read the block from
 * @return 0 on success or when the family carries no block, -1 on a corrupt block or an allocation
 *         failure
 */
static int cf_load_range_tombstones(cf_t *cf, tidesdb_manifest_t *manifest)
{
    uint8_t *blob = NULL;
    uint32_t len = 0;
    if (tidesdb_manifest_get_range_dels(manifest, cf->cf_id, &blob, &len) != 0) return -1;
    if (!blob || len == 0) return 0;

    const int rc = cf_range_tombstones_adopt(cf, blob, len);
    free(blob);
    return rc == TDB_SUCCESS ? 0 : -1;
}

/* zero-initialize the cf's atomic stat counters and the compacting flag */
static void cf_init_counters(cf_t *cf)
{
    atomic_init(&cf->compacting, 0);
    atomic_init(&cf->user_bytes_written, 0);
    atomic_init(&cf->wal_bytes_written, 0);
    atomic_init(&cf->flush_bytes_written, 0);
    atomic_init(&cf->flush_count, 0);
    atomic_init(&cf->compaction_bytes_written, 0);
    atomic_init(&cf->compaction_bytes_read, 0);
    atomic_init(&cf->compaction_count, 0);
    atomic_init(&cf->commit_hook_fn, NULL);
    atomic_init(&cf->commit_hook_ctx, NULL);
}

int cf_create(const char *db_dir, const uint64_t cf_id,
              const tidesdb_column_family_config_t *config, const tidesdb_encoding_registry_t *reg,
              vlog_t *vlog, cache_t *cache, fd_manager_t *fdm, arena_pool_t *arena_pool,
              _Atomic(int64_t) *now, cf_t **out)
{
    if (!db_dir || !config || !out) return -1;
    if (cf_config_validate(config, reg) != 0) return -1;

    cf_t *cf = calloc(1, sizeof(*cf));
    if (!cf) return -1;

    cf->cf_id = cf_id;
    if (cf_config_publish(cf, config) != TDB_SUCCESS)
    {
        free(cf);
        return -1;
    }
    cf->vlog = vlog;
    cf->cache = cache;
    cf->arena_pool = arena_pool;
    cf->now = now;
    cf->fdm = fdm;
    cf->encodings = reg;
    cf_init_counters(cf);
    if (pthread_rwlock_init(&cf->range_tombstone_lock, NULL) != 0)
    {
        free(cf);
        return -1;
    }
    snprintf(cf->name, sizeof(cf->name), "%s", config->name);
    if (cf_dir_path(cf->dir, sizeof(cf->dir), db_dir) != 0)
    {
        free(cf);
        return -1;
    }

    if (level_set_create(&cf->levels) != 0)
    {
        cf_free(cf);
        return -1;
    }

    *out = cf;
    return 0;
}

int cf_open(const char *db_dir, tidesdb_manifest_t *manifest, const uint64_t cf_id,
            const char *name, const uint8_t *config_blob, const size_t blob_len,
            const tidesdb_encoding_registry_t *reg, vlog_t *vlog, cache_t *cache, fd_manager_t *fdm,
            const int sync_mode, arena_pool_t *arena_pool, _Atomic(int64_t) *now, cf_t **out)
{
    if (!db_dir || !manifest || !name || !config_blob || !out) return -1;

    cf_t *cf = calloc(1, sizeof(*cf));
    if (!cf) return -1;

    cf->cf_id = cf_id;
    cf->vlog = vlog;
    cf->cache = cache;
    cf->arena_pool = arena_pool;
    cf->now = now;
    cf->fdm = fdm;
    cf->encodings = reg;
    cf_init_counters(cf);
    if (pthread_rwlock_init(&cf->range_tombstone_lock, NULL) != 0)
    {
        free(cf);
        return -1;
    }
    snprintf(cf->name, sizeof(cf->name), "%s", name);
    /* zeroed first because the decoder leaves any field the blob does not carry untouched, and this
     * is the copy that becomes the family's configuration */
    tidesdb_column_family_config_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    if (cf_config_deserialize(config_blob, blob_len, &loaded) != 0)
    {
        free(cf);
        return -1;
    }
    snprintf(loaded.name, sizeof(loaded.name), "%s", name);
    if (cf_config_publish(cf, &loaded) != TDB_SUCCESS)
    {
        free(cf);
        return -1;
    }

    if (cf_dir_path(cf->dir, sizeof(cf->dir), db_dir) != 0)
    {
        free(cf);
        return -1;
    }

    if (level_set_create(&cf->levels) != 0 ||
        cf_load_entries(cf, manifest, sync_mode, CF_LOAD_SELF_HEAL) != 0 ||
        cf_load_range_tombstones(cf, manifest) != 0)
    {
        cf_free(cf);
        return -1;
    }

    *out = cf;
    return 0;
}

int cf_reload_levels(cf_t *cf, tidesdb_manifest_t *manifest, const int sync_mode)
{
    if (!cf || !manifest) return -1;

    /* close the old sstables before reopening -- their resident klog block managers hold the files
     * at a preallocated, untruncated size, so a second block manager opened over the same file
     * would read a stale end-of-file. closing truncates each klog to its logical size first. the
     * caller has quiesced compaction and flushes and holds the registry write lock, so no reader or
     * the fd reaper is mid-access on this set as it is dropped. on failure the data stays on disk
     * and is recovered on the next open */
    level_set_free(cf->levels);
    cf->levels = NULL;
    if (level_set_create(&cf->levels) != 0) return -1;
    return cf_load_entries(cf, manifest, sync_mode, CF_LOAD_STRICT) == 0 ? 0 : -1;
}

void cf_free(cf_t *cf)
{
    if (!cf) return;
    level_set_free(cf->levels);
    /* nothing can be mid-copy of a configuration by the time the family is freed, so the retired
     * ones drain unconditionally and the live one is freed outright */
    tdb_retire_drain(&cf->config_retire, NULL, NULL);
    free(atomic_load_explicit(&cf->config, memory_order_acquire));
    range_tombstone_set_free(cf->range_tombstones);
    (void)pthread_rwlock_destroy(&cf->range_tombstone_lock);
    free(cf);
}

int cf_range_tombstones_adopt(cf_t *cf, const uint8_t *blob, const size_t blob_len)
{
    if (!cf || !blob || blob_len == 0) return TDB_ERR_INVALID_ARGS;

    range_tombstone_set_t *set = NULL;
    const int rc = range_tombstone_set_deserialize(blob, blob_len, &set);
    if (rc != TDB_SUCCESS) return rc;

    pthread_rwlock_wrlock(&cf->range_tombstone_lock);
    range_tombstone_set_free(cf->range_tombstones);
    cf->range_tombstones = set;
    atomic_store_explicit(&cf->range_tombstone_frags, range_tombstone_set_count(set),
                          memory_order_release);
    pthread_rwlock_unlock(&cf->range_tombstone_lock);
    return TDB_SUCCESS;
}

int cf_range_tombstone_add(cf_t *cf, const uint8_t *lo, const size_t lo_size, const uint8_t *hi,
                           const size_t hi_size, const uint64_t seq)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    pthread_rwlock_wrlock(&cf->range_tombstone_lock);
    int rc = TDB_SUCCESS;
    if (!cf->range_tombstones)
    {
        cf->range_tombstones = range_tombstone_set_new();
        if (!cf->range_tombstones) rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS)
        rc = range_tombstone_set_add(cf->range_tombstones, lo, lo_size, hi, hi_size, seq);
    if (rc == TDB_SUCCESS)
        atomic_store_explicit(&cf->range_tombstone_frags,
                              range_tombstone_set_count(cf->range_tombstones),
                              memory_order_release);
    pthread_rwlock_unlock(&cf->range_tombstone_lock);
    return rc;
}

int cf_range_tombstone_covering(cf_t *cf, const uint8_t *key, const size_t key_size,
                                const uint64_t snapshot, uint64_t *out_seq)
{
    if (!cf || !key || !out_seq) return 0;
    if (atomic_load_explicit(&cf->range_tombstone_frags, memory_order_acquire) == 0) return 0;

    pthread_rwlock_rdlock(&cf->range_tombstone_lock);
    const int covered =
        range_tombstone_max_covering(cf->range_tombstones, key, key_size, snapshot, out_seq) == 1;
    pthread_rwlock_unlock(&cf->range_tombstone_lock);
    return covered;
}

/* tables one sweep reads before it gives up rather than risk a partial view; a family with more
 * than this simply keeps its tombstones until a later sweep finds it smaller */
#define CF_SWEEP_MAX_TABLES 512

uint64_t cf_range_tombstones_applied_through(const cf_t *cf, const uint64_t ceiling)
{
    if (!cf) return 0;
    if (atomic_load_explicit(&cf->range_tombstone_frags, memory_order_acquire) == 0) return 0;

    pthread_rwlock_t *lock = (pthread_rwlock_t *)&cf->range_tombstone_lock;
    pthread_rwlock_rdlock(lock);
    const uint64_t seq = range_tombstone_set_max_seq_through(cf->range_tombstones, ceiling);
    pthread_rwlock_unlock(lock);
    return seq;
}

int cf_range_tombstones_sweep(cf_t *cf, size_t *out_dropped)
{
    if (!cf || !out_dropped) return TDB_ERR_INVALID_ARGS;
    *out_dropped = 0;
    if (atomic_load_explicit(&cf->range_tombstone_frags, memory_order_acquire) == 0)
        return TDB_SUCCESS;

    sstable_t **tables = malloc(CF_SWEEP_MAX_TABLES * sizeof(*tables));
    if (!tables) return TDB_ERR_MEMORY;

    const int n = level_set_collect_all(cf->levels, tables, CF_SWEEP_MAX_TABLES);
    if (n > CF_SWEEP_MAX_TABLES)
    {
        /* a partial view would take the minimum over a subset, which reads higher than the true one
         * and would retire a tombstone some unseen table still needs. the references the collect
         * did take are still this call's to drop */
        for (int i = 0; i < CF_SWEEP_MAX_TABLES; i++)
            if (sstable_unref(tables[i])) sstable_close(tables[i]);
        free(tables);
        return TDB_SUCCESS;
    }

    uint64_t applied = UINT64_MAX;
    for (int i = 0; i < n; i++)
    {
        if (tables[i]->range_del_applied_seq < applied) applied = tables[i]->range_del_applied_seq;
        if (sstable_unref(tables[i])) sstable_close(tables[i]);
    }
    free(tables);
    if (applied == 0) return TDB_SUCCESS;

    pthread_rwlock_wrlock(&cf->range_tombstone_lock);
    *out_dropped = range_tombstone_set_forget_through(cf->range_tombstones, applied);
    if (*out_dropped)
        atomic_store_explicit(&cf->range_tombstone_frags,
                              range_tombstone_set_count(cf->range_tombstones),
                              memory_order_release);
    pthread_rwlock_unlock(&cf->range_tombstone_lock);
    return TDB_SUCCESS;
}

int cf_range_tombstones_serialize(const cf_t *cf, uint8_t **out, size_t *out_size)
{
    if (!cf || !out || !out_size) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    *out_size = 0;

    /* the lock is bookkeeping for the read, not part of the family's state, so taking it does not
     * make the family any less const to the caller -- the same reasoning cf_config_get runs on */
    pthread_rwlock_t *lock = (pthread_rwlock_t *)&cf->range_tombstone_lock;
    pthread_rwlock_rdlock(lock);
    const int rc = cf->range_tombstones
                       ? range_tombstone_set_serialize(cf->range_tombstones, out, out_size)
                       : TDB_SUCCESS;
    pthread_rwlock_unlock(lock);
    return rc;
}

/* free a configuration displaced by a reconfigure, once the epoch says no reader holds it */
static void cf_config_reclaim(void *payload, void *ctx)
{
    (void)ctx;
    free(payload);
}

void cf_config_get(const cf_t *cf, tidesdb_column_family_config_t *out)
{
    if (!cf || !out) return;
    /* the epoch counter is bookkeeping for the read, not part of the family's state, so bracketing
     * the copy with it does not make the family any less const to the caller */
    tdb_epoch_t *epoch = (tdb_epoch_t *)&cf->config_epoch;
    tdb_epoch_enter(epoch);
    const tidesdb_column_family_config_t *cur =
        atomic_load_explicit(&cf->config, memory_order_acquire);
    if (cur)
        *out = *cur;
    else
        memset(out, 0, sizeof(*out));
    tdb_epoch_exit(epoch);
}

tidesdb_isolation_level_t cf_config_default_isolation(cf_t *cf)
{
    if (!cf) return TDB_ISOLATION_READ_COMMITTED;
    tdb_epoch_enter(&cf->config_epoch);
    const tidesdb_column_family_config_t *cur =
        atomic_load_explicit(&cf->config, memory_order_acquire);
    const tidesdb_isolation_level_t level =
        cur ? cur->default_isolation_level : TDB_ISOLATION_READ_COMMITTED;
    tdb_epoch_exit(&cf->config_epoch);
    return level;
}

int cf_config_publish(cf_t *cf, const tidesdb_column_family_config_t *config)
{
    if (!cf || !config) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_config_t *fresh = malloc(sizeof(*fresh));
    if (!fresh) return TDB_ERR_MEMORY;
    *fresh = *config;

    tidesdb_column_family_config_t *old =
        atomic_exchange_explicit(&cf->config, fresh, memory_order_acq_rel);
    if (old) tdb_retire(&cf->config_retire, old, &cf->config_epoch, cf_config_reclaim, NULL);
    return TDB_SUCCESS;
}
