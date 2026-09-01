/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* the key log name format */
#include "base/errors.h"
#include "base/log.h"
#include "column_family/cf_config.h"
#include "compat.h" /* rename, PATH_SEPARATOR, usleep */
#include "engine.h"
#include "io/block_manager.h"
#include "manifest/manifest.h"
#include "sstable/sstable.h" /* sstable_klog_filename */

/* the poll interval and bound a cf DDL operation waits for an in-flight compaction to finish before
 * it can claim the family; the product caps the wait so a stuck compaction surfaces as busy */
#define ENGINE_CF_QUIESCE_STALL_US 1000
#define ENGINE_CF_QUIESCE_TICKS    60000

int engine_list_column_families(tidesdb_t *db, char ***out_names, int *out_count)
{
    if (!db || !out_names || !out_count) return TDB_ERR_INVALID_ARGS;
    *out_names = NULL;
    *out_count = 0;

    cf_t **live = NULL;
    int n = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &live, &n);
    char **names = n > 0 ? calloc((size_t)n, sizeof(*names)) : NULL;
    int rc = (n == 0 || names) ? TDB_SUCCESS : TDB_ERR_MEMORY;
    int filled = 0;
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        const cf_t *cf = live[i];
        if (!cf) continue;
        const size_t len = strlen(cf->name) + 1;
        names[filled] = malloc(len);
        if (!names[filled])
        {
            rc = TDB_ERR_MEMORY;
            break;
        }
        memcpy(names[filled], cf->name, len);
        filled++;
    }
    cf_registry_view_leave(db->cfs, view);

    if (rc != TDB_SUCCESS)
    {
        for (int i = 0; i < filled; i++) free(names[i]);
        free(names);
        return rc;
    }
    *out_names = names;
    *out_count = filled;
    return TDB_SUCCESS;
}

/* register a family's name and config in the manifest and commit; the caller has set config already
 */
static int engine_cf_persist_config(tidesdb_t *db, uint64_t cf_id, const char *name,
                                    const tidesdb_column_family_config_t *config)
{
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (cf_config_serialize(config, &blob, &blob_len) != 0) return TDB_ERR_MEMORY;
    const int ok =
        tidesdb_manifest_add_cf(db->manifest, cf_id, name, blob, blob_len) == 0 &&
        tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_durable_writes(db)) == 0;
    free(blob);
    return ok ? TDB_SUCCESS : TDB_ERR_IO;
}

int engine_cf_update_runtime_config(tidesdb_t *db, cf_t *cf,
                                    const tidesdb_column_family_config_t *new_config, int persist)
{
    if (!db || !cf || !new_config) return TDB_ERR_INVALID_ARGS;
    /* validated against the registry, exactly as a create is. with no registry the pipeline ids are
     * only range-checked, so an id naming a codec this build lacks would be accepted here and then
     * fail in every later sstable build -- leaving the family unflushable and its data stranded in
     * the write-ahead logs, from a call that reported success */
    if (cf_config_validate(new_config, &db->encodings) != 0) return TDB_ERR_INVALID_ARGS;

    /* claim the family so this is the only reconfigure or ddl in flight on it. readers no longer
     * need the claim -- the configuration is published whole and a reader takes an immutable
     * snapshot of it -- but two reconfigures racing could still install one configuration and
     * persist the other, leaving the manifest describing a family the engine is not running.
     * a family already claimed reports locked instead of waiting, since the holder may be a
     * compaction that runs for minutes */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&cf->compacting, &expected, 1)) return TDB_ERR_LOCKED;

    /* the name and id identify the family and never change here -- a rename is a separate operation
     * -- so the incoming name is ignored and the current one preserved */
    tidesdb_column_family_config_t merged = *new_config;
    snprintf(merged.name, sizeof(merged.name), "%s", cf->name);
    if (cf_config_publish(cf, &merged) != TDB_SUCCESS)
    {
        atomic_store_explicit(&cf->compacting, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    /* the planner's knobs just changed, so the shape the scheduler last planned at no longer
     * implies the same plan; clearing this makes the next tick reconsider the family */
    cf->planned_generation = 0;
    cf->planned_gc_floor = 0;

    const int rc =
        persist ? engine_cf_persist_config(db, cf->cf_id, cf->name, &merged) : TDB_SUCCESS;

    atomic_store_explicit(&cf->compacting, 0, memory_order_release);
    return rc;
}

/* claim a family for a DDL operation, waiting out an in-flight compaction; a family that stays
 * claimed for the whole wait reports locked, since these results reach a public caller and the
 * internal contention code must not */
static int engine_cf_claim(cf_t *cf)
{
    for (int tick = 0; tick < ENGINE_CF_QUIESCE_TICKS; tick++)
    {
        int expected = 0;
        if (atomic_compare_exchange_strong(&cf->compacting, &expected, 1)) return TDB_SUCCESS;
        usleep(ENGINE_CF_QUIESCE_STALL_US);
    }
    return TDB_ERR_LOCKED;
}

int engine_rename_cf(tidesdb_t *db, const char *old_name, const char *new_name)
{
    if (!db || !old_name || !new_name) return TDB_ERR_INVALID_ARGS;
    const size_t nl = strlen(new_name);
    if (nl == 0 || nl >= TDB_MAX_CF_NAME_LEN) return TDB_ERR_INVALID_ARGS;

    cf_t *cf = cf_registry_get_by_name(db->cfs, old_name);
    if (!cf) return TDB_ERR_NOT_FOUND;
    if (cf_registry_get_by_name(db->cfs, new_name)) return TDB_ERR_EXISTS;

    /* a family's files live under its id, so a rename touches no file and moves no directory. that
     * leaves nothing on disk to keep in step with the name -- no flush to drain first, no level set
     * to tear down and rebuild, and so nothing that has to exclude a flush or stall a committer.
     * what remains is the name itself, in the registry index and in the persisted config.
     *
     * the family is still claimed for the update. the claim is not protecting files here, it keeps
     * a second DDL and the compaction planner off the config while it is replaced, which is the
     * same reason a runtime config update takes it */
    int rc = engine_cf_claim(cf);
    if (rc != TDB_SUCCESS) return rc;

    rc = cf_registry_rename(db->cfs, cf, new_name);
    tidesdb_column_family_config_t renamed;
    cf_config_get(cf, &renamed);
    if (rc == TDB_SUCCESS)
    {
        snprintf(renamed.name, sizeof(renamed.name), "%s", new_name);
        rc = cf_config_publish(cf, &renamed);
    }

    /* the manifest commit fsyncs and needs no lock; the claim keeps another DDL off the family */
    if (rc == TDB_SUCCESS) rc = engine_cf_persist_config(db, cf->cf_id, new_name, &renamed);

    /* the old name is gone from every in-memory record once this returns, so the line naming both
     * is the only place the two ever appear together */
    if (rc == TDB_SUCCESS) TDB_DEBUG_LOG(TDB_LOG_INFO, "renamed cf %s to %s", old_name, new_name);

    atomic_store_explicit(&cf->compacting, 0, memory_order_release);
    return rc;
}

/* build the .klog path for a family id and an sstable id into dst, under the directory their key
 * logs live in */
static int engine_klog_path(char *dst, size_t cap, const char *cf_dir, uint64_t cf_id, uint64_t id)
{
    tidesdb_manifest_entry_t name_entry;
    memset(&name_entry, 0, sizeof(name_entry));
    name_entry.id = id;
    /* the family belongs in the name. source and destination share a directory, so without it a
     * clone would build the same path for both and copy a file onto itself */
    name_entry.column_family_id = cf_id;
    char name[TDB_SSTABLE_KLOG_NAME_MAX];
    if (sstable_klog_filename(&name_entry, name, sizeof(name)) != TDB_SUCCESS) return -1;
    const int n = snprintf(dst, cap, "%s%s%s", cf_dir, PATH_SEPARATOR, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* copy every source sstable into the destination under a fresh id, sharing the value-log offsets
 * the klog bytes already hold, and register each in the manifest; commits once at the end. the
 * caller holds the compaction claim on both families and takes no rotation lock -- the claim is
 * what keeps the source's entries and files still, since compaction is the only path that removes
 * one, and a flush landing a new file meanwhile is simply not in the manifest snapshot this copies
 * from */
static int engine_clone_copy_sstables(tidesdb_t *db, const cf_t *src, cf_t *dst)
{
    const int count = tidesdb_manifest_copy_entries(db->manifest, src->cf_id, NULL, 0);
    if (count <= 0) return count == 0 ? TDB_SUCCESS : TDB_ERR_IO;

    tidesdb_manifest_entry_t *entries = malloc((size_t)count * sizeof(*entries));
    if (!entries) return TDB_ERR_MEMORY;
    const int got = tidesdb_manifest_copy_entries(db->manifest, src->cf_id, entries, count);

    int rc = TDB_SUCCESS;
    for (int i = 0; i < got && rc == TDB_SUCCESS; i++)
    {
        const uint64_t new_id =
            atomic_fetch_add_explicit(&db->next_sstable_id, 1, memory_order_relaxed);
        char src_path[CF_DIR_PATH_LEN], dst_path[CF_DIR_PATH_LEN];
        if (engine_klog_path(src_path, sizeof(src_path), src->dir, src->cf_id, entries[i].id) !=
                0 ||
            engine_klog_path(dst_path, sizeof(dst_path), dst->dir, dst->cf_id, new_id) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        rc = engine_copy_file(src_path, dst_path, entries[i].size_bytes);
        if (rc == TDB_SUCCESS &&
            tidesdb_manifest_add_sstable(db->manifest, dst->cf_id, entries[i].level, new_id,
                                         entries[i].num_entries, entries[i].size_bytes,
                                         entries[i].partition) != 0)
            rc = TDB_ERR_IO;
    }
    free(entries);

    /* the clone takes on the source's files, and a table carries the intervals it was built with,
     * so the copied records bring the deletes with them and there is nothing else to hand over */
    if (rc == TDB_SUCCESS &&
        tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_durable_writes(db)) != 0)
        rc = TDB_ERR_IO;
    return rc;
}

int engine_clone_cf(tidesdb_t *db, const char *src_name, const char *dst_name)
{
    if (!db || !src_name || !dst_name) return TDB_ERR_INVALID_ARGS;

    cf_t *src = cf_registry_get_by_name(db->cfs, src_name);
    if (!src) return TDB_ERR_NOT_FOUND;
    if (cf_registry_get_by_name(db->cfs, dst_name)) return TDB_ERR_EXISTS;

    int rc = engine_cf_claim(src);
    if (rc != TDB_SUCCESS) return rc;

    /* land the source's memtable data in L1 so the clone captures every committed write */
    rc = engine_flush_memtable(db);
    if (rc != TDB_SUCCESS)
    {
        atomic_store_explicit(&src->compacting, 0, memory_order_release);
        return rc;
    }

    /* create the destination as an empty family carrying the source's config, minus the
     * runtime-only commit hook, which a clone does not inherit */
    tidesdb_column_family_config_t dst_cfg;
    cf_config_get(src, &dst_cfg);
    snprintf(dst_cfg.name, sizeof(dst_cfg.name), "%s", dst_name);
    dst_cfg.commit_hook_fn = NULL;
    dst_cfg.commit_hook_ctx = NULL;
    rc = engine_create_cf(db, dst_name, &dst_cfg);

    if (rc == TDB_SUCCESS)
    {
        cf_t *dst = cf_registry_get_by_name(db->cfs, dst_name);

        /* the destination is already published in the registry, and the scheduler plans a claimed
         * family after it gives its borrow back, so holding the registry alone does not keep a
         * planner off dst while its level set is rebuilt. claiming dst waits that planner out,
         * which is the quiesce cf_reload_levels requires */
        rc = engine_cf_claim(dst);
        if (rc == TDB_SUCCESS)
        {
            /* no rotation lock across the copy: that lock is what every committer takes to rotate
             * a full memtable, and a clone copies every sstable, so holding it would stop every
             * writer for as long as the family's data takes to copy. the copy needs no freeze --
             * it works from a manifest snapshot taken up front and reads each file to the length
             * that snapshot recorded, so a flush landing a new sstable meanwhile is simply not in
             * it, which is what a point-in-time clone means. the one hazard is a file being removed
             * mid-copy, and the only path that removes one is compaction, already claimed above */
            rc = engine_clone_copy_sstables(db, src, dst);
            if (rc == TDB_SUCCESS)
            {
                /* the reload frees the destination's level set and builds a new one, and the
                 * compaction scheduler reads every published family's overlap depth whether or not
                 * it is claimed -- so the claim above does not keep it off this set. the family is
                 * taken out of the published view for the swap instead, which waits out the borrows
                 * that could still name it and leaves nothing able to reach the set being freed.
                 *
                 * the destination is invisible for that window. it is a half-built clone that no
                 * caller has been given yet, and the only cost is that a create racing for the same
                 * name could take it, which fails this clone rather than corrupting either */
                cf_t *detached = NULL;
                if (cf_registry_remove(db->cfs, dst_name, &detached) != TDB_SUCCESS)
                    rc = TDB_ERR_NOT_FOUND;
                if (rc == TDB_SUCCESS &&
                    cf_reload_levels(dst, db->manifest, engine_sstable_bm_sync(db)) != 0)
                    rc = TDB_ERR_IO;
                if (detached && cf_registry_add(db->cfs, detached) != TDB_SUCCESS)
                    rc = TDB_ERR_EXISTS;
            }

            /* released before the undo below, which waits the same flag out */
            atomic_store_explicit(&dst->compacting, 0, memory_order_release);
        }

        if (rc != TDB_SUCCESS) (void)engine_drop_cf(db, dst_name); /* undo a partial clone */
    }

    /* a clone copies every sstable, so it is the one family operation whose cost scales with the
     * data, and the destination appears with a full level set rather than empty */
    if (rc == TDB_SUCCESS) TDB_DEBUG_LOG(TDB_LOG_INFO, "cloned cf %s to %s", src_name, dst_name);

    atomic_store_explicit(&src->compacting, 0, memory_order_release);
    return rc;
}

int engine_cf_set_commit_hook(tidesdb_t *db, cf_t *cf, tidesdb_commit_hook_fn fn, void *ctx)
{
    if (!db || !cf) return TDB_ERR_INVALID_ARGS;

    /* publish the context before the function so the commit path never reads a new function against
     * a stale context; the function swap then flips the hook on atomically */
    atomic_store_explicit(&cf->commit_hook_ctx, ctx, memory_order_release);
    const tidesdb_commit_hook_fn old =
        atomic_exchange_explicit(&cf->commit_hook_fn, fn, memory_order_acq_rel);

    /* keep the db-level gate exact: a hook only appears or disappears when the null-ness flips */
    if ((old == NULL) != (fn == NULL))
        atomic_fetch_add_explicit(&db->commit_hook_count, fn ? 1 : -1, memory_order_relaxed);
    return TDB_SUCCESS;
}
