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

#include "base/encoding/serialization.h" /* TDB_WAL_EXT */
#include "base/errors.h"
#include "base/log.h"
#include "column_family/level/level_set.h"
#include "compat.h" /* mkdir, opendir/readdir, stat, S_ISDIR, PATH_SEPARATOR, usleep, errno */
#include "engine.h"
#include "io/block_manager.h"
#include "manifest/manifest.h"
#include "sstable/sstable.h"
#include "txn/mvcc.h"

/* a backup directory and its per-cf subdirectories are created with the same mode as the live db */
#define ENGINE_BACKUP_DIR_MODE 0755

/* the copy buffer for streaming one file to the backup */
#define ENGINE_BACKUP_COPY_BUF 65536

/* the poll interval and bound backup waits for an in-progress compaction to finish before it can
 * claim a family; the product caps the wait so a stuck compaction surfaces as busy */
#define ENGINE_BACKUP_FREEZE_STALL_US 1000
#define ENGINE_BACKUP_FREEZE_TICKS    60000

/* upper bound on a backup path (destination dir, a separator, a cf name, a separator, a klog name)
 */
#define ENGINE_BACKUP_PATH_MAX 4096

/* upper bound on a klog file name (a zero-padded id and the extension) */
#define ENGINE_BACKUP_KLOG_NAME_MAX 64

/* join a directory and a leaf into dst with the platform separator; returns -1 if it would not fit
 */
static int engine_join(char *dst, size_t cap, const char *dir, const char *leaf)
{
    const int n = snprintf(dst, cap, "%s%s%s", dir, PATH_SEPARATOR, leaf);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/* whether a top-level file is a write-ahead log; the backup skips wals since the flush already
 * drained every committed write into the copied sstables, and a live wal would copy torn */
static int engine_is_wal_name(const char *name)
{
    const size_t nlen = strlen(name), elen = strlen(TDB_WAL_EXT);
    return nlen >= elen && strcmp(name + nlen - elen, TDB_WAL_EXT) == 0;
}

int engine_copy_file(const char *src, const char *dst, uint64_t limit)
{
    FILE *in = fopen(src, "rb");
    if (!in)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup cannot read %s", src);
        return TDB_ERR_IO;
    }
    FILE *out = fopen(dst, "wb");
    if (!out)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup cannot write %s", dst);
        fclose(in);
        return TDB_ERR_IO;
    }

    int rc = TDB_SUCCESS;
    uint8_t *buf = malloc(ENGINE_BACKUP_COPY_BUF);
    if (!buf)
        rc = TDB_ERR_MEMORY;
    else
    {
        uint64_t remaining = limit;
        while (remaining > 0)
        {
            const size_t want =
                remaining < ENGINE_BACKUP_COPY_BUF ? (size_t)remaining : ENGINE_BACKUP_COPY_BUF;
            const size_t got = fread(buf, 1, want, in);
            if (got == 0) break;
            if (fwrite(buf, 1, got, out) != got)
            {
                rc = TDB_ERR_IO;
                break;
            }
            remaining -= got;
        }
        if (rc == TDB_SUCCESS && ferror(in)) rc = TDB_ERR_IO;
    }

    free(buf);
    if (fclose(out) != 0) rc = rc == TDB_SUCCESS ? TDB_ERR_IO : rc;
    fclose(in);
    if (rc != TDB_SUCCESS) TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup copy of %s failed rc=%d", src, rc);
    return rc;
}

/* the file name after the last path separator */
static const char *engine_basename(const char *path)
{
    const char *sep = strrchr(path, PATH_SEPARATOR[0]);
    return sep ? sep + 1 : path;
}

/* the logical length to copy a value-log segment to, or zero when the name is not a segment the
 * store currently holds. a segment's preallocated tail is not part of its contents, so copying the
 * whole file would produce a backup that differs from the source */
static uint64_t engine_backup_segment_size(const vlog_segment_info_t *segs, size_t n,
                                           const char *name)
{
    for (size_t i = 0; i < n; i++)
    {
        if (strcmp(segs[i].name, name) == 0) return segs[i].logical_size;
    }
    return 0;
}

/* copy the manifest into dir. the length is measured and applied inside one hold, because a commit
 * that pushes the log past its rollover bound renames a fresh snapshot over this path -- a length
 * measured before the copy would then be applied to a file that is not the one it described.
 * copying it before anything else is what makes the backup coherent, since every klog and segment
 * it names is captured by the passes that follow, and nothing removes one while the compaction and
 * reclaim claims are held */
static int engine_backup_copy_manifest(tidesdb_t *db, const char *dir)
{
    char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
    const char *name = engine_basename(db->manifest->path);
    if (engine_join(dst, sizeof(dst), dir, name) != 0) return TDB_ERR_IO;
    if (engine_join(src, sizeof(src), db->db_path, name) != 0) return TDB_ERR_IO;

    uint64_t len = 0;
    if (tidesdb_manifest_hold(db->manifest, &len) != 0) return TDB_ERR_IO;
    const int rc = engine_copy_file(src, dst, len);
    tidesdb_manifest_release(db->manifest);
    return rc;
}

/* copy the db's top-level files into dir: each value-log segment to its logical size, every wal
 * skipped, the manifest already taken, every cf subdirectory left for the manifest-driven klog
 * pass */
static int engine_backup_copy_toplevel(tidesdb_t *db, const char *dir)
{
    vlog_segment_info_t *segs = calloc(VLOG_MAX_SEGMENTS, sizeof(*segs));
    if (!segs) return TDB_ERR_MEMORY;
    size_t n_segs = 0;
    if (db->vlog && vlog_list_segments(db->vlog, segs, VLOG_MAX_SEGMENTS, &n_segs) != VLOG_OK)
    {
        free(segs);
        return TDB_ERR_IO;
    }
    const char *manifest_name = engine_basename(db->manifest->path);

    DIR *d = opendir(db->db_path);
    if (!d) return TDB_ERR_IO;

    int rc = TDB_SUCCESS;
    struct dirent *ent;
    while (rc == TDB_SUCCESS && (ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (engine_is_wal_name(ent->d_name)) continue;

        char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
        if (engine_join(src, sizeof(src), db->db_path, ent->d_name) != 0 ||
            engine_join(dst, sizeof(dst), dir, ent->d_name) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }

        struct stat st;
        if (stat(src, &st) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        if (S_ISDIR(st.st_mode)) continue; /* a cf subdirectory, copied by the klog pass */

        if (strcmp(ent->d_name, manifest_name) == 0) continue; /* already taken, under its hold */

        /* a segment retired between the listing and this pass is already fully reclaimed, so
         * skipping it copies a store that is consistent rather than one missing live values */
        const uint64_t size = engine_backup_segment_size(segs, n_segs, ent->d_name);
        if (size > 0) rc = engine_copy_file(src, dst, size);
    }
    closedir(d);
    free(segs);
    return rc;
}

/* copy one family's klogs into the backup, each to the exact on-disk size the manifest records so
 * the preallocated tail of a live file is dropped. the files sit beside each other in the backup
 * root as they do in the source, their names carrying which family they belong to */
static int engine_backup_copy_cf(tidesdb_t *db, cf_t *cf, const char *dir)
{
    const int count = tidesdb_manifest_copy_entries(db->manifest, cf->cf_id, NULL, 0);
    if (count <= 0) return count == 0 ? TDB_SUCCESS : TDB_ERR_IO;

    tidesdb_manifest_entry_t *entries = malloc((size_t)count * sizeof(*entries));
    if (!entries) return TDB_ERR_MEMORY;
    const int got = tidesdb_manifest_copy_entries(db->manifest, cf->cf_id, entries, count);

    int rc = TDB_SUCCESS;
    for (int i = 0; i < got && rc == TDB_SUCCESS; i++)
    {
        char name[ENGINE_BACKUP_KLOG_NAME_MAX];
        char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
        if (sstable_klog_filename(&entries[i], name, sizeof(name)) != TDB_SUCCESS ||
            engine_join(src, sizeof(src), cf->dir, name) != 0 ||
            engine_join(dst, sizeof(dst), dir, name) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        rc = engine_copy_file(src, dst, entries[i].size_bytes);
    }
    free(entries);
    return rc;
}

/* fsync every resident klog of one family so the copied file holds all its data, even under sync
 * none */
static int engine_sync_cf_klogs(cf_t *cf)
{
    const int total = level_set_snapshot(cf->levels, NULL, 0);
    if (total <= 0) return TDB_SUCCESS;
    level_set_snapshot_entry_t *all = calloc((size_t)total, sizeof(*all));
    if (!all) return TDB_ERR_MEMORY;

    int rc = TDB_SUCCESS;
    if (level_set_snapshot(cf->levels, all, total) == total)
        for (int j = 0; j < total; j++)
            if (all[j].sst && sstable_sync_klog(all[j].sst) != TDB_SUCCESS) rc = TDB_ERR_IO;
    for (int j = 0; j < total; j++)
        if (all[j].sst && sstable_unref(all[j].sst)) sstable_close(all[j].sst);
    free(all);
    return rc;
}

/* force the value log and every klog to disk so the copy captures complete files, then commit the
 * clock high-water */
static int engine_backup_sync(tidesdb_t *db, cf_t *const *cfs, int n)
{
    for (int i = 0; i < n; i++)
    {
        const int rc = engine_sync_cf_klogs(cfs[i]);
        if (rc != TDB_SUCCESS) return rc;
    }
    if (db->vlog && vlog_sync(db->vlog) != VLOG_OK) return TDB_ERR_IO;

    /* record the clock high-water so a database opened on the copy, which has no wal to replay,
     * seeds its sequence past every key the copied sstables hold rather than filtering them out */
    tidesdb_manifest_update_sequence(db->manifest, tidesdb_mvcc_current_seq(db->clock));
    return tidesdb_manifest_commit(db->manifest, db->manifest->path, 1) == 0 ? TDB_SUCCESS
                                                                             : TDB_ERR_IO;
}

/* copy the manifest, then the db's other top-level files, then every family's klogs into dir. the
 * caller holds every family's compaction claim and the value-log reclaim claim, which between them
 * are every path that removes a file, so everything the copied manifest names is still there for
 * the passes that follow it. a flush may still add a klog or a segment meanwhile, which the
 * manifest taken first does not name and a restore sweeps away */
static int engine_backup_copy(tidesdb_t *db, const char *dir, cf_t *const *cfs, int n)
{
    int rc = engine_backup_copy_manifest(db, dir);
    if (rc == TDB_SUCCESS) rc = engine_backup_copy_toplevel(db, dir);
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++) rc = engine_backup_copy_cf(db, cfs[i], dir);
    return rc;
}

/**
 * engine_backup_claim_vlog_gc
 * claim the value-log reclaim flag so no segment is unlinked while the copy reads the store. a
 * reclaim copies a segment's live values into the active segment and then unlinks it, so one
 * running mid-copy can move values from a segment already copied into one copied earlier, leaving
 * the backup missing them
 * @param db the database
 * @param out_claimed set to 1 when the flag was taken and the caller must release it
 * @return TDB_SUCCESS, or TDB_ERR_LOCKED when a reclaim would not finish in time
 */
static int engine_backup_claim_vlog_gc(tidesdb_t *db, int *out_claimed)
{
    for (int tick = 0; tick < ENGINE_BACKUP_FREEZE_TICKS; tick++)
    {
        int expected = 0;
        if (atomic_compare_exchange_strong(&db->vlog_gc_active, &expected, 1))
        {
            *out_claimed = 1;
            return TDB_SUCCESS;
        }
        usleep(ENGINE_BACKUP_FREEZE_STALL_US);
    }
    return TDB_ERR_LOCKED;
}

int engine_backup(tidesdb_t *db, const char *dir)
{
    if (!db || !dir) return TDB_ERR_INVALID_ARGS;
    if (mkdir(dir, ENGINE_BACKUP_DIR_MODE) != 0 && errno != EEXIST) return TDB_ERR_IO;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s starting to %s", db->db_path, dir);

    /* land the memtable in L1 first, so the copied sstables hold every committed write */
    int rc = engine_flush_memtable(db);
    if (rc != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup could not flush the memtable first rc=%d", rc);
        return rc;
    }

    /* claim every cf's compaction flag, which freezes compaction, the only path that deletes a
     * klog, so the snapshot the manifest references cannot lose a file mid-copy. the claimed
     * handles are captured here rather than re-indexed later, because a drop removes a family from
     * the registry before it waits the flag out, so an index taken now would name a different
     * family afterwards. this waits under the registry read lock alone and never rotate_lock, so a
     * claim that has to wait out a running compaction does not stall rotations and flushes for the
     * whole wait */
    cf_registry_rdlock(db->cfs);
    const int n = cf_registry_count_locked(db->cfs);
    cf_t **cfs = n ? malloc((size_t)n * sizeof(*cfs)) : NULL;
    int claimed = 0;
    if (n && !cfs) rc = TDB_ERR_MEMORY;
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        cf_t *cf = cf_registry_at_locked(db->cfs, i);
        int got = 0;
        for (int tick = 0; tick < ENGINE_BACKUP_FREEZE_TICKS; tick++)
        {
            int expected = 0;
            if (atomic_compare_exchange_strong(&cf->compacting, &expected, 1))
            {
                got = 1;
                break;
            }
            usleep(ENGINE_BACKUP_FREEZE_STALL_US);
        }
        if (got)
            cfs[claimed++] = cf;
        else
        {
            /* a family whose compaction will not release reports locked, since this result reaches
             * a public caller and the engine-internal contention code must not */
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "backup gave up freezing compaction on cf %s after %d ticks", cf->name,
                          ENGINE_BACKUP_FREEZE_TICKS);
            rc = TDB_ERR_LOCKED;
        }
    }
    cf_registry_rdunlock(db->cfs);

    /* the claims keep these families alive across the copy, since a drop waits the flag out before
     * it frees one, so the copy needs no registry lock at all.
     *
     * it needs no rotation lock either, and must not take one: that lock is what every committer
     * takes to rotate a full memtable, so holding it across a copy of the whole database stops
     * every writer for as long as the copy runs. what the copy actually requires is that nothing
     * removes a file it is about to read, and the two things that remove files are both claimed
     * rather than locked out -- compaction above, and the value-log reclaim here. a flush landing a
     * new klog meanwhile is harmless, because it only adds, and the manifest is copied to the
     * length it had before that could happen */
    int vlog_claimed = 0;
    if (rc == TDB_SUCCESS && db->vlog)
    {
        rc = engine_backup_claim_vlog_gc(db, &vlog_claimed);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "backup could not quiesce the value log reclaim, one is still running");
    }

    if (rc == TDB_SUCCESS)
    {
        rc = engine_backup_sync(db, cfs, claimed);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup could not sync the durable base rc=%d", rc);
        else
        {
            rc = engine_backup_copy(db, dir, cfs, claimed);
            if (rc != TDB_SUCCESS)
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup copy to %s failed rc=%d", dir, rc);
        }
    }

    if (vlog_claimed) atomic_store_explicit(&db->vlog_gc_active, 0, memory_order_release);
    for (int i = 0; i < claimed; i++)
        atomic_store_explicit(&cfs[i]->compacting, 0, memory_order_release);
    free(cfs);

    if (rc == TDB_SUCCESS)
        TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s complete, %d families copied to %s", db->db_path,
                      claimed, dir);
    return rc;
}
