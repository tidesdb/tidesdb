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

#include "base/encoding/serialization.h" /* TDB_SSTABLE_KLOG_NAME_MAX */
#include "base/errors.h"
#include "base/log.h"
#include "column_family/level/level_set.h"
#include "compat.h" /* mkdir, opendir/readdir, stat, S_ISDIR, PATH_SEPARATOR, usleep, errno */
#include "engine.h"
#include "io/block_manager.h"
#include "manifest/manifest.h"
#include "sstable/sstable.h"
#include "sstable/vlog_group_disk.h"
#include "txn/mvcc.h"

/* keep the unfinished image private until its single directory rename */
#define ENGINE_BACKUP_DIR_MODE    0700
#define ENGINE_BACKUP_STAGE_TRIES 64

/* the copy buffer for streaming one file to the backup */
#define ENGINE_BACKUP_COPY_BUF 65536

/* the poll interval and bound backup waits for an in-progress compaction to finish before it can
 * claim a family; the product caps the wait so a stuck compaction surfaces as busy */
#define ENGINE_BACKUP_FREEZE_STALL_US 1000
#define ENGINE_BACKUP_FREEZE_TICKS    60000

/* upper bound on a backup path (destination dir, a separator, a cf name, a separator, a klog name)
 */
#define ENGINE_BACKUP_PATH_MAX 4096

/* join a directory and a leaf into dst with the platform separator; returns -1 if it would not fit
 */
static int engine_join(char *dst, size_t cap, const char *dir, const char *leaf)
{
    const int n = snprintf(dst, cap, "%s%s%s", dir, PATH_SEPARATOR, leaf);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/* compare opened files before truncating, so path aliases cannot destroy the source */
static int engine_copy_prepare(int src_fd, int dst_fd)
{
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION src_info, dst_info;
    if (!GetFileInformationByHandle((HANDLE)_get_osfhandle(src_fd), &src_info) ||
        !GetFileInformationByHandle((HANDLE)_get_osfhandle(dst_fd), &dst_info))
        return TDB_ERR_IO;
    if (src_info.dwVolumeSerialNumber == dst_info.dwVolumeSerialNumber &&
        src_info.nFileIndexHigh == dst_info.nFileIndexHigh &&
        src_info.nFileIndexLow == dst_info.nFileIndexLow)
        return TDB_ERR_IO;
#else
    struct stat src_info, dst_info;
    if (fstat(src_fd, &src_info) != 0 || fstat(dst_fd, &dst_info) != 0) return TDB_ERR_IO;
    if (src_info.st_dev == dst_info.st_dev && src_info.st_ino == dst_info.st_ino) return TDB_ERR_IO;
    /* devices such as /dev/null accept writes but cannot be truncated */
    if (!S_ISREG(dst_info.st_mode)) return TDB_SUCCESS;
#endif
    return ftruncate(dst_fd, 0) == 0 ? TDB_SUCCESS : TDB_ERR_IO;
}

int engine_copy_file(const char *src, const char *dst, uint64_t limit, const int durable)
{
    FILE *in = fopen(src, "rb");
    if (!in)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup cannot read %s", src);
        return TDB_ERR_IO;
    }
    /* omit truncation until the opened destination is known to differ from the source */
#ifdef _WIN32
    const int dst_fd = open(dst, O_WRONLY | O_CREAT | O_BINARY, 0666);
#else
    const int dst_fd = open(dst, O_WRONLY | O_CREAT, 0666);
#endif
    if (dst_fd < 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup cannot write %s", dst);
        fclose(in);
        return TDB_ERR_IO;
    }

    if (engine_copy_prepare(tdb_fileno(in), dst_fd) != TDB_SUCCESS)
    {
        close(dst_fd);
        fclose(in);
        return TDB_ERR_IO;
    }
#ifdef _WIN32
    FILE *out = _fdopen(dst_fd, "wb");
#else
    FILE *out = fdopen(dst_fd, "wb");
#endif
    if (!out)
    {
        close(dst_fd);
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
            if (got < want) break; /* EOF or a read error, checked below against the extent */
        }
        if (rc == TDB_SUCCESS && (ferror(in) || (limit != UINT64_MAX && remaining > 0)))
            rc = TDB_ERR_IO;
    }

    /* a durable copy is relied on the moment this returns, a clone's catalogue names it and a
     * backup is handed back as finished, so its bytes and then its name reach the device first */
    if (durable && rc == TDB_SUCCESS && (fflush(out) != 0 || tdb_fsync(tdb_fileno(out)) != 0))
        rc = TDB_ERR_IO;

    free(buf);
    if (fclose(out) != 0) rc = rc == TDB_SUCCESS ? TDB_ERR_IO : rc;
    fclose(in);
    if (durable && rc == TDB_SUCCESS && tdb_fsync_parent_dir(dst) != 0) rc = TDB_ERR_IO;
    if (rc != TDB_SUCCESS) TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup copy of %s failed rc=%d", src, rc);
    return rc;
}

/* the file name after the last path separator */
static const char *engine_basename(const char *path)
{
    const char *sep = strrchr(path, PATH_SEPARATOR[0]);
    return sep ? sep + 1 : path;
}

/* capture the manifest and its exact table inventory in one short read hold. the hold keeps a
 * rollover from replacing the path while it is copied, and makes every later klog decision come
 * from the catalogue image actually placed in the backup. it deliberately ends before the bulk
 * data copies, so a slow backup does not block flush or DDL commits. */
static int engine_backup_capture_manifest(tidesdb_t* db, const char* dir,
                                          tidesdb_manifest_entry_t** out_entries, int* out_count)
{
    char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
    const char *name = engine_basename(db->manifest->path);
    if (engine_join(dst, sizeof(dst), dir, name) != 0) return TDB_ERR_IO;
    if (engine_join(src, sizeof(src), db->db_path, name) != 0) return TDB_ERR_IO;

    uint64_t len = 0;
    if (tidesdb_manifest_hold(db->manifest, &len) != 0) return TDB_ERR_IO;
    const int count = db->manifest->num_entries;
    int rc = TDB_SUCCESS;
    if (count > 0)
    {
        *out_entries = malloc((size_t)count * sizeof(**out_entries));
        if (*out_entries)
            memcpy(*out_entries, db->manifest->entries, (size_t)count * sizeof(**out_entries));
        else
            rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS) rc = engine_copy_file(src, dst, len, 1);
    tidesdb_manifest_release(db->manifest);
    *out_count = count;
    return rc;
}

/* every append through the transaction cut has finished, its flush has installed, and the
 * maintenance claims exclude builders and reclamation while the extents are sampled. */
static int engine_backup_capture_vlog(tidesdb_t* db, vlog_segment_info_t** out, size_t* count)
{
    if (!db->vlog) return TDB_SUCCESS;
    const uint32_t capacity = vlog_max_segments(db->vlog);
    *out = calloc(capacity, sizeof(**out));
    if (!*out) return TDB_ERR_MEMORY;
    const int rc = vlog_backup_inventory(db->vlog, *out, capacity, count);
    if (rc == VLOG_ERR_MEMORY) return TDB_ERR_MEMORY;
    if (rc == VLOG_ERR_BUSY) return TDB_ERR_LOCKED;
    return rc == VLOG_OK ? TDB_SUCCESS : TDB_ERR_IO;
}

/* copy each captured prefix once. reclaim is excluded through the final index rebind. */
static int engine_backup_copy_vlog(tidesdb_t* db, const char* dir, const vlog_segment_info_t* segs,
                                   size_t count)
{
    int rc = TDB_SUCCESS;
    for (size_t i = 0; rc == TDB_SUCCESS && i < count; i++)
    {
        char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
        const char* source_dir = db->db_path;
        const char* destination_dir = dir;
        char source_guard[ENGINE_BACKUP_PATH_MAX], destination_guard[ENGINE_BACKUP_PATH_MAX];
        if (segs[i].group != VLOG_GROUP_UNGROUPED)
        {
            if (engine_join(source_guard, sizeof(source_guard), db->db_path,
                            VLOG_GROUP_GUARD_NAME) != 0 ||
                engine_join(destination_guard, sizeof(destination_guard), dir,
                            VLOG_GROUP_GUARD_NAME) != 0 ||
                vlog_group_disk_guard_create(dir) != VLOG_OK)
            {
                rc = TDB_ERR_IO;
                break;
            }
            source_dir = source_guard;
            destination_dir = destination_guard;
        }
        char name[VLOG_SEGMENT_NAME_MAX];
        if (vlog_segment_name(segs[i].number, name, sizeof(name)) != VLOG_OK ||
            engine_join(src, sizeof(src), source_dir, name) != 0 ||
            engine_join(dst, sizeof(dst), destination_dir, name) != 0)
            rc = TDB_ERR_IO;
        else
            rc = engine_copy_file(src, dst, segs[i].logical_size, 1);
        if (rc == TDB_SUCCESS)
        {
            const int indexed = vlog_backup_index(db->vlog, &segs[i], src, dst, dir);
            if (indexed != VLOG_OK) rc = indexed == VLOG_ERR_MEMORY ? TDB_ERR_MEMORY : TDB_ERR_IO;
        }
    }
    return rc;
}

/* copy the klogs named by the captured catalogue, each to its recorded size so the preallocated
 * tail of a live file is dropped. compaction claims prevent any of these names from being removed
 * after the manifest hold ends; a later flush adds a different entry and is outside this cut. */
static int engine_backup_copy_entries(tidesdb_t* db, const char* dir,
                                      const tidesdb_manifest_entry_t* entries, int count)
{
    int rc = TDB_SUCCESS;
    for (int i = 0; i < count && rc == TDB_SUCCESS; i++)
    {
        char name[TDB_SSTABLE_KLOG_NAME_MAX];
        char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
        if (sstable_klog_filename(&entries[i], name, sizeof(name)) != TDB_SUCCESS ||
            engine_join(src, sizeof(src), db->db_path, name) != 0 ||
            engine_join(dst, sizeof(dst), dir, name) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        rc = engine_copy_file(src, dst, entries[i].size_bytes, 1);
    }
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
static int engine_backup_sync(tidesdb_t* db, cf_t* const* cfs, int n, uint64_t sequence)
{
    for (int i = 0; i < n; i++)
    {
        const int rc = engine_sync_cf_klogs(cfs[i]);
        if (rc != TDB_SUCCESS) return rc;
    }
    if (db->vlog && vlog_sync(db->vlog) != VLOG_OK) return TDB_ERR_IO;

    /* record the clock high-water so a database opened on the copy, which has no wal to replay,
     * seeds its sequence past every key the copied sstables hold rather than filtering them out */
    tidesdb_manifest_update_sequence(db->manifest, sequence);
    return tidesdb_manifest_commit(db->manifest, db->manifest->path, 1) == 0 ? TDB_SUCCESS
                                                                             : TDB_ERR_IO;
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

static int engine_backup_into(tidesdb_t* db, const char* dir)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s starting to %s", db->db_path, dir);

    int rc = TDB_SUCCESS;

    /* exclude DDL before borrowing and claiming the families. a drop holds this lock while it
     * waits for a claim, so taking it after a backup claim could deadlock; taken first it also
     * means no newly cloned family can enter the manifest between this inventory and the cut below.
     */
    pthread_mutex_lock(&db->ddl_lock);

    /* claim every cf's compaction flag, which freezes compaction, the only path that deletes a
     * klog, so the snapshot the manifest references cannot lose a file mid-copy. the view keeps a
     * handle alive while it is claimed; DDL remains excluded until the cut has named all claims. */
    cf_t **live = NULL;
    int n = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &live, &n);
    cf_t **cfs = n ? malloc((size_t)n * sizeof(*cfs)) : NULL;
    int claimed = 0;
    if (n && !cfs) rc = TDB_ERR_MEMORY;
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        cf_t *cf = live[i];
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
    cf_registry_view_leave(db->cfs, view);

    /* the claims keep these families alive across the copy, since a drop waits the flag out before
     * it frees one. the value-log claim similarly excludes its only deleting path. */
    int vlog_claimed = 0;
    if (rc == TDB_SUCCESS && db->vlog)
    {
        rc = engine_backup_claim_vlog_gc(db, &vlog_claimed);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "backup could not quiesce the value log reclaim, one is still running");
    }

    tidesdb_manifest_entry_t* entries = NULL;
    int entry_count = 0;
    vlog_segment_info_t* segs = NULL;
    size_t segment_count = 0;
    int backup_gate = 0;
    uint64_t bound = 0;
    if (rc == TDB_SUCCESS)
    {
        if (tidesdb_mvcc_backup_begin(db->clock, &bound) != 0)
            rc = TDB_ERR_LOCKED;
        else
        {
            backup_gate = 1;
            /* every later draw waits inside the clock before it can append or apply, while every
             * earlier sequence is already drawn and must reach a visible decision here. */
            if (bound > 1) tidesdb_mvcc_wait_visible(db->clock, bound - 1);
            if (tidesdb_mvcc_visible_seq(db->clock) < bound - 1)
                rc = TDB_ERR_LOCKED;
            else
                rc = engine_flush_memtable(db);
        }
    }
    if (rc == TDB_SUCCESS)
    {
        /* form one completed install prefix. rotate_lock prevents a new immutable from joining the
         * cut, and install_lock waits out and then excludes every flush install. this is
         * deliberately held only while syncing and capturing metadata, never during the bulk file
         * copy. */
        pthread_mutex_lock(&db->rotate_lock);
        pthread_mutex_lock(&db->install_lock);
        rc = engine_backup_sync(db, cfs, claimed, bound - 1);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup could not sync the durable base rc=%d", rc);
        else
        {
            /* no flush, compaction, or DDL can mutate the manifest here, so its in-memory entries
             * and copied on-disk log describe the same atomic cross-family install prefix. */
            rc = engine_backup_capture_manifest(db, dir, &entries, &entry_count);
            if (rc != TDB_SUCCESS)
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup could not capture the manifest rc=%d", rc);
        }
        if (rc == TDB_SUCCESS) rc = engine_backup_capture_vlog(db, &segs, &segment_count);
        pthread_mutex_unlock(&db->install_lock);
        pthread_mutex_unlock(&db->rotate_lock);
    }

    /* DDL and committers resume before the potentially long value-log and klog copy. a later
     * flush is outside this cut; the claims above still prevent removal of every captured file. */
    pthread_mutex_unlock(&db->ddl_lock);

    if (backup_gate) tidesdb_mvcc_backup_end(db->clock);

    if (rc == TDB_SUCCESS)
    {
        rc = engine_backup_copy_vlog(db, dir, segs, segment_count);
        if (rc == TDB_SUCCESS) rc = engine_backup_copy_entries(db, dir, entries, entry_count);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup copy to %s failed rc=%d", dir, rc);
    }

    if (vlog_claimed) atomic_store_explicit(&db->vlog_gc_active, 0, memory_order_release);
    for (int i = 0; i < claimed; i++)
        atomic_store_explicit(&cfs[i]->compacting, 0, memory_order_release);
    free(segs);
    free(entries);
    free(cfs);

    if (rc == TDB_SUCCESS)
        TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s staged, %d families copied to %s", db->db_path,
                      claimed, dir);
    return rc;
}

/* avoid touching the source if the target already holds data. the final rename also refuses
 * a nonempty directory, including one populated by a competing backup after this check. */
static int engine_backup_destination(const char* dir)
{
    DIR* d = opendir(dir);
    if (!d) return errno == ENOENT ? TDB_SUCCESS : TDB_ERR_IO;
    int rc = TDB_SUCCESS;
    struct dirent* ent;
    errno = 0;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
    }
    if (errno != 0) rc = TDB_ERR_IO;
    if (closedir(d) != 0) rc = TDB_ERR_IO;
    return rc;
}

/* place the scratch directory beside the destination so publication stays on one filesystem.
 * mkdir exclusively claims an unused name even across processes or after an interrupted call. */
static int engine_backup_stage(const char* dir, char* stage, size_t capacity)
{
    size_t base = strlen(dir);
    while (base && dir[base - 1] != '/' && dir[base - 1] != PATH_SEPARATOR[0]) --base;
    /* different leading characters keep even a caller-chosen staging-like name distinct */
    const char lead = dir[base] == '.' ? '_' : '.';
    for (int attempt = 0; attempt < ENGINE_BACKUP_STAGE_TRIES; ++attempt)
    {
        const int n = snprintf(stage, capacity, "%.*s%ctidesdb-backup-%ld-%d", (int)base, dir, lead,
                               (long)TDB_GETPID(), attempt);
        if (n < 0 || (size_t)n >= capacity) return TDB_ERR_IO;
        if (mkdir(stage, ENGINE_BACKUP_DIR_MODE) == 0) return TDB_SUCCESS;
        if (errno != EEXIST) return TDB_ERR_IO;
    }
    return TDB_ERR_IO;
}

int engine_backup(tidesdb_t* db, const char* dir)
{
    if (!db || !dir) return TDB_ERR_INVALID_ARGS;
    char destination[ENGINE_BACKUP_PATH_MAX], stage[ENGINE_BACKUP_PATH_MAX];
    size_t len = strlen(dir);
    if (!len || len >= sizeof(destination)) return TDB_ERR_IO;
    memcpy(destination, dir, len + 1);
    while (len > 1 && (destination[len - 1] == '/' || destination[len - 1] == PATH_SEPARATOR[0]))
        destination[--len] = '\0';
    int rc = engine_backup_destination(destination);
    if (rc != TDB_SUCCESS) return rc;
    rc = engine_backup_stage(destination, stage, sizeof(stage));
    if (rc != TDB_SUCCESS) return rc;
    rc = engine_backup_into(db, stage);
    if (rc == TDB_SUCCESS && tdb_publish_directory(stage, destination) == 0)
        return tdb_fsync_parent_dir(destination) == 0 ? TDB_SUCCESS : TDB_ERR_IO;
    if (remove_directory(stage) != 0)
        TDB_DEBUG_LOG(TDB_LOG_WARN, "could not clean incomplete backup %s", stage);
    return rc == TDB_SUCCESS ? TDB_ERR_IO : rc;
}
