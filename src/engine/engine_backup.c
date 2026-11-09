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

#include "base/errors.h"
#include "base/log.h"
#include "column_family/level/level_set.h"
#include "compat.h" /* mkdir, opendir/readdir, stat, S_ISDIR, PATH_SEPARATOR, usleep, errno */
#include "engine_internal.h"
#include "io/block_manager.h"
#include "manifest/manifest.h"
#include "sstable/sstable.h"
#include "txn/mvcc.h"

/* a backup directory and its per-cf subdirectories are created with the same mode as the live db */
#define ENGINE_BACKUP_DIR_MODE 0755

/* the copy buffer for streaming one file to the backup */
#define ENGINE_BACKUP_COPY_BUF 65536

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
            if (got < want)
                break; /* eof or a stream error, checked against the requested extent below */
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

/* a flush after the cut can add tables and a writer can extend the active value log. capture the
 * exact names and lengths before releasing writers, then copy just those bytes. */
typedef struct
{
    tidesdb_manifest_entry_t *tables;
    int num_tables;
    vlog_segment_info_t *segments;
    size_t num_segments;
} engine_backup_files_t;

static int engine_backup_capture(tidesdb_t *db, const char *dir, engine_backup_files_t *files)
{
    if (db->vlog)
    {
        files->segments = calloc(VLOG_MAX_SEGMENTS, sizeof(*files->segments));
        if (!files->segments) return TDB_ERR_MEMORY;
        if (vlog_list_segments(db->vlog, files->segments, VLOG_MAX_SEGMENTS,
                               &files->num_segments) != VLOG_OK)
            return TDB_ERR_IO;
    }

    char dst[ENGINE_BACKUP_PATH_MAX];
    if (engine_join(dst, sizeof(dst), dir, engine_basename(db->manifest->path)) != 0)
        return TDB_ERR_IO;

    uint64_t len = 0;
    if (tidesdb_manifest_hold(db->manifest, &len) != 0) return TDB_ERR_IO;
    int rc = TDB_SUCCESS;
    files->num_tables = db->manifest->num_entries;
    if (files->num_tables > 0)
    {
        const size_t bytes = (size_t)files->num_tables * sizeof(*files->tables);
        files->tables = malloc(bytes);
        if (files->tables)
            memcpy(files->tables, db->manifest->entries, bytes);
        else
            rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS) rc = engine_copy_file(db->manifest->path, dst, len, 1);
    tidesdb_manifest_release(db->manifest);
    return rc;
}

static int engine_backup_copy_extent(const char *source, const char *dir, const char *name,
                                     uint64_t size)
{
    char src[ENGINE_BACKUP_PATH_MAX], dst[ENGINE_BACKUP_PATH_MAX];
    if (engine_join(src, sizeof(src), source, name) != 0 ||
        engine_join(dst, sizeof(dst), dir, name) != 0)
        return TDB_ERR_IO;
    return engine_copy_file(src, dst, size, 1);
}

static int engine_backup_copy(const char *source, const char *dir,
                              const engine_backup_files_t *files)
{
    for (size_t i = 0; i < files->num_segments; i++)
    {
        const vlog_segment_info_t *seg = &files->segments[i];
        const int rc = engine_backup_copy_extent(source, dir, seg->name, seg->logical_size);
        if (rc != TDB_SUCCESS) return rc;
    }
    for (int i = 0; i < files->num_tables; i++)
    {
        char name[TDB_SSTABLE_KLOG_NAME_MAX];
        const tidesdb_manifest_entry_t *entry = &files->tables[i];
        if (sstable_klog_filename(entry, name, sizeof(name)) != TDB_SUCCESS) return TDB_ERR_IO;
        const int rc = engine_backup_copy_extent(source, dir, name, entry->size_bytes);
        if (rc != TDB_SUCCESS) return rc;
    }
    return TDB_SUCCESS;
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
static int engine_backup_sync(tidesdb_t *db, cf_t *const *cfs, int n, uint64_t sequence)
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

/* earlier draws have finished applying to l0 once the watermark reaches the cut. later draws
 * cannot append or apply until its manifest and value-log extents have been captured. */
static int engine_backup_cut(tidesdb_t *db, const char *dir, cf_t *const *cfs, int n,
                             engine_backup_files_t *files)
{
    uint64_t bound = 0;
    if (tidesdb_mvcc_backup_begin(db->clock, &bound) != 0) return TDB_ERR_LOCKED;
    const uint64_t sequence = bound - 1;
    tidesdb_mvcc_wait_visible(db->clock, sequence);
    int rc = tidesdb_mvcc_visible_seq(db->clock) >= sequence ? engine_flush_memtable(db)
                                                             : TDB_ERR_LOCKED;
    if (rc == TDB_SUCCESS)
    {
        /* the queue can drain just before its last flush finishes installing. no new transaction
         * can fill the active memtable while we wait for that install and capture its files. */
        pthread_mutex_lock(&db->install_lock);
        rc = engine_backup_sync(db, cfs, n, sequence);
        if (rc == TDB_SUCCESS) rc = engine_backup_capture(db, dir, files);
        pthread_mutex_unlock(&db->install_lock);
    }
    tidesdb_mvcc_backup_end(db->clock);
    return rc;
}

int engine_backup(tidesdb_t *db, const char *dir)
{
    if (!db || !dir) return TDB_ERR_INVALID_ARGS;
    if (mkdir(dir, ENGINE_BACKUP_DIR_MODE) != 0 && errno != EEXIST) return TDB_ERR_IO;

    /* reject nonempty destinations before flushing or copying any source files */
    DIR *d = opendir(dir);
    if (!d) return TDB_ERR_IO;
    struct dirent *ent;
    errno = 0;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        closedir(d);
        return TDB_ERR_IO;
    }
    const int read_error = errno;
    if (closedir(d) != 0 || read_error != 0) return TDB_ERR_IO;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s starting to %s", db->db_path, dir);

    /* a drop owns ddl_lock before it waits on its family's compaction claim. use that order here
     * and hold ddl_lock through the cut so the manifest cannot name a newly created family we
     * never claimed. the registry view keeps the list of claims valid through the file copies. */
    pthread_mutex_lock(&db->ddl_lock);
    cf_t **cfs = NULL;
    int n = 0, claimed = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &cfs, &n);
    int rc = TDB_SUCCESS;
    while (claimed < n && rc == TDB_SUCCESS)
    {
        rc = engine_claim_maintenance(&cfs[claimed]->compacting);
        if (rc == TDB_SUCCESS) claimed++;
    }

    int vlog_claimed = 0;
    if (rc == TDB_SUCCESS && db->vlog)
    {
        rc = engine_claim_maintenance(&db->vlog_gc_active);
        vlog_claimed = rc == TDB_SUCCESS;
    }
    engine_backup_files_t files = {0};
    if (rc == TDB_SUCCESS) rc = engine_backup_cut(db, dir, cfs, n, &files);
    pthread_mutex_unlock(&db->ddl_lock);

    if (rc == TDB_SUCCESS) rc = engine_backup_copy(db->db_path, dir, &files);
    free(files.tables);
    free(files.segments);
    if (vlog_claimed) atomic_store_explicit(&db->vlog_gc_active, 0, memory_order_release);
    for (int i = 0; i < claimed; i++)
        atomic_store_explicit(&cfs[i]->compacting, 0, memory_order_release);
    cf_registry_view_leave(db->cfs, view);

    if (rc == TDB_SUCCESS)
        TDB_DEBUG_LOG(TDB_LOG_INFO, "backup of %s complete, %d families copied to %s", db->db_path,
                      claimed, dir);
    else
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "backup of %s to %s failed rc=%d", db->db_path, dir, rc);
    return rc;
}
