/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/log.h"
#include "manifest/manifest_internal.h"

#define MANIFEST_TMP_EXT     ".tmp."
#define MANIFEST_TMP_EXT_LEN (sizeof(MANIFEST_TMP_EXT) - 1)

/**
 * manifest_replay_locked
 * replay every committed block in the open log into the in-memory set. a torn tail (a crash mid
 * append leaves the last block unreadable) is skipped so the last durable commit wins, but a
 * corrupt block that is followed by valid blocks is genuine mid-file corruption -- an append-only
 * log never writes past a torn tail -- so it fails loud rather than silently dropping entries. a
 * batch payload that will not decode under a valid block frame is corruption too
 * @param manifest the manifest whose open log is replayed
 * @return 0 on a clean replay, -1 on mid-file corruption (the caller must refuse to open)
 */
static int manifest_replay_locked(tidesdb_manifest_t *manifest)
{
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, manifest->bm) != 0) return 0;

    int rc = 0;
    int skipped = 0; /* set on a skipped unreadable block; a later valid block means mid-file rot */
    if (block_manager_cursor_goto_first(cursor) == 0)
    {
        while (1)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (!block)
            {
                if (block_manager_cursor_skip_corrupt(cursor) == 0)
                {
                    skipped = 1;
                    continue;
                }
                if (block_manager_cursor_resync_past_hole(cursor) == 0)
                {
                    skipped = 1;
                    continue;
                }
                break; /* nothing valid follows -- torn tail, tolerated */
            }
            if (skipped || manifest_apply_batch(manifest, (const uint8_t *)block->data,
                                                (size_t)block->size) != 0)
            {
                block_manager_block_free(block);
                rc = -1;
                break;
            }
            block_manager_block_free(block);
            if (block_manager_cursor_next(cursor) != 0) break;
        }
    }

    block_manager_cursor_free(cursor);
    return rc;
}

/**
 * manifest_snapshot_size
 * bytes a full snapshot batch occupies -- the version byte, one CF_ADD per registered cf (variable
 * for its name), one ADD_P per entry, and the two sequence records
 * @param manifest the manifest to measure
 * @return the byte count
 */
static size_t manifest_snapshot_size(const tidesdb_manifest_t *manifest)
{
    size_t need = MANIFEST_BATCH_HDR_SIZE +
                  (size_t)manifest->num_entries * MANIFEST_REC_ADD_P_SIZE + MANIFEST_REC_SEQ_SIZE +
                  MANIFEST_REC_CF_SEQ_SIZE;
    for (int i = 0; i < manifest->num_cfs; i++)
        need += MANIFEST_REC_CF_ADD_HDR_SIZE +
                strnlen(manifest->cfs[i].name, MANIFEST_CF_NAME_MAX - 1) +
                manifest->cfs[i].config_blob_len;
    return need;
}

/**
 * manifest_encode_snapshot
 * lay the whole live set down in one buffer -- the cf registry, then every live sstable, then each
 * family's range tombstone set, then the two sequence records that close it
 * @param manifest the manifest whose set is being written
 * @param buf the snapshot buffer, sized by manifest_snapshot_size
 * @return the number of bytes written
 */
static size_t manifest_encode_snapshot(const tidesdb_manifest_t *manifest, uint8_t *buf)
{
    size_t off = 0;
    buf[off++] = (uint8_t)MANIFEST_VERSION;

    for (int i = 0; i < manifest->num_cfs; i++)
    {
        const size_t name_len = strnlen(manifest->cfs[i].name, MANIFEST_CF_NAME_MAX - 1);
        const size_t blob_len = manifest->cfs[i].config_blob_len;
        buf[off] = MANIFEST_OP_CF_ADD;
        manifest_put_u64(buf + off + 1, manifest->cfs[i].id);
        manifest_put_u16(buf + off + 9, (uint16_t)name_len);
        manifest_put_u16(buf + off + 11, (uint16_t)blob_len);
        memcpy(buf + off + MANIFEST_REC_CF_ADD_HDR_SIZE, manifest->cfs[i].name, name_len);
        if (blob_len)
            memcpy(buf + off + MANIFEST_REC_CF_ADD_HDR_SIZE + name_len,
                   manifest->cfs[i].config_blob, blob_len);
        off += MANIFEST_REC_CF_ADD_HDR_SIZE + name_len + blob_len;
    }
    for (int i = 0; i < manifest->num_entries; i++)
    {
        buf[off] = MANIFEST_OP_ADD_P;
        manifest_put_u64(buf + off + 1, manifest->entries[i].column_family_id);
        manifest_put_u32(buf + off + 9, (uint32_t)manifest->entries[i].level);
        manifest_put_u64(buf + off + 13, manifest->entries[i].id);
        manifest_put_u64(buf + off + 21, manifest->entries[i].num_entries);
        manifest_put_u64(buf + off + 29, manifest->entries[i].size_bytes);
        manifest_put_u32(buf + off + 37, (uint32_t)manifest->entries[i].partition);
        manifest_put_u32(buf + off + 41, (uint32_t)manifest->entries[i].birth_level);
        off += MANIFEST_REC_ADD_P_SIZE;
    }

    buf[off] = MANIFEST_OP_SEQ;
    manifest_put_u64(buf + off + 1, atomic_load(&manifest->sequence));
    off += MANIFEST_REC_SEQ_SIZE;

    /* a snapshot emits only the live families, so without this record the high-water would fall
     * back to the largest surviving id and a dropped family's id would become reusable again */
    buf[off] = MANIFEST_OP_CF_SEQ;
    manifest_put_u64(buf + off + 1, atomic_load(&manifest->next_cf_id));
    off += MANIFEST_REC_CF_SEQ_SIZE;
    return off;
}

/**
 * manifest_write_snapshot_temp
 * write the encoded snapshot as one block to a temp log beside the manifest and make it durable
 * @param manifest the manifest being snapshotted, for the path the temp sits beside
 * @param buf the encoded snapshot, freed by this call
 * @param len the encoded length
 * @param temp_path receives the temp path written, valid only on success
 * @param temp_path_size capacity of temp_path
 * @param durable_sync non-zero to fsync the temp log before it is renamed into place
 * @return 0 on success, -1 on a path, open, write, or sync failure -- the sync counts because the
 *         caller renames this file over the live manifest, so a barrier that did not hold must not
 *         be reported as a durable snapshot
 */
static int manifest_write_snapshot_temp(tidesdb_manifest_t *manifest, uint8_t *buf, size_t len,
                                        char *temp_path, size_t temp_path_size,
                                        const int durable_sync)
{
    /* temp path is the manifest path plus a per-thread/pid suffix. a truncated temp path would
     * rename over the wrong file, so bail if it would not fit rather than proceed with a clipped
     * name */
    const int tp_written = snprintf(temp_path, temp_path_size, "%s" MANIFEST_TMP_EXT "%lu.%d",
                                    manifest->path, (unsigned long)TDB_THREAD_ID(), TDB_GETPID());
    if (tp_written < 0 || (size_t)tp_written >= temp_path_size)
    {
        free(buf);
        return -1;
    }

    /* the log is opened SYNC_NONE and made durable by an explicit fdatasync so a non-durable commit
     * pays no fsync; the snapshot uses the same discipline */
    block_manager_t *tbm = NULL;
    if (block_manager_open_pre(&tbm, temp_path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) != 0)
    {
        free(buf);
        return -1;
    }

    block_manager_block_t *blk = block_manager_block_create(len, buf);
    free(buf);

    int64_t woff = -1;
    if (blk)
    {
        woff = block_manager_block_write(tbm, blk);
        block_manager_block_free(blk);
    }
    if (woff < 0)
    {
        (void)block_manager_close(tbm);
        remove(temp_path);
        return -1;
    }

    /* the caller renames this file over the live manifest, so a barrier that did not hold must stop
     * it there. reporting the snapshot durable when the sync failed would publish a catalogue whose
     * bytes are still only in the page cache, and the rename would leave nothing to fall back to */
    if (durable_sync && block_manager_escalate_fsync(tbm) != 0)
    {
        (void)block_manager_close(tbm);
        remove(temp_path);
        return -1;
    }
    (void)block_manager_close(tbm);
    return 0;
}

/**
 * manifest_rollover_locked
 * write the current set as one snapshot block to a temp log, fsync it when durable, atomically
 * rename it over the manifest path, and reopen the log handle. this bounds recovery replay and, on
 * a path change, re-points the manifest to the new path. caller holds the write lock
 * @param manifest the manifest to snapshot
 * @param durable_sync non-zero to fsync the snapshot and its directory before returning
 * @return 0 on success, -1 on failure
 */
static int manifest_rollover_locked(tidesdb_manifest_t *manifest, const int durable_sync)
{
    uint8_t *buf = malloc(manifest_snapshot_size(manifest));
    if (!buf) return -1;

    const size_t len = manifest_encode_snapshot(manifest, buf);

    char temp_path[MANIFEST_PATH_LEN + MANIFEST_TMP_SUFFIX_MAX];
    if (manifest_write_snapshot_temp(manifest, buf, len, temp_path, sizeof(temp_path),
                                     durable_sync) != 0)
        return -1;

    /* the log handle goes before the rename rather than after it. the rename replaces the very file
     * that handle holds open, and windows refuses to replace an open file, so an order that closed
     * afterwards could only ever have worked on posix. the caller holds the write lock and a reader
     * waits on the read lock, so nothing reads the manifest across the gap */
    if (manifest->bm)
    {
        (void)block_manager_close(manifest->bm);
        manifest->bm = NULL;
    }

    if (atomic_rename_file(temp_path, manifest->path) != 0)
    {
        remove(temp_path);
        /* the snapshot never landed, so the log still standing at the path is the live one. it is
         * reopened here because the close above already happened, and a manifest left with no
         * handle would fail every commit after this rather than just this one */
        if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE, 0) != 0)
            manifest->bm = NULL;
        return -1;
    }
    /* the platform helper rather than a local copy -- it flushes the directory on windows too,
     * takes the last separator of either kind, and heap-allocates for a path longer than its stack
     * buffer instead of truncating and flushing whatever that left */
    if (durable_sync) tdb_fsync_parent_dir(manifest->path);

    /* reopen the log on the (possibly new) path so subsequent commits append to the snapshot */
    if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) != 0)
    {
        manifest->bm = NULL;
        return -1;
    }

    manifest->records_since_snapshot = 0;
    return manifest_pending_reset(manifest);
}

/**
 * manifest_cleanup_orphaned_temps
 * remove leftover temp files from an interrupted commit/rollover -- if the main manifest exists,
 * any <base>.tmp.* is stale
 * @param path the manifest path whose siblings are swept
 */
static void manifest_cleanup_orphaned_temps(const char *path)
{
    char dir_path[MANIFEST_PATH_LEN];
    const char *last_sep = strrchr(path, PATH_SEPARATOR[0]);
    if (last_sep)
    {
        const size_t dir_len = (size_t)(last_sep - path);
        if (dir_len < sizeof(dir_path))
        {
            memcpy(dir_path, path, dir_len);
            dir_path[dir_len] = '\0';
        }
        else
        {
            strcpy(dir_path, ".");
        }
    }
    else
    {
        strcpy(dir_path, ".");
    }

    const char *base_name = last_sep ? last_sep + 1 : path;
    const size_t base_len = strlen(base_name);

    DIR *dir = opendir(dir_path);
    if (!dir) return;
    const size_t dir_path_len = strlen(dir_path);
    const size_t sep_len = strlen(PATH_SEPARATOR);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        const size_t entry_len = strlen(entry->d_name);
        if (entry_len > base_len + MANIFEST_TMP_EXT_LEN &&
            strncmp(entry->d_name, base_name, base_len) == 0 &&
            strncmp(entry->d_name + base_len, MANIFEST_TMP_EXT, MANIFEST_TMP_EXT_LEN) == 0)
        {
            char temp_full_path[MANIFEST_PATH_LEN];
            if (dir_path_len + sep_len + entry_len + 1 <= MANIFEST_PATH_LEN)
            {
                size_t offset = 0;
                memcpy(temp_full_path + offset, dir_path, dir_path_len);
                offset += dir_path_len;
                memcpy(temp_full_path + offset, PATH_SEPARATOR, sep_len);
                offset += sep_len;
                memcpy(temp_full_path + offset, entry->d_name, entry_len);
                offset += entry_len;
                temp_full_path[offset] = '\0';
                remove(temp_full_path);
            }
        }
    }
    closedir(dir);
}

/**
 * manifest_alloc
 * allocate a manifest with an empty set and its lock ready, before any file is touched
 * @param path the manifest path, copied
 * @return the manifest, or NULL on an allocation or lock init failure
 */
static tidesdb_manifest_t *manifest_alloc(const char *path)
{
    tidesdb_manifest_t *manifest = malloc(sizeof(tidesdb_manifest_t));
    if (!manifest) return NULL;

    manifest->entries = malloc(sizeof(tidesdb_manifest_entry_t) * MANIFEST_INITIAL_CAPACITY);
    if (!manifest->entries)
    {
        free(manifest);
        return NULL;
    }

    manifest->num_entries = 0;
    manifest->capacity = MANIFEST_INITIAL_CAPACITY;
    /* built on the first insert, since a manifest with no entries has nothing to index */
    manifest->index = NULL;
    manifest->index_cap = 0;
    manifest->index_tombs = 0;
    /* the cf registry and the range tombstone sets are allocated lazily on first insert so a
     * database that uses neither carries no extra bookkeeping */
    manifest->cfs = NULL;
    manifest->num_cfs = 0;
    manifest->cfs_capacity = 0;
    atomic_init(&manifest->sequence, 0);
    atomic_init(&manifest->next_cf_id, 0);
    manifest->bm = NULL;
    manifest->pending = NULL;
    manifest->pending_len = 0;
    manifest->pending_cap = 0;
    manifest->records_since_snapshot = 0;
    manifest->self_healed = 0;
    atomic_init(&manifest->active_ops, 0);
    /* the struct is malloc'd, so every field is set here or holds what the allocator left */
    tdb_wait_init(&manifest->commit_wait);
    strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
    manifest->path[MANIFEST_PATH_LEN - 1] = '\0';

    if (tdb_wprwlock_init(&manifest->lock) != 0)
    {
        free(manifest->entries);
        free(manifest->index);
        free(manifest);
        return NULL;
    }
    return manifest;
}

/**
 * manifest_free_unopened
 * release a manifest that never got its log open, so tidesdb_manifest_close cannot be used
 * @param manifest the manifest to release
 */
static void manifest_free_unopened(tidesdb_manifest_t *manifest)
{
    tdb_wprwlock_destroy(&manifest->lock);
    free(manifest->entries);
    free(manifest->index);
    manifest->index = NULL;
    free(manifest);
}

/**
 * manifest_discard_empty_file
 * drop a zero-length manifest left by an interrupted create, which has no block manager header for
 * the open below to validate
 * @param path the manifest path
 * @return 0 when the path is now openable, -1 when it could not be examined
 */
static int manifest_discard_empty_file(const char *path)
{
    FILE *sf = tdb_fopen(path, "rb");
    if (!sf) return errno == ENOENT ? 0 : -1;

    char probe;
    const int file_empty = (fread(&probe, 1, sizeof(probe), sf) == 0);
    fclose(sf);

    if (file_empty) remove(path);
    return 0;
}

/**
 * manifest_open_log
 * open the append-only log, self-healing past a header that will not validate. an unreadable
 * manifest is discarded for a fresh log rather than failing the open, and the caller checks
 * tidesdb_manifest_self_healed to know it must readopt the sstables on disk into the empty
 * catalogue this leaves behind
 * @param manifest the manifest whose log to open, marked self-healed if it had to be discarded
 * @return 0 on success, -1 when even a fresh log could not be created
 */
static int manifest_open_log(tidesdb_manifest_t *manifest)
{
    if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) == 0)
        return 0;

    manifest->bm = NULL;
    manifest->self_healed = 1;
    TDB_DEBUG_LOG(TDB_LOG_WARN, "manifest unreadable header in %s self-healing to a fresh log",
                  manifest->path[0] ? manifest->path : "(unknown)");
    remove(manifest->path);

    if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) != 0)
    {
        manifest->bm = NULL;
        return -1;
    }
    return 0;
}

tidesdb_manifest_t *tidesdb_manifest_open(const char *path)
{
    if (!path) return NULL;

    tidesdb_manifest_t *manifest = manifest_alloc(path);
    if (!manifest) return NULL;

    manifest_cleanup_orphaned_temps(path);

    if (manifest_discard_empty_file(path) != 0 || manifest_open_log(manifest) != 0)
    {
        manifest_free_unopened(manifest);
        return NULL;
    }

    const int replay_rc = manifest_replay_locked(manifest);
    if (manifest_pending_reset(manifest) != 0)
    {
        tidesdb_manifest_close(manifest);
        return NULL;
    }
    if (replay_rc != 0)
    {
        /* mid-file corruption -- self-heal rather than refuse. the sstable files on disk are the
         * ground truth and recovery reloads them, so keep the replayed prefix and rewrite
         * the log as a clean snapshot, discarding the unreadable remainder */
        manifest->self_healed = 1;
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "manifest corruption in %s self-healing from the recovered prefix",
                      manifest->path[0] ? manifest->path : "(unknown)");
        if (manifest_rollover_locked(manifest, 1) != 0)
        {
            tidesdb_manifest_close(manifest);
            return NULL;
        }
    }
    return manifest;
}

/* the commit itself; wrapped below so its several exits are timed in one place rather than each */
static int manifest_commit_inner(tidesdb_manifest_t *manifest, const char *path,
                                 const int durable_sync)
{
    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);

    int result = 0;

    /* a path change re-points the manifest and persists the whole set at the new path via a
     * rollover, which reopens the log there */
    if (strcmp(manifest->path, path) != 0)
    {
        strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
        manifest->path[MANIFEST_PATH_LEN - 1] = '\0';
        result = manifest_rollover_locked(manifest, durable_sync);
        tdb_wprwlock_unlock(&manifest->lock);
        atomic_fetch_sub(&manifest->active_ops, 1);
        return result;
    }

    if (!manifest->bm)
    {
        if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE,
                                   0 /* preallocation disabled */) != 0)
        {
            manifest->bm = NULL;
            tdb_wprwlock_unlock(&manifest->lock);
            atomic_fetch_sub(&manifest->active_ops, 1);
            return -1;
        }
    }

    /* close the batch with a SEQ record carrying the current sequence so replay's last SEQ wins,
     * and a CF_SEQ record so the cf-id high-water survives a drop that removed the largest id */
    if (manifest_pending_add_record(manifest, MANIFEST_OP_SEQ, 0, 0,
                                    atomic_load(&manifest->sequence), 0, 0,
                                    MANIFEST_NO_PARTITION) != 0)
        result = -1;
    if (manifest_pending_add_record(manifest, MANIFEST_OP_CF_SEQ, 0, 0,
                                    atomic_load(&manifest->next_cf_id), 0, 0,
                                    MANIFEST_NO_PARTITION) != 0)
        result = -1;

    if (result == 0)
    {
        block_manager_block_t *blk =
            block_manager_block_create(manifest->pending_len, manifest->pending);
        if (!blk)
        {
            result = -1;
        }
        else
        {
            const int64_t off = block_manager_block_write(manifest->bm, blk);
            block_manager_block_free(blk);
            if (off < 0) result = -1;
            /* the barrier is the commit's whole claim under a durable mode, so a failed one is a
             * failed commit. swallowing it reports the catalogue durable while the records are
             * still only in the page cache -- and a compaction goes on to unlink inputs the
             * manifest would name again after a crash */
            else if (durable_sync && block_manager_escalate_fsync(manifest->bm) != 0)
                result = -1;
        }
    }

    /* the SEQ record is one more log record regardless of whether the batch carried changes */
    manifest->records_since_snapshot++;
    /* a reset that cannot re-arm the buffer leaves it NULL, which the next reserve re-attempts and
     * fails cleanly on, so there is nothing to report from here */
    (void)manifest_pending_reset(manifest);

    /* roll the log over once it grows past a small multiple of the live set, keeping replay bounded
     */
    if (result == 0)
    {
        int bound = manifest->num_entries * MANIFEST_ROLLOVER_LIVE_MULTIPLE;
        if (bound < MANIFEST_ROLLOVER_MIN_RECORDS) bound = MANIFEST_ROLLOVER_MIN_RECORDS;
        if (manifest->records_since_snapshot > bound)
            result = manifest_rollover_locked(manifest, durable_sync);
    }

    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path, const int durable_sync)
{
    if (!manifest || !path) return -1;

    /* every flush install, every compaction install and every ddl serialises through this call, so
     * a database that stops making progress is often waiting here. counted because the stall
     * breakdown had no bucket for it, which left a stalled create with nothing to name */
    const uint64_t commit_from = tdb_monotonic_us();
    const int rc = manifest_commit_inner(manifest, path, durable_sync);
    tdb_wait_note(&manifest->commit_wait, tdb_monotonic_us() - commit_from);
    return rc;
}

void tidesdb_manifest_close(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    int wait_count = 0;
    while (atomic_load(&manifest->active_ops) > 0 && wait_count < MANIFEST_CLOSE_MAX_WAITS)
    {
        usleep(MANIFEST_CLOSE_WAIT_US);
        wait_count++;
    }

    if (atomic_load(&manifest->active_ops) > 0)
    {
        TDB_DEBUG_LOG(
            TDB_LOG_WARN,
            "manifest closing %s with %d operations still active after the drain wait, the "
            "caller did not quiesce manifest users before close",
            manifest->path[0] ? manifest->path : "(unknown)", atomic_load(&manifest->active_ops));
    }

    if (manifest->pending_len > 0) tdb_wprwlock_wrlock(&manifest->lock);
    if (manifest->bm)
    {
        (void)block_manager_close(manifest->bm);
        manifest->bm = NULL;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    tdb_wprwlock_destroy(&manifest->lock);
    free(manifest->pending);
    free(manifest->cfs);
    free(manifest->entries);
    free(manifest->index);
    manifest->index = NULL;
    free(manifest);
}
