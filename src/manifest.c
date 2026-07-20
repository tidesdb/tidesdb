/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "manifest.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xxhash.h"

#define MANIFEST_TMP_EXT     ".tmp."
#define MANIFEST_TMP_EXT_LEN (sizeof(MANIFEST_TMP_EXT) - 1)

static inline void manifest_put_u32(uint8_t *p, const uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void manifest_put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--)
    {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static inline uint32_t manifest_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t manifest_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* forward declarations; documented at their definitions */
static int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, int level,
                                                 uint64_t id, uint64_t num_entries,
                                                 uint64_t size_bytes, int partition);
static int manifest_rollover_locked(tidesdb_manifest_t *manifest, int durable_sync);

/**
 * tidesdb_manifest_add_sstable_unlocked
 * upsert an sstable into the in-memory entry array. updates in place on a matching (level,id).
 */
static int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, const int level,
                                                 const uint64_t id, const uint64_t num_entries,
                                                 const uint64_t size_bytes, const int partition)
{
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            manifest->entries[i].num_entries = num_entries;
            manifest->entries[i].size_bytes = size_bytes;
            manifest->entries[i].partition = partition;
            return 0;
        }
    }

    if (manifest->num_entries >= manifest->capacity)
    {
        const int new_capacity = manifest->capacity * 2;
        tidesdb_manifest_entry_t *new_entries =
            realloc(manifest->entries, sizeof(tidesdb_manifest_entry_t) * new_capacity);
        if (!new_entries) return -1;
        manifest->entries = new_entries;
        manifest->capacity = new_capacity;
    }

    manifest->entries[manifest->num_entries].level = level;
    manifest->entries[manifest->num_entries].id = id;
    manifest->entries[manifest->num_entries].num_entries = num_entries;
    manifest->entries[manifest->num_entries].size_bytes = size_bytes;
    manifest->entries[manifest->num_entries].partition = partition;
    manifest->num_entries++;
    return 0;
}

/**
 * manifest_remove_entry_unlocked
 * remove a matching (level,id) from the array with an O(1) swap. returns 1 if removed, 0 if absent.
 */
static int manifest_remove_entry_unlocked(tidesdb_manifest_t *manifest, const int level,
                                          const uint64_t id)
{
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            manifest->entries[i] = manifest->entries[manifest->num_entries - 1];
            manifest->num_entries--;
            return 1;
        }
    }
    return 0;
}

/**
 * manifest_pending_reset
 * reset the pending buffer to a fresh batch containing only the format byte. allocates the buffer
 * on first use. returns 0 on success, -1 on allocation failure.
 */
static int manifest_pending_reset(tidesdb_manifest_t *manifest)
{
    if (!manifest->pending)
    {
        manifest->pending = malloc(MANIFEST_BODY_INIT_CAP);
        if (!manifest->pending) return -1;
        manifest->pending_cap = MANIFEST_BODY_INIT_CAP;
    }
    manifest->pending[0] = (uint8_t)MANIFEST_BATCH_FORMAT;
    manifest->pending_len = MANIFEST_BATCH_HDR_SIZE;
    return 0;
}

/**
 * manifest_pending_add_record
 * append one record to the pending batch. for MANIFEST_OP_SEQ the sequence is passed in id. grows
 * the buffer by doubling. returns 0 on success, -1 on allocation failure.
 */
static int manifest_pending_add_record(tidesdb_manifest_t *manifest, const uint8_t op,
                                       const int level, const uint64_t id,
                                       const uint64_t num_entries, const uint64_t size_bytes,
                                       const int partition)
{
    size_t need;
    switch (op)
    {
        case MANIFEST_OP_ADD_P:
            need = MANIFEST_REC_ADD_P_SIZE;
            break;
        case MANIFEST_OP_REMOVE:
            need = MANIFEST_REC_REMOVE_SIZE;
            break;
        case MANIFEST_OP_SEQ:
            need = MANIFEST_REC_SEQ_SIZE;
            break;
        default:
            return -1;
    }

    if (!manifest->pending && manifest_pending_reset(manifest) != 0) return -1;

    if (manifest->pending_len + need > manifest->pending_cap)
    {
        size_t new_cap = manifest->pending_cap ? manifest->pending_cap : MANIFEST_BODY_INIT_CAP;
        while (new_cap < manifest->pending_len + need) new_cap *= 2;
        uint8_t *nb = realloc(manifest->pending, new_cap);
        if (!nb) return -1;
        manifest->pending = nb;
        manifest->pending_cap = new_cap;
    }

    uint8_t *p = manifest->pending + manifest->pending_len;
    *p++ = op;
    if (op == MANIFEST_OP_SEQ)
    {
        manifest_put_u64(p, id);
    }
    else
    {
        manifest_put_u32(p, (uint32_t)level);
        p += 4;
        manifest_put_u64(p, id);
        p += 8;
        if (op == MANIFEST_OP_ADD_P)
        {
            manifest_put_u64(p, num_entries);
            p += 8;
            manifest_put_u64(p, size_bytes);
            p += 8;
            manifest_put_u32(p, (uint32_t)partition);
        }
    }
    manifest->pending_len += need;
    return 0;
}

/**
 * manifest_apply_batch
 * decode one committed block payload (format byte then self-delimiting records) and apply each
 * record to the in-memory set. a record whose fields would overrun the payload marks the batch
 * truncated. returns 0 on a clean batch, -1 if the batch was truncated (a torn final commit).
 */
static int manifest_apply_batch(tidesdb_manifest_t *manifest, const uint8_t *data,
                                const size_t size)
{
    if (size < MANIFEST_BATCH_HDR_SIZE) return -1;
    /* data[0] is the batch format byte; unknown formats are refused rather than misread */
    if (data[0] != (uint8_t)MANIFEST_BATCH_FORMAT) return -1;

    size_t off = MANIFEST_BATCH_HDR_SIZE;
    while (off < size)
    {
        const uint8_t op = data[off];
        switch (op)
        {
            case MANIFEST_OP_ADD:
            {
                /* legacy record with no partition -- a pre-partition-aware writer produced it, so
                 * it is a non-partitioned sstable */
                if (off + MANIFEST_REC_ADD_SIZE > size) return -1;
                const int level = (int)manifest_get_u32(data + off + 1);
                const uint64_t id = manifest_get_u64(data + off + 5);
                const uint64_t ne = manifest_get_u64(data + off + 13);
                const uint64_t sz = manifest_get_u64(data + off + 21);
                tidesdb_manifest_add_sstable_unlocked(manifest, level, id, ne, sz,
                                                      MANIFEST_NO_PARTITION);
                off += MANIFEST_REC_ADD_SIZE;
                break;
            }
            case MANIFEST_OP_ADD_P:
            {
                if (off + MANIFEST_REC_ADD_P_SIZE > size) return -1;
                const int level = (int)manifest_get_u32(data + off + 1);
                const uint64_t id = manifest_get_u64(data + off + 5);
                const uint64_t ne = manifest_get_u64(data + off + 13);
                const uint64_t sz = manifest_get_u64(data + off + 21);
                const int partition = (int)manifest_get_u32(data + off + 29);
                tidesdb_manifest_add_sstable_unlocked(manifest, level, id, ne, sz, partition);
                off += MANIFEST_REC_ADD_P_SIZE;
                break;
            }
            case MANIFEST_OP_REMOVE:
            {
                if (off + MANIFEST_REC_REMOVE_SIZE > size) return -1;
                const int level = (int)manifest_get_u32(data + off + 1);
                const uint64_t id = manifest_get_u64(data + off + 5);
                manifest_remove_entry_unlocked(manifest, level, id);
                off += MANIFEST_REC_REMOVE_SIZE;
                break;
            }
            case MANIFEST_OP_SEQ:
            {
                if (off + MANIFEST_REC_SEQ_SIZE > size) return -1;
                const uint64_t seq = manifest_get_u64(data + off + 1);
                atomic_store(&manifest->sequence, seq);
                off += MANIFEST_REC_SEQ_SIZE;
                break;
            }
            default:
                return -1; /* unknown opcode -- we treat as corruption */
        }
    }
    return 0;
}

/**
 * manifest_replay_locked
 * replay every committed block in the open log into the in-memory set. a torn tail (a crash mid
 * append leaves the last block unreadable) is skipped so the last durable commit wins, but a
 * corrupt block that is followed by valid blocks is genuine mid-file corruption -- an append-only
 * log never writes past a torn tail -- so it fails loud rather than silently dropping entries. a
 * batch payload that will not decode under a valid block frame is corruption too. returns 0 on a
 * clean replay, -1 on mid-file corruption (the caller must refuse to open).
 */
static int manifest_replay_locked(tidesdb_manifest_t *manifest)
{
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, manifest->bm) != 0) return 0;

    int rc = 0;
    int skipped = 0; /* we skipped an unreadable block; a later valid block means mid-file rot */
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
 * manifest_rollover_locked
 * write the current set as one snapshot block (all live ADDs then the final SEQ) to a temp log,
 * fsync it when durable, atomically rename it over the manifest path, and reopen the log handle.
 * this bounds recovery replay and, on a path change, re-points the manifest to the new path.
 * caller holds the write lock. returns 0 on success, -1 on error.
 */
static int manifest_rollover_locked(tidesdb_manifest_t *manifest, const int durable_sync)
{
    const size_t need = MANIFEST_BATCH_HDR_SIZE +
                        (size_t)manifest->num_entries * MANIFEST_REC_ADD_P_SIZE +
                        MANIFEST_REC_SEQ_SIZE;
    uint8_t *buf = malloc(need);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = (uint8_t)MANIFEST_BATCH_FORMAT;
    for (int i = 0; i < manifest->num_entries; i++)
    {
        buf[off] = MANIFEST_OP_ADD_P;
        manifest_put_u32(buf + off + 1, (uint32_t)manifest->entries[i].level);
        manifest_put_u64(buf + off + 5, manifest->entries[i].id);
        manifest_put_u64(buf + off + 13, manifest->entries[i].num_entries);
        manifest_put_u64(buf + off + 21, manifest->entries[i].size_bytes);
        manifest_put_u32(buf + off + 29, (uint32_t)manifest->entries[i].partition);
        off += MANIFEST_REC_ADD_P_SIZE;
    }
    buf[off] = MANIFEST_OP_SEQ;
    manifest_put_u64(buf + off + 1, atomic_load(&manifest->sequence));
    off += MANIFEST_REC_SEQ_SIZE;

    /* temp path is the manifest path plus a per-thread/pid suffix. a truncated temp path would
     * rename over the wrong file, so bail if it would not fit rather than proceed with a clipped
     * name */
    char temp_path[MANIFEST_PATH_LEN + 64];
    const int tp_written = snprintf(temp_path, sizeof(temp_path), "%s" MANIFEST_TMP_EXT "%lu.%d",
                                    manifest->path, (unsigned long)TDB_THREAD_ID(), TDB_GETPID());
    if (tp_written < 0 || (size_t)tp_written >= sizeof(temp_path)) return -1;

    /* the log is opened SYNC_NONE and made durable by an explicit fdatasync so a non-durable commit
     * pays no fsync; the snapshot uses the same discipline */
    block_manager_t *tbm = NULL;
    if (block_manager_open_pre(&tbm, temp_path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) != 0)
    {
        free(buf);
        return -1;
    }

    block_manager_block_t *blk = block_manager_block_create(off, buf);
    free(buf);
    if (!blk)
    {
        block_manager_close(tbm);
        remove(temp_path);
        return -1;
    }
    const int64_t woff = block_manager_block_write(tbm, blk);
    block_manager_block_free(blk);
    if (woff < 0)
    {
        block_manager_close(tbm);
        remove(temp_path);
        return -1;
    }
    if (durable_sync) block_manager_escalate_fsync(tbm);
    block_manager_close(tbm);

    if (atomic_rename_file(temp_path, manifest->path) != 0)
    {
        remove(temp_path);
        return -1;
    }

    if (durable_sync)
    {
        char dir_buf[MANIFEST_PATH_LEN];
        strncpy(dir_buf, manifest->path, sizeof(dir_buf) - 1);
        dir_buf[sizeof(dir_buf) - 1] = '\0';
        char *last_sep = strrchr(dir_buf, '/');
#ifdef _WIN32
        if (!last_sep) last_sep = strrchr(dir_buf, '\\');
#endif
        if (last_sep)
        {
            *last_sep = '\0';
            tdb_sync_directory(dir_buf);
        }
    }

    /* reopen the log on the (possibly new) path so subsequent commits append to the snapshot */
    if (manifest->bm)
    {
        block_manager_close(manifest->bm);
        manifest->bm = NULL;
    }
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
 * manifest_body_append
 * append a raw text line's bytes to the growable body buffer used to verify the version 8 checksum.
 */
static int manifest_body_append(char **body, size_t *len, size_t *cap, const char *line)
{
    const size_t ll = strlen(line);
    if (*len + ll > *cap)
    {
        size_t new_cap = *cap ? *cap : MANIFEST_BODY_INIT_CAP;
        while (new_cap < *len + ll) new_cap *= 2;
        char *new_body = realloc(*body, new_cap);
        if (!new_body) return -1;
        *body = new_body;
        *cap = new_cap;
    }
    memcpy(*body + *len, line, ll);
    *len += ll;
    return 0;
}

/**
 * manifest_parse_legacy_text
 * parse an old text manifest (version 7 without a checksum, version 8 with an xxhash64 body
 * checksum) into the in-memory set. returns 0 on success, -1 on a bad version or checksum mismatch.
 */
static int manifest_parse_legacy_text(tidesdb_manifest_t *manifest, FILE *fp)
{
    char line[MANIFEST_MAX_LINE_LEN];

    int is_v8 = 0;
    if (fgets(line, sizeof(line), fp))
    {
        char *endptr;
        const long version = strtol(line, &endptr, 10);
        if (endptr == line || (version != MANIFEST_VERSION && version != MANIFEST_VERSION_LEGACY))
            return -1;
        is_v8 = (version == MANIFEST_VERSION);
    }
    else
    {
        return 0; /* empty file -- empty set */
    }

    uint64_t expected_checksum = 0;
    char *body = NULL;
    size_t body_len = 0;
    size_t body_cap = 0;
    if (is_v8)
    {
        char *cs_endptr;
        if (!fgets(line, sizeof(line), fp) ||
            (expected_checksum = strtoull(line, &cs_endptr, 16), cs_endptr == line))
            return -1;
    }

    if (fgets(line, sizeof(line), fp))
    {
        if (is_v8 && manifest_body_append(&body, &body_len, &body_cap, line) != 0)
        {
            free(body);
            return -1;
        }
        char *seq_endptr;
        const unsigned long long seq = strtoull(line, &seq_endptr, 10);
        if (seq_endptr == line ||
            (*seq_endptr != '\0' && *seq_endptr != '\n' && *seq_endptr != '\r'))
        {
            free(body);
            return -1;
        }
        atomic_store(&manifest->sequence, seq);
    }

    int skipped_lines = 0;
    while (fgets(line, sizeof(line), fp))
    {
        if (is_v8 && manifest_body_append(&body, &body_len, &body_cap, line) != 0)
        {
            free(body);
            return -1;
        }

        const char *ptr = line;
        char *endptr;
        const long level_val = strtol(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',')
        {
            skipped_lines++;
            continue;
        }
        const int level = (int)level_val;
        ptr = endptr + 1;

        const uint64_t id = strtoull(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',')
        {
            skipped_lines++;
            continue;
        }
        ptr = endptr + 1;

        const uint64_t num_entries = strtoull(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',')
        {
            skipped_lines++;
            continue;
        }
        ptr = endptr + 1;

        const uint64_t size_bytes = strtoull(ptr, &endptr, 10);
        if (endptr == ptr)
        {
            skipped_lines++;
            continue;
        }

        /* legacy text manifest predates partition tracking -- non-partitioned */
        tidesdb_manifest_add_sstable_unlocked(manifest, level, id, num_entries, size_bytes,
                                              MANIFEST_NO_PARTITION);
    }

    if (is_v8)
    {
        const uint64_t actual_checksum = XXH64(body, body_len, 0);
        free(body);
        if (actual_checksum != expected_checksum)
        {
            fprintf(stderr, "tidesdb manifest: checksum mismatch loading %s, refusing to open\n",
                    manifest->path[0] ? manifest->path : "(unknown)");
            return -1;
        }
    }

    if (skipped_lines > 0)
    {
        fprintf(stderr, "tidesdb manifest: skipped %d malformed entry line(s) while loading %s\n",
                skipped_lines, manifest->path[0] ? manifest->path : "(unknown)");
    }
    return 0;
}

/**
 * manifest_cleanup_orphaned_temps
 * remove leftover temp files from an interrupted commit/rollover -- if the main manifest exists,
 * any <base>.tmp.* is stale.
 */
static void manifest_cleanup_orphaned_temps(const char *path)
{
    char dir_path[MANIFEST_PATH_LEN];
    const char *last_sep = strrchr(path, PATH_SEPARATOR[0]);
    if (last_sep)
    {
        const size_t dir_len = last_sep - path;
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

tidesdb_manifest_t *tidesdb_manifest_open(const char *path)
{
    if (!path) return NULL;

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
    atomic_init(&manifest->sequence, 0);
    manifest->bm = NULL;
    manifest->pending = NULL;
    manifest->pending_len = 0;
    manifest->pending_cap = 0;
    manifest->records_since_snapshot = 0;
    manifest->self_healed = 0;
    atomic_init(&manifest->active_ops, 0);
    strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
    manifest->path[MANIFEST_PATH_LEN - 1] = '\0';

    if (pthread_rwlock_init(&manifest->lock, NULL) != 0)
    {
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    manifest_cleanup_orphaned_temps(path);

    /* format detection -- a legacy text manifest starts with its version digit ('7' or '8'); a
     * new-format log starts with the block manager header magic (a non-digit byte). */
    unsigned char sniff = 0;
    int have_sniff = 0;
    int file_empty = 0;
    FILE *sf = tdb_fopen(path, "rb");
    if (sf)
    {
        const size_t got = fread(&sniff, 1, 1, sf);
        have_sniff = (got == 1);
        file_empty = (got == 0); /* exists but has no bytes -- a stale zero-length file */
        fclose(sf);
    }

    if (!sf && errno != ENOENT)
    {
        pthread_rwlock_destroy(&manifest->lock);
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    /* an empty existing file has no block manager header, so drop it and let the log be created
     * fresh below (matches the legacy behavior of opening an empty manifest as an empty set) */
    if (file_empty) remove(path);

    if (have_sniff && (sniff == '7' || sniff == '8'))
    {
        /* legacy text -- we parse then convert forward to the append-only format */
        FILE *fp = tdb_fopen(path, "r");
        if (!fp || manifest_parse_legacy_text(manifest, fp) != 0)
        {
            if (fp) fclose(fp);
            pthread_rwlock_destroy(&manifest->lock);
            free(manifest->entries);
            free(manifest);
            return NULL;
        }
        fclose(fp);
        if (manifest_pending_reset(manifest) != 0 || manifest_rollover_locked(manifest, 1) != 0)
        {
            tidesdb_manifest_close(manifest);
            return NULL;
        }
        return manifest;
    }

    /* new format (or a fresh/empty database) -- open the log and replay it */
    if (block_manager_open_pre(&manifest->bm, path, BLOCK_MANAGER_SYNC_NONE,
                               0 /* preallocation disabled */) != 0)
    {
        /* the file exists but its header will not validate (garbage / truncated header). the
         * sstable files on disk are the ground truth that recovery reloads, so self-heal by
         * discarding the unreadable manifest and starting a fresh log rather than failing the open
         */
        manifest->bm = NULL;
        manifest->self_healed = 1;
        fprintf(stderr, "tidesdb manifest: unreadable header in %s, self-healing to a fresh log\n",
                path[0] ? path : "(unknown)");
        remove(path);
        if (block_manager_open_pre(&manifest->bm, path, BLOCK_MANAGER_SYNC_NONE,
                                   0 /* preallocation disabled */) != 0)
        {
            manifest->bm = NULL;
            pthread_rwlock_destroy(&manifest->lock);
            free(manifest->entries);
            free(manifest);
            return NULL;
        }
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
         * ground truth and recovery reloads them, so keep the good prefix we replayed and rewrite
         * the log as a clean snapshot, discarding the unreadable remainder */
        manifest->self_healed = 1;
        fprintf(stderr,
                "tidesdb manifest: corruption in %s, self-healing from the recovered prefix\n",
                manifest->path[0] ? manifest->path : "(unknown)");
        if (manifest_rollover_locked(manifest, 1) != 0)
        {
            tidesdb_manifest_close(manifest);
            return NULL;
        }
        return manifest;
    }
    return manifest;
}

int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, const int level, const uint64_t id,
                                 const uint64_t num_entries, const uint64_t size_bytes,
                                 const int partition)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);
    int result = tidesdb_manifest_add_sstable_unlocked(manifest, level, id, num_entries, size_bytes,
                                                       partition);
    if (result == 0)
    {
        result = manifest_pending_add_record(manifest, MANIFEST_OP_ADD_P, level, id, num_entries,
                                             size_bytes, partition);
        if (result == 0) manifest->records_since_snapshot++;
    }
    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, const int level,
                                    const uint64_t id)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);
    int result = -1;
    if (manifest_remove_entry_unlocked(manifest, level, id))
    {
        result = manifest_pending_add_record(manifest, MANIFEST_OP_REMOVE, level, id, 0, 0,
                                             MANIFEST_NO_PARTITION);
        if (result == 0) manifest->records_since_snapshot++;
    }
    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, const int level, const uint64_t id)
{
    if (!manifest) return 0;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_rdlock(&manifest->lock);
    int found = 0;
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return found;
}

void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence)
{
    if (!manifest) return;

    /* monotonic guard -- the sequence seeds next_sstable_id on recovery, so it must never regress
     * or recovery would re-hand-out live sstable ids and collide. the value is persisted by the
     * next commit, which appends a SEQ record for the current sequence. */
    uint64_t cur = atomic_load(&manifest->sequence);
    while (sequence > cur && !atomic_compare_exchange_weak(&manifest->sequence, &cur, sequence))
    {
        /* cur reloaded with the live value on failure; loop re-checks sequence > cur */
    }
}

int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path, const int durable_sync)
{
    if (!manifest || !path) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);

    int result = 0;

    /* a path change re-points the manifest and persists the whole set at the new path via a
     * rollover, which reopens the log there */
    if (strcmp(manifest->path, path) != 0)
    {
        strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
        manifest->path[MANIFEST_PATH_LEN - 1] = '\0';
        result = manifest_rollover_locked(manifest, durable_sync);
        pthread_rwlock_unlock(&manifest->lock);
        atomic_fetch_sub(&manifest->active_ops, 1);
        return result;
    }

    if (!manifest->bm)
    {
        if (block_manager_open_pre(&manifest->bm, manifest->path, BLOCK_MANAGER_SYNC_NONE,
                                   0 /* preallocation disabled */) != 0)
        {
            manifest->bm = NULL;
            pthread_rwlock_unlock(&manifest->lock);
            atomic_fetch_sub(&manifest->active_ops, 1);
            return -1;
        }
    }

    /* close the batch with a SEQ record carrying the current sequence so replay's last SEQ wins */
    if (manifest_pending_add_record(manifest, MANIFEST_OP_SEQ, 0, atomic_load(&manifest->sequence),
                                    0, 0, MANIFEST_NO_PARTITION) != 0)
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
            if (off < 0)
                result = -1;
            else if (durable_sync)
                block_manager_escalate_fsync(manifest->bm);
        }
    }

    /* the SEQ record is one more log record regardless of whether the batch carried changes */
    manifest->records_since_snapshot++;
    manifest_pending_reset(manifest);

    /* roll the log over once it grows past a small multiple of the live set, keeping replay bounded
     */
    if (result == 0)
    {
        int bound = manifest->num_entries * MANIFEST_ROLLOVER_LIVE_MULTIPLE;
        if (bound < MANIFEST_ROLLOVER_MIN_RECORDS) bound = MANIFEST_ROLLOVER_MIN_RECORDS;
        if (manifest->records_since_snapshot > bound)
            result = manifest_rollover_locked(manifest, durable_sync);
    }

    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
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
        fprintf(stderr,
                "tidesdb manifest: closing %s with %d operation(s) still active after the drain "
                "wait -- the caller did not quiesce manifest users before close\n",
                manifest->path[0] ? manifest->path : "(unknown)",
                atomic_load(&manifest->active_ops));
    }

    pthread_rwlock_wrlock(&manifest->lock);
    if (manifest->bm)
    {
        block_manager_close(manifest->bm);
        manifest->bm = NULL;
    }
    pthread_rwlock_unlock(&manifest->lock);
    pthread_rwlock_destroy(&manifest->lock);
    free(manifest->pending);
    free(manifest->entries);
    free(manifest);
}
