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

tidesdb_manifest_t *tidesdb_manifest_create(void)
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
    manifest->sequence = 0;
    manifest->bm = NULL;
    manifest->path[0] = '\0';
    manifest->block_count = 0;

    return manifest;
}

tidesdb_manifest_t *tidesdb_manifest_load(const char *path)
{
    /* try to open block manager file */
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        /* file doesn't exist, create new manifest */
        if (errno == ENOENT) return tidesdb_manifest_create();
        return NULL;
    }

    /* validate last block (permissive mode: truncate to last valid block) */
    if (block_manager_validate_last_block(bm, 0) != 0)
    {
        block_manager_close(bm);
        return NULL;
    }

    /* create cursor and go to last block (most recent manifest state) */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return NULL;
    }

    if (block_manager_cursor_goto_last(cursor) != 0)
    {
        /* empty file, create new manifest */
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return tidesdb_manifest_create();
    }

    /* read last block */
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    block_manager_cursor_free(cursor);
    block_manager_close(bm);

    if (!block)
    {
        return NULL;
    }

    /* deserialize manifest from binary format */
    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    if (!manifest)
    {
        block_manager_block_free(block);
        return NULL;
    }

    uint8_t *ptr = (uint8_t *)block->data;
    uint8_t *end = ptr + block->size;

    /* read header */
    if (ptr + 16 > end) /* need at least 16 bytes for header */
    {
        block_manager_block_free(block);
        tidesdb_manifest_free(manifest);
        return NULL;
    }

    uint32_t version;
    memcpy(&version, ptr, 4);
    ptr += 4;

    if (version != MANIFEST_VERSION)
    {
        block_manager_block_free(block);
        tidesdb_manifest_free(manifest);
        return NULL;
    }

    memcpy(&manifest->sequence, ptr, 8);
    ptr += 8;

    uint32_t num_entries;
    memcpy(&num_entries, ptr, 4);
    ptr += 4;

    /* read entries */
    size_t entry_size = 4 + 8 + 8 + 8; /* 28 bytes per entry */
    for (uint32_t i = 0; i < num_entries; i++)
    {
        if (ptr + entry_size > end)
        {
            block_manager_block_free(block);
            tidesdb_manifest_free(manifest);
            return NULL;
        }

        uint32_t level;
        memcpy(&level, ptr, 4);
        ptr += 4;

        uint64_t id;
        memcpy(&id, ptr, 8);
        ptr += 8;

        uint64_t entry_num_entries;
        memcpy(&entry_num_entries, ptr, 8);
        ptr += 8;

        uint64_t size_bytes;
        memcpy(&size_bytes, ptr, 8);
        ptr += 8;

        tidesdb_manifest_add_sstable(manifest, (int)level, id, entry_num_entries, size_bytes);
    }

    block_manager_block_free(block);

    /* compact manifest -- remove entries for sstables that no longer exist on disk
     * this prevents manifest from growing indefinitely with stale entries
     * only run if manifest is in a real directory (not current dir)
     * skip for test manifests in current directory */
    char dir_path[MANIFEST_PATH_LEN];
    const char *last_sep = strrchr(path, '/');
    const char *last_sep_backslash = strrchr(path, '\\');

    /* use whichever separator appears last in the path */
    if (last_sep_backslash && (!last_sep || last_sep_backslash > last_sep))
    {
        last_sep = last_sep_backslash;
    }

    /* determine which separator to use based on what was found in the path */
    const char *path_sep = PATH_SEPARATOR;
    if (last_sep && *last_sep == '/')
    {
        path_sep = "/";
    }

    /* only compact if manifest is in a real subdirectory (not . or ./) */
    if (last_sep && (last_sep - path) > 0)
    {
        size_t dir_len = last_sep - path;
        if (dir_len < sizeof(dir_path) && dir_len > 1) /* skip "." */
        {
            memcpy(dir_path, path, dir_len);
            dir_path[dir_len] = '\0';

            /* verify each sstable exists, remove if not */
            int i = 0;
            int removed_count = 0;
            while (i < manifest->num_entries)
            {
                tidesdb_manifest_entry_t *entry = &manifest->entries[i];

                /* check both partitioned and non-partitioned formats
                 * we don't know which format was used, so try both */
                int exists = 0;
                struct stat st;

                /* ensure we have room for path + filename (conservative estimate: 100 bytes) */
                if (dir_len + 100 >= MANIFEST_PATH_LEN)
                {
                    /* path too long, skip this entry */
                    i++;
                    continue;
                }

                /* try non-partitioned format: L{level}_{id}.klog */
                char klog_path[MANIFEST_PATH_LEN];
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
                (void)snprintf(klog_path, sizeof(klog_path), "%s%sL%d_%" PRIu64 ".klog", dir_path,
                               path_sep, entry->level, entry->id);
                if (STAT_FUNC(klog_path, &st) == 0)
                {
                    exists = 1;
                }
                else
                {
                    /* try partitioned formats: L{level}P{partition}_{id}.klog
                     * check common partition numbers (0-15 should cover most cases) */
                    for (int p = 0; p < 16 && !exists; p++)
                    {
                        (void)snprintf(klog_path, sizeof(klog_path), "%s%sL%dP%d_%" PRIu64 ".klog",
                                       dir_path, path_sep, entry->level, p, entry->id);
                        if (STAT_FUNC(klog_path, &st) == 0)
                        {
                            exists = 1;
                            break;
                        }
                    }
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
                }

                if (!exists)
                {
                    /* file doesnt exist in any format, remove from manifest */
                    memmove(&manifest->entries[i], &manifest->entries[i + 1],
                            sizeof(tidesdb_manifest_entry_t) * (manifest->num_entries - i - 1));
                    manifest->num_entries--;
                    removed_count++;
                    /* don't increment i, check the same position again */
                }
                else
                {
                    i++;
                }
            }

            /* if we removed any entries, commit the compacted manifest */
            if (removed_count > 0)
            {
                tidesdb_manifest_commit(manifest, path);
            }
        }
    }

    return manifest;
}

int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id,
                                 uint64_t num_entries, uint64_t size_bytes)
{
    if (!manifest) return -1;

    /* check if already exists (update instead of add) */
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            /* update existing entry */
            manifest->entries[i].num_entries = num_entries;
            manifest->entries[i].size_bytes = size_bytes;
            return 0;
        }
    }

    /* grow array if needed */
    if (manifest->num_entries >= manifest->capacity)
    {
        int new_capacity = manifest->capacity * 2;
        tidesdb_manifest_entry_t *new_entries =
            realloc(manifest->entries, sizeof(tidesdb_manifest_entry_t) * new_capacity);
        if (!new_entries) return -1;

        manifest->entries = new_entries;
        manifest->capacity = new_capacity;
    }

    /* add new entry */
    manifest->entries[manifest->num_entries].level = level;
    manifest->entries[manifest->num_entries].id = id;
    manifest->entries[manifest->num_entries].num_entries = num_entries;
    manifest->entries[manifest->num_entries].size_bytes = size_bytes;
    manifest->num_entries++;

    return 0;
}

int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return -1;

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            /* shift remaining entries down */
            memmove(&manifest->entries[i], &manifest->entries[i + 1],
                    sizeof(tidesdb_manifest_entry_t) * (manifest->num_entries - i - 1));
            manifest->num_entries--;
            return 0;
        }
    }

    return -1; /* not found */
}

int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return 0;

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            return 1;
        }
    }

    return 0;
}

void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence)
{
    if (manifest) manifest->sequence = sequence;
}

int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path)
{
    if (!manifest || !path) return -1;

    /* serialize manifest to binary format:
     * [version:4][sequence:8][num_entries:4][entries...]
     * each entry: [level:4][id:8][num_entries:8][size_bytes:8] */
    size_t entry_size = 4 + 8 + 8 + 8; /* 28 bytes per entry */
    size_t total_size = 4 + 8 + 4 + (manifest->num_entries * entry_size);

    uint8_t *data = malloc(total_size);
    if (!data) return -1;

    uint8_t *ptr = data;

    /* write header */
    uint32_t version = MANIFEST_VERSION;
    memcpy(ptr, &version, 4);
    ptr += 4;

    memcpy(ptr, &manifest->sequence, 8);
    ptr += 8;

    uint32_t num_entries = (uint32_t)manifest->num_entries;
    memcpy(ptr, &num_entries, 4);
    ptr += 4;

    /* write entries */
    for (int i = 0; i < manifest->num_entries; i++)
    {
        uint32_t level = (uint32_t)manifest->entries[i].level;
        memcpy(ptr, &level, 4);
        ptr += 4;

        memcpy(ptr, &manifest->entries[i].id, 8);
        ptr += 8;

        memcpy(ptr, &manifest->entries[i].num_entries, 8);
        ptr += 8;

        memcpy(ptr, &manifest->entries[i].size_bytes, 8);
        ptr += 8;
    }

    /* open or reuse block manager */
    block_manager_t *bm = manifest->bm;
    int need_close = 0;

    if (bm == NULL)
    {
        /* first commit - open with SYNC_FULL */
        if (block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_FULL) != 0)
        {
            free(data);
            return -1;
        }
        manifest->block_count = block_manager_count_blocks(bm);
        need_close = 1;
    }
    else
    {
        /* reopen temporarily with SYNC_FULL for this commit */
        block_manager_close(manifest->bm);
        manifest->bm = NULL;

        if (block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_FULL) != 0)
        {
            free(data);
            return -1;
        }
        need_close = 1;
    }

    /* compact if file has too many old blocks (>MANIFEST_TRUNCATE_AT)
     * this prevents unbounded growth while amortizing compaction cost */
    if (manifest->block_count > MANIFEST_TRUNCATE_AT)
    {
        if (block_manager_truncate(bm) != 0)
        {
            if (need_close) block_manager_close(bm);
            free(data);
            return -1;
        }
        manifest->block_count = 0;
    }

    /* create block and append (COW: old blocks remain, new block is atomic)
     * block_manager_block_create_from_buffer takes ownership of data */
    block_manager_block_t *block = block_manager_block_create_from_buffer(total_size, data);
    if (!block)
    {
        if (need_close) block_manager_close(bm);
        free(data); /* only free on error before block creation */
        return -1;
    }

    /* write block atomically with checksum */
    int64_t offset = block_manager_block_write(bm, block);
    block_manager_block_free(block); /* this frees data */

    if (offset < 0)
    {
        if (need_close) block_manager_close(bm);
        /* data already freed by block_manager_block_free */
        return -1;
    }

    manifest->block_count++;

    /* fsync is handled by block_manager with SYNC_FULL */
    /* close and reopen with SYNC_NONE for future reads */
    if (need_close)
    {
        block_manager_close(bm);

        /* reopen for future use (SYNC_NONE for reads) */
        strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
        manifest->path[MANIFEST_PATH_LEN - 1] = '\0';

        if (block_manager_open(&manifest->bm, path, BLOCK_MANAGER_SYNC_NONE) == 0)
        {
            /* already tracking block_count */
        }
    }

    /* data already freed by block_manager_block_free */
    return 0;
}

void tidesdb_manifest_free(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    if (manifest->bm)
    {
        block_manager_close(manifest->bm);
        manifest->bm = NULL;
    }

    free(manifest->entries);
    free(manifest);
}