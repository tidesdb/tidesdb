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

    return manifest;
}

tidesdb_manifest_t *tidesdb_manifest_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        /* file doesn't exist, create new manifest */
        if (errno == ENOENT) return tidesdb_manifest_create();
        return NULL;
    }

    tidesdb_manifest_t *manifest = tidesdb_manifest_create();
    if (!manifest)
    {
        fclose(f);
        return NULL;
    }

    char line[512];
    int version = 0;

    while (fgets(line, sizeof(line), f))
    {
        /* skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;

        /* parse version */
        if (sscanf(line, "VERSION %d", &version) == 1)
        {
            if (version != MANIFEST_VERSION)
            {
                fclose(f);
                tidesdb_manifest_free(manifest);
                return NULL;
            }
            continue;
        }

        /* parse sequence */
        if (sscanf(line, "SEQUENCE %" SCNu64, &manifest->sequence) == 1)
        {
            continue;
        }

        /* parse sstable entry */
        int level;
        uint64_t id, num_entries, size_bytes;
        if (sscanf(line, "SSTABLE %d %" SCNu64 " %" SCNu64 " %" SCNu64, &level, &id, &num_entries,
                   &size_bytes) == 4)
        {
            tidesdb_manifest_add_sstable(manifest, level, id, num_entries, size_bytes);
        }
    }

    fclose(f);

    /* compact manifest -- remove entries for sstables that no longer exist on disk
     * this prevents manifest from growing indefinitely with stale entries
     * only run if manifest is in a real directory (not current dir)
     * skip for test manifests in current directory */
    char dir_path[MANIFEST_PATH_LEN];
    const char *last_sep = strrchr(path, '/');
    if (!last_sep) last_sep = strrchr(path, '\\');

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
                (void)snprintf(klog_path, sizeof(klog_path),
                               "%s" PATH_SEPARATOR "L%d_%" PRIu64 ".klog", dir_path, entry->level,
                               entry->id);
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
                        (void)snprintf(klog_path, sizeof(klog_path),
                                       "%s" PATH_SEPARATOR "L%dP%d_%" PRIu64 ".klog", dir_path,
                                       entry->level, p, entry->id);
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
                    /* file doesn't exist in any format, remove from manifest */
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

    /* write to temp file */
    char temp_path[MANIFEST_PATH_LEN];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    FILE *f = fopen(temp_path, "w");
    if (!f) return -1;

    /* write header */
    fprintf(f, "# TidesDB Manifest\n");
    fprintf(f, "VERSION %d\n", MANIFEST_VERSION);
    fprintf(f, "SEQUENCE %" PRIu64 "\n", manifest->sequence);
    fprintf(f, "# Format: SSTABLE <level> <id> <num_entries> <size_bytes>\n");

    /* write entries */
    for (int i = 0; i < manifest->num_entries; i++)
    {
        fprintf(f, "SSTABLE %d %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", manifest->entries[i].level,
                manifest->entries[i].id, manifest->entries[i].num_entries,
                manifest->entries[i].size_bytes);
    }

    /* fsync before close */
    fflush(f);
    int fd = tdb_fileno(f);
    if (fd >= 0)
    {
        fsync(fd);
    }
    fclose(f);

    /* atomic rename using compat abstraction */
    if (atomic_rename_file(temp_path, path) != 0)
    {
        tdb_unlink(temp_path);
        return -1;
    }

    return 0;
}

void tidesdb_manifest_free(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    free(manifest->entries);
    free(manifest);
}