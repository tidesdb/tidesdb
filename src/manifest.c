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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MANIFEST_TMP_EXT ".tmp."

/**
 * tidesdb_manifest_add_sstable_unlocked
 * adds an sstable to the manifest
 * @param manifest manifest to add sstable to
 * @param level level of sstable
 * @param id id of sstable
 * @param num_entries number of entries in sstable
 * @param size_bytes size of sstable in bytes
 * @return 0 on success, -1 on error
 */
static int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, int level,
                                                 uint64_t id, uint64_t num_entries,
                                                 uint64_t size_bytes);

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
    manifest->fp = NULL;
    atomic_init(&manifest->active_ops, 0);
    strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
    manifest->path[MANIFEST_PATH_LEN - 1] = '\0';

    if (pthread_rwlock_init(&manifest->lock, NULL) != 0)
    {
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    /* we clean up orphaned temp files from incomplete commits
     * temp files are named -- <path>MANIFEST_TMP_EXT<thread_id>.<pid>
     * if main manifest exists, temp files are stale and can be removed */
    char dir_path[MANIFEST_PATH_LEN];
    const char *last_sep = strrchr(path, PATH_SEPARATOR[0]);
    if (last_sep)
    {
        size_t dir_len = last_sep - path;
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

    /* get base filename for pattern matching */
    const char *base_name = last_sep ? last_sep + 1 : path;
    size_t base_len = strlen(base_name);

    /* scan directory for orphaned temp files */
    DIR *dir = opendir(dir_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            /* check if filename matches pattern: <base_name>MANIFEST_TMP_EXT* */
            size_t entry_len = strlen(entry->d_name);
            if (entry_len > base_len + 5 && strncmp(entry->d_name, base_name, base_len) == 0 &&
                strncmp(entry->d_name + base_len, MANIFEST_TMP_EXT, 5) == 0)
            {
                /* found orphaned temp file, remove it */
                char temp_full_path[MANIFEST_PATH_LEN];
                size_t dir_path_len = strlen(dir_path);
                size_t sep_len = strlen(PATH_SEPARATOR);
                /* check if combined path fits in buffer (dir + separator + entry + null) */
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

    FILE *fp = tdb_fopen(path, "r");
    if (!fp)
    {
        /* file doesnt exist, return empty manifest */
        if (errno == ENOENT) return manifest;
        /* other error */
        pthread_rwlock_destroy(&manifest->lock);
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    char line[MANIFEST_MAX_LINE_LEN];

    if (fgets(line, sizeof(line), fp))
    {
        char *endptr;
        long version = strtol(line, &endptr, 10);
        if (endptr == line || version != MANIFEST_VERSION)
        {
            fclose(fp);
            pthread_rwlock_destroy(&manifest->lock);
            free(manifest->entries);
            free(manifest);
            return NULL;
        }
    }
    else
    {
        /* empty file, keep it open */
        manifest->fp = fp;
        return manifest;
    }

    if (fgets(line, sizeof(line), fp))
    {
        atomic_store(&manifest->sequence, strtoull(line, NULL, 10));
    }

    while (fgets(line, sizeof(line), fp))
    {
        int level;
        uint64_t id, num_entries, size_bytes;
        char *ptr = line;
        char *endptr;

        /* parse level */
        long level_val = strtol(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',') continue;
        level = (int)level_val;
        ptr = endptr + 1;

        /* parse id */
        id = strtoull(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',') continue;
        ptr = endptr + 1;

        /* parse num_entries */
        num_entries = strtoull(ptr, &endptr, 10);
        if (endptr == ptr || *endptr != ',') continue;
        ptr = endptr + 1;

        /* parse size_bytes */
        size_bytes = strtoull(ptr, &endptr, 10);
        if (endptr == ptr) continue;

        tidesdb_manifest_add_sstable_unlocked(manifest, level, id, num_entries, size_bytes);
    }

    /* keep file open for future use */
    manifest->fp = fp;

    return manifest;
}

/**
 * tidesdb_manifest_add_sstable_unlocked
 * adds an sstable to the manifest
 * @param manifest manifest to add sstable to
 * @param level level of sstable
 * @param id id of sstable
 * @param num_entries number of entries in sstable
 * @param size_bytes size of sstable in bytes
 * @return 0 on success, -1 on error
 */
static int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, int level,
                                                 uint64_t id, uint64_t num_entries,
                                                 uint64_t size_bytes)
{
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            manifest->entries[i].num_entries = num_entries;
            manifest->entries[i].size_bytes = size_bytes;
            return 0;
        }
    }

    if (manifest->num_entries >= manifest->capacity)
    {
        int new_capacity = manifest->capacity * 2;
        tidesdb_manifest_entry_t *new_entries =
            realloc(manifest->entries, sizeof(tidesdb_manifest_entry_t) * new_capacity);
        if (!new_entries)
        {
            return -1;
        }

        manifest->entries = new_entries;
        manifest->capacity = new_capacity;
    }

    manifest->entries[manifest->num_entries].level = level;
    manifest->entries[manifest->num_entries].id = id;
    manifest->entries[manifest->num_entries].num_entries = num_entries;
    manifest->entries[manifest->num_entries].size_bytes = size_bytes;
    manifest->num_entries++;

    return 0;
}

int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id,
                                 uint64_t num_entries, uint64_t size_bytes)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);
    int result =
        tidesdb_manifest_add_sstable_unlocked(manifest, level, id, num_entries, size_bytes);
    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            memmove(&manifest->entries[i], &manifest->entries[i + 1],
                    sizeof(tidesdb_manifest_entry_t) * (manifest->num_entries - i - 1));
            manifest->num_entries--;
            pthread_rwlock_unlock(&manifest->lock);
            atomic_fetch_sub(&manifest->active_ops, 1);
            return 0;
        }
    }

    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return -1;
}

int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return 0;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_rdlock(&manifest->lock);

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            pthread_rwlock_unlock(&manifest->lock);
            atomic_fetch_sub(&manifest->active_ops, 1);
            return 1;
        }
    }

    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return 0;
}

void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence)
{
    if (!manifest) return;

    /* sequence is atomic, no lock needed for simple store */
    atomic_store(&manifest->sequence, sequence);
}

int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path)
{
    if (!manifest || !path) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    pthread_rwlock_wrlock(&manifest->lock);

    /* close existing file pointer if path changed */
    if (manifest->fp && strcmp(manifest->path, path) != 0)
    {
        fclose(manifest->fp);
        manifest->fp = NULL;
        strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
        manifest->path[MANIFEST_PATH_LEN - 1] = '\0';
    }

    /* close for rewriting */
    if (manifest->fp)
    {
        fclose(manifest->fp);
        manifest->fp = NULL;
    }

    char temp_path[MANIFEST_PATH_LEN];
    snprintf(temp_path, sizeof(temp_path), "%s" MANIFEST_TMP_EXT "%lu.%d", path,
             (unsigned long)TDB_THREAD_ID(), TDB_GETPID());

    FILE *fp = tdb_fopen(temp_path, "w");
    if (!fp)
    {
        pthread_rwlock_unlock(&manifest->lock);
        atomic_fetch_sub(&manifest->active_ops, 1);
        return -1;
    }

    fprintf(fp, "%d\n", MANIFEST_VERSION);
    fprintf(fp, "%" PRIu64 "\n", atomic_load(&manifest->sequence));

    for (int i = 0; i < manifest->num_entries; i++)
    {
        fprintf(fp, "%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", manifest->entries[i].level,
                manifest->entries[i].id, manifest->entries[i].num_entries,
                manifest->entries[i].size_bytes);
    }

    if (fflush(fp) != 0)
    {
        fclose(fp);
        remove(temp_path);
        pthread_rwlock_unlock(&manifest->lock);
        atomic_fetch_sub(&manifest->active_ops, 1);
        return -1;
    }

    const int fd = tdb_fileno(fp);
    if (fd >= 0)
    {
        if (tdb_fsync(fd) != 0)
        {
            fclose(fp);
            remove(temp_path);
            pthread_rwlock_unlock(&manifest->lock);
            atomic_fetch_sub(&manifest->active_ops, 1);
            return -1;
        }
    }

    fclose(fp);

    /* atomic rename -- this is the commit point */
    if (atomic_rename_file(temp_path, path) != 0)
    {
        remove(temp_path);
        pthread_rwlock_unlock(&manifest->lock);
        atomic_fetch_sub(&manifest->active_ops, 1);
        return -1;
    }

    /* reopen for reading */
    manifest->fp = tdb_fopen(path, "r");

    pthread_rwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return 0;
}

void tidesdb_manifest_close(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    /* wait for all active operations to complete before destroying */
    int wait_count = 0;
    while (atomic_load(&manifest->active_ops) > 0 && wait_count < MANIFEST_CLOSE_MAX_WAITS)
    {
        usleep(MANIFEST_CLOSE_WAIT_US);
        wait_count++;
    }

    pthread_rwlock_wrlock(&manifest->lock);

    if (manifest->fp)
    {
        fclose(manifest->fp);
        manifest->fp = NULL;
    }

    /* unlock before destroying */
    pthread_rwlock_unlock(&manifest->lock);
    pthread_rwlock_destroy(&manifest->lock);
    free(manifest->entries);
    free(manifest);
}