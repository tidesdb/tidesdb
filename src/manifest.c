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
    manifest->sequence = 0;
    manifest->fp = NULL;
    strncpy(manifest->path, path, MANIFEST_PATH_LEN - 1);
    manifest->path[MANIFEST_PATH_LEN - 1] = '\0';

    if (pthread_rwlock_init(&manifest->lock, NULL) != 0)
    {
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    FILE *fp = tdb_fopen(path, "r");
    if (!fp)
    {
        /* file doesn't exist, return empty manifest */
        if (errno == ENOENT) return manifest;
        /* other error */
        free(manifest->entries);
        free(manifest);
        return NULL;
    }

    char line[MANIFEST_MAX_LINE_LEN];

    if (fgets(line, sizeof(line), fp))
    {
        int version = atoi(line);
        if (version != MANIFEST_VERSION)
        {
            fclose(fp);
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
        manifest->sequence = strtoull(line, NULL, 10);
    }

    while (fgets(line, sizeof(line), fp))
    {
        int level;
        uint64_t id, num_entries, size_bytes;

        if (sscanf(line, "%d,%" SCNu64 ",%" SCNu64 ",%" SCNu64, &level, &id, &num_entries,
                   &size_bytes) == 4)
        {
            tidesdb_manifest_add_sstable(manifest, level, id, num_entries, size_bytes);
        }
    }

    /* keep file open for future use */
    manifest->fp = fp;

    return manifest;
}

int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id,
                                 uint64_t num_entries, uint64_t size_bytes)
{
    if (!manifest) return -1;

    pthread_rwlock_wrlock(&manifest->lock);

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
        if (!new_entries) return -1;

        manifest->entries = new_entries;
        manifest->capacity = new_capacity;
    }

    manifest->entries[manifest->num_entries].level = level;
    manifest->entries[manifest->num_entries].id = id;
    manifest->entries[manifest->num_entries].num_entries = num_entries;
    manifest->entries[manifest->num_entries].size_bytes = size_bytes;
    manifest->num_entries++;

    pthread_rwlock_unlock(&manifest->lock);
    return 0;
}

int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return -1;

    pthread_rwlock_wrlock(&manifest->lock);

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            memmove(&manifest->entries[i], &manifest->entries[i + 1],
                    sizeof(tidesdb_manifest_entry_t) * (manifest->num_entries - i - 1));
            manifest->num_entries--;
            pthread_rwlock_unlock(&manifest->lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&manifest->lock);
    return -1;
}

int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id)
{
    if (!manifest) return 0;

    pthread_rwlock_rdlock(&manifest->lock);

    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].level == level && manifest->entries[i].id == id)
        {
            pthread_rwlock_unlock(&manifest->lock);
            return 1;
        }
    }

    pthread_rwlock_unlock(&manifest->lock);
    return 0;
}

void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence)
{
    if (!manifest) return;

    pthread_rwlock_wrlock(&manifest->lock);
    manifest->sequence = sequence;
    pthread_rwlock_unlock(&manifest->lock);
}

int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path)
{
    if (!manifest || !path) return -1;

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

    /* open for writing (truncates file) */
    FILE *fp = tdb_fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "%d\n", MANIFEST_VERSION);
    fprintf(fp, "%" PRIu64 "\n", manifest->sequence);

    for (int i = 0; i < manifest->num_entries; i++)
    {
        fprintf(fp, "%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", manifest->entries[i].level,
                manifest->entries[i].id, manifest->entries[i].num_entries,
                manifest->entries[i].size_bytes);
    }

    if (fflush(fp) != 0)
    {
        fclose(fp);
        return -1;
    }

    int fd = tdb_fileno(fp);
    if (fd >= 0)
    {
        tdb_fsync(fd);
    }

    fclose(fp);

    /* reopen for reading */
    manifest->fp = tdb_fopen(path, "r");

    pthread_rwlock_unlock(&manifest->lock);
    return 0;
}

void tidesdb_manifest_close(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    if (manifest->fp)
    {
        fclose(manifest->fp);
        manifest->fp = NULL;
    }

    pthread_rwlock_destroy(&manifest->lock);
    free(manifest->entries);
    free(manifest);
    manifest = NULL;
}