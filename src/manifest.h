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
#ifndef __MANIFEST_H__
#define __MANIFEST_H__

#define MANIFEST_INITIAL_CAPACITY 64
/* we align with tidesdb core major */
#define MANIFEST_VERSION     6
#define MANIFEST_PATH_LEN    4096
#define MANIFEST_TRUNCATE_AT 100 /* 100 blocks */

#include "block_manager.h"
#include "compat.h"

/**
 * tidesdb_manifest_entry_t
 * represents a single sstable entry in the manifest
 * @param level level number (1-based)
 * @param id sstable ID
 * @param num_entries number of entries in sstable
 * @param size_bytes total size in bytes
 */
typedef struct
{
    int level;
    uint64_t id;
    uint64_t num_entries;
    uint64_t size_bytes;
} tidesdb_manifest_entry_t;

/**
 * tidesdb_manifest_t
 * in-memory representation of manifest file
 * @param entries array of sstable entries
 * @param num_entries number of entries
 * @param capacity capacity of entries array
 * @param sequence current global sequence number
 * @param bm block manager for manifest file (kept open for fast commits)
 * @param path path to manifest file
 * @param block_count number of blocks in manifest file (for compaction tracking)
 */
typedef struct
{
    tidesdb_manifest_entry_t *entries;
    int num_entries;
    int capacity;
    uint64_t sequence;
    block_manager_t *bm;
    char path[MANIFEST_PATH_LEN];
    int block_count;
} tidesdb_manifest_t;

/**
 * tidesdb_manifest_create
 * creates a new empty manifest
 * @return new manifest or NULL on error
 */
tidesdb_manifest_t *tidesdb_manifest_create(void);

/**
 * tidesdb_manifest_load
 * loads manifest from file
 * @param path path to manifest file
 * @return loaded manifest or NULL on error (creates new if file doesn't exist)
 */
tidesdb_manifest_t *tidesdb_manifest_load(const char *path);

/**
 * tidesdb_manifest_add_sstable
 * adds an sstable entry to the manifest
 * @param manifest manifest to modify
 * @param level level number
 * @param id sstable ID
 * @param num_entries number of entries
 * @param size_bytes size in bytes
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id,
                                 uint64_t num_entries, uint64_t size_bytes);

/**
 * tidesdb_manifest_remove_sstable
 * removes an sstable entry from the manifest
 * @param manifest manifest to modify
 * @param level level number
 * @param id sstable ID
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id);

/**
 * tidesdb_manifest_has_sstable
 * checks if manifest contains an sstable
 * @param manifest manifest to check
 * @param level level number
 * @param id sstable ID
 * @return 1 if exists, 0 if not
 */
int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id);

/**
 * tidesdb_manifest_update_sequence
 * updates the global sequence number
 * @param manifest manifest to modify
 * @param sequence new sequence number
 */
void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence);

/**
 * tidesdb_manifest_commit
 * atomically writes manifest to disk (write temp + rename)
 * @param manifest manifest to write
 * @param path path to manifest file
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path);

/**
 * tidesdb_manifest_free
 * frees manifest memory
 * @param manifest manifest to free
 */
void tidesdb_manifest_free(tidesdb_manifest_t *manifest);

#endif /* __MANIFEST_H__ */