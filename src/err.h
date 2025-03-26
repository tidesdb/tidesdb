/*
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
#ifndef __TIDESDB_ERR_H__
#define __TIDESDB_ERR_H__
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TDB_ERR_MAX_MESSAGE_SIZE 1024

#define TIDESDB_ERR_WITH_CONTEXT    1
#define TIDESDB_ERR_WITHOUT_CONTEXT 0

/*
 * tidesdb_err_t
 * the TidesDB error struct
 * used for error handling in TidesDB
 * @param code the error code
 * @param message the error message
 */
typedef struct
{
    int code;      /* the error code */
    char *message; /* the error message */
} tidesdb_err_t;

/*
 * tidesdb_err_info_t
 * the TidesDB error info struct used for error handling with error codes
 * used for error handling in TidesDB
 * @param code the error code
 * @param message the error message
 * @param has_context flag to indicate if the error has context/object
 */
typedef struct
{
    int code;            /* the error code */
    const char *message; /* the error message */
    uint8_t has_context; /* flag to indicate if the error has context */
} tidesdb_err_info_t;

/*
 * tidesdb_err_code_t
 * the TidesDB error codes enum
 */
typedef enum
{
    TIDESDB_ERR_INVALID_DB,
    TIDESDB_ERR_INVALID_DB_DIR,
    TIDESDB_ERR_MEMORY_ALLOC,
    TIDESDB_ERR_MKDIR,
    TIDESDB_ERR_LOAD_COLUMN_FAMILIES,
    TIDESDB_ERR_FAILED_TO_INIT_LOCK,
    TIDESDB_ERR_FAILED_TO_DESTROY_LOCK,
    TIDESDB_ERR_INVALID_NAME,
    TIDESDB_ERR_INVALID_FLUSH_THRESHOLD,
    TIDESDB_ERR_INVALID_MEMTABLE_MAX_LEVEL,
    TIDESDB_ERR_INVALID_MEMTABLE_PROBABILITY,
    TIDESDB_ERR_FAILED_TO_CREATE_COLUMN_FAMILY,
    TIDESDB_ERR_FAILED_TO_ADD_COLUMN_FAMILY,
    TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND,
    TIDESDB_ERR_REALLOC_FAILED,
    TIDESDB_ERR_RM_FAILED,
    TIDESDB_ERR_INVALID_COLUMN_FAMILY,
    TIDESDB_ERR_INVALID_KEY,
    TIDESDB_ERR_INVALID_VALUE,
    TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL,
    TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE,
    TIDESDB_ERR_KEY_NOT_FOUND,
    TIDESDB_ERR_FAILED_TO_INIT_CURSOR,
    TIDESDB_ERR_INVALID_MAX_THREADS,
    TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK,
    TIDESDB_ERR_INVALID_SSTABLES_FOR_COMPACTION,
    TIDESDB_ERR_FAILED_TO_RELEASE_LOCK,
    TIDESDB_ERR_FAILED_TO_COMPACT_SSTABLES,
    TIDESDB_ERR_INVALID_TXN,
    TIDESDB_ERR_INVALID_CURSOR,
    TIDESDB_ERR_AT_END_OF_CURSOR,
    TIDESDB_ERR_INVALID_ARGUMENT,
    TIDESDB_ERR_AT_START_OF_CURSOR,
    TIDESDB_ERR_INVALID_COMPRESSION_ALGO,
    TIDESDB_ERR_FAILED_TO_DESERIALIZE,
    TIDESDB_ERR_NOT_IMPLEMENTED,
    TIDESDB_ERR_COLUMN_FAMILY_ALREADY_EXISTS,
    TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_INTERVAL,
    TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_MIN_SST,
    TIDESDB_ERR_INCREMENTAL_MERGE_ALREADY_STARTED,
    TIDESDB_ERR_THREAD_CREATION_FAILED,
    TIDESDB_ERR_LOG_INIT_FAILED,
    TIDESDB_ERR_PUT_MEMORY_OVERFLOW,
    TIDESDB_ERR_FAILED_TO_GET_SYSTEM_MEMORY,
    TIDESDB_ERR_FAILED_TO_OPEN_DIRECTORY,
    TIDESDB_ERR_FAILED_TO_OPEN_WAL,
    TIDESDB_ERR_FAILED_ADD_COLUMN_FAMILY,
    TIDESDB_ERR_FAILED_COLUMN_FAMILY_WAL_REPLAY,
    TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY,
    TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER,
    TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_FLUSH,
    TIDESDB_ERR_FAILED_TO_OPEN_SSTABLE,
    TIDESDB_ERR_FAILED_TO_INIT_WAL_CURSOR,
    TIDESDB_ERR_FAILED_TO_INIT_CURSOR_FOR_FLUSH,
    TIDESDB_ERR_FAILED_TO_SERIALIZE,
    TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
    TIDESDB_ERR_FAILED_TO_CLEAR_MEMTABLE,
    TIDESDB_ERR_FAILED_TO_TRUNCATE_WAL,
    TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES,
    TIDESDB_ERR_FAILED_TO_REMOVE_SSTABLES_ON_COMPACTION,
    TIDESDB_ERR_FAILED_TO_GET_MERGED_SSTABLE_PATH,
    TIDESDB_ERR_FAILED_TO_CLOSE_RENAME_MERGED_SSTABLE,
    TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGED_SSTABLE,
    TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK_FOR_MERGE,
    TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGE,
    TIDESDB_ERR_INVALID_BLOCK_MANAGER,
    TIDESDB_ERR_FAILED_TO_GET_SSTABLE_SIZE,
    TIDESDB_ERR_INVALID_STAT,
    TIDESDB_ERR_INVALID_NAME_LENGTH,
    TIDESDB_ERR_PATH_TOO_LONG,
    TIDESDB_ERR_FAILED_TO_GET_SYSTEM_THREADS,
    TIDESDB_ERR_FAILED_TO_REMOVE_TEMP_FILE,
    TIDESDB_ERR_INVALID_COMPARISON_METHOD,
    TIDESDB_ERR_FAILED_TO_ESCALATE_FSYNC,
    TIDESDB_ERR_FAILED_TO_GET_MIN_KEY_FOR_FLUSH,
    TIDESDB_ERR_FAILED_TO_GET_MAX_KEY_FOR_FLUSH,
    TIDESDB_ERR_PUT_TOMBSTONE,
} TIDESDB_ERR_CODE;

/* TidesDB error messages */
static const tidesdb_err_info_t tidesdb_err_messages[] = {
    {TIDESDB_ERR_INVALID_DB, "Invalid database argument.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_DB_DIR, "Invalid database directory.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_MEMORY_ALLOC, "Memory allocation failed for %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_MKDIR, "Failed to create directory %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_LOAD_COLUMN_FAMILIES, "Failed to load column families.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_INIT_LOCK, "Failed to initialize lock for %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_DESTROY_LOCK, "Failed to destroy lock for %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_NAME, "Invalid name for %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_FLUSH_THRESHOLD, "Invalid flush threshold.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_MEMTABLE_MAX_LEVEL, "Invalid memtable max level.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_MEMTABLE_PROBABILITY, "Invalid memtable probability.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_CREATE_COLUMN_FAMILY, "Failed to create column family.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_ADD_COLUMN_FAMILY, "Failed to add column family.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND, "Column family not found.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_RM_FAILED, "Failed to remove %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_REALLOC_FAILED, "Memory reallocation failed for %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_COLUMN_FAMILY, "Invalid column family.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_KEY, "Invalid key.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_VALUE, "Invalid value.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL, "Failed to append to WAL.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE, "Failed to flush memtable.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_KEY_NOT_FOUND, "Key not found.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_INIT_CURSOR, "Failed to initialize cursor.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_MAX_THREADS, "Invalid max threads for multithreaded compaction.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "Failed to acquire lock for %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_SSTABLES_FOR_COMPACTION, "Invalid number of SSTables for compaction.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "Failed to release lock for %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_COMPACT_SSTABLES, "Failed to compact SSTables.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_TXN, "Invalid transaction.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_CURSOR, "Invalid cursor.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_AT_END_OF_CURSOR, "At end of cursor.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_ARGUMENT, "Invalid argument.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_AT_START_OF_CURSOR, "At start of cursor.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_COMPRESSION_ALGO, "Invalid compression algorithm.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_DESERIALIZE, "Failed to deserialize %s for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_NOT_IMPLEMENTED, "Not implemented.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_COLUMN_FAMILY_ALREADY_EXISTS, "Column family already exists.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_INTERVAL, "Invalid incremental merge interval.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_MIN_SST, "Invalid incremental merge min SSTables.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_INCREMENTAL_MERGE_ALREADY_STARTED,
     "Incremental merge already started for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_THREAD_CREATION_FAILED, "Failed to create thread.\n", TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_LOG_INIT_FAILED, "Failed to initialize db debug log.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_PUT_MEMORY_OVERFLOW,
     "Memory overflow while putting key-value pair.  Attempting to write data greater than "
     "available memory.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_SYSTEM_MEMORY, "Failed to get system memory.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_DIRECTORY, "Failed to open directory %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_WAL, "Failed to open WAL file for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_ADD_COLUMN_FAMILY, "Failed to add column family %s to database.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_COLUMN_FAMILY_WAL_REPLAY, "Failed to replay WAL for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY, "Failed to close directory %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_SSTABLE, "Failed to open SSTable %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_INIT_WAL_CURSOR,
     "Failed to initialize WAL cursor for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER,
     "Failed to open block manager for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_FLUSH,
     "Failed to open block manager for flush for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_INIT_CURSOR_FOR_FLUSH,
     "Failed to serialize key-value pair for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_CLEAR_MEMTABLE, "Failed to clear memtable for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_TRUNCATE_WAL, "Failed to truncate WAL for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES, "Failed to merge SSTables for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_REMOVE_SSTABLES_ON_COMPACTION,
     "Failed to remove SST pair on compaction for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_MERGED_SSTABLE_PATH,
     "Failed to get merged SSTable path for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_CLOSE_RENAME_MERGED_SSTABLE,
     "Failed to close and rename merged SSTable for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGED_SSTABLE,
     "Failed to open block manager for merged SSTable for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK_FOR_MERGE,
     "Failed to acquire shared file name lock for merge for column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGE,
     "Failed to open block manager for merge for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_BLOCK_MANAGER, "Invalid block manager for %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_SSTABLE_SIZE,
     "Failed to get SSTable size from block managed file %s and column family %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_STAT, "Invalid stat for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_NAME_LENGTH, "Invalid name length for %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_PATH_TOO_LONG, "Path too long for %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_SYSTEM_THREADS, "Failed to get system threads.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_REMOVE_TEMP_FILE, "Failed to remove temporary file %s.\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_INVALID_COMPARISON_METHOD, "Invalid comparison method for filter.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_ESCALATE_FSYNC, "Failed to escalate fsync.\n",
     TIDESDB_ERR_WITHOUT_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_MIN_KEY_FOR_FLUSH,
     "Failed to get minimum key for flush for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_GET_MAX_KEY_FOR_FLUSH,
     "Failed to get maximum key for flush for column family %s.\n", TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_WRITE_BLOCK, "Failed to write %s block for column family %s\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_FAILED_TO_SERIALIZE, "Failed to serialize %s for column family %s\n",
     TIDESDB_ERR_WITH_CONTEXT},
    {TIDESDB_ERR_PUT_TOMBSTONE, "Cannot write a tombstone\n", TIDESDB_ERR_WITHOUT_CONTEXT}};

/*
 * tidesdb_err_new
 * create a new TidesDB error
 * @param code the error code
 * @param message the error message
 */
tidesdb_err_t *tidesdb_err_new(int code, char *message);

/*
 * tidesdb_err_free
 * free a TidesDB error
 * @param e the error to free
 */
void tidesdb_err_free(tidesdb_err_t *e);

/*
 * tidesdb_err_from_code
 * create a new TidesDB error from an error code
 * @param code the error code
 * @param ... the error message
 */
tidesdb_err_t *tidesdb_err_from_code(TIDESDB_ERR_CODE code, ...);

#endif /* __TIDESDB_ERR_H__ */