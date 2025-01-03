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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TDB_ERR_MAX_MESSAGE_SIZE 1024

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
 */
typedef struct
{
    int code;            /* the error code */
    const char *message; /* the error message */
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
    TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE,
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
    TIDESDB_ERR_COULD_NOT_GET_KEY_VALUE_FROM_CURSOR,
    TIDESDB_ERR_INVALID_ARGUMENT,
    TIDESDB_ERR_AT_START_OF_CURSOR,
    TIDESDB_ERR_INVALID_COMPRESSION_ALGO,
    TIDESDB_ERR_FAILED_TO_DESERIALIZE_BLOOM_FILTER,
    TIDESDB_ERR_NOT_IMPLEMENTED,
    TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE,
    TIDESDB_ERR_COLUMN_FAMILY_ALREADY_EXISTS,
    TIDESDB_ERR_INVALID_PARTIAL_MERGE_INTERVAL,
    TIDESDB_ERR_INVALID_PARTIAL_MERGE_MIN_SST,
    TIDESDB_ERR_PARTIAL_MERGE_ALREADY_STARTED,
    TIDESDB_ERR_THREAD_CREATION_FAILED,
    TIDESDB_ERR_LOG_INIT_FAILED,
    TIDESDB_ERR_PUT_MEMORY_OVERFLOW,
} TIDESDB_ERR_CODE;

/* TidesDB error messages */
static const tidesdb_err_info_t tidesdb_err_messages[] = {
    {TIDESDB_ERR_INVALID_DB, "Invalid database argument.\n"},
    {TIDESDB_ERR_INVALID_DB_DIR, "Invalid database directory.\n"},
    {TIDESDB_ERR_MEMORY_ALLOC, "Memory allocation failed for %s.\n"},
    {TIDESDB_ERR_MKDIR, "Failed to create directory %s.\n"},
    {TIDESDB_ERR_LOAD_COLUMN_FAMILIES, "Failed to load column families.\n"},
    {TIDESDB_ERR_FAILED_TO_INIT_LOCK, "Failed to initialize lock for %s.\n"},
    {TIDESDB_ERR_FAILED_TO_DESTROY_LOCK, "Failed to destroy lock for %s.\n"},
    {TIDESDB_ERR_INVALID_NAME, "Invalid name for %s.\n"},
    {TIDESDB_ERR_INVALID_FLUSH_THRESHOLD, "Invalid flush threshold.\n"},
    {TIDESDB_ERR_INVALID_MEMTABLE_MAX_LEVEL, "Invalid memtable max level.\n"},
    {TIDESDB_ERR_INVALID_MEMTABLE_PROBABILITY, "Invalid memtable probability.\n"},
    {TIDESDB_ERR_FAILED_TO_CREATE_COLUMN_FAMILY, "Failed to create column family.\n"},
    {TIDESDB_ERR_FAILED_TO_ADD_COLUMN_FAMILY, "Failed to add column family.\n"},
    {TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND, "Column family not found.\n"},
    {TIDESDB_ERR_RM_FAILED, "Failed to remove %s.\n"},
    {TIDESDB_ERR_REALLOC_FAILED, "Memory reallocation failed for %s.\n"},
    {TIDESDB_ERR_INVALID_COLUMN_FAMILY, "Invalid column family.\n"},
    {TIDESDB_ERR_INVALID_KEY, "Invalid key.\n"},
    {TIDESDB_ERR_INVALID_VALUE, "Invalid value.\n"},
    {TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL, "Failed to append to WAL.\n"},
    {TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE, "Failed to put to memtable.\n"},
    {TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE, "Failed to flush memtable.\n"},
    {TIDESDB_ERR_KEY_NOT_FOUND, "Key not found.\n"},
    {TIDESDB_ERR_FAILED_TO_INIT_CURSOR, "Failed to initialize cursor.\n"},
    {TIDESDB_ERR_INVALID_MAX_THREADS, "Invalid max threads for multithreaded compaction.\n"},
    {TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "Failed to acquire lock for %s.\n"},
    {TIDESDB_ERR_INVALID_SSTABLES_FOR_COMPACTION, "Invalid number of SSTables for compaction.\n"},
    {TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "Failed to release lock for %s.\n"},
    {TIDESDB_ERR_FAILED_TO_COMPACT_SSTABLES, "Failed to compact SSTables.\n"},
    {TIDESDB_ERR_INVALID_TXN, "Invalid transaction.\n"},
    {TIDESDB_ERR_INVALID_CURSOR, "Invalid cursor.\n"},
    {TIDESDB_ERR_AT_END_OF_CURSOR, "At end of cursor.\n"},
    {TIDESDB_ERR_COULD_NOT_GET_KEY_VALUE_FROM_CURSOR,
     "Could not get key-value pair from cursor.\n"},
    {TIDESDB_ERR_INVALID_ARGUMENT, "Invalid argument.\n"},
    {TIDESDB_ERR_AT_START_OF_CURSOR, "At start of cursor.\n"},
    {TIDESDB_ERR_INVALID_COMPRESSION_ALGO, "Invalid compression algorithm.\n"},
    {TIDESDB_ERR_FAILED_TO_DESERIALIZE_BLOOM_FILTER, "Failed to deserialize bloom filter.\n"},
    {TIDESDB_ERR_NOT_IMPLEMENTED, "Not implemented.\n"},
    {TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE, "Invalid memtable data structure.\n"},
    {TIDESDB_ERR_COLUMN_FAMILY_ALREADY_EXISTS, "Column family already exists.\n"},
    {TIDESDB_ERR_INVALID_PARTIAL_MERGE_INTERVAL, "Invalid partial merge interval.\n"},
    {TIDESDB_ERR_INVALID_PARTIAL_MERGE_MIN_SST, "Invalid partial merge min SSTables.\n"},
    {TIDESDB_ERR_PARTIAL_MERGE_ALREADY_STARTED,
     "Partial merge already started for column family %s.\n"},
    {TIDESDB_ERR_THREAD_CREATION_FAILED, "Failed to create thread.\n"},
    {TIDESDB_ERR_LOG_INIT_FAILED, "Failed to initialize db debug log.\n"},
    {TIDESDB_ERR_PUT_MEMORY_OVERFLOW,
     "Memory overflow while putting key-value pair.  Attempting to write data greater than "
     "available memory.\n"},
};

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