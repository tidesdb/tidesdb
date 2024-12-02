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
#ifndef TIDESDB_H
#define TIDESDB_H
#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloomfilter.h"
#include "err.h"
#include "id_gen.h"
#include "pager.h"
#include "queue.h"
#include "serialize.h"
#include "skiplist.h"

/* ** * @TODO windows support */

#define BLOOMFILTER_SIZE                                                                      \
    1000 /* size of each bloom filter.  Bloom filters are linked once they reach this size in \
            occupied capacity */
#define WAL_EXT                       ".wal"     /* extension for the write-ahead log file */
#define SSTABLE_EXT                   ".sst"     /* extension for the SSTable file */
#define COLUMN_FAMILY_CONFIG_FILE_EXT ".cfc"     /* configuration file for the column family */
#define TOMBSTONE                     0xDEADBEEF /* tombstone value for deleted keys */

/*
 * tidesdb_config_t
 * create a new TidesDB config
 * @param db_path the path for/to TidesDB
 * @param compressed_wal whether the wal should be compressed
 */
typedef struct
{
    char* db_path;       /* the path for/to TidesDB.  This is where column families are stored */
    bool compressed_wal; /* whether the wal entries should be compressed */
} tidesdb_config_t;

/*
 * sstable_t
 * struct for the SSTable
 * @param pager the pager for the SSTable
 */
typedef struct
{
    pager_t* pager; /* the pager for the SSTable */
} sstable_t;

/*
 * wal_t
 * struct for the write-ahead log
 * @param pager the pager for the WAL
 * @param lock the read-write lock for the WAL
 */
typedef struct
{
    pager_t* pager;        /* the pager for the WAL */
    pthread_rwlock_t lock; /* Read-write lock for the SSTable */
} wal_t;

/*
 * column_family_t
 * struct for a column family
 * @param config the configuration for the column family
 * @param path the path to the column family
 * @param sstables the sstables for the column family
 * @param num_sstables the number of sstables for the column family
 * @param sstables_lock Read-write lock for SSTables mainly for when adding a new sstable
 * @param memtable the memtable for the column family
 * @param id_gen id generator for the column family; mainly used for sstable filenames
 * @param compaction_or_flush_lock lock for compaction or flush
 * @param wal the write-ahead log for column family
 */
typedef struct
{
    column_family_config_t config; /* the configuration for the column family */
    char* path;                    /* the path to the column family */
    sstable_t** sstables;          /* the sstables for the column family */
    int num_sstables;              /* the number of sstables for the column family */
    pthread_rwlock_t
        sstables_lock;    /* Read-write lock for SSTables mainly for when adding a new sstable */
    skiplist_t* memtable; /* the memtable for the column family */
    id_gen_t* id_gen; /* id generator for the column family; mainly used for sstable filenames */
    pthread_rwlock_t compaction_or_flush_lock; /* lock for compaction or flush */
    wal_t* wal;                                /* the write-ahead log for column family */
} column_family_t;

/*
 * tidesdb_txn_op_t
 * struct for a transaction operation
 * @param op the operation for the transaction
 * @param rollback_op the rollback operation for the operation
 * @param committed whether the transaction op has been committed
 */
typedef struct
{
    operation_t* op;          /* the operation for the transaction */
    operation_t* rollback_op; /* the rollback operation for the operation */
    bool committed;           /* whether the transaction op has been committed */
} tidesdb_txn_op_t;

/*
 * tidesdb_t
 * struct for TidesDB
 * @param config the configuration for TidesDB
 * @param column_families the column families currently
 * @param column_families_lock Read-write lock for column families
 * @param num_column_families the number of column families currently
 * @param flush_thread the thread for flushing memtables
 * @param flush_queue the queue for flushing memtables
 * @param flush_lock the flush lock
 * @param compaction_lock the compaction lock
 * @param flush_cond the condition variable for flush thread
 * @param compaction_cond the condition variable for compaction
 * @param stop_flush_thread flag to stop the flush thread
 */
typedef struct
{
    tidesdb_config_t config;               /* the configuration for tidesdb */
    column_family_t* column_families;      /* the column families currently */
    pthread_rwlock_t column_families_lock; /* Read-write lock for column families */
    int num_column_families;               /* the number of column families currently */
    pthread_t flush_thread;                /* the thread for flushing memtables */
    queue_t* flush_queue;                  /* the queue for flushing memtables */
    pthread_mutex_t flush_lock;            /* flush lock */
    pthread_cond_t flush_cond;             /* condition variable for flush thread */
    bool stop_flush_thread;                /* flag to stop the flush thread */
} tidesdb_t;

/*
 * tidesdb_txn_t
 * struct for a transaction
 * @param tdb the tidesdb instance
 * @param ops the operations in the transaction
 * @param num_ops the number of operations in the transaction
 * @param column_family the column family for the transaction
 * @param lock the lock for the transaction
 */
typedef struct
{
    tidesdb_t* tdb;        /* the tidesdb instance */
    tidesdb_txn_op_t* ops; /* the operations in the transaction */
    int num_ops;           /* the number of operations in the transaction */
    char* column_family;   /* the column family for the transaction */
    pthread_mutex_t lock;  /* lock for the transaction */
} tidesdb_txn_t;

/*
 * tidesdb_cursor_t
 * struct for a TidesDB cursor
 * @param tidesdb the tidesdb instance
 * @param cf the column family
 * @param memtable_cursor the cursor for the memtable
 * @param sstable_index the index of the sstable
 * @param sstable_cursor the cursor for the sstable
 * @param current the current key-value pair
 * @param at_start whether the cursor is at the start
 */
typedef struct
{
    tidesdb_t* tidesdb;                 /* tidesdb instance */
    column_family_t* cf;                /* the column family */
    skiplist_cursor_t* memtable_cursor; /* the cursor for the memtable */
    size_t sstable_index;               /* the index of the sstable */
    pager_cursor_t* sstable_cursor;     /* the cursor for the sstable */
    key_value_pair_t* current;          /* the current key-value pair */
} tidesdb_cursor_t;

/*
 * queue_entry
 * struct for a queue entry
 * @param memtable the memtable
 * @param cf the column family
 * @param wal_checkpoint the point in the wal to truncate after flush
 */
typedef struct
{
    skiplist_t* memtable;  /* the memtable */
    column_family_t* cf;   /* the column family */
    size_t wal_checkpoint; /* the point in the wal to truncate after flush */
} queue_entry_t;

/*
 * compact_thread_args
 * struct for the arguments for a compact thread
 * @param cf the column family
 * @param start the start index for the sstables
 * @param end the end index for the sstables
 * @param sem semaphore to limit concurrent threads
 */
typedef struct
{
    column_family_t* cf; /* the column family */
    int start;           /* the start index for the sstables */
    int end;             /* the end index for the sstables */
    sem_t* sem;          /* semaphore to limit concurrent threads */
} compact_thread_args_t;

/* TidesDB function prototypes */

/* functions prefixed with _ are internal functions */
/* api functions return a tidesdb_err* */

/*
 * tidesdb_open
 * open a TidesDB instance
 * @param config the configuration for TidesDB
 * @param tdb the TidesDB instance (should be null)
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_open(const tidesdb_config_t* config, tidesdb_t** tdb);

/*
 * tidesdb_close
 * close a TidesDB instance
 * @param tdb the TidesDB instance
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_close(tidesdb_t* tdb);

/*
 * tidesdb_create_column_family
 * create a new column family
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param flush_threshold the threshold at which the memtable should be flushed to disk
 * @param max_level the maximum level for the memtable(skiplist)
 * @param probability the probability for skip list
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_create_column_family(tidesdb_t* tdb, const char* name, int flush_threshold,
                                            int max_level, float probability, bool compressed);

/*
 * tidesdb_drop_column_family
 * drops a column family and all associated data
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_drop_column_family(tidesdb_t* tdb, const char* name);

/*
 * _get_column_family
 * get a column family by name
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param cf the column family
 * @return 0 if the column family was found, -1 if not
 */
int _get_column_family(tidesdb_t* tdb, const char* name, column_family_t** cf);

/*
 * tidesdb_compact_sstables
 * compact the sstables for a column family
 * @param tdb the TidesDB instance
 * @param column_family the column family name
 * @param max_threads the maximum number of threads to use
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_compact_sstables(tidesdb_t* tdb, const char* column_family, int max_threads);

/*
 * tidesdb_put
 * put a key-value pair into TidesDB
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_put(tidesdb_t* tdb, const char* column_family_name, const uint8_t* key,
                           size_t key_size, const uint8_t* value, size_t value_size, time_t ttl);

/*
 * tidesdb_get
 * get a value from TidesDB
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_get(tidesdb_t* tdb, const char* column_family_name, const uint8_t* key,
                           size_t key_size, uint8_t** value, size_t* value_size);

/*
 * tidesdb_delete
 * delete a key-value pair from TidesDB
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param key the key
 * @param key_size the size of the key
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_delete(tidesdb_t* tdb, const char* column_family_name, const uint8_t* key,
                              size_t key_size);

/*
 * tidesdb_txn_begin
 * begin a transaction
 * @param tdb the TidesDB instance
 * @param transaction the transaction
 * @param column_family the column family
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_begin(tidesdb_t* tdb, tidesdb_txn_t** transaction,
                                 const char* column_family);

/*
 * tidesdb_txn_put
 * put a key-value pair into a transaction
 * @param transaction the transaction
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_put(tidesdb_txn_t* transaction, const uint8_t* key, size_t key_size,
                               const uint8_t* value, size_t value_size, time_t ttl);

/*
 * tidesdb_txn_delete
 * delete a key-value pair from a transaction
 * @param transaction the transaction
 * @param key the key
 * @param key_size the size of the key
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_delete(tidesdb_txn_t* transaction, const uint8_t* key, size_t key_size);

/*
 * tidesdb_txn_commit
 * commit a transaction
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_commit(tidesdb_txn_t* transaction);

/*
 * tidesdb_txn_rollback
 * rollback a transaction
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_rollback(tidesdb_txn_t* transaction);

/*
 * tidesdb_txn_free
 * free a transaction
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_txn_free(tidesdb_txn_t* transaction);

/*
 * tidesdb_cursor_init
 * initialize a new TidesDB cursor
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_cursor_init(tidesdb_t* tdb, const char* column_family_name,
                                   tidesdb_cursor_t** cursor);

/*
 * tidesdb_cursor_next
 * move the cursor to the next key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_cursor_next(tidesdb_cursor_t* cursor);

/*
 * tidesdb_cursor_prev
 * move the cursor to the previous key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_cursor_prev(tidesdb_cursor_t* cursor);

/*
 * tidesdb_cursor_get
 * get the current key-value pair from the cursor
 * @param cursor the TidesDB cursor
 * @param kv the key-value pair
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_cursor_get(tidesdb_cursor_t* cursor, key_value_pair_t* kv);

/*
 * tidesdb_cursor_free
 * free the memory for the cursor
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t* tidesdb_cursor_free(tidesdb_cursor_t* cursor);

/*
 * _new_column_family
 * create a new column family
 * @param db_path the path for/to TidesDB
 * @param name the name of the column family
 * @param flush_threshold the threshold at which the memtable should be flushed to disk
 * @param max_level the maximum level for the memtable(skiplist)
 * @param probability the probability for skip list
 * @param cf the column family
 * @return 0 if the column family was created, -1 if not
 */
int _new_column_family(const char* db_path, const char* name, int flush_threshold, int max_level,
                       float probability, column_family_t** cf, bool compressed);

/*
 * _add_column_family
 * adds a new column family to TidesDB
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @return 0 if the column family was added, -1 if not
 */
int _add_column_family(tidesdb_t* tdb, column_family_t* cf);

/*
 * _load_column_families
 * load the column families for TidesDB
 * @param tdb the TidesDB instance
 * @return 0 if the column families were loaded, -1 if not
 */
int _load_column_families(tidesdb_t* tdb);

/*
 * _get_path_seperator
 * get the path separator for the current OS
 * @return the path separator
 */
const char* _get_path_seperator();

/*
 * _append_to_wal
 * append an operation to the write-ahead log
 * @param tdb the TidesDB instance
 * @param wal the write-ahead log
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair
 * @param op_code the operation code
 * @param cf the column family
 * @return 0 if the operation was appended, -1 if not
 */
int _append_to_wal(tidesdb_t* tdb, wal_t* wal, const uint8_t* key, size_t key_size,
                   const uint8_t* value, size_t value_size, time_t ttl, OP_CODE op_code,
                   const char* cf);

/*
 * _open_wal
 * open the write-ahead log
 * @param db_path the path for/to TidesDB
 * @param w the write-ahead log
 * @return 0 if the wal was opened, -1 if not
 */
int _open_wal(const char* db_path, wal_t** w);

/*
 * _close_wal
 * close the write-ahead log
 * @param wal the write-ahead log
 */
void _close_wal(wal_t* wal);

/*
 * _truncate_wal
 * truncate the write-ahead log
 * @param wal the write-ahead log
 * @param checkpoint the point in the wal to truncate
 * @return 0 if the wal was truncated, -1 if not
 */
int _truncate_wal(wal_t* wal, int checkpoint);

/*
 * _replay_from_wal
 * replay the write-ahead log
 * @param tdb the TidesDB instance
 * @param wal the write-ahead log
 * @return 0 if the wal was replayed, -1 if not
 */
int _replay_from_wal(tidesdb_t* tdb, wal_t* wal);

/*
 * _free_sstable
 * free the memory for an SSTable
 * @param sst the SSTable
 * @return 0 if the SSTable was freed, -1 if not
 */
int _free_sstable(sstable_t* sst);

/*
 * _compare_sstables
 * compare two sstables
 * @param a the first sstable
 * @param b the second sstable
 * @return the comparison
 */
int _compare_sstables(const void* a, const void* b);

/*
 * _flush_memtable
 * flushes a memtable to disk
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @param memtable a memtable
 * @param wal_checkpoint the point in the wal to truncate after flush
 * @return 0 if the memtable was flushed, -1 if not
 */
int _flush_memtable(tidesdb_t* tdb, column_family_t* cf, skiplist_t* memtable, int wal_checkpoint);

/*
 * _flush_memtable_thread
 * thread for flushing memtables
 * @param arg the arguments for the thread in this case a tidesdb instance
 */
void* _flush_memtable_thread(void* arg);

/*
 * _is_tombstone
 * checks if value is a tombstone
 * @param value the value
 * @param value_size the size of the value
 * @return 1 if the value is a tombstone, 0 if not
 */
int _is_tombstone(const uint8_t* value, size_t value_size);

/*
 * _load_sstables
 * load the sstables for a column family
 * @param cf the column family
 * @return 0 if the sstables were loaded, -1 if not
 */
int _load_sstables(column_family_t* cf);

/*
 * _sort_sstables
 * sort the sstables for a column family by last modified being last
 * @param cf the column family
 * @return 0 if the sstables were sorted, -1 if not
 */
int _sort_sstables(const column_family_t* cf);

/*
 * remove_directory
 * recursively remove a directory and its contents
 * @param path the path to the directory
 * @return 0 if the directory was removed, -1 if not
 */
int _remove_directory(const char* path);

/*
 * _compact_sstables_thread
 * a thread for compacting sstable pairs
 * @param arg the arguments for the thread in this case a compact_thread_args struct
 */
void _compact_sstables_thread(void* arg);

/*
 * _merge_sstables
 * merges two sstables into a new sstable
 * @param sst1 the first sstable
 * @param sst2 the second sstable
 * @param cf the column family
 * @return the new sstable
 */
sstable_t* _merge_sstables(sstable_t* sst1, sstable_t* sst2, column_family_t* cf);

/*
 * _free_column_families
 * free the memory for the column families
 * @param tdb the TidesDB instance
 */
void _free_column_families(tidesdb_t* tdb);

/*
 * _free_key_value_pair
 * free the memory for a key-value pair
 * @param kv the key-value pair
 */
void _free_key_value_pair(key_value_pair_t* kv);

/*
 * _free_operation
 * free the memory for an operation
 * @param op the operation
 */
void _free_operation(operation_t* op);

/*
 * _compare_keys
 * compare two keys
 * @param key1 the first key
 * @param key1_size the size of the first key
 * @param key2 the second key
 * @param key2_size the size of the second key
 * @return the comparison, 1, 0, or -1
 */
int _compare_keys(const uint8_t* key1, size_t key1_size, const uint8_t* key2, size_t key2_size);

#endif /* TIDESDB_H */