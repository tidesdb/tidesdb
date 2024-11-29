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

#define BLOOMFILTER_SIZE                                                                      \
    1000 /* size of each bloom filter.  Bloom filters are linked once they reach this size in \
            occupied capacity */
#define WAL_EXT                       ".wal"     /* extension for the write-ahead log file */
#define SSTABLE_EXT                   ".sst"     /* extension for the SSTable file */
#define COLUMN_FAMILY_CONFIG_FILE_EXT ".cfc"     /* configuration file for the column family */
#define TOMBSTONE                     0xDEADBEEF /* tombstone value for deleted keys */

/*
 * tidesdb_config_new
 * create a new TidesDB config
 * @param db_path the path for/to TidesDB
 * @param compressed_wal whether the wal should be compressed
 */
typedef struct
{
    char* db_path;       /* the path for/to TidesDB.  This is where column families are stored */
    bool compressed_wal; /* whether the wal should be compressed */
} tidesdb_config;

/*
 * sstable
 * struct for the SSTable
 * @param pager the pager for the SSTable
 */
typedef struct
{
    pager* pager; /* the pager for the SSTable */
} sstable;

/*
 * wal
 * struct for the write-ahead log
 * @param pager the pager for the WAL
 * @param lock the read-write lock for the WAL
 */
typedef struct
{
    pager* pager;          /* the pager for the WAL */
    pthread_rwlock_t lock; /* Read-write lock for the SSTable */
} wal;

/*
 * column_family
 * struct for a column family
 * @param config the configuration for the column family
 * @param path the path to the column family
 * @param sstables the sstables for the column family
 * @param num_sstables the number of sstables for the column family
 * @param sstables_lock Read-write lock for SSTables mainly for when adding a new sstable
 * @param memtable the memtable for the column family
 * @param id_gen id generator for the column family; mainly used for sstable filenames
 */
typedef struct
{
    column_family_config config; /* the configuration for the column family */
    char* path;                  /* the path to the column family */
    sstable** sstables;          /* the sstables for the column family */
    int num_sstables;            /* the number of sstables for the column family */
    pthread_rwlock_t
        sstables_lock;  /* Read-write lock for SSTables mainly for when adding a new sstable */
    skiplist* memtable; /* the memtable for the column family */
    id_gen* id_gen;     /* id generator for the column family; mainly used for sstable filenames */
} column_family;

/*
 * txn_op
 * struct for a transaction operation
 * @param op the operation for the transaction
 * @param rollback_op the rollback operation for the operation
 * @param committed whether the transaction op has been committed
 */
typedef struct
{
    operation* op;          /* the operation for the transaction */
    operation* rollback_op; /* the rollback operation for the operation */
    bool committed;         /* whether the transaction op has been committed */
} txn_op;

/*
 * txn
 * struct for a transaction
 * @param ops the operations in the transaction
 * @param num_ops the number of operations in the transaction
 * @param column_family the column family for the transaction
 */
typedef struct
{
    txn_op* ops;         /* the operations in the transaction */
    int num_ops;         /* the number of operations in the transaction */
    char* column_family; /* the column family for the transaction */
} txn;

/*
 * tidesdb
 * struct for TidesDB
 * @param config the configuration for TidesDB
 * @param column_families the column families currently
 * @param column_families_lock Read-write lock for column families
 * @param num_column_families the number of column families currently
 * @param wal the write-ahead log for TidesDB
 * @param flush_thread the thread for flushing memtables
 * @param flush_queue the queue for flushing memtables
 * @param flush_lock the flush lock
 * @param flush_cond the condition variable for flush thread
 * @param stop_flush_thread flag to stop the flush thread
 */
typedef struct
{
    tidesdb_config config;                 /* the configuration for tidesdb */
    column_family* column_families;        /* the column families currently */
    pthread_rwlock_t column_families_lock; /* Read-write lock for column families */
    int num_column_families;               /* the number of column families currently */
    wal* wal;                              /* the write-ahead log for tidesdb */
    pthread_t flush_thread;                /* the thread for flushing memtables */
    queue* flush_queue;                    /* the queue for flushing memtables */
    pthread_mutex_t flush_lock;            /* flush lock */
    pthread_cond_t flush_cond;             /* condition variable for flush thread */
    bool stop_flush_thread;                /* flag to stop the flush thread */
} tidesdb;

/*
 * tidesdb_cursor
 * struct for a TidesDB cursor
 * @param tidesdb the tidesdb instance
 * @param cf the column family
 * @param memtable_cursor the cursor for the memtable
 * @param sstable_index the index of the sstable
 * @param sstable_cursor the cursor for the sstable
 * @param current the current key-value pair
 */
typedef struct
{
    tidesdb* tidesdb;                 /* tidesdb instance */
    column_family* cf;                /* the column family */
    skiplist_cursor* memtable_cursor; /* the cursor for the memtable */
    size_t sstable_index;             /* the index of the sstable */
    pager_cursor* sstable_cursor;     /* the cursor for the sstable */
    key_value_pair* current;          /* the current key-value pair */
} tidesdb_cursor;

/*
 * queue_entry
 * struct for a queue entry
 * @param memtable the memtable
 * @param cf the column family
 * @param wal_checkpoint the point in the wal to truncate after flush
 */
typedef struct
{
    skiplist* memtable;    /* the memtable */
    column_family* cf;     /* the column family */
    size_t wal_checkpoint; /* the point in the wal to truncate after flush */
} queue_entry;

/*
 * compact_thread_args
 * struct for the arguments for a compact thread
 * @param cf the column family
 * @param start the start index for the sstables
 * @param end the end index for the sstables
 */
typedef struct
{
    column_family* cf; /* the column family */
    int start;         /* the start index for the sstables */
    int end;           /* the end index for the sstables */
} compact_thread_args;

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
tidesdb_err* tidesdb_open(const tidesdb_config* config, tidesdb** tdb);

/*
 * tidesdb_close
 * close a TidesDB instance
 * @param tdb the TidesDB instance
 * @return error or NULL
 */
tidesdb_err* tidesdb_close(tidesdb* tdb);

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
tidesdb_err* tidesdb_create_column_family(tidesdb* tdb, const char* name, int flush_threshold,
                                          int max_level, float probability, bool compressed);

/*
 * tidesdb_drop_column_family
 * drops a column family and all associated data
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @return error or NULL
 */
tidesdb_err* tidesdb_drop_column_family(tidesdb* tdb, const char* name);

/*
 * _get_column_family
 * get a column family by name
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param cf the column family
 * @return whether the column family was found
 */
bool _get_column_family(tidesdb* tdb, const char* name, column_family** cf);

/*
 * tidesdb_compact_sstables
 * compact the sstables for a column family
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @param max_threads the maximum number of threads to use
 * @return error or NULL
 */
tidesdb_err* tidesdb_compact_sstables(tidesdb* tdb, column_family* cf, int max_threads);

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
tidesdb_err* tidesdb_put(tidesdb* tdb, const char* column_family_name, const uint8_t* key,
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
tidesdb_err* tidesdb_get(tidesdb* tdb, const char* column_family_name, const uint8_t* key,
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
tidesdb_err* tidesdb_delete(tidesdb* tdb, const char* column_family_name, const uint8_t* key,
                            size_t key_size);

/*
 * tidesdb_txn_begin
 * begin a transaction
 * @param transaction the transaction
 * @param column_family the column family
 * @return error or NULL
 */
tidesdb_err* tidesdb_txn_begin(txn** transaction, const char* column_family);

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
tidesdb_err* tidesdb_txn_put(txn* transaction, const uint8_t* key, size_t key_size,
                             const uint8_t* value, size_t value_size, time_t ttl);

/*
 * tidesdb_txn_delete
 * delete a key-value pair from a transaction
 * @param transaction the transaction
 * @param key the key
 * @param key_size the size of the key
 * @return error or NULL
 */
tidesdb_err* tidesdb_txn_delete(txn* transaction, const uint8_t* key, size_t key_size);

/*
 * tidesdb_txn_commit
 * commit a transaction
 * @param tdb the TidesDB instance
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err* tidesdb_txn_commit(tidesdb* tdb, txn* transaction);

/*
 * tidesdb_txn_rollback
 * rollback a transaction
 * @param tdb the TidesDB instance
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err* tidesdb_txn_rollback(tidesdb* tdb, txn* transaction);

/*
 * tidesdb_txn_free
 * free a transaction
 * @param transaction the transaction
 * @return error or NULL
 */
tidesdb_err* tidesdb_txn_free(txn* transaction);

/*
 * tidesdb_cursor_init
 * initialize a new TidesDB cursor
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err* tidesdb_cursor_init(tidesdb* tdb, const char* column_family_name,
                                 tidesdb_cursor** cursor);

/*
 * tidesdb_cursor_next
 * move the cursor to the next key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err* tidesdb_cursor_next(tidesdb_cursor* cursor);

/*
 * tidesdb_cursor_prev
 * move the cursor to the previous key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err* tidesdb_cursor_prev(tidesdb_cursor* cursor);

/*
 * tidesdb_cursor_get
 * get the current key-value pair from the cursor
 * @param cursor the TidesDB cursor
 * @param kv the key-value pair
 * @return error or NULL
 */
tidesdb_err* tidesdb_cursor_get(tidesdb_cursor* cursor, key_value_pair** kv);

/*
 * tidesdb_cursor_free
 * free the memory for the cursor
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err* tidesdb_cursor_free(tidesdb_cursor* cursor);

/*
 * _new_column_family
 * create a new column family
 * @param db_path the path for/to TidesDB
 * @param name the name of the column family
 * @param flush_threshold the threshold at which the memtable should be flushed to disk
 * @param max_level the maximum level for the memtable(skiplist)
 * @param probability the probability for skip list
 * @param cf the column family
 * @return whether the column family was created
 */
bool _new_column_family(const char* db_path, const char* name, int flush_threshold, int max_level,
                        float probability, column_family** cf, bool compressed);

/*
 * _add_column_family
 * adds a new column family to TidesDB
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @return whether the column family was added
 */
bool _add_column_family(tidesdb* tdb, column_family* cf);

/*
 * _load_column_families
 * load the column families for TidesDB
 * @param tdb the TidesDB instance
 * @return whether the column families were loaded
 */
bool _load_column_families(tidesdb* tdb);

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
 * @return whether the operation was appended to the wal
 */
bool _append_to_wal(tidesdb* tdb, wal* wal, const uint8_t* key, size_t key_size,
                    const uint8_t* value, size_t value_size, time_t ttl, enum OP_CODE op_code,
                    const char* cf);

/*
 * _open_wal
 * open the write-ahead log
 * @param db_path the path for/to TidesDB
 * @param w the write-ahead log
 * @return whether the wal was opened
 */
bool _open_wal(const char* db_path, wal** w);

/*
 * _close_wal
 * close the write-ahead log
 * @param wal the write-ahead log
 */
void _close_wal(wal* wal);

/*
 * _truncate_wal
 * truncate the write-ahead log
 * @param wal the write-ahead log
 * @param checkpoint the point in the wal to truncate
 * @return whether the wal was truncated
 */
bool _truncate_wal(wal* wal, int checkpoint);

/*
 * _replay_from_wal
 * replay the write-ahead log
 * @param tdb the TidesDB instance
 * @param wal the write-ahead log
 * @return whether the wal was replayed
 */
bool _replay_from_wal(tidesdb* tdb, wal* wal);

/*
 * _free_sstable
 * free the memory for an SSTable
 * @param sst the SSTable
 * @return whether the SSTable was freed
 */
bool _free_sstable(sstable* sst);

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
 * @return whether the memtable was flushed
 */
bool _flush_memtable(tidesdb* tdb, column_family* cf, skiplist* memtable, int wal_checkpoint);

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
 * @return whether the value is a tombstone
 */
bool _is_tombstone(const uint8_t* value, size_t value_size);

/*
 * _load_sstables
 * load the sstables for a column family
 * @param cf the column family
 * @return whether the sstables were loaded
 */
bool _load_sstables(column_family* cf);

/*
 * _sort_sstables
 * sort the sstables for a column family by last modified being last
 * @param cf the column family
 * @return whether the sstables were sorted
 */
bool _sort_sstables(const column_family* cf);

/*
 * remove_directory
 * recursively remove a directory and its contents
 * @param path the path to the directory
 */
int _remove_directory(const char* path);

/*
 * _compact_sstables_thread
 * a thread for compacting sstable pairs
 * @param arg the arguments for the thread in this case a compact_thread_args struct
 */
void* _compact_sstables_thread(void* arg);

/*
 * _merge_sstables
 * merges two sstables into a new sstable
 * @param sst1 the first sstable
 * @param sst2 the second sstable
 * @param cf the column family
 */
sstable* _merge_sstables(sstable* sst1, sstable* sst2, column_family* cf);

/*
 * _free_column_families
 * free the memory for the column families
 * @param tdb the TidesDB instance
 */
void _free_column_families(tidesdb* tdb);

/*
 * _free_key_value_pair
 * free the memory for a key-value pair
 * @param kv the key-value pair
 */
void _free_key_value_pair(key_value_pair* kv);

/*
 * _free_operation
 * free the memory for an operation
 * @param op the operation
 */
void _free_operation(operation* op);

/*
 * _compare_keys
 * compare two keys
 * @param key1 the first key
 * @param key1_size the size of the first key
 * @param key2 the second key
 * @param key2_size the size of the second key
 * @return the comparison
 */
int _compare_keys(const uint8_t* key1, size_t key1_size, const uint8_t* key2, size_t key2_size);

#endif /* TIDESDB_H */