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
#ifndef __TIDESDB_H__
#define __TIDESDB_H__

#include <stdbool.h>

#include "binary_hash_array.h"
#include "block_manager.h"
#include "bloom_filter.h"
/* we include compat.h in above headers already */
#include "compress.h"
#include "err.h"
#include "hash_table.h"
#include "log.h"
#include "skip_list.h"

/* TidesDB uses tidesdb, _tidesdb_, and TDB as prefixes for functions, types, and constants */

#define TDB_WAL_EXT                       ".wal"     /* extension for the write-ahead log file */
#define TDB_SSTABLE_EXT                   ".sst"     /* extension for the SSTable file */
#define TDB_COLUMN_FAMILY_CONFIG_FILE_EXT ".cfc"     /* configuration file for the column family */
#define TDB_TEMP_EXT                      ".tmp"     /* extension for temporary files, names */
#define TDB_TOMBSTONE                     0xDEADBEEF /* tombstone value for deleted keys */
#define TDB_SYNC_INTERVAL                 0.24       /* interval for syncing mainly WAL */
#define TDB_BLOOM_FILTER_P                0.01       /*  the false positive rate for bloom filter */
#define TDB_BLOCK_INDICES                                                                          \
    1 /* whether to store block indices in SSTable. Will cause more memory usage but reads will be \
         faster */
#define TDB_SSTABLE_PREFIX                "sstable_" /* prefix for SSTable files */
#define TDB_FLUSH_THRESHOLD               1048576    /* default flush threshold for column family */
#define TDB_MIN_MAX_LEVEL                 5          /* minimum max level for column family */
#define TDB_MIN_PROBABILITY               0.1        /* minimum probability for column family */
#define TDB_USING_HT_MAX_LEVEL            0          /* max level for using hash table memtable */
#define TDB_USING_HT_PROBABILITY          0.0f       /* probability for using hash table memtable */
#define TDB_DEFAULT_SKIP_LIST_MAX_LEVEL   12         /* default max level for skip list memtable */
#define TDB_DEFAULT_SKIP_LIST_PROBABILITY 0.24f /* default probability for skip list memtable */
#define TDB_AVAILABLE_MEMORY_THRESHOLD \
    0.6f                     /* allow key value pairs that take up 60% of available system memory */
#define TDB_DEBUG_LOG 1      /* or 0 */
#define TDB_LOG_EXT   ".log" /* extension for the log file */
#define TDB_DEBUG_LOG_TRUNCATE_AT                    \
    (int)100000 /* if not -1 we truncate log file at \
              TDB_DEBUG_LOG_TRUNCATE_AT entries */

/*
 * tidesdb_compression_algo_t
 * compression algorithm enum
 * used for compression algorithms in TidesDB
 */
typedef enum
{
    TDB_NO_COMPRESSION,
    TDB_COMPRESS_SNAPPY,
    TDB_COMPRESS_LZ4,
    TDB_COMPRESS_ZSTD
} tidesdb_compression_algo_t;

/*
 * tidesdb_sstable_t
 * struct for a TidesDB SSTable
 * @param block_manager the block manager for the SSTable
 */
typedef struct
{
    block_manager_t *block_manager;
} tidesdb_sstable_t;

/*
 * tidesdb_wal_t
 * struct for write-ahead logs in TidesDB
 * @param block_manager the block manager for the WAL
 * @param compress whether to compress the WAL
 * @param compress_algo the compression algorithm to use if you want to compress the WAL
 */
typedef struct
{
    block_manager_t *block_manager;
    bool compress;
    tidesdb_compression_algo_t compress_algo;
} tidesdb_wal_t;

/*
 * TIDESDB_MEMTABLE_DS
 * memtable data structure enum
 * used to select the data structure for a column family memtable
 */
typedef enum
{
    TDB_MEMTABLE_SKIP_LIST, /* a skip list data structure for the memtable */
    TDB_MEMTABLE_HASH_TABLE /* a hash table data structure for the memtable */
} tidesdb_memtable_ds_t;

/*
 * tidesdb_column_family_config_t
 * struct for a column family configuration
 * used for column family configuration in TidesDB
 * @param name the name of the column family
 * @param flush_threshold the flush threshold of the column family
 * @param max_level the max level of the column family
 * @param probability the probability of the column family
 * @param compressed the compressed status of the column family
 * @param bloom_filter whether to use a bloom filter for the column family sstables
 */
typedef struct
{
    char *name;
    int32_t flush_threshold;
    int32_t max_level;
    float probability;
    bool compressed;
    tidesdb_compression_algo_t compress_algo;
    tidesdb_memtable_ds_t memtable_ds;
    bool bloom_filter;
} tidesdb_column_family_config_t;

/* forward declaration of tidesdb_t */
typedef struct tidesdb_t tidesdb_t;

/*
 * tidesdb_column_family_t
 * struct for a column family in TidesDB
 * @param tdb the TidesDB instance
 * @param config the configuration for the column family
 * @param path the path to the column family
 * @param sstables the sstables for the column family
 * @param num_sstables the number of sstables for the column family
 * @param rwlock read-write lock for column family
 * @param memtable_sl the skip list memtable for the column family. Can be NULL
 * @param memtable_ht the hash table memtable for the column family. Can be NULL
 * @param wal the write-ahead log for column family
 * @param partial_merging whether the column family has been started with partially merging.  If so
 * you cannot manually compact the column family.
 * @param partial_merge_thread the thread for partial merging
 * @param partial_merge_interval the interval for partial merging
 * @param partial_merge_min_sstables the minimum number of sstables to trigger a partial merge
 */
typedef struct
{
    tidesdb_t *tdb;
    tidesdb_column_family_config_t config;
    char *path;
    tidesdb_sstable_t **sstables;
    int num_sstables;
    pthread_rwlock_t rwlock;
    skip_list_t *memtable_sl; /* we once had a void* for the memtable but found it safer to have
                                 separate memtables */
    hash_table_t *memtable_ht;
    tidesdb_wal_t *wal;
    bool partial_merging;
    pthread_t partial_merge_thread;
    int partial_merge_interval;
    int partial_merge_min_sstables;
} tidesdb_column_family_t;

/*
 * tidesdb_key_value_pair_t
 * key value pair struct for TidesDB SSTables and WAL
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time to live of the key value pair
 */
typedef struct
{
    uint8_t *key;
    uint32_t key_size;
    uint8_t *value;
    uint32_t value_size;
    int64_t ttl;
} tidesdb_key_value_pair_t;

/*
 * TIDESDB_OP_CODE
 * operation code enum
 * used for operation codes in TidesDB mainly for transactions and WAL entries
 */
typedef enum
{
    TIDESDB_OP_PUT,   /* a put operation into a column family */
    TIDESDB_OP_DELETE /* a delete operation from a column family */
} TIDESDB_OP_CODE;

/*
 * tidesdb_operation_t
 * struct for a TidesDB operation
 * @param op_code the operation code
 * @param kv the key value pair for the operation
 * @param cf_name the column family name for the operation
 */
typedef struct
{
    TIDESDB_OP_CODE op_code;
    tidesdb_key_value_pair_t *kv;
    char *cf_name;
} tidesdb_operation_t;

/*
 * tidesdb_txn_op_t
 * struct for a transaction operation
 * @param op the operation for the transaction
 * @param rollback_op the rollback operation for the operation
 * @param committed whether the transaction op has been committed
 */
typedef struct
{
    tidesdb_operation_t *op;
    tidesdb_operation_t *rollback_op;
    bool committed;
} tidesdb_txn_op_t;

/*
 * tidesdb_t
 * struct for TidesDB
 * @param directory the directory for the database
 * @param column_families the column families currently
 * @param num_column_families the number of column families
 * @param rwlock read-write lock for the database
 * @param log the log for the database
 * @param available_mem the available memory for the system.  TidesDB gets
 * TDB_AVAILABLE_MEMORY_THRESHOLD % of available memory on start up and will not allow kvp to be
 * added if exceeds available memory.
 */
struct tidesdb_t
{
    char *directory;
    tidesdb_column_family_t **column_families;
    int num_column_families;
    pthread_rwlock_t rwlock;
    log_t *log;
    size_t available_mem;
};

/*
 * tidesdb_txn_t
 * struct for a transaction
 * @param tdb the tidesdb instance
 * @param ops the operations in the transaction
 * @param num_ops the number of operations in the transaction
 * @param cf the column family for the transaction
 * @param lock the lock for the transaction
 */
typedef struct
{
    tidesdb_t *tdb;
    tidesdb_txn_op_t *ops;
    int num_ops;
    tidesdb_column_family_t *cf;
    pthread_mutex_t lock;
} tidesdb_txn_t;

/*
 * tidesdb_cursor_t
 * struct for a TidesDB cursor
 * @param tidesdb the tidesdb instance
 * @param cf the column family
 * @param memtable_cursor the cursor for the memtable
 * @param sstable_index the current index of the sstable the cursor is on
 * @param sstable_cursor the cursor for the sstable
 * @param current the current key-value pair
 */
typedef struct
{
    tidesdb_t *tidesdb;
    tidesdb_column_family_t *cf;
    void *memtable_cursor;
    int sstable_index;
    block_manager_cursor_t *sstable_cursor;
    tidesdb_key_value_pair_t *current;
} tidesdb_cursor_t;

/*
 * tidesdb_compact_thread_args_t
 * struct for the arguments for a compact thread
 * @param cf the column family
 * @param start the start index for the sstables
 * @param end the end index for the sstables
 * @param sem semaphore to limit concurrent threads
 * @param lock for the path creation on parallel compaction
 */
typedef struct
{
    tidesdb_column_family_t *cf; /* the column family */
    int start;                   /* the start index for the sstables */
    int end;                     /* the end index for the sstables */
    sem_t *sem;                  /* semaphore to limit concurrent threads */
    pthread_mutex_t *lock;       /* lock for the path creation on parallel compaction */
} tidesdb_compact_thread_args_t;

/*
 * tidesdb_partial_merge_thread_args_t
 * struct for the arguments for a partial merge thread
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @param lock for the path creation on compaction (required as its part of merge method)
 */
typedef struct
{
    tidesdb_t *tdb;
    tidesdb_column_family_t *cf;
    pthread_mutex_t *lock;
} tidesdb_partial_merge_thread_args_t;

/* functions prefixed with _ are internal functions */
/* api functions return a tidesdb_err* */

/*
 * tidesdb_open
 * open a TidesDB instance
 * @param directory the directory for the database in which where
 *** column families and their data will be stored or are stored
 * @param tdb the TidesDB instance (should be null)
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_open(const char *directory, tidesdb_t **tdb);

/*
 * tidesdb_close
 * close a TidesDB instance gracefully
 * @param tdb the TidesDB instance
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_close(tidesdb_t *tdb);

/*
 * tidesdb_create_column_family
 * create a new column family
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param flush_threshold the threshold at which the memtable should be flushed to disk
 * @param max_level the maximum level for the memtable(skiplist)
 * @param probability the probability for skip list
 * @param compressed whether the column family WAL and SSTables should be compressed
 * @param compress_algo the compression algorithm to use if you want to compress the column family
 * @param bloom_filter whether the column family should use a bloom filter
 * @param memtable_ds the data structure for the memtable
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_create_column_family(tidesdb_t *tdb, const char *name, int flush_threshold,
                                            int max_level, float probability, bool compressed,
                                            tidesdb_compression_algo_t compress_algo,
                                            bool bloom_filter, tidesdb_memtable_ds_t memtable_ds);

/*
 * tidesdb_drop_column_family
 * drops a column family and all associated data
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_drop_column_family(tidesdb_t *tdb, const char *name);

/*
 * tidesdb_compact_sstables
 * pairs and merges sstables in a column family
 * @param tdb the TidesDB instance
 * @param column_family the column family name
 * @param max_threads the maximum number of threads to use
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_compact_sstables(tidesdb_t *tdb, const char *column_family_name,
                                        int max_threads);

/*
 * tidesdb_put
 * put a key-value pair into TidesDB
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair, you can provide -1 for no ttl
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_put(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                           size_t key_size, const uint8_t *value, size_t value_size, time_t ttl);

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
tidesdb_err_t *tidesdb_get(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                           size_t key_size, uint8_t **value, size_t *value_size);

/*
 * tidesdb_delete
 * delete a key-value pair from TidesDB
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param key the key
 * @param key_size the size of the key
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_delete(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                              size_t key_size);

/*
 * tidesdb_txn_begin
 * begin a transaction
 * @param tdb the TidesDB instance
 * @param txn the transaction to begin
 * @param column_family the column family
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_begin(tidesdb_t *tdb, tidesdb_txn_t **txn, const char *column_family);

/*
 * tidesdb_txn_put
 * put a key-value pair into a transaction
 * @param txn the transaction
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_put(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size,
                               const uint8_t *value, size_t value_size, time_t ttl);

/*
 * tidesdb_txn_delete
 * delete a key-value pair from a transaction
 * @param txn the transaction
 * @param key the key
 * @param key_size the size of the key
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_delete(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size);

/*
 * tidesdb_txn_commit
 * commit a transaction
 * @param txn the transaction to be commited
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_commit(tidesdb_txn_t *txn);

/*
 * tidesdb_txn_rollback
 * rollback a transaction
 * @param txn the transaction
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_rollback(tidesdb_txn_t *txn);

/*
 * tidesdb_txn_free
 * free a transaction and its operations
 * @param txn the transaction
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_txn_free(tidesdb_txn_t *txn);

/*
 * tidesdb_cursor_init
 * initialize a new TidesDB cursor
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_cursor_init(tidesdb_t *tdb, const char *column_family_name,
                                   tidesdb_cursor_t **cursor);

/*
 * tidesdb_cursor_next
 * move the cursor to the next key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_cursor_next(tidesdb_cursor_t *cursor);

/*
 * tidesdb_cursor_prev
 * move the cursor to the previous key-value pair
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_cursor_prev(tidesdb_cursor_t *cursor);

/*
 * tidesdb_cursor_get
 * get the current key-value pair from the cursor
 * @param cursor the TidesDB cursor
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_cursor_get(tidesdb_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size);

/*
 * tidesdb_cursor_free
 * free the memory for the cursor
 * @param cursor the TidesDB cursor
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_cursor_free(tidesdb_cursor_t *cursor);

/*
 * tidesdb_list_column_families
 * list the column families in TidesDB
 * @param tdb the TidesDB instance
 * @param list the list of column families
 * @return error or NULL
 */
tidesdb_err_t *tidesdb_list_column_families(tidesdb_t *tdb, char **list);

/*
 * tidesdb_start_background_partial_merge
 * starts background partial merge for column family. Will incrementally when minimum is reached
 * pair and merge sstables. Blocks less than full compaction as sstables are copied and merged in
 * the background then replaced.
 * @param tdb the TidesDB instance
 * @param column_family_name the name of the column family
 * @param seconds the interval in seconds for the partial merges, each provided seconds a partial
 * merge will occur from oldest sstable making its way to newest
 * @param min_sstables the minimum number of sstables to trigger a partial merge
 * @return error or NULL if thread was started
 */
tidesdb_err_t *tidesdb_start_background_partial_merge(tidesdb_t *tdb,
                                                      const char *column_family_name, int seconds,
                                                      int min_sstables);

/* internal functions */

/*
 * _tidesdb_get_column_family
 * get a column family by name
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param cf the column family we found
 * @return 0 if the column family was found, -1 if not
 */
int _tidesdb_get_column_family(tidesdb_t *tdb, const char *name, tidesdb_column_family_t **cf);

/*
 * _tidesdb_new_column_family
 * create a new column family
 * @param tdb the TidesDB instance
 * @param name the name of the column family
 * @param flush_threshold the threshold at which the memtable should be flushed to disk
 * @param max_level the maximum level for the memtable(skiplist)
 * @param probability the probability for skip list
 * @param cf the column family
 * @param compressed whether the column family WAL and SSTables should be compressed
 * @param compress_algo the compression algorithm to use if you want to compress the column family
 * @param bloom_filter whether the column family should use a bloom filter
 * @param memtable_ds the data structure for the memtable
 * @return 0 if the column family was created, -1 if not
 */
int _tidesdb_new_column_family(tidesdb_t *tdb, const char *name, int flush_threshold, int max_level,
                               float probability, tidesdb_column_family_t **cf, bool compressed,
                               tidesdb_compression_algo_t compress_algo, bool bloom_filter,
                               tidesdb_memtable_ds_t memtable_ds);

/*
 * _tidesdb_add_column_family
 * adds a new column family to TidesDB
 * @param tdb the TidesDB instance
 * @param cf the column family
 * @return 0 if the column family was added, -1 if not
 */
int _tidesdb_add_column_family(tidesdb_t *tdb, tidesdb_column_family_t *cf);

/*
 * _tidesdb_load_column_families
 * load the column families for TidesDB
 * @param tdb the TidesDB instance
 * @return 0 if the column families were loaded, -1 if not
 */
int _tidesdb_load_column_families(tidesdb_t *tdb);

/*
 * _tidesdb_get_path_seperator
 * get the path separator for the current OS
 * @return the path separator
 */
const char *_tidesdb_get_path_seperator();

/*
 * _tidesdb_append_to_wal
 * append an operation to the write-ahead log
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
int _tidesdb_append_to_wal(tidesdb_wal_t *wal, const uint8_t *key, size_t key_size,
                           const uint8_t *value, size_t value_size, time_t ttl,
                           TIDESDB_OP_CODE op_code, const char *cf);

/*
 * _tidesdb_open_wal
 * open the write-ahead log
 * @param cf_path the path to the column family
 * @param w the write-ahead log
 * @param compress whether to compress the wal
 * @param compress_algo the compression algorithm to use
 * @return 0 if the wal was opened, -1 if not
 */
int _tidesdb_open_wal(const char *cf_path, tidesdb_wal_t **w, bool compress,
                      tidesdb_compression_algo_t compress_algo);

/*
 * _tidesdb_close_wal
 * close the write-ahead log
 * @param wal the write-ahead log
 */
void _tidesdb_close_wal(tidesdb_wal_t *wal);

/*
 * _tidesdb_replay_from_wal
 * replay the write-ahead log and populate column family memtable
 * @param cf the column family
 * @return 0 if the wal was replayed, -1 if not
 */
int _tidesdb_replay_from_wal(tidesdb_column_family_t *cf);

/*
 * _tidesdb_free_sstable
 * free the memory for an SSTable
 * @param sst the SSTable
 * @return 0 if the SSTable was freed, -1 if not
 */
int _tidesdb_free_sstable(tidesdb_sstable_t *sst);

/*
 * _tidesdb_compare_sstables
 * compare two sstables
 * @param a the first sstable
 * @param b the second sstable
 * @return the comparison
 */
int _tidesdb_compare_sstables(const void *a, const void *b);

/*
 * _tidesdb_flush_memtable
 * flushes a memtable to disk in an SSTable from a skip list memtable
 * @param cf the column family
 * @return 0 if the memtable was flushed, -1 if not
 */
int _tidesdb_flush_memtable(tidesdb_column_family_t *cf);

/*
 * _tidesdb_flush_memtable_f_hash_table
 * flushes a memtable to disk in an SSTable from a hash table memtable
 * @param cf the column family
 * @return 0 if the memtable was flushed, -1 if not
 */
int _tidesdb_flush_memtable_f_hash_table(tidesdb_column_family_t *cf);

/*
 * _tidesdb_flush_memtable_w_bloom_filter
 * flushes a memtable to disk in an SSTable with a bloom filter at initial block from a skip list
 * memtable
 * @param cf the column family
 * @return 0 if the memtable was flushed, -1 if not
 */
int _tidesdb_flush_memtable_w_bloom_filter(tidesdb_column_family_t *cf);

/*
 * _tidesdb_flush_memtable_w_bloom_filter_f_hash_table
 * flushes a memtable to disk in an SSTable with a bloom filter at initial block from a hash table
 * memtable
 * @param cf the column family
 * @return 0 if the memtable was flushed, -1 if not
 */
int _tidesdb_flush_memtable_w_bloom_filter_f_hash_table(tidesdb_column_family_t *cf);

/*
 * _tidesdb_is_tombstone
 * checks if value is a tombstone TDB_TOMBSTONE
 * @param value the value to check
 * @param value_size the size of the value to check
 * @return 1 if the value is a tombstone, 0 if not
 */
int _tidesdb_is_tombstone(const uint8_t *value, size_t value_size);

/*
 * _tidesdb_load_sstables
 * load the sstables for a column family
 * @param cf the column family
 * @return 0 if the sstables were loaded, -1 if not
 */
int _tidesdb_load_sstables(tidesdb_column_family_t *cf);

/*
 * _tidesdb_sort_sstables
 * sort the sstables for a column family by last modified being last in the array
 * @param cf the column family
 * @return 0 if the sstables were sorted, -1 if not
 */
int _tidesdb_sort_sstables(const tidesdb_column_family_t *cf);

/*
 * _tidesdb_remove_directory
 * remove a directory and its contents
 * @param path the path to the directory
 * @return 0 if the directory was removed, -1 if not
 */
int _tidesdb_remove_directory(const char *path);

/*
 * _tidesdb_compact_sstables_thread
 * a thread for compacting sstable pairs
 * @param arg the arguments for the thread in this case a compact_thread_args struct
 */
void *_tidesdb_compact_sstables_thread(void *arg);

/*
 * _tidesdb_merge_sstables
 * merges two sstables into a new sstable
 * @param sst1 the first sstable
 * @param sst2 the second sstable
 * @param cf the column family
 * @param shared_lock the lock for the path creation on parallel compaction
 * @return the new merged sstable
 */
tidesdb_sstable_t *_tidesdb_merge_sstables(tidesdb_sstable_t *sst1, tidesdb_sstable_t *sst2,
                                           tidesdb_column_family_t *cf,
                                           pthread_mutex_t *shared_lock);

/*
 * _tidesdb_merge_sstables_w_bloom_filter
 * merges two sstables into a new sstable and adds a bloom filter to initial block
 * @param sst1 the first sstable
 * @param sst2 the second sstable
 * @param cf the column family
 * @param shared_lock the lock for the path creation on parallel compaction
 * @return the new merged sstable
 */
tidesdb_sstable_t *_tidesdb_merge_sstables_w_bloom_filter(tidesdb_sstable_t *sst1,
                                                          tidesdb_sstable_t *sst2,
                                                          tidesdb_column_family_t *cf,
                                                          pthread_mutex_t *shared_lock);

/*
 * _tidesdb_free_column_families
 * free's and closes column families
 * @param tdb the TidesDB instance
 */
void _tidesdb_free_column_families(tidesdb_t *tdb);

/*
 * _tidesdb_free_key_value_pair
 * free the memory for a key-value pair
 * @param kv the key-value pair
 */
void _tidesdb_free_key_value_pair(tidesdb_key_value_pair_t *kv);

/*
 * _tidesdb_free_operation
 * free the memory for an operation
 * @param op the operation
 */
void _tidesdb_free_operation(tidesdb_operation_t *op);

/*
 * _tidesdb_compare_keys
 * compare two keys mainly for equality operations in TidesDB
 * @param key1 the first key
 * @param key1_size the size of the first key
 * @param key2 the second key
 * @param key2_size the size of the second key
 * @return the comparison, 1, 0, or -1
 */
int _tidesdb_compare_keys(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                          size_t key2_size);

/* serialization is used for tidesdb_key_value_pair_t and tidesdb_operation_t */

/*
 * _tidesdb_serialize_key_value_pair
 * serialize a key-value pair
 * @param kv the key-value pair
 * @param out_size the size of the serialized data
 * @param compress whether to compress the data
 * @param compress_algo the compression algorithm to use
 * @return the serialized data
 */
uint8_t *_tidesdb_serialize_key_value_pair(tidesdb_key_value_pair_t *kv, size_t *out_size,
                                           bool compress, tidesdb_compression_algo_t compress_algo);

/*
 * _tidesdb_deserialize_key_value_pair
 * deserialize a key-value pair
 * @param data the serialized data
 * @param data_size the size of the data
 * @param decompress whether to decompress the data
 * @return the deserialized key-value pair
 */
tidesdb_key_value_pair_t *_tidesdb_deserialize_key_value_pair(
    uint8_t *data, size_t data_size, bool decompress, tidesdb_compression_algo_t compress_algo);

/*
 * _tidesdb_serialize_operation
 * serialize an operation
 * @param op the operation
 * @param out_size the size of the serialized data
 * @param compress whether to compress the data
 * @param compress_algo the compression algorithm to use
 * @return the serialized data
 */
uint8_t *_tidesdb_serialize_operation(tidesdb_operation_t *op, size_t *out_size, bool compress,
                                      tidesdb_compression_algo_t compress_algo);

/*
 * _tidesdb_deserialize_operation
 * deserialize an operation
 * @param data the serialized data
 * @param data_size the size of the data
 * @param decompress whether to decompress the data
 * @param compress_algo the compression algorithm used
 * @return the deserialized operation
 */
tidesdb_operation_t *_tidesdb_deserialize_operation(uint8_t *data, size_t data_size,
                                                    bool decompress,
                                                    tidesdb_compression_algo_t compress_algo);

/*
 * _tidesdb_serialize_column_family_config
 * serialize a column family configuration
 * @param config the column family configuration
 * @param out_size the size of the serialized data
 * @return the serialized data
 */
uint8_t *_tidesdb_serialize_column_family_config(tidesdb_column_family_config_t *config,
                                                 size_t *out_size);

/*
 * _tidesdb_deserialize_column_family_config
 * deserialize a column family configuration
 * @param data the serialized data
 * @return the deserialized column family configuration
 */
tidesdb_column_family_config_t *_tidesdb_deserialize_column_family_config(const uint8_t *data);

/*
 * _tidesdb_key_value_pair_new
 * create a new key-value pair
 * @param key the key
 * @param key_size the size of the key
 * @param value the value
 * @param value_size the size of the value
 * @param ttl the time-to-live for the key-value pair
 * @return the key-value pair
 */
tidesdb_key_value_pair_t *_tidesdb_key_value_pair_new(const uint8_t *key, size_t key_size,
                                                      const uint8_t *value, size_t value_size,
                                                      int64_t ttl);

/*
 * _tidesdb_is_expired
 * checks if a key-value pair is expired by comparing the ttl with the current time or if set to -1
 * @param ttl the time-to-live for the key-value pair
 * @return 1 if the key-value pair is expired, 0 if not
 */
int _tidesdb_is_expired(int64_t ttl);

/*
 * _tidesdb_map_compression_algo
 * maps a tidesdb compression algo to a compress_type algo
 * @param algo the tidesdb compression algo
 * @return the correct compress_type algo
 */
compress_type _tidesdb_map_compression_algo(tidesdb_compression_algo_t algo);

/*
 * _tidesdb_partial_merge_thread
 * a thread for pair merging column family sstables partially, and incrementally.  Merges are only
 * trigger when a threshold of sstables are reached.
 * @param arg the arguments for the thread in this case a partial_merge_thread_args struct
 */
void *_tidesdb_partial_merge_thread(void *arg);

/*
 * _tidesdb_get_available_mem
 * get the available memory for the system, usually on start up.
 * @return the available memory
 */
size_t _tidesdb_get_available_mem();

/*
 * _tidesdb_merge_sort
 * merges 2 sstables into a new sstable using block managers.  A memory efficient approach to
 * merging ssts.  Method will also removed expired keys if ttl set and tombstones.  The second
 * sstable block manager supercedes the first sstable block manager.
 * @param cf the column family
 * @param bm1 the block manager for the first sstable
 * @param bm2 the block manager for the second sstable
 * @param bm_out the block manager for the new sstable
 * @return 0 if the sstables were merged, -1 if not
 */
int _tidesdb_merge_sort(tidesdb_column_family_t *cf, block_manager_t *bm1, block_manager_t *bm2,
                        block_manager_t *bm_out);

#endif /* __TIDESDB_H__ */