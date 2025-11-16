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
#include "block_manager.h"
#include "bloom_filter.h"
#include "compress.h"
#include "ini.h"
#include "lru.h"
#include "queue.h"
#include "skip_list.h"
#include "succinct_trie.h"

/* follow your passion, be obsessed, don't worry too much. */

extern int _tidesdb_debug_enabled;
#if defined(_MSC_VER)
#define TDB_DEBUG_LOG(fmt, ...)                                                               \
    do                                                                                        \
    {                                                                                         \
        if (_tidesdb_debug_enabled)                                                           \
        {                                                                                     \
            struct timespec _ts;                                                              \
            timespec_get(&_ts, TIME_UTC);                                                     \
            time_t _sec = _ts.tv_sec;                                                         \
            struct tm _tm;                                                                    \
            tdb_localtime(&_sec, &_tm);                                                       \
            fprintf(stderr, "[%02d:%02d:%02d.%03ld] [TidesDB] %s:%d: " fmt "\n", _tm.tm_hour, \
                    _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000L, __FILE__, __LINE__,       \
                    ##__VA_ARGS__);                                                           \
        }                                                                                     \
    } while (0)
#else
#define TDB_DEBUG_LOG(fmt, ...)                                                               \
    do                                                                                        \
    {                                                                                         \
        if (_tidesdb_debug_enabled)                                                           \
        {                                                                                     \
            struct timespec _ts;                                                              \
            clock_gettime(CLOCK_REALTIME, &_ts);                                              \
            time_t _sec = _ts.tv_sec;                                                         \
            struct tm _tm;                                                                    \
            tdb_localtime(&_sec, &_tm);                                                       \
            fprintf(stderr, "[%02d:%02d:%02d.%03ld] [TidesDB] %s:%d: " fmt "\n", _tm.tm_hour, \
                    _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000L, __FILE__, __LINE__,       \
                    ##__VA_ARGS__);                                                           \
        }                                                                                     \
    } while (0)
#endif

/* defaults */
#define TDB_DEFAULT_MEMTABLE_FLUSH_SIZE (64 * 1024 * 1024)
#define TDB_DEFAULT_MAX_SSTABLES \
    8 /* compact frequently to reduce write amplification and improve read performance */
#define TDB_DEFAULT_COMPACTION_THREADS             2
#define TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL 1000000
#define TDB_DEFAULT_MAX_OPEN_FILE_HANDLES          1024
#define TDB_DEFAULT_SKIPLIST_LEVELS                12
#define TDB_DEFAULT_SKIPLIST_PROBABILITY           0.25
#define TDB_DEFAULT_BLOOM_FILTER_FP_RATE           0.01
#define TDB_DEFAULT_THREAD_POOL_SIZE               2
#define TDB_DEFAULT_WAL_RECOVERY_POLL_INTERVAL_MS  100000
#define TDB_DEFAULT_WAIT_FOR_WAL_RECOVERY          0
#define TDB_DEFAULT_BLOCK_CACHE_SIZE               (64 * 1024 * 1024) /* 64MB block cache */

/* limits */
#define TDB_MAX_CF_NAME_LENGTH  128
#define TDB_MAX_PATH_LENGTH     1024
#define TDB_MAX_COMPARATOR_NAME 64
#define TDB_MAX_COMPARATORS     32

/* if a key-value exceeds this percentage users system memory we throw an error */
#define TDB_MEMORY_PERCENTAGE 60

/* minimum allowed size for a single key-value pair (1MB), regardless of available memory */
#define TDB_MIN_KEY_VALUE_SIZE (1024 * 1024)

/* extensions, prefixes, and file names */
#define TDB_WAL_EXT                       ".log"
#define TDB_SSTABLE_EXT                   ".sst"
#define TDB_COLUMN_FAMILY_CONFIG_FILE_EXT ".cfc"
#define TDB_TEMP_EXT                      ".tmp"
#define TDB_WAL_PREFIX                    "wal_"
#define TDB_SSTABLE_PREFIX                "sstable_"
#define TDB_CONFIG_FILE_NAME              "config"

/* used for key value pair headers on disk */
#define TDB_KV_FORMAT_VERSION 4

#define TDB_KV_HEADER_SIZE \
    26 /* version(1) + flags(1) + key_size(4) + value_size(4) + ttl(8) + seq(8) */

/* "SSTM" sstable meta magic number */
#define TDB_SST_META_MAGIC 0x5353544D

#define SUCCINCT_TRIE_INITIAL_BUFFER_SIZE (1024 * 1024)

/* flags for key-value pair header */
#define TDB_KV_FLAG_TOMBSTONE 0x01

/* error codes */
#define TDB_SUCCESS                  0
#define TDB_ERROR                    -1
#define TDB_ERR_MEMORY               -2
#define TDB_ERR_INVALID_ARGS         -3
#define TDB_ERR_IO                   -4
#define TDB_ERR_NOT_FOUND            -5
#define TDB_ERR_EXISTS               -6
#define TDB_ERR_CORRUPT              -7
#define TDB_ERR_LOCK                 -8
#define TDB_ERR_TXN_COMMITTED        -9
#define TDB_ERR_TXN_ABORTED          -10
#define TDB_ERR_READONLY             -11
#define TDB_ERR_INVALID_NAME         -12
#define TDB_ERR_COMPARATOR_NOT_FOUND -13
#define TDB_ERR_MAX_COMPARATORS      -14
#define TDB_ERR_INVALID_CF           -15
#define TDB_ERR_THREAD               -16
#define TDB_ERR_CHECKSUM             -17
#define TDB_ERR_MEMORY_LIMIT         -18

typedef enum
{
    TDB_SYNC_NONE, /* no fsync/fdatasync - fastest, least durable */
    TDB_SYNC_FULL, /* full fsync/fdatasync on every write to a block manager, slowest, most durable
                    */
} tidesdb_sync_mode_t;

typedef struct tidesdb_t tidesdb_t;
typedef struct tidesdb_column_family_t tidesdb_column_family_t;
typedef struct tidesdb_sstable_t tidesdb_sstable_t;
typedef struct tidesdb_txn_t tidesdb_txn_t;
typedef struct tidesdb_iter_t tidesdb_iter_t;

/*
 * tidesdb_kv_pair_header_t
 * header for serialized key-value pairs
 * streamlined format [header][key][value]
 * @param version format version
 * @param flags bit flags (bit 0 tombstone/deleted)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live (expiration time)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
/*
 * tidesdb_kv_pair_header_t
 * header for serialized key-value pairs
 * streamlined format [header][key][value]
 * @param version format version
 * @param flags bit flags (bit 0 tombstone/deleted)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live (expiration time)
 */
typedef struct
{
    uint8_t version;
    uint8_t flags;
    uint32_t key_size;
    uint32_t value_size;
    int64_t ttl;
} tidesdb_kv_pair_header_t;
#pragma pack(pop)
#else
/*
 * tidesdb_kv_pair_header_t
 * header for serialized key-value pairs
 * streamlined format [header][key][value]
 * @param version format version
 * @param flags bit flags (bit 0 tombstone/deleted)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live (expiration time)
 */
typedef struct __attribute__((packed))
{
    uint8_t version;
    uint8_t flags;
    uint32_t key_size;
    uint32_t value_size;
    int64_t ttl;
} tidesdb_kv_pair_header_t;
#endif

/*
 * tidesdb_config_t
 * configuration for tidesdb instance
 * @param db_path path to the database directory
 * @param enable_debug_logging enable debug logging
 * @param max_open_file_handles maximum number of open file handles (block managers) to cache
 *        0 = disabled (no caching, unlimited open files)
 *        > 0 = cache up to N open files, auto-close LRU when full
 * @param num_flush_threads number of threads in flush thread pool (default 2)
 * @param num_compaction_threads number of threads in compaction thread pool (default 2)
 * @param wait_for_wal_recovery if true, tidesdb_open blocks until all WAL recovery flushes complete
 *        (default: false for fast startup, set true for guaranteed data availability)
 * @param wal_recovery_poll_interval_ms polling interval in milliseconds when waiting for WAL
 * recovery (default: 100ms, only used if wait_for_wal_recovery is true)
 */
typedef struct
{
    char db_path[TDB_MAX_PATH_LENGTH];
    int enable_debug_logging;
    int max_open_file_handles;
    int num_flush_threads;
    int num_compaction_threads;
    int wait_for_wal_recovery;
    int wal_recovery_poll_interval_ms;
} tidesdb_config_t;

/*
 * tidesdb_column_family_config_t
 * configuration for individual column families
 * @param memtable_flush_size size threshold for memtable flush (bytes)
 * @param max_sstables_before_compaction max sstables before triggering compaction (background or
 * manual)
 * @param compaction_threads number of threads to use for parallel compaction (0 = single-threaded)
 * @param sl_max_level maximum skip list level
 * @param sl_probability skip list probability
 * @param enable_compression whether or not to enable compression
 * @param compression_algorithm compression algorithm to use if compression is enabled for column
 * family
 * @param enable_bloom_filter whether to use bloom filters for this column family
 * @param bloom_filter_fp_rate bloom filter false positive rate (only used if enable_bloom_filter is
 * true)
 * @param enable_background_compaction enable automatic background compaction
 * @param background_compaction_interval interval in microseconds between compaction checks (default
 * 1000000 = 1 second)
 * @param enable_block_indexes use succinct trie for block offset indexing (faster key lookups)
 * @param sync_mode sync mode for this column family (TDB_SYNC_NONE or TDB_SYNC_FULL)
 * @param comparator_name name of registered comparator (NULL = use default "memcmp")
 * during compaction/flush (default 1000 = 1ms)
 * @param block_manager_cache_size if you want block managers to use an LRU cache for blocks set to
 * > 0
 */
typedef struct
{
    size_t memtable_flush_size;
    int max_sstables_before_compaction;
    int compaction_threads;
    int sl_max_level;
    float sl_probability;
    int enable_compression;
    compression_algorithm compression_algorithm;
    int enable_bloom_filter;
    double bloom_filter_fp_rate;
    int enable_background_compaction;
    int background_compaction_interval;
    int enable_block_indexes;
    tidesdb_sync_mode_t sync_mode;
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    int block_manager_cache_size;
} tidesdb_column_family_config_t;

/*
 * tidesdb_sstable_t
 * represents an sstable on disk
 * @param id unique identifier for this sstable
 * @param cf pointer to parent column family
 * @param block_manager block manager for this sstable
 * @param index succinct trie index (key -> block offset)
 * @param bloom_filter bloom filter for membership testing
 * @param min_key minimum key in this sstable
 * @param max_key maximum key in this sstable
 * @param min_key_size size of minimum key
 * @param max_key_size size of maximum key
 * @param num_entries number of entries in this sstable
 * @param data_end_offset byte offset where KV data ends
 * @param ref_count reference count
 */
struct tidesdb_sstable_t
{
    uint64_t id;
    tidesdb_column_family_t *cf;
    block_manager_t *block_manager;
    succinct_trie_t *index;
    bloom_filter_t *bloom_filter;
    uint8_t *min_key;
    uint8_t *max_key;
    size_t min_key_size;
    size_t max_key_size;
    _Atomic int num_entries;
    uint64_t data_end_offset;
    _Atomic(int) ref_count;
};

/*
 * tidesdb_memtable_t
 * represents a memtable instance with its own WAL
 * @param memtable in-memory skip list
 * @param wal write-ahead log block manager for this memtable
 * @param id unique identifier (timestamp-based)
 * @param created_at creation timestamp
 * @param ref_count reference count
 * @param flushed 1 if flushed to sstable, 0 otherwise
 */
typedef struct
{
    skip_list_t *memtable;
    block_manager_t *wal;
    uint64_t id;
    time_t created_at;
    _Atomic(int) ref_count;
    _Atomic(int) flushed;
} tidesdb_memtable_t;

/*
 * tidesdb_column_family_t
 * represents a column family (logical keyspace)
 * @param name name of the column family
 * @param db pointer to parent tidesdb instance
 * @param active_memtable current active memtable for writes
 * @param immutable_memtables queue of memtables being flushed
 * @param sstables array of sstable pointers
 * @param num_sstables current number of sstables
 * @param sstable_array_capacity allocated capacity of sstables array (internal, can grow)
 * @param next_sstable_id next sstable ID to assign
 * @param cf_lock reader-writer lock for this column family
 * @param flush_lock lock for flush operations
 * @param compaction_lock lock for compaction operations
 * @param memtable_write_lock lock for memtable writes
 * @param next_memtable_id next memtable ID to assign
 * @param next_wal_seq sequence number for lock-free WAL writes
 * @param is_dropping flag indicating if the column family is being dropped
 * @param active_operations count of background tasks currently executing
 * @param config configuration for this column family (config.sstable_capacity triggers compaction)
 */
struct tidesdb_column_family_t
{
    char name[TDB_MAX_CF_NAME_LENGTH];
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    tidesdb_t *db;
    _Atomic(tidesdb_memtable_t *) active_memtable;
    queue_t *immutable_memtables;
    tidesdb_sstable_t **sstables;
    _Atomic(int) num_sstables;
    int sstable_array_capacity;
    _Atomic(uint64_t) next_sstable_id;
    _Atomic(uint64_t) next_memtable_id;
    _Atomic(uint64_t) next_wal_seq;
    pthread_rwlock_t cf_lock;
    pthread_mutex_t flush_lock;
    pthread_mutex_t compaction_lock;
    _Atomic(int) is_dropping;
    _Atomic(int) active_operations;
    tidesdb_column_family_config_t config;
};

/* forward declaration for thread pool */
typedef struct tidesdb_thread_pool_t tidesdb_thread_pool_t;

/*
 * tidesdb_t
 * main tidesdb instance
 * @param config database configuration
 * @param column_families array of column family pointers
 * @param num_cfs number of column families
 * @param cf_capacity capacity of column families array
 * @param db_lock global database lock which is mainly used for column family addition, deletion,
 * and modification
 * @param block_manager_cache LRU cache for open block managers (file handles)
 * @param flush_pool thread pool for flush operations
 * @param compaction_pool thread pool for compaction operations
 * @param total_memory total system memory at startup
 * @param available_memory available memory at startup
 */
struct tidesdb_t
{
    tidesdb_config_t config;
    tidesdb_column_family_t **column_families;
    int num_cfs;
    int cf_capacity;
    pthread_rwlock_t db_lock;
    lru_cache_t *block_manager_cache;
    tidesdb_thread_pool_t *flush_pool;
    tidesdb_thread_pool_t *compaction_pool;
    size_t total_memory;
    size_t available_memory;
};

/*
 * tidesdb_operation_t
 * transaction operation type
 */
typedef enum
{
    TIDESDB_OP_PUT,
    TIDESDB_OP_DELETE
} tidesdb_operation_type_t;

/*
 * tidesdb_operation_t
 * represents a single operation in a transaction
 * @param type operation type (PUT or DELETE)
 * @param cf_name column family name
 * @param key key
 * @param key_size key size
 * @param value value (NULL for delete)
 * @param value_size value size
 * @param ttl time-to-live
 */
typedef struct
{
    tidesdb_operation_type_t type;
    char cf_name[TDB_MAX_CF_NAME_LENGTH];
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
} tidesdb_operation_t;

/*
 * tidesdb_txn_t
 * transaction handle
 * @param db pointer to tidesdb instance
 * @param operations array of operations
 * @param num_ops number of operations
 * @param op_capacity capacity of operations array
 * @param committed whether transaction has been committed
 * @param read_only whether this is a read-only transaction
 */
struct tidesdb_txn_t
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    tidesdb_operation_t *operations;
    int num_ops;
    int op_capacity;
    int committed;
    int read_only;
};

/*
 * tidesdb_iter_entry_t
 * represents a pending entry from one source (memtable/sstable)
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param deleted whether this entry is deleted
 * @param ttl time-to-live
 * @param source_type source type (0=active memtable, 1=immutable memtable, 2=sstable)
 * @param source_index index of immutable memtable or sstable
 */
typedef struct
{
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    uint8_t deleted;
    time_t ttl;
    int source_type;
    int source_index;
} tidesdb_iter_entry_t;
/*
 * tidesdb_iter_t
 * iterator for traversing key-value pairs (tied to transaction)
 * @param txn transaction this iterator belongs to
 * @param cf column family being iterated
 * @param memtable_cursor skip list cursor for active memtable
 * @param active_memtable reference to active memtable
 * @param immutable_memtable_cursors array of skip list cursors for immutable memtables
 * @param immutable_memtables array of immutable memtable references
 * @param num_immutable_cursors number of immutable memtable cursors
 * @param sstable_cursors array of block manager cursors for sstables
 * @param sstables array of sstable references
 * @param num_sstable_cursors number of sstable cursors
 * @param current_key current key
 * @param current_value current value
 * @param current_key_size current key size
 * @param current_value_size current value size
 * @param current_deleted whether current entry is deleted
 * @param current_source_type source type of current entry (0=memtable, 1=immutable, 2=sstable)
 * @param valid whether iterator is at a valid position
 * @param direction iteration direction (1 = forward, -1 = backward)
 * @param heap array of pending entries from each source (min-heap)
 * @param heap_size current number of entries in heap
 * @param heap_capacity allocated capacity of heap
 */
struct tidesdb_iter_t
{
    tidesdb_txn_t *txn;
    tidesdb_column_family_t *cf;
    skip_list_cursor_t *memtable_cursor;
    tidesdb_memtable_t *active_memtable;
    skip_list_cursor_t **immutable_memtable_cursors;
    tidesdb_memtable_t **immutable_memtables;
    int num_immutable_cursors;
    block_manager_cursor_t **sstable_cursors;
    tidesdb_sstable_t **sstables;
    int num_sstable_cursors;
    uint8_t *current_key;
    uint8_t *current_value;
    size_t current_key_size;
    size_t current_value_size;
    uint8_t current_deleted;
    int current_source_type;
    int valid;
    int direction;
    tidesdb_iter_entry_t *heap;
    int heap_size;
    int heap_capacity;
    /* cached comparator to avoid atomic ops on every comparison */
    int (*comparator)(const uint8_t *, size_t, const uint8_t *, size_t, void *);
    void *comparator_ctx;
};

/*
 * tidesdb_column_family_stat_t
 * statistics for a column family
 * @param name column family name
 * @param comparator_name comparator name
 * @param num_sstables number of SSTables
 * @param memtable_size size of memtable in bytes
 * @param memtable_entries number of entries in memtable
 * @param total_sstable_size total size of SSTables in bytes
 * @param config column family configuration
 */
typedef struct
{
    char name[TDB_MAX_CF_NAME_LENGTH];
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    int num_sstables;
    size_t memtable_size;
    int memtable_entries;
    size_t total_sstable_size;
    tidesdb_column_family_config_t config;
} tidesdb_column_family_stat_t;

/*
 * tidesdb_column_family_update_config_t
 * runtime-updatable configuration for column families
 * only includes settings that can be safely changed without affecting existing data
 * @param memtable_flush_size size threshold for memtable flush (bytes)
 * @param max_sstables_before_compaction max sstables before triggering compaction
 * @param compaction_threads number of threads to use for parallel compaction
 * @param max_level maximum skip list level (for new memtables)
 * @param probability skip list probability (for new memtables)
 * @param enable_bloom_filter whether to use bloom filters (for new SSTables)
 * @param bloom_filter_fp_rate bloom filter false positive rate (for new SSTables)
 * @param enable_background_compaction enable automatic background compaction
 * @param background_compaction_interval interval in microseconds between compaction checks
 * @param block_manager_cache_size if column family block managers will cache most recent blocks
 * @param sync_mode synchronization mode for new WAL and SSTable files
 */
typedef struct
{
    size_t memtable_flush_size;
    int max_sstables_before_compaction;
    int compaction_threads;
    int sl_max_level;
    float sl_probability;
    int enable_bloom_filter;
    double bloom_filter_fp_rate;
    int enable_background_compaction;
    int background_compaction_interval;
    int block_manager_cache_size;
    tidesdb_sync_mode_t sync_mode;
} tidesdb_column_family_update_config_t;

/*
 * tidesdb_open
 * opens or creates a tidesdb instance
 * @param config database configuration
 * @param db pointer to store tidesdb instance
 * @return 0 on success, -1 on failure
 */
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);

/*
 * tidesdb_close
 * closes a tidesdb instance and frees resources
 * @param db tidesdb instance
 * @return 0 on success, -1 on failure
 */
int tidesdb_close(tidesdb_t *db);

/*
 * tidesdb_default_column_family_config
 * returns default column family configuration
 * @return default configuration
 */
tidesdb_column_family_config_t tidesdb_default_column_family_config(void);

/*
 * tidesdb_create_column_family
 * creates a new column family with specified configuration
 * @param db tidesdb instance
 * @param name column family name
 * @param config column family configuration (NULL for defaults)
 * @return 0 on success, -1 on failure
 */
int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config);

/*
 * tidesdb_drop_column_family
 * drops a column family
 * @param db tidesdb instance
 * @param name column family name
 * @return 0 on success, -1 on failure
 */
int tidesdb_drop_column_family(tidesdb_t *db, const char *name);

/*
 * tidesdb_get_column_family
 * retrieves a column family by name
 * @param db tidesdb instance
 * @param name column family name
 * @return column family pointer or NULL if not found
 */
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);

/*
 * tidesdb_list_column_families
 * gets list of all column family names
 * @param db tidesdb instance
 * @param names pointer to store array of names (caller must free each name and array)
 * @param count pointer to store count of column families
 * @return 0 on success, -1 on failure
 */
int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count);

/*
 * tidesdb_get_column_family_stats
 * gets statistics for a column family
 * @param db tidesdb instance
 * @param name column family name
 * @param stats pointer to store statistics (caller must free)
 * @return 0 on success, -1 on failure
 */
int tidesdb_get_column_family_stats(tidesdb_t *db, const char *name,
                                    tidesdb_column_family_stat_t **stats);

/*
 * tidesdb_update_column_family_config
 * updates runtime-safe configuration for a column family
 * only affects new operations, does not modify existing data
 * @param db tidesdb instance
 * @param name column family name
 * @param update_config new configuration values
 * @return 0 on success, -1 on failure
 */
int tidesdb_update_column_family_config(tidesdb_t *db, const char *name,
                                        const tidesdb_column_family_update_config_t *update_config);

/*
 * tidesdb_flush_memtable
 * manually flushes memtable to sstable
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
int tidesdb_flush_memtable(tidesdb_column_family_t *cf);

/*
 * tidesdb_compact
 * manually trigger compaction for a column family
 * routes to parallel compaction if compaction_threads > 0
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
int tidesdb_compact(tidesdb_column_family_t *cf);

/*
 * tidesdb_compact_parallel
 * manual parallel compaction using multiple threads with semaphore-based work queue
 * each thread compacts a pair of SSTables concurrently
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
int tidesdb_compact_parallel(tidesdb_column_family_t *cf);

/*
 * tidesdb_txn_begin
 * begins a new read-write transaction
 * @param db tidesdb instance
 * @param cf column family pointer
 * @param txn pointer to store transaction handle
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn);

/*
 * tidesdb_txn_begin_read
 * begins a new read-only transaction
 * @param db tidesdb instance
 * @param cf column family pointer
 * @param txn pointer to store transaction handle
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_begin_read(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn);

/*
 * tidesdb_txn_get
 * gets a value within a transaction
 * @param txn transaction handle
 * @param key key
 * @param key_size key size
 * @param value pointer to store value (allocated by function)
 * @param value_size pointer to store value size
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_get(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, uint8_t **value,
                    size_t *value_size);

/*
 * tidesdb_txn_put
 * adds a put operation to transaction
 * @param txn transaction handle
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param ttl time-to-live (Unix timestamp in seconds, -1 for no expiration)
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_put(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, const uint8_t *value,
                    size_t value_size, time_t ttl);

/*
 * tidesdb_txn_delete
 * adds a delete operation to transaction
 * @param txn transaction handle
 * @param key key
 * @param key_size key size
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_delete(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size);

/*
 * tidesdb_txn_commit
 * commits a transaction atomically
 * @param txn transaction handle
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_commit(tidesdb_txn_t *txn);

/*
 * tidesdb_txn_rollback
 * rolls back a transaction
 * @param txn transaction handle
 * @return 0 on success, -1 on failure
 */
int tidesdb_txn_rollback(tidesdb_txn_t *txn);

/*
 * tidesdb_txn_free
 * frees transaction resources
 * @param txn transaction handle
 */
void tidesdb_txn_free(tidesdb_txn_t *txn);

/*
 * tidesdb_iter_new
 * creates a new iterator for a column family within a transaction
 * @param txn transaction handle
 * @param iter pointer to store iterator
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_iter_t **iter);

/*
 * tidesdb_iter_seek_to_first
 * positions iterator at first key
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);

/*
 * tidesdb_iter_seek_to_last
 * positions iterator at last key
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter);

/*
 * tidesdb_iter_seek
 * positions iterator at first key >= target key
 * @param iter iterator
 * @param key target key to seek to
 * @param key_size size of target key
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/*
 * tidesdb_iter_seek_for_prev
 * positions iterator at last key <= target key
 * @param iter iterator
 * @param key target key to seek to
 * @param key_size size of target key
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/*
 * tidesdb_iter_next
 * moves iterator to next key
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_next(tidesdb_iter_t *iter);

/*
 * tidesdb_iter_prev
 * moves iterator to previous key
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_prev(tidesdb_iter_t *iter);

/*
 * tidesdb_iter_valid
 * checks if iterator is at a valid position
 * @param iter iterator
 * @return 1 if valid, 0 if not
 */
int tidesdb_iter_valid(tidesdb_iter_t *iter);

/*
 * tidesdb_iter_key
 * gets current key from iterator
 * @param iter iterator
 * @param key pointer to store key
 * @param key_size pointer to store key size
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size);

/*
 * tidesdb_iter_value
 * gets current value from iterator
 * @param iter iterator
 * @param value pointer to store value
 * @param value_size pointer to store value size
 * @return 0 on success, -1 on failure
 */
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);

/*
 * tidesdb_iter_free
 * frees an iterator
 * @param iter iterator to free
 */
void tidesdb_iter_free(tidesdb_iter_t *iter);

/*
 * skip_list_comparator_memcmp
 * memcmp comparator for skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx comparator context (not used)
 * @return negative if key1 < key2, zero if equal, positive if key1 > key2
 */
extern int skip_list_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                       size_t key2_size, void *ctx);

/*
 * skip_list_comparator_string
 * string comparator for skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx comparator context (not used)
 * @return negative if key1 < key2, zero if equal, positive if key1 > key2
 */
extern int skip_list_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                       size_t key2_size, void *ctx);

/*
 * skip_list_comparator_numeric
 * numeric comparator for skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx comparator context (not used)
 * @return negative if key1 < key2, zero if equal, positive if key1 > key2
 */
extern int skip_list_comparator_numeric(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                        size_t key2_size, void *ctx);

/*
 * tidesdb_register_comparator
 * register a custom comparator function with a name
 * must be called before creating column families that use this comparator
 * @param name unique name for the comparator
 * @param compare_fn the comparison function
 * @return 0 on success, -1 on failure
 */
int tidesdb_register_comparator(const char *name, skip_list_comparator_fn compare_fn);

/*
 * tidesdb_get_comparator
 * get a registered comparator by name
 * @param name name of the comparator
 * @return comparator function or NULL if not found
 */
skip_list_comparator_fn tidesdb_get_comparator(const char *name);

#endif /* __TIDESDB_H__ */