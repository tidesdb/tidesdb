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
#ifndef __TIDESDB_H__
#define __TIDESDB_H__

#include "block_manager.h"
#include "bloom_filter.h"
#include "buffer.h"
#include "clock_cache.h"
#include "compat.h"
#include "compress.h"
#include "ini.h"
#include "manifest.h"
#include "queue.h"
#include "skip_list.h"

/* logging levels for TDB_DEBUG_LOG */
typedef enum
{
    TDB_LOG_DEBUG = 0, /* general debugging info (most verbose) */
    TDB_LOG_INFO = 1,  /* informational messages */
    TDB_LOG_WARN = 2,  /* warnings (e.g., "Retry attempt N"..) */
    TDB_LOG_ERROR = 3, /* errors (e.g., "Failed to open file", "Invalid checksum") */
    TDB_LOG_FATAL = 4, /* fatal errors (e.g., "Corruption detected", "Out of memory") */
    TDB_LOG_NONE = 99  /* disable all logging */
} tidesdb_log_level_t;

extern int _tidesdb_log_level; /* minimum level to log (default is TDB_LOG_DEBUG) */

#if defined(_MSC_VER)
#define TDB_DEBUG_LOG(level, fmt, ...)                                                    \
    do                                                                                    \
    {                                                                                     \
        if ((level) >= _tidesdb_log_level && _tidesdb_log_level != TDB_LOG_NONE)          \
        {                                                                                 \
            struct timespec _ts;                                                          \
            timespec_get(&_ts, TIME_UTC);                                                 \
            time_t _sec = _ts.tv_sec;                                                     \
            struct tm _tm;                                                                \
            tdb_localtime(&_sec, &_tm);                                                   \
            const char *_level_str = (level) == TDB_LOG_DEBUG   ? "DEBUG"                 \
                                     : (level) == TDB_LOG_INFO  ? "INFO"                  \
                                     : (level) == TDB_LOG_WARN  ? "WARN"                  \
                                     : (level) == TDB_LOG_ERROR ? "ERROR"                 \
                                                                : "FATAL";                \
            fprintf(stderr, "[%02d:%02d:%02d.%03ld] [%s] %s:%d: " fmt "\n", _tm.tm_hour,  \
                    _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000L, _level_str, __FILE__, \
                    __LINE__, ##__VA_ARGS__);                                             \
        }                                                                                 \
    } while (0)
#else
#define TDB_DEBUG_LOG(level, fmt, ...)                                                    \
    do                                                                                    \
    {                                                                                     \
        if ((level) >= _tidesdb_log_level && _tidesdb_log_level != TDB_LOG_NONE)          \
        {                                                                                 \
            struct timespec _ts;                                                          \
            clock_gettime(CLOCK_REALTIME, &_ts);                                          \
            time_t _sec = _ts.tv_sec;                                                     \
            struct tm _tm;                                                                \
            tdb_localtime(&_sec, &_tm);                                                   \
            const char *_level_str = (level) == TDB_LOG_DEBUG   ? "DEBUG"                 \
                                     : (level) == TDB_LOG_INFO  ? "INFO"                  \
                                     : (level) == TDB_LOG_WARN  ? "WARN"                  \
                                     : (level) == TDB_LOG_ERROR ? "ERROR"                 \
                                                                : "FATAL";                \
            fprintf(stderr, "[%02d:%02d:%02d.%03ld] [%s] %s:%d: " fmt "\n", _tm.tm_hour,  \
                    _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000L, _level_str, __FILE__, \
                    __LINE__, ##__VA_ARGS__);                                             \
        }                                                                                 \
    } while (0)
#endif

/**
 * tidesdb_isolation_level_t
 * isolation levels for transactions
 *
 * tdb_isolation_read_uncommitted (0)
 *   -- sees all versions including uncommitted changes (dirty reads)
 *   -- no snapshot isolation, uses uint64_max to bypass filtering
 *   -- fastest but allows dirty reads, non-repeatable reads, and phantom reads
 *   -- no conflict detection
 *   -- good for analytics on non-critical data where performance is paramount
 *
 * tdb_isolation_read_committed (1)
 *   -- refreshes snapshot on each read operation
 *   -- prevents dirty reads by only seeing committed data
 *   -- allows non-repeatable reads (same key may return different values)
 *   -- allows phantom reads (range queries may see different rows)
 *   -- no conflict detection
 *   -- good default for most applications, good balance of consistency and performance
 *
 * tdb_isolation_repeatable_read (2)
 *   -- consistent snapshot taken at transaction start
 *   -- prevents dirty reads and non-repeatable reads for point reads
 *   -- allows phantom reads (new rows can appear in range queries)
 *   -- uses read-write conflict detection only
 *   -- aborts if a read key was modified by another transaction
 *   -- good for applications requiring consistent reads but tolerating some write conflicts
 *
 * tdb_isolation_snapshot (3)
 *   -- consistent snapshot with first-committer-wins semantics
 *   -- prevents dirty reads and non-repeatable reads
 *   -- prevents lost updates via write-write conflict detection
 *   -- still allows some phantom reads
 *   -- uses read-write and write-write conflict detection
 *   -- aborts on any read or write conflict
 *   -- good for financial transactions, inventory management
 *
 * tdb_isolation_serializable (4)
 *   -- full serializability using ssi (serializable snapshot isolation)
 *   -- prevents dirty reads, non-repeatable reads, and phantom reads
 *   -- uses read-write, write-write, and rw-antidependency conflict detection
 *   -- tracks active transactions for dangerous structure detection
 *   -- highest isolation but lowest concurrency
 *   -- great for critical transactions requiring full acid guarantees
 */
typedef enum
{
    TDB_ISOLATION_READ_UNCOMMITTED = 0,
    TDB_ISOLATION_READ_COMMITTED = 1,
    TDB_ISOLATION_REPEATABLE_READ = 2,
    TDB_ISOLATION_SNAPSHOT = 3,
    TDB_ISOLATION_SERIALIZABLE = 4
} tidesdb_isolation_level_t;

/* error codes */
#define TDB_SUCCESS          0
#define TDB_ERR_MEMORY       -1
#define TDB_ERR_INVALID_ARGS -2
#define TDB_ERR_NOT_FOUND    -3
#define TDB_ERR_IO           -4
#define TDB_ERR_CORRUPTION   -5
#define TDB_ERR_EXISTS       -6
#define TDB_ERR_CONFLICT     -7
#define TDB_ERR_OVERFLOW     -8
#define TDB_ERR_TOO_LARGE    -9
#define TDB_ERR_MEMORY_LIMIT -10
#define TDB_ERR_INVALID_DB   -11
#define TDB_ERR_UNKNOWN      -12

#define TDB_VERSION_MAJOR 6
#define TDB_VERSION_MINOR 0
#define TDB_VERSION_PATCH 0

/* read profiling (enable with TDB_ENABLE_READ_PROFILING) */
#ifdef TDB_ENABLE_READ_PROFILING
typedef struct
{
    _Atomic(uint64_t) total_reads;
    _Atomic(uint64_t) memtable_hits;
    _Atomic(uint64_t) immutable_hits;
    _Atomic(uint64_t) sstable_hits;
    _Atomic(uint64_t) levels_searched;
    _Atomic(uint64_t) sstables_checked;
    _Atomic(uint64_t) bloom_checks;
    _Atomic(uint64_t) bloom_hits;
    _Atomic(uint64_t) blocks_read;
    _Atomic(uint64_t) cache_block_hits;
    _Atomic(uint64_t) cache_block_misses;
    _Atomic(uint64_t) disk_reads;
} tidesdb_read_stats_t;
#endif

/**
 * tidesdb_sync_mode_t
 * synchronization modes for write ahead logging mainly.  sstable writes are sync'ed on completion.
 */
typedef enum
{
    TDB_SYNC_NONE,
    TDB_SYNC_FULL,
    TDB_SYNC_INTERVAL,
} tidesdb_sync_mode_t;

/* default configuration values */
#define TDB_DEFAULT_WRITE_BUFFER_SIZE           (64 * 1024 * 1024)
#define TDB_DEFAULT_LEVEL_SIZE_RATIO            10
#define TDB_DEFAULT_MIN_LEVELS                  5
#define TDB_DEFAULT_DIVIDING_LEVEL_OFFSET       2
#define TDB_DEFAULT_COMPACTION_THREAD_POOL_SIZE 2
#define TDB_DEFAULT_FLUSH_THREAD_POOL_SIZE      2
#define TDB_DEFAULT_BLOOM_FPR                   0.01
#define TDB_DEFAULT_KLOG_VALUE_THRESHOLD        1024 * 4
#define TDB_DEFAULT_INDEX_SAMPLE_RATIO          1
#define TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN      16
#define TDB_DEFAULT_MIN_DISK_SPACE              (100 * 1024 * 1024)
#define TDB_DEFAULT_MAX_OPEN_SSTABLES           512
#define TDB_DEFAULT_ACTIVE_TXN_BUFFER_SIZE      (1024 * 64)
#define TDB_DEFAULT_BLOCK_CACHE_SIZE            (64 * 1024 * 1024)
#define TDB_DEFAULT_SYNC_INTERVAL_US            128000

/* configuration limits */
#define TDB_MAX_COMPARATOR_NAME 64
#define TDB_MAX_COMPARATOR_CTX  256

/* file system permissions */
#define TDB_DIR_PERMISSIONS 0755

/**
 * tidesdb_comparator_fn
 * comparator function type for custom key ordering
 */
typedef int (*tidesdb_comparator_fn)(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx);

/* forward declarations for internal types */
#define TDB_MAX_LEVELS 32
typedef struct tidesdb_txn_op_t tidesdb_txn_op_t;
typedef struct tidesdb_merge_heap_t tidesdb_merge_heap_t;
typedef struct tidesdb_kv_pair_t tidesdb_kv_pair_t;
typedef struct tidesdb_commit_status_t tidesdb_commit_status_t;
typedef struct tidesdb_level_t tidesdb_level_t;
typedef struct tidesdb_sstable_t tidesdb_sstable_t;
typedef struct tidesdb_block_index_t tidesdb_block_index_t;

/* forward declarations for main types to allow self-referential pointers */
typedef struct tidesdb_t tidesdb_t;
typedef struct tidesdb_column_family_t tidesdb_column_family_t;
typedef struct tidesdb_txn_t tidesdb_txn_t;
typedef struct tidesdb_iter_t tidesdb_iter_t;
typedef struct tidesdb_stats_t tidesdb_stats_t;

/**
 * tidesdb_column_family_config_t
 * configuration for a column family
 * @param write_buffer_size size of write buffer
 * @param level_size_ratio ratio of level sizes
 * @param min_levels minimum number of levels
 * @param dividing_level_offset offset for dividing level
 * @param klog_value_threshold threshold for klog value
 * @param compression_algorithm compression algorithm
 * @param enable_bloom_filter enable bloom filter
 * @param bloom_fpr bloom filter false positive rate
 * @param enable_block_indexes enable block indexes
 * @param index_sample_ratio index sample ratio
 * @param block_index_prefix_len block index prefix length
 * @param sync_mode sync mode
 * @param sync_interval_us sync interval in microseconds
 * @param comparator_name name of comparator
 * @param comparator_ctx_str comparator context string
 * @param comparator_fn_cached cached comparator function
 * @param comparator_ctx_cached cached comparator context
 * @param skip_list_max_level skip list max level
 * @param skip_list_probability skip list probability
 * @param default_isolation_level default isolation level
 * @param min_disk_space minimum free disk space required (bytes)
 */
typedef struct tidesdb_column_family_config_t
{
    size_t write_buffer_size;
    size_t level_size_ratio;
    int min_levels;
    int dividing_level_offset;
    size_t klog_value_threshold;
    compression_algorithm compression_algorithm;
    int enable_bloom_filter;
    double bloom_fpr;
    int enable_block_indexes;
    int index_sample_ratio;
    int block_index_prefix_len;
    int sync_mode;
    uint64_t sync_interval_us;
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    char comparator_ctx_str[TDB_MAX_COMPARATOR_CTX];
    skip_list_comparator_fn comparator_fn_cached;
    void *comparator_ctx_cached;
    int skip_list_max_level;
    float skip_list_probability;
    tidesdb_isolation_level_t default_isolation_level;
    uint64_t min_disk_space;
} tidesdb_column_family_config_t;

/**
 * tidesdb_comparator_entry_t
 * comparator registry entry
 * @param name unique name for the comparator
 * @param fn comparator function pointer
 * @param ctx_str optional context string (for serialization)
 * @param ctx runtime context pointer (reconstructed from ctx_str or set at registration)
 */
typedef struct tidesdb_comparator_entry_t
{
    char name[TDB_MAX_COMPARATOR_NAME];
    tidesdb_comparator_fn fn;
    char ctx_str[TDB_MAX_COMPARATOR_CTX];
    void *ctx;
} tidesdb_comparator_entry_t;

/**
 * tidesdb_config_t
 * configuration for the database
 * @param db_path path to the database
 * @param num_flush_threads number of flush threads
 * @param num_compaction_threads number of compaction threads
 * @param log_level minimum log level to display (TDB_LOG_DEBUG, TDB_LOG_INFO, TDB_LOG_WARN,
 * TDB_LOG_ERROR, TDB_LOG_FATAL, TDB_LOG_NONE)
 * @param block_cache_size size of clock cache for hot sstable blocks
 * @param max_open_sstables maximum number of open sstables
 * @param wait_for_txns_on_close if true, wait up to defined time for active transactions on close
 *                                if false (default), close immediately and fail active transactions
 */
typedef struct tidesdb_config_t
{
    char *db_path;
    int num_flush_threads;
    int num_compaction_threads;
    tidesdb_log_level_t log_level;
    size_t block_cache_size;
    size_t max_open_sstables;
    int wait_for_txns_on_close;
} tidesdb_config_t;

/**
 * tidesdb_column_family_t
 * a column family is independent key-value storage
 * @param name name of column family
 * @param directory directory for column family
 * @param config column family configuration
 * @param active_memtable active memtable
 * @param memtable_id id of active memtable
 * @param memtable_generation generation counter for memtable rotation
 * @param active_wal active write-ahead log
 * @param immutable_memtables queue of immutable memtables being flushed
 * @param pending_commits count of in-flight commits
 * @param active_txn_buffer buffer of active transactions for ssi conflict detection
 * @param levels fixed array of disk levels
 * @param num_active_levels number of currently active disk levels
 * @param next_sstable_id next sstable id
 * @param is_compacting atomic flag indicating compaction is queued
 * @param is_flushing atomic flag indicating flush is queued
 * @param immutable_cleanup_counter counter for batched immutable cleanup
 * @param wal_group_buffer shared buffer for batching wal writes (lock-free group commit)
 * @param wal_group_buffer_size current size of data in buffer (atomic)
 * @param wal_group_buffer_capacity total capacity of buffer
 * @param wal_group_leader atomic flag indicating a thread is leading group commit (CAS)
 * @param wal_group_generation generation counter to detect buffer flushes (prevents race
 * conditions)
 * @param manifest manifest for column family
 * @param db parent database reference
 */
struct tidesdb_column_family_t
{
    char *name;
    char *directory;
    tidesdb_column_family_config_t config;
    _Atomic(skip_list_t *) active_memtable;
    _Atomic(uint64_t) memtable_id;
    _Atomic(uint64_t) memtable_generation;
    _Atomic(block_manager_t *) active_wal;
    queue_t *immutable_memtables;
    _Atomic(uint64_t) pending_commits;
    buffer_t *active_txn_buffer;
    tidesdb_level_t *levels[TDB_MAX_LEVELS];
    _Atomic(int) num_active_levels;
    _Atomic(uint64_t) next_sstable_id;
    _Atomic(int) is_compacting;
    _Atomic(int) is_flushing;
    _Atomic(int) immutable_cleanup_counter;
    uint8_t *wal_group_buffer;
    _Atomic(size_t) wal_group_buffer_size;
    size_t wal_group_buffer_capacity;
    _Atomic(int) wal_group_leader;
    _Atomic(uint64_t) wal_group_generation;
    tidesdb_manifest_t *manifest;
    tidesdb_t *db;
};

/**
 * tidesdb_sstable_t
 * an immutable sorted string table on disk
 * consists of two files: .klog (keys + metadata) and .vlog (large values)
 * @param id unique identifier
 * @param klog_path path to .klog file
 * @param vlog_path path to .vlog file
 * @param min_key minimum key in this sstable
 * @param min_key_size size of minimum key
 * @param max_key maximum key in this sstable
 * @param max_key_size size of maximum key
 * @param num_entries total number of keys
 * @param num_klog_blocks number of blocks in klog
 * @param num_vlog_blocks number of blocks in vlog
 * @param klog_data_end_offset offset where data ends in klog (before footer)
 * @param klog_size total size of klog file
 * @param vlog_size total size of vlog file
 * @param max_seq maximum sequence number in this sstable
 * @param bloom_filter bloom filter for key existence checks
 * @param block_indexes block indexes for fast key lookup
 * @param refcount reference count for safe concurrent access
 * @param klog_bm klog block manager
 * @param vlog_bm vlog block manager
 * @param config column family configuration
 * @param marked_for_deletion flag indicating sstable is marked for deletion
 * @param last_access_time last access time for lru eviction
 * @param db database handle (for resolving comparators from registry)
 */
struct tidesdb_sstable_t
{
    uint64_t id;
    char *klog_path;
    char *vlog_path;
    uint8_t *min_key;
    size_t min_key_size;
    uint8_t *max_key;
    size_t max_key_size;
    uint64_t num_entries;
    uint64_t num_klog_blocks;
    uint64_t num_vlog_blocks;
    uint64_t klog_data_end_offset;
    uint64_t klog_size;
    uint64_t vlog_size;
    uint64_t max_seq;
    bloom_filter_t *bloom_filter;
    tidesdb_block_index_t *block_indexes;
    _Atomic(int) refcount;
    block_manager_t *klog_bm;
    block_manager_t *vlog_bm;
    tidesdb_column_family_config_t *config;
    _Atomic(int) marked_for_deletion;
    _Atomic(time_t) last_access_time;
    tidesdb_t *db;
};

/**
 * tidesdb_level_t
 * a level in the lsm tree
 * @param level_num level number
 * @param capacity capacity of level in bytes
 * @param current_size current size of level in bytes
 * @param sstables array of sstable pointers (copy-on-write)
 * @param num_sstables number of sstables in array
 * @param sstables_capacity capacity of sstables array
 * @param file_boundaries file boundaries for partitioning
 * @param boundary_sizes sizes of boundary keys
 * @param num_boundaries number of boundaries
 */
struct tidesdb_level_t
{
    int level_num;
    _Atomic(size_t) capacity;
    _Atomic(size_t) current_size;
    _Atomic(tidesdb_sstable_t **) sstables;
    _Atomic(int) num_sstables;
    _Atomic(int) sstables_capacity;
    _Atomic(uint8_t **) file_boundaries;
    _Atomic(size_t *) boundary_sizes;
    _Atomic(int) num_boundaries;
};

/**
 * tidesdb_t
 * main database handle
 * @param db_path path to database directory
 * @param config database configuration
 * @param column_families array of column families
 * @param num_column_families number of column families
 * @param cf_capacity capacity of column families array
 * @param is_open atomic flag indicating database is fully open and ready for operations
 * @param is_recovering flag to determine if system is recovering
 * @param comparators atomic pointer to comparators array (lock-free COW)
 * @param num_comparators atomic count of registered comparators
 * @param comparators_capacity atomic capacity of comparators array
 * @param flush_threads array of flush threads
 * @param flush_queue queue of flush work items
 * @param compaction_threads array of compaction threads
 * @param compaction_queue queue of compaction work items
 * @param sync_thread background thread for interval syncing
 * @param sync_thread_active atomic flag indicating if sync thread is active
 * @param sync_thread_mutex mutex for sync thread
 * @param sync_thread_cond condition variable for sync thread
 * @param reaper_thread background thread for evicting most un-accessed sstables
 * @param reaper_thread_active atomic flag indicating if reaper thread is active
 * @param reaper_thread_mutex mutex for reaper thread
 * @param reaper_thread_cond condition variable for reaper thread
 * @param clock_cache clock cache for hot sstable blocks
 * @param num_open_sstables global counter for open sstables
 * @param next_txn_id global transaction id counter
 * @param global_seq global sequence counter for snapshots and commits
 * @param commit_status tracks which sequences are committed
 * @param oldest_active_seq oldest active transaction sequence for gc
 * @param active_txns_lock rwlock for active transactions list
 * @param active_txns array of active serializable transactions
 * @param num_active_txns number of active transactions
 * @param active_txns_capacity capacity of active transactions array
 * @param cached_available_disk_space cached available disk space in bytes
 * @param last_disk_space_check timestamp of last disk space check
 * @param cached_current_time cached current time updated by reaper thread to avoid syscalls
 * @param available_memory available system memory in bytes
 * @param total_memory total system memory in bytes
 * @param cf_list_lock rwlock for cf list modifications
 */
struct tidesdb_t
{
    char *db_path;
    tidesdb_config_t config;
    tidesdb_column_family_t **column_families;
    int num_column_families;
    int cf_capacity;
    _Atomic(int) is_open;
    _Atomic(int) is_recovering;
    _Atomic(tidesdb_comparator_entry_t *) comparators;
    _Atomic(int) num_comparators;
    _Atomic(int) comparators_capacity;
    pthread_t *flush_threads;
    queue_t *flush_queue;
    pthread_t *compaction_threads;
    queue_t *compaction_queue;
    pthread_t sync_thread;
    _Atomic(int) sync_thread_active;
    pthread_mutex_t sync_thread_mutex;
    pthread_cond_t sync_thread_cond;
    pthread_t sstable_reaper_thread;
    _Atomic(int) sstable_reaper_active;
    pthread_mutex_t reaper_thread_mutex;
    pthread_cond_t reaper_thread_cond;
    clock_cache_t *clock_cache;
    _Atomic(int) num_open_sstables;
    _Atomic(uint64_t) next_txn_id;
    _Atomic(uint64_t) global_seq;
    tidesdb_commit_status_t *commit_status;
    _Atomic(uint64_t) oldest_active_seq;
    pthread_rwlock_t active_txns_lock;
    tidesdb_txn_t **active_txns;
    int num_active_txns;
    int active_txns_capacity;
    _Atomic(uint64_t) cached_available_disk_space;
    _Atomic(time_t) last_disk_space_check;
    _Atomic(time_t) cached_current_time;
    uint64_t available_memory;
    uint64_t total_memory;
    pthread_rwlock_t cf_list_lock;
#ifdef TDB_ENABLE_READ_PROFILING
    tidesdb_read_stats_t read_stats;
#endif
};

/**
 * tidesdb_txn_t
 * transaction handle for batched operations with acid guarantees
 *
 * supports multiple isolation levels:
 * -- read_uncommitted -- sees all versions including uncommitted (dirty reads allowed)
 * -- read_committed -- refreshes snapshot on each read (prevents dirty reads)
 * -- repeatable_read -- consistent snapshot, read-write conflict detection
 * -- snapshot -- consistent snapshot, read-write + write-write conflict detection
 * -- serializable -- full ssi with dangerous structure detection (prevents all anomalies)
 *
 * snapshot isolation semantics:
 * -- snapshot captured at begin (all committed txns with seq <= snapshot_seq are visible)
 * -- conflict detection at commit (isolation level dependent)
 * -- commit sequence acquired after conflict detection
 * -- no retries -- conflicts cause immediate abort
 * -- works across multiple column families
 *
 * @param db database handle
 * @param txn_id transaction id
 * @param snapshot_seq snapshot sequence captured at begin
 * @param commit_seq commit sequence (0 until commit)
 * @param ops array of operations
 * @param num_ops number of operations
 * @param ops_capacity capacity of operations array
 * @param read_keys array of read keys for conflict detection
 * @param read_key_sizes array of read key sizes
 * @param read_seqs array of read sequence numbers
 * @param read_cfs array of column families for each read key
 * @param read_set_count number of read keys
 * @param read_set_capacity capacity of read keys array
 * @param write_set_hash hash table for O(1) write set lookup (NULL if num_ops < 256)
 * @param read_set_hash hash table for O(1) read set lookup (NULL if read_set_count < 256)
 * @param cfs array of column families involved in transaction
 * @param num_cfs number of column families
 * @param cf_capacity capacity of column families array
 * @param savepoints array of savepoint transaction states
 * @param savepoint_names array of savepoint names
 * @param num_savepoints number of savepoints
 * @param savepoints_capacity capacity of savepoints array
 * @param is_committed flag indicating if transaction is committed
 * @param is_aborted flag indicating if transaction is aborted
 * @param isolation_level isolation level for this transaction
 * @param has_rw_conflict_in flag indicating rw-conflict-in (another txn read our writes)
 * @param has_rw_conflict_out flag indicating rw-conflict-out (we read another txn's writes)
 */
struct tidesdb_txn_t
{
    tidesdb_t *db;
    uint64_t txn_id;
    uint64_t snapshot_seq;
    uint64_t commit_seq;
    tidesdb_txn_op_t *ops;
    int num_ops;
    int ops_capacity;
    uint8_t **read_keys;
    size_t *read_key_sizes;
    uint64_t *read_seqs;
    tidesdb_column_family_t **read_cfs;
    int read_set_count;
    int read_set_capacity;
    void *write_set_hash;
    void *read_set_hash;
    tidesdb_column_family_t **cfs;
    int num_cfs;
    int cf_capacity;
    tidesdb_txn_t **savepoints;
    char **savepoint_names;
    int num_savepoints;
    int savepoints_capacity;
    int is_committed;
    int is_aborted;
    tidesdb_isolation_level_t isolation_level;
    int has_rw_conflict_in;
    int has_rw_conflict_out;
};

/**
 * tidesdb_iter_t
 * iterator for database
 * @param cf column family (for single-cf iteration)
 * @param txn transaction (for isolation and multi-cf iteration)
 * @param heap merge heap
 * @param current current key-value pair
 * @param valid validity flag
 * @param direction direction of iteration (1=forward, -n=backward)
 * @param snapshot_time snapshot time for ttl checks
 * @param cf_snapshot snapshot sequence for visibility checks
 */
struct tidesdb_iter_t
{
    tidesdb_column_family_t *cf;
    tidesdb_txn_t *txn;
    tidesdb_merge_heap_t *heap;
    tidesdb_kv_pair_t *current;
    int valid;
    int direction;
    time_t snapshot_time;
    uint64_t cf_snapshot;
};

/**
 * tidesdb_stats_t
 * statistics for database
 * @param num_levels number of levels
 * @param memtable_size size of memtable
 * @param level_sizes sizes of each level
 * @param level_num_sstables number of sstables in each level
 * @param config column family configuration
 */
struct tidesdb_stats_t
{
    int num_levels;
    size_t memtable_size;
    size_t *level_sizes;
    int *level_num_sstables;
    tidesdb_column_family_config_t *config;
};

/**
 * tidesdb_default_column_family_config
 * returns default configuration for column family
 * @return default configuration for column family
 */
tidesdb_column_family_config_t tidesdb_default_column_family_config(void);

/**
 * tidesdb_default_config
 * returns default configuration for database
 * @return default configuration for database
 */
tidesdb_config_t tidesdb_default_config(void);

/**
 * tidesdb_open
 * opens an existing database or creates a new one
 * @param config database configuration
 * @param db output parameter for database handle
 * @return 0 on success, -n on failure
 */
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);

/**
 * tidesdb_register_comparator
 * registers a custom comparator function
 * @param db database handle
 * @param name unique name for the comparator (max 63 chars)
 * @param fn comparator function pointer
 * @param ctx_str optional context string for serialization (can be NULL)
 * @param ctx optional runtime context pointer (can be NULL)
 * @return 0 on success, -n on failure (duplicate name, invalid args, etc.)
 */
int tidesdb_register_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn fn,
                                const char *ctx_str, void *ctx);

/**
 * tidesdb_get_comparator
 * retrieves a registered comparator by name
 * @param db database handle
 * @param name comparator name
 * @param fn output parameter for comparator function (can be NULL)
 * @param ctx output parameter for runtime context pointer (can be NULL)
 * @return 0 on success, -n if not found
 */
int tidesdb_get_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn *fn,
                           void **ctx);

/**
 * tidesdb_close
 * closes a database
 *
 * behavior depends on config.wait_for_txns_on_close:
 * -- false (default) -- proceeds immediately with close. active transactions will fail
 *   on next operation with TDB_ERR_INVALID_DB. this is the recommended behavior
 *   used by RocksDB, LevelDB, etc. Close completes in < N-ms.
 * -- true -- waits up to n seconds for active transactions to complete. If timeout
 *   expires, aborts close and returns TDB_ERR_UNKNOWN. This is legacy behavior
 *   that can cause unpredictable latency and potential deadlocks.
 *
 * applications should finish all transactions before calling close.
 *
 * @param db database handle
 * @return 0 on success, -n on failure
 */
int tidesdb_close(tidesdb_t *db);

#ifdef TDB_ENABLE_READ_PROFILING
/**
 * tidesdb_get_read_stats
 * gets read profiling statistics
 * @param db the database
 * @param stats output statistics structure
 * @return TDB_SUCCESS on success, error code on failure
 */
int tidesdb_get_read_stats(tidesdb_t *db, tidesdb_read_stats_t *stats);

/**
 * tidesdb_print_read_stats
 * prints read profiling statistics to stdout
 * @param db the database
 */
void tidesdb_print_read_stats(tidesdb_t *db);

/**
 * tidesdb_reset_read_stats
 * resets read profiling statistics
 * @param db the database
 */
void tidesdb_reset_read_stats(tidesdb_t *db);
#endif

/**
 * tidesdb_create_column_family
 * creates a column family
 * @param db database handle
 * @param name name of column family
 * @param config configuration for column family
 * @return 0 on success, -n on failure
 */
int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config);

/**
 * tidesdb_drop_column_family
 * drops a column family
 * @param db database handle
 * @param name name of column family
 * @return 0 on success, -n on failure
 */
int tidesdb_drop_column_family(tidesdb_t *db, const char *name);

/**
 * tidesdb_get_column_family
 * gets a column family
 * @param db database handle
 * @param name name of column family
 * @return pointer to column family, NULL on failure
 */
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);

/**
 * tidesdb_list_column_families
 * lists all column families in the database
 * @param db database handle
 * @param names pointer to array of column family names (caller must free each name and the array)
 * @param count pointer to store the number of column families
 * @return 0 on success, -n on failure
 */
int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count);

/**
 * tidesdb_txn_begin
 * begins a transaction with default isolation level (READ_COMMITTED)
 * @param db database handle
 * @param txn pointer to transaction handle
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn);

/**
 * tidesdb_txn_begin_with_isolation
 * begins a transaction with specified isolation level
 * @param db database handle
 * @param isolation isolation level
 * @param txn pointer to transaction handle
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn);

/**
 * tidesdb_txn_put
 * adds a put operation to the transaction
 * @param txn transaction handle
 * @param cf column family to put into
 * @param key key to put
 * @param key_size size of key
 * @param value value to put
 * @param value_size size of value
 * @param ttl time-to-live for key-value pair
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl);

/**
 * tidesdb_txn_get
 * gets a value from the transaction
 * @param txn transaction handle
 * @param cf column family to get from
 * @param key key to get
 * @param key_size size of key
 * @param value pointer to value
 * @param value_size pointer to size of value
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size);

/**
 * tidesdb_txn_delete
 * adds a delete operation to the transaction
 * @param txn transaction handle
 * @param cf column family to delete from
 * @param key key to delete
 * @param key_size size of key
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size);

/**
 * tidesdb_txn_rollback
 * rolls back the transaction
 * @param txn transaction handle
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_rollback(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_commit
 * commits the transaction
 * @param txn transaction handle
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_commit(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_free
 * frees the transaction
 * @param txn transaction handle
 */
void tidesdb_txn_free(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_savepoint
 * creates a savepoint in the transaction
 * @param txn transaction handle
 * @param name name of savepoint
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name);

/**
 * tidesdb_txn_rollback_to_savepoint
 * rolls back transaction to a savepoint
 * @param txn transaction handle
 * @param name name of savepoint
 * @return 0 on success, -n on failure
 */
int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name);

/**
 * tidesdb_iter_new
 * creates a new iterator for a specific cf in the transaction
 * @param txn transaction handle
 * @param cf column family to iterate
 * @param iter pointer to iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter);

/**
 * tidesdb_iter_seek
 * seeks to a key in the iterator
 * @param iter iterator handle
 * @param key key to seek to
 * @param key_size size of key
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/**
 * tidesdb_iter_seek_for_prev
 * seeks to the previous key in the iterator
 * @param iter iterator handle
 * @param key key to seek to
 * @param key_size size of key
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/**
 * tidesdb_iter_seek_to_first
 * seeks to the first key in the iterator
 * @param iter iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_seek_to_last
 * seeks to the last key in the iterator
 * @param iter iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_next
 * seeks to the next key in the iterator
 * @param iter iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_next(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_prev
 * seeks to the previous key in the iterator
 * @param iter iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_prev(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_valid
 * checks if the iterator is valid
 * @param iter iterator handle
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_valid(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_key
 * gets the key from the iterator
 * @param iter iterator handle
 * @param key pointer to key
 * @param key_size pointer to size of key
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size);

/**
 * tidesdb_iter_value
 * gets the value from the iterator
 * @param iter iterator handle
 * @param value pointer to value
 * @param value_size pointer to size of value
 * @return 0 on success, -n on failure
 */
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);

/**
 * tidesdb_iter_free
 * frees the iterator
 * @param iter iterator handle
 */
void tidesdb_iter_free(tidesdb_iter_t *iter);

/**
 * tidesdb_comparator_memcmp
 * binary comparison using memcmp (default)
 * compares keys byte-by-byte
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx unused context
 * @return <0 if key1 < key2, 0 if equal, >0 if key1 > key2
 */
int tidesdb_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx);

/**
 * tidesdb_comparator_lexicographic
 * lexicographic string comparison
 * treats keys as null-terminated strings
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx unused context
 * @return <0 if key1 < key2, 0 if equal, >0 if key1 > key2
 */
int tidesdb_comparator_lexicographic(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx);

/**
 * tidesdb_comparator_uint64
 * compares keys as 64-bit unsigned integers (little-endian)
 * keys must be exactly 8 bytes
 * @param key1 first key (8 bytes)
 * @param key1_size size of first key (must be 8)
 * @param key2 second key (8 bytes)
 * @param key2_size size of second key (must be 8)
 * @param ctx unused context
 * @return <0 if key1 < key2, 0 if equal, >0 if key1 > key2
 */
int tidesdb_comparator_uint64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx);

/**
 * tidesdb_comparator_int64
 * compares keys as 64-bit signed integers (little-endian)
 * keys must be exactly 8 bytes
 * @param key1 first key (8 bytes)
 * @param key1_size size of first key (must be 8)
 * @param key2 second key (8 bytes)
 * @param key2_size size of second key (must be 8)
 * @param ctx unused context
 * @return <0 if key1 < key2, 0 if equal, >0 if key1 > key2
 */
int tidesdb_comparator_int64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                             size_t key2_size, void *ctx);

/**
 * tidesdb_comparator_reverse_memcmp
 * reverse binary comparison (descending order)
 * useful for reverse-sorted indexes
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx unused context
 * @return >0 if key1 < key2, 0 if equal, <0 if key1 > key2
 */
int tidesdb_comparator_reverse_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                      size_t key2_size, void *ctx);

/**
 * tidesdb_comparator_case_insensitive
 * case-insensitive string comparison
 * treats keys as ASCII strings
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @param ctx unused context
 * @return <0 if key1 < key2, 0 if equal, >0 if key1 > key2
 */
int tidesdb_comparator_case_insensitive(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                        size_t key2_size, void *ctx);

/**
 * tidesdb_compact
 * compacts the column family
 * @param cf column family handle
 * @return 0 on success, -n on failure
 */
int tidesdb_compact(tidesdb_column_family_t *cf);

/**
 * tidesdb_flush_memtable
 * flushes the memtable to disk
 * @param cf column family handle
 * @return 0 on success, -n on failure
 */
int tidesdb_flush_memtable(tidesdb_column_family_t *cf);

/**
 * tidesdb_cf_config_load_from_ini
 * loads the column family configuration from an INI file
 * @param ini_file INI file path
 * @param section_name section name in INI file
 * @param config pointer to column family configuration
 * @return 0 on success, -n on failure
 */
int tidesdb_cf_config_load_from_ini(const char *ini_file, const char *section_name,
                                    tidesdb_column_family_config_t *config);

/**
 * tidesdb_cf_config_save_to_ini
 * saves the column family configuration to an INI file
 * @param ini_file INI file path
 * @param section_name section name in INI file
 * @param config pointer to column family configuration
 * @return 0 on success, -n on failure
 */
int tidesdb_cf_config_save_to_ini(const char *ini_file, const char *section_name,
                                  const tidesdb_column_family_config_t *config);

/**
 * tidesdb_cf_update_runtime_config
 * updates the runtime configuration of the column family
 * @param cf column family handle
 * @param new_config new configuration
 * @param persist_to_disk whether to persist the configuration to disk
 * @return 0 on success, -n on failure
 */
int tidesdb_cf_update_runtime_config(tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk);

/**
 * tidesdb_get_stats
 * gets the statistics of the column family
 * @param cf column family handle
 * @param stats pointer to statistics
 * @return 0 on success, -n on failure
 */
int tidesdb_get_stats(tidesdb_column_family_t *cf, tidesdb_stats_t **stats);

/**
 * tidesdb_free_stats
 * frees the statistics
 * @param stats statistics
 */
void tidesdb_free_stats(tidesdb_stats_t *stats);

#endif /* __TIDESDB_H__ */