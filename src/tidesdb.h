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
#include "compress.h"
#include "fifo.h"
#include "ini.h"
#include "queue.h"
#include "skip_list.h"
#include "succinct_trie.h"

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

/* forward declarations */
typedef struct tidesdb_t tidesdb_t;
typedef struct tidesdb_column_family_t tidesdb_column_family_t;
typedef struct tidesdb_level_t tidesdb_level_t;
typedef struct tidesdb_sstable_t tidesdb_sstable_t;
typedef struct tidesdb_txn_t tidesdb_txn_t;
typedef struct tidesdb_iter_t tidesdb_iter_t;
typedef struct tidesdb_stats_t tidesdb_stats_t;
typedef struct tidesdb_flush_work_t tidesdb_flush_work_t;
typedef struct tidesdb_compaction_work_t tidesdb_compaction_work_t;

/**
 * tidesdb_immutable_memtable_t
 * an immutable memtable being flushed to disk
 * @param memtable the immutable memtable
 * @param wal associated write-ahead log
 * @param refcount reference count for safe concurrent access
 * @param flushed 1 if flushed to sstable, 0 otherwise
 */
typedef struct
{
    skip_list_t *memtable;
    block_manager_t *wal;
    _Atomic(int) refcount;
    _Atomic(int) flushed;
} tidesdb_immutable_memtable_t;

/* error codes */
#define TDB_SUCCESS          0
#define TDB_ERR_MEMORY       -1
#define TDB_ERR_INVALID_ARGS -2
#define TDB_ERR_NOT_FOUND    -3
#define TDB_ERR_IO           -4
#define TDB_ERR_CORRUPTION   -5
#define TDB_ERR_EXISTS       -6
#define TDB_ERR_LOCK         -7
#define TDB_ERR_CONFLICT     -8
#define TDB_ERR_OVERFLOW     -9
#define TDB_ERR_TOO_LARGE    -10

/* sync modes */
typedef enum
{
    TDB_SYNC_NONE, /* no fsync/fdatasync -- fastest, least durable */
    TDB_SYNC_FULL, /* full fsync/fdatasync on every write to a block manager, slowest, most durable
                    */
} tidesdb_sync_mode_t;

/* KV pair flags */
#define TDB_KV_FLAG_TOMBSTONE 0x01

/* multi-CF transaction sequence flag (high bit set = global sequence) */
#define TDB_MULTI_CF_SEQ_FLAG (1ULL << 63)

typedef enum
{
    TDB_ISOLATION_READ_UNCOMMITTED = 0, /* sees all versions, no snapshot */
    TDB_ISOLATION_READ_COMMITTED = 1,   /* refreshes snapshot on each read */
    TDB_ISOLATION_REPEATABLE_READ = 2,  /* consistent snapshot, no phantom protection */
    TDB_ISOLATION_SNAPSHOT = 3,         /* consistent snapshot with write conflict detection */
    TDB_ISOLATION_SERIALIZABLE = 4      /* full serializability with rw-conflict detection */
} tidesdb_isolation_level_t;

typedef int (*tidesdb_comparator_fn)(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx);

#define TDB_WAL_PREFIX                "wal_"   /* prefix for write-ahead log files */
#define TDB_WAL_EXT                   ".log"   /* extension for write-ahead log files */
#define TDB_COLUMN_FAMILY_CONFIG_NAME "config" /* base name for column family config files */
#define TDB_COLUMN_FAMILY_CONFIG_EXT  ".ini"   /* extension for column family config files */
#define TDB_LEVEL_PREFIX              "L"      /* prefix for level directories in LSM tree */
#define TDB_LEVEL_PARTITION_PREFIX    "P" /* prefix for partition identifiers in sstable names */
#define TDB_SSTABLE_KLOG_EXT          ".klog" /* extension for sstable key log files */
#define TDB_SSTABLE_VLOG_EXT          ".vlog" /* extension for sstable value log files */
#define TDB_SSTABLE_CACHE_PREFIX      "sst_"  /* prefix for sstable cache keys */
#define TDB_CACHE_KEY_LEN             128     /* maximum length for cache key strings */

/* default configuration values */
#define TDB_DEFAULT_WRITE_BUFFER_SIZE              (64 * 1024 * 1024) /* 64MB */
#define TDB_DEFAULT_LEVEL_SIZE_RATIO               10 /* size ratio between levels (T) i.e. L1 = L0 * T */
#define TDB_DEFAULT_MAX_LEVELS                     7 /* maximum number of levels for lsm tree's per cf */
#define TDB_DEFAULT_DIVIDING_LEVEL_OFFSET          2 /* X = L-2 */
#define TDB_DEFAULT_COMPACTION_THREAD_POOL_SIZE    2 /* thread pool size for global compactions */
#define TDB_DEFAULT_FLUSH_THREAD_POOL_SIZE         2 /* thread pool size for global flushes */
#define TDB_DEFAULT_BLOOM_FPR                      0.01        /* 1% false positive rate */
#define TDB_DEFAULT_KLOG_BLOCK_SIZE                (32 * 1024) /* 32KB per klog block */
#define TDB_DEFAULT_VLOG_BLOCK_SIZE                (4 * 1024)  /* 4KB per vlog block */
#define TDB_DEFAULT_VALUE_THRESHOLD                1024        /* values >= 1KB go to vlog */
#define TDB_DEFAULT_INDEX_SAMPLE_RATIO             16          /* sample every 16th key for index */
#define TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL 1000        /* 1000ms = 1 second */
#define TDB_DEFAULT_MIN_DISK_SPACE                 (100 * 1024 * 1024) /* 100MB minimum free space */
#define TDB_DEFAULT_MAX_IMMUTABLE_MEMTABLES        8   /* soft limit -- start slowing writes */
#define TDB_DEFAULT_WRITE_STALL_THRESHOLD          32  /* hard limit -- block writes completely */
#define TDB_DEFAULT_MAX_OPEN_SSTABLES              512 /* max open sstables globally */
#define TDB_DEFAULT_ACTIVE_TXN_BUFFER_SIZE         1024 * 64 /* max concurrent txns per cf */

#define TDB_MAX_TXN_CFS         10000  /* maximum number of cfs per transaction */
#define TDB_MAX_PATH_LEN        4096   /* maximum path length */
#define TDB_MAX_TXN_OPS         100000 /* maximum transaction operations */
#define TDB_MAX_CF_NAME_LEN     256    /* maximum column family name length */
#define TDB_MAX_COMPARATOR_NAME 64     /* maximum comparator name length */
#define TDB_MAX_COMPARATOR_CTX  256    /* maximum comparator context string length */
#define TDB_ENSURE_OPEN_SSTABLE_WAIT_US \
    1024 /* microseconds to sleep when spinning on sstable open */
#define TDB_ENSURE_OPEN_SSTABLE_WAIT_COUNT                \
    128 /* spin count before sleeping during sstable open \
         */
#define TDB_WRITE_STALL_BACKOFF_US \
    100000 /* microseconds to sleep during hard write stall (100ms) */
#define TDB_WRITE_SLOWDOWN_MAX_SLEEP_MS                       \
    500 /* maximum sleep time for write slowdown backpressure \
         */
#define TDB_WRITE_SLOWDOWN_EXPO             10 /* milliseconds per extra sstable in exponential backoff */
#define TDB_L0_COMPACTION_TRIGGER           4  /* l0 sstable count that triggers compaction */
#define TDB_L0_SLOWDOWN_THRESHOLD           8  /* l0 sstable count that triggers write throttling */
#define TDB_IMMUTABLE_QUEUE_SLOWDOWN_FACTOR 50 /* milliseconds per extra immutable memtable */
#define TDB_TXN_SPIN_COUNT \
    1000 /* spin iterations before yielding in transaction conflict resolution */
#define TDB_CF_LIST_BACKOFF_US \
    100 /* microseconds to sleep while waiting for CF list modification to complete */
#define TDB_CF_LEVELS_BACKOFF_US \
    100 /* microseconds to sleep while waiting for CF levels modification to complete */

/**
 * tidesdb_column_family_config_t
 * configuration for a column family
 * @param write_buffer_size write buffer size for memtable flushes
 * @param level_size_ratio size ratio between levels (T)
 * @param max_levels maximum number of levels
 * @param dividing_level_offset X = L - dividing_level_offset
 * @param klog_block_size size of each klog block (holds multiple keys)
 * @param vlog_block_size size of each vlog block (holds multiple values)
 * @param value_threshold values >= this size go to vlog
 * @param compression_algorithm compression algorithm
 * @param enable_bloom_filter enable bloom filter
 * @param bloom_fpr bloom filter false positive rate
 * @param enable_block_indexes enable block indexes
 * @param index_sample_ratio sample every nth key for sparse index
 * @param block_manager_cache_size block manager cache size
 * @param sync_mode sync mode
 * @param comparator_name name of registered comparator
 * @param comparator_ctx_str optional context string for comparator
 * @param comparator_fn_cached cached comparator function (avoids lock)
 * @param comparator_ctx_cached cached comparator context (avoids lock)
 * @param compaction_interval_ms compaction interval in milliseconds
 * @param enable_background_compaction enable background compaction
 * @param skip_list_max_level skip list max level
 * @param skip_list_probability skip list probability
 * @param default_isolation_level default isolation level
 * @param min_disk_space minimum free disk space required (bytes)
 * @param max_immutable_memtables soft limit for immutable memtables (triggers slowdown)
 * @param write_stall_threshold hard limit for immutable memtables (blocks writes)
 */
typedef struct
{
    size_t write_buffer_size;
    size_t level_size_ratio;
    int max_levels;
    int dividing_level_offset;
    size_t klog_block_size;
    size_t vlog_block_size;
    size_t value_threshold;
    compression_algorithm compression_algorithm;
    int enable_bloom_filter;
    double bloom_fpr;
    int enable_block_indexes;
    int index_sample_ratio;
    size_t block_manager_cache_size;
    int sync_mode;
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    char comparator_ctx_str[TDB_MAX_COMPARATOR_CTX];
    skip_list_comparator_fn comparator_fn_cached;
    void *comparator_ctx_cached;
    unsigned int compaction_interval_ms;
    int enable_background_compaction;
    int skip_list_max_level;
    float skip_list_probability;
    tidesdb_isolation_level_t default_isolation_level;
    uint64_t min_disk_space;
    int max_immutable_memtables;
    int write_stall_threshold;
} tidesdb_column_family_config_t;

/**
 * tidesdb_comparator_entry_t
 * comparator registry entry
 * @param name unique name for the comparator
 * @param fn comparator function pointer
 * @param ctx_str optional context string (for serialization)
 * @param ctx runtime context pointer (reconstructed from ctx_str or set at registration)
 */
typedef struct
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
 * @param enable_debug_logging enable debug logging
 * @param max_open_sstables maximum number of open sstables (FIFO cache)
 */
typedef struct
{
    char *db_path;
    int num_flush_threads;
    int num_compaction_threads;
    int enable_debug_logging;
    size_t max_open_sstables;
} tidesdb_config_t;

/**
 * tidesdb_klog_entry_t
 * entry in the klog (key log)
 * stores key metadata and either inline value or vlog offset
 * @param version format version
 * @param flags TDB_KV_FLAG_TOMBSTONE, etc.
 * @param key_size size of key
 * @param value_size size of value (actual, not stored)
 * @param ttl unix timestamp (0 = no expiration)
 * @param seq sequence number for mvcc
 * @param vlog_offset offset in vlog (0 if inline)
 */
#pragma pack(push, 1)
typedef struct
{
    uint8_t version;
    uint8_t flags;
    uint32_t key_size;
    uint32_t value_size;
    int64_t ttl;
    uint64_t seq;
    uint64_t vlog_offset;
} tidesdb_klog_entry_t;
#pragma pack(pop)

/**
 * tidesdb_multi_cf_txn_metadata_t
 * metadata for multi-cf transaction entries
 * written before klog_entry when entry has multi-cf flag
 * @param num_participant_cfs number of column families in transaction
 * @param checksum xxhash64 checksum of num_participant_cfs + cf_names
 * followed by: char cf_names[num_participant_cfs][TDB_MAX_CF_NAME_LEN] (null-terminated cf names)
 */
#pragma pack(push, 1)
typedef struct
{
    uint8_t num_participant_cfs;
    uint64_t checksum;
} tidesdb_multi_cf_txn_metadata_t;
#pragma pack(pop)

/**
 * tidesdb_klog_block_t
 * a block in the klog containing multiple key entries
 * @param num_entries number of entries in this block
 * @param block_size total size of this block
 * @param entries array of entries
 * @param keys array of key data
 * @param inline_values array of inline values (null if in vlog)
 * @param max_key maximum key in this block (for seek optimization)
 * @param max_key_size size of maximum key
 */
typedef struct
{
    uint32_t num_entries;
    uint32_t block_size;
    tidesdb_klog_entry_t *entries;
    uint8_t **keys;
    uint8_t **inline_values;
    uint8_t *max_key;
    size_t max_key_size;
} tidesdb_klog_block_t;

/**
 * tidesdb_vlog_block_t
 * a block in the vlog containing multiple values
 * @param num_values number of values in this block
 * @param block_size total size of this block
 * @param value_sizes array of value sizes
 * @param values array of value data
 */
typedef struct
{
    uint32_t num_values;
    uint32_t block_size;
    uint32_t *value_sizes;
    uint8_t **values;
} tidesdb_vlog_block_t;

/**
 * tidesdb_kv_pair_t
 * in-memory representation of a key-value pair
 * @param entry klog entry
 * @param key key data
 * @param value value data
 */
typedef struct
{
    tidesdb_klog_entry_t entry;
    uint8_t *key;
    uint8_t *value;
} tidesdb_kv_pair_t;

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
 * @param num_klog_blocks number of klog blocks
 * @param num_vlog_blocks number of vlog blocks
 * @param klog_data_end_offset file offset where data blocks end (before index/bloom/metadata)
 * @param klog_size size of klog file
 * @param vlog_size size of vlog file
 * @param max_seq maximum sequence number in this sstable
 * @param bloom_filter bloom filter for fast lookups
 * @param block_index succinct trie for fast lookups
 * @param refcount reference count
 * @param bm_open_state atomic state for block manager (0=closed, 1=opening, 2=open)
 * @param klog_bm block manager for klog
 * @param vlog_bm block manager for vlog
 * @param config column family configuration
 * @param marked_for_deletion atomic flag indicating if sstable is marked for deletion
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
    _Atomic(uint64_t) num_klog_blocks;
    _Atomic(uint64_t) num_vlog_blocks;
    uint64_t klog_data_end_offset;
    uint64_t klog_size;
    uint64_t vlog_size;
    uint64_t max_seq;
    bloom_filter_t *bloom_filter;
    succinct_trie_t *block_index;
    _Atomic(int) refcount;
    _Atomic(int) bm_open_state;
    block_manager_t *klog_bm;
    block_manager_t *vlog_bm;
    tidesdb_column_family_config_t *config;
    _Atomic(int) marked_for_deletion;
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
    size_t capacity;
    _Atomic(size_t) current_size;
    _Atomic(tidesdb_sstable_t **) sstables;
    _Atomic(int) num_sstables;
    _Atomic(int) sstables_capacity;
    uint8_t **file_boundaries;
    size_t *boundary_sizes;
    _Atomic(int) num_boundaries;
};

/**
 * tidesdb_commit_entry_t
 * entry in the commit buffer tracking a pending commit
 * @param seq_num sequence number being committed
 * @param committed atomic flag: 0=pending, 1=committed
 * @param txn_id transaction id for debugging
 */
typedef struct
{
    uint64_t seq_num;
    _Atomic(int) committed;
    uint64_t txn_id;
} tidesdb_commit_entry_t;

/**
 * tidesdb_txn_entry_t
 * entry in the active transaction buffer
 * @param txn_id transaction ID
 * @param snapshot_seq snapshot sequence number
 * @param isolation isolation level
 * @param buffer_slot_id slot id in buffer for quick access
 * @param generation generation counter for ABA prevention
 */
typedef struct
{
    uint64_t txn_id;
    uint64_t snapshot_seq;
    tidesdb_isolation_level_t isolation;
    uint32_t buffer_slot_id;
    uint64_t generation;
} tidesdb_txn_entry_t;

/**
 * tidesdb_column_family_t
 * a column family is independent key-value storage
 * @param name name of column family
 * @param directory directory for column family
 * @param config column family configuration
 * @param active_memtable active memtable (level 0)
 * @param memtable_id id of active memtable
 * @param memtable_generation generation counter for memtable rotation
 * @param active_wal active write-ahead log
 * @param immutable_memtables queue of immutable memtables
 * @param next_seq_num next sequence number for mvcc
 * @param commit_seq commit sequence for isolation levels
 * @param commit_ticket ticket counter for serializing commits
 * @param commit_serving serving counter for serializing commits
 * @param active_txn_buffer buffer of active transactions for this cf
 * @param levels_lock protects levels and num_levels
 * @param flush_lock serializes flush operations
 * @param compaction_lock serializes compaction operations
 * @param levels array of disk levels
 * @param num_levels number of disk levels
 * @param compaction_thread thread for background compaction
 * @param compaction_should_stop flag to stop compaction thread
 * @param next_sstable_id next sstable id
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
    _Atomic(uint64_t) next_seq_num;
    _Atomic(uint64_t) commit_seq;
    _Atomic(uint64_t) commit_ticket;
    _Atomic(uint64_t) commit_serving;
    buffer_t *active_txn_buffer;
    pthread_rwlock_t levels_lock;
    pthread_mutex_t flush_lock;
    pthread_mutex_t compaction_lock;
    tidesdb_level_t **levels;
    int num_levels;
    pthread_t compaction_thread;
    _Atomic(int) compaction_should_stop;
    _Atomic(uint64_t) next_sstable_id;
    tidesdb_t *db;
};

/**
 * tidesdb_flush_work_t
 * work item for flush thread pool
 * @param cf column family
 * @param imm immutable memtable wrapper (holds refcount)
 * @param sst_id sstable id
 */
struct tidesdb_flush_work_t
{
    tidesdb_column_family_t *cf;
    tidesdb_immutable_memtable_t *imm;
    uint64_t sst_id;
};

/**
 * tidesdb_compaction_work_t
 * work item for compaction thread pool
 * @param cf column family
 * @param start_level starting level
 * @param target_level target level
 */
struct tidesdb_compaction_work_t
{
    tidesdb_column_family_t *cf;
    int start_level;
    int target_level;
};

/**
 * tidesdb_t
 * main database handle
 * @param db_path path to database directory
 * @param config database configuration
 * @param column_families array of column families
 * @param num_column_families number of column families
 * @param cf_capacity capacity of column families array
 * @param comparators array of registered comparators
 * @param num_comparators number of registered comparators
 * @param comparators_capacity capacity of comparators array
 * @param comparators_lock mutex for comparator registry
 * @param flush_threads array of flush threads
 * @param flush_queue queue of flush work items
 * @param flush_should_stop flag to stop flush threads
 * @param active_flush_workers number of workers actively processing
 * @param compaction_threads array of compaction threads
 * @param compaction_queue queue of compaction work items
 * @param compaction_should_stop flag to stop compaction threads
 * @param sstable_cache fifo cache for sstable file handles
 * @param is_open flag to indicate if database is open
 * @param global_txn_seq global sequence counter for multi-cf transactions
 * @param next_txn_id global transaction id counter
 * @param cached_available_disk_space cached available disk space in bytes
 * @param last_disk_space_check timestamp of last disk space check
 * @param cf_list_lock rwlock for cf list modifications
 * @param recovery_lock protects recovery_complete flag
 * @param recovery_cond signals when recovery is complete
 * @param recovery_complete flag indicating if recovery process is complete
 */
struct tidesdb_t
{
    char *db_path;
    tidesdb_config_t config;
    tidesdb_column_family_t **column_families;
    int num_column_families;
    int cf_capacity;
    tidesdb_comparator_entry_t *comparators;
    int num_comparators;
    int comparators_capacity;
    pthread_mutex_t comparators_lock;
    pthread_t *flush_threads;
    queue_t *flush_queue;
    _Atomic(int) flush_should_stop;
    _Atomic(int) active_flush_workers;
    pthread_t *compaction_threads;
    queue_t *compaction_queue;
    _Atomic(int) compaction_should_stop;
    fifo_cache_t *sstable_cache;
    _Atomic(int) is_open;
    _Atomic(uint64_t) global_txn_seq;
    _Atomic(uint64_t) next_txn_id;
    _Atomic(uint64_t) cached_available_disk_space;
    _Atomic(time_t) last_disk_space_check;
    pthread_rwlock_t cf_list_lock;
    pthread_mutex_t recovery_lock;
    pthread_cond_t recovery_cond;
    int recovery_complete;
};

/**
 * tidesdb_txn_op_t
 * operation structure for transactions
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param ttl time-to-live
 * @param is_delete delete flag
 * @param cf column family (for multi-cf transactions)
 */
typedef struct
{
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
    int is_delete;
    tidesdb_column_family_t *cf;
} tidesdb_txn_op_t;

/**
 * tidesdb_txn_t
 * transaction handle for batched operations with acid guarantees
 * @param db database handle
 * @param isolation_level isolation level
 * @param txn_id transaction id
 * @param ops array of operations
 * @param num_ops number of operations
 * @param ops_capacity capacity of operations array
 * @param read_keys array of read keys
 * @param read_key_sizes array of read key sizes
 * @param read_seqs array of read sequence numbers
 * @param read_cfs array of cfs for each read key
 * @param read_set_count number of read keys
 * @param read_set_capacity capacity of read keys array
 * @param write_keys array of write keys
 * @param write_key_sizes array of write key sizes
 * @param write_cfs array of cfs for each write key
 * @param write_set_count number of write keys
 * @param write_set_capacity capacity of write keys array
 * @param cfs array of column families involved in transaction
 * @param cf_snapshots array of per-cf snapshot sequences (indexed same as cfs)
 * @param cf_txn_slots array of per-cf transaction buffer slot ids (indexed same as cfs)
 * @param num_cfs number of column families
 * @param cf_capacity capacity of column families array
 * @param global_snapshot_seq global snapshot point for consistent multi-cf reads
 * @param parent parent transaction (for nested transactions)
 * @param savepoints array of savepoints
 * @param savepoint_names array of savepoint names
 * @param num_savepoints number of savepoints
 * @param savepoints_capacity capacity of savepoints array
 * @param is_committed flag to indicate if transaction is committed
 * @param is_aborted flag to indicate if transaction is aborted
 * @param is_read_only flag to indicate if transaction is read-only
 */
struct tidesdb_txn_t
{
    tidesdb_t *db;
    tidesdb_isolation_level_t isolation_level;
    uint64_t txn_id;
    tidesdb_txn_op_t *ops;
    int num_ops;
    int ops_capacity;
    uint8_t **read_keys;
    size_t *read_key_sizes;
    uint64_t *read_seqs;
    tidesdb_column_family_t **read_cfs;
    int read_set_count;
    int read_set_capacity;
    uint8_t **write_keys;
    size_t *write_key_sizes;
    tidesdb_column_family_t **write_cfs;
    int write_set_count;
    int write_set_capacity;
    tidesdb_column_family_t **cfs;
    uint64_t *cf_snapshots;
    uint32_t *cf_txn_slots;
    int num_cfs;
    int cf_capacity;
    uint64_t global_snapshot_seq;
    tidesdb_txn_t *parent;
    tidesdb_txn_t **savepoints;
    char **savepoint_names;
    int num_savepoints;
    int savepoints_capacity;
    int is_committed;
    int is_aborted;
    int is_read_only;
};

/**
 * tidesdb_merge_source_t
 * is a source for merging (memtable or sstable)
 * @param type type of source (memtable or sstable)
 * @param source union of memtable or sstable source
 * @param current_kv current key-value pair
 * @param config column family configuration
 */
typedef struct
{
    enum
    {
        MERGE_SOURCE_MEMTABLE,
        MERGE_SOURCE_SSTABLE
    } type;

    union
    {
        struct
        {
            skip_list_cursor_t *cursor;
            tidesdb_immutable_memtable_t *imm;
        } memtable;

        struct
        {
            tidesdb_t *db;
            tidesdb_sstable_t *sst;
            block_manager_cursor_t *klog_cursor;
            tidesdb_klog_block_t *current_block;
            block_manager_block_t *current_block_data;
            uint8_t *decompressed_data;
            int current_entry_idx;
        } sstable;
    } source;

    tidesdb_kv_pair_t *current_kv;
    tidesdb_column_family_config_t *config;
} tidesdb_merge_source_t;

/**
 * tidesdb_merge_heap_t
 * min-heap for efficient multi-way merge
 * @param sources array of merge sources
 * @param num_sources number of sources
 * @param capacity capacity of sources array
 * @param comparator comparator function for sorting
 * @param comparator_ctx comparator context
 */
typedef struct
{
    tidesdb_merge_source_t **sources;
    int num_sources;
    int capacity;
    skip_list_comparator_fn comparator;
    void *comparator_ctx;
} tidesdb_merge_heap_t;

/**
 * tidesdb_iter_t
 * iterator for database
 * @param cf column family (for single-cf iteration)
 * @param txn transaction (for isolation and multi-cf iteration)
 * @param heap merge heap
 * @param current current key-value pair
 * @param valid validity flag
 * @param direction direction of iteration (1=forward, -1=backward)
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
typedef struct tidesdb_stats_t
{
    int num_levels;
    size_t memtable_size;
    size_t *level_sizes;
    int *level_num_sstables;
    tidesdb_column_family_config_t *config;
} tidesdb_stats_t;

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
 * opens a database
 * @param config configuration for database
 * @param db pointer to database handle
 * @return 0 on success, -n on failure
 */
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);

/**
 * tidesdb_register_comparator
 * registers a custom comparator function
 * must be called before creating column families that use this comparator
 * @param db database handle
 * @param name unique name for the comparator
 * @param fn comparator function pointer
 * @param ctx_str optional context string (for serialization, can be NULL or empty)
 * @param ctx optional runtime context pointer (can be NULL)
 * @return 0 on success, -1 on failure (duplicate name, invalid args, etc.)
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
 * @return 0 on success, -1 if not found
 */
int tidesdb_get_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn *fn,
                           void **ctx);

/**
 * tidesdb_close
 * closes a database
 * @param db database handle
 */
int tidesdb_close(tidesdb_t *db);

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