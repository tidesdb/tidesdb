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

#include "tidesdb.h"

#include <errno.h>
#include <stdarg.h>

#include "xxhash.h"

/* read profiling macros */
#ifdef TDB_ENABLE_READ_PROFILING
#define PROFILE_INC(db, field)      atomic_fetch_add(&(db)->read_stats.field, 1)
#define PROFILE_ADD(db, field, val) atomic_fetch_add(&(db)->read_stats.field, val)
#else
#define PROFILE_INC(db, field)      ((void)0)
#define PROFILE_ADD(db, field, val) ((void)0)
#endif

/* global log level definition */
int _tidesdb_log_level = TDB_LOG_DEBUG;

/* global log file pointer (NULL = stderr, non-NULL = file) */
FILE *_tidesdb_log_file = NULL;

/* global log truncation threshold (0 = no truncation) */
size_t _tidesdb_log_truncate = 0;

/* global log file path for truncation */
char _tidesdb_log_path[MAX_FILE_PATH_LENGTH] = {0};

/* mutex to protect log file access during truncation */
static pthread_mutex_t tidesdb_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * tidesdb_log_write
 * writes a log message to the log file or stderr
 * handles truncation if configured
 * @param level log level
 * @param file source file name
 * @param line source line number
 * @param fmt format string
 * @param ... format arguments
 */
void tidesdb_log_write(const int level, const char *file, const int line, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    const time_t sec = ts.tv_sec;
    struct tm tm_info;
    tdb_localtime(&sec, &tm_info);

    const char *level_str = (level == TDB_LOG_DEBUG)   ? "DEBUG"
                            : (level == TDB_LOG_INFO)  ? "INFO"
                            : (level == TDB_LOG_WARN)  ? "WARN"
                            : (level == TDB_LOG_ERROR) ? "ERROR"
                                                       : "FATAL";

    pthread_mutex_lock(&tidesdb_log_mutex);

    FILE *log_out = _tidesdb_log_file ? _tidesdb_log_file : stderr;

    fprintf(log_out, "[%02d:%02d:%02d.%03d] [%s] %s:%d: ", tm_info.tm_hour, tm_info.tm_min,
            tm_info.tm_sec, (int)(ts.tv_nsec / 1000000), level_str, file, line);

    va_list args;
    va_start(args, fmt);
    if (fmt) vfprintf(log_out, fmt, args);
    va_end(args);

    fprintf(log_out, "\n");

    if (_tidesdb_log_file)
    {
        fflush(_tidesdb_log_file);

        if (_tidesdb_log_truncate > 0 && _tidesdb_log_path[0] != '\0')
        {
            const long current_pos = ftell(_tidesdb_log_file);
            if (current_pos > 0 && (size_t)current_pos >= _tidesdb_log_truncate)
            {
                fclose(_tidesdb_log_file);
                _tidesdb_log_file = fopen(_tidesdb_log_path, "w");
                if (_tidesdb_log_file)
                {
                    tdb_setlinebuf(_tidesdb_log_file);
                    fprintf(_tidesdb_log_file, "[LOG TRUNCATED - exceeded %zu bytes]\n",
                            _tidesdb_log_truncate);
                    fflush(_tidesdb_log_file);
                }
            }
        }
    }

    pthread_mutex_unlock(&tidesdb_log_mutex);
}

typedef struct tidesdb_flush_work_t tidesdb_flush_work_t;
typedef struct tidesdb_compaction_work_t tidesdb_compaction_work_t;
typedef tidesdb_memtable_t tidesdb_immutable_memtable_t;

/* kv pair flags */
#define TDB_KV_FLAG_TOMBSTONE 0x01
#define TDB_KV_FLAG_HAS_TTL   0x02
#define TDB_KV_FLAG_HAS_VLOG  0x04
#define TDB_KV_FLAG_DELTA_SEQ 0x08
#define TDB_KV_FLAG_ARENA     0x80

#define TDB_LOG_FILE                     "LOG"
#define TDB_WAL_PREFIX                   "wal_"
#define TDB_WAL_EXT                      ".log"
#define TDB_COLUMN_FAMILY_CONFIG_NAME    "config"
#define TDB_COLUMN_FAMILY_MANIFEST_NAME  "MANIFEST"
#define TDB_COLUMN_FAMILY_CONFIG_EXT     ".ini"
#define TDB_LEVEL_PREFIX                 "L"
#define TDB_LEVEL_PARTITION_PREFIX       "P"
#define TDB_SSTABLE_KLOG_EXT             ".klog"
#define TDB_SSTABLE_VLOG_EXT             ".vlog"
#define TDB_LOCK_FILE                    "LOCK"
#define TDB_CACHE_KEY_SIZE               64
#define TDB_SSTABLE_METADATA_MAGIC       0x5353544D
#define TDB_SSTABLE_METADATA_HEADER_SIZE 84
#define TDB_KLOG_BLOCK_SIZE              (64 * 1024)
#define TDB_STACK_SSTS                   64
#define TDB_ITER_STACK_KEY_SIZE          256
#define TDB_BACKUP_COPY_BUFFER_SIZE      (256 * 1024)

/* initial capacity values for dynamic arrays */
#define TDB_INITIAL_MERGE_HEAP_CAPACITY    16
#define TDB_INITIAL_CF_CAPACITY            16
#define TDB_INITIAL_COMPARATOR_CAPACITY    8
#define TDB_INITIAL_TXN_OPS_CAPACITY       16
#define TDB_INITIAL_TXN_READ_SET_CAPACITY  16
#define TDB_INITIAL_TXN_CF_CAPACITY        4
#define TDB_INITIAL_TXN_SAVEPOINT_CAPACITY 4
#define TDB_INITIAL_BLOCK_INDEX_CAPACITY   16

/* create write set hash table at this many ops */
#define TDB_TXN_WRITE_HASH_THRESHOLD 64
/* create read set hash table at this many reads */
#define TDB_TXN_READ_HASH_THRESHOLD 64
/* scan last N ops for small txns */
#define TDB_TXN_SMALL_SCAN_LIMIT 64
/* grow read set by this amount */
#define TDB_TXN_READ_SET_BATCH_GROW 256
/* arena size for read key allocation (4KB) */
#define TDB_TXN_READ_KEY_ARENA_SIZE 4096
/* initial arena array capacity */
#define TDB_TXN_READ_KEY_ARENA_INITIAL_CAPACITY 4
/* initial capacity for active txn list */
#define TDB_ACTIVE_TXN_INITIAL_CAPACITY 1024
/* hash table capacity for write set (power of 2) */
#define TDB_WRITE_SET_HASH_CAPACITY 2048
/* hash table capacity for read set (power of 2) */
#define TDB_READ_SET_HASH_CAPACITY 2048
/* empty slot marker for write set hash */
#define TDB_WRITE_SET_HASH_EMPTY (-1)
/* empty slot marker for read set hash */
#define TDB_READ_SET_HASH_EMPTY (-1)
/* xxhash seed for transaction hash tables */
#define TDB_TXN_HASH_SEED 0x9e3779b9
/* max linear probe attempts before giving up */
#define TDB_TXN_MAX_PROBE_LENGTH 32

#define TDB_TXN_DEDUP_SKIP_THRESHOLD  8    /* skip dedup hash for txns with fewer ops */
#define TDB_TXN_DEDUP_MIN_HASH_SIZE   64   /* minimum hash size when dedup is used */
#define TDB_TXN_DEDUP_HASH_MULTIPLIER 2    /* hash size = num_ops * multiplier */
#define TDB_TXN_DEDUP_MAX_TRACKED     1024 /* max slots to track for fast iteration */
#define TDB_MAX_TXN_OPS_BEFORE_BATCH  10   /* use batch methods when ops exceed this threshold */

/* flush and close retry configuration */
#define TDB_FLUSH_ENQUEUE_MAX_ATTEMPTS         100
#define TDB_FLUSH_ENQUEUE_BACKOFF_US           10000
#define TDB_FLUSH_RETRY_DELAY_US               100000
#define TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS      100
#define TDB_CLOSE_FLUSH_WAIT_SLEEP_US          10000
#define TDB_CLOSE_TXN_WAIT_SLEEP_US            1000
#define TDB_COMPACTION_FLUSH_WAIT_SLEEP_US     10000
#define TDB_COMPACTION_FLUSH_WAIT_MAX_ATTEMPTS 100
#define TDB_OPENING_WAIT_MAX_MS                100
#define TDB_MAX_FFLUSH_RETRY_ATTEMPTS          5
#define TDB_FLUSH_RETRY_BACKOFF_US             100000
#define TDB_SHUTDOWN_BROADCAST_ATTEMPTS        10
#define TDB_SHUTDOWN_BROADCAST_INTERVAL_US     5000

/* sstable reaper thread configuration */
#define TDB_SSTABLE_REAPER_SLEEP_US    100000
#define TDB_SSTABLE_REAPER_EVICT_RATIO 0.25

/* immutable memtable cleanup configuration
 * cleanup runs frequently to prevent memory exhaustion from old immutables
 * only flushed immutables with no active readers are removed (safe cleanup) */
#define TDB_IMMUTABLE_CLEANUP_THRESHOLD      2       /* check every 2 flushes */
#define TDB_IMMUTABLE_MAX_QUEUE_SIZE         4       /* trigger cleanup when queue > 4 */
#define TDB_IMMUTABLE_FORCE_CLEANUP_SIZE     8       /* force blocking cleanup at this size */
#define TDB_IMMUTABLE_FORCE_CLEANUP_SPIN_US  100     /* spin interval when waiting for readers */
#define TDB_IMMUTABLE_FORCE_CLEANUP_MAX_WAIT 1000000 /* max 1 second wait per immutable */

/* refcount drain configuration for flush worker
 * used when waiting for in-flight writers to finish before flushing memtable */
#define TDB_REFCOUNT_DRAIN_SPIN_THRESHOLD  64     /* spin with cpu_pause up to this count */
#define TDB_REFCOUNT_DRAIN_YIELD_THRESHOLD 1024   /* yield up to this count, then sleep */
#define TDB_REFCOUNT_DRAIN_SLEEP_US        10     /* sleep interval after yield threshold */
#define TDB_REFCOUNT_DRAIN_LOG_INTERVAL    0xFFFF /* log warning every ~64K iterations */
#define TDB_REFCOUNT_DRAIN_BASELINE        2      /* baseline refcount -- 1 original + 1 work ref */

/* default L0/L1 management configuration */
#define TDB_DEFAULT_L1_FILE_COUNT_TRIGGER    4
#define TDB_DEFAULT_L0_QUEUE_STALL_THRESHOLD 20

/* backpressure timing configuration
 * */
#define TDB_BACKPRESSURE_STALL_CHECK_INTERVAL_US  10000 /* 10ms between stall checks */
#define TDB_BACKPRESSURE_STALL_MAX_ITERATIONS     1000  /* max 10 seconds stall */
#define TDB_BACKPRESSURE_HIGH_DELAY_US            2000  /* 2ms for high pressure (was 5ms) */
#define TDB_BACKPRESSURE_MODERATE_DELAY_US        500   /* 0.5ms for moderate pressure (was 1ms) */
#define TDB_BACKPRESSURE_HIGH_THRESHOLD_RATIO     0.8   /* 80% of stall threshold (was 60%) */
#define TDB_BACKPRESSURE_MODERATE_THRESHOLD_RATIO 0.5   /* 50% of stall threshold (was 30%) */
#define TDB_BACKPRESSURE_L1_HIGH_MULTIPLIER       4     /* 4x L1 trigger = high  */
#define TDB_BACKPRESSURE_L1_MODERATE_MULTIPLIER   3     /* 3x L1 trigger = moderate */

/* time conversion constants for pthread_cond_timedwait */
#define TDB_MICROSECONDS_PER_SECOND     1000000
#define TDB_NANOSECONDS_PER_SECOND      1000000000
#define TDB_NANOSECONDS_PER_MICROSECOND 1000

#define TDB_MAX_TXN_CFS                         256
#define TDB_MAX_PATH_LEN                        4096
#define TDB_MAX_TXN_OPS                         100000
#define TDB_MEMORY_PERCENTAGE                   0.6
#define TDB_MIN_KEY_VALUE_SIZE                  (1024 * 1024)
#define TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY 32
#define TDB_DISK_SPACE_CHECK_INTERVAL_SECONDS   60
#define TDB_NO_CF_SYNC_SLEEP_US                 100000

/* klog block configuration */
#define TDB_KLOG_BLOCK_INITIAL_CAPACITY 512

/* block index validation */
#define TDB_BLOCK_INDEX_PREFIX_MIN 4
#define TDB_BLOCK_INDEX_PREFIX_MAX 256
#define TDB_BLOCK_INDEX_MAX_COUNT  1000000

/* merge and serialization configuration */
#define TDB_MERGE_MIN_ESTIMATED_ENTRIES 100
#define TDB_KLOG_DELTA_SEQ_MAX_DIFF     1000000

/* iterator seek configuration */
/* max blocks to scan during seek */
#define TDB_ITER_SEEK_MAX_BLOCKS_SCAN 100000

#define TDB_COMMIT_STATUS_BUFFER_SIZE 65536

/* uint32_t max value */
#define TDB_MAX_KEY_VALUE_SIZE UINT32_MAX

/**
 * tidesdb_klog_entry_t
 * entry in klog block
 * @param flags entry flags (tombstone, ttl, vlog, delta_seq)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live timestamp
 * @param seq sequence number
 * @param vlog_offset offset in vlog file (0 if inline)
 */
typedef struct
{
    uint8_t flags;
    uint32_t key_size;
    uint32_t value_size;
    int64_t ttl;
    uint64_t seq;
    uint64_t vlog_offset;
} tidesdb_klog_entry_t;

/**
 * tidesdb_cached_entry_t
 * cached entry structure for lock-free block cache
 * stores deserialized, decompressed entry with key and value/vlog_offset
 * @param flags entry flags (tombstone, ttl, vlog, delta_seq)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes (actual value size, not inline size)
 * @param ttl time-to-live timestamp
 * @param seq sequence number
 * @param vlog_offset offset in vlog file (0 if inline, >0 if in vlog)
 * @param data flexible array [key_data][value_data if inline]
 */
typedef struct
{
    uint8_t flags;
    uint32_t key_size;
    uint32_t value_size;
    int64_t ttl;
    uint64_t seq;
    uint64_t vlog_offset;
#ifdef _MSC_VER
    uint8_t data[1]; /* MSVC requires size 1 */
#else
    uint8_t data[]; /* flexible array */
#endif
} tidesdb_cached_entry_t;

/**
 * tidesdb_multi_cf_txn_metadata_t
 * metadata for multi-cf transaction entries
 * written before klog_entry when entry has multi-cf flag
 * @param num_participant_cfs number of column families in transaction
 * @param checksum xxhash64 checksum of num_participant_cfs + cf_names
 * followed by char cf_names[num_participant_cfs][TDB_MAX_CF_NAME_LEN] (null-terminated cf names)
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
 * @param capacity allocated capacity for arrays
 * @param is_arena_allocated 1 if arena-allocated (deserialized), 0 if separate mallocs (created)
 * @param entries array of entries
 * @param keys array of key data
 * @param inline_values array of inline values (null if in vlog)
 * @param max_key maximum key in this block
 * @param max_key_size size of maximum key
 */
typedef struct
{
    uint32_t num_entries;
    uint32_t block_size;
    uint32_t capacity;
    uint8_t is_arena_allocated;
    tidesdb_klog_entry_t *entries;
    uint8_t **keys;
    uint8_t **inline_values;
    uint8_t *max_key;
    size_t max_key_size;
} tidesdb_klog_block_t;

/**
 * tidesdb_block_index_t
 * compact block index for fast key lookups
 * stores min/max key prefixes and file positions for each block
 * @param min_key_prefixes array of minimum key prefixes
 * @param max_key_prefixes array of maximum key prefixes
 * @param file_positions array of file positions for each block
 * @param count number of blocks indexed
 * @param capacity capacity of arrays
 * @param prefix_len length of key prefix stored
 * @param comparator comparator function for key ordering
 * @param comparator_ctx comparator context
 */
struct tidesdb_block_index_t
{
    uint8_t *min_key_prefixes;
    uint8_t *max_key_prefixes;
    uint64_t *file_positions;
    uint32_t count;
    uint32_t capacity;
    uint8_t prefix_len;
    tidesdb_comparator_fn comparator;
    void *comparator_ctx;
};

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
 * key-value pair
 * @param entry klog entry
 * @param key key data
 * @param value value data
 */
struct tidesdb_kv_pair_t
{
    tidesdb_klog_entry_t entry;
    uint8_t *key;
    uint8_t *value;
};

#define TDB_COMMIT_STATUS_IN_PROGRESS 0
#define TDB_COMMIT_STATUS_COMMITTED   1

/**
 * tidesdb_commit_status_t
 * @param status array of commit statuses (0=in-progress, 1=committed)
 * @param min_seq minimum sequence number tracked in this buffer
 * @param max_seq maximum sequence number tracked in this buffer
 * @param capacity size of the status array
 */
struct tidesdb_commit_status_t
{
    _Atomic(uint8_t) *status;
    _Atomic(uint64_t) min_seq;
    _Atomic(uint64_t) max_seq;
    size_t capacity;
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
struct tidesdb_txn_op_t
{
    uint8_t *key;
    size_t key_size;
    uint8_t *value;
    size_t value_size;
    time_t ttl;
    int is_delete;
    tidesdb_column_family_t *cf;
};

/* forward declaration for ref-counted block type */
typedef struct tidesdb_ref_counted_block_t tidesdb_ref_counted_block_t;

/**
 * tidesdb_merge_source_t
 * is a source for merging (memtable, sstable, or transaction write buffer)
 * @param type type of source (memtable, sstable, btree, or txn_ops)
 * @param source union of source-specific state
 * @param current_kv current key-value pair
 * @param config column family configuration
 * @param is_cached if 1, dont free when popped from heap (for iterators)
 */
typedef struct
{
    enum
    {
        MERGE_SOURCE_MEMTABLE,
        MERGE_SOURCE_SSTABLE,
        MERGE_SOURCE_BTREE,
        MERGE_SOURCE_TXN_OPS
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
            block_manager_cursor_t *vlog_cursor;
            tidesdb_klog_block_t *current_block;
            block_manager_block_t *current_block_data;
            tidesdb_ref_counted_block_t *current_rc_block;
            uint8_t *decompressed_data;
            int current_entry_idx;
        } sstable;

        struct
        {
            tidesdb_t *db;
            tidesdb_sstable_t *sst;
            btree_cursor_t *cursor;
            block_manager_cursor_t *vlog_cursor;
        } btree;

        /* transaction write buffer source for read-your-own-writes
         * sorted_indices is an array of indices into txn->ops, sorted by key
         * and deduplicated (last write per key wins) */
        struct
        {
            tidesdb_txn_t *txn;
            tidesdb_column_family_t *cf;
            int *sorted_indices;
            int count;
            int pos;
        } txn_ops;
    } source;

    tidesdb_kv_pair_t *current_kv;
    tidesdb_column_family_config_t *config;
    int is_cached;
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
struct tidesdb_merge_heap_t
{
    tidesdb_merge_source_t **sources;
    int num_sources;
    int capacity;
    skip_list_comparator_fn comparator;
    void *comparator_ctx;
};

/**
 * tidesdb_commit_status_create
 * creates a new commit status tracker
 * @return commit status tracker or NULL on error
 */
static tidesdb_commit_status_t *tidesdb_commit_status_create()
{
    tidesdb_commit_status_t *cs = malloc(sizeof(tidesdb_commit_status_t));
    if (!cs) return NULL;

    cs->status = malloc(TDB_COMMIT_STATUS_BUFFER_SIZE * sizeof(_Atomic(uint8_t)));
    if (!cs->status)
    {
        free(cs);
        return NULL;
    }

    /* init all slots as in-progress (will be updated as txns complete) */
    for (size_t i = 0; i < TDB_COMMIT_STATUS_BUFFER_SIZE; i++)
    {
        atomic_init(&cs->status[i], TDB_COMMIT_STATUS_IN_PROGRESS);
    }

    atomic_init(&cs->min_seq, 1);
    atomic_init(&cs->max_seq, 0);
    cs->capacity = TDB_COMMIT_STATUS_BUFFER_SIZE;

    return cs;
}

/**
 * tidesdb_commit_status_destroy
 * destroys a commit status tracker
 * @param cs commit status tracker
 */
static void tidesdb_commit_status_destroy(tidesdb_commit_status_t *cs)
{
    if (!cs) return;
    free((void *)cs->status);
    free(cs);
}

/**
 * tidesdb_commit_status_mark
 * marks a sequence as committed
 * @param cs commit status tracker
 * @param seq sequence number
 * @param status TDB_COMMIT_STATUS_COMMITTED or TDB_COMMIT_STATUS_IN_PROGRESS
 */
static void tidesdb_commit_status_mark(tidesdb_commit_status_t *cs, uint64_t seq, uint8_t status)
{
    if (!cs || seq == 0) return;

    uint64_t current_max = atomic_load_explicit(&cs->max_seq, memory_order_acquire);
    while (seq > current_max)
    {
        if (atomic_compare_exchange_weak_explicit(&cs->max_seq, &current_max, seq,
                                                  memory_order_release, memory_order_acquire))
        {
            break; /* successfully updated */
        }
        /* CAS failed, current_max was updated by atomic_compare_exchange_weak, retry */
    }

    size_t idx = seq % cs->capacity;
    atomic_store_explicit(&cs->status[idx], status, memory_order_release);
}

/**
 * tidesdb_visibility_check_callback
 * callback for skip list to check if a sequence is committed
 * used by skip_list_get_with_seq for visibility determination
 * @param opaque_ctx commit_status pointer (cast from void*)
 * @param seq sequence number to check
 * @return 1 if committed, 0 otherwise
 */
static int tidesdb_visibility_check_callback(void *opaque_ctx, const uint64_t seq)
{
    if (!opaque_ctx || seq == 0) return 0;

    tidesdb_commit_status_t *cs = (tidesdb_commit_status_t *)opaque_ctx;

    /* we map seq to circular buffer index */
    const size_t idx = seq % cs->capacity;
    uint8_t status = atomic_load_explicit(&cs->status[idx], memory_order_acquire);

    /* only COMMITTED versions are visible */
    return (status == TDB_COMMIT_STATUS_COMMITTED);
}

/**
 * encode_varint
 * encode uint64_t as varint (1-10 bytes)
 * @param buf output buffer (must have at least 10 bytes)
 * @param value value to encode
 * @return number of bytes written
 */
static inline int encode_varint(uint8_t *buf, uint64_t value)
{
    int pos = 0;
    while (value >= 0x80)
    {
        buf[pos++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    buf[pos++] = (uint8_t)value;
    return pos;
}

/**
 * decode_varint
 * decode varint to uint64_t
 * @param buf input buffer
 * @param value output value
 * @param max_bytes maximum bytes to read (bounds check)
 * @return number of bytes read, or -1 on error
 */
static inline int decode_varint(const uint8_t *buf, uint64_t *value, const int max_bytes)
{
    if (TDB_UNLIKELY(max_bytes <= 0)) return -1;

    /* fast path for 1-byte varints (values < 128) -- most common case */
    if (TDB_LIKELY(!(buf[0] & 0x80)))
    {
        *value = buf[0];
        return 1;
    }

    /* slow path for multi-byte varints */
    *value = (uint64_t)(buf[0] & 0x7F);
    int shift = 7;
    int pos = 1;

    while (pos < max_bytes)
    {
        const uint8_t byte = buf[pos++];
        *value |= (uint64_t)(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0)
        {
            return pos; /* success */
        }

        shift += 7;
        if (shift >= 64)
        {
            return -1; /* oflow */
        }
    }

    return -1; /* incomplete varint */
}

/**
 * tdb_parse_wal_id
 * parse WAL ID from filename like "wal_12345.log"
 * @param filename the filename to parse
 * @param id output WAL ID
 * @return 1 on success, 0 on failure
 */
static int tdb_parse_wal_id(const char *filename, uint64_t *id)
{
    if (!filename || !id) return 0;

    const size_t prefix_len = strlen(TDB_WAL_PREFIX);
    if (strncmp(filename, TDB_WAL_PREFIX, prefix_len) != 0) return 0;

    const char *p = filename + prefix_len;
    char *endptr;

    const unsigned long long val = strtoull(p, &endptr, 10);
    if (endptr == p) return 0;

    if (strcmp(endptr, TDB_WAL_EXT) != 0) return 0;

    *id = (uint64_t)val;
    return 1;
}

/**
 * tdb_parse_level_num
 * parse level number from filename like "L5_..."
 * @param filename the filename to parse
 * @param level_num output level number
 * @return 1 on success, 0 on failure
 */
static int tdb_parse_level_num(const char *filename, int *level_num)
{
    if (!filename || !level_num) return 0;

    const size_t prefix_len = strlen(TDB_LEVEL_PREFIX);
    if (strncmp(filename, TDB_LEVEL_PREFIX, prefix_len) != 0) return 0;

    const char *p = filename + prefix_len;
    char *endptr;
    const long val = strtol(p, &endptr, 10);
    if (endptr == p) return 0;

    *level_num = (int)val;
    return 1;
}

/**
 * tdb_parse_sstable_non_partitioned
 * parse non-partitioned sstable filename like "L5_12345.klog"
 * @param filename the filename to parse
 * @param level_num output level number
 * @param sst_id output sstable id
 * @return 1 on success, 0 on failure
 */
static int tdb_parse_sstable_non_partitioned(const char *filename, int *level_num,
                                             unsigned long long *sst_id)
{
    if (!filename || !level_num || !sst_id) return 0;

    const size_t prefix_len = strlen(TDB_LEVEL_PREFIX);
    if (strncmp(filename, TDB_LEVEL_PREFIX, prefix_len) != 0) return 0;

    const char *p = filename + prefix_len;
    char *endptr;
    const long level = strtol(p, &endptr, 10);
    if (endptr == p || *endptr != '_') return 0;

    p = endptr + 1;
    const unsigned long long id = strtoull(p, &endptr, 10);
    if (endptr == p) return 0;

    if (strcmp(endptr, TDB_SSTABLE_KLOG_EXT) != 0) return 0;

    *level_num = (int)level;
    *sst_id = id;
    return 1;
}

/**
 * tdb_parse_sstable_partitioned
 * parse partitioned sstable filename like "L5P2_12345.klog"
 * @param filename the filename to parse
 * @param level_num output level number
 * @param partition_num output partition number
 * @param sst_id output sstable id
 * @return 1 on success, 0 on failure
 */
static int tdb_parse_sstable_partitioned(const char *filename, int *level_num, int *partition_num,
                                         unsigned long long *sst_id)
{
    if (!filename || !level_num || !partition_num || !sst_id) return 0;

    const size_t level_prefix_len = strlen(TDB_LEVEL_PREFIX);
    if (strncmp(filename, TDB_LEVEL_PREFIX, level_prefix_len) != 0) return 0;

    const char *p = filename + level_prefix_len;
    char *endptr;
    const long level = strtol(p, &endptr, 10);
    if (endptr == p) return 0;

    const size_t partition_prefix_len = strlen(TDB_LEVEL_PARTITION_PREFIX);
    if (strncmp(endptr, TDB_LEVEL_PARTITION_PREFIX, partition_prefix_len) != 0) return 0;

    p = endptr + partition_prefix_len;
    const long partition = strtol(p, &endptr, 10);
    if (endptr == p || *endptr != '_') return 0;

    p = endptr + 1;
    const unsigned long long id = strtoull(p, &endptr, 10);
    if (endptr == p) return 0;

    if (strcmp(endptr, TDB_SSTABLE_KLOG_EXT) != 0) return 0;

    *level_num = (int)level;
    *partition_num = (int)partition;
    *sst_id = id;
    return 1;
}

static tidesdb_klog_block_t *tidesdb_klog_block_create(void);
static void tidesdb_klog_block_free(tidesdb_klog_block_t *block);
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        const tidesdb_column_family_config_t *config,
                                        skip_list_comparator_fn comparator_fn,
                                        void *comparator_ctx);
static int tidesdb_klog_block_is_full(const tidesdb_klog_block_t *block, size_t max_size);
static int tidesdb_klog_block_serialize(tidesdb_klog_block_t *block, uint8_t **out,
                                        size_t *out_size);
static int tidesdb_klog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_klog_block_t **block);

/**
 * tidesdb_block_managers_t
 * temporary structure to hold block manager pointers retrieved from cache
 * @param klog_bm klog block manager
 * @param vlog_bm value log block manager
 */
typedef struct
{
    block_manager_t *klog_bm;
    block_manager_t *vlog_bm;
} tidesdb_block_managers_t;

static int tidesdb_sstable_get_block_managers(const tidesdb_t *db, tidesdb_sstable_t *sst,
                                              tidesdb_block_managers_t *bms);
static int tidesdb_vlog_read_value(const tidesdb_t *db, tidesdb_sstable_t *sst,
                                   uint64_t vlog_offset, size_t value_size, uint8_t **value);
static tidesdb_sstable_t *tidesdb_sstable_create(tidesdb_t *db, const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config);
static void tidesdb_sstable_free(tidesdb_sstable_t *sst);

static void compact_block_index_free(tidesdb_block_index_t *index);
static int compact_block_index_find_predecessor(const tidesdb_block_index_t *index,
                                                const uint8_t *key, size_t key_len,
                                                uint64_t *file_position);
static int compact_block_index_add(tidesdb_block_index_t *index, const uint8_t *min_key,
                                   size_t min_key_len, const uint8_t *max_key, size_t max_key_len,
                                   uint64_t file_position);
static tidesdb_block_index_t *compact_block_index_create(uint32_t initial_capacity,
                                                         uint8_t prefix_len,
                                                         tidesdb_comparator_fn comparator,
                                                         void *comparator_ctx);
static uint8_t *compact_block_index_serialize(const tidesdb_block_index_t *index, size_t *out_size);
static tidesdb_block_index_t *compact_block_index_deserialize(const uint8_t *data,
                                                              size_t data_size);
static void tidesdb_sstable_ref(tidesdb_sstable_t *sst);
static int tidesdb_sstable_try_ref(tidesdb_sstable_t *sst);
static void tidesdb_sstable_unref(const tidesdb_t *db, tidesdb_sstable_t *sst);
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable);
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               size_t key_size, tidesdb_kv_pair_t **kv);
static int tidesdb_sstable_load(tidesdb_t *db, tidesdb_sstable_t *sst);
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity);
static void tidesdb_level_free(const tidesdb_t *db, tidesdb_level_t *level);
static int tidesdb_level_add_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst);
static int tidesdb_level_remove_sstable(const tidesdb_t *db, tidesdb_level_t *level,
                                        tidesdb_sstable_t *sst);
static int tidesdb_level_update_boundaries(tidesdb_level_t *level, tidesdb_level_t *largest_level);
static tidesdb_merge_heap_t *tidesdb_merge_heap_create(skip_list_comparator_fn comparator,
                                                       void *comparator_ctx);
static void tidesdb_merge_heap_free(tidesdb_merge_heap_t *heap);
static int tidesdb_merge_heap_add_source(tidesdb_merge_heap_t *heap,
                                         tidesdb_merge_source_t *source);
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap,
                                                 tidesdb_sstable_t **corrupted_sst);
static int tidesdb_merge_heap_empty(const tidesdb_merge_heap_t *heap);
static tidesdb_merge_source_t *tidesdb_merge_source_from_memtable(
    skip_list_t *memtable, tidesdb_column_family_config_t *config,
    tidesdb_immutable_memtable_t *imm);
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable_klog(tidesdb_t *db,
                                                                      tidesdb_sstable_t *sst);
static tidesdb_merge_source_t *tidesdb_merge_source_from_btree(tidesdb_t *db,
                                                               tidesdb_sstable_t *sst);
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable(tidesdb_t *db,
                                                                 tidesdb_sstable_t *sst);
static void tidesdb_merge_source_free(tidesdb_merge_source_t *source);
static int tidesdb_merge_source_advance(tidesdb_merge_source_t *source);
static int tidesdb_merge_source_retreat(tidesdb_merge_source_t *source);
static int tidesdb_full_preemptive_merge(tidesdb_column_family_t *cf, int start_level,
                                         int target_level);
static int tidesdb_dividing_merge(tidesdb_column_family_t *cf, int target_level);
static int tidesdb_partitioned_merge(tidesdb_column_family_t *cf, int start_level, int end_level);
static int tidesdb_sstable_write_from_heap_btree(tidesdb_column_family_t *cf,
                                                 tidesdb_sstable_t *sst, tidesdb_merge_heap_t *heap,
                                                 block_manager_t *klog_bm, block_manager_t *vlog_bm,
                                                 bloom_filter_t *bloom, queue_t *sstables_to_delete,
                                                 int is_largest_level);
static int tidesdb_trigger_compaction(tidesdb_column_family_t *cf);
static int tidesdb_wal_recover(tidesdb_column_family_t *cf, const char *wal_path,
                               skip_list_t **memtable);
static size_t tidesdb_calculate_level_capacity(int level_num, size_t base_capacity, size_t ratio);

static int tidesdb_add_level(tidesdb_column_family_t *cf);
static int tidesdb_remove_level(tidesdb_column_family_t *cf);
static int tidesdb_apply_dca(tidesdb_column_family_t *cf);
static int tidesdb_recover_database(tidesdb_t *db);
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf);
static void tidesdb_column_family_free(tidesdb_column_family_t *cf);
static void *tidesdb_flush_worker_thread(void *arg);
static void *tidesdb_compaction_worker_thread(void *arg);
static void *tidesdb_sync_worker_thread(void *arg);
static void *tidesdb_sstable_reaper_thread(void *arg);
static tidesdb_kv_pair_t *tidesdb_kv_pair_create(const uint8_t *key, size_t key_size,
                                                 const uint8_t *value, size_t value_size,
                                                 time_t ttl, uint64_t seq, int is_tombstone);
static void tidesdb_kv_pair_free(tidesdb_kv_pair_t *kv);
static tidesdb_kv_pair_t *tidesdb_kv_pair_clone(const tidesdb_kv_pair_t *kv);
static int tidesdb_iter_kv_visible(tidesdb_iter_t *iter, tidesdb_kv_pair_t *kv);
static int tidesdb_sstable_ensure_open(tidesdb_t *db, tidesdb_sstable_t *sst);
static int wait_for_open(tidesdb_t *db);

/**
 * tidesdb_ref_counted_block_t
 * reference-counted wrapper for deserialized blocks (thread-safe shared access)
 * @member block pointer to deserialized block
 * @member ref_count number of active references
 * @member block_memory memory footprint for accounting
 */
struct tidesdb_ref_counted_block_t
{
    tidesdb_klog_block_t *block;
    atomic_int ref_count;
    size_t block_memory;
};

/**
 * tidesdb_block_acquire
 * increment reference count when accessing a cached block
 * @param rc_block block to acquire
 */
static void tidesdb_block_acquire(tidesdb_ref_counted_block_t *rc_block)
{
    if (rc_block)
    {
        atomic_fetch_add_explicit(&rc_block->ref_count, 1, memory_order_relaxed);
    }
}

/**
 * tidesdb_block_release
 * decrement reference count and free if no more references
 * @param rc_block block to release
 */
static void tidesdb_block_release(tidesdb_ref_counted_block_t *rc_block)
{
    if (!rc_block) return;

    int old_count = atomic_fetch_sub_explicit(&rc_block->ref_count, 1, memory_order_release);
    if (old_count == 1)
    {
        /* last reference released, safe to free */
        atomic_thread_fence(memory_order_acquire);
        if (rc_block->block)
        {
            tidesdb_klog_block_free(rc_block->block);
        }
        free(rc_block);
    }
}

/**
 * tidesdb_cache_evict_block
 * eviction callback -- only free if ref_count is 0
 * @param payload pointer to block to free
 * @param payload_len size of payload
 */
static void tidesdb_cache_evict_block(void *payload, const size_t payload_len)
{
    if (!payload || payload_len != sizeof(tidesdb_ref_counted_block_t *)) return;

    tidesdb_ref_counted_block_t *rc_block = *(tidesdb_ref_counted_block_t **)payload;
    if (rc_block)
    {
        /* release cache's reference */
        tidesdb_block_release(rc_block);
    }
}

/**
 * tidesdb_block_cache_key
 * generate a cache key for a block
 * @param cf_name column family name
 * @param klog_path path to klog file
 * @param block_position position of block in klog
 * @param key_buffer buffer to store the cache key
 * @param buffer_size size of key_buffer
 * @return length of the generated key, 0 on error
 *
 * format "cf_name:filename:block_position"
 * example "users:L2P3_1336.klog:0", "users:L2P3_1337.klog:65536"
 * eses filename instead of full path for shorter cache keys
 */
static size_t tidesdb_block_cache_key(const char *cf_name, const char *klog_path,
                                      const uint64_t block_position, char *key_buffer,
                                      const size_t buffer_size)
{
    if (!cf_name || !klog_path || !key_buffer || buffer_size == 0) return 0;

    /* we extract filename from path (cross-platform) */
    const char *filename = strrchr(klog_path, '/');
    if (!filename) filename = strrchr(klog_path, '\\');
    filename = filename ? filename + 1 : klog_path;

    /* format is "cf_name:filename:block_position" */
    const int len = snprintf(key_buffer, buffer_size, "%s:%s:%llu", cf_name, filename,
                             (unsigned long long)block_position);
    if (len < 0 || (size_t)len >= buffer_size) return 0;

    return (size_t)len;
}

/**
 * tidesdb_cache_block_put
 * caches deserialized block with reference counting (zero-copy on cache hit!)
 * @param db the database
 * @param cf_name column family name
 * @param klog_path path to klog file
 * @param block_position position of block in file
 * @param block_data raw decompressed block data (serialized klog block)
 * @param block_size size of block data
 * @return 0 on success, -1 on failure
 */
static int tidesdb_cache_block_put(tidesdb_t *db, const char *cf_name, const char *klog_path,
                                   const uint64_t block_position, const void *block_data,
                                   const size_t block_size)
{
    if (!db || !db->clock_cache || !cf_name || !klog_path || !block_data || block_size == 0)
        return -1;

    char cache_key[TDB_CACHE_KEY_SIZE];
    const size_t key_len =
        tidesdb_block_cache_key(cf_name, klog_path, block_position, cache_key, sizeof(cache_key));
    if (key_len == 0) return -1;

    tidesdb_klog_block_t *block = NULL;
    if (tidesdb_klog_block_deserialize(block_data, block_size, &block) != 0 || !block) return -1;

    tidesdb_ref_counted_block_t *rc_block = malloc(sizeof(tidesdb_ref_counted_block_t));
    if (!rc_block)
    {
        tidesdb_klog_block_free(block);
        return -1;
    }

    rc_block->block = block;
    atomic_init(&rc_block->ref_count, 1); /* cache holds 1 reference */
    rc_block->block_memory = sizeof(tidesdb_klog_block_t) +
                             (block->num_entries * sizeof(tidesdb_klog_entry_t)) +
                             (block->num_entries * sizeof(uint8_t *) * 2) + block->block_size;

    /* we cache pointer to ref-counted block */
    const int result = clock_cache_put(db->clock_cache, cache_key, key_len, &rc_block,
                                       sizeof(tidesdb_ref_counted_block_t *));
    if (result != 0)
    {
        tidesdb_klog_block_free(block);
        free(rc_block);
    }
    return result;
}

/**
 * tidesdb_cache_block_get
 * retrieves cached ref-counted block (zero-copy, just increment ref count!)
 * @param db the database
 * @param cf_name column family name
 * @param klog_path path to klog file
 * @param block_position position of block in file
 * @param rc_block_out output parameter for ref-counted block (caller must release!)
 * @return deserialized klog block if found, NULL otherwise (do not free, call
 * tidesdb_block_release on rc_block_out)
 */
static tidesdb_klog_block_t *tidesdb_cache_block_get(tidesdb_t *db, const char *cf_name,
                                                     const char *klog_path,
                                                     const uint64_t block_position,
                                                     tidesdb_ref_counted_block_t **rc_block_out)
{
    if (!db || !db->clock_cache || !cf_name || !klog_path || !rc_block_out) return NULL;

    char cache_key[TDB_CACHE_KEY_SIZE];
    const size_t key_len =
        tidesdb_block_cache_key(cf_name, klog_path, block_position, cache_key, sizeof(cache_key));
    if (key_len == 0) return NULL;

    size_t payload_len = 0;
    clock_cache_entry_t *cache_entry = NULL;
    const void *payload =
        clock_cache_get_zero_copy(db->clock_cache, cache_key, key_len, &payload_len, &cache_entry);

    if (!payload || payload_len != sizeof(tidesdb_ref_counted_block_t *))
    {
        if (cache_entry) clock_cache_release(cache_entry);
        return NULL;
    }

    /* we extract ref-counted block pointer */
    tidesdb_ref_counted_block_t *rc_block = *(tidesdb_ref_counted_block_t *const *)payload;

    /* we release cache entry ref_bit now that we've read the pointer */
    clock_cache_release(cache_entry);

    if (!rc_block || !rc_block->block) return NULL;

    tidesdb_block_acquire(rc_block);
    *rc_block_out = rc_block;

    return rc_block->block;
}

/**
 * tidesdb_get_cf_name_from_path
 * extracts column family name from sstable path
 * @param path the sstable path (e.g., "/path/to/cf_name/L2P3_1337.klog")
 * @param cf_name_out buffer to store CF name (must be at least TDB_CACHE_KEY_SIZE bytes)
 * @return 0 on success, -1 on failure
 *
 * this method handles both '/' and '\\' separators for cross-platform portability.
 * a database created on linux (using '/') must be readable on windows (using '\\') and vice versa.
 */
static int tidesdb_get_cf_name_from_path(const char *path, char *cf_name_out)
{
    if (!path || !cf_name_out) return -1;
    const char sep_unix = '/';
    const char sep_windows = '\\';

    /* we find the last directory separator (check both types for portability) */
    const char *last_slash = strrchr(path, sep_unix);
    const char *last_backslash = strrchr(path, sep_windows);
    const char *last_sep = (last_slash > last_backslash) ? last_slash : last_backslash;
    if (!last_sep) return -1;

    /* we find the second-to-last directory separator */
    const char *second_last_sep = last_sep - 1;
    while (second_last_sep > path && *second_last_sep != sep_unix &&
           *second_last_sep != sep_windows)
    {
        second_last_sep--;
    }

    if (*second_last_sep != sep_unix && *second_last_sep != sep_windows) return -1;
    size_t cf_name_len = last_sep - second_last_sep - 1;
    if (cf_name_len >= TDB_CACHE_KEY_SIZE) cf_name_len = TDB_CACHE_KEY_SIZE - 1;

    memcpy(cf_name_out, second_last_sep + 1, cf_name_len);
    cf_name_out[cf_name_len] = '\0';

    return 0;
}

/**
 * tidesdb_read_block
 * reads and decompresses a block from disk
 * @param db the database
 * @param sst the sstable (for compression config)
 * @param cursor the block manager cursor
 * @return the decompressed block if successful, NULL otherwise
 */
static block_manager_block_t *tidesdb_read_block(tidesdb_t *db, tidesdb_sstable_t *sst,
                                                 block_manager_cursor_t *cursor)
{
    if (!db || !sst || !cursor) return NULL;

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    if (!block) return NULL;

    if (sst->config && sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        size_t decompressed_size;
        uint8_t *decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                                sst->config->compression_algorithm);
        if (decompressed)
        {
            /* we replace compressed data with decompressed data in the block */
            free(block->data);
            block->data = decompressed;
            block->size = decompressed_size;
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Decompression failed for SSTable %s (id=%" PRIu64
                          ") "
                          "compression=%u block_size=%zu",
                          sst->klog_path ? sst->klog_path : "unknown", sst->id,
                          (unsigned int)sst->config->compression_algorithm, (size_t)block->size);
            block_manager_block_release(block);
            return NULL;
        }
    }

    return block;
}

/**
 * tidesdb_read_block_and_advance
 * reads, decompresses a block from disk, and advances cursor in one operation
 * more efficient than tidesdb_read_block + cursor_next as it avoids redundant pread
 * @param db the database
 * @param sst the sstable (for compression config)
 * @param cursor the block manager cursor (will be advanced)
 * @return the decompressed block if successful, NULL otherwise
 */
static block_manager_block_t *tidesdb_read_block_and_advance(tidesdb_t *db, tidesdb_sstable_t *sst,
                                                             block_manager_cursor_t *cursor)
{
    if (!db || !sst || !cursor) return NULL;

    block_manager_block_t *block = block_manager_cursor_read_and_advance(cursor);
    if (!block) return NULL;

    if (sst->config && sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        size_t decompressed_size;
        uint8_t *decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                                sst->config->compression_algorithm);
        if (decompressed)
        {
            free(block->data);
            block->data = decompressed;
            block->size = decompressed_size;
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Decompression failed for SSTable %s (id=%" PRIu64
                          ") compression=%u block_size=%zu",
                          sst->klog_path ? sst->klog_path : "unknown", sst->id,
                          (unsigned int)sst->config->compression_algorithm, (size_t)block->size);
            block_manager_block_release(block);
            return NULL;
        }
    }

    return block;
}

/**
 * tidesdb_check_disk_space
 * check if theres enough free disk space using cached value
 * refreshes cache every DISK_SPACE_CHECK_INTERVAL_SECONDS seconds to avoid expensive statvfs calls
 * @param db database handle
 * @param path directory path to check
 * @param min_required minimum required free space in bytes
 * @return 1 if enough space, 0 if not enough, -1 on error
 */
static int tidesdb_check_disk_space(tidesdb_t *db, const char *path, uint64_t min_required)
{
    if (!db) return -1;

    time_t now = atomic_load_explicit(&db->cached_current_time, memory_order_relaxed);
    time_t last_check = atomic_load_explicit(&db->last_disk_space_check, memory_order_relaxed);

    if (now - last_check >= TDB_DISK_SPACE_CHECK_INTERVAL_SECONDS)
    {
        uint64_t available;
        if (tdb_get_available_disk_space(path, &available) == 0)
        {
            atomic_store_explicit(&db->cached_available_disk_space, available,
                                  memory_order_relaxed);
            atomic_store_explicit(&db->last_disk_space_check, now, memory_order_relaxed);
        }
        else
        {
            return -1;
        }
    }

    uint64_t available =
        atomic_load_explicit(&db->cached_available_disk_space, memory_order_relaxed);
    return (available >= min_required) ? 1 : 0;
}

/**
 * tidesdb_validate_kv_size
 * validates that a key-value pair size does not exceed memory limits
 * maximum allowed size is max(available_memory * TDB_MEMORY_PERCENTAGE, TDB_MIN_KEY_VALUE_SIZE)
 * @param db database handle
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @return 0 if valid, TDB_ERR_MEMORY_LIMIT if too large
 */
static int tidesdb_validate_kv_size(tidesdb_t *db, const size_t key_size, const size_t value_size)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* we enforce architectural limit! all sizes are uint32_t */
    if (key_size > TDB_MAX_KEY_VALUE_SIZE)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "Key size (%zu bytes) exceeds TDB_MAX_KEY_VALUE_SIZE",
                      key_size);
        return TDB_ERR_INVALID_ARGS;
    }
    if (value_size > TDB_MAX_KEY_VALUE_SIZE)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "Value size (%zu bytes) exceeds TDB_MAX_KEY_VALUE_SIZE",
                      value_size);
        return TDB_ERR_INVALID_ARGS;
    }

    /* we check for overflow before doing addition */
    if (key_size > TDB_MAX_KEY_VALUE_SIZE - value_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "Total key+value size (key: %zu + value: %zu) exceeds TDB_MAX_KEY_VALUE_SIZE",
                      key_size, value_size);
        return TDB_ERR_INVALID_ARGS;
    }

    const size_t total_size = key_size + value_size;

    const uint64_t memory_based_limit =
        (uint64_t)((double)db->available_memory * TDB_MEMORY_PERCENTAGE);
    const uint64_t max_allowed_size =
        memory_based_limit > TDB_MIN_KEY_VALUE_SIZE ? memory_based_limit : TDB_MIN_KEY_VALUE_SIZE;

    if (total_size > max_allowed_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "Key-value pair size (%zu bytes) exceeds memory limit (%" PRIu64
                      " bytes, based on available memory: %" PRIu64 " bytes)",
                      total_size, max_allowed_size, (uint64_t)db->available_memory);
        return TDB_ERR_MEMORY_LIMIT;
    }

    return 0;
}

/**
 * sstable_metadata_header_t
 * @param magic magic number for validation
 * @param num_entries total number of entries
 * @param num_klog_blocks number of klog blocks
 * @param num_vlog_blocks number of vlog blocks
 * @param klog_size size of klog file
 * @param vlog_size size of vlog file
 * @param min_key_size size of min key
 * @param max_key_size size of max key
 * @param compression_algorithm compression algorithm used (0=none, 1=snappy, 2=lz4, 3=zstd,
 * 4=lz4_fast)
 * @param flags metadata flags (bit 0 = use_btree, bits 1-31 reserved)
 * @param checksum xxHash64 checksum of all fields except checksum itself
 *
 * if flags & SSTABLE_FLAG_BTREE is set, additional btree metadata follows after max_key:
 *   -- int64_t btree_root_offset
 *   -- int64_t btree_first_leaf
 *   -- int64_t btree_last_leaf
 *   -- uint64_t btree_node_count
 *   -- uint32_t btree_height
 */
typedef struct
{
    uint32_t magic;
    uint64_t num_entries;
    uint64_t num_klog_blocks;
    uint64_t num_vlog_blocks;
    uint64_t klog_size;
    uint64_t vlog_size;
    uint64_t min_key_size;
    uint64_t max_key_size;
    uint32_t compression_algorithm;
    uint32_t flags;
    uint64_t checksum;
} sstable_metadata_header_t;

/* sstable metadata flags */
#define SSTABLE_FLAG_BTREE 0x01 /* sstable uses btree format instead of klog blocks */

/**
 * sstable_metadata_serialize
 * @param sst sstable to serialize
 * @param out_data output data
 * @param out_size output size
 * @return 0 on success, -1 on failure
 */
static int sstable_metadata_serialize(tidesdb_sstable_t *sst, uint8_t **out_data, size_t *out_size)
{
    if (!sst || !out_data || !out_size) return -1;

    /* we calculate size -- header + keys + btree metadata (if applicable) + checksum */
    const size_t header_size = TDB_SSTABLE_METADATA_HEADER_SIZE;
    const size_t checksum_size = 8;

    /* btree metadata size -- root_offset(8) + first_leaf(8) + last_leaf(8) + node_count(8) +
     * height(4)
     */
    size_t btree_meta_size = 0;
    if (sst->use_btree)
    {
        btree_meta_size = 8 + 8 + 8 + 8 + 4;
    }

    const size_t total_size =
        header_size + sst->min_key_size + sst->max_key_size + btree_meta_size + checksum_size;

    uint8_t *data = malloc(total_size);
    if (!data) return -1;

    uint8_t *ptr = data;

    /* we serialize fields with explicit little-endian encoding */
    encode_uint32_le_compat(ptr, TDB_SSTABLE_METADATA_MAGIC);
    ptr += 4;
    encode_uint64_le_compat(ptr, sst->num_entries);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->num_klog_blocks);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->num_vlog_blocks);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->klog_data_end_offset);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->klog_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->vlog_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->min_key_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->max_key_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->max_seq); /* maximum sequence number */
    ptr += 8;
    encode_uint32_le_compat(ptr, sst->config->compression_algorithm);
    ptr += 4;

    /* flags field -- we set SSTABLE_FLAG_BTREE if using btree */
    uint32_t flags = 0;
    if (sst->use_btree)
    {
        flags |= SSTABLE_FLAG_BTREE;
    }
    encode_uint32_le_compat(ptr, flags);
    ptr += 4;

    if (sst->min_key && sst->min_key_size > 0)
    {
        memcpy(ptr, sst->min_key, sst->min_key_size);
        ptr += sst->min_key_size;
    }
    if (sst->max_key && sst->max_key_size > 0)
    {
        memcpy(ptr, sst->max_key, sst->max_key_size);
        ptr += sst->max_key_size;
    }

    /* btree metadata (if applicable) */
    if (sst->use_btree)
    {
        encode_int64_le_compat(ptr, sst->btree_root_offset);
        ptr += 8;
        encode_int64_le_compat(ptr, sst->btree_first_leaf);
        ptr += 8;
        encode_int64_le_compat(ptr, sst->btree_last_leaf);
        ptr += 8;
        encode_uint64_le_compat(ptr, sst->btree_node_count);
        ptr += 8;
        encode_uint32_le_compat(ptr, sst->btree_height);
        ptr += 4;
    }

    /* we compute and append checksum over everything except the checksum field itself */
    const size_t checksum_data_size = total_size - checksum_size;
    const uint64_t checksum = XXH64(data, checksum_data_size, 0);
    encode_uint64_le_compat(ptr, checksum);

    *out_data = data;
    *out_size = total_size;
    return 0;
}

/**
 * sstable_metadata_deserialize
 * deserialize sstable metadata
 * @param data data to deserialize
 * @param data_size data size
 * @param sst sstable to deserialize
 * @return 0 on success, -1 on failure
 */
static int sstable_metadata_deserialize(const uint8_t *data, const size_t data_size,
                                        tidesdb_sstable_t *sst)
{
    if (!data || !sst || data_size < 92) return -1;

    const uint8_t *ptr = data;

    const uint32_t magic = decode_uint32_le_compat(ptr);
    ptr += 4;

    if (magic != TDB_SSTABLE_METADATA_MAGIC)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "SSTable metadata has an invalid magic 0x%08x (expected 0x%08x)", magic,
                      TDB_SSTABLE_METADATA_MAGIC);
        return -1;
    }

    const uint64_t num_entries = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t num_klog_blocks = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t num_vlog_blocks = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t klog_data_end_offset = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t klog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t vlog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t min_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    const uint64_t max_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;

    const uint64_t max_seq = decode_uint64_le_compat(ptr);
    ptr += 8;

    const uint32_t compression_algorithm = decode_uint32_le_compat(ptr);
    ptr += 4;

    /* read flags field (was reserved in older versions, 0 = legacy block-based) */
    const uint32_t flags = decode_uint32_le_compat(ptr);
    ptr += 4;

    const int use_btree = (flags & SSTABLE_FLAG_BTREE) ? 1 : 0;

    /* we calculate expected size based on whether btree metadata is present */
    size_t btree_meta_size = 0;

    if (use_btree)
    {
        /* btree metadata -- root(8) + first_leaf(8) + last_leaf(8) + node_count(8) + height(4) = 36
         * bytes */
        btree_meta_size = 8 + 8 + 8 + 8 + 4;
    }

    const size_t expected_size = 92 + min_key_size + max_key_size + btree_meta_size;
    if (data_size != expected_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "SSTable metadata size mismatch (expected: %zu, got: %zu)",
                      expected_size, data_size);
        return -1;
    }

    /* we verify checksum over everything except checksum field */
    const size_t checksum_data_size = data_size - 8;
    const uint64_t computed_checksum = XXH64(data, checksum_data_size, 0);

    /* we checksum is at the end of the data */
    const uint8_t *checksum_ptr = data + data_size - 8;
    const uint64_t stored_checksum = decode_uint64_le_compat(checksum_ptr);

    if (computed_checksum != stored_checksum)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "SSTable metadata checksum mismatch (expected: %" PRIu64 ", got: %" PRIu64
                      ")",
                      stored_checksum, computed_checksum);
        return -1;
    }

    sst->num_entries = num_entries;
    sst->num_klog_blocks = num_klog_blocks;
    sst->num_vlog_blocks = num_vlog_blocks;
    sst->klog_data_end_offset = klog_data_end_offset;
    sst->klog_size = klog_size;
    sst->vlog_size = vlog_size;
    sst->max_seq = max_seq; /* assign recovered max sequence number */
    sst->use_btree = use_btree;

    /* we restore compression algorithm from metadata */
    if (sst->config)
    {
        /* we validate compression algorithm value */
        if (compression_algorithm != TDB_COMPRESS_NONE &&
#ifndef __sun
            compression_algorithm != TDB_COMPRESS_SNAPPY &&
#endif
            compression_algorithm != TDB_COMPRESS_LZ4 &&
            compression_algorithm != TDB_COMPRESS_LZ4_FAST &&
            compression_algorithm != TDB_COMPRESS_ZSTD)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable metadata has invalid compression_algorithm: %u",
                          compression_algorithm);
            return -1;
        }
        sst->config->compression_algorithm = compression_algorithm;
    }

    /* we read keys */
    if (min_key_size > 0)
    {
        sst->min_key = malloc(min_key_size);
        if (!sst->min_key) return -1;
        memcpy(sst->min_key, ptr, min_key_size);
        sst->min_key_size = min_key_size;
        ptr += min_key_size;
    }

    if (max_key_size > 0)
    {
        sst->max_key = malloc(max_key_size);
        if (!sst->max_key)
        {
            free(sst->min_key);
            sst->min_key = NULL;
            sst->min_key_size = 0;
            return -1;
        }
        memcpy(sst->max_key, ptr, max_key_size);
        sst->max_key_size = max_key_size;
        ptr += max_key_size;
    }

    /* we read btree metadata if present */
    if (use_btree)
    {
        sst->btree_root_offset = decode_int64_le_compat(ptr);
        ptr += 8;
        sst->btree_first_leaf = decode_int64_le_compat(ptr);
        ptr += 8;
        sst->btree_last_leaf = decode_int64_le_compat(ptr);
        ptr += 8;
        sst->btree_node_count = decode_uint64_le_compat(ptr);
        ptr += 8;
        sst->btree_height = decode_uint32_le_compat(ptr);
        ptr += 4;
    }

    return 0;
}

/**
 * tidesdb_resolve_comparator
 * resolves a comparator function and context from config using the registry
 * @param db database handle
 * @param config column family config
 * @param fn output parameter for comparator function
 * @param ctx output parameter for comparator context
 * @return 0 on success, -1 if comparator not found
 */
static int tidesdb_resolve_comparator(tidesdb_t *db, const tidesdb_column_family_config_t *config,
                                      skip_list_comparator_fn *fn, void **ctx)
{
    if (!db || !config || !fn) return -1;

    if (config->comparator_fn_cached)
    {
        *fn = config->comparator_fn_cached;
        if (ctx) *ctx = config->comparator_ctx_cached;
        return 0;
    }

    /* if we reach here, cached comparator is NULL but we need to resolve it */
    const int has_custom_comparator =
        (config->comparator_name[0] != '\0' && strcmp(config->comparator_name, "memcmp") != 0);

    if (tidesdb_get_comparator(db, config->comparator_name, fn, ctx) != TDB_SUCCESS)
    {
        if (has_custom_comparator)
        {
            /* custom comparator specified but not in registry and not cached!
             * this should never happen if CF creation validated properly.
             * */
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Comparator '%s' not found in registry and not cached",
                          config->comparator_name);
            return -1;
        }

        /* no comparator specified or explicitly requested memcmp, we use default */
        *fn = tidesdb_comparator_memcmp;
        if (ctx) *ctx = NULL;
        return 0;
    }

    return 0;
}

int tidesdb_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx)
{
    (void)ctx;
    /* fast path -- equal size keys (most common case) */
    if (TDB_LIKELY(key1_size == key2_size))
    {
        return memcmp(key1, key2, key1_size);
    }

    /* slow path -- different size keys */
    const size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    const int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp;
    return (key1_size < key2_size) ? -1 : 1;
}

int tidesdb_comparator_lexicographic(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx)
{
    (void)ctx;
    (void)key1_size;
    (void)key2_size;
    return strcmp((const char *)key1, (const char *)key2);
}

int tidesdb_comparator_uint64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx)
{
    (void)ctx;
    if (key1_size != 8 || key2_size != 8)
    {
        /* fallback to memcmp if sizes are wrong */
        return tidesdb_comparator_memcmp(key1, key1_size, key2, key2_size, NULL);
    }

    uint64_t val1, val2;
    memcpy(&val1, key1, 8);
    memcpy(&val2, key2, 8);

    if (val1 < val2) return -1;
    if (val1 > val2) return 1;
    return 0;
}

int tidesdb_comparator_int64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                             size_t key2_size, void *ctx)
{
    (void)ctx;
    if (key1_size != 8 || key2_size != 8)
    {
        /* fallback to memcmp if sizes are wrong */
        return tidesdb_comparator_memcmp(key1, key1_size, key2, key2_size, NULL);
    }

    int64_t val1, val2;
    memcpy(&val1, key1, 8);
    memcpy(&val2, key2, 8);

    if (val1 < val2) return -1;
    if (val1 > val2) return 1;
    return 0;
}

int tidesdb_comparator_reverse_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                      size_t key2_size, void *ctx)
{
    /* reverse the comparison result */
    return -tidesdb_comparator_memcmp(key1, key1_size, key2, key2_size, ctx);
}

int tidesdb_comparator_case_insensitive(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                        size_t key2_size, void *ctx)
{
    (void)ctx;
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;

    for (size_t i = 0; i < min_size; i++)
    {
        unsigned char c1 = key1[i];
        unsigned char c2 = key2[i];

        /* we convert to lowercase for ASCII characters */
        if (c1 >= 'A' && c1 <= 'Z') c1 = c1 + ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z') c2 = c2 + ('a' - 'A');

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }

    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    return (tidesdb_column_family_config_t){
        .write_buffer_size = TDB_DEFAULT_WRITE_BUFFER_SIZE,
        .level_size_ratio = TDB_DEFAULT_LEVEL_SIZE_RATIO,
        .min_levels = TDB_DEFAULT_MIN_LEVELS,
        .dividing_level_offset = TDB_DEFAULT_DIVIDING_LEVEL_OFFSET,
        .klog_value_threshold = TDB_DEFAULT_KLOG_VALUE_THRESHOLD,
        .compression_algorithm = TDB_COMPRESS_LZ4,
        .enable_bloom_filter = 1,
        .bloom_fpr = TDB_DEFAULT_BLOOM_FPR,
        .enable_block_indexes = 1,
        .index_sample_ratio = TDB_DEFAULT_INDEX_SAMPLE_RATIO,
        .block_index_prefix_len = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN,
        .sync_mode = TDB_SYNC_NONE,
        .sync_interval_us = TDB_DEFAULT_SYNC_INTERVAL_US,
        .comparator_fn_cached = NULL,
        .comparator_ctx_cached = NULL,
        .skip_list_max_level = 12,
        .skip_list_probability = 0.25f,
        .default_isolation_level = TDB_ISOLATION_READ_COMMITTED,
        .min_disk_space = TDB_DEFAULT_MIN_DISK_SPACE,
        .l1_file_count_trigger = TDB_DEFAULT_L1_FILE_COUNT_TRIGGER,
        .l0_queue_stall_threshold = TDB_DEFAULT_L0_QUEUE_STALL_THRESHOLD,
        .use_btree = 0};
}

tidesdb_config_t tidesdb_default_config(void)
{
    return (tidesdb_config_t){.db_path = "./tidesdb",
                              .log_level = TDB_LOG_INFO,
                              .num_flush_threads = TDB_DEFAULT_FLUSH_THREAD_POOL_SIZE,
                              .num_compaction_threads = TDB_DEFAULT_COMPACTION_THREAD_POOL_SIZE,
                              .block_cache_size = TDB_DEFAULT_BLOCK_CACHE_SIZE,
                              .max_open_sstables = TDB_DEFAULT_MAX_OPEN_SSTABLES,
                              .log_to_file = 0,
                              .log_truncation_at = TDB_DEFAULT_LOG_FILE_TRUNCATION};
}

/**
 * create a new KV pair
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param ttl time to live
 * @param seq sequence number
 * @param is_tombstone is tombstone
 * @return new KV pair
 */
static tidesdb_kv_pair_t *tidesdb_kv_pair_create(const uint8_t *key, const size_t key_size,
                                                 const uint8_t *value, const size_t value_size,
                                                 const time_t ttl, const uint64_t seq,
                                                 const int is_tombstone)
{
    /* arena allocation -- single malloc for struct + key + value
     * [tidesdb_kv_pair_t][key_data][value_data]
     * this reduces malloc calls from 3 to 1, improves cache locality! */
    const size_t value_alloc = (value_size > 0 && value) ? value_size : 0;
    const size_t arena_size = sizeof(tidesdb_kv_pair_t) + key_size + value_alloc;

    uint8_t *arena = malloc(arena_size);
    if (!arena) return NULL;

    tidesdb_kv_pair_t *kv = (tidesdb_kv_pair_t *)arena;
    memset(kv, 0, sizeof(tidesdb_kv_pair_t));

    kv->entry.flags = is_tombstone ? TDB_KV_FLAG_TOMBSTONE : 0;
    kv->entry.flags |= TDB_KV_FLAG_ARENA; /* mark as arena-allocated */
    kv->entry.key_size = (uint32_t)key_size;
    kv->entry.value_size = (uint32_t)value_size;
    kv->entry.ttl = ttl;
    kv->entry.seq = seq;
    kv->entry.vlog_offset = 0;

    /* key immediately follows struct */
    kv->key = arena + sizeof(tidesdb_kv_pair_t);
    memcpy(kv->key, key, key_size);

    /* value follows key */
    if (value_alloc > 0)
    {
        kv->value = kv->key + key_size;
        memcpy(kv->value, value, value_size);
    }

    return kv;
}

/**
 * tidesdb_kv_pair_free
 * free a KV pair
 * @param kv KV pair to free
 */
static void tidesdb_kv_pair_free(tidesdb_kv_pair_t *kv)
{
    if (!kv) return;

    /* arena-allocated KV pairs use single allocation for struct + key + value
     * however, value may be loaded separately (e.g., from vlog) after creation
     * [struct][key_data][value_data_if_included]
     * if value was included in arena, it points to exactly kv->key + key_size */
    if (kv->entry.flags & TDB_KV_FLAG_ARENA)
    {
        if (kv->value != NULL)
        {
            /* value is in arena only if it points to key + key_size
             * otherwise it was allocated separately and must be freed */
            const uint8_t *expected_arena_value = kv->key + kv->entry.key_size;
            if (kv->value != expected_arena_value)
            {
                free(kv->value); /* value was allocated separately */
            }
        }

        free(kv); /* single free for arena (struct + key + maybe value) */
        return;
    }

    /* legacy path for non-arena KV pairs */
    free(kv->key);
    free(kv->value);
    free(kv);
}

/**
 * tidesdb_kv_pair_clone
 * clone a KV pair
 * @param kv KV pair to clone
 * @return cloned KV pair
 */
static tidesdb_kv_pair_t *tidesdb_kv_pair_clone(const tidesdb_kv_pair_t *kv)
{
    if (!kv) return NULL;

    tidesdb_kv_pair_t *clone = tidesdb_kv_pair_create(
        kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl, kv->entry.seq,
        kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);
    if (clone)
    {
        clone->entry.vlog_offset = kv->entry.vlog_offset;
    }
    return clone;
}

/**
 * tidesdb_klog_block_create
 * create a new klog block
 * @return new klog block
 */
static tidesdb_klog_block_t *tidesdb_klog_block_create(void)
{
    tidesdb_klog_block_t *block = calloc(1, sizeof(tidesdb_klog_block_t));
    if (!block) return NULL;

    /* we pre-allocate for expected entries per block
     * with 64KB blocks and ~116 byte entries, expect ~560 entries
     * we pre-allocate to avoid realloc in common case */
    const uint32_t initial_capacity = TDB_KLOG_BLOCK_INITIAL_CAPACITY;

    block->entries = malloc(initial_capacity * sizeof(tidesdb_klog_entry_t));
    block->keys = malloc(initial_capacity * sizeof(uint8_t *));
    block->inline_values = malloc(initial_capacity * sizeof(uint8_t *));
    block->capacity = initial_capacity; /* track allocated capacity */

    if (!block->entries || !block->keys || !block->inline_values)
    {
        free(block->entries);
        free(block->keys);
        free(block->inline_values);
        free(block);
        return NULL;
    }

    /* we init pointers to NULL for safety */
    memset(block->keys, 0, initial_capacity * sizeof(uint8_t *));
    memset(block->inline_values, 0, initial_capacity * sizeof(uint8_t *));

    /* mark as not arena-allocated (separate mallocs) */
    block->is_arena_allocated = 0;

    return block;
}

/**
 * tidesdb_klog_block_free
 * free a klog block
 * @param block klog block to free
 */
static void tidesdb_klog_block_free(tidesdb_klog_block_t *block)
{
    if (!block) return;

    if (block->is_arena_allocated)
    {
        /* with arena allocation everything is in one contiguous block
         * except max_key which is allocated separately during deserialization */
        free(block->max_key);
        free(block);
    }
    else
    {
        /* separate allocations free each component individually */
        for (uint32_t i = 0; i < block->num_entries; i++)
        {
            free(block->keys[i]);
            free(block->inline_values[i]);
        }
        free(block->entries);
        free(block->keys);
        free(block->inline_values);
        free(block->max_key);
        free(block);
    }
}

/**
 * tidesdb_klog_block_add_entry
 * add an entry to a klog block
 * @param block klog block to add entry to
 * @param kv KV pair to add
 * @param config column family config
 * @param comparator_fn pre-resolved comparator function (avoids repeated lookups)
 * @param comparator_ctx pre-resolved comparator context
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        const tidesdb_column_family_config_t *config,
                                        skip_list_comparator_fn comparator_fn, void *comparator_ctx)
{
    if (!block || !kv || !config || !comparator_fn) return -1;

    const int inline_value = (kv->entry.value_size < config->klog_value_threshold);

    /** we calculate actual entry size to match serialization
     * we must use actual varint sizes, not max sizes, so block_size is accurate
     */
    size_t entry_size = 1; /* flags */

    /* we calculate actual varint sizes for key_size, value_size, seq */
    uint8_t temp_buf[10];
    entry_size += encode_varint(temp_buf, kv->entry.key_size);
    entry_size += encode_varint(temp_buf, kv->entry.value_size);
    entry_size += encode_varint(temp_buf, kv->entry.seq);

    if (kv->entry.ttl != 0) entry_size += 8;
    if (kv->entry.vlog_offset != 0)
    {
        entry_size += encode_varint(temp_buf, kv->entry.vlog_offset);
    }

    entry_size += kv->entry.key_size;
    if (inline_value)
    {
        entry_size += kv->entry.value_size;
    }

    const uint32_t new_count = block->num_entries + 1;

    if (new_count > block->capacity)
    {
        const uint32_t old_capacity = block->capacity;
        const uint32_t new_capacity = old_capacity * 2;

        tidesdb_klog_entry_t *new_entries =
            realloc(block->entries, new_capacity * sizeof(tidesdb_klog_entry_t));
        if (!new_entries) return TDB_ERR_MEMORY;
        block->entries = new_entries;

        uint8_t **new_keys = realloc(block->keys, new_capacity * sizeof(uint8_t *));
        if (!new_keys) return TDB_ERR_MEMORY;
        block->keys = new_keys;

        uint8_t **new_inline_values =
            realloc(block->inline_values, new_capacity * sizeof(uint8_t *));
        if (!new_inline_values) return TDB_ERR_MEMORY;
        block->inline_values = new_inline_values;

        const size_t new_elements = new_capacity - old_capacity;
        memset(block->keys + old_capacity, 0, new_elements * sizeof(uint8_t *));
        memset(block->inline_values + old_capacity, 0, new_elements * sizeof(uint8_t *));

        block->capacity = new_capacity;
    }

    memcpy(&block->entries[block->num_entries], &kv->entry, sizeof(tidesdb_klog_entry_t));

    block->keys[block->num_entries] = malloc(kv->entry.key_size);
    if (!block->keys[block->num_entries]) return TDB_ERR_MEMORY;
    memcpy(block->keys[block->num_entries], kv->key, kv->entry.key_size);

    if (inline_value && kv->entry.value_size > 0)
    {
        block->inline_values[block->num_entries] = malloc(kv->entry.value_size);
        if (!block->inline_values[block->num_entries]) return TDB_ERR_MEMORY;
        memcpy(block->inline_values[block->num_entries], kv->value, kv->entry.value_size);
        block->entries[block->num_entries].vlog_offset = 0;
    }
    else
    {
        block->inline_values[block->num_entries] = NULL;
    }

    block->num_entries++;
    block->block_size += (uint32_t)entry_size;

    /* we update max_key for seek using pre-resolved comparator */
    if (block->num_entries == 1 || comparator_fn(kv->key, kv->entry.key_size, block->max_key,
                                                 block->max_key_size, comparator_ctx) > 0)
    {
        if (kv->entry.key_size != block->max_key_size)
        {
            free(block->max_key);
            block->max_key = malloc(kv->entry.key_size);
            if (!block->max_key)
            {
                block->max_key_size = 0;
                return TDB_ERR_MEMORY;
            }
            block->max_key_size = kv->entry.key_size;
        }
        memcpy(block->max_key, kv->key, kv->entry.key_size);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_klog_block_is_full
 * check if a klog block is full
 * @param block klog block to check
 * @param max_size maximum size of block
 * @return 1 if block is full, 0 otherwise
 *
 * we use 2x max_size threshold because blocks are compressed before writing.
 * ZSTD typically achieves 2-4x compression on structured data, so filling to 2x
 * the target size ensures blocks are well-utilized after compression.
 *
 * 64KB target -> fill to 128KB uncompressed -> compresses to ~40-60KB
 * this maximizes block density while staying under the target after compression.
 */
static int tidesdb_klog_block_is_full(const tidesdb_klog_block_t *block, const size_t max_size)
{
    if (!block || !max_size) return -1;

    return block->block_size >= (max_size * 2);
}

/**
 * tidesdb_klog_block_serialize
 * @param block klog block to serialize
 * @param out output buffer
 * @param out_size output buffer size
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_serialize(tidesdb_klog_block_t *block, uint8_t **out,
                                        size_t *out_size)
{
    if (!block || !out || !out_size) return TDB_ERR_INVALID_ARGS;

    size_t estimated_size = 8; /* header -- num_entries + block_size */
    for (uint32_t i = 0; i < block->num_entries; i++)
    {
        /* flags (1) + key_size varint (max 10) + value_size varint (max 10) + seq varint (max 10)
         */
        estimated_size += 1 + 10 + 10 + 10;

        if (block->entries[i].ttl != 0)
        {
            estimated_size += sizeof(int64_t); /* 8 bytes */
        }

        /* vlog_offset only if value is in vlog */
        if (block->entries[i].vlog_offset != 0)
        {
            estimated_size += 10; /* varint max */
        }

        /* key data */
        estimated_size += block->entries[i].key_size;

        /* inline value data only if not in vlog */
        if (block->entries[i].vlog_offset == 0)
        {
            estimated_size += block->entries[i].value_size;
        }
    }

    *out = malloc(estimated_size);
    if (!*out) return TDB_ERR_MEMORY;

    uint8_t *ptr = *out;
    const uint8_t *start = ptr;

    encode_uint32_le_compat(ptr, block->num_entries);
    ptr += sizeof(uint32_t);
    encode_uint32_le_compat(ptr, block->block_size);
    ptr += sizeof(uint32_t);

    uint64_t prev_seq = 0;

    for (uint32_t i = 0; i < block->num_entries; i++)
    {
        const tidesdb_klog_entry_t *entry = &block->entries[i];
        uint8_t flags = entry->flags;

        uint64_t seq_value = entry->seq;
        if (i > 0 && entry->seq > prev_seq && (entry->seq - prev_seq) < TDB_KLOG_DELTA_SEQ_MAX_DIFF)
        {
            flags |= TDB_KV_FLAG_DELTA_SEQ;
            seq_value = entry->seq - prev_seq;
        }

        if (entry->ttl != 0) flags |= TDB_KV_FLAG_HAS_TTL;
        if (entry->vlog_offset != 0) flags |= TDB_KV_FLAG_HAS_VLOG;

        *ptr++ = flags;

        ptr += encode_varint(ptr, entry->key_size);
        ptr += encode_varint(ptr, entry->value_size);

        ptr += encode_varint(ptr, seq_value);

        if (flags & TDB_KV_FLAG_HAS_TTL)
        {
            encode_int64_le_compat(ptr, entry->ttl);
            ptr += sizeof(int64_t);
        }

        if (flags & TDB_KV_FLAG_HAS_VLOG)
        {
            ptr += encode_varint(ptr, entry->vlog_offset);
        }

        memcpy(ptr, block->keys[i], entry->key_size);
        ptr += entry->key_size;

        if (!(flags & TDB_KV_FLAG_HAS_VLOG) && block->inline_values[i])
        {
            memcpy(ptr, block->inline_values[i], entry->value_size);
            ptr += entry->value_size;
        }

        prev_seq = entry->seq;
    }

    *out_size = ptr - start;

    if (*out_size > estimated_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "klog serialization buffer overrun! wrote %zu bytes, allocated %zu bytes",
                      *out_size, estimated_size);
        free(*out);
        *out = NULL;
        return TDB_ERR_CORRUPTION;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_klog_block_deserialize
 * @param data input buffer
 * @param data_size input buffer size
 * @param block output klog block
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_klog_block_t **block)
{
    if (!data || !data_size || !block) return TDB_ERR_INVALID_ARGS;

    if (data_size < sizeof(uint32_t) * 2) return TDB_ERR_CORRUPTION;

    /* we use arena allocation -- single malloc for entire block structure
     * layout -- block_struct | entries[] | keys[] | inline_values[] | key_data | value_data
     * this reduces malloc calls from O(N) to O(1) per block */
    const uint8_t *ptr = data;

    uint32_t num_entries = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    uint32_t block_size = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);

    /* sanity check: num_entries must be reasonable for the data size
     * each entry needs at least 4 bytes (flags + 3 varints min) */
    if (num_entries > data_size / 4) return TDB_ERR_CORRUPTION;

    /* we use data_size as upper bound for key+value data instead of scanning
     * the entire serialized stream first. this eliminates the pre-scan pass
     * which was the #1 source of branch mispredictions (34% of all branch misses).
     * the second (actual deserialization) pass validates everything anyway. */
    const size_t data_payload_bound = data_size;

    /* block + entries + key_ptrs + value_ptrs + key_data + value_data */
    const size_t arena_size = sizeof(tidesdb_klog_block_t) +
                              (num_entries * sizeof(tidesdb_klog_entry_t)) +
                              (num_entries * sizeof(uint8_t *)) + /* keys array */
                              (num_entries * sizeof(uint8_t *)) + /* inline_values array */
                              data_payload_bound;

    uint8_t *arena = malloc(arena_size);
    if (!arena) return TDB_ERR_MEMORY;

    /* we partition arena into sections */
    *block = (tidesdb_klog_block_t *)arena;
    memset(*block, 0, sizeof(tidesdb_klog_block_t));

    /* we mark as arena-allocated for proper cleanup */
    (*block)->is_arena_allocated = 1;

    uint8_t *arena_ptr = arena + sizeof(tidesdb_klog_block_t);
    (*block)->entries = (tidesdb_klog_entry_t *)arena_ptr;
    arena_ptr += num_entries * sizeof(tidesdb_klog_entry_t);

    (*block)->keys = (uint8_t **)arena_ptr;
    arena_ptr += num_entries * sizeof(uint8_t *);

    (*block)->inline_values = (uint8_t **)arena_ptr;
    arena_ptr += num_entries * sizeof(uint8_t *);

    uint8_t *data_arena = arena_ptr;

    (*block)->num_entries = 0;
    (*block)->block_size = block_size;
    (*block)->capacity = num_entries;

    uint64_t prev_seq = 0;
    size_t remaining = data_size - (ptr - data);
    size_t data_offset = 0;

    for (uint32_t i = 0; i < num_entries; i++)
    {
        if (remaining < 1)
        {
            TDB_DEBUG_LOG(TDB_LOG_FATAL, "Entry exceeds bounds at entry %u", i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }

        uint8_t flags = *ptr++;
        remaining--;
        (*block)->entries[i].flags = flags & ~TDB_KV_FLAG_DELTA_SEQ;

        uint64_t key_size_u64;
        int bytes_read = decode_varint(ptr, &key_size_u64, (int)remaining);
        if (bytes_read < 0 || key_size_u64 > UINT32_MAX)
        {
            TDB_DEBUG_LOG(TDB_LOG_FATAL, "Invalid key_size varint at entry %u", i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }
        ptr += bytes_read;
        remaining -= bytes_read;
        (*block)->entries[i].key_size = (uint32_t)key_size_u64;

        uint64_t value_size_u64;
        bytes_read = decode_varint(ptr, &value_size_u64, (int)remaining);
        if (bytes_read < 0 || value_size_u64 > UINT32_MAX)
        {
            TDB_DEBUG_LOG(TDB_LOG_FATAL, "Invalid value_size varint at entry %u", i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }
        ptr += bytes_read;
        remaining -= bytes_read;
        (*block)->entries[i].value_size = (uint32_t)value_size_u64;

        uint64_t seq_value;
        bytes_read = decode_varint(ptr, &seq_value, (int)remaining);
        if (bytes_read < 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_FATAL, "Invalid seq varint at entry %u", i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }
        ptr += bytes_read;
        remaining -= bytes_read;

        if (flags & TDB_KV_FLAG_DELTA_SEQ)
        {
            (*block)->entries[i].seq = prev_seq + seq_value;
        }
        else
        {
            (*block)->entries[i].seq = seq_value;
        }
        prev_seq = (*block)->entries[i].seq;

        if (flags & TDB_KV_FLAG_HAS_TTL)
        {
            if (remaining < sizeof(int64_t))
            {
                TDB_DEBUG_LOG(TDB_LOG_FATAL, "TTL exceeds bounds at entry %u", i);
                tidesdb_klog_block_free(*block);
                *block = NULL;
                return TDB_ERR_CORRUPTION;
            }
            (*block)->entries[i].ttl = decode_int64_le_compat(ptr);
            ptr += sizeof(int64_t);
            remaining -= sizeof(int64_t);
        }
        else
        {
            (*block)->entries[i].ttl = 0;
        }

        if (flags & TDB_KV_FLAG_HAS_VLOG)
        {
            uint64_t vlog_offset;
            bytes_read = decode_varint(ptr, &vlog_offset, (int)remaining);
            if (bytes_read < 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_FATAL, "Invalid vlog_offset varint at entry %u", i);
                tidesdb_klog_block_free(*block);
                *block = NULL;
                return TDB_ERR_CORRUPTION;
            }
            ptr += bytes_read;
            remaining -= bytes_read;
            (*block)->entries[i].vlog_offset = vlog_offset;
        }
        else
        {
            (*block)->entries[i].vlog_offset = 0;
        }

        if (remaining < (*block)->entries[i].key_size)
        {
            TDB_DEBUG_LOG(TDB_LOG_FATAL, "Key data exceeds bounds at entry %u", i);
            free(arena);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }

        /* we point into arena instead of malloc */
        (*block)->keys[i] = data_arena + data_offset;
        memcpy((*block)->keys[i], ptr, (*block)->entries[i].key_size);
        data_offset += (*block)->entries[i].key_size;
        ptr += (*block)->entries[i].key_size;
        remaining -= (*block)->entries[i].key_size;

        if (!(flags & TDB_KV_FLAG_HAS_VLOG) && (*block)->entries[i].value_size > 0)
        {
            if (remaining < (*block)->entries[i].value_size)
            {
                TDB_DEBUG_LOG(TDB_LOG_FATAL, "Inline value exceeds bounds at entry %u", i);
                free(arena);
                *block = NULL;
                return TDB_ERR_CORRUPTION;
            }

            (*block)->inline_values[i] = data_arena + data_offset;
            memcpy((*block)->inline_values[i], ptr, (*block)->entries[i].value_size);
            data_offset += (*block)->entries[i].value_size;
            ptr += (*block)->entries[i].value_size;
            remaining -= (*block)->entries[i].value_size;
        }
    }

    (*block)->num_entries = num_entries;

    if (num_entries > 0)
    {
        const uint32_t last_idx = num_entries - 1;
        (*block)->max_key = malloc((*block)->entries[last_idx].key_size);
        if ((*block)->max_key)
        {
            memcpy((*block)->max_key, (*block)->keys[last_idx],
                   (*block)->entries[last_idx].key_size);
            (*block)->max_key_size = (*block)->entries[last_idx].key_size;
        }
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_vlog_read_value
 * read a value from vlog
 * @param db database instance
 * @param sst sstable containing vlog
 * @param vlog_offset offset of value in vlog
 * @param value_size size of value
 * @param value output value
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_read_value(const tidesdb_t *db, tidesdb_sstable_t *sst,
                                   const uint64_t vlog_offset, const size_t value_size,
                                   uint8_t **value)
{
    if (!db || !sst || !value) return TDB_ERR_INVALID_ARGS;

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        return TDB_ERR_IO;
    }

    /* vlog_offset is a direct file offset pointing to the vlog block containing the raw value */
    uint32_t block_size;
    if (block_manager_get_block_size_at_offset(bms.vlog_bm, vlog_offset, &block_size) != 0)
    {
        return TDB_ERR_IO;
    }

    uint8_t *block_data = malloc(block_size);
    if (!block_data)
    {
        return TDB_ERR_MEMORY;
    }

    const uint64_t data_offset = vlog_offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (block_manager_read_at_offset(bms.vlog_bm, data_offset, block_size, block_data) != 0)
    {
        free(block_data);
        return TDB_ERR_IO;
    }

    if (sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        size_t decompressed_size;
        uint8_t *decompressed = decompress_data(block_data, block_size, &decompressed_size,
                                                sst->config->compression_algorithm);
        if (decompressed)
        {
            free(block_data);
            *value = decompressed;

            /*** we validate size if provided */
            if (value_size > 0 && decompressed_size != value_size)
            {
                TDB_DEBUG_LOG(TDB_LOG_FATAL, "Value size mismatch (expected %zu, got %zu)",
                              value_size, decompressed_size);
                free(*value);
                *value = NULL;
                return TDB_ERR_CORRUPTION;
            }
            return TDB_SUCCESS;
        }
        /* decompression failed */
        free(block_data);
        return TDB_ERR_CORRUPTION;
    }

    *value = block_data;

    if (value_size > 0 && block_size != value_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "Value size mismatch (expected %zu, got %u)", value_size,
                      block_size);
        free(*value);
        *value = NULL;
        return TDB_ERR_CORRUPTION;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_get_block_managers
 * gets block managers for an sstable through the cache
 * @param db database instance
 * @param sst sstable
 * @param bms output block managers structure
 * @return TDB_SUCCESS on success, TDB_ERR_IO on failure
 */
static int tidesdb_sstable_get_block_managers(const tidesdb_t *db, tidesdb_sstable_t *sst,
                                              tidesdb_block_managers_t *bms)
{
    if (!db || !sst || !bms) return TDB_ERR_IO;

    bms->klog_bm = sst->klog_bm;
    bms->vlog_bm = sst->vlog_bm;

    if (!bms->klog_bm || !bms->vlog_bm)
    {
        return TDB_ERR_IO;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_ensure_open
 * ensures an sstable's block managers are open, using the cache
 * @param db database instance
 * @param sst sstable to ensure is open
 * @return 0 on success, -1 on error
 */
static int tidesdb_sstable_ensure_open(tidesdb_t *db, tidesdb_sstable_t *sst)
{
    if (!db || !sst) return -1;
    if (!sst->config || !sst->klog_path || !sst->vlog_path) return -1;

    /* we only open block managers if not already open */
    if (sst->klog_bm && sst->vlog_bm)
    {
        return 0; /* already open */
    }

    /* we open block managers if needed, using CAS to prevent race conditions
     * where two threads both try to open the same sstable simultaneously */
    if (!sst->klog_bm)
    {
        block_manager_t *new_klog_bm = NULL;
        if (block_manager_open(&new_klog_bm, sst->klog_path,
                               convert_sync_mode(sst->config->sync_mode == TDB_SYNC_INTERVAL
                                                     ? TDB_SYNC_FULL
                                                     : sst->config->sync_mode)) != 0)
        {
            return -1;
        }
        /* CAS to set klog_bm -- if another thread already set it, close ours */
        block_manager_t *expected = NULL;
        if (!atomic_compare_exchange_strong((atomic_uintptr_t *)&sst->klog_bm,
                                            (uintptr_t *)&expected, (uintptr_t)new_klog_bm))
        {
            /* another thread already opened it, close our duplicate */
            block_manager_close(new_klog_bm);
        }
    }

    if (!sst->vlog_bm)
    {
        block_manager_t *new_vlog_bm = NULL;
        if (block_manager_open(&new_vlog_bm, sst->vlog_path,
                               convert_sync_mode(sst->config->sync_mode)) != 0)
        {
            /* we dont close klog_bm here -- it may be used by another thread */
            return -1;
        }

        /* hint that vlog access is random (point lookups by offset)
         * this disables read-ahead which would waste I/O for random access */
        set_file_random_hint(new_vlog_bm->fd);

        /* CAS to set vlog_bm -- if another thread already set it, close ours */
        block_manager_t *expected = NULL;
        if (!atomic_compare_exchange_strong((atomic_uintptr_t *)&sst->vlog_bm,
                                            (uintptr_t *)&expected, (uintptr_t)new_vlog_bm))
        {
            /* another thread already opened it, close our duplicate */
            block_manager_close(new_vlog_bm);
        }
    }

    atomic_store(&sst->last_access_time, atomic_load(&db->cached_current_time));

    return 0;
}

/**
 * tidesdb_sstable_create
 * create a new sstable
 * @param db database instance
 * @param base_path base path for sstable files
 * @param id sstable id
 * @param config column family configuration
 * @return sstable on success, NULL on failure
 */
static tidesdb_sstable_t *tidesdb_sstable_create(tidesdb_t *db, const char *base_path,
                                                 const uint64_t id,
                                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !base_path || !config) return NULL;

    tidesdb_sstable_t *sst = calloc(1, sizeof(tidesdb_sstable_t));
    if (!sst) return NULL;

    sst->db = db;
    sst->config = malloc(sizeof(tidesdb_column_family_config_t));
    if (!sst->config)
    {
        free(sst);
        return NULL;
    }
    memcpy(sst->config, config, sizeof(tidesdb_column_family_config_t));

    sst->id = id;
    atomic_init(&sst->refcount, 1);
    sst->num_klog_blocks = 0;
    sst->num_vlog_blocks = 0;
    sst->klog_data_end_offset = 0;
    atomic_init(&sst->marked_for_deletion, 0);
    atomic_init(&sst->last_access_time, 0);
    sst->klog_bm = NULL;
    sst->vlog_bm = NULL;
    sst->use_btree = config->use_btree;

    /* we cache resolved comparator on the sstable to avoid per-lookup resolution */
    sst->cached_comparator_fn = NULL;
    sst->cached_comparator_ctx = NULL;
    sst->is_reverse = 0;
    tidesdb_resolve_comparator(db, config, &sst->cached_comparator_fn, &sst->cached_comparator_ctx);

    const size_t path_len = strlen(base_path) + 32;
    sst->klog_path = malloc(path_len);
    sst->vlog_path = malloc(path_len);

    if (!sst->klog_path || !sst->vlog_path)
    {
        free(sst->klog_path);
        free(sst->vlog_path);
        free(sst->config);
        free(sst);
        return NULL;
    }

    snprintf(sst->klog_path, path_len, "%s_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT, base_path,
             TDB_U64_CAST(id));
    snprintf(sst->vlog_path, path_len, "%s_" TDB_U64_FMT TDB_SSTABLE_VLOG_EXT, base_path,
             TDB_U64_CAST(id));

    /* we cache CF name from path to avoid repeated parsing during reads */
    if (tidesdb_get_cf_name_from_path(sst->klog_path, sst->cf_name) != 0)
    {
        sst->cf_name[0] = '\0'; /* fallback: empty string if extraction fails */
    }

    return sst;
}

/**
 * tidesdb_btree_cache_delete_callback
 * callback for clock_cache_foreach_prefix to delete matching entries
 */
static int tidesdb_btree_cache_delete_callback(const char *key, size_t key_len,
                                               const uint8_t *payload, size_t payload_len,
                                               void *user_data)
{
    (void)payload;
    (void)payload_len;
    clock_cache_t *cache = (clock_cache_t *)user_data;
    clock_cache_delete(cache, key, key_len);
    return 0; /* continue iteration */
}

/**
 * tidesdb_invalidate_btree_cache_for_sstable
 * invalidate all btree node cache entries for a specific sstable
 * @param db the database
 * @param sst_id the sstable ID
 */
static void tidesdb_invalidate_btree_cache_for_sstable(tidesdb_t *db, uint64_t sst_id)
{
    if (!db || !db->btree_node_cache) return;

    char prefix[32];
    const int prefix_len = snprintf(prefix, sizeof(prefix), "%" PRIu64 ":", sst_id);
    clock_cache_foreach_prefix(db->btree_node_cache, prefix, (size_t)prefix_len,
                               tidesdb_btree_cache_delete_callback, db->btree_node_cache);
}

/**
 * tidesdb_block_cache_delete_callback
 * callback for clock_cache_foreach_prefix to delete matching block cache entries
 */
static int tidesdb_block_cache_delete_callback(const char *key, size_t key_len,
                                               const uint8_t *payload, size_t payload_len,
                                               void *user_data)
{
    (void)payload;
    (void)payload_len;
    clock_cache_t *cache = (clock_cache_t *)user_data;
    clock_cache_delete(cache, key, key_len);
    return 0; /* continue iteration */
}

/**
 * tidesdb_invalidate_block_cache_for_sstable
 * invalidate all block cache entries for a specific sstable
 * block cache keys are formatted as "cf_name:filename:block_position"
 * e.g., "users:L2_1337.klog:0", "users:L2_1337.klog:65536"
 * @param db the database
 * @param cf_name column family name
 * @param klog_path path to klog file (used to extract filename)
 */
static void tidesdb_invalidate_block_cache_for_sstable(tidesdb_t *db, const char *cf_name,
                                                       const char *klog_path)
{
    if (!db || !db->clock_cache || !cf_name || !klog_path) return;

    /* we extract filename from path (cross-platform) */
    const char *filename = strrchr(klog_path, '/');
    if (!filename) filename = strrchr(klog_path, '\\');
    filename = filename ? filename + 1 : klog_path;

    char prefix[TDB_CACHE_KEY_SIZE];
    const int prefix_len = snprintf(prefix, sizeof(prefix), "%s:%s:", cf_name, filename);
    if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) return;

    clock_cache_foreach_prefix(db->clock_cache, prefix, (size_t)prefix_len,
                               tidesdb_block_cache_delete_callback, db->clock_cache);
}

/**
 * tidesdb_invalidate_block_cache_for_cf
 * invalidate all block cache entries for a column family
 * @param db the database
 * @param cf_name column family name
 */
static void tidesdb_invalidate_block_cache_for_cf(tidesdb_t *db, const char *cf_name)
{
    if (!db || !db->clock_cache || !cf_name) return;

    char prefix[TDB_MAX_CF_NAME_LEN + 2];
    const int prefix_len = snprintf(prefix, sizeof(prefix), "%s:", cf_name);
    if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) return;

    clock_cache_foreach_prefix(db->clock_cache, prefix, (size_t)prefix_len,
                               tidesdb_block_cache_delete_callback, db->clock_cache);
}

/**
 * tidesdb_sstable_free
 * free an sstable
 * @param sst sstable to free
 */
static void tidesdb_sstable_free(tidesdb_sstable_t *sst)
{
    if (!sst) return;

    /* we invalidate btree node cache entries for this sstable before freeing */
    if (sst->use_btree && sst->db && sst->db->btree_node_cache)
    {
        tidesdb_invalidate_btree_cache_for_sstable(sst->db, sst->id);
    }

    /* we invalidate block cache entries for this sstable before freeing */
    if (sst->db && sst->db->clock_cache && sst->cf_name[0] != '\0' && sst->klog_path)
    {
        tidesdb_invalidate_block_cache_for_sstable(sst->db, sst->cf_name, sst->klog_path);
    }

    /* if marked for deletion, evict file data from page cache before closing
     * this prevents cache pollution from compacted-away sstables */
    if (atomic_load_explicit(&sst->marked_for_deletion, memory_order_acquire))
    {
        if (sst->klog_bm)
        {
            evict_file_region(sst->klog_bm->fd, 0, 0);
        }
        if (sst->vlog_bm)
        {
            evict_file_region(sst->vlog_bm->fd, 0, 0);
        }
    }

    if (sst->klog_bm)
    {
        block_manager_close(sst->klog_bm);
        sst->klog_bm = NULL;
    }
    if (sst->vlog_bm)
    {
        block_manager_close(sst->vlog_bm);
        sst->vlog_bm = NULL;
    }

    /* we delete files only when refcount reaches 0
     * this ensures active transactions can still read from old sstables
     * during compaction */
    if (atomic_load_explicit(&sst->marked_for_deletion, memory_order_acquire))
    {
        tdb_unlink(sst->klog_path);
        tdb_unlink(sst->vlog_path);
    }

    free(sst->klog_path);
    free(sst->vlog_path);
    free(sst->min_key);
    free(sst->max_key);
    free(sst->config);

    if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
    if (sst->block_indexes) compact_block_index_free(sst->block_indexes);

    free(sst);
}

/**
 * tidesdb_sstable_ref
 * increment reference count of an sstable
 * @param sst sstable to reference
 */
static void tidesdb_sstable_ref(tidesdb_sstable_t *sst)
{
    if (sst)
    {
        atomic_fetch_add(&sst->refcount, 1);
    }
}

/**
 * tidesdb_sstable_try_ref
 * try to increment reference count of an sstable using CAS
 * this is safe to call on an sstable that might be concurrently freed
 * @param sst sstable to reference
 * @return 1 if reference was acquired, 0 if sstable is being freed (refcount was 0)
 */
static int tidesdb_sstable_try_ref(tidesdb_sstable_t *sst)
{
    if (!sst) return 0;

    /* we use CAS loop to only increment if refcount > 0
     * if refcount is 0, the sstable is being freed and we must not touch it */
    int old_refcount = atomic_load_explicit(&sst->refcount, memory_order_acquire);
    while (old_refcount > 0)
    {
        if (atomic_compare_exchange_weak_explicit(&sst->refcount, &old_refcount, old_refcount + 1,
                                                  memory_order_acq_rel, memory_order_acquire))
        {
            return 1; /* successfully acquired reference */
        }
        /* CAS failed, old_refcount was updated, retry if still > 0 */
    }
    return 0; /* refcount was 0, sstable is being freed */
}

/**
 * tidesdb_sstable_unref
 * decrement reference count of an sstable
 * @param db database instance
 * @param sst sstable to unreference
 */
static void tidesdb_sstable_unref(const tidesdb_t *db, tidesdb_sstable_t *sst)
{
    (void)db;
    if (!sst) return;
    const int old_refcount = atomic_fetch_sub(&sst->refcount, 1);
    if (old_refcount == 1)
    {
        tidesdb_sstable_free(sst);
    }
}

static int tidesdb_flush_memtable_internal(tidesdb_column_family_t *cf, int already_holds_lock,
                                           int force);

/**
 * tidesdb_write_set_hash_t
 * hash table for O(1) write set lookups in large transactions
 * uses open addressing with linear probing for cache locality
 * @param slots maps hash -> ops index, -1 if empty
 * @param capacity always TDB_WRITE_SET_HASH_CAPACITY
 */
typedef struct
{
    int *slots;
    int capacity;
} tidesdb_write_set_hash_t;

/**
 * tidesdb_write_set_hash_create
 * create hash table for write set
 * @return hash table on success, NULL on failure
 */
static tidesdb_write_set_hash_t *tidesdb_write_set_hash_create(void)
{
    tidesdb_write_set_hash_t *hash = malloc(sizeof(tidesdb_write_set_hash_t));
    if (!hash) return NULL;

    hash->capacity = TDB_WRITE_SET_HASH_CAPACITY;
    hash->slots = malloc(hash->capacity * sizeof(int));
    if (!hash->slots)
    {
        free(hash);
        return NULL;
    }

    for (int i = 0; i < hash->capacity; i++)
    {
        hash->slots[i] = TDB_WRITE_SET_HASH_EMPTY;
    }

    return hash;
}

/**
 * tidesdb_write_set_hash_free
 * free hash table
 */
static void tidesdb_write_set_hash_free(tidesdb_write_set_hash_t *hash)
{
    if (!hash) return;
    free(hash->slots);
    free(hash);
}

/**
 * tidesdb_write_set_hash_key
 * compute hash for key+cf combination using xxhash
 * @param cf column family
 * @param key key
 * @param key_size key size
 * @return hash value
 */
static uint32_t tidesdb_write_set_hash_key(tidesdb_column_family_t *cf, const uint8_t *key,
                                           const size_t key_size)
{
    /* we mix CF pointer into seed for better distribution across CFs */
    const uint64_t seed = TDB_TXN_HASH_SEED ^ (uint64_t)(uintptr_t)cf;
    return (uint32_t)XXH64(key, key_size, seed);
}

/**
 * tidesdb_write_set_hash_insert
 * insert operation index into hash table
 * overwrites existing entry for same key (keeps newest)
 * @param hash hash table
 * @param txn transaction
 * @param op_index operation index
 */
static void tidesdb_write_set_hash_insert(tidesdb_write_set_hash_t *hash, const tidesdb_txn_t *txn,
                                          const int op_index)
{
    if (!hash || op_index < 0 || op_index >= txn->num_ops) return;

    const tidesdb_txn_op_t *op = &txn->ops[op_index];
    const uint32_t h = tidesdb_write_set_hash_key(op->cf, op->key, op->key_size);
    int slot = (int)(h % (uint32_t)hash->capacity);

    /* we utilize linear probing to find empty slot or matching key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        const int existing_idx = hash->slots[slot];

        if (existing_idx == TDB_WRITE_SET_HASH_EMPTY)
        {
            /* empty slot, insert here */
            hash->slots[slot] = op_index;
            return;
        }

        /* we check if this slot has the same key (update case) */
        const tidesdb_txn_op_t *existing = &txn->ops[existing_idx];
        if (existing->cf == op->cf && existing->key_size == op->key_size &&
            memcmp(existing->key, op->key, op->key_size) == 0)
        {
            /* same key, update to newer operation */
            hash->slots[slot] = op_index;
            return;
        }

        /* collision, try next slot */
        slot = (slot + 1) % hash->capacity;
    }
    /* probe limit exceeded--hash table may be too full, but continue without hash */
}

/**
 * tidesdb_write_set_hash_lookup
 * find operation index for given key+cf
 * @param hash hash table
 * @param txn transaction
 * @param cf column family
 * @param key key
 * @param key_size key size
 * @return operation index if found, -1 if not found
 */
static int tidesdb_write_set_hash_lookup(tidesdb_write_set_hash_t *hash, const tidesdb_txn_t *txn,
                                         tidesdb_column_family_t *cf, const uint8_t *key,
                                         const size_t key_size)
{
    if (!hash) return -1;

    const uint32_t h = tidesdb_write_set_hash_key(cf, key, key_size);
    int slot = (int)(h % (uint32_t)hash->capacity);

    /* we utilize linear probing to find key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        const int op_index = hash->slots[slot];

        if (op_index == TDB_WRITE_SET_HASH_EMPTY)
        {
            /* empty slot means key not in hash */
            return -1;
        }

        const tidesdb_txn_op_t *op = &txn->ops[op_index];
        if (op->cf == cf && op->key_size == key_size && memcmp(op->key, key, key_size) == 0)
        {
            /* found it */
            return op_index;
        }

        /* collision, we try next slot */
        slot = (slot + 1) % hash->capacity;
    }

    /* probe limit exceeded--assume not found */
    return -1;
}

/**
 * tidesdb_read_set_hash_t
 * hash table for O(1) read set lookups in SSI conflict detection
 * uses xxhash for better distribution and larger capacity for fewer collisions
 * @param slots maps hash -> read_set index, -1 if empty
 * @param capacity always TDB_READ_SET_HASH_CAPACITY
 */
typedef struct
{
    int *slots;
    int capacity;
} tidesdb_read_set_hash_t;

/**
 * tidesdb_read_set_hash_create
 * create hash table for read set
 */
static tidesdb_read_set_hash_t *tidesdb_read_set_hash_create(void)
{
    tidesdb_read_set_hash_t *hash = malloc(sizeof(tidesdb_read_set_hash_t));
    if (!hash) return NULL;

    hash->capacity = TDB_READ_SET_HASH_CAPACITY;
    hash->slots = malloc(hash->capacity * sizeof(int));
    if (!hash->slots)
    {
        free(hash);
        return NULL;
    }

    for (int i = 0; i < hash->capacity; i++)
    {
        hash->slots[i] = TDB_READ_SET_HASH_EMPTY;
    }

    return hash;
}

/**
 * tidesdb_read_set_hash_free
 * free hash table
 * @param hash hash table to free
 */
static void tidesdb_read_set_hash_free(tidesdb_read_set_hash_t *hash)
{
    if (!hash) return;
    free(hash->slots);
    free(hash);
}

/**
 * tidesdb_read_set_hash_key
 * compute hash for key+cf combination using xxhash
 * @param cf column family
 * @param key key
 * @param key_size key size
 * @return hash value
 */
static uint32_t tidesdb_read_set_hash_key(tidesdb_column_family_t *cf, const uint8_t *key,
                                          const size_t key_size)
{
    /* mix CF pointer into seed for better distribution across CFs */
    const uint64_t seed = TDB_TXN_HASH_SEED ^ (uint64_t)(uintptr_t)cf;
    return (uint32_t)XXH64(key, key_size, seed);
}

/**
 * tidesdb_read_set_hash_insert
 * insert read set index into hash table
 * @param hash hash table
 * @param txn transaction
 * @param read_index read set index
 */
static void tidesdb_read_set_hash_insert(tidesdb_read_set_hash_t *hash, const tidesdb_txn_t *txn,
                                         const int read_index)
{
    if (!hash || read_index < 0 || read_index >= txn->read_set_count) return;

    const uint32_t h = tidesdb_read_set_hash_key(
        txn->read_cfs[read_index], txn->read_keys[read_index], txn->read_key_sizes[read_index]);
    int slot = (int)(h % (uint32_t)hash->capacity);

    /* linear probing to find empty slot or matching key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        const int existing_idx = hash->slots[slot];

        if (existing_idx == TDB_READ_SET_HASH_EMPTY)
        {
            /* empty slot, insert here */
            hash->slots[slot] = read_index;
            return;
        }

        /* we check if this slot has the same key (update case) */
        if (txn->read_cfs[existing_idx] == txn->read_cfs[read_index] &&
            txn->read_key_sizes[existing_idx] == txn->read_key_sizes[read_index] &&
            memcmp(txn->read_keys[existing_idx], txn->read_keys[read_index],
                   txn->read_key_sizes[read_index]) == 0)
        {
            /* same key, update to newer read */
            hash->slots[slot] = read_index;
            return;
        }

        /* collision, try next slot */
        slot = (slot + 1) % hash->capacity;
    }
    /* probe limit exceeded -- hash table may be too full, but continue without hash */
}

/**
 * tidesdb_read_set_hash_check_conflict
 * check if a write key conflicts with any read in the hash table
 * @param hash hash table
 * @param txn transaction
 * @param cf column family
 * @param key key
 * @param key_size key size
 * @return 1 if conflict found, 0 otherwise
 */
static int tidesdb_read_set_hash_check_conflict(tidesdb_read_set_hash_t *hash,
                                                const tidesdb_txn_t *txn,
                                                tidesdb_column_family_t *cf, const uint8_t *key,
                                                const size_t key_size)
{
    if (!hash) return 0;

    if (txn == NULL || cf == NULL || key == NULL || key_size == 0) return 0;

    const uint32_t h = tidesdb_read_set_hash_key(cf, key, key_size);
    int slot = (int)(h % (uint32_t)hash->capacity);

    /* we use linear probing to find key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        const int read_index = hash->slots[slot];

        if (read_index == TDB_READ_SET_HASH_EMPTY)
        {
            /* empty slot means key not in hash */
            return 0;
        }

        if (txn->read_cfs[read_index] == cf && txn->read_key_sizes[read_index] == key_size &&
            memcmp(txn->read_keys[read_index], key, key_size) == 0)
        {
            /* found conflict */
            return 1;
        }

        /* collision, try next slot */
        slot = (slot + 1) % hash->capacity;
    }

    /* probe limit exceeded -- assume no conflict (conservative) */
    return 0;
}

/**
 * tidesdb_immutable_memtable_ref
 * increment reference count of an immutable memtable
 * @param imm immutable memtable to reference
 */
static void tidesdb_immutable_memtable_ref(tidesdb_immutable_memtable_t *imm)
{
    if (imm) atomic_fetch_add(&imm->refcount, 1);
}

/**
 * tidesdb_skip_list_free_wrapper
 * pthread-compatible wrapper for skip_list_free
 */
static void *tidesdb_skip_list_free_wrapper(void *arg)
{
    skip_list_free((skip_list_t *)arg);
    return NULL;
}

/**
 * tidesdb_immutable_memtable_unref
 * decrement reference count of an immutable memtable
 * @param imm immutable memtable to unreference
 */
static void tidesdb_immutable_memtable_unref(tidesdb_immutable_memtable_t *imm)
{
    if (!imm) return;
    if (atomic_fetch_sub(&imm->refcount, 1) == 1)
    {
        skip_list_t *memtable_to_free = imm->skip_list;
        if (imm->wal) block_manager_close(imm->wal);
        free(imm);

        if (memtable_to_free)
        {
            pthread_t cleanup_thread;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

            if (pthread_create(&cleanup_thread, &attr, tidesdb_skip_list_free_wrapper,
                               memtable_to_free) != 0)
            {
                skip_list_free(memtable_to_free);
            }
            pthread_attr_destroy(&attr);
        }
    }
}

#define TDB_IMM_SNAPSHOT_STACK_SIZE 8

typedef struct
{
    tidesdb_immutable_memtable_t **items;
    tidesdb_immutable_memtable_t *stack_items[TDB_IMM_SNAPSHOT_STACK_SIZE];
    size_t count;
    size_t capacity;
    int failed;
    int heap_allocated;
} tidesdb_imm_snapshot_ctx_t;

static void tidesdb_collect_imm_snapshot(void *data, void *context)
{
    tidesdb_imm_snapshot_ctx_t *ctx = (tidesdb_imm_snapshot_ctx_t *)context;
    if (!ctx || ctx->failed || !data) return;

    if (ctx->count >= ctx->capacity)
    {
        const size_t new_capacity = ctx->capacity * 2;
        tidesdb_immutable_memtable_t **new_items;
        if (!ctx->heap_allocated)
        {
            /* first overflow from stack to heap */
            new_items = malloc(new_capacity * sizeof(tidesdb_immutable_memtable_t *));
            if (!new_items)
            {
                ctx->failed = 1;
                return;
            }
            memcpy(new_items, ctx->stack_items,
                   ctx->count * sizeof(tidesdb_immutable_memtable_t *));
            ctx->heap_allocated = 1;
        }
        else
        {
            new_items = realloc(ctx->items, new_capacity * sizeof(tidesdb_immutable_memtable_t *));
            if (!new_items)
            {
                ctx->failed = 1;
                return;
            }
        }
        ctx->items = new_items;
        ctx->capacity = new_capacity;
    }

    tidesdb_immutable_memtable_t *imm = (tidesdb_immutable_memtable_t *)data;
    tidesdb_immutable_memtable_ref(imm);
    ctx->items[ctx->count++] = imm;
}

static tidesdb_immutable_memtable_t **tidesdb_snapshot_immutable_memtables(queue_t *queue,
                                                                           size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (!queue) return NULL;

    tidesdb_imm_snapshot_ctx_t ctx = {0};
    ctx.capacity = TDB_IMM_SNAPSHOT_STACK_SIZE;
    ctx.items = ctx.stack_items;
    ctx.heap_allocated = 0;

    queue_foreach(queue, tidesdb_collect_imm_snapshot, &ctx);

    if (ctx.failed || ctx.count == 0)
    {
        for (size_t i = 0; i < ctx.count; i++)
        {
            if (ctx.items[i]) tidesdb_immutable_memtable_unref(ctx.items[i]);
        }
        if (ctx.heap_allocated) free(ctx.items);
        return NULL;
    }

    /* if still on stack, copy to heap for caller ownership */
    if (!ctx.heap_allocated)
    {
        tidesdb_immutable_memtable_t **heap_items =
            malloc(ctx.count * sizeof(tidesdb_immutable_memtable_t *));
        if (!heap_items)
        {
            for (size_t i = 0; i < ctx.count; i++)
            {
                if (ctx.items[i]) tidesdb_immutable_memtable_unref(ctx.items[i]);
            }
            return NULL;
        }
        memcpy(heap_items, ctx.stack_items, ctx.count * sizeof(tidesdb_immutable_memtable_t *));
        ctx.items = heap_items;
    }

    if (out_count) *out_count = ctx.count;
    return ctx.items;
}

/**
 * tidesdb_write_vlog_entry
 * write a large value to vlog and update kv with offset
 * @param sst sstable
 * @param vlog_bm vlog block manager
 * @param kv key-value pair (vlog_offset updated on success)
 * @param vlog_block_num counter to increment
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_write_vlog_entry(const tidesdb_sstable_t *sst, block_manager_t *vlog_bm,
                                    tidesdb_kv_pair_t *kv, uint64_t *vlog_block_num)
{
    const uint8_t *final_data = kv->value;
    size_t final_size = kv->entry.value_size;
    uint8_t *compressed = NULL;

    if (sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        size_t compressed_size;
        compressed = compress_data(kv->value, kv->entry.value_size, &compressed_size,
                                   sst->config->compression_algorithm);
        if (!compressed)
        {
            return TDB_ERR_CORRUPTION;
        }
        final_data = compressed;
        final_size = compressed_size;
    }

    block_manager_block_t *vlog_block = block_manager_block_create(final_size, final_data);
    if (vlog_block)
    {
        const int64_t block_offset = block_manager_block_write(vlog_bm, vlog_block);
        if (block_offset >= 0)
        {
            kv->entry.vlog_offset = (uint64_t)block_offset;
            (*vlog_block_num)++;
        }
        block_manager_block_release(vlog_block);
    }

    free(compressed);
    return TDB_SUCCESS;
}

/**
 * tidesdb_flush_klog_block
 * serialize and write a klog block to disk
 * @param sst sstable
 * @param klog_bm klog block manager
 * @param block klog block to flush
 * @param block_indexes optional block index to update
 * @param block_first_key first key in block
 * @param block_first_key_size size of first key
 * @param block_last_key last key in block
 * @param block_last_key_size size of last key
 * @param klog_block_num block counter (incremented on success)
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_flush_klog_block(const tidesdb_sstable_t *sst, block_manager_t *klog_bm,
                                    tidesdb_klog_block_t *block,
                                    tidesdb_block_index_t *block_indexes,
                                    const uint8_t *block_first_key,
                                    const size_t block_first_key_size,
                                    const uint8_t *block_last_key, const size_t block_last_key_size,
                                    uint64_t *klog_block_num)
{
    if (block->num_entries == 0) return TDB_SUCCESS;

    uint8_t *klog_data;
    size_t klog_size;
    if (tidesdb_klog_block_serialize(block, &klog_data, &klog_size) != 0)
    {
        return TDB_ERR_MEMORY;
    }

    uint8_t *final_klog_data = klog_data;
    size_t final_klog_size = klog_size;

    if (sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        size_t compressed_size;
        uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                            sst->config->compression_algorithm);
        if (compressed)
        {
            free(klog_data);
            final_klog_data = compressed;
            final_klog_size = compressed_size;
        }
        else
        {
            free(klog_data);
            return TDB_ERR_CORRUPTION;
        }
    }

    block_manager_block_t *klog_block =
        block_manager_block_create(final_klog_size, final_klog_data);
    if (!klog_block)
    {
        free(final_klog_data);
        return TDB_ERR_MEMORY;
    }

    /* we capture file position before writing */
    const uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);

    block_manager_block_write(klog_bm, klog_block);
    block_manager_block_release(klog_block);

    /* we add to index if enabled and sampling matches */
    if (block_indexes && block_first_key && block_last_key)
    {
        if (*klog_block_num % sst->config->index_sample_ratio == 0)
        {
            compact_block_index_add(block_indexes, block_first_key, block_first_key_size,
                                    block_last_key, block_last_key_size, block_file_position);
        }
    }

    (*klog_block_num)++;
    free(final_klog_data);
    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_write_footer
 * write index, bloom filter, and metadata blocks to klog
 * @param sst sstable (block_indexes and bloom_filter assigned here)
 * @param klog_bm klog block manager
 * @param vlog_bm vlog block manager
 * @param block_indexes block indexes (ownership transferred to sst)
 * @param bloom bloom filter (ownership transferred to sst)
 * @return TDB_SUCCESS on success
 */
static int tidesdb_sstable_write_footer(tidesdb_sstable_t *sst, block_manager_t *klog_bm,
                                        block_manager_t *vlog_bm,
                                        tidesdb_block_index_t *block_indexes, bloom_filter_t *bloom)
{
    /* we capture klog file offset where data blocks end */
    block_manager_get_size(klog_bm, &sst->klog_data_end_offset);

    /* we write index block */
    if (block_indexes)
    {
        sst->block_indexes = block_indexes;

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "SSTable " TDB_U64_FMT " block indexes built - %" PRIu32
                      " samples, " TDB_U64_FMT " total blocks",
                      TDB_U64_CAST(sst->id), sst->block_indexes->count,
                      TDB_U64_CAST(sst->num_klog_blocks));

        size_t index_size;
        uint8_t *index_data = compact_block_index_serialize(sst->block_indexes, &index_size);
        if (index_data)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes serialized to %zu bytes",
                          sst->id, index_size);
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(klog_bm, index_block);
                block_manager_block_release(index_block);
            }
            free(index_data);
        }
    }
    else
    {
        /* we write empty index block as placeholder */
        uint8_t empty_index_data[5];
        encode_uint32_le_compat(empty_index_data, 0);
        empty_index_data[4] = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN;
        block_manager_block_t *empty_index = block_manager_block_create(5, empty_index_data);
        if (empty_index)
        {
            block_manager_block_write(klog_bm, empty_index);
            block_manager_block_release(empty_index);
        }
    }

    /* we write bloom filter block */
    if (bloom)
    {
        size_t bloom_size;
        uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(klog_bm, bloom_block);
                block_manager_block_release(bloom_block);
            }
            free(bloom_data);
        }
        sst->bloom_filter = bloom;
    }
    else
    {
        /* we write empty bloom block as placeholder */
        const uint8_t empty_bloom_data[1] = {0};
        block_manager_block_t *empty_bloom = block_manager_block_create(1, empty_bloom_data);
        if (empty_bloom)
        {
            block_manager_block_write(klog_bm, empty_bloom);
            block_manager_block_release(empty_bloom);
        }
    }

    /* we write metadata block */
    uint64_t klog_size_before_metadata;
    uint64_t vlog_size_before_metadata;
    block_manager_get_size(klog_bm, &klog_size_before_metadata);
    block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

    sst->klog_size = klog_size_before_metadata;
    sst->vlog_size = vlog_size_before_metadata;

    uint8_t *metadata_data = NULL;
    size_t metadata_size = 0;
    if (sstable_metadata_serialize(sst, &metadata_data, &metadata_size) == 0)
    {
        block_manager_block_t *metadata_block =
            block_manager_block_create(metadata_size, metadata_data);
        if (metadata_block)
        {
            block_manager_block_write(klog_bm, metadata_block);
            block_manager_block_release(metadata_block);
        }
        free(metadata_data);
    }

    /* we get final file sizes */
    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    if (klog_bm) block_manager_escalate_fsync(klog_bm);
    if (vlog_bm) block_manager_escalate_fsync(vlog_bm);

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_write_from_memtable_btree
 * write a memtable to an sstable using B+tree format
 * @param db database instance
 * @param sst sstable to write to
 * @param memtable memtable to write from
 * @return 0 on success, -1 on error
 */
static int tidesdb_sstable_write_from_memtable_btree(tidesdb_t *db, tidesdb_sstable_t *sst,
                                                     skip_list_t *memtable)
{
    if (!db || !sst || !memtable) return TDB_ERR_INVALID_ARGS;

    int num_entries = skip_list_count_entries(memtable);
    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "SSTable %" PRIu64 " writing from memtable using B+tree (%d entries)", sst->id,
                  num_entries);

    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to ensure open", sst->id);
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to get block managers", sst->id);
        return TDB_ERR_IO;
    }

    block_manager_t *klog_bm = bms.klog_bm;
    block_manager_t *vlog_bm = bms.vlog_bm;

    /* resolve comparator from column family config */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(db, sst->config, &comparator_fn, &comparator_ctx);

    /* we create btree builder with column family's comparator
     * btree uses BTREE_CMP_CUSTOM when a custom comparator is provided */
    const btree_config_t btree_config = {
        .target_node_size = BTREE_DEFAULT_NODE_SIZE,
        .value_threshold = sst->config->klog_value_threshold,
        .comparator = (btree_comparator_fn)comparator_fn,
        .comparator_ctx = comparator_ctx,
        .cmp_type = comparator_fn ? BTREE_CMP_CUSTOM : BTREE_CMP_MEMCMP,
        .compression_algo = sst->config->compression_algorithm};

    btree_builder_t *builder = NULL;
    if (btree_builder_new(&builder, klog_bm, &btree_config) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to create btree builder", sst->id);
        return TDB_ERR_MEMORY;
    }

    /* we create bloom filter if enabled */
    bloom_filter_t *bloom = NULL;
    if (sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, sst->config->bloom_fpr, num_entries) != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to create bloom filter",
                          sst->id);
            btree_builder_free(builder);
            return TDB_ERR_MEMORY;
        }
    }

    /* iterate memtable and add entries to btree */
    skip_list_cursor_t *cursor = NULL;
    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        if (bloom) bloom_filter_free(bloom);
        btree_builder_free(builder);
        return TDB_ERR_MEMORY;
    }

    uint64_t entry_count = 0;
    uint64_t max_seq = 0;

    while (skip_list_cursor_valid(cursor))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get_with_seq(cursor, &key, &key_size, &value, &value_size, &ttl,
                                          &deleted, &seq) != 0)
        {
            skip_list_cursor_next(cursor);
            continue;
        }

        /* write value to vlog and get offset */
        uint64_t vlog_offset = 0;
        if (value && value_size > 0 && !deleted)
        {
            block_manager_block_t *vlog_block = block_manager_block_create(value_size, value);
            if (vlog_block)
            {
                int64_t offset = block_manager_block_write(vlog_bm, vlog_block);
                if (offset >= 0)
                {
                    vlog_offset = (uint64_t)offset;
                }
                block_manager_block_release(vlog_block);
            }
        }

        /* we add to btree */
        const uint8_t flags = deleted ? 1 : 0; /* BTREE_ENTRY_FLAG_TOMBSTONE = 1 */
        if (btree_builder_add(builder, key, key_size, NULL, value_size, vlog_offset, seq, ttl,
                              flags) != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to add entry to btree",
                          sst->id);
        }

        /* we add to bloom filter */
        if (bloom)
        {
            bloom_filter_add(bloom, key, key_size);
        }

        if (seq > max_seq) max_seq = seq;
        entry_count++;

        skip_list_cursor_next(cursor);
    }

    skip_list_cursor_free(cursor);

    /* we finish btree build */
    btree_t *tree = NULL;
    if (btree_builder_finish(builder, &tree) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to finish btree", sst->id);
        if (bloom) bloom_filter_free(bloom);
        btree_builder_free(builder);
        return TDB_ERR_IO;
    }

    /* we copy btree metadata to sstable */
    sst->use_btree = 1;
    sst->btree_root_offset = tree->root_offset;
    sst->btree_first_leaf = tree->first_leaf_offset;
    sst->btree_last_leaf = tree->last_leaf_offset;
    sst->btree_node_count = tree->node_count;
    sst->btree_height = tree->height;
    sst->num_entries = entry_count;
    sst->max_seq = max_seq;

    /* copy min/max keys */
    if (tree->min_key && tree->min_key_size > 0)
    {
        sst->min_key = malloc(tree->min_key_size);
        if (sst->min_key)
        {
            memcpy(sst->min_key, tree->min_key, tree->min_key_size);
            sst->min_key_size = tree->min_key_size;
        }
    }
    if (tree->max_key && tree->max_key_size > 0)
    {
        sst->max_key = malloc(tree->max_key_size);
        if (sst->max_key)
        {
            memcpy(sst->max_key, tree->max_key, tree->max_key_size);
            sst->max_key_size = tree->max_key_size;
        }
    }

    btree_free(tree);
    btree_builder_free(builder);

    /* we write bloom filter block */
    if (bloom)
    {
        size_t bloom_size = 0;
        uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(klog_bm, bloom_block);
                block_manager_block_release(bloom_block);
            }
            free(bloom_data);
        }
        sst->bloom_filter = bloom;
    }
    else
    {
        const uint8_t empty_bloom_data[1] = {0};
        block_manager_block_t *empty_bloom = block_manager_block_create(1, empty_bloom_data);
        if (empty_bloom)
        {
            block_manager_block_write(klog_bm, empty_bloom);
            block_manager_block_release(empty_bloom);
        }
    }

    /* write metadata block */
    uint64_t klog_size_before_metadata;
    uint64_t vlog_size_before_metadata;
    block_manager_get_size(klog_bm, &klog_size_before_metadata);
    block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

    sst->klog_size = klog_size_before_metadata;
    sst->vlog_size = vlog_size_before_metadata;

    uint8_t *metadata_data = NULL;
    size_t metadata_size = 0;
    if (sstable_metadata_serialize(sst, &metadata_data, &metadata_size) == 0)
    {
        block_manager_block_t *metadata_block =
            block_manager_block_create(metadata_size, metadata_data);
        if (metadata_block)
        {
            block_manager_block_write(klog_bm, metadata_block);
            block_manager_block_release(metadata_block);
        }
        free(metadata_data);
    }

    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    if (klog_bm) block_manager_escalate_fsync(klog_bm);
    if (vlog_bm) block_manager_escalate_fsync(vlog_bm);

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "SSTable %" PRIu64 " btree flush complete: %" PRIu64 " entries, root=%ld",
                  sst->id, entry_count, sst->btree_root_offset);

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_write_from_heap_btree
 * write merged entries from a heap to an sstable using B+tree format
 * @param cf column family
 * @param sst sstable to write to
 * @param heap merge heap containing entries
 * @param klog_bm klog block manager (already open)
 * @param vlog_bm vlog block manager (already open)
 * @param bloom bloom filter (optional, may be NULL)
 * @param sstables_to_delete queue for corrupted sstables
 * @param is_largest_level whether this is the largest level
 * @return 0 on success, error code on failure
 */
static int tidesdb_sstable_write_from_heap_btree(tidesdb_column_family_t *cf,
                                                 tidesdb_sstable_t *sst, tidesdb_merge_heap_t *heap,
                                                 block_manager_t *klog_bm, block_manager_t *vlog_bm,
                                                 bloom_filter_t *bloom, queue_t *sstables_to_delete,
                                                 const int is_largest_level)
{
    if (!cf || !sst || !heap || !klog_bm || !vlog_bm) return TDB_ERR_INVALID_ARGS;

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    btree_config_t btree_config = {
        .target_node_size = BTREE_DEFAULT_NODE_SIZE,
        .value_threshold = cf->config.klog_value_threshold,
        .cmp_type = comparator_fn ? BTREE_CMP_CUSTOM : BTREE_CMP_MEMCMP,
        .comparator = (btree_comparator_fn)comparator_fn,
        .comparator_ctx = comparator_ctx,
        .compression_algo = cf->config.compression_algorithm,
    };

    btree_builder_t *builder = NULL;
    if (btree_builder_new(&builder, klog_bm, &btree_config) != 0)
    {
        return TDB_ERR_MEMORY;
    }

    uint8_t *last_key = NULL;
    size_t last_key_size = 0;
    uint64_t entry_count = 0;
    uint64_t max_seq = 0;
    uint64_t vlog_block_num = 0;

    while (!tidesdb_merge_heap_empty(heap))
    {
        tidesdb_sstable_t *corrupted_sst = NULL;
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap, &corrupted_sst);

        if (corrupted_sst && sstables_to_delete)
        {
            queue_enqueue(sstables_to_delete, corrupted_sst);
        }

        if (!kv) break;

        if (last_key && last_key_size == kv->entry.key_size &&
            memcmp(last_key, kv->key, last_key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        free(last_key);
        last_key = malloc(kv->entry.key_size);
        if (last_key)
        {
            memcpy(last_key, kv->key, kv->entry.key_size);
            last_key_size = kv->entry.key_size;
        }

        /* we only drop tombstones when merging into the largest level */
        if ((kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) && is_largest_level)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (kv->entry.ttl > 0 && kv->entry.ttl < atomic_load_explicit(&cf->db->cached_current_time,
                                                                      memory_order_relaxed))
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (bloom)
        {
            bloom_filter_add(bloom, kv->key, kv->entry.key_size);
        }

        uint64_t vlog_offset = 0;
        if (kv->entry.value_size >= cf->config.klog_value_threshold && kv->value)
        {
            uint8_t *final_data = kv->value;
            size_t final_size = kv->entry.value_size;
            uint8_t *compressed = NULL;

            if (sst->config->compression_algorithm != TDB_COMPRESS_NONE)
            {
                size_t compressed_size;
                compressed = compress_data(kv->value, kv->entry.value_size, &compressed_size,
                                           sst->config->compression_algorithm);
                if (compressed)
                {
                    final_data = compressed;
                    final_size = compressed_size;
                }
            }

            block_manager_block_t *vlog_block = block_manager_block_create(final_size, final_data);
            if (vlog_block)
            {
                const int64_t block_offset = block_manager_block_write(vlog_bm, vlog_block);
                if (block_offset >= 0)
                {
                    vlog_offset = (uint64_t)block_offset;
                    vlog_block_num++;
                }
                block_manager_block_release(vlog_block);
            }
            free(compressed);
        }

        const uint8_t *value_to_store = (vlog_offset > 0) ? NULL : kv->value;
        const size_t value_size_to_store = (vlog_offset > 0) ? 0 : kv->entry.value_size;

        if (btree_builder_add(builder, kv->key, kv->entry.key_size, value_to_store,
                              value_size_to_store, vlog_offset, kv->entry.seq, kv->entry.ttl,
                              (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) != 0) != 0)
        {
            tidesdb_kv_pair_free(kv);
            free(last_key);
            btree_builder_free(builder);
            return TDB_ERR_IO;
        }

        if (kv->entry.seq > max_seq) max_seq = kv->entry.seq;

        if (!sst->min_key)
        {
            sst->min_key = malloc(kv->entry.key_size);
            if (sst->min_key)
            {
                memcpy(sst->min_key, kv->key, kv->entry.key_size);
                sst->min_key_size = kv->entry.key_size;
            }
        }

        free(sst->max_key);
        sst->max_key = malloc(kv->entry.key_size);
        if (sst->max_key)
        {
            memcpy(sst->max_key, kv->key, kv->entry.key_size);
            sst->max_key_size = kv->entry.key_size;
        }

        entry_count++;
        tidesdb_kv_pair_free(kv);
    }

    free(last_key);

    btree_t *tree = NULL;
    if (btree_builder_finish(builder, &tree) != 0 || !tree)
    {
        btree_builder_free(builder);
        return TDB_ERR_IO;
    }

    sst->btree_root_offset = tree->root_offset;
    sst->btree_first_leaf = tree->first_leaf_offset;
    sst->btree_last_leaf = tree->last_leaf_offset;
    sst->btree_node_count = tree->node_count;
    sst->btree_height = tree->height;
    sst->num_entries = entry_count;
    sst->max_seq = max_seq;
    sst->num_vlog_blocks = vlog_block_num;

    block_manager_get_size(klog_bm, &sst->klog_data_end_offset);
    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    if (bloom)
    {
        size_t bloom_size;
        uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(klog_bm, bloom_block);
                block_manager_block_release(bloom_block);
            }
            free(bloom_data);
        }
        sst->bloom_filter = bloom;
    }

    uint8_t *metadata = NULL;
    size_t metadata_size = 0;
    if (sstable_metadata_serialize(sst, &metadata, &metadata_size) == 0 && metadata)
    {
        block_manager_block_t *metadata_block = block_manager_block_create(metadata_size, metadata);
        if (metadata_block)
        {
            block_manager_block_write(klog_bm, metadata_block);
            block_manager_block_release(metadata_block);
        }
        free(metadata);
    }

    btree_free(tree);
    btree_builder_free(builder);

    if (klog_bm) block_manager_escalate_fsync(klog_bm);
    if (vlog_bm) block_manager_escalate_fsync(vlog_bm);

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_write_from_memtable
 * write a memtable to an sstable
 * @param db database instance
 * @param sst sstable to write to
 * @param memtable memtable to write from
 * @return 0 on success, -1 on error
 */
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable)
{
    if (!db || !sst || !memtable) return TDB_ERR_INVALID_ARGS;

    int num_entries = skip_list_count_entries(memtable);
    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "SSTable %" PRIu64 " writing from memtable (sorted run to disk) (%d entries)",
                  sst->id, num_entries);

    /* we ensure sstable is open and get block managers */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to ensure open", sst->id);
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to get block managers", sst->id);
        return TDB_ERR_IO;
    }

    /* we create bloom filter and block indexes */
    int result = TDB_SUCCESS;
    bloom_filter_t *bloom = NULL;
    tidesdb_block_index_t *block_indexes = NULL;
    tidesdb_klog_block_t *current_klog_block = NULL;
    skip_list_cursor_t *cursor = NULL;
    uint8_t *first_key = NULL;
    uint8_t *last_key = NULL;
    uint8_t *block_first_key = NULL;
    uint8_t *block_last_key = NULL;

    /* we resolve comparator once for the entire flush operation */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

    if (sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, sst->config->bloom_fpr, num_entries) != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to create bloom filter",
                          sst->id);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "SSTable %" PRIu64 " bloom filter created (fpr: %.4f, entries: %d)", sst->id,
                      sst->config->bloom_fpr, num_entries);
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " bloom filter disabled", sst->id);
    }

    if (sst->config->enable_block_indexes)
    {
        uint32_t initial_capacity = (num_entries / sst->config->index_sample_ratio) + 1;
        block_indexes = compact_block_index_create(
            initial_capacity, sst->config->block_index_prefix_len, comparator_fn, comparator_ctx);
        if (!block_indexes)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to create block indexes",
                          sst->id);
            result = TDB_ERR_MEMORY;
            goto cleanup;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes enabled (sample ratio: %d)",
                      sst->id, sst->config->index_sample_ratio);
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes disabled", sst->id);
    }

    /* we initialize klog block and cursor */
    current_klog_block = tidesdb_klog_block_create();
    if (!current_klog_block)
    {
        result = TDB_ERR_MEMORY;
        goto cleanup;
    }

    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        result = TDB_ERR_MEMORY;
        goto cleanup;
    }

    /* we iterate memtable and write entries */
    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    size_t first_key_size = 0;
    size_t last_key_size = 0;
    uint64_t entry_count = 0;
    uint64_t max_seq = 0;
    size_t block_first_key_size = 0;
    size_t block_last_key_size = 0;

    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        size_t block_first_key_capacity = 0;
        size_t block_last_key_capacity = 0;
        size_t first_key_capacity = 0;
        size_t last_key_capacity = 0;
        /* we use stack-allocated KV pair to avoid malloc/free per entry */
        tidesdb_kv_pair_t kv_stack = {0};

        do
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            int64_t ttl;
            uint8_t deleted;
            uint64_t seq;

            if (skip_list_cursor_get_with_seq(cursor, &key, &key_size, &value, &value_size, &ttl,
                                              &deleted, &seq) != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_WARN,
                              "Skipping entry during flush - cursor read failed (entry %" PRIu64
                              ")",
                              entry_count);
                continue;
            }

            /* we populate stack-allocated KV pair (no malloc needed) */
            kv_stack.key = key;
            kv_stack.value = value;
            kv_stack.entry.key_size = (uint32_t)key_size;
            kv_stack.entry.value_size = (uint32_t)value_size;
            kv_stack.entry.ttl = ttl;
            kv_stack.entry.seq = seq;
            kv_stack.entry.flags = deleted ? TDB_KV_FLAG_TOMBSTONE : 0;
            if (ttl != 0) kv_stack.entry.flags |= TDB_KV_FLAG_HAS_TTL;
            kv_stack.entry.vlog_offset = 0;

            /* we write large values to vlog */
            if (value_size >= sst->config->klog_value_threshold && !deleted && value)
            {
                result = tidesdb_write_vlog_entry(sst, bms.vlog_bm, &kv_stack, &vlog_block_num);
                if (result != TDB_SUCCESS)
                {
                    goto cleanup;
                }
            }

            /* we track first key of block */
            const int is_first_entry_in_block = (current_klog_block->num_entries == 0);
            tidesdb_klog_block_add_entry(current_klog_block, &kv_stack, sst->config, comparator_fn,
                                         comparator_ctx);

            /* we reuse block_first_key buffer with capacity tracking */
            if (is_first_entry_in_block)
            {
                if (key_size > block_first_key_capacity)
                {
                    free(block_first_key);
                    block_first_key = malloc(key_size);
                    block_first_key_capacity = block_first_key ? key_size : 0;
                }
                if (block_first_key)
                {
                    memcpy(block_first_key, key, key_size);
                    block_first_key_size = key_size;
                }
            }

            /* we reuse block_last_key buffer with capacity tracking */
            if (key_size > block_last_key_capacity)
            {
                free(block_last_key);
                block_last_key = malloc(key_size);
                block_last_key_capacity = block_last_key ? key_size : 0;
            }
            if (block_last_key)
            {
                memcpy(block_last_key, key, key_size);
                block_last_key_size = key_size;
            }

            /* we flush full klog block */
            if (tidesdb_klog_block_is_full(current_klog_block, TDB_KLOG_BLOCK_SIZE))
            {
                result = tidesdb_flush_klog_block(
                    sst, bms.klog_bm, current_klog_block, block_indexes, block_first_key,
                    block_first_key_size, block_last_key, block_last_key_size, &klog_block_num);
                if (result != TDB_SUCCESS)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " klog block flush failed",
                                  sst->id);
                    goto cleanup;
                }

                tidesdb_klog_block_free(current_klog_block);
                current_klog_block = tidesdb_klog_block_create();

                /* reset sizes but keep buffers for reuse */
                block_first_key_size = 0;
                block_last_key_size = 0;
            }

            /* we track max sequence */
            if (seq > max_seq) max_seq = seq;

            if (bloom) bloom_filter_add(bloom, key, key_size);

            /* we reuse first_key buffer with capacity tracking */
            if (first_key_size == 0)
            {
                if (key_size > first_key_capacity)
                {
                    free(first_key);
                    first_key = malloc(key_size);
                    first_key_capacity = first_key ? key_size : 0;
                }
                if (first_key)
                {
                    memcpy(first_key, key, key_size);
                    first_key_size = key_size;
                }
            }

            /* we reuse last_key buffer with capacity tracking */
            if (key_size > last_key_capacity)
            {
                free(last_key);
                last_key = malloc(key_size);
                last_key_capacity = last_key ? key_size : 0;
            }
            if (last_key)
            {
                memcpy(last_key, key, key_size);
                last_key_size = key_size;
            }

            sst->num_entries++;
            entry_count++;

        } while (skip_list_cursor_next(cursor) == 0);
    }

    skip_list_cursor_free(cursor);
    cursor = NULL;

    /* we flush remaining klog block */
    if (current_klog_block && current_klog_block->num_entries > 0)
    {
        result = tidesdb_flush_klog_block(sst, bms.klog_bm, current_klog_block, block_indexes,
                                          block_first_key, block_first_key_size, block_last_key,
                                          block_last_key_size, &klog_block_num);
        if (result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " final klog block flush failed",
                          sst->id);
            goto cleanup;
        }
    }

    free(block_first_key);
    free(block_last_key);
    block_first_key = NULL;
    block_last_key = NULL;

    tidesdb_klog_block_free(current_klog_block);
    current_klog_block = NULL;

    /* we finalize sstable metadata */
    sst->num_entries = entry_count;
    sst->num_klog_blocks = klog_block_num;
    sst->num_vlog_blocks = vlog_block_num;
    sst->min_key = first_key;
    sst->min_key_size = first_key_size;
    sst->max_key = last_key;
    sst->max_key_size = last_key_size;
    sst->max_seq = max_seq;

    /* ownership transferred to sst */
    first_key = NULL;
    last_key = NULL;

    /* we write footer (index, bloom, metadata) */
    result = tidesdb_sstable_write_footer(sst, bms.klog_bm, bms.vlog_bm, block_indexes, bloom);

    /* ownership transferred to sst via footer */
    block_indexes = NULL;
    bloom = NULL;

    return result;

cleanup:
    if (cursor) skip_list_cursor_free(cursor);
    if (current_klog_block) tidesdb_klog_block_free(current_klog_block);
    if (bloom) bloom_filter_free(bloom);
    if (block_indexes) compact_block_index_free(block_indexes);
    free(first_key);
    free(last_key);
    free(block_first_key);
    free(block_last_key);
    return result;
}

/**
 * tidesdb_klog_block_find_key
 * binary search for a key in a klog block
 * @param block the klog block to search
 * @param key the key to find
 * @param key_size the size of the key
 * @param comparator_fn the comparator function
 * @param comparator_ctx the comparator context
 * @param found_idx output: index of found key, or -1 if not found
 * @return 0 if found, -1 if not found
 */
static int tidesdb_klog_block_find_key(const tidesdb_klog_block_t *block, const uint8_t *key,
                                       const size_t key_size, skip_list_comparator_fn comparator_fn,
                                       void *comparator_ctx, int32_t *found_idx)
{
    *found_idx = -1;

    if (!block || block->num_entries == 0) return -1;

    int32_t left = 0;
    int32_t right = (int32_t)block->num_entries - 1;

    while (left <= right)
    {
        const int32_t mid = left + (right - left) / 2;
        const int cmp = comparator_fn(key, key_size, block->keys[mid], block->entries[mid].key_size,
                                      comparator_ctx);

        if (cmp == 0)
        {
            *found_idx = mid;
            return 0;
        }
        if (cmp < 0)
        {
            right = mid - 1;
        }
        else
        {
            left = mid + 1;
        }
    }

    return -1;
}

/**
 * tidesdb_kv_pair_load_value
 * load value for a kv pair from inline storage or vlog
 * @param db the database
 * @param sst the sstable
 * @param block the klog block containing the entry
 * @param idx the index of the entry in the block
 * @param kv the kv pair to populate with value
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_kv_pair_load_value(const tidesdb_t *db, tidesdb_sstable_t *sst,
                                      const tidesdb_klog_block_t *block, const uint32_t idx,
                                      tidesdb_kv_pair_t *kv)
{
    const uint64_t vlog_offset = block->entries[idx].vlog_offset;
    const size_t value_size = block->entries[idx].value_size;

    if (vlog_offset == 0 && block->inline_values[idx] && value_size > 0)
    {
        /* inline value path -- data already in memory */
        kv->value = malloc(value_size);
        if (!kv->value) return TDB_ERR_MEMORY;

        memcpy(kv->value, block->inline_values[idx], value_size);
    }
    else if (vlog_offset > 0)
    {
        /* vlog path -- requires disk I/O */
        if (tidesdb_vlog_read_value(db, sst, vlog_offset, value_size, &kv->value) != TDB_SUCCESS)
        {
            return TDB_ERR_IO;
        }
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_read_klog_block_cached
 * read a klog block with cache support
 * @param db the database
 * @param sst the sstable
 * @param cursor the block manager cursor
 * @param block_position the file position of the block
 * @param cf_name the column family name (for cache key)
 * @param has_cf_name whether cf_name is valid
 * @param advance_cursor if true, advance cursor after reading (avoids redundant pread)
 * @param klog_block_out output: the deserialized klog block
 * @param rc_block_out output: ref-counted block if from cache (NULL if not cached)
 * @param raw_block_out output: raw block if read from disk (NULL if from cache)
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_read_klog_block_cached(tidesdb_t *db, tidesdb_sstable_t *sst,
                                          block_manager_cursor_t *cursor,
                                          const uint64_t block_position, const char *cf_name,
                                          const int has_cf_name, const int advance_cursor,
                                          tidesdb_klog_block_t **klog_block_out,
                                          tidesdb_ref_counted_block_t **rc_block_out,
                                          block_manager_block_t **raw_block_out)
{
    *klog_block_out = NULL;
    *rc_block_out = NULL;
    *raw_block_out = NULL;

    /* we try cache first */
    if (db->clock_cache && has_cf_name)
    {
        *klog_block_out =
            tidesdb_cache_block_get(db, cf_name, sst->klog_path, block_position, rc_block_out);
        if (*klog_block_out)
        {
            PROFILE_INC(db, cache_block_hits);
            return TDB_SUCCESS;
        }
    }

    /* we read from disk */
    PROFILE_INC(db, cache_block_misses);
    PROFILE_INC(db, disk_reads);

    block_manager_block_t *block = advance_cursor ? tidesdb_read_block_and_advance(db, sst, cursor)
                                                  : tidesdb_read_block(db, sst, cursor);
    if (!block)
    {
        return TDB_ERR_IO;
    }

    PROFILE_INC(db, blocks_read);

    tidesdb_klog_block_t *klog_block = NULL;
    const int deser_result = tidesdb_klog_block_deserialize(block->data, block->size, &klog_block);
    if (deser_result != 0)
    {
        block_manager_block_release(block);
        return TDB_ERR_CORRUPTION;
    }

    /* we add to cache if enabled */
    if (db->clock_cache && has_cf_name && klog_block)
    {
        tidesdb_cache_block_put(db, cf_name, sst->klog_path, block_position, block->data,
                                block->size);
    }

    *klog_block_out = klog_block;
    *raw_block_out = block;
    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_get_btree
 * get a key-value pair from a btree-based sstable
 * @param db the database
 * @param sst the sstable
 * @param key the key
 * @param key_size the size of the key
 * @param kv the key-value pair
 */
static int tidesdb_sstable_get_btree(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                                     const size_t key_size, tidesdb_kv_pair_t **kv)
{
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "SSTable %" PRIu64 " failed to ensure open (btree)", sst->id);
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        return TDB_ERR_IO;
    }

    if (!sst->min_key || !sst->max_key)
    {
        return TDB_ERR_NOT_FOUND;
    }

    /* we use cached comparator from sstable (resolved at load/create time) */
    skip_list_comparator_fn comparator_fn = sst->cached_comparator_fn;
    void *comparator_ctx = sst->cached_comparator_ctx;
    if (TDB_UNLIKELY(!comparator_fn))
    {
        tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);
    }

    const int min_cmp =
        comparator_fn(key, key_size, sst->min_key, sst->min_key_size, comparator_ctx);
    const int max_cmp =
        comparator_fn(key, key_size, sst->max_key, sst->max_key_size, comparator_ctx);

    if (min_cmp < 0 || max_cmp > 0)
    {
        return TDB_ERR_NOT_FOUND;
    }

    if (sst->bloom_filter)
    {
        PROFILE_INC(db, bloom_checks);
        if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
        {
            return TDB_ERR_NOT_FOUND;
        }
        PROFILE_INC(db, bloom_hits);
    }

    btree_t tree = {.bm = bms.klog_bm,
                    .root_offset = sst->btree_root_offset,
                    .first_leaf_offset = sst->btree_first_leaf,
                    .last_leaf_offset = sst->btree_last_leaf,
                    .config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                               .value_threshold = sst->config->klog_value_threshold,
                               .comparator = (btree_comparator_fn)comparator_fn,
                               .comparator_ctx = comparator_ctx,
                               .cmp_type = comparator_fn ? BTREE_CMP_CUSTOM : BTREE_CMP_MEMCMP,
                               .compression_algo = sst->config->compression_algorithm},
                    .node_cache = db->btree_node_cache,
                    .cache_key_prefix = sst->id};

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    const int result =
        btree_get(&tree, key, key_size, &value, &value_size, &vlog_offset, &seq, &ttl, &deleted);
    if (result != 0)
    {
        return TDB_ERR_NOT_FOUND;
    }

    /* we return tombstones so caller can handle cross-level masking
     * the caller (tidesdb_txn_get) needs to see tombstones to properly
     * mask keys in lower levels */
    if (deleted)
    {
        *kv = tidesdb_kv_pair_create(key, key_size, NULL, 0, ttl, seq, 1);
        free(value);
        if (!*kv) return TDB_ERR_MEMORY;
        return TDB_SUCCESS;
    }

    /* we check TTL */
    if (ttl > 0)
    {
        const int64_t now = (int64_t)atomic_load(&db->cached_current_time);
        if (now > ttl)
        {
            free(value);
            return TDB_ERR_NOT_FOUND;
        }
    }

    /* if value is in vlog, read it */
    if (vlog_offset > 0)
    {
        free(value); /* free placeholder if any */
        value = NULL;

        block_manager_cursor_t vlog_cursor;
        if (block_manager_cursor_init_stack(&vlog_cursor, bms.vlog_bm) != 0)
        {
            return TDB_ERR_IO;
        }

        block_manager_cursor_goto(&vlog_cursor, vlog_offset);
        block_manager_block_t *vlog_block = block_manager_cursor_read(&vlog_cursor);
        if (!vlog_block)
        {
            return TDB_ERR_IO;
        }

        value = malloc(vlog_block->size);
        if (!value)
        {
            block_manager_block_free(vlog_block);
            return TDB_ERR_MEMORY;
        }
        memcpy(value, vlog_block->data, vlog_block->size);
        value_size = vlog_block->size;
        block_manager_block_free(vlog_block);
    }

    /* we create kv pair */
    tidesdb_kv_pair_t *pair = malloc(sizeof(tidesdb_kv_pair_t));
    if (!pair)
    {
        free(value);
        return TDB_ERR_MEMORY;
    }

    pair->key = malloc(key_size);
    if (!pair->key)
    {
        free(value);
        free(pair);
        return TDB_ERR_MEMORY;
    }
    memcpy(pair->key, key, key_size);
    pair->entry.key_size = (uint32_t)key_size;
    pair->value = value;
    pair->entry.value_size = (uint32_t)value_size;
    pair->entry.ttl = ttl;
    pair->entry.seq = seq;
    pair->entry.vlog_offset = vlog_offset;
    pair->entry.flags = 0;

    *kv = pair;
    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_get
 * get a key-value pair from an sstable
 * @param db the database
 * @param sst the sstable
 * @param key the key
 * @param key_size the size of the key
 * @param kv the key-value pair
 */
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               const size_t key_size, tidesdb_kv_pair_t **kv)
{
    /* we branch based on sstable type */
    if (sst->use_btree)
    {
        return tidesdb_sstable_get_btree(db, sst, key, key_size, kv);
    }

    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "SSTable %" PRIu64 " failed to ensure open", sst->id);
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        return TDB_ERR_IO;
    }

    if (!sst->min_key || !sst->max_key)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "SSTable %" PRIu64 " has no min/max keys", sst->id);
        return TDB_ERR_NOT_FOUND;
    }

    /* we use cached comparator from sstable (resolved at load/create time) */
    skip_list_comparator_fn comparator_fn = sst->cached_comparator_fn;
    void *comparator_ctx = sst->cached_comparator_ctx;
    if (TDB_UNLIKELY(!comparator_fn))
    {
        tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);
    }

    const int min_cmp =
        comparator_fn(key, key_size, sst->min_key, sst->min_key_size, comparator_ctx);
    const int max_cmp =
        comparator_fn(key, key_size, sst->max_key, sst->max_key_size, comparator_ctx);

    if (sst->is_reverse)
    {
        if (min_cmp > 0 || max_cmp < 0) return TDB_ERR_NOT_FOUND;
    }
    else
    {
        if (min_cmp < 0 || max_cmp > 0) return TDB_ERR_NOT_FOUND;
    }

    /* we check bloom filter for early exit (after range check since bloom is more expensive) */
    if (sst->bloom_filter)
    {
        PROFILE_INC(db, bloom_checks);
        if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
        {
            return TDB_ERR_NOT_FOUND;
        }
        PROFILE_INC(db, bloom_hits);
    }

    /* we utilize block indexes to find starting klog block */
    uint64_t start_file_position = 0;
    if (sst->block_indexes)
    {
        const int index_result = compact_block_index_find_predecessor(
            sst->block_indexes, key, key_size, &start_file_position);
        if (index_result == 0 && start_file_position > 0)
        {
        }
        else
        {
            start_file_position = 0;
        }
    }

    /* we initialize cursor using stack allocation */
    block_manager_cursor_t klog_cursor_stack;
    block_manager_cursor_t *klog_cursor = &klog_cursor_stack;

    if (block_manager_cursor_init_stack(klog_cursor, bms.klog_bm) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to initialize klog cursor",
                      sst->id);
        return TDB_ERR_IO;
    }

    if (start_file_position > 0)
    {
        block_manager_cursor_goto(klog_cursor, start_file_position);
    }
    else
    {
        block_manager_cursor_goto_first(klog_cursor);
    }

    if (sst->klog_data_end_offset > 0 && klog_cursor->current_pos >= sst->klog_data_end_offset)
    {
        return TDB_ERR_NOT_FOUND;
    }

    /* we use cached CF name from sst struct to avoid repeated path parsing */
    const char *cf_name = sst->cf_name;
    const int has_cf_name = (cf_name[0] != '\0');

    uint64_t blocks_scanned = 0;
    int used_block_index = (start_file_position > 0);

    while (blocks_scanned < sst->num_klog_blocks)
    {
        if (sst->klog_data_end_offset > 0 && klog_cursor->current_pos >= sst->klog_data_end_offset)
        {
            break;
        }

        const uint64_t block_num = blocks_scanned;
        const uint64_t block_position = klog_cursor->current_pos;

        tidesdb_klog_block_t *klog_block = NULL;
        tidesdb_ref_counted_block_t *rc_block = NULL;
        block_manager_block_t *raw_block = NULL;

        /* we read block with cache support
         * advance_cursor=1 when reading from disk to avoid redundant pread in cursor_next */
        const int read_result =
            tidesdb_read_klog_block_cached(db, sst, klog_cursor, block_position, cf_name,
                                           has_cf_name, 1, &klog_block, &rc_block, &raw_block);
        /*** we track if cursor was advanced (only on disk read, not cache hit) */
        const int cursor_advanced = (rc_block == NULL && raw_block != NULL);
        if (read_result != TDB_SUCCESS)
        {
            if (read_result == TDB_ERR_CORRUPTION)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "SSTable %" PRIu64 " block %" PRIu64 " deserialization failed",
                              sst->id, block_num);
                blocks_scanned++;
                if (block_manager_cursor_next(klog_cursor) != 0) break;
                continue;
            }
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to read block %" PRIu64,
                          sst->id, block_num);
            break;
        }

        int should_stop_search = 0;
        int restart_scan = 0;

        if (klog_block && klog_block->num_entries > 0)
        {
            /* we skip block if key > max_key */
            if (klog_block->max_key && klog_block->max_key_size > 0)
            {
                const int max_key_cmp = comparator_fn(key, key_size, klog_block->max_key,
                                                      klog_block->max_key_size, comparator_ctx);
                if (max_key_cmp > 0)
                {
                    goto release_and_next;
                }
            }

            /* we check first key before binary search to avoid O(log n) comparisons
             * when key is below blocks range */
            const int first_key_cmp =
                comparator_fn(key, key_size, klog_block->keys[0], klog_block->entries[0].key_size,
                              comparator_ctx);
            if (first_key_cmp < 0)
            {
                if (used_block_index)
                {
                    used_block_index = 0;
                    restart_scan = 1;
                }
                else
                {
                    should_stop_search = 1;
                }
                goto release_and_next;
            }

            /* we binary search for key in block (key is within block range) */
            int32_t found_idx = -1;
            if (tidesdb_klog_block_find_key(klog_block, key, key_size, comparator_fn,
                                            comparator_ctx, &found_idx) == 0)
            {
                const uint32_t i = (uint32_t)found_idx;

                *kv = tidesdb_kv_pair_create(klog_block->keys[i], klog_block->entries[i].key_size,
                                             NULL, 0, klog_block->entries[i].ttl,
                                             klog_block->entries[i].seq,
                                             klog_block->entries[i].flags & TDB_KV_FLAG_TOMBSTONE);

                if (*kv)
                {
                    /* we preserve arena flag when copying entry */
                    const uint8_t arena_flag = (*kv)->entry.flags & TDB_KV_FLAG_ARENA;
                    (*kv)->entry = klog_block->entries[i];
                    (*kv)->entry.flags |= arena_flag;
                    const int load_rc = tidesdb_kv_pair_load_value(db, sst, klog_block, i, *kv);
                    if (load_rc != TDB_SUCCESS)
                    {
                        tidesdb_kv_pair_free(*kv);
                        *kv = NULL;
                        if (rc_block)
                            tidesdb_block_release(rc_block);
                        else
                            tidesdb_klog_block_free(klog_block);
                        if (raw_block) block_manager_block_release(raw_block);
                        return load_rc;
                    }

                    /* we release resources and return success */
                    if (rc_block)
                        tidesdb_block_release(rc_block);
                    else
                        tidesdb_klog_block_free(klog_block);
                    if (raw_block) block_manager_block_release(raw_block);

                    return TDB_SUCCESS;
                }
            }
        }

    release_and_next:
        /* we release block resources */
        if (rc_block)
            tidesdb_block_release(rc_block);
        else if (klog_block)
            tidesdb_klog_block_free(klog_block);
        if (raw_block) block_manager_block_release(raw_block);

        if (restart_scan)
        {
            if (block_manager_cursor_goto_first(klog_cursor) != 0) break;
            blocks_scanned = 0;
            continue;
        }

        if (should_stop_search)
        {
            break;
        }

        blocks_scanned++;
        /* only call cursor_next if cursor wasn't already advanced by read_and_advance */
        if (!cursor_advanced && block_manager_cursor_next(klog_cursor) != 0)
        {
            break;
        }
    }

    return TDB_ERR_NOT_FOUND;
}

/**
 * tidesdb_sstable_load
 * load an sstable from disk
 * @param db database instance (can be NULL during startup)
 * @param sst the sstable to load
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_sstable_load(tidesdb_t *db, tidesdb_sstable_t *sst)
{
    /* we open block managers temporarily for loading; they'll be managed by cache later */
    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open(&klog_bm, sst->klog_path, convert_sync_mode(sst->config->sync_mode)) !=
        0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "Failed to open klog file %s (may be leftover from incomplete cleanup)",
                      sst->klog_path);
        return -1;
    }

    /* we validate klog file (strict mode -- reject any corruption) */
    if (block_manager_validate_last_block(klog_bm, BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable klog file %s is corrupted", sst->klog_path);
        block_manager_close(klog_bm);
        return TDB_ERR_CORRUPTION;
    }

    if (block_manager_open(&vlog_bm, sst->vlog_path, convert_sync_mode(sst->config->sync_mode)) !=
        0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "Failed to open vlog file %s (may be leftover from incomplete cleanup)",
                      sst->vlog_path);
        block_manager_close(klog_bm);
        return -1;
    }

    /* validate vlog file (strict mode -- reject any corruption) */
    if (block_manager_validate_last_block(vlog_bm, BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable vlog file %s is corrupted", sst->vlog_path);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_CORRUPTION;
    }

    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    /* we check for empty or corrupted files */
    if (sst->klog_size == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Empty klog file %s (corrupted or incomplete SSTable)",
                      sst->klog_path);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_CORRUPTION;
    }

    /* read metadata from last block */
    block_manager_cursor_t *metadata_cursor;
    int metadata_corrupt = 0;
    if (block_manager_cursor_init(&metadata_cursor, klog_bm) == 0)
    {
        if (block_manager_cursor_goto_last(metadata_cursor) == 0)
        {
            block_manager_block_t *metadata_block = block_manager_cursor_read(metadata_cursor);
            if (metadata_block && metadata_block->size > 0)
            {
                if (sstable_metadata_deserialize(metadata_block->data, metadata_block->size, sst) ==
                    0)
                {
                    block_manager_block_release(metadata_block);
                    block_manager_cursor_free(metadata_cursor);

                    if (sst->klog_data_end_offset > 0)
                    {
                        if (sst->klog_data_end_offset > sst->klog_size)
                        {
                            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                          "SSTable %s metadata invalid: klog_data_end_offset "
                                          "(%" PRIu64 ") > klog_size (%" PRIu64 ")",
                                          sst->klog_path, sst->klog_data_end_offset,
                                          sst->klog_size);
                            block_manager_close(klog_bm);
                            block_manager_close(vlog_bm);
                            return TDB_ERR_CORRUPTION;
                        }

                        /* we must have at least block manager header before data */
                        if (sst->klog_data_end_offset < BLOCK_MANAGER_HEADER_SIZE)
                        {
                            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                          "SSTable %s metadata invalid: klog_data_end_offset "
                                          "(%" PRIu64 ") < header size (%d)",
                                          sst->klog_path, sst->klog_data_end_offset,
                                          BLOCK_MANAGER_HEADER_SIZE);
                            block_manager_close(klog_bm);
                            block_manager_close(vlog_bm);
                            return TDB_ERR_CORRUPTION;
                        }
                    }

                    /* we validate num_klog_blocks is reasonable */
                    if (sst->num_klog_blocks > 0)
                    {
                        /* for sanity each block needs at least header + footer */
                        uint64_t min_size_per_block =
                            BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
                        uint64_t min_required_size =
                            BLOCK_MANAGER_HEADER_SIZE + (sst->num_klog_blocks * min_size_per_block);

                        if (sst->klog_data_end_offset > 0 &&
                            sst->klog_data_end_offset < min_required_size)
                        {
                            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                          "SSTable %s metadata invalid: claims %" PRIu64
                                          " blocks but klog_data_end_offset (%" PRIu64
                                          ") too small (min %" PRIu64 ")",
                                          sst->klog_path, sst->num_klog_blocks,
                                          sst->klog_data_end_offset, min_required_size);
                            block_manager_close(klog_bm);
                            block_manager_close(vlog_bm);
                            return TDB_ERR_CORRUPTION;
                        }

                        /* we validate first data block is readable to detect incomplete ssts */
                        block_manager_cursor_t *validate_cursor;
                        if (block_manager_cursor_init(&validate_cursor, klog_bm) == 0)
                        {
                            if (block_manager_cursor_goto_first(validate_cursor) == 0)
                            {
                                block_manager_block_t *first_block =
                                    block_manager_cursor_read(validate_cursor);
                                if (!first_block || first_block->size == 0)
                                {
                                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                                  "SSTable %s first data block unreadable or empty",
                                                  sst->klog_path);
                                    if (first_block) block_manager_block_release(first_block);
                                    block_manager_cursor_free(validate_cursor);
                                    block_manager_close(klog_bm);
                                    block_manager_close(vlog_bm);
                                    return TDB_ERR_CORRUPTION;
                                }
                                block_manager_block_release(first_block);
                            }
                            block_manager_cursor_free(validate_cursor);
                        }
                    }

                    /* metadata loaded successfully, skip reading min/max from blocks */
                    goto load_bloom_and_index;
                }
                metadata_corrupt = 1;
                block_manager_block_release(metadata_block);
            }
        }
        block_manager_cursor_free(metadata_cursor);
    }

    /* if metadata was found but corrupted, or if no metadata block exists, fail immediately */
    if (metadata_corrupt)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "SSTable metadata corrupted for %s", sst->klog_path);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_CORRUPTION;
    }

    block_manager_close(klog_bm);
    block_manager_close(vlog_bm);
    return TDB_ERR_CORRUPTION;

load_bloom_and_index:; /* empty statement for C89/C90 compatibility */
    /* load bloom filter and index from last blocks */
    /* [klog blocks...] [index block] [bloom filter block] [metadata block] */

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, klog_bm) != 0)
    {
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_IO;
    }

    /* we go to last block (metadata) and skip it */
    if (block_manager_cursor_goto_last(cursor) == 0)
    {
        /* we skip metadata block, go to bloom filter */
        if (block_manager_cursor_prev(cursor) == 0)
        {
            block_manager_block_t *bloom_block = block_manager_cursor_read(cursor);
            if (bloom_block)
            {
                if (bloom_block->size > 0 && sst->config && sst->config->enable_bloom_filter)
                {
                    sst->bloom_filter = bloom_filter_deserialize(bloom_block->data);
                }
                else
                {
                    sst->bloom_filter = NULL;
                }
                block_manager_block_release(bloom_block);
            }

            /* go to index block */
            if (block_manager_cursor_prev(cursor) == 0)
            {
                block_manager_block_t *index_block = block_manager_cursor_read(cursor);
                if (index_block)
                {
                    if (index_block->size > 0)
                    {
                        sst->block_indexes =
                            compact_block_index_deserialize(index_block->data, index_block->size);

                        /* use cached comparator from config (already resolved during CF creation)
                         * this avoids hash table lookup for every sst during recovery */
                        if (sst->block_indexes)
                        {
                            sst->block_indexes->comparator = sst->config->comparator_fn_cached;
                            sst->block_indexes->comparator_ctx = sst->config->comparator_ctx_cached;
                        }
                    }
                    block_manager_block_release(index_block);
                }
            }
        }
    }

    block_manager_cursor_free(cursor);

    /* we keep block managers open and store them in the sstable
     * they will be managed by the cache and closed when the sstable is evicted or freed */
    sst->klog_bm = klog_bm;
    sst->vlog_bm = vlog_bm;

    /* we cache resolved comparator on the sstable to avoid per-lookup resolution */
    sst->cached_comparator_fn = NULL;
    sst->cached_comparator_ctx = NULL;
    sst->is_reverse = 0;
    if (db && sst->config)
    {
        tidesdb_resolve_comparator(db, sst->config, &sst->cached_comparator_fn,
                                   &sst->cached_comparator_ctx);

        /* we cache is_reverse to avoid recomputing on every klog get */
        if (sst->cached_comparator_fn && sst->min_key && sst->max_key)
        {
            const int min_max_cmp =
                sst->cached_comparator_fn(sst->min_key, sst->min_key_size, sst->max_key,
                                          sst->max_key_size, sst->cached_comparator_ctx);
            sst->is_reverse = (min_max_cmp > 0);
        }
    }

    /* we track that this file is now open */
    if (db)
    {
        atomic_store(&sst->last_access_time,
                     atomic_load_explicit(&db->cached_current_time, memory_order_relaxed));
        atomic_fetch_add(&db->num_open_sstables, 1);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_level_create
 * create a new level
 * @param level_num level number
 * @param capacity capacity of level
 * @return level on success, NULL on failure
 */
static tidesdb_level_t *tidesdb_level_create(const int level_num, size_t capacity)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Creating level %d with capacity %zu", level_num, capacity);

    tidesdb_level_t *level = calloc(1, sizeof(tidesdb_level_t));
    if (!level) return NULL;

    level->level_num = level_num;
    atomic_init(&level->capacity, capacity);
    atomic_init(&level->current_size, 0);

    tidesdb_sstable_t **sstables =
        calloc(TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY, sizeof(tidesdb_sstable_t *));
    if (!sstables)
    {
        free(level);
        return NULL;
    }

    atomic_init(&level->sstables, sstables);
    atomic_init(&level->num_sstables, 0);
    atomic_init(&level->sstables_capacity, TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY);
    atomic_init(&level->num_boundaries, 0);
    atomic_init(&level->retired_sstables_arr, NULL);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Level %d created with capacity %zu", level_num, capacity);

    return level;
}

/**
 * tidesdb_level_free
 * free a level
 * @param db database
 * @param level level to free
 */
static void tidesdb_level_free(const tidesdb_t *db, tidesdb_level_t *level)
{
    if (!level) return;

    int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
    tidesdb_sstable_t **ssts = atomic_load_explicit(&level->sstables, memory_order_acquire);

    for (int i = 0; i < num_ssts; i++)
    {
        if (ssts[i])
        {
            tidesdb_sstable_unref(db, ssts[i]);
        }
    }

    free(ssts);

    /* we free any retired array that was deferred */
    tidesdb_sstable_t **retired =
        atomic_load_explicit(&level->retired_sstables_arr, memory_order_acquire);
    free(retired);
    int num_boundaries = atomic_load_explicit(&level->num_boundaries, memory_order_acquire);
    uint8_t **file_boundaries = atomic_load_explicit(&level->file_boundaries, memory_order_acquire);
    size_t *boundary_sizes = atomic_load_explicit(&level->boundary_sizes, memory_order_acquire);

    for (int i = 0; i < num_boundaries; i++)
    {
        free(file_boundaries[i]); /* free individual boundary entries */
    }

    free(file_boundaries); /* then free the array itself */
    free(boundary_sizes);

    free(level);
}

/**
 * tidesdb_level_add_sstable
 * add an sstable to a level
 * @param level level to add sstable to
 * @param sst sstable to add
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_level_add_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst)
{
    tidesdb_sstable_ref(sst);

    while (1)
    {
        /* we load current array state atomically */
        tidesdb_sstable_t **old_arr = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int old_capacity = atomic_load_explicit(&level->sstables_capacity, memory_order_acquire);
        int old_num = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        /* we check if we need to grow the array */
        if (old_num >= old_capacity)
        {
            int new_capacity =
                old_capacity == 0 ? TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY : old_capacity * 2;
            tidesdb_sstable_t **new_arr = malloc(new_capacity * sizeof(tidesdb_sstable_t *));
            if (!new_arr)
            {
                tidesdb_sstable_unref(sst->db, sst); /* release ref on failure */
                return TDB_ERR_MEMORY;
            }

            memcpy(new_arr, old_arr, old_num * sizeof(tidesdb_sstable_t *));

            new_arr[old_num] = sst;

            /* CAS to swap in new array */
            if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                        memory_order_release, memory_order_acquire))
            {
                /* success! update capacity and count */
                atomic_store_explicit(&level->sstables_capacity, new_capacity,
                                      memory_order_release);
                atomic_store_explicit(&level->num_sstables, old_num + 1, memory_order_release);

                atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                          memory_order_relaxed);

                tidesdb_sstable_t **prev_retired = atomic_exchange_explicit(
                    &level->retired_sstables_arr, old_arr, memory_order_acq_rel);
                free(prev_retired);

                return TDB_SUCCESS;
            }
            /* CAS failed, retry with new state */
            free(new_arr);
        }
        else
        {
            int expected = old_num;

            /* we must verify we have space before trying to add */
            if (expected >= old_capacity)
            {
                /* no space, retry with resize path */
                continue;
            }

            /* we create new array with the additional sstable already in place */
            tidesdb_sstable_t **new_arr = malloc(old_capacity * sizeof(tidesdb_sstable_t *));
            if (!new_arr)
            {
                tidesdb_sstable_unref(sst->db, sst);
                return TDB_ERR_MEMORY;
            }

            memcpy(new_arr, old_arr, old_num * sizeof(tidesdb_sstable_t *));
            new_arr[old_num] = sst;

            if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                        memory_order_release, memory_order_acquire))
            {
                /* array swapped successfully, now update count
                 * readers will see new array with sst already in place before count increases */
                atomic_thread_fence(memory_order_seq_cst);
                atomic_store_explicit(&level->num_sstables, old_num + 1, memory_order_release);

                atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                          memory_order_relaxed);

                tidesdb_sstable_t **prev_retired = atomic_exchange_explicit(
                    &level->retired_sstables_arr, old_arr, memory_order_acq_rel);
                free(prev_retired);

                return TDB_SUCCESS;
            }
            /* CAS failed, another thread modified the array first, retry */
            free(new_arr);
        }
    }
}

/**
 * tidesdb_level_remove_sstable
 * remove an sstable from a level
 * @param db database instance (for cache removal)
 * @param level level to remove sstable from
 * @param sst sstable to remove
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_level_remove_sstable(const tidesdb_t *db, tidesdb_level_t *level,
                                        tidesdb_sstable_t *sst)
{
    while (1)
    {
        tidesdb_sstable_t **old_arr = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int old_num = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        const int old_capacity =
            atomic_load_explicit(&level->sstables_capacity, memory_order_acquire);

        int found_idx = -1;
        for (int i = 0; i < old_num; i++)
        {
            if (old_arr[i] == sst)
            {
                found_idx = i;
                break;
            }
        }

        if (found_idx == -1)
        {
            return TDB_ERR_NOT_FOUND;
        }

        tidesdb_sstable_t **new_arr = calloc(old_capacity, sizeof(tidesdb_sstable_t *));
        if (!new_arr)
        {
            return TDB_ERR_MEMORY;
        }

        int new_idx = 0;
        for (int i = 0; i < old_num; i++)
        {
            if (i != found_idx)
            {
                new_arr[new_idx] = old_arr[i];
                tidesdb_sstable_ref(new_arr[new_idx]);
                new_idx++;
            }
        }

        /* for remove -- swap array first, then update count
         * readers use pattern -- load array, load count, re-load count, use min(count1, count2)
         * this handles both add-with-resize (array changes, count increases) and
         * remove (array changes, count decreases) races safely */
        if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                    memory_order_release, memory_order_acquire))
        {
            /* array swapped, now update count */
            atomic_thread_fence(memory_order_seq_cst);
            atomic_store_explicit(&level->num_sstables, new_idx, memory_order_release);

            /* success! update size */
            atomic_fetch_sub_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                      memory_order_relaxed);

            /* we unref old array's sstables */
            for (int i = 0; i < old_num; i++)
            {
                tidesdb_sstable_unref(db, old_arr[i]);
            }

            tidesdb_sstable_t **prev_retired = atomic_exchange_explicit(
                &level->retired_sstables_arr, old_arr, memory_order_acq_rel);
            free(prev_retired);

            return TDB_SUCCESS;
        }
        /* CAS failed, cleanup and retry */
        for (int i = 0; i < new_idx; i++)
        {
            tidesdb_sstable_unref(db, new_arr[i]);
        }
        free(new_arr);
    }
}

static void tidesdb_bump_sstable_layout_version(tidesdb_column_family_t *cf)
{
    atomic_fetch_add_explicit(&cf->sstable_layout_version, 1, memory_order_release);
}

/**
 * tidesdb_level_update_boundaries
 * update the boundaries of a level
 * @param level level to update boundaries for
 * @param largest_level largest level
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_level_update_boundaries(tidesdb_level_t *level, tidesdb_level_t *largest_level)
{
    uint8_t **file_boundaries = atomic_load_explicit(&level->file_boundaries, memory_order_acquire);
    int num_boundaries = atomic_load_explicit(&level->num_boundaries, memory_order_acquire);
    size_t *boundary_sizes = atomic_load_explicit(&level->boundary_sizes, memory_order_acquire);

    if (file_boundaries)
    {
        for (int i = 0; i < num_boundaries; i++)
        {
            if (file_boundaries[i] == NULL) continue;
            free(file_boundaries[i]);
        }

        free(file_boundaries); /* already inside if (file_boundaries) block */
    }

    if (boundary_sizes)
    {
        free(boundary_sizes);
    }

    int num_ssts = atomic_load_explicit(&largest_level->num_sstables, memory_order_relaxed);
    tidesdb_sstable_t **sstables =
        atomic_load_explicit(&largest_level->sstables, memory_order_relaxed);

    if (num_ssts > 0)
    {
        file_boundaries = malloc(num_ssts * sizeof(uint8_t *));
        boundary_sizes = malloc(num_ssts * sizeof(size_t));

        if (!file_boundaries || !boundary_sizes)
        {
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];

            boundary_sizes[i] = sst->min_key_size;

            file_boundaries[i] = malloc(sst->min_key_size);
            if (!file_boundaries[i])
            {
                return TDB_ERR_MEMORY;
            }
            if (sst->min_key && sst->min_key_size > 0)
            {
                memcpy(file_boundaries[i], sst->min_key, sst->min_key_size);
            }
        }
    }
    atomic_store_explicit(&level->file_boundaries, file_boundaries, memory_order_relaxed);
    atomic_store_explicit(&level->boundary_sizes, boundary_sizes, memory_order_relaxed);
    atomic_store_explicit(&level->num_boundaries, num_ssts, memory_order_relaxed);
    return TDB_SUCCESS;
}

/**
 * heap_swap
 * swap two elements in a heap
 * @param a first element
 * @param b second element
 */
static void heap_swap(tidesdb_merge_source_t **a, tidesdb_merge_source_t **b)
{
    tidesdb_merge_source_t *temp = *a;
    *a = *b;
    *b = temp;
}

/**
 * heap_compare
 * compare two elements in a heap
 * @param heap heap to compare
 * @param i index of first element
 * @param j index of second element
 * @return comparison result
 */
static int heap_compare(const tidesdb_merge_heap_t *heap, const int i, const int j)
{
    tidesdb_kv_pair_t *a = heap->sources[i]->current_kv;
    tidesdb_kv_pair_t *b = heap->sources[j]->current_kv;

    if (!a && !b) return 0;
    if (!a) return 1;  /* a is greater, push to end */
    if (!b) return -1; /* b is greater, push to end */

    const int cmp = heap->comparator(a->key, a->entry.key_size, b->key, b->entry.key_size,
                                     heap->comparator_ctx);

    if (cmp == 0)
    {
        /* same key,  prefer higher sequence number (newer) */
        if (a->entry.seq > b->entry.seq) return -1;
        if (a->entry.seq < b->entry.seq) return 1;
    }

    return cmp;
}

/**
 * heap_compare_max
 * compare two elements in a max-heap
 * for equal keys, prefer higher sequence number (newer) on top
 * this ensures tombstones (seq=UINT64_MAX) are popped before committed values
 * @param heap heap containing elements
 * @param i index of first element
 * @param j index of second element
 * @return comparison result
 */
static int heap_compare_max(const tidesdb_merge_heap_t *heap, const int i, const int j)
{
    tidesdb_kv_pair_t *a = heap->sources[i]->current_kv;
    tidesdb_kv_pair_t *b = heap->sources[j]->current_kv;

    if (!a && !b) return 0;
    if (!a) return -1; /* a is smaller, push to end in max-heap */
    if (!b) return 1;  /* b is smaller, push to end in max-heap */

    const int cmp = heap->comparator(a->key, a->entry.key_size, b->key, b->entry.key_size,
                                     heap->comparator_ctx);

    if (cmp == 0)
    {
        /* same key, prefer higher sequence number (newer) on top of max-heap */
        if (a->entry.seq > b->entry.seq) return 1;
        if (a->entry.seq < b->entry.seq) return -1;
    }

    return cmp;
}

/**
 * heap_sift_down
 * sift down an element in a heap
 * @param heap heap to sift down
 * @param idx index of element to sift down
 */
static void heap_sift_down(const tidesdb_merge_heap_t *heap, int idx)
{
    while (idx * 2 + 1 < heap->num_sources)
    {
        const int left = idx * 2 + 1;
        const int right = idx * 2 + 2;
        int smallest = idx;

        if (left < heap->num_sources && heap_compare(heap, left, smallest) < 0)
        {
            smallest = left;
        }
        if (right < heap->num_sources && heap_compare(heap, right, smallest) < 0)
        {
            smallest = right;
        }

        if (smallest == idx) break;

        heap_swap(&heap->sources[idx], &heap->sources[smallest]);
        idx = smallest;
    }
}

/**
 * heap_sift_up
 * sift up an element in a heap
 * @param heap heap to sift up
 * @param idx index of element to sift up
 */
static void heap_sift_up(const tidesdb_merge_heap_t *heap, int idx)
{
    while (idx > 0)
    {
        const int parent = (idx - 1) / 2;
        if (heap_compare(heap, idx, parent) >= 0) break;

        heap_swap(&heap->sources[idx], &heap->sources[parent]);
        idx = parent;
    }
}

/**
 * heap_sift_down_max
 * sift down an element in a max-heap (largest on top)
 * @param heap heap to sift down
 * @param idx index of element to sift down
 */
static void heap_sift_down_max(const tidesdb_merge_heap_t *heap, int idx)
{
    while (idx * 2 + 1 < heap->num_sources)
    {
        const int left = idx * 2 + 1;
        const int right = idx * 2 + 2;
        int largest = idx;

        /* for max-heap, we want largest element on top */
        if (left < heap->num_sources && heap_compare_max(heap, left, largest) > 0)
        {
            largest = left;
        }
        if (right < heap->num_sources && heap_compare_max(heap, right, largest) > 0)
        {
            largest = right;
        }

        if (largest == idx) break;

        heap_swap(&heap->sources[idx], &heap->sources[largest]);
        idx = largest;
    }
}

/**
 * tidesdb_merge_heap_pop_max
 * pop the largest element from a max-heap
 * @param heap heap to pop from
 * @return pointer to the largest kv pair
 */
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop_max(tidesdb_merge_heap_t *heap)
{
    if (heap->num_sources == 0) return NULL;

    tidesdb_merge_source_t *top = heap->sources[0];
    if (!top->current_kv)
    {
        /* top source exhausted, remove it */
        if (!top->is_cached)
        {
            tidesdb_merge_source_free(top);
        }
        heap->sources[0] = heap->sources[heap->num_sources - 1];
        heap->num_sources--;
        if (heap->num_sources > 0) heap_sift_down_max(heap, 0);
        return NULL;
    }

    /* we transfer ownership instead of cloning (same as pop) */
    tidesdb_kv_pair_t *result = top->current_kv;
    top->current_kv = NULL;

    /* the source to get its previous entry */
    if (tidesdb_merge_source_retreat(top) != TDB_SUCCESS)
    {
        /* source exhausted, remove it */
        if (!top->is_cached)
        {
            tidesdb_merge_source_free(top);
        }
        heap->sources[0] = heap->sources[heap->num_sources - 1];
        heap->num_sources--;
    }

    /* restore max-heap property */
    if (heap->num_sources > 0) heap_sift_down_max(heap, 0);

    return result;
}

/**
 * tidesdb_merge_heap_create
 * create a new merge heap
 * @param comparator comparator function
 * @param comparator_ctx comparator context
 * @return pointer to the new merge heap
 */
static tidesdb_merge_heap_t *tidesdb_merge_heap_create(const skip_list_comparator_fn comparator,
                                                       void *comparator_ctx)
{
    tidesdb_merge_heap_t *heap = calloc(1, sizeof(tidesdb_merge_heap_t));
    if (!heap) return NULL;

    heap->capacity = TDB_INITIAL_MERGE_HEAP_CAPACITY;
    heap->sources = malloc(heap->capacity * sizeof(tidesdb_merge_source_t *));
    if (!heap->sources)
    {
        free(heap);
        return NULL;
    }

    heap->comparator = comparator;
    heap->comparator_ctx = comparator_ctx;

    return heap;
}

/**
 * tidesdb_merge_heap_free
 * free a merge heap
 * @param heap merge heap to free
 */
static void tidesdb_merge_heap_free(tidesdb_merge_heap_t *heap)
{
    if (!heap) return;

    for (int i = 0; i < heap->num_sources; i++)
    {
        /* we skip freeing cached sources -- they're owned by the iterator */
        if (!heap->sources[i]->is_cached)
        {
            tidesdb_merge_source_free(heap->sources[i]);
        }
    }

    free(heap->sources);
    free(heap);
}

/**
 * tidesdb_merge_heap_add_source
 * add a source to a merge heap
 * @param heap merge heap to add source to
 * @param source source to add
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_merge_heap_add_source(tidesdb_merge_heap_t *heap, tidesdb_merge_source_t *source)
{
    if (heap->num_sources >= heap->capacity)
    {
        const int new_capacity = heap->capacity * 2;
        tidesdb_merge_source_t **new_sources =
            realloc(heap->sources, new_capacity * sizeof(tidesdb_merge_source_t *));
        if (!new_sources) return TDB_ERR_MEMORY;
        heap->sources = new_sources;
        heap->capacity = new_capacity;
    }

    heap->sources[heap->num_sources] = source;
    heap->num_sources++;

    heap_sift_up(heap, heap->num_sources - 1);

    return TDB_SUCCESS;
}

/**
 * tidesdb_merge_heap_pop
 * pop the smallest element from a merge heap
 * @param heap merge heap to pop from
 * @param corrupted_sst output parameter for corrupted sst (NULL if none)
 * @return smallest element
 */
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap,
                                                 tidesdb_sstable_t **corrupted_sst)
{
    if (corrupted_sst) *corrupted_sst = NULL;
    if (heap->num_sources == 0) return NULL;

    tidesdb_merge_source_t *top = heap->sources[0];
    if (!top->current_kv) return NULL;

    /* we transfer ownership of current_kv instead of cloning.
     ** advance() starts with kv_pair_free(current_kv) which is a no-op on NULL.
     *** eliminates 1 malloc + 1 free + 2 memcpy per pop. */
    tidesdb_kv_pair_t *result = top->current_kv;
    top->current_kv = NULL;

    const int advance_result = tidesdb_merge_source_advance(top);
    if (advance_result != 0)
    {
        /* the source is exhausted or corrupted */
        if (advance_result == TDB_ERR_CORRUPTION && top->type == MERGE_SOURCE_SSTABLE &&
            corrupted_sst)
        {
            /* return corrupted sst for deletion */
            *corrupted_sst = top->source.sstable.sst;
            tidesdb_sstable_ref(*corrupted_sst);
        }

        /* we remove from heap */
        heap->sources[0] = heap->sources[heap->num_sources - 1];
        heap->num_sources--;

        /* we only free if not cached for reuse */
        if (!top->is_cached)
        {
            tidesdb_merge_source_free(top);
        }
    }

    if (heap->num_sources > 0)
    {
        heap_sift_down(heap, 0);
    }

    return result;
}

/**
 * tidesdb_merge_heap_empty
 * check if a merge heap is empty
 * @param heap merge heap to check
 * @return 1 if empty, 0 otherwise
 */
static int tidesdb_merge_heap_empty(const tidesdb_merge_heap_t *heap)
{
    return heap->num_sources == 0;
}

/**
 * tidesdb_merge_source_from_memtable
 * create a merge source from a memtable
 * @param memtable memtable to create merge source from
 * @param config column family config
 * @param imm immutable memtable wrapper (NULL for active memtable)
 * @return merge source
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_memtable(
    skip_list_t *memtable, tidesdb_column_family_config_t *config,
    tidesdb_immutable_memtable_t *imm)
{
    tidesdb_merge_source_t *source = calloc(1, sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_MEMTABLE;
    source->config = config;
    source->source.memtable.imm = imm;
    source->is_cached = 0; /* memtable sources are not cached */

    if (imm)
    {
        tidesdb_immutable_memtable_ref(imm);
    }

    if (skip_list_cursor_init(&source->source.memtable.cursor, memtable) != 0)
    {
        if (imm) tidesdb_immutable_memtable_unref(imm);
        free(source);
        return NULL;
    }

    const int goto_result = skip_list_cursor_goto_first(source->source.memtable.cursor);

    if (goto_result == 0)
    {
        uint8_t *key, *value;
        size_t key_size, value_size;
        int64_t ttl;
        uint8_t deleted;
        uint64_t seq;

        if (skip_list_cursor_get_with_seq(source->source.memtable.cursor, &key, &key_size, &value,
                                          &value_size, &ttl, &deleted, &seq) == 0)
        {
            source->current_kv =
                tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
        }
    }

    return source;
}

/**
 * tidesdb_txn_ops_sort_ctx_t
 * context for qsort_r comparator when sorting transaction ops indices
 * @param ops pointer to the transaction ops array
 * @param comparator key comparator function
 * @param comparator_ctx comparator context
 */
typedef struct
{
    tidesdb_txn_op_t *ops;
    skip_list_comparator_fn comparator;
    void *comparator_ctx;
} tidesdb_txn_ops_sort_ctx_t;

/* thread-local context for qsort comparator (cross-platform alternative to qsort_r) */
static _Thread_local const tidesdb_txn_ops_sort_ctx_t *tidesdb_txn_ops_sort_ctx_tls = NULL;

/**
 * tidesdb_txn_ops_index_cmp
 * qsort comparator that orders two indices into the txn ops array by key
 * uses thread-local context for cross-platform compatibility
 * @param a pointer to first index
 * @param b pointer to second index
 * @return <0 if a < b, 0 if equal, >0 if a > b
 */
static int tidesdb_txn_ops_index_cmp(const void *a, const void *b)
{
    const int ia = *(const int *)a;
    const int ib = *(const int *)b;
    const tidesdb_txn_ops_sort_ctx_t *c = tidesdb_txn_ops_sort_ctx_tls;

    return c->comparator(c->ops[ia].key, c->ops[ia].key_size, c->ops[ib].key, c->ops[ib].key_size,
                         c->comparator_ctx);
}

/**
 * tidesdb_merge_source_from_txn_ops
 * create a merge source from transaction pending writes for read-your-own-writes
 *
 * filters txn->ops for the target column family, deduplicates (last write per
 * key wins by scanning in reverse), sorts by key using the cf comparator, and
 * positions at the first entry.
 *
 * entries use seq=UINT64_MAX so they always win over committed data with the
 * same key in the merge heap.
 *
 * @param txn transaction handle
 * @param cf column family to filter for
 * @param config column family configuration
 * @return merge source or NULL if no ops for this cf (or on error)
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_txn_ops(
    tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_column_family_config_t *config)
{
    if (!txn || !cf || txn->num_ops == 0) return NULL;

    /* we resolve the comparator for this column family */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);
    if (!comparator_fn) comparator_fn = tidesdb_comparator_memcmp;

    /* first pass is to collect indices of ops belonging to this CF
     * we scan in reverse so the first occurrence of each key is the newest write */
    int *candidate_indices = malloc(txn->num_ops * sizeof(int));
    if (!candidate_indices) return NULL;

    int candidate_count = 0;

    /* we use a simple seen-set to deduplicate
     * for each key we only keep the latest (highest index) op */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        const tidesdb_txn_op_t *op = &txn->ops[i];

        /* quick CF check (pointer comparison) */
        if (op->cf != cf) continue;

        /* we check if we already have a newer op for this key */
        int already_seen = 0;
        for (int j = 0; j < candidate_count; j++)
        {
            const tidesdb_txn_op_t *existing = &txn->ops[candidate_indices[j]];
            if (existing->key_size == op->key_size &&
                comparator_fn(existing->key, existing->key_size, op->key, op->key_size,
                              comparator_ctx) == 0)
            {
                already_seen = 1;
                break;
            }
        }

        if (!already_seen)
        {
            candidate_indices[candidate_count++] = i;
        }
    }

    if (candidate_count == 0)
    {
        free(candidate_indices);
        return NULL;
    }

    /* we shrink to actual size */
    int *sorted_indices = realloc(candidate_indices, candidate_count * sizeof(int));
    if (!sorted_indices)
        sorted_indices = candidate_indices; /* realloc shrink cant fail, but safe */

    /* we sort by key using the column family comparator */
    tidesdb_txn_ops_sort_ctx_t sort_ctx = {
        .ops = txn->ops, .comparator = comparator_fn, .comparator_ctx = comparator_ctx};

    tidesdb_txn_ops_sort_ctx_tls = &sort_ctx;
    qsort(sorted_indices, candidate_count, sizeof(int), tidesdb_txn_ops_index_cmp);
    tidesdb_txn_ops_sort_ctx_tls = NULL;

    /* we create the merge source */
    tidesdb_merge_source_t *source = calloc(1, sizeof(tidesdb_merge_source_t));
    if (!source)
    {
        free(sorted_indices);
        return NULL;
    }

    source->type = MERGE_SOURCE_TXN_OPS;
    source->config = config;
    source->is_cached = 0;
    source->source.txn_ops.txn = txn;
    source->source.txn_ops.cf = cf;
    source->source.txn_ops.sorted_indices = sorted_indices;
    source->source.txn_ops.count = candidate_count;
    source->source.txn_ops.pos = 0;

    /* we set current_kv from the first sorted entry */
    const tidesdb_txn_op_t *first_op = &txn->ops[sorted_indices[0]];
    source->current_kv = tidesdb_kv_pair_create(first_op->key, first_op->key_size, first_op->value,
                                                first_op->value_size, first_op->ttl, UINT64_MAX,
                                                first_op->is_delete);

    return source;
}

/**
 * tidesdb_merge_source_from_sstable_klog
 * create a merge source from a klog-based sstable
 * @param db database instance
 * @param sst sstable
 * @return merge source or NULL on error
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable_klog(tidesdb_t *db,
                                                                      tidesdb_sstable_t *sst)
{
    tidesdb_merge_source_t *source = malloc(sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_SSTABLE;
    source->source.sstable.sst = sst;
    source->source.sstable.db = db; /* store db for later vlog reads */
    source->is_cached = 0;          /* will be set to 1 if cached by iterator */

    tidesdb_sstable_ref(sst);

    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    if (block_manager_cursor_init(&source->source.sstable.klog_cursor, bms.klog_bm) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    if (block_manager_cursor_init(&source->source.sstable.vlog_cursor, bms.vlog_bm) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        free(source);
        return NULL;
    }

    /* we hint to OS that this is streaming read (data will be accessed only once)
     * this helps prevent cache pollution during compaction * * */
    set_file_noreuse_hint(bms.klog_bm->fd, 0, 0);
    set_file_noreuse_hint(bms.vlog_bm->fd, 0, 0);

    source->source.sstable.current_block_data = NULL; /* no block data yet */
    source->source.sstable.current_rc_block = NULL;   /* no ref-counted block yet */
    source->source.sstable.decompressed_data = NULL;  /* no decompressed data yet */
    source->source.sstable.current_block = NULL;      /* no current block yet */
    source->current_kv = NULL;                        /* no current kv yet */
    source->config = sst->config;

    /* we only read data blocks, not the metadata block at the end */
    if (sst->num_klog_blocks == 0)
    {
        /* empty sstable, no data blocks to read */
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        block_manager_cursor_free(source->source.sstable.vlog_cursor);
        free(source);
        return NULL;
    }

    if (block_manager_cursor_goto_first(source->source.sstable.klog_cursor) == 0)
    {
        /* we check cursor is within data region (before index/bloom/metadata blocks) */
        if (sst->klog_data_end_offset > 0 &&
            source->source.sstable.klog_cursor->current_pos >= sst->klog_data_end_offset)
        {
            /* cursor is at or past data end offset */
            tidesdb_sstable_unref(db, sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            block_manager_cursor_free(source->source.sstable.vlog_cursor);
            free(source);
            return NULL;
        }

        block_manager_block_t *block =
            tidesdb_read_block(db, sst, source->source.sstable.klog_cursor);
        if (!block)
        {
            /* no block available */
            tidesdb_sstable_unref(db, sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            block_manager_cursor_free(source->source.sstable.vlog_cursor);
            free(source);
            return NULL;
        }

        const uint8_t *data = block->data;
        const size_t data_size = block->size;

        tidesdb_klog_block_t *klog_block = NULL;
        if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) != 0)
        {
            block_manager_block_release(block);
            tidesdb_sstable_unref(db, sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            block_manager_cursor_free(source->source.sstable.vlog_cursor);
            free(source);
            return NULL;
        }

        if (klog_block && klog_block->num_entries > 0)
        {
            /* deserialization succeeded, now safe to store block */
            source->source.sstable.current_block = klog_block;
            source->source.sstable.current_block_data = block;
            source->source.sstable.current_entry_idx = 0;

            /* we create KV pair from first entry */
            const uint8_t *value = klog_block->inline_values[0];

            /* if not inline, read from vlog */
            uint8_t *vlog_value = NULL;
            if (klog_block->entries[0].vlog_offset > 0)
            {
                tidesdb_vlog_read_value(source->source.sstable.db, sst,
                                        klog_block->entries[0].vlog_offset,
                                        klog_block->entries[0].value_size, &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                klog_block->keys[0], klog_block->entries[0].key_size, value,
                klog_block->entries[0].value_size, klog_block->entries[0].ttl,
                klog_block->entries[0].seq, klog_block->entries[0].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);

            /* if kv pair creation failed, clean up and return NULL */
            if (!source->current_kv)
            {
                tidesdb_klog_block_free(klog_block);
                block_manager_block_release(block);
                tidesdb_sstable_unref(db, sst);
                block_manager_cursor_free(source->source.sstable.klog_cursor);
                block_manager_cursor_free(source->source.sstable.vlog_cursor);
                free(source);
                return NULL;
            }

            /* dont free decompressed or release block,we're still using the deserialized data */
            return source;
        }

        /* empty block, clean up and return NULL */
        if (klog_block) tidesdb_klog_block_free(klog_block);
        if (block) block_manager_block_release(block);
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        block_manager_cursor_free(source->source.sstable.vlog_cursor);
        free(source);
        return NULL;
    }

    /* cursor_goto_first failed, clean up and return NULL */
    tidesdb_sstable_unref(db, sst);
    block_manager_cursor_free(source->source.sstable.klog_cursor);
    block_manager_cursor_free(source->source.sstable.vlog_cursor);
    free(source);
    return NULL;
}

/**
 * tidesdb_merge_source_from_btree
 * create a merge source from a btree-based sstable
 * @param db database instance
 * @param sst sstable with btree index
 * @return merge source or NULL on error
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_btree(tidesdb_t *db,
                                                               tidesdb_sstable_t *sst)
{
    tidesdb_merge_source_t *source = malloc(sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_BTREE;
    source->source.btree.sst = sst;
    source->source.btree.db = db;
    source->is_cached = 0;

    tidesdb_sstable_ref(sst);

    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    /* resolve comparator */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(db, sst->config, &comparator_fn, &comparator_ctx);

    /* we create btree handle */
    btree_t *tree = malloc(sizeof(btree_t));
    if (!tree)
    {
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    memset(tree, 0, sizeof(btree_t));
    tree->bm = bms.klog_bm;
    tree->root_offset = sst->btree_root_offset;
    tree->first_leaf_offset = sst->btree_first_leaf;
    tree->last_leaf_offset = sst->btree_last_leaf;
    tree->config.target_node_size = BTREE_DEFAULT_NODE_SIZE;
    tree->config.value_threshold = sst->config->klog_value_threshold;
    tree->config.comparator = (btree_comparator_fn)comparator_fn;
    tree->config.comparator_ctx = comparator_ctx;
    tree->config.cmp_type = comparator_fn ? BTREE_CMP_CUSTOM : BTREE_CMP_MEMCMP;
    tree->config.compression_algo = sst->config->compression_algorithm;
    tree->node_cache = db->btree_node_cache;
    tree->cache_key_prefix = sst->id;

    btree_cursor_t *cursor = NULL;
    if (btree_cursor_init(&cursor, tree) != 0)
    {
        free(tree);
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    if (btree_cursor_goto_first(cursor) != 0)
    {
        btree_cursor_free(cursor);
        free(tree);
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    source->source.btree.cursor = cursor;

    /* we init vlog cursor */
    if (block_manager_cursor_init(&source->source.btree.vlog_cursor, bms.vlog_bm) != 0)
    {
        btree_cursor_free(cursor);
        free(tree);
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    source->current_kv = NULL;
    source->config = sst->config;

    /* we get first entry */
    uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    if (btree_cursor_get(cursor, &key, &key_size, &value, &value_size, &vlog_offset, &seq, &ttl,
                         &deleted) != 0)
    {
        block_manager_cursor_free(source->source.btree.vlog_cursor);
        btree_cursor_free(cursor);
        free(tree);
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    const uint8_t *actual_value = value;
    size_t actual_value_size = value_size;
    uint8_t *vlog_value = NULL;
    if (vlog_offset > 0)
    {
        block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
        block_manager_block_t *vlog_block =
            block_manager_cursor_read(source->source.btree.vlog_cursor);
        if (vlog_block)
        {
            vlog_value = malloc(vlog_block->size);
            if (vlog_value)
            {
                memcpy(vlog_value, vlog_block->data, vlog_block->size);
                actual_value = vlog_value;
                actual_value_size = vlog_block->size;
            }
            block_manager_block_free(vlog_block);
        }
    }

    source->current_kv =
        tidesdb_kv_pair_create(key, key_size, actual_value, actual_value_size, ttl, seq, deleted);
    free(vlog_value); /* only free vlog_value if we allocated it */

    if (!source->current_kv)
    {
        block_manager_cursor_free(source->source.btree.vlog_cursor);
        btree_cursor_free(cursor);
        free(tree);
        tidesdb_sstable_unref(db, sst);
        free(source);
        return NULL;
    }

    return source;
}

/**
 * tidesdb_merge_source_from_sstable
 * create a merge source from an sstable (branches based on use_btree flag)
 * @param db database instance
 * @param sst sstable
 * @return merge source or NULL on error
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable(tidesdb_t *db,
                                                                 tidesdb_sstable_t *sst)
{
    /* we use sst->use_btree which is set from metadata, not config */
    if (sst->use_btree)
    {
        return tidesdb_merge_source_from_btree(db, sst);
    }
    return tidesdb_merge_source_from_sstable_klog(db, sst);
}

/**
 * tidesdb_merge_source_free
 * free a merge source
 * @param source merge source to free
 */
static void tidesdb_merge_source_free(tidesdb_merge_source_t *source)
{
    if (!source) return;

    if (source->type == MERGE_SOURCE_MEMTABLE)
    {
        skip_list_cursor_free(source->source.memtable.cursor);
        if (source->source.memtable.imm)
        {
            tidesdb_immutable_memtable_unref(source->source.memtable.imm);
        }
    }
    else if (source->type == MERGE_SOURCE_BTREE)
    {
        if (source->source.btree.cursor)
        {
            btree_t *tree = source->source.btree.cursor->tree;
            btree_cursor_free(source->source.btree.cursor);
            free(tree);
        }
        block_manager_cursor_free(source->source.btree.vlog_cursor);
        tidesdb_sstable_unref(NULL, source->source.btree.sst);
    }
    else if (source->type == MERGE_SOURCE_TXN_OPS)
    {
        /* we only free the sorted index array
         * txn and cf are borrowed pointers, not owned */
        free(source->source.txn_ops.sorted_indices);
    }
    else
    {
        if (source->source.sstable.current_rc_block)
        {
            tidesdb_block_release(source->source.sstable.current_rc_block);
        }
        else if (source->source.sstable.current_block)
        {
            tidesdb_klog_block_free(source->source.sstable.current_block);
        }
        if (source->source.sstable.decompressed_data)
        {
            free(source->source.sstable.decompressed_data);
        }
        if (source->source.sstable.current_block_data)
        {
            block_manager_block_release(source->source.sstable.current_block_data);
        }
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        block_manager_cursor_free(source->source.sstable.vlog_cursor);
        tidesdb_sstable_unref(NULL, source->source.sstable.sst);
    }

    tidesdb_kv_pair_free(source->current_kv);
    free(source);
}

/**
 * tidesdb_merge_source_advance
 * advance a merge source
 * @param source merge source to advance
 * @return 0 on success, -1 on failure
 */
static int tidesdb_merge_source_advance(tidesdb_merge_source_t *source)
{
    tidesdb_kv_pair_free(source->current_kv);
    source->current_kv = NULL;

    if (source->type == MERGE_SOURCE_MEMTABLE)
    {
        if (skip_list_cursor_next(source->source.memtable.cursor) == 0)
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            int64_t ttl;
            uint8_t deleted;
            uint64_t seq;

            if (skip_list_cursor_get_with_seq(source->source.memtable.cursor, &key, &key_size,
                                              &value, &value_size, &ttl, &deleted, &seq) == 0)
            {
                source->current_kv =
                    tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
                return TDB_SUCCESS;
            }
        }
    }
    else if (source->type == MERGE_SOURCE_BTREE)
    {
        if (btree_cursor_next(source->source.btree.cursor) == 0)
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;

            if (btree_cursor_get(source->source.btree.cursor, &key, &key_size, &value, &value_size,
                                 &vlog_offset, &seq, &ttl, &deleted) == 0)
            {
                const uint8_t *actual_value = value;
                size_t actual_value_size = value_size;
                uint8_t *vlog_value = NULL;
                if (vlog_offset > 0)
                {
                    block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
                    block_manager_block_t *vlog_block =
                        block_manager_cursor_read(source->source.btree.vlog_cursor);
                    if (vlog_block)
                    {
                        vlog_value = malloc(vlog_block->size);
                        if (vlog_value)
                        {
                            memcpy(vlog_value, vlog_block->data, vlog_block->size);
                            actual_value = vlog_value;
                            actual_value_size = vlog_block->size;
                        }
                        block_manager_block_free(vlog_block);
                    }
                }

                source->current_kv = tidesdb_kv_pair_create(key, key_size, actual_value,
                                                            actual_value_size, ttl, seq, deleted);
                free(vlog_value); /* only free vlog_value if we allocated it */
                return TDB_SUCCESS;
            }
        }
    }
    else if (source->type == MERGE_SOURCE_TXN_OPS)
    {
        /* advance to next entry in sorted txn ops index */
        source->source.txn_ops.pos++;
        if (source->source.txn_ops.pos < source->source.txn_ops.count)
        {
            const int op_idx = source->source.txn_ops.sorted_indices[source->source.txn_ops.pos];
            const tidesdb_txn_op_t *op = &source->source.txn_ops.txn->ops[op_idx];

            source->current_kv =
                tidesdb_kv_pair_create(op->key, op->key_size, op->value, op->value_size, op->ttl,
                                       UINT64_MAX, op->is_delete);
            return TDB_SUCCESS;
        }
        return TDB_ERR_NOT_FOUND;
    }
    else
    {
        /* we advance to next entry in current block or next block */
        source->source.sstable.current_entry_idx++;

        const tidesdb_klog_block_t *kb = source->source.sstable.current_block;
        if (kb && (uint32_t)source->source.sstable.current_entry_idx < kb->num_entries)
        {
            /* we get next entry from current block */
            const int idx = source->source.sstable.current_entry_idx;
            const uint8_t *value = kb->inline_values[idx];

            uint8_t *vlog_value = NULL;
            if (kb->entries[idx].vlog_offset > 0)
            {
                tidesdb_vlog_read_value(source->source.sstable.db, source->source.sstable.sst,
                                        kb->entries[idx].vlog_offset, kb->entries[idx].value_size,
                                        &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                kb->keys[idx], kb->entries[idx].key_size, value, kb->entries[idx].value_size,
                kb->entries[idx].ttl, kb->entries[idx].seq,
                kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);
            return TDB_SUCCESS;
        }

        if (source->source.sstable.current_rc_block)
        {
            tidesdb_block_release(source->source.sstable.current_rc_block);
            source->source.sstable.current_rc_block = NULL;
        }
        else if (source->source.sstable.current_block)
        {
            tidesdb_klog_block_free(source->source.sstable.current_block);
        }
        source->source.sstable.current_block = NULL;
        if (source->source.sstable.decompressed_data)
        {
            free(source->source.sstable.decompressed_data);
            source->source.sstable.decompressed_data = NULL;
        }
        if (source->source.sstable.current_block_data)
        {
            block_manager_block_release(source->source.sstable.current_block_data);
            source->source.sstable.current_block_data = NULL;
        }

        /* we loop to handle block read failures by trying next block */
        while (block_manager_cursor_next(source->source.sstable.klog_cursor) == 0)
        {
            if (source->source.sstable.sst->klog_data_end_offset > 0 &&
                source->source.sstable.klog_cursor->current_pos >=
                    source->source.sstable.sst->klog_data_end_offset)
            {
                /* reached end of data blocks */
                return TDB_ERR_NOT_FOUND;
            }

            block_manager_block_t *block =
                block_manager_cursor_read(source->source.sstable.klog_cursor);
            if (!block)
            {
                /* block read failed, try next block */
                continue;
            }

            /* block is owned by us, decompress if needed */
            const uint8_t *data = block->data;
            size_t data_size = block->size;
            uint8_t *decompressed = NULL;

            if (source->config->compression_algorithm != TDB_COMPRESS_NONE)
            {
                size_t decompressed_size;
                decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                               source->config->compression_algorithm);
                if (decompressed)
                {
                    data = decompressed;
                    data_size = decompressed_size;
                    /* keep decompressed buffer, deserialized pointers reference it */
                    source->source.sstable.decompressed_data = decompressed;
                }
            }

            tidesdb_klog_block_free(source->source.sstable.current_block);
            source->source.sstable.current_block = NULL;

            const int deserialize_result = tidesdb_klog_block_deserialize(
                data, data_size, &source->source.sstable.current_block);

            if (deserialize_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Klog block deserialization failed (error=%d), "
                              "trying next block for SSTable %" PRIu64,
                              deserialize_result, source->source.sstable.sst->id);
                if (decompressed)
                {
                    free(decompressed);
                    source->source.sstable.decompressed_data = NULL;
                }
                block_manager_block_release(block);
                /* deserialization failed, try next block */
                continue;
            }

            if (source->source.sstable.current_block &&
                source->source.sstable.current_block->num_entries > 0)
            {
                source->source.sstable.current_entry_idx = 0;

                const tidesdb_klog_block_t *current_kb = source->source.sstable.current_block;
                const uint8_t *value = current_kb->inline_values[0];

                uint8_t *vlog_value = NULL;
                if (current_kb->entries[0].vlog_offset > 0)
                {
                    tidesdb_vlog_read_value(source->source.sstable.db, source->source.sstable.sst,
                                            current_kb->entries[0].vlog_offset,
                                            current_kb->entries[0].value_size, &vlog_value);
                    value = vlog_value;
                }

                source->current_kv = tidesdb_kv_pair_create(
                    current_kb->keys[0], current_kb->entries[0].key_size, value,
                    current_kb->entries[0].value_size, current_kb->entries[0].ttl,
                    current_kb->entries[0].seq,
                    (current_kb->entries[0].flags & TDB_KV_FLAG_TOMBSTONE) != 0);

                free(vlog_value);
                source->source.sstable.current_block_data = block;
                return TDB_SUCCESS;
            }

            /* empty block or other issue, clean up and try next block */
            if (decompressed)
            {
                free(decompressed);
                source->source.sstable.decompressed_data = NULL;
            }
            block_manager_block_release(block);
            source->source.sstable.current_block_data = NULL;
        }
    }

    return TDB_ERR_NOT_FOUND;
}

/**
 * tidesdb_merge_source_retreat
 * retreat a merge source
 * @param source merge source to retreat
 * @return 0 on success, -1 on failure
 */
static int tidesdb_merge_source_retreat(tidesdb_merge_source_t *source)
{
    if (source == NULL) return -1;

    tidesdb_kv_pair_free(source->current_kv);
    source->current_kv = NULL;

    if (source->type == MERGE_SOURCE_MEMTABLE)
    {
        if (skip_list_cursor_prev(source->source.memtable.cursor) == 0)
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            int64_t ttl;
            uint8_t deleted;
            uint64_t seq;

            if (skip_list_cursor_get_with_seq(source->source.memtable.cursor, &key, &key_size,
                                              &value, &value_size, &ttl, &deleted, &seq) == 0)
            {
                source->current_kv =
                    tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
                return TDB_SUCCESS;
            }
        }
    }
    else if (source->type == MERGE_SOURCE_BTREE)
    {
        if (btree_cursor_prev(source->source.btree.cursor) == 0)
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;

            if (btree_cursor_get(source->source.btree.cursor, &key, &key_size, &value, &value_size,
                                 &vlog_offset, &seq, &ttl, &deleted) == 0)
            {
                const uint8_t *actual_value = value;
                size_t actual_value_size = value_size;
                uint8_t *vlog_value = NULL;
                if (vlog_offset > 0)
                {
                    block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
                    block_manager_block_t *vlog_block =
                        block_manager_cursor_read(source->source.btree.vlog_cursor);
                    if (vlog_block)
                    {
                        vlog_value = malloc(vlog_block->size);
                        if (vlog_value)
                        {
                            memcpy(vlog_value, vlog_block->data, vlog_block->size);
                            actual_value = vlog_value;
                            actual_value_size = vlog_block->size;
                        }
                        block_manager_block_free(vlog_block);
                    }
                }

                source->current_kv = tidesdb_kv_pair_create(key, key_size, actual_value,
                                                            actual_value_size, ttl, seq, deleted);
                free(vlog_value); /* we only free vlog_value if we allocated it */
                return TDB_SUCCESS;
            }
        }
    }
    else if (source->type == MERGE_SOURCE_TXN_OPS)
    {
        /* retreat to previous entry in sorted txn ops index */
        source->source.txn_ops.pos--;
        if (source->source.txn_ops.pos >= 0)
        {
            const int op_idx = source->source.txn_ops.sorted_indices[source->source.txn_ops.pos];
            const tidesdb_txn_op_t *op = &source->source.txn_ops.txn->ops[op_idx];

            source->current_kv =
                tidesdb_kv_pair_create(op->key, op->key_size, op->value, op->value_size, op->ttl,
                                       UINT64_MAX, op->is_delete);
            return TDB_SUCCESS;
        }
        return TDB_ERR_NOT_FOUND;
    }
    else
    {
        /* we move to previous entry in current block or previous block */
        const tidesdb_klog_block_t *kb = source->source.sstable.current_block;

        /* we check if we can move to previous entry in current block */
        if (kb && source->source.sstable.current_entry_idx > 0)
        {
            /* we move to previous entry in current block */
            source->source.sstable.current_entry_idx--;
            const int idx = source->source.sstable.current_entry_idx;
            const uint8_t *value = kb->inline_values[idx];

            uint8_t *vlog_value = NULL;
            if (kb->entries[idx].vlog_offset > 0)
            {
                tidesdb_vlog_read_value(source->source.sstable.db, source->source.sstable.sst,
                                        kb->entries[idx].vlog_offset, kb->entries[idx].value_size,
                                        &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                kb->keys[idx], kb->entries[idx].key_size, value, kb->entries[idx].value_size,
                kb->entries[idx].ttl, kb->entries[idx].seq,
                kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);
            return TDB_SUCCESS;
        }
        /** we check if we can move to a previous block */
        if (!block_manager_cursor_has_prev(source->source.sstable.klog_cursor))
        {
            /* already at first block, cant go back */
            return TDB_ERR_NOT_FOUND;
        }

        if (source->source.sstable.current_rc_block)
        {
            tidesdb_block_release(source->source.sstable.current_rc_block);
            source->source.sstable.current_rc_block = NULL;
        }
        else if (source->source.sstable.current_block)
        {
            tidesdb_klog_block_free(source->source.sstable.current_block);
        }
        source->source.sstable.current_block = NULL;
        if (source->source.sstable.decompressed_data)
        {
            free(source->source.sstable.decompressed_data);
            source->source.sstable.decompressed_data = NULL;
        }
        if (source->source.sstable.current_block_data)
        {
            block_manager_block_release(source->source.sstable.current_block_data);
            source->source.sstable.current_block_data = NULL;
        }

        /* we must loop to handle block read failures by trying previous block */
        while (block_manager_cursor_prev(source->source.sstable.klog_cursor) == 0)
        {
            /* we check if cursor is past data end offset (into auxiliary structures) */
            if (source->source.sstable.sst->klog_data_end_offset > 0 &&
                source->source.sstable.klog_cursor->current_pos >=
                    source->source.sstable.sst->klog_data_end_offset)
            {
                /* reached end of data blocks (moved into auxiliary structures) */
                return TDB_ERR_NOT_FOUND;
            }

            block_manager_block_t *block =
                block_manager_cursor_read(source->source.sstable.klog_cursor);
            if (!block)
            {
                /* block read failed, try previous block */
                continue;
            }

            /* block is owned by us, we decompress if needed */
            const uint8_t *data = block->data;
            size_t data_size = block->size;
            uint8_t *decompressed = NULL;

            if (source->config->compression_algorithm != TDB_COMPRESS_NONE)
            {
                size_t decompressed_size;
                decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                               source->config->compression_algorithm);
                if (decompressed)
                {
                    data = decompressed;
                    data_size = decompressed_size;
                    /* we keep decompressed buffer, deserialized pointers reference it */
                    source->source.sstable.decompressed_data = decompressed;
                }
            }

            tidesdb_klog_block_free(source->source.sstable.current_block);
            source->source.sstable.current_block = NULL;

            const int deserialize_result = tidesdb_klog_block_deserialize(
                data, data_size, &source->source.sstable.current_block);

            if (deserialize_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Klog block deserialization failed (error=%d), "
                              "trying previous block for SSTable %" PRIu64,
                              deserialize_result, source->source.sstable.sst->id);
                if (decompressed)
                {
                    free(decompressed);
                    source->source.sstable.decompressed_data = NULL;
                }
                block_manager_block_release(block);
                /* deserialization failed, try previous block */
                continue;
            }

            if (source->source.sstable.current_block &&
                source->source.sstable.current_block->num_entries > 0)
            {
                /* deserialization succeeded? now safe to store block */
                source->source.sstable.current_block_data = block;

                /* we start at last entry of previous block */
                source->source.sstable.current_entry_idx =
                    (int)(source->source.sstable.current_block->num_entries - 1);

                const tidesdb_klog_block_t *current_kb = source->source.sstable.current_block;
                const int idx = source->source.sstable.current_entry_idx;
                const uint8_t *value = current_kb->inline_values[idx];

                uint8_t *vlog_value = NULL;
                if (current_kb->entries[idx].vlog_offset > 0)
                {
                    tidesdb_vlog_read_value(source->source.sstable.db, source->source.sstable.sst,
                                            current_kb->entries[idx].vlog_offset,
                                            current_kb->entries[idx].value_size, &vlog_value);
                    value = vlog_value;
                }

                source->current_kv = tidesdb_kv_pair_create(
                    current_kb->keys[idx], current_kb->entries[idx].key_size, value,
                    current_kb->entries[idx].value_size, current_kb->entries[idx].ttl,
                    current_kb->entries[idx].seq,
                    (current_kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE) != 0);

                free(vlog_value);
                return TDB_SUCCESS;
            }

            /* empty block or other issue, clean up and try previous block */
            if (decompressed)
            {
                free(decompressed);
                source->source.sstable.decompressed_data = NULL;
            }
            block_manager_block_release(block);
        }
    }

    return TDB_ERR_NOT_FOUND;
}

/**
 * tidesdb_calculate_level_capacity
 * calculate the capacity of a level based on the level number, base capacity, and ratio
 * used for initial level sizing. once data is written, DCA (Dynamic Capacity
 * Adaptation) will adjust capacities using the formula C_i = N_L / T^(L-i) where N_L is the
 * actual data size at the largest level. This initial formula C_i = base * T^(i-1) provides
 * a reasonable starting point that grows exponentially with the size ratio.
 * @param level_num the level number (1-indexed)
 * @param base_capacity the base capacity (typically write_buffer_size)
 * @param ratio the size ratio (T)
 * @return the capacity of the level
 */
static size_t tidesdb_calculate_level_capacity(const int level_num, const size_t base_capacity,
                                               const size_t ratio)
{
    /*** initial capacity formula
     * C_i = base * T^(i-1) for level i
     * l1 -- base * T^0 = base
     * l2 -- base * T^1 = base * T
     * l3 -- base * T^2 = base * T^2
     * will be adjusted by DCA once data is written
     * uses overflow checking to prevent wraparound */
    size_t capacity = base_capacity;
    const size_t max_capacity = SIZE_MAX / 2; /* cap at half of SIZE_MAX for safety */

    for (int i = 1; i < level_num; i++)
    {
        /* we must check for overflow before multiplication */
        if (capacity > max_capacity / ratio)
        {
            /* would overflow -- saturate at max_capacity */
            TDB_DEBUG_LOG(
                TDB_LOG_WARN,
                "Level capacity calculation would overflow at level %d, saturating at %zu",
                level_num, max_capacity);
            return max_capacity;
        }
        capacity *= ratio;
    }
    return capacity;
}

/**
 * tidesdb_add_level
 * add a new level to the column family
 * @param cf the column family
 * @return TDB_SUCCESS on success, TDB_ERR_MEMORY on failure
 */
static int tidesdb_add_level(tidesdb_column_family_t *cf)
{
    int old_num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    if (old_num_levels >= TDB_MAX_LEVELS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Cannot add level - already at max (%d)", TDB_MAX_LEVELS);
        return TDB_ERR_INVALID_ARGS;
    }

    if (old_num_levels > 0)
    {
        tidesdb_level_t *largest = cf->levels[old_num_levels - 1];
        size_t largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
        size_t largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        int num_sstables = atomic_load_explicit(&largest->num_sstables, memory_order_acquire);

        /* we recheck if largest level still needs expansion */
        if (num_sstables == 0 && largest_size < largest_capacity)
        {
            return TDB_SUCCESS;
        }
    }

    /* we calculate capacity for new level */
    size_t new_capacity = tidesdb_calculate_level_capacity(
        old_num_levels + 1, cf->config.write_buffer_size, cf->config.level_size_ratio);

    /* we create new largest level at next slot */
    tidesdb_level_t *new_level = tidesdb_level_create(old_num_levels + 1, new_capacity);
    if (!new_level)
    {
        return TDB_ERR_MEMORY;
    }
    cf->levels[old_num_levels] = new_level;

    /* new level is empty -- data will flow down naturally through compaction.
     * old largest level keeps its ssts.
     *
     * spooky paper (algorithm 1) suggests moving data from old
     * largest to new largest during level addition. we intentionally do not do this
     * because it causes key loss and breaks the LSM-tree structure. instead, we let
     * normal compaction move data down, which is simpler and correct. */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Added empty level %d, old largest level %d keeps its data",
                  new_level->level_num, old_num_levels);

    /* we atomically increment active level count -- this publishes the new level
     * release ordering ensures the new level is visible to other threads */
    atomic_store_explicit(&cf->num_active_levels, old_num_levels + 1, memory_order_release);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Published %d active levels", old_num_levels + 1);
    for (int log_i = 0; log_i < old_num_levels + 1; log_i++)
    {
        tidesdb_level_t *log_lvl = cf->levels[log_i];
        if (log_lvl)
        {
            int log_num = atomic_load_explicit(&log_lvl->num_sstables, memory_order_acquire);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Levels[%d] level_num=%d, %d SSTables", log_i,
                          log_lvl->level_num, log_num);
        }
    }

    /* we must ensure level addition is visible to all threads */
    atomic_thread_fence(memory_order_release);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Added level %d, now have %d levels", new_level->level_num,
                  old_num_levels + 1);

    return TDB_SUCCESS;
}

/**
 * tidesdb_remove_level
 * remove the last level from the column family
 * @param cf the column family
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
static int tidesdb_remove_level(tidesdb_column_family_t *cf)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Attempting to remove level from CF '%s'", cf->name);
    int old_num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* we enforce minimum levels! never go below min_levels, the floor */
    if (old_num_levels <= cf->config.min_levels)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "At minimum levels (%d <= %d), not removing", old_num_levels,
                      cf->config.min_levels);
        return TDB_SUCCESS; /* not an error, just at minimum */
    }

    tidesdb_level_t *largest = cf->levels[old_num_levels - 1];
    int num_largest_ssts = atomic_load_explicit(&largest->num_sstables, memory_order_acquire);

    /* we only remove level if it's completely empty */
    if (num_largest_ssts > 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Cannot remove level %d - has %d SSTables", largest->level_num,
                      num_largest_ssts);
        return TDB_SUCCESS;
    }

    /** we update capacity of new largest level (was L-1, now L)
     * C_new_L = C_old_L / T */
    int new_num_levels = old_num_levels - 1;
    if (new_num_levels > 0)
    {
        tidesdb_level_t *new_largest = cf->levels[new_num_levels - 1];
        size_t old_largest_capacity =
            atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        size_t new_largest_capacity = old_largest_capacity / cf->config.level_size_ratio;

        if (new_largest_capacity < cf->config.write_buffer_size)
        {
            new_largest_capacity = cf->config.write_buffer_size;
        }

        atomic_store_explicit(&new_largest->capacity, new_largest_capacity, memory_order_release);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Updated new largest level %d capacity to %zu",
                      new_largest->level_num, new_largest_capacity);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Freeing removed level %d (num_sstables=%d, current_size=%zu)",
                  largest->level_num,
                  atomic_load_explicit(&largest->num_sstables, memory_order_acquire),
                  atomic_load_explicit(&largest->current_size, memory_order_relaxed));
    tidesdb_level_free(cf->db, largest);
    cf->levels[old_num_levels - 1] = NULL;

    /* we update num_active_levels to reflect removed level
     * release ordering ensures the level removal is visible to other threads */
    atomic_store_explicit(&cf->num_active_levels, new_num_levels, memory_order_release);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Removed level, now have %d levels", new_num_levels);

    tidesdb_apply_dca(cf);

    return TDB_SUCCESS;
}

/**
 * tidesdb_apply_dca
 * apply dynamic capacity adaptation to the column family
 * @param cf the column family
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
static int tidesdb_apply_dca(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    if (num_levels < 2)
    {
        return TDB_SUCCESS;
    }

    /* we get data size at largest level */
    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t N_L = atomic_load(&largest->current_size);

    /* we update capacities C_i = N_L / T^(L-i)
     * paper uses 1-based level numbering (level 1, 2, 3...)
     * we use 0-based array indexing (levels[0], levels[1], levels[2]...)
     * so we adjust -- for array index i, the level number is i+1
     * formula becomes -- C[i] = N_L / T^(L-(i+1)) = N_L / T^(L-1-i) */
    for (int i = 0; i < num_levels - 1; i++)
    {
        size_t power = num_levels - 1 - i; /* L - 1 - i (adjusted for 0-based indexing) */
        size_t divisor = 1;
        for (size_t p = 0; p < power; p++)
        {
            divisor *= cf->config.level_size_ratio;
        }

        size_t old_capacity = atomic_load_explicit(&cf->levels[i]->capacity, memory_order_acquire);
        size_t new_capacity = N_L / divisor;

        if (new_capacity < cf->config.write_buffer_size)
        {
            new_capacity = cf->config.write_buffer_size;
        }

        if (new_capacity != old_capacity)
        {
            atomic_store_explicit(&cf->levels[i]->capacity, new_capacity, memory_order_release);
        }
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_snapshot_sst_ids
 * snapshot sstable IDs from a range of levels to prevent race with flush workers
 * @param cf the column family
 * @param start_level start level (0-indexed)
 * @param end_level end level (0-indexed, inclusive)
 * @return queue of uint64_t* IDs, or NULL on failure
 */
static queue_t *tidesdb_snapshot_sst_ids(const tidesdb_column_family_t *cf, const int start_level,
                                         const int end_level)
{
    queue_t *snapshot = queue_new();
    if (!snapshot) return NULL;

    for (int level = start_level; level <= end_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        const int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            uint64_t *id_copy = malloc(sizeof(uint64_t));
            if (id_copy)
            {
                *id_copy = sst->id;
                queue_enqueue(snapshot, id_copy);
            }
        }
    }

    return snapshot;
}

/**
 * tidesdb_cleanup_snapshot_ids
 * free all IDs in a snapshot queue and the queue itself
 * @param snapshot the snapshot queue to cleanup
 */
static void tidesdb_cleanup_snapshot_ids(queue_t *snapshot)
{
    if (!snapshot) return;

    while (queue_size(snapshot) > 0)
    {
        uint64_t *id_ptr = (uint64_t *)queue_dequeue(snapshot);
        free(id_ptr);
    }
    queue_free(snapshot);
}

/**
 * tidesdb_sst_in_snapshot
 * check if an sstable ID is in the snapshot
 * @param snapshot the snapshot queue
 * @param sst_id the sstable ID to check
 * @return 1 if in snapshot, 0 otherwise
 */
static int tidesdb_sst_in_snapshot(queue_t *snapshot, const uint64_t sst_id)
{
    const size_t snapshot_size = queue_size(snapshot);
    for (size_t j = 0; j < snapshot_size; j++)
    {
        const uint64_t *id_ptr = (uint64_t *)queue_peek_at(snapshot, j);
        if (id_ptr && *id_ptr == sst_id)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * tidesdb_collect_ssts_from_snapshot
 * collect sstables matching snapshot IDs with references
 * @param cf the column family
 * @param start_level start level (0-indexed)
 * @param end_level end level (0-indexed, inclusive)
 * @param snapshot the snapshot queue of IDs
 * @param ssts_out output array of sstables (caller must free)
 * @param count_out output count of sstables
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_collect_ssts_from_snapshot(const tidesdb_column_family_t *cf,
                                              const int start_level, const int end_level,
                                              queue_t *snapshot, tidesdb_sstable_t ***ssts_out,
                                              int *count_out)
{
    *ssts_out = NULL;
    *count_out = 0;

    const size_t snapshot_size = queue_size(snapshot);
    if (snapshot_size == 0) return TDB_SUCCESS;

    tidesdb_sstable_t **ssts_array = malloc(snapshot_size * sizeof(tidesdb_sstable_t *));
    if (!ssts_array) return TDB_ERR_MEMORY;

    int sst_idx = 0;

    for (int level = start_level; level <= end_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        const int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            if (tidesdb_sst_in_snapshot(snapshot, sst->id))
            {
                tidesdb_sstable_ref(sst);
                ssts_array[sst_idx++] = sst;
            }
        }
    }

    *ssts_out = ssts_array;
    *count_out = sst_idx;
    return TDB_SUCCESS;
}

/**
 * tidesdb_add_ssts_to_merge_heap
 * create merge sources from sstables and add to heap
 * @param db the database
 * @param ssts array of sstables
 * @param count number of sstables
 * @param heap the merge heap
 * @param delete_queue queue to add sstables for later deletion
 */
static void tidesdb_add_ssts_to_merge_heap(tidesdb_t *db, tidesdb_sstable_t **ssts, const int count,
                                           tidesdb_merge_heap_t *heap, queue_t *delete_queue)
{
    for (int i = 0; i < count; i++)
    {
        tidesdb_sstable_t *sst = ssts[i];

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "Creating merge source for SSTable %" PRIu64 " (num_klog_blocks=%" PRIu64
                      ", klog_data_end_offset=%" PRIu64 ")",
                      sst->id, sst->num_klog_blocks, sst->klog_data_end_offset);

        tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(db, sst);
        if (source)
        {
            if (source->current_kv)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Added merge source for SSTable %" PRIu64, sst->id);
                if (tidesdb_merge_heap_add_source(heap, source) != TDB_SUCCESS)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Failed to add merge source for SSTable %" PRIu64 " to heap",
                                  sst->id);
                    tidesdb_merge_source_free(source);
                }
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Merge source for SSTable %" PRIu64 " has no current_kv, skipping",
                              sst->id);
                tidesdb_merge_source_free(source);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create merge source for SSTable %" PRIu64,
                          sst->id);
        }

        queue_enqueue(delete_queue, sst);
    }
}

/**
 * tidesdb_cleanup_merged_sstables
 * remove old sstables from levels and manifest after merge
 * @param cf the column family
 * @param delete_queue queue of sstables to delete
 * @param start_level start level (0-indexed)
 * @param end_level end level (0-indexed, inclusive)
 */
static void tidesdb_cleanup_merged_sstables(tidesdb_column_family_t *cf, queue_t *delete_queue,
                                            const int start_level, const int end_level)
{
    const int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    while (!queue_is_empty(delete_queue))
    {
        tidesdb_sstable_t *sst = queue_dequeue(delete_queue);
        if (!sst) continue;

        atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

        int removed = 0;
        int removed_level = -1;

        for (int level = start_level; level <= end_level && level < num_levels; level++)
        {
            tidesdb_level_t *lvl = cf->levels[level];
            const int result = tidesdb_level_remove_sstable(cf->db, lvl, sst);
            if (result == TDB_SUCCESS)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Removed SSTable %" PRIu64 " from level %d", sst->id,
                              lvl->level_num);
                atomic_fetch_add_explicit(&cf->next_sstable_id, 1, memory_order_release);
                tidesdb_bump_sstable_layout_version(cf);
                removed = 1;
                removed_level = lvl->level_num;
                break;
            }
        }

        if (removed)
        {
            tidesdb_manifest_remove_sstable(cf->manifest, removed_level, sst->id);
            const int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
            if (manifest_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Failed to commit manifest after removing SSTable %" PRIu64
                              " (error: %d)",
                              sst->id, manifest_result);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " not found in any level", sst->id);
        }

        tidesdb_sstable_unref(cf->db, sst);
    }
}

/**
 * tidesdb_full_preemptive_merge
 * perform a full preemptive merge on the column family
 * @param cf the column family
 * @param start_level the start level
 * @param target_level the target level
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
static int tidesdb_full_preemptive_merge(tidesdb_column_family_t *cf, int start_level,
                                         int target_level)
{
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    if (start_level < 0 || target_level >= num_levels)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    /* we determine if we're merging into the largest (bottommost) level
     * tombstones can only be dropped when merging into the largest level
     * because there's no lower level that might contain the data being deleted */
    const int is_largest_level = (target_level == num_levels - 1);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Starting full preemptive merge on CF '%s', levels %d->%d",
                  cf->name, start_level + 1, target_level + 1);

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    tidesdb_merge_heap_t *heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
    if (!heap) return TDB_ERR_MEMORY;

    queue_t *sstables_to_delete = queue_new();
    if (!sstables_to_delete)
    {
        tidesdb_merge_heap_free(heap);
        return TDB_ERR_MEMORY;
    }

    queue_t *sstable_ids_snapshot = tidesdb_snapshot_sst_ids(cf, start_level, target_level);
    if (!sstable_ids_snapshot)
    {
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        return TDB_ERR_MEMORY;
    }

    if (queue_size(sstable_ids_snapshot) == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "No SSTables to merge, skipping");
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return TDB_SUCCESS;
    }

    tidesdb_sstable_t **ssts_array = NULL;
    int sst_count = 0;
    int collect_result = tidesdb_collect_ssts_from_snapshot(
        cf, start_level, target_level, sstable_ids_snapshot, &ssts_array, &sst_count);
    if (collect_result != TDB_SUCCESS)
    {
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return collect_result;
    }

    tidesdb_add_ssts_to_merge_heap(cf->db, ssts_array, sst_count, heap, sstables_to_delete);
    free(ssts_array);

    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char path[MAX_FILE_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d", cf->directory,
             target_level + 1);

    tidesdb_sstable_t *new_sst = tidesdb_sstable_create(cf->db, path, new_id, &cf->config);
    if (!new_sst)
    {
        tidesdb_merge_heap_free(heap);
        tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_level, target_level);
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return TDB_ERR_MEMORY;
    }

    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open(&klog_bm, new_sst->klog_path,
                           convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                 ? TDB_SYNC_FULL
                                                 : cf->config.sync_mode)) != 0)
    {
        tidesdb_sstable_unref(cf->db, new_sst);
        tidesdb_merge_heap_free(heap);
        tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_level, target_level);
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return TDB_ERR_IO;
    }

    if (block_manager_open(&vlog_bm, new_sst->vlog_path,
                           convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                 ? TDB_SYNC_FULL
                                                 : cf->config.sync_mode)) != 0)
    {
        block_manager_close(klog_bm);
        tidesdb_sstable_unref(cf->db, new_sst);
        tidesdb_merge_heap_free(heap);
        tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_level, target_level);
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return TDB_ERR_IO;
    }

    /* we calc expected number of entries for bloom filter sizing
     * during merge, duplicates are eliminated and tombstones may be removed,
     * so the actual count will be lower. we use the sum as an upper bound to ensure
     * the bloom filter is adequately sized. */
    uint64_t estimated_entries = 0;

    /* we reload levels for estimated entries calculation */
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];

        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            /* we check for null as concurrent compactions may have removed sstables */
            if (sst)
            {
                estimated_entries += sst->num_entries;
            }
        }
    }

    if (estimated_entries < TDB_MERGE_MIN_ESTIMATED_ENTRIES)
        estimated_entries = TDB_MERGE_MIN_ESTIMATED_ENTRIES;

    bloom_filter_t *bloom = NULL;
    tidesdb_block_index_t *block_indexes = NULL;

    if (new_sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, new_sst->config->bloom_fpr, (int)estimated_entries) == 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Bloom filter created (estimated entries: %" PRIu64 ")",
                          estimated_entries);
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Bloom filter creation failed");
            bloom = NULL;
        }
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Bloom filter disabled");
    }

    if (new_sst->config->enable_block_indexes && !cf->config.use_btree)
    {
        block_indexes =
            compact_block_index_create(estimated_entries, new_sst->config->block_index_prefix_len,
                                       comparator_fn, comparator_ctx);
        if (block_indexes)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Block indexes created");
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Block indexes builder creation failed");
        }
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Block indexes disabled");
    }

    /* we branch to btree output if use_btree is enabled */
    if (cf->config.use_btree)
    {
        int btree_result = tidesdb_sstable_write_from_heap_btree(
            cf, new_sst, heap, klog_bm, vlog_bm, bloom, sstables_to_delete, is_largest_level);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        tidesdb_merge_heap_free(heap);

        if (btree_result != TDB_SUCCESS)
        {
            tidesdb_sstable_unref(cf->db, new_sst);
            tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_level, target_level);
            queue_free(sstables_to_delete);
            tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
            return btree_result;
        }

        bloom = NULL;
        goto merge_complete;
    }

    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();

    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    uint64_t max_seq = 0;

    uint8_t *last_key = NULL;
    size_t last_key_size = 0;

    /* we track first and last key of current block for block index */
    uint8_t *block_first_key = NULL;
    size_t block_first_key_size = 0;
    uint8_t *block_last_key = NULL;
    size_t block_last_key_size = 0;

    /* merge using heap */
    while (!tidesdb_merge_heap_empty(heap))
    {
        tidesdb_sstable_t *corrupted_sst = NULL;
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap, &corrupted_sst);

        /* if corruption detected, add to deletion queue */
        if (corrupted_sst)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Detected corrupted SSTable %" PRIu64 ", marking for deletion",
                          corrupted_sst->id);
            queue_enqueue(sstables_to_delete, corrupted_sst);
        }

        if (!kv)
        {
            break;
        }

        /* we skip duplicate keys (keep newest based on seq) */
        if (last_key && last_key_size == kv->entry.key_size &&
            memcmp(last_key, kv->key, last_key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* we update last key */
        free(last_key);
        last_key = malloc(kv->entry.key_size);
        if (last_key)
        {
            memcpy(last_key, kv->key, kv->entry.key_size);
            last_key_size = kv->entry.key_size;
        }

        /* we only drop tombstones when merging into the largest level
         * tombstones must be preserved in upper levels to mask deleted keys in lower levels */
        if ((kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) && is_largest_level)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (kv->entry.ttl > 0 && kv->entry.ttl < atomic_load_explicit(&cf->db->cached_current_time,
                                                                      memory_order_relaxed))
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (kv->entry.value_size >= cf->config.klog_value_threshold && kv->value)
        {
            /* we write value directly to vlog */
            uint8_t *final_data = kv->value;
            size_t final_size = kv->entry.value_size;
            uint8_t *compressed = NULL;

            if (new_sst->config->compression_algorithm != TDB_COMPRESS_NONE)
            {
                size_t compressed_size;
                compressed = compress_data(kv->value, kv->entry.value_size, &compressed_size,
                                           new_sst->config->compression_algorithm);
                if (compressed)
                {
                    final_data = compressed;
                    final_size = compressed_size;
                }
            }

            block_manager_block_t *vlog_block = block_manager_block_create(final_size, final_data);
            if (vlog_block)
            {
                int64_t block_offset = block_manager_block_write(vlog_bm, vlog_block);
                if (block_offset >= 0)
                {
                    kv->entry.vlog_offset = (uint64_t)block_offset;
                    vlog_block_num++;
                }
                block_manager_block_release(vlog_block);
            }
            free(compressed);
        }

        /* we check if this is the first entry in a new block */
        int is_first_entry_in_block = (current_klog_block->num_entries == 0);

        tidesdb_klog_block_add_entry(current_klog_block, kv, &cf->config, comparator_fn,
                                     comparator_ctx);

        /* we track first key of block */
        if (is_first_entry_in_block)
        {
            free(block_first_key);
            block_first_key = malloc(kv->entry.key_size);
            if (block_first_key)
            {
                memcpy(block_first_key, kv->key, kv->entry.key_size);
                block_first_key_size = kv->entry.key_size;
            }
        }

        /* we always update last key of block */
        free(block_last_key);
        block_last_key = malloc(kv->entry.key_size);
        if (block_last_key)
        {
            memcpy(block_last_key, kv->key, kv->entry.key_size);
            block_last_key_size = kv->entry.key_size;
        }

        if (tidesdb_klog_block_is_full(current_klog_block, TDB_KLOG_BLOCK_SIZE))
        {
            uint8_t *klog_data;
            size_t klog_size;
            if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
            {
                uint8_t *final_data = klog_data;
                size_t final_size = klog_size;

                if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
                {
                    size_t compressed_size;
                    uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                        cf->config.compression_algorithm);
                    if (compressed)
                    {
                        free(klog_data);
                        final_data = compressed;
                        final_size = compressed_size;
                    }
                }

                block_manager_block_t *klog_block =
                    block_manager_block_create(final_size, final_data);
                if (klog_block)
                {
                    uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);
                    block_manager_block_write(klog_bm, klog_block);
                    block_manager_block_release(klog_block);

                    if (block_indexes && block_first_key && block_last_key)
                    {
                        if (klog_block_num % cf->config.index_sample_ratio == 0)
                        {
                            compact_block_index_add(block_indexes, block_first_key,
                                                    block_first_key_size, block_last_key,
                                                    block_last_key_size, block_file_position);
                        }
                    }

                    klog_block_num++;
                }
                free(final_data);
            }

            tidesdb_klog_block_free(current_klog_block);
            current_klog_block = tidesdb_klog_block_create();

            free(block_first_key);
            free(block_last_key);
            block_first_key = NULL;
            block_last_key = NULL;
        }

        if (kv->entry.seq > max_seq)
        {
            max_seq = kv->entry.seq;
        }

        if (bloom)
        {
            bloom_filter_add(bloom, kv->key, kv->entry.key_size);
        }

        if (!new_sst->min_key)
        {
            new_sst->min_key = malloc(kv->entry.key_size);
            if (new_sst->min_key)
            {
                memcpy(new_sst->min_key, kv->key, kv->entry.key_size);
                new_sst->min_key_size = kv->entry.key_size;
            }
        }

        free(new_sst->max_key);
        new_sst->max_key = malloc(kv->entry.key_size);
        if (new_sst->max_key)
        {
            memcpy(new_sst->max_key, kv->key, kv->entry.key_size);
            new_sst->max_key_size = kv->entry.key_size;
        }

        new_sst->num_entries++;

        tidesdb_kv_pair_free(kv);
    }

    new_sst->max_seq = max_seq;

    free(last_key);

    if (current_klog_block->num_entries > 0)
    {
        uint8_t *klog_data;
        size_t klog_size;
        if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
        {
            uint8_t *final_data = klog_data;
            size_t final_size = klog_size;

            if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
            {
                size_t compressed_size;
                uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                    cf->config.compression_algorithm);
                if (compressed)
                {
                    free(klog_data);
                    final_data = compressed;
                    final_size = compressed_size;
                }
            }

            block_manager_block_t *klog_block = block_manager_block_create(final_size, final_data);
            if (klog_block)
            {
                uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);
                block_manager_block_write(klog_bm, klog_block);
                block_manager_block_release(klog_block);

                if (block_indexes && block_first_key && block_last_key)
                {
                    if (klog_block_num % cf->config.index_sample_ratio == 0)
                    {
                        compact_block_index_add(block_indexes, block_first_key,
                                                block_first_key_size, block_last_key,
                                                block_last_key_size, block_file_position);
                    }
                }

                klog_block_num++;
            }
            free(final_data);
        }
    }

    free(block_first_key);
    free(block_last_key);

    tidesdb_klog_block_free(current_klog_block);

    new_sst->num_klog_blocks = klog_block_num;
    new_sst->num_vlog_blocks = vlog_block_num;

    block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

    /* we write auxiliary structures (always write, even if empty, to maintain consistent file
     * structure) */
    if (new_sst->num_entries > 0)
    {
        /* write index block */
        if (block_indexes)
        {
            /* we assign the built index to the sstable */
            new_sst->block_indexes = block_indexes;

            TDB_DEBUG_LOG(TDB_LOG_INFO, "Block index built with %u samples",
                          new_sst->block_indexes->count);
            size_t index_size;
            uint8_t *index_data =
                compact_block_index_serialize(new_sst->block_indexes, &index_size);
            if (index_data)
            {
                block_manager_block_t *index_block =
                    block_manager_block_create(index_size, index_data);
                if (index_block)
                {
                    block_manager_block_write(klog_bm, index_block);
                    block_manager_block_release(index_block);
                }
                free(index_data);
            }
        }
        else
        {
            /* we write empty index block as placeholder */
            block_manager_block_t *empty_index = block_manager_block_create(0, NULL);
            if (empty_index)
            {
                block_manager_block_write(klog_bm, empty_index);
                block_manager_block_release(empty_index);
            }
        }

        if (bloom)
        {
            size_t bloom_size;
            uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
            if (bloom_data)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Bloom filter serialized to %zu bytes", bloom_size);
                block_manager_block_t *bloom_block =
                    block_manager_block_create(bloom_size, bloom_data);
                if (bloom_block)
                {
                    block_manager_block_write(klog_bm, bloom_block);
                    block_manager_block_release(bloom_block);
                }
                free(bloom_data);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "Bloom filter serialization failed");
            }
            new_sst->bloom_filter = bloom;
        }
        else
        {
            /* we write empty bloom block as placeholder */
            block_manager_block_t *empty_bloom = block_manager_block_create(0, NULL);
            if (empty_bloom)
            {
                block_manager_block_write(klog_bm, empty_bloom);
                block_manager_block_release(empty_bloom);
            }
        }
    }

    /* we get file sizes before metadata write for serialization */
    uint64_t klog_size_before_metadata;
    uint64_t vlog_size_before_metadata;
    block_manager_get_size(klog_bm, &klog_size_before_metadata);
    block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

    new_sst->klog_size = klog_size_before_metadata;
    new_sst->vlog_size = vlog_size_before_metadata;

    /* we write metadata block as the last block -- only if we have entries */
    uint8_t *metadata_data = NULL;
    size_t metadata_size = 0;
    if (new_sst->num_entries > 0 &&
        sstable_metadata_serialize(new_sst, &metadata_data, &metadata_size) == 0)
    {
        block_manager_block_t *metadata_block =
            block_manager_block_create(metadata_size, metadata_data);
        if (metadata_block)
        {
            block_manager_block_write(klog_bm, metadata_block);
            block_manager_block_release(metadata_block);
        }
        free(metadata_data);
    }

    block_manager_get_size(klog_bm, &new_sst->klog_size);
    block_manager_get_size(vlog_bm, &new_sst->vlog_size);

    tidesdb_merge_heap_free(heap);

    block_manager_escalate_fsync(klog_bm);
    block_manager_escalate_fsync(vlog_bm);

    new_sst->klog_bm = klog_bm;
    new_sst->vlog_bm = vlog_bm;
    atomic_store(&new_sst->last_access_time,
                 atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed));
    atomic_fetch_add(&cf->db->num_open_sstables, 1);

    /* we ensure all writes are visible before making sstable discoverable */
    atomic_thread_fence(memory_order_seq_cst);

    /* we close write handles before adding to level
     * readers will reopen files on-demand through tidesdb_sstable_ensure_open
     * this prevents file locking issues where readers try to open files
     * that are still open for writing */
    if (klog_bm)
    {
        block_manager_close(klog_bm);
        new_sst->klog_bm = NULL;
    }
    if (vlog_bm)
    {
        block_manager_close(vlog_bm);
        new_sst->vlog_bm = NULL;
    }

merge_complete:;
    /* we save metadata for logging before potentially freeing sstable */
    const uint64_t sst_id = new_sst->id;
    const uint64_t num_entries = new_sst->num_entries;
    const uint64_t num_klog_blocks = new_sst->num_klog_blocks;
    const uint64_t num_vlog_blocks = new_sst->num_vlog_blocks;

    /* we only add sstable if it has entries -- empty sstables cause corruption */
    if (num_entries > 0)
    {
        /* we reload levels and num_levels as DCA may have changed them
         * we load num_levels first to match store order */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

        /* we find the target level by level_num, not by stale array index */
        int target_level_num = target_level + 1;
        int target_idx = -1;
        for (int i = 0; i < num_levels; i++)
        {
            if (cf->levels[i]->level_num == target_level_num)
            {
                target_idx = i;
                break;
            }
        }

        if (target_idx < 0 || target_idx >= num_levels)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Target level %d not found (current_num_levels=%d)",
                          target_level_num, num_levels);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "Adding merged SSTable %" PRIu64 " to level %d (array index %d)",
                          new_sst->id, cf->levels[target_idx]->level_num, target_idx);
            tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);
            tidesdb_bump_sstable_layout_version(cf);

            tidesdb_manifest_add_sstable(cf->manifest, cf->levels[target_idx]->level_num,
                                         new_sst->id, new_sst->num_entries,
                                         new_sst->klog_size + new_sst->vlog_size);
            atomic_store(&cf->manifest->sequence, atomic_load(&cf->next_sstable_id));
            int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
            if (manifest_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Failed to commit manifest for new SSTable %" PRIu64 " (error: %d)",
                              new_sst->id, manifest_result);
            }

            tidesdb_sstable_unref(cf->db, new_sst);
        }
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Skipping empty SSTable %" PRIu64 " (0 entries)", sst_id);
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        remove(new_sst->klog_path);
        remove(new_sst->vlog_path);
        tidesdb_sstable_unref(cf->db, new_sst);
    }

    tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_level, target_level);
    queue_free(sstables_to_delete);
    tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "Full preemptive merge completed for CF '%s', created SSTable %" PRIu64
                  " with %" PRIu64 " entries, %" PRIu64 " klog blocks, %" PRIu64 " vlog blocks",
                  cf->name, sst_id, num_entries, num_klog_blocks, num_vlog_blocks);

    return TDB_SUCCESS;
}

/**
 * tidesdb_dividing_merge
 * dividing merge into level X and partition based on largest level boundaries
 * @param cf column family
 * @param target_level target level
 * @return 0 on success, negative on failure
 */
static int tidesdb_dividing_merge(tidesdb_column_family_t *cf, int target_level)
{
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    if (target_level >= num_levels || target_level < 0)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Starting dividing merge for CF '%s', target_level=%d", cf->name,
                  target_level + 1);

    if (target_level >= num_levels - 1)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "Target level %d is the largest level, need to add new level before merge",
                      target_level + 1);

        /*** we ensure there's a level to merge into */
        if (target_level + 1 >= num_levels)
        {
            int add_result = tidesdb_add_level(cf);
            if (add_result != TDB_SUCCESS)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to add level before merge, error: %d",
                              add_result);
                return add_result;
            }

            num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

            TDB_DEBUG_LOG(TDB_LOG_INFO, "Added level, now have %d levels", num_levels);
        }

        return tidesdb_full_preemptive_merge(cf, 0, target_level);
    }

    tidesdb_level_t *target = cf->levels[target_level];
    /** dividing merge
     * we use boundaries from target_level+1 (the level we're merging into) */
    tidesdb_level_t *next_level = cf->levels[target_level + 1];

    tidesdb_level_update_boundaries(target, next_level);

    int next_level_num_ssts = atomic_load_explicit(&next_level->num_sstables, memory_order_acquire);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Next level (L%d) has %d SSTables", next_level->level_num,
                  next_level_num_ssts);
    tidesdb_sstable_t **next_level_ssts =
        atomic_load_explicit(&next_level->sstables, memory_order_acquire);
    for (int i = 0; i < next_level_num_ssts; i++)
    {
        tidesdb_sstable_t *sst = next_level_ssts[i];
        if (sst)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "Next level SSTable %" PRIu64 " (min_key_size=%zu, max_key_size=%zu)",
                          sst->id, sst->min_key_size, sst->max_key_size);
        }
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    queue_t *sstables_to_delete = queue_new();
    if (!sstables_to_delete) return TDB_ERR_MEMORY;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Snapshotting SSTable IDs from levels 1-%d", target_level + 1);
    queue_t *sstable_ids_snapshot = tidesdb_snapshot_sst_ids(cf, 0, target_level);
    if (!sstable_ids_snapshot)
    {
        queue_free(sstables_to_delete);
        return TDB_ERR_MEMORY;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Collecting SSTables from levels 1-%d", target_level + 1);
    tidesdb_sstable_t **ssts_array = NULL;
    int sst_count = 0;
    int collect_result = tidesdb_collect_ssts_from_snapshot(
        cf, 0, target_level, sstable_ids_snapshot, &ssts_array, &sst_count);
    if (collect_result != TDB_SUCCESS)
    {
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return collect_result;
    }

    for (int i = 0; i < sst_count; i++)
    {
        tidesdb_sstable_t *sst = ssts_array[i];
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "collecting SSTable %" PRIu64 " (min_key_size=%zu, max_key_size=%zu)",
                      sst->id, sst->min_key_size, sst->max_key_size);
        queue_enqueue(sstables_to_delete, sst);
    }
    free(ssts_array);

    /* we get partition boundaries from target level */
    target = cf->levels[target_level];
    int num_boundaries = atomic_load_explicit(&target->num_boundaries, memory_order_acquire);
    uint8_t **file_boundaries =
        atomic_load_explicit(&target->file_boundaries, memory_order_acquire);
    size_t *boundary_sizes = atomic_load_explicit(&target->boundary_sizes, memory_order_acquire);

    /* we get number of sstables being merged */
    size_t num_sstables_to_merge = queue_size(sstables_to_delete);

    /* if no boundaries, do a simple full merge */
    if (num_boundaries == 0)
    {
        int result = tidesdb_full_preemptive_merge(cf, 0, target_level);

        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(cf->db, sst);
        }
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);

        return result;
    }

    /* we calculate total estimated entries from all ssts being merged */
    uint64_t total_estimated_entries = 0;
    for (size_t i = 0; i < num_sstables_to_merge; i++)
    {
        tidesdb_sstable_t *sst = queue_peek_at(sstables_to_delete, i);
        if (sst)
        {
            total_estimated_entries += sst->num_entries;
        }
    }

    /* partitioned merge creates one sstable per partition */
    int num_partitions = num_boundaries + 1;

    /* we estimate entries per partition (divide total by number of partitions) */
    uint64_t partition_estimated_entries = total_estimated_entries / num_partitions;
    if (partition_estimated_entries < TDB_MERGE_MIN_ESTIMATED_ENTRIES)
        partition_estimated_entries = TDB_MERGE_MIN_ESTIMATED_ENTRIES;

    for (int partition = 0; partition < num_partitions; partition++)
    {
        /* we create separate heap for this partition to avoid data loss */
        tidesdb_merge_heap_t *partition_heap =
            tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
        if (!partition_heap)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create heap for partition %d", partition);
            continue;
        }

        /* we determine key range for this partition */
        uint8_t *range_start = (partition > 0) ? file_boundaries[partition - 1] : NULL;
        size_t range_start_size = (partition > 0) ? boundary_sizes[partition - 1] : 0;
        uint8_t *range_end = (partition < num_boundaries) ? file_boundaries[partition] : NULL;
        size_t range_end_size = (partition < num_boundaries) ? boundary_sizes[partition] : 0;

        TDB_DEBUG_LOG(TDB_LOG_INFO, "Partition %d range [start_size=%zu, end_size=%zu)", partition,
                      range_start_size, range_end_size);

        /* we add only overlapping sstables to this partitions heap */
        uint64_t partition_entries = 0;
        size_t num_sstables_in_partition = queue_size(sstables_to_delete);
        for (size_t i = 0; i < num_sstables_in_partition; i++)
        {
            tidesdb_sstable_t *sst = queue_peek_at(sstables_to_delete, i);
            if (!sst) continue;

            /* we check if this sstable overlaps with partition range */
            int overlaps = 1;

            if (range_start && comparator_fn(sst->max_key, sst->max_key_size, range_start,
                                             range_start_size, comparator_ctx) < 0)
            {
                overlaps = 0; /* sst is entirely before partition */
            }

            if (overlaps && range_end &&
                comparator_fn(sst->min_key, sst->min_key_size, range_end, range_end_size,
                              comparator_ctx) >= 0)
            {
                overlaps = 0; /* sst is entirely after partition */
            }

            if (overlaps)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "Partition %d SSTable %" PRIu64
                              " overlaps (min_key_size=%zu, max_key_size=%zu)",
                              partition, sst->id, sst->min_key_size, sst->max_key_size);
                tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
                if (source)
                {
                    if (source->current_kv)
                    {
                        if (tidesdb_merge_heap_add_source(partition_heap, source) == TDB_SUCCESS)
                        {
                            partition_entries += sst->num_entries;
                        }
                        else
                        {
                            tidesdb_merge_source_free(source);
                        }
                    }
                    else
                    {
                        tidesdb_merge_source_free(source);
                    }
                }
            }
        }

        if (partition_estimated_entries < TDB_MERGE_MIN_ESTIMATED_ENTRIES)
            partition_estimated_entries = TDB_MERGE_MIN_ESTIMATED_ENTRIES;

        if (tidesdb_merge_heap_empty(partition_heap))
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "Partition %d skipping empty partition (no overlapping SSTables)",
                          partition);
            tidesdb_merge_heap_free(partition_heap);
            continue;
        }

        /* we create new sst for this partition with partition naming */
        uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char sst_path[MAX_FILE_PATH_LENGTH];
        snprintf(sst_path, sizeof(sst_path),
                 "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                 cf->directory, target_level + 1, partition);

        tidesdb_sstable_t *new_sst = tidesdb_sstable_create(cf->db, sst_path, sst_id, &cf->config);
        if (!new_sst)
        {
            tidesdb_merge_heap_free(partition_heap);
            continue;
        }

        block_manager_t *klog_bm = NULL;
        block_manager_t *vlog_bm = NULL;

        if (block_manager_open(&klog_bm, new_sst->klog_path,
                               convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                     ? TDB_SYNC_FULL
                                                     : cf->config.sync_mode)) != 0)
        {
            tidesdb_merge_heap_free(partition_heap);
            tidesdb_sstable_unref(cf->db, new_sst);
            continue;
        }

        if (block_manager_open(&vlog_bm, new_sst->vlog_path,
                               convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                     ? TDB_SYNC_FULL
                                                     : cf->config.sync_mode)) != 0)
        {
            block_manager_close(klog_bm);
            tidesdb_merge_heap_free(partition_heap);
            tidesdb_sstable_unref(cf->db, new_sst);
            continue;
        }

        /* we merge keys in this partition's range */
        tidesdb_klog_block_t *klog_block = tidesdb_klog_block_create();

        uint64_t entry_count = 0;
        uint64_t klog_block_num = 0;
        uint64_t vlog_block_num = 0;
        uint64_t max_seq = 0;
        uint8_t *first_key = NULL;
        size_t first_key_size = 0;
        uint8_t *last_key = NULL;
        size_t last_key_size = 0;

        bloom_filter_t *bloom = NULL;
        tidesdb_block_index_t *block_indexes = NULL;

        /* we track first and last key of current block for block index */
        uint8_t *block_first_key = NULL;
        size_t block_first_key_size = 0;
        uint8_t *block_last_key = NULL;
        size_t block_last_key_size = 0;

        if (cf->config.enable_bloom_filter)
        {
            if (bloom_filter_new(&bloom, cf->config.bloom_fpr, (int)partition_entries) == 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "Partition %d bloom filter created (estimated entries: %" PRIu64 ")",
                              partition, partition_entries);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "Partition %d bloom filter creation failed",
                              partition);
                bloom = NULL;
            }
        }

        if (cf->config.enable_block_indexes && !cf->config.use_btree)
        {
            block_indexes =
                compact_block_index_create(partition_entries, cf->config.block_index_prefix_len,
                                           comparator_fn, comparator_ctx);
        }

        /* we branch to btree output if use_btree is enabled
         * dividing merge never goes to largest level (it adds a level first) */
        if (cf->config.use_btree)
        {
            int btree_result = tidesdb_sstable_write_from_heap_btree(
                cf, new_sst, partition_heap, klog_bm, vlog_bm, bloom, NULL, 0);
            block_manager_close(klog_bm);
            block_manager_close(vlog_bm);
            tidesdb_merge_heap_free(partition_heap);

            bloom = NULL;

            if (btree_result != TDB_SUCCESS || new_sst->num_entries == 0)
            {
                if (new_sst->num_entries == 0)
                {
                    remove(new_sst->klog_path);
                    remove(new_sst->vlog_path);
                }
                tidesdb_sstable_unref(cf->db, new_sst);
                continue;
            }

            /* add the btree sstable to target level */
            tidesdb_level_add_sstable(cf->levels[target_level], new_sst);
            tidesdb_bump_sstable_layout_version(cf);
            tidesdb_manifest_add_sstable(cf->manifest, cf->levels[target_level]->level_num,
                                         new_sst->id, new_sst->num_entries,
                                         new_sst->klog_size + new_sst->vlog_size);
            tidesdb_sstable_unref(cf->db, new_sst);
            continue;
        }

        /* we process entries from partition-specific heap -- filter keys by partition range */
        while (!tidesdb_merge_heap_empty(partition_heap))
        {
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(partition_heap, NULL);
            if (!kv) break;

            /* we filter keys by partition range -- merge source reads all keys from sst
             * but we only want keys that fall within this partitions boundaries */
            if (range_start && comparator_fn(kv->key, kv->entry.key_size, range_start,
                                             range_start_size, comparator_ctx) < 0)
            {
                /* key is before partition range, skip */
                tidesdb_kv_pair_free(kv);
                continue;
            }
            if (range_end && comparator_fn(kv->key, kv->entry.key_size, range_end, range_end_size,
                                           comparator_ctx) >= 0)
            {
                /* key is at or after partition end, skip */
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* we skip duplicate keys (keep newest based on seq) */
            if (last_key && last_key_size == kv->entry.key_size &&
                memcmp(last_key, kv->key, last_key_size) == 0)
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* we update last key for duplicate detection */
            free(last_key);
            last_key = malloc(kv->entry.key_size);
            if (last_key)
            {
                memcpy(last_key, kv->key, kv->entry.key_size);
                last_key_size = kv->entry.key_size;
            }

            /* dividing merge never goes to largest level, so preserve tombstones */

            if (kv->entry.ttl > 0 &&
                kv->entry.ttl <
                    atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed))
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* we add to sst */
            if (!first_key)
            {
                first_key = malloc(kv->entry.key_size);
                if (first_key)
                {
                    memcpy(first_key, kv->key, kv->entry.key_size);
                    first_key_size = kv->entry.key_size;
                }
            }

            if (last_key) free(last_key);
            last_key = malloc(kv->entry.key_size);
            if (last_key)
            {
                memcpy(last_key, kv->key, kv->entry.key_size);
                last_key_size = kv->entry.key_size;
            }

            if (bloom)
            {
                bloom_filter_add(bloom, kv->key, kv->entry.key_size);
            }

            /* we check if this is the first entry in a new block */
            int is_first_entry_in_block = (klog_block->num_entries == 0);

            tidesdb_klog_block_add_entry(klog_block, kv, &cf->config, comparator_fn,
                                         comparator_ctx);

            /* we track first key of block */
            if (is_first_entry_in_block)
            {
                free(block_first_key);
                block_first_key = malloc(kv->entry.key_size);
                if (block_first_key)
                {
                    memcpy(block_first_key, kv->key, kv->entry.key_size);
                    block_first_key_size = kv->entry.key_size;
                }
            }

            /* we always update last key of block */
            free(block_last_key);
            block_last_key = malloc(kv->entry.key_size);
            if (block_last_key)
            {
                memcpy(block_last_key, kv->key, kv->entry.key_size);
                block_last_key_size = kv->entry.key_size;
            }

            if (tidesdb_klog_block_is_full(klog_block, TDB_KLOG_BLOCK_SIZE))
            {
                uint8_t *klog_data;
                size_t klog_size;
                if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                {
                    uint8_t *final_klog_data = klog_data;
                    size_t final_klog_size = klog_size;

                    if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
                    {
                        size_t compressed_size;
                        uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                            cf->config.compression_algorithm);
                        if (compressed)
                        {
                            free(klog_data);
                            final_klog_data = compressed;
                            final_klog_size = compressed_size;
                        }
                    }

                    block_manager_block_t *klog_bm_block =
                        block_manager_block_create(final_klog_size, final_klog_data);
                    if (klog_bm_block)
                    {
                        uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);
                        block_manager_block_write(klog_bm, klog_bm_block);
                        block_manager_block_release(klog_bm_block);

                        if (block_indexes && block_first_key && block_last_key)
                        {
                            if (klog_block_num % cf->config.index_sample_ratio == 0)
                            {
                                compact_block_index_add(block_indexes, block_first_key,
                                                        block_first_key_size, block_last_key,
                                                        block_last_key_size, block_file_position);
                            }
                        }

                        klog_block_num++;
                    }
                    free(final_klog_data);
                }

                tidesdb_klog_block_free(klog_block);
                klog_block = tidesdb_klog_block_create();

                /* we reset block tracking for new block */
                free(block_first_key);
                free(block_last_key);
                block_first_key = NULL;
                block_last_key = NULL;
            }

            /* we track maximum sequence number */
            if (kv->entry.seq > max_seq)
            {
                max_seq = kv->entry.seq;
            }

            entry_count++;

            tidesdb_kv_pair_free(kv);
        }

        tidesdb_merge_heap_free(partition_heap);

        /* we must write remaining klog block if it has data */
        if (klog_block->num_entries > 0)
        {
            uint8_t *klog_data;
            size_t klog_size;
            if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
            {
                uint8_t *final_klog_data = klog_data;
                size_t final_klog_size = klog_size;

                if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
                {
                    size_t compressed_size;
                    uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                        cf->config.compression_algorithm);
                    if (compressed)
                    {
                        free(klog_data);
                        final_klog_data = compressed;
                        final_klog_size = compressed_size;
                    }
                }

                block_manager_block_t *block =
                    block_manager_block_create(final_klog_size, final_klog_data);
                if (block)
                {
                    /* capture file position before writing the block */
                    uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);
                    block_manager_block_write(klog_bm, block);
                    block_manager_block_release(block);

                    /* we add final block to index after writing with correct file position */
                    if (block_indexes && block_first_key && block_last_key)
                    {
                        /* we sample every Nth block (ratio validated to be >= 1) */
                        if (klog_block_num % cf->config.index_sample_ratio == 0)
                        {
                            compact_block_index_add(block_indexes, block_first_key,
                                                    block_first_key_size, block_last_key,
                                                    block_last_key_size, block_file_position);
                        }
                    }

                    klog_block_num++;
                }
                free(final_klog_data);
            }
        }

        /* cleanup block tracking ***/
        free(block_first_key);
        free(block_last_key);

        tidesdb_klog_block_free(klog_block);

        new_sst->num_klog_blocks = klog_block_num;
        new_sst->num_vlog_blocks = vlog_block_num;

        new_sst->num_entries = entry_count;
        new_sst->max_seq = max_seq;
        new_sst->min_key = first_key;
        new_sst->min_key_size = first_key_size;
        new_sst->max_key = last_key;
        new_sst->max_key_size = last_key_size;

        /* we capture klog file offset where data blocks end (before writing index/bloom/metadata)
         */
        block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

        /* we write auxiliary structures (always write, even if empty, to maintain consistent file
         * structure) */
        if (entry_count > 0)
        {
            if (block_indexes)
            {
                new_sst->block_indexes = block_indexes;

                size_t index_size;
                uint8_t *index_data =
                    compact_block_index_serialize(new_sst->block_indexes, &index_size);
                if (index_data)
                {
                    block_manager_block_t *index_block =
                        block_manager_block_create(index_size, index_data);
                    if (index_block)
                    {
                        block_manager_block_write(klog_bm, index_block);
                        block_manager_block_release(index_block);
                    }
                    free(index_data);
                }
            }
            else
            {
                /* we write empty index block as placeholder (5 bytes -- count=0 + prefix_len) */
                uint8_t empty_index_data[5];
                encode_uint32_le_compat(empty_index_data, 0);             /* count = 0 */
                empty_index_data[4] = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN; /* prefix_len */
                block_manager_block_t *empty_index =
                    block_manager_block_create(5, empty_index_data);
                if (empty_index)
                {
                    block_manager_block_write(klog_bm, empty_index);
                    block_manager_block_release(empty_index);
                }
            }

            if (bloom)
            {
                new_sst->bloom_filter = bloom;

                size_t bloom_size;
                uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
                if (bloom_data)
                {
                    block_manager_block_t *bloom_block =
                        block_manager_block_create(bloom_size, bloom_data);
                    if (bloom_block)
                    {
                        block_manager_block_write(klog_bm, bloom_block);
                        block_manager_block_release(bloom_block);
                    }
                    free(bloom_data);
                }
            }
            else
            {
                /* we write empty bloom block as placeholder (1 byte -- size=0) */
                uint8_t empty_bloom_data[1] = {0};
                block_manager_block_t *empty_bloom =
                    block_manager_block_create(1, empty_bloom_data);
                if (empty_bloom)
                {
                    block_manager_block_write(klog_bm, empty_bloom);
                    block_manager_block_release(empty_bloom);
                }
            }
        }

        /* we get file sizes before metadata write for serialization */
        uint64_t klog_size_before_metadata;
        uint64_t vlog_size_before_metadata;
        block_manager_get_size(klog_bm, &klog_size_before_metadata);
        block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

        /* temporarily set sizes for metadata serialization */
        new_sst->klog_size = klog_size_before_metadata;
        new_sst->vlog_size = vlog_size_before_metadata;

        /* we write metadata block as the last block -- only if we have entries */
        uint8_t *metadata_data = NULL;
        size_t metadata_size = 0;
        if (entry_count > 0 &&
            sstable_metadata_serialize(new_sst, &metadata_data, &metadata_size) == 0)
        {
            block_manager_block_t *metadata_block =
                block_manager_block_create(metadata_size, metadata_data);
            if (metadata_block)
            {
                block_manager_block_write(klog_bm, metadata_block);
                block_manager_block_release(metadata_block);
            }
            free(metadata_data);
        }

        /* we get final file sizes after metadata write */
        block_manager_get_size(klog_bm, &new_sst->klog_size);
        block_manager_get_size(vlog_bm, &new_sst->vlog_size);

        /* we keep block managers open for immediate reads, reaper will close if needed once it's
         * evicted */
        new_sst->klog_bm = klog_bm;
        new_sst->vlog_bm = vlog_bm;
        atomic_store(&new_sst->last_access_time,
                     atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed));
        atomic_fetch_add(&cf->db->num_open_sstables, 1);

        /* we ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* we add to target level */
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Partition %d: Merged %" PRIu64 " entries", partition,
                      entry_count);

        if (entry_count > 0)
        {
            /* we reload num_levels as DCA may have changed it */
            int current_num_levels =
                atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

            /* we find the target level by level_num, not by stale array index */
            int target_level_num = target_level + 1;
            int target_idx = -1;
            for (int i = 0; i < current_num_levels; i++)
            {
                if (cf->levels[i]->level_num == target_level_num)
                {
                    target_idx = i;
                    break;
                }
            }

            if (target_idx < 0 || target_idx >= current_num_levels)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Partition %d: Target level %d not found "
                              "(current_num_levels=%d)",
                              partition, target_level_num, current_num_levels);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
            else
            {
                TDB_DEBUG_LOG(
                    TDB_LOG_INFO,
                    "Partition %d: Adding merged SSTable %" PRIu64 " to level %d (array index %d)",
                    partition, new_sst->id, cf->levels[target_idx]->level_num, target_idx);
                tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);
                tidesdb_bump_sstable_layout_version(cf);

                tidesdb_manifest_add_sstable(cf->manifest, cf->levels[target_idx]->level_num,
                                             new_sst->id, new_sst->num_entries,
                                             new_sst->klog_size + new_sst->vlog_size);
                atomic_store(&cf->manifest->sequence, atomic_load(&cf->next_sstable_id));
                int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
                if (manifest_result != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Partition %d: Failed to commit manifest for SSTable %" PRIu64
                                  " (error: %d)",
                                  partition, new_sst->id, manifest_result);
                }

                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "Partition %d: Skipping empty SSTable %" PRIu64 " (0 entries)", partition,
                          new_sst->id);

            if (bloom) bloom_filter_free(bloom);
            if (block_indexes) compact_block_index_free(block_indexes);

            remove(new_sst->klog_path);
            remove(new_sst->vlog_path);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
    }

    tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, 0, target_level);
    queue_free(sstables_to_delete);
    tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Completed dividing merge for CF '%s'", cf->name);
    return TDB_SUCCESS;
}

/**
 * partitioned merge
 * merge one partition at a time using file boundaries
 * @param cf column family
 * @param start_level start level
 * @param end_level end level
 * @return 0 on success, -1 on failure
 */
static int tidesdb_partitioned_merge(tidesdb_column_family_t *cf, int start_level, int end_level)
{
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* we convert 1-indexed level numbers to 0-indexed array indices */
    int start_idx = start_level - 1;
    int end_idx = end_level - 1;

    if (start_idx < 0 || end_idx >= num_levels)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "Starting partitioned merge: CF '%s', levels %d->%d (array indices %d->%d)",
                  cf->name, start_level, end_level, start_idx, end_idx);

    tidesdb_level_t *largest = cf->levels[num_levels - 1];

    /* get file boundaries from largest level */
    tidesdb_sstable_t **largest_sstables =
        atomic_load_explicit(&largest->sstables, memory_order_acquire);
    int num_partitions = atomic_load_explicit(&largest->num_sstables, memory_order_acquire);

    /* we check if largest level is empty before collecting sstables */
    if (num_partitions == 0)
    {
        /* largest level is empty, fall back to full preemptive merge.
         * we dont collect sstables since we're not doing partitioned merge.
         * tidesdb_full_preemptive_merge expects 0-indexed array indices, not 1-indexed level
         * numbers */

        return tidesdb_full_preemptive_merge(cf, start_idx, end_idx);
    }

    queue_t *sstables_to_delete = queue_new();
    if (!sstables_to_delete) return TDB_ERR_MEMORY;

    queue_t *sstable_ids_snapshot = tidesdb_snapshot_sst_ids(cf, start_idx, end_idx);
    if (!sstable_ids_snapshot)
    {
        queue_free(sstables_to_delete);
        return TDB_ERR_MEMORY;
    }

    tidesdb_sstable_t **ssts_array = NULL;
    int sst_count = 0;
    int collect_result = tidesdb_collect_ssts_from_snapshot(
        cf, start_idx, end_idx, sstable_ids_snapshot, &ssts_array, &sst_count);
    if (collect_result != TDB_SUCCESS)
    {
        queue_free(sstables_to_delete);
        tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);
        return collect_result;
    }

    for (int i = 0; i < sst_count; i++)
    {
        queue_enqueue(sstables_to_delete, ssts_array[i]);
    }
    free(ssts_array);

    uint8_t **boundaries = malloc(num_partitions * sizeof(uint8_t *));
    size_t *boundary_sizes = malloc(num_partitions * sizeof(size_t));

    for (int i = 0; i < num_partitions; i++)
    {
        /* we check for null as concurrent compactions may have removed sstables */
        if (!largest_sstables[i])
        {
            boundaries[i] = NULL;
            boundary_sizes[i] = 0;
            continue;
        }

        boundaries[i] = malloc(largest_sstables[i]->min_key_size);
        boundary_sizes[i] = largest_sstables[i]->min_key_size;
        if (largest_sstables[i]->min_key && boundary_sizes[i] > 0)
        {
            memcpy(boundaries[i], largest_sstables[i]->min_key, boundary_sizes[i]);
        }
    }

    /* we merge one partition at a time */
    for (int partition = 0; partition < num_partitions; partition++)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Processing partition %d/%d", partition + 1, num_partitions);

        skip_list_comparator_fn comparator_fn = NULL;
        void *comparator_ctx = NULL;
        tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

        tidesdb_merge_heap_t *heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
        if (!heap)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create merge heap for partition %d", partition);
            continue;
        }

        uint8_t *range_start = boundaries[partition];
        size_t range_start_size = boundary_sizes[partition];
        uint8_t *range_end = (partition + 1 < num_partitions) ? boundaries[partition + 1] : NULL;
        size_t range_end_size =
            (partition + 1 < num_partitions) ? boundary_sizes[partition + 1] : 0;

        /* we add overlapping ssts as sources and calculate estimated entries */
        uint64_t estimated_entries = 0;

        /* we reload levels for each partition */

        for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
        {
            tidesdb_level_t *lvl = cf->levels[level_idx];

            int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
            tidesdb_sstable_t **sstables =
                atomic_load_explicit(&lvl->sstables, memory_order_acquire);

            for (int i = 0; i < num_ssts; i++)
            {
                tidesdb_sstable_t *sst = sstables[i];
                /* we check for null as concurrent compactions may have removed sstables */
                if (!sst) continue;

                int overlaps = 1;

                if (comparator_fn(sst->max_key, sst->max_key_size, range_start, range_start_size,
                                  comparator_ctx) < 0)
                {
                    overlaps = 0;
                }

                if (range_end && comparator_fn(sst->min_key, sst->min_key_size, range_end,
                                               range_end_size, comparator_ctx) >= 0)
                {
                    overlaps = 0;
                }

                if (overlaps)
                {
                    /* tidesdb_merge_source_from_sstable takes its own reference */
                    tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
                    if (source)
                    {
                        if (tidesdb_merge_heap_add_source(heap, source) == TDB_SUCCESS)
                        {
                            estimated_entries += sst->num_entries;
                        }
                        else
                        {
                            /* failed to add source to heap, free it to prevent leak */
                            tidesdb_merge_source_free(source);
                        }
                    }
                    /* if merge source creation failed, no reference was taken, nothing to clean up
                     */
                }
                /* if sstable doesnt overlap, we dont need to do anything */
            }
        }

        if (estimated_entries < TDB_MERGE_MIN_ESTIMATED_ENTRIES)
            estimated_entries = TDB_MERGE_MIN_ESTIMATED_ENTRIES;

        /* we create output sst for this partition */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char path[MAX_FILE_PATH_LENGTH];
        snprintf(path, sizeof(path),
                 "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                 cf->directory, end_level + 1, partition);

        tidesdb_sstable_t *new_sst = tidesdb_sstable_create(cf->db, path, new_id, &cf->config);
        if (new_sst)
        {
            block_manager_t *klog_bm = NULL;
            block_manager_t *vlog_bm = NULL;

            block_manager_open(&klog_bm, new_sst->klog_path,
                               convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                     ? TDB_SYNC_FULL
                                                     : cf->config.sync_mode));
            block_manager_open(&vlog_bm, new_sst->vlog_path,
                               convert_sync_mode(cf->config.sync_mode == TDB_SYNC_INTERVAL
                                                     ? TDB_SYNC_FULL
                                                     : cf->config.sync_mode));

            bloom_filter_t *bloom = NULL;
            tidesdb_block_index_t *block_indexes = NULL;

            if (cf->config.enable_bloom_filter)
            {
                if (bloom_filter_new(&bloom, cf->config.bloom_fpr, (int)estimated_entries) == 0)
                {
                    TDB_DEBUG_LOG(
                        TDB_LOG_INFO,
                        "Partitioned merge partition %d: Bloom filter created (estimated entries: "
                        "%" PRIu64 ")",
                        partition, estimated_entries);
                }
                else
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Partitioned merge partition %d: Bloom filter creation failed",
                                  partition);
                    bloom = NULL;
                }
            }

            if (cf->config.enable_block_indexes && !cf->config.use_btree)
            {
                /* we reuse comparator_fn and comparator_ctx from outer scope */
                block_indexes =
                    compact_block_index_create(estimated_entries, cf->config.block_index_prefix_len,
                                               comparator_fn, comparator_ctx);
            }

            /* we branch to btree output if use_btree is enabled
             * partitioned merge goes to the level before largest, so not largest level */
            if (cf->config.use_btree)
            {
                int btree_result = tidesdb_sstable_write_from_heap_btree(cf, new_sst, heap, klog_bm,
                                                                         vlog_bm, bloom, NULL, 0);
                block_manager_close(klog_bm);
                block_manager_close(vlog_bm);
                tidesdb_merge_heap_free(heap);

                bloom = NULL;

                if (btree_result != TDB_SUCCESS || new_sst->num_entries == 0)
                {
                    if (new_sst->num_entries == 0)
                    {
                        remove(new_sst->klog_path);
                        remove(new_sst->vlog_path);
                    }
                    tidesdb_sstable_unref(cf->db, new_sst);
                    continue;
                }

                /* add the btree sstable to target level */
                tidesdb_level_add_sstable(cf->levels[end_idx], new_sst);
                tidesdb_bump_sstable_layout_version(cf);
                tidesdb_manifest_add_sstable(cf->manifest, cf->levels[end_idx]->level_num,
                                             new_sst->id, new_sst->num_entries,
                                             new_sst->klog_size + new_sst->vlog_size);
                tidesdb_sstable_unref(cf->db, new_sst);
                continue;
            }

            /* we merge and write entries in partition range */
            tidesdb_klog_block_t *klog_block = tidesdb_klog_block_create();
            uint64_t entry_count = 0;
            uint64_t klog_block_num = 0;
            uint64_t vlog_block_num = 0;
            uint64_t max_seq = 0;
            uint8_t *first_key = NULL;
            size_t first_key_size = 0;
            uint8_t *last_key = NULL;
            size_t last_key_size = 0;

            /* we track first and last key of current block for block index */
            uint8_t *block_first_key = NULL;
            size_t block_first_key_size = 0;
            uint8_t *block_last_key = NULL;
            size_t block_last_key_size = 0;

            /* we track last key for duplicate detection */
            uint8_t *last_seen_key = NULL;
            size_t last_seen_key_size = 0;

            while (!tidesdb_merge_heap_empty(heap))
            {
                tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap, NULL);
                if (!kv) break;

                skip_list_comparator_fn cmp_fn = NULL;
                void *cmp_ctx = NULL;
                tidesdb_resolve_comparator(cf->db, &cf->config, &cmp_fn, &cmp_ctx);

                /* we check if key is in partition range */
                if (cmp_fn(kv->key, kv->entry.key_size, range_start, range_start_size, cmp_ctx) < 0)
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

                if (range_end &&
                    cmp_fn(kv->key, kv->entry.key_size, range_end, range_end_size, cmp_ctx) >= 0)
                {
                    tidesdb_kv_pair_free(kv);
                    break;
                }

                /* we skip duplicate keys (keep newest based on seq) */
                if (last_seen_key && last_seen_key_size == kv->entry.key_size &&
                    memcmp(last_seen_key, kv->key, last_seen_key_size) == 0)
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

                /* we update last seen key for duplicate detection */
                free(last_seen_key);
                last_seen_key = malloc(kv->entry.key_size);
                if (last_seen_key)
                {
                    memcpy(last_seen_key, kv->key, kv->entry.key_size);
                    last_seen_key_size = kv->entry.key_size;
                }

                /* partitioned merge goes to level before largest, so preserve tombstones */

                if (kv->entry.ttl > 0 &&
                    kv->entry.ttl <
                        atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed))
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

                if (!first_key)
                {
                    first_key = malloc(kv->entry.key_size);
                    if (first_key)
                    {
                        memcpy(first_key, kv->key, kv->entry.key_size);
                        first_key_size = kv->entry.key_size;
                    }
                }

                if (last_key) free(last_key);
                last_key = malloc(kv->entry.key_size);
                if (last_key)
                {
                    memcpy(last_key, kv->key, kv->entry.key_size);
                    last_key_size = kv->entry.key_size;
                }

                if (kv->entry.value_size >= cf->config.klog_value_threshold && kv->value)
                {
                    uint8_t *final_data = kv->value;
                    size_t final_size = kv->entry.value_size;
                    uint8_t *compressed = NULL;

                    if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
                    {
                        size_t compressed_size;
                        compressed =
                            compress_data(kv->value, kv->entry.value_size, &compressed_size,
                                          cf->config.compression_algorithm);
                        if (compressed)
                        {
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *vblock =
                        block_manager_block_create(final_size, final_data);
                    if (vblock)
                    {
                        int64_t block_offset = block_manager_block_write(vlog_bm, vblock);
                        if (block_offset >= 0)
                        {
                            kv->entry.vlog_offset = (uint64_t)block_offset;
                            vlog_block_num++;
                        }
                        block_manager_block_release(vblock);
                    }
                    free(compressed);
                }

                if (bloom)
                {
                    bloom_filter_add(bloom, kv->key, kv->entry.key_size);
                }

                /* we check if this is first entry in a new block (before adding) */
                int is_first_entry_in_block = (klog_block->num_entries == 0);

                tidesdb_klog_block_add_entry(klog_block, kv, &cf->config, comparator_fn,
                                             comparator_ctx);

                /* we track first key of block */
                if (is_first_entry_in_block)
                {
                    free(block_first_key);
                    block_first_key = malloc(kv->entry.key_size);
                    if (block_first_key)
                    {
                        memcpy(block_first_key, kv->key, kv->entry.key_size);
                        block_first_key_size = kv->entry.key_size;
                    }
                }

                /* we always update last key of block */
                free(block_last_key);
                block_last_key = malloc(kv->entry.key_size);
                if (block_last_key)
                {
                    memcpy(block_last_key, kv->key, kv->entry.key_size);
                    block_last_key_size = kv->entry.key_size;
                }

                /** we track maximum sequence number */
                if (kv->entry.seq > max_seq)
                {
                    max_seq = kv->entry.seq;
                }

                entry_count++;

                if (tidesdb_klog_block_is_full(klog_block, TDB_KLOG_BLOCK_SIZE))
                {
                    uint8_t *klog_data;
                    size_t klog_size;
                    if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                    {
                        uint8_t *final_data = klog_data;
                        size_t final_size = klog_size;

                        if (cf->config.compression_algorithm != TDB_COMPRESS_NONE)
                        {
                            size_t compressed_size;
                            uint8_t *compressed =
                                compress_data(klog_data, klog_size, &compressed_size,
                                              cf->config.compression_algorithm);
                            if (compressed)
                            {
                                free(klog_data);
                                final_data = compressed;
                                final_size = compressed_size;
                            }
                        }

                        block_manager_block_t *block =
                            block_manager_block_create(final_size, final_data);
                        if (block)
                        {
                            /* we capture file position before writing the block */
                            uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);

                            block_manager_block_write(klog_bm, block);
                            block_manager_block_release(block);

                            /* we add completed block to index after writing with file position */
                            if (block_indexes && block_first_key && block_last_key)
                            {
                                /* we sample every Nth block (ratio validated to be >= 1) */
                                if (klog_block_num % cf->config.index_sample_ratio == 0)
                                {
                                    compact_block_index_add(
                                        block_indexes, block_first_key, block_first_key_size,
                                        block_last_key, block_last_key_size, block_file_position);
                                }
                            }

                            klog_block_num++;
                        }
                        free(final_data);
                    }
                    tidesdb_klog_block_free(klog_block);
                    klog_block = tidesdb_klog_block_create();

                    /* we reset block tracking for new block */
                    free(block_first_key);
                    free(block_last_key);
                    block_first_key = NULL;
                    block_last_key = NULL;
                }

                tidesdb_kv_pair_free(kv);
            }

            /* we clean up duplicate detection tracking */
            free(last_seen_key);

            /* we write remaining block */
            if (klog_block->num_entries > 0)
            {
                uint8_t *klog_data;
                size_t klog_size;
                if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                {
                    uint8_t *final_data = klog_data;
                    size_t final_size = klog_size;

                    if (new_sst->config->compression_algorithm != TDB_COMPRESS_NONE)
                    {
                        size_t compressed_size;
                        uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                            new_sst->config->compression_algorithm);
                        if (compressed)
                        {
                            free(klog_data);
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *block =
                        block_manager_block_create(final_size, final_data);
                    if (block)
                    {
                        /* we capture file position before writing the block */
                        uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);

                        block_manager_block_write(klog_bm, block);
                        block_manager_block_release(block);

                        /* we add final block to index after writing with file position */
                        if (block_indexes && block_first_key && block_last_key)
                        {
                            /* we sample every Nth block (ratio validated to be >= 1) */
                            if (klog_block_num % cf->config.index_sample_ratio == 0)
                            {
                                compact_block_index_add(block_indexes, block_first_key,
                                                        block_first_key_size, block_last_key,
                                                        block_last_key_size, block_file_position);
                            }
                        }

                        klog_block_num++;
                    }
                    free(final_data);
                }
            }

            tidesdb_klog_block_free(klog_block);

            /* we cleanup block tracking */
            free(block_first_key);
            free(block_last_key);

            new_sst->num_klog_blocks = klog_block_num;
            new_sst->num_vlog_blocks = vlog_block_num;

            new_sst->num_entries = entry_count;
            new_sst->max_seq = max_seq;
            new_sst->min_key = first_key;
            new_sst->min_key_size = first_key_size;
            new_sst->max_key = last_key;
            new_sst->max_key_size = last_key_size;

            /* we capture klog file offset where data blocks end (before writing
             * index/bloom/metadata)
             */
            block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

            /* we write auxiliary structures (always write, even if empty, to maintain consistent
             * file structure) */
            if (entry_count > 0)
            {
                /* we write index block */
                if (block_indexes)
                {
                    new_sst->block_indexes = block_indexes;

                    size_t index_size;
                    uint8_t *index_data =
                        compact_block_index_serialize(new_sst->block_indexes, &index_size);
                    if (index_data)
                    {
                        block_manager_block_t *index_block =
                            block_manager_block_create(index_size, index_data);
                        if (index_block)
                        {
                            block_manager_block_write(klog_bm, index_block);
                            block_manager_block_release(index_block);
                        }
                        free(index_data);
                    }
                }
                else
                {
                    /* we write empty index block as placeholder (5 bytes -- count=0 + prefix_len)
                     */
                    uint8_t empty_index_data[5];
                    encode_uint32_le_compat(empty_index_data, 0);             /* count = 0 */
                    empty_index_data[4] = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN; /* prefix_len */
                    block_manager_block_t *empty_index =
                        block_manager_block_create(5, empty_index_data);
                    if (empty_index)
                    {
                        block_manager_block_write(klog_bm, empty_index);
                        block_manager_block_release(empty_index);
                    }
                }

                if (bloom)
                {
                    new_sst->bloom_filter = bloom;

                    size_t bloom_size;
                    uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
                    if (bloom_data)
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_INFO,
                            "Partitioned merge partition %d bloom filter serialized to %zu bytes",
                            partition, bloom_size);
                        block_manager_block_t *bloom_block =
                            block_manager_block_create(bloom_size, bloom_data);
                        if (bloom_block)
                        {
                            block_manager_block_write(klog_bm, bloom_block);
                            block_manager_block_release(bloom_block);
                        }
                        free(bloom_data);
                    }
                    else
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_ERROR,
                            "Partitioned merge partition %d bloom filter serialization failed",
                            partition);
                    }
                }
                else
                {
                    /* we write empty bloom block as placeholder (1 byte -- size=0) */
                    uint8_t empty_bloom_data[1] = {0};
                    block_manager_block_t *empty_bloom =
                        block_manager_block_create(1, empty_bloom_data);
                    if (empty_bloom)
                    {
                        block_manager_block_write(klog_bm, empty_bloom);
                        block_manager_block_release(empty_bloom);
                    }
                }
            }

            /* we get file sizes before metadata write for serialization */
            uint64_t klog_size_before_metadata;
            uint64_t vlog_size_before_metadata;
            block_manager_get_size(klog_bm, &klog_size_before_metadata);
            block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

            /* temporarily set sizes for metadata serialization */
            new_sst->klog_size = klog_size_before_metadata;
            new_sst->vlog_size = vlog_size_before_metadata;

            /* we write metadata block as the last block -- only if we have entries */
            uint8_t *metadata_data = NULL;
            size_t metadata_size = 0;
            if (entry_count > 0 &&
                sstable_metadata_serialize(new_sst, &metadata_data, &metadata_size) == 0)
            {
                block_manager_block_t *metadata_block =
                    block_manager_block_create(metadata_size, metadata_data);
                if (metadata_block)
                {
                    block_manager_block_write(klog_bm, metadata_block);
                    block_manager_block_release(metadata_block);
                }
                free(metadata_data);
            }

            block_manager_get_size(klog_bm, &new_sst->klog_size);
            block_manager_get_size(vlog_bm, &new_sst->vlog_size);

            /* we close write handles before adding to level */
            if (klog_bm)
            {
                block_manager_close(klog_bm);
                new_sst->klog_bm = NULL;
            }
            if (vlog_bm)
            {
                block_manager_close(vlog_bm);
                new_sst->vlog_bm = NULL;
            }

            /* we ensure all writes are visible before making sstable discoverable */
            atomic_thread_fence(memory_order_seq_cst);

            /* we add to level if not empty */
            if (entry_count > 0)
            {
                /* we reload num_levels as DCA may have changed it */
                int current_num_levels =
                    atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

                /* we find the target level by level_num, not by stale array index
                 * partitioned merge writes to end_level (the largest level being merged) */
                int target_level_num = end_level;
                int target_idx = -1;
                for (int i = 0; i < current_num_levels; i++)
                {
                    if (cf->levels[i]->level_num == target_level_num)
                    {
                        target_idx = i;
                        break;
                    }
                }

                if (target_idx < 0 || target_idx >= current_num_levels)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Partitioned merge partition %d, target level %d not found "
                                  "(current_num_levels=%d), data would be lost!",
                                  partition, target_level_num, current_num_levels);
                    tidesdb_sstable_unref(cf->db, new_sst);
                    tidesdb_merge_heap_free(heap);
                    continue;
                }

                tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);
                tidesdb_bump_sstable_layout_version(cf);

                tidesdb_manifest_add_sstable(cf->manifest, cf->levels[target_idx]->level_num,
                                             new_sst->id, new_sst->num_entries,
                                             new_sst->klog_size + new_sst->vlog_size);
                atomic_store(&cf->manifest->sequence, atomic_load(&cf->next_sstable_id));
                int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
                if (manifest_result != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Partitioned merge partition %d: Failed to commit manifest for "
                                  "SSTable %" PRIu64 " (error: %d)",
                                  partition, new_sst->id, manifest_result);
                }

                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "Partitioned merge partition %d complete, created SSTable %" PRIu64
                              " with %" PRIu64 " entries, %" PRIu64 " klog blocks, %" PRIu64
                              " vlog blocks",
                              partition, new_sst->id, new_sst->num_entries,
                              new_sst->num_klog_blocks, new_sst->num_vlog_blocks);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
            else
            {
                TDB_DEBUG_LOG(
                    TDB_LOG_INFO,
                    "Partitioned merge partition %d no entries, skipping SSTable creation",
                    partition);
                if (bloom) bloom_filter_free(bloom);
                if (block_indexes) compact_block_index_free(block_indexes);
                remove(new_sst->klog_path);
                remove(new_sst->vlog_path);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }

        tidesdb_merge_heap_free(heap);
    }

    tidesdb_cleanup_merged_sstables(cf, sstables_to_delete, start_idx, end_idx);
    queue_free(sstables_to_delete);
    tidesdb_cleanup_snapshot_ids(sstable_ids_snapshot);

    for (int i = 0; i < num_partitions; i++)
    {
        free(boundaries[i]);
    }
    free(boundaries);
    free(boundary_sizes);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Partitioned merge complete for CF '%s', processed %d partitions",
                  cf->name, num_partitions);

    return TDB_SUCCESS;
}

/**
 * tidesdb_trigger_compaction
 * trigger compaction for a column family using the spooky algorithm
 *
 * spooky implementation notes
 * -- we implement the generalized spooky algorithm (section 4.2 of the paper)
 * -- parameter X (dividing level) is configurable via dividing_level_offset
 * -- we perform full preemptive merge at levels 1 to X-1 (array indices 0 to X-2)
 * -- we perform dividing merge into level X (partitioned by largest level boundaries)
 * -- we perform partitioned preemptive merge at levels X to L when level X is full
 * -- we use spooky algo 2 to find target levels (smallest level that cannot accommodate)
 *
 * key differences from paper:
 * -- we use 0-based array indexing (paper uses 1-based level numbering)
 * -- level 0 is memtable in paper, but we treat level 1 (array index 0) as first disk level
 *
 * @param cf the column family
 * @return TDB_SUCCESS on success, error code on failure
 */
int tidesdb_trigger_compaction(tidesdb_column_family_t *cf)
{
    /* we check if CF is marked for deletion before doing any work */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        return TDB_SUCCESS;
    }

    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&cf->is_compacting, &expected, 1,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        /* another compaction is already running, skip this one */
        return TDB_SUCCESS;
    }

    /* we check again after acquiring is_compacting in case drop happened between checks */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    /* we update cached_current_time to ensure TTL checks during compaction use fresh time
     * this prevents race conditions where stale cached time causes expired keys to not be filtered
     */
    atomic_store(&cf->db->cached_current_time, tdb_get_current_time());

    /* we force flush memtable before compaction to ensure all data is in ssts
     * this prevents data loss where keys in memtable are not included in compaction */
    tidesdb_flush_memtable_internal(cf, 0, 1);

    /* wait for flush to complete by checking the flush queue
     * this ensures the flushed sst is available before compaction starts */
    for (int i = 0; i < TDB_COMPACTION_FLUSH_WAIT_MAX_ATTEMPTS; i++)
    {
        if (queue_size(cf->db->flush_queue) == 0)
        {
            /* queue empty, give flush workers a moment to finish */
            usleep(TDB_COMPACTION_FLUSH_WAIT_SLEEP_US);
            break;
        }
        usleep(TDB_COMPACTION_FLUSH_WAIT_SLEEP_US);
    }

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Triggering compaction for column family: %s (levels: %d)",
                  cf->name, num_levels);

    /* we calculate X (dividing level) */
    int X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    int target_lvl = X; /* default to X if no suitable level found */

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Calculating target compaction level (X=%d)", X);

    /* spooky algo 2 -- find smallest level q where C_q < Σ(N_i) for i=0 to q
     * this means we're looking for the first level that cannot accommodate the merge */
    for (int q = 1; q <= X && q < num_levels; q++)
    {
        size_t cumulative_size = 0;

        for (int i = 0; i <= q && i < num_levels; i++)
        {
            cumulative_size +=
                atomic_load_explicit(&cf->levels[i]->current_size, memory_order_relaxed);
        }

        /* we check if C_q < cumulative_size (level cannot accommodate the merge) */
        size_t level_q_capacity =
            atomic_load_explicit(&cf->levels[q]->capacity, memory_order_relaxed);
        if (level_q_capacity < cumulative_size)
        {
            /* we found smallest level that cannot accommodate -- this is our target */
            target_lvl = q;
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Target level %d capacity=%zu < cumulative_size=%zu", q,
                          level_q_capacity, cumulative_size);
            break;
        }
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Final target compaction level: %d", target_lvl);

    int result = TDB_SUCCESS;
    if (target_lvl < X)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Full preemptive merge levels 1 to %d", target_lvl);
        result = tidesdb_full_preemptive_merge(cf, 0, target_lvl - 1); /* convert to 0-indexed */
    }
    else if (target_lvl == X)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Dividing merge at level %d", X);
        result = tidesdb_dividing_merge(cf, X - 1); /* convert to 0-indexed */
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Target_lvl > X, defaulting to dividing merge");
        result = tidesdb_dividing_merge(cf, X - 1); /* convert to 0-indexed */
    }

    /* we reload num_levels atomically after compaction */
    num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* we recalculate X with potentially new num_levels */
    X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    int z = -1;
    int need_partitioned_merge = 0;

    if (X > 0 && X < num_levels)
    {
        tidesdb_level_t *level_x = cf->levels[X - 1];

        size_t level_x_size = atomic_load_explicit(&level_x->current_size, memory_order_relaxed);
        size_t level_x_capacity = atomic_load_explicit(&level_x->capacity, memory_order_relaxed);

        if (level_x_size >= level_x_capacity)
        {
            need_partitioned_merge = 1;

            /* spooky algo 2 -- find smallest level z where C_z < Σ(N_i) for i=X to z
             * this means we're looking for the first level that cannot accommodate the merge */
            for (int candidate_z = X + 1; candidate_z <= num_levels; candidate_z++)
            {
                size_t cumulative = 0;
                for (int i = X; i <= candidate_z && (i - 1) < num_levels; i++)
                {
                    cumulative += atomic_load_explicit(&cf->levels[i - 1]->current_size,
                                                       memory_order_relaxed);
                }

                size_t candidate_capacity = atomic_load_explicit(
                    &cf->levels[candidate_z - 1]->capacity, memory_order_relaxed);
                if (candidate_capacity < cumulative)
                {
                    z = candidate_z;
                    TDB_DEBUG_LOG(TDB_LOG_INFO,
                                  "Partitioned merge target z=%d capacity=%zu < cumulative=%zu",
                                  candidate_z, candidate_capacity, cumulative);
                    break;
                }
            }

            if (z == -1 || z <= X)
            {
                z = num_levels;
            }
        }
    }

    /* we get largest level info for later checks */
    if (num_levels == 0)
    {
        atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
    size_t largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);

    /* we perform partitioned merge if needed */
    if (need_partitioned_merge)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Level %d is full, triggering partitioned preemptive merge", X);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Partitioned preemptive merge levels %d to %d", X, z);
        result = tidesdb_partitioned_merge(cf, X, z);

        /* we reload num_levels after merge */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        if (num_levels > 0)
        {
            largest = cf->levels[num_levels - 1];
            largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
            largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        }
    }

    int just_added_level = 0;
    if (largest_size >= largest_capacity)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "Largest size is %zu, Largest capacity %zu, Number of levels %d",
                      largest_size, largest_capacity, num_levels);
        tidesdb_add_level(cf);
        just_added_level = 1; /* track that we just added a level */
        /* we re-fetch num_levels after add_level */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        if (num_levels > 0)
        {
            largest = cf->levels[num_levels - 1];
            largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
            largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        }
    }

    /* we check if largest level is truly empty by checking num_sstables, not current_size
     * current_size uses relaxed memory ordering and can be stale
     * we re-fetch levels and largest pointer as they may have changed due to compactions
     *
     * we dont remove a level we just added in this same compaction cycle!
     * the new level is intentionally empty and will be filled by future compactions. */

    num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    int largest_num_sstables =
        (num_levels > 1)
            ? atomic_load_explicit(&cf->levels[num_levels - 1]->num_sstables, memory_order_acquire)
            : -1;

    if (!just_added_level && num_levels > 1 && largest_num_sstables == 0)
    {
        size_t pending_flushes = queue_size(cf->immutable_memtables);

        int level1_sstables =
            (cf->levels[0] != NULL)
                ? atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire)
                : 0;

        if (pending_flushes == 0 && level1_sstables == 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Largest level is empty, removing level for CF '%s'",
                          cf->name);
            tidesdb_remove_level(cf);
            num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        }
        else
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "Largest level is empty but work pending (flushes: %zu, L1 sstables: %d), keeping "
                "level for CF '%s'",
                pending_flushes, level1_sstables, cf->name);
        }
    }

    tidesdb_apply_dca(cf);

    atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
    return result;
}

/**
 * tidesdb_wal_recover
 * recover the WAL
 * @param cf the column family
 * @param wal_path the path to the WAL
 * @param memtable the memtable
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
static int tidesdb_wal_recover(tidesdb_column_family_t *cf, const char *wal_path,
                               skip_list_t **memtable)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' starting WAL recovery from: %s", cf->name, wal_path);
    block_manager_t *wal;
    if (block_manager_open(&wal, wal_path, TDB_SYNC_FULL) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "CF '%s' failed to open WAL: %s", cf->name, wal_path);
        return TDB_ERR_IO;
    }

    /** we hint to OS that we'll read the entire WAL sequentially and only once
     * this optimizes read-ahead and allows kernel to deprioritize these pages */
    set_file_sequential_hint(wal->fd);
    set_file_noreuse_hint(wal->fd, 0, 0);

    /* prefetch WAL file into page cache for faster recovery */
    uint64_t wal_size = atomic_load(&wal->current_file_size);
    if (wal_size > 0)
    {
        prefetch_file_region(wal->fd, 0, (off_t)wal_size);
    }

    if (block_manager_validate_last_block(wal, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' WAL validation failed: %s", cf->name, wal_path);
        block_manager_close(wal);
        return TDB_ERR_IO;
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' WAL validation passed: %s", cf->name, wal_path);

    /* we resolve comparator for recovered memtable */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    if (tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx) != 0)
    {
        /* comparator not found, use default memcmp */
        comparator_fn = skip_list_comparator_memcmp;
        comparator_ctx = NULL;
    }

    if (skip_list_new_with_comparator_and_cached_time(
            memtable, cf->config.skip_list_max_level, cf->config.skip_list_probability,
            comparator_fn, comparator_ctx, &cf->db->cached_current_time) != 0)
    {
        block_manager_close(wal);
        return TDB_ERR_MEMORY;
    }

    /* we read all entries from WAL */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, wal) != 0)
    {
        skip_list_free(*memtable);
        block_manager_close(wal);
        return TDB_ERR_IO;
    }

    int block_count = 0;
    int entry_count = 0;
    if (block_manager_cursor_goto_first(cursor) == 0)
    {
        do
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (!block) break;
            block_count++;

            const uint8_t *ptr = block->data;
            size_t remaining = block->size;

            while (remaining > 0)
            {
                if (remaining < 1)
                {
                    TDB_DEBUG_LOG(
                        TDB_LOG_WARN,
                        "CF '%s' WAL block has insufficient data for entry (remaining: %zu)",
                        cf->name, remaining);
                    break;
                }

                tidesdb_klog_entry_t entry;
                entry.flags = *ptr++;
                remaining--;
                entry_count++;

                uint64_t key_size_u64;
                int bytes_read = decode_varint(ptr, &key_size_u64, (int)remaining);
                if (bytes_read < 0 || key_size_u64 > UINT32_MAX)
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' WAL entry %d: invalid key_size", cf->name,
                                  entry_count);
                    break;
                }
                ptr += bytes_read;
                remaining -= bytes_read;
                entry.key_size = (uint32_t)key_size_u64;

                uint64_t value_size_u64;
                bytes_read = decode_varint(ptr, &value_size_u64, (int)remaining);
                if (bytes_read < 0 || value_size_u64 > UINT32_MAX)
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' WAL entry %d: invalid value_size",
                                  cf->name, entry_count);
                    break;
                }
                ptr += bytes_read;
                remaining -= bytes_read;
                entry.value_size = (uint32_t)value_size_u64;

                uint64_t seq_value;
                bytes_read = decode_varint(ptr, &seq_value, (int)remaining);
                if (bytes_read < 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' WAL entry %d: invalid seq", cf->name,
                                  entry_count);
                    break;
                }
                ptr += bytes_read;
                remaining -= bytes_read;
                entry.seq = seq_value;

                if (entry.flags & TDB_KV_FLAG_HAS_TTL)
                {
                    if (remaining < sizeof(int64_t))
                    {
                        TDB_DEBUG_LOG(TDB_LOG_WARN,
                                      "CF '%s' WAL entry %d: insufficient data for TTL", cf->name,
                                      entry_count);
                        break;
                    }
                    entry.ttl = decode_int64_le_compat(ptr);
                    ptr += sizeof(int64_t);
                    remaining -= sizeof(int64_t);
                }
                else
                {
                    entry.ttl = 0;
                }

                entry.vlog_offset = 0;

                if (remaining < entry.key_size)
                {
                    TDB_DEBUG_LOG(
                        TDB_LOG_WARN,
                        "CF '%s' WAL entry %d: insufficient data for key (need %u, have %zu)",
                        cf->name, entry_count, entry.key_size, remaining);
                    break;
                }

                uint8_t *key = (uint8_t *)ptr;
                ptr += entry.key_size;
                remaining -= entry.key_size;

                uint8_t *value = NULL;
                if (entry.value_size > 0)
                {
                    if (remaining < entry.value_size)
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_WARN,
                            "CF '%s' WAL entry %d: insufficient data for value (need %u, have %zu)",
                            cf->name, entry_count, entry.value_size, remaining);
                        break;
                    }
                    value = (uint8_t *)ptr;
                    ptr += entry.value_size;
                    remaining -= entry.value_size;
                }

                if (entry.flags & TDB_KV_FLAG_TOMBSTONE)
                {
                    skip_list_put_with_seq(*memtable, key, entry.key_size, NULL, 0, 0, entry.seq,
                                           1);
                }
                else
                {
                    skip_list_put_with_seq(*memtable, key, entry.key_size, value, entry.value_size,
                                           entry.ttl, entry.seq, 0);
                }
            }

            block_manager_block_release(block);

        } while (block_manager_cursor_next(cursor) == 0);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' WAL recovery completed: %d blocks, %d entries, memtable has %d entries",
                  cf->name, block_count, entry_count, skip_list_count_entries(*memtable));

    block_manager_cursor_free(cursor);

    /* we evict WAL data from page cache after recovery, data is now in memtable
     * this frees cache space for more useful data during normal operation */
    evict_file_region(wal->fd, 0, 0);

    block_manager_close(wal);

    return TDB_SUCCESS;
}

/**
 * tidesdb_column_family_free
 * free column family
 * @param cf the column family
 */
static void tidesdb_column_family_free(tidesdb_column_family_t *cf)
{
    if (!cf) return;

    tidesdb_memtable_t *mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    if (mt)
    {
        if (mt->skip_list) skip_list_free(mt->skip_list);
        if (mt->wal) block_manager_close(mt->wal);
        free(mt);
    }

    int immutable_count = 0;
    while (!queue_is_empty(cf->immutable_memtables))
    {
        tidesdb_immutable_memtable_t *immutable =
            (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
        if (immutable)
        {
            int refcount = atomic_load_explicit(&immutable->refcount, memory_order_acquire);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is cleaning immutable with refcount=%d", cf->name,
                          refcount);
            tidesdb_immutable_memtable_unref(immutable);
            immutable_count++;
        }
    }
    if (immutable_count > 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' freed %d immutable memtables in CF cleanup", cf->name,
                      immutable_count);
    }
    queue_free(cf->immutable_memtables);

    for (int i = 0; i < TDB_MAX_LEVELS; i++)
    {
        if (cf->levels[i])
        {
            tidesdb_level_free(cf->db, cf->levels[i]);
        }
    }

    if (cf->active_txn_buffer)
    {
        buffer_free(cf->active_txn_buffer);
        cf->active_txn_buffer = NULL;
    }

    if (cf->manifest)
    {
        tidesdb_manifest_close(cf->manifest);
    }

    free(cf->name);
    free(cf->directory);
    free(cf);
}

/**
 * tidesdb_flush_worker_thread
 * worker thread that processes flush work items from the queue
 */
static void *tidesdb_flush_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Flush worker thread started");

    while (1)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Flush worker is waiting for work (queue size: %zu)",
                      queue_size(db->flush_queue));
        /* we wait for work (blocking dequeue) */
        tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue_wait(db->flush_queue);

        if (!work)
        {
            /* NULL sentinel signals shutdown */
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Flush worker has received NULL work, exiting");
            break;
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "Flush worker has received work for SSTable %" PRIu64,
                      work->sst_id);

        tidesdb_column_family_t *cf = work->cf;
        tidesdb_immutable_memtable_t *imm = work->imm;

        /* we check if CF is marked for deletion -- if so, skip processing and cleanup */
        if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' is marked for deletion, skipping flush for SSTable %" PRIu64,
                          cf->name, work->sst_id);
            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        skip_list_t *memtable = imm->skip_list;
        block_manager_t *wal = imm->wal;

        /* we wait for all in-flight writers to finish before reading from memtable
         * writers hold refcount while writing to WAL and skip_list
         * we must wait for them to complete to ensure we capture all entries
         * refcount accounting -- 1 (original) + 1 (work ref) = 2 when no external refs
         * this wait happens in the background flush thread, not the hot path */
        int drain_iterations = 0;
        while (atomic_load_explicit(&imm->refcount, memory_order_acquire) >
               TDB_REFCOUNT_DRAIN_BASELINE)
        {
            drain_iterations++;
            if (drain_iterations < TDB_REFCOUNT_DRAIN_SPIN_THRESHOLD)
            {
                cpu_pause();
            }
            else if (drain_iterations < TDB_REFCOUNT_DRAIN_YIELD_THRESHOLD)
            {
                cpu_yield();
            }
            else
            {
                usleep(TDB_REFCOUNT_DRAIN_SLEEP_US);
            }
            if ((drain_iterations & TDB_REFCOUNT_DRAIN_LOG_INTERVAL) == 0)
            {
                TDB_DEBUG_LOG(
                    TDB_LOG_WARN,
                    "CF '%s' flush worker waiting for memtable refcount to drain (current=%d)",
                    cf->name, atomic_load_explicit(&imm->refcount, memory_order_acquire));
            }
        }
        atomic_thread_fence(memory_order_acquire);

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "CF '%s' encountered insufficient disk space for flush (required: %" PRIu64
                " bytes)",
                cf->name, cf->config.min_disk_space);

            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

            /* we release work and skip flush -- the memtable stays in memory */
            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        char sst_path[MAX_FILE_PATH_LENGTH];
        snprintf(sst_path, sizeof(sst_path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "1",
                 cf->directory);

        /* once we create the sstable, we must complete the flush to avoid leaking it */
        tidesdb_sstable_t *sst = tidesdb_sstable_create(db, sst_path, work->sst_id, &cf->config);
        if (!sst)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "CF '%s' SSTable %" PRIu64 " creation failed", cf->name,
                          work->sst_id);

            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        /* branch based on use_btree config */
        int write_result;
        if (cf->config.use_btree)
        {
            write_result = tidesdb_sstable_write_from_memtable_btree(db, sst, memtable);
        }
        else
        {
            write_result = tidesdb_sstable_write_from_memtable(db, sst, memtable);
        }
        if (write_result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' SSTable %" PRIu64 " write failed (error: %d), will retry",
                          cf->name, work->sst_id, write_result);

            tidesdb_sstable_unref(cf->db, sst);

            usleep(TDB_FLUSH_RETRY_DELAY_US);

            /* we re-enqueue for retry (work still has valid imm reference) */
            if (queue_enqueue(cf->db->flush_queue, work) != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "CF '%s' failed to re-enqueue flush work for retry. "
                              "WAL will be recovered on next open.",
                              cf->name);

                tidesdb_immutable_memtable_unref(imm);
                atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
                free(work);
            }
            /* work re-enqueued, dont free it */
            continue;
        }

        /* we must always sync sstable files regardless of sync_mode
         * sstable durability is required before we can delete WAL */
        tidesdb_block_managers_t bms;
        if (tidesdb_sstable_get_block_managers(db, sst, &bms) == TDB_SUCCESS)
        {
            if (bms.klog_bm) block_manager_escalate_fsync(bms.klog_bm);
            if (bms.vlog_bm) block_manager_escalate_fsync(bms.vlog_bm);
        }

        /* we ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* we close write handles before adding to level
         * readers will reopen files on-demand through tidesdb_sstable_ensure_open
         * this prevents file locking issues where readers cannot open files
         * that are still held open by the flush worker */
        if (sst->klog_bm)
        {
            block_manager_close(sst->klog_bm);
            sst->klog_bm = NULL;
        }
        if (sst->vlog_bm)
        {
            block_manager_close(sst->vlog_bm);
            sst->vlog_bm = NULL;
        }

        /* we validate flush ordering -- new sst should have higher sequence than existing ones
         * this maintains LSM invariant that newer data has higher sequence numbers */
        int num_existing = atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);
        if (num_existing > 0)
        {
            tidesdb_sstable_t **existing_ssts =
                atomic_load_explicit(&cf->levels[0]->sstables, memory_order_acquire);
            for (int i = 0; i < num_existing; i++)
            {
                if (existing_ssts[i] && existing_ssts[i]->max_seq >= sst->max_seq)
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN,
                                  "CF '%s' flush ordering violation - SSTable %" PRIu64
                                  " (max_seq=%" PRIu64
                                  ") "
                                  "added after SSTable %" PRIu64 " (max_seq=%" PRIu64 ")",
                                  cf->name, work->sst_id, sst->max_seq, existing_ssts[i]->id,
                                  existing_ssts[i]->max_seq);
                }
            }
        }

        /* we add sstable to level 1 (array index 0) -- load levels atomically */

        /* levels array is fixed, access directly */
        tidesdb_level_add_sstable(cf->levels[0], sst);
        tidesdb_bump_sstable_layout_version(cf);

        atomic_thread_fence(memory_order_release);

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' flushed SSTable %" PRIu64 " (max_seq=%" PRIu64
                      ") to level %d (array index 0)",
                      cf->name, work->sst_id, sst->max_seq, cf->levels[0]->level_num);

        /* we commit sstable to manifest before deleting WAL and before triggering compaction
         * this ensures crash recovery knows which sstables are complete
         * we must commit manifest before triggering compaction to avoid deadlock
         * where flush worker holds manifest lock while compaction worker waits for it */
        tidesdb_manifest_add_sstable(cf->manifest, 1, work->sst_id, sst->num_entries,
                                     sst->klog_size + sst->vlog_size);
        atomic_store(&cf->manifest->sequence, atomic_load(&cf->next_sstable_id));
        int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
        if (manifest_result != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "CF '%s' failed to commit manifest for SSTable %" PRIu64 " (error: %d)",
                          cf->name, work->sst_id, manifest_result);
        }

        /* we check file count in addition to size
         * cf->levels[0] (level_num=1) is TidesDB's first disk level, equivalent to
         * RocksDB's rLevel 0 in the spooky paper. this is where memtable flushes land.
         * files at this level have overlapping key ranges, so reads must check all files.
         * trigger compaction at α=4 files to prevent read amplification. */
        int num_l1_sstables =
            atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);
        size_t level1_size =
            atomic_load_explicit(&cf->levels[0]->current_size, memory_order_acquire);
        size_t level1_capacity =
            atomic_load_explicit(&cf->levels[0]->capacity, memory_order_acquire);

        int should_compact = 0;
        const char *trigger_reason = NULL;

        /* file count trigger at level 1 */
        if (num_l1_sstables >= cf->config.l1_file_count_trigger)
        {
            should_compact = 1;
            trigger_reason = "file count";
        }

        else if (level1_size >= level1_capacity)
        {
            should_compact = 1;
            trigger_reason = "size";
        }

        if (should_compact)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' level %d (first disk level) triggering compaction (%s): "
                          "files=%d (trigger=%d), size=%zu (capacity=%zu)",
                          cf->name, cf->levels[0]->level_num, trigger_reason, num_l1_sstables,
                          cf->config.l1_file_count_trigger, level1_size, level1_capacity);
            tidesdb_compact(cf);
        }

        /* we release our reference -- the level now owns it */
        tidesdb_sstable_unref(cf->db, sst);

        /* safe to delete WAL -- sstable is committed to manifest */
        if (wal)
        {
            char *wal_path_to_delete = tdb_strdup(wal->file_path);
            block_manager_close(wal);
            imm->wal = NULL;
            tdb_unlink(wal_path_to_delete);
            free(wal_path_to_delete);
        }

        atomic_thread_fence(memory_order_seq_cst);

        atomic_store_explicit(&imm->flushed, 1, memory_order_release);

        tidesdb_immutable_memtable_unref(imm);

        /* batched cleanup only run every N flushes or when queue is large
         * this reduces overhead while preventing unbounded memory growth */
        const int cleanup_threshold = TDB_IMMUTABLE_CLEANUP_THRESHOLD;
        size_t max_queue_size = TDB_IMMUTABLE_MAX_QUEUE_SIZE;
        size_t force_cleanup_size = TDB_IMMUTABLE_FORCE_CLEANUP_SIZE;
        int counter =
            atomic_fetch_add_explicit(&cf->immutable_cleanup_counter, 1, memory_order_relaxed);
        size_t current_queue_size = queue_size(cf->immutable_memtables);

        int should_cleanup =
            (counter % cleanup_threshold == 0) || (current_queue_size > max_queue_size);
        int force_cleanup = (current_queue_size >= force_cleanup_size);

        if (force_cleanup)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_WARN,
                "CF '%s' immutable queue critical size %zu >= %zu, forcing blocking cleanup",
                cf->name, current_queue_size, force_cleanup_size);
        }

        /* we cleanup flushed immutables from queue if they have no active readers
         * we need to keep them in queue until all reads complete to maintain MVCC correctness
         * when force_cleanup is set, we block waiting for readers to finish */
        queue_t *temp_queue = (should_cleanup || force_cleanup) ? queue_new() : NULL;
        if (temp_queue)
        {
            int cleaned = 0;
            int force_cleaned = 0;
            while (!queue_is_empty(cf->immutable_memtables))
            {
                tidesdb_immutable_memtable_t *queued_imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
                if (queued_imm)
                {
                    int is_flushed =
                        atomic_load_explicit(&queued_imm->flushed, memory_order_acquire);

                    /* we use atomic CAS to try claiming the last reference
                     * if refcount is 1, try to CAS it to 0 to claim ownership for cleanup
                     * if CAS succeeds, we own it and can free; if it fails, someone else ref'd it
                     */
                    int expected_refcount = 1;
                    int can_cleanup = 0;

                    if (is_flushed)
                    {
                        /* we try to claim the last reference atomically */
                        if (atomic_compare_exchange_strong_explicit(
                                &queued_imm->refcount, &expected_refcount, 0, memory_order_acquire,
                                memory_order_relaxed))
                        {
                            can_cleanup = 1;
                        }
                        else if (force_cleanup)
                        {
                            /* force cleanup, spin waiting for readers to finish */
                            int64_t waited_us = 0;
                            while (waited_us < TDB_IMMUTABLE_FORCE_CLEANUP_MAX_WAIT)
                            {
                                expected_refcount = 1;
                                if (atomic_compare_exchange_strong_explicit(
                                        &queued_imm->refcount, &expected_refcount, 0,
                                        memory_order_acquire, memory_order_relaxed))
                                {
                                    can_cleanup = 1;
                                    force_cleaned++;
                                    break;
                                }
                                usleep(TDB_IMMUTABLE_FORCE_CLEANUP_SPIN_US);
                                waited_us += TDB_IMMUTABLE_FORCE_CLEANUP_SPIN_US;
                            }
                            if (!can_cleanup)
                            {
                                TDB_DEBUG_LOG(TDB_LOG_WARN,
                                              "CF '%s' force cleanup timed out waiting for "
                                              "immutable refcount "
                                              "(refcount=%d)",
                                              cf->name,
                                              atomic_load_explicit(&queued_imm->refcount,
                                                                   memory_order_acquire));
                            }
                        }
                    }

                    if (can_cleanup)
                    {
                        /* we successfully claimed it -- safe to free
                         * manually free since we set refcount to 0 */
                        if (queued_imm->skip_list) skip_list_free(queued_imm->skip_list);
                        if (queued_imm->wal) block_manager_close(queued_imm->wal);
                        free(queued_imm);
                        cleaned++;
                    }
                    else
                    {
                        /* keep in queue -- either not flushed or has active readers
                         * restore refcount if we decremented it */
                        if (is_flushed && expected_refcount == 0)
                        {
                            /* CAS failed after we saw refcount=1, someone else took a ref
                             * refcount is already correct, just re-enqueue */
                        }
                        queue_enqueue(temp_queue, queued_imm);
                    }
                }
            }

            /* we restore kept immutables back to original queue */
            while (!queue_is_empty(temp_queue))
            {
                tidesdb_immutable_memtable_t *queued_imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(temp_queue);
                if (queued_imm)
                {
                    queue_enqueue(cf->immutable_memtables, queued_imm);
                }
            }
            queue_free(temp_queue);

            if (cleaned > 0)
            {
                TDB_DEBUG_LOG(
                    TDB_LOG_INFO,
                    "CF '%s' cleaned up %d flushed immutable(s) (%d forced) with no active "
                    "readers",
                    cf->name, cleaned, force_cleaned);
            }
        }

        /* we clear is_flushing flag now that flush is complete
         * this allows new flushes to be triggered */
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        free(work);
    }

    return NULL;
}

/**
 * tidesdb_compaction_worker_thread
 * worker thread that processes compaction work items from the queue
 *
 * this allows parallel compaction across multiple column families.
 * the is_compacting flag ensures only one compaction per CF at a time,
 * but multiple workers can compact different CFs concurrently.
 */
static void *tidesdb_compaction_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction worker thread started");

    while (1)
    {
        /* wait for work (blocking dequeue) */
        tidesdb_compaction_work_t *work =
            (tidesdb_compaction_work_t *)queue_dequeue_wait(db->compaction_queue);

        if (!work)
        {
            /* NULL work item signals shutdown */
            break;
        }

        tidesdb_column_family_t *cf = work->cf;

        if (cf == NULL)
        {
            free(work);
            continue;
        }

        /* we check if CF is marked for deletion -- if so, skip processing */
        if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is marked for deletion, skipping compaction",
                          cf->name);
            atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
            free(work);
            continue;
        }

        const int space_check =
            tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_WARN,
                "CF '%s' encountered insufficient disk space for compaction (required: %" PRIu64
                " bytes)",
                cf->name, cf->config.min_disk_space);
            /* we clear is_compacting flag so compaction can be retried later */
            atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
            free(work);
            continue;
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "Compacting CF '%s'", cf->name);
        const int result = tidesdb_trigger_compaction(cf);
        if (result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' compaction failed with error %d", cf->name,
                          result);
            /* is_compacting is cleared inside tidesdb_trigger_compaction on both success and
             * failure */
        }

        free(work);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction worker thread stopped");

    return NULL;
}

/**
 * tidesdb_sync_worker_thread
 * background thread that periodically syncs WAL files for CFs with TDB_SYNC_INTERVAL mode
 */
static void *tidesdb_sync_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread started");

    while (atomic_load(&db->sync_thread_active))
    {
        uint64_t min_interval = UINT64_MAX;

        /* we scan all CFs to find minimum sync interval */
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            const tidesdb_column_family_t *cf = db->column_families[i];
            if (cf && cf->config.sync_mode == TDB_SYNC_INTERVAL && cf->config.sync_interval_us > 0)
            {
                if (cf->config.sync_interval_us < min_interval)
                {
                    min_interval = cf->config.sync_interval_us;
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        uint64_t sleep_us;
        if (min_interval == UINT64_MAX)
        {
            /* no CFs need interval syncing, sleep longer */
            sleep_us = TDB_NO_CF_SYNC_SLEEP_US;
        }
        else
        {
            sleep_us = min_interval;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(sleep_us / TDB_MICROSECONDS_PER_SECOND);
        ts.tv_nsec +=
            (long)(sleep_us % TDB_MICROSECONDS_PER_SECOND) * TDB_NANOSECONDS_PER_MICROSECOND;
        if (ts.tv_nsec >= TDB_NANOSECONDS_PER_SECOND)
        {
            ts.tv_sec++;
            ts.tv_nsec -= TDB_NANOSECONDS_PER_SECOND;
        }

        pthread_mutex_lock(&db->sync_thread_mutex);

        while (atomic_load(&db->sync_thread_active))
        {
            const int wait_result =
                pthread_cond_timedwait(&db->sync_thread_cond, &db->sync_thread_mutex, &ts);

            if (wait_result == ETIMEDOUT || !atomic_load(&db->sync_thread_active))
            {
                break;
            }
        }
        const int should_exit = !atomic_load(&db->sync_thread_active);
        pthread_mutex_unlock(&db->sync_thread_mutex);

        if (should_exit)
        {
            break;
        }

        if (min_interval == UINT64_MAX)
        {
            /* no CFs needed syncing, skip sync */
            continue;
        }

        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            if (cf && cf->config.sync_mode == TDB_SYNC_INTERVAL && cf->config.sync_interval_us > 0)
            {
                tidesdb_memtable_t *mt = atomic_load(&cf->active_memtable);
                if (mt && mt->wal)
                {
                    block_manager_escalate_fsync(mt->wal);
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        /* we check shutdown flag after sync operations to exit promptly */
        if (!atomic_load(&db->sync_thread_active))
        {
            break;
        }
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread stopped");
    return NULL;
}

/**
 * compare_sstable_candidates
 * comparison function for sorting sstable candidates by last_access_time
 * @param a pointer to first sstable candidate
 * @param b pointer to second sstable candidate
 * @return negative if a < b, positive if a > b, zero if equal
 */
static int compare_sstable_candidates(const void *a, const void *b)
{
    const time_t time_a = ((const struct {
                              void *sst;
                              time_t last_access;
                          } *)a)
                              ->last_access;
    const time_t time_b = ((const struct {
                              void *sst;
                              time_t last_access;
                          } *)b)
                              ->last_access;
    if (time_a < time_b) return -1;
    if (time_a > time_b) return 1;
    return 0;
}

/**
 * tidesdb_sstable_reaper_thread
 * background thread that closes unused sstable files when limits are reached
 * evicts TDB_SSTABLE_REAPER_EVICT_RATIO of oldest ssts (by last_access_time) when num_open_sstables
 * >= max
 */
static void *tidesdb_sstable_reaper_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;
    TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper thread started");

    while (atomic_load(&db->sstable_reaper_active))
    {
        time_t now = tdb_get_current_time();
        atomic_store_explicit(&db->cached_current_time, now, memory_order_seq_cst);

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (TDB_SSTABLE_REAPER_SLEEP_US / TDB_MICROSECONDS_PER_SECOND);
        ts.tv_nsec += (TDB_SSTABLE_REAPER_SLEEP_US % TDB_MICROSECONDS_PER_SECOND) *
                      TDB_NANOSECONDS_PER_MICROSECOND;
        if (ts.tv_nsec >= TDB_NANOSECONDS_PER_SECOND)
        {
            ts.tv_sec++;
            ts.tv_nsec -= TDB_NANOSECONDS_PER_SECOND;
        }

        pthread_mutex_lock(&db->reaper_thread_mutex);

        if (atomic_load(&db->sstable_reaper_active))
        {
            pthread_cond_timedwait(&db->reaper_thread_cond, &db->reaper_thread_mutex, &ts);
        }
        int should_exit = !atomic_load(&db->sstable_reaper_active);
        pthread_mutex_unlock(&db->reaper_thread_mutex);

        if (should_exit)
        {
            break;
        }

        int current_open = atomic_load(&db->num_open_sstables);
        int max_open = (int)db->config.max_open_sstables;

        if (current_open < max_open)
        {
            continue; /* under limit, nothing to do */
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper triggered: %d/%d open SSTables", current_open,
                      max_open);

        /**
         * sstable_candidate_t
         * @param sst sstable to close
         * @param last_access last access time
         * collect all ssts with refcount=0 and last_access_time */
        typedef struct
        {
            tidesdb_sstable_t *sst;
            time_t last_access;
        } sstable_candidate_t;

        sstable_candidate_t *candidates = malloc(current_open * sizeof(sstable_candidate_t));
        if (!candidates)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable reaper: failed to allocate candidates array");
            continue;
        }

        int candidate_count = 0;

        if (!atomic_load(&db->sstable_reaper_active))
        {
            free(candidates);
            break;
        }

        /* we scan all column families for closeable ssts
         * we check shutdown flag frequently to allow prompt exit on BSD systems
         * where the scan loop may take longer due to scheduler behavior */
        int shutdown_requested = 0;
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families && !shutdown_requested; i++)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            if (!cf) continue;

            /* we check shutdown inside loop to exit promptly */
            if (!atomic_load(&db->sstable_reaper_active))
            {
                shutdown_requested = 1;
                break;
            }

            int num_levels = atomic_load(&cf->num_active_levels);
            for (int level = 0; level < num_levels && level < TDB_MAX_LEVELS; level++)
            {
                tidesdb_level_t *lvl = cf->levels[level];
                if (!lvl) continue;

                /* we load array pointer and count with careful ordering to handle concurrent
                 * modifications re-load count to detect concurrent remove, use minimum to avoid OOB
                 */
                tidesdb_sstable_t **ssts =
                    atomic_load_explicit(&lvl->sstables, memory_order_acquire);
                int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);

                /* we re-load count to detect concurrent remove */
                int num_ssts_recheck =
                    atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
                if (num_ssts_recheck < num_ssts) num_ssts = num_ssts_recheck;

                /* we verify array hasnt changed (handles add-with-resize race) */
                tidesdb_sstable_t **ssts_check =
                    atomic_load_explicit(&lvl->sstables, memory_order_acquire);
                if (ssts_check != ssts)
                {
                    ssts = ssts_check;
                    num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
                }

                for (int j = 0; j < num_ssts; j++)
                {
                    tidesdb_sstable_t *sst = ssts[j];
                    if (!sst) continue;

                    /* we only consider ssts that are open and not in use
                     * we use try_ref to safely acquire reference -- if it fails, sstable is being
                     * freed after acquiring ref, check if refcount is now 2 (level ref + our ref)
                     */
                    if (sst->klog_bm && sst->vlog_bm)
                    {
                        if (!tidesdb_sstable_try_ref(sst))
                        {
                            continue; /* sstable is being freed, skip it */
                        }

                        /* now we check if we're the only extra ref (refcount should be 2) */
                        if (atomic_load(&sst->refcount) == 2)
                        {
                            candidates[candidate_count].sst = sst;
                            candidates[candidate_count].last_access =
                                atomic_load(&sst->last_access_time);
                            candidate_count++;
                        }
                        else
                        {
                            /* someone else is using it, release our ref */
                            tidesdb_sstable_unref(db, sst);
                        }
                    }
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        /* if shutdown was requested during scan, release any acquired refs and exit */
        if (shutdown_requested)
        {
            for (int i = 0; i < candidate_count; i++)
            {
                tidesdb_sstable_unref(db, candidates[i].sst);
            }
            free(candidates);
            break;
        }

        if (!atomic_load(&db->sstable_reaper_active))
        {
            free(candidates);
            break;
        }

        if (candidate_count == 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN, "SSTable reaper: no closeable SSTables found");
            free(candidates);
            continue;
        }

        qsort(candidates, candidate_count, sizeof(sstable_candidate_t), compare_sstable_candidates);

        int to_close = (int)(candidate_count * TDB_SSTABLE_REAPER_EVICT_RATIO);
        if (to_close == 0 && candidate_count > 0) to_close = 1; /* close at least 1 */

        int closed_count = 0;
        for (int i = 0; i < to_close && i < candidate_count; i++)
        {
            tidesdb_sstable_t *sst = candidates[i].sst;

            /* we double-check refcount before closing (should be 2b -- our ref + base ref) */
            if (atomic_load(&sst->refcount) == 2 && sst->klog_bm && sst->vlog_bm)
            {
                block_manager_close(sst->klog_bm);
                block_manager_close(sst->vlog_bm);
                sst->klog_bm = NULL;
                sst->vlog_bm = NULL;
                atomic_fetch_sub(&db->num_open_sstables, 1);
                closed_count++;
            }
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper: closed %d/%d SSTables, %d now open",
                      closed_count, to_close, atomic_load(&db->num_open_sstables));

        /* we release all candidate refcounts */
        for (int i = 0; i < candidate_count; i++)
        {
            tidesdb_sstable_unref(db, candidates[i].sst);
        }

        free(candidates);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper thread stopped");
    return NULL;
}

int tidesdb_register_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn fn,
                                const char *ctx_str, void *ctx)
{
    if (!db || !name || !fn) return TDB_ERR_INVALID_ARGS;
    if (strlen(name) >= TDB_MAX_COMPARATOR_NAME) return TDB_ERR_INVALID_ARGS;

    while (1)
    {
        tidesdb_comparator_entry_t *old_array =
            atomic_load_explicit(&db->comparators, memory_order_acquire);
        int old_count = atomic_load_explicit(&db->num_comparators, memory_order_acquire);
        int old_capacity = atomic_load_explicit(&db->comparators_capacity, memory_order_acquire);

        /* we check for duplicate name */
        for (int i = 0; i < old_count; i++)
        {
            if (strcmp(old_array[i].name, name) == 0)
            {
                return TDB_ERR_INVALID_ARGS; /* duplicate name */
            }
        }

        int new_capacity = old_capacity;
        if (old_count >= old_capacity)
        {
            new_capacity = old_capacity * 2;
        }

        tidesdb_comparator_entry_t *new_array =
            malloc(new_capacity * sizeof(tidesdb_comparator_entry_t));
        if (!new_array) return TDB_ERR_MEMORY;

        if (old_count > 0)
        {
            memcpy(new_array, old_array, old_count * sizeof(tidesdb_comparator_entry_t));
        }

        tidesdb_comparator_entry_t *entry = &new_array[old_count];
        strncpy(entry->name, name, TDB_MAX_COMPARATOR_NAME - 1);
        entry->name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
        entry->fn = fn;
        entry->ctx = ctx;

        if (ctx_str && strlen(ctx_str) > 0)
        {
            strncpy(entry->ctx_str, ctx_str, TDB_MAX_COMPARATOR_CTX - 1);
            entry->ctx_str[TDB_MAX_COMPARATOR_CTX - 1] = '\0';
        }
        else
        {
            entry->ctx_str[0] = '\0';
        }

        if (atomic_compare_exchange_strong_explicit(&db->comparators, &old_array, new_array,
                                                    memory_order_release, memory_order_acquire))
        {
            /* success! update count and capacity */
            atomic_store_explicit(&db->num_comparators, old_count + 1, memory_order_release);
            atomic_store_explicit(&db->comparators_capacity, new_capacity, memory_order_release);

            free(old_array);
            return TDB_SUCCESS;
        }

        /* CAS failed, another thread modified array, retry */
        free(new_array);
    }
}

int tidesdb_get_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn *fn, void **ctx)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    tidesdb_comparator_entry_t *array =
        atomic_load_explicit(&db->comparators, memory_order_acquire);
    int count = atomic_load_explicit(&db->num_comparators, memory_order_acquire);

    for (int i = 0; i < count; i++)
    {
        if (strcmp(array[i].name, name) == 0)
        {
            if (fn) *fn = array[i].fn;
            if (ctx) *ctx = array[i].ctx;
            return TDB_SUCCESS;
        }
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db)
{
    /* auto-initialize with system allocator if not already initialized */
    tidesdb_ensure_initialized();

    if (!config || !db) return TDB_ERR_INVALID_ARGS;

    *db = calloc(1, sizeof(tidesdb_t));
    if (!*db)
    {
        return TDB_ERR_MEMORY;
    }

    (*db)->db_path = tdb_strdup(config->db_path);
    if (!(*db)->db_path)
    {
        free(*db);
        return TDB_ERR_MEMORY;
    }

    memcpy(&(*db)->config, config, sizeof(tidesdb_config_t));

    _tidesdb_log_level = config->log_level;

    /* we initialize log file to NULL (stderr) by default */
    (*db)->log_file = NULL;
    _tidesdb_log_file = NULL;
    _tidesdb_log_truncate = 0;
    _tidesdb_log_path[0] = '\0';

    if (mkdir((*db)->db_path, TDB_DIR_PERMISSIONS) != 0 && errno != EEXIST)
    {
        fprintf(stderr, "Failed to create database directory %s: %s\n", (*db)->db_path,
                strerror(errno));
        free((*db)->db_path);
        free(*db);
        *db = NULL;
        return TDB_ERR_IO;
    }

    /* if log_to_file is enabled, open the log file in the database directory */
    if (config->log_to_file)
    {
        char log_path[TDB_MAX_PATH_LEN];
        snprintf(log_path, sizeof(log_path), "%s" PATH_SEPARATOR TDB_LOG_FILE, (*db)->db_path);

        (*db)->log_file = fopen(log_path, "a");
        if ((*db)->log_file)
        {
            _tidesdb_log_file = (*db)->log_file;
            /* we must set line buffering for better real-time logging */
            tdb_setlinebuf((*db)->log_file);

            /* we set up log truncation if configured */
            _tidesdb_log_truncate = config->log_truncation_at;
            if (_tidesdb_log_truncate > 0)
            {
                snprintf(_tidesdb_log_path, sizeof(_tidesdb_log_path), "%s", log_path);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to open log file %s, falling back to default.",
                          log_path);
        }
    }

    const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"};
    const char *level_str =
        (_tidesdb_log_level >= TDB_LOG_DEBUG && _tidesdb_log_level <= TDB_LOG_FATAL)
            ? level_names[_tidesdb_log_level]
            : (_tidesdb_log_level == TDB_LOG_NONE ? "NONE" : "UNKNOWN");

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Opening TidesDB with path=%s, log_level=%s, workers=%d%s",
                  config->db_path, level_str, config->num_compaction_threads,
                  config->log_to_file ? ", logging to file" : "");

    char lock_path[TDB_MAX_PATH_LEN];
    snprintf(lock_path, sizeof(lock_path), "%s" PATH_SEPARATOR TDB_LOCK_FILE, (*db)->db_path);

    int lock_result;
    (*db)->lock_fd = tdb_open_lock_file(lock_path, &lock_result);
    if ((*db)->lock_fd < 0)
    {
        if (lock_result == TDB_LOCK_HELD)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Database is locked by another process. Only one process can open a "
                          "database directory at a time.");
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to open lock file: %s", lock_path);
        }
        free((*db)->db_path);
        free(*db);
        *db = NULL;
        return (lock_result == TDB_LOCK_HELD) ? TDB_ERR_LOCKED : TDB_ERR_IO;
    }

    lock_result = tdb_file_lock_exclusive((*db)->lock_fd, TDB_LOCK_DEFAULT_RETRIES);
    if (lock_result != TDB_LOCK_SUCCESS)
    {
        if (lock_result == TDB_LOCK_HELD)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Database is locked by another process. Only one process can open a "
                          "database directory at a time.");
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "Failed to acquire database lock due to an irrecoverable error.");
        }
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        *db = NULL;
        return (lock_result == TDB_LOCK_HELD) ? TDB_ERR_LOCKED : TDB_ERR_IO;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Acquired exclusive lock on database directory");

    (*db)->cf_capacity = TDB_INITIAL_CF_CAPACITY;
    tidesdb_column_family_t **cfs = calloc((*db)->cf_capacity, sizeof(tidesdb_column_family_t *));
    if (!cfs)
    {
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    (*db)->column_families = cfs;
    (*db)->num_column_families = 0;

    atomic_init(&(*db)->is_open, 0);
    atomic_init(&(*db)->is_recovering, 1);

    if (pthread_rwlock_init(&(*db)->cf_list_lock, NULL) != 0)
    {
        free(cfs);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    tidesdb_comparator_entry_t *initial_comparators =
        calloc(TDB_INITIAL_COMPARATOR_CAPACITY, sizeof(tidesdb_comparator_entry_t));
    if (!initial_comparators)
    {
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    atomic_init(&(*db)->comparators, initial_comparators);
    atomic_init(&(*db)->num_comparators, 0);
    atomic_init(&(*db)->comparators_capacity, TDB_INITIAL_COMPARATOR_CAPACITY);

    tidesdb_register_comparator(*db, "memcmp", tidesdb_comparator_memcmp, NULL, NULL);
    tidesdb_register_comparator(*db, "lexicographic", tidesdb_comparator_lexicographic, NULL, NULL);
    tidesdb_register_comparator(*db, "uint64", tidesdb_comparator_uint64, NULL, NULL);
    tidesdb_register_comparator(*db, "int64", tidesdb_comparator_int64, NULL, NULL);
    tidesdb_register_comparator(*db, "reverse", tidesdb_comparator_reverse_memcmp, NULL, NULL);
    tidesdb_register_comparator(*db, "case_insensitive", tidesdb_comparator_case_insensitive, NULL,
                                NULL);

    (*db)->flush_queue = queue_new();
    (*db)->compaction_queue = queue_new();

    if (!(*db)->flush_queue || !(*db)->compaction_queue)
    {
        if ((*db)->flush_queue) queue_free((*db)->flush_queue);
        if ((*db)->compaction_queue) queue_free((*db)->compaction_queue);
        free(initial_comparators);
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    atomic_init(&(*db)->next_txn_id, 1);
    atomic_init(&(*db)->global_seq, 1);
    atomic_init(&(*db)->num_open_sstables, 0);

    (*db)->commit_status = tidesdb_commit_status_create();
    if (!(*db)->commit_status)
    {
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    if (pthread_rwlock_init(&(*db)->active_txns_lock, NULL) != 0)
    {
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    /* we start with larger capacity to avoid realloc under lock */
    (*db)->active_txns_capacity = TDB_ACTIVE_TXN_INITIAL_CAPACITY;
    (*db)->active_txns = calloc((*db)->active_txns_capacity, sizeof(tidesdb_txn_t *));
    if (!(*db)->active_txns)
    {
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    (*db)->num_active_txns = 0;

    uint64_t initial_space = 0;
    if (tdb_get_available_disk_space((*db)->db_path, &initial_space) == 0)
    {
        atomic_init(&(*db)->cached_available_disk_space, initial_space);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Initial available disk space is %" PRIu64 " bytes",
                      initial_space);
    }
    else
    {
        /* failed to get disk space, set to 0 to trigger checks */
        atomic_init(&(*db)->cached_available_disk_space, 0);
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to get initial disk space");
    }
    atomic_init(&(*db)->last_disk_space_check, time(NULL));

    (*db)->total_memory = get_total_memory();
    (*db)->available_memory = get_available_memory();
    if ((*db)->total_memory > 0 && (*db)->available_memory > 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "System memory is total=%" PRIu64 " bytes, available=%" PRIu64 " bytes",
                      (uint64_t)(*db)->total_memory, (uint64_t)(*db)->available_memory);
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to get system memory information");
        free((*db)->active_txns);
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    if (config->block_cache_size > 0)
    {
        cache_config_t cache_config;
        clock_cache_compute_config(config->block_cache_size, &cache_config);
        cache_config.evict_callback = tidesdb_cache_evict_block; /* ref-counted block cleanup */

        (*db)->clock_cache = clock_cache_create(&cache_config);
        if (!(*db)->clock_cache)
        {
            free((*db)->active_txns);
            pthread_rwlock_destroy(&(*db)->active_txns_lock);
            tidesdb_commit_status_destroy((*db)->commit_status);
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free(atomic_load(&(*db)->comparators));
            pthread_rwlock_destroy(&(*db)->cf_list_lock);
            free((*db)->column_families);
            tdb_file_unlock((*db)->lock_fd);
            close((*db)->lock_fd);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Block clock cache created with max_bytes=%.2f MB",
                      (double)config->block_cache_size / (1024 * 1024));
    }
    else
    {
        (*db)->clock_cache = NULL;
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Block clock cache disabled (block_cache_size=0)");
    }

    /* we create btree node cache (uses same size as block cache for now) */
    if (config->block_cache_size > 0)
    {
        (*db)->btree_node_cache = btree_create_node_cache(config->block_cache_size);
        if ((*db)->btree_node_cache)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "B+tree node cache created with max_bytes=%.2f MB",
                          (double)config->block_cache_size / (1024 * 1024));
        }
    }
    else
    {
        (*db)->btree_node_cache = NULL;
    }

    /* we initialize cached_current_time before recovery so skip lists created during
     * recovery have a valid time pointer for TTL checks
     * use seq_cst for strongest memory ordering on all platforms */
    atomic_store_explicit(&(*db)->cached_current_time, tdb_get_current_time(),
                          memory_order_seq_cst);

    int rc = tidesdb_recover_database(*db);
    if (rc != TDB_SUCCESS)
    {
        free((*db)->active_txns);
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        if ((*db)->clock_cache) clock_cache_destroy((*db)->clock_cache);
        free(*db);
        return rc;
    }

    (*db)->flush_threads = malloc(config->num_flush_threads * sizeof(pthread_t));
    if (!(*db)->flush_threads)
    {
        clock_cache_destroy((*db)->clock_cache);
        free((*db)->active_txns);
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    for (int i = 0; i < config->num_flush_threads; i++)
    {
        if (pthread_create(&(*db)->flush_threads[i], NULL, tidesdb_flush_worker_thread, *db) != 0)
        {
            for (int j = 0; j < i; j++)
            {
                pthread_join((*db)->flush_threads[j], NULL);
            }
            free((*db)->flush_threads);
            clock_cache_destroy((*db)->clock_cache);
            free((*db)->active_txns);
            pthread_rwlock_destroy(&(*db)->active_txns_lock);
            tidesdb_commit_status_destroy((*db)->commit_status);
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free(atomic_load(&(*db)->comparators));
            pthread_rwlock_destroy(&(*db)->cf_list_lock);
            free((*db)->column_families);
            tdb_file_unlock((*db)->lock_fd);
            close((*db)->lock_fd);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
    }

    (*db)->compaction_threads = malloc(config->num_compaction_threads * sizeof(pthread_t));
    if (!(*db)->compaction_threads)
    {
        for (int i = 0; i < config->num_flush_threads; i++)
        {
            pthread_join((*db)->flush_threads[i], NULL);
        }
        free((*db)->flush_threads);
        clock_cache_destroy((*db)->clock_cache);
        free((*db)->active_txns);
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free(atomic_load(&(*db)->comparators));
        pthread_rwlock_destroy(&(*db)->cf_list_lock);
        free((*db)->column_families);
        tdb_file_unlock((*db)->lock_fd);
        close((*db)->lock_fd);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    for (int i = 0; i < config->num_compaction_threads; i++)
    {
        if (pthread_create(&(*db)->compaction_threads[i], NULL, tidesdb_compaction_worker_thread,
                           *db) != 0)
        {
            for (int j = 0; j < i; j++)
            {
                pthread_join((*db)->compaction_threads[j], NULL);
            }
            free((*db)->compaction_threads);

            for (int k = 0; k < config->num_flush_threads; k++)
            {
                pthread_join((*db)->flush_threads[k], NULL);
            }
            free((*db)->flush_threads);
            clock_cache_destroy((*db)->clock_cache);
            free((*db)->active_txns);
            pthread_rwlock_destroy(&(*db)->active_txns_lock);
            tidesdb_commit_status_destroy((*db)->commit_status);
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free(atomic_load(&(*db)->comparators));
            pthread_rwlock_destroy(&(*db)->cf_list_lock);
            free((*db)->column_families);
            tdb_file_unlock((*db)->lock_fd);
            close((*db)->lock_fd);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
    }

    /* we check if any CF needs interval syncing and start sync thread if needed */
    int needs_sync_thread = 0;
    pthread_rwlock_rdlock(&(*db)->cf_list_lock);
    for (int i = 0; i < (*db)->num_column_families; i++)
    {
        if ((*db)->column_families[i] &&
            (*db)->column_families[i]->config.sync_mode == TDB_SYNC_INTERVAL &&
            (*db)->column_families[i]->config.sync_interval_us > 0)
        {
            needs_sync_thread = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&(*db)->cf_list_lock);

    pthread_mutex_init(&(*db)->sync_thread_mutex, NULL);
    pthread_cond_init(&(*db)->sync_thread_cond, NULL);

    if (needs_sync_thread && !atomic_load(&(*db)->sync_thread_active))
    {
        /* we only start if not already started during recovery by tidesdb_create_column_family */
        atomic_store(&(*db)->sync_thread_active, 1);
        if (pthread_create(&(*db)->sync_thread, NULL, tidesdb_sync_worker_thread, *db) != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create sync worker thread");
            atomic_store(&(*db)->sync_thread_active, 0);
            pthread_mutex_destroy(&(*db)->sync_thread_mutex);
            pthread_cond_destroy(&(*db)->sync_thread_cond);
            /* non-fatal, continue without sync thread */
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread created");
        }
    }
    else if (!needs_sync_thread && !atomic_load(&(*db)->sync_thread_active))
    {
        atomic_store(&(*db)->sync_thread_active, 0);
    }

    pthread_mutex_init(&(*db)->reaper_thread_mutex, NULL);
    pthread_cond_init(&(*db)->reaper_thread_cond, NULL);

    atomic_store(&(*db)->sstable_reaper_active, 1);
    if (pthread_create(&(*db)->sstable_reaper_thread, NULL, tidesdb_sstable_reaper_thread, *db) !=
        0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create SSTable reaper thread");
        atomic_store(&(*db)->sstable_reaper_active, 0);
        pthread_mutex_destroy(&(*db)->reaper_thread_mutex);
        pthread_cond_destroy(&(*db)->reaper_thread_cond);
        /* non-fatal, continue without reaper thread */
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper thread created");
    }

    atomic_store(&(*db)->is_open, 1);
    atomic_store(&(*db)->is_recovering, 0);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Database is now open and ready for operations");

    return TDB_SUCCESS;
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Closing TidesDB at path: %s", db->db_path);
    atomic_store(&db->is_open, 0);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Flushing all active memtables before close");
    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i])
        {
            tidesdb_column_family_t *cf = db->column_families[i];

            /* we wait for any in-progress flush to complete */
            int wait_count = 0;
            while (atomic_load_explicit(&cf->is_flushing, memory_order_acquire) != 0 &&
                   wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
            {
                usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
                wait_count++;
                if (wait_count % 10 == 0)
                {
                    TDB_DEBUG_LOG(
                        TDB_LOG_INFO,
                        "CF '%s' is waiting for in-progress flush to complete (waited %dms)",
                        cf->name, wait_count * 10);
                }
            }

            tidesdb_memtable_t *mt =
                atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
            int entry_count = (mt && mt->skip_list) ? skip_list_count_entries(mt->skip_list) : 0;

            if (entry_count > 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is flushing %d entries before close", cf->name,
                              entry_count);

                /* we retry flush with backoff to prevent data loss */
                int flush_result = TDB_ERR_UNKNOWN;
                int retry_count = 0;

                while (retry_count < TDB_MAX_FFLUSH_RETRY_ATTEMPTS)
                {
                    flush_result = tidesdb_flush_memtable_internal(cf, 0, 1); /* force flush */
                    if (flush_result == TDB_SUCCESS)
                    {
                        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' flush before close succeeded",
                                      cf->name);
                        break;
                    }

                    retry_count++;
                    if (retry_count < TDB_MAX_FFLUSH_RETRY_ATTEMPTS)
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_ERROR,
                            "CF '%s' flush before close failed (attempt %d/%d, error %d), "
                            "retrying",
                            cf->name, retry_count, TDB_MAX_FFLUSH_RETRY_ATTEMPTS, flush_result);
                        usleep(TDB_FLUSH_RETRY_BACKOFF_US *
                               retry_count); /* linear backoff -- TDB_FLUSH_RETRY_BACKOFF_US * N */
                    }
                }

                if (flush_result != TDB_SUCCESS)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "CF '%s' flush before close failed after %d attempts (error "
                                  "%d). "
                                  "Data is persisted in WAL and will be recovered on next open.",
                                  cf->name, TDB_MAX_FFLUSH_RETRY_ATTEMPTS, flush_result);
                }
            }
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "All memtables flushed");

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for background flushes to complete");
    int flush_wait_count = 0;
    pthread_rwlock_rdlock(&db->cf_list_lock);
    while (1)
    {
        int any_flushing = 0;
        size_t queue_size_val = 0;

        for (int i = 0; i < db->num_column_families; i++)
        {
            if (db->column_families[i])
            {
                if (atomic_load_explicit(&db->column_families[i]->is_flushing,
                                         memory_order_acquire))
                {
                    any_flushing = 1;
                    break;
                }
            }
        }

        /* we also check if flush queue has pending work */
        if (db->flush_queue)
        {
            queue_size_val = queue_size(db->flush_queue);
        }

        if (!any_flushing && queue_size_val == 0)
        {
            break;
        }

        if (flush_wait_count % 1000 == 0 && flush_wait_count > 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "Still waiting for background flushes (waited %d seconds, queue_size=%zu)",
                flush_wait_count / 1000, queue_size_val);
        }

        pthread_rwlock_unlock(&db->cf_list_lock);
        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        flush_wait_count++;
        pthread_rwlock_rdlock(&db->cf_list_lock);
    }
    pthread_rwlock_unlock(&db->cf_list_lock);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "All background flushes completed (queue is empty)");

    /* we wait for any in-progress compactions to complete before shutdown
     * this prevents data loss from compaction removing old ssts while
     * the new merged sst is not yet fully persisted */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for in-progress compactions to complete");
    int compaction_wait_count = 0;
    while (1)
    {
        int any_compacting = 0;
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            if (db->column_families[i])
            {
                if (atomic_load_explicit(&db->column_families[i]->is_compacting,
                                         memory_order_acquire))
                {
                    any_compacting = 1;
                    break;
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        if (!any_compacting)
        {
            break;
        }

        if (compaction_wait_count % 100 == 0 && compaction_wait_count > 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Still waiting for in-progress compactions (waited %d ms)",
                          compaction_wait_count);
        }

        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        compaction_wait_count++;
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "All in-progress compactions completed");

    if (db->flush_queue)
    {
        /* we set shutdown flag first, before enqueueing NULLs
         * this ensures queue_dequeue_wait will return NULL even if
         * a thread enters the wait after we broadcast */
        queue_shutdown(db->flush_queue);

        /* we enqueue NULL items for each thread as a courtesy
         * (not strictly needed since shutdown=1, but maintains consistency) */
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
            queue_enqueue(db->flush_queue, NULL);
        }

        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            queue_shutdown(db->flush_queue);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }
    }

    if (db->compaction_queue)
    {
        /* we set shutdown flag first, before enqueueing NULLs
         * this ensures queue_dequeue_wait will return NULL even if
         * a thread enters the wait after we broadcast */
        queue_shutdown(db->compaction_queue);
        for (int i = 0; i < db->config.num_compaction_threads; i++)
        {
            queue_enqueue(db->compaction_queue, NULL);
        }

        /* we keep broadcasting periodically until all threads have exited
         * this handles the race where a thread might be between the while loop check
         * and pthread_cond_wait when we set shutdown=1 */
        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            queue_shutdown(db->compaction_queue);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for %d flush threads to finish",
                  db->config.num_flush_threads);
    if (db->flush_threads)
    {
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
            if (db->flush_queue)
            {
                for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
                {
                    queue_shutdown(db->flush_queue);
                    usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
                }
            }

            pthread_join(db->flush_threads[i], NULL);
        }
        free(db->flush_threads);
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Flush threads finished");

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for %d compaction threads to finish",
                  db->config.num_compaction_threads);
    if (db->compaction_threads)
    {
        for (int i = 0; i < db->config.num_compaction_threads; i++)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Joining compaction thread %d", i);

            /** on netbsd, pthread_cond_wait can miss signals, so we keep broadcasting
             * while waiting for each thread to exit */
            if (db->compaction_queue)
            {
                for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
                {
                    queue_shutdown(db->compaction_queue);
                    usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
                }
            }

            pthread_join(db->compaction_threads[i], NULL);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction thread %d joined", i);
        }
        free(db->compaction_threads);
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction threads finished");

    if (atomic_load(&db->sync_thread_active))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Stopping sync worker thread");

        pthread_mutex_lock(&db->sync_thread_mutex);
        atomic_store(&db->sync_thread_active, 0);
        pthread_cond_signal(&db->sync_thread_cond);
        pthread_mutex_unlock(&db->sync_thread_mutex);

        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            pthread_mutex_lock(&db->sync_thread_mutex);
            pthread_cond_signal(&db->sync_thread_cond);
            pthread_mutex_unlock(&db->sync_thread_mutex);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }

        pthread_join(db->sync_thread, NULL);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread stopped");
    }

    /*** we always destroy sync mutex/cond since they're always initialized */
    pthread_mutex_destroy(&db->sync_thread_mutex);
    pthread_cond_destroy(&db->sync_thread_cond);

    if (atomic_load(&db->sstable_reaper_active))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Stopping reaper thread");

        /* we set shutdown flag inside mutex to ensure proper synchronization
         * with the worker's while loop predicate check (NetBSD PR #56275) */
        pthread_mutex_lock(&db->reaper_thread_mutex);
        atomic_store(&db->sstable_reaper_active, 0);
        pthread_cond_signal(&db->reaper_thread_cond);
        pthread_mutex_unlock(&db->reaper_thread_mutex);

        /* we keep signaling periodically as a fallback for edge cases */
        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            pthread_mutex_lock(&db->reaper_thread_mutex);
            pthread_cond_signal(&db->reaper_thread_cond);
            pthread_mutex_unlock(&db->reaper_thread_mutex);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }

        pthread_join(db->sstable_reaper_thread, NULL);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper thread stopped");

        pthread_mutex_destroy(&db->reaper_thread_mutex);
        pthread_cond_destroy(&db->reaper_thread_cond);
    }

    if (db->flush_queue)
    {
        while (!queue_is_empty(db->flush_queue))
        {
            tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue(db->flush_queue);
            if (work)
            {
                /* we each flush work holds a reference to the immutable memtable */
                tidesdb_immutable_memtable_unref(work->imm);
                free(work);
            }
        }
        queue_free(db->flush_queue);
    }

    if (db->compaction_queue)
    {
        while (!queue_is_empty(db->compaction_queue))
        {
            tidesdb_compaction_work_t *work =
                (tidesdb_compaction_work_t *)queue_dequeue(db->compaction_queue);
            if (work) free(work);
        }
        queue_free(db->compaction_queue);
    }

    /* we clean up all immutable memtables that remain in CF queues
     * after flush workers have exited, we need to clean up any remaining immutables
     * whether flushed or not */
    pthread_rwlock_wrlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (cf && cf->immutable_memtables)
        {
            int queue_count = (int)queue_size(cf->immutable_memtables);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' %d immutables in queue before shutdown cleanup",
                          cf->name, queue_count);
            int cleaned = 0;
            int skipped = 0;

            /* we only clean up immutable memtables that have been flushed
             * unflushed immutables still contain data that needs to be persisted
             * they will be recovered from WAL on next startup */
            size_t queue_size_before = queue_size(cf->immutable_memtables);
            for (size_t idx = 0; idx < queue_size_before; idx++)
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
                if (imm)
                {
                    int is_flushed = atomic_load_explicit(&imm->flushed, memory_order_acquire);
                    int refcount = atomic_load_explicit(&imm->refcount, memory_order_acquire);

                    if (is_flushed)
                    {
                        TDB_DEBUG_LOG(TDB_LOG_INFO,
                                      "CF '%s' cleaning up flushed immutable with refcount=%d",
                                      cf->name, refcount);
                        tidesdb_immutable_memtable_unref(imm);
                        cleaned++;
                    }
                    else
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_WARN,
                            "CF '%s' skipping unflushed immutable with refcount=%d (data in WAL)",
                            cf->name, refcount);
                        queue_enqueue(cf->immutable_memtables, imm);
                        skipped++;
                    }
                }
            }
            if (cleaned > 0 || skipped > 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "CF '%s' cleaned up %d flushed immutables, skipped %d unflushed "
                              "during shutdown",
                              cf->name, cleaned, skipped);
            }
        }
    }
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_free(db->column_families[i]);
    }
    free(db->column_families);
    pthread_rwlock_unlock(&db->cf_list_lock);

    pthread_rwlock_destroy(&db->cf_list_lock);

    tidesdb_comparator_entry_t *comparators =
        atomic_load_explicit(&db->comparators, memory_order_relaxed);
    if (comparators)
    {
        free(comparators);
    }

    free(db->db_path);

    if (db->clock_cache)
    {
        clock_cache_stats_t stats;
        clock_cache_get_stats(db->clock_cache, &stats);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Freeing clock cache (bytes: %zu, entries: %zu)",
                      stats.total_bytes, stats.total_entries);
        clock_cache_destroy(db->clock_cache);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Clock cache freed");
    }

    if (db->btree_node_cache)
    {
        clock_cache_stats_t stats;
        clock_cache_get_stats(db->btree_node_cache, &stats);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Freeing btree node cache (bytes: %zu, entries: %zu)",
                      stats.total_bytes, stats.total_entries);
        clock_cache_destroy(db->btree_node_cache);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "B+tree node cache freed");
    }

    if (db->commit_status)
    {
        tidesdb_commit_status_destroy(db->commit_status);
    }

    if (db->active_txns)
    {
        free(db->active_txns);
        pthread_rwlock_destroy(&db->active_txns_lock);
    }

    if (db->lock_fd >= 0)
    {
        tdb_file_unlock(db->lock_fd);
        close(db->lock_fd);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Released database directory lock");
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "TidesDB closed successfully");

    /* we close log file if it was opened (protected by log mutex) */
    pthread_mutex_lock(&tidesdb_log_mutex);
    if (_tidesdb_log_file)
    {
        fflush(_tidesdb_log_file);
        fclose(_tidesdb_log_file);
        _tidesdb_log_file = NULL;
        _tidesdb_log_truncate = 0;
        _tidesdb_log_path[0] = '\0';
    }
    db->log_file = NULL;
    pthread_mutex_unlock(&tidesdb_log_mutex);

    free(db);

    db = NULL;

    return TDB_SUCCESS;
}

/**
 * txn_entry_evict
 * eviction callback for active transaction buffer
 */
static void txn_entry_evict(void *data, void *ctx)
{
    (void)ctx;
    if (data) free(data);
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name || !config) return TDB_ERR_INVALID_ARGS;

    if (!atomic_load(&db->is_recovering))
    {
        int wait_result = wait_for_open(db);
        if (wait_result != TDB_SUCCESS) return wait_result;
    }

    if (config->sync_mode == TDB_SYNC_INTERVAL && config->sync_interval_us == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "Invalid config TDB_SYNC_INTERVAL requires sync_interval_us > 0");
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Creating column family: %s", name);

    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, name) == 0)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            TDB_DEBUG_LOG(TDB_LOG_WARN, "Column family %s already exists", name);
            return TDB_ERR_EXISTS;
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    tidesdb_column_family_t *cf = calloc(1, sizeof(tidesdb_column_family_t));
    if (!cf)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to allocate memory for column family structure");
        return TDB_ERR_MEMORY;
    }

    cf->name = tdb_strdup(name);
    if (!cf->name)
    {
        free(cf);
        return TDB_ERR_MEMORY;
    }

    char dir_path[TDB_MAX_PATH_LEN];
    snprintf(dir_path, sizeof(dir_path), "%s" PATH_SEPARATOR "%s", db->db_path, name);

    struct stat st = {0};
    if (stat(dir_path, &st) == -1)
    {
        if (mkdir(dir_path, TDB_DIR_PERMISSIONS) != 0)
        {
            free(cf->name);
            free(cf);
            return TDB_ERR_IO;
        }

        /* we sync parent directory to ensure directory entry is persisted
         * without this, the directory might not survive a crash/close
         * uses cross-platform tdb_sync_directory (no-op on Windows, fsync on POSIX) */
        tdb_sync_directory(db->db_path);
    }

    cf->directory = tdb_strdup(dir_path);
    if (!cf->directory)
    {
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    cf->config = *config;
    cf->db = db;

    /* we validate and fix index_sample_ratio (must be at least 1 to avoid division by zero) */
    if (cf->config.index_sample_ratio < 1)
    {
        cf->config.index_sample_ratio = TDB_DEFAULT_INDEX_SAMPLE_RATIO;
    }

    /* we validate and fix block_index_prefix_len */
    if (cf->config.block_index_prefix_len < TDB_BLOCK_INDEX_PREFIX_MIN ||
        cf->config.block_index_prefix_len > TDB_BLOCK_INDEX_PREFIX_MAX)
    {
        cf->config.block_index_prefix_len = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN;
    }

    skip_list_t *new_memtable = NULL;

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;

    /* we check if a custom comparator is specified */
    int has_custom_comparator =
        (config->comparator_name[0] != '\0' && strcmp(config->comparator_name, "memcmp") != 0);

    if (tidesdb_get_comparator(db, config->comparator_name, &comparator_fn, &comparator_ctx) !=
        TDB_SUCCESS)
    {
        if (has_custom_comparator)
        {
            /* custom comparator specified but not registered!
             * this would cause data corruption if we fall back to memcmp.
             * user must register comparator before creating/opening CF. */
            TDB_DEBUG_LOG(
                TDB_LOG_FATAL,
                "Column family '%s' requires comparator '%s' but it is not registered. "
                "Register comparator with tidesdb_register_comparator() before opening database.",
                name, config->comparator_name);
            free(cf->directory);
            free(cf->name);
            free(cf);
            return TDB_ERR_NOT_FOUND;
        }

        /* no comparator specified or explicitly requested memcmp, use default */
        comparator_fn = tidesdb_comparator_memcmp;
        comparator_ctx = NULL;
    }

    cf->config.comparator_fn_cached = comparator_fn;
    cf->config.comparator_ctx_cached = comparator_ctx;

    if (skip_list_new_with_comparator_and_cached_time(
            &new_memtable, config->skip_list_max_level, config->skip_list_probability,
            comparator_fn, comparator_ctx, &db->cached_current_time) != 0)
    {
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    cf->immutable_memtables = queue_new();
    if (!cf->immutable_memtables)
    {
        skip_list_free(new_memtable);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    char wal_path[TDB_MAX_PATH_LEN];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, 0ULL);

    block_manager_t *new_wal = NULL;
    if (block_manager_open(&new_wal, wal_path, config->sync_mode) != 0)
    {
        queue_free(cf->immutable_memtables);
        skip_list_free(new_memtable);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_IO;
    }

    if (block_manager_truncate(new_wal) != 0)
    {
        block_manager_close(new_wal);
        queue_free(cf->immutable_memtables);
        skip_list_free(new_memtable);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_IO;
    }

    tidesdb_memtable_t *initial_mt = malloc(sizeof(tidesdb_memtable_t));
    if (!initial_mt)
    {
        block_manager_close(new_wal);
        queue_free(cf->immutable_memtables);
        skip_list_free(new_memtable);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    initial_mt->skip_list = new_memtable;
    initial_mt->wal = new_wal;
    initial_mt->id = 0;
    initial_mt->generation = 0;
    atomic_init(&initial_mt->refcount, 1);
    atomic_init(&initial_mt->flushed, 0);
    atomic_init(&cf->active_memtable, initial_mt);

    int min_levels = cf->config.min_levels;

    /* we check if directory already has existing levels from disk */
    DIR *existing_dir = opendir(cf->directory);
    int max_existing_level = 0;
    if (existing_dir)
    {
        struct dirent *entry;
        while ((entry = readdir(existing_dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_SSTABLE_KLOG_EXT) != NULL)
            {
                int level_num = 0;
                if (tdb_parse_level_num(entry->d_name, &level_num))
                {
                    if (level_num > max_existing_level)
                    {
                        max_existing_level = level_num;
                    }
                }
            }
        }
        closedir(existing_dir);
    }

    /* we ensure we have enough levels for existing data */
    if (max_existing_level > min_levels)
    {
        min_levels = max_existing_level;
    }

    /* we validate we dont exceed max levels */
    if (min_levels > TDB_MAX_LEVELS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Cannot create CF requires %d levels but max is %d", min_levels,
                      TDB_MAX_LEVELS);
        tidesdb_memtable_t *mt_cleanup = atomic_load(&cf->active_memtable);
        if (mt_cleanup)
        {
            if (mt_cleanup->skip_list) skip_list_free(mt_cleanup->skip_list);
            if (mt_cleanup->wal) block_manager_close(mt_cleanup->wal);
            free(mt_cleanup);
        }
        queue_free(cf->immutable_memtables);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_INVALID_ARGS;
    }

    size_t base_capacity = config->write_buffer_size * config->level_size_ratio;

    /* we initialize fixed levels array -- create min_levels, rest are NULL */
    for (int i = 0; i < min_levels; i++)
    {
        size_t level_capacity = base_capacity;
        /* we calculate capacity
         * C_i = write_buffer_size * T^i */
        for (int j = 1; j <= i; j++)
        {
            level_capacity *= config->level_size_ratio;
        }

        cf->levels[i] = tidesdb_level_create(i + 1, level_capacity);
        if (!cf->levels[i])
        {
            /* we cleanup already created levels */
            for (int cleanup_idx = 0; cleanup_idx < i; cleanup_idx++)
            {
                if (cf->levels[cleanup_idx])
                {
                    tidesdb_level_free(db, cf->levels[cleanup_idx]);
                }
            }
            tidesdb_memtable_t *mt_cleanup2 = atomic_load(&cf->active_memtable);
            if (mt_cleanup2)
            {
                if (mt_cleanup2->skip_list) skip_list_free(mt_cleanup2->skip_list);
                if (mt_cleanup2->wal) block_manager_close(mt_cleanup2->wal);
                free(mt_cleanup2);
            }
            queue_free(cf->immutable_memtables);
            free(cf->directory);
            free(cf->name);
            free(cf);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Creating level %d with capacity %zu", i + 1, level_capacity);
    }

    /* we initialize remaining slots to NULL */
    for (int i = min_levels; i < TDB_MAX_LEVELS; i++)
    {
        cf->levels[i] = NULL;
    }

    atomic_init(&cf->num_active_levels, min_levels);

    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->sstable_layout_version, 0);
    atomic_init(&cf->is_compacting, 0);
    atomic_init(&cf->is_flushing, 0);
    atomic_init(&cf->immutable_cleanup_counter, 0);
    atomic_init(&cf->pending_commits, 0);

    char manifest_path[TDB_MAX_PATH_LEN];
    snprintf(manifest_path, sizeof(manifest_path), "%s" PATH_SEPARATOR "%s", cf->directory,
             TDB_COLUMN_FAMILY_MANIFEST_NAME);
    cf->manifest = tidesdb_manifest_open(manifest_path);
    if (!cf->manifest)
    {
        /* we cleanup all created levels */
        for (int cleanup_idx = 0; cleanup_idx < min_levels; cleanup_idx++)
        {
            if (cf->levels[cleanup_idx])
            {
                tidesdb_level_free(db, cf->levels[cleanup_idx]);
            }
        }

        tidesdb_memtable_t *mt_cleanup4 = atomic_load(&cf->active_memtable);
        if (mt_cleanup4)
        {
            if (mt_cleanup4->skip_list) skip_list_free(mt_cleanup4->skip_list);
            if (mt_cleanup4->wal) block_manager_close(mt_cleanup4->wal);
            free(mt_cleanup4);
        }
        queue_free(cf->immutable_memtables);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    if (buffer_new_with_eviction(&cf->active_txn_buffer, TDB_DEFAULT_ACTIVE_TXN_BUFFER_SIZE,
                                 txn_entry_evict, NULL) != 0)
    {
        for (int cleanup_idx = 0; cleanup_idx < min_levels; cleanup_idx++)
        {
            if (cf->levels[cleanup_idx])
            {
                tidesdb_level_free(db, cf->levels[cleanup_idx]);
            }
        }
        tidesdb_manifest_close(cf->manifest);

        tidesdb_memtable_t *mt_cleanup5 = atomic_load(&cf->active_memtable);
        if (mt_cleanup5)
        {
            if (mt_cleanup5->skip_list) skip_list_free(mt_cleanup5->skip_list);
            if (mt_cleanup5->wal) block_manager_close(mt_cleanup5->wal);
            free(mt_cleanup5);
        }
        queue_free(cf->immutable_memtables);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    pthread_rwlock_wrlock(&db->cf_list_lock);

    if (db->num_column_families >= db->cf_capacity)
    {
        int new_cap = db->cf_capacity * 2;
        tidesdb_column_family_t **new_array =
            realloc(db->column_families, new_cap * sizeof(tidesdb_column_family_t *));
        if (!new_array)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            tidesdb_column_family_free(cf);
            return TDB_ERR_MEMORY;
        }

        for (int i = db->cf_capacity; i < new_cap; i++)
        {
            new_array[i] = NULL;
        }

        db->column_families = new_array;
        db->cf_capacity = new_cap;
    }

    db->column_families[db->num_column_families] = cf;
    db->num_column_families++;
    pthread_rwlock_unlock(&db->cf_list_lock);

    /* we save configuration to disk for recovery */
    char config_path[MAX_FILE_PATH_LENGTH];
    snprintf(config_path, sizeof(config_path),
             "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT,
             cf->directory);

    int save_result = tidesdb_cf_config_save_to_ini(config_path, name, config);
    if (save_result != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to save CF config for '%s' (error: %d)", name,
                      save_result);
        /* non-fatal, continue */
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Created CF '%s' (total: %d)", name, db->num_column_families);

    /* we start sync thread if this CF needs interval syncing and thread isn't running
     * but not during recovery -- tidesdb_open will handle thread creation after recovery */
    if (config->sync_mode == TDB_SYNC_INTERVAL && config->sync_interval_us > 0 &&
        !atomic_load(&db->is_recovering))
    {
        if (!atomic_load(&db->sync_thread_active))
        {
            atomic_store(&db->sync_thread_active, 1);
            if (pthread_create(&db->sync_thread, NULL, tidesdb_sync_worker_thread, db) != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create sync worker thread for new CF");
                atomic_store(&db->sync_thread_active, 0);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread started for CF '%s'", name);
            }
        }
    }

    return TDB_SUCCESS;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Dropping column family: %s", name);

    tidesdb_column_family_t *cf_to_drop = NULL;

    pthread_rwlock_wrlock(&db->cf_list_lock);

    /* we find the CF to drop */
    int found_idx = -1;
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, name) == 0)
        {
            found_idx = i;
            cf_to_drop = db->column_families[i];
            break;
        }
    }

    if (found_idx == -1)
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_NOT_FOUND;
    }

    /* we mark CF for deletion first -- workers will check this flag and skip processing */
    atomic_store_explicit(&cf_to_drop->marked_for_deletion, 1, memory_order_release);

    /* we shift remaining CFs down */
    for (int i = found_idx; i < db->num_column_families - 1; i++)
    {
        db->column_families[i] = db->column_families[i + 1];
    }
    db->column_families[db->num_column_families - 1] = NULL;
    db->num_column_families--;

    pthread_rwlock_unlock(&db->cf_list_lock);

    /* we wait for any in-progress flush to complete before freeing CF
     * workers check marked_for_deletion and will skip new work, but we must
     * wait for any work that started before we set the flag */
    int wait_count = 0;
    while (atomic_load_explicit(&cf_to_drop->is_flushing, memory_order_acquire) != 0 &&
           wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
        wait_count++;
    }

    /* we wait for any in-progress compaction to complete */
    wait_count = 0;
    while (atomic_load_explicit(&cf_to_drop->is_compacting, memory_order_acquire) != 0 &&
           wait_count < TDB_COMPACTION_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        usleep(TDB_COMPACTION_FLUSH_WAIT_SLEEP_US);
        wait_count++;
    }

    /* we invalidate all block cache entries for this column family before freeing */
    tidesdb_invalidate_block_cache_for_cf(db, cf_to_drop->name);

    const int result = remove_directory(cf_to_drop->directory);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Deleted column family directory: %s (result: %d)",
                  cf_to_drop->directory, result);

    tidesdb_column_family_free(cf_to_drop);

    return TDB_SUCCESS;
}

int tidesdb_rename_column_family(tidesdb_t *db, const char *old_name, const char *new_name)
{
    if (!db || !old_name || !new_name) return TDB_ERR_INVALID_ARGS;

    /* we validate new name length */
    if (strlen(new_name) == 0 || strlen(new_name) >= TDB_MAX_CF_NAME_LEN)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    /** we check for same name */
    if (strcmp(old_name, new_name) == 0)
    {
        return TDB_SUCCESS; /* no-op */
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Renaming column family: %s -> %s", old_name, new_name);

    pthread_rwlock_wrlock(&db->cf_list_lock);

    /* we find the CF to rename */
    tidesdb_column_family_t *cf = NULL;
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, old_name) == 0)
        {
            cf = db->column_families[i];
            break;
        }
    }

    if (!cf)
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_NOT_FOUND;
    }

    /* we we check if new name already exists */
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, new_name) == 0)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            return TDB_ERR_EXISTS;
        }
    }

    /* we wait for any in-progress flush to complete */
    int wait_count = 0;
    while (atomic_load_explicit(&cf->is_flushing, memory_order_acquire) != 0 &&
           wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
        wait_count++;
        pthread_rwlock_wrlock(&db->cf_list_lock);
    }

    /* we wait for any in-progress compaction to complete */
    wait_count = 0;
    while (atomic_load_explicit(&cf->is_compacting, memory_order_acquire) != 0 &&
           wait_count < TDB_COMPACTION_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        usleep(TDB_COMPACTION_FLUSH_WAIT_SLEEP_US);
        wait_count++;
        pthread_rwlock_wrlock(&db->cf_list_lock);
    }

    /* we invalidate all block cache entries for the old CF name before renaming */
    tidesdb_invalidate_block_cache_for_cf(db, old_name);

    /* we build new directory path */
    char new_directory[MAX_FILE_PATH_LENGTH];
    int written = snprintf(new_directory, sizeof(new_directory), "%s%s%s", db->db_path,
                           PATH_SEPARATOR, new_name);
    if (written < 0 || (size_t)written >= sizeof(new_directory))
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_INVALID_ARGS;
    }

    struct STAT_STRUCT st;
    if (STAT_FUNC(new_directory, &st) == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "Cannot rename CF '%s' to '%s': destination directory already exists",
                      old_name, new_name);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_EXISTS;
    }

    /* on windows, we must close all file handles before renaming directory
     * close the active memtable's WAL */
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    block_manager_t *old_wal = NULL;
    uint64_t old_wal_id = 0;
    if (active_mt && active_mt->wal)
    {
        old_wal = active_mt->wal;
        old_wal_id = active_mt->id;
        block_manager_close(old_wal);
        active_mt->wal = NULL;
    }

    /* we close all sst file handles before rename (required on Windows) */
    const int num_levels = atomic_load(&cf->num_active_levels);
    for (int lvl = 0; lvl < num_levels; lvl++)
    {
        tidesdb_level_t *level = cf->levels[lvl];
        if (!level) continue;

        const int num_sst = atomic_load(&level->num_sstables);
        tidesdb_sstable_t **sstables = atomic_load(&level->sstables);
        for (int s = 0; s < num_sst; s++)
        {
            tidesdb_sstable_t *sst = sstables[s];
            if (!sst) continue;

            if (sst->klog_bm)
            {
                block_manager_close(sst->klog_bm);
                sst->klog_bm = NULL;
            }
            if (sst->vlog_bm)
            {
                block_manager_close(sst->vlog_bm);
                sst->vlog_bm = NULL;
            }
        }
    }

    /* we close manifest file handle before rename (required on Windows) */
    if (cf->manifest)
    {
        pthread_rwlock_wrlock(&cf->manifest->lock);
        if (cf->manifest->fp)
        {
            fclose(cf->manifest->fp);
            cf->manifest->fp = NULL;
        }
        pthread_rwlock_unlock(&cf->manifest->lock);
    }

    /* we rename directory on disk (use atomic_rename_dir for Windows compatibility) */
    if (atomic_rename_dir(cf->directory, new_directory) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to rename directory %s to %s: %s", cf->directory,
                      new_directory, strerror(errno));
        /* we try to reopen WAL at old location */
        if (old_wal)
        {
            char wal_path[MAX_FILE_PATH_LENGTH];
            snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR "wal_%" PRIu64 ".log",
                     cf->directory, old_wal_id);
            block_manager_open(&active_mt->wal, wal_path, cf->config.sync_mode);
        }
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_IO;
    }

    /* we reopen WAL at new location */
    if (old_wal)
    {
        char new_wal_path[MAX_FILE_PATH_LENGTH];
        int wal_written =
            snprintf(new_wal_path, sizeof(new_wal_path), "%s" PATH_SEPARATOR "wal_%" PRIu64 ".log",
                     new_directory, old_wal_id);
        if (wal_written > 0 && (size_t)wal_written < sizeof(new_wal_path))
        {
            if (block_manager_open(&active_mt->wal, new_wal_path, cf->config.sync_mode) != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to reopen WAL at %s after rename",
                              new_wal_path);
            }
        }
    }

    /* we update CF name */
    char *new_name_copy = strdup(new_name);
    if (!new_name_copy)
    {
        /* try to revert directory rename */
        atomic_rename_dir(new_directory, cf->directory);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    /* we update CF directory */
    char *new_dir_copy = strdup(new_directory);
    if (!new_dir_copy)
    {
        free(new_name_copy);
        /* we try to revert directory rename */
        atomic_rename_dir(new_directory, cf->directory);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    /* we swap in new values */
    char *old_name_ptr = cf->name;
    char *old_dir_ptr = cf->directory;
    cf->name = new_name_copy;
    cf->directory = new_dir_copy;

    /* we update all sst file paths in all levels
     * note -- we already hold cf_list_lock and waited for flush/compaction to complete,
     * so it's safe to modify sstable paths without additional locking */
    for (int lvl = 0; lvl < num_levels; lvl++)
    {
        tidesdb_level_t *level = cf->levels[lvl];
        if (!level) continue;

        const int num_sst = atomic_load(&level->num_sstables);
        tidesdb_sstable_t **sstables = atomic_load(&level->sstables);
        for (int s = 0; s < num_sst; s++)
        {
            tidesdb_sstable_t *sst = sstables[s];
            if (!sst) continue;

            /* we build new klog path */
            char new_klog_path[MAX_FILE_PATH_LENGTH];
            int path_written = snprintf(new_klog_path, sizeof(new_klog_path),
                                        "%s" PATH_SEPARATOR "L%d_%" PRIu64 ".klog", new_directory,
                                        lvl + 1, sst->id);
            if (path_written > 0 && (size_t)path_written < sizeof(new_klog_path))
            {
                char *new_klog = strdup(new_klog_path);
                if (new_klog)
                {
                    free(sst->klog_path);
                    sst->klog_path = new_klog;
                }
            }

            /* we build new vlog path */
            char new_vlog_path[MAX_FILE_PATH_LENGTH];
            path_written = snprintf(new_vlog_path, sizeof(new_vlog_path),
                                    "%s" PATH_SEPARATOR "L%d_%" PRIu64 ".vlog", new_directory,
                                    lvl + 1, sst->id);
            if (path_written > 0 && (size_t)path_written < sizeof(new_vlog_path))
            {
                char *new_vlog = strdup(new_vlog_path);
                if (new_vlog)
                {
                    free(sst->vlog_path);
                    sst->vlog_path = new_vlog;
                }
            }
        }
    }

    /* we update config file with new name */
    char config_path[MAX_FILE_PATH_LENGTH];
    written =
        snprintf(config_path, sizeof(config_path),
                 "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT,
                 new_directory);
    if (written > 0 && (size_t)written < sizeof(config_path))
    {
        tidesdb_cf_config_save_to_ini(config_path, new_name, &cf->config);
    }

    /* we update manifest path -- must update internal path before commit! */
    if (cf->manifest)
    {
        char manifest_path[MAX_FILE_PATH_LENGTH];
        written = snprintf(manifest_path, sizeof(manifest_path),
                           "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_MANIFEST_NAME, new_directory);
        if (written > 0 && (size_t)written < sizeof(manifest_path))
        {
            /* we update the manifest's internal path to the new location
             *** note -- fp was already closed before rename for Windows compatibility */
            pthread_rwlock_wrlock(&cf->manifest->lock);
            memcpy(cf->manifest->path, manifest_path, sizeof(manifest_path));
            pthread_rwlock_unlock(&cf->manifest->lock);

            /* commit manifest to new location to ensure it's written */
            tidesdb_manifest_commit(cf->manifest, manifest_path);
        }
    }

    pthread_rwlock_unlock(&db->cf_list_lock);

    free(old_name_ptr);
    free(old_dir_ptr);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Successfully renamed column family: %s -> %s", old_name, new_name);

    return TDB_SUCCESS;
}

static tidesdb_column_family_t *tidesdb_get_column_family_internal(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;
    tidesdb_column_family_t *result = NULL;
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, name) == 0)
        {
            result = db->column_families[i];
            break;
        }
    }
    return result;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

    const int wait_result = wait_for_open(db);
    if (wait_result != TDB_SUCCESS) return NULL;

    pthread_rwlock_rdlock(&db->cf_list_lock);
    tidesdb_column_family_t *result = NULL;

    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, name) == 0)
        {
            result = db->column_families[i];
            break;
        }
    }

    pthread_rwlock_unlock(&db->cf_list_lock);
    return result;
}

static int wait_for_open(tidesdb_t *db)
{
    /* we wait for database to open and finish recovery, but timeout if it's closing
     * this prevents threads from hanging forever when database is being closed
     * and prevents transactions from starting during recovery */
    int wait_count = 0;

    while (!atomic_load_explicit(&db->is_open, memory_order_acquire) ||
           atomic_load_explicit(&db->is_recovering, memory_order_acquire))
    {
        if (wait_count >= TDB_OPENING_WAIT_MAX_MS)
        {
            /* the database is not open and hasnt opened after timeout
             * it's likely closing or closed */
            return TDB_ERR_INVALID_DB;
        }

        /* we spin-wait with small sleep to avoid busy loop
         * we use same interval as transaction wait for consistency */
        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        wait_count++;
    }

    return TDB_SUCCESS;
}

int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count)
{
    if (!db || !names || !count) return TDB_ERR_INVALID_ARGS;

    pthread_rwlock_rdlock(&db->cf_list_lock);

    *count = db->num_column_families;
    if (*count == 0)
    {
        *names = NULL;
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_SUCCESS;
    }

    *names = malloc(sizeof(char *) * (*count));
    if (!*names)
    {
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    for (int i = 0; i < *count; i++)
    {
        if (db->column_families[i] && db->column_families[i]->name)
        {
            (*names)[i] = strdup(db->column_families[i]->name);
            if (!(*names)[i])
            {
                for (int j = 0; j < i; j++)
                {
                    free((*names)[j]);
                }
                free(*names);
                *names = NULL;
                *count = 0;
                pthread_rwlock_unlock(&db->cf_list_lock);
                return TDB_ERR_MEMORY;
            }
        }
        else
        {
            (*names)[i] = NULL;
        }
    }

    pthread_rwlock_unlock(&db->cf_list_lock);
    return TDB_SUCCESS;
}

int tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    return tidesdb_flush_memtable_internal(cf, 0, 0);
}

int tidesdb_is_flushing(tidesdb_column_family_t *cf)
{
    if (!cf) return 0;
    return atomic_load_explicit(&cf->is_flushing, memory_order_acquire) != 0 ? 1 : 0;
}

int tidesdb_is_compacting(tidesdb_column_family_t *cf)
{
    if (!cf) return 0;
    return atomic_load_explicit(&cf->is_compacting, memory_order_acquire) != 0 ? 1 : 0;
}

static int tidesdb_flush_memtable_internal(tidesdb_column_family_t *cf,
                                           const int already_holds_lock, int force)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* we check if CF is marked for deletion -- skip flush if so */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        return TDB_SUCCESS;
    }

    if (!already_holds_lock)
    {
        int expected = 0;
        if (!atomic_compare_exchange_strong_explicit(&cf->is_flushing, &expected, 1,
                                                     memory_order_acquire, memory_order_relaxed))
        {
            /* another flush is already running, skip this one */
            return TDB_SUCCESS;
        }
    }

    /* we check again after acquiring is_flushing in case drop happened between checks */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        if (!already_holds_lock)
        {
            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        }
        return TDB_SUCCESS;
    }

    /* we update cached_current_time to ensure TTL checks during flush use fresh time */
    atomic_store(&cf->db->cached_current_time, tdb_get_current_time());

    tidesdb_memtable_t *old_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *old_memtable = old_mt ? old_mt->skip_list : NULL;
    size_t current_size = old_memtable ? (size_t)skip_list_get_size(old_memtable) : 0;
    int current_entries = old_memtable ? skip_list_count_entries(old_memtable) : 0;

    if (current_entries == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' memtable is empty, skipping flush", cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    /* we only check size threshold if not forcing flush */
    if (!force && current_size < cf->config.write_buffer_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' memtable size %zu < threshold %zu and force=0, skipping flush",
                      cf->name, current_size, cf->config.write_buffer_size);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' is flushing memtable (entries: %d, size: %zu bytes / %.2f MB, "
                  "threshold: %zu bytes "
                  "/ %.2f MB)",
                  cf->name, current_entries, current_size, current_size / (1024.0 * 1024.0),
                  cf->config.write_buffer_size, cf->config.write_buffer_size / (1024.0 * 1024.0));

    block_manager_t *old_wal = old_mt ? old_mt->wal : NULL;
    uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);

    /* if using TDB_SYNC_INTERVAL, sync the old WAL before rotation
     * this essentially ensures WAL durability before it becomes immutable */
    if (cf->config.sync_mode == TDB_SYNC_INTERVAL && old_wal)
    {
        block_manager_escalate_fsync(old_wal);
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    if (tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx) != 0)
    {
        /* comparator not found, use default memcmp */
        comparator_fn = skip_list_comparator_memcmp;
        comparator_ctx = NULL;
    }

    /* we check marked_for_deletion again before allocating resources
     * this prevents leaking memtable/WAL if CF is being dropped */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' is marked for deletion, aborting flush before resource allocation",
                      cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    skip_list_t *new_memtable;
    if (skip_list_new_with_comparator_and_cached_time(
            &new_memtable, cf->config.skip_list_max_level, cf->config.skip_list_probability,
            comparator_fn, comparator_ctx, &cf->db->cached_current_time) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to create new memtable", cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    uint64_t wal_id = sst_id + 1;
    char wal_path[MAX_FILE_PATH_LENGTH];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(wal_id));

    block_manager_t *new_wal;

    if (block_manager_open(&new_wal, wal_path, convert_sync_mode(cf->config.sync_mode)) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to open new WAL: %s", cf->name, wal_path);
        skip_list_free(new_memtable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_IO;
    }

    if (block_manager_truncate(new_wal) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to truncate new WAL: %s", cf->name, wal_path);
        block_manager_close(new_wal);
        skip_list_free(new_memtable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_IO;
    }

    /* we create new tidesdb_memtable_t structure pairing skip_list and wal */
    tidesdb_memtable_t *new_mt = malloc(sizeof(tidesdb_memtable_t));
    if (!new_mt)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to allocate new memtable structure", cf->name);
        skip_list_free(new_memtable);
        block_manager_close(new_wal);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }
    new_mt->skip_list = new_memtable;
    new_mt->wal = new_wal;
    new_mt->id = sst_id + 1;
    new_mt->generation = old_mt ? old_mt->generation + 1 : 1;
    atomic_init(&new_mt->refcount, 1);
    atomic_init(&new_mt->flushed, 0);

    /* we check marked_for_deletion again after allocating resources
     * this handles the race where CF is dropped while we were allocating */
    if (atomic_load_explicit(&cf->marked_for_deletion, memory_order_acquire))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' is marked for deletion, cleaning up newly allocated resources",
                      cf->name);
        skip_list_free(new_memtable);
        block_manager_close(new_wal);
        free(new_mt);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    /* we swap active_memtable pointer -- new writers will use the new memtable
     * no need to wait for old memtable refcount to drain here becase:
     * -- old memtable becomes immutable and is enqueued for background flush
     * -- refcount naturally drains as in-flight writers finish
     * -- tidesdb_immutable_memtable_unref() handles cleanup when refcount hits 0 */
    atomic_store_explicit(&cf->active_memtable, new_mt, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);

    /* we reuse old_mt directly as the immutable memtable instead of allocating a new structure
     * this avoids a race condition where another thread still holds a pointer to old_mt
     * and tries to decrement its refcount after we free it
     * the old_mt structure stays alive until all references are released */
    tidesdb_immutable_memtable_t *immutable = old_mt;
    if (!immutable)
    {
        /* no old memtable to flush -- this shouldnt happen but handle gracefully
         * note -- new_mt is already stored as active_memtable, so we cannot free it here
         * the new memtable will be cleaned up when the CF is freed */
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' no old memtable to flush", cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    /* old_mt already has correct skip_list, wal, id, generation, and refcount
     * just reset flushed flag */
    atomic_store_explicit(&immutable->flushed, 0, memory_order_release);

    /* enqueue immutable -- this should never fail but check anyway to prevent data loss */
    if (queue_enqueue(cf->immutable_memtables, immutable) != 0)
    {
        TDB_DEBUG_LOG(
            TDB_LOG_ERROR,
            "CF '%s' CRITICAL: failed to enqueue immutable memtable - data in WAL for recovery",
            cf->name);

        /* we free the skip_list and wal -- data is still in WAL for recovery on restart */
        skip_list_free(old_memtable);
        if (old_wal) block_manager_close(old_wal);
        free(immutable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' memtable swapped, allocating flush work for SSTable %" PRIu64, cf->name,
                  sst_id);

    tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
    if (!work)
    {
        /* immutable is already queued but flush will never happen
         * we must clean it up to prevent memory leak */
        tidesdb_immutable_memtable_unref(immutable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    work->cf = cf;
    work->imm = immutable;
    work->sst_id = sst_id;

    tidesdb_immutable_memtable_ref(immutable);

    size_t queue_size_before = queue_size(cf->db->flush_queue);
    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' is enqueueing flush work for SSTable %" PRIu64
                  " (queue size before: %zu)",
                  cf->name, sst_id, queue_size_before);

    /* we retry enqueue with backoff -- we must not lose this flush work
     * the WAL has been rotated and data is only in the immutable memtable */
    int enqueue_attempts = 0;
    while (queue_enqueue(cf->db->flush_queue, work) != 0)
    {
        enqueue_attempts++;
        if (enqueue_attempts >= TDB_FLUSH_ENQUEUE_MAX_ATTEMPTS)
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "CF '%s' failed to enqueue flush work after %d attempts for SSTable "
                          "%" PRIu64,
                          cf->name, TDB_FLUSH_ENQUEUE_MAX_ATTEMPTS, sst_id);
            tidesdb_immutable_memtable_unref(immutable); /* remove work ref */
            free(work);
            /* leave is_flushing set to prevent more flushes until this resolves */
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' flush queue full, retry %d/%d for SSTable %" PRIu64,
                      cf->name, enqueue_attempts, TDB_FLUSH_ENQUEUE_MAX_ATTEMPTS, sst_id);
        usleep(TDB_FLUSH_ENQUEUE_BACKOFF_US);
    }

    size_t queue_size_after = queue_size(cf->db->flush_queue);
    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' has successfully enqueued flush work for SSTable %" PRIu64
                  " (queue size after: %zu)",
                  cf->name, sst_id, queue_size_after);

    return TDB_SUCCESS;
}

int tidesdb_compact(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    if (atomic_load_explicit(&cf->is_compacting, memory_order_acquire))
    {
        /* compaction already running, skip */
        return TDB_SUCCESS;
    }

    /* we enqueue compaction work */
    tidesdb_compaction_work_t *work = malloc(sizeof(tidesdb_compaction_work_t));
    if (!work)
    {
        return TDB_ERR_MEMORY;
    }

    work->cf = cf;
    if (queue_enqueue(cf->db->compaction_queue, work) != 0)
    {
        free(work);
        return TDB_ERR_MEMORY;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_apply_backpressure
 * checks L0 queue and L1 file count and applies coordinated backpressure
 * implements stall mechanism when L0 queue exceeds threshold (blocking flush)
 * @param cf the column family
 * @return TDB_SUCCESS or error code
 */
static int tidesdb_apply_backpressure(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* we check L0 immutable queue depth */
    const size_t l0_queue_depth = queue_size(cf->immutable_memtables);

    /* we check L1 file count */
    int l1_file_count = atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);

    /* l0 queue exceeds threshold -- force blocking flush of all immutables
     * this prevents unbounded memory growth when flush worker falls behind */
    if (l0_queue_depth >= (size_t)cf->config.l0_queue_stall_threshold)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "CF '%s' L0 queue stall triggered: %zu immutables (threshold=%d) - "
                      "blocking until flushes complete",
                      cf->name, l0_queue_depth, cf->config.l0_queue_stall_threshold);

        /* we wait for queue to drain below threshold
         * flush worker is processing in background, we just need to wait */
        int wait_iterations = 0;
        while (queue_size(cf->immutable_memtables) >= (size_t)cf->config.l0_queue_stall_threshold)
        {
            usleep(TDB_BACKPRESSURE_STALL_CHECK_INTERVAL_US);
            wait_iterations++;

            if (wait_iterations >= TDB_BACKPRESSURE_STALL_MAX_ITERATIONS)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "CF '%s' L0 queue stall timeout after %d iterations - "
                              "flush worker may be stuck",
                              cf->name, wait_iterations);
                return TDB_ERR_IO; /* flush worker appears stuck */
            }
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' L0 queue stall resolved after %d iterations (%dms)",
                      cf->name, wait_iterations,
                      wait_iterations * (TDB_BACKPRESSURE_STALL_CHECK_INTERVAL_US / 1000));
    }
    /* coordinated L0/L1 backpressure
     * we apply graduated delays based on queue depth and L1 file count */
    else if (l0_queue_depth >= (size_t)(cf->config.l0_queue_stall_threshold *
                                        TDB_BACKPRESSURE_HIGH_THRESHOLD_RATIO) ||
             l1_file_count >=
                 (cf->config.l1_file_count_trigger * TDB_BACKPRESSURE_L1_HIGH_MULTIPLIER))
    {
        /* high pressure -- TDB_BACKPRESSURE_HIGH_THRESHOLD_RATIO of stall threshold or
         * TDB_BACKPRESSURE_L1_HIGH_MULTIPLIER x L1 trigger */
        usleep(TDB_BACKPRESSURE_HIGH_DELAY_US);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' high backpressure: L0=%zu L1=%d - %dus delay",
                      cf->name, l0_queue_depth, l1_file_count, TDB_BACKPRESSURE_HIGH_DELAY_US);
    }
    else if (l0_queue_depth >= (size_t)(cf->config.l0_queue_stall_threshold *
                                        TDB_BACKPRESSURE_MODERATE_THRESHOLD_RATIO) ||
             l1_file_count >=
                 (cf->config.l1_file_count_trigger * TDB_BACKPRESSURE_L1_MODERATE_MULTIPLIER))
    {
        /* moderate pressure -- TDB_BACKPRESSURE_MODERATE_THRESHOLD_RATIO of stall threshold or
         * TDB_BACKPRESSURE_L1_MODERATE_MULTIPLIER x L1 trigger */
        usleep(TDB_BACKPRESSURE_MODERATE_DELAY_US);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' moderate backpressure: L0=%zu L1=%d - %dus delay",
                      cf->name, l0_queue_depth, l1_file_count, TDB_BACKPRESSURE_MODERATE_DELAY_US);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_add_cf_internal
 * internal helper to add a CF to transaction and take snapshot
 * @param txn the transaction
 * @param cf the column family
 */
static int tidesdb_txn_add_cf_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf);

/**
 * tidesdb_txn_remove_from_active_list
 * internal helper to remove a SERIALIZABLE transaction from the active list
 * @param txn the transaction to remove
 */
static void tidesdb_txn_remove_from_active_list(tidesdb_txn_t *txn)
{
    if (!txn || !txn->db) return;
    if (txn->isolation_level != TDB_ISOLATION_SERIALIZABLE) return;

    pthread_rwlock_wrlock(&txn->db->active_txns_lock);
    for (int i = 0; i < txn->db->num_active_txns; i++)
    {
        if (txn->db->active_txns[i] == txn)
        {
            /* we shift remaining transactions down */
            for (int j = i; j < txn->db->num_active_txns - 1; j++)
            {
                txn->db->active_txns[j] = txn->db->active_txns[j + 1];
            }
            txn->db->num_active_txns--;
            break;
        }
    }
    pthread_rwlock_unlock(&txn->db->active_txns_lock);
}

/**
 * tidesdb_txn_add_to_read_set
 * internal helper to add a key to the read set for conflict detection
 * @param txn the transaction
 * @param cf the column family
 * @param key the key
 * @param key_size the key size
 * @param seq the sequence number
 * @return 0 on success, -1 on failure
 */
static int tidesdb_txn_add_to_read_set(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                                       const uint8_t *key, const size_t key_size,
                                       const uint64_t seq)
{
    /* we skip read tracking for isolation levels that dont need conflict detection */
    if (txn->isolation_level < TDB_ISOLATION_REPEATABLE_READ)
    {
        return 0; /* READ_UNCOMMITTED and READ_COMMITTED dont need read tracking */
    }

    /** we check last few entries first (hot cache, likely duplicates)
     * most iterators read sequentially, so recent keys are often duplicates */
    const int check_recent = (txn->read_set_count < 8) ? txn->read_set_count : 8;
    for (int i = txn->read_set_count - 1; i >= txn->read_set_count - check_recent; i--)
    {
        if (txn->read_cfs[i] == cf && txn->read_key_sizes[i] == key_size &&
            memcmp(txn->read_keys[i], key, key_size) == 0)
        {
            /* already in read set, update sequence if newer */
            if (seq > txn->read_seqs[i])
            {
                txn->read_seqs[i] = seq;
            }
            return 0;
        }
    }

    if (txn->read_set_count >= txn->read_set_capacity)
    {
        int new_cap = txn->read_set_capacity * 2;
        if (new_cap < txn->read_set_capacity + TDB_TXN_READ_SET_BATCH_GROW)
        {
            new_cap = txn->read_set_capacity + TDB_TXN_READ_SET_BATCH_GROW;
        }

        uint8_t **new_keys = realloc(txn->read_keys, new_cap * sizeof(uint8_t *));
        if (!new_keys) return -1;

        size_t *new_sizes = realloc(txn->read_key_sizes, new_cap * sizeof(size_t));
        if (!new_sizes)
        {
            /* new_keys succeeded, so we need to keep it */
            txn->read_keys = new_keys;
            return -1;
        }

        uint64_t *new_seqs = realloc(txn->read_seqs, new_cap * sizeof(uint64_t));
        if (!new_seqs)
        {
            txn->read_keys = new_keys;
            txn->read_key_sizes = new_sizes;
            return -1;
        }

        tidesdb_column_family_t **new_cfs =
            realloc(txn->read_cfs, new_cap * sizeof(tidesdb_column_family_t *));
        if (!new_cfs)
        {
            txn->read_keys = new_keys;
            txn->read_key_sizes = new_sizes;
            txn->read_seqs = new_seqs;
            return -1;
        }

        txn->read_keys = new_keys;
        txn->read_key_sizes = new_sizes;
        txn->read_seqs = new_seqs;
        txn->read_cfs = new_cfs;
        txn->read_set_capacity = new_cap;
    }

    /* arena allocation for read keys to reduce malloc overhead */
    uint8_t *key_ptr = NULL;

    /* we check if current arena has space */
    if (txn->read_key_arenas && txn->read_key_arena_count > 0)
    {
        const size_t remaining = TDB_TXN_READ_KEY_ARENA_SIZE - txn->read_key_arena_used;
        if (key_size <= remaining)
        {
            /* bump allocate from current arena */
            key_ptr =
                txn->read_key_arenas[txn->read_key_arena_count - 1] + txn->read_key_arena_used;
            txn->read_key_arena_used += key_size;
        }
    }

    /* we need new arena or first allocation */
    if (!key_ptr)
    {
        const size_t arena_size =
            (key_size > TDB_TXN_READ_KEY_ARENA_SIZE) ? key_size : TDB_TXN_READ_KEY_ARENA_SIZE;
        uint8_t *new_arena = malloc(arena_size);
        if (!new_arena) return -1;

        /* we grow arena array if needed */
        if (!txn->read_key_arenas)
        {
            txn->read_key_arenas =
                malloc(TDB_TXN_READ_KEY_ARENA_INITIAL_CAPACITY * sizeof(uint8_t *));
            if (!txn->read_key_arenas)
            {
                free(new_arena);
                return -1;
            }
        }
        else if ((txn->read_key_arena_count & (txn->read_key_arena_count - 1)) == 0 &&
                 txn->read_key_arena_count >= TDB_TXN_READ_KEY_ARENA_INITIAL_CAPACITY)
        {
            /* power of 2 and >= initial capacity, double the array */
            const int new_cap = txn->read_key_arena_count * 2;
            uint8_t **new_arenas = realloc(txn->read_key_arenas, new_cap * sizeof(uint8_t *));
            if (!new_arenas)
            {
                free(new_arena);
                return -1;
            }
            txn->read_key_arenas = new_arenas;
        }

        txn->read_key_arenas[txn->read_key_arena_count++] = new_arena;
        key_ptr = new_arena;
        txn->read_key_arena_used = key_size;
    }

    memcpy(key_ptr, key, key_size);
    txn->read_keys[txn->read_set_count] = key_ptr;
    txn->read_key_sizes[txn->read_set_count] = key_size;
    txn->read_seqs[txn->read_set_count] = seq;
    txn->read_cfs[txn->read_set_count] = cf;

    txn->read_set_count++;
    if (txn->read_set_count == TDB_TXN_READ_HASH_THRESHOLD && !txn->read_set_hash)
    {
        txn->read_set_hash = tidesdb_read_set_hash_create();
        if (txn->read_set_hash)
        {
            /* we populate hash with all existing reads */
            for (int i = 0; i < txn->read_set_count; i++)
            {
                tidesdb_read_set_hash_insert((tidesdb_read_set_hash_t *)txn->read_set_hash, txn, i);
            }
        }
    }
    else if (txn->read_set_hash)
    {
        /* we add new read to existing hash */
        tidesdb_read_set_hash_insert((tidesdb_read_set_hash_t *)txn->read_set_hash, txn,
                                     txn->read_set_count - 1);
    }

    return 0;
}

/**
 * tidesdb_txn_begin
 * begins a new transaction with default isolation level (READ_COMMITTED)
 * @param db database handle
 * @param txn output transaction handle
 * @return TDB_SUCCESS or error code
 */
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn)
{
    return tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, txn);
}

/**
 * tidesdb_txn_begin_with_isolation
 * begins a new transaction with specified isolation level
 *
 * isolation levels
 * -- READ_UNCOMMITTED -- sees all versions including uncommitted (dirty reads allowed)
 * -- READ_COMMITTED -- refreshes snapshot on each read (prevents dirty reads)
 * -- REPEATABLE_READ -- consistent snapshot, read-write conflict detection
 * -- SNAPSHOT -- consistent snapshot, read-write + write-write conflict detection
 * -- SERIALIZABLE -- full SSI with dangerous structure detection (prevents all anomalies)
 *
 * @param db database handle
 * @param isolation isolation level
 * @param txn output transaction handle
 * @return TDB_SUCCESS or error code
 */
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, const tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;

    const int wait_result = wait_for_open(db);
    if (wait_result != TDB_SUCCESS)
    {
        return wait_result;
    }

    if (isolation < TDB_ISOLATION_READ_UNCOMMITTED || isolation > TDB_ISOLATION_SERIALIZABLE)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    *txn = calloc(1, sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->isolation_level = isolation;

    /* we assign unique transaction id from database counter */
    (*txn)->txn_id = atomic_fetch_add_explicit(&db->next_txn_id, 1, memory_order_relaxed);

    if (isolation == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        (*txn)->snapshot_seq = UINT64_MAX; /* we see all versions */
    }
    else if (isolation == TDB_ISOLATION_READ_COMMITTED)
    {
        /* we snapshot will be refreshed on each read -- initial value doesnt matter */
        (*txn)->snapshot_seq = 0;
    }
    else
    {
        /* REPEATABLE_READ, SNAPSHOT, SERIALIZABLE = consistent snapshot
         * we capture global_seq -- 1 to see only transactions committed before we started */
        uint64_t current_seq = atomic_load_explicit(&db->global_seq, memory_order_acquire);
        (*txn)->snapshot_seq = (current_seq > 0) ? current_seq - 1 : 0;
    }

    (*txn)->commit_seq = 0;

    (*txn)->ops_capacity = TDB_INITIAL_TXN_OPS_CAPACITY;
    (*txn)->ops = calloc((*txn)->ops_capacity, sizeof(tidesdb_txn_op_t));
    if (!(*txn)->ops)
    {
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    /* we defer read set allocation for isolation levels that dont need conflict detection
     * READ_UNCOMMITTED and READ_COMMITTED skip read tracking entirely */
    if (isolation >= TDB_ISOLATION_REPEATABLE_READ)
    {
        (*txn)->read_set_capacity = TDB_INITIAL_TXN_READ_SET_CAPACITY;
        (*txn)->read_keys = calloc((*txn)->read_set_capacity, sizeof(uint8_t *));
        (*txn)->read_key_sizes = calloc((*txn)->read_set_capacity, sizeof(size_t));
        (*txn)->read_seqs = calloc((*txn)->read_set_capacity, sizeof(uint64_t));
        (*txn)->read_cfs = calloc((*txn)->read_set_capacity, sizeof(tidesdb_column_family_t *));

        if (!(*txn)->read_keys || !(*txn)->read_key_sizes || !(*txn)->read_seqs ||
            !(*txn)->read_cfs)
        {
            free((*txn)->read_keys);
            free((*txn)->read_key_sizes);
            free((*txn)->read_seqs);
            free((*txn)->read_cfs);
            free((*txn)->ops);
            free(*txn);
            *txn = NULL;
            return TDB_ERR_MEMORY;
        }
    }
    else
    {
        /* low isolation levels dont track reads */
        (*txn)->read_set_capacity = 0;
        (*txn)->read_keys = NULL;
        (*txn)->read_key_sizes = NULL;
        (*txn)->read_seqs = NULL;
        (*txn)->read_cfs = NULL;
    }

    (*txn)->write_set_hash = NULL; /* hash table created lazily for large transactions */
    (*txn)->read_set_hash = NULL;  /* hash table created lazily for large read sets */

    (*txn)->cf_capacity = TDB_INITIAL_TXN_CF_CAPACITY;
    (*txn)->cfs = calloc((*txn)->cf_capacity, sizeof(tidesdb_column_family_t *));

    if (!(*txn)->cfs)
    {
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->read_cfs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->savepoints_capacity = TDB_INITIAL_TXN_SAVEPOINT_CAPACITY;
    (*txn)->savepoints = calloc((*txn)->savepoints_capacity, sizeof(tidesdb_txn_t *));
    (*txn)->savepoint_names = calloc((*txn)->savepoints_capacity, sizeof(char *));

    if (!(*txn)->savepoints || !(*txn)->savepoint_names)
    {
        free((*txn)->savepoints);
        free((*txn)->savepoint_names);
        free((*txn)->cfs);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->read_cfs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->num_cfs = 0;

    (*txn)->has_rw_conflict_in = 0;
    (*txn)->has_rw_conflict_out = 0;

    /* we register SERIALIZABLE transactions in active list for SSI tracking */
    if (isolation == TDB_ISOLATION_SERIALIZABLE)
    {
        pthread_rwlock_wrlock(&db->active_txns_lock);

        if (db->num_active_txns < db->active_txns_capacity)
        {
            db->active_txns[db->num_active_txns++] = *txn;
        }
        else
        {
            /* capacity exceeded -- log warning but continue.
             * this transaction wont participate in SSI conflict detection,
             * but will still get correct snapshot isolation semantics. */
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "Active transaction list full (%d), SSI may be less effective",
                          db->active_txns_capacity);
        }

        pthread_rwlock_unlock(&db->active_txns_lock);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_add_cf_internal
 * internal helper to add a CF to transaction and take snapshot
 * @param txn
 * @param cf
 * @return error code
 */
static int tidesdb_txn_add_cf_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf)
{
    if (!txn || !cf) return -1;
    if (txn->is_committed || txn->is_aborted) return -1;

    /* fast path -- we check last-used CF (covers single-CF workloads in O(1)) */
    if (txn->last_cf == cf) return txn->last_cf_index;

    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf)
        {
            txn->last_cf = cf;
            txn->last_cf_index = i;
            return i;
        }
    }

    if (txn->num_cfs >= txn->cf_capacity)
    {
        /* we check if we've hit the maximum column family limit */
        if (txn->cf_capacity >= TDB_MAX_TXN_CFS)
        {
            return -1;
        }

        int new_cap = txn->cf_capacity * 2;

        /* cap at maximum to prevent overflow */
        if (new_cap > TDB_MAX_TXN_CFS) new_cap = TDB_MAX_TXN_CFS;

        tidesdb_column_family_t **new_cfs =
            realloc(txn->cfs, new_cap * sizeof(tidesdb_column_family_t *));

        if (!new_cfs) return -1;

        for (int i = txn->cf_capacity; i < new_cap; i++)
        {
            new_cfs[i] = NULL;
        }

        txn->cfs = new_cfs;
        txn->cf_capacity = new_cap;
    }

    const int cf_index = txn->num_cfs;
    txn->cfs[cf_index] = cf;
    txn->num_cfs++;

    txn->last_cf = cf;
    txn->last_cf_index = cf_index;

    return cf_index;
}

int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    const size_t key_size, const uint8_t *value, const size_t value_size,
                    const time_t ttl)
{
    if (!txn || !cf || !key || key_size == 0 || !value) return TDB_ERR_INVALID_ARGS;

    /* we wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    /* we apply coordinated L0/L1 backpressure before accepting write
     * this prevents memory exhaustion and coordinates flush/compaction */
    const int backpressure_result = tidesdb_apply_backpressure(cf);
    if (backpressure_result != TDB_SUCCESS) return backpressure_result;

    /* we validate key-value size against memory limits */
    const int size_check = tidesdb_validate_kv_size(txn->db, key_size, value_size);
    if (size_check != 0) return size_check;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* we add CF to transaction if not already added */
    const int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    if (txn->num_ops >= TDB_MAX_TXN_OPS)
    {
        return TDB_ERR_TOO_LARGE;
    }

    if (txn->num_ops >= txn->ops_capacity)
    {
        int new_capacity = txn->ops_capacity * 2;

        /* we ensure we dont exceed max even with doubling */
        if (new_capacity > TDB_MAX_TXN_OPS) new_capacity = TDB_MAX_TXN_OPS;

        if (new_capacity <= txn->ops_capacity) return TDB_ERR_TOO_LARGE;

        tidesdb_txn_op_t *new_ops = realloc(txn->ops, new_capacity * sizeof(tidesdb_txn_op_t));
        if (!new_ops) return TDB_ERR_MEMORY;

        txn->ops = new_ops;
        txn->ops_capacity = new_capacity;
    }

    tidesdb_txn_op_t *op = &txn->ops[txn->num_ops];
    memset(op, 0, sizeof(tidesdb_txn_op_t));

    op->key = malloc(key_size);
    if (!op->key) return TDB_ERR_MEMORY;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;

    if (value && value_size > 0)
    {
        op->value = malloc(value_size);
        if (!op->value)
        {
            free(op->key);
            return TDB_ERR_MEMORY;
        }
        memcpy(op->value, value, value_size);
        op->value_size = value_size;
    }
    else
    {
        op->value = NULL;
        op->value_size = 0;
    }

    op->ttl = ttl;
    op->is_delete = 0;
    op->cf = cf;

    txn->num_ops++;

    if (txn->num_ops == TDB_TXN_WRITE_HASH_THRESHOLD && !txn->write_set_hash)
    {
        txn->write_set_hash = tidesdb_write_set_hash_create();
        if (txn->write_set_hash)
        {
            /* we populate hash with all existing operations */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                              i);
            }
        }
    }
    else if (txn->write_set_hash)
    {
        tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                      txn->num_ops - 1);
    }

    return TDB_SUCCESS;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    const size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf || !key || key_size == 0 || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    PROFILE_INC(txn->db, total_reads);

    /* we wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    /* we add CF to transaction if not already added */
    const int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    /* we check write set first (read your own writes)
     * transaction must see its own uncommitted changes before checking cache/memtable
     * use search strategy based on transaction size:
     * -- small txns  -- linear scan from end (cache-friendly, low overhead)
     * -- medium txns -- linear scan with early termination per CF
     * -- large txns  -- O(1) hash table lookup
     *
     * we search in reverse order (newest first) to find most recent write */

    /* for large transactions, use hash table for O(1) lookup */
    if (txn->write_set_hash)
    {
        const int op_index = tidesdb_write_set_hash_lookup(
            (tidesdb_write_set_hash_t *)txn->write_set_hash, txn, cf, key, key_size);

        if (op_index >= 0)
        {
            tidesdb_txn_op_t *op = &txn->ops[op_index];
            if (op->is_delete)
            {
                return TDB_ERR_NOT_FOUND;
            }
            *value = malloc(op->value_size);
            if (!*value) return TDB_ERR_MEMORY;
            memcpy(*value, op->value, op->value_size);
            *value_size = op->value_size;
            return TDB_SUCCESS;
        }
        /* not in write set, fall through to memtable search */
    }
    else
    {
        /** for small transactions, scan last N ops only
         * this handles 99% of cases with minimal overhead */
        const int scan_start = txn->num_ops - 1;
        const int scan_end = (txn->num_ops > TDB_TXN_SMALL_SCAN_LIMIT)
                                 ? (txn->num_ops - TDB_TXN_SMALL_SCAN_LIMIT)
                                 : 0;

        for (int i = scan_start; i >= scan_end; i--)
        {
            const tidesdb_txn_op_t *op = &txn->ops[i];

            /* quick CF check first (pointer comparison) */
            if (op->cf != cf) continue;

            /* then size check (cheap integer comparison) */
            if (op->key_size != key_size) continue;

            /* finally memcmp (most expensive) */
            if (memcmp(op->key, key, key_size) == 0)
            {
                if (op->is_delete)
                {
                    return TDB_ERR_NOT_FOUND;
                }
                *value = malloc(op->value_size);
                if (!*value) return TDB_ERR_MEMORY;
                memcpy(*value, op->value, op->value_size);
                *value_size = op->value_size;
                return TDB_SUCCESS;
            }
        }

        /* if transaction is large and we didnt find in recent ops, scan remainder */
        if (scan_end > 0)
        {
            for (int i = scan_end - 1; i >= 0; i--)
            {
                tidesdb_txn_op_t *op = &txn->ops[i];
                if (op->cf != cf) continue;
                if (op->key_size != key_size) continue;
                if (memcmp(op->key, key, key_size) == 0)
                {
                    if (op->is_delete) return TDB_ERR_NOT_FOUND;
                    *value = malloc(op->value_size);
                    if (!*value) return TDB_ERR_MEMORY;
                    memcpy(*value, op->value, op->value_size);
                    *value_size = op->value_size;
                    return TDB_SUCCESS;
                }
            }
        }
    }

    /* determine snapshot based on isolation level
     * -- READ_UNCOMMITTED -- UINT64_MAX (see all versions, no visibility check)
     * -- READ_COMMITTED -- refresh snapshot on each read (latest committed data)
     * -- REPEATABLE_READ/SNAPSHOT/SERIALIZABLE -- use consistent snapshot from BEGIN */
    uint64_t snapshot_seq;
    skip_list_visibility_check_fn visibility_check;

    if (txn->isolation_level == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        snapshot_seq = UINT64_MAX;
        visibility_check = NULL; /* no visibility check -- see everything */
    }
    else if (txn->isolation_level == TDB_ISOLATION_READ_COMMITTED)
    {
        /* refresh snapshot to see latest committed data
         * READ_COMMITTED doesnt need visibility callback because:
         * 1. it refreshes snapshot on each read to see all data up to current global_seq
         * 2. commit status buffer is circular and can have stale entries after recovery
         * 3. any data in memtable with seq <= snapshot_seq is considered visible
         *
         * we use current_seq (not current_seq - 1) because committed transactions have
         * seq <= global_seq. After recovery, global_seq is set to max_seq from ssts,
         * so we need snapshot_seq = global_seq to see all committed data. */
        uint64_t current_seq = atomic_load_explicit(&txn->db->global_seq, memory_order_acquire);
        snapshot_seq = current_seq;
        visibility_check = NULL; /* no visibility check needed for READ_COMMITTED */
    }
    else
    {
        /* REPEATABLE_READ, SNAPSHOT, SERIALIZABLE = consistent snapshot */
        snapshot_seq = txn->snapshot_seq;
        visibility_check = tidesdb_visibility_check_callback;
    }

    /* we now load active memtable -- any keys that rotated are already in our immutable snapshot */
    tidesdb_memtable_t *active_mt_struct =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;

    atomic_thread_fence(memory_order_acquire);

    /* we cache current time once for consistent TTL checks throughout this read */
    const int64_t now = (int64_t)atomic_load(&txn->db->cached_current_time);

    uint8_t *temp_value;
    size_t temp_value_size;
    int64_t ttl;
    uint8_t deleted;
    uint64_t found_seq = 0;

    int memtable_result = skip_list_get_with_seq(
        active_mt, key, key_size, &temp_value, &temp_value_size, &ttl, &deleted, &found_seq,
        snapshot_seq, visibility_check, txn->db->commit_status);

    if (memtable_result == 0)
    {
        if (deleted)
        {
            /* we found a tombstone in active memtable, key is deleted */
            free(temp_value);
            return TDB_ERR_NOT_FOUND;
        }

        if (ttl <= 0 || ttl > now)
        {
            *value = temp_value;
            *value_size = temp_value_size;

            PROFILE_INC(txn->db, memtable_hits);
            tidesdb_txn_add_to_read_set(txn, cf, key, key_size, found_seq);
            return TDB_SUCCESS;
        }

        /* TTL expired -- newest version is expired, do not fall through to older data */
        free(temp_value);
        return TDB_ERR_NOT_FOUND;
    }

    tidesdb_immutable_memtable_t **immutable_refs = NULL;
    size_t immutable_count = 0;

    /* we skip snapshot allocation if immutable queue is empty */
    if (!queue_is_empty(cf->immutable_memtables))
    {
        immutable_refs =
            tidesdb_snapshot_immutable_memtables(cf->immutable_memtables, &immutable_count);
    }

    /* we now search immutable memtables safely with references held
     * search in reverse order (newest first) to find most recent version */

    if (immutable_refs && immutable_count > 0)
    {
        int result = TDB_ERR_UNKNOWN;
        for (int i = (int)immutable_count - 1; i >= 0; i--)
        {
            const tidesdb_immutable_memtable_t *immutable = immutable_refs[i];
            if (immutable && immutable->skip_list)
            {
                if (skip_list_get_with_seq(immutable->skip_list, key, key_size, &temp_value,
                                           &temp_value_size, &ttl, &deleted, &found_seq,
                                           snapshot_seq, visibility_check,
                                           visibility_check ? txn->db->commit_status : NULL) == 0)
                {
                    if (deleted)
                    {
                        /* we found a tombstone in immutable memtable, key is deleted */
                        free(temp_value);
                        result = TDB_ERR_NOT_FOUND;
                        goto cleanup_immutables;
                    }

                    if (ttl <= 0 || ttl > now)
                    {
                        *value = temp_value;
                        *value_size = temp_value_size;
                        PROFILE_INC(txn->db, immutable_hits);
                        tidesdb_txn_add_to_read_set(txn, cf, key, key_size, found_seq);
                        result = TDB_SUCCESS;
                        goto cleanup_immutables;
                    }

                    /* TTL expired */
                    free(temp_value);
                    result = TDB_ERR_NOT_FOUND;
                    goto cleanup_immutables;
                }
            }
        }

    cleanup_immutables:
        for (size_t i = 0; i < immutable_count; i++)
        {
            if (immutable_refs[i]) tidesdb_immutable_memtable_unref(immutable_refs[i]);
        }
        free(immutable_refs);

        /* if we jumped here from immutable search, return the result */
        if (result != TDB_ERR_UNKNOWN) return result;
    }

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    for (int level_num = 0; level_num < num_levels; level_num++)
    {
    retry_level:
        PROFILE_INC(txn->db, levels_searched);
        tidesdb_level_t *level = cf->levels[level_num];

        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        /* we re-load count to detect concurrent remove that swapped array but hasnt updated count
         * yet
         */
        int num_ssts_recheck = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        if (num_ssts_recheck < num_ssts)
        {
            num_ssts = num_ssts_recheck; /* use smaller count to avoid OOB */
        }

        /* we also verify array hasnt changed (handles add-with-resize race) */
        tidesdb_sstable_t **sstables_check =
            atomic_load_explicit(&level->sstables, memory_order_acquire);
        if (sstables_check != sstables)
        {
            /* the array was resized, reload everything */
            sstables = sstables_check;
            num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        }

        const int start = (level_num == 0) ? num_ssts - 1 : 0;
        const int end = (level_num == 0) ? -1 : num_ssts;
        const int step = (level_num == 0) ? -1 : 1;

        for (int j = start; j != end; j += step)
        {
            tidesdb_sstable_t *sst = sstables[j];
            if (!sst) continue;

            PROFILE_INC(txn->db, sstables_checked);

            /* we try to take ref for ssts we will check
             * we use try_ref to safely handle concurrent removal -- if refcount is 0,
             * the sstable is being freed and we must skip it
             **********************************************************************
             *** when try_ref fails, the array may have been swapped with a new one
             * containing the merged sstable, so we must retry the entire level */
            if (!tidesdb_sstable_try_ref(sst))
            {
                goto retry_level;
            }

            tidesdb_kv_pair_t *candidate_kv = NULL;
            int get_result = tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv);

            if (get_result == TDB_SUCCESS && candidate_kv)
            {
                const uint64_t candidate_seq = candidate_kv->entry.seq;
                const int accept =
                    (snapshot_seq == UINT64_MAX) ? 1 : (candidate_seq <= snapshot_seq);

                if (accept)
                {
                    const int is_tombstone =
                        (candidate_kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) != 0;
                    const int ttl_ok =
                        (candidate_kv->entry.ttl <= 0 || candidate_kv->entry.ttl > now);

                    PROFILE_INC(txn->db, sstable_hits);

                    if (!is_tombstone && ttl_ok)
                    {
                        *value = malloc(candidate_kv->entry.value_size);
                        if (!*value)
                        {
                            tidesdb_kv_pair_free(candidate_kv);
                            tidesdb_sstable_unref(cf->db, sst);
                            return TDB_ERR_MEMORY;
                        }
                        memcpy(*value, candidate_kv->value, candidate_kv->entry.value_size);
                        *value_size = candidate_kv->entry.value_size;

                        tidesdb_txn_add_to_read_set(txn, cf, key, key_size, candidate_seq);

                        tidesdb_kv_pair_free(candidate_kv);
                        tidesdb_sstable_unref(cf->db, sst);
                        return TDB_SUCCESS;
                    }

                    tidesdb_kv_pair_free(candidate_kv);
                    tidesdb_sstable_unref(cf->db, sst);
                    return TDB_ERR_NOT_FOUND;
                }

                tidesdb_kv_pair_free(candidate_kv);
            }

            tidesdb_sstable_unref(cf->db, sst);
        }
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       const size_t key_size)
{
    if (!txn || !cf || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    /* we wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    const int backpressure_result = tidesdb_apply_backpressure(cf);
    if (backpressure_result != TDB_SUCCESS) return backpressure_result;

    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* we add CF to transaction if not already added */
    const int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    if (txn->num_ops >= TDB_MAX_TXN_OPS)
    {
        return TDB_ERR_TOO_LARGE;
    }

    /* we expand ops array if needed */
    if (txn->num_ops >= txn->ops_capacity)
    {
        int new_capacity = txn->ops_capacity * 2;

        if (new_capacity > TDB_MAX_TXN_OPS) new_capacity = TDB_MAX_TXN_OPS;

        if (new_capacity <= txn->ops_capacity) return TDB_ERR_TOO_LARGE;

        tidesdb_txn_op_t *new_ops = realloc(txn->ops, new_capacity * sizeof(tidesdb_txn_op_t));
        if (!new_ops) return TDB_ERR_MEMORY;

        txn->ops = new_ops;
        txn->ops_capacity = new_capacity;
    }

    tidesdb_txn_op_t *op = &txn->ops[txn->num_ops];
    memset(op, 0, sizeof(tidesdb_txn_op_t));

    op->key = malloc(key_size);
    if (!op->key) return TDB_ERR_MEMORY;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;

    op->value = NULL;
    op->value_size = 0;
    op->ttl = 0;
    op->is_delete = 1;
    op->cf = cf;

    txn->num_ops++;

    /* we create hash table when we cross threshold for O(1) lookups */
    if (txn->num_ops == TDB_TXN_WRITE_HASH_THRESHOLD && !txn->write_set_hash)
    {
        txn->write_set_hash = tidesdb_write_set_hash_create();
        if (txn->write_set_hash)
        {
            /* we populate hash with all existing operations */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                              i);
            }
        }
    }
    else if (txn->write_set_hash)
    {
        /* we add new operation to existing hash */
        tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                      txn->num_ops - 1);
    }

    return TDB_SUCCESS;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed) return TDB_ERR_INVALID_ARGS;

    /* we remove from active list if SERIALIZABLE */
    tidesdb_txn_remove_from_active_list(txn);

    /* we mark as aborted; operations never applied */
    txn->is_aborted = 1;
    return TDB_SUCCESS;
}

void tidesdb_txn_free(tidesdb_txn_t *txn) /* NOLINT(misc-no-recursion) */
{
    if (!txn) return;

    for (int i = 0; i < txn->num_ops; i++)
    {
        free(txn->ops[i].key);
        free(txn->ops[i].value);
    }
    free(txn->ops);
    for (int i = 0; i < txn->read_key_arena_count; i++)
    {
        free(txn->read_key_arenas[i]);
    }
    free(txn->read_key_arenas);
    free(txn->read_keys);
    free(txn->read_key_sizes);
    free(txn->read_seqs);
    free(txn->read_cfs);

    if (txn->write_set_hash)
    {
        tidesdb_write_set_hash_free((tidesdb_write_set_hash_t *)txn->write_set_hash);
    }
    if (txn->read_set_hash)
    {
        tidesdb_read_set_hash_free((tidesdb_read_set_hash_t *)txn->read_set_hash);
    }

    for (int i = 0; i < txn->num_savepoints; i++)
    {
        free(txn->savepoint_names[i]);
        tidesdb_txn_free(txn->savepoints[i]);
    }
    free(txn->savepoints);
    free(txn->savepoint_names);

    free(txn->cfs);
    free(txn);
}

int tidesdb_txn_reset(tidesdb_txn_t *txn, const tidesdb_isolation_level_t isolation)
{
    if (!txn || !txn->db) return TDB_ERR_INVALID_ARGS;
    if (!txn->is_committed && !txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    if (isolation < TDB_ISOLATION_READ_UNCOMMITTED || isolation > TDB_ISOLATION_SERIALIZABLE)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    const int wait_result = wait_for_open(txn->db);
    if (wait_result != TDB_SUCCESS)
    {
        return wait_result;
    }

    /* we remove from SERIALIZABLE active list if the old isolation was SERIALIZABLE */
    if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        tidesdb_txn_remove_from_active_list(txn);
    }

    /* we free op key/value data but keep the ops array itself */
    for (int i = 0; i < txn->num_ops; i++)
    {
        free(txn->ops[i].key);
        txn->ops[i].key = NULL;
        free(txn->ops[i].value);
        txn->ops[i].value = NULL;
    }
    txn->num_ops = 0;

    /* we reset read set -- keep arrays allocated, free arena buffers to avoid leaks */
    txn->read_set_count = 0;

    /* we free individual arena buffers but keep the pointer array for reuse */
    for (int i = 0; i < txn->read_key_arena_count; i++)
    {
        free(txn->read_key_arenas[i]);
        txn->read_key_arenas[i] = NULL;
    }
    txn->read_key_arena_count = 0;
    txn->read_key_arena_used = 0;

    /* we allocate read set arrays if switching to higher isolation that needs them */
    if (isolation >= TDB_ISOLATION_REPEATABLE_READ && !txn->read_keys)
    {
        txn->read_set_capacity = TDB_INITIAL_TXN_READ_SET_CAPACITY;
        txn->read_keys = calloc(txn->read_set_capacity, sizeof(uint8_t *));
        txn->read_key_sizes = calloc(txn->read_set_capacity, sizeof(size_t));
        txn->read_seqs = calloc(txn->read_set_capacity, sizeof(uint64_t));
        txn->read_cfs = calloc(txn->read_set_capacity, sizeof(tidesdb_column_family_t *));

        if (!txn->read_keys || !txn->read_key_sizes || !txn->read_seqs || !txn->read_cfs)
        {
            return TDB_ERR_MEMORY;
        }
    }

    /* we free hash tables -- they contain stale indices.  will be rebuilt lazily */
    if (txn->write_set_hash)
    {
        tidesdb_write_set_hash_free((tidesdb_write_set_hash_t *)txn->write_set_hash);
        txn->write_set_hash = NULL;
    }
    if (txn->read_set_hash)
    {
        tidesdb_read_set_hash_free((tidesdb_read_set_hash_t *)txn->read_set_hash);
        txn->read_set_hash = NULL;
    }

    /* we free any savepoints */
    for (int i = 0; i < txn->num_savepoints; i++)
    {
        free(txn->savepoint_names[i]);
        tidesdb_txn_free(txn->savepoints[i]);
    }
    txn->num_savepoints = 0;

    /* we reset cf tracking */
    txn->num_cfs = 0;
    txn->last_cf = NULL;
    txn->last_cf_index = 0;

    /* we assign fresh transaction identity */
    txn->isolation_level = isolation;
    txn->txn_id = atomic_fetch_add_explicit(&txn->db->next_txn_id, 1, memory_order_relaxed);

    if (isolation == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        txn->snapshot_seq = UINT64_MAX;
    }
    else if (isolation == TDB_ISOLATION_READ_COMMITTED)
    {
        txn->snapshot_seq = 0;
    }
    else
    {
        uint64_t current_seq = atomic_load_explicit(&txn->db->global_seq, memory_order_acquire);
        txn->snapshot_seq = (current_seq > 0) ? current_seq - 1 : 0;
    }

    txn->commit_seq = 0;
    txn->is_committed = 0;
    txn->is_aborted = 0;
    txn->has_rw_conflict_in = 0;
    txn->has_rw_conflict_out = 0;

    /* we register in active list if new isolation is SERIALIZABLE */
    if (isolation == TDB_ISOLATION_SERIALIZABLE)
    {
        pthread_rwlock_wrlock(&txn->db->active_txns_lock);

        if (txn->db->num_active_txns < txn->db->active_txns_capacity)
        {
            txn->db->active_txns[txn->db->num_active_txns++] = txn;
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "Active transaction list full (%d), SSI may be less effective",
                          txn->db->active_txns_capacity);
        }

        pthread_rwlock_unlock(&txn->db->active_txns_lock);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_check_seq_conflict
 * check sequence conflicts in memtable/immutable
 * @param sl skip list to check
 * @param key key to check
 * @param key_size key size
 * @param threshold_seq threshold sequence
 * @return 1 if conflict, 0 if no conflict
 */
static int tidesdb_txn_check_seq_conflict(skip_list_t *sl, const uint8_t *key,
                                          const size_t key_size, const uint64_t threshold_seq)
{
    if (!sl) return 0;

    uint64_t found_seq = 0;
    if (skip_list_get_max_seq(sl, key, key_size, &found_seq) == 0)
    {
        return (found_seq > threshold_seq) ? 1 : 0;
    }
    return 0;
}

/**
 * tidesdb_txn_get_imm_snapshot
 * get immutable memtable snapshot with refcounting
 * @param cf column family to get snapshot for
 * @param out_count output parameter for number of immutable memtables
 * @return immutable memtable references
 */
static tidesdb_immutable_memtable_t **tidesdb_txn_get_imm_snapshot(
    const tidesdb_column_family_t *cf, size_t *out_count)
{
    return tidesdb_snapshot_immutable_memtables(cf->immutable_memtables, out_count);
}

/**
 * tidesdb_txn_cleanup_imm_snapshot
 * cleanup immutable memtable snapshot
 * @param imm_refs immutable memtable references
 * @param imm_count number of immutable memtables
 */
static void tidesdb_txn_cleanup_imm_snapshot(tidesdb_immutable_memtable_t **imm_refs,
                                             const size_t imm_count)
{
    if (!imm_refs) return;
    for (size_t i = 0; i < imm_count; i++)
    {
        if (imm_refs[i]) tidesdb_immutable_memtable_unref(imm_refs[i]);
    }
    free(imm_refs);
}

/**
 * tidesdb_txn_check_sstable_conflict
 * check if any sstable in the column family has a newer version of the key
 * @param db database handle
 * @param cf column family to check
 * @param key key to check
 * @param key_size key size
 * @param threshold_seq threshold sequence
 * @return 1 if conflict, 0 if no conflict
 */
static int tidesdb_txn_check_sstable_conflict(tidesdb_t *db, tidesdb_column_family_t *cf,
                                              const uint8_t *key, const size_t key_size,
                                              const uint64_t threshold_seq)
{
    if (!db || !cf) return 0;

    /* we track highest sequence found across all ssts
     * in L1 (levels[0]), ssts can overlap and newer ones are appended at the end
     * we must check all ssts to find the true highest sequence for this key */
    uint64_t max_found_seq = 0;
    int found_any = 0;

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    for (int level_idx = 0; level_idx < num_levels; level_idx++)
    {
        tidesdb_level_t *level = cf->levels[level_idx];
        if (!level) continue;

        /* we load array pointer and count with careful ordering to handle concurrent modifications
         * re-load count to detect concurrent remove, use minimum to avoid OOB */
        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int num_sstables = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        /* we re-load count to detect concurrent remove */
        int num_sstables_recheck = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        if (num_sstables_recheck < num_sstables) num_sstables = num_sstables_recheck;

        /* we verify array hasnt changed (handles add-with-resize race) */
        tidesdb_sstable_t **sstables_check =
            atomic_load_explicit(&level->sstables, memory_order_acquire);
        if (sstables_check != sstables)
        {
            sstables = sstables_check;
            num_sstables = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        }

        const int start = (level_idx == 0) ? num_sstables - 1 : 0;
        const int end = (level_idx == 0) ? -1 : num_sstables;
        const int step = (level_idx == 0) ? -1 : 1;

        for (int sst_idx = start; sst_idx != end; sst_idx += step)
        {
            tidesdb_sstable_t *sst = sstables[sst_idx];
            if (!sst) continue;

            /* we try to take ref to safely handle concurrent removal */
            if (!tidesdb_sstable_try_ref(sst))
            {
                continue; /* sstable is being freed, skip it */
            }

            tidesdb_kv_pair_t *kv = NULL;
            if (tidesdb_sstable_get(db, sst, key, key_size, &kv) == TDB_SUCCESS && kv)
            {
                uint64_t found_seq = kv->entry.seq;
                tidesdb_kv_pair_free(kv);
                found_any = 1;
                if (found_seq > max_found_seq)
                {
                    max_found_seq = found_seq;
                }
                if (found_seq > threshold_seq)
                {
                    tidesdb_sstable_unref(db, sst);
                    return 1;
                }
            }

            tidesdb_sstable_unref(db, sst);
        }
    }

    /** conflict if we found any version with seq > threshold */
    return (found_any && max_found_seq > threshold_seq) ? 1 : 0;
}

/**
 * tidesdb_txn_check_key_conflict
 * unified conflict check for a single key against memtable, immutables, and sstables
 * @param txn transaction
 * @param cf column family
 * @param key key to check
 * @param key_size key size
 * @param threshold_seq sequence threshold for conflict detection
 * @param imm_refs cached immutable refs (will be refreshed if cf changes)
 * @param imm_count count of immutable refs
 * @param last_cf pointer to last CF checked (for caching)
 * @return TDB_SUCCESS if no conflict, TDB_ERR_CONFLICT if conflict detected
 */
static int tidesdb_txn_check_key_conflict(const tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                                          const uint8_t *key, const size_t key_size,
                                          const uint64_t threshold_seq,
                                          tidesdb_immutable_memtable_t ***imm_refs,
                                          size_t *imm_count, tidesdb_column_family_t **last_cf)
{
    /* refresh imm snapshot only when CF changes */
    if (cf != *last_cf)
    {
        if (*imm_refs) tidesdb_txn_cleanup_imm_snapshot(*imm_refs, *imm_count);
        *imm_refs = tidesdb_txn_get_imm_snapshot(cf, imm_count);
        *last_cf = cf;
    }

    tidesdb_memtable_t *mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

    if (tidesdb_txn_check_seq_conflict(mt ? mt->skip_list : NULL, key, key_size, threshold_seq))
    {
        return TDB_ERR_CONFLICT;
    }

    for (size_t i = 0; i < *imm_count; i++)
    {
        if (tidesdb_txn_check_seq_conflict((*imm_refs)[i]->skip_list, key, key_size, threshold_seq))
        {
            return TDB_ERR_CONFLICT;
        }
    }

    if (tidesdb_txn_check_sstable_conflict(txn->db, cf, key, key_size, threshold_seq))
    {
        return TDB_ERR_CONFLICT;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_check_read_conflicts
 * check read-set for conflicts (repeatable read and higher)
 * @param txn transaction to check
 * @return TDB_SUCCESS if no conflicts, TDB_ERR_CONFLICT otherwise
 */
static int tidesdb_txn_check_read_conflicts(const tidesdb_txn_t *txn)
{
    if (txn->isolation_level < TDB_ISOLATION_REPEATABLE_READ || txn->read_set_count == 0)
    {
        return TDB_SUCCESS;
    }

    tidesdb_column_family_t *last_cf = NULL;
    tidesdb_immutable_memtable_t **imm_refs = NULL;
    size_t imm_count = 0;

    for (int r = 0; r < txn->read_set_count; r++)
    {
        const int result = tidesdb_txn_check_key_conflict(txn, txn->read_cfs[r], txn->read_keys[r],
                                                          txn->read_key_sizes[r], txn->read_seqs[r],
                                                          &imm_refs, &imm_count, &last_cf);

        if (result != TDB_SUCCESS)
        {
            if (imm_refs) tidesdb_txn_cleanup_imm_snapshot(imm_refs, imm_count);
            return result;
        }
    }

    if (imm_refs) tidesdb_txn_cleanup_imm_snapshot(imm_refs, imm_count);
    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_check_write_conflicts
 * check write-set for conflicts (snapshot isolation and higher)
 * @param txn transaction to check
 * @return TDB_SUCCESS if no conflicts, TDB_ERR_CONFLICT otherwise
 */
static int tidesdb_txn_check_write_conflicts(const tidesdb_txn_t *txn)
{
    if (txn->isolation_level < TDB_ISOLATION_SNAPSHOT || txn->num_ops == 0)
    {
        return TDB_SUCCESS;
    }

    tidesdb_column_family_t *last_cf = NULL;
    tidesdb_immutable_memtable_t **imm_refs = NULL;
    size_t imm_count = 0;

    for (int w = 0; w < txn->num_ops; w++)
    {
        const tidesdb_txn_op_t *op = &txn->ops[w];

        const int result = tidesdb_txn_check_key_conflict(
            txn, op->cf, op->key, op->key_size, txn->snapshot_seq, &imm_refs, &imm_count, &last_cf);

        if (result != TDB_SUCCESS)
        {
            if (imm_refs) tidesdb_txn_cleanup_imm_snapshot(imm_refs, imm_count);
            return result;
        }
    }

    if (imm_refs) tidesdb_txn_cleanup_imm_snapshot(imm_refs, imm_count);
    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_check_ssi_conflicts
 * check serializable snapshot isolation conflicts
 * @param txn transaction to check
 * @return TDB_SUCCESS if no conflicts, TDB_ERR_CONFLICT otherwise
 */
static int tidesdb_txn_check_ssi_conflicts(tidesdb_txn_t *txn)
{
    if (txn->isolation_level != TDB_ISOLATION_SERIALIZABLE)
    {
        return TDB_SUCCESS;
    }

    pthread_rwlock_rdlock(&txn->db->active_txns_lock);
    int snapshot_count = txn->db->num_active_txns;
    tidesdb_txn_t **snapshot = NULL;

    if (snapshot_count > 0)
    {
        snapshot = malloc(snapshot_count * sizeof(tidesdb_txn_t *));
        if (snapshot)
        {
            memcpy(snapshot, txn->db->active_txns, snapshot_count * sizeof(tidesdb_txn_t *));
        }
        else
        {
            snapshot_count = 0;
        }
    }
    pthread_rwlock_unlock(&txn->db->active_txns_lock);

    /* we detect rw-conflicts */
    for (int i = 0; i < snapshot_count; i++)
    {
        tidesdb_txn_t *other = snapshot[i];
        if (other == txn || other->is_committed || other->is_aborted) continue;

        if (txn->read_set_hash && txn->read_set_count >= TDB_TXN_READ_HASH_THRESHOLD)
        {
            for (int w = 0; w < other->num_ops && !txn->has_rw_conflict_out; w++)
            {
                const tidesdb_txn_op_t *op = &other->ops[w];
                if (tidesdb_read_set_hash_check_conflict(
                        (tidesdb_read_set_hash_t *)txn->read_set_hash, txn, op->cf, op->key,
                        op->key_size))
                {
                    txn->has_rw_conflict_out = 1;
                    other->has_rw_conflict_in = 1;
                    break;
                }
            }
        }
        else
        {
            for (int r = 0; r < txn->read_set_count && !txn->has_rw_conflict_out; r++)
            {
                for (int w = 0; w < other->num_ops; w++)
                {
                    const tidesdb_txn_op_t *op = &other->ops[w];
                    if (txn->read_key_sizes[r] == op->key_size && txn->read_cfs[r] == op->cf &&
                        memcmp(txn->read_keys[r], op->key, op->key_size) == 0)
                    {
                        txn->has_rw_conflict_out = 1;
                        other->has_rw_conflict_in = 1;
                        break;
                    }
                }
            }
        }
    }

    /* we check for dangerous structures */
    if (txn->has_rw_conflict_in && txn->has_rw_conflict_out)
    {
        free(snapshot);
        tidesdb_txn_remove_from_active_list(txn);
        return TDB_ERR_CONFLICT;
    }

    if (txn->num_ops > 0)
    {
        for (int i = 0; i < snapshot_count; i++)
        {
            const tidesdb_txn_t *other = snapshot[i];
            if (other == txn || other->is_committed || other->is_aborted ||
                !other->has_rw_conflict_in || !other->has_rw_conflict_out)
            {
                continue;
            }

            for (int w = 0; w < txn->num_ops; w++)
            {
                const tidesdb_txn_op_t *op = &txn->ops[w];
                for (int r = 0; r < other->read_set_count; r++)
                {
                    if (op->key_size == other->read_key_sizes[r] && op->cf == other->read_cfs[r] &&
                        memcmp(op->key, other->read_keys[r], op->key_size) == 0)
                    {
                        free(snapshot);
                        tidesdb_txn_remove_from_active_list(txn);
                        return TDB_ERR_CONFLICT;
                    }
                }
            }
        }
    }

    free(snapshot);
    return TDB_SUCCESS;
}

/**
 * tidesdb_txn_apply_ops_to_memtable
 * apply transaction operations to a memtable with deduplication
 * @param txn transaction
 * @param cf column family
 * @param memtable skip list to apply to
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_txn_apply_ops_to_memtable(const tidesdb_txn_t *txn,
                                             const tidesdb_column_family_t *cf,
                                             skip_list_t *memtable)
{
    /* count ops for this CF */
    int cf_op_count = 0;
    for (int i = 0; i < txn->num_ops; i++)
    {
        if (txn->ops[i].cf == cf) cf_op_count++;
    }

    if (cf_op_count == 0) return TDB_SUCCESS;

    if (cf_op_count < TDB_TXN_DEDUP_SKIP_THRESHOLD)
    {
        for (int i = txn->num_ops - 1; i >= 0; i--)
        {
            const tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            /* we check if this key appears later (newer version exists) */
            int is_superseded = 0;
            for (int j = i + 1; j < txn->num_ops; j++)
            {
                const tidesdb_txn_op_t *later_op = &txn->ops[j];
                if (later_op->cf == cf && later_op->key_size == op->key_size &&
                    memcmp(later_op->key, op->key, op->key_size) == 0)
                {
                    is_superseded = 1;
                    break;
                }
            }
            if (is_superseded) continue;

            if (skip_list_put_with_seq(memtable, op->key, op->key_size, op->value, op->value_size,
                                       op->ttl, txn->commit_seq, op->is_delete) != 0)
            {
                return TDB_ERR_MEMORY;
            }
        }
        return TDB_SUCCESS;
    }

    int dedup_hash_size = cf_op_count * TDB_TXN_DEDUP_HASH_MULTIPLIER;
    if (dedup_hash_size < TDB_TXN_DEDUP_MIN_HASH_SIZE)
        dedup_hash_size = TDB_TXN_DEDUP_MIN_HASH_SIZE;

    typedef struct
    {
        uint8_t *key;
        size_t key_size;
        int op_idx;
    } dedup_entry_t;

    dedup_entry_t *dedup_hash = calloc(dedup_hash_size, sizeof(dedup_entry_t));

    int *used_slots = NULL;
    const int used_slots_capacity = cf_op_count < TDB_TXN_DEDUP_MAX_TRACKED ? cf_op_count : 0;
    if (used_slots_capacity > 0)
    {
        used_slots = malloc(used_slots_capacity * sizeof(int));
    }

    if (!dedup_hash)
    {
        /* the fallback is to write all ops without dedup */
        free(used_slots);
        for (int i = 0; i < txn->num_ops; i++)
        {
            const tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;
            if (skip_list_put_with_seq(memtable, op->key, op->key_size, op->value, op->value_size,
                                       op->ttl, txn->commit_seq, op->is_delete) != 0)
            {
                return TDB_ERR_MEMORY;
            }
        }
        return TDB_SUCCESS;
    }

    int used_slot_count = 0;
    /* we build hash table from newest to oldest (reverse order) */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        const tidesdb_txn_op_t *op = &txn->ops[i];
        if (op->cf != cf) continue;

        const uint32_t hash = XXH32(op->key, op->key_size, TDB_TXN_HASH_SEED);
        int slot = (int)(hash % (uint32_t)dedup_hash_size);

        /* we utilize linear probing to find empty slot or matching key */
        int inserted = 0;
        int is_duplicate = 0;
        for (int probe = 0; probe < dedup_hash_size; probe++)
        {
            if (dedup_hash[slot].key == NULL)
            {
                dedup_hash[slot].key = op->key;
                dedup_hash[slot].key_size = op->key_size;
                dedup_hash[slot].op_idx = i;
                inserted = 1;
                if (used_slots && used_slot_count < used_slots_capacity)
                {
                    used_slots[used_slot_count++] = slot;
                }
                break;
            }
            if (dedup_hash[slot].key_size == op->key_size &&
                memcmp(dedup_hash[slot].key, op->key, op->key_size) == 0)
            {
                is_duplicate = 1;
                break;
            }
            slot = (slot + 1) % dedup_hash_size;
        }

        if (!inserted && !is_duplicate)
        {
            if (skip_list_put_with_seq(memtable, op->key, op->key_size, op->value, op->value_size,
                                       op->ttl, txn->commit_seq, op->is_delete) != 0)
            {
                free(dedup_hash);
                free(used_slots);
                return TDB_ERR_MEMORY;
            }
        }
    }

    int result = TDB_SUCCESS;
    const int dedup_count = used_slots ? used_slot_count : cf_op_count;

    if (dedup_count >= TDB_MAX_TXN_OPS_BEFORE_BATCH)
    {
        /* we use batch put for better performance */
        skip_list_batch_entry_t *batch_entries =
            malloc(dedup_count * sizeof(skip_list_batch_entry_t));
        if (!batch_entries)
        {
            free(dedup_hash);
            free(used_slots);
            return TDB_ERR_MEMORY;
        }

        int batch_idx = 0;
        if (used_slots && used_slot_count > 0)
        {
            for (int i = 0; i < used_slot_count; i++)
            {
                const int slot = used_slots[i];
                const tidesdb_txn_op_t *op = &txn->ops[dedup_hash[slot].op_idx];
                batch_entries[batch_idx].key = op->key;
                batch_entries[batch_idx].key_size = op->key_size;
                batch_entries[batch_idx].value = op->value;
                batch_entries[batch_idx].value_size = op->value_size;
                batch_entries[batch_idx].ttl = op->ttl;
                batch_entries[batch_idx].seq = txn->commit_seq;
                batch_entries[batch_idx].deleted = op->is_delete;
                batch_idx++;
            }
        }
        else
        {
            for (int slot = 0; slot < dedup_hash_size; slot++)
            {
                if (dedup_hash[slot].key != NULL)
                {
                    const tidesdb_txn_op_t *op = &txn->ops[dedup_hash[slot].op_idx];
                    batch_entries[batch_idx].key = op->key;
                    batch_entries[batch_idx].key_size = op->key_size;
                    batch_entries[batch_idx].value = op->value;
                    batch_entries[batch_idx].value_size = op->value_size;
                    batch_entries[batch_idx].ttl = op->ttl;
                    batch_entries[batch_idx].seq = txn->commit_seq;
                    batch_entries[batch_idx].deleted = op->is_delete;
                    batch_idx++;
                }
            }
        }

        if (skip_list_put_batch(memtable, batch_entries, batch_idx) < 0)
        {
            result = TDB_ERR_MEMORY;
        }
        free(batch_entries);
    }
    else if (used_slots && used_slot_count > 0)
    {
        for (int i = 0; i < used_slot_count; i++)
        {
            const int slot = used_slots[i];
            const tidesdb_txn_op_t *op = &txn->ops[dedup_hash[slot].op_idx];
            if (skip_list_put_with_seq(memtable, op->key, op->key_size, op->value, op->value_size,
                                       op->ttl, txn->commit_seq, op->is_delete) != 0)
            {
                result = TDB_ERR_MEMORY;
                break;
            }
        }
    }
    else
    {
        /* we scan full table (only for very large txns) */
        for (int slot = 0; slot < dedup_hash_size; slot++)
        {
            if (dedup_hash[slot].key != NULL)
            {
                const tidesdb_txn_op_t *op = &txn->ops[dedup_hash[slot].op_idx];
                if (skip_list_put_with_seq(memtable, op->key, op->key_size, op->value,
                                           op->value_size, op->ttl, txn->commit_seq,
                                           op->is_delete) != 0)
                {
                    result = TDB_ERR_MEMORY;
                    break;
                }
            }
        }
    }

    free(dedup_hash);
    free(used_slots);
    return result;
}

/**
 * tidesdb_txn_serialize_wal
 * serialize a transaction's WAL batch for a column family
 * @param txn transaction to serialize
 * @param cf column family to serialize for
 * @param out_size output parameter for serialized size
 * @return serialized WAL batch
 */
static uint8_t *tidesdb_txn_serialize_wal(const tidesdb_txn_t *txn,
                                          const tidesdb_column_family_t *cf, size_t *out_size)
{
    /*** single-pass serialization with pre-sized buffer
     ** we estimate size based on average entry overhead + actual key/value sizes
     ** overhead per entry -- flags(1) + varints(~15 max) + ttl(8 optional) = ~24 bytes max */
    size_t estimated_size = 0;
    int cf_op_count = 0;

    /* we do a quick scan to count ops and estimate size */
    for (int i = 0; i < txn->num_ops; i++)
    {
        const tidesdb_txn_op_t *op = &txn->ops[i];
        if (op->cf == cf)
        {
            cf_op_count++;
            estimated_size += 24 + op->key_size + op->value_size;
        }
    }

    if (cf_op_count == 0)
    {
        *out_size = 0;
        return NULL;
    }

    uint8_t *wal_batch = malloc(estimated_size);
    if (!wal_batch)
    {
        *out_size = estimated_size; /* signal alloc failure */
        return NULL;
    }

    uint8_t *wal_ptr = wal_batch;

    /* we write operations directly */
    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_txn_op_t *op = &txn->ops[i];
        if (op->cf != cf) continue;

        uint8_t flags = op->is_delete ? TDB_KV_FLAG_TOMBSTONE : 0;
        if (op->ttl != 0) flags |= TDB_KV_FLAG_HAS_TTL;
        *wal_ptr++ = flags;

        wal_ptr += encode_varint(wal_ptr, op->key_size);
        wal_ptr += encode_varint(wal_ptr, op->value_size);
        wal_ptr += encode_varint(wal_ptr, txn->commit_seq);

        if (op->ttl != 0)
        {
            encode_int64_le_compat(wal_ptr, op->ttl);
            wal_ptr += sizeof(int64_t);
        }

        memcpy(wal_ptr, op->key, op->key_size);
        wal_ptr += op->key_size;

        if (op->value_size > 0 && op->value)
        {
            memcpy(wal_ptr, op->value, op->value_size);
            wal_ptr += op->value_size;
        }
    }

    *out_size = (size_t)(wal_ptr - wal_batch);
    return wal_batch;
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* validate */
    if (txn->num_ops > 0)
    {
        if (txn->num_cfs <= 0 || txn->num_ops > TDB_MAX_TXN_OPS) return TDB_ERR_INVALID_ARGS;
    }

    /* read-only fast path */
    if (txn->num_ops == 0 && txn->isolation_level < TDB_ISOLATION_REPEATABLE_READ)
    {
        txn->is_committed = 1;
        return TDB_SUCCESS;
    }

    int result = tidesdb_txn_check_read_conflicts(txn);
    if (result != TDB_SUCCESS) return result;

    result = tidesdb_txn_check_write_conflicts(txn);
    if (result != TDB_SUCCESS) return result;

    result = tidesdb_txn_check_ssi_conflicts(txn);
    if (result != TDB_SUCCESS) return result;

    txn->commit_seq = atomic_fetch_add_explicit(&txn->db->global_seq, 1, memory_order_relaxed);
    tidesdb_commit_status_mark(txn->db->commit_status, txn->commit_seq,
                               TDB_COMMIT_STATUS_IN_PROGRESS);

    const size_t alloc_size = txn->num_cfs > 0 ? txn->num_cfs : 1;
    tidesdb_memtable_t **cf_memtables = calloc(alloc_size, sizeof(tidesdb_memtable_t *));
    skip_list_t **cf_skiplists = calloc(alloc_size, sizeof(skip_list_t *));
    if (!cf_memtables || !cf_skiplists)
    {
        free(cf_memtables);
        free(cf_skiplists);
        return TDB_ERR_MEMORY;
    }

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];
        tidesdb_memtable_t *mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

        if (mt) atomic_fetch_add_explicit(&mt->refcount, 1, memory_order_acq_rel);
        cf_memtables[cf_idx] = mt;
        cf_skiplists[cf_idx] = mt ? mt->skip_list : NULL;

        size_t wal_size = 0;
        uint8_t *wal_batch = tidesdb_txn_serialize_wal(txn, cf, &wal_size);

        if (!wal_batch)
        {
            if (wal_size > 0)
            {
                /* allocation failed */
                goto cleanup_error_memory;
            }
            continue;
        }

        block_manager_t *wal = mt ? mt->wal : NULL;
        if (wal)
        {
            block_manager_block_t *wal_block = block_manager_block_create(wal_size, wal_batch);
            if (!wal_block)
            {
                free(wal_batch);
                goto cleanup_error_memory;
            }

            int64_t wal_result = block_manager_block_write(wal, wal_block);
            block_manager_block_release(wal_block);
            if (wal_result < 0)
            {
                free(wal_batch);
                goto cleanup_error_io;
            }
        }

        free(wal_batch);
    }

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_memtable_t *mt = cf_memtables[cf_idx];
        if (!mt) continue;

        tidesdb_column_family_t *cf = txn->cfs[cf_idx];
        skip_list_t *memtable = cf_skiplists[cf_idx];

        result = tidesdb_txn_apply_ops_to_memtable(txn, cf, memtable);
        if (result != TDB_SUCCESS)
        {
            goto cleanup_error_result;
        }

        const size_t memtable_size = (size_t)skip_list_get_size(memtable);
        const size_t flush_threshold =
            cf->config.write_buffer_size + (cf->config.write_buffer_size / 4);
        const int needs_flush = (memtable_size >= flush_threshold);

        atomic_fetch_sub_explicit(&mt->refcount, 1, memory_order_release);
        cf_memtables[cf_idx] = NULL; /* mark as released */

        if (needs_flush)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    free(cf_memtables);
    free(cf_skiplists);

    txn->is_committed = 1;
    atomic_thread_fence(memory_order_seq_cst);
    tidesdb_commit_status_mark(txn->db->commit_status, txn->commit_seq,
                               TDB_COMMIT_STATUS_COMMITTED);
    tidesdb_txn_remove_from_active_list(txn);

    return TDB_SUCCESS;

cleanup_error_memory:
    result = TDB_ERR_MEMORY;
    goto cleanup;

cleanup_error_io:
    result = TDB_ERR_IO;
    goto cleanup;

cleanup_error_result:
    /* result already set */
    goto cleanup;

cleanup:
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (cf_memtables[i])
        {
            atomic_fetch_sub_explicit(&cf_memtables[i]->refcount, 1, memory_order_release);
        }
    }
    free(cf_memtables);
    free(cf_skiplists);
    return result;
}

int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* we check if savepoint with this name already exists */
    for (int i = 0; i < txn->num_savepoints; i++)
    {
        if (strcmp(txn->savepoint_names[i], name) == 0)
        {
            /* we update existing savepoint */
            tidesdb_txn_t *old_sp = txn->savepoints[i];

            tidesdb_txn_t *savepoint = calloc(1, sizeof(tidesdb_txn_t));
            if (!savepoint) return TDB_ERR_MEMORY;

            savepoint->ops_capacity = txn->num_ops + 16;
            savepoint->ops = malloc(savepoint->ops_capacity * sizeof(tidesdb_txn_op_t));
            if (!savepoint->ops)
            {
                free(savepoint);
                return TDB_ERR_MEMORY;
            }

            for (int j = 0; j < txn->num_ops; j++)
            {
                savepoint->ops[j].key = malloc(txn->ops[j].key_size);
                if (savepoint->ops[j].key)
                {
                    memcpy(savepoint->ops[j].key, txn->ops[j].key, txn->ops[j].key_size);
                }
                savepoint->ops[j].key_size = txn->ops[j].key_size;

                if (txn->ops[j].value_size > 0)
                {
                    savepoint->ops[j].value = malloc(txn->ops[j].value_size);
                    if (savepoint->ops[j].value)
                    {
                        memcpy(savepoint->ops[j].value, txn->ops[j].value, txn->ops[j].value_size);
                    }
                }
                savepoint->ops[j].value_size = txn->ops[j].value_size;
                savepoint->ops[j].ttl = txn->ops[j].ttl;
                savepoint->ops[j].is_delete = txn->ops[j].is_delete;
                savepoint->ops[j].cf = txn->ops[j].cf;
            }
            savepoint->num_ops = txn->num_ops;

            if (old_sp)
            {
                tidesdb_txn_free(old_sp);
            }
            txn->savepoints[i] = savepoint;

            return TDB_SUCCESS;
        }
    }

    if (txn->num_savepoints >= txn->savepoints_capacity)
    {
        const int new_capacity = txn->savepoints_capacity == 0 ? 4 : txn->savepoints_capacity * 2;
        tidesdb_txn_t **new_savepoints =
            realloc(txn->savepoints, new_capacity * sizeof(tidesdb_txn_t *));
        char **new_names = realloc(txn->savepoint_names, new_capacity * sizeof(char *));
        if (!new_savepoints || !new_names)
        {
            free(new_savepoints);
            free(new_names);
            return TDB_ERR_MEMORY;
        }
        txn->savepoints = new_savepoints;
        txn->savepoint_names = new_names;
        txn->savepoints_capacity = new_capacity;
    }

    /* we create child transaction */
    tidesdb_txn_t *savepoint = calloc(1, sizeof(tidesdb_txn_t));
    if (!savepoint) return TDB_ERR_MEMORY;

    savepoint->db = txn->db;
    savepoint->txn_id = txn->txn_id;

    savepoint->snapshot_seq = txn->snapshot_seq;
    savepoint->commit_seq = txn->commit_seq;

    savepoint->num_cfs = txn->num_cfs;
    savepoint->cf_capacity = txn->num_cfs;
    if (txn->num_cfs > 0)
    {
        savepoint->cfs = malloc(txn->num_cfs * sizeof(tidesdb_column_family_t *));
        if (!savepoint->cfs)
        {
            free(savepoint->cfs);
            free(savepoint);
            return TDB_ERR_MEMORY;
        }
        memcpy(savepoint->cfs, txn->cfs, txn->num_cfs * sizeof(tidesdb_column_family_t *));
    }

    /* we copy current operations as baseline */
    savepoint->ops_capacity = txn->num_ops + 16;
    savepoint->ops = malloc(savepoint->ops_capacity * sizeof(tidesdb_txn_op_t));
    if (!savepoint->ops)
    {
        free(savepoint);
        return TDB_ERR_MEMORY;
    }

    for (int i = 0; i < txn->num_ops; i++)
    {
        savepoint->ops[i].key = malloc(txn->ops[i].key_size);
        if (savepoint->ops[i].key)
        {
            memcpy(savepoint->ops[i].key, txn->ops[i].key, txn->ops[i].key_size);
        }
        savepoint->ops[i].key_size = txn->ops[i].key_size;

        if (txn->ops[i].value_size > 0)
        {
            savepoint->ops[i].value = malloc(txn->ops[i].value_size);
            if (savepoint->ops[i].value)
            {
                memcpy(savepoint->ops[i].value, txn->ops[i].value, txn->ops[i].value_size);
            }
        }
        savepoint->ops[i].value_size = txn->ops[i].value_size;
        savepoint->ops[i].ttl = txn->ops[i].ttl;
        savepoint->ops[i].is_delete = txn->ops[i].is_delete;
        savepoint->ops[i].cf = txn->ops[i].cf;
    }
    savepoint->num_ops = txn->num_ops;

    /* we store savepoint with name */
    txn->savepoints[txn->num_savepoints] = savepoint;
    txn->savepoint_names[txn->num_savepoints] = tdb_strdup(name);
    if (!txn->savepoint_names[txn->num_savepoints])
    {
        free(savepoint->ops);
        free(savepoint);
        return TDB_ERR_MEMORY;
    }
    txn->num_savepoints++;

    return TDB_SUCCESS;
}

int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name || txn->num_savepoints == 0 || txn->is_committed || txn->is_aborted)
        return TDB_ERR_INVALID_ARGS;

    int savepoint_idx = -1;
    for (int i = 0; i < txn->num_savepoints; i++)
    {
        if (strcmp(txn->savepoint_names[i], name) == 0)
        {
            savepoint_idx = i;
            break;
        }
    }

    if (savepoint_idx == -1) return TDB_ERR_NOT_FOUND;

    tidesdb_txn_t *savepoint = txn->savepoints[savepoint_idx];

    for (int i = savepoint->num_ops; i < txn->num_ops; i++)
    {
        free(txn->ops[i].key);
        free(txn->ops[i].value);
    }

    /* restore operations from savepoint (deep copy back) */
    for (int i = 0; i < savepoint->num_ops; i++)
    {
        free(txn->ops[i].key);
        free(txn->ops[i].value);

        txn->ops[i].key = malloc(savepoint->ops[i].key_size);
        if (txn->ops[i].key)
        {
            memcpy(txn->ops[i].key, savepoint->ops[i].key, savepoint->ops[i].key_size);
        }
        txn->ops[i].key_size = savepoint->ops[i].key_size;

        if (savepoint->ops[i].value_size > 0)
        {
            txn->ops[i].value = malloc(savepoint->ops[i].value_size);
            if (txn->ops[i].value)
            {
                memcpy(txn->ops[i].value, savepoint->ops[i].value, savepoint->ops[i].value_size);
            }
        }
        else
        {
            txn->ops[i].value = NULL;
        }
        txn->ops[i].value_size = savepoint->ops[i].value_size;
        txn->ops[i].ttl = savepoint->ops[i].ttl;
        txn->ops[i].is_delete = savepoint->ops[i].is_delete;
        txn->ops[i].cf = savepoint->ops[i].cf;
    }

    /* we restore operation count */
    txn->num_ops = savepoint->num_ops;

    /* we remove all savepoints from savepoint_idx onwards (invalidate later savepoints) */
    for (int i = savepoint_idx; i < txn->num_savepoints; i++)
    {
        tidesdb_txn_free(txn->savepoints[i]);
        free(txn->savepoint_names[i]);
    }
    txn->num_savepoints = savepoint_idx;

    return TDB_SUCCESS;
}

int tidesdb_txn_release_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name || txn->num_savepoints == 0 || txn->is_committed || txn->is_aborted)
        return TDB_ERR_INVALID_ARGS;

    /* we find savepoint by name */
    int savepoint_idx = -1;
    for (int i = 0; i < txn->num_savepoints; i++)
    {
        if (strcmp(txn->savepoint_names[i], name) == 0)
        {
            savepoint_idx = i;
            break;
        }
    }

    if (savepoint_idx == -1) return TDB_ERR_NOT_FOUND;

    /* we free the savepoint without rolling back */
    tidesdb_txn_free(txn->savepoints[savepoint_idx]);
    free(txn->savepoint_names[savepoint_idx]);

    /* we shift remaining savepoints down */
    for (int i = savepoint_idx; i < txn->num_savepoints - 1; i++)
    {
        txn->savepoints[i] = txn->savepoints[i + 1];
        txn->savepoint_names[i] = txn->savepoint_names[i + 1];
    }
    txn->num_savepoints--;

    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_kv_visible
 * check if a KV pair should be visible to the iterator based on:
 *  isolation level
 *  TTL expiration
 *  tombstone flag
 * @param iter iterator
 * @param kv KV pair
 * @return 1 if visible, 0 if should be skipped, -1 if tombstone (skip all versions of this key)
 */
static int tidesdb_iter_kv_visible(tidesdb_iter_t *iter, tidesdb_kv_pair_t *kv)
{
    if (!iter || !kv) return 0;

    /* we check sequence visibility first (before tombstone check)
     * entries from our own transaction write buffer use seq=UINT64_MAX
     * these are always visible to the owning transaction (read-your-own-writes) */
    const int seq_visible = (kv->entry.seq == UINT64_MAX) || (kv->entry.seq <= iter->cf_snapshot);

    if (!seq_visible)
    {
        return 0; /* not visible due to isolation level */
    }

    /* we now check if it's a tombstone -- if visible tombstone, return -1 to signal
     * that all versions of this key should be skipped */
    if (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
    {
        return -1; /* tombstone -- we skip all versions of this key */
    }

    if (kv->entry.ttl > 0 && kv->entry.ttl < iter->snapshot_time)
    {
        return 0;
    }

    return 1;
}

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter)
{
    if (!txn || !cf || !iter) return TDB_ERR_INVALID_ARGS;

    const int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    *iter = calloc(1, sizeof(tidesdb_iter_t));
    if (!*iter) return TDB_ERR_MEMORY;

    (*iter)->cf = cf;
    (*iter)->txn = txn;
    (*iter)->valid = 0;
    (*iter)->direction = 0;
    (*iter)->snapshot_time = atomic_load(&txn->db->cached_current_time);
    (*iter)->cached_sources = NULL;
    (*iter)->num_cached_sources = 0;
    (*iter)->cached_sources_capacity = 0;
    (*iter)->cached_layout_version =
        atomic_load_explicit(&cf->sstable_layout_version, memory_order_acquire);

    /* we create merge heap for this CF */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    (*iter)->heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
    if (!(*iter)->heap)
    {
        free(*iter);
        return TDB_ERR_MEMORY;
    }

    size_t imm_count = 0;
    tidesdb_immutable_memtable_t **imm_snapshot =
        tidesdb_snapshot_immutable_memtables(cf->immutable_memtables, &imm_count);

    /* we now load active memtable -- any keys that rotated are already in our snapshot */
    tidesdb_memtable_t *active_mt_struct =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;

    /* memory fence ensures consistent view */
    atomic_thread_fence(memory_order_acquire);

    if (txn->isolation_level == TDB_ISOLATION_READ_COMMITTED)
    {
        uint64_t current_seq = atomic_load_explicit(&cf->db->global_seq, memory_order_acquire);
        (*iter)->cf_snapshot = (current_seq > 0) ? current_seq - 1 : 0;
    }
    else
    {
        (*iter)->cf_snapshot = txn->snapshot_seq;
    }

    tidesdb_merge_source_t *memtable_source =
        tidesdb_merge_source_from_memtable(active_mt, &cf->config, active_mt_struct);
    if (memtable_source && memtable_source->current_kv != NULL)
    {
        if (tidesdb_merge_heap_add_source((*iter)->heap, memtable_source) != TDB_SUCCESS)
        {
            tidesdb_merge_source_free(memtable_source);
        }
    }
    else if (memtable_source)
    {
        tidesdb_merge_source_free(memtable_source);
    }

    /* we add transaction write buffer as a merge source for read-your-own-ops
     * this allows iterators to see uncommitted puts/deletes from the owning txn */
    if (txn->num_ops > 0)
    {
        tidesdb_merge_source_t *txn_ops_source =
            tidesdb_merge_source_from_txn_ops(txn, cf, &cf->config);
        if (txn_ops_source && txn_ops_source->current_kv != NULL)
        {
            if (tidesdb_merge_heap_add_source((*iter)->heap, txn_ops_source) != TDB_SUCCESS)
            {
                tidesdb_merge_source_free(txn_ops_source);
            }
        }
        else if (txn_ops_source)
        {
            tidesdb_merge_source_free(txn_ops_source);
        }
    }

    /* we add immutables from our snapshot to merge heap */
    if (imm_snapshot)
    {
        for (size_t i = 0; i < imm_count; i++)
        {
            tidesdb_immutable_memtable_t *imm = imm_snapshot[i];
            if (imm && imm->skip_list)
            {
                /* tidesdb_merge_source_from_memtable will take its own ref */
                tidesdb_merge_source_t *source =
                    tidesdb_merge_source_from_memtable(imm->skip_list, &cf->config, imm);
                if (source && source->current_kv != NULL)
                {
                    if (tidesdb_merge_heap_add_source((*iter)->heap, source) != TDB_SUCCESS)
                    {
                        tidesdb_merge_source_free(source);
                    }
                }
                else if (source)
                {
                    tidesdb_merge_source_free(source);
                }

                tidesdb_immutable_memtable_unref(imm);
            }
        }
        free(imm_snapshot);
    }

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    int ssts_capacity = TDB_STACK_SSTS;
    tidesdb_sstable_t **ssts_array = malloc(ssts_capacity * sizeof(tidesdb_sstable_t *));
    int sst_count = 0;

    if (ssts_array)
    {
        /* iterate through levels and take refs immediately to minimize race window */
        for (int i = 0; i < num_levels; i++)
        {
            tidesdb_level_t *level = cf->levels[i];

        retry_level:;
            /* we load array pointer and count with careful ordering to handle concurrent
             * modifications re-load count to detect concurrent remove, use minimum to avoid OOB */
            tidesdb_sstable_t **sstables =
                atomic_load_explicit(&level->sstables, memory_order_acquire);
            int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

            /* re-load count to detect concurrent remove */
            int num_ssts_recheck = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
            if (num_ssts_recheck < num_ssts) num_ssts = num_ssts_recheck;

            /* verify array hasnt changed (handles add-with-resize race) */
            tidesdb_sstable_t **sstables_check =
                atomic_load_explicit(&level->sstables, memory_order_acquire);
            if (sstables_check != sstables)
            {
                sstables = sstables_check;
                num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
            }

            /* we track how many refs we had before this level to allow rollback on retry */
            const int sst_count_before_level = sst_count;

            /* we take refs on all sstables in this level immediately in tight loop
             * this minimizes window where compaction could free the array */
            int need_retry = 0;
            for (int j = 0; j < num_ssts; j++)
            {
                /* we check if array changed before accessing -- if so, our sstables pointer is
                 * stale
                 */
                tidesdb_sstable_t **current_arr =
                    atomic_load_explicit(&level->sstables, memory_order_acquire);
                if (current_arr != sstables)
                {
                    /* the array was swapped, release refs and retry with new array */
                    for (int k = sst_count_before_level; k < sst_count; k++)
                    {
                        tidesdb_sstable_unref(cf->db, ssts_array[k]);
                    }
                    sst_count = sst_count_before_level;
                    need_retry = 1;
                    break;
                }

                tidesdb_sstable_t *sst = sstables[j];
                if (!sst) continue;

                if (sst_count >= ssts_capacity)
                {
                    int new_capacity = ssts_capacity * 2;
                    tidesdb_sstable_t **new_array =
                        realloc(ssts_array, new_capacity * sizeof(tidesdb_sstable_t *));
                    if (!new_array)
                    {
                        /* we cleanup refs taken so far */
                        for (int k = 0; k < sst_count; k++)
                        {
                            tidesdb_sstable_unref(cf->db, ssts_array[k]);
                        }
                        free(ssts_array);
                        ssts_array = NULL;
                        break;
                    }
                    ssts_array = new_array;
                    ssts_capacity = new_capacity;
                }

                /* we try to acquire reference to protect against concurrent deletion
                 * if try_ref fails, the sstable is being freed by compaction
                 * we must retry the entire level to get the updated array with new merged sstable
                 */
                if (!tidesdb_sstable_try_ref(sst))
                {
                    /* release refs acquired for this level and retry */
                    for (int k = sst_count_before_level; k < sst_count; k++)
                    {
                        tidesdb_sstable_unref(cf->db, ssts_array[k]);
                    }
                    sst_count = sst_count_before_level;
                    need_retry = 1;
                    break;
                }
                ssts_array[sst_count++] = sst;
            }

            if (!ssts_array) break; /* allocation failed */
            if (need_retry) goto retry_level;
        }
    }

    /* cache sst sources for reuse across seeks */
    if (ssts_array)
    {
        (*iter)->cached_sources_capacity = sst_count;
        (*iter)->cached_sources = malloc(sst_count * sizeof(tidesdb_merge_source_t *));
        if (!(*iter)->cached_sources)
        {
            for (int i = 0; i < sst_count; i++)
            {
                tidesdb_sstable_unref(cf->db, ssts_array[i]);
            }
            free(ssts_array);
            tidesdb_merge_heap_free((*iter)->heap);
            free(*iter);
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < sst_count; i++)
        {
            tidesdb_sstable_t *sst = ssts_array[i];

            tidesdb_merge_source_t *sst_source = tidesdb_merge_source_from_sstable(cf->db, sst);
            if (sst_source)
            {
                /* we mark as cached so it wont be freed when popped from heap */
                sst_source->is_cached = 1;

                /* we cache the source for reuse */
                (*iter)->cached_sources[(*iter)->num_cached_sources++] = sst_source;

                /* we add to heap if it has initial data */
                if (sst_source->current_kv != NULL)
                {
                    if (tidesdb_merge_heap_add_source((*iter)->heap, sst_source) != TDB_SUCCESS)
                    {
                        /* source is still cached, just not in heap initially */
                    }
                }
            }

            tidesdb_sstable_unref(cf->db, sst);
        }

        free(ssts_array);
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_rebuild_sst_cache
 * rebuild cached sstable sources when sstable layout has changed
 * @param iter the iterator
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_iter_rebuild_sst_cache(tidesdb_iter_t *iter)
{
    tidesdb_column_family_t *cf = iter->cf;

    /* we clear heap first to remove references to cached sources */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        if (!iter->heap->sources[i]->is_cached)
        {
            tidesdb_merge_source_free(iter->heap->sources[i]);
        }
    }
    iter->heap->num_sources = 0;

    /* we invalidate cached sources */
    for (int i = 0; i < iter->num_cached_sources; i++)
    {
        tidesdb_merge_source_free(iter->cached_sources[i]);
    }
    iter->num_cached_sources = 0;
    iter->cached_layout_version =
        atomic_load_explicit(&cf->sstable_layout_version, memory_order_acquire);

    /* we collect all sstables with references */
    tidesdb_sstable_t **ssts_array = NULL;
    int sst_count = 0;
    const int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    for (int lvl = 0; lvl < num_levels; lvl++)
    {
        tidesdb_level_t *level = cf->levels[lvl];
        if (!level) continue;

    retry_level:;
        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        const int num_ssts_recheck =
            atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        if (num_ssts_recheck < num_ssts) num_ssts = num_ssts_recheck;

        tidesdb_sstable_t **sstables_check =
            atomic_load_explicit(&level->sstables, memory_order_acquire);
        if (sstables_check != sstables)
        {
            sstables = sstables_check;
            num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        }
        if (num_ssts == 0) continue;

        const int sst_count_before_level = sst_count;
        int need_retry = 0;

        for (int j = 0; j < num_ssts; j++)
        {
            tidesdb_sstable_t **current_arr =
                atomic_load_explicit(&level->sstables, memory_order_acquire);
            if (current_arr != sstables)
            {
                for (int k = sst_count_before_level; k < sst_count; k++)
                    tidesdb_sstable_unref(cf->db, ssts_array[k]);
                sst_count = sst_count_before_level;
                need_retry = 1;
                break;
            }

            tidesdb_sstable_t *sst = sstables[j];
            if (sst)
            {
                if (!tidesdb_sstable_try_ref(sst))
                {
                    for (int k = sst_count_before_level; k < sst_count; k++)
                        tidesdb_sstable_unref(cf->db, ssts_array[k]);
                    sst_count = sst_count_before_level;
                    need_retry = 1;
                    break;
                }

                tidesdb_sstable_t **new_array =
                    realloc(ssts_array, (sst_count + 1) * sizeof(tidesdb_sstable_t *));
                if (!new_array)
                {
                    tidesdb_sstable_unref(cf->db, sst);
                    for (int k = 0; k < sst_count; k++)
                        tidesdb_sstable_unref(cf->db, ssts_array[k]);
                    free(ssts_array);
                    return TDB_ERR_MEMORY;
                }
                ssts_array = new_array;
                ssts_array[sst_count++] = sst;
            }
        }

        if (need_retry) goto retry_level;
    }

    if (!ssts_array) return TDB_SUCCESS;

    /* we create cached sources from collected sstables */
    if (!iter->cached_sources || iter->cached_sources_capacity < sst_count)
    {
        void **new_cached = realloc(iter->cached_sources, sst_count * sizeof(void *));
        if (!new_cached)
        {
            for (int k = 0; k < sst_count; k++) tidesdb_sstable_unref(cf->db, ssts_array[k]);
            free(ssts_array);
            return TDB_ERR_MEMORY;
        }
        iter->cached_sources = new_cached;
        iter->cached_sources_capacity = sst_count;
    }

    for (int i = 0; i < sst_count; i++)
    {
        tidesdb_sstable_t *sst = ssts_array[i];
        tidesdb_merge_source_t *sst_source = tidesdb_merge_source_from_sstable(cf->db, sst);
        if (sst_source)
        {
            sst_source->is_cached = 1;
            iter->cached_sources[iter->num_cached_sources++] = sst_source;
        }
        tidesdb_sstable_unref(cf->db, sst);
    }
    free(ssts_array);

    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_collect_memtable_sources
 * collect sources from active and immutable memtables
 * @param iter the iterator
 * @param sources output array of sources
 * @param count output count of sources
 * @param capacity output capacity of sources array
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_iter_collect_memtable_sources(const tidesdb_iter_t *iter,
                                                 tidesdb_merge_source_t ***sources, int *count,
                                                 int *capacity)
{
    tidesdb_column_family_t *cf = iter->cf;

    *sources = malloc(16 * sizeof(tidesdb_merge_source_t *));
    if (!*sources) return TDB_ERR_MEMORY;
    *count = 0;
    *capacity = 16;

    /* we collect active memtable source */
    tidesdb_memtable_t *active_mt_struct =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;

    tidesdb_merge_source_t *memtable_source =
        tidesdb_merge_source_from_memtable(active_mt, &cf->config, active_mt_struct);
    if (memtable_source)
    {
        (*sources)[(*count)++] = memtable_source;
    }

    /* we snapshot immutable memtables */
    size_t imm_snapshot_count = 0;
    tidesdb_immutable_memtable_t **imm_snapshot =
        tidesdb_snapshot_immutable_memtables(cf->immutable_memtables, &imm_snapshot_count);

    /* we create sources from snapshot */
    for (size_t i = 0; i < imm_snapshot_count; i++)
    {
        tidesdb_immutable_memtable_t *imm = imm_snapshot[i];
        if (imm->skip_list)
        {
            tidesdb_merge_source_t *source =
                tidesdb_merge_source_from_memtable(imm->skip_list, &cf->config, imm);
            if (source)
            {
                if (*count >= *capacity)
                {
                    *capacity *= 2;
                    tidesdb_merge_source_t **new_sources =
                        realloc(*sources, *capacity * sizeof(tidesdb_merge_source_t *));
                    if (!new_sources)
                    {
                        tidesdb_merge_source_free(source);
                        for (int j = 0; j < *count; j++) tidesdb_merge_source_free((*sources)[j]);
                        for (size_t k = i; k < imm_snapshot_count; k++)
                            tidesdb_immutable_memtable_unref(imm_snapshot[k]);
                        free(imm_snapshot);
                        free(*sources);
                        *sources = NULL;
                        return TDB_ERR_MEMORY;
                    }
                    *sources = new_sources;
                }
                (*sources)[(*count)++] = source;
            }
        }
        tidesdb_immutable_memtable_unref(imm);
    }
    free(imm_snapshot);

    /* we add transaction write buffer source for read-your-own-writes on re-seek */
    if (iter->txn && iter->txn->num_ops > 0)
    {
        tidesdb_merge_source_t *txn_ops_source =
            tidesdb_merge_source_from_txn_ops(iter->txn, cf, &cf->config);
        if (txn_ops_source)
        {
            if (*count >= *capacity)
            {
                const int new_capacity = *capacity * 2;
                tidesdb_merge_source_t **new_sources =
                    realloc(*sources, new_capacity * sizeof(tidesdb_merge_source_t *));
                if (!new_sources)
                {
                    tidesdb_merge_source_free(txn_ops_source);
                    /* dont fail the whole collect -- memtable sources are still valid */
                }
                else
                {
                    *sources = new_sources;
                    *capacity = new_capacity;
                    (*sources)[(*count)++] = txn_ops_source;
                }
            }
            else
            {
                (*sources)[(*count)++] = txn_ops_source;
            }
        }
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_add_cached_sst_sources
 * add cached sstable sources to the sources array
 * @param iter the iterator
 * @param sources sources array to add to
 * @param count current count (updated)
 * @param capacity current capacity (updated if needed)
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_iter_add_cached_sst_sources(const tidesdb_iter_t *iter,
                                               tidesdb_merge_source_t ***sources, int *count,
                                               int *capacity)
{
    for (int i = 0; i < iter->num_cached_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->cached_sources[i];
        if (*count >= *capacity)
        {
            *capacity *= 2;
            tidesdb_merge_source_t **new_sources =
                realloc(*sources, *capacity * sizeof(tidesdb_merge_source_t *));
            if (!new_sources)
            {
                for (int j = 0; j < *count; j++)
                {
                    if (!(*sources)[j]->is_cached) tidesdb_merge_source_free((*sources)[j]);
                }
                free(*sources);
                *sources = NULL;
                return TDB_ERR_MEMORY;
            }
            *sources = new_sources;
        }
        (*sources)[(*count)++] = source;
    }
    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_seek_memtable_source
 * seek a memtable source to the target key
 * @param source the memtable source
 * @param key the target key
 * @param key_size the size of the key
 * @param direction 1 for forward (>=), -1 for backward (<=)
 */
static void tidesdb_iter_seek_memtable_source(tidesdb_merge_source_t *source, const uint8_t *key,
                                              const size_t key_size, const int direction)
{
    skip_list_cursor_t *cursor = source->source.memtable.cursor;

    if (direction > 0)
    {
        /* forward seek -- find first entry >= key
         * skip_list_cursor_seek positions at node before target, must call next */
        if (skip_list_cursor_seek(cursor, (uint8_t *)key, key_size) == 0)
        {
            if (skip_list_cursor_next(cursor) == 0)
            {
                uint8_t *k, *v;
                size_t k_size, v_size;
                int64_t ttl;
                uint8_t deleted;
                uint64_t seq;

                if (skip_list_cursor_get_with_seq(cursor, &k, &k_size, &v, &v_size, &ttl, &deleted,
                                                  &seq) == 0)
                {
                    source->current_kv =
                        tidesdb_kv_pair_create(k, k_size, v, v_size, ttl, seq, deleted);
                }
            }
        }
    }
    else
    {
        /* backward seek -- find first entry <= key
         * skip_list_cursor_seek_for_prev positions directly at target */
        if (skip_list_cursor_seek_for_prev(cursor, (uint8_t *)key, key_size) == 0)
        {
            uint8_t *k, *v;
            size_t k_size, v_size;
            int64_t ttl;
            uint8_t deleted;
            uint64_t seq;

            if (skip_list_cursor_get_with_seq(cursor, &k, &k_size, &v, &v_size, &ttl, &deleted,
                                              &seq) == 0)
            {
                source->current_kv =
                    tidesdb_kv_pair_create(k, k_size, v, v_size, ttl, seq, deleted);
            }
        }
    }
}

/**
 * tidesdb_iter_release_sst_source_block
 * release current block resources from an sstable source
 * @param source the sstable source
 */
static void tidesdb_iter_release_sst_source_block(tidesdb_merge_source_t *source)
{
    if (source->source.sstable.current_rc_block)
    {
        tidesdb_block_release(source->source.sstable.current_rc_block);
        source->source.sstable.current_rc_block = NULL;
    }
    else if (source->source.sstable.current_block)
    {
        tidesdb_klog_block_free(source->source.sstable.current_block);
    }
    source->source.sstable.current_block = NULL;

    if (source->source.sstable.decompressed_data)
    {
        free(source->source.sstable.decompressed_data);
        source->source.sstable.decompressed_data = NULL;
    }
    if (source->source.sstable.current_block_data)
    {
        block_manager_block_release(source->source.sstable.current_block_data);
        source->source.sstable.current_block_data = NULL;
    }
    source->source.sstable.current_entry_idx = 0;
}

/**
 * tidesdb_iter_read_klog_block
 * read a klog block from cache or disk
 * @param sst the sstable
 * @param cursor the block manager cursor
 * @param cf_name the column family name for cache
 * @param has_cf_name whether cf_name is valid
 * @param kb_out output klog block
 * @param rc_block_out output ref-counted block (if from cache)
 * @param bmblock_out output raw block (if from disk)
 * @param decompressed_out output decompressed data (if decompression was needed)
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_iter_read_klog_block(const tidesdb_sstable_t *sst,
                                        block_manager_cursor_t *cursor, const char *cf_name,
                                        const int has_cf_name, tidesdb_klog_block_t **kb_out,
                                        tidesdb_ref_counted_block_t **rc_block_out,
                                        block_manager_block_t **bmblock_out,
                                        uint8_t **decompressed_out)
{
    *kb_out = NULL;
    *rc_block_out = NULL;
    *bmblock_out = NULL;
    *decompressed_out = NULL;

    /* we try cache first */
    if (sst->db->clock_cache && has_cf_name)
    {
        *kb_out = tidesdb_cache_block_get(sst->db, cf_name, sst->klog_path, cursor->current_pos,
                                          rc_block_out);
        if (*kb_out) return TDB_SUCCESS;
    }

    /* we read from disk */
    block_manager_block_t *bmblock = block_manager_cursor_read(cursor);
    if (!bmblock) return TDB_ERR_IO;

    const uint8_t *data = bmblock->data;
    size_t data_size = bmblock->size;

    if (sst->config->compression_algorithm != TDB_COMPRESS_NONE)
    {
        *decompressed_out = decompress_data(bmblock->data, bmblock->size, &data_size,
                                            sst->config->compression_algorithm);
        if (*decompressed_out)
        {
            data = *decompressed_out;
        }
    }

    tidesdb_klog_block_t *kb = NULL;
    if (tidesdb_klog_block_deserialize(data, data_size, &kb) != 0 || !kb)
    {
        if (*decompressed_out) free(*decompressed_out);
        *decompressed_out = NULL;
        block_manager_block_release(bmblock);
        return TDB_ERR_CORRUPTION;
    }

    /* we cache this block */
    if (sst->db->clock_cache && has_cf_name)
    {
        tidesdb_cache_block_put(sst->db, cf_name, sst->klog_path, cursor->current_pos, data,
                                data_size);
    }

    *kb_out = kb;
    *bmblock_out = bmblock;
    return TDB_SUCCESS;
}

/**
 * tidesdb_iter_create_kv_from_block
 * create a kv pair from a klog block entry
 * @param iter the iterator
 * @param sst the sstable
 * @param kb the klog block
 * @param idx the entry index
 * @return the created kv pair, or NULL on failure
 */
static tidesdb_kv_pair_t *tidesdb_iter_create_kv_from_block(const tidesdb_iter_t *iter,
                                                            tidesdb_sstable_t *sst,
                                                            const tidesdb_klog_block_t *kb,
                                                            const int idx)
{
    const uint8_t *value = kb->inline_values[idx];
    uint8_t *vlog_value = NULL;

    if (kb->entries[idx].vlog_offset > 0)
    {
        if (tidesdb_vlog_read_value(iter->cf->db, sst, kb->entries[idx].vlog_offset,
                                    kb->entries[idx].value_size, &vlog_value) == TDB_SUCCESS)
        {
            value = vlog_value;
        }
    }

    tidesdb_kv_pair_t *kv = tidesdb_kv_pair_create(
        kb->keys[idx], kb->entries[idx].key_size, value, kb->entries[idx].value_size,
        kb->entries[idx].ttl, kb->entries[idx].seq, kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

    free(vlog_value);
    return kv;
}

/**
 * tidesdb_iter_seek_btree_source_forward
 * seek a btree source forward to find first entry >= key
 * @param source the btree source
 * @param key the target key
 * @param key_size the size of the key
 */
static void tidesdb_iter_seek_btree_source_forward(tidesdb_merge_source_t *source,
                                                   const uint8_t *key, const size_t key_size)
{
    btree_cursor_t *cursor = source->source.btree.cursor;

    tidesdb_kv_pair_free(source->current_kv);
    source->current_kv = NULL;

    if (btree_cursor_seek(cursor, key, key_size) != 0)
    {
        return;
    }

    uint8_t *found_key = NULL, *value = NULL;
    size_t found_key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    if (btree_cursor_get(cursor, &found_key, &found_key_size, &value, &value_size, &vlog_offset,
                         &seq, &ttl, &deleted) != 0)
    {
        return;
    }

    const uint8_t *actual_value = value;
    size_t actual_value_size = value_size;
    uint8_t *vlog_value = NULL;
    if (vlog_offset > 0)
    {
        block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
        block_manager_block_t *vlog_block =
            block_manager_cursor_read(source->source.btree.vlog_cursor);
        if (vlog_block)
        {
            vlog_value = malloc(vlog_block->size);
            if (vlog_value)
            {
                memcpy(vlog_value, vlog_block->data, vlog_block->size);
                actual_value = vlog_value;
                actual_value_size = vlog_block->size;
            }
            block_manager_block_free(vlog_block);
        }
    }

    source->current_kv = tidesdb_kv_pair_create(found_key, found_key_size, actual_value,
                                                actual_value_size, ttl, seq, deleted);
    free(vlog_value); /* only free vlog_value if we allocated it */
}

/**
 * tidesdb_iter_seek_btree_source_backward
 * seek a btree source backward to find last entry <= key
 * @param source the btree source
 * @param key the target key
 * @param key_size the size of the key
 */
static void tidesdb_iter_seek_btree_source_backward(tidesdb_merge_source_t *source,
                                                    const uint8_t *key, const size_t key_size)
{
    btree_cursor_t *cursor = source->source.btree.cursor;

    tidesdb_kv_pair_free(source->current_kv);
    source->current_kv = NULL;

    if (btree_cursor_seek(cursor, key, key_size) != 0)
    {
        if (btree_cursor_goto_last(cursor) != 0) return;
    }

    uint8_t *found_key = NULL, *value = NULL;
    size_t found_key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    if (btree_cursor_get(cursor, &found_key, &found_key_size, &value, &value_size, &vlog_offset,
                         &seq, &ttl, &deleted) != 0)
    {
        return;
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(source->source.btree.db, source->config, &comparator_fn,
                               &comparator_ctx);

    int cmp = comparator_fn(found_key, found_key_size, key, key_size, comparator_ctx);
    if (cmp > 0)
    {
        if (btree_cursor_prev(cursor) != 0) return;

        if (btree_cursor_get(cursor, &found_key, &found_key_size, &value, &value_size, &vlog_offset,
                             &seq, &ttl, &deleted) != 0)
        {
            return;
        }
    }

    uint8_t *actual_value = value;
    size_t actual_value_size = value_size;
    uint8_t *vlog_value = NULL;
    if (vlog_offset > 0)
    {
        block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
        block_manager_block_t *vlog_block =
            block_manager_cursor_read(source->source.btree.vlog_cursor);
        if (vlog_block)
        {
            vlog_value = malloc(vlog_block->size);
            if (vlog_value)
            {
                memcpy(vlog_value, vlog_block->data, vlog_block->size);
                actual_value = vlog_value;
                actual_value_size = vlog_block->size;
            }
            block_manager_block_free(vlog_block);
        }
    }

    source->current_kv = tidesdb_kv_pair_create(found_key, found_key_size, actual_value,
                                                actual_value_size, ttl, seq, deleted);
    free(vlog_value); /* only free vlog_value if we allocated it */
}

/**
 * tidesdb_iter_seek_sstable_source_forward
 * seek an sstable source forward to find first entry >= key
 * @param iter the iterator
 * @param source the sstable source
 * @param key the target key
 * @param key_size the size of the key
 */
static void tidesdb_iter_seek_sstable_source_forward(const tidesdb_iter_t *iter,
                                                     tidesdb_merge_source_t *source,
                                                     const uint8_t *key, const size_t key_size)
{
    tidesdb_sstable_t *sst = source->source.sstable.sst;
    block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;

    tidesdb_iter_release_sst_source_block(source);

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

    /* we use block index to find starting position */
    uint64_t block_position = 0;
    if (sst->block_indexes && sst->block_indexes->count > 0)
    {
        compact_block_index_find_predecessor(sst->block_indexes, key, key_size, &block_position);
    }

    if (block_position > 0)
    {
        block_manager_cursor_goto(cursor, block_position);
    }
    else
    {
        block_manager_cursor_goto_first(cursor);
    }

    const char *cf_name = sst->cf_name;
    const int has_cf_name = (cf_name[0] != '\0');

    int blocks_scanned = 0;

    while (blocks_scanned < TDB_ITER_SEEK_MAX_BLOCKS_SCAN)
    {
        if (sst->klog_data_end_offset > 0 && cursor->current_pos >= sst->klog_data_end_offset)
        {
            break;
        }

        tidesdb_klog_block_t *kb = NULL;
        tidesdb_ref_counted_block_t *rc_block = NULL;
        block_manager_block_t *bmblock = NULL;
        uint8_t *decompressed = NULL;

        const int read_result = tidesdb_iter_read_klog_block(sst, cursor, cf_name, has_cf_name, &kb,
                                                             &rc_block, &bmblock, &decompressed);
        if (read_result != TDB_SUCCESS)
        {
            if (block_manager_cursor_next(cursor) != 0) break;
            continue;
        }
        blocks_scanned++;

        /* we check if first key > target (first entry is the answer) */
        const int cmp_first =
            comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size, comparator_ctx);

        if (cmp_first > 0)
        {
            source->source.sstable.current_block_data = bmblock;
            source->source.sstable.current_rc_block = rc_block;
            source->source.sstable.current_block = kb;
            source->source.sstable.decompressed_data = decompressed;
            source->source.sstable.current_entry_idx = 0;
            source->current_kv = tidesdb_iter_create_kv_from_block(iter, sst, kb, 0);
            return;
        }

        /* we check if target could be in this block */
        const int cmp_last =
            comparator_fn(kb->keys[kb->num_entries - 1], kb->entries[kb->num_entries - 1].key_size,
                          key, key_size, comparator_ctx);

        if (cmp_last >= 0)
        {
            /* we binary search for first entry >= target */
            int left = 0;
            int right = (int)kb->num_entries - 1;
            int result_idx = (int)kb->num_entries;

            while (left <= right)
            {
                const int mid = left + (right - left) / 2;
                const int cmp = comparator_fn(kb->keys[mid], kb->entries[mid].key_size, key,
                                              key_size, comparator_ctx);

                if (cmp >= 0)
                {
                    result_idx = mid;
                    right = mid - 1;
                }
                else
                {
                    left = mid + 1;
                }
            }

            if ((uint32_t)result_idx < kb->num_entries)
            {
                source->source.sstable.current_block_data = bmblock;
                source->source.sstable.current_rc_block = rc_block;
                source->source.sstable.current_block = kb;
                source->source.sstable.decompressed_data = decompressed;
                source->source.sstable.current_entry_idx = result_idx;
                source->current_kv = tidesdb_iter_create_kv_from_block(iter, sst, kb, result_idx);
                return;
            }
        }

        /* we release and try next block */
        if (rc_block)
            tidesdb_block_release(rc_block);
        else
            tidesdb_klog_block_free(kb);
        if (decompressed) free(decompressed);
        if (bmblock) block_manager_block_release(bmblock);

        if (block_manager_cursor_next(cursor) != 0) break;
    }
}

/**
 * tidesdb_iter_seek_txn_ops_source
 * seek a txn ops source to the target key
 * uses binary search on the sorted index array
 * @param source the txn ops source
 * @param key the target key
 * @param key_size the size of the key
 * @param direction 1 for forward (first entry >= key), -1 for backward (last entry <= key)
 */
static void tidesdb_iter_seek_txn_ops_source(tidesdb_merge_source_t *source, const uint8_t *key,
                                             const size_t key_size, const int direction)
{
    tidesdb_txn_t *txn = source->source.txn_ops.txn;
    tidesdb_column_family_t *cf = source->source.txn_ops.cf;
    const int count = source->source.txn_ops.count;
    const int *indices = source->source.txn_ops.sorted_indices;

    /* we resolve the comparator */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);
    if (!comparator_fn) comparator_fn = tidesdb_comparator_memcmp;

    /* binary search for the target position */
    int lo = 0, hi = count;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        const tidesdb_txn_op_t *op = &txn->ops[indices[mid]];
        const int cmp = comparator_fn(op->key, op->key_size, key, key_size, comparator_ctx);
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    /* lo is now the index of the first entry >= key */

    if (direction > 0)
    {
        /* forward -- first entry >= key */
        if (lo < count)
        {
            source->source.txn_ops.pos = lo;
            const tidesdb_txn_op_t *op = &txn->ops[indices[lo]];
            source->current_kv =
                tidesdb_kv_pair_create(op->key, op->key_size, op->value, op->value_size, op->ttl,
                                       UINT64_MAX, op->is_delete);
        }
    }
    else
    {
        /* backward -- last entry <= key
         * if lo points to an exact match, use it; otherwise use lo-1 */
        int pos = lo;
        if (pos < count)
        {
            const tidesdb_txn_op_t *op = &txn->ops[indices[pos]];
            const int cmp = comparator_fn(op->key, op->key_size, key, key_size, comparator_ctx);
            if (cmp > 0) pos--;
        }
        else
        {
            pos = count - 1;
        }

        if (pos >= 0)
        {
            source->source.txn_ops.pos = pos;
            const tidesdb_txn_op_t *op = &txn->ops[indices[pos]];
            source->current_kv =
                tidesdb_kv_pair_create(op->key, op->key_size, op->value, op->value_size, op->ttl,
                                       UINT64_MAX, op->is_delete);
        }
    }
}

/**
 * tidesdb_iter_seek_sstable_source_backward
 * seek an sstable source backward to find last entry <= key
 * @param iter the iterator
 * @param source the sstable source
 * @param key the target key
 * @param key_size the size of the key
 */
static void tidesdb_iter_seek_sstable_source_backward(const tidesdb_iter_t *iter,
                                                      tidesdb_merge_source_t *source,
                                                      const uint8_t *key, const size_t key_size)
{
    tidesdb_sstable_t *sst = source->source.sstable.sst;
    block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;

    tidesdb_iter_release_sst_source_block(source);

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

    /* we use block index to find starting position */
    uint64_t block_position = 0;
    if (sst->block_indexes && sst->block_indexes->count > 0)
    {
        compact_block_index_find_predecessor(sst->block_indexes, key, key_size, &block_position);
    }

    if (block_position > 0)
    {
        block_manager_cursor_goto(cursor, block_position);
    }
    else
    {
        block_manager_cursor_goto_first(cursor);
    }

    /* we use cached CF name from sst struct to avoid repeated path parsing */
    const char *cf_name = sst->cf_name;
    const int has_cf_name = (cf_name[0] != '\0');

    tidesdb_klog_block_t *last_valid_block = NULL;
    int last_valid_idx = -1;
    block_manager_block_t *last_valid_bmblock = NULL;
    uint8_t *last_valid_decompressed = NULL;
    tidesdb_ref_counted_block_t *last_valid_rc_block = NULL;

    int blocks_scanned = 0;

    while (blocks_scanned < TDB_ITER_SEEK_MAX_BLOCKS_SCAN)
    {
        if (sst->klog_data_end_offset > 0 && cursor->current_pos >= sst->klog_data_end_offset)
        {
            break;
        }

        tidesdb_klog_block_t *kb = NULL;
        tidesdb_ref_counted_block_t *rc_block = NULL;
        block_manager_block_t *bmblock = NULL;
        uint8_t *decompressed = NULL;

        const int read_result = tidesdb_iter_read_klog_block(sst, cursor, cf_name, has_cf_name, &kb,
                                                             &rc_block, &bmblock, &decompressed);
        if (read_result != TDB_SUCCESS)
        {
            if (block_manager_cursor_next(cursor) != 0) break;
            continue;
        }
        blocks_scanned++;

        /* we check if first key > target (use previous block) */
        const int cmp_first =
            comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size, comparator_ctx);

        if (cmp_first > 0)
        {
            if (rc_block)
                tidesdb_block_release(rc_block);
            else
                tidesdb_klog_block_free(kb);
            if (decompressed) free(decompressed);
            if (bmblock) block_manager_block_release(bmblock);
            break;
        }

        /* we binary search for last entry <= target */
        int left = 0;
        int right = (int)kb->num_entries - 1;
        int result_idx = -1;

        while (left <= right)
        {
            const int mid = left + (right - left) / 2;
            const int cmp = comparator_fn(kb->keys[mid], kb->entries[mid].key_size, key, key_size,
                                          comparator_ctx);

            if (cmp <= 0)
            {
                result_idx = mid;
                left = mid + 1;
            }
            else
            {
                right = mid - 1;
            }
        }

        if (result_idx >= 0)
        {
            /* we clean up previous candidate */
            if (last_valid_rc_block)
                tidesdb_block_release(last_valid_rc_block);
            else if (last_valid_block)
                tidesdb_klog_block_free(last_valid_block);
            if (last_valid_decompressed) free(last_valid_decompressed);
            if (last_valid_bmblock) block_manager_block_release(last_valid_bmblock);

            last_valid_block = kb;
            last_valid_idx = result_idx;
            last_valid_bmblock = bmblock;
            last_valid_decompressed = decompressed;
            last_valid_rc_block = rc_block;
        }
        else
        {
            if (rc_block)
                tidesdb_block_release(rc_block);
            else
                tidesdb_klog_block_free(kb);
            if (decompressed) free(decompressed);
            if (bmblock) block_manager_block_release(bmblock);
        }

        if (block_manager_cursor_next(cursor) != 0) break;
    }

    /* we use the last valid entry we found */
    if (last_valid_block && last_valid_idx >= 0)
    {
        source->source.sstable.current_block = last_valid_block;
        source->source.sstable.current_block_data = last_valid_bmblock;
        source->source.sstable.current_rc_block = last_valid_rc_block;
        source->source.sstable.decompressed_data = last_valid_decompressed;
        source->source.sstable.current_entry_idx = last_valid_idx;
        source->current_kv =
            tidesdb_iter_create_kv_from_block(iter, sst, last_valid_block, last_valid_idx);
    }
}

/**
 * tidesdb_iter_find_visible_entry
 * find the first visible entry from the heap
 * @param iter the iterator
 * @param direction 1 for forward (min-heap), -1 for backward (max-heap)
 * @return TDB_SUCCESS if found, TDB_ERR_NOT_FOUND otherwise
 */
static int tidesdb_iter_find_visible_entry(tidesdb_iter_t *iter, const int direction)
{
    /* we rebuild heap */
    if (direction > 0)
    {
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down(iter->heap, i);
        }
    }
    else
    {
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down_max(iter->heap, i);
        }
    }

    /* we find first visible entry */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = (direction > 0) ? tidesdb_merge_heap_pop(iter->heap, NULL)
                                                : tidesdb_merge_heap_pop_max(iter->heap);
        if (!kv) break;

        const int visible = tidesdb_iter_kv_visible(iter, kv);
        if (visible == -1)
        {
            /*** tombstone -- we skip all versions of this key */
            const uint8_t *tombstone_key = kv->key;
            const size_t tombstone_key_size = kv->entry.key_size;

            /* we pop and discard all entries with the same key */
            while (!tidesdb_merge_heap_empty(iter->heap))
            {
                tidesdb_kv_pair_t *peek =
                    iter->heap->sources[0]->current_kv; /* peek at top without popping */
                if (!peek) break;

                const int cmp =
                    iter->heap->comparator(peek->key, peek->entry.key_size, tombstone_key,
                                           tombstone_key_size, iter->heap->comparator_ctx);
                if (cmp != 0) break; /* different key, stop skipping */

                /* same key, we pop and discard */
                tidesdb_kv_pair_t *dup = (direction > 0) ? tidesdb_merge_heap_pop(iter->heap, NULL)
                                                         : tidesdb_merge_heap_pop_max(iter->heap);
                tidesdb_kv_pair_free(dup);
            }

            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (visible == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, const size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = 1;

    tidesdb_column_family_t *cf = iter->cf;

    /* we check if sst layout has changed */
    const uint64_t current_version =
        atomic_load_explicit(&cf->sstable_layout_version, memory_order_acquire);
    if (current_version != iter->cached_layout_version)
    {
        const int result = tidesdb_iter_rebuild_sst_cache(iter);
        if (result != TDB_SUCCESS) return result;
    }
    else
    {
        /* we free non-cached sources that are currently in the heap */
        for (int i = 0; i < iter->heap->num_sources; i++)
        {
            if (!iter->heap->sources[i]->is_cached)
            {
                tidesdb_merge_source_free(iter->heap->sources[i]);
            }
        }
        iter->heap->num_sources = 0;
    }

    /* we collect all sources */
    tidesdb_merge_source_t **temp_sources = NULL;
    int temp_count = 0;
    int temp_capacity = 0;

    int result =
        tidesdb_iter_collect_memtable_sources(iter, &temp_sources, &temp_count, &temp_capacity);
    if (result != TDB_SUCCESS) return result;

    result = tidesdb_iter_add_cached_sst_sources(iter, &temp_sources, &temp_count, &temp_capacity);
    if (result != TDB_SUCCESS)
    {
        free(temp_sources);
        return result;
    }

    /* we reposition all sources to target key */
    for (int i = 0; i < temp_count; i++)
    {
        tidesdb_merge_source_t *source = temp_sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            tidesdb_iter_seek_memtable_source(source, key, key_size, 1);
        }
        else if (source->type == MERGE_SOURCE_BTREE)
        {
            tidesdb_iter_seek_btree_source_forward(source, key, key_size);
        }
        else if (source->type == MERGE_SOURCE_TXN_OPS)
        {
            tidesdb_iter_seek_txn_ops_source(source, key, key_size, 1);
        }
        else
        {
            tidesdb_iter_seek_sstable_source_forward(iter, source, key, key_size);
        }
    }

    /* we add all repositioned sources to heap */
    for (int i = 0; i < temp_count; i++)
    {
        tidesdb_merge_source_t *source = temp_sources[i];
        if (source->current_kv != NULL)
        {
            if (tidesdb_merge_heap_add_source(iter->heap, source) != TDB_SUCCESS)
            {
                if (!source->is_cached) tidesdb_merge_source_free(source);
            }
        }
        else
        {
            if (!source->is_cached) tidesdb_merge_source_free(source);
        }
    }
    free(temp_sources);

    return tidesdb_iter_find_visible_entry(iter, 1);
}

int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, const size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = -1;

    tidesdb_column_family_t *cf = iter->cf;

    /* we check if sst layout has changed */
    const uint64_t current_version =
        atomic_load_explicit(&cf->sstable_layout_version, memory_order_acquire);
    if (current_version != iter->cached_layout_version)
    {
        const int result = tidesdb_iter_rebuild_sst_cache(iter);
        if (result != TDB_SUCCESS) return result;
    }
    else
    {
        /* we free non-cached sources that are currently in the heap */
        for (int i = 0; i < iter->heap->num_sources; i++)
        {
            if (!iter->heap->sources[i]->is_cached)
            {
                tidesdb_merge_source_free(iter->heap->sources[i]);
            }
        }
        iter->heap->num_sources = 0;
    }

    /* we collect all sources */
    tidesdb_merge_source_t **temp_sources = NULL;
    int temp_count = 0;
    int temp_capacity = 0;

    int result =
        tidesdb_iter_collect_memtable_sources(iter, &temp_sources, &temp_count, &temp_capacity);
    if (result != TDB_SUCCESS) return result;

    result = tidesdb_iter_add_cached_sst_sources(iter, &temp_sources, &temp_count, &temp_capacity);
    if (result != TDB_SUCCESS)
    {
        free(temp_sources);
        return result;
    }

    /* we reposition all sources to target key (backward) */
    for (int i = 0; i < temp_count; i++)
    {
        tidesdb_merge_source_t *source = temp_sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            tidesdb_iter_seek_memtable_source(source, key, key_size, -1);
        }
        else if (source->type == MERGE_SOURCE_BTREE)
        {
            tidesdb_iter_seek_btree_source_backward(source, key, key_size);
        }
        else if (source->type == MERGE_SOURCE_TXN_OPS)
        {
            tidesdb_iter_seek_txn_ops_source(source, key, key_size, -1);
        }
        else
        {
            tidesdb_iter_seek_sstable_source_backward(iter, source, key, key_size);
        }
    }

    /* we add all repositioned sources to heap */
    for (int i = 0; i < temp_count; i++)
    {
        tidesdb_merge_source_t *source = temp_sources[i];
        if (source->current_kv != NULL)
        {
            if (tidesdb_merge_heap_add_source(iter->heap, source) != TDB_SUCCESS)
            {
                if (!source->is_cached) tidesdb_merge_source_free(source);
            }
        }
        else
        {
            if (!source->is_cached) tidesdb_merge_source_free(source);
        }
    }
    free(temp_sources);

    return tidesdb_iter_find_visible_entry(iter, -1);
}

int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;

    /* we pop from heap until we find a valid entry */
    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;

    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap, NULL);
        if (!kv) break;

        /* we check visibility (isolation, TTL, tombstones) */
        const int visible = tidesdb_iter_kv_visible(iter, kv);
        if (visible == -1)
        {
            /* tombstone -- we skip all versions of this key */
            const uint8_t *tombstone_key = kv->key;
            const size_t tombstone_key_size = kv->entry.key_size;

            /* we pop and discard all entries with the same key */
            while (!tidesdb_merge_heap_empty(iter->heap))
            {
                tidesdb_kv_pair_t *peek = iter->heap->sources[0]->current_kv;
                if (!peek) break;

                const int cmp =
                    iter->heap->comparator(peek->key, peek->entry.key_size, tombstone_key,
                                           tombstone_key_size, iter->heap->comparator_ctx);
                if (cmp != 0) break;

                tidesdb_kv_pair_t *dup = tidesdb_merge_heap_pop(iter->heap, NULL);
                tidesdb_kv_pair_free(dup);
            }

            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (visible == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        iter->current = kv;
        iter->valid = 1;
        iter->direction = 1; /* set forward direction */
        return TDB_SUCCESS;
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = -1; /* set to backward */

    /* we position all sources at their last entries */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            if (skip_list_cursor_goto_last(source->source.memtable.cursor) == 0)
            {
                uint8_t *key, *value;
                size_t key_size, value_size;
                int64_t ttl;
                uint8_t deleted;
                uint64_t seq;

                if (skip_list_cursor_get_with_seq(source->source.memtable.cursor, &key, &key_size,
                                                  &value, &value_size, &ttl, &deleted, &seq) == 0)
                {
                    tidesdb_kv_pair_free(source->current_kv);
                    source->current_kv =
                        tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
                }
            }
        }
        else if (source->type == MERGE_SOURCE_BTREE)
        {
            if (btree_cursor_goto_last(source->source.btree.cursor) == 0)
            {
                uint8_t *key = NULL, *value = NULL;
                size_t key_size = 0, value_size = 0;
                uint64_t vlog_offset = 0, seq = 0;
                int64_t ttl = 0;
                uint8_t deleted = 0;

                if (btree_cursor_get(source->source.btree.cursor, &key, &key_size, &value,
                                     &value_size, &vlog_offset, &seq, &ttl, &deleted) == 0)
                {
                    const uint8_t *actual_value = value;
                    size_t actual_value_size = value_size;
                    uint8_t *vlog_value = NULL;
                    if (vlog_offset > 0)
                    {
                        block_manager_cursor_goto(source->source.btree.vlog_cursor, vlog_offset);
                        block_manager_block_t *vlog_block =
                            block_manager_cursor_read(source->source.btree.vlog_cursor);
                        if (vlog_block)
                        {
                            vlog_value = malloc(vlog_block->size);
                            if (vlog_value)
                            {
                                memcpy(vlog_value, vlog_block->data, vlog_block->size);
                                actual_value = vlog_value;
                                actual_value_size = vlog_block->size;
                            }
                            block_manager_block_free(vlog_block);
                        }
                    }

                    tidesdb_kv_pair_free(source->current_kv);
                    source->current_kv = tidesdb_kv_pair_create(
                        key, key_size, actual_value, actual_value_size, ttl, seq, deleted);
                    free(vlog_value);
                }
            }
        }
        else if (source->type == MERGE_SOURCE_TXN_OPS)
        {
            /* position at the last entry in the sorted txn ops index */
            if (source->source.txn_ops.count > 0)
            {
                source->source.txn_ops.pos = source->source.txn_ops.count - 1;
                const int op_idx =
                    source->source.txn_ops.sorted_indices[source->source.txn_ops.pos];
                const tidesdb_txn_op_t *op = &source->source.txn_ops.txn->ops[op_idx];

                source->current_kv =
                    tidesdb_kv_pair_create(op->key, op->key_size, op->value, op->value_size,
                                           op->ttl, UINT64_MAX, op->is_delete);
            }
        }
        else
        {
            /* klog sstable source */
            const uint64_t num_blocks = source->source.sstable.sst->num_klog_blocks;
            block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;

            if (num_blocks > 0)
            {
                if (block_manager_cursor_goto_first(cursor) == 0)
                {
                    for (uint64_t b = 1; b < num_blocks; b++)
                    {
                        if (block_manager_cursor_next(cursor) != 0) break;
                    }
                }

                /* we clean up old data from iterator creation before reading new block */
                if (source->source.sstable.decompressed_data)
                {
                    free(source->source.sstable.decompressed_data);
                    source->source.sstable.decompressed_data = NULL;
                }
                if (source->source.sstable.current_block_data)
                {
                    block_manager_block_release(source->source.sstable.current_block_data);
                    source->source.sstable.current_block_data = NULL;
                }
                if (source->source.sstable.current_block)
                {
                    tidesdb_klog_block_free(source->source.sstable.current_block);
                    source->source.sstable.current_block = NULL;
                }

                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
                    const uint8_t *data = block->data;
                    size_t data_size = block->size;
                    uint8_t *decompressed = NULL;

                    if (source->config->compression_algorithm != TDB_COMPRESS_NONE)
                    {
                        size_t decompressed_size;
                        decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                                       source->config->compression_algorithm);
                        if (decompressed)
                        {
                            data = decompressed;
                            data_size = decompressed_size;
                            /* keep decompressed buffer, deserialized pointers reference it */
                            source->source.sstable.decompressed_data = decompressed;
                        }
                    }

                    tidesdb_klog_block_free(source->source.sstable.current_block);
                    source->source.sstable.current_block = NULL;

                    if (tidesdb_klog_block_deserialize(data, data_size,
                                                       &source->source.sstable.current_block) == 0)
                    {
                        if (source->source.sstable.current_block->num_entries > 0)
                        {
                            /* deserialization succeeded, now safe to store block */
                            source->source.sstable.current_block_data = block;

                            /* last entry in last block */
                            const int idx =
                                (int)source->source.sstable.current_block->num_entries - 1;
                            source->source.sstable.current_entry_idx = idx;

                            tidesdb_klog_block_t *kb = source->source.sstable.current_block;
                            uint8_t *value = kb->inline_values[idx];

                            uint8_t *vlog_value = NULL;
                            if (kb->entries[idx].vlog_offset > 0)
                            {
                                tidesdb_vlog_read_value(source->source.sstable.db,
                                                        source->source.sstable.sst,
                                                        kb->entries[idx].vlog_offset,
                                                        kb->entries[idx].value_size, &vlog_value);
                                value = vlog_value;
                            }

                            tidesdb_kv_pair_free(source->current_kv);
                            source->current_kv = tidesdb_kv_pair_create(
                                kb->keys[idx], kb->entries[idx].key_size, value,
                                kb->entries[idx].value_size, kb->entries[idx].ttl,
                                kb->entries[idx].seq,
                                kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

                            free(vlog_value);
                        }
                        else
                        {
                            /* empty block, release it */
                            block_manager_block_release(block);
                        }
                    }
                    else
                    {
                        /* deserialization failed, release block */
                        block_manager_block_release(block);
                    }

                    /* dont free decompressed or release block if we're still using the
                     * deserialized data (stored in current_block_data) */
                }
            }
        }
    }

    /* we build max-heap (for backward iteration) and find largest key */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        heap_sift_down_max(iter->heap, i);
    }

    /* we get the largest (last) key, handling tombstones */
    while (iter->heap->num_sources > 0 && iter->heap->sources[0]->current_kv)
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop_max(iter->heap);
        if (!kv) break;

        const int visible = tidesdb_iter_kv_visible(iter, kv);
        if (visible == -1)
        {
            /* tombstone -- we skip all versions of this key */
            const uint8_t *tombstone_key = kv->key;
            const size_t tombstone_key_size = kv->entry.key_size;

            /* we pop and discard all entries with the same key */
            while (!tidesdb_merge_heap_empty(iter->heap))
            {
                tidesdb_kv_pair_t *peek = iter->heap->sources[0]->current_kv;
                if (!peek) break;

                const int cmp =
                    iter->heap->comparator(peek->key, peek->entry.key_size, tombstone_key,
                                           tombstone_key_size, iter->heap->comparator_ctx);
                if (cmp != 0) break;

                tidesdb_kv_pair_t *dup = tidesdb_merge_heap_pop_max(iter->heap);
                tidesdb_kv_pair_free(dup);
            }

            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (visible == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_next(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid) return TDB_ERR_INVALID_ARGS;

    /* we check if direction changed from backward to forward */
    const int direction_changed = (iter->direction == -1);

    /* we set direction to forward */
    iter->direction = 1;

    /* we keep previous entry alive for duplicate detection instead
     * of copying its key into a separate buffer.  This avoids a memcpy (and
     * potential malloc for keys > TDB_ITER_STACK_KEY_SIZE) per iter_next call.
     * prev is freed once we find the next visible entry or at end-of-scan. */
    tidesdb_kv_pair_t *prev = iter->current;
    iter->current = NULL;
    iter->valid = 0;

    /* if direction changed, advance all sources and rebuild as min-heap */
    if (direction_changed)
    {
        for (int i = 0; i < iter->heap->num_sources; i++)
        {
            tidesdb_merge_source_t *source = iter->heap->sources[i];
            if (tidesdb_merge_source_advance(source) != TDB_SUCCESS)
            {
                source->current_kv = NULL;
            }
        }

        /* we rebuild as min-heap for forward iteration */
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down(iter->heap, i);
        }
    }

    /* we pop from heap until we find next visible entry */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap, NULL);
        if (!kv) break;

        /* we skip duplicates (same key as previous) */
        if (prev && prev->entry.key_size == kv->entry.key_size &&
            memcmp(prev->key, kv->key, prev->entry.key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        const int visible = tidesdb_iter_kv_visible(iter, kv);
        if (visible == -1)
        {
            /* tombstone -- we skip all versions of this key */
            const uint8_t *tombstone_key = kv->key;
            const size_t tombstone_key_size = kv->entry.key_size;

            /* we pop and discard all entries with the same key */
            while (!tidesdb_merge_heap_empty(iter->heap))
            {
                tidesdb_kv_pair_t *peek = iter->heap->sources[0]->current_kv;
                if (!peek) break;

                const int cmp =
                    iter->heap->comparator(peek->key, peek->entry.key_size, tombstone_key,
                                           tombstone_key_size, iter->heap->comparator_ctx);
                if (cmp != 0) break;

                tidesdb_kv_pair_t *dup = tidesdb_merge_heap_pop(iter->heap, NULL);
                tidesdb_kv_pair_free(dup);
            }

            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (visible == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* snapshot isolation -- we track read for conflict detection */
        tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                    kv->entry.seq);

        tidesdb_kv_pair_free(prev);
        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    tidesdb_kv_pair_free(prev);
    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_prev(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid) return TDB_ERR_INVALID_ARGS;

    /* we check if direction changed from forward to backward */
    const int direction_changed = (iter->direction == 1);

    /* we set direction to backward */
    iter->direction = -1;

    /* we keep previous entry alive for duplicate detection (same as iter_next) */
    tidesdb_kv_pair_t *prev = iter->current;
    iter->current = NULL;
    iter->valid = 0;

    /* if direction changed, retreat all sources and rebuild as max-heap */
    if (direction_changed)
    {
        for (int i = 0; i < iter->heap->num_sources; i++)
        {
            tidesdb_merge_source_t *source = iter->heap->sources[i];
            if (tidesdb_merge_source_retreat(source) != TDB_SUCCESS)
            {
                source->current_kv = NULL;
            }
        }

        /* we rebuild as max-heap for backward iteration */
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down_max(iter->heap, i);
        }
    }

    /* we pop from max-heap until we find previous visible entry */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop_max(iter->heap);
        if (!kv) break;

        /* we skip duplicates (same key as previous) */
        if (prev && prev->entry.key_size == kv->entry.key_size &&
            memcmp(prev->key, kv->key, prev->entry.key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* we skip invisible entries */
        const int visible = tidesdb_iter_kv_visible(iter, kv);
        if (visible == -1)
        {
            /* tombstone - skip all versions of this key */
            const uint8_t *tombstone_key = kv->key;
            const size_t tombstone_key_size = kv->entry.key_size;

            /* pop and discard all entries with the same key */
            while (!tidesdb_merge_heap_empty(iter->heap))
            {
                tidesdb_kv_pair_t *peek = iter->heap->sources[0]->current_kv;
                if (!peek) break;

                const int cmp =
                    iter->heap->comparator(peek->key, peek->entry.key_size, tombstone_key,
                                           tombstone_key_size, iter->heap->comparator_ctx);
                if (cmp != 0) break;

                tidesdb_kv_pair_t *dup = tidesdb_merge_heap_pop_max(iter->heap);
                tidesdb_kv_pair_free(dup);
            }

            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (visible == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* snapshot isolation -- track read for conflict detection */
        tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                    kv->entry.seq);

        tidesdb_kv_pair_free(prev);
        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    tidesdb_kv_pair_free(prev);
    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_valid(tidesdb_iter_t *iter)
{
    if (!iter) return 0;
    return iter->valid;
}

int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size)
{
    if (!iter || !key || !key_size) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid || !iter->current) return TDB_ERR_INVALID_ARGS;

    *key = iter->current->key;
    *key_size = iter->current->entry.key_size;

    return TDB_SUCCESS;
}

int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid || !iter->current) return TDB_ERR_INVALID_ARGS;

    *value = iter->current->value;
    *value_size = iter->current->entry.value_size;

    return TDB_SUCCESS;
}

void tidesdb_iter_free(tidesdb_iter_t *iter)
{
    if (!iter) return;

    tidesdb_kv_pair_free(iter->current);
    tidesdb_merge_heap_free(iter->heap);

    if (iter->cached_sources)
    {
        for (int i = 0; i < iter->num_cached_sources; i++)
        {
            tidesdb_merge_source_free(iter->cached_sources[i]);
        }
        free(iter->cached_sources);
    }

    free(iter);
}

/**
 * tidesdb_sort_wal_files
 * sort WAL files by ID
 * @param wal_files queue of WAL file paths
 */
static void tidesdb_sort_wal_files(queue_t *wal_files)
{
    const size_t wal_count = queue_size(wal_files);
    if (wal_count <= 1) return;

    char **wal_array = malloc(wal_count * sizeof(char *));
    if (!wal_array) return;

    for (size_t i = 0; i < wal_count; i++)
    {
        wal_array[i] = queue_dequeue(wal_files);
    }

    for (size_t i = 0; i < wal_count - 1; i++)
    {
        for (size_t j = 0; j < wal_count - i - 1; j++)
        {
            uint64_t id1 = 0, id2 = 0;
            const char *name1 = strrchr(wal_array[j], PATH_SEPARATOR[0]);
            const char *name2 = strrchr(wal_array[j + 1], PATH_SEPARATOR[0]);
            if (name1)
                name1++;
            else
                name1 = wal_array[j];
            if (name2)
                name2++;
            else
                name2 = wal_array[j + 1];

            tdb_parse_wal_id(name1, &id1);
            tdb_parse_wal_id(name2, &id2);

            if (id1 > id2)
            {
                char *temp = wal_array[j];
                wal_array[j] = wal_array[j + 1];
                wal_array[j + 1] = temp;
            }
        }
    }

    for (size_t i = 0; i < wal_count; i++)
    {
        queue_enqueue(wal_files, wal_array[i]);
    }
    free(wal_array);
}

/**
 * tidesdb_recover_single_wal
 * recover a single WAL file and queue for flush
 * @param cf column family
 * @param wal_path path to WAL file (ownership transferred, will be freed)
 */
static void tidesdb_recover_single_wal(tidesdb_column_family_t *cf, char *wal_path)
{
    skip_list_t *recovered_memtable = NULL;
    const int recover_result = tidesdb_wal_recover(cf, wal_path, &recovered_memtable);

    if (recover_result != TDB_SUCCESS || !recovered_memtable)
    {
        if (recovered_memtable) skip_list_free(recovered_memtable);
        free(wal_path);
        return;
    }

    const int recovered_entries = skip_list_count_entries(recovered_memtable);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' recovered memtable from WAL: %s (%d entries)", cf->name,
                  wal_path, recovered_entries);

    if (recovered_entries == 0)
    {
        skip_list_free(recovered_memtable);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' empty recovered memtable, deleting WAL: %s", cf->name,
                      wal_path);
        tdb_unlink(wal_path);
        free(wal_path);
        return;
    }

    block_manager_t *wal_bm = NULL;
    if (block_manager_open(&wal_bm, wal_path, TDB_SYNC_FULL) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to reopen WAL for flush tracking: %s", cf->name,
                      wal_path);
        skip_list_free(recovered_memtable);
        free(wal_path);
        return;
    }

    tidesdb_immutable_memtable_t *imm = calloc(1, sizeof(tidesdb_immutable_memtable_t));
    if (!imm)
    {
        block_manager_close(wal_bm);
        skip_list_free(recovered_memtable);
        free(wal_path);
        return;
    }

    imm->skip_list = recovered_memtable;
    imm->wal = wal_bm;
    imm->id = 0;
    imm->generation = 0;
    atomic_init(&imm->refcount, 1);
    atomic_init(&imm->flushed, 0);

    if (queue_enqueue(cf->immutable_memtables, imm) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to enqueue recovered memtable", cf->name);
        tidesdb_immutable_memtable_unref(imm);
        free(wal_path);
        return;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' has queued recovered memtable for async flush (WAL: %s)",
                  cf->name, wal_path);

    tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
    if (work)
    {
        work->cf = cf;
        work->imm = imm;
        work->sst_id = atomic_fetch_add_explicit(&cf->next_sstable_id, 1, memory_order_relaxed);
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' allocated SSTable ID %" PRIu64 " for recovered WAL flush", cf->name,
                      work->sst_id);
        tidesdb_immutable_memtable_ref(imm);

        if (queue_enqueue(cf->db->flush_queue, work) != 0)
        {
            tidesdb_immutable_memtable_unref(imm);
            free(work);
        }
    }

    free(wal_path);
}

/**
 * tidesdb_recover_wals
 * discover and recover all WAL files for a column family
 * @param cf column family
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_recover_wals(tidesdb_column_family_t *cf)
{
    DIR *dir = opendir(cf->directory);
    if (!dir) return TDB_ERR_IO;

    queue_t *wal_files = queue_new();
    if (!wal_files)
    {
        closedir(dir);
        return TDB_ERR_MEMORY;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, TDB_WAL_PREFIX) == entry->d_name)
        {
            const size_t path_len = strlen(cf->directory) + strlen(entry->d_name) + 2;
            char *wal_path = malloc(path_len);
            if (wal_path)
            {
                snprintf(wal_path, path_len, "%s" PATH_SEPARATOR "%s", cf->directory,
                         entry->d_name);
                if (queue_enqueue(wal_files, wal_path) != 0)
                {
                    free(wal_path);
                }
            }
        }
    }
    closedir(dir);

    /* we restore next_sstable_id from manifest before WAL recovery */
    const uint64_t manifest_seq = atomic_load(&cf->manifest->sequence);
    if (cf->manifest && manifest_seq > 0)
    {
        atomic_store_explicit(&cf->next_sstable_id, manifest_seq, memory_order_relaxed);
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' pre-loaded next_sstable_id=%" PRIu64
                      " from manifest before WAL recovery",
                      cf->name, manifest_seq);
    }

    tidesdb_sort_wal_files(wal_files);

    while (!queue_is_empty(wal_files))
    {
        char *wal_path = queue_dequeue(wal_files);
        if (wal_path)
        {
            tidesdb_recover_single_wal(cf, wal_path);
        }
    }

    queue_free(wal_files);
    return TDB_SUCCESS;
}

/**
 * tidesdb_recover_single_sstable
 * recover a single sstable from disk
 * @param cf column family
 * @param entry directory entry for the .klog file
 */
static void tidesdb_recover_single_sstable(tidesdb_column_family_t *cf, const struct dirent *entry)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' found .klog file: %s", cf->name, entry->d_name);

    int level_num = 1;
    int partition_num = -1;
    unsigned long long sst_id_ull = 0;
    char sst_base[TDB_MAX_PATH_LEN];
    int parsed = 0;

    /* we try parsing partitioned format first: L{level}P{partition}_{id}.klog */
    if (tdb_parse_sstable_partitioned(entry->d_name, &level_num, &partition_num, &sst_id_ull))
    {
        snprintf(sst_base, sizeof(sst_base),
                 "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                 cf->directory, level_num, partition_num);
        parsed = 1;
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "Parsed partitioned SSTable level=%d, partition=%d, id=%" PRIu64, level_num,
                      partition_num, (uint64_t)sst_id_ull);
    }
    /* we try non-partitioned format: L{level}_{id}.klog */
    else if (tdb_parse_sstable_non_partitioned(entry->d_name, &level_num, &sst_id_ull))
    {
        snprintf(sst_base, sizeof(sst_base), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d",
                 cf->directory, level_num);
        parsed = 1;
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' parsed non-partitioned SSTable level=%d, id=%" PRIu64,
                      cf->name, level_num, (uint64_t)sst_id_ull);
    }

    if (!parsed) return;

    const uint64_t sst_id = (uint64_t)sst_id_ull;

    /* we check manifest to see if this sstable is complete */
    const int in_manifest = tidesdb_manifest_has_sstable(cf->manifest, level_num, sst_id);

    if (!in_manifest)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "CF '%s' SSTable %" PRIu64
                      " at level %d not in manifest, deleting (incomplete write)",
                      cf->name, sst_id, level_num);

        char klog_path[TDB_MAX_PATH_LEN];
        char vlog_path[TDB_MAX_PATH_LEN];
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
        snprintf(klog_path, sizeof(klog_path), "%s_%" PRIu64 TDB_SSTABLE_KLOG_EXT, sst_base,
                 sst_id);
        snprintf(vlog_path, sizeof(vlog_path), "%s_%" PRIu64 TDB_SSTABLE_VLOG_EXT, sst_base,
                 sst_id);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
        tdb_unlink(klog_path);
        tdb_unlink(vlog_path);
        return;
    }

    tidesdb_sstable_t *sst = tidesdb_sstable_create(cf->db, sst_base, sst_id, &cf->config);
    if (!sst) return;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is recovering SSTable %" PRIu64 " at level %d", cf->name,
                  sst_id, level_num);

    if (tidesdb_sstable_load(cf->db, sst) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "CF '%s' SSTable %" PRIu64 " failed to load (corrupted), deleting files",
                      cf->name, sst_id);

        char klog_path[TDB_MAX_PATH_LEN];
        char vlog_path[TDB_MAX_PATH_LEN];
        snprintf(klog_path, sizeof(klog_path), "%s", sst->klog_path);
        snprintf(vlog_path, sizeof(vlog_path), "%s", sst->vlog_path);

        tidesdb_sstable_unref(cf->db, sst);

        (void)remove(klog_path);
        (void)remove(vlog_path);
        return;
    }

    int current_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    while (current_levels < level_num)
    {
        if (tidesdb_add_level(cf) != TDB_SUCCESS) break;
        current_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    }

    if (level_num <= current_levels)
    {
        tidesdb_level_add_sstable(cf->levels[level_num - 1], sst);
        tidesdb_bump_sstable_layout_version(cf);
    }

    tidesdb_sstable_unref(cf->db, sst);
}

/**
 * tidesdb_recover_sstables
 * discover and recover all sstables for a column family
 * @param cf column family
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_recover_sstables(tidesdb_column_family_t *cf)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Recovering SSTables from directory: %s", cf->directory);

    DIR *dir = opendir(cf->directory);
    if (!dir) return TDB_ERR_IO;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, TDB_SSTABLE_KLOG_EXT) != NULL)
        {
            tidesdb_recover_single_sstable(cf, entry);
        }
    }
    closedir(dir);

    return TDB_SUCCESS;
}

/**
 * tidesdb_scan_max_sequence
 * scan all sources (sstables and immutable memtables) for max sequence number
 * @param cf column family
 * @return maximum sequence number found
 */
static uint64_t tidesdb_scan_max_sequence(tidesdb_column_family_t *cf)
{
    uint64_t global_max_seq = 0;

    const int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is scanning sources for max_seq", cf->name);

    for (int level_idx = 0; level_idx < num_levels; level_idx++)
    {
        tidesdb_level_t *level = cf->levels[level_idx];
        if (!level) continue;

        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        const int num_ssts_recheck =
            atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        if (num_ssts_recheck < num_ssts) num_ssts = num_ssts_recheck;

        tidesdb_sstable_t **sstables_check =
            atomic_load_explicit(&level->sstables, memory_order_acquire);
        if (sstables_check != sstables)
        {
            sstables = sstables_check;
            num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        }

        for (int sst_idx = 0; sst_idx < num_ssts; sst_idx++)
        {
            tidesdb_sstable_t *sst = sstables[sst_idx];
            if (sst && sst->max_seq > global_max_seq)
            {
                global_max_seq = sst->max_seq;
            }
        }
    }

    /* we scan immutable memtables */
    if (cf->immutable_memtables)
    {
        const size_t imm_count = queue_size(cf->immutable_memtables);

        for (size_t i = 0; i < imm_count; i++)
        {
            tidesdb_immutable_memtable_t *imm = queue_peek_at(cf->immutable_memtables, i);
            if (!imm || !imm->skip_list) continue;

            skip_list_cursor_t *cursor;
            if (skip_list_cursor_init(&cursor, imm->skip_list) != 0) continue;

            if (skip_list_cursor_goto_first(cursor) == 0)
            {
                do
                {
                    uint8_t *key, *value;
                    size_t key_size, value_size;
                    int64_t ttl;
                    uint8_t deleted;
                    uint64_t seq;

                    if (skip_list_cursor_get_with_seq(cursor, &key, &key_size, &value, &value_size,
                                                      &ttl, &deleted, &seq) == 0)
                    {
                        if (seq > global_max_seq)
                        {
                            global_max_seq = seq;
                        }
                    }
                } while (skip_list_cursor_next(cursor) == 0);
            }
            skip_list_cursor_free(cursor);
        }
    }

    return global_max_seq;
}

/**
 * tidesdb_recover_column_family
 * recover a column family from disk after crash
 * @param cf
 * @return error code
 */
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    int result = tidesdb_recover_wals(cf);
    if (result != TDB_SUCCESS) return result;

    result = tidesdb_recover_sstables(cf);
    if (result != TDB_SUCCESS) return result;

    const uint64_t global_max_seq = tidesdb_scan_max_sequence(cf);

    /* we update global sequence based on recovered data */
    const uint64_t current_seq = atomic_load_explicit(&cf->db->global_seq, memory_order_acquire);
    if (global_max_seq >= current_seq)
    {
        atomic_store(&cf->db->global_seq, global_max_seq + 1);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' has updated global_seq from %" PRIu64 " to %" PRIu64,
                      cf->name, current_seq, global_max_seq + 1);
    }

    /* we update commit status */
    if (global_max_seq > 0)
    {
        tidesdb_commit_status_t *cs = cf->db->commit_status;

        const uint64_t current_max = atomic_load_explicit(&cs->max_seq, memory_order_acquire);
        if (global_max_seq > current_max)
        {
            atomic_store_explicit(&cs->max_seq, global_max_seq, memory_order_release);
        }

        for (uint64_t seq = 1; seq <= global_max_seq; seq++)
        {
            const size_t idx = seq % cs->capacity;
            atomic_store_explicit(&cs->status[idx], TDB_COMMIT_STATUS_COMMITTED,
                                  memory_order_release);
        }
    }

    /* we restore next_sstable_id from manifest to prevent ID collisions */
    if (cf->manifest)
    {
        const uint64_t manifest_seq = atomic_load(&cf->manifest->sequence);
        if (manifest_seq > atomic_load(&cf->next_sstable_id))
        {
            atomic_store(&cf->next_sstable_id, manifest_seq);
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' restored next_sstable_id=%" PRIu64 " from manifest", cf->name,
                          manifest_seq);
        }
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' recovery is complete, global_max_seq=%" PRIu64, cf->name,
                  global_max_seq);

    return TDB_SUCCESS;
}

/**
 * tidesdb_recover_database
 * recover entire database from disk
 * @param db database to recover
 * @return error code
 */
static int tidesdb_recover_database(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Starting database recovery from: %s", db->db_path);

    DIR *dir = opendir(db->db_path);
    if (!dir)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "No existing database directory found (fresh start)");
        return TDB_SUCCESS; /* not an error, fresh database */
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        char full_path[MAX_FILE_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s%s%s", db->db_path, PATH_SEPARATOR,
                 entry->d_name);

        struct STAT_STRUCT st;
        if (STAT_FUNC(full_path, &st) == 0 && S_ISDIR(st.st_mode))
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Found CF directory: %s", entry->d_name);
            tidesdb_column_family_t *cf = tidesdb_get_column_family_internal(db, entry->d_name);

            if (!cf)
            {
                tidesdb_column_family_config_t config = tidesdb_default_column_family_config();

                /* we ensure we have room for full_path + "/" + "config.ini" + null terminator */
                const size_t full_path_len = strlen(full_path);
                if (full_path_len + 1 +
                        strlen(TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT) >=
                    TDB_MAX_PATH_LEN)
                {
                    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' config path too long, using defaults",
                                  entry->d_name);
                    goto create_cf_with_config;
                }

                char config_path[TDB_MAX_PATH_LEN];
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
                snprintf(
                    config_path, TDB_MAX_PATH_LEN,
                    "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT,
                    full_path);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

                if (tidesdb_cf_config_load_from_ini(config_path, entry->d_name, &config) ==
                    TDB_SUCCESS)
                {
                    TDB_DEBUG_LOG(TDB_LOG_INFO,
                                  "CF '%s' has loaded config from disk (write_buffer_size=%zu, "
                                  "level_size_ratio=%zu)",
                                  entry->d_name, config.write_buffer_size, config.level_size_ratio);
                }
                else
                {
                    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' has no saved config found, using defaults",
                                  entry->d_name);
                }

            create_cf_with_config:;
                int create_result = tidesdb_create_column_family(db, entry->d_name, &config);

                if (create_result == TDB_SUCCESS)
                {
                    cf = tidesdb_get_column_family_internal(db, entry->d_name);
                }
                else if (create_result == TDB_ERR_EXISTS)
                {
                    /* CF already exists in memory, try to get it again */
                    cf = tidesdb_get_column_family_internal(db, entry->d_name);
                    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF already exists during recovery: %s",
                                  entry->d_name);
                }
                else
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN,
                                  "Failed to create CF during recovery: %s (error code: %d)",
                                  entry->d_name, create_result);
                }
            }

            if (cf)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Recovering CF: %s", entry->d_name);
                tidesdb_recover_column_family(cf);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to get/create CF: %s", entry->d_name);
            }
        }
    }
    closedir(dir);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Database recovery completed successfully");
    return TDB_SUCCESS;
}

int tidesdb_get_stats(tidesdb_column_family_t *cf, tidesdb_stats_t **stats)
{
    if (!cf || !stats) return TDB_ERR_INVALID_ARGS;

    *stats = calloc(1, sizeof(tidesdb_stats_t));
    if (!*stats) return TDB_ERR_MEMORY;

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    (*stats)->num_levels = num_levels;
    tidesdb_memtable_t *active_mt_struct =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;
    (*stats)->memtable_size = skip_list_get_size(active_mt);

    (*stats)->level_sizes = malloc((*stats)->num_levels * sizeof(size_t));
    (*stats)->level_num_sstables = malloc((*stats)->num_levels * sizeof(int));
    (*stats)->level_key_counts = malloc((*stats)->num_levels * sizeof(uint64_t));
    (*stats)->config = malloc(sizeof(tidesdb_column_family_config_t));

    if (!(*stats)->level_sizes || !(*stats)->level_num_sstables || !(*stats)->level_key_counts ||
        !(*stats)->config)
    {
        free((*stats)->level_sizes);
        free((*stats)->level_num_sstables);
        free((*stats)->level_key_counts);
        free((*stats)->config);
        free(*stats);
        return TDB_ERR_MEMORY;
    }

    memcpy((*stats)->config, &cf->config, sizeof(tidesdb_column_family_config_t));

    /* we count memtable keys */
    uint64_t memtable_keys = active_mt ? (uint64_t)skip_list_count_entries(active_mt) : 0;
    uint64_t total_keys = memtable_keys;
    uint64_t total_data_size = 0;
    uint64_t total_klog_size = 0;

    /* btree stats aggregation */
    uint64_t btree_total_nodes = 0;
    uint32_t btree_max_height = 0;
    uint64_t btree_height_sum = 0;
    int btree_sstable_count = 0;

    for (int i = 0; i < (*stats)->num_levels; i++)
    {
        (*stats)->level_sizes[i] = atomic_load(&cf->levels[i]->current_size);
        int num_sstables = atomic_load_explicit(&cf->levels[i]->num_sstables, memory_order_acquire);
        (*stats)->level_num_sstables[i] = num_sstables;

        /* we count keys per level from sstables */
        uint64_t level_keys = 0;
        tidesdb_sstable_t **sstables =
            atomic_load_explicit(&cf->levels[i]->sstables, memory_order_acquire);
        for (int j = 0; j < num_sstables; j++)
        {
            if (sstables[j])
            {
                level_keys += sstables[j]->num_entries;
                total_data_size += sstables[j]->klog_size + sstables[j]->vlog_size;
                total_klog_size += sstables[j]->klog_size;

                /* we aggregate btree stats if this sstable uses btree */
                if (sstables[j]->use_btree && sstables[j]->btree_root_offset >= 0)
                {
                    btree_sstable_count++;
                    btree_total_nodes += sstables[j]->btree_node_count;
                    btree_height_sum += sstables[j]->btree_height;
                    if (sstables[j]->btree_height > btree_max_height)
                    {
                        btree_max_height = sstables[j]->btree_height;
                    }
                }
            }
        }
        (*stats)->level_key_counts[i] = level_keys;
        total_keys += level_keys;
    }

    /* we populate btree stats */
    (*stats)->use_btree = cf->config.use_btree;
    (*stats)->btree_total_nodes = btree_total_nodes;
    (*stats)->btree_max_height = btree_max_height;
    (*stats)->btree_avg_height =
        btree_sstable_count > 0 ? (double)btree_height_sum / btree_sstable_count : 0.0;

    (*stats)->total_keys = total_keys;
    (*stats)->total_data_size = total_data_size;

    /* we estimate avg key/value sizes from memtable size and sstable data */
    if (total_keys > 0)
    {
        /* memtable tracks total_size as key_size + value_size for each entry */
        const uint64_t memtable_data_size = (*stats)->memtable_size;
        const uint64_t total_kv_size = memtable_data_size + total_klog_size;
        double avg_entry_size = (double)total_kv_size / (double)total_keys;
        /* we assume roughly equal key/value split as approximation */
        (*stats)->avg_key_size = avg_entry_size * 0.3;
        (*stats)->avg_value_size = avg_entry_size * 0.7;
    }
    else
    {
        (*stats)->avg_key_size = 0.0;
        (*stats)->avg_value_size = 0.0;
    }

    /* we calculate read amplification: worst case is 1 (memtable) + sum of sstables per level
     * note -- levels[0] is L1 (first sstable level), L0 is the immutable memtables queue */
    double read_amp = 1.0; /* memtable lookup */
    for (int i = 0; i < (*stats)->num_levels; i++)
    {
        /* L1 (levels[0]) may have overlapping sstables from flushes, L2+ are sorted/non-overlapping
         */
        if (i == 0)
        {
            read_amp += (*stats)->level_num_sstables[i];
        }
        else
        {
            read_amp += ((*stats)->level_num_sstables[i] > 0 ? 1.0 : 0.0);
        }
    }
    (*stats)->read_amp = read_amp;

    /* we get cache hit rate from database if available */
    (*stats)->hit_rate = 0.0;
    if (cf->db && cf->db->clock_cache)
    {
        tidesdb_cache_stats_t cache_stats;
        if (tidesdb_get_cache_stats(cf->db, &cache_stats) == TDB_SUCCESS && cache_stats.enabled)
        {
            (*stats)->hit_rate = cache_stats.hit_rate;
        }
    }

    return TDB_SUCCESS;
}

void tidesdb_free_stats(tidesdb_stats_t *stats)
{
    if (!stats) return;
    free(stats->level_sizes);
    free(stats->level_num_sstables);
    free(stats->level_key_counts);
    free(stats->config);
    free(stats);
}

int tidesdb_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;

    memset(stats, 0, sizeof(tidesdb_cache_stats_t));

    if (!db->clock_cache)
    {
        stats->enabled = 0;
        return TDB_SUCCESS;
    }

    stats->enabled = 1;

    clock_cache_stats_t cache_stats;
    clock_cache_get_stats(db->clock_cache, &cache_stats);

    stats->total_entries = cache_stats.total_entries;
    stats->total_bytes = cache_stats.total_bytes;
    stats->hits = cache_stats.hits;
    stats->misses = cache_stats.misses;
    stats->hit_rate = cache_stats.hit_rate;
    stats->num_partitions = cache_stats.num_partitions;

    return TDB_SUCCESS;
}

typedef enum
{
    TDB_BACKUP_COPY_IMMUTABLE = 1,
    TDB_BACKUP_COPY_FINAL = 2
} tidesdb_backup_copy_mode_t;

static int tidesdb_backup_is_sstable_file(const char *name)
{
    if (!name) return 0;
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    return (strcmp(ext, TDB_SSTABLE_KLOG_EXT) == 0 || strcmp(ext, TDB_SSTABLE_VLOG_EXT) == 0);
}

static int tidesdb_backup_is_wal_file(const char *name)
{
    if (!name) return 0;
    const size_t name_len = strlen(name);
    const size_t prefix_len = strlen(TDB_WAL_PREFIX);
    const size_t ext_len = strlen(TDB_WAL_EXT);
    if (name_len <= prefix_len + ext_len) return 0;
    if (strncmp(name, TDB_WAL_PREFIX, prefix_len) != 0) return 0;
    if (strcmp(name + name_len - ext_len, TDB_WAL_EXT) != 0) return 0;
    return 1;
}

static int tidesdb_backup_sstable_in_manifest(const tidesdb_column_family_t *cf, const char *name)
{
    if (!cf || !cf->manifest || !name) return 0;

    int level_num = 0;
    int partition_num = 0;
    unsigned long long sst_id_ull = 0;

    if (tdb_parse_sstable_partitioned(name, &level_num, &partition_num, &sst_id_ull))
    {
        return tidesdb_manifest_has_sstable(cf->manifest, level_num, (uint64_t)sst_id_ull);
    }

    if (tdb_parse_sstable_non_partitioned(name, &level_num, &sst_id_ull))
    {
        return tidesdb_manifest_has_sstable(cf->manifest, level_num, (uint64_t)sst_id_ull);
    }

    return 0;
}

static int tidesdb_backup_copy_file(const char *src_path, const char *dst_path)
{
    FILE *src = tdb_fopen(src_path, "rb");
    if (!src)
    {
        if (errno == ENOENT) return TDB_SUCCESS;
        return TDB_ERR_IO;
    }

    FILE *dst = tdb_fopen(dst_path, "wb");
    if (!dst)
    {
        fclose(src);
        return TDB_ERR_IO;
    }

    char buffer[TDB_BACKUP_COPY_BUFFER_SIZE];
    size_t bytes_read = 0;
    int result = TDB_SUCCESS;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        if (fwrite(buffer, 1, bytes_read, dst) != bytes_read)
        {
            result = TDB_ERR_IO;
            break;
        }
    }

    if (ferror(src)) result = TDB_ERR_IO;

    if (fflush(dst) != 0) result = TDB_ERR_IO;

    if (fclose(dst) != 0) result = TDB_ERR_IO;
    fclose(src);

    return result;
}

static int tidesdb_backup_copy_dir(const char *src_dir, const char *dst_dir,
                                   const tidesdb_backup_copy_mode_t mode,
                                   const tidesdb_column_family_t *cf)
{
    struct STAT_STRUCT dst_st;
    if (STAT_FUNC(dst_dir, &dst_st) != 0)
    {
        if (mkdir(dst_dir, TDB_DIR_PERMISSIONS) != 0)
        {
            return TDB_ERR_IO;
        }
    }
    else if (!S_ISDIR(dst_st.st_mode))
    {
        return TDB_ERR_IO;
    }

    DIR *dir = opendir(src_dir);
    if (!dir) return TDB_ERR_IO;

    struct dirent *entry;
    int result = TDB_SUCCESS;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (strcmp(entry->d_name, TDB_LOCK_FILE) == 0) continue;

        const size_t src_len = strlen(src_dir) + strlen(PATH_SEPARATOR) + strlen(entry->d_name) + 1;
        const size_t dst_len = strlen(dst_dir) + strlen(PATH_SEPARATOR) + strlen(entry->d_name) + 1;
        char *src_path = malloc(src_len);
        char *dst_path = malloc(dst_len);
        if (!src_path || !dst_path)
        {
            free(src_path);
            free(dst_path);
            result = TDB_ERR_MEMORY;
            break;
        }

        snprintf(src_path, src_len, "%s%s%s", src_dir, PATH_SEPARATOR, entry->d_name);
        snprintf(dst_path, dst_len, "%s%s%s", dst_dir, PATH_SEPARATOR, entry->d_name);

        struct STAT_STRUCT src_st;
        if (STAT_FUNC(src_path, &src_st) != 0)
        {
            if (errno != ENOENT) result = TDB_ERR_IO;
            free(src_path);
            free(dst_path);
            if (result != TDB_SUCCESS) break;
            continue;
        }

        if (S_ISDIR(src_st.st_mode))
        {
            result = tidesdb_backup_copy_dir(src_path, dst_path, mode, cf);
        }
        else
        {
            const int is_sstable = tidesdb_backup_is_sstable_file(entry->d_name);
            const int is_wal = tidesdb_backup_is_wal_file(entry->d_name);
            int should_copy = 0;

            if (mode == TDB_BACKUP_COPY_IMMUTABLE)
            {
                if (is_wal)
                {
                    should_copy = 0;
                }
                else if (is_sstable)
                {
                    should_copy = tidesdb_backup_sstable_in_manifest(cf, entry->d_name);
                }
                else
                {
                    should_copy = 1;
                }
            }
            else
            {
                if (is_sstable)
                {
                    struct STAT_STRUCT existing_st;
                    if (STAT_FUNC(dst_path, &existing_st) != 0)
                    {
                        should_copy = 1;
                    }
                }
                else
                {
                    should_copy = 1;
                }
            }

            if (should_copy) result = tidesdb_backup_copy_file(src_path, dst_path);
        }

        free(src_path);
        free(dst_path);

        if (result != TDB_SUCCESS) break;
    }

    closedir(dir);
    return result;
}

static int tidesdb_backup_copy_all_cfs(tidesdb_t *db, const char *dir,
                                       const tidesdb_backup_copy_mode_t mode)
{
    int result = TDB_SUCCESS;

    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (!cf) continue;

        char dst_dir[TDB_MAX_PATH_LEN];
        const int needed =
            snprintf(dst_dir, sizeof(dst_dir), "%s" PATH_SEPARATOR "%s", dir, cf->name);
        if (needed < 0 || (size_t)needed >= sizeof(dst_dir))
        {
            result = TDB_ERR_IO;
            break;
        }

        result = tidesdb_backup_copy_dir(cf->directory, dst_dir, mode, cf);
        if (result != TDB_SUCCESS) break;
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    return result;
}

int tidesdb_backup(tidesdb_t *db, char *dir)
{
    if (!db || !dir) return TDB_ERR_INVALID_ARGS;

    const int wait_result = wait_for_open(db);
    if (wait_result != TDB_SUCCESS) return wait_result;

    if (strcmp(db->db_path, dir) == 0) return TDB_ERR_INVALID_ARGS;

    struct STAT_STRUCT st;
    if (STAT_FUNC(dir, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode)) return TDB_ERR_INVALID_ARGS;
        if (!is_directory_empty(dir)) return TDB_ERR_EXISTS;
    }
    else
    {
        if (mkdir(dir, TDB_DIR_PERMISSIONS) != 0) return TDB_ERR_IO;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Starting backup to directory: %s", dir);

    int result = tidesdb_backup_copy_all_cfs(db, dir, TDB_BACKUP_COPY_IMMUTABLE);
    if (result != TDB_SUCCESS) return result;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Flushing memtables before final backup copy");
    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (!cf) continue;

        int wait_count = 0;
        while (atomic_load_explicit(&cf->is_flushing, memory_order_acquire) != 0 &&
               wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
        {
            usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
            wait_count++;
        }

        result = tidesdb_flush_memtable_internal(cf, 0, 1);
        if (result != TDB_SUCCESS)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            return result;
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for background flushes to complete");
    int flush_wait_count = 0;
    pthread_rwlock_rdlock(&db->cf_list_lock);
    while (1)
    {
        int any_flushing = 0;
        size_t queue_size_val = 0;

        for (int i = 0; i < db->num_column_families; i++)
        {
            if (db->column_families[i])
            {
                if (atomic_load_explicit(&db->column_families[i]->is_flushing,
                                         memory_order_acquire))
                {
                    any_flushing = 1;
                    break;
                }
            }
        }

        if (db->flush_queue)
        {
            queue_size_val = queue_size(db->flush_queue);
        }

        if (!any_flushing && queue_size_val == 0)
        {
            break;
        }

        if (flush_wait_count % 1000 == 0 && flush_wait_count > 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "Still waiting for background flushes (waited %d seconds, queue_size=%zu)",
                flush_wait_count / 1000, queue_size_val);
        }

        pthread_rwlock_unlock(&db->cf_list_lock);
        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        flush_wait_count++;
        pthread_rwlock_rdlock(&db->cf_list_lock);
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for in-progress compactions to complete");
    int compaction_wait_count = 0;
    while (1)
    {
        int any_compacting = 0;
        size_t compaction_queue_size = 0;

        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            if (db->column_families[i])
            {
                if (atomic_load_explicit(&db->column_families[i]->is_compacting,
                                         memory_order_acquire))
                {
                    any_compacting = 1;
                    break;
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        if (db->compaction_queue)
        {
            compaction_queue_size = queue_size(db->compaction_queue);
        }

        if (!any_compacting && compaction_queue_size == 0)
        {
            break;
        }

        if (compaction_wait_count % 100 == 0 && compaction_wait_count > 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "Still waiting for in-progress compactions (waited %d ms, queue_size=%zu)",
                compaction_wait_count, compaction_queue_size);
        }

        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        compaction_wait_count++;
    }

    result = tidesdb_backup_copy_all_cfs(db, dir, TDB_BACKUP_COPY_FINAL);
    if (result != TDB_SUCCESS) return result;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Backup completed successfully: %s", dir);
    return TDB_SUCCESS;
}

/**
 * tidesdb_clone_copy_cf_dir
 * copy a column family directory to a new location, copying all files
 * @param src_dir source directory
 * @param dst_dir destination directory
 * @return TDB_SUCCESS on success, error code on failure
 */
static int tidesdb_clone_copy_cf_dir(const char *src_dir, const char *dst_dir)
{
    struct STAT_STRUCT dst_st;
    if (STAT_FUNC(dst_dir, &dst_st) != 0)
    {
        if (mkdir(dst_dir, TDB_DIR_PERMISSIONS) != 0)
        {
            return TDB_ERR_IO;
        }
    }
    else if (!S_ISDIR(dst_st.st_mode))
    {
        return TDB_ERR_IO;
    }

    DIR *dir = opendir(src_dir);
    if (!dir) return TDB_ERR_IO;

    struct dirent *entry;
    int result = TDB_SUCCESS;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (strcmp(entry->d_name, TDB_LOCK_FILE) == 0) continue;

        /* we skip WAL files -- we don't want to copy uncommitted data */
        if (tidesdb_backup_is_wal_file(entry->d_name)) continue;

        const size_t src_len = strlen(src_dir) + strlen(PATH_SEPARATOR) + strlen(entry->d_name) + 1;
        const size_t dst_len = strlen(dst_dir) + strlen(PATH_SEPARATOR) + strlen(entry->d_name) + 1;
        char *src_path = malloc(src_len);
        char *dst_path = malloc(dst_len);
        if (!src_path || !dst_path)
        {
            free(src_path);
            free(dst_path);
            result = TDB_ERR_MEMORY;
            break;
        }

        snprintf(src_path, src_len, "%s%s%s", src_dir, PATH_SEPARATOR, entry->d_name);
        snprintf(dst_path, dst_len, "%s%s%s", dst_dir, PATH_SEPARATOR, entry->d_name);

        struct STAT_STRUCT src_st;
        if (STAT_FUNC(src_path, &src_st) != 0)
        {
            if (errno != ENOENT) result = TDB_ERR_IO;
            free(src_path);
            free(dst_path);
            if (result != TDB_SUCCESS) break;
            continue;
        }

        if (S_ISDIR(src_st.st_mode))
        {
            result = tidesdb_clone_copy_cf_dir(src_path, dst_path);
        }
        else
        {
            result = tidesdb_backup_copy_file(src_path, dst_path);
        }

        free(src_path);
        free(dst_path);

        if (result != TDB_SUCCESS) break;
    }

    closedir(dir);
    return result;
}

int tidesdb_clone_column_family(tidesdb_t *db, const char *src_name, const char *dst_name)
{
    if (!db || !src_name || !dst_name) return TDB_ERR_INVALID_ARGS;

    const int wait_result = wait_for_open(db);
    if (wait_result != TDB_SUCCESS) return wait_result;

    /* we validate names are different */
    if (strcmp(src_name, dst_name) == 0) return TDB_ERR_INVALID_ARGS;

    /* we check destination doesn't already exist */
    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, dst_name) == 0)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            TDB_DEBUG_LOG(TDB_LOG_WARN, "Clone destination CF '%s' already exists", dst_name);
            return TDB_ERR_EXISTS;
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    tidesdb_column_family_t *src_cf = tidesdb_get_column_family(db, src_name);
    if (!src_cf)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Clone source CF '%s' not found", src_name);
        return TDB_ERR_NOT_FOUND;
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Cloning column family '%s' to '%s'", src_name, dst_name);

    /* wait for any in-progress flush to complete */
    int wait_count = 0;
    while (atomic_load_explicit(&src_cf->is_flushing, memory_order_acquire) != 0 &&
           wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
        wait_count++;
    }

    /* we flush the source memtable to ensure all data is on disk */
    int result = tidesdb_flush_memtable_internal(src_cf, 0, 1);
    if (result != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to flush source CF '%s' before clone", src_name);
        return result;
    }

    /* we wait for flush to complete */
    wait_count = 0;
    while (atomic_load_explicit(&src_cf->is_flushing, memory_order_acquire) != 0 &&
           wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
        wait_count++;
    }

    /* we wait for any in-progress compaction to complete */
    wait_count = 0;
    while (atomic_load_explicit(&src_cf->is_compacting, memory_order_acquire) != 0 &&
           wait_count < TDB_CLOSE_FLUSH_WAIT_MAX_ATTEMPTS)
    {
        usleep(TDB_CLOSE_FLUSH_WAIT_SLEEP_US);
        wait_count++;
    }

    char dst_dir[TDB_MAX_PATH_LEN];
    snprintf(dst_dir, sizeof(dst_dir), "%s" PATH_SEPARATOR "%s", db->db_path, dst_name);

    /* we check destination directory doesn't exist */
    struct STAT_STRUCT st;
    if (STAT_FUNC(dst_dir, &st) == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Clone destination directory '%s' already exists", dst_dir);
        return TDB_ERR_EXISTS;
    }

    /* we copy all files from source to destination */
    result = tidesdb_clone_copy_cf_dir(src_cf->directory, dst_dir);
    if (result != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to copy CF directory from '%s' to '%s'",
                      src_cf->directory, dst_dir);
        /* we attempt cleanup */
        remove_directory(dst_dir);
        return result;
    }

    /* we update config.ini with new name */
    char config_path[TDB_MAX_PATH_LEN];
    const int config_written = snprintf(
        config_path, sizeof(config_path),
        "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT, dst_dir);

    if (config_written < 0 || (size_t)config_written >= sizeof(config_path))
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Config path too long for cloned CF '%s'", dst_name);
        remove_directory(dst_dir);
        return TDB_ERR_INVALID_ARGS;
    }

    result = tidesdb_cf_config_save_to_ini(config_path, dst_name, &src_cf->config);
    if (result != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Failed to save config for cloned CF '%s' (error: %d)",
                      dst_name, result);
        /* non-fatal, continue */
    }

    tdb_sync_directory(dst_dir);

    /* we create the new column family structure by loading from disk */
    tidesdb_column_family_config_t clone_config = src_cf->config;

    /* we clear cached comparator pointers -- they will be re-resolved */
    clone_config.comparator_fn_cached = NULL;
    clone_config.comparator_ctx_cached = NULL;

    result = tidesdb_create_column_family(db, dst_name, &clone_config);
    if (result != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create cloned CF structure '%s' (error: %d)",
                      dst_name, result);
        remove_directory(dst_dir);
        return result;
    }

    /* we get the newly created CF and recover its sstables */
    tidesdb_column_family_t *dst_cf = tidesdb_get_column_family(db, dst_name);
    if (dst_cf)
    {
        /* we recover ssts from the copied files */
        result = tidesdb_recover_sstables(dst_cf);
        if (result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to recover SSTables for cloned CF '%s'", dst_name);
            /* CF is created but may be incomplete -- the user should drop and retry */
            return result;
        }

        /* we update next_sstable_id to prevent overwriting recovered sstables
         * we scan all levels to find the maximum sstable ID */
        uint64_t max_sst_id = 0;
        const int num_levels =
            atomic_load_explicit(&dst_cf->num_active_levels, memory_order_acquire);
        for (int level_idx = 0; level_idx < num_levels; level_idx++)
        {
            tidesdb_level_t *level = dst_cf->levels[level_idx];
            if (!level) continue;

            tidesdb_sstable_t **sstables =
                atomic_load_explicit(&level->sstables, memory_order_acquire);
            const int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

            for (int sst_idx = 0; sst_idx < num_ssts; sst_idx++)
            {
                tidesdb_sstable_t *sst = sstables[sst_idx];
                if (sst && sst->id >= max_sst_id)
                {
                    max_sst_id = sst->id + 1;
                }
            }
        }

        if (max_sst_id > atomic_load(&dst_cf->next_sstable_id))
        {
            atomic_store(&dst_cf->next_sstable_id, max_sst_id);
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' updated next_sstable_id to %" PRIu64 " after clone", dst_name,
                          max_sst_id);
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "Successfully cloned CF '%s' to '%s'", src_name, dst_name);
    }

    return TDB_SUCCESS;
}

/**
 * ini_config_context_t
 * INI configuration handler context
 * @param config
 * @param target_section
 */
typedef struct
{
    tidesdb_column_family_config_t *config;
    const char *target_section;
} ini_config_context_t;

/**
 * ini_config_handler
 * INI parser handler for loading configuration
 * @param user
 * @param section
 * @param name
 * @param value
 * @return int
 */
static int ini_config_handler(void *user, const char *section, const char *name, const char *value)
{
    ini_config_context_t *ctx = (ini_config_context_t *)user;

    /* we only process our target section */
    if (strcmp(section, ctx->target_section) != 0)
    {
        return 1; /* continue parsing */
    }

    if (strcmp(name, "write_buffer_size") == 0)
    {
        ctx->config->write_buffer_size = (size_t)strtoll(value, NULL, 10);
    }
    else if (strcmp(name, "level_size_ratio") == 0)
    {
        ctx->config->level_size_ratio = (size_t)strtoll(value, NULL, 10);
    }
    else if (strcmp(name, "min_levels") == 0)
    {
        ctx->config->min_levels = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "dividing_level_offset") == 0)
    {
        ctx->config->dividing_level_offset = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "value_threshold") == 0)
    {
        ctx->config->klog_value_threshold = (size_t)strtoll(value, NULL, 10);
    }
    else if (strcmp(name, "compression_algorithm") == 0)
    {
        if (strcmp(value, "NONE") == 0)
            ctx->config->compression_algorithm = TDB_COMPRESS_NONE;
        else if (strcmp(value, "LZ4") == 0)
            ctx->config->compression_algorithm = TDB_COMPRESS_LZ4;
        else if (strcmp(value, "LZ4_FAST") == 0)
            ctx->config->compression_algorithm = TDB_COMPRESS_LZ4_FAST;
        else if (strcmp(value, "ZSTD") == 0)
            ctx->config->compression_algorithm = TDB_COMPRESS_ZSTD;
#ifndef __sun
        else if (strcmp(value, "SNAPPY") == 0)
            ctx->config->compression_algorithm = TDB_COMPRESS_SNAPPY;
#endif
    }
    else if (strcmp(name, "enable_bloom_filter") == 0)
    {
        ctx->config->enable_bloom_filter = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "bloom_fpr") == 0)
    {
        ctx->config->bloom_fpr = strtod(value, NULL);
    }
    else if (strcmp(name, "enable_block_indexes") == 0)
    {
        ctx->config->enable_block_indexes = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "index_sample_ratio") == 0)
    {
        ctx->config->index_sample_ratio = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "block_index_prefix_len") == 0)
    {
        ctx->config->block_index_prefix_len = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "sync_mode") == 0)
    {
        ctx->config->sync_mode = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "sync_interval_us") == 0)
    {
        ctx->config->sync_interval_us = (size_t)strtoll(value, NULL, 10);
    }
    else if (strcmp(name, "skip_list_max_level") == 0)
    {
        ctx->config->skip_list_max_level = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "skip_list_probability") == 0)
    {
        ctx->config->skip_list_probability = (float)strtod(value, NULL);
    }
    else if (strcmp(name, "default_isolation_level") == 0)
    {
        const int level = (int)strtol(value, NULL, 10);
        if (level >= TDB_ISOLATION_READ_UNCOMMITTED && level <= TDB_ISOLATION_SERIALIZABLE)
        {
            ctx->config->default_isolation_level = (tidesdb_isolation_level_t)level;
        }
    }
    else if (strcmp(name, "l1_file_count_trigger") == 0)
    {
        ctx->config->l1_file_count_trigger = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "l0_queue_stall_threshold") == 0)
    {
        ctx->config->l0_queue_stall_threshold = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "min_disk_space") == 0)
    {
        ctx->config->min_disk_space = (uint64_t)strtoull(value, NULL, 10);
    }
    else if (strcmp(name, "use_btree") == 0)
    {
        ctx->config->use_btree = (int)strtol(value, NULL, 10);
    }
    else if (strcmp(name, "comparator_name") == 0)
    {
        strncpy(ctx->config->comparator_name, value, TDB_MAX_COMPARATOR_NAME - 1);
        ctx->config->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    }
    else if (strcmp(name, "comparator_ctx_str") == 0)
    {
        strncpy(ctx->config->comparator_ctx_str, value, TDB_MAX_COMPARATOR_CTX - 1);
        ctx->config->comparator_ctx_str[TDB_MAX_COMPARATOR_CTX - 1] = '\0';
    }

    return 1; /* continue parsing */
}

int tidesdb_cf_config_load_from_ini(const char *ini_file, const char *section_name,
                                    tidesdb_column_family_config_t *config)
{
    if (!ini_file || !section_name || !config) return TDB_ERR_INVALID_ARGS;

    *config = tidesdb_default_column_family_config();

    ini_config_context_t ctx = {.config = config, .target_section = section_name};

    const int result = ini_parse(ini_file, ini_config_handler, &ctx);
    if (result < 0)
    {
        return TDB_ERR_IO; /* failed to open or parse */
    }
    if (result > 0)
    {
        return TDB_ERR_CORRUPTION;
    }

    return TDB_SUCCESS;
}

int tidesdb_cf_config_save_to_ini(const char *ini_file, const char *section_name,
                                  const tidesdb_column_family_config_t *config)
{
    if (!ini_file || !section_name || !config) return TDB_ERR_INVALID_ARGS;

    FILE *fp = fopen(ini_file, "w");
    if (!fp) return TDB_ERR_IO;

    fprintf(fp, "[%s]\n", section_name);

    fprintf(fp, "write_buffer_size = %zu\n", config->write_buffer_size);
    fprintf(fp, "level_size_ratio = %zu\n", config->level_size_ratio);
    fprintf(fp, "min_levels = %d\n", config->min_levels);
    fprintf(fp, "dividing_level_offset = %d\n", config->dividing_level_offset);
    fprintf(fp, "value_threshold = %zu\n", config->klog_value_threshold);

    const char *compression_str = "NONE";
    switch (config->compression_algorithm)
    {
        case TDB_COMPRESS_NONE:
            compression_str = "NONE";
            break;
        case TDB_COMPRESS_LZ4:
            compression_str = "LZ4";
            break;
        case TDB_COMPRESS_LZ4_FAST:
            compression_str = "LZ4_FAST";
            break;
        case TDB_COMPRESS_ZSTD:
            compression_str = "ZSTD";
            break;
#ifndef __sun
        case TDB_COMPRESS_SNAPPY:
            compression_str = "SNAPPY";
            break;
#endif
    }
    fprintf(fp, "compression_algorithm = %s\n", compression_str);

    fprintf(fp, "enable_bloom_filter = %d\n", config->enable_bloom_filter);
    fprintf(fp, "bloom_fpr = %f\n", config->bloom_fpr);
    fprintf(fp, "enable_block_indexes = %d\n", config->enable_block_indexes);
    fprintf(fp, "index_sample_ratio = %d\n", config->index_sample_ratio);
    fprintf(fp, "block_index_prefix_len = %d\n", config->block_index_prefix_len);
    fprintf(fp, "sync_mode = %d\n", config->sync_mode);
    fprintf(fp, "sync_interval_us = %" PRIu64 "\n", config->sync_interval_us);
    fprintf(fp, "skip_list_max_level = %d\n", config->skip_list_max_level);
    fprintf(fp, "skip_list_probability = %f\n", config->skip_list_probability);
    fprintf(fp, "default_isolation_level = %d\n", config->default_isolation_level);
    fprintf(fp, "l1_file_count_trigger = %d\n", config->l1_file_count_trigger);
    fprintf(fp, "l0_queue_stall_threshold = %d\n", config->l0_queue_stall_threshold);
    fprintf(fp, "min_disk_space = %" PRIu64 "\n", config->min_disk_space);
    fprintf(fp, "use_btree = %d\n", config->use_btree);

    fprintf(fp, "comparator_name = %s\n", config->comparator_name);
    if (config->comparator_ctx_str[0] != '\0')
    {
        fprintf(fp, "comparator_ctx_str = %s\n", config->comparator_ctx_str);
    }

    fflush(fp);
    const int fd = tdb_fileno(fp);
    if (fd >= 0)
    {
        fsync(fd);
    }
    fclose(fp);

    /* we have to sync parent directory to ensure file entry is persisted
     * uses cross-platform tdb_sync_directory (no-op on Windows, fsync on POSIX) */
    const char *last_sep = strrchr(ini_file, PATH_SEPARATOR[0]);
    if (last_sep)
    {
        char parent_dir[TDB_MAX_PATH_LEN];
        size_t parent_len = last_sep - ini_file;
        if (parent_len < TDB_MAX_PATH_LEN)
        {
            memcpy(parent_dir, ini_file, parent_len);
            parent_dir[parent_len] = '\0';
            tdb_sync_directory(parent_dir);
        }
    }

    return TDB_SUCCESS;
}

int tidesdb_cf_update_runtime_config(tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     const int persist_to_disk)
{
    if (!cf || !new_config) return TDB_ERR_INVALID_ARGS;

    cf->config.enable_bloom_filter = new_config->enable_bloom_filter;
    cf->config.bloom_fpr = new_config->bloom_fpr;
    cf->config.enable_block_indexes = new_config->enable_block_indexes;
    cf->config.index_sample_ratio = new_config->index_sample_ratio;
    cf->config.block_index_prefix_len = new_config->block_index_prefix_len;
    cf->config.compression_algorithm = new_config->compression_algorithm;
    cf->config.write_buffer_size = new_config->write_buffer_size;
    cf->config.level_size_ratio = new_config->level_size_ratio;
    cf->config.min_levels = new_config->min_levels;
    cf->config.dividing_level_offset = new_config->dividing_level_offset;
    cf->config.sync_mode = new_config->sync_mode;
    cf->config.sync_interval_us = new_config->sync_interval_us;
    cf->config.klog_value_threshold = new_config->klog_value_threshold;
    cf->config.default_isolation_level = new_config->default_isolation_level;
    cf->config.skip_list_max_level = new_config->skip_list_max_level;
    cf->config.skip_list_probability = new_config->skip_list_probability;
    cf->config.l1_file_count_trigger = new_config->l1_file_count_trigger;
    cf->config.l0_queue_stall_threshold = new_config->l0_queue_stall_threshold;
    cf->config.min_disk_space = new_config->min_disk_space;

    tidesdb_memtable_t *mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    if (mt && mt->wal)
    {
        block_manager_set_sync_mode(mt->wal, new_config->sync_mode);
    }

    if (persist_to_disk)
    {
        char config_path[MAX_FILE_PATH_LENGTH];
        snprintf(config_path, sizeof(config_path),
                 "%s" PATH_SEPARATOR
                 "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT,
                 cf->db->config.db_path, cf->name);

        const int result = tidesdb_cf_config_save_to_ini(config_path, cf->name, &cf->config);
        if (result != TDB_SUCCESS)
        {
            return result;
        }
    }

    return TDB_SUCCESS;
}

static tidesdb_block_index_t *compact_block_index_create(uint32_t initial_capacity,
                                                         uint8_t prefix_len,
                                                         const tidesdb_comparator_fn comparator,
                                                         void *comparator_ctx)
{
    if (initial_capacity == 0) initial_capacity = TDB_INITIAL_BLOCK_INDEX_CAPACITY;
    if (prefix_len < TDB_BLOCK_INDEX_PREFIX_MIN) prefix_len = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN;

    tidesdb_block_index_t *index = calloc(1, sizeof(tidesdb_block_index_t));
    if (!index) return NULL;

    index->min_key_prefixes = malloc(initial_capacity * prefix_len);
    index->max_key_prefixes = malloc(initial_capacity * prefix_len);
    index->file_positions = malloc(initial_capacity * sizeof(uint64_t));

    if (!index->min_key_prefixes || !index->max_key_prefixes || !index->file_positions)
    {
        compact_block_index_free(index);
        return NULL;
    }

    index->capacity = initial_capacity;
    index->count = 0;
    index->prefix_len = prefix_len;
    index->comparator = comparator;
    index->comparator_ctx = comparator_ctx;

    return index;
}

static uint8_t *compact_block_index_serialize(const tidesdb_block_index_t *index, size_t *out_size)
{
    if (!index || !out_size) return NULL;

    /* header
     * count (4) + prefix_len (1) + file_positions (varint) + min/max prefixes */
    const size_t max_size = sizeof(uint32_t) + sizeof(uint8_t) +
                            index->count * 10 +                   /* file_positions (varint) */
                            index->count * index->prefix_len * 2; /* min + max prefixes */

    uint8_t *data = malloc(max_size);
    if (!data) return NULL;

    uint8_t *ptr = data;

    /* header
     * count + prefix_len */
    encode_uint32_le_compat(ptr, index->count);
    ptr += sizeof(uint32_t);
    *ptr++ = index->prefix_len;

    /* delta encode + varint compress file_positions */
    if (index->count > 0)
    {
        /* first file position stored as-is */
        ptr += encode_varint(ptr, index->file_positions[0]);

        /* remaining file positions stored as deltas */
        for (uint32_t i = 1; i < index->count; i++)
        {
            const uint64_t delta = index->file_positions[i] - index->file_positions[i - 1];
            ptr += encode_varint(ptr, delta);
        }
    }

    const size_t prefix_bytes = index->count * index->prefix_len;
    memcpy(ptr, index->min_key_prefixes, prefix_bytes);
    ptr += prefix_bytes;
    memcpy(ptr, index->max_key_prefixes, prefix_bytes);
    ptr += prefix_bytes;

    /* we calc actual size and shrink buffer */
    const size_t actual_size = ptr - data;
    uint8_t *final_data = realloc(data, actual_size);
    if (!final_data)
    {
        /* realloc failed, but the original data is still valid */
        *out_size = actual_size;
        return data;
    }

    *out_size = actual_size;
    return final_data;
}

static tidesdb_block_index_t *compact_block_index_deserialize(const uint8_t *data,
                                                              const size_t data_size)
{
    if (!data || data_size < sizeof(uint32_t) + sizeof(uint8_t)) return NULL;

    const uint8_t *ptr = data;
    const uint8_t *end = data + data_size;

    /* we read header
     * count + prefix_len */
    const uint32_t count = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    const uint8_t prefix_len = *ptr++;

    if (prefix_len < TDB_BLOCK_INDEX_PREFIX_MIN)
    {
        TDB_DEBUG_LOG(
            TDB_LOG_WARN,
            "Block index deserialization failed with invalid prefix_len=%u (must be %d-%d)",
            prefix_len, TDB_BLOCK_INDEX_PREFIX_MIN, TDB_BLOCK_INDEX_PREFIX_MAX);
        return NULL; /* invalid format */
    }

    if (count > TDB_BLOCK_INDEX_MAX_COUNT)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Block index deserialization failed with unreasonable count=%u",
                      count);
        return NULL;
    }

    tidesdb_block_index_t *index = calloc(1, sizeof(tidesdb_block_index_t));
    if (!index) return NULL;

    /* we handle empty index (count = 0) */
    if (count == 0)
    {
        index->count = 0;
        index->capacity = 0;
        index->prefix_len = prefix_len;
        index->min_key_prefixes = NULL;
        index->max_key_prefixes = NULL;
        index->file_positions = NULL;
        return index;
    }

    index->min_key_prefixes = malloc(count * prefix_len);
    index->max_key_prefixes = malloc(count * prefix_len);
    index->file_positions = malloc(count * sizeof(uint64_t));

    if (!index->min_key_prefixes || !index->max_key_prefixes || !index->file_positions)
    {
        compact_block_index_free(index);
        return NULL;
    }

    /* we decode file_positions (delta-encoded varints) */
    if (count > 0)
    {
        uint64_t value;
        /* first file position */
        int bytes_read = decode_varint(ptr, &value, (int)(end - ptr));
        if (bytes_read < 0) goto error;
        index->file_positions[0] = value;
        ptr += bytes_read;

        /* remaining file positions (deltas) */
        for (uint32_t i = 1; i < count; i++)
        {
            uint64_t delta;
            bytes_read = decode_varint(ptr, &delta, (int)(end - ptr));
            if (bytes_read < 0) goto error;
            ptr += bytes_read;
            index->file_positions[i] = index->file_positions[i - 1] + delta;
        }
    }

    const size_t prefix_bytes = count * prefix_len;
    if (ptr + prefix_bytes > end) goto error;
    memcpy(index->min_key_prefixes, ptr, prefix_bytes);
    ptr += prefix_bytes;

    if (ptr + prefix_bytes > end) goto error;
    memcpy(index->max_key_prefixes, ptr, prefix_bytes);
    ptr += prefix_bytes;

    index->count = count;
    index->capacity = count;
    index->prefix_len = prefix_len;
    index->comparator = NULL;
    index->comparator_ctx = NULL;

    return index;

error:
    compact_block_index_free(index);
    return NULL;
}

/**
 * compact_block_index_add
 * add a new entry to the block index
 * @param index block index
 * @param min_key minimum key in block
 * @param min_key_len length of minimum key
 * @param max_key maximum key in block
 * @param max_key_len length of maximum key
 * @param file_position position of block in file
 * @return 0 on success, -1 on error
 */
static int compact_block_index_add(tidesdb_block_index_t *index, const uint8_t *min_key,
                                   const size_t min_key_len, const uint8_t *max_key,
                                   const size_t max_key_len, const uint64_t file_position)
{
    if (!index || !min_key || !max_key) return -1;

    if (index->count >= index->capacity)
    {
        const uint32_t new_capacity = index->capacity * 2;

        /* we must handle realloc failures carefully to avoid memory leaks
         * if any realloc fails, we keep the original pointers intact */
        uint8_t *new_min = realloc(index->min_key_prefixes, new_capacity * index->prefix_len);
        if (!new_min) return -1;
        index->min_key_prefixes = new_min;

        uint8_t *new_max = realloc(index->max_key_prefixes, new_capacity * index->prefix_len);
        if (!new_max) return -1;
        index->max_key_prefixes = new_max;

        uint64_t *new_positions = realloc(index->file_positions, new_capacity * sizeof(uint64_t));
        if (!new_positions) return -1;
        index->file_positions = new_positions;

        index->capacity = new_capacity;
    }

    /* we copy prefixes (pad with zeros if key is shorter than prefix_len) */
    const size_t min_copy_len = (min_key_len < index->prefix_len) ? min_key_len : index->prefix_len;
    const size_t max_copy_len = (max_key_len < index->prefix_len) ? max_key_len : index->prefix_len;

    uint8_t *min_dest = index->min_key_prefixes + (index->count * index->prefix_len);
    uint8_t *max_dest = index->max_key_prefixes + (index->count * index->prefix_len);

    memcpy(min_dest, min_key, min_copy_len);
    if (min_copy_len < index->prefix_len)
    {
        memset(min_dest + min_copy_len, 0, index->prefix_len - min_copy_len);
    }

    memcpy(max_dest, max_key, max_copy_len);
    if (max_copy_len < index->prefix_len)
    {
        memset(max_dest + max_copy_len, 0, index->prefix_len - max_copy_len);
    }

    index->file_positions[index->count] = file_position;
    index->count++;

    return 0;
}

/**
 * compact_block_index_find_predecessor
 * finds the block that should contain the given key using binary search
 *
 * algorithm:
 * 1. early exit if key < first blocks min_key (return first block)
 * 2. binary search for rightmost block where min_key <= search_key <= max_key
 * 3. if no exact range match, fallback to last block where min_key <= search_key
 *
 * this ensures we always start searching from the correct block, avoiding
 * false negatives when keys fall between indexed blocks or at block boundaries.
 *
 * @param index the block index to search
 * @param key the search key
 * @param key_len length of the search key
 * @param file_position output parameter for the found block file position
 * @return 0 on success, -1 if no suitable block found
 */
static int compact_block_index_find_predecessor(const tidesdb_block_index_t *index,
                                                const uint8_t *key, const size_t key_len,
                                                uint64_t *file_position)
{
    if (!index || !key || index->count == 0) return -1;

    uint8_t search_prefix[TDB_BLOCK_INDEX_PREFIX_MAX];
    const size_t copy_len = (key_len < index->prefix_len) ? key_len : index->prefix_len;
    memcpy(search_prefix, key, copy_len);
    if (copy_len < index->prefix_len)
    {
        memset(search_prefix + copy_len, 0, index->prefix_len - copy_len);
    }

    /* we check if key is before first block */
    const uint8_t *first_min = index->min_key_prefixes;
    int cmp_first;
    if (index->comparator)
    {
        cmp_first = index->comparator(search_prefix, index->prefix_len, first_min,
                                      index->prefix_len, index->comparator_ctx);
    }
    else
    {
        cmp_first = memcmp(search_prefix, first_min, index->prefix_len);
    }

    if (cmp_first < 0)
    {
        *file_position = index->file_positions[0];
        return 0;
    }

    /* we utilize binary search to find the rightmost block where min_key <= search_key <= max_key
     * or the last block where min_key <= search_key if no exact range match */
    int64_t left = 0;
    int64_t right = index->count - 1;
    int64_t exact_match = -1;
    int64_t fallback = -1;

    while (left <= right)
    {
        const int64_t mid = left + (right - left) / 2;
        const uint8_t *mid_min_prefix = index->min_key_prefixes + (mid * index->prefix_len);
        const uint8_t *mid_max_prefix = index->max_key_prefixes + (mid * index->prefix_len);

        /* we compare search key with blocks min and max keys */
        int cmp_min, cmp_max;
        if (index->comparator)
        {
            cmp_min = index->comparator(mid_min_prefix, index->prefix_len, search_prefix,
                                        index->prefix_len, index->comparator_ctx);
            cmp_max = index->comparator(search_prefix, index->prefix_len, mid_max_prefix,
                                        index->prefix_len, index->comparator_ctx);
        }
        else
        {
            cmp_min = memcmp(mid_min_prefix, search_prefix, index->prefix_len);
            cmp_max = memcmp(search_prefix, mid_max_prefix, index->prefix_len);
        }

        if (cmp_min <= 0)
        {
            /* min_key <= search_key, keep it as fallback candidate */
            fallback = mid;

            if (cmp_max <= 0)
            {
                /* key lies inside this block; we must remember and search right for the rightmost
                 * match */
                exact_match = mid;
                left = mid + 1;
            }
            else
            {
                /* search_key > max_key -- we need to search right for a tighter block */
                left = mid + 1;
            }
        }
        else
        {
            /* search_key < min_key -- we need to search left */
            right = mid - 1;
        }
    }

    if (exact_match >= 0)
    {
        *file_position = index->file_positions[exact_match];
        return 0;
    }

    if (fallback >= 0)
    {
        *file_position = index->file_positions[fallback];
        return 0;
    }

    return -1; /* no predecessor found */
}

/**
 * compact_block_index_free
 * free a block index
 * @param index block index to free
 */
static void compact_block_index_free(tidesdb_block_index_t *index)
{
    if (!index) return;
    free(index->min_key_prefixes);
    free(index->max_key_prefixes);
    free(index->file_positions);
    free(index);
}

#ifdef TDB_ENABLE_READ_PROFILING

/**
 * tidesdb_get_read_stats
 * get read statistics for the passed database
 * @param db database to query
 * @param stats pointer to read stats structure
 * @return 0 on success, -1 on error
 */
int tidesdb_get_read_stats(tidesdb_t *db, tidesdb_read_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;

    stats->total_reads = atomic_load(&db->read_stats.total_reads);
    stats->memtable_hits = atomic_load(&db->read_stats.memtable_hits);
    stats->immutable_hits = atomic_load(&db->read_stats.immutable_hits);
    stats->sstable_hits = atomic_load(&db->read_stats.sstable_hits);
    stats->levels_searched = atomic_load(&db->read_stats.levels_searched);
    stats->sstables_checked = atomic_load(&db->read_stats.sstables_checked);
    stats->bloom_checks = atomic_load(&db->read_stats.bloom_checks);
    stats->bloom_hits = atomic_load(&db->read_stats.bloom_hits);
    stats->blocks_read = atomic_load(&db->read_stats.blocks_read);
    stats->cache_block_hits = atomic_load(&db->read_stats.cache_block_hits);
    stats->cache_block_misses = atomic_load(&db->read_stats.cache_block_misses);
    stats->disk_reads = atomic_load(&db->read_stats.disk_reads);

    return TDB_SUCCESS;
}

/**
 * tidesdb_print_read_stats
 * print read statistics for passed database
 * @param db database to query
 */
void tidesdb_print_read_stats(tidesdb_t *db)
{
    if (!db) return;

    tidesdb_read_stats_t stats;
    tidesdb_get_read_stats(db, &stats);

    uint64_t total_block_accesses = stats.cache_block_hits + stats.cache_block_misses;
    double cache_hit_rate =
        total_block_accesses > 0 ? (100.0 * stats.cache_block_hits / total_block_accesses) : 0.0;
    double bloom_hit_rate =
        stats.bloom_checks > 0 ? (100.0 * stats.bloom_hits / stats.bloom_checks) : 0.0;
    double avg_levels_per_read =
        stats.total_reads > 0 ? ((double)stats.levels_searched / stats.total_reads) : 0.0;
    double avg_sstables_per_read =
        stats.total_reads > 0 ? ((double)stats.sstables_checked / stats.total_reads) : 0.0;
    double avg_blocks_per_read =
        stats.total_reads > 0 ? ((double)stats.blocks_read / stats.total_reads) : 0.0;
    printf("\n*---------------------- TidesDB Read Profiling Stats ----------------------*\n");
    printf("Total Reads:           %" PRIu64 "\n", stats.total_reads);
    printf("\nRead Hit Location:\n");
    printf("  Memtable hits:       %" PRIu64 " (%.1f%%)\n", stats.memtable_hits,
           stats.total_reads > 0 ? 100.0 * stats.memtable_hits / stats.total_reads : 0.0);
    printf("  Immutable hits:      %" PRIu64 " (%.1f%%)\n", stats.immutable_hits,
           stats.total_reads > 0 ? 100.0 * stats.immutable_hits / stats.total_reads : 0.0);
    printf("  SSTable hits:        %" PRIu64 " (%.1f%%)\n", stats.sstable_hits,
           stats.total_reads > 0 ? 100.0 * stats.sstable_hits / stats.total_reads : 0.0);
    printf("\nSSTable Search:\n");
    printf("  Levels searched:     %" PRIu64 " (avg: %.2f per read)\n", stats.levels_searched,
           avg_levels_per_read);
    printf("  SSTables checked:    %" PRIu64 " (avg: %.2f per read)\n", stats.sstables_checked,
           avg_sstables_per_read);
    printf("  Bloom checks:        %" PRIu64 "\n", stats.bloom_checks);
    printf("  Bloom hits:          %" PRIu64 " (%.1f%%)\n", stats.bloom_hits, bloom_hit_rate);
    printf("\nBlock-Level Cache:\n");
    printf("  Cache hits:          %" PRIu64 "\n", stats.cache_block_hits);
    printf("  Cache misses:        %" PRIu64 "\n", stats.cache_block_misses);
    printf("  Cache hit rate:      %.1f%%\n", cache_hit_rate);
    printf("  Blocks read:         %" PRIu64 " (avg: %.2f per read)\n", stats.blocks_read,
           avg_blocks_per_read);
    printf("  Disk reads:          %" PRIu64 "\n", stats.disk_reads);

    if (db->clock_cache)
    {
        clock_cache_stats_t cache_stats;
        clock_cache_get_stats(db->clock_cache, &cache_stats);
        printf("\nClock Cache Stats:\n");
        printf("  Total entries:       %zu\n", cache_stats.total_entries);
        printf("  Total bytes:         %.2f MB\n", cache_stats.total_bytes / (1024.0 * 1024.0));
        printf("  Global hits:         %" PRIu64 "\n", cache_stats.hits);
        printf("  Global misses:       %" PRIu64 "\n", cache_stats.misses);
        printf("  Global hit rate:     %.1f%%\n", cache_stats.hit_rate * 100.0);
    }
    printf("*--------------------------------------------------------------------------*\n\n");
}

/**
 * tidesdb_reset_read_stats
 * reset read statistics for the database
 * @param db database to reset stats for
 */
void tidesdb_reset_read_stats(tidesdb_t *db)
{
    if (!db) return;

    atomic_store(&db->read_stats.total_reads, 0);
    atomic_store(&db->read_stats.memtable_hits, 0);
    atomic_store(&db->read_stats.immutable_hits, 0);
    atomic_store(&db->read_stats.sstable_hits, 0);
    atomic_store(&db->read_stats.levels_searched, 0);
    atomic_store(&db->read_stats.sstables_checked, 0);
    atomic_store(&db->read_stats.bloom_checks, 0);
    atomic_store(&db->read_stats.bloom_hits, 0);
    atomic_store(&db->read_stats.blocks_read, 0);
    atomic_store(&db->read_stats.cache_block_hits, 0);
    atomic_store(&db->read_stats.cache_block_misses, 0);
    atomic_store(&db->read_stats.disk_reads, 0);
}
#endif

void tidesdb_free(void *ptr)
{
    if (!ptr) return;
    free(ptr);
}