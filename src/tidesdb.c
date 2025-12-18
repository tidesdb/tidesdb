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
int _tidesdb_log_level = TDB_LOG_DEBUG; /* default to DEBUG level */

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

/* kv pair flags */
#define TDB_KV_FLAG_TOMBSTONE 0x01
#define TDB_KV_FLAG_HAS_TTL   0x02
#define TDB_KV_FLAG_HAS_VLOG  0x04
#define TDB_KV_FLAG_DELTA_SEQ 0x08

/* multi-cf transaction sequence flag */
#define TDB_MULTI_CF_SEQ_FLAG (1ULL << 63)

#define TDB_WAL_PREFIX                   "wal_"
#define TDB_WAL_EXT                      ".log"
#define TDB_COLUMN_FAMILY_CONFIG_NAME    "config"
#define TDB_COLUMN_FAMILY_MANIFEST_NAME  "MANIFEST"
#define TDB_COLUMN_FAMILY_CONFIG_EXT     ".ini"
#define TDB_LEVEL_PREFIX                 "L"
#define TDB_LEVEL_PARTITION_PREFIX       "P"
#define TDB_SSTABLE_KLOG_EXT             ".klog"
#define TDB_SSTABLE_VLOG_EXT             ".vlog"
#define TDB_CACHE_KEY_SIZE               32
#define TDB_SSTABLE_METADATA_MAGIC       0x5353544D
#define TDB_SSTABLE_METADATA_HEADER_SIZE 84
#define TDB_KLOG_BLOCK_SIZE              (64 * 1024)
#define TDB_STACK_SSTS                   64
#define TDB_ITER_STACK_KEY_SIZE          256

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
/* initial capacity for active txn list */
#define TDB_ACTIVE_TXN_INITIAL_CAPACITY 1024
/* hash table capacity for write set (power of 2) */
#define TDB_WRITE_SET_HASH_CAPACITY 2048
/* hash table capacity for read set (power of 2) */
#define TDB_READ_SET_HASH_CAPACITY 2048
/* empty slot marker for write set hash */
#define TDB_WRITE_SET_HASH_EMPTY -1
/* empty slot marker for read set hash */
#define TDB_READ_SET_HASH_EMPTY -1
/* xxhash seed for transaction hash tables */
#define TDB_TXN_HASH_SEED 0x9e3779b9
/* max linear probe attempts before giving up */
#define TDB_TXN_MAX_PROBE_LENGTH 32

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

/* spooky-style Level 1 file count compaction triggers
 * α (alpha) -- trigger compaction when Level 1 reaches this many files
 * β (beta) -- slow down writes when Level 1 reaches this many files
 * γ (gamma) -- stop writes when Level 1 reaches this many files (emergency) */
#define TDB_L1_FILE_NUM_COMPACTION_TRIGGER 4      /* α -- compact at 4 files */
#define TDB_L1_SLOWDOWN_WRITES_TRIGGER     20     /* β -- throttle at 20 files */
#define TDB_L1_STOP_WRITES_TRIGGER         36     /* γ -- stall at 36 files */
#define TDB_L1_SLOWDOWN_WRITES_DELAY_US    20000  /* β delay 20ms throttle */
#define TDB_L1_STOP_WRITES_DELAY_US        100000 /* γ delay 100ms stall */

/* backpressure configuration */
#define TDB_BACKPRESSURE_THRESHOLD_L1_FULL     99
#define TDB_BACKPRESSURE_THRESHOLD_L1_CRITICAL 98
#define TDB_BACKPRESSURE_THRESHOLD_L1_HIGH     95
#define TDB_BACKPRESSURE_THRESHOLD_L1_MODERATE 90
#define TDB_BACKPRESSURE_DELAY_EMERGENCY_US    50000
#define TDB_BACKPRESSURE_DELAY_CRITICAL_US     10000
#define TDB_BACKPRESSURE_DELAY_HIGH_US         5000
#define TDB_BACKPRESSURE_DELAY_MODERATE_US     1000

/* immutable queue backpressure configuration */
#define TDB_BACKPRESSURE_IMMUTABLE_EMERGENCY          10
#define TDB_BACKPRESSURE_IMMUTABLE_CRITICAL           6
#define TDB_BACKPRESSURE_IMMUTABLE_MODERATE           3
#define TDB_BACKPRESSURE_IMMUTABLE_EMERGENCY_DELAY_US 20000
#define TDB_BACKPRESSURE_IMMUTABLE_CRITICAL_DELAY_US  5000
#define TDB_BACKPRESSURE_IMMUTABLE_MODERATE_DELAY_US  1000

/* sstable reaper thread configuration */
#define TDB_SSTABLE_REAPER_SLEEP_US    100000
#define TDB_SSTABLE_REAPER_EVICT_RATIO 0.25

/* time conversion constants for pthread_cond_timedwait */
#define TDB_MICROSECONDS_PER_SECOND     1000000
#define TDB_NANOSECONDS_PER_SECOND      1000000000
#define TDB_NANOSECONDS_PER_MICROSECOND 1000

#define TDB_MAX_TXN_CFS  10000
#define TDB_MAX_PATH_LEN 4096
#define TDB_MAX_TXN_OPS  100000
/* similar to relational database systems like oracle, where table and column names are limited to
 * 128 characters */
#define TDB_MAX_CF_NAME_LEN                     128
#define TDB_MEMORY_PERCENTAGE                   0.6
#define TDB_MIN_KEY_VALUE_SIZE                  (1024 * 1024)
#define TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY 32
#define TDB_MAX_LEVELS                          32
#define TDB_DISK_SPACE_CHECK_INTERVAL_SECONDS   60
#define NO_CF_SYNC_SLEEP_US                     100000

/* klog block configuration */
#define TDB_KLOG_BLOCK_INITIAL_CAPACITY 512

/* block index validation */
#define TDB_BLOCK_INDEX_PREFIX_MIN 4
#define TDB_BLOCK_INDEX_PREFIX_MAX 256
#define TDB_BLOCK_INDEX_MAX_COUNT  1000000

/* merge and serialization configuration */
#define TDB_MERGE_MIN_ESTIMATED_ENTRIES 100
#define TDB_KLOG_DELTA_SEQ_MAX_DIFF     1000000

/* recovery configuration */
#define TDB_MULTI_CF_TRACKER_INITIAL_CAPACITY 1024

/* iterator seek configuration */
/* max blocks to scan during seek (prevents infinite loops) */
#define TDB_ITER_SEEK_MAX_BLOCKS_SCAN 100000

#define TDB_COMMIT_STATUS_BUFFER_SIZE    65536
#define TDB_WAL_GROUP_COMMIT_BUFFER_SIZE (4 * 1024 * 1024)

/* WAL group buffer writer synchronization */
#define TDB_WAL_GROUP_WRITER_WAIT_US         10
#define TDB_WAL_GROUP_WRITER_MAX_WAIT_CYCLES 1000

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
 * @param data flexible array: [key_data][value_data if inline]
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
 * @param capacity allocated capacity for arrays (to prevent buffer overflow)
 * @param is_arena_allocated 1 if arena-allocated (deserialized), 0 if separate mallocs (created)
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

/**
 * tidesdb_commit_status_t
 * tracks commit status of transactions for visibility determination
 * uses a circular buffer to track recent commit sequences
 * all operations are lock-free using atomics and CAS
 * @param status array of commit statuses (0=in-progress, 1=committed, 2=aborted)
 * @param min_seq minimum sequence number tracked in this buffer
 * @param max_seq maximum sequence number tracked in this buffer
 * @param capacity size of the status array
 */
#define TDB_COMMIT_STATUS_IN_PROGRESS 0
#define TDB_COMMIT_STATUS_COMMITTED   1
#define TDB_COMMIT_STATUS_ABORTED     2

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
            block_manager_cursor_t *vlog_cursor;
            tidesdb_klog_block_t *current_block;
            block_manager_block_t *current_block_data;
            tidesdb_ref_counted_block_t *current_rc_block;
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
 * @param capacity size of the circular buffer
 * @return commit status tracker or NULL on error
 */
static tidesdb_commit_status_t *tidesdb_commit_status_create(size_t capacity)
{
    tidesdb_commit_status_t *cs = malloc(sizeof(tidesdb_commit_status_t));
    if (!cs) return NULL;

    cs->status = malloc(capacity * sizeof(_Atomic(uint8_t)));
    if (!cs->status)
    {
        free(cs);
        return NULL;
    }

    /* init all slots as in-progress (will be updated as txns complete) */
    for (size_t i = 0; i < capacity; i++)
    {
        atomic_init(&cs->status[i], TDB_COMMIT_STATUS_IN_PROGRESS);
    }

    atomic_init(&cs->min_seq, 1);
    atomic_init(&cs->max_seq, 0);
    cs->capacity = capacity;

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
 * marks a sequence as committed or aborted
 * @param cs commit status tracker
 * @param seq sequence number
 * @param status TDB_COMMIT_STATUS_COMMITTED or TDB_COMMIT_STATUS_ABORTED
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
static int tidesdb_visibility_check_callback(void *opaque_ctx, uint64_t seq)
{
    if (!opaque_ctx || seq == 0) return 0;

    tidesdb_commit_status_t *cs = (tidesdb_commit_status_t *)opaque_ctx;

    /* we map seq to circular buffer index */
    size_t idx = seq % cs->capacity;
    uint8_t status = atomic_load_explicit(&cs->status[idx], memory_order_acquire);

    /* only COMMITTED versions are visible */
    return (status == TDB_COMMIT_STATUS_COMMITTED);
}

/**
 * multi_cf_txn_entry_t
 * @param seq global sequence number
 * @param cf_names array of CF names that have this sequence
 * @param num_cfs_seen how many CFs have this seq
 * @param expected_num_cfs how many CFs should have it
 * @param expected_cf_names which CFs should have it
 * @param next linked list for hash collisions
 */
typedef struct multi_cf_txn_entry_t
{
    uint64_t seq;
    char **cf_names;
    int num_cfs_seen;
    int expected_num_cfs;
    char **expected_cf_names;
    struct multi_cf_txn_entry_t *next;
} multi_cf_txn_entry_t;

/**
 * multi_cf_txn_tracker_t
 * tracks multi-CF transactions during recovery to validate completeness
 * simple hash table where seq -> list of CF names that have this sequence
 * @param buckets hash table buckets
 * @param num_buckets size of hash table
 */
typedef struct
{
    multi_cf_txn_entry_t **buckets;
    int num_buckets;
} multi_cf_txn_tracker_t;

/**
 * multi_cf_txn_tracker_create
 * creates a new multi-CF transaction tracker
 * @param num_buckets number of buckets in hash table
 * @return pointer to new tracker or NULL on failure
 */
static multi_cf_txn_tracker_t *multi_cf_tracker_create(int num_buckets)
{
    multi_cf_txn_tracker_t *tracker = calloc(1, sizeof(multi_cf_txn_tracker_t));
    if (!tracker) return NULL;

    tracker->buckets = calloc(num_buckets, sizeof(multi_cf_txn_entry_t *));
    if (!tracker->buckets)
    {
        free(tracker);
        return NULL;
    }
    tracker->num_buckets = num_buckets;
    return tracker;
}

/**
 * multi_cf_tracker_free
 * frees a multi-CF transaction tracker
 * @param tracker tracker to free
 */
static void multi_cf_tracker_free(multi_cf_txn_tracker_t *tracker)
{
    if (!tracker) return;

    for (int i = 0; i < tracker->num_buckets; i++)
    {
        multi_cf_txn_entry_t *entry = tracker->buckets[i];
        while (entry)
        {
            multi_cf_txn_entry_t *next = entry->next;
            for (int j = 0; j < entry->num_cfs_seen; j++)
            {
                free(entry->cf_names[j]);
            }
            free(entry->cf_names);
            for (int j = 0; j < entry->expected_num_cfs; j++)
            {
                free(entry->expected_cf_names[j]);
            }
            free(entry->expected_cf_names);
            free(entry);
            entry = next;
        }
    }
    free(tracker->buckets);
    free(tracker);
}

/**
 * multi_cf_tracker_add
 * adds a new entry to the multi-CF transaction tracker
 * @param tracker tracker to add entry to
 * @param seq global sequence number
 * @param cf_name CF name
 * @param expected_cfs array of expected CF names
 * @param num_expected number of expected CFs
 */
static void multi_cf_tracker_add(multi_cf_txn_tracker_t *tracker, uint64_t seq, const char *cf_name,
                                 char **expected_cfs, int num_expected)
{
    if (!tracker || !cf_name) return;

    int bucket = (int)(seq % tracker->num_buckets);

    multi_cf_txn_entry_t *entry = tracker->buckets[bucket];
    while (entry && entry->seq != seq)
    {
        entry = entry->next;
    }

    if (!entry)
    {
        entry = calloc(1, sizeof(multi_cf_txn_entry_t));
        if (!entry) return;

        entry->seq = seq;
        entry->cf_names = NULL;
        entry->num_cfs_seen = 0;
        entry->expected_num_cfs = num_expected;

        if (num_expected > 0 && expected_cfs)
        {
            entry->expected_cf_names = calloc(num_expected, sizeof(char *));
            if (entry->expected_cf_names)
            {
                for (int i = 0; i < num_expected; i++)
                {
                    entry->expected_cf_names[i] = tdb_strdup(expected_cfs[i]);
                }
            }
        }

        entry->next = tracker->buckets[bucket];
        tracker->buckets[bucket] = entry;
    }

    char **new_cf_names = realloc(entry->cf_names, (entry->num_cfs_seen + 1) * sizeof(char *));
    if (new_cf_names)
    {
        entry->cf_names = new_cf_names;
        entry->cf_names[entry->num_cfs_seen] = tdb_strdup(cf_name);
        entry->num_cfs_seen++;
    }
}

/**
 * multi_cf_tracker_is_complete
 * checks if a multi-CF transaction is complete
 * @param tracker tracker to check
 * @param seq global sequence number
 * @return 1 if transaction is complete, 0 otherwise
 */
static int multi_cf_tracker_is_complete(multi_cf_txn_tracker_t *tracker, uint64_t seq)
{
    if (!tracker) return 0;

    const int bucket = (int)(seq % tracker->num_buckets);
    multi_cf_txn_entry_t *entry = tracker->buckets[bucket];

    while (entry && entry->seq != seq)
    {
        entry = entry->next;
    }

    if (!entry) return 0;

    /* tx is complete if all expected CFs have it */
    if (entry->num_cfs_seen != entry->expected_num_cfs) return 0;

    /* verify all expected CFs are present */
    for (int i = 0; i < entry->expected_num_cfs; i++)
    {
        int found = 0;
        for (int j = 0; j < entry->num_cfs_seen; j++)
        {
            if (strcmp(entry->expected_cf_names[i], entry->cf_names[j]) == 0)
            {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }

    return 1;
}

/**
 * encode_varint_v2
 * encode uint64_t as varint (1-10 bytes)
 * @param buf output buffer (must have at least 10 bytes)
 * @param value value to encode
 * @return number of bytes written
 */
static inline int encode_varint_v2(uint8_t *buf, uint64_t value)
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
 * decode_varint_v2
 * decode varint to uint64_t
 * @param buf input buffer
 * @param value output value
 * @param max_bytes maximum bytes to read (bounds check)
 * @return number of bytes read, or -1 on error
 */
static inline int decode_varint_v2(const uint8_t *buf, uint64_t *value, int max_bytes)
{
    *value = 0;
    int shift = 0;
    int pos = 0;

    while (pos < max_bytes)
    {
        uint8_t byte = buf[pos++];
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
 * varint_size
 * calculate exact size of varint encoding for a value
 * @param value value to encode
 * @return number of bytes needed
 */
static inline size_t varint_size(uint64_t value)
{
    size_t size = 1;
    while (value >= 0x80)
    {
        size++;
        value >>= 7;
    }
    return size;
}

static tidesdb_klog_block_t *tidesdb_klog_block_create(void);
static void tidesdb_klog_block_free(tidesdb_klog_block_t *block);
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        tidesdb_t *db, tidesdb_column_family_config_t *config);
static int tidesdb_klog_block_is_full(tidesdb_klog_block_t *block, size_t max_size);
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

static int tidesdb_sstable_get_block_managers(tidesdb_t *db, tidesdb_sstable_t *sst,
                                              tidesdb_block_managers_t *bms);
static int tidesdb_vlog_read_value(tidesdb_t *db, tidesdb_sstable_t *sst, uint64_t vlog_offset,
                                   size_t value_size, uint8_t **value);
static int tidesdb_vlog_read_value_with_cursor(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               block_manager_cursor_t *cursor, uint64_t vlog_offset,
                                               size_t value_size, uint8_t **value);
static tidesdb_sstable_t *tidesdb_sstable_create(tidesdb_t *db, const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config);
static void tidesdb_sstable_free(tidesdb_t *db, tidesdb_sstable_t *sst);

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
static void tidesdb_sstable_unref(tidesdb_t *db, tidesdb_sstable_t *sst);
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable, tidesdb_column_family_t *cf);
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               size_t key_size, tidesdb_kv_pair_t **kv);
static int tidesdb_sstable_load(tidesdb_t *db, tidesdb_sstable_t *sst);
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity);
static void tidesdb_level_free(tidesdb_t *db, tidesdb_level_t *level);
static int tidesdb_level_add_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst);
static int tidesdb_level_remove_sstable(tidesdb_t *db, tidesdb_level_t *level,
                                        tidesdb_sstable_t *sst);
static int tidesdb_level_update_boundaries(tidesdb_level_t *level, tidesdb_level_t *largest_level);
static tidesdb_merge_heap_t *tidesdb_merge_heap_create(skip_list_comparator_fn comparator,
                                                       void *comparator_ctx);
static void tidesdb_merge_heap_free(tidesdb_merge_heap_t *heap);
static int tidesdb_merge_heap_add_source(tidesdb_merge_heap_t *heap,
                                         tidesdb_merge_source_t *source);
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap,
                                                 tidesdb_sstable_t **corrupted_sst);
static int tidesdb_merge_heap_empty(tidesdb_merge_heap_t *heap);
static tidesdb_merge_source_t *tidesdb_merge_source_from_memtable(
    skip_list_t *memtable, tidesdb_column_family_config_t *config,
    tidesdb_immutable_memtable_t *imm);
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable(tidesdb_t *db,
                                                                 tidesdb_sstable_t *sst);
static void tidesdb_merge_source_free(tidesdb_merge_source_t *source);
static int tidesdb_merge_source_advance(tidesdb_merge_source_t *source);
static int tidesdb_merge_source_retreat(tidesdb_merge_source_t *source);
static int tidesdb_full_preemptive_merge(tidesdb_column_family_t *cf, int start_level,
                                         int target_level);
static int tidesdb_dividing_merge(tidesdb_column_family_t *cf, int target_level);
static int tidesdb_partitioned_merge(tidesdb_column_family_t *cf, int start_level, int end_level);
static int tidesdb_trigger_compaction(tidesdb_column_family_t *cf);
static int tidesdb_wal_recover(tidesdb_column_family_t *cf, const char *wal_path,
                               skip_list_t **memtable, multi_cf_txn_tracker_t *tracker);
static size_t tidesdb_calculate_level_capacity(int level_num, size_t base_capacity, size_t ratio);
static void tidesdb_flush_wal_group_buffer(tidesdb_column_family_t *cf);

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
 * tidesdb_block_cache_key
 * generates a cache key for a klog block
 * @param cf_name column family name
 * @param klog_path path to klog file
 * @param block_position position of block in file
 * @param key_buffer buffer to store the cache key
 * @param buffer_size size of key_buffer
 * @return length of the generated key, 0 on error
 *
 * format: "cf_name:filename:block_position"
 * example: "users:L2P3_1336.klog:0", "users:L2P3_1337.klog:65536"
 * eses filename instead of full path for shorter cache keys
 */
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
static void tidesdb_cache_evict_block(void *payload, size_t payload_len)
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
 * format: "cf_name:filename:block_position"
 * example: "users:L2P3_1336.klog:0", "users:L2P3_1337.klog:65536"
 * eses filename instead of full path for shorter cache keys
 */
static size_t tidesdb_block_cache_key(const char *cf_name, const char *klog_path,
                                      uint64_t block_position, char *key_buffer, size_t buffer_size)
{
    if (!cf_name || !klog_path || !key_buffer || buffer_size == 0) return 0;

    /* extract filename from path (cross-platform) */
    const char *filename = strrchr(klog_path, '/');
    if (!filename) filename = strrchr(klog_path, '\\');
    filename = filename ? filename + 1 : klog_path;

    /* format: "cf_name:filename:block_position" */
    int len = snprintf(key_buffer, buffer_size, "%s:%s:%llu", cf_name, filename,
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
                                   uint64_t block_position, const void *block_data,
                                   size_t block_size)
{
    if (!db || !db->clock_cache || !cf_name || !klog_path || !block_data || block_size == 0)
        return -1;

    char cache_key[TDB_CACHE_KEY_SIZE];
    size_t key_len =
        tidesdb_block_cache_key(cf_name, klog_path, block_position, cache_key, sizeof(cache_key));
    if (key_len == 0) return -1;

    /* deserialize block once */
    tidesdb_klog_block_t *block = NULL;
    if (tidesdb_klog_block_deserialize(block_data, block_size, &block) != 0 || !block) return -1;

    /* create ref-counted wrapper */
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

    /* cache pointer to ref-counted block */
    int result = clock_cache_put(db->clock_cache, cache_key, key_len, &rc_block,
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
                                                     const char *klog_path, uint64_t block_position,
                                                     tidesdb_ref_counted_block_t **rc_block_out)
{
    if (!db || !db->clock_cache || !cf_name || !klog_path || !rc_block_out) return NULL;

    char cache_key[TDB_CACHE_KEY_SIZE];
    size_t key_len =
        tidesdb_block_cache_key(cf_name, klog_path, block_position, cache_key, sizeof(cache_key));
    if (key_len == 0) return NULL;

    size_t payload_len = 0;
    void *payload = clock_cache_get(db->clock_cache, cache_key, key_len, &payload_len);
    if (!payload || payload_len != sizeof(tidesdb_ref_counted_block_t *))
    {
        free(payload);
        return NULL;
    }

    /* extract ref-counted block pointer */
    tidesdb_ref_counted_block_t *rc_block = *(tidesdb_ref_counted_block_t **)payload;
    free(payload);

    if (!rc_block || !rc_block->block) return NULL;

    /* acquire reference for caller */
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

    /* define both separator types for cross-platform compatibility */
    const char sep_unix = '/';
    const char sep_windows = '\\';

    /* find the last directory separator (check both types for portability) */
    const char *last_slash = strrchr(path, sep_unix);
    const char *last_backslash = strrchr(path, sep_windows);
    const char *last_sep = (last_slash > last_backslash) ? last_slash : last_backslash;
    if (!last_sep) return -1;

    /* find the second-to-last directory separator */
    const char *second_last_sep = last_sep - 1;
    while (second_last_sep > path && *second_last_sep != sep_unix &&
           *second_last_sep != sep_windows)
    {
        second_last_sep--;
    }

    if (*second_last_sep != sep_unix && *second_last_sep != sep_windows) return -1;

    /* copy the CF name */
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

    /* decompress block immediately after reading from disk */
    if (sst->config && sst->config->compression_algorithm != NO_COMPRESSION)
    {
        size_t decompressed_size;
        uint8_t *decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                                sst->config->compression_algorithm);
        if (decompressed)
        {
            /* replace compressed data with decompressed data in the block */
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
static int tidesdb_validate_kv_size(tidesdb_t *db, size_t key_size, size_t value_size)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* enforce architectural limit! all sizes are uint32_t */
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

    /* check for overflow before doing addition */
    if (key_size > TDB_MAX_KEY_VALUE_SIZE - value_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "Total key+value size (key: %zu + value: %zu) exceeds TDB_MAX_KEY_VALUE_SIZE",
                      key_size, value_size);
        return TDB_ERR_INVALID_ARGS;
    }

    size_t total_size = key_size + value_size;

    uint64_t memory_based_limit = (uint64_t)(db->available_memory * TDB_MEMORY_PERCENTAGE);
    uint64_t max_allowed_size =
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
 * @param compression_algorithm compression algorithm used (0=none, 1=lz4, 2=zstd, 3=snappy)
 * @param reserved  padding for alignment
 * @param checksum xxHash64 checksum of all fields except checksum itself
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
    uint32_t reserved;
    uint64_t checksum;
} sstable_metadata_header_t;

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

    /* calculate size: header + keys + checksum */
    size_t header_size = TDB_SSTABLE_METADATA_HEADER_SIZE;
    size_t checksum_size = 8;
    size_t total_size = header_size + sst->min_key_size + sst->max_key_size + checksum_size;

    uint8_t *data = malloc(total_size);
    if (!data) return -1;

    uint8_t *ptr = data;

    /* serialize fields with explicit little-endian encoding */
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
    encode_uint32_le_compat(ptr, 0); /* reserved */
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

    /* compute and append checksum over everything except the checksum field itself */
    size_t checksum_data_size = total_size - checksum_size;
    uint64_t checksum = XXH64(data, checksum_data_size, 0);
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
static int sstable_metadata_deserialize(const uint8_t *data, size_t data_size,
                                        tidesdb_sstable_t *sst)
{
    if (!data || !sst || data_size < 92) return -1;

    const uint8_t *ptr = data;

    /* deserialize fields with explicit little-endian decoding */
    uint32_t magic = decode_uint32_le_compat(ptr);
    ptr += 4;

    if (magic != TDB_SSTABLE_METADATA_MAGIC)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "SSTable metadata has an invalid magic 0x%08x (expected 0x%08x)", magic,
                      TDB_SSTABLE_METADATA_MAGIC);
        return -1;
    }

    uint64_t num_entries = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t num_klog_blocks = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t num_vlog_blocks = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t klog_data_end_offset = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t klog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t vlog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t min_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t max_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;

    uint64_t max_seq = decode_uint64_le_compat(ptr);
    ptr += 8;

    uint32_t compression_algorithm = decode_uint32_le_compat(ptr);
    ptr += 4;

    /* skip reserved field */
    ptr += 4;

    size_t expected_size = 92 + min_key_size + max_key_size;
    if (data_size != expected_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL, "SSTable metadata size mismatch (expected: %zu, got: %zu)",
                      expected_size, data_size);
        return -1;
    }

    /* we read keys and checksum */
    const uint8_t *key_ptr = ptr;
    const uint8_t *checksum_ptr = key_ptr + min_key_size + max_key_size;
    uint64_t stored_checksum = decode_uint64_le_compat(checksum_ptr);

    /* we verify checksum over everything except checksum field */
    size_t checksum_data_size = data_size - 8;
    uint64_t computed_checksum = XXH64(data, checksum_data_size, 0);

    if (computed_checksum != stored_checksum)
    {
        TDB_DEBUG_LOG(TDB_LOG_FATAL,
                      "SSTable metadata checksum mismatch (expected: %" PRIu64 ", got: %" PRIu64
                      ")",
                      stored_checksum, computed_checksum);
        return -1;
    }

    /* assign values */
    sst->num_entries = num_entries;
    sst->num_klog_blocks = num_klog_blocks;
    sst->num_vlog_blocks = num_vlog_blocks;
    sst->klog_data_end_offset = klog_data_end_offset;
    sst->klog_size = klog_size;
    sst->vlog_size = vlog_size;
    sst->max_seq = max_seq; /* assign recovered max sequence number */

    /* restore compression algorithm from metadata */
    if (sst->config)
    {
        /* validate compression algorithm value */
        if (compression_algorithm != NO_COMPRESSION &&
#ifndef __sun
            compression_algorithm != SNAPPY_COMPRESSION &&
#endif
            compression_algorithm != LZ4_COMPRESSION && compression_algorithm != ZSTD_COMPRESSION)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable metadata has invalid compression_algorithm: %u",
                          compression_algorithm);
            return -1;
        }
        sst->config->compression_algorithm = compression_algorithm;
    }

    /* read keys */
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
            return -1;
        }
        memcpy(sst->max_key, ptr, max_key_size);
        sst->max_key_size = max_key_size;
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
    int has_custom_comparator =
        (config->comparator_name[0] != '\0' && strcmp(config->comparator_name, "memcmp") != 0);

    if (tidesdb_get_comparator(db, config->comparator_name, fn, ctx) != TDB_SUCCESS)
    {
        if (has_custom_comparator)
        {
            /* custom comparator specified but not in registry and not cached!
             * this should never happen if CF creation validated properly.
             * */
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Comparator '%s' not found in registry and not cached. ",
                          config->comparator_name);
            return -1;
        }

        /* no comparator specified or explicitly requested memcmp, use default */
        *fn = tidesdb_comparator_memcmp;
        if (ctx) *ctx = NULL;
        return -1;
    }

    return 0;
}

int tidesdb_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx)
{
    (void)ctx;

    /* handle null pointers */
    if (!key1 && !key2) return 0;
    if (!key1) return -1;
    if (!key2) return 1;

    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = (min_size > 0) ? memcmp(key1, key2, min_size) : 0;
    if (cmp != 0) return cmp < 0 ? -1 : 1; /* normalize to -1 or 1 */
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
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

        /* convert to lowercase for ASCII characters */
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
    tidesdb_column_family_config_t config = {
        .write_buffer_size = TDB_DEFAULT_WRITE_BUFFER_SIZE,
        .level_size_ratio = TDB_DEFAULT_LEVEL_SIZE_RATIO,
        .min_levels = TDB_DEFAULT_MIN_LEVELS,
        .dividing_level_offset = TDB_DEFAULT_DIVIDING_LEVEL_OFFSET,
        .klog_value_threshold = TDB_DEFAULT_KLOG_VALUE_THRESHOLD,
        .compression_algorithm = LZ4_COMPRESSION,
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
        .min_disk_space = TDB_DEFAULT_MIN_DISK_SPACE};
    return config;
}

tidesdb_config_t tidesdb_default_config(void)
{
    tidesdb_config_t config = {.db_path = "./tidesdb",
                               .log_level = TDB_LOG_INFO,
                               .num_flush_threads = TDB_DEFAULT_FLUSH_THREAD_POOL_SIZE,
                               .num_compaction_threads = TDB_DEFAULT_COMPACTION_THREAD_POOL_SIZE,
                               .block_cache_size = TDB_DEFAULT_BLOCK_CACHE_SIZE,
                               .max_open_sstables = TDB_DEFAULT_MAX_OPEN_SSTABLES};
    return config;
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
static tidesdb_kv_pair_t *tidesdb_kv_pair_create(const uint8_t *key, size_t key_size,
                                                 const uint8_t *value, size_t value_size,
                                                 time_t ttl, uint64_t seq, int is_tombstone)
{
    tidesdb_kv_pair_t *kv = calloc(1, sizeof(tidesdb_kv_pair_t));
    if (!kv) return NULL;

    kv->entry.flags = is_tombstone ? TDB_KV_FLAG_TOMBSTONE : 0;
    kv->entry.key_size = (uint32_t)key_size;
    kv->entry.value_size = (uint32_t)value_size;
    kv->entry.ttl = ttl;
    kv->entry.seq = seq;
    kv->entry.vlog_offset = 0;

    kv->key = malloc(key_size);
    if (!kv->key)
    {
        free(kv);
        return NULL;
    }
    memcpy(kv->key, key, key_size);

    if (value_size > 0 && value)
    {
        kv->value = malloc(value_size);
        if (!kv->value)
        {
            free(kv->key);
            free(kv);
            return NULL;
        }
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
        /* arena allocation everything is in one contiguous block
         * except max_key which is allocated separately during deserialization */
        free(block->max_key);
        /* free the entire arena (block itself is the start of the arena) */
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
 * @param db database handle
 * @param config column family config
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        tidesdb_t *db, tidesdb_column_family_config_t *config)
{
    int inline_value = (kv->entry.value_size < config->klog_value_threshold);

    /** calculate actual entry size to match serialization:
     * we must use actual varint sizes, not max sizes, so block_size is accurate
     */
    size_t entry_size = 1; /* flags */

    /* calculate actual varint sizes for key_size, value_size, seq */
    uint8_t temp_buf[10];
    entry_size += encode_varint_v2(temp_buf, kv->entry.key_size);
    entry_size += encode_varint_v2(temp_buf, kv->entry.value_size);
    entry_size += encode_varint_v2(temp_buf, kv->entry.seq);

    if (kv->entry.ttl != 0) entry_size += 8;
    if (kv->entry.vlog_offset != 0)
    {
        entry_size += encode_varint_v2(temp_buf, kv->entry.vlog_offset);
    }

    entry_size += kv->entry.key_size;
    if (inline_value)
    {
        entry_size += kv->entry.value_size;
    }

    uint32_t new_count = block->num_entries + 1;

    if (new_count > block->capacity)
    {
        uint32_t old_capacity = block->capacity;
        uint32_t new_capacity = old_capacity * 2;

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

        size_t new_elements = new_capacity - old_capacity;
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

    /* update max_key for seek
     * keep track of largest key in this block */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(db, config, &comparator_fn, &comparator_ctx);

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
static int tidesdb_klog_block_is_full(tidesdb_klog_block_t *block, size_t max_size)
{
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

    size_t estimated_size = 8; /* header: num_entries + block_size */
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
    uint8_t *start = ptr;

    encode_uint32_le_compat(ptr, block->num_entries);
    ptr += sizeof(uint32_t);
    encode_uint32_le_compat(ptr, block->block_size);
    ptr += sizeof(uint32_t);

    uint64_t prev_seq = 0;

    for (uint32_t i = 0; i < block->num_entries; i++)
    {
        tidesdb_klog_entry_t *entry = &block->entries[i];
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

        ptr += encode_varint_v2(ptr, entry->key_size);
        ptr += encode_varint_v2(ptr, entry->value_size);

        ptr += encode_varint_v2(ptr, seq_value);

        if (flags & TDB_KV_FLAG_HAS_TTL)
        {
            encode_int64_le_compat(ptr, entry->ttl);
            ptr += sizeof(int64_t);
        }

        if (flags & TDB_KV_FLAG_HAS_VLOG)
        {
            ptr += encode_varint_v2(ptr, entry->vlog_offset);
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
    if (data_size < sizeof(uint32_t) * 2) return TDB_ERR_CORRUPTION;

    /* use arena allocation: single malloc for entire block structure
     * layout: block_struct | entries[] | keys[] | inline_values[] | key_data | value_data
     * this reduces malloc calls from O(N) to O(1) per block */
    const uint8_t *ptr = data;

    uint32_t num_entries = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    uint32_t block_size = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);

    /* calculate total size needed for arena allocation */
    size_t total_key_size = 0;
    size_t total_value_size = 0;
    const uint8_t *scan_ptr = ptr;
    size_t scan_remaining = data_size - (scan_ptr - data);

    for (uint32_t i = 0; i < num_entries; i++)
    {
        if (scan_remaining < 1) return TDB_ERR_CORRUPTION;
        uint8_t flags = *scan_ptr++;
        scan_remaining--;

        uint64_t key_size_u64, value_size_u64, seq_value;
        int bytes_read;

        bytes_read = decode_varint_v2(scan_ptr, &key_size_u64, (int)scan_remaining);
        if (bytes_read < 0 || key_size_u64 > UINT32_MAX) return TDB_ERR_CORRUPTION;
        scan_ptr += bytes_read;
        scan_remaining -= bytes_read;
        total_key_size += (size_t)key_size_u64;

        bytes_read = decode_varint_v2(scan_ptr, &value_size_u64, (int)scan_remaining);
        if (bytes_read < 0 || value_size_u64 > UINT32_MAX) return TDB_ERR_CORRUPTION;
        scan_ptr += bytes_read;
        scan_remaining -= bytes_read;

        bytes_read = decode_varint_v2(scan_ptr, &seq_value, (int)scan_remaining);
        if (bytes_read < 0) return TDB_ERR_CORRUPTION;
        scan_ptr += bytes_read;
        scan_remaining -= bytes_read;

        if (flags & TDB_KV_FLAG_HAS_TTL)
        {
            if (scan_remaining < sizeof(int64_t)) return TDB_ERR_CORRUPTION;
            scan_ptr += sizeof(int64_t);
            scan_remaining -= sizeof(int64_t);
        }

        if (flags & TDB_KV_FLAG_HAS_VLOG)
        {
            uint64_t vlog_offset;
            bytes_read = decode_varint_v2(scan_ptr, &vlog_offset, (int)scan_remaining);
            if (bytes_read < 0) return TDB_ERR_CORRUPTION;
            scan_ptr += bytes_read;
            scan_remaining -= bytes_read;
        }

        if (scan_remaining < key_size_u64) return TDB_ERR_CORRUPTION;
        scan_ptr += key_size_u64;
        scan_remaining -= key_size_u64;

        if (!(flags & TDB_KV_FLAG_HAS_VLOG) && value_size_u64 > 0)
        {
            if (scan_remaining < value_size_u64) return TDB_ERR_CORRUPTION;
            scan_ptr += value_size_u64;
            scan_remaining -= value_size_u64;
            total_value_size += (size_t)value_size_u64;
        }
    }

    /* block + entries + key_ptrs + value_ptrs + key_data + value_data */
    size_t arena_size = sizeof(tidesdb_klog_block_t) +
                        (num_entries * sizeof(tidesdb_klog_entry_t)) +
                        (num_entries * sizeof(uint8_t *)) + /* keys array */
                        (num_entries * sizeof(uint8_t *)) + /* inline_values array */
                        total_key_size + total_value_size;

    uint8_t *arena = malloc(arena_size);
    if (!arena) return TDB_ERR_MEMORY;

    /* partition arena into sections */
    *block = (tidesdb_klog_block_t *)arena;
    memset(*block, 0, sizeof(tidesdb_klog_block_t));

    /* mark as arena-allocated for proper cleanup */
    (*block)->is_arena_allocated = 1;

    uint8_t *arena_ptr = arena + sizeof(tidesdb_klog_block_t);
    (*block)->entries = (tidesdb_klog_entry_t *)arena_ptr;
    arena_ptr += num_entries * sizeof(tidesdb_klog_entry_t);

    (*block)->keys = (uint8_t **)arena_ptr;
    arena_ptr += num_entries * sizeof(uint8_t *);

    (*block)->inline_values = (uint8_t **)arena_ptr;
    arena_ptr += num_entries * sizeof(uint8_t *);

    uint8_t *key_data_arena = arena_ptr;
    uint8_t *value_data_arena = arena_ptr + total_key_size;

    (*block)->num_entries = 0;
    (*block)->block_size = block_size;
    (*block)->capacity = num_entries;

    uint64_t prev_seq = 0;
    size_t remaining = data_size - (ptr - data);
    size_t key_offset = 0;
    size_t value_offset = 0;

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
        int bytes_read = decode_varint_v2(ptr, &key_size_u64, (int)remaining);
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
        bytes_read = decode_varint_v2(ptr, &value_size_u64, (int)remaining);
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
        bytes_read = decode_varint_v2(ptr, &seq_value, (int)remaining);
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
            bytes_read = decode_varint_v2(ptr, &vlog_offset, (int)remaining);
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

        /* point into arena instead of malloc */
        (*block)->keys[i] = key_data_arena + key_offset;
        memcpy((*block)->keys[i], ptr, (*block)->entries[i].key_size);
        key_offset += (*block)->entries[i].key_size;
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

            /* point into arena instead of malloc */
            (*block)->inline_values[i] = value_data_arena + value_offset;
            memcpy((*block)->inline_values[i], ptr, (*block)->entries[i].value_size);
            value_offset += (*block)->entries[i].value_size;
            ptr += (*block)->entries[i].value_size;
            remaining -= (*block)->entries[i].value_size;
        }
    }

    (*block)->num_entries = num_entries;

    if (num_entries > 0)
    {
        uint32_t last_idx = num_entries - 1;
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
 * @param sst sstable containing vlog
 * @param vlog_offset offset of value in vlog
 * @param value_size size of value
 * @param value output value
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_read_value(tidesdb_t *db, tidesdb_sstable_t *sst, uint64_t vlog_offset,
                                   size_t value_size, uint8_t **value)
{
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

    /* allocate buffer and read block data (skip header: size + checksum) */
    uint8_t *block_data = malloc(block_size);
    if (!block_data)
    {
        return TDB_ERR_MEMORY;
    }

    uint64_t data_offset = vlog_offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (block_manager_read_at_offset(bms.vlog_bm, data_offset, block_size, block_data) != 0)
    {
        free(block_data);
        return TDB_ERR_IO;
    }

    if (sst->config->compression_algorithm != NO_COMPRESSION)
    {
        size_t decompressed_size;
        uint8_t *decompressed = decompress_data(block_data, block_size, &decompressed_size,
                                                sst->config->compression_algorithm);
        if (decompressed)
        {
            free(block_data);
            *value = decompressed;

            /* validate size if provided */
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
        else
        {
            /* decompression failed */
            free(block_data);
            return TDB_ERR_CORRUPTION;
        }
    }

    *value = block_data;

    /* validate size if provided */
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
 * tidesdb_vlog_read_value_with_cursor
 * read a value from vlog using a reusable cursor
 * @param db database instance
 * @param sst sstable containing vlog
 * @param cursor reusable vlog cursor
 * @param vlog_offset offset of value in vlog
 * @param value_size expected size of value
 * @param value output value
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_read_value_with_cursor(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               block_manager_cursor_t *cursor, uint64_t vlog_offset,
                                               size_t value_size, uint8_t **value)
{
    (void)cursor; /* cursor not needed with direct offset access */

    /* just delegate to the non-cursor version since we use direct offset access */
    return tidesdb_vlog_read_value(db, sst, vlog_offset, value_size, value);
}

/**
 * tidesdb_sstable_get_block_managers
 * gets block managers for an sstable through the cache
 * @param db database instance
 * @param sst sstable
 * @param bms output block managers structure
 * @return TDB_SUCCESS on success, TDB_ERR_IO on failure
 */
static int tidesdb_sstable_get_block_managers(tidesdb_t *db, tidesdb_sstable_t *sst,
                                              tidesdb_block_managers_t *bms)
{
    if (!db || !sst || !bms) return TDB_ERR_IO;

    /* get block managers directly from the sst */
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
    if (!sst) return -1;

    /* only open block managers if not already open */
    if (sst->klog_bm && sst->vlog_bm)
    {
        return 0; /* already open */
    }

    /* open block managers if needed */
    if (!sst->klog_bm)
    {
        if (block_manager_open(&sst->klog_bm, sst->klog_path,
                               convert_sync_mode(sst->config->sync_mode)) != 0)
        {
            return -1;
        }
    }

    if (!sst->vlog_bm)
    {
        if (block_manager_open(&sst->vlog_bm, sst->vlog_path,
                               convert_sync_mode(sst->config->sync_mode)) != 0)
        {
            if (sst->klog_bm)
            {
                block_manager_close(sst->klog_bm);
                sst->klog_bm = NULL;
            }
            return -1;
        }
    }

    atomic_store(&sst->last_access_time, atomic_load(&db->cached_current_time));
    atomic_fetch_add(&db->num_open_sstables, 1);

    return 0;
}

/**
 * tidesdb_sstable_create
 * create a new sstable
 * @param base_path base path for sstable files
 * @param id sstable id
 * @param config column family configuration
 * @return sstable on success, NULL on failure
 */
static tidesdb_sstable_t *tidesdb_sstable_create(tidesdb_t *db, const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config)
{
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

    size_t path_len = strlen(base_path) + 32;
    sst->klog_path = malloc(path_len);
    sst->vlog_path = malloc(path_len);

    if (!sst->klog_path || !sst->vlog_path)
    {
        free(sst->klog_path);
        free(sst->vlog_path);
        free(sst);
        return NULL;
    }

    snprintf(sst->klog_path, path_len, "%s_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT, base_path,
             TDB_U64_CAST(id));
    snprintf(sst->vlog_path, path_len, "%s_" TDB_U64_FMT TDB_SSTABLE_VLOG_EXT, base_path,
             TDB_U64_CAST(id));

    return sst;
}

/**
 * tidesdb_sstable_free
 * free an sstable
 * @param db database instance
 * @param sst sstable to free
 */
static void tidesdb_sstable_free(tidesdb_t *db, tidesdb_sstable_t *sst)
{
    (void)db; /* db parameter kept for API consistency but not needed */
    if (!sst) return;

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

    /* delete files only when refcount reaches 0
     * this ensures active transactions can still read from old sstables
     * during compaction, preventing data loss */
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
 * tidesdb_sstable_unref
 * decrement reference count of an sstable
 * @param db database instance
 * @param sst sstable to unreference
 */
static void tidesdb_sstable_unref(tidesdb_t *db, tidesdb_sstable_t *sst)
{
    if (!sst) return;
    int old_refcount = atomic_fetch_sub(&sst->refcount, 1);
    if (old_refcount == 1)
    {
        tidesdb_sstable_free(db, sst);
    }
}

static int tidesdb_flush_memtable_internal(tidesdb_column_family_t *cf, int already_holds_lock,
                                           int force);

/**
 * tidesdb_write_set_hash_t
 * simple hash table for O(1) write set lookups in large transactions
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
                                           size_t key_size)
{
    /* mix CF pointer into seed for better distribution across CFs */
    uint64_t seed = TDB_TXN_HASH_SEED ^ (uint64_t)(uintptr_t)cf;
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
static void tidesdb_write_set_hash_insert(tidesdb_write_set_hash_t *hash, tidesdb_txn_t *txn,
                                          int op_index)
{
    if (!hash || op_index < 0 || op_index >= txn->num_ops) return;

    tidesdb_txn_op_t *op = &txn->ops[op_index];
    uint32_t h = tidesdb_write_set_hash_key(op->cf, op->key, op->key_size);
    int slot = h % hash->capacity;

    /* linear probing to find empty slot or matching key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        int existing_idx = hash->slots[slot];

        if (existing_idx == TDB_WRITE_SET_HASH_EMPTY)
        {
            /* empty slot, insert here */
            hash->slots[slot] = op_index;
            return;
        }

        /* check if this slot has the same key (update case) */
        tidesdb_txn_op_t *existing = &txn->ops[existing_idx];
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
static int tidesdb_write_set_hash_lookup(tidesdb_write_set_hash_t *hash, tidesdb_txn_t *txn,
                                         tidesdb_column_family_t *cf, const uint8_t *key,
                                         size_t key_size)
{
    if (!hash) return -1;

    uint32_t h = tidesdb_write_set_hash_key(cf, key, key_size);
    int slot = h % hash->capacity;

    /* linear probing to find key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        int op_index = hash->slots[slot];

        if (op_index == TDB_WRITE_SET_HASH_EMPTY)
        {
            /* empty slot means key not in hash */
            return -1;
        }

        tidesdb_txn_op_t *op = &txn->ops[op_index];
        if (op->cf == cf && op->key_size == key_size && memcmp(op->key, key, key_size) == 0)
        {
            /* found it */
            return op_index;
        }

        /* collision, try next slot */
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
                                          size_t key_size)
{
    /* mix CF pointer into seed for better distribution across CFs */
    uint64_t seed = TDB_TXN_HASH_SEED ^ (uint64_t)(uintptr_t)cf;
    return (uint32_t)XXH64(key, key_size, seed);
}

/**
 * tidesdb_read_set_hash_insert
 * insert read set index into hash table
 * @param hash hash table
 * @param txn transaction
 * @param read_index read set index
 */
static void tidesdb_read_set_hash_insert(tidesdb_read_set_hash_t *hash, tidesdb_txn_t *txn,
                                         int read_index)
{
    if (!hash || read_index < 0 || read_index >= txn->read_set_count) return;

    uint32_t h = tidesdb_read_set_hash_key(txn->read_cfs[read_index], txn->read_keys[read_index],
                                           txn->read_key_sizes[read_index]);
    int slot = h % hash->capacity;

    /* linear probing to find empty slot or matching key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        int existing_idx = hash->slots[slot];

        if (existing_idx == TDB_READ_SET_HASH_EMPTY)
        {
            /* empty slot, insert here */
            hash->slots[slot] = read_index;
            return;
        }

        /* check if this slot has the same key (update case) */
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
static int tidesdb_read_set_hash_check_conflict(tidesdb_read_set_hash_t *hash, tidesdb_txn_t *txn,
                                                tidesdb_column_family_t *cf, const uint8_t *key,
                                                size_t key_size)
{
    if (!hash) return 0;

    uint32_t h = tidesdb_read_set_hash_key(cf, key, key_size);
    int slot = h % hash->capacity;

    /* linear probing to find key */
    for (int probe = 0; probe < TDB_TXN_MAX_PROBE_LENGTH; probe++)
    {
        int read_index = hash->slots[slot];

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
        skip_list_t *memtable_to_free = imm->memtable;
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

/**
 * tidesdb_flush_wal_group_buffer
 * flush any pending data in the WAL group commit buffer to disk
 * this must be called before WAL rotation to prevent data loss
 * @param cf the column family
 */
static void tidesdb_flush_wal_group_buffer(tidesdb_column_family_t *cf)
{
    if (!cf) return;

    /* atomically capture current buffer size and increment generation
     * this prevents new writes from interfering and ensures threads
     * that reserved space know if their generation was flushed */
    uint64_t old_generation = atomic_load(&cf->wal_group_generation);
    size_t flush_size = atomic_exchange(&cf->wal_group_buffer_size, 0);

    /* increment generation to signal that buffer has been flushed
     * threads that reserved space in the old generation will detect this */
    atomic_fetch_add(&cf->wal_group_generation, 1);

    /* wait for all in-flight writers to complete their memcpy operations
     * this is critical to prevent data corruption */
    int wait_cycles = 0;
    while (atomic_load(&cf->wal_group_writers) > 0)
    {
        usleep(TDB_WAL_GROUP_WRITER_WAIT_US);
        if (++wait_cycles > TDB_WAL_GROUP_WRITER_MAX_WAIT_CYCLES)
        {
            break;
        }
    }

    /* memory fence to ensure all memcpy operations from threads that reserved space
     * before the exchange are visible to us before we flush */
    atomic_thread_fence(memory_order_acquire);

    if (flush_size > 0)
    {
        /* clamp to capacity to prevent overflow */
        if (flush_size > cf->wal_group_buffer_capacity)
        {
            flush_size = cf->wal_group_buffer_capacity;
        }

        block_manager_t *target_wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);
        if (target_wal)
        {
            block_manager_block_t *group_block =
                block_manager_block_create(flush_size, cf->wal_group_buffer);

            if (group_block)
            {
                int64_t wal_offset = block_manager_block_write(target_wal, group_block);

                block_manager_block_release(group_block);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "CF '%s' failed to create WAL group block for flush (size: %zu)",
                              cf->name, flush_size);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "CF '%s' WAL group buffer flush failed: no active WAL",
                          cf->name);
        }
    }
}

/**
 * tidesdb_sstable_write_from_memtable
 * write a memtable to an sstable
 * @param db database instance
 * @param sst sstable to write to
 * @param memtable memtable to write from
 * @param cf column family
 * @return 0 on success, -1 on error
 */
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable, tidesdb_column_family_t *cf)
{
    (void)cf; /* unused parameter */
    int num_entries = skip_list_count_entries(memtable);
    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "SSTable %" PRIu64 " writing from memtable (sorted run to disk) (%d entries)",
                  sst->id, num_entries);

    /* ensure sstable is in cache and get block managers */
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

    /* create bloom filter and indexes if enabled */
    bloom_filter_t *bloom = NULL;
    tidesdb_block_index_t *block_indexes = NULL;

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
        skip_list_comparator_fn comparator_fn = NULL;
        void *comparator_ctx = NULL;
        tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

        /* calc initial capacity based on expected samples */
        uint32_t initial_capacity = (num_entries / sst->config->index_sample_ratio) + 1;
        block_indexes = compact_block_index_create(
            initial_capacity, sst->config->block_index_prefix_len, comparator_fn, comparator_ctx);
        if (!block_indexes)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to create block indexes",
                          sst->id);
            if (bloom) bloom_filter_free(bloom);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes enabled (sample ratio: %d)",
                      sst->id, sst->config->index_sample_ratio);
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes disabled", sst->id);
    }

    /* init klog block */
    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();

    if (!current_klog_block)
    {
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        tidesdb_klog_block_free(current_klog_block);
        return TDB_ERR_MEMORY;
    }

    skip_list_cursor_t *cursor;
    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        tidesdb_klog_block_free(current_klog_block);
        return TDB_ERR_MEMORY;
    }

    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    uint8_t *first_key = NULL;
    size_t first_key_size = 0;
    uint8_t *last_key = NULL;
    size_t last_key_size = 0;
    uint64_t entry_count = 0;
    uint64_t max_seq = 0; /* track maximum sequence number */

    /* track first and last key of current block for block index */
    uint8_t *block_first_key = NULL;
    size_t block_first_key_size = 0;
    uint8_t *block_last_key = NULL;
    size_t block_last_key_size = 0;

    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        do
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            time_t ttl;
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

            tidesdb_kv_pair_t *kv =
                tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
            if (!kv) continue;

            if (value_size >= sst->config->klog_value_threshold && !deleted && value)
            {
                uint8_t *final_data = (uint8_t *)value;
                size_t final_size = value_size;
                uint8_t *compressed = NULL;

                /* compress if configured */
                if (sst->config->compression_algorithm != NO_COMPRESSION)
                {
                    size_t compressed_size;
                    compressed = compress_data(value, value_size, &compressed_size,
                                               sst->config->compression_algorithm);
                    if (compressed)
                    {
                        final_data = compressed;
                        final_size = compressed_size;
                    }
                    else
                    {
                        /* compression failed -- fatal error */
                        tidesdb_klog_block_free(current_klog_block);
                        skip_list_cursor_free(cursor);
                        if (bloom) bloom_filter_free(bloom);
                        if (block_indexes) compact_block_index_free(block_indexes);
                        return TDB_ERR_CORRUPTION;
                    }
                }

                /* write value directly as a block */
                block_manager_block_t *vlog_block =
                    block_manager_block_create(final_size, final_data);
                if (vlog_block)
                {
                    /* capture the file offset where this block is written */
                    int64_t block_offset = block_manager_block_write(bms.vlog_bm, vlog_block);
                    if (block_offset >= 0)
                    {
                        kv->entry.vlog_offset = (uint64_t)block_offset;
                        vlog_block_num++;
                    }
                    block_manager_block_release(vlog_block);
                }

                free(compressed);
            }

            /* check if this is the first entry in a new block */
            int is_first_entry_in_block = (current_klog_block->num_entries == 0);

            /* add entry to block first */
            tidesdb_klog_block_add_entry(current_klog_block, kv, sst->db, sst->config);

            /* track first key of block */
            if (is_first_entry_in_block)
            {
                free(block_first_key);
                block_first_key = malloc(key_size);
                if (block_first_key)
                {
                    memcpy(block_first_key, key, key_size);
                    block_first_key_size = key_size;
                }
            }

            /* always update last key of block */
            free(block_last_key);
            block_last_key = malloc(key_size);
            if (block_last_key)
            {
                memcpy(block_last_key, key, key_size);
                block_last_key_size = key_size;
            }

            if (tidesdb_klog_block_is_full(current_klog_block, TDB_KLOG_BLOCK_SIZE))
            {
                uint8_t *klog_data;
                size_t klog_size;
                if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
                {
                    uint8_t *final_klog_data = klog_data;
                    size_t final_klog_size = klog_size;

                    if (sst->config->compression_algorithm != NO_COMPRESSION)
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
                            /* compression failed -- this is fatal since config says we're
                             * compressed
                             */
                            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                          "SSTable %" PRIu64 " klog compression failed!", sst->id);
                            free(klog_data);
                            tidesdb_klog_block_free(current_klog_block);
                            skip_list_cursor_free(cursor);
                            if (bloom) bloom_filter_free(bloom);
                            if (block_indexes) compact_block_index_free(block_indexes);
                            free(block_first_key);
                            free(block_last_key);
                            return TDB_ERR_CORRUPTION;
                        }
                    }

                    block_manager_block_t *klog_block =
                        block_manager_block_create(final_klog_size, final_klog_data);
                    if (klog_block)
                    {
                        /* capture file position before writing the block */
                        uint64_t block_file_position = atomic_load(&bms.klog_bm->current_file_size);

                        block_manager_block_write(bms.klog_bm, klog_block);
                        block_manager_block_release(klog_block);

                        /* add completed block to index after writing with file position */
                        if (block_indexes && block_first_key && block_last_key)
                        {
                            /* sample every Nth block (ratio validated to be >= 1) */
                            if (klog_block_num % sst->config->index_sample_ratio == 0)
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

                tidesdb_klog_block_free(current_klog_block);
                current_klog_block = tidesdb_klog_block_create();

                /* reset block tracking for new block */
                free(block_first_key);
                free(block_last_key);
                block_first_key = NULL;
                block_last_key = NULL;
            }

            /* track maximum sequence number */
            if (seq > max_seq)
            {
                max_seq = seq;
            }

            if (bloom)
            {
                bloom_filter_add(bloom, key, key_size);
            }

            if (!first_key)
            {
                first_key = malloc(key_size);
                if (first_key)
                {
                    memcpy(first_key, key, key_size);
                    first_key_size = key_size;
                }
            }

            free(last_key);
            last_key = malloc(key_size);
            if (last_key)
            {
                memcpy(last_key, key, key_size);
                last_key_size = key_size;
            }

            sst->num_entries++;
            entry_count++;
            tidesdb_kv_pair_free(kv);

        } while (skip_list_cursor_next(cursor) == 0);
    }

    skip_list_cursor_free(cursor);

    /* write remaining blocks */
    if (current_klog_block->num_entries > 0)
    {
        uint8_t *klog_data;
        size_t klog_size;
        if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
        {
            uint8_t *final_klog_data = klog_data;
            size_t final_klog_size = klog_size;

            if (sst->config->compression_algorithm != NO_COMPRESSION)
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
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "SSTable %" PRIu64 " final klog compression failed!", sst->id);
                    free(klog_data);
                    tidesdb_klog_block_free(current_klog_block);
                    if (bloom) bloom_filter_free(bloom);
                    if (block_indexes) compact_block_index_free(block_indexes);
                    free(block_first_key);
                    free(block_last_key);
                    return TDB_ERR_CORRUPTION;
                }
            }

            block_manager_block_t *klog_block =
                block_manager_block_create(final_klog_size, final_klog_data);
            if (klog_block)
            {
                /* capture file position before writing the block */
                uint64_t block_file_position = atomic_load(&bms.klog_bm->current_file_size);

                block_manager_block_write(bms.klog_bm, klog_block);
                block_manager_block_release(klog_block);

                /* add final block to index after writing with file position */
                if (block_indexes && block_first_key && block_last_key)
                {
                    /* sample every Nth block (ratio validated to be >= 1) */
                    if (klog_block_num % sst->config->index_sample_ratio == 0)
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

    /* cleanup block tracking */
    free(block_first_key);
    free(block_last_key);

    tidesdb_klog_block_free(current_klog_block);

    sst->num_entries = entry_count;
    sst->num_klog_blocks = klog_block_num;
    sst->num_vlog_blocks = vlog_block_num;

    sst->min_key = first_key;
    sst->min_key_size = first_key_size;
    sst->max_key = last_key;
    sst->max_key_size = last_key_size;
    sst->max_seq = max_seq; /* store maximum sequence number */

    /* capture klog file offset where data blocks end (before writing index/bloom/metadata) */
    block_manager_get_size(bms.klog_bm, &sst->klog_data_end_offset);

    /* write index block (always write, even if empty, to maintain consistent file structure)
     * file structure -- [data blocks] [index block] [bloom block] [metadata block] */
    if (block_indexes)
    {
        /* we assign the built index to the sst */
        sst->block_indexes = block_indexes;

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "SSTable " TDB_U64_FMT " block indexes built - %" PRIu32
                      " samples, " TDB_U64_FMT " total blocks",
                      TDB_U64_CAST(sst->id), sst->block_indexes->count,
                      TDB_U64_CAST(klog_block_num));

        size_t index_size;
        uint8_t *index_data = compact_block_index_serialize(sst->block_indexes, &index_size);
        if (index_data)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable %" PRIu64 " block indexes serialized to %zu bytes",
                          sst->id, index_size);
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(bms.klog_bm, index_block);
                block_manager_block_release(index_block);
            }
            free(index_data);
        }
    }
    else
    {
        /* write empty index block as placeholder (5 bytes: count=0 + prefix_len) */
        uint8_t empty_index_data[5];
        encode_uint32_le_compat(empty_index_data, 0);             /* count = 0 */
        empty_index_data[4] = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN; /* prefix_len */
        block_manager_block_t *empty_index = block_manager_block_create(5, empty_index_data);
        if (empty_index)
        {
            block_manager_block_write(bms.klog_bm, empty_index);
            block_manager_block_release(empty_index);
        }
    }

    /* write bloom filter block (always write, even if empty, to maintain consistent file structure)
     */
    if (bloom)
    {
        size_t bloom_size;
        uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(bms.klog_bm, bloom_block);
                block_manager_block_release(bloom_block);
            }
            free(bloom_data);
        }
        sst->bloom_filter = bloom;
    }
    else
    {
        /* write empty bloom block as placeholder (1 byte: size=0) */
        uint8_t empty_bloom_data[1] = {0};
        block_manager_block_t *empty_bloom = block_manager_block_create(1, empty_bloom_data);
        if (empty_bloom)
        {
            block_manager_block_write(bms.klog_bm, empty_bloom);
            block_manager_block_release(empty_bloom);
        }
    }

    /* we need to write metadata in two passes to avoid size mismatch
     * pass 1 -- get current file sizes and serialize metadata with those sizes
     * pass 2 -- write the metadata block (which increases file size)
     * pass 3 -- update sst struct with final sizes for in-memory consistency
     *
     * the metadata will contain pre-metadata sizes, but that's ok because
     * -- klog_data_end_offset marks where data blocks end
     * -- recovery uses actual file sizes, not metadata sizes
     * -- the sizes in metadata are primarily for validation/debugging
     */

    uint64_t klog_size_before_metadata;
    uint64_t vlog_size_before_metadata;
    block_manager_get_size(bms.klog_bm, &klog_size_before_metadata);
    block_manager_get_size(bms.vlog_bm, &vlog_size_before_metadata);

    /* temporarily set sizes for metadata serialization */
    sst->klog_size = klog_size_before_metadata;
    sst->vlog_size = vlog_size_before_metadata;

    /* write metadata block as the last block */
    uint8_t *metadata_data = NULL;
    size_t metadata_size = 0;
    if (sstable_metadata_serialize(sst, &metadata_data, &metadata_size) == 0)
    {
        block_manager_block_t *metadata_block =
            block_manager_block_create(metadata_size, metadata_data);
        if (metadata_block)
        {
            block_manager_block_write(bms.klog_bm, metadata_block);
            block_manager_block_release(metadata_block);
        }
        free(metadata_data);
    }

    /* get final file sizes after writing metadata block
     * this ensures in-memory sst struct has correct sizes */
    block_manager_get_size(bms.klog_bm, &sst->klog_size);
    block_manager_get_size(bms.vlog_bm, &sst->vlog_size);

    if (bms.klog_bm) block_manager_escalate_fsync(bms.klog_bm);
    if (bms.vlog_bm) block_manager_escalate_fsync(bms.vlog_bm);

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_get
 * get a key-value pair from an sstable
 * @param sst the sstable
 * @param key the key
 * @param key_size the size of the key
 * @param kv the key-value pair
 */
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               size_t key_size, tidesdb_kv_pair_t **kv)
{
    /* ensure sstable is open through cache */
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

    if (sst->bloom_filter && !bloom_filter_contains(sst->bloom_filter, key, key_size))
    {
        return TDB_ERR_NOT_FOUND;
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

    /* check if this is a reverse comparator (min_key > max_key in actual values) */
    int min_max_cmp = comparator_fn(sst->min_key, sst->min_key_size, sst->max_key,
                                    sst->max_key_size, comparator_ctx);
    int is_reverse = (min_max_cmp > 0); /* min > max in comparator order means reverse */

    int min_cmp = comparator_fn(key, key_size, sst->min_key, sst->min_key_size, comparator_ctx);
    int max_cmp = comparator_fn(key, key_size, sst->max_key, sst->max_key_size, comparator_ctx);

    if (is_reverse)
    {
        /* for reverse comparators, min_key is largest, max_key is smallest
         * key is in range if max_key <= key <= min_key (in actual values)
         * with reverse comparator: key >= max means cmp(key,max) <= 0, key <= min means
         * cmp(key,min) >= 0 */
        if (min_cmp < 0 || max_cmp > 0)
        {
            return TDB_ERR_NOT_FOUND;
        }
    }
    else
    {
        /* normal order */
        if (min_cmp < 0 || max_cmp > 0)
        {
            return TDB_ERR_NOT_FOUND;
        }
    }

    /* use block indexes to find starting klog block */
    uint64_t start_file_position = 0;
    if (sst->block_indexes)
    {
        int index_result = compact_block_index_find_predecessor(sst->block_indexes, key, key_size,
                                                                &start_file_position);

        if (index_result != 0)
        {
            start_file_position = 0;
        }
    }

    /* search klog blocks using block manager cursor */
    block_manager_cursor_t *klog_cursor;

    if (block_manager_cursor_init(&klog_cursor, bms.klog_bm) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to initialize klog cursor",
                      sst->id);
        return TDB_ERR_IO;
    }

    /* use block index hint to jump directly to the right block, or start at beginning */
    if (start_file_position > 0)
    {
        block_manager_cursor_goto(klog_cursor, start_file_position);
    }
    else
    {
        block_manager_cursor_goto_first(klog_cursor);
    }

    /* check if we're already past data blocks after navigation */
    if (sst->klog_data_end_offset > 0 && klog_cursor->current_pos >= sst->klog_data_end_offset)
    {
        /* block index pointed us to auxiliary structures, key not found */
        block_manager_cursor_free(klog_cursor);
        return TDB_ERR_NOT_FOUND;
    }

    int result = TDB_ERR_NOT_FOUND;
    uint64_t block_num = 0;

    /* track block position for cache keys */
    uint64_t block_position = klog_cursor->current_pos;
    char cf_name[TDB_CACHE_KEY_SIZE];
    int has_cf_name = (tidesdb_get_cf_name_from_path(sst->klog_path, cf_name) == 0);

    while (block_num < sst->num_klog_blocks)
    {
        /* check if cursor is past data end offset (into auxiliary structures) */
        if (sst->klog_data_end_offset > 0 && klog_cursor->current_pos >= sst->klog_data_end_offset)
        {
            /* reached auxiliary structures, stop reading data blocks */
            break;
        }

        tidesdb_klog_block_t *klog_block = NULL;
        tidesdb_ref_counted_block_t *rc_block = NULL;
        block_manager_block_t *block = NULL;

        if (db->clock_cache && has_cf_name)
        {
            klog_block = tidesdb_cache_block_get(db, cf_name, sst->klog_path,
                                                 klog_cursor->current_pos, &rc_block);
            if (klog_block)
            {
                PROFILE_INC(db, cache_block_hits);
            }
        }

        if (!klog_block)
        {
            PROFILE_INC(db, cache_block_misses);
            PROFILE_INC(db, disk_reads);
            block = tidesdb_read_block(db, sst, klog_cursor);

            if (!block)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable %" PRIu64 " failed to read block %" PRIu64,
                              sst->id, block_num);
                break;
            }

            /* block is already decompressed by tidesdb_read_block */
            uint8_t *data = block->data;
            size_t data_size = block->size;

            PROFILE_INC(db, blocks_read);
            int deser_result = tidesdb_klog_block_deserialize(data, data_size, &klog_block);

            if (deser_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "SSTable %" PRIu64 " block %" PRIu64 " deserialization failed",
                              sst->id, block_num);
                block_manager_block_release(block);
                block_num++;
                if (block_manager_cursor_next(klog_cursor) != 0) break;
                continue;
            }

            if (db->clock_cache && has_cf_name && klog_block)
            {
                tidesdb_cache_block_put(db, cf_name, sst->klog_path, block_position, data,
                                        data_size);
            }
        }

        if (klog_block && klog_block->num_entries > 0)
        {
            /* binary search entries in this block (entries are sorted by key) */
            int32_t left = 0;
            int32_t right = (int32_t)klog_block->num_entries - 1;
            int32_t found_idx = -1;

            while (left <= right)
            {
                int32_t mid = left + (right - left) / 2;

                int cmp = comparator_fn(key, key_size, klog_block->keys[mid],
                                        klog_block->entries[mid].key_size, comparator_ctx);

                if (cmp == 0)
                {
                    found_idx = mid;
                    break;
                }
                else if (cmp < 0)
                {
                    right = mid - 1;
                }
                else
                {
                    left = mid + 1;
                }
            }

            if (found_idx >= 0)
            {
                /* found! */
                uint32_t i = (uint32_t)found_idx;

                *kv = tidesdb_kv_pair_create(klog_block->keys[i], klog_block->entries[i].key_size,
                                             NULL, 0, klog_block->entries[i].ttl,
                                             klog_block->entries[i].seq,
                                             klog_block->entries[i].flags & TDB_KV_FLAG_TOMBSTONE);

                if (*kv)
                {
                    (*kv)->entry = klog_block->entries[i];

                    /* get value (inline or from vlog) */
                    if (klog_block->entries[i].vlog_offset == 0)
                    {
                        if (klog_block->inline_values[i])
                        {
                            (*kv)->value = malloc(klog_block->entries[i].value_size);

                            if ((*kv)->value)
                            {
                                memcpy((*kv)->value, klog_block->inline_values[i],
                                       klog_block->entries[i].value_size);
                            }
                        }
                    }
                    else
                    {
                        tidesdb_vlog_read_value(db, sst, klog_block->entries[i].vlog_offset,
                                                klog_block->entries[i].value_size, &(*kv)->value);
                    }

                    result = TDB_SUCCESS;

                    /* release ref-counted block or free deserialized block */
                    if (rc_block)
                        tidesdb_block_release(rc_block);
                    else
                        tidesdb_klog_block_free(klog_block);

                    if (block) block_manager_block_release(block);

                    goto cleanup;
                }
            }
        }
        /* key not found in this block, continue to next block */

        /* release ref-counted block or free deserialized block */
        if (rc_block)
            tidesdb_block_release(rc_block);
        else if (klog_block)
            tidesdb_klog_block_free(klog_block);

        /* cleanup block resources before moving to next */
        if (block) block_manager_block_release(block);

        /* reset for next iteration */
        rc_block = NULL;
        klog_block = NULL;

        block_num++;
        block_position = klog_cursor->current_pos;

        if (block_manager_cursor_next(klog_cursor) != 0)
        {
            break;
        }
    }

cleanup:
    block_manager_cursor_free(klog_cursor);
    return result;
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
    (void)db; /* unused parameter */
    /* open block managers temporarily for loading; they'll be managed by cache later */
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

    /* validate klog file (strict mode: reject any corruption) */
    if (block_manager_validate_last_block(klog_bm, 1) != 0)
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

    /* validate vlog file (strict mode: reject any corruption) */
    if (block_manager_validate_last_block(vlog_bm, 1) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "SSTable vlog file %s is corrupted", sst->vlog_path);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_CORRUPTION;
    }

    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    /* check for empty or corrupted files */
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
                /* try to deserialize metadata */
                if (sstable_metadata_deserialize(metadata_block->data, metadata_block->size, sst) ==
                    0)
                {
                    block_manager_block_release(metadata_block);
                    block_manager_cursor_free(metadata_cursor);

                    /* validate metadata claims against actual file structure */
                    if (sst->klog_data_end_offset > 0)
                    {
                        /* klog_data_end_offset must be within file bounds */
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

                        /* must have at least block manager header before data */
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

                    /* validate num_klog_blocks is reasonable */
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

    /* go to last block (metadata) and skip it */
    if (block_manager_cursor_goto_last(cursor) == 0)
    {
        /* skip metadata block, go to bloom filter */
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

    /* keep block managers open and store them in the sstable
     * they will be managed by the cache and closed when the sstable is evicted or freed */
    sst->klog_bm = klog_bm;
    sst->vlog_bm = vlog_bm;

    /* track that this file is now open */
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
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity)
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

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Level %d created with capacity %zu", level_num, capacity);

    return level;
}

/**
 * tidesdb_level_free
 * free a level
 * @param level level to free
 */
static void tidesdb_level_free(tidesdb_t *db, tidesdb_level_t *level)
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
    /* take reference before adding to level */
    tidesdb_sstable_ref(sst);

    while (1)
    {
        /* load current array state atomically */
        tidesdb_sstable_t **old_arr = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int old_capacity = atomic_load_explicit(&level->sstables_capacity, memory_order_acquire);
        int old_num = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        /* check if we need to grow the array */
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

            /* copy existing sstables */
            memcpy(new_arr, old_arr, old_num * sizeof(tidesdb_sstable_t *));

            /* add new sstable */
            new_arr[old_num] = sst;

            /* CAS to swap in new array */
            if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                        memory_order_release, memory_order_acquire))
            {
                /* success! update capacity and count */
                atomic_store_explicit(&level->sstables_capacity, new_capacity,
                                      memory_order_release);
                atomic_store_explicit(&level->num_sstables, old_num + 1, memory_order_release);

                /* update size */
                atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                          memory_order_relaxed);

                /* free the old array now that new one is swapped in */
                free(old_arr);

                return TDB_SUCCESS;
            }
            /* CAS failed, retry with new state */
            free(new_arr);
        }
        else
        {
            /* no resize needed, just add to existing array */
            /* atomically reserve a slot by incrementing count first */
            int expected = old_num;

            /* verify we have space before trying to reserve */
            if (expected >= old_capacity)
            {
                /* no space, retry with resize path */
                continue;
            }

            /* write sst pointer to array first, before incrementing count
             * this prevents readers from seeing incremented count while slot is unpopulated */
            old_arr[old_num] = sst;

            /* ensure write is visible before count increment */
            atomic_thread_fence(memory_order_release);

            /* now atomically increment count to publish the new sst */
            if (atomic_compare_exchange_strong_explicit(&level->num_sstables, &expected,
                                                        old_num + 1, memory_order_release,
                                                        memory_order_acquire))
            {
                /* success! sst is now visible to readers */
                atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                          memory_order_relaxed);
                return TDB_SUCCESS;
            }
            else
            {
                /* CAS failed -- another thread modified count
                 * clear the slot we wrote to and retry */
                old_arr[old_num] = NULL;
                atomic_thread_fence(memory_order_release);
            }
            /* CAS failed, another thread modified count, retry */
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
static int tidesdb_level_remove_sstable(tidesdb_t *db, tidesdb_level_t *level,
                                        tidesdb_sstable_t *sst)
{
    while (1)
    {
        /* load current array state */
        tidesdb_sstable_t **old_arr = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int old_num = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        int old_capacity = atomic_load_explicit(&level->sstables_capacity, memory_order_acquire);

        /* find the sstable to remove */
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

        /* create new array without the removed entry */
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

        /* try to swap in new array first
         * we must swap array before updating count to prevent race where
         * readers see new (smaller) count with old (larger) array, missing ssts */
        if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                    memory_order_release, memory_order_acquire))
        {
            /* CAS succeeded, now atomically update count
             * fence ensures array swap is visible before count update */
            atomic_thread_fence(memory_order_seq_cst);
            atomic_store_explicit(&level->num_sstables, new_idx, memory_order_release);
            /* success! update size */
            atomic_fetch_sub_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                      memory_order_relaxed);

            /* unref old array's sstables */
            for (int i = 0; i < old_num; i++)
            {
                tidesdb_sstable_unref(db, old_arr[i]);
            }

            free(old_arr);

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

    /* free old boundaries, we check for NULL to prevent double-free in concurrent scenarios.. */
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
static int heap_compare(tidesdb_merge_heap_t *heap, int i, int j)
{
    tidesdb_kv_pair_t *a = heap->sources[i]->current_kv;
    tidesdb_kv_pair_t *b = heap->sources[j]->current_kv;

    if (!a && !b) return 0;
    if (!a) return 1;  /* a is greater, push to end */
    if (!b) return -1; /* b is greater, push to end */

    int cmp = heap->comparator(a->key, a->entry.key_size, b->key, b->entry.key_size,
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
 * heap_sift_down
 * sift down an element in a heap
 * @param heap heap to sift down
 * @param idx index of element to sift down
 */
static void heap_sift_down(tidesdb_merge_heap_t *heap, int idx)
{
    while (idx * 2 + 1 < heap->num_sources)
    {
        int left = idx * 2 + 1;
        int right = idx * 2 + 2;
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
static void heap_sift_up(tidesdb_merge_heap_t *heap, int idx)
{
    while (idx > 0)
    {
        int parent = (idx - 1) / 2;
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
static void heap_sift_down_max(tidesdb_merge_heap_t *heap, int idx)
{
    while (idx * 2 + 1 < heap->num_sources)
    {
        int left = idx * 2 + 1;
        int right = idx * 2 + 2;
        int largest = idx;

        /* for max-heap, we want largest element on top */
        if (left < heap->num_sources && heap_compare(heap, left, largest) > 0)
        {
            largest = left;
        }
        if (right < heap->num_sources && heap_compare(heap, right, largest) > 0)
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
        tidesdb_merge_source_free(top);
        heap->sources[0] = heap->sources[heap->num_sources - 1];
        heap->num_sources--;
        if (heap->num_sources > 0) heap_sift_down_max(heap, 0);
        return NULL;
    }

    tidesdb_kv_pair_t *result = top->current_kv;
    top->current_kv = NULL;

    /* retreat the source to get its previous entry */
    if (tidesdb_merge_source_retreat(top) != TDB_SUCCESS)
    {
        /* source exhausted, remove it */
        tidesdb_merge_source_free(top);
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
static tidesdb_merge_heap_t *tidesdb_merge_heap_create(skip_list_comparator_fn comparator,
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
        tidesdb_merge_source_free(heap->sources[i]);
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
        int new_capacity = heap->capacity * 2;
        tidesdb_merge_source_t **new_sources =
            realloc(heap->sources, new_capacity * sizeof(tidesdb_merge_source_t *));
        if (!new_sources) return TDB_ERR_MEMORY;
        heap->sources = new_sources;
        heap->capacity = new_capacity;
    }

    heap->sources[heap->num_sources] = source;
    heap->num_sources++;

    /* heapify */
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

    tidesdb_kv_pair_t *result = tidesdb_kv_pair_clone(top->current_kv);

    /* advance source */
    int advance_result = tidesdb_merge_source_advance(top);
    if (advance_result != 0)
    {
        /* source exhausted or corrupted */
        if (advance_result == TDB_ERR_CORRUPTION && top->type == MERGE_SOURCE_SSTABLE &&
            corrupted_sst)
        {
            /* return corrupted sst for deletion */
            *corrupted_sst = top->source.sstable.sst;
            tidesdb_sstable_ref(*corrupted_sst);
        }

        /* remove from heap */
        heap->sources[0] = heap->sources[heap->num_sources - 1];
        heap->num_sources--;
        tidesdb_merge_source_free(top);
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
static int tidesdb_merge_heap_empty(tidesdb_merge_heap_t *heap)
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

    int goto_result = skip_list_cursor_goto_first(source->source.memtable.cursor);

    if (goto_result == 0)
    {
        uint8_t *key, *value;
        size_t key_size, value_size;
        time_t ttl;
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
 * tidesdb_merge_source_from_sstable
 * create a merge source from an sstable
 * @param db database instance
 * @param sst sstable
 * @return merge source or NULL on error
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable(tidesdb_t *db,
                                                                 tidesdb_sstable_t *sst)
{
    tidesdb_merge_source_t *source = malloc(sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_SSTABLE;
    source->source.sstable.sst = sst;
    source->source.sstable.db = db; /* store db for later vlog reads */

    tidesdb_sstable_ref(sst);

    /* ensure sstable is open through cache before getting block managers */
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

    /* initialize vlog cursor for efficient value reads */
    if (block_manager_cursor_init(&source->source.sstable.vlog_cursor, bms.vlog_bm) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        free(source);
        return NULL;
    }

    source->source.sstable.current_block_data = NULL; /* no block data yet */
    source->source.sstable.current_rc_block = NULL;   /* no ref-counted block yet */
    source->source.sstable.decompressed_data = NULL;  /* no decompressed data yet */
    source->source.sstable.current_block = NULL;      /* no current block yet */
    source->current_kv = NULL;                        /* no current kv yet */
    source->config = sst->config;

    /* only read data blocks, not the metadata block at the end */
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
        /* check cursor is within data region (before index/bloom/metadata blocks) */
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

        /* read first block and first entry */
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

        /* block is already decompressed by tidesdb_read_block */
        uint8_t *data = block->data;
        size_t data_size = block->size;

        tidesdb_klog_block_t *klog_block = NULL;
        if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) != 0)
        {
            /* deserialization failed */
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

            /* create KV pair from first entry */
            uint8_t *value = klog_block->inline_values[0];

            /* if not inline, read from vlog */
            uint8_t *vlog_value = NULL;
            if (klog_block->entries[0].vlog_offset > 0)
            {
                tidesdb_vlog_read_value_with_cursor(source->source.sstable.db, sst,
                                                    source->source.sstable.vlog_cursor,
                                                    klog_block->entries[0].vlog_offset,
                                                    klog_block->entries[0].value_size, &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                klog_block->keys[0], klog_block->entries[0].key_size, value,
                klog_block->entries[0].value_size, klog_block->entries[0].ttl,
                klog_block->entries[0].seq, klog_block->entries[0].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);
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

    return source;
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
        /* release immutable memtable reference if held */
        if (source->source.memtable.imm)
        {
            tidesdb_immutable_memtable_unref(source->source.memtable.imm);
        }
    }
    else
    {
        /* release ref-counted block or free regular block */
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
            time_t ttl;
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
    else
    {
        /* advance to next entry in current block or next block */
        source->source.sstable.current_entry_idx++;

        tidesdb_klog_block_t *kb = source->source.sstable.current_block;
        if (kb && (uint32_t)source->source.sstable.current_entry_idx < kb->num_entries)
        {
            /* get next entry from current block */
            int idx = source->source.sstable.current_entry_idx;
            uint8_t *value = kb->inline_values[idx];

            uint8_t *vlog_value = NULL;
            if (kb->entries[idx].vlog_offset > 0)
            {
                tidesdb_vlog_read_value_with_cursor(
                    source->source.sstable.db, source->source.sstable.sst,
                    source->source.sstable.vlog_cursor, kb->entries[idx].vlog_offset,
                    kb->entries[idx].value_size, &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                kb->keys[idx], kb->entries[idx].key_size, value, kb->entries[idx].value_size,
                kb->entries[idx].ttl, kb->entries[idx].seq,
                kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);
            return TDB_SUCCESS;
        }
        else
        {
            /* move to next block, cursor will handle position tracking */

            /* release previous block and decompressed data before moving to next */
            /* free current_block first since its pointers reference decompressed_data */
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

            /* move to next block */
            if (block_manager_cursor_next(source->source.sstable.klog_cursor) == 0)
            {
                /* check if cursor is past data end offset */
                if (source->source.sstable.sst->klog_data_end_offset > 0 &&
                    source->source.sstable.klog_cursor->current_pos >=
                        source->source.sstable.sst->klog_data_end_offset)
                {
                    /* reached end of data blocks */
                    return TDB_ERR_NOT_FOUND;
                }

                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
                    /* block is owned by us, decompress if needed */
                    uint8_t *data = block->data;
                    size_t data_size = block->size;
                    uint8_t *decompressed = NULL;

                    if (source->config->compression_algorithm != NO_COMPRESSION)
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

                    int deserialize_result = tidesdb_klog_block_deserialize(
                        data, data_size, &source->source.sstable.current_block);

                    if (deserialize_result != 0)
                    {
                        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                      "klog block deserialization failed (error=%d), "
                                      "aborting source for SSTable %" PRIu64,
                                      deserialize_result, source->source.sstable.sst->id);
                        if (decompressed)
                        {
                            free(decompressed);
                            source->source.sstable.decompressed_data = NULL;
                        }
                        block_manager_block_release(block);
                        return TDB_ERR_CORRUPTION;
                    }

                    if (source->source.sstable.current_block &&
                        source->source.sstable.current_block->num_entries > 0)
                    {
                        source->source.sstable.current_entry_idx = 0;

                        tidesdb_klog_block_t *current_kb = source->source.sstable.current_block;
                        uint8_t *value = current_kb->inline_values[0];

                        uint8_t *vlog_value = NULL;
                        if (current_kb->entries[0].vlog_offset > 0)
                        {
                            tidesdb_vlog_read_value_with_cursor(
                                source->source.sstable.db, source->source.sstable.sst,
                                source->source.sstable.vlog_cursor,
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

                    /* empty block or other issue, clean up and continue */
                    if (decompressed)
                    {
                        free(decompressed);
                        source->source.sstable.decompressed_data = NULL;
                    }
                    block_manager_block_release(block);
                    source->source.sstable.current_block_data = NULL;
                }
            }
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
    tidesdb_kv_pair_free(source->current_kv);
    source->current_kv = NULL;

    if (source->type == MERGE_SOURCE_MEMTABLE)
    {
        if (skip_list_cursor_prev(source->source.memtable.cursor) == 0)
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            time_t ttl;
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
    else
    {
        /* move to previous entry in current block or previous block */
        tidesdb_klog_block_t *kb = source->source.sstable.current_block;

        /* check if we can move to previous entry in current block */
        if (kb && source->source.sstable.current_entry_idx > 0)
        {
            /* move to previous entry in current block */
            source->source.sstable.current_entry_idx--;
            int idx = source->source.sstable.current_entry_idx;
            uint8_t *value = kb->inline_values[idx];

            uint8_t *vlog_value = NULL;
            if (kb->entries[idx].vlog_offset > 0)
            {
                tidesdb_vlog_read_value_with_cursor(
                    source->source.sstable.db, source->source.sstable.sst,
                    source->source.sstable.vlog_cursor, kb->entries[idx].vlog_offset,
                    kb->entries[idx].value_size, &vlog_value);
                value = vlog_value;
            }

            source->current_kv = tidesdb_kv_pair_create(
                kb->keys[idx], kb->entries[idx].key_size, value, kb->entries[idx].value_size,
                kb->entries[idx].ttl, kb->entries[idx].seq,
                kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE);

            free(vlog_value);
            return TDB_SUCCESS;
        }
        /* check if we can move to a previous block */
        if (!block_manager_cursor_has_prev(source->source.sstable.klog_cursor))
        {
            /* already at first block, can't go back */
            return TDB_ERR_NOT_FOUND;
        }

        /* release previous block and decompressed data before moving to prior block */
        /* free current_block first since its pointers reference decompressed_data */
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

        /* move to previous block */
        if (block_manager_cursor_prev(source->source.sstable.klog_cursor) == 0)
        {
            /* check if cursor is past data end offset (into auxiliary structures) */
            if (source->source.sstable.sst->klog_data_end_offset > 0 &&
                source->source.sstable.klog_cursor->current_pos >=
                    source->source.sstable.sst->klog_data_end_offset)
            {
                /* reached end of data blocks (moved into auxiliary structures) */
                return TDB_ERR_NOT_FOUND;
            }

            block_manager_block_t *block =
                block_manager_cursor_read(source->source.sstable.klog_cursor);
            if (block)
            {
                /* block is owned by us, decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;
                uint8_t *decompressed = NULL;

                if (source->config->compression_algorithm != NO_COMPRESSION)
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

                int deserialize_result = tidesdb_klog_block_deserialize(
                    data, data_size, &source->source.sstable.current_block);

                if (deserialize_result != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "klog block deserialization failed (error=%d), "
                                  "aborting source for SSTable %" PRIu64,
                                  deserialize_result, source->source.sstable.sst->id);
                    if (decompressed)
                    {
                        free(decompressed);
                        source->source.sstable.decompressed_data = NULL;
                    }
                    block_manager_block_release(block);
                    return TDB_ERR_CORRUPTION;
                }

                if (source->source.sstable.current_block &&
                    source->source.sstable.current_block->num_entries > 0)
                {
                    /* deserialization succeeded, now safe to store block */
                    source->source.sstable.current_block_data = block;

                    /* start at last entry of previous block */
                    source->source.sstable.current_entry_idx =
                        source->source.sstable.current_block->num_entries - 1;

                    tidesdb_klog_block_t *current_kb = source->source.sstable.current_block;
                    int idx = source->source.sstable.current_entry_idx;
                    uint8_t *value = current_kb->inline_values[idx];

                    uint8_t *vlog_value = NULL;
                    if (current_kb->entries[idx].vlog_offset > 0)
                    {
                        tidesdb_vlog_read_value_with_cursor(
                            source->source.sstable.db, source->source.sstable.sst,
                            source->source.sstable.vlog_cursor,
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
                    /* dont free decompressed or release block as  we're still using the
                     * deserialized data */
                    return TDB_SUCCESS;
                }

                /* on error, clean up and release */
                if (decompressed)
                {
                    free(decompressed);
                    source->source.sstable.decompressed_data = NULL;
                }
                block_manager_block_release(block);
            }
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
static size_t tidesdb_calculate_level_capacity(int level_num, size_t base_capacity, size_t ratio)
{
    /*** initial capacity formula: C_i = base * T^(i-1) for level i
     * l1: base * T^0 = base
     * l2: base * T^1 = base * T
     * l3: base * T^2 = base * T^2
     * will be adjusted by DCA once data is written
     * uses overflow checking to prevent wraparound */
    size_t capacity = base_capacity;
    const size_t max_capacity = SIZE_MAX / 2; /* cap at half of SIZE_MAX for safety */

    for (int i = 1; i < level_num; i++)
    {
        /* check for overflow before multiplication */
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

    /* check if we've hit max levels */
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

        /* recheck if largest level still needs expansion */
        if (num_sstables == 0 && largest_size < largest_capacity)
        {
            return TDB_SUCCESS;
        }
    }

    /* calculate capacity for new level */
    size_t new_capacity = tidesdb_calculate_level_capacity(
        old_num_levels + 1, cf->config.write_buffer_size, cf->config.level_size_ratio);

    /* create new largest level at next slot */
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

    /* atomically increment active level count -- this publishes the new level
     * release ordering ensures the new level is visible to other threads */
    atomic_store_explicit(&cf->num_active_levels, old_num_levels + 1, memory_order_release);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Published %d active levels", old_num_levels + 1);
    for (int log_i = 0; log_i < old_num_levels + 1; log_i++)
    {
        tidesdb_level_t *log_lvl = cf->levels[log_i];
        if (log_lvl)
        {
            int log_num = atomic_load_explicit(&log_lvl->num_sstables, memory_order_acquire);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "levels[%d] level_num=%d, %d SSTables", log_i,
                          log_lvl->level_num, log_num);
        }
    }

    /* ensure level addition is visible to all threads */
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

    /* enforce minimum levels! never go below min_levels */
    if (old_num_levels <= cf->config.min_levels)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "At minimum levels (%d <= %d), not removing", old_num_levels,
                      cf->config.min_levels);
        return TDB_SUCCESS; /* not an error, just at minimum */
    }

    tidesdb_level_t *largest = cf->levels[old_num_levels - 1];
    int num_largest_ssts = atomic_load_explicit(&largest->num_sstables, memory_order_acquire);

    /* only remove level if it's completely empty */
    if (num_largest_ssts > 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Cannot remove level %d - has %d SSTables", largest->level_num,
                      num_largest_ssts);
        return TDB_SUCCESS;
    }

    /** update capacity of new largest level (was L-1, now L):
     * C_new_L = C_old_L / T */
    int new_num_levels = old_num_levels - 1;
    if (new_num_levels > 0)
    {
        tidesdb_level_t *new_largest = cf->levels[new_num_levels - 1];
        size_t old_largest_capacity =
            atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        size_t new_largest_capacity = old_largest_capacity / cf->config.level_size_ratio;

        /* ensure capacity doesnt become zero */
        if (new_largest_capacity < cf->config.write_buffer_size)
        {
            new_largest_capacity = cf->config.write_buffer_size;
        }

        atomic_store_explicit(&new_largest->capacity, new_largest_capacity, memory_order_release);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Updated new largest level %d capacity to %zu",
                      new_largest->level_num, new_largest_capacity);
    }

    /* free the largest level struct */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Freeing removed level %d (num_sstables=%d, current_size=%zu)",
                  largest->level_num,
                  atomic_load_explicit(&largest->num_sstables, memory_order_acquire),
                  atomic_load_explicit(&largest->current_size, memory_order_relaxed));
    tidesdb_level_free(cf->db, largest);
    cf->levels[old_num_levels - 1] = NULL;

    /* update num_active_levels to reflect removed level
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
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    if (num_levels < 2)
    {
        return TDB_SUCCESS;
    }

    /* get data size at largest level */
    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t N_L = atomic_load(&largest->current_size);

    /* update capacities C_i = N_L / T^(L-i)
     * paper uses 1-based level numbering (level 1, 2, 3...)
     * we use 0-based array indexing (levels[0], levels[1], levels[2]...)
     * so we adjust -- for array index i, the level number is i+1
     * formula becomes: C[i] = N_L / T^(L-(i+1)) = N_L / T^(L-1-i) */
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

        /* ensure capacity doesnt become zero */
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

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Starting full preemptive merge on CF '%s', levels %d->%d",
                  cf->name, start_level + 1, target_level + 1);

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    tidesdb_merge_heap_t *heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
    if (!heap)
    {
        return TDB_ERR_MEMORY;
    }

    /* track ssts to delete */
    queue_t *sstables_to_delete = queue_new();
    if (!sstables_to_delete)
    {
        tidesdb_merge_heap_free(heap);
        return TDB_ERR_MEMORY;
    }

    /* snapshot sst IDs to prevent race with flush workers */
    queue_t *sstable_ids_snapshot = queue_new();
    if (!sstable_ids_snapshot)
    {
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        return TDB_ERR_MEMORY;
    }

    /* snapshot sst IDs atomically */
    int total_ssts = 0;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            uint64_t *id_copy = malloc(sizeof(uint64_t));
            if (id_copy)
            {
                *id_copy = sst->id;
                queue_enqueue(sstable_ids_snapshot, id_copy);
                total_ssts++;
            }
        }
    }

    /* if no sstables to merge, return early */
    if (total_ssts == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "No SSTables to merge, skipping");
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        queue_free(sstable_ids_snapshot);
        return TDB_SUCCESS;
    }

    /* allocate array to hold sstable pointers */
    tidesdb_sstable_t **ssts_array = malloc(total_ssts * sizeof(tidesdb_sstable_t *));
    if (!ssts_array)
    {
        while (queue_size(sstable_ids_snapshot) > 0)
        {
            uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
            free(id_ptr);
        }
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        queue_free(sstable_ids_snapshot);
        return TDB_ERR_MEMORY;
    }

    /* collect sstable pointers matching snapshot (with references) */
    int sst_idx = 0;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            /* only collect if this sst was in our snapshot */
            int in_snapshot = 0;
            size_t snapshot_size = queue_size(sstable_ids_snapshot);
            for (size_t j = 0; j < snapshot_size; j++)
            {
                uint64_t *id_ptr = (uint64_t *)queue_peek_at(sstable_ids_snapshot, j);
                if (id_ptr && *id_ptr == sst->id)
                {
                    in_snapshot = 1;
                    break;
                }
            }

            if (in_snapshot)
            {
                tidesdb_sstable_ref(sst); /* take reference on sstable */
                ssts_array[sst_idx++] = sst;
            }
        }
    }

    for (int i = 0; i < sst_idx; i++)
    {
        tidesdb_sstable_t *sst = ssts_array[i];

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "Creating merge source for SSTable %" PRIu64 " (num_klog_blocks=%" PRIu64
                      ", klog_data_end_offset=%" PRIu64 ")",
                      sst->id, sst->num_klog_blocks, sst->klog_data_end_offset);

        tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
        if (source)
        {
            if (source->current_kv)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Added merge source for SSTable %" PRIu64, sst->id);
                if (tidesdb_merge_heap_add_source(heap, source) != TDB_SUCCESS)
                {
                    /* failed to add source to heap, free it to prevent leak */
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

        queue_enqueue(sstables_to_delete, sst); /* add to cleanup queue */
    }

    free(ssts_array);

    /* create new sst for merged output */
    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char path[MAX_FILE_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d", cf->directory,
             target_level + 1);

    tidesdb_sstable_t *new_sst = tidesdb_sstable_create(cf->db, path, new_id, &cf->config);
    if (!new_sst)
    {
        tidesdb_merge_heap_free(heap);
        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(cf->db, sst);
        }
        queue_free(sstables_to_delete);
        while (queue_size(sstable_ids_snapshot) > 0)
        {
            uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
            free(id_ptr);
        }
        queue_free(sstable_ids_snapshot);
        return TDB_ERR_MEMORY;
    }

    /* open block managers for writing new sstable */
    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open(&klog_bm, new_sst->klog_path, convert_sync_mode(cf->config.sync_mode)) !=
        0)
    {
        tidesdb_sstable_unref(cf->db, new_sst);
        tidesdb_merge_heap_free(heap);
        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(cf->db, sst);
        }
        queue_free(sstables_to_delete);
        while (queue_size(sstable_ids_snapshot) > 0)
        {
            uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
            free(id_ptr);
        }
        queue_free(sstable_ids_snapshot);
        return TDB_ERR_IO;
    }

    if (block_manager_open(&vlog_bm, new_sst->vlog_path, convert_sync_mode(cf->config.sync_mode)) !=
        0)
    {
        block_manager_close(klog_bm);
        tidesdb_sstable_unref(cf->db, new_sst);
        tidesdb_merge_heap_free(heap);
        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(cf->db, sst);
        }
        queue_free(sstables_to_delete);
        while (queue_size(sstable_ids_snapshot) > 0)
        {
            uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
            free(id_ptr);
        }
        queue_free(sstable_ids_snapshot);
        return TDB_ERR_IO;
    }

    /* calc expected number of entries for bloom filter sizing
     * during merge, duplicates are eliminated and tombstones may be removed,
     * so the actual count will be lower. we use the sum as an upper bound to ensure
     * the bloom filter is adequately sized. */
    uint64_t estimated_entries = 0;

    /* reload levels for estimated entries calculation */
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];

        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            /* check for null as concurrent compactions may have removed sstables */
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
        if (bloom_filter_new(&bloom, new_sst->config->bloom_fpr, estimated_entries) == 0)
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

    if (new_sst->config->enable_block_indexes)
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

    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();

    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    uint64_t max_seq = 0;

    uint8_t *last_key = NULL;
    size_t last_key_size = 0;

    /* track first and last key of current block for block index */
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

        /* skip duplicate keys (keep newest based on seq) */
        if (last_key && last_key_size == kv->entry.key_size &&
            memcmp(last_key, kv->key, last_key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* update last key */
        free(last_key);
        last_key = malloc(kv->entry.key_size);
        if (last_key)
        {
            memcpy(last_key, kv->key, kv->entry.key_size);
            last_key_size = kv->entry.key_size;
        }

        /* skip tombstones (deleted keys) */
        if (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* we check TTL expiration */
        if (kv->entry.ttl > 0 && kv->entry.ttl < atomic_load_explicit(&cf->db->cached_current_time,
                                                                      memory_order_relaxed))
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (kv->entry.value_size >= cf->config.klog_value_threshold && kv->value)
        {
            /* write value directly to vlog */
            uint8_t *final_data = kv->value;
            size_t final_size = kv->entry.value_size;
            uint8_t *compressed = NULL;

            if (new_sst->config->compression_algorithm != NO_COMPRESSION)
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

        /* check if this is the first entry in a new block */
        int is_first_entry_in_block = (current_klog_block->num_entries == 0);

        /* add entry to block first */
        tidesdb_klog_block_add_entry(current_klog_block, kv, cf->db, &cf->config);

        /* track first key of block */
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

        /* always update last key of block */
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

                if (cf->config.compression_algorithm != NO_COMPRESSION)
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

            /* reset block tracking for new block */
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

            if (cf->config.compression_algorithm != NO_COMPRESSION)
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

    /* cleanup block tracking */
    free(block_first_key);
    free(block_last_key);

    tidesdb_klog_block_free(current_klog_block);

    new_sst->num_klog_blocks = klog_block_num;
    new_sst->num_vlog_blocks = vlog_block_num;

    block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

    /* write auxiliary structures (always write, even if empty, to maintain consistent file
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
            /* write empty index block as placeholder */
            block_manager_block_t *empty_index = block_manager_block_create(0, NULL);
            if (empty_index)
            {
                block_manager_block_write(klog_bm, empty_index);
                block_manager_block_release(empty_index);
            }
        }

        /* write bloom filter block */
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
            /* write empty bloom block as placeholder */
            block_manager_block_t *empty_bloom = block_manager_block_create(0, NULL);
            if (empty_bloom)
            {
                block_manager_block_write(klog_bm, empty_bloom);
                block_manager_block_release(empty_bloom);
            }
        }
    }

    /* get file sizes before metadata write for serialization */
    uint64_t klog_size_before_metadata;
    uint64_t vlog_size_before_metadata;
    block_manager_get_size(klog_bm, &klog_size_before_metadata);
    block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

    /* temporarily set sizes for metadata serialization */
    new_sst->klog_size = klog_size_before_metadata;
    new_sst->vlog_size = vlog_size_before_metadata;

    /* write metadata block as the last block -- only if we have entries */
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

    /* get final file sizes after metadata write */
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

    /* ensure all writes are visible before making sstable discoverable */
    atomic_thread_fence(memory_order_seq_cst);

    /* close write handles before adding to level
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

    /* save metadata for logging before potentially freeing sstable */
    uint64_t sst_id = new_sst->id;
    uint64_t num_entries = new_sst->num_entries;
    uint64_t num_klog_blocks = new_sst->num_klog_blocks;
    uint64_t num_vlog_blocks = new_sst->num_vlog_blocks;

    /* only add sstable if it has entries -- empty sstables cause corruption */
    if (num_entries > 0)
    {
        /* reload levels and num_levels as DCA may have changed them
         * we load num_levels first to match store order */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

        /* find the target level by level_num, not by stale array index */
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

            /* add new sstable to manifest
             * manifest operations take internal locks for thread safety */
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
        /* free bloom filter and block indexes that were allocated but never used */
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        /* delete the empty sstable files */
        remove(new_sst->klog_path);
        remove(new_sst->vlog_path);
        tidesdb_sstable_unref(cf->db, new_sst);
    }

    /* remove old sstables from levels */
    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        /* reload levels for removal */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

        /* mark for deletion before removing from levels to avoid use-after-free */
        atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

        /* find which level this sst belongs to and remove it -- break on first success */
        int removed = 0;
        int removed_level = -1;
        for (int level = start_level; level <= target_level && level < num_levels; level++)
        {
            tidesdb_level_t *lvl = cf->levels[level];
            int result = tidesdb_level_remove_sstable(cf->db, lvl, sst);
            if (result == TDB_SUCCESS)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "Removed SSTable %" PRIu64 " from level %d", sst->id,
                              lvl->level_num);
                removed = 1;
                removed_level = lvl->level_num;
                break; /* found and removed, no need to check other levels */
            }
        }
        if (removed)
        {
            /* remove from manifest - manifest operations take internal locks for thread safety */
            tidesdb_manifest_remove_sstable(cf->manifest, removed_level, sst->id);
            int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
            if (manifest_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Failed to commit manifest after removing SSTable %" PRIu64
                              " (error: %d)",
                              sst->id, manifest_result);
            }
        }
        if (!removed)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "WARNING - SSTable %" PRIu64 " not found in any level!",
                          sst->id);
        }

        /* release the reference we took when collecting sstables */
        tidesdb_sstable_unref(cf->db, sst);
    }

    queue_free(sstables_to_delete);

    /* cleanup snapshot IDs */
    while (queue_size(sstable_ids_snapshot) > 0)
    {
        uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
        free(id_ptr);
    }
    queue_free(sstable_ids_snapshot);

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

        /* ensure there's a level to merge into */
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
    /** dividing merge:
     * use boundaries from target_level+1 (the level we're merging into) */
    tidesdb_level_t *next_level = cf->levels[target_level + 1];

    tidesdb_level_update_boundaries(target, next_level);

    int next_level_num_ssts = atomic_load_explicit(&next_level->num_sstables, memory_order_acquire);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "next_level (L%d) has %d SSTables", next_level->level_num,
                  next_level_num_ssts);
    tidesdb_sstable_t **next_level_ssts =
        atomic_load_explicit(&next_level->sstables, memory_order_acquire);
    for (int i = 0; i < next_level_num_ssts; i++)
    {
        tidesdb_sstable_t *sst = next_level_ssts[i];
        if (sst)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "next_level SSTable %" PRIu64 " (min_key_size=%zu, max_key_size=%zu)",
                          sst->id, sst->min_key_size, sst->max_key_size);
        }
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    queue_t *sstables_to_delete = queue_new();
    queue_t *sstable_ids_snapshot = queue_new(); /* track IDs being compacted */

    /* snapshot sst IDs atomically to prevent race with flush workers */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "snapshotting SSTable IDs from levels 1-%d", target_level + 1);
    for (int level = 0; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            /* store sst ID in snapshot */
            uint64_t *id_copy = malloc(sizeof(uint64_t));
            if (id_copy)
            {
                *id_copy = sst->id;
                queue_enqueue(sstable_ids_snapshot, id_copy);
            }
        }
    }

    /* collect ssts matching the snapshot (with references) */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "collecting SSTables from levels 1-%d", target_level + 1);
    for (int level = 0; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        TDB_DEBUG_LOG(TDB_LOG_INFO, "L%d has %d SSTables", level, num_ssts);
        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            /* only collect if this sst was in our snapshot */
            int in_snapshot = 0;
            size_t snapshot_size = queue_size(sstable_ids_snapshot);
            for (size_t j = 0; j < snapshot_size; j++)
            {
                uint64_t *id_ptr = (uint64_t *)queue_peek_at(sstable_ids_snapshot, j);
                if (id_ptr && *id_ptr == sst->id)
                {
                    in_snapshot = 1;
                    break;
                }
            }

            if (in_snapshot)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "collecting SSTable %" PRIu64
                              " from L%d (min_key_size=%zu, max_key_size=%zu)",
                              sst->id, level, sst->min_key_size, sst->max_key_size);
                tidesdb_sstable_ref(sst);
                queue_enqueue(sstables_to_delete, sst);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "skipping SSTable %" PRIu64 " from L%d (added after snapshot)",
                              sst->id, level);
            }
        }
    }

    /* get partition boundaries from target level */
    target = cf->levels[target_level];
    int num_boundaries = atomic_load_explicit(&target->num_boundaries, memory_order_acquire);
    uint8_t **file_boundaries =
        atomic_load_explicit(&target->file_boundaries, memory_order_acquire);
    size_t *boundary_sizes = atomic_load_explicit(&target->boundary_sizes, memory_order_acquire);
    (void)file_boundaries; /* used for partition range determination */
    (void)boundary_sizes;  /* used for partition range determination */

    /* get number of sstables being merged */
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

        /* cleanup snapshot IDs */
        while (queue_size(sstable_ids_snapshot) > 0)
        {
            uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
            free(id_ptr);
        }
        queue_free(sstable_ids_snapshot);

        return result;
    }

    /* calculate total estimated entries from all ssts being merged */
    uint64_t total_estimated_entries = 0;
    for (size_t i = 0; i < num_sstables_to_merge; i++)
    {
        tidesdb_sstable_t *sst = queue_peek_at(sstables_to_delete, i);
        if (sst)
        {
            total_estimated_entries += sst->num_entries;
        }
    }

    /* partitioned merge create one sstable per partition */
    int num_partitions = num_boundaries + 1;

    /* estimate entries per partition (divide total by number of partitions) */
    uint64_t partition_estimated_entries = total_estimated_entries / num_partitions;
    if (partition_estimated_entries < TDB_MERGE_MIN_ESTIMATED_ENTRIES)
        partition_estimated_entries = TDB_MERGE_MIN_ESTIMATED_ENTRIES;

    for (int partition = 0; partition < num_partitions; partition++)
    {
        /* create separate heap for this partition to avoid data loss */
        tidesdb_merge_heap_t *partition_heap =
            tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
        if (!partition_heap)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "Failed to create heap for partition %d", partition);
            continue;
        }

        /* determine key range for this partition */
        uint8_t *range_start = (partition > 0) ? file_boundaries[partition - 1] : NULL;
        size_t range_start_size = (partition > 0) ? boundary_sizes[partition - 1] : 0;
        uint8_t *range_end = (partition < num_boundaries) ? file_boundaries[partition] : NULL;
        size_t range_end_size = (partition < num_boundaries) ? boundary_sizes[partition] : 0;

        TDB_DEBUG_LOG(TDB_LOG_INFO, "partition %d range [start_size=%zu, end_size=%zu)", partition,
                      range_start_size, range_end_size);

        /* add only overlapping sstables to this partitions heap */
        uint64_t partition_entries = 0;
        size_t num_sstables_in_partition = queue_size(sstables_to_delete);
        for (size_t i = 0; i < num_sstables_in_partition; i++)
        {
            tidesdb_sstable_t *sst = queue_peek_at(sstables_to_delete, i);
            if (!sst) continue;

            /* check if this sstable overlaps with partition range */
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
                              "partition %d SSTable %" PRIu64
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
                          "partition %d skipping empty partition (no overlapping SSTables)",
                          partition);
            tidesdb_merge_heap_free(partition_heap);
            continue;
        }

        /* create new sst for this partition with partition naming */
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
                               convert_sync_mode(cf->config.sync_mode)) != 0)
        {
            tidesdb_merge_heap_free(partition_heap);
            tidesdb_sstable_unref(cf->db, new_sst);
            continue;
        }

        if (block_manager_open(&vlog_bm, new_sst->vlog_path,
                               convert_sync_mode(cf->config.sync_mode)) != 0)
        {
            block_manager_close(klog_bm);
            tidesdb_merge_heap_free(partition_heap);
            tidesdb_sstable_unref(cf->db, new_sst);
            continue;
        }

        /* merge keys in this partition's range */
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

        /* track first and last key of current block for block index */
        uint8_t *block_first_key = NULL;
        size_t block_first_key_size = 0;
        uint8_t *block_last_key = NULL;
        size_t block_last_key_size = 0;

        if (cf->config.enable_bloom_filter)
        {
            if (bloom_filter_new(&bloom, cf->config.bloom_fpr, partition_entries) == 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "partition %d bloom filter created (estimated entries: %" PRIu64 ")",
                              partition, partition_entries);
            }
            else
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "partition %d bloom filter creation failed",
                              partition);
                bloom = NULL;
            }
        }

        if (cf->config.enable_block_indexes)
        {
            block_indexes =
                compact_block_index_create(partition_entries, cf->config.block_index_prefix_len,
                                           comparator_fn, comparator_ctx);
        }

        /* process entries from partition-specific heap -- all keys are guaranteed to be in range */
        while (!tidesdb_merge_heap_empty(partition_heap))
        {
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(partition_heap, NULL);
            if (!kv) break;

            /* skip duplicate keys (keep newest based on seq) */
            if (last_key && last_key_size == kv->entry.key_size &&
                memcmp(last_key, kv->key, last_key_size) == 0)
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* update last key for duplicate detection */
            free(last_key);
            last_key = malloc(kv->entry.key_size);
            if (last_key)
            {
                memcpy(last_key, kv->key, kv->entry.key_size);
                last_key_size = kv->entry.key_size;
            }

            /* skip tombstones (deleted keys) */
            if (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* check TTL expiration */
            if (kv->entry.ttl > 0 &&
                kv->entry.ttl <
                    atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed))
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* add to sst */
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

            /* check if this is the first entry in a new block */
            int is_first_entry_in_block = (klog_block->num_entries == 0);

            /* add entry to block first */
            tidesdb_klog_block_add_entry(klog_block, kv, cf->db, &cf->config);

            /* track first key of block */
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

            /* always update last key of block */
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

                    if (cf->config.compression_algorithm != NO_COMPRESSION)
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

                /* reset block tracking for new block */
                free(block_first_key);
                free(block_last_key);
                block_first_key = NULL;
                block_last_key = NULL;
            }

            /* track maximum sequence number */
            if (kv->entry.seq > max_seq)
            {
                max_seq = kv->entry.seq;
            }

            entry_count++;

            tidesdb_kv_pair_free(kv);
        }

        /* free partition heap */
        tidesdb_merge_heap_free(partition_heap);

        /* write remaining klog block if it has data */
        if (klog_block->num_entries > 0)
        {
            uint8_t *klog_data;
            size_t klog_size;
            if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
            {
                uint8_t *final_klog_data = klog_data;
                size_t final_klog_size = klog_size;

                if (cf->config.compression_algorithm != NO_COMPRESSION)
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

                    /* add final block to index after writing with correct file position */
                    if (block_indexes && block_first_key && block_last_key)
                    {
                        /* sample every Nth block (ratio validated to be >= 1) */
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

        /* cleanup block tracking */
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

        /* capture klog file offset where data blocks end (before writing index/bloom/metadata) */
        block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

        /* write auxiliary structures (always write, even if empty, to maintain consistent file
         * structure) */
        if (entry_count > 0)
        {
            /* write index block */
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
                /* write empty index block as placeholder (5 bytes: count=0 + prefix_len) */
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

            /* write bloom filter block */
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
                /* write empty bloom block as placeholder (1 byte: size=0) */
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

        /* get file sizes before metadata write for serialization */
        uint64_t klog_size_before_metadata;
        uint64_t vlog_size_before_metadata;
        block_manager_get_size(klog_bm, &klog_size_before_metadata);
        block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

        /* temporarily set sizes for metadata serialization */
        new_sst->klog_size = klog_size_before_metadata;
        new_sst->vlog_size = vlog_size_before_metadata;

        /* write metadata block as the last block -- only if we have entries */
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

        /* get final file sizes after metadata write */
        block_manager_get_size(klog_bm, &new_sst->klog_size);
        block_manager_get_size(vlog_bm, &new_sst->vlog_size);

        /* keep block managers open for immediate reads, reaper will close if needed */
        new_sst->klog_bm = klog_bm;
        new_sst->vlog_bm = vlog_bm;
        atomic_store(&new_sst->last_access_time,
                     atomic_load_explicit(&cf->db->cached_current_time, memory_order_relaxed));
        atomic_fetch_add(&cf->db->num_open_sstables, 1);

        /* ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* add to target level */
        TDB_DEBUG_LOG(TDB_LOG_INFO, "partition %d: Merged %" PRIu64 " entries", partition,
                      entry_count);

        if (entry_count > 0)
        {
            /* reload num_levels as DCA may have changed it */
            int current_num_levels =
                atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

            /* find the target level by level_num, not by stale array index */
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
                              "partition %d: Target level %d not found "
                              "(current_num_levels=%d)",
                              partition, target_level_num, current_num_levels);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
            else
            {
                TDB_DEBUG_LOG(
                    TDB_LOG_INFO,
                    "partition %d: Adding merged SSTable %" PRIu64 " to level %d (array index %d)",
                    partition, new_sst->id, cf->levels[target_idx]->level_num, target_idx);
                tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);

                /* add new sstable to manifest -- manifest operations take internal locks */
                tidesdb_manifest_add_sstable(cf->manifest, cf->levels[target_idx]->level_num,
                                             new_sst->id, new_sst->num_entries,
                                             new_sst->klog_size + new_sst->vlog_size);
                atomic_store(&cf->manifest->sequence, atomic_load(&cf->next_sstable_id));
                int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
                if (manifest_result != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "partition %d: Failed to commit manifest for SSTable %" PRIu64
                                  " (error: %d)",
                                  partition, new_sst->id, manifest_result);
                }

                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }
        else
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "partition %d: Skipping empty SSTable %" PRIu64 " (0 entries)", partition,
                          new_sst->id);

            /* free bloom and block_indexes since they won't be freed by sstable_unref */
            if (bloom) bloom_filter_free(bloom);
            if (block_indexes) compact_block_index_free(block_indexes);

            /* delete the empty sstable files */
            remove(new_sst->klog_path);
            remove(new_sst->vlog_path);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
    }

    int current_num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (sst)
        {
            /* mark for deletion before removing from levels to avoid use-after-free */
            atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

            /* try to remove from each level -- break on first success since each sst is only in one
             * level */
            int removed_level = -1;
            for (int level = 0; level <= target_level && level < current_num_levels; level++)
            {
                int result = tidesdb_level_remove_sstable(cf->db, cf->levels[level], sst);
                if (result == TDB_SUCCESS)
                {
                    removed_level = cf->levels[level]->level_num;
                    break; /* found and removed, no need to check other levels */
                }
            }

            /* remove from manifest if successfully removed from level
             * manifest operations take internal locks for thread safety */
            if (removed_level != -1)
            {
                tidesdb_manifest_remove_sstable(cf->manifest, removed_level, sst->id);
                int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
                if (manifest_result != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                  "Failed to commit manifest after removing SSTable %" PRIu64
                                  " (error: %d)",
                                  sst->id, manifest_result);
                }
            }

            /* release the reference we took when collecting sstables */
            tidesdb_sstable_unref(cf->db, sst);
        }
    }

    queue_free(sstables_to_delete);

    /* cleanup snapshot IDs */
    while (queue_size(sstable_ids_snapshot) > 0)
    {
        uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
        free(id_ptr);
    }
    queue_free(sstable_ids_snapshot);

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

    /* convert 1-indexed level numbers to 0-indexed array indices */
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

    /* check if largest level is empty before collecting sstables */
    if (num_partitions == 0)
    {
        /* largest level is empty, fall back to full preemptive merge.
         * we dont collect sstables since we're not doing partitioned merge.
         * tidesdb_full_preemptive_merge expects 0-indexed array indices, not 1-indexed level
         * numbers */

        return tidesdb_full_preemptive_merge(cf, start_idx, end_idx);
    }

    /* snapshot sst IDs to prevent race with flush workers */
    queue_t *sstable_ids_snapshot = queue_new();
    queue_t *sstables_to_delete = queue_new();

    /* snapshot sst IDs atomically */
    for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
    {
        tidesdb_level_t *lvl = cf->levels[level_idx];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            if (!sstables[i]) continue;

            uint64_t *id_copy = malloc(sizeof(uint64_t));
            if (id_copy)
            {
                *id_copy = sstables[i]->id;
                queue_enqueue(sstable_ids_snapshot, id_copy);
            }
        }
    }

    /* collect sstables matching snapshot (with references) */
    for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
    {
        tidesdb_level_t *lvl = cf->levels[level_idx];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            if (!sstables[i]) continue;

            /* only collect if this sst was in our snapshot */
            int in_snapshot = 0;
            size_t snapshot_size = queue_size(sstable_ids_snapshot);
            for (size_t j = 0; j < snapshot_size; j++)
            {
                uint64_t *id_ptr = (uint64_t *)queue_peek_at(sstable_ids_snapshot, j);
                if (id_ptr && *id_ptr == sstables[i]->id)
                {
                    in_snapshot = 1;
                    break;
                }
            }

            if (in_snapshot)
            {
                tidesdb_sstable_ref(sstables[i]);
                queue_enqueue(sstables_to_delete, sstables[i]);
            }
        }
    }

    uint8_t **boundaries = malloc(num_partitions * sizeof(uint8_t *));
    size_t *boundary_sizes = malloc(num_partitions * sizeof(size_t));

    for (int i = 0; i < num_partitions; i++)
    {
        /* check for null as concurrent compactions may have removed sstables */
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

    /* merge one partition at a time */
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

        /* add overlapping ssts as sources and calculate estimated entries */
        uint64_t estimated_entries = 0;

        /* reload levels for each partition */

        for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
        {
            tidesdb_level_t *lvl = cf->levels[level_idx];

            int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
            tidesdb_sstable_t **sstables =
                atomic_load_explicit(&lvl->sstables, memory_order_acquire);

            for (int i = 0; i < num_ssts; i++)
            {
                tidesdb_sstable_t *sst = sstables[i];
                /* check for null as concurrent compactions may have removed sstables */
                if (!sst) continue;

                /* reuse comparator_fn and comparator_ctx from outer scope */

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

        /* create output sst for this partition */
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
                               convert_sync_mode(cf->config.sync_mode));
            block_manager_open(&vlog_bm, new_sst->vlog_path,
                               convert_sync_mode(cf->config.sync_mode));

            bloom_filter_t *bloom = NULL;
            tidesdb_block_index_t *block_indexes = NULL;

            if (cf->config.enable_bloom_filter)
            {
                if (bloom_filter_new(&bloom, cf->config.bloom_fpr, estimated_entries) == 0)
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

            if (cf->config.enable_block_indexes)
            {
                /* reuse comparator_fn and comparator_ctx from outer scope */
                block_indexes =
                    compact_block_index_create(estimated_entries, cf->config.block_index_prefix_len,
                                               comparator_fn, comparator_ctx);
            }

            /* merge and write entries in partition range */
            tidesdb_klog_block_t *klog_block = tidesdb_klog_block_create();
            uint64_t entry_count = 0;
            uint64_t klog_block_num = 0;
            uint64_t vlog_block_num = 0;
            uint64_t max_seq = 0;
            uint8_t *first_key = NULL;
            size_t first_key_size = 0;
            uint8_t *last_key = NULL;
            size_t last_key_size = 0;

            /* track first and last key of current block for block index */
            uint8_t *block_first_key = NULL;
            size_t block_first_key_size = 0;
            uint8_t *block_last_key = NULL;
            size_t block_last_key_size = 0;

            /* track last key for duplicate detection */
            uint8_t *last_seen_key = NULL;
            size_t last_seen_key_size = 0;

            while (!tidesdb_merge_heap_empty(heap))
            {
                tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap, NULL);
                if (!kv) break;

                skip_list_comparator_fn cmp_fn = NULL;
                void *cmp_ctx = NULL;
                tidesdb_resolve_comparator(cf->db, &cf->config, &cmp_fn, &cmp_ctx);

                /* check if key is in partition range */
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

                /* skip duplicate keys (keep newest based on seq) */
                if (last_seen_key && last_seen_key_size == kv->entry.key_size &&
                    memcmp(last_seen_key, kv->key, last_seen_key_size) == 0)
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

                /* update last seen key for duplicate detection */
                free(last_seen_key);
                last_seen_key = malloc(kv->entry.key_size);
                if (last_seen_key)
                {
                    memcpy(last_seen_key, kv->key, kv->entry.key_size);
                    last_seen_key_size = kv->entry.key_size;
                }

                if (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

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
                    /* write value directly to vlog */
                    uint8_t *final_data = kv->value;
                    size_t final_size = kv->entry.value_size;
                    uint8_t *compressed = NULL;

                    if (cf->config.compression_algorithm != NO_COMPRESSION)
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

                /* add to klog block */
                tidesdb_klog_block_add_entry(klog_block, kv, cf->db, &cf->config);

                /* track first key of block */
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

                /* always update last key of block */
                free(block_last_key);
                block_last_key = malloc(kv->entry.key_size);
                if (block_last_key)
                {
                    memcpy(block_last_key, kv->key, kv->entry.key_size);
                    block_last_key_size = kv->entry.key_size;
                }

                /* track maximum sequence number */
                if (kv->entry.seq > max_seq)
                {
                    max_seq = kv->entry.seq;
                }

                entry_count++;

                /* flush klog block if full */
                if (tidesdb_klog_block_is_full(klog_block, TDB_KLOG_BLOCK_SIZE))
                {
                    uint8_t *klog_data;
                    size_t klog_size;
                    if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                    {
                        uint8_t *final_data = klog_data;
                        size_t final_size = klog_size;

                        if (cf->config.compression_algorithm != NO_COMPRESSION)
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
                            /* capture file position before writing the block */
                            uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);

                            block_manager_block_write(klog_bm, block);
                            block_manager_block_release(block);

                            /* add completed block to index after writing with file position */
                            if (block_indexes && block_first_key && block_last_key)
                            {
                                /* sample every Nth block (ratio validated to be >= 1) */
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

                    /* reset block tracking for new block */
                    free(block_first_key);
                    free(block_last_key);
                    block_first_key = NULL;
                    block_last_key = NULL;
                }

                tidesdb_kv_pair_free(kv);
            }

            /* cleanup duplicate detection tracking */
            free(last_seen_key);

            /* write remaining block */
            if (klog_block->num_entries > 0)
            {
                uint8_t *klog_data;
                size_t klog_size;
                if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                {
                    uint8_t *final_data = klog_data;
                    size_t final_size = klog_size;

                    if (new_sst->config->compression_algorithm != NO_COMPRESSION)
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
                        /* capture file position before writing the block */
                        uint64_t block_file_position = atomic_load(&klog_bm->current_file_size);

                        block_manager_block_write(klog_bm, block);
                        block_manager_block_release(block);

                        /* add final block to index after writing with file position */
                        if (block_indexes && block_first_key && block_last_key)
                        {
                            /* sample every Nth block (ratio validated to be >= 1) */
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

            /* cleanup block tracking */
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

            /* capture klog file offset where data blocks end (before writing index/bloom/metadata)
             */
            block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

            /* write auxiliary structures (always write, even if empty, to maintain consistent file
             * structure) */
            if (entry_count > 0)
            {
                /* write index block */
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
                    /* write empty index block as placeholder (5 bytes: count=0 + prefix_len) */
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

                /* write bloom filter block */
                if (bloom)
                {
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
                    /* write empty bloom block as placeholder (1 byte: size=0) */
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

            new_sst->bloom_filter = bloom;

            /* get file sizes before metadata write for serialization */
            uint64_t klog_size_before_metadata;
            uint64_t vlog_size_before_metadata;
            block_manager_get_size(klog_bm, &klog_size_before_metadata);
            block_manager_get_size(vlog_bm, &vlog_size_before_metadata);

            /* temporarily set sizes for metadata serialization */
            new_sst->klog_size = klog_size_before_metadata;
            new_sst->vlog_size = vlog_size_before_metadata;

            /* write metadata block as the last block -- only if we have entries */
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

            /* get final file sizes after metadata write */
            block_manager_get_size(klog_bm, &new_sst->klog_size);
            block_manager_get_size(vlog_bm, &new_sst->vlog_size);

            /* close write handles before adding to level */
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

            /* ensure all writes are visible before making sstable discoverable */
            atomic_thread_fence(memory_order_seq_cst);

            /* add to level if not empty */
            if (entry_count > 0)
            {
                /* reload num_levels as DCA may have changed it */
                int current_num_levels =
                    atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

                /* find the target level by level_num, not by stale array index
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

                /* add new sstable to manifest -- manifest operations take internal locks */
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
                /* free bloom filter and block indexes that were allocated but never used */
                if (bloom) bloom_filter_free(bloom);
                if (block_indexes) compact_block_index_free(block_indexes);
                /* delete the empty sstable files */
                remove(new_sst->klog_path);
                remove(new_sst->vlog_path);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }

        tidesdb_merge_heap_free(heap);
    }

    /* reload for removal */

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        /* mark for deletion before removing from levels to avoid use-after-free */
        atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

        /* try to remove from each level -- break on first success since each sst is only in one
         * level */
        int removed_level = -1;
        for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
        {
            int result = tidesdb_level_remove_sstable(cf->db, cf->levels[level_idx], sst);
            if (result == TDB_SUCCESS)
            {
                removed_level = cf->levels[level_idx]->level_num;
                break; /* found and removed, no need to check other levels */
            }
        }

        /* remove from manifest if successfully removed from level
         * manifest operations take internal locks for thread safety */
        if (removed_level != -1)
        {
            tidesdb_manifest_remove_sstable(cf->manifest, removed_level, sst->id);
            int manifest_result = tidesdb_manifest_commit(cf->manifest, cf->manifest->path);
            if (manifest_result != 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "Failed to commit manifest after removing SSTable %" PRIu64
                              " (error: %d)",
                              sst->id, manifest_result);
            }
        }

        /* release the reference we took when collecting sstables */
        tidesdb_sstable_unref(cf->db, sst);
    }

    queue_free(sstables_to_delete);

    /* cleanup snapshot IDs */
    while (queue_size(sstable_ids_snapshot) > 0)
    {
        uint64_t *id_ptr = (uint64_t *)queue_dequeue(sstable_ids_snapshot);
        free(id_ptr);
    }
    queue_free(sstable_ids_snapshot);

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
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&cf->is_compacting, &expected, 1,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        /* another compaction is already running, skip this one */
        return TDB_SUCCESS;
    }

    /* force flush memtable before compaction to ensure all data is in ssts
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

    /* load num_levels atomically */
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Triggering compaction for column family: %s (levels: %d)",
                  cf->name, num_levels);

    /* calculate X (dividing level) */
    int X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    int target_lvl = X; /* default to X if no suitable level found */

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Calculating target compaction level (X=%d)", X);

    /* spooky algo 2 find smallest level q where C_q < Σ(N_i) for i=0 to q
     * this means we're looking for the first level that cannot accommodate the merge */
    for (int q = 1; q <= X && q < num_levels; q++)
    {
        size_t cumulative_size = 0;

        for (int i = 0; i <= q && i < num_levels; i++)
        {
            cumulative_size +=
                atomic_load_explicit(&cf->levels[i]->current_size, memory_order_relaxed);
        }

        /* check if C_q < cumulative_size (level cannot accommodate the merge) */
        size_t level_q_capacity =
            atomic_load_explicit(&cf->levels[q]->capacity, memory_order_relaxed);
        if (level_q_capacity < cumulative_size)
        {
            /* found smallest level that cannot accommodate -- this is our target */
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
        TDB_DEBUG_LOG(TDB_LOG_WARN, "target_lvl > X, defaulting to dividing merge");
        result = tidesdb_dividing_merge(cf, X - 1); /* convert to 0-indexed */
    }

    /* reload num_levels atomically after compaction */
    num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* recalculate X with potentially new num_levels */
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

            /* spooky algo 2 find smallest level z where C_z < Σ(N_i) for i=X to z
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

    /* get largest level info for later checks */
    if (num_levels == 0)
    {
        atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
    size_t largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);

    /* perform partitioned merge if needed */
    if (need_partitioned_merge)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Level %d is full, triggering partitioned preemptive merge", X);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Partitioned preemptive merge levels %d to %d", X, z);
        result = tidesdb_partitioned_merge(cf, X, z);

        /* reload num_levels after merge */
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
        /* re-fetch num_levels after add_level */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        if (num_levels > 0)
        {
            largest = cf->levels[num_levels - 1];
            largest_size = atomic_load_explicit(&largest->current_size, memory_order_relaxed);
            largest_capacity = atomic_load_explicit(&largest->capacity, memory_order_relaxed);
        }
    }

    /* check if largest level is truly empty by checking num_sstables, not current_size
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

        /* levels array is fixed, access directly */
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
 * @param tracker multi-CF transaction tracker for validation
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
static int tidesdb_wal_recover(tidesdb_column_family_t *cf, const char *wal_path,
                               skip_list_t **memtable, multi_cf_txn_tracker_t *tracker)
{
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' starting WAL recovery from: %s", cf->name, wal_path);
    block_manager_t *wal;
    if (block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "CF '%s' failed to open WAL: %s", cf->name, wal_path);
        return TDB_ERR_IO;
    }

    /* validate and recover WAL file (permissive mode truncate partial writes) */
    if (block_manager_validate_last_block(wal, 0) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' WAL validation failed: %s", cf->name, wal_path);
        block_manager_close(wal);
        return TDB_ERR_IO;
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' WAL validation passed: %s", cf->name, wal_path);

    /* resolve comparator for recovered memtable */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    if (tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx) != 0)
    {
        /* comparator not found, use default memcmp */
        comparator_fn = skip_list_comparator_memcmp;
        comparator_ctx = NULL;
    }

    if (skip_list_new_with_comparator(memtable, cf->config.skip_list_max_level,
                                      cf->config.skip_list_probability, comparator_fn,
                                      comparator_ctx) != 0)
    {
        block_manager_close(wal);
        return TDB_ERR_MEMORY;
    }

    /* read all entries from WAL */
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

            /* we check for multi-CF transaction metadata (once per block) */
            int is_multi_cf_entry = 0;
            uint8_t num_participant_cfs = 0;
            char **expected_cfs = NULL;

            if (remaining >= sizeof(tidesdb_multi_cf_txn_metadata_t))
            {
                /* peek at potential metadata header with proper endianness */
                const uint8_t *peek_ptr = ptr;
                uint8_t peek_num_cfs = *peek_ptr++;
                uint64_t peek_checksum = decode_uint64_le_compat(peek_ptr);

                /* if num_participant_cfs > 1, this is multi-CF metadata */
                if (peek_num_cfs > 1 && peek_num_cfs < 255)
                {
                    is_multi_cf_entry = 1;
                    num_participant_cfs = peek_num_cfs;

                    /* calculate metadata size */
                    size_t cf_names_size = num_participant_cfs * TDB_MAX_CF_NAME_LEN;
                    size_t metadata_size = sizeof(tidesdb_multi_cf_txn_metadata_t) + cf_names_size;

                    if (remaining < metadata_size)
                    {
                        block_manager_block_release(block);
                        continue;
                    }

                    const uint8_t *cf_names_ptr = ptr + sizeof(tidesdb_multi_cf_txn_metadata_t);
                    size_t checksum_data_size = sizeof(uint8_t) + cf_names_size;
                    uint8_t *checksum_data = malloc(checksum_data_size);
                    if (checksum_data)
                    {
                        checksum_data[0] = peek_num_cfs;
                        memcpy(checksum_data + 1, cf_names_ptr, cf_names_size);
                        uint64_t computed_checksum = XXH64(checksum_data, checksum_data_size, 0);
                        free(checksum_data);

                        if (computed_checksum != peek_checksum)
                        {
                            TDB_DEBUG_LOG(TDB_LOG_WARN,
                                          "CF '%s' has a multi-CF metadata checksum mismatch "
                                          "(expected: %" PRIu64 ", got: %" PRIu64
                                          ") - skipping entry",
                                          cf->name, peek_checksum, computed_checksum);
                            block_manager_block_release(block);
                            continue;
                        }
                    }
                    else
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_WARN,
                            "CF '%s' has failed to allocate memory for checksum verification - "
                            "skipping entry",
                            cf->name);
                        block_manager_block_release(block);
                        continue;
                    }

                    /* checksum is valid so we extract CF names and populate tracker */
                    if (tracker && num_participant_cfs > 0)
                    {
                        expected_cfs = malloc(num_participant_cfs * sizeof(char *));
                        if (expected_cfs)
                        {
                            const uint8_t *name_ptr = cf_names_ptr;
                            for (int i = 0; i < num_participant_cfs; i++)
                            {
                                expected_cfs[i] = malloc(TDB_MAX_CF_NAME_LEN);
                                if (expected_cfs[i])
                                {
                                    memcpy(expected_cfs[i], name_ptr, TDB_MAX_CF_NAME_LEN);
                                    expected_cfs[i][TDB_MAX_CF_NAME_LEN - 1] = '\0';
                                }
                                name_ptr += TDB_MAX_CF_NAME_LEN;
                            }
                        }
                    }

                    /* skip past metadata and CF names */
                    ptr += metadata_size;
                    remaining -= metadata_size;
                }
            }

            /* parse all entries within this block */
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
                int bytes_read = decode_varint_v2(ptr, &key_size_u64, (int)remaining);
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
                bytes_read = decode_varint_v2(ptr, &value_size_u64, (int)remaining);
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
                bytes_read = decode_varint_v2(ptr, &seq_value, (int)remaining);
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

                /* for multi-CF transactions, add to tracker and validate completeness */
                int should_apply = 1;
                if (is_multi_cf_entry && (entry.seq & TDB_MULTI_CF_SEQ_FLAG))
                {
                    if (tracker && expected_cfs)
                    {
                        multi_cf_tracker_add(tracker, entry.seq, cf->name, expected_cfs,
                                             num_participant_cfs);
                    }

                    /* only apply if transaction is complete across all CFs */
                    should_apply = multi_cf_tracker_is_complete(tracker, entry.seq);
                }

                if (should_apply)
                {
                    if (entry.flags & TDB_KV_FLAG_TOMBSTONE)
                    {
                        skip_list_put_with_seq(*memtable, key, entry.key_size, NULL, 0, 0,
                                               entry.seq, 1);
                    }
                    else
                    {
                        skip_list_put_with_seq(*memtable, key, entry.key_size, value,
                                               entry.value_size, entry.ttl, entry.seq, 0);
                    }

                    /* block-level cache will be populated during normal read operations */
                }
                else
                {
                    TDB_DEBUG_LOG(
                        TDB_LOG_INFO,
                        "CF '%s' WAL entry %d: skipping (incomplete multi-CF txn, seq=%" PRIu64 ")",
                        cf->name, entry_count, entry.seq);
                }
            }

            if (expected_cfs)
            {
                for (int i = 0; i < num_participant_cfs; i++)
                {
                    free(expected_cfs[i]);
                }
                free(expected_cfs);
            }

            block_manager_block_release(block);

        } while (block_manager_cursor_next(cursor) == 0);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO,
                  "CF '%s' WAL recovery completed: %d blocks, %d entries, memtable has %d entries",
                  cf->name, block_count, entry_count, skip_list_count_entries(*memtable));

    block_manager_cursor_free(cursor);
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

    skip_list_t *memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    block_manager_t *wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);

    skip_list_free(memtable);
    block_manager_close(wal);

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

    /* free all non-NULL levels in fixed array */
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

    if (cf->wal_group_buffer)
    {
        free(cf->wal_group_buffer);
        cf->wal_group_buffer = NULL;
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
        /* wait for work (blocking dequeue) */
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
        skip_list_t *memtable = imm->memtable;
        block_manager_t *wal = imm->wal;

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_INFO,
                "CF '%s' encountered insufficient disk space for flush (required: %" PRIu64
                " bytes)",
                cf->name, cf->config.min_disk_space);

            /* clear is_flushing to allow retries */
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
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' SSTable %" PRIu64 " creation failed", cf->name,
                          work->sst_id);

            /* clear is_flushing to allow retries */
            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        int write_result = tidesdb_sstable_write_from_memtable(db, sst, memtable, cf);
        if (write_result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "CF '%s' SSTable %" PRIu64 " write failed (error: %d), will retry",
                          cf->name, work->sst_id, write_result);

            tidesdb_sstable_unref(cf->db, sst);

            usleep(TDB_FLUSH_RETRY_DELAY_US);

            /* re-enqueue for retry (work still has valid imm reference) */
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

        /* ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* close write handles before adding to level
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

        /* validate flush ordering -- new sst should have higher sequence than existing ones
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

        /* add sstable to Level 1 (array index 0) -- load levels atomically */

        /* levels array is fixed, access directly */
        tidesdb_level_add_sstable(cf->levels[0], sst);

        atomic_thread_fence(memory_order_release);

        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' flushed SSTable %" PRIu64 " (max_seq=%" PRIu64
                      ") to level %d (array index 0)",
                      cf->name, work->sst_id, sst->max_seq, cf->levels[0]->level_num);

        /* commit sstable to manifest before deleting WAL and before triggering compaction
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

        /*  check file count in addition to size
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

        /* file count trigger (Spooky α parameter) */
        if (num_l1_sstables >= TDB_L1_FILE_NUM_COMPACTION_TRIGGER)
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
                          TDB_L1_FILE_NUM_COMPACTION_TRIGGER, level1_size, level1_capacity);
            tidesdb_compact(cf);
        }

        /* release our reference -- the level now owns it */
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

        /* release the work items reference now that flush is complete */
        tidesdb_immutable_memtable_unref(imm);

        /* batched cleanup only run every N flushes or when queue is large
         * this reduces overhead while preventing unbounded memory growth */
        int cleanup_threshold = 10;
        size_t max_queue_size = 20;
        int counter =
            atomic_fetch_add_explicit(&cf->immutable_cleanup_counter, 1, memory_order_relaxed);
        size_t current_queue_size = queue_size(cf->immutable_memtables);

        int should_cleanup =
            (counter % cleanup_threshold == 0) || (current_queue_size > max_queue_size);

        /* cleanup flushed immutables from queue if they have no active readers
         * we need to keep them in queue until all reads complete to maintain MVCC correctness */
        queue_t *temp_queue = should_cleanup ? queue_new() : NULL;
        if (temp_queue)
        {
            int cleaned = 0;
            while (!queue_is_empty(cf->immutable_memtables))
            {
                tidesdb_immutable_memtable_t *queued_imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
                if (queued_imm)
                {
                    int is_flushed =
                        atomic_load_explicit(&queued_imm->flushed, memory_order_acquire);

                    /* use atomic CAS to try claiming the last reference
                     * if refcount is 1, try to CAS it to 0 to claim ownership for cleanup
                     * if CAS succeeds, we own it and can free; if it fails, someone else ref'd it
                     */
                    int expected_refcount = 1;
                    int can_cleanup = 0;

                    if (is_flushed)
                    {
                        /* try to claim the last reference atomically */
                        if (atomic_compare_exchange_strong_explicit(
                                &queued_imm->refcount, &expected_refcount, 0, memory_order_acquire,
                                memory_order_relaxed))
                        {
                            can_cleanup = 1;
                        }
                    }

                    if (can_cleanup)
                    {
                        /* we successfully claimed it -- safe to free
                         * manually free since we set refcount to 0 */
                        if (queued_imm->memtable) skip_list_free(queued_imm->memtable);
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

            /* restore kept immutables back to original queue */
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
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "CF '%s' cleaned up %d flushed immutable(s) with no active readers",
                              cf->name, cleaned);
            }
        }

        /* clear is_flushing flag now that flush is complete
         * this allows new flushes to be triggered */
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

        /* compaction trigger moved earlier (right after flush) to use Spooky-style
         * file count + size checking for better read performance */

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

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG(
                TDB_LOG_WARN,
                "CF '%s' encountered insufficient disk space for compaction (required: %" PRIu64
                " bytes)",
                cf->name, cf->config.min_disk_space);
            /* clear is_compacting flag so compaction can be retried later */
            atomic_store_explicit(&cf->is_compacting, 0, memory_order_release);
            free(work);
            continue;
        }

        TDB_DEBUG_LOG(TDB_LOG_INFO, "Compacting CF '%s'", cf->name);
        int result = tidesdb_trigger_compaction(cf);
        if (result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' compaction failed with error %d", cf->name,
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

        /* scan all CFs to find minimum sync interval */
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
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
            sleep_us = NO_CF_SYNC_SLEEP_US;
        }
        else
        {
            sleep_us = min_interval;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (sleep_us / TDB_MICROSECONDS_PER_SECOND);
        ts.tv_nsec += (sleep_us % TDB_MICROSECONDS_PER_SECOND) * TDB_NANOSECONDS_PER_MICROSECOND;
        if (ts.tv_nsec >= TDB_NANOSECONDS_PER_SECOND)
        {
            ts.tv_sec++;
            ts.tv_nsec -= TDB_NANOSECONDS_PER_SECOND;
        }

        pthread_mutex_lock(&db->sync_thread_mutex);
        pthread_cond_timedwait(&db->sync_thread_cond, &db->sync_thread_mutex, &ts);
        pthread_mutex_unlock(&db->sync_thread_mutex);

        /* check shutdown flag after wait to avoid lock contention during shutdown */
        if (!atomic_load(&db->sync_thread_active))
        {
            break;
        }

        if (min_interval == UINT64_MAX)
        {
            /* no CFs needed syncing, skip sync phase */
            continue;
        }

        /* sync all CFs that need it */
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            if (cf && cf->config.sync_mode == TDB_SYNC_INTERVAL && cf->config.sync_interval_us > 0)
            {
                block_manager_t *wal = atomic_load(&cf->active_wal);
                if (wal)
                {
                    block_manager_escalate_fsync(wal);
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);
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
        atomic_store(&db->cached_current_time, time(NULL));

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
        pthread_cond_timedwait(&db->reaper_thread_cond, &db->reaper_thread_mutex, &ts);
        pthread_mutex_unlock(&db->reaper_thread_mutex);

        if (!atomic_load(&db->sstable_reaper_active))
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

        /* collect all ssts with refcount=0 and last_access_time */
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

        /* scan all column families for closeable ssts */
        pthread_rwlock_rdlock(&db->cf_list_lock);
        for (int i = 0; i < db->num_column_families; i++)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            if (!cf) continue;

            int num_levels = atomic_load(&cf->num_active_levels);
            for (int level = 0; level < num_levels && level < TDB_MAX_LEVELS; level++)
            {
                tidesdb_level_t *lvl = cf->levels[level];
                if (!lvl) continue;

                /* atomically load sstables array and count */
                tidesdb_sstable_t **ssts = atomic_load(&lvl->sstables);
                int num_ssts = atomic_load(&lvl->num_sstables);

                for (int j = 0; j < num_ssts; j++)
                {
                    tidesdb_sstable_t *sst = ssts[j];
                    if (!sst) continue;

                    /* only consider ssts that are open and not in use
                     * increment refcount to prevent use-after-free if compaction frees this sst */
                    if (sst->klog_bm && sst->vlog_bm && atomic_load(&sst->refcount) == 1)
                    {
                        atomic_fetch_add(&sst->refcount, 1);
                        candidates[candidate_count].sst = sst;
                        candidates[candidate_count].last_access =
                            atomic_load(&sst->last_access_time);
                        candidate_count++;
                    }
                }
            }
        }
        pthread_rwlock_unlock(&db->cf_list_lock);

        /* check shutdown flag after releasing lock to exit promptly */
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

        /* sort by last_access_time (oldest first) */
        qsort(candidates, candidate_count, sizeof(sstable_candidate_t), compare_sstable_candidates);

        /* close oldest (TDB_SSTABLE_REAPER_EVICT_RATIO) */
        int to_close = (int)(candidate_count * TDB_SSTABLE_REAPER_EVICT_RATIO);
        if (to_close == 0 && candidate_count > 0) to_close = 1; /* close at least 1 */

        int closed_count = 0;
        for (int i = 0; i < to_close && i < candidate_count; i++)
        {
            tidesdb_sstable_t *sst = candidates[i].sst;

            /* double-check refcount before closing (should be 2: our ref + base ref) */
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

        /* release all candidate refcounts */
        for (int i = 0; i < candidate_count; i++)
        {
            atomic_fetch_sub(&candidates[i].sst->refcount, 1);
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
        /* load current array atomically */
        tidesdb_comparator_entry_t *old_array =
            atomic_load_explicit(&db->comparators, memory_order_acquire);
        int old_count = atomic_load_explicit(&db->num_comparators, memory_order_acquire);
        int old_capacity = atomic_load_explicit(&db->comparators_capacity, memory_order_acquire);

        /* check for duplicate name */
        for (int i = 0; i < old_count; i++)
        {
            if (strcmp(old_array[i].name, name) == 0)
            {
                return TDB_ERR_INVALID_ARGS; /* duplicate name */
            }
        }

        /* determine new capacity */
        int new_capacity = old_capacity;
        if (old_count >= old_capacity)
        {
            new_capacity = old_capacity * 2;
        }

        /* allocate new array (COW) */
        tidesdb_comparator_entry_t *new_array =
            malloc(new_capacity * sizeof(tidesdb_comparator_entry_t));
        if (!new_array) return TDB_ERR_MEMORY;

        /* copy existing entries */
        if (old_count > 0)
        {
            memcpy(new_array, old_array, old_count * sizeof(tidesdb_comparator_entry_t));
        }

        /* add new comparator */
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

        /* try to swap in new array with CAS */
        if (atomic_compare_exchange_strong_explicit(&db->comparators, &old_array, new_array,
                                                    memory_order_release, memory_order_acquire))
        {
            /* success! update count and capacity */
            atomic_store_explicit(&db->num_comparators, old_count + 1, memory_order_release);
            atomic_store_explicit(&db->comparators_capacity, new_capacity, memory_order_release);

            /* free old array (safe because readers use atomic loads) */
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

    /* set log level from config */
    _tidesdb_log_level = config->log_level;

    const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE"};
    const char *level_str =
        (_tidesdb_log_level >= TDB_LOG_DEBUG && _tidesdb_log_level <= TDB_LOG_FATAL)
            ? level_names[_tidesdb_log_level]
            : (_tidesdb_log_level == TDB_LOG_NONE ? "NONE" : "UNKNOWN");

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Opening TidesDB with path=%s, log_level=%s, workers=%d",
                  config->db_path, level_str, config->num_compaction_threads);

    mkdir((*db)->db_path, TDB_DIR_PERMISSIONS);

    (*db)->cf_capacity = TDB_INITIAL_CF_CAPACITY;
    tidesdb_column_family_t **cfs = calloc((*db)->cf_capacity, sizeof(tidesdb_column_family_t *));
    if (!cfs)
    {
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
        queue_free((*db)->compaction_queue);
        queue_free((*db)->flush_queue);
        free((*db)->compaction_threads);
        free((*db)->flush_threads);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    tidesdb_comparator_entry_t *initial_comparators =
        calloc(TDB_INITIAL_COMPARATOR_CAPACITY, sizeof(tidesdb_comparator_entry_t));
    if (!initial_comparators)
    {
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    atomic_init(&(*db)->comparators, initial_comparators);
    atomic_init(&(*db)->num_comparators, 0);
    atomic_init(&(*db)->comparators_capacity, TDB_INITIAL_COMPARATOR_CAPACITY);

    /* register default comparators */
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
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    atomic_init(&(*db)->next_txn_id, 1);
    atomic_init(&(*db)->global_seq, 1);
    atomic_init(&(*db)->oldest_active_seq, 0);
    atomic_init(&(*db)->num_open_sstables, 0);

    (*db)->commit_status = tidesdb_commit_status_create(TDB_COMMIT_STATUS_BUFFER_SIZE);
    if (!(*db)->commit_status)
    {
        clock_cache_destroy((*db)->clock_cache);
        if ((*db)->flush_queue) queue_free((*db)->flush_queue);
        if ((*db)->compaction_queue) queue_free((*db)->compaction_queue);
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    if (pthread_rwlock_init(&(*db)->active_txns_lock, NULL) != 0)
    {
        tidesdb_commit_status_destroy((*db)->commit_status);
        clock_cache_destroy((*db)->clock_cache);
        if ((*db)->flush_queue) queue_free((*db)->flush_queue);
        if ((*db)->compaction_queue) queue_free((*db)->compaction_queue);
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    /* start with larger capacity to avoid realloc under lock */
    (*db)->active_txns_capacity = TDB_ACTIVE_TXN_INITIAL_CAPACITY;
    (*db)->active_txns = calloc((*db)->active_txns_capacity, sizeof(tidesdb_txn_t *));
    if (!(*db)->active_txns)
    {
        pthread_rwlock_destroy(&(*db)->active_txns_lock);
        tidesdb_commit_status_destroy((*db)->commit_status);
        clock_cache_destroy((*db)->clock_cache);
        if ((*db)->flush_queue) queue_free((*db)->flush_queue);
        if ((*db)->compaction_queue) queue_free((*db)->compaction_queue);
        free((*db)->column_families);
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
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free((*db)->column_families);
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

    tidesdb_recover_database(*db);

    /* now start background workers;  they will wait for recovery_complete signal */
    (*db)->flush_threads = malloc(config->num_flush_threads * sizeof(pthread_t));
    if (!(*db)->flush_threads)
    {
        clock_cache_destroy((*db)->clock_cache);
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free((*db)->column_families);
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
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free((*db)->column_families);
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
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free((*db)->column_families);
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
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free((*db)->column_families);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
    }

    /* check if any CF needs interval syncing and start sync thread if needed */
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

    /* initialize sync thread synchronization primitives */
    pthread_mutex_init(&(*db)->sync_thread_mutex, NULL);
    pthread_cond_init(&(*db)->sync_thread_cond, NULL);

    if (needs_sync_thread)
    {
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
    else
    {
        atomic_store(&(*db)->sync_thread_active, 0);
    }

    /* initialize cached time to avoid expensive time() syscalls in hot paths */
    atomic_store(&(*db)->cached_current_time, time(NULL));

    /* initialize reaper thread synchronization primitives */
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

            /* wait for any in-progress flush to complete */
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

            skip_list_t *memtable =
                atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
            int entry_count = skip_list_count_entries(memtable);

            if (entry_count > 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is flushing %d entries before close", cf->name,
                              entry_count);

                /* flush group commit buffer before syncing WAL to prevent data loss
                 * any pending writes in the buffer must be written to the WAL file
                 * before we rotate the WAL during flush */
                tidesdb_flush_wal_group_buffer(cf);

                /* ensure WAL is synced before attempting flush to prevent data loss */
                block_manager_t *active_wal =
                    atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                if (active_wal)
                {
                    block_manager_escalate_fsync(active_wal);
                    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' WAL is now synced before close", cf->name);
                }

                /* retry flush with backoff to prevent data loss */
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
                               retry_count); /* i.e exponential backoff 100ms, 200ms, 300ms... */
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

    /* wait for enqueued flushes to complete before shutting down flush threads
     * this ensures data is written to sstables, not left in WAL
     * we must wait indefinitely - terminating flush workers while they have
     * active work causes data loss */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for background flushes to complete");
    int flush_wait_count = 0;
    pthread_rwlock_rdlock(&db->cf_list_lock);
    while (1)
    {
        int any_flushing = 0;
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

        if (!any_flushing)
        {
            break;
        }

        if (flush_wait_count % 1000 == 0 && flush_wait_count > 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Still waiting for background flushes (waited %d seconds)",
                          flush_wait_count / 1000);
        }

        pthread_rwlock_unlock(&db->cf_list_lock);
        usleep(TDB_CLOSE_TXN_WAIT_SLEEP_US);
        flush_wait_count++;
        pthread_rwlock_rdlock(&db->cf_list_lock);
    }
    pthread_rwlock_unlock(&db->cf_list_lock);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "All background flushes completed");

    if (db->flush_queue)
    {
        /* set shutdown flag first, before enqueueing NULLs
         * this ensures queue_dequeue_wait will return NULL even if
         * a thread enters the wait after we broadcast */
        pthread_mutex_lock(&db->flush_queue->lock);
        atomic_store(&db->flush_queue->shutdown, 1);
        pthread_cond_broadcast(&db->flush_queue->not_empty);
        pthread_mutex_unlock(&db->flush_queue->lock);

        /* enqueue NULL items for each thread as a courtesy
         * (not strictly needed since shutdown=1, but maintains consistency) */
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
            queue_enqueue(db->flush_queue, NULL);
        }

        /* keep broadcasting periodically until all threads have exited
         * this handles the race where a thread might be between the while loop check
         * and pthread_cond_wait when we set shutdown=1 */
        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            pthread_mutex_lock(&db->flush_queue->lock);
            pthread_cond_broadcast(&db->flush_queue->not_empty);
            pthread_mutex_unlock(&db->flush_queue->lock);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }
    }

    if (db->compaction_queue)
    {
        /* set shutdown flag first, before enqueueing NULLs
         * this ensures queue_dequeue_wait will return NULL even if
         * a thread enters the wait after we broadcast */
        pthread_mutex_lock(&db->compaction_queue->lock);
        atomic_store(&db->compaction_queue->shutdown, 1);
        pthread_cond_broadcast(&db->compaction_queue->not_empty);
        pthread_mutex_unlock(&db->compaction_queue->lock);

        /* enqueue NULL items for each thread as a courtesy
         * (not strictly needed since shutdown=1, but maintains consistency) */
        for (int i = 0; i < db->config.num_compaction_threads; i++)
        {
            queue_enqueue(db->compaction_queue, NULL);
        }

        /* keep broadcasting periodically until all threads have exited
         * this handles the race where a thread might be between the while loop check
         * and pthread_cond_wait when we set shutdown=1 */
        for (int attempt = 0; attempt < TDB_SHUTDOWN_BROADCAST_ATTEMPTS; attempt++)
        {
            pthread_mutex_lock(&db->compaction_queue->lock);
            pthread_cond_broadcast(&db->compaction_queue->not_empty);
            pthread_mutex_unlock(&db->compaction_queue->lock);
            usleep(TDB_SHUTDOWN_BROADCAST_INTERVAL_US);
        }
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Waiting for %d flush threads to finish",
                  db->config.num_flush_threads);
    if (db->flush_threads)
    {
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
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
            pthread_join(db->compaction_threads[i], NULL);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction thread %d joined", i);
        }
        free(db->compaction_threads);
    }
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Compaction threads finished");

    /* stop sync worker thread if running */
    if (atomic_load(&db->sync_thread_active))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Stopping sync worker thread");
        atomic_store(&db->sync_thread_active, 0);

        pthread_mutex_lock(&db->sync_thread_mutex);
        pthread_cond_signal(&db->sync_thread_cond);
        pthread_mutex_unlock(&db->sync_thread_mutex);

        pthread_join(db->sync_thread, NULL);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Sync worker thread stopped");

        /* clean up synchronization primitives */
        pthread_mutex_destroy(&db->sync_thread_mutex);
        pthread_cond_destroy(&db->sync_thread_cond);
    }

    /* stop sstable file reaper thread if running */
    if (atomic_load(&db->sstable_reaper_active))
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Stopping SSTable reaper thread");
        atomic_store(&db->sstable_reaper_active, 0);

        pthread_mutex_lock(&db->reaper_thread_mutex);
        pthread_cond_signal(&db->reaper_thread_cond);
        pthread_mutex_unlock(&db->reaper_thread_mutex);

        pthread_join(db->sstable_reaper_thread, NULL);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "SSTable reaper thread stopped");

        /* clean up synchronization primitives */
        pthread_mutex_destroy(&db->reaper_thread_mutex);
        pthread_cond_destroy(&db->reaper_thread_cond);
    }

    /* drain and free any remaining work items before freeing queues */
    if (db->flush_queue)
    {
        while (!queue_is_empty(db->flush_queue))
        {
            tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue(db->flush_queue);
            if (work)
            {
                /* each flush work holds a reference to the immutable memtable */
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

    /* clean up all immutable memtables that remain in CF queues
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
            while (!queue_is_empty(cf->immutable_memtables))
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
                if (imm)
                {
                    int refcount = atomic_load_explicit(&imm->refcount, memory_order_acquire);
                    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' dequeuing immutable with refcount=%d",
                                  cf->name, refcount);
                    tidesdb_immutable_memtable_unref(imm);
                    cleaned++;
                }
            }
            if (cleaned > 0)
            {
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "CF '%s' cleaned up %d immutable memtables during shutdown", cf->name,
                              cleaned);
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

    /* free comparator registry */
    if (db->comparators)
    {
        tidesdb_comparator_entry_t *comparators =
            atomic_load_explicit(&db->comparators, memory_order_acquire);
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

    if (db->commit_status)
    {
        tidesdb_commit_status_destroy(db->commit_status);
    }

    if (db->active_txns)
    {
        free(db->active_txns);
        pthread_rwlock_destroy(&db->active_txns_lock);
    }

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

    /* validate sync configuration */
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

        /* sync parent directory to ensure directory entry is persisted
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

    /* validate and fix index_sample_ratio (must be at least 1 to avoid division by zero) */
    if (cf->config.index_sample_ratio < 1)
    {
        cf->config.index_sample_ratio = TDB_DEFAULT_INDEX_SAMPLE_RATIO;
    }

    /* validate and fix block_index_prefix_len */
    if (cf->config.block_index_prefix_len < TDB_BLOCK_INDEX_PREFIX_MIN ||
        cf->config.block_index_prefix_len > TDB_BLOCK_INDEX_PREFIX_MAX)
    {
        cf->config.block_index_prefix_len = TDB_DEFAULT_BLOCK_INDEX_PREFIX_LEN;
    }

    skip_list_t *new_memtable = NULL;

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;

    /* check if a custom comparator is specified */
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

    if (skip_list_new_with_comparator(&new_memtable, config->skip_list_max_level,
                                      config->skip_list_probability, comparator_fn,
                                      comparator_ctx) != 0)
    {
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    atomic_init(&cf->active_memtable, new_memtable);

    cf->immutable_memtables = queue_new();
    if (!cf->immutable_memtables)
    {
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    /* initialize memtable_id before creating WAL so we can use it for filename */
    atomic_init(&cf->memtable_id, 0);

    char wal_path[TDB_MAX_PATH_LEN];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(atomic_load(&cf->memtable_id)));

    block_manager_t *new_wal = NULL;
    if (block_manager_open(&new_wal, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_IO;
    }

    /* truncate WAL to prevent reading stale data from previous runs
     * this is critical on Windows where file deletion may be delayed due to file locking */
    if (block_manager_truncate(new_wal) != 0)
    {
        block_manager_close(new_wal);
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_IO;
    }

    atomic_init(&cf->active_wal, new_wal);

    /* initialize with min_levels */
    int min_levels = cf->config.min_levels;

    /* check if directory already has existing levels from disk */
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
                if (sscanf(entry->d_name, TDB_LEVEL_PREFIX "%d_", &level_num) >= 1)
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

    /* ensure we have enough levels for existing data */
    if (max_existing_level > min_levels)
    {
        min_levels = max_existing_level;
    }

    /* validate we dont exceed max levels */
    if (min_levels > TDB_MAX_LEVELS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Cannot create CF requires %d levels but max is %d", min_levels,
                      TDB_MAX_LEVELS);
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_INVALID_ARGS;
    }

    size_t base_capacity = config->write_buffer_size * config->level_size_ratio;

    /* initialize fixed levels array -- create min_levels, rest are NULL */
    for (int i = 0; i < min_levels; i++)
    {
        size_t level_capacity = base_capacity;
        /* calculate capacity
         * C_i = write_buffer_size * T^i */
        for (int j = 1; j <= i; j++)
        {
            level_capacity *= config->level_size_ratio;
        }

        cf->levels[i] = tidesdb_level_create(i + 1, level_capacity);
        if (!cf->levels[i])
        {
            /* cleanup already created levels */
            for (int cleanup_idx = 0; cleanup_idx < i; cleanup_idx++)
            {
                if (cf->levels[cleanup_idx])
                {
                    tidesdb_level_free(db, cf->levels[cleanup_idx]);
                }
            }
            block_manager_close(atomic_load(&cf->active_wal));
            queue_free(cf->immutable_memtables);
            skip_list_free(atomic_load(&cf->active_memtable));
            free(cf->directory);
            free(cf->name);
            free(cf);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG(TDB_LOG_INFO, "Creating level %d with capacity %zu", i + 1, level_capacity);
    }

    /* initialize remaining slots to NULL */
    for (int i = min_levels; i < TDB_MAX_LEVELS; i++)
    {
        cf->levels[i] = NULL;
    }

    atomic_init(&cf->num_active_levels, min_levels);

    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->is_compacting, 0);
    atomic_init(&cf->is_flushing, 0);
    atomic_init(&cf->immutable_cleanup_counter, 0);
    atomic_init(&cf->memtable_generation, 0);
    atomic_init(&cf->pending_commits, 0);

    cf->wal_group_buffer = malloc(TDB_WAL_GROUP_COMMIT_BUFFER_SIZE);
    if (!cf->wal_group_buffer)
    {
        /* cleanup all created levels */
        for (int cleanup_idx = 0; cleanup_idx < min_levels; cleanup_idx++)
        {
            if (cf->levels[cleanup_idx])
            {
                tidesdb_level_free(db, cf->levels[cleanup_idx]);
            }
        }
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    atomic_init(&cf->wal_group_buffer_size, 0);
    cf->wal_group_buffer_capacity = TDB_WAL_GROUP_COMMIT_BUFFER_SIZE;
    atomic_init(&cf->wal_group_leader, 0);
    atomic_init(&cf->wal_group_generation, 0);
    atomic_init(&cf->wal_group_writers, 0);

    /* zero the buffer to prevent uninitialized memory from being written to WAL */
    memset(cf->wal_group_buffer, 0, cf->wal_group_buffer_capacity);

    char manifest_path[TDB_MAX_PATH_LEN];
    snprintf(manifest_path, sizeof(manifest_path), "%s" PATH_SEPARATOR "%s", cf->directory,
             TDB_COLUMN_FAMILY_MANIFEST_NAME);
    cf->manifest = tidesdb_manifest_open(manifest_path);
    if (!cf->manifest)
    {
        /* cleanup all created levels */
        for (int cleanup_idx = 0; cleanup_idx < min_levels; cleanup_idx++)
        {
            if (cf->levels[cleanup_idx])
            {
                tidesdb_level_free(db, cf->levels[cleanup_idx]);
            }
        }
        free(cf->wal_group_buffer);

        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    /* no manifest_lock needed -- operations are serialized by design */

    if (buffer_new_with_eviction(&cf->active_txn_buffer, TDB_DEFAULT_ACTIVE_TXN_BUFFER_SIZE,
                                 txn_entry_evict, NULL) != 0)
    {
        /* cleanup all created levels */
        for (int cleanup_idx = 0; cleanup_idx < min_levels; cleanup_idx++)
        {
            if (cf->levels[cleanup_idx])
            {
                tidesdb_level_free(db, cf->levels[cleanup_idx]);
            }
        }
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    pthread_rwlock_wrlock(&db->cf_list_lock);

    /* check if we need to grow the array */
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

    /* save configuration to disk for recovery */
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

    return TDB_SUCCESS;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Dropping column family: %s", name);

    tidesdb_column_family_t *cf_to_drop = NULL;

    pthread_rwlock_wrlock(&db->cf_list_lock);

    /* find the CF to drop */
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

    /* shift remaining CFs down */
    for (int i = found_idx; i < db->num_column_families - 1; i++)
    {
        db->column_families[i] = db->column_families[i + 1];
    }
    db->column_families[db->num_column_families - 1] = NULL;
    db->num_column_families--;

    pthread_rwlock_unlock(&db->cf_list_lock);

    int result = remove_directory(cf_to_drop->directory);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "Deleted column family directory: %s (result: %d)",
                  cf_to_drop->directory, result);

    tidesdb_column_family_free(cf_to_drop);

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

    int wait_result = wait_for_open(db);
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
    /* wait for database to open and finish recovery, but timeout if its closing
     * this prevents threads from hanging forever when database is being closed
     * and prevents transactions from starting during recovery */
    int wait_count = 0;

    while (!atomic_load(&db->is_open) || atomic_load(&db->is_recovering))
    {
        if (wait_count >= TDB_OPENING_WAIT_MAX_MS)
        {
            /* database is not open and hasn't opened after timeout
             * its likely closing or closed */
            return TDB_ERR_INVALID_DB;
        }

        /* spin-wait with small sleep to avoid busy loop
         * use same interval as transaction wait for consistency */
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
                /* cleanup on failure */
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

static int tidesdb_flush_memtable_internal(tidesdb_column_family_t *cf, int already_holds_lock,
                                           int force)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

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

    skip_list_t *old_memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    size_t current_size = (size_t)skip_list_get_size(old_memtable);
    int current_entries = skip_list_count_entries(old_memtable);

    if (current_entries == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' memtable is empty, skipping flush", cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    /* only check size threshold if not forcing flush */
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

    block_manager_t *old_wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);
    uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);

    /** we flush group commit buffer before WAL rotation to prevent data loss
     * any pending writes in the buffer must be written to the old WAL file
     * before we rotate to a new WAL */
    tidesdb_flush_wal_group_buffer(cf);

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

    skip_list_t *new_memtable;
    if (skip_list_new_with_comparator(&new_memtable, cf->config.skip_list_max_level,
                                      cf->config.skip_list_probability, comparator_fn,
                                      comparator_ctx) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to create new memtable", cf->name);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    uint64_t wal_id = atomic_fetch_add(&cf->memtable_id, 1);
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

    /* truncate WAL to prevent reading stale data from previous runs
     * this is critical on Windows where file deletion may be delayed due to file locking
     * if an old WAL file exists, it may contain garbage data that would corrupt recovery */
    if (block_manager_truncate(new_wal) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to truncate new WAL: %s", cf->name, wal_path);
        block_manager_close(new_wal);
        skip_list_free(new_memtable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_IO;
    }

    tidesdb_immutable_memtable_t *immutable = malloc(sizeof(tidesdb_immutable_memtable_t));
    if (!immutable)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to allocate immutable memtable", cf->name);
        skip_list_free(new_memtable);
        block_manager_close(new_wal);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    immutable->memtable = old_memtable;
    immutable->wal = old_wal;
    atomic_init(&immutable->refcount, 1); /* starts with refcount = 1 */
    immutable->flushed = 0;               /* not yet flushed */
    queue_enqueue(cf->immutable_memtables, immutable);

    /* increment generation before waiting for pending commits
     * this signals new commits to use the new memtable */
    atomic_fetch_add_explicit(&cf->memtable_generation, 1, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);

    /* now wait for all commits that started with the old generation to complete */
    while (atomic_load_explicit(&cf->pending_commits, memory_order_acquire) > 0)
    {
        cpu_pause(); /* spin until all in-flight commits finish */
    }
    atomic_thread_fence(memory_order_seq_cst);

    /* swap active memtable with new empty one
     * commits that started after generation increment will see the new memtable */
    atomic_store_explicit(&cf->active_memtable, new_memtable, memory_order_release);
    atomic_store_explicit(&cf->active_wal, new_wal, memory_order_release);

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

    /* retry enqueue with backoff -- we must not lose this flush work
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

    /* check if compaction is already running to avoid flooding queue */
    if (atomic_load_explicit(&cf->is_compacting, memory_order_acquire))
    {
        /* compaction already running, skip */
        return TDB_SUCCESS;
    }

    /* enqueue compaction work */
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
                                       const uint8_t *key, size_t key_size, uint64_t seq)
{
    /* we skip read tracking for isolation levels that dont need conflict detection */
    if (txn->isolation_level < TDB_ISOLATION_REPEATABLE_READ)
    {
        return 0; /* READ_UNCOMMITTED and READ_COMMITTED dont need read tracking */
    }

    /**  check last few entries first (hot cache, likely duplicates)
     * most iterators read sequentially, so recent keys are often duplicates */
    int check_recent = (txn->read_set_count < 8) ? txn->read_set_count : 8;
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
        /* batch allocation grow by larger chunks for iterators
         * reduces realloc overhead when scanning many keys */
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

    txn->read_keys[txn->read_set_count] = malloc(key_size);
    if (!txn->read_keys[txn->read_set_count]) return -1;

    memcpy(txn->read_keys[txn->read_set_count], key, key_size);
    txn->read_key_sizes[txn->read_set_count] = key_size;
    txn->read_seqs[txn->read_set_count] = seq;
    txn->read_cfs[txn->read_set_count] = cf;

    txn->read_set_count++;

    /* create hash table when we cross threshold for O(1) SSI lookups */
    if (txn->read_set_count == TDB_TXN_READ_HASH_THRESHOLD && !txn->read_set_hash)
    {
        txn->read_set_hash = tidesdb_read_set_hash_create();
        if (txn->read_set_hash)
        {
            /* populate hash with all existing reads */
            for (int i = 0; i < txn->read_set_count; i++)
            {
                tidesdb_read_set_hash_insert((tidesdb_read_set_hash_t *)txn->read_set_hash, txn, i);
            }
        }
    }
    else if (txn->read_set_hash)
    {
        /* add new read to existing hash */
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
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;

    int wait_result = wait_for_open(db);
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

    /* assign unique transaction id from database counter */
    (*txn)->txn_id = atomic_fetch_add_explicit(&db->next_txn_id, 1, memory_order_relaxed);

    if (isolation == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        (*txn)->snapshot_seq = UINT64_MAX; /* we see all versions */
    }
    else if (isolation == TDB_ISOLATION_READ_COMMITTED)
    {
        /* snapshot will be refreshed on each read -- initial value doesnt matter */
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

    (*txn)->read_set_capacity = TDB_INITIAL_TXN_READ_SET_CAPACITY;
    (*txn)->read_keys = calloc((*txn)->read_set_capacity, sizeof(uint8_t *));
    (*txn)->read_key_sizes = calloc((*txn)->read_set_capacity, sizeof(size_t));
    (*txn)->read_seqs = calloc((*txn)->read_set_capacity, sizeof(uint64_t));
    (*txn)->read_cfs = calloc((*txn)->read_set_capacity, sizeof(tidesdb_column_family_t *));

    if (!(*txn)->read_keys || !(*txn)->read_key_sizes || !(*txn)->read_seqs || !(*txn)->read_cfs)
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

    /* register SERIALIZABLE transactions in active list for SSI tracking */
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
             * this transaction won't participate in SSI conflict detection,
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
 * @return int
 */
static int tidesdb_txn_add_cf_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf)
{
    if (!txn || !cf) return -1;
    if (txn->is_committed || txn->is_aborted) return -1;

    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf) return i;
    }

    if (txn->num_cfs >= txn->cf_capacity)
    {
        /* check if we've hit the maximum column family limit */
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

    int cf_index = txn->num_cfs;
    txn->cfs[cf_index] = cf;
    txn->num_cfs++;

    return cf_index;
}

int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf || !key || key_size == 0 || !value) return TDB_ERR_INVALID_ARGS;

    /* wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    /* validate key-value size against memory limits */
    int size_check = tidesdb_validate_kv_size(txn->db, key_size, value_size);
    if (size_check != 0) return size_check;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* add CF to transaction if not already added */
    int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    if (txn->num_ops >= TDB_MAX_TXN_OPS)
    {
        return TDB_ERR_TOO_LARGE;
    }

    /* expand ops array if needed */
    if (txn->num_ops >= txn->ops_capacity)
    {
        int new_capacity = txn->ops_capacity * 2;

        /* ensure we dont exceed max even with doubling */
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

    /* create hash table when we cross threshold for O(1) lookups */
    if (txn->num_ops == TDB_TXN_WRITE_HASH_THRESHOLD && !txn->write_set_hash)
    {
        txn->write_set_hash = tidesdb_write_set_hash_create();
        if (txn->write_set_hash)
        {
            /* populate hash with all existing operations */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                              i);
            }
        }
    }
    else if (txn->write_set_hash)
    {
        /* add new operation to existing hash */
        tidesdb_write_set_hash_insert((tidesdb_write_set_hash_t *)txn->write_set_hash, txn,
                                      txn->num_ops - 1);
    }

    return TDB_SUCCESS;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf || !key || key_size == 0 || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    PROFILE_INC(txn->db, total_reads);

    /* wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    /* add CF to transaction if not already added */
    int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    /* check write set first (read your own writes)
     * transaction must see its own uncommitted changes before checking cache/memtable
     * use search strategy based on transaction size:
     * -- small txns -- linear scan from end (cache-friendly, low overhead)
     * -- medium txns -- linear scan with early termination per CF
     * -- large txns -- O(1) hash table lookup
     *
     * search in reverse order (newest first) to find most recent write */

    /* for large transactions, use hash table for O(1) lookup */
    if (txn->write_set_hash)
    {
        int op_index = tidesdb_write_set_hash_lookup(
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
        int scan_start = txn->num_ops - 1;
        int scan_end = (txn->num_ops > TDB_TXN_SMALL_SCAN_LIMIT)
                           ? (txn->num_ops - TDB_TXN_SMALL_SCAN_LIMIT)
                           : 0;

        for (int i = scan_start; i >= scan_end; i--)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];

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

        /* if transaction is large and we didn't find in recent ops, scan remainder */
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
         * READ_COMMITTED doesn't need visibility callback because:
         * 1. it refreshes snapshot on each read to see all data up to current global_seq
         * 2. commit status buffer is circular and can have stale entries after recovery
         * 3. any data in memtable with seq <= snapshot_seq is considered visible
         *
         * use current_seq (not current_seq - 1) because committed transactions have
         * seq <= global_seq. After recovery, global_seq is set to max_seq from ssts,
         * so we need snapshot_seq = global_seq to see all committed data. */
        uint64_t current_seq = atomic_load_explicit(&txn->db->global_seq, memory_order_acquire);
        txn->snapshot_seq = current_seq; /* update transaction snapshot for debugging/visibility */
        snapshot_seq = current_seq;
        visibility_check = NULL; /* no visibility check needed for READ_COMMITTED */
    }
    else
    {
        /* REPEATABLE_READ, SNAPSHOT, SERIALIZABLE = consistent snapshot */
        snapshot_seq = txn->snapshot_seq;
        visibility_check = tidesdb_visibility_check_callback;
    }

    /* atomically capture memtable snapshot to prevent race with flush
     * we must load immutables before active memtable to avoid missing keys
     * during memtable rotation (when active becomes immutable) */

    /* lock free snapshot using queues atomic_head and atomic size
     * queue_peek_at() uses atomic loads without mutex, eliminating contention */
    tidesdb_immutable_memtable_t **immutable_refs = NULL;
    size_t immutable_count = 0;

    /* atomically read queue size (no lock needed) */
    immutable_count = atomic_load_explicit(&cf->immutable_memtables->size, memory_order_acquire);
    if (immutable_count > 0)
    {
        immutable_refs = malloc(immutable_count * sizeof(tidesdb_immutable_memtable_t *));
        if (immutable_refs)
        {
            size_t idx = 0;
            for (size_t i = 0; i < immutable_count; i++)
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                if (imm)
                {
                    tidesdb_immutable_memtable_ref(imm);
                    immutable_refs[idx++] = imm;
                }
            }
            immutable_count = idx;
        }
        else
        {
            immutable_count = 0;
        }
    }

    /* now load active memtable -- any keys that rotated are already in our immutable snapshot */
    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

    /* memory fence ensures we see consistent state */
    atomic_thread_fence(memory_order_acquire);

    uint8_t *temp_value;
    size_t temp_value_size;
    time_t ttl;
    uint8_t deleted;
    uint64_t found_seq = 0;

    int memtable_result = skip_list_get_with_seq(
        active_mt, key, key_size, &temp_value, &temp_value_size, &ttl, &deleted, &found_seq,
        snapshot_seq, visibility_check, visibility_check ? txn->db->commit_status : NULL);

    if (memtable_result == 0)
    {
        if (deleted)
        {
            /* found a tombstone in active memtable, key is deleted */
            free(temp_value);
            /* cleanup immutable refs before returning */
            for (size_t i = 0; i < immutable_count; i++)
            {
                if (immutable_refs[i]) tidesdb_immutable_memtable_unref(immutable_refs[i]);
            }
            free(immutable_refs);
            return TDB_ERR_NOT_FOUND;
        }

        if (ttl <= 0 || ttl > atomic_load(&txn->db->cached_current_time))
        {
            *value = temp_value;
            *value_size = temp_value_size;

            PROFILE_INC(txn->db, memtable_hits);
            tidesdb_txn_add_to_read_set(txn, cf, key, key_size, found_seq);

            /* cleanup immutable refs before returning */
            for (size_t i = 0; i < immutable_count; i++)
            {
                if (immutable_refs[i]) tidesdb_immutable_memtable_unref(immutable_refs[i]);
            }
            free(immutable_refs);
            return TDB_SUCCESS;
        }

        /* TTL expired */
        free(temp_value);
        /* fall through to check immutables */
    }

    /* now search immutable memtables safely with references held
     * search in reverse order (newest first) to find most recent version */

    int result = TDB_ERR_UNKNOWN; /* used for cleanup label */
    if (immutable_refs && immutable_count > 0)
    {
        for (int i = (int)immutable_count - 1; i >= 0; i--)
        {
            tidesdb_immutable_memtable_t *immutable = immutable_refs[i];
            if (immutable && immutable->memtable)
            {
                if (skip_list_get_with_seq(immutable->memtable, key, key_size, &temp_value,
                                           &temp_value_size, &ttl, &deleted, &found_seq,
                                           snapshot_seq, visibility_check,
                                           visibility_check ? txn->db->commit_status : NULL) == 0)
                {
                    if (deleted)
                    {
                        /* found a tombstone in immutable memtable, key is deleted */
                        free(temp_value);
                        result = TDB_ERR_NOT_FOUND;
                        goto cleanup_immutables;
                    }

                    if (ttl <= 0 || ttl > atomic_load(&txn->db->cached_current_time))
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

    /* block-level cache is used in tidesdb_sstable_get for efficient caching */

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    tidesdb_kv_pair_t *best_kv = NULL;
    uint64_t best_seq = UINT64_MAX;
    int found_any = 0;

    /* search level-by-level with early termination
     * for non-existent keys, this avoids checking all ssts in all levels
     * for existing keys in Level 1, this stops immediately without checking deeper levels */
    for (int level_num = 0; level_num < num_levels; level_num++)
    {
        PROFILE_INC(txn->db, levels_searched);
        tidesdb_level_t *level = cf->levels[level_num];
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);

        for (int j = 0; j < num_ssts; j++)
        {
            tidesdb_sstable_t *sst = sstables[j];
            if (!sst) continue;

            PROFILE_INC(txn->db, sstables_checked);

            /* range check -- skip ssts that don't overlap key */
            if (sst->min_key && sst->max_key)
            {
                int min_max_cmp = comparator_fn(sst->min_key, sst->min_key_size, sst->max_key,
                                                sst->max_key_size, comparator_ctx);
                int is_reverse = (min_max_cmp > 0);
                int cmp_min =
                    comparator_fn(key, key_size, sst->min_key, sst->min_key_size, comparator_ctx);
                int cmp_max =
                    comparator_fn(key, key_size, sst->max_key, sst->max_key_size, comparator_ctx);

                int out_of_range =
                    is_reverse ? (cmp_min > 0 || cmp_max < 0) : (cmp_min < 0 || cmp_max > 0);
                if (out_of_range)
                {
                    continue;
                }
            }

            /* bloom filter check -- skip if definitely not present */
            if (sst->bloom_filter)
            {
                PROFILE_INC(txn->db, bloom_checks);
                if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
                {
                    continue;
                }
                PROFILE_INC(txn->db, bloom_hits);
            }

            /* take ref only for ssts we will actually read */
            tidesdb_sstable_ref(sst);

            tidesdb_kv_pair_t *candidate_kv = NULL;
            int get_result = tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv);

            if (get_result == TDB_SUCCESS && candidate_kv)
            {
                uint64_t candidate_seq = candidate_kv->entry.seq;
                int accept = (snapshot_seq == UINT64_MAX) ? 1 : (candidate_seq <= snapshot_seq);

                if (accept && (best_seq == UINT64_MAX || candidate_seq > best_seq))
                {
                    if (best_kv) tidesdb_kv_pair_free(best_kv);
                    best_kv = candidate_kv;
                    best_seq = candidate_seq;
                    found_any = 1;
                    PROFILE_INC(txn->db, sstable_hits);

                    /* Level 1 hit -- stop immediately, no need to check deeper levels */
                    if (level_num == 0)
                    {
                        tidesdb_sstable_unref(cf->db, sst);

                        goto check_found_result;
                    }
                }
                else
                {
                    tidesdb_kv_pair_free(candidate_kv);
                }
            }

            tidesdb_sstable_unref(cf->db, sst);
        }

        /* early termination -- if we found key in this level, stop searching deeper
         * this is safe because newer versions are always in shallower levels */
        if (found_any && level_num == 0)
        {
            break;
        }
    }

check_found_result:

    /* check if we found a valid (non-deleted, non-expired) version */
    if (found_any && best_kv)
    {
        if (!(best_kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) &&
            (best_kv->entry.ttl == 0 ||
             best_kv->entry.ttl > atomic_load(&txn->db->cached_current_time)))
        {
            *value = malloc(best_kv->entry.value_size);
            if (*value)
            {
                memcpy(*value, best_kv->value, best_kv->entry.value_size);
                *value_size = best_kv->entry.value_size;

                tidesdb_txn_add_to_read_set(txn, cf, key, key_size, best_seq);

                tidesdb_kv_pair_free(best_kv);

                return TDB_SUCCESS;
            }
        }
        tidesdb_kv_pair_free(best_kv);
    }
    return TDB_ERR_NOT_FOUND;
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size)
{
    if (!txn || !cf || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    /* wait for database to finish opening, or fail if shutting down */
    if (!txn->db) return TDB_ERR_INVALID_ARGS;

    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* add CF to transaction if not already added */
    int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    if (txn->num_ops >= TDB_MAX_TXN_OPS)
    {
        return TDB_ERR_TOO_LARGE;
    }

    /* expand ops array if needed */
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

    return TDB_SUCCESS;
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* read-only transactions need conflict checking for REPEATABLE_READ and above */
    if (txn->num_ops == 0)
    {
        /* for READ_UNCOMMITTED and READ_COMMITTED, read-only transactions can commit immediately */
        if (txn->isolation_level < TDB_ISOLATION_REPEATABLE_READ)
        {
            txn->is_committed = 1;
            return TDB_SUCCESS;
        }
        /* for REPEATABLE_READ and above, we need to check if our reads are still valid */
        /* continue to conflict detection phase */
    }

    /*  we validate transaction state (allow read-only transactions) */
    if (txn->num_ops > 0)
    {
        if (txn->num_cfs <= 0) return TDB_ERR_INVALID_ARGS;
        if (txn->num_ops > TDB_MAX_TXN_OPS) return TDB_ERR_INVALID_ARGS;
    }

    /**
     * CONFLICT DETECTION (isolation level dependent)
     **/

    /* conflict detection based on isolation level
     * -- READ_UNCOMMITTED -- no conflict detection
     * -- READ_COMMITTED -- no conflict detection (each read sees latest committed)
     * -- REPEATABLE_READ -- read-write conflict detection only
     * -- SNAPSHOT -- read-write + write-write conflict detection
     * -- SERIALIZABLE -- full SSI (read-write + write-write + dangerous structures) */

    /* we check read-write conflicts (REPEATABLE_READ and above) */
    if (txn->isolation_level >= TDB_ISOLATION_REPEATABLE_READ)
    {
        for (int read_idx = 0; read_idx < txn->read_set_count; read_idx++)
        {
            tidesdb_column_family_t *key_cf = txn->read_cfs[read_idx];
            uint64_t key_read_seq = txn->read_seqs[read_idx];
            uint64_t found_seq = 0;

            skip_list_t *active_mt =
                atomic_load_explicit(&key_cf->active_memtable, memory_order_acquire);
            uint8_t *temp_value;
            size_t temp_value_size;
            time_t ttl;
            uint8_t deleted;

            if (skip_list_get_with_seq(active_mt, txn->read_keys[read_idx],
                                       txn->read_key_sizes[read_idx], &temp_value, &temp_value_size,
                                       &ttl, &deleted, &found_seq, UINT64_MAX, NULL, NULL) == 0)
            {
                free(temp_value);
                if (found_seq > key_read_seq)
                {
                    return TDB_ERR_CONFLICT;
                }
            }

            /* use safe snapshot to prevent use-after-free during concurrent flush */
            /* lock free immutable snapshot for conflict detection */
            tidesdb_immutable_memtable_t **imm_refs = NULL;
            size_t imm_count = 0;

            imm_count =
                atomic_load_explicit(&key_cf->immutable_memtables->size, memory_order_acquire);
            if (imm_count > 0)
            {
                imm_refs = malloc(imm_count * sizeof(tidesdb_immutable_memtable_t *));
                if (imm_refs)
                {
                    size_t idx = 0;
                    for (size_t imm_ref_idx = 0; imm_ref_idx < imm_count; imm_ref_idx++)
                    {
                        tidesdb_immutable_memtable_t *imm =
                            (tidesdb_immutable_memtable_t *)queue_peek_at(
                                key_cf->immutable_memtables, imm_ref_idx);
                        if (imm)
                        {
                            tidesdb_immutable_memtable_ref(imm);
                            imm_refs[idx++] = imm;
                        }
                    }
                    imm_count = idx;
                }
                else
                {
                    imm_count = 0;
                }
            }

            for (size_t imm_idx = 0; imm_idx < imm_count; imm_idx++)
            {
                tidesdb_immutable_memtable_t *imm = imm_refs[imm_idx];
                if (!imm || !imm->memtable) continue;

                if (skip_list_get_with_seq(imm->memtable, txn->read_keys[read_idx],
                                           txn->read_key_sizes[read_idx], &temp_value,
                                           &temp_value_size, &ttl, &deleted, &found_seq, UINT64_MAX,
                                           NULL, NULL) == 0)
                {
                    free(temp_value);
                    if (found_seq > key_read_seq)
                    {
                        /* cleanup refs before returning */
                        for (size_t k = 0; k < imm_count; k++)
                        {
                            if (imm_refs[k]) tidesdb_immutable_memtable_unref(imm_refs[k]);
                        }
                        free(imm_refs);
                        return TDB_ERR_CONFLICT;
                    }
                    break;
                }
            }

            /* cleanup immutable refs */
            for (size_t k = 0; k < imm_count; k++)
            {
                if (imm_refs[k]) tidesdb_immutable_memtable_unref(imm_refs[k]);
            }
            free(imm_refs);
        }
    }

    /* check write-write conflicts (SNAPSHOT and SERIALIZABLE) */
    if (txn->isolation_level >= TDB_ISOLATION_SNAPSHOT)
    {
        /* iterate through all write operations in txn->ops[] */
        for (int write_idx = 0; write_idx < txn->num_ops; write_idx++)
        {
            tidesdb_txn_op_t *op = &txn->ops[write_idx];
            tidesdb_column_family_t *key_cf = op->cf;
            uint64_t found_seq = 0;

            skip_list_t *active_mt =
                atomic_load_explicit(&key_cf->active_memtable, memory_order_acquire);
            uint8_t *temp_value;
            size_t temp_value_size;
            time_t ttl;
            uint8_t deleted;

            if (skip_list_get_with_seq(active_mt, op->key, op->key_size, &temp_value,
                                       &temp_value_size, &ttl, &deleted, &found_seq, UINT64_MAX,
                                       NULL, NULL) == 0)
            {
                free(temp_value);
                if (found_seq > txn->snapshot_seq)
                {
                    return TDB_ERR_CONFLICT;
                }
            }

            /* use safe snapshot to prevent use-after-free during concurrent flush */
            /* lock free immutable snapshot for conflict detection */
            tidesdb_immutable_memtable_t **imm_refs = NULL;
            size_t imm_count = 0;

            imm_count =
                atomic_load_explicit(&key_cf->immutable_memtables->size, memory_order_acquire);
            if (imm_count > 0)
            {
                imm_refs = malloc(imm_count * sizeof(tidesdb_immutable_memtable_t *));
                if (imm_refs)
                {
                    size_t idx = 0;
                    for (size_t imm_ref_idx = 0; imm_ref_idx < imm_count; imm_ref_idx++)
                    {
                        tidesdb_immutable_memtable_t *imm =
                            (tidesdb_immutable_memtable_t *)queue_peek_at(
                                key_cf->immutable_memtables, imm_ref_idx);
                        if (imm)
                        {
                            tidesdb_immutable_memtable_ref(imm);
                            imm_refs[idx++] = imm;
                        }
                    }
                    imm_count = idx;
                }
                else
                {
                    imm_count = 0;
                }
            }

            for (size_t imm_idx = 0; imm_idx < imm_count; imm_idx++)
            {
                tidesdb_immutable_memtable_t *imm = imm_refs[imm_idx];
                if (!imm || !imm->memtable) continue;

                if (skip_list_get_with_seq(imm->memtable, op->key, op->key_size, &temp_value,
                                           &temp_value_size, &ttl, &deleted, &found_seq, UINT64_MAX,
                                           NULL, NULL) == 0)
                {
                    free(temp_value);
                    if (found_seq > txn->snapshot_seq)
                    {
                        /* cleanup refs before returning */
                        for (size_t k = 0; k < imm_count; k++)
                        {
                            if (imm_refs[k]) tidesdb_immutable_memtable_unref(imm_refs[k]);
                        }
                        free(imm_refs);
                        return TDB_ERR_CONFLICT;
                    }
                    break;
                }
            }

            /* cleanup immutable refs */
            for (size_t k = 0; k < imm_count; k++)
            {
                if (imm_refs[k]) tidesdb_immutable_memtable_unref(imm_refs[k]);
            }
            free(imm_refs);
        }
    }

    if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        /* single lock acquisition -- take snapshot of active transactions
         * then process lock-free. this reduces lock acquisitions from O(N*M) to O(1)
         * where N = active txns, M = write keys. */
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
                /* fallback to old behavior if malloc fails */
                snapshot_count = 0;
            }
        }
        pthread_rwlock_unlock(&txn->db->active_txns_lock);

        /* process snapshot lock-free -- transaction pointers remain valid because
         * transactions are only freed after removal from active list */
        for (int i = 0; i < snapshot_count; i++)
        {
            tidesdb_txn_t *other = snapshot[i];
            if (other == txn || other->is_committed || other->is_aborted) continue;

            /* we use hash table for O(1) conflict detection when read set is large
             * for small read sets, nested loop is faster due to cache locality
             * for large read sets, hash table provides O(m) instead of O(n*m) */
            if (txn->read_set_hash && txn->read_set_count >= TDB_TXN_READ_HASH_THRESHOLD)
            {
                /* O(m) hash-based conflict detection for large read sets */
                for (int w = 0; w < other->num_ops && !txn->has_rw_conflict_out; w++)
                {
                    tidesdb_txn_op_t *other_op = &other->ops[w];
                    if (tidesdb_read_set_hash_check_conflict(
                            (tidesdb_read_set_hash_t *)txn->read_set_hash, txn, other_op->cf,
                            other_op->key, other_op->key_size))
                    {
                        txn->has_rw_conflict_out = 1;
                        other->has_rw_conflict_in = 1;
                        break;
                    }
                }
            }
            else
            {
                /* O(n*m) nested loop for small read sets -- better cache locality */
                for (int r = 0; r < txn->read_set_count && !txn->has_rw_conflict_out; r++)
                {
                    for (int w = 0; w < other->num_ops; w++)
                    {
                        tidesdb_txn_op_t *other_op = &other->ops[w];
                        /* size check first (int comparison -- fastest) */
                        if (txn->read_key_sizes[r] != other_op->key_size) continue;
                        /* CF pointer check (pointer comparison -- fast) */
                        if (txn->read_cfs[r] != other_op->cf) continue;
                        /* memcmp last (most expensive) */
                        if (memcmp(txn->read_keys[r], other_op->key, txn->read_key_sizes[r]) == 0)
                        {
                            txn->has_rw_conflict_out = 1;
                            other->has_rw_conflict_in = 1;
                            break;
                        }
                    }
                }
            }
        }

        /* check for dangerous structures (rw-antidependency cycles)
         * a dangerous structure exists if
         * T1 -> T2 -> T3 -> T1 where
         * -- T1 has rw-conflict-out to T2 (T1 reads, T2 writes same key)
         * -- T2 has rw-conflict-out to T3
         * -- T3 has rw-conflict-in from T1 (creates cycle)
         *
         * if this tx has both rw-conflict-in and rw-conflict-out,
         * its part of a potential dangerous structure and must abort.
         */
        if (txn->has_rw_conflict_in && txn->has_rw_conflict_out)
        {
            free(snapshot);
            tidesdb_txn_remove_from_active_list(txn);
            return TDB_ERR_CONFLICT;
        }

        if (txn->num_ops == 0)
        {
            free(snapshot);
            goto skip_ssi_check;
        }

        /* check for dangerous structures--process snapshot lock-free */
        for (int i = 0; i < snapshot_count; i++)
        {
            tidesdb_txn_t *other = snapshot[i];

            if (other == txn || other->is_committed || other->is_aborted ||
                !other->has_rw_conflict_in || !other->has_rw_conflict_out)
            {
                continue;
            }

            int has_overlap = 0;
            for (int w = 0; w < txn->num_ops && !has_overlap; w++)
            {
                tidesdb_txn_op_t *txn_op = &txn->ops[w];
                for (int r = 0; r < other->read_set_count; r++)
                {
                    if (txn_op->key_size != other->read_key_sizes[r]) continue;
                    if (txn_op->cf != other->read_cfs[r]) continue;

                    if (memcmp(txn_op->key, other->read_keys[r], txn_op->key_size) == 0)
                    {
                        has_overlap = 1;
                        break;
                    }
                }
            }

            if (has_overlap)
            {
                free(snapshot);
                tidesdb_txn_remove_from_active_list(txn);
                return TDB_ERR_CONFLICT;
            }
        }

        free(snapshot);
    }

skip_ssi_check:

    /*
     * ACQUIRE COMMIT SEQUENCE (establishes commit order)
     * we acquire this after conflict detection passes,
     * so we never waste sequence numbers on aborted transactions.
     * */
    txn->commit_seq = atomic_fetch_add_explicit(&txn->db->global_seq, 1, memory_order_relaxed);

    /* mark this sequence as in-progress in commit status tracker */
    tidesdb_commit_status_mark(txn->db->commit_status, txn->commit_seq,
                               TDB_COMMIT_STATUS_IN_PROGRESS);

    /* for multi-CF transactions, add metadata size to each CF's WAL */
    size_t multi_cf_metadata_size = 0;
    if (txn->num_cfs > 1)
    {
        /* metadata: num_cfs (1 byte) + checksum (8 bytes) + CF names */
        multi_cf_metadata_size =
            sizeof(tidesdb_multi_cf_txn_metadata_t) + (txn->num_cfs * TDB_MAX_CF_NAME_LEN);
    }

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];

        int cf_op_count = 0;
        size_t cf_wal_size = multi_cf_metadata_size; /* start with metadata size */

        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf == cf)
            {
                cf_op_count++;
                /* flags byte */
                cf_wal_size += 1;
                /* exact varint sizes for key_size, value_size, and sequence */
                cf_wal_size += varint_size(op->key_size);
                cf_wal_size += varint_size(op->value_size);
                cf_wal_size += varint_size(txn->commit_seq);
                /* TTL: 8 bytes if present */
                if (op->ttl != 0) cf_wal_size += 8;
                /* key and value data */
                cf_wal_size += op->key_size;
                if (op->value_size > 0) cf_wal_size += op->value_size;
            }
        }

        if (cf_op_count == 0) continue;

        /* serialize WAL batch */
        uint8_t *wal_batch = malloc(cf_wal_size);
        if (!wal_batch) return TDB_ERR_MEMORY;

        /* zero the buffer to prevent uninitialized memory in WAL */
        memset(wal_batch, 0, cf_wal_size);

        uint8_t *wal_ptr = wal_batch;

        /* write multi-CF metadata if this is a multi-CF transaction */
        if (txn->num_cfs > 1)
        {
            /* write num_participant_cfs */
            *wal_ptr++ = (uint8_t)txn->num_cfs;

            /* prepare checksum data: num_cfs + all CF names */
            size_t cf_names_size = txn->num_cfs * TDB_MAX_CF_NAME_LEN;
            size_t checksum_data_size = sizeof(uint8_t) + cf_names_size;
            uint8_t *checksum_data = malloc(checksum_data_size);
            if (!checksum_data)
            {
                free(wal_batch);
                return TDB_ERR_MEMORY;
            }

            checksum_data[0] = (uint8_t)txn->num_cfs;
            uint8_t *name_ptr = checksum_data + 1;

            /* copy all CF names into checksum data and WAL */
            for (int i = 0; i < txn->num_cfs; i++)
            {
                memset(name_ptr, 0, TDB_MAX_CF_NAME_LEN);
                strncpy((char *)name_ptr, txn->cfs[i]->name, TDB_MAX_CF_NAME_LEN - 1);
                name_ptr += TDB_MAX_CF_NAME_LEN;
            }

            /* compute checksum */
            uint64_t checksum = XXH64(checksum_data, checksum_data_size, 0);
            free(checksum_data);

            /* write checksum (8 bytes, little-endian) */
            encode_uint64_le_compat(wal_ptr, checksum);
            wal_ptr += sizeof(uint64_t);

            /* write CF names */
            for (int i = 0; i < txn->num_cfs; i++)
            {
                memset(wal_ptr, 0, TDB_MAX_CF_NAME_LEN);
                strncpy((char *)wal_ptr, txn->cfs[i]->name, TDB_MAX_CF_NAME_LEN - 1);
                wal_ptr += TDB_MAX_CF_NAME_LEN;
            }
        }

        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            uint8_t flags = op->is_delete ? TDB_KV_FLAG_TOMBSTONE : 0;
            if (op->ttl != 0) flags |= TDB_KV_FLAG_HAS_TTL;
            *wal_ptr++ = flags;

            /* write variable-length sizes */
            wal_ptr += encode_varint_v2(wal_ptr, op->key_size);
            wal_ptr += encode_varint_v2(wal_ptr, op->value_size);

            /* write sequence (full, not delta -- each WAL entry is independent) */
            wal_ptr += encode_varint_v2(wal_ptr, txn->commit_seq);

            /* write TTL only if present */
            if (op->ttl != 0)
            {
                encode_int64_le_compat(wal_ptr, op->ttl);
                wal_ptr += sizeof(int64_t);
            }

            /* no vlog_offset in WAL -- values are always inline */

            /* write key and value data */
            memcpy(wal_ptr, op->key, op->key_size);
            wal_ptr += op->key_size;

            if (op->value_size > 0 && op->value)
            {
                memcpy(wal_ptr, op->value, op->value_size);
                wal_ptr += op->value_size;
            }
        }

        /* check if transaction is too large for group commit buffer */
        if (cf_wal_size > cf->wal_group_buffer_capacity)
        {
            /* transaction too large -- bypass group commit and write directly */
            block_manager_t *target_wal =
                atomic_load_explicit(&cf->active_wal, memory_order_acquire);
            block_manager_block_t *wal_block = block_manager_block_create(cf_wal_size, wal_batch);

            if (wal_block)
            {
                int64_t wal_offset = block_manager_block_write(target_wal, wal_block);
                block_manager_block_release(wal_block);

                if (wal_offset < 0)
                {
                    free(wal_batch);
                    return TDB_ERR_IO;
                }
            }

            free(wal_batch);
        }
        else
        {
            /* capture current generation before reserving space */
            uint64_t my_generation = atomic_load(&cf->wal_group_generation);

            /* atomically reserve space in buffer (lock-free!) */
            size_t my_offset = atomic_fetch_add(&cf->wal_group_buffer_size, cf_wal_size);

            /* check if we exceeded capacity */
            if (my_offset + cf_wal_size > cf->wal_group_buffer_capacity)
            {
                /* buffer full -- need to flush
                 * try to become the flusher (only one thread wins) */

                int expected = 0;
                if (atomic_compare_exchange_strong(&cf->wal_group_leader, &expected, 1))
                {
                    size_t flush_size = atomic_exchange(&cf->wal_group_buffer_size, 0);

                    /* subtract our own reservation that was never copied */
                    if (flush_size >= my_offset + cf_wal_size)
                    {
                        flush_size = my_offset; /* only flush data before our reservation */
                    }

                    /* increment generation to invalidate any pending writes */
                    atomic_fetch_add(&cf->wal_group_generation, 1);

                    /* wait for all in-flight writers to complete */
                    int wait_cycles = 0;
                    while (atomic_load(&cf->wal_group_writers) > 0)
                    {
                        usleep(TDB_WAL_GROUP_WRITER_WAIT_US);
                        if (++wait_cycles > TDB_WAL_GROUP_WRITER_MAX_WAIT_CYCLES) break;
                    }

                    /* memory fence to ensure all memcpy operations from threads that reserved space
                     * before the exchange are visible to us before we flush */
                    atomic_thread_fence(memory_order_acquire);

                    /***
                     * append our own data to the buffer and flush everything in ONE atomic write
                     * this prevents write ordering issues on Windows where multiple pwrite calls
                     * may not be visible in order during recovery */
                    if (flush_size + cf_wal_size <= cf->wal_group_buffer_capacity)
                    {
                        /* safe to append our data to the buffer */
                        memcpy(cf->wal_group_buffer + flush_size, wal_batch, cf_wal_size);
                        flush_size += cf_wal_size;
                    }

                    /* flush buffer (now includes our data) in a single atomic write */
                    if (flush_size > 0)
                    {
                        block_manager_t *target_wal =
                            atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                        block_manager_block_t *group_block =
                            block_manager_block_create(flush_size, cf->wal_group_buffer);

                        if (group_block)
                        {
                            int64_t wal_offset = block_manager_block_write(target_wal, group_block);

                            block_manager_block_release(group_block);
                        }
                        else
                        {
                            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                                          "CF '%s' txn seq=%" PRIu64
                                          " leader failed to create group block",
                                          cf->name, txn->commit_seq);
                        }
                    }

                    /* buffer is now empty, reset state */
                    atomic_store(&cf->wal_group_buffer_size, 0);
                    atomic_store(&cf->wal_group_leader, 0);
                }
                else
                {
                    /* someone else is flushing -- write directly to avoid blocking
                     * this improves parallelism under high concurrency by avoiding spin-waits */

                    block_manager_t *target_wal =
                        atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                    block_manager_block_t *direct_block =
                        block_manager_block_create(cf_wal_size, wal_batch);
                    if (direct_block)
                    {
                        int64_t wal_offset = block_manager_block_write(target_wal, direct_block);

                        block_manager_block_release(direct_block);
                    }
                    free(wal_batch);
                    continue; /* skip to next CF */
                }
            }
            else
            {
                /* space reserved successfully -- copy data
                 * but first check if our generation is still valid */
                uint64_t current_generation = atomic_load(&cf->wal_group_generation);

                if (current_generation != my_generation)
                {
                    block_manager_t *target_wal =
                        atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                    block_manager_block_t *direct_block =
                        block_manager_block_create(cf_wal_size, wal_batch);
                    if (direct_block)
                    {
                        int64_t wal_offset = block_manager_block_write(target_wal, direct_block);

                        block_manager_block_release(direct_block);
                    }
                }
                else if (my_offset + cf_wal_size <= cf->wal_group_buffer_capacity)
                {
                    /* generation is still valid and we have space -- copy data
                     * increment writer count before memcpy to prevent premature flush */
                    atomic_fetch_add(&cf->wal_group_writers, 1);

                    /* re-check generation after incrementing writers */
                    if (atomic_load(&cf->wal_group_generation) != my_generation)
                    {
                        atomic_fetch_sub(&cf->wal_group_writers, 1);

                        block_manager_t *target_wal =
                            atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                        block_manager_block_t *direct_block =
                            block_manager_block_create(cf_wal_size, wal_batch);
                        if (direct_block)
                        {
                            int64_t wal_offset =
                                block_manager_block_write(target_wal, direct_block);

                            block_manager_block_release(direct_block);
                        }
                    }
                    else
                    {
                        /* safe to copy now */

                        memcpy(cf->wal_group_buffer + my_offset, wal_batch, cf_wal_size);

                        /* memory fence to ensure our memcpy is visible before decrementing writers
                         */
                        atomic_thread_fence(memory_order_release);

                        /* decrement writer count to signal we're done */
                        atomic_fetch_sub(&cf->wal_group_writers, 1);
                    }
                }
                else
                {
                    /* race condition detected -- write directly instead */
                    atomic_fetch_sub(&cf->wal_group_buffer_size, cf_wal_size);
                    block_manager_t *target_wal =
                        atomic_load_explicit(&cf->active_wal, memory_order_acquire);
                    block_manager_block_t *direct_block =
                        block_manager_block_create(cf_wal_size, wal_batch);
                    if (direct_block)
                    {
                        block_manager_block_write(target_wal, direct_block);
                        block_manager_block_release(direct_block);
                    }
                }
            }

            free(wal_batch);
        }
    }

    /*
     * WRITE TO MEMTABLES (deterministic, no retries)
     * since we acquired commit_seq after conflict detection,
     * we know this sequence is unique and monotonically increasing.
     * writes cannot fail due to sequence conflicts.
     * */

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];

        /* use relaxed ordering for increment--only final decrement needs release */
        atomic_fetch_add_explicit(&cf->pending_commits, 1, memory_order_relaxed);

        skip_list_t *memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

#define TXN_KEY_HASH_SIZE   1024
#define TXN_STACK_HASH_SIZE 256
        typedef struct
        {
            uint8_t *key;
            size_t key_size;
            tidesdb_column_family_t *cf;
        } seen_key_t;

        /* use stack allocation for small transactions to avoid malloc failure path
         * this ensures O(N) dedup even under memory pressure */
        seen_key_t stack_hash[TXN_STACK_HASH_SIZE];
        memset(stack_hash, 0, sizeof(stack_hash));

        seen_key_t *seen_keys = stack_hash;
        int hash_size = TXN_STACK_HASH_SIZE;
        int needs_free = 0;

        /* for large transactions, try heap allocation for better hash distribution */
        if (txn->num_ops > TXN_STACK_HASH_SIZE)
        {
            seen_key_t *heap_hash = calloc(TXN_KEY_HASH_SIZE, sizeof(seen_key_t));
            if (heap_hash)
            {
                seen_keys = heap_hash;
                hash_size = TXN_KEY_HASH_SIZE;
                needs_free = 1;
            }
            /* else fall back to stack hash -- still O(N) with more collisions */
        }

        /* always use hash-based dedup (O(N)) -- no O(N²) fallback */
        {
            for (int i = txn->num_ops - 1; i >= 0; i--)
            {
                tidesdb_txn_op_t *op = &txn->ops[i];
                if (op->cf != cf) continue;

                uint32_t hash = 0;
                for (size_t b = 0; b < op->key_size; b++)
                {
                    hash = hash * 31 + op->key[b];
                }

                int slot = hash % hash_size;
                int found = 0;
                for (int probe = 0; probe < hash_size; probe++)
                {
                    if (seen_keys[slot].key == NULL)
                    {
                        seen_keys[slot].key = op->key;
                        seen_keys[slot].key_size = op->key_size;
                        seen_keys[slot].cf = cf;
                        break;
                    }
                    if (seen_keys[slot].cf == cf && seen_keys[slot].key_size == op->key_size &&
                        memcmp(seen_keys[slot].key, op->key, op->key_size) == 0)
                    {
                        found = 1;
                        break;
                    }
                    slot = (slot + 1) % hash_size;
                }

                if (found) continue;

                int put_result =
                    skip_list_put_with_seq(memtable, op->key, op->key_size, op->value,
                                           op->value_size, op->ttl, txn->commit_seq, op->is_delete);
                if (put_result != 0)
                {
                    if (needs_free) free(seen_keys);
                    /* error path -- use relaxed since we're aborting anyway */
                    atomic_fetch_sub_explicit(&cf->pending_commits, 1, memory_order_relaxed);
                    return TDB_ERR_IO;
                }

                /* we intentionally do not populate cache on writes.
                 * cache is read-optimized for hot keys only and concurrency
                 * populating on writes
                 * -- pollutes cache with potentially cold/write-once keys
                 * -- hurts write performance with serialization overhead
                 * -- prevents natural read-based cache warming
                 * cache will be populated on first read via tidesdb_sstable_get */
            }
            if (needs_free) free(seen_keys);
        }

        atomic_thread_fence(memory_order_seq_cst);

        atomic_fetch_sub_explicit(&cf->pending_commits, 1, memory_order_release);
    }

    txn->is_committed = 1;

    /*
     * CHECK IF MEMTABLES NEED FLUSHING (after commit completes)
     * we check after releasing pending_commits to avoid
     * deadlock if flush queue blocks. this is safe because the data is
     * already committed and visible.
     * */

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];
        skip_list_t *memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

        /* check if memtable needs flushing
         * we use 1.25x threshold (25% hysteresis) to prevent excessive small ssts
         * from batched transactions. this allows multiple batches to accumulate
         * before flushing, reducing sst count and overhead.
         *
         * for example with 64MB buffer and 1000-op batches
         *   old -- flush at 64MB → 1 sst per ~5 batches
         *   new -- flush at 80MB → 1 sst per ~6-7 batches (20% fewer ssts)
         */
        size_t memtable_size = (size_t)skip_list_get_size(memtable);
        size_t flush_threshold = cf->config.write_buffer_size + (cf->config.write_buffer_size / 4);

        if (memtable_size >= flush_threshold)
        {
            /* immutable memtable queue backpressure -- if too many pending flushes,
             * slow down writes to prevent unbounded queue growth and stalls.
             * this is critical when writes outpace flush workers. */
            size_t immutable_queue_depth = queue_size(cf->immutable_memtables);

            if (immutable_queue_depth >= TDB_BACKPRESSURE_IMMUTABLE_EMERGENCY)
            {
                /* emergency 10+ pending flushes, apply strong backpressure */
                usleep(TDB_BACKPRESSURE_IMMUTABLE_EMERGENCY_DELAY_US);
            }
            else if (immutable_queue_depth >= TDB_BACKPRESSURE_IMMUTABLE_CRITICAL)
            {
                /* critical 6-9 pending flushes */
                usleep(TDB_BACKPRESSURE_IMMUTABLE_CRITICAL_DELAY_US);
            }
            else if (immutable_queue_depth >= TDB_BACKPRESSURE_IMMUTABLE_MODERATE)
            {
                /* moderate 3-5 pending flushes */
                usleep(TDB_BACKPRESSURE_IMMUTABLE_MODERATE_DELAY_US);
            }

            /* spooky-style file-count-based backpressure (β and γ triggers)
             * file count is more critical than capacity for write amplification control */
            int num_l1_sstables =
                atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);

            if (num_l1_sstables >= TDB_L1_STOP_WRITES_TRIGGER)
            {
                /* γ (gamma) -- emergency stop: 36+ files, stall writes completely */
                usleep(TDB_L1_STOP_WRITES_DELAY_US);
                TDB_DEBUG_LOG(TDB_LOG_ERROR,
                              "CF '%s' L1 file count critical (%d >= %d), stalling writes (%dms)",
                              cf->name, num_l1_sstables, TDB_L1_STOP_WRITES_TRIGGER,
                              TDB_L1_STOP_WRITES_DELAY_US / 1000);
            }
            else if (num_l1_sstables >= TDB_L1_SLOWDOWN_WRITES_TRIGGER)
            {
                /* β (beta) -- slowdown: 20+ files, throttle writes */
                usleep(TDB_L1_SLOWDOWN_WRITES_DELAY_US);
                TDB_DEBUG_LOG(TDB_LOG_WARN,
                              "CF '%s' L1 file count high (%d >= %d), throttling writes (20ms)",
                              cf->name, num_l1_sstables, TDB_L1_SLOWDOWN_WRITES_TRIGGER);
            }

            /* capacity-based backpressure -- if Level 1 is near capacity, slow down writes
             * to give compaction time to catch up. This prevents runaway sst creation
             * during heavy batched writes.
             * i.e
             *   -- 90-95% full -- 1ms delay (gentle slowdown)
             *   -- 95-98% full -- 5ms delay (moderate slowdown)
             *   -- 98-100% full -- 10ms delay (aggressive slowdown)
             *   -- >100% full -- 50ms delay (emergency brake)
             */
            size_t level1_size =
                atomic_load_explicit(&cf->levels[0]->current_size, memory_order_relaxed);
            size_t level1_capacity =
                atomic_load_explicit(&cf->levels[0]->capacity, memory_order_relaxed);

            if (level1_capacity > 0)
            {
                int utilization_pct = (int)((level1_size * 100) / level1_capacity);

                if (utilization_pct >= TDB_BACKPRESSURE_THRESHOLD_L1_FULL)
                {
                    /* Level 1 is full, apply strong backpressure */
                    usleep(TDB_BACKPRESSURE_DELAY_EMERGENCY_US);
                    TDB_DEBUG_LOG(TDB_LOG_WARN,
                                  "CF '%s' Level 1 capacity full (%d%%), applying emergency "
                                  "backpressure (50ms)",
                                  cf->name, utilization_pct);
                }
                else if (utilization_pct >= TDB_BACKPRESSURE_THRESHOLD_L1_CRITICAL)
                {
                    usleep(TDB_BACKPRESSURE_DELAY_CRITICAL_US);
                }
                else if (utilization_pct >= TDB_BACKPRESSURE_THRESHOLD_L1_HIGH)
                {
                    usleep(TDB_BACKPRESSURE_DELAY_HIGH_US);
                }
                else if (utilization_pct >= TDB_BACKPRESSURE_THRESHOLD_L1_MODERATE)
                {
                    usleep(TDB_BACKPRESSURE_DELAY_MODERATE_US);
                }
            }

            tidesdb_flush_memtable(cf);
        }
    }

    /*
     * MARK COMMITTED
     * readers check commit status to determine visibility.
     * out-of-order commits are handled correctly -- no visibility gap!
     **/

    /* ensure all memtable writes are globally visible before marking committed */
    atomic_thread_fence(memory_order_seq_cst);

    /* mark this sequence as committed in the status tracker
     * this makes the transaction visible to all readers */
    tidesdb_commit_status_mark(txn->db->commit_status, txn->commit_seq,
                               TDB_COMMIT_STATUS_COMMITTED);

    /* remove SERIALIZABLE transactions from active list on successful commit */
    tidesdb_txn_remove_from_active_list(txn);

    txn->is_committed = 1;
    return TDB_SUCCESS;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed) return TDB_ERR_INVALID_ARGS;

    /* remove from active list if SERIALIZABLE */
    tidesdb_txn_remove_from_active_list(txn);

    /* we mark as aborted; operations never applied */
    txn->is_aborted = 1;
    return TDB_SUCCESS;
}

void tidesdb_txn_free(tidesdb_txn_t *txn)
{
    if (!txn) return;

    for (int i = 0; i < txn->num_ops; i++)
    {
        free(txn->ops[i].key);
        free(txn->ops[i].value);
    }
    free(txn->ops);

    for (int i = 0; i < txn->read_set_count; i++)
    {
        free(txn->read_keys[i]);
    }
    free(txn->read_keys);
    free(txn->read_key_sizes);
    free(txn->read_seqs);
    free(txn->read_cfs);

    /* free hash tables if they were created */
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

int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* check if savepoint with this name already exists */
    for (int i = 0; i < txn->num_savepoints; i++)
    {
        if (strcmp(txn->savepoint_names[i], name) == 0)
        {
            /* update existing savepoint */
            tidesdb_txn_t *old_sp = txn->savepoints[i];

            tidesdb_txn_t *savepoint = calloc(1, sizeof(tidesdb_txn_t));
            if (!savepoint) return TDB_ERR_MEMORY;

            savepoint->num_ops = txn->num_ops;
            savepoint->ops = malloc(txn->num_ops * sizeof(tidesdb_txn_op_t));
            if (!savepoint->ops && txn->num_ops > 0)
            {
                free(savepoint);
                return TDB_ERR_MEMORY;
            }
            memcpy(savepoint->ops, txn->ops, txn->num_ops * sizeof(tidesdb_txn_op_t));

            if (old_sp)
            {
                free(old_sp->ops);
                free(old_sp);
            }
            txn->savepoints[i] = savepoint;

            return TDB_SUCCESS;
        }
    }

    /* resize savepoints array if needed */
    if (txn->num_savepoints >= txn->savepoints_capacity)
    {
        int new_capacity = txn->savepoints_capacity == 0 ? 4 : txn->savepoints_capacity * 2;
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

    /* create child transaction */
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

    /* copy current operations as baseline */
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

    /* store savepoint with name */
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
    if (!txn || !name || txn->num_savepoints == 0) return TDB_ERR_INVALID_ARGS;

    /* find savepoint by name */
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

    /* restore to savepoint state */
    txn->num_ops = savepoint->num_ops;

    /* remove savepoint and its name */
    tidesdb_txn_free(savepoint);
    free(txn->savepoint_names[savepoint_idx]);

    /* shift remaining savepoints down if needed */
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
 * @return 1 if visible, 0 if should be skipped
 */
static int tidesdb_iter_kv_visible(tidesdb_iter_t *iter, tidesdb_kv_pair_t *kv)
{
    if (!iter || !kv) return 0;

    if (kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
    {
        return 0;
    }

    /* check TTL expiration using cached snapshot time */
    if (kv->entry.ttl > 0 && kv->entry.ttl < iter->snapshot_time)
    {
        return 0;
    }

    /* snapshot isolation we only accept versions <= snapshot sequence */
    return (kv->entry.seq <= iter->cf_snapshot);
}

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter)
{
    if (!txn || !cf || !iter) return TDB_ERR_INVALID_ARGS;

    /* add CF to transaction if not already added */
    int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    *iter = calloc(1, sizeof(tidesdb_iter_t));
    if (!*iter) return TDB_ERR_MEMORY;

    (*iter)->cf = cf;
    (*iter)->txn = txn;
    (*iter)->valid = 0;
    (*iter)->direction = 0;
    (*iter)->snapshot_time = atomic_load(&txn->db->cached_current_time);

    /* create merge heap for this CF */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    (*iter)->heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
    if (!(*iter)->heap)
    {
        free(*iter);
        return TDB_ERR_MEMORY;
    }

    /* lock free memtable snapshot to prevent race with flush
     *  load immutables before active memtable to avoid missing keys */
    tidesdb_immutable_memtable_t **imm_snapshot = NULL;
    size_t imm_count = 0;

    imm_count = atomic_load_explicit(&cf->immutable_memtables->size, memory_order_acquire);
    if (imm_count > 0)
    {
        imm_snapshot = malloc(imm_count * sizeof(tidesdb_immutable_memtable_t *));
        if (imm_snapshot)
        {
            size_t idx = 0;
            for (size_t i = 0; i < imm_count; i++)
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                if (imm)
                {
                    tidesdb_immutable_memtable_ref(imm);
                    imm_snapshot[idx++] = imm;
                }
            }
            imm_count = idx;
        }
        else
        {
            imm_count = 0;
        }
    }

    /* now load active memtable -- any keys that rotated are already in our snapshot */
    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

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
        tidesdb_merge_source_from_memtable(active_mt, &cf->config, NULL);
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

    /* add immutables from our snapshot to merge heap */
    if (imm_snapshot)
    {
        for (size_t i = 0; i < imm_count; i++)
        {
            tidesdb_immutable_memtable_t *imm = imm_snapshot[i];
            if (imm && imm->memtable)
            {
                /* tidesdb_merge_source_from_memtable will take its own ref */
                tidesdb_merge_source_t *source =
                    tidesdb_merge_source_from_memtable(imm->memtable, &cf->config, imm);
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

    /* collect sstable pointers with references held
     * use dynamic array that grows as needed */
    int ssts_capacity = TDB_STACK_SSTS;
    tidesdb_sstable_t **ssts_array = malloc(ssts_capacity * sizeof(tidesdb_sstable_t *));
    int sst_count = 0;

    if (ssts_array)
    {
        /* iterate through levels and take refs immediately to minimize race window */
        for (int i = 0; i < num_levels; i++)
        {
            tidesdb_level_t *level = cf->levels[i];

            int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
            tidesdb_sstable_t **sstables =
                atomic_load_explicit(&level->sstables, memory_order_acquire);

            /* take refs on all sstables in this level immediately in tight loop
             * this minimizes window where compaction could free the array */
            for (int j = 0; j < num_ssts; j++)
            {
                tidesdb_sstable_t *sst = sstables[j];
                if (!sst) continue;

                /* expand array if needed */
                if (sst_count >= ssts_capacity)
                {
                    int new_capacity = ssts_capacity * 2;
                    tidesdb_sstable_t **new_array =
                        realloc(ssts_array, new_capacity * sizeof(tidesdb_sstable_t *));
                    if (!new_array)
                    {
                        /* cleanup refs taken so far */
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

                /* acquire reference to protect against concurrent deletion */
                tidesdb_sstable_ref(sst);
                ssts_array[sst_count++] = sst;
            }

            if (!ssts_array) break; /* allocation failed */
        }
    }

    if (ssts_array)
    {
        for (int i = 0; i < sst_count; i++)
        {
            tidesdb_sstable_t *sst = ssts_array[i];

            tidesdb_merge_source_t *sst_source = tidesdb_merge_source_from_sstable(cf->db, sst);
            if (sst_source && sst_source->current_kv != NULL)
            {
                if (tidesdb_merge_heap_add_source((*iter)->heap, sst_source) != TDB_SUCCESS)
                {
                    tidesdb_merge_source_free(sst_source);
                }
            }
            else if (sst_source)
            {
                tidesdb_merge_source_free(sst_source);
            }

            tidesdb_sstable_unref(cf->db, sst);
        }

        free(ssts_array);
    }

    return TDB_SUCCESS;
}

int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = 1;

    /* reposition each source to target key */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            skip_list_cursor_t *cursor = source->source.memtable.cursor;
            /* seek positions cursor at node before target, need to advance once */
            if (skip_list_cursor_seek(cursor, (uint8_t *)key, key_size) == 0)
            {
                /* advance to the actual target node */
                if (skip_list_cursor_next(cursor) == 0)
                {
                    /* read current entry directly without advance overhead */
                    uint8_t *k, *v;
                    size_t k_size, v_size;
                    time_t ttl;
                    uint8_t deleted;
                    uint64_t seq;

                    if (skip_list_cursor_get_with_seq(cursor, &k, &k_size, &v, &v_size, &ttl,
                                                      &deleted, &seq) == 0)
                    {
                        source->current_kv =
                            tidesdb_kv_pair_create(k, k_size, v, v_size, ttl, seq, deleted);
                    }
                }
            }
        }
        else /* MERGE_SOURCE_SSTABLE */
        {
            tidesdb_sstable_t *sst = source->source.sstable.sst;
            block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;

            /* use bloom filter to skip sstables that definitely don't contain the key */
            if (sst->bloom_filter)
            {
                if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
                {
                    /* key definitely not in this sst, skip it */
                    continue;
                }
            }

            /* clean up previous state */
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

            skip_list_comparator_fn comparator_fn = NULL;
            void *comparator_ctx = NULL;
            tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

            /* use block index to find starting position (O(log N) binary search) */
            uint64_t block_position = 0;
            if (sst->block_indexes && sst->block_indexes->count > 0)
            {
                /* find predecessor: largest indexed block where first_key <= target */
                compact_block_index_find_predecessor(sst->block_indexes, key, key_size,
                                                     &block_position);
            }

            /* position cursor at block index result or start of file */
            if (block_position > 0)
            {
                block_manager_cursor_goto(cursor, block_position);
            }
            else
            {
                block_manager_cursor_goto_first(cursor);
            }

            /* manually load and scan blocks to find target */
            source->source.sstable.current_entry_idx = 0;

            /* extract CF name once for cache operations */
            char cf_name[TDB_CACHE_KEY_SIZE];
            int has_cf_name = (tidesdb_get_cf_name_from_path(sst->klog_path, cf_name) == 0);

            int blocks_scanned = 0;
            tidesdb_klog_block_t *kb = NULL;
            tidesdb_ref_counted_block_t *rc_block = NULL;
            block_manager_block_t *bmblock = NULL;
            uint8_t *decompressed = NULL;

            while (1)
            {
                /* if we didn't use cached block, try cache then disk */
                if (!kb)
                {
                    /* sanity check: prevent infinite loop in case of corruption */
                    if (blocks_scanned >= TDB_ITER_SEEK_MAX_BLOCKS_SCAN)
                    {
                        break;
                    }

                    /* check if cursor is past data end offset */
                    if (sst->klog_data_end_offset > 0 &&
                        cursor->current_pos >= sst->klog_data_end_offset)
                    {
                        break;
                    }

                    /* try cache first (zero-copy if hit!) */
                    if (sst->db->clock_cache && has_cf_name)
                    {
                        kb = tidesdb_cache_block_get(sst->db, cf_name, sst->klog_path,
                                                     cursor->current_pos, &rc_block);
                    }

                    if (!kb)
                    {
                        /* cache miss */
                        bmblock = block_manager_cursor_read(cursor);
                        if (!bmblock)
                        {
                            break;
                        }
                        blocks_scanned++;

                        uint8_t *data = bmblock->data;
                        size_t data_size = bmblock->size;
                        decompressed = NULL;

                        /* handle compression */
                        if (sst->config->compression_algorithm != NO_COMPRESSION)
                        {
                            decompressed = decompress_data(bmblock->data, bmblock->size, &data_size,
                                                           sst->config->compression_algorithm);
                            if (decompressed)
                            {
                                data = decompressed;
                                source->source.sstable.decompressed_data = decompressed;
                            }
                        }

                        if (tidesdb_klog_block_deserialize(data, data_size, &kb) != 0 || !kb)
                        {
                            if (decompressed)
                            {
                                free(decompressed);
                                source->source.sstable.decompressed_data = NULL;
                            }
                            block_manager_block_release(bmblock);
                            break;
                        }

                        source->source.sstable.current_block = kb;

                        /* cache this block for future seeks (critical for performance!) */
                        if (sst->db->clock_cache && has_cf_name)
                        {
                            tidesdb_cache_block_put(sst->db, cf_name, sst->klog_path,
                                                    cursor->current_pos, data, data_size);
                        }
                    }
                    else
                    {
                        /* cache hit */
                        source->source.sstable.current_block = kb;
                        blocks_scanned++;
                    }
                }

                /* check if target could be in this block -- check both min and max */
                int cmp_first = comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size,
                                              comparator_ctx);
                int cmp_last = comparator_fn(kb->keys[kb->num_entries - 1],
                                             kb->entries[kb->num_entries - 1].key_size, key,
                                             key_size, comparator_ctx);

                /*  if first key > target, we've gone past it
                 * this is a critical early exit that prevents scanning remaining blocks.
                 * since blocks are ordered, if the first key of this block is greater than
                 * our target, the target cannot exist in this or any subsequent block. */
                if (cmp_first > 0)
                {
                    /* release ref-counted block or free deserialized block */
                    if (rc_block)
                    {
                        tidesdb_block_release(rc_block);
                    }
                    else
                    {
                        tidesdb_klog_block_free(kb);
                    }
                    source->source.sstable.current_block = NULL;
                    if (decompressed)
                    {
                        free(decompressed);
                        source->source.sstable.decompressed_data = NULL;
                    }
                    if (bmblock) block_manager_block_release(bmblock);
                    break; /* target not in sst -- early exit */
                }

                /* target is in range [first, last] if first <= target <= last */
                if (cmp_last >= 0)
                {
                    /* target might be in this block, binary search */
                    int left = 0;
                    int right = kb->num_entries - 1;
                    int result_idx = kb->num_entries;

                    while (left <= right)
                    {
                        int mid = left + (right - left) / 2;
                        int cmp = comparator_fn(kb->keys[mid], kb->entries[mid].key_size, key,
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
                        /* found target entry, store block and keep rc_block alive */
                        source->source.sstable.current_block_data = bmblock;
                        source->source.sstable.current_rc_block = rc_block;
                        source->source.sstable.current_block = kb; /* points to rc_block->block */
                        source->source.sstable.current_entry_idx = result_idx;

                        uint8_t *value = kb->inline_values[result_idx];
                        uint8_t *vlog_value = NULL;
                        if (kb->entries[result_idx].vlog_offset > 0)
                        {
                            tidesdb_vlog_read_value_with_cursor(
                                iter->cf->db, sst, source->source.sstable.vlog_cursor,
                                kb->entries[result_idx].vlog_offset,
                                kb->entries[result_idx].value_size, &vlog_value);
                            value = vlog_value;
                        }

                        source->current_kv = tidesdb_kv_pair_create(
                            kb->keys[result_idx], kb->entries[result_idx].key_size, value,
                            kb->entries[result_idx].value_size, kb->entries[result_idx].ttl,
                            kb->entries[result_idx].seq,
                            kb->entries[result_idx].flags & TDB_KV_FLAG_TOMBSTONE);

                        free(vlog_value);
                        /* dont release rc_block here -- it's now owned by the source */
                        rc_block = NULL;
                        break; /* found, exit loop */
                    }
                }

                /* target not in this block, clean up and try next */
                /* release ref-counted block or free deserialized block */
                if (rc_block)
                {
                    tidesdb_block_release(rc_block);
                    rc_block = NULL;
                }
                else
                {
                    tidesdb_klog_block_free(kb);
                }
                source->source.sstable.current_block = NULL;
                kb = NULL; /* reset for next iteration */

                if (decompressed)
                {
                    free(decompressed);
                    source->source.sstable.decompressed_data = NULL;
                    decompressed = NULL;
                }

                if (bmblock)
                {
                    block_manager_block_release(bmblock);
                    bmblock = NULL;
                }

                if (block_manager_cursor_next(cursor) != 0)
                {
                    break;
                }
            }
        }
    }

    /* rebuild heap as min-heap */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        heap_sift_down(iter->heap, i);
    }

    /* peek at first visible entry (dont pop yet, sources are already positioned) */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_merge_source_t *top = iter->heap->sources[0];
        if (!top->current_kv) break;

        if (!tidesdb_iter_kv_visible(iter, top->current_kv))
        {
            /* not visible, advance this source and re-heapify */
            if (tidesdb_merge_source_advance(top) != 0)
            {
                /* source exhausted, remove from heap */
                iter->heap->sources[0] = iter->heap->sources[iter->heap->num_sources - 1];
                iter->heap->num_sources--;
                tidesdb_merge_source_free(top);
            }
            if (iter->heap->num_sources > 0)
            {
                heap_sift_down(iter->heap, 0);
            }
            continue;
        }

        /* found visible entry, clone it without advancing */
        iter->current = tidesdb_kv_pair_clone(top->current_kv);
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = -1;

    /* reposition each source to target key */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            skip_list_cursor_t *cursor = source->source.memtable.cursor;
            /* seek_for_prev positions cursor at first entry <= key */
            if (skip_list_cursor_seek_for_prev(cursor, (uint8_t *)key, key_size) == 0)
            {
                /* read current entry without advancing (cursor is already positioned) */
                uint8_t *k, *v;
                size_t k_size, v_size;
                time_t ttl;
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
        else /* MERGE_SOURCE_SSTABLE */
        {
            tidesdb_sstable_t *sst = source->source.sstable.sst;
            block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;

            if (sst->bloom_filter)
            {
                if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
                {
                    /* key definitely not in this sst, skip it */
                    continue;
                }
            }

            /* clean up previous state */
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

            skip_list_comparator_fn comparator_fn = NULL;
            void *comparator_ctx = NULL;
            tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

            /* use block index to find starting position (O(log N) binary search) */
            uint64_t block_position = 0;
            if (sst->block_indexes && sst->block_indexes->count > 0)
            {
                /* find predecessor: largest indexed block where first_key <= target */
                compact_block_index_find_predecessor(sst->block_indexes, key, key_size,
                                                     &block_position);
            }

            /* position cursor at block index result or start of file */
            if (block_position > 0)
            {
                block_manager_cursor_goto(cursor, block_position);
            }
            else
            {
                block_manager_cursor_goto_first(cursor);
            }

            /* manually scan blocks to find last entry <= target */
            source->source.sstable.current_entry_idx = 0;

            /* extract CF name once for cache operations */
            char cf_name[TDB_CACHE_KEY_SIZE];
            int has_cf_name = (tidesdb_get_cf_name_from_path(sst->klog_path, cf_name) == 0);

            tidesdb_klog_block_t *last_valid_block = NULL;
            int last_valid_idx = -1;
            block_manager_block_t *last_valid_bmblock = NULL;
            uint8_t *last_valid_decompressed = NULL;
            tidesdb_ref_counted_block_t *last_valid_rc_block = NULL;

            tidesdb_klog_block_t *kb = NULL;
            block_manager_block_t *bmblock = NULL;
            uint8_t *decompressed = NULL;
            tidesdb_ref_counted_block_t *rc_block = NULL;

            int blocks_scanned = 0;

            while (1)
            {
                /* if we didn't use cached block, try cache then disk */
                if (!kb)
                {
                    /* sanity check: prevent infinite loop in case of corruption */
                    if (blocks_scanned >= TDB_ITER_SEEK_MAX_BLOCKS_SCAN)
                    {
                        break;
                    }

                    /* check if cursor is past data end offset */
                    if (sst->klog_data_end_offset > 0 &&
                        cursor->current_pos >= sst->klog_data_end_offset)
                    {
                        break;
                    }

                    /* try cache first (zero-copy if hit!) */
                    if (sst->db->clock_cache && has_cf_name)
                    {
                        kb = tidesdb_cache_block_get(sst->db, cf_name, sst->klog_path,
                                                     cursor->current_pos, &rc_block);
                    }

                    if (!kb)
                    {
                        /* cache miss, we gotta read from disk */
                        bmblock = block_manager_cursor_read(cursor);
                        if (!bmblock) break;

                        blocks_scanned++;

                        uint8_t *data = bmblock->data;
                        size_t data_size = bmblock->size;
                        decompressed = NULL;

                        /* handle compression */
                        if (sst->config->compression_algorithm != NO_COMPRESSION)
                        {
                            decompressed = decompress_data(bmblock->data, bmblock->size, &data_size,
                                                           sst->config->compression_algorithm);
                            if (decompressed)
                            {
                                data = decompressed;
                            }
                        }

                        if (tidesdb_klog_block_deserialize(data, data_size, &kb) != 0 || !kb)
                        {
                            if (decompressed) free(decompressed);
                            block_manager_block_release(bmblock);
                            break;
                        }

                        /* cache this block for future seeks (critical for performance!) */
                        if (sst->db->clock_cache && has_cf_name)
                        {
                            tidesdb_cache_block_put(sst->db, cf_name, sst->klog_path,
                                                    cursor->current_pos, data, data_size);
                        }
                    }
                    else
                    {
                        /* cache hit, no disk I/O, decompression, or deserialization needed */
                        blocks_scanned++;
                    }
                }

                /* check if first key in this block is > target */
                int cmp_first = comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size,
                                              comparator_ctx);

                if (cmp_first > 0)
                {
                    /* this blocks first key is beyond target, use previous block */
                    /* release ref-counted block or free deserialized block */
                    if (rc_block)
                    {
                        tidesdb_block_release(rc_block);
                    }
                    else
                    {
                        tidesdb_klog_block_free(kb);
                    }
                    if (decompressed) free(decompressed);
                    if (bmblock) block_manager_block_release(bmblock);
                    break;
                }

                /* this block might contain the target, binary search for last entry <= target */
                int left = 0;
                int right = kb->num_entries - 1;
                int result_idx = -1;

                while (left <= right)
                {
                    int mid = left + (right - left) / 2;
                    int cmp = comparator_fn(kb->keys[mid], kb->entries[mid].key_size, key, key_size,
                                            comparator_ctx);

                    if (cmp <= 0)
                    {
                        result_idx = mid;
                        left = mid + 1; /* search right half for larger matches */
                    }
                    else
                    {
                        right = mid - 1; /* search left half */
                    }
                }

                /* if we found a valid entry in this block, remember it */
                if (result_idx >= 0)
                {
                    /* clean up previous candidate */
                    if (last_valid_rc_block)
                    {
                        tidesdb_block_release(last_valid_rc_block);
                    }
                    else if (last_valid_block)
                    {
                        tidesdb_klog_block_free(last_valid_block);
                    }
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
                    /* no valid entry in this block */
                    /* release ref-counted block or free deserialized block */
                    if (rc_block)
                    {
                        tidesdb_block_release(rc_block);
                    }
                    else
                    {
                        tidesdb_klog_block_free(kb);
                    }
                    if (decompressed) free(decompressed);
                    if (bmblock) block_manager_block_release(bmblock);
                }

                /* reset for next iteration */
                kb = NULL;
                bmblock = NULL;
                decompressed = NULL;
                rc_block = NULL;

                /* try next block */
                if (block_manager_cursor_next(cursor) != 0) break;
            }

            /* use the last valid entry we found */
            if (last_valid_block && last_valid_idx >= 0)
            {
                source->source.sstable.current_block = last_valid_block;
                source->source.sstable.current_block_data = last_valid_bmblock;
                source->source.sstable.current_rc_block = last_valid_rc_block;
                source->source.sstable.decompressed_data = last_valid_decompressed;
                source->source.sstable.current_entry_idx = last_valid_idx;

                uint8_t *value = last_valid_block->inline_values[last_valid_idx];
                uint8_t *vlog_value = NULL;
                if (last_valid_block->entries[last_valid_idx].vlog_offset > 0)
                {
                    tidesdb_vlog_read_value_with_cursor(
                        iter->cf->db, sst, source->source.sstable.vlog_cursor,
                        last_valid_block->entries[last_valid_idx].vlog_offset,
                        last_valid_block->entries[last_valid_idx].value_size, &vlog_value);
                    value = vlog_value;
                }

                source->current_kv = tidesdb_kv_pair_create(
                    last_valid_block->keys[last_valid_idx],
                    last_valid_block->entries[last_valid_idx].key_size, value,
                    last_valid_block->entries[last_valid_idx].value_size,
                    last_valid_block->entries[last_valid_idx].ttl,
                    last_valid_block->entries[last_valid_idx].seq,
                    last_valid_block->entries[last_valid_idx].flags & TDB_KV_FLAG_TOMBSTONE);

                free(vlog_value);
                /* rc_block is now owned by the source, don't release it */
            }
        }
    }

    /* rebuild heap as max-heap for backward iteration */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        int current = i;
        while (current * 2 + 1 < iter->heap->num_sources)
        {
            int largest = current;
            int left = 2 * current + 1;
            int right = 2 * current + 2;

            if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv &&
                (!iter->heap->sources[largest]->current_kv ||
                 iter->heap->comparator(iter->heap->sources[left]->current_kv->key,
                                        iter->heap->sources[left]->current_kv->entry.key_size,
                                        iter->heap->sources[largest]->current_kv->key,
                                        iter->heap->sources[largest]->current_kv->entry.key_size,
                                        iter->heap->comparator_ctx) > 0))
            {
                largest = left;
            }

            if (right < iter->heap->num_sources && iter->heap->sources[right]->current_kv &&
                (!iter->heap->sources[largest]->current_kv ||
                 iter->heap->comparator(iter->heap->sources[right]->current_kv->key,
                                        iter->heap->sources[right]->current_kv->entry.key_size,
                                        iter->heap->sources[largest]->current_kv->key,
                                        iter->heap->sources[largest]->current_kv->entry.key_size,
                                        iter->heap->comparator_ctx) > 0))
            {
                largest = right;
            }

            if (largest == current) break;

            tidesdb_merge_source_t *temp = iter->heap->sources[current];
            iter->heap->sources[current] = iter->heap->sources[largest];
            iter->heap->sources[largest] = temp;
            current = largest;
        }
    }

    /* pop largest visible entry */
    while (iter->heap->num_sources > 0 && iter->heap->sources[0]->current_kv)
    {
        tidesdb_kv_pair_t *kv = iter->heap->sources[0]->current_kv;

        if (tidesdb_iter_kv_visible(iter, kv))
        {
            iter->current = tidesdb_kv_pair_create(
                kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl,
                kv->entry.seq, kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);
            iter->valid = 1;
            return TDB_SUCCESS;
        }

        /* not visible, retreat and re-heapify */
        tidesdb_merge_source_retreat(iter->heap->sources[0]);

        /* sift down from root */
        int current = 0;
        while (current * 2 + 1 < iter->heap->num_sources)
        {
            int largest = current;
            int left = 2 * current + 1;
            int right = 2 * current + 2;

            if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv &&
                (!iter->heap->sources[largest]->current_kv ||
                 iter->heap->comparator(iter->heap->sources[left]->current_kv->key,
                                        iter->heap->sources[left]->current_kv->entry.key_size,
                                        iter->heap->sources[largest]->current_kv->key,
                                        iter->heap->sources[largest]->current_kv->entry.key_size,
                                        iter->heap->comparator_ctx) > 0))
            {
                largest = left;
            }

            if (right < iter->heap->num_sources && iter->heap->sources[right]->current_kv &&
                (!iter->heap->sources[largest]->current_kv ||
                 iter->heap->comparator(iter->heap->sources[right]->current_kv->key,
                                        iter->heap->sources[right]->current_kv->entry.key_size,
                                        iter->heap->sources[largest]->current_kv->key,
                                        iter->heap->sources[largest]->current_kv->entry.key_size,
                                        iter->heap->comparator_ctx) > 0))
            {
                largest = right;
            }

            if (largest == current) break;

            tidesdb_merge_source_t *temp = iter->heap->sources[current];
            iter->heap->sources[current] = iter->heap->sources[largest];
            iter->heap->sources[largest] = temp;
            current = largest;
        }
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;

    /* pop from heap until we find a valid entry */
    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;

    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap, NULL);
        if (!kv) break;

        /* check visibility (isolation, TTL, tombstones) */
        if (!tidesdb_iter_kv_visible(iter, kv))
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

    /* position all sources at their last entries */
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
                time_t ttl;
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
        else
        {
            /* seek to last block in sstable, always go to last physical position */
            /* the comparator has already ordered the data, so last physical = last logical */

            uint64_t num_blocks = source->source.sstable.sst->num_klog_blocks;
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

                /* clean up old data from iterator creation before reading new block */
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
                    /* decompress the block */
                    uint8_t *data = block->data;
                    size_t data_size = block->size;
                    uint8_t *decompressed = NULL;

                    if (source->config->compression_algorithm != NO_COMPRESSION)
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
                            int idx = source->source.sstable.current_block->num_entries - 1;
                            source->source.sstable.current_entry_idx = idx;

                            tidesdb_klog_block_t *kb = source->source.sstable.current_block;
                            uint8_t *value = kb->inline_values[idx];

                            uint8_t *vlog_value = NULL;
                            if (kb->entries[idx].vlog_offset > 0)
                            {
                                tidesdb_vlog_read_value_with_cursor(
                                    source->source.sstable.db, source->source.sstable.sst,
                                    source->source.sstable.vlog_cursor,
                                    kb->entries[idx].vlog_offset, kb->entries[idx].value_size,
                                    &vlog_value);
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

    /* build max-heap (for backward iteration) and find largest key */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        int current = i;
        while (current < iter->heap->num_sources)
        {
            int largest = current;
            int left = 2 * current + 1;
            int right = 2 * current + 2;

            if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv)
            {
                if (!iter->heap->sources[largest]->current_kv)
                {
                    largest = left;
                }
                else
                {
                    int cmp = iter->heap->comparator(
                        iter->heap->sources[left]->current_kv->key,
                        iter->heap->sources[left]->current_kv->entry.key_size,
                        iter->heap->sources[largest]->current_kv->key,
                        iter->heap->sources[largest]->current_kv->entry.key_size,
                        iter->heap->comparator_ctx);
                    if (cmp > 0) largest = left;
                }
            }

            if (right < iter->heap->num_sources && iter->heap->sources[right]->current_kv)
            {
                if (!iter->heap->sources[largest]->current_kv)
                {
                    largest = right;
                }
                else
                {
                    int cmp = iter->heap->comparator(
                        iter->heap->sources[right]->current_kv->key,
                        iter->heap->sources[right]->current_kv->entry.key_size,
                        iter->heap->sources[largest]->current_kv->key,
                        iter->heap->sources[largest]->current_kv->entry.key_size,
                        iter->heap->comparator_ctx);
                    if (cmp > 0) largest = right;
                }
            }

            if (largest != current)
            {
                tidesdb_merge_source_t *temp = iter->heap->sources[current];
                iter->heap->sources[current] = iter->heap->sources[largest];
                iter->heap->sources[largest] = temp;
                current = largest;
            }
            else
            {
                break;
            }
        }
    }

    /* get the largest (last) key */
    if (iter->heap->num_sources > 0 && iter->heap->sources[0]->current_kv)
    {
        tidesdb_kv_pair_t *kv = iter->heap->sources[0]->current_kv;

        /* check visibility (isolation, TTL, tombstones) */
        if (tidesdb_iter_kv_visible(iter, kv))
        {
            iter->current = tidesdb_kv_pair_create(
                kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl,
                kv->entry.seq, kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);
            iter->valid = 1;
            return TDB_SUCCESS;
        }
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_next(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid) return TDB_ERR_INVALID_ARGS;

    /* check if direction changed from backward to forward */
    int direction_changed = (iter->direction == -1);

    /* set direction to forward */
    iter->direction = 1;

    uint8_t stack_key[TDB_ITER_STACK_KEY_SIZE];
    uint8_t *current_key = NULL;
    size_t current_key_size = 0;
    int key_on_heap = 0;

    if (iter->current)
    {
        current_key_size = iter->current->entry.key_size;
        if (current_key_size <= TDB_ITER_STACK_KEY_SIZE)
        {
            current_key = stack_key;
            memcpy(current_key, iter->current->key, current_key_size);
        }
        else
        {
            current_key = malloc(current_key_size);
            if (current_key)
            {
                memcpy(current_key, iter->current->key, current_key_size);
                key_on_heap = 1;
            }
        }
    }

    tidesdb_kv_pair_free(iter->current);
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

        /* rebuild as min-heap for forward iteration */
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down(iter->heap, i);
        }
    }

    if (iter->heap->num_sources == 1)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[0];
        while (source->current_kv)
        {
            tidesdb_kv_pair_t *kv = source->current_kv;

            if (current_key && current_key_size == kv->entry.key_size &&
                memcmp(current_key, kv->key, current_key_size) == 0)
            {
                if (tidesdb_merge_source_advance(source) != TDB_SUCCESS) break;
                continue;
            }

            if (!tidesdb_iter_kv_visible(iter, kv))
            {
                if (tidesdb_merge_source_advance(source) != TDB_SUCCESS) break;
                continue;
            }

            /* snapshot isolation -- track read for conflict detection */
            tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                        kv->entry.seq);

            /* create copy for iterator */
            iter->current = tidesdb_kv_pair_create(
                kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl,
                kv->entry.seq, kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);

            if (key_on_heap) free(current_key);

            /* advance source for next iteration */
            tidesdb_merge_source_advance(source);

            iter->valid = 1;
            return TDB_SUCCESS;
        }
    }
    else
    {
        while (!tidesdb_merge_heap_empty(iter->heap))
        {
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap, NULL);
            if (!kv) break;

            if (current_key && current_key_size == kv->entry.key_size &&
                memcmp(current_key, kv->key, current_key_size) == 0)
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            if (!tidesdb_iter_kv_visible(iter, kv))
            {
                tidesdb_kv_pair_free(kv);
                continue;
            }

            /* snapshot isolation -- track read for conflict detection */
            tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                        kv->entry.seq);

            if (key_on_heap) free(current_key);
            iter->current = kv;
            iter->valid = 1;
            return TDB_SUCCESS;
        }
    }

    if (key_on_heap) free(current_key);
    return TDB_ERR_NOT_FOUND;
}

int tidesdb_iter_prev(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid) return TDB_ERR_INVALID_ARGS;

    /* check if direction changed from forward to backward */
    int direction_changed = (iter->direction == 1);

    /* set direction to backward */
    iter->direction = -1;

    uint8_t stack_key[TDB_ITER_STACK_KEY_SIZE];
    uint8_t *current_key = NULL;
    size_t current_key_size = 0;
    int key_on_heap = 0;

    if (iter->current)
    {
        current_key_size = iter->current->entry.key_size;
        if (current_key_size <= TDB_ITER_STACK_KEY_SIZE)
        {
            current_key = stack_key;
            memcpy(current_key, iter->current->key, current_key_size);
        }
        else
        {
            current_key = malloc(current_key_size);
            if (current_key)
            {
                memcpy(current_key, iter->current->key, current_key_size);
                key_on_heap = 1;
            }
        }
    }

    tidesdb_kv_pair_free(iter->current);
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

        /* rebuild as max-heap for backward iteration */
        for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
        {
            heap_sift_down_max(iter->heap, i);
        }
    }

    if (iter->heap->num_sources == 1)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[0];
        while (source->current_kv)
        {
            tidesdb_kv_pair_t *kv = source->current_kv;

            if (current_key && current_key_size == kv->entry.key_size &&
                memcmp(current_key, kv->key, current_key_size) == 0)
            {
                if (tidesdb_merge_source_retreat(source) != TDB_SUCCESS) break;
                continue;
            }

            if (!tidesdb_iter_kv_visible(iter, kv))
            {
                if (tidesdb_merge_source_retreat(source) != TDB_SUCCESS) break;
                continue;
            }

            /* snapshot isolation -- track read for conflict detection */
            tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                        kv->entry.seq);

            /* create copy for iterator */
            iter->current = tidesdb_kv_pair_create(
                kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl,
                kv->entry.seq, kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);

            if (key_on_heap) free(current_key);

            tidesdb_merge_source_retreat(source);

            iter->valid = 1;
            return TDB_SUCCESS;
        }

        if (key_on_heap) free(current_key);
        return TDB_ERR_NOT_FOUND;
    }

    /* get previous entry, skipping duplicates */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop_max(iter->heap);
        if (!kv) break;

        if (current_key && current_key_size == kv->entry.key_size &&
            memcmp(current_key, kv->key, current_key_size) == 0)
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (!tidesdb_iter_kv_visible(iter, kv))
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        /* snapshot isolation -- track read for conflict detection */
        tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                    kv->entry.seq);

        if (key_on_heap) free(current_key);
        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    if (key_on_heap) free(current_key);
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

    free(iter);
}

/**
 * tidesdb_recover_column_family
 * recover a column family from disk after crash
 * @param cf
 * @return int
 */
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    DIR *dir = opendir(cf->directory);
    if (!dir) return TDB_ERR_IO;

    struct dirent *entry;
    queue_t *wal_files = queue_new();
    if (!wal_files)
    {
        closedir(dir);
        return TDB_ERR_MEMORY;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, TDB_WAL_PREFIX) == entry->d_name)
        {
            size_t path_len = strlen(cf->directory) + strlen(entry->d_name) + 2;
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

    /* restore next_sstable_id from manifest before WAL recovery
     * to prevent id collisions when flushing recovered WALs
     * manifest is already loaded in cf->manifest with block manager open */
    uint64_t manifest_seq = atomic_load(&cf->manifest->sequence);
    if (cf->manifest && manifest_seq > 0)
    {
        atomic_store_explicit(&cf->next_sstable_id, manifest_seq, memory_order_relaxed);
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "CF '%s' pre-loaded next_sstable_id=%" PRIu64
                      " from manifest before WAL recovery",
                      cf->name, manifest_seq);
    }

    /* sort WAL files by ID to ensure correct recovery order
     * WAL filenames are wal_<id>.log, so we can sort by extracting the numeric ID */
    size_t wal_count = queue_size(wal_files);
    if (wal_count > 1)
    {
        /* extract to array for sorting */
        char **wal_array = malloc(wal_count * sizeof(char *));
        if (wal_array)
        {
            for (size_t i = 0; i < wal_count; i++)
            {
                wal_array[i] = queue_dequeue(wal_files);
            }

            /* bubble sort by WAL ID */
            for (size_t i = 0; i < wal_count - 1; i++)
            {
                for (size_t j = 0; j < wal_count - i - 1; j++)
                {
                    /* extract IDs from filenames */
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

                    sscanf(name1, TDB_WAL_PREFIX "%" PRIu64 TDB_WAL_EXT, &id1);
                    sscanf(name2, TDB_WAL_PREFIX "%" PRIu64 TDB_WAL_EXT, &id2);

                    if (id1 > id2)
                    {
                        char *temp = wal_array[j];
                        wal_array[j] = wal_array[j + 1];
                        wal_array[j + 1] = temp;
                    }
                }
            }

            /* re-enqueue in sorted order */
            for (size_t i = 0; i < wal_count; i++)
            {
                queue_enqueue(wal_files, wal_array[i]);
            }
            free(wal_array);
        }
    }

    multi_cf_txn_tracker_t *tracker =
        multi_cf_tracker_create(TDB_MULTI_CF_TRACKER_INITIAL_CAPACITY);
    if (!tracker)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "CF '%s' failed to create multi-CF tracker, proceeding without validation",
                      cf->name);
    }

    /* we scan all WALs to collect multi-CF transaction info */
    if (tracker)
    {
        wal_count = queue_size(wal_files);
        for (size_t i = 0; i < wal_count; i++)
        {
            char *wal_path = queue_peek_at(wal_files, i);
            if (!wal_path) continue;

            skip_list_t *temp_memtable = NULL;

            tidesdb_wal_recover(cf, wal_path, &temp_memtable, tracker);
            if (temp_memtable)
            {
                skip_list_free(temp_memtable);
            }
        }
    }

    /* we recover from each WAL file, applying all transactions
     * we pass NULL for tracker here because during per-CF recovery,
     * the tracker only has information from this CF's WAL files.
     * for multi-CF transactions, we cannot determine completeness from a single CF's perspective.
     * since each CF is recovered independently, we must apply all entries from the WAL. */
    while (!queue_is_empty(wal_files))
    {
        char *wal_path = queue_dequeue(wal_files);
        if (!wal_path) continue;

        skip_list_t *recovered_memtable = NULL;
        int recover_result = tidesdb_wal_recover(cf, wal_path, &recovered_memtable, NULL);

        if (recover_result == TDB_SUCCESS && recovered_memtable)
        {
            int recovered_entries = skip_list_count_entries(recovered_memtable);
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' recovered memtable from WAL: %s (%d entries)",
                          cf->name, wal_path, recovered_entries);
            if (recovered_entries > 0)
            {
                block_manager_t *wal_bm = NULL;

                if (block_manager_open(&wal_bm, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0)
                {
                    TDB_DEBUG_LOG(TDB_LOG_WARN,
                                  "CF '%s' failed to reopen WAL for flush tracking: %s", cf->name,
                                  wal_path);
                    skip_list_free(recovered_memtable);
                    free(wal_path);
                    continue;
                }

                tidesdb_immutable_memtable_t *imm = calloc(1, sizeof(tidesdb_immutable_memtable_t));
                if (imm)
                {
                    imm->memtable = recovered_memtable;
                    imm->wal = wal_bm;
                    atomic_init(&imm->refcount, 1);
                    imm->flushed = 0;

                    if (queue_enqueue(cf->immutable_memtables, imm) == 0)
                    {
                        TDB_DEBUG_LOG(
                            TDB_LOG_INFO,
                            "CF '%s' has queued recovered memtable for async flush (WAL: %s)",
                            cf->name, wal_path);

                        tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
                        if (work)
                        {
                            work->cf = cf;
                            work->imm = imm;
                            work->sst_id = atomic_fetch_add_explicit(&cf->next_sstable_id, 1,
                                                                     memory_order_relaxed);
                            TDB_DEBUG_LOG(TDB_LOG_INFO,
                                          "CF '%s' allocated SSTable ID %" PRIu64
                                          " for recovered WAL flush",
                                          cf->name, work->sst_id);
                            tidesdb_immutable_memtable_ref(imm);

                            if (queue_enqueue(cf->db->flush_queue, work) != 0)
                            {
                                tidesdb_immutable_memtable_unref(imm);
                                free(work);
                            }
                        }
                    }
                    else
                    {
                        TDB_DEBUG_LOG(TDB_LOG_WARN, "CF '%s' failed to enqueue recovered memtable",
                                      cf->name);
                        tidesdb_immutable_memtable_unref(imm);
                    }
                }
                else
                {
                    block_manager_close(wal_bm);
                    skip_list_free(recovered_memtable);
                }
            }
            else
            {
                /* empty recovered memtable ,safe to delete WAL since it contains no data */
                skip_list_free(recovered_memtable);
                TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' empty recovered memtable, deleting WAL: %s",
                              cf->name, wal_path);
                tdb_unlink(wal_path);
            }
        }
        else if (recovered_memtable)
        {
            skip_list_free(recovered_memtable);
        }

        free(wal_path);
    }

    queue_free(wal_files);

    if (tracker)
    {
        multi_cf_tracker_free(tracker);
    }

    TDB_DEBUG_LOG(TDB_LOG_INFO, "Recovering SSTables from directory: %s", cf->directory);
    dir = opendir(cf->directory);
    if (!dir) return TDB_ERR_IO;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, TDB_SSTABLE_KLOG_EXT) != NULL)
        {
            TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' found .klog file: %s", cf->name, entry->d_name);
            int level_num = 1;
            int partition_num = -1;
            unsigned long long sst_id_ull = 0;
            char sst_base[TDB_MAX_PATH_LEN];
            int parsed = 0;

            /** try parsing partitioned format first:
             * L{level}P{partition}_{id}.klog */
            if (sscanf(entry->d_name,
                       TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX
                                        "%d_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT,
                       &level_num, &partition_num, &sst_id_ull) == 3)
            {
                snprintf(sst_base, sizeof(sst_base),
                         "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                         cf->directory, level_num, partition_num);
                parsed = 1;
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "Parsed partitioned SSTable level=%d, partition=%d, id=%" PRIu64,
                              level_num, partition_num, (uint64_t)sst_id_ull);
            }
            /** try non-partitioned format:
             * L{level}_{id}.klog */
            else if (sscanf(entry->d_name, TDB_LEVEL_PREFIX "%d_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT,
                            &level_num, &sst_id_ull) == 2)
            {
                snprintf(sst_base, sizeof(sst_base), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d",
                         cf->directory, level_num);
                parsed = 1;
                TDB_DEBUG_LOG(TDB_LOG_INFO,
                              "CF '%s' parsed non-partitioned SSTable level=%d, id=%" PRIu64,
                              cf->name, level_num, (uint64_t)sst_id_ull);
            }

            if (parsed)
            {
                uint64_t sst_id = (uint64_t)sst_id_ull;

                /* check manifest to see if this sstable is complete
                 * only load sstables that are in the manifest
                 * no lock needed -- recovery is single-threaded */
                int in_manifest = tidesdb_manifest_has_sstable(cf->manifest, level_num, sst_id);

                if (!in_manifest)
                {
                    /* sstable not in manifest = incomplete/corrupted, delete it */
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
                    snprintf(klog_path, sizeof(klog_path), "%s_%" PRIu64 TDB_SSTABLE_KLOG_EXT,
                             sst_base, sst_id);
                    snprintf(vlog_path, sizeof(vlog_path), "%s_%" PRIu64 TDB_SSTABLE_VLOG_EXT,
                             sst_base, sst_id);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
                    tdb_unlink(klog_path);
                    tdb_unlink(vlog_path);
                    continue;
                }

                tidesdb_sstable_t *sst =
                    tidesdb_sstable_create(cf->db, sst_base, sst_id, &cf->config);
                if (sst)
                {
                    TDB_DEBUG_LOG(TDB_LOG_INFO,
                                  "CF '%s' is recovering SSTable %" PRIu64 " at level %d", cf->name,
                                  sst_id, level_num);
                    if (tidesdb_sstable_load(cf->db, sst) == TDB_SUCCESS)
                    {
                        int current_levels =
                            atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

                        while (current_levels < level_num)
                        {
                            if (tidesdb_add_level(cf) != TDB_SUCCESS) break;

                            current_levels =
                                atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
                        }

                        if (level_num <= current_levels)
                        {
                            tidesdb_level_add_sstable(cf->levels[level_num - 1], sst);

                            tidesdb_sstable_unref(cf->db, sst);
                        }
                        else
                        {
                            tidesdb_sstable_unref(cf->db, sst);
                        }
                    }
                    else
                    {
                        /* the sstable failed to load, likely corruption.
                         * we delete both klog and vlog files to prevent repeated recovery attempts
                         */
                        TDB_DEBUG_LOG(TDB_LOG_WARN,
                                      "CF '%s' SSTable %" PRIu64
                                      " failed to load (corrupted), deleting files",
                                      cf->name, sst_id);

                        /* save paths before unreferencing */
                        char klog_path[TDB_MAX_PATH_LEN];
                        char vlog_path[TDB_MAX_PATH_LEN];
                        snprintf(klog_path, sizeof(klog_path), "%s", sst->klog_path);
                        snprintf(vlog_path, sizeof(vlog_path), "%s", sst->vlog_path);

                        tidesdb_sstable_unref(cf->db, sst);

                        /* delete the corrupted files */
                        (void)remove(klog_path);
                        (void)remove(vlog_path);
                    }
                }
            }
        }
    }
    closedir(dir);

    uint64_t global_max_seq = 0;

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' is scanning sources for max_seq", cf->name);

    for (int level_idx = 0; level_idx < num_levels; level_idx++)
    {
        tidesdb_level_t *level = cf->levels[level_idx];
        if (!level) continue;

        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);

        for (int sst_idx = 0; sst_idx < num_ssts; sst_idx++)
        {
            tidesdb_sstable_t *sst = sstables[sst_idx];
            if (sst)
            {
                if (sst->max_seq > global_max_seq)
                {
                    global_max_seq = sst->max_seq;
                }
            }
        }
    }

    if (cf->immutable_memtables)
    {
        size_t imm_count = queue_size(cf->immutable_memtables);

        /* skip lists are ordered by KEY, not by sequence!
         * we must scan all entries to find the maximum sequence number */
        for (size_t i = 0; i < imm_count; i++)
        {
            tidesdb_immutable_memtable_t *imm = queue_peek_at(cf->immutable_memtables, i);
            if (imm && imm->memtable)
            {
                skip_list_cursor_t *cursor;
                if (skip_list_cursor_init(&cursor, imm->memtable) == 0)
                {
                    /* scan all entries to find max sequence */
                    if (skip_list_cursor_goto_first(cursor) == 0)
                    {
                        do
                        {
                            uint8_t *key, *value;
                            size_t key_size, value_size;
                            time_t ttl;
                            uint8_t deleted;
                            uint64_t seq;

                            if (skip_list_cursor_get_with_seq(cursor, &key, &key_size, &value,
                                                              &value_size, &ttl, &deleted,
                                                              &seq) == 0)
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
        }
    }

    /* update global sequence based on recovered data */
    uint64_t current_seq = atomic_load_explicit(&cf->db->global_seq, memory_order_acquire);
    if (global_max_seq > atomic_load(&cf->db->global_seq))
    {
        uint64_t old_seq = atomic_load(&cf->db->global_seq);
        atomic_store(&cf->db->global_seq, global_max_seq + 1);
        TDB_DEBUG_LOG(TDB_LOG_INFO, "CF '%s' has updated global_seq from %" PRIu64 " to %" PRIu64,
                      cf->name, old_seq, global_max_seq + 1);
    }

    if (global_max_seq > 0)
    {
        tidesdb_commit_status_t *cs = cf->db->commit_status;
        /* no lock needed -- recovery is single-threaded and operations are already atomic */

        /* update max_seq */
        uint64_t current_max = atomic_load_explicit(&cs->max_seq, memory_order_acquire);
        if (global_max_seq > current_max)
        {
            atomic_store_explicit(&cs->max_seq, global_max_seq, memory_order_release);
        }

        /* mark all sequences as committed */
        for (uint64_t seq = 1; seq <= global_max_seq; seq++)
        {
            size_t idx = seq % cs->capacity;
            atomic_store_explicit(&cs->status[idx], TDB_COMMIT_STATUS_COMMITTED,
                                  memory_order_release);
        }
    }

    /* restore next_sstable_id from manifest to prevent ID collisions
     /* restore next_sstable_id from manifest */
    if (cf->manifest)
    {
        uint64_t manifest_seq = atomic_load(&cf->manifest->sequence);
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
 * @param db
 * @return int
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
                /* try to load persisted config from disk */
                tidesdb_column_family_config_t config = tidesdb_default_column_family_config();

                /* ensure we have room for full_path + "/" + "config.ini" + null terminator */
                size_t full_path_len = strlen(full_path);
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
    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    (*stats)->memtable_size = skip_list_get_size(active_mt);

    (*stats)->level_sizes = malloc((*stats)->num_levels * sizeof(size_t));
    (*stats)->level_num_sstables = malloc((*stats)->num_levels * sizeof(int));

    if (!(*stats)->level_sizes || !(*stats)->level_num_sstables)
    {
        free((*stats)->level_sizes);
        free((*stats)->level_num_sstables);
        free(*stats);
        return TDB_ERR_MEMORY;
    }
    for (int i = 0; i < (*stats)->num_levels; i++)
    {
        (*stats)->level_sizes[i] = atomic_load(&cf->levels[i]->current_size);
        (*stats)->level_num_sstables[i] =
            atomic_load_explicit(&cf->levels[i]->num_sstables, memory_order_acquire);
    }

    return TDB_SUCCESS;
}

void tidesdb_free_stats(tidesdb_stats_t *stats)
{
    if (!stats) return;
    free(stats->level_sizes);
    free(stats->level_num_sstables);
    free(stats);
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

    /* only process our target section */
    if (strcmp(section, ctx->target_section) != 0)
    {
        return 1; /* continue parsing */
    }

    /* parse numeric fields */
    if (strcmp(name, "write_buffer_size") == 0)
    {
        ctx->config->write_buffer_size = (size_t)atoll(value);
    }
    else if (strcmp(name, "level_size_ratio") == 0)
    {
        ctx->config->level_size_ratio = (size_t)atoll(value);
    }
    else if (strcmp(name, "min_levels") == 0)
    {
        ctx->config->min_levels = atoi(value);
    }
    else if (strcmp(name, "dividing_level_offset") == 0)
    {
        ctx->config->dividing_level_offset = atoi(value);
    }
    else if (strcmp(name, "value_threshold") == 0)
    {
        ctx->config->klog_value_threshold = (size_t)atoll(value);
    }
    else if (strcmp(name, "compression_algorithm") == 0)
    {
        if (strcmp(value, "LZ4") == 0)
            ctx->config->compression_algorithm = LZ4_COMPRESSION;
        else if (strcmp(value, "ZSTD") == 0)
            ctx->config->compression_algorithm = ZSTD_COMPRESSION;
#ifndef __sun
        else if (strcmp(value, "SNAPPY") == 0)
            ctx->config->compression_algorithm = SNAPPY_COMPRESSION;
#endif
    }
    else if (strcmp(name, "enable_bloom_filter") == 0)
    {
        ctx->config->enable_bloom_filter = atoi(value);
    }
    else if (strcmp(name, "bloom_fpr") == 0)
    {
        ctx->config->bloom_fpr = atof(value);
    }
    else if (strcmp(name, "enable_block_indexes") == 0)
    {
        ctx->config->enable_block_indexes = atoi(value);
    }
    else if (strcmp(name, "index_sample_ratio") == 0)
    {
        ctx->config->index_sample_ratio = atoi(value);
    }
    else if (strcmp(name, "block_index_prefix_len") == 0)
    {
        ctx->config->block_index_prefix_len = atoi(value);
    }
    else if (strcmp(name, "sync_mode") == 0)
    {
        ctx->config->sync_mode = atoi(value);
    }
    else if (strcmp(name, "sync_interval_us") == 0)
    {
        ctx->config->sync_interval_us = (uint64_t)atoll(value);
    }
    else if (strcmp(name, "skip_list_max_level") == 0)
    {
        ctx->config->skip_list_max_level = atoi(value);
    }
    else if (strcmp(name, "skip_list_probability") == 0)
    {
        ctx->config->skip_list_probability = (float)atof(value);
    }
    else if (strcmp(name, "default_isolation_level") == 0)
    {
        int level = atoi(value);
        if (level >= TDB_ISOLATION_READ_UNCOMMITTED && level <= TDB_ISOLATION_SERIALIZABLE)
        {
            ctx->config->default_isolation_level = (tidesdb_isolation_level_t)level;
        }
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

    /* parse INI file */
    ini_config_context_t ctx = {.config = config, .target_section = section_name};

    int result = ini_parse(ini_file, ini_config_handler, &ctx);
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
        case NO_COMPRESSION:
            compression_str = "NONE";
            break;
        case LZ4_COMPRESSION:
            compression_str = "LZ4";
            break;
        case ZSTD_COMPRESSION:
            compression_str = "ZSTD";
            break;
#ifndef __sun
        case SNAPPY_COMPRESSION:
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

    fprintf(fp, "comparator_name = %s\n", config->comparator_name);
    if (config->comparator_ctx_str[0] != '\0')
    {
        fprintf(fp, "comparator_ctx_str = %s\n", config->comparator_ctx_str);
    }

    /* fsync config file to ensure its persisted */
    fflush(fp);
    int fd = tdb_fileno(fp);
    if (fd >= 0)
    {
        fsync(fd);
    }
    fclose(fp);

    /* sync parent directory to ensure file entry is persisted
     * uses cross-platform tdb_sync_directory (no-op on Windows, fsync on POSIX) */
    char *last_sep = strrchr(ini_file, PATH_SEPARATOR[0]);
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
                                     int persist_to_disk)
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

    if (persist_to_disk)
    {
        char config_path[MAX_FILE_PATH_LENGTH];
        snprintf(config_path, sizeof(config_path),
                 "%s" PATH_SEPARATOR
                 "%s" PATH_SEPARATOR TDB_COLUMN_FAMILY_CONFIG_NAME TDB_COLUMN_FAMILY_CONFIG_EXT,
                 cf->db->config.db_path, cf->name);

        int result = tidesdb_cf_config_save_to_ini(config_path, cf->name, &cf->config);
        if (result != TDB_SUCCESS)
        {
            return result;
        }
    }

    return TDB_SUCCESS;
}

static tidesdb_block_index_t *compact_block_index_create(uint32_t initial_capacity,
                                                         uint8_t prefix_len,
                                                         tidesdb_comparator_fn comparator,
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

/**
 * encode_varint
 * encode varint for block index (value, buffer) signature
 * @param value the value to encode
 * @param buffer the buffer to write to
 * @return number of bytes written
 */
static inline size_t encode_varint(uint64_t value, uint8_t *buffer)
{
    size_t bytes = 0;
    while (value >= 0x80)
    {
        buffer[bytes++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    buffer[bytes++] = (uint8_t)value;
    return bytes;
}

/**
 * decode_varint
 * decode varint for block index (buffer, bytes_read) signature
 * @param buffer the buffer to read from
 * @param bytes_read output parameter for bytes consumed
 * @return the decoded value
 */
static inline uint64_t decode_varint(const uint8_t *buffer, size_t *bytes_read)
{
    uint64_t result = 0;
    int shift = 0;
    size_t i = 0;

    while (buffer[i] & 0x80)
    {
        result |= ((uint64_t)(buffer[i] & 0x7F)) << shift;
        shift += 7;
        i++;
    }
    result |= ((uint64_t)buffer[i]) << shift;
    *bytes_read = i + 1;
    return result;
}

static uint8_t *compact_block_index_serialize(const tidesdb_block_index_t *index, size_t *out_size)
{
    if (!index || !out_size) return NULL;

    /* header: count (4) + prefix_len (1) + file_positions (varint) + min/max prefixes */
    size_t max_size = sizeof(uint32_t) + sizeof(uint8_t) +
                      index->count * 10 +                   /* file_positions (varint) */
                      index->count * index->prefix_len * 2; /* min + max prefixes */

    uint8_t *data = malloc(max_size);
    if (!data) return NULL;

    uint8_t *ptr = data;

    /* header: count + prefix_len */
    encode_uint32_le_compat(ptr, index->count);
    ptr += sizeof(uint32_t);
    *ptr++ = index->prefix_len;

    /* delta encode + varint compress file_positions */
    if (index->count > 0)
    {
        /* first file position stored as-is */
        ptr += encode_varint(index->file_positions[0], ptr);

        /* remaining file positions stored as deltas */
        for (uint32_t i = 1; i < index->count; i++)
        {
            uint64_t delta = index->file_positions[i] - index->file_positions[i - 1];
            ptr += encode_varint(delta, ptr);
        }
    }

    /* copy min_key_prefixes */
    size_t prefix_bytes = index->count * index->prefix_len;
    memcpy(ptr, index->min_key_prefixes, prefix_bytes);
    ptr += prefix_bytes;

    /* copy max_key_prefixes */
    memcpy(ptr, index->max_key_prefixes, prefix_bytes);
    ptr += prefix_bytes;

    /* calc actual size and shrink buffer */
    size_t actual_size = ptr - data;
    uint8_t *final_data = realloc(data, actual_size);
    if (!final_data)
    {
        /* realloc failed, but original data is still valid */
        *out_size = actual_size;
        return data;
    }

    *out_size = actual_size;
    return final_data;
}

static tidesdb_block_index_t *compact_block_index_deserialize(const uint8_t *data, size_t data_size)
{
    if (!data || data_size < sizeof(uint32_t) + sizeof(uint8_t)) return NULL;

    const uint8_t *ptr = data;
    const uint8_t *end = data + data_size;

    /* read header: count + prefix_len */
    uint32_t count = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    uint8_t prefix_len = *ptr++;

    if (prefix_len < TDB_BLOCK_INDEX_PREFIX_MIN)
    {
        TDB_DEBUG_LOG(
            TDB_LOG_WARN,
            "Block index deserialization failed with invalid prefix_len=%u (must be %d-%d)",
            prefix_len, TDB_BLOCK_INDEX_PREFIX_MIN, TDB_BLOCK_INDEX_PREFIX_MAX);
        return NULL; /* invalid format */
    }

    /* validate count is reasonable (prevent integer overflow attacks) */
    if (count > TDB_BLOCK_INDEX_MAX_COUNT)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "Block index deserialization failed with unreasonable count=%u",
                      count);
        return NULL;
    }

    tidesdb_block_index_t *index = calloc(1, sizeof(tidesdb_block_index_t));
    if (!index) return NULL;

    /* handle empty index (count = 0) */
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

    /* decode file_positions (delta-encoded varints) */
    if (count > 0)
    {
        size_t bytes_read;
        /* first file position */
        index->file_positions[0] = decode_varint(ptr, &bytes_read);
        ptr += bytes_read;

        /* remaining file positions (deltas) */
        for (uint32_t i = 1; i < count; i++)
        {
            uint64_t delta = decode_varint(ptr, &bytes_read);
            ptr += bytes_read;
            index->file_positions[i] = index->file_positions[i - 1] + delta;
        }
    }

    /* copy min_key_prefixes */
    size_t prefix_bytes = count * prefix_len;
    if (ptr + prefix_bytes > end) goto error;
    memcpy(index->min_key_prefixes, ptr, prefix_bytes);
    ptr += prefix_bytes;

    /* copy max_key_prefixes */
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
                                   size_t min_key_len, const uint8_t *max_key, size_t max_key_len,
                                   uint64_t file_position)
{
    if (!index || !min_key || !max_key) return -1;

    if (index->count >= index->capacity)
    {
        uint32_t new_capacity = index->capacity * 2;
        uint8_t *new_min = realloc(index->min_key_prefixes, new_capacity * index->prefix_len);
        uint8_t *new_max = realloc(index->max_key_prefixes, new_capacity * index->prefix_len);
        uint64_t *new_positions = realloc(index->file_positions, new_capacity * sizeof(uint64_t));

        if (!new_min || !new_max || !new_positions)
        {
            free(new_min);
            free(new_max);
            free(new_positions);
            return -1;
        }

        index->min_key_prefixes = new_min;
        index->max_key_prefixes = new_max;
        index->file_positions = new_positions;
        index->capacity = new_capacity;
    }

    /* copy prefixes (pad with zeros if key is shorter than prefix_len) */
    size_t min_copy_len = (min_key_len < index->prefix_len) ? min_key_len : index->prefix_len;
    size_t max_copy_len = (max_key_len < index->prefix_len) ? max_key_len : index->prefix_len;

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
 * @param block_num output parameter for the found block number
 * @return 0 on success, -1 if no suitable block found
 */
static int compact_block_index_find_predecessor(const tidesdb_block_index_t *index,
                                                const uint8_t *key, size_t key_len,
                                                uint64_t *file_position)
{
    if (!index || !key || index->count == 0) return -1;

    /* create prefix of search key for comparison */
    uint8_t search_prefix[TDB_BLOCK_INDEX_PREFIX_MAX];
    size_t copy_len = (key_len < index->prefix_len) ? key_len : index->prefix_len;
    memcpy(search_prefix, key, copy_len);
    if (copy_len < index->prefix_len)
    {
        memset(search_prefix + copy_len, 0, index->prefix_len - copy_len);
    }

    /* check if key is before first block */
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

    /* binary search to find the rightmost block where min_key <= search_key <= max_key
     * or the last block where min_key <= search_key if no exact range match */
    int64_t left = 0, right = index->count - 1, result = -1;

    while (left <= right)
    {
        int64_t mid = left + (right - left) / 2;
        const uint8_t *mid_min_prefix = index->min_key_prefixes + (mid * index->prefix_len);
        const uint8_t *mid_max_prefix = index->max_key_prefixes + (mid * index->prefix_len);

        /* compare search key with blocks min and max keys */
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

        /* check if key is within this blocks range: min_key <= search_key <= max_key */
        if (cmp_min <= 0 && cmp_max <= 0)
        {
            /* key is within this blocks range, this is a valid candidate */
            result = mid;
            /* continue searching right to find the rightmost matching block */
            left = mid + 1;
        }
        else if (cmp_min > 0)
        {
            /* search_key < min_key, search left */
            right = mid - 1;
        }
        else
        {
            /* search_key > max_key, search right */
            left = mid + 1;
        }
    }

    if (result >= 0)
    {
        /* found a valid predecessor block
         * now check if search_key is beyond this blocks max_key
         * if so, key definitely doesn't exist in this sst */
        const uint8_t *result_max_prefix = index->max_key_prefixes + (result * index->prefix_len);
        int cmp_result_max;
        if (index->comparator)
        {
            cmp_result_max = index->comparator(search_prefix, index->prefix_len, result_max_prefix,
                                               index->prefix_len, index->comparator_ctx);
        }
        else
        {
            cmp_result_max = memcmp(search_prefix, result_max_prefix, index->prefix_len);
        }

        /* if search_key > max_key of this block, key is beyond indexed range */
        if (cmp_result_max > 0)
        {
            /* check if this is the last block, if so, key doesnt exist */
            if (result == (int64_t)(index->count - 1))
            {
                return -1; /* key is beyond last block, doesn't exist */
            }
            /* otherwise, key might be in next block (gap between blocks)
             * return this blocks position and let sequential scan handle it */
        }

        *file_position = index->file_positions[result];
        return 0;
    }

    /* if no exact match found, return the last block where min_key <= search_key
     * this handles cases where the key falls between indexed blocks */
    for (int64_t i = index->count - 1; i >= 0; i--)
    {
        const uint8_t *min_prefix = index->min_key_prefixes + (i * index->prefix_len);
        int cmp;
        if (index->comparator)
        {
            cmp = index->comparator(min_prefix, index->prefix_len, search_prefix, index->prefix_len,
                                    index->comparator_ctx);
        }
        else
        {
            cmp = memcmp(min_prefix, search_prefix, index->prefix_len);
        }

        if (cmp <= 0)
        {
            *file_position = index->file_positions[i];
            return 0;
        }
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
 * get read statistics for the database
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
 * print read statistics for the database
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

    printf("\n*=== TidesDB Read Profiling Stats ===*\n");
    printf("Total Reads:           " PRIu64 "\n", stats.total_reads);
    printf("\nRead Hit Location:\n");
    printf("  Memtable hits:       " PRIu64 " (%.1f%%)\n", stats.memtable_hits,
           stats.total_reads > 0 ? 100.0 * stats.memtable_hits / stats.total_reads : 0.0);
    printf("  Immutable hits:      " PRIu64 " (%.1f%%)\n", stats.immutable_hits,
           stats.total_reads > 0 ? 100.0 * stats.immutable_hits / stats.total_reads : 0.0);
    printf("  SSTable hits:        " PRIu64 " (%.1f%%)\n", stats.sstable_hits,
           stats.total_reads > 0 ? 100.0 * stats.sstable_hits / stats.total_reads : 0.0);
    printf("\nSSTable Search:\n");
    printf("  Levels searched:     " PRIu64 " (avg: %.2f per read)\n", stats.levels_searched,
           avg_levels_per_read);
    printf("  SSTables checked:    " PRIu64 " (avg: %.2f per read)\n", stats.sstables_checked,
           avg_sstables_per_read);
    printf("  Bloom checks:        " PRIu64 "\n", stats.bloom_checks);
    printf("  Bloom hits:          " PRIu64 " (%.1f%%)\n", stats.bloom_hits, bloom_hit_rate);
    printf("\nBlock-Level Cache:\n");
    printf("  Cache hits:          " PRIu64 "\n", stats.cache_block_hits);
    printf("  Cache misses:        " PRIu64 "\n", stats.cache_block_misses);
    printf("  Cache hit rate:      %.1f%%\n", cache_hit_rate);
    printf("  Blocks read:         " PRIu64 " (avg: %.2f per read)\n", stats.blocks_read,
           avg_blocks_per_read);
    printf("  Disk reads:          " PRIu64 "\n", stats.disk_reads);

    if (db->clock_cache)
    {
        clock_cache_stats_t cache_stats;
        clock_cache_get_stats(db->clock_cache, &cache_stats);
        printf("\nClock Cache Stats:\n");
        printf("  Total entries:       %zu\n", cache_stats.total_entries);
        printf("  Total bytes:         %.2f MB\n", cache_stats.total_bytes / (1024.0 * 1024.0));
        printf("  Global hits:         " PRIu64 "\n", cache_stats.hits);
        printf("  Global misses:       " PRIu64 "\n", cache_stats.misses);
        printf("  Global hit rate:     %.1f%%\n", cache_stats.hit_rate * 100.0);
    }
    printf("*====================================*\n\n");
}

/**
 * tidesdb_reset_read_stats
 * reset read statistics for the database
 * @param db database to reset
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