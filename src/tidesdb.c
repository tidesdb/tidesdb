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

/* global debug flag definition */
int _tidesdb_debug_enabled = 0;

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

/** forward declarations */
static tidesdb_klog_block_t *tidesdb_klog_block_create(void);
static void tidesdb_klog_block_free(tidesdb_klog_block_t *block);
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        tidesdb_t *db, tidesdb_column_family_config_t *config);
static int tidesdb_klog_block_is_full(tidesdb_klog_block_t *block, size_t max_size);
static int tidesdb_klog_block_serialize(tidesdb_klog_block_t *block, uint8_t **out,
                                        size_t *out_size);
static int tidesdb_klog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_klog_block_t **block);

static tidesdb_vlog_block_t *tidesdb_vlog_block_create(void);
static void tidesdb_vlog_block_free(tidesdb_vlog_block_t *block);
static int tidesdb_vlog_block_add_value(tidesdb_vlog_block_t *block, const uint8_t *value,
                                        size_t value_size, uint64_t *offset_in_block);
static int tidesdb_vlog_block_is_full(tidesdb_vlog_block_t *block, size_t max_size);
static int tidesdb_vlog_block_serialize(tidesdb_vlog_block_t *block, uint8_t **out,
                                        size_t *out_size);
static int tidesdb_vlog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_vlog_block_t **block);
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
                                                int64_t *block_num);
static int compact_block_index_add(tidesdb_block_index_t *index, const uint8_t *min_key,
                                   size_t min_key_len, const uint8_t *max_key, size_t max_key_len,
                                   int64_t block_num);
static tidesdb_block_index_t *compact_block_index_create(uint32_t initial_capacity,
                                                         tidesdb_comparator_fn comparator,
                                                         void *comparator_ctx);
static uint8_t *compact_block_index_serialize(const tidesdb_block_index_t *index, size_t *out_size);
static tidesdb_block_index_t *compact_block_index_deserialize(const uint8_t *data,
                                                              size_t data_size);

/**
 *** block cache helper functions
 * global block cache format: "cf_name:sstable_id:block_type:offset"
 * where block_type is 'k' for klog or 'v' for vlog
 */

/**
 * tidesdb_block_cache_key
 * generates a cache key for a block
 * @param cf_name column family name
 * @param sstable_id sstable id
 * @param block_type 'k' for klog, 'v' for vlog
 * @param offset block offset
 * @param key_buffer buffer to store the key (must be at least TDB_CACHE_KEY_SIZE bytes)
 */
static void tidesdb_block_cache_key(const char *cf_name, uint64_t sstable_id, char block_type,
                                    uint64_t offset, char *key_buffer)
{
    snprintf(key_buffer, TDB_CACHE_KEY_SIZE, "%s:%" PRIu64 ":%c:%" PRIu64, cf_name, sstable_id,
             block_type, offset);
}

/**
 * tidesdb_block_evict_callback
 * called when a block is evicted from the global cache
 * releases the block's reference
 * @param key the cache key
 * @param value the cached block
 * @param user_data unused
 */
static void tidesdb_block_evict_callback(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    block_manager_block_t *block = (block_manager_block_t *)value;
    if (block)
    {
        block_manager_block_release(block);
    }
}

/**
 * tidesdb_block_acquire_copy_fn
 * copy function for lru_cache_get_copy that acquires a block reference
 * this is called while the LRU entry reference is held, preventing eviction
 * @param value the cached block
 * @return the block if reference acquired, NULL otherwise
 */
static void *tidesdb_block_acquire_copy_fn(void *value)
{
    block_manager_block_t *block = (block_manager_block_t *)value;
    if (!block) return NULL;

    /* try to acquire reference while LRU entry is protected */
    if (block_manager_block_acquire(block))
    {
        return block;
    }
    return NULL;
}

/**
 * tidesdb_get_cf_name_from_path
 * extracts column family name from sstable path
 * @param path the sstable path (e.g., "/path/to/cf_name/123.klog")
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
 * tidesdb_cached_block_read
 * reads a block from cache or disk
 * @param db the database
 * @param cf_name column family name
 * @param sstable_id sstable id
 * @param block_type 'k' for klog, 'v' for vlog
 * @param cursor the block manager cursor
 * @return the block if successful, NULL otherwise (caller must release)
 */
static block_manager_block_t *tidesdb_cached_block_read(tidesdb_t *db, const char *cf_name,
                                                        uint64_t sstable_id, char block_type,
                                                        block_manager_cursor_t *cursor)
{
    if (!db || !cf_name || !cursor) return NULL;

    uint64_t offset = cursor->current_pos;

    /* check global cache first */
    if (db->block_cache)
    {
        char cache_key[TDB_CACHE_KEY_SIZE];
        tidesdb_block_cache_key(cf_name, sstable_id, block_type, offset, cache_key);

        /* use get_copy with acquire function to atomically get and acquire reference */
        block_manager_block_t *cached_block = (block_manager_block_t *)lru_cache_get_copy(
            db->block_cache, cache_key, tidesdb_block_acquire_copy_fn);

        if (cached_block)
        {
            /* cache hit -- reference already acquired */
            return cached_block;
        }
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    if (!block) return NULL;

    /* try to cache the block for future reads */
    if (db->block_cache)
    {
        char cache_key[TDB_CACHE_KEY_SIZE];
        tidesdb_block_cache_key(cf_name, sstable_id, block_type, offset, cache_key);

        /* acquire reference for cache before inserting */
        if (block_manager_block_acquire(block))
        {
            int put_result = lru_cache_put(db->block_cache, cache_key, block,
                                           tidesdb_block_evict_callback, NULL);
            if (put_result < 0)
            {
                /* insertion failed, release the extra reference */
                block_manager_block_release(block);
            }
            /* if put_result >= 0, cache now owns a reference */
        }
    }

    /* return block to caller (caller has initial reference) */
    return block;
}

static void tidesdb_sstable_ref(tidesdb_sstable_t *sst);
static void tidesdb_sstable_unref(tidesdb_t *db, tidesdb_sstable_t *sst);
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable);
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
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap);
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

/**
 * tidesdb_wait_for_dca
 * spin-wait until DCA operation completes
 * @param cf the column family
 */
static inline void tidesdb_wait_for_dca(tidesdb_column_family_t *cf)
{
    /* No-op: DCA operations are now safe to run concurrently with reads.
     * Readers take atomic snapshots of num_active_levels and use refcounting
     * to protect SSTables from deletion during access. */
    (void)cf;
}

static int tidesdb_add_level(tidesdb_column_family_t *cf);
static int tidesdb_remove_level(tidesdb_column_family_t *cf);
static int tidesdb_apply_dca(tidesdb_column_family_t *cf);
static int tidesdb_recover_database(tidesdb_t *db);
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf);
static void tidesdb_column_family_free(tidesdb_column_family_t *cf);
static void *tidesdb_flush_worker_thread(void *arg);
static void *tidesdb_compaction_worker_thread(void *arg);
static void *tidesdb_sync_worker_thread(void *arg);
static tidesdb_kv_pair_t *tidesdb_kv_pair_create(const uint8_t *key, size_t key_size,
                                                 const uint8_t *value, size_t value_size,
                                                 time_t ttl, uint64_t seq, int is_tombstone);
static void tidesdb_kv_pair_free(tidesdb_kv_pair_t *kv);
static tidesdb_kv_pair_t *tidesdb_kv_pair_clone(const tidesdb_kv_pair_t *kv);
static int tidesdb_iter_kv_visible(tidesdb_iter_t *iter, tidesdb_kv_pair_t *kv);
static void tidesdb_sstable_cache_evict_cb(const char *key, void *value, void *user_data);
static int tidesdb_sstable_ensure_open(tidesdb_t *db, tidesdb_sstable_t *sst);

/**
 * tidesdb_check_disk_space
 * check if there's enough free disk space using cached value
 * refreshes cache every DISK_SPACE_CHECK_INTERVAL_SECONDS seconds to avoid expensive statvfs calls
 * @param db database handle
 * @param path directory path to check
 * @param min_required minimum required free space in bytes
 * @return 1 if enough space, 0 if not enough, -1 on error
 */
static int tidesdb_check_disk_space(tidesdb_t *db, const char *path, uint64_t min_required)
{
    if (!db) return -1;

    time_t now = time(NULL);
    time_t last_check = atomic_load_explicit(&db->last_disk_space_check, memory_order_relaxed);

    if (now - last_check >= DISK_SPACE_CHECK_INTERVAL_SECONDS)
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
 * Validates that a key-value pair size does not exceed memory limits
 * Maximum allowed size is max(available_memory * TDB_MEMORY_PERCENTAGE, TDB_MIN_KEY_VALUE_SIZE)
 * @param db database handle
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @return 0 if valid, TDB_ERR_MEMORY_LIMIT if too large
 */
static int tidesdb_validate_kv_size(tidesdb_t *db, size_t key_size, size_t value_size)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    size_t total_size = key_size + value_size;

    uint64_t memory_based_limit = (uint64_t)(db->available_memory * TDB_MEMORY_PERCENTAGE);
    uint64_t max_allowed_size =
        memory_based_limit > TDB_MIN_KEY_VALUE_SIZE ? memory_based_limit : TDB_MIN_KEY_VALUE_SIZE;

    if (total_size > max_allowed_size)
    {
        TDB_DEBUG_LOG("Key-value pair size (%zu bytes) exceeds memory limit (%" PRIu64
                      " bytes, based on available memory: %" PRIu64 " bytes)",
                      total_size, max_allowed_size, (uint64_t)db->available_memory);
        return TDB_ERR_MEMORY_LIMIT;
    }

    return 0;
}

/**
 * sstable metadata header
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
 * serialize sstable metadata
 * @param sst sstable to serialize
 * @param out_data output data
 * @param out_size output size
 * @return 0 on success, -1 on failure
 */
static int sstable_metadata_serialize(tidesdb_sstable_t *sst, uint8_t **out_data, size_t *out_size)
{
    if (!sst || !out_data || !out_size) return -1;

    /* calculate size: all fields + keys + checksum */
    size_t header_size = 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4; /* fixed 84 bytes */
    size_t checksum_size = 8;
    size_t total_size = header_size + sst->min_key_size + sst->max_key_size + checksum_size;

    uint8_t *data = malloc(total_size);
    if (!data) return -1;

    uint8_t *ptr = data;

    /* serialize fields with explicit little-endian encoding */
    encode_uint32_le_compat(ptr, SSTABLE_METADATA_MAGIC);
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

    if (magic != SSTABLE_METADATA_MAGIC)
    {
        TDB_DEBUG_LOG("SSTable metadata: Invalid magic 0x%08x (expected 0x%08x)", magic,
                      SSTABLE_METADATA_MAGIC);
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
        TDB_DEBUG_LOG("SSTable metadata: Size mismatch (expected: %zu, got: %zu)", expected_size,
                      data_size);
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
        TDB_DEBUG_LOG("SSTable metadata: Checksum mismatch (expected: %" PRIu64 ", got: %" PRIu64
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

    if (tidesdb_get_comparator(db, config->comparator_name, fn, ctx) != TDB_SUCCESS)
    {
        /* comparator not found, use default */
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
    if (cmp != 0) return cmp;
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
        .klog_block_size = TDB_DEFAULT_KLOG_BLOCK_SIZE,
        .vlog_block_size = TDB_DEFAULT_VLOG_BLOCK_SIZE,
        .value_threshold = TDB_DEFAULT_VALUE_THRESHOLD,
        .compression_algorithm = LZ4_COMPRESSION,
        .enable_bloom_filter = 1,
        .bloom_fpr = TDB_DEFAULT_BLOOM_FPR,
        .enable_block_indexes = 1,
        .index_sample_ratio = TDB_DEFAULT_INDEX_SAMPLE_RATIO,
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
                               .enable_debug_logging = 0,
                               .num_flush_threads = TDB_DEFAULT_FLUSH_THREAD_POOL_SIZE,
                               .num_compaction_threads = TDB_DEFAULT_COMPACTION_THREAD_POOL_SIZE,
                               .block_cache_size = TDB_DEFAULT_BLOCK_CACHE_SIZE,
                               .max_open_sstables = TDB_DEFAULT_MAX_OPEN_SSTABLES,
                               .flush_queue_threshold = TDB_DEFAULT_FLUSH_QUEUE_THRESHOLD};
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

    kv->entry.version = BLOCK_MANAGER_VERSION;
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
    int inline_value = (kv->entry.value_size < config->value_threshold);

    size_t entry_size = sizeof(tidesdb_klog_entry_t) + kv->entry.key_size;
    if (inline_value)
    {
        entry_size += kv->entry.value_size;
    }

    uint32_t new_count = block->num_entries + 1;

    tidesdb_klog_entry_t *new_entries =
        realloc(block->entries, new_count * sizeof(tidesdb_klog_entry_t));
    if (!new_entries) return TDB_ERR_MEMORY;
    block->entries = new_entries;

    uint8_t **new_keys = realloc(block->keys, new_count * sizeof(uint8_t *));
    if (!new_keys) return TDB_ERR_MEMORY;
    block->keys = new_keys;

    uint8_t **new_inline_values = realloc(block->inline_values, new_count * sizeof(uint8_t *));
    if (!new_inline_values) return TDB_ERR_MEMORY;
    block->inline_values = new_inline_values;

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
        free(block->max_key);
        block->max_key = malloc(kv->entry.key_size);
        if (block->max_key)
        {
            memcpy(block->max_key, kv->key, kv->entry.key_size);
            block->max_key_size = kv->entry.key_size;
        }
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_klog_block_is_full
 * check if a klog block is full
 * @param block klog block to check
 * @param max_size maximum size of block
 * @return 1 if block is full, 0 otherwise
 */
static int tidesdb_klog_block_is_full(tidesdb_klog_block_t *block, size_t max_size)
{
    return block->block_size >= max_size;
}

/**
 * tidesdb_klog_block_serialize
 * serialize a klog block
 * @param block klog block to serialize
 * @param out output buffer
 * @param out_size output buffer size
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_serialize(tidesdb_klog_block_t *block, uint8_t **out,
                                        size_t *out_size)
{
    if (!block || !out || !out_size) return TDB_ERR_INVALID_ARGS;

    size_t total_size = sizeof(uint32_t) * 2;

    for (uint32_t i = 0; i < block->num_entries; i++)
    {
        /* check for overflow on each addition */
        size_t entry_size = sizeof(tidesdb_klog_entry_t);
        if (SIZE_MAX - total_size < entry_size) return TDB_ERR_OVERFLOW;
        total_size += entry_size;

        if (SIZE_MAX - total_size < block->entries[i].key_size) return TDB_ERR_OVERFLOW;
        total_size += block->entries[i].key_size;

        if (block->entries[i].vlog_offset == 0 && block->inline_values[i])
        {
            if (SIZE_MAX - total_size < block->entries[i].value_size) return TDB_ERR_OVERFLOW;
            total_size += block->entries[i].value_size;
        }
    }

    *out = malloc(total_size);
    if (!*out) return TDB_ERR_MEMORY;

    uint8_t *ptr = *out;

    encode_uint32_le_compat(ptr, block->num_entries);
    ptr += sizeof(uint32_t);
    encode_uint32_le_compat(ptr, block->block_size);
    ptr += sizeof(uint32_t);

    for (uint32_t i = 0; i < block->num_entries; i++)
    {
        /* serialize entry fields with proper endianness */
        *ptr++ = block->entries[i].version;
        *ptr++ = block->entries[i].flags;
        encode_uint32_le_compat(ptr, block->entries[i].key_size);
        ptr += sizeof(uint32_t);
        encode_uint32_le_compat(ptr, block->entries[i].value_size);
        ptr += sizeof(uint32_t);
        encode_int64_le_compat(ptr, block->entries[i].ttl);
        ptr += sizeof(int64_t);
        encode_uint64_le_compat(ptr, block->entries[i].seq);
        ptr += sizeof(uint64_t);
        encode_uint64_le_compat(ptr, block->entries[i].vlog_offset);
        ptr += sizeof(uint64_t);

        memcpy(ptr, block->keys[i], block->entries[i].key_size);
        ptr += block->entries[i].key_size;

        if (block->entries[i].vlog_offset == 0 && block->inline_values[i])
        {
            memcpy(ptr, block->inline_values[i], block->entries[i].value_size);
            ptr += block->entries[i].value_size;
        }
    }

    *out_size = total_size;
    return TDB_SUCCESS;
}

/**
 * tidesdb_klog_block_deserialize
 * deserialize a klog block
 * @param data input buffer
 * @param data_size input buffer size
 * @param block output klog block
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_klog_block_t **block)
{
    if (data_size < sizeof(uint32_t) * 2) return TDB_ERR_CORRUPTION;

    *block = tidesdb_klog_block_create();
    if (!*block) return TDB_ERR_MEMORY;

    const uint8_t *ptr = data;

    uint32_t num_entries = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    uint32_t block_size = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);

    (*block)->entries = malloc(num_entries * sizeof(tidesdb_klog_entry_t));
    (*block)->keys = calloc(num_entries, sizeof(uint8_t *));
    (*block)->inline_values = calloc(num_entries, sizeof(uint8_t *));

    if (!(*block)->entries || !(*block)->keys || !(*block)->inline_values)
    {
        if ((*block)->entries) free((*block)->entries);
        if ((*block)->keys) free((*block)->keys);
        if ((*block)->inline_values) free((*block)->inline_values);
        free(*block);
        *block = NULL;
        return TDB_ERR_MEMORY;
    }

    (*block)->num_entries = 0;
    (*block)->block_size = block_size;

    for (uint32_t i = 0; i < num_entries; i++)
    {
        size_t offset = ptr - data;
        (void)offset; /* unused but kept for debugging */

        if (ptr + sizeof(tidesdb_klog_entry_t) > data + data_size)
        {
            TDB_DEBUG_LOG("Entry header exceeds bounds at entry %u", i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }

        /* deserialize entry fields with proper endianness */
        (*block)->entries[i].version = *ptr++;
        (*block)->entries[i].flags = *ptr++;
        (*block)->entries[i].key_size = decode_uint32_le_compat(ptr);
        ptr += sizeof(uint32_t);
        (*block)->entries[i].value_size = decode_uint32_le_compat(ptr);
        ptr += sizeof(uint32_t);
        (*block)->entries[i].ttl = decode_int64_le_compat(ptr);
        ptr += sizeof(int64_t);
        (*block)->entries[i].seq = decode_uint64_le_compat(ptr);
        ptr += sizeof(uint64_t);
        (*block)->entries[i].vlog_offset = decode_uint64_le_compat(ptr);
        ptr += sizeof(uint64_t);

        if (ptr + (*block)->entries[i].key_size > data + data_size)
        {
            TDB_DEBUG_LOG("Key data exceeds bounds at entry %u (key_size=%u)", i,
                          (*block)->entries[i].key_size);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }

        (*block)->keys[i] = malloc((*block)->entries[i].key_size);
        if (!(*block)->keys[i])
        {
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_MEMORY;
        }
        memcpy((*block)->keys[i], ptr, (*block)->entries[i].key_size);
        ptr += (*block)->entries[i].key_size;

        if ((*block)->entries[i].vlog_offset == 0 && (*block)->entries[i].value_size > 0)
        {
            if (ptr + (*block)->entries[i].value_size > data + data_size)
            {
                TDB_DEBUG_LOG(
                    "Inline value exceeds bounds at entry %u "
                    "(value_size=%u)",
                    i, (*block)->entries[i].value_size);
                tidesdb_klog_block_free(*block);
                *block = NULL;
                return TDB_ERR_CORRUPTION;
            }

            (*block)->inline_values[i] = malloc((*block)->entries[i].value_size);
            if (!(*block)->inline_values[i])
            {
                tidesdb_klog_block_free(*block);
                *block = NULL;
                return TDB_ERR_MEMORY;
            }
            memcpy((*block)->inline_values[i], ptr, (*block)->entries[i].value_size);
            ptr += (*block)->entries[i].value_size;
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
 * tidesdb_vlog_block_create
 * create a new vlog block
 * @return new vlog block
 */
static tidesdb_vlog_block_t *tidesdb_vlog_block_create(void)
{
    return calloc(1, sizeof(tidesdb_vlog_block_t));
}

/**
 * tidesdb_vlog_block_free
 * free a vlog block
 * @param block vlog block to free
 */
static void tidesdb_vlog_block_free(tidesdb_vlog_block_t *block)
{
    if (!block) return;

    for (uint32_t i = 0; i < block->num_values; i++)
    {
        free(block->values[i]);
    }

    free(block->value_sizes);
    free(block->values);
    free(block);
}

/**
 * tidesdb_vlog_block_add_value
 * add a value to a vlog block
 * @param block vlog block to add value to
 * @param value value to add
 * @param value_size size of value
 * @param offset_in_block offset of value in block
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_block_add_value(tidesdb_vlog_block_t *block, const uint8_t *value,
                                        size_t value_size, uint64_t *offset_in_block)
{
    uint32_t new_count = block->num_values + 1;

    uint32_t *new_sizes = realloc(block->value_sizes, new_count * sizeof(uint32_t));
    if (!new_sizes) return TDB_ERR_MEMORY;
    block->value_sizes = new_sizes;

    uint8_t **new_values = realloc(block->values, new_count * sizeof(uint8_t *));
    if (!new_values) return TDB_ERR_MEMORY;
    block->values = new_values;

    *offset_in_block = (sizeof(uint32_t) * 2) + block->block_size;

    block->value_sizes[block->num_values] = (uint32_t)value_size;
    block->values[block->num_values] = malloc(value_size);
    if (!block->values[block->num_values]) return TDB_ERR_MEMORY;
    memcpy(block->values[block->num_values], value, value_size);

    block->num_values++;
    block->block_size += (uint32_t)(sizeof(uint32_t) + value_size);

    return TDB_SUCCESS;
}

/**
 * tidesdb_vlog_block_is_full
 * check if a vlog block is full
 * @param block vlog block to check
 * @param max_size maximum size of block
 * @return 1 if block is full, 0 otherwise
 */
static int tidesdb_vlog_block_is_full(tidesdb_vlog_block_t *block, size_t max_size)
{
    return block->block_size >= max_size;
}

/**
 * tidesdb_vlog_block_serialize
 * serialize a vlog block
 * @param block vlog block to serialize
 * @param out output buffer
 * @param out_size output buffer size
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_block_serialize(tidesdb_vlog_block_t *block, uint8_t **out,
                                        size_t *out_size)
{
    size_t total_size = sizeof(uint32_t) * 2;

    for (uint32_t i = 0; i < block->num_values; i++)
    {
        total_size += sizeof(uint32_t) + block->value_sizes[i];
    }

    *out = malloc(total_size);
    if (!*out) return TDB_ERR_MEMORY;

    uint8_t *ptr = *out;

    encode_uint32_le_compat(ptr, block->num_values);
    ptr += sizeof(uint32_t);
    encode_uint32_le_compat(ptr, block->block_size);
    ptr += sizeof(uint32_t);

    for (uint32_t i = 0; i < block->num_values; i++)
    {
        encode_uint32_le_compat(ptr, block->value_sizes[i]);
        ptr += sizeof(uint32_t);

        memcpy(ptr, block->values[i], block->value_sizes[i]);
        ptr += block->value_sizes[i];
    }

    *out_size = ptr - *out;
    return TDB_SUCCESS;
}

/**
 * tidesdb_vlog_block_deserialize
 * deserialize a vlog block
 * @param data input buffer
 * @param data_size input buffer size
 * @param block output vlog block
 * @return 0 on success, -1 on error
 */
static int tidesdb_vlog_block_deserialize(const uint8_t *data, size_t data_size,
                                          tidesdb_vlog_block_t **block)
{
    if (data_size < sizeof(uint32_t) * 2) return TDB_ERR_CORRUPTION;

    *block = tidesdb_vlog_block_create();
    if (!*block) return TDB_ERR_MEMORY;

    const uint8_t *ptr = data;

    (*block)->num_values = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);
    (*block)->block_size = decode_uint32_le_compat(ptr);
    ptr += sizeof(uint32_t);

    (*block)->value_sizes = malloc((*block)->num_values * sizeof(uint32_t));
    (*block)->values = malloc((*block)->num_values * sizeof(uint8_t *));

    if (!(*block)->value_sizes || !(*block)->values)
    {
        tidesdb_vlog_block_free(*block);
        return TDB_ERR_MEMORY;
    }

    for (uint32_t i = 0; i < (*block)->num_values; i++)
    {
        if (ptr + sizeof(uint32_t) > data + data_size)
        {
            tidesdb_vlog_block_free(*block);
            return TDB_ERR_CORRUPTION;
        }

        (*block)->value_sizes[i] = decode_uint32_le_compat(ptr);
        ptr += sizeof(uint32_t);

        if (ptr + (*block)->value_sizes[i] > data + data_size)
        {
            tidesdb_vlog_block_free(*block);
            return TDB_ERR_CORRUPTION;
        }

        (*block)->values[i] = malloc((*block)->value_sizes[i]);
        if (!(*block)->values[i])
        {
            tidesdb_vlog_block_free(*block);
            return TDB_ERR_MEMORY;
        }
        memcpy((*block)->values[i], ptr, (*block)->value_sizes[i]);
        ptr += (*block)->value_sizes[i];
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

    /* calculate which vlog block contains this offset */
    uint64_t block_num = vlog_offset / sst->config->vlog_block_size;
    uint64_t offset_in_block = vlog_offset % sst->config->vlog_block_size;

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bms.vlog_bm) != 0)
    {
        return TDB_ERR_IO;
    }

    if (block_manager_cursor_goto_first(cursor) != 0)
    {
        block_manager_cursor_free(cursor);
        return TDB_ERR_IO;
    }

    for (uint64_t i = 0; i < block_num && block_manager_cursor_has_next(cursor); i++)
    {
        block_manager_cursor_next(cursor);
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    if (!block)
    {
        block_manager_cursor_free(cursor);
        return TDB_ERR_IO;
    }

    /* block is now owned by us, no acquire needed */

    uint8_t *data = block->data;
    size_t data_size = block->size;
    uint8_t *decompressed = NULL;

    if (sst->config->compression_algorithm != NO_COMPRESSION)
    {
        size_t decompressed_size;
        decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                       sst->config->compression_algorithm);
        if (decompressed)
        {
            data = decompressed;
            data_size = decompressed_size;
        }
    }

    tidesdb_vlog_block_t *vlog_block;
    int result = tidesdb_vlog_block_deserialize(data, data_size, &vlog_block);

    free(decompressed);
    block_manager_block_release(block);
    block_manager_cursor_free(cursor);

    if (result != TDB_SUCCESS)
    {
        return result;
    }

    /* find value at offset */
    uint64_t current_offset = sizeof(uint32_t) * 2; /* header */
    for (uint32_t i = 0; i < vlog_block->num_values; i++)
    {
        if (current_offset == offset_in_block)
        {
            *value = malloc(vlog_block->value_sizes[i]);
            if (!*value)
            {
                tidesdb_vlog_block_free(vlog_block);
                return TDB_ERR_MEMORY;
            }

            /* validate value size matches expected */
            if (value_size > 0 && vlog_block->value_sizes[i] != value_size)
            {
                TDB_DEBUG_LOG("Value size mismatch at entry %d (expected %zu, got %u)", i,
                              value_size, vlog_block->value_sizes[i]);
                free(*value);
                *value = NULL;
                tidesdb_vlog_block_free(vlog_block);
                return TDB_ERR_CORRUPTION;
            }

            memcpy(*value, vlog_block->values[i], vlog_block->value_sizes[i]);
            tidesdb_vlog_block_free(vlog_block);
            return TDB_SUCCESS;
        }
        current_offset += sizeof(uint32_t) + vlog_block->value_sizes[i];
    }

    tidesdb_vlog_block_free(vlog_block);
    return TDB_ERR_NOT_FOUND;
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
    (void)db; /* unused but kept for API consistency */
    if (!cursor) return TDB_ERR_INVALID_ARGS;

    /* calculate which vlog block contains this offset */
    uint64_t block_num = vlog_offset / sst->config->vlog_block_size;
    uint64_t offset_in_block = vlog_offset % sst->config->vlog_block_size;

    /* use position cache for O(1) random access if available */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        /* position cache available and not being rebuilt -- direct jump to block */
        if (block_num >= (uint64_t)cursor->bm->block_count)
        {
            return TDB_ERR_IO; /* block number out of range */
        }
        cursor->block_index = (int)block_num;
        cursor->current_pos = cursor->bm->block_positions[block_num];
        cursor->current_block_size = cursor->bm->block_sizes[block_num];
    }
    else
    {
        /* no position cache -- fall back to sequential seek */
        if (block_manager_cursor_goto_first(cursor) != 0)
        {
            return TDB_ERR_IO;
        }

        /* goto_first without cache positions at header (block_index=-1)
         * so we need to advance to first block (block 0) first */
        for (uint64_t i = 0; i <= block_num && block_manager_cursor_has_next(cursor); i++)
        {
            if (block_manager_cursor_next(cursor) != 0)
            {
                return TDB_ERR_IO;
            }
        }
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    if (!block)
    {
        return TDB_ERR_IO;
    }

    /* block is now owned by us */
    uint8_t *data = block->data;
    size_t data_size = block->size;
    uint8_t *decompressed = NULL;

    if (sst->config->compression_algorithm != NO_COMPRESSION)
    {
        size_t decompressed_size;
        decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                       sst->config->compression_algorithm);
        if (decompressed)
        {
            data = decompressed;
            data_size = decompressed_size;
        }
    }

    tidesdb_vlog_block_t *vlog_block;
    int result = tidesdb_vlog_block_deserialize(data, data_size, &vlog_block);

    free(decompressed);
    block_manager_block_release(block);

    if (result != TDB_SUCCESS)
    {
        return result;
    }

    /* find value at offset */
    uint64_t current_offset = sizeof(uint32_t) * 2; /* header */
    for (uint32_t i = 0; i < vlog_block->num_values; i++)
    {
        if (current_offset == offset_in_block)
        {
            *value = malloc(vlog_block->value_sizes[i]);
            if (!*value)
            {
                tidesdb_vlog_block_free(vlog_block);
                return TDB_ERR_MEMORY;
            }

            /* validate value size matches expected */
            if (value_size > 0 && vlog_block->value_sizes[i] != value_size)
            {
                free(*value);
                *value = NULL;
                tidesdb_vlog_block_free(vlog_block);
                return TDB_ERR_CORRUPTION;
            }

            memcpy(*value, vlog_block->values[i], vlog_block->value_sizes[i]);
            tidesdb_vlog_block_free(vlog_block);
            return TDB_SUCCESS;
        }
        current_offset += sizeof(uint32_t) + vlog_block->value_sizes[i];
    }

    tidesdb_vlog_block_free(vlog_block);
    return TDB_ERR_NOT_FOUND;
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

    /* ensure sstable block managers are open */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        return TDB_ERR_IO;
    }

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
 * tidesdb_sstable_cache_evict_cb
 * callback when an sstable is evicted from cache
 * releases the sstable reference
 */
static void tidesdb_sstable_cache_evict_cb(const char *key, void *value, void *user_data)
{
    (void)key;
    tidesdb_t *db = (tidesdb_t *)user_data;
    tidesdb_sstable_t *sst = (tidesdb_sstable_t *)value;

    if (!sst) return;

    /* release the cache's reference to the sstable */
    tidesdb_sstable_unref(db, sst);
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

    /* create cache key from sstable id */
    char cache_key[TDB_CACHE_KEY_SIZE];
    snprintf(cache_key, sizeof(cache_key), TDB_SSTABLE_CACHE_PREFIX "%" PRIu64, sst->id);

    /* check if already in cache */
    void *cached = lru_cache_get(db->sstable_cache, cache_key);
    if (!cached)
    {
        /* increment refcount before adding to cache -- cache now owns a reference */
        tidesdb_sstable_ref(sst);

        /* add to cache, which will evict old entries if needed
         * returns 0 = new insertion, 1 = updated existing, -1 = error */
        int put_result =
            lru_cache_put(db->sstable_cache, cache_key, sst, tidesdb_sstable_cache_evict_cb, db);
        if (put_result < 0)
        {
            /* Cache add failed (likely full with all entries protected by hazard pointers).
             * This is OK - we can still open the SSTable, it just won't be cached.
             * Release the ref we took for the cache. */
            TDB_DEBUG_LOG("SSTable %" PRIu64 ": cache_put FAILED - proceeding without cache",
                          sst->id);
            tidesdb_sstable_unref(db, sst);
            /* Continue to open the SSTable below - cache is an optimization, not required */
        }
        /* if put_result == 0, new entry was inserted successfully
         * if put_result == 1, entry was updated
         *   evict callback unreffed old value
         *   we took a ref before calling put
         *   cache now holds the new value with correct refcount
         *   do not unref here, refcount is already correct */
    }

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
     * This ensures active transactions can still read from old sstables
     * during compaction, preventing data loss */
    if (atomic_load_explicit(&sst->marked_for_deletion, memory_order_acquire))
    {
        unlink(sst->klog_path);
        unlink(sst->vlog_path);
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
 * tidesdb_immutable_memtable_unref
 * decrement reference count of an immutable memtable
 * @param imm immutable memtable to unreference
 */
static void tidesdb_immutable_memtable_unref(tidesdb_immutable_memtable_t *imm)
{
    if (!imm) return;
    if (atomic_fetch_sub(&imm->refcount, 1) == 1)
    {
        if (imm->memtable) skip_list_free(imm->memtable);
        if (imm->wal) block_manager_close(imm->wal);
        free(imm);
    }
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
    int num_entries = skip_list_count_entries(memtable);
    TDB_DEBUG_LOG("SSTable %" PRIu64 ": Writing from memtable (%d entries)", sst->id, num_entries);

    /* ensure sstable is in cache and get block managers */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Failed to ensure open", sst->id);
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Failed to get block managers", sst->id);
        return TDB_ERR_IO;
    }

    /* create bloom filter and indexes if enabled */
    bloom_filter_t *bloom = NULL;
    tidesdb_block_index_t *block_indexes = NULL;

    if (sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, sst->config->bloom_fpr, num_entries) != 0)
        {
            TDB_DEBUG_LOG("SSTable %" PRIu64 ": Failed to create bloom filter", sst->id);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Bloom filter created (fpr: %.4f, entries: %d)", sst->id,
                      sst->config->bloom_fpr, num_entries);
    }
    else
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Bloom filter disabled", sst->id);
    }

    if (sst->config->enable_block_indexes)
    {
        skip_list_comparator_fn comparator_fn = NULL;
        void *comparator_ctx = NULL;
        tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

        /* calc initial capacity based on expected samples */
        uint32_t initial_capacity = (num_entries / sst->config->index_sample_ratio) + 1;
        block_indexes = compact_block_index_create(initial_capacity, comparator_fn, comparator_ctx);
        if (!block_indexes)
        {
            TDB_DEBUG_LOG("SSTable %" PRIu64 ": Failed to create block indexes", sst->id);
            if (bloom) bloom_filter_free(bloom);
            return TDB_ERR_MEMORY;
        }
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Block indexes enabled (sample ratio: %d)", sst->id,
                      sst->config->index_sample_ratio);
    }
    else
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Block indexes disabled", sst->id);
    }

    /* init blocks */
    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();
    tidesdb_vlog_block_t *current_vlog_block = tidesdb_vlog_block_create();

    if (!current_klog_block || !current_vlog_block)
    {
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        tidesdb_klog_block_free(current_klog_block);
        tidesdb_vlog_block_free(current_vlog_block);
        return TDB_ERR_MEMORY;
    }

    skip_list_cursor_t *cursor;
    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        if (bloom) bloom_filter_free(bloom);
        if (block_indexes) compact_block_index_free(block_indexes);
        tidesdb_klog_block_free(current_klog_block);
        tidesdb_vlog_block_free(current_vlog_block);
        return TDB_ERR_MEMORY;
    }

    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    uint64_t current_vlog_file_offset = 0;
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
                TDB_DEBUG_LOG(
                    "WARNING: Skipping entry during flush - cursor read failed (entry %" PRIu64 ")",
                    entry_count);
                continue;
            }

            tidesdb_kv_pair_t *kv =
                tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, seq, deleted);
            if (!kv) continue;

            /* handle large values  */
            if (value_size >= sst->config->value_threshold && !deleted && value)
            {
                /* check if vlog block is full */
                if (tidesdb_vlog_block_is_full(current_vlog_block, sst->config->vlog_block_size))
                {
                    /* serialize and write vlog block */
                    uint8_t *vlog_data;
                    size_t vlog_size;
                    if (tidesdb_vlog_block_serialize(current_vlog_block, &vlog_data, &vlog_size) ==
                        0)
                    {
                        uint8_t *final_vlog_data = vlog_data;
                        size_t final_vlog_size = vlog_size;

                        if (sst->config->compression_algorithm != NO_COMPRESSION)
                        {
                            size_t compressed_size;
                            uint8_t *compressed =
                                compress_data(vlog_data, vlog_size, &compressed_size,
                                              sst->config->compression_algorithm);
                            if (compressed)
                            {
                                free(vlog_data);
                                final_vlog_data = compressed;
                                final_vlog_size = compressed_size;
                            }
                            else
                            {
                                /* compression failed -- fatal error */
                                free(vlog_data);
                                tidesdb_klog_block_free(current_klog_block);
                                tidesdb_vlog_block_free(current_vlog_block);
                                skip_list_cursor_free(cursor);
                                if (bloom) bloom_filter_free(bloom);
                                if (block_indexes) compact_block_index_free(block_indexes);
                                return TDB_ERR_CORRUPTION;
                            }
                        }

                        block_manager_block_t *vlog_block =
                            block_manager_block_create(final_vlog_size, final_vlog_data);
                        if (vlog_block)
                        {
                            block_manager_block_write(bms.vlog_bm, vlog_block);
                            block_manager_block_release(vlog_block);

                            current_vlog_file_offset +=
                                vlog_size; /* use uncompressed size for logical offset */
                            vlog_block_num++;
                        }
                        free(final_vlog_data);
                    }

                    tidesdb_vlog_block_free(current_vlog_block);
                    current_vlog_block = tidesdb_vlog_block_create();
                }

                uint64_t offset_in_block;
                if (tidesdb_vlog_block_add_value(current_vlog_block, value, value_size,
                                                 &offset_in_block) == 0)
                {
                    kv->entry.vlog_offset = current_vlog_file_offset + offset_in_block;
                }
            }

            if (tidesdb_klog_block_is_full(current_klog_block, sst->config->klog_block_size))
            {
                /* add completed block to index before writing */
                if (block_indexes && block_first_key && block_last_key)
                {
                    if (sst->config->index_sample_ratio <= 1 ||
                        (klog_block_num % sst->config->index_sample_ratio == 0))
                    {
                        compact_block_index_add(block_indexes, block_first_key,
                                                block_first_key_size, block_last_key,
                                                block_last_key_size, klog_block_num);
                    }
                }

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
                            TDB_DEBUG_LOG("SSTable %" PRIu64 ": klog compression FAILED!", sst->id);
                            free(klog_data);
                            tidesdb_klog_block_free(current_klog_block);
                            tidesdb_vlog_block_free(current_vlog_block);
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
                        block_manager_block_write(bms.klog_bm, klog_block);
                        block_manager_block_release(klog_block);
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

            /* check if this is the first entry in a new block */
            int is_first_entry_in_block = (current_klog_block->num_entries == 0);

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
        /* add final block to index */
        if (block_indexes && block_first_key && block_last_key)
        {
            if (sst->config->index_sample_ratio <= 1 ||
                (klog_block_num % sst->config->index_sample_ratio == 0))
            {
                compact_block_index_add(block_indexes, block_first_key, block_first_key_size,
                                        block_last_key, block_last_key_size, klog_block_num);
            }
        }

        uint8_t *klog_data;
        size_t klog_size;
        if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
        {
            if (sst->config->compression_algorithm != NO_COMPRESSION)
            {
                size_t compressed_size;
                uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                    sst->config->compression_algorithm);
                if (compressed)
                {
                    free(klog_data);
                    klog_data = compressed;
                    klog_size = compressed_size;
                }
                else
                {
                    TDB_DEBUG_LOG("SSTable %" PRIu64 ": final klog compression FAILED!", sst->id);
                    free(klog_data);
                    tidesdb_klog_block_free(current_klog_block);
                    tidesdb_vlog_block_free(current_vlog_block);
                    if (bloom) bloom_filter_free(bloom);
                    if (block_indexes) compact_block_index_free(block_indexes);
                    free(block_first_key);
                    free(block_last_key);
                    return TDB_ERR_CORRUPTION;
                }
            }

            block_manager_block_t *klog_block = block_manager_block_create(klog_size, klog_data);
            if (klog_block)
            {
                block_manager_block_write(bms.klog_bm, klog_block);
                block_manager_block_release(klog_block);
                klog_block_num++;
            }
            free(klog_data);
        }
    }

    /* cleanup block tracking */
    free(block_first_key);
    free(block_last_key);

    if (current_vlog_block->num_values > 0)
    {
        uint8_t *vlog_data;
        size_t vlog_size;
        if (tidesdb_vlog_block_serialize(current_vlog_block, &vlog_data, &vlog_size) == 0)
        {
            if (sst->config->compression_algorithm != NO_COMPRESSION)
            {
                size_t compressed_size;
                uint8_t *compressed = compress_data(vlog_data, vlog_size, &compressed_size,
                                                    sst->config->compression_algorithm);
                if (compressed)
                {
                    free(vlog_data);
                    vlog_data = compressed;
                    vlog_size = compressed_size;
                }
                else
                {
                    free(vlog_data);
                    tidesdb_klog_block_free(current_klog_block);
                    tidesdb_vlog_block_free(current_vlog_block);
                    if (bloom) bloom_filter_free(bloom);
                    if (block_indexes) compact_block_index_free(block_indexes);
                    return TDB_ERR_CORRUPTION;
                }
            }

            block_manager_block_t *vlog_block = block_manager_block_create(vlog_size, vlog_data);
            if (vlog_block)
            {
                block_manager_block_write(bms.vlog_bm, vlog_block);
                block_manager_block_release(vlog_block);
                vlog_block_num++;
            }
            free(vlog_data);
        }
    }

    tidesdb_klog_block_free(current_klog_block);
    tidesdb_vlog_block_free(current_vlog_block);

    sst->num_klog_blocks = klog_block_num;
    sst->num_vlog_blocks = vlog_block_num;
    sst->min_key = first_key;
    sst->min_key_size = first_key_size;
    sst->max_key = last_key;
    sst->max_key_size = last_key_size;
    sst->max_seq = max_seq; /* store maximum sequence number */

    /* capture klog file offset where data blocks end (before writing index/bloom/metadata) */
    block_manager_get_size(bms.klog_bm, &sst->klog_data_end_offset);

    /* build and write index */
    if (block_indexes)
    {
        /* we assign the built index to the sst */
        sst->block_indexes = block_indexes;

        TDB_DEBUG_LOG("SSTable %" PRIu64 ": Block indexes built - %u samples, %" PRIu64
                      " total blocks",
                      sst->id, sst->block_indexes->count, klog_block_num);
        size_t index_size;
        uint8_t *index_data = compact_block_index_serialize(sst->block_indexes, &index_size);
        if (index_data)
        {
            TDB_DEBUG_LOG("SSTable %" PRIu64 ": Block indexes serialized to %zu bytes", sst->id,
                          index_size);
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(bms.klog_bm, index_block);
                block_manager_block_release(index_block);
            }
            free(index_data);
        }
    }

    /* write bloom filter */
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

    /* get file sizes before writing metadata */
    block_manager_get_size(bms.klog_bm, &sst->klog_size);
    block_manager_get_size(bms.vlog_bm, &sst->vlog_size);

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
        TDB_DEBUG_LOG("SSTable " TDB_U64_FMT " ensure_open FAILED", TDB_U64_CAST(sst->id));
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": get_block_managers FAILED", sst->id);
        return TDB_ERR_IO;
    }

    if (!sst->min_key || !sst->max_key)
    {
        return TDB_ERR_NOT_FOUND;
    }

    /* check bloom filter first (faster than comparisons: ~50-100ns vs ~100-200ns) */
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
    int64_t start_block = 0;
    if (sst->block_indexes)
    {
        if (compact_block_index_find_predecessor(sst->block_indexes, key, key_size, &start_block) !=
            0)
        {
            start_block = 0;
        }
    }

    /* search klog blocks using block manager cursor */
    block_manager_cursor_t *klog_cursor;

    if (block_manager_cursor_init(&klog_cursor, bms.klog_bm) != 0)
    {
        TDB_DEBUG_LOG("SSTable %" PRIu64 ": FAILED to initialize klog cursor", sst->id);
        return TDB_ERR_IO;
    }

    if (block_manager_cursor_goto_first(klog_cursor) != 0)
    {
        block_manager_cursor_free(klog_cursor);
        return TDB_ERR_NOT_FOUND;
    }

    /* we navigate to starting block using block index hint */
    for (int64_t i = 0; i < start_block && block_manager_cursor_has_next(klog_cursor); i++)
    {
        block_manager_cursor_next(klog_cursor);
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

    char cf_name[TDB_CACHE_KEY_SIZE];
    if (tidesdb_get_cf_name_from_path(sst->klog_path, cf_name) != 0)
    {
        block_manager_cursor_free(klog_cursor);
        return TDB_ERR_NOT_FOUND;
    }

    while (block_num < sst->num_klog_blocks)
    {
        /* check if cursor is past data end offset (into auxiliary structures) */
        if (sst->klog_data_end_offset > 0 && klog_cursor->current_pos >= sst->klog_data_end_offset)
        {
            /* reached auxiliary structures, stop reading data blocks */
            break;
        }

        block_manager_block_t *block =
            tidesdb_cached_block_read(db, cf_name, sst->id, 'k', klog_cursor);
        if (!block)
        {
            break;
        }

        uint8_t *data = block->data;
        size_t data_size = block->size;
        uint8_t *decompressed = NULL;
        int need_free_decompressed = 0;

        if (sst->config->compression_algorithm != NO_COMPRESSION)
        {
            size_t decompressed_size;
            decompressed = decompress_data(block->data, block->size, &decompressed_size,
                                           sst->config->compression_algorithm);
            if (decompressed)
            {
                data = decompressed;
                data_size = decompressed_size;
                need_free_decompressed = 1;
            }
            else
            {
                TDB_DEBUG_LOG("SSTable " TDB_U64_FMT " decompression FAILED (returned NULL)",
                              TDB_U64_CAST(sst->id));
            }
        }

        tidesdb_klog_block_t *klog_block;
        int deser_result = tidesdb_klog_block_deserialize(data, data_size, &klog_block);

        if (deser_result == 0)
        {
            /* reuse comparator_fn and comparator_ctx from function scope */

            /* search entries in this block */
            for (uint32_t i = 0; i < klog_block->num_entries; i++)
            {
                int cmp = comparator_fn(key, key_size, klog_block->keys[i],
                                        klog_block->entries[i].key_size, comparator_ctx);

                if (cmp == 0)
                {
                    /* found! */
                    *kv = tidesdb_kv_pair_create(
                        klog_block->keys[i], klog_block->entries[i].key_size, NULL, 0,
                        klog_block->entries[i].ttl, klog_block->entries[i].seq,
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
                                                    klog_block->entries[i].value_size,
                                                    &(*kv)->value);
                        }

                        result = TDB_SUCCESS;
                    }

                    tidesdb_klog_block_free(klog_block);
                    if (need_free_decompressed) free(decompressed);
                    block_manager_block_release(block);
                    goto cleanup;
                }
                else if (cmp < 0)
                {
                    /* passed the key */
                    tidesdb_klog_block_free(klog_block);
                    if (need_free_decompressed) free(decompressed);
                    block_manager_block_release(block);
                    goto cleanup;
                }
            }

            tidesdb_klog_block_free(klog_block);
        }

        if (need_free_decompressed) free(decompressed);
        block_manager_block_release(block);

        block_num++; /* increment after processing block */

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
        TDB_DEBUG_LOG("Failed to open klog file: %s (may be leftover from incomplete cleanup)",
                      sst->klog_path);
        return -1;
    }

    if (block_manager_open(&vlog_bm, sst->vlog_path, convert_sync_mode(sst->config->sync_mode)) !=
        0)
    {
        TDB_DEBUG_LOG("Failed to open vlog file: %s (may be leftover from incomplete cleanup)",
                      sst->vlog_path);
        block_manager_close(klog_bm);
        return -1;
    }

    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    /* check for empty or corrupted files */
    if (sst->klog_size == 0)
    {
        TDB_DEBUG_LOG("Empty klog file: %s (corrupted or incomplete SSTable)", sst->klog_path);
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
        TDB_DEBUG_LOG("SSTable metadata corrupted: %s", sst->klog_path);
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_CORRUPTION;
    }

    block_manager_close(klog_bm);
    block_manager_close(vlog_bm);
    return TDB_ERR_CORRUPTION;

load_bloom_and_index:
    /* load bloom filter and index from last blocks */
    /* [klog blocks...] [index block] [bloom filter block] [metadata block] */
    ;
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
                if (bloom_block->size > 0)
                {
                    sst->bloom_filter = bloom_filter_deserialize(bloom_block->data);
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

                        /* we set comparator after deserialization */
                        if (sst->block_indexes)
                        {
                            skip_list_comparator_fn comparator_fn = NULL;
                            void *comparator_ctx = NULL;
                            tidesdb_resolve_comparator(db, sst->config, &comparator_fn,
                                                       &comparator_ctx);
                            sst->block_indexes->comparator = comparator_fn;
                            sst->block_indexes->comparator_ctx = comparator_ctx;
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
    TDB_DEBUG_LOG("Creating level %d with capacity %zu", level_num, capacity);

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

    TDB_DEBUG_LOG("tidesdb_level_create: Allocated sstables array %p for level %d (capacity %d)",
                  (void *)sstables, level_num, TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY);

    atomic_init(&level->sstables, sstables);
    atomic_init(&level->num_sstables, 0);
    atomic_init(&level->sstables_capacity, TDB_MIN_LEVEL_SSTABLES_INITIAL_CAPACITY);
    atomic_init(&level->num_boundaries, 0);

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

    TDB_DEBUG_LOG("tidesdb_level_free: Freeing level %d", level->level_num);

    /* Load count before array to prevent TOCTOU race */
    int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
    tidesdb_sstable_t **ssts = atomic_load_explicit(&level->sstables, memory_order_acquire);

    TDB_DEBUG_LOG("tidesdb_level_free: Level %d has %d sstables to unref, array ptr=%p",
                  level->level_num, num_ssts, (void *)ssts);

    for (int i = 0; i < num_ssts; i++)
    {
        if (ssts[i])
        {
            tidesdb_sstable_unref(db, ssts[i]);
        }
    }

    TDB_DEBUG_LOG("tidesdb_level_free: Freeing sstables array %p for level %d", (void *)ssts,
                  level->level_num);
    TDB_DEBUG_LOG("tidesdb_level_free: Freed sstables array %p for level %d", (void *)ssts,
                  level->level_num);

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

    TDB_DEBUG_LOG("tidesdb_level_free: Freeing level %d struct", level->level_num);
    free(level);
    TDB_DEBUG_LOG("tidesdb_level_free: Level struct freed");
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

        TDB_DEBUG_LOG("tidesdb_level_add_sstable: SSTable %" PRIu64
                      " to level %d: old_num=%d, old_capacity=%d, old_arr=%p",
                      sst->id, level->level_num, old_num, old_capacity, (void *)old_arr);

        /* check if we need to grow the array */
        if (old_num >= old_capacity)
        {
            TDB_DEBUG_LOG(
                "tidesdb_level_add_sstable: RESIZE PATH - level %d needs resize (num=%d >= cap=%d)",
                level->level_num, old_num, old_capacity);
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
                TDB_DEBUG_LOG(
                    "tidesdb_level_add_sstable: Freeing old array %p (was capacity %d), new array "
                    "%p (capacity %d) for level %d",
                    (void *)old_arr, old_capacity, (void *)new_arr, new_capacity, level->level_num);
                free(old_arr);

                return TDB_SUCCESS;
            }
            /* CAS failed, retry with new state */
            free(new_arr);
        }
        else
        {
            /* no resize needed, just add to existing array */
            TDB_DEBUG_LOG("tidesdb_level_add_sstable: NON-RESIZE PATH - level %d (num=%d < cap=%d)",
                          level->level_num, old_num, old_capacity);
            /* atomically reserve a slot by incrementing count first */
            int expected = old_num;

            /* verify we have space before trying to reserve */
            if (expected >= old_capacity)
            {
                /* no space, retry with resize path */
                continue;
            }

            /* try to atomically reserve slot by incrementing count */
            if (atomic_compare_exchange_strong_explicit(&level->num_sstables, &expected,
                                                        old_num + 1, memory_order_release,
                                                        memory_order_acquire))
            {
                /* success! we reserved slot at index old_num */
                /* verify array pointer hasn't changed (another thread might have resized) */
                tidesdb_sstable_t **current_arr =
                    atomic_load_explicit(&level->sstables, memory_order_acquire);
                if (current_arr != old_arr)
                {
                    /* array was resized, write to the NEW array at our reserved index */
                    current_arr[old_num] = sst;
                    atomic_thread_fence(memory_order_release);
                    atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                              memory_order_relaxed);
                    return TDB_SUCCESS;
                }

                /* array is still valid, write to our reserved slot */
                old_arr[old_num] = sst;

                /* ensure write is visible */
                atomic_thread_fence(memory_order_release);

                /* update size */
                atomic_fetch_add_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                          memory_order_relaxed);
                return TDB_SUCCESS;
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

            /* remove from cache if present to avoid stale cache entries */
            if (db && db->sstable_cache)
            {
                char cache_key[TDB_CACHE_KEY_SIZE];
                snprintf(cache_key, sizeof(cache_key), TDB_SSTABLE_CACHE_PREFIX "%" PRIu64,
                         sst->id);
                lru_cache_remove(db->sstable_cache, cache_key);
            }

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

        if (file_boundaries != NULL) free(file_boundaries);
    }

    if (boundary_sizes)
    {
        free(boundary_sizes);
    }

    /* Load count before array to prevent TOCTOU race */
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

    heap->capacity = 16;
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
 * @return smallest element
 */
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap)
{
    if (heap->num_sources == 0) return NULL;

    tidesdb_merge_source_t *top = heap->sources[0];
    if (!top->current_kv) return NULL;

    tidesdb_kv_pair_t *result = tidesdb_kv_pair_clone(top->current_kv);

    /* advance source */
    if (tidesdb_merge_source_advance(top) != 0)
    {
        /* source exhausted, remove from heap */
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

    /* ensure sstable is open through cache */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        block_manager_cursor_free(source->source.sstable.vlog_cursor);
        free(source);
        return NULL;
    }

    source->source.sstable.current_block_data = NULL; /* no block data yet */
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
        char cf_name[TDB_CACHE_KEY_SIZE];
        if (tidesdb_get_cf_name_from_path(sst->klog_path, cf_name) != 0)
        {
            /* failed to extract CF name */
            tidesdb_sstable_unref(db, sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            block_manager_cursor_free(source->source.sstable.vlog_cursor);
            free(source);
            return NULL;
        }

        block_manager_block_t *block = tidesdb_cached_block_read(
            db, cf_name, sst->id, 'k', source->source.sstable.klog_cursor);
        if (!block)
        {
            /* no block available */
            tidesdb_sstable_unref(db, sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            block_manager_cursor_free(source->source.sstable.vlog_cursor);
            free(source);
            return NULL;
        }

        /* block is owned by us, decompress it */
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

        if (tidesdb_klog_block_deserialize(data, data_size,
                                           &source->source.sstable.current_block) == 0)
        {
            if (source->source.sstable.current_block->num_entries > 0)
            {
                /* deserialization succeeded, now safe to store block */
                source->source.sstable.current_block_data = block;
                source->source.sstable.current_entry_idx = 0;

                /* create KV pair from first entry */
                tidesdb_klog_block_t *kb = source->source.sstable.current_block;
                uint8_t *value = kb->inline_values[0];

                /* if not inline, read from vlog */
                uint8_t *vlog_value = NULL;
                if (kb->entries[0].vlog_offset > 0)
                {
                    tidesdb_vlog_read_value_with_cursor(
                        source->source.sstable.db, sst, source->source.sstable.vlog_cursor,
                        kb->entries[0].vlog_offset, kb->entries[0].value_size, &vlog_value);
                    value = vlog_value;
                }

                source->current_kv = tidesdb_kv_pair_create(
                    kb->keys[0], kb->entries[0].key_size, value, kb->entries[0].value_size,
                    kb->entries[0].ttl, kb->entries[0].seq,
                    kb->entries[0].flags & TDB_KV_FLAG_TOMBSTONE);

                free(vlog_value);
                /* don't free decompressed or release block,we're still using the deserialized data
                 */
                return source;
            }
        }

        /* deserialization failed or empty block, clean up and return NULL */
        if (decompressed) free(decompressed);
        block_manager_block_release(block);
        tidesdb_sstable_unref(db, sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
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
        if (source->source.sstable.current_block)
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
            if (source->source.sstable.current_block)
            {
                tidesdb_klog_block_free(source->source.sstable.current_block);
                source->source.sstable.current_block = NULL;
            }
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

                    if (tidesdb_klog_block_deserialize(data, data_size,
                                                       &source->source.sstable.current_block) == 0)
                    {
                        if (source->source.sstable.current_block->num_entries > 0)
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
                            /* store block reference so it will be released on next advance or free
                             */
                            source->source.sstable.current_block_data = block;
                            /* don't free decompressed or release block, we're still using the
                             * deserialized data */
                            return TDB_SUCCESS;
                        }
                    }

                    /* on error, clean up and release */
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
        if (source->source.sstable.current_block)
        {
            tidesdb_klog_block_free(source->source.sstable.current_block);
            source->source.sstable.current_block = NULL;
        }
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

                if (tidesdb_klog_block_deserialize(data, data_size,
                                                   &source->source.sstable.current_block) == 0)
                {
                    if (source->source.sstable.current_block->num_entries > 0)
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
                        /* don't free decompressed or release block as  we're still using the
                         * deserialized data */
                        return TDB_SUCCESS;
                    }
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
     * L1: base * T^0 = base
     * L2: base * T^1 = base * T
     * L3: base * T^2 = base * T^2
     * will be adjusted by DCA once data is written */
    size_t capacity = base_capacity;
    for (int i = 1; i < level_num; i++)
    {
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
    TDB_DEBUG_LOG("tidesdb_add_level called for CF '%s'", cf->name);
    TDB_DEBUG_LOG("DCA: add_level starting");

    int old_num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* check if we've hit max levels */
    if (old_num_levels >= TDB_MAX_LEVELS)
    {
        TDB_DEBUG_LOG("DCA: Cannot add level - already at max (%d)", TDB_MAX_LEVELS);
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
     * largest to new largest during level addition. we intentionally do NOT do this
     * because it causes key loss and breaks the LSM-tree structure. instead, we let
     * normal compaction move data down, which is simpler and correct. */
    TDB_DEBUG_LOG("DCA: Added empty level %d, old largest level %d keeps its data",
                  new_level->level_num, old_num_levels);

    /* atomically increment active level count -- this publishes the new level
     * release ordering ensures the new level is visible to other threads */
    atomic_store_explicit(&cf->num_active_levels, old_num_levels + 1, memory_order_release);

    TDB_DEBUG_LOG("DCA: Published %d active levels", old_num_levels + 1);
    for (int log_i = 0; log_i < old_num_levels + 1; log_i++)
    {
        tidesdb_level_t *log_lvl = cf->levels[log_i];
        if (log_lvl)
        {
            int log_num = atomic_load_explicit(&log_lvl->num_sstables, memory_order_acquire);
            TDB_DEBUG_LOG("DCA: levels[%d]: level_num=%d, %d SSTables", log_i, log_lvl->level_num,
                          log_num);
        }
    }

    atomic_thread_fence(memory_order_seq_cst);

    TDB_DEBUG_LOG("DCA: add_level complete");

    TDB_DEBUG_LOG("Added level %d, now have %d levels", new_level->level_num, old_num_levels + 1);

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
    TDB_DEBUG_LOG("tidesdb_remove_level called for CF '%s'", cf->name);


    int old_num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* enforce minimum levels! never go below min_levels */
    if (old_num_levels <= cf->config.min_levels)
    {
        TDB_DEBUG_LOG("tidesdb_remove_level: At minimum levels (%d <= %d), not removing",
                      old_num_levels, cf->config.min_levels);
        return TDB_SUCCESS; /* not an error, just at minimum */
    }

    tidesdb_level_t *largest = cf->levels[old_num_levels - 1];
    int num_largest_ssts = atomic_load_explicit(&largest->num_sstables, memory_order_acquire);

    /* only remove level if it's completely empty */
    if (num_largest_ssts > 0)
    {
        TDB_DEBUG_LOG("DCA: Cannot remove level %d - has %d SSTables", largest->level_num,
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

        /* ensure capacity doesn't become zero */
        if (new_largest_capacity < cf->config.write_buffer_size)
        {
            new_largest_capacity = cf->config.write_buffer_size;
        }

        atomic_store_explicit(&new_largest->capacity, new_largest_capacity, memory_order_release);
        TDB_DEBUG_LOG("Updated new largest level %d capacity to %zu", new_largest->level_num,
                      new_largest_capacity);
    }

    /* free the largest level struct */
    TDB_DEBUG_LOG("DCA: Freeing removed level %d (num_sstables=%d, current_size=%zu)",
                  largest->level_num,
                  atomic_load_explicit(&largest->num_sstables, memory_order_acquire),
                  atomic_load_explicit(&largest->current_size, memory_order_relaxed));
    tidesdb_level_free(cf->db, largest);
    cf->levels[old_num_levels - 1] = NULL;

    /* atomically decrement active level count
     * release ordering ensures the level removal is visible to other threads */
    atomic_store_explicit(&cf->num_active_levels, new_num_levels, memory_order_release);

    atomic_thread_fence(memory_order_seq_cst);

    TDB_DEBUG_LOG("Removed level, now have %d levels", new_num_levels);

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
     * paper uses 1-based level numbering (Level 1, 2, 3...)
     * we use 0-based array indexing (levels[0], levels[1], levels[2]...)
     * so we adjust: for array index i, the level number is i+1
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

        /* ensure capacity doesn't become zero */
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

    TDB_DEBUG_LOG("Starting full preemptive merge: CF '%s', levels %d->%d", cf->name, start_level,
                  target_level + 1);

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

    tidesdb_wait_for_dca(cf);

    /* count total sstables first */
    int total_ssts = 0;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        total_ssts += lvl->num_sstables;
    }

    /* if no sstables to merge, return early */
    if (total_ssts == 0)
    {
        TDB_DEBUG_LOG("Full preemptive merge: No SSTables to merge, skipping");
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        return TDB_SUCCESS;
    }

    /* allocate array to hold sstable pointers */
    tidesdb_sstable_t **ssts_array = malloc(total_ssts * sizeof(tidesdb_sstable_t *));
    if (!ssts_array)
    {
        tidesdb_merge_heap_free(heap);
        queue_free(sstables_to_delete);
        return TDB_ERR_MEMORY;
    }

    /* collect sstable pointers and take references */
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

            tidesdb_sstable_ref(sst); /* take reference on sstable */
            ssts_array[sst_idx++] = sst;
        }
    }

    for (int i = 0; i < sst_idx; i++)
    {
        tidesdb_sstable_t *sst = ssts_array[i];

        tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
        if (source)
        {
            if (source->current_kv)
            {
                if (tidesdb_merge_heap_add_source(heap, source) != TDB_SUCCESS)
                {
                    /* failed to add source to heap, free it to prevent leak */
                    tidesdb_merge_source_free(source);
                }
            }
            else
            {
                tidesdb_merge_source_free(source);
            }
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

    if (estimated_entries < 100) estimated_entries = 100;

    bloom_filter_t *bloom = NULL;
    tidesdb_block_index_t *block_indexes = NULL;

    if (new_sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, new_sst->config->bloom_fpr, estimated_entries) == 0)
        {
            TDB_DEBUG_LOG("Full preemptive merge: Bloom filter created (estimated entries: %" PRIu64
                          ")",
                          estimated_entries);
        }
        else
        {
            TDB_DEBUG_LOG("Full preemptive merge: Bloom filter creation failed");
            bloom = NULL;
        }
    }
    else
    {
        TDB_DEBUG_LOG("Full preemptive merge: Bloom filter disabled");
    }

    if (new_sst->config->enable_block_indexes)
    {
        block_indexes =
            compact_block_index_create(estimated_entries, comparator_fn, comparator_ctx);
        if (block_indexes)
        {
            TDB_DEBUG_LOG("Full preemptive merge: Block indexes created");
        }
        else
        {
            TDB_DEBUG_LOG("Full preemptive merge: Block indexes builder creation failed");
        }
    }
    else
    {
        TDB_DEBUG_LOG("Full preemptive merge: Block indexes disabled");
    }

    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();
    tidesdb_vlog_block_t *current_vlog_block = tidesdb_vlog_block_create();

    uint64_t klog_block_num = 0;
    uint64_t vlog_block_num = 0;
    uint64_t current_vlog_file_offset = 0;
    uint64_t entry_count = 0;
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
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap);
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
        if (kv->entry.ttl > 0 && kv->entry.ttl < time(NULL))
        {
            tidesdb_kv_pair_free(kv);
            continue;
        }

        if (kv->entry.value_size >= cf->config.value_threshold && kv->value)
        {
            if (tidesdb_vlog_block_is_full(current_vlog_block, cf->config.vlog_block_size))
            {
                uint8_t *vlog_data;
                size_t vlog_size;
                if (tidesdb_vlog_block_serialize(current_vlog_block, &vlog_data, &vlog_size) == 0)
                {
                    uint8_t *final_data = vlog_data;
                    size_t final_size = vlog_size;

                    if (new_sst->config->compression_algorithm != NO_COMPRESSION)
                    {
                        size_t compressed_size;
                        uint8_t *compressed = compress_data(vlog_data, vlog_size, &compressed_size,
                                                            new_sst->config->compression_algorithm);
                        if (compressed)
                        {
                            free(vlog_data);
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *vlog_block =
                        block_manager_block_create(final_size, final_data);
                    if (vlog_block)
                    {
                        block_manager_block_write(vlog_bm, vlog_block);
                        block_manager_block_release(vlog_block);
                        current_vlog_file_offset += vlog_size;
                        vlog_block_num++;
                    }
                    free(final_data);
                }

                tidesdb_vlog_block_free(current_vlog_block);
                current_vlog_block = tidesdb_vlog_block_create();
            }

            uint64_t offset_in_block;
            if (tidesdb_vlog_block_add_value(current_vlog_block, kv->value, kv->entry.value_size,
                                             &offset_in_block) == 0)
            {
                kv->entry.vlog_offset =
                    current_vlog_file_offset +
                    offset_in_block; /* will be adjusted with file offset later */
            }
        }

        if (tidesdb_klog_block_is_full(current_klog_block, cf->config.klog_block_size))
        {
            /* add completed block to index before writing */
            if (block_indexes && block_first_key && block_last_key)
            {
                if (cf->config.index_sample_ratio <= 1 ||
                    (klog_block_num % cf->config.index_sample_ratio == 0))
                {
                    compact_block_index_add(block_indexes, block_first_key, block_first_key_size,
                                            block_last_key, block_last_key_size, klog_block_num);
                }
            }

            uint8_t *klog_data;
            size_t klog_size;
            if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
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

                block_manager_block_t *klog_block =
                    block_manager_block_create(final_size, final_data);
                if (klog_block)
                {
                    block_manager_block_write(klog_bm, klog_block);
                    block_manager_block_release(klog_block);
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

        /* check if this is the first entry in a new block */
        int is_first_entry_in_block = (current_klog_block->num_entries == 0);

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
        entry_count++;

        tidesdb_kv_pair_free(kv);
    }

    new_sst->max_seq = max_seq;

    free(last_key);

    if (current_klog_block->num_entries > 0)
    {
        /* add final block to index */
        if (block_indexes && block_first_key && block_last_key)
        {
            if (cf->config.index_sample_ratio <= 1 ||
                (klog_block_num % cf->config.index_sample_ratio == 0))
            {
                compact_block_index_add(block_indexes, block_first_key, block_first_key_size,
                                        block_last_key, block_last_key_size, klog_block_num);
            }
        }

        uint8_t *klog_data;
        size_t klog_size;
        if (tidesdb_klog_block_serialize(current_klog_block, &klog_data, &klog_size) == 0)
        {
            if (new_sst->config->compression_algorithm != NO_COMPRESSION)
            {
                size_t compressed_size;
                uint8_t *compressed = compress_data(klog_data, klog_size, &compressed_size,
                                                    new_sst->config->compression_algorithm);
                if (compressed)
                {
                    free(klog_data);
                    klog_data = compressed;
                    klog_size = compressed_size;
                }
            }

            block_manager_block_t *klog_block = block_manager_block_create(klog_size, klog_data);
            if (klog_block)
            {
                block_manager_block_write(klog_bm, klog_block);
                block_manager_block_release(klog_block);
                klog_block_num++;
            }
            free(klog_data);
        }
    }

    /* cleanup block tracking */
    free(block_first_key);
    free(block_last_key);

    if (current_vlog_block->num_values > 0)
    {
        uint8_t *vlog_data;
        size_t vlog_size;
        if (tidesdb_vlog_block_serialize(current_vlog_block, &vlog_data, &vlog_size) == 0)
        {
            if (new_sst->config->compression_algorithm != NO_COMPRESSION)
            {
                size_t compressed_size;
                uint8_t *compressed = compress_data(vlog_data, vlog_size, &compressed_size,
                                                    new_sst->config->compression_algorithm);
                if (compressed)
                {
                    free(vlog_data);
                    vlog_data = compressed;
                    vlog_size = compressed_size;
                }
            }

            block_manager_block_t *vlog_block = block_manager_block_create(vlog_size, vlog_data);
            if (vlog_block)
            {
                block_manager_block_write(vlog_bm, vlog_block);
                block_manager_block_release(vlog_block);
                vlog_block_num++;
            }
            free(vlog_data);
        }
    }

    tidesdb_klog_block_free(current_klog_block);
    tidesdb_vlog_block_free(current_vlog_block);

    new_sst->num_klog_blocks = klog_block_num;
    new_sst->num_vlog_blocks = vlog_block_num;

    block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

    /* only write auxiliary structures if we have entries */
    if (new_sst->num_entries > 0 && block_indexes)
    {
        /* we assign the built index to the sstable */
        new_sst->block_indexes = block_indexes;

        TDB_DEBUG_LOG("Full preemptive merge: Block index built with %u samples",
                      new_sst->block_indexes->count);
        size_t index_size;
        uint8_t *index_data = compact_block_index_serialize(new_sst->block_indexes, &index_size);
        if (index_data)
        {
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(klog_bm, index_block);
                block_manager_block_release(index_block);
            }
            free(index_data);
        }
    }

    if (new_sst->num_entries > 0 && bloom)
    {
        size_t bloom_size;
        uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
        if (bloom_data)
        {
            TDB_DEBUG_LOG("Full preemptive merge: Bloom filter serialized to %zu bytes",
                          bloom_size);
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(klog_bm, bloom_block);
                block_manager_block_release(bloom_block);
            }
            free(bloom_data);
        }
        else
        {
            TDB_DEBUG_LOG("Full preemptive merge: Bloom filter serialization failed");
        }
        new_sst->bloom_filter = bloom;
    }

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

    block_manager_get_size(klog_bm, &new_sst->klog_size);
    block_manager_get_size(vlog_bm, &new_sst->vlog_size);

    tidesdb_merge_heap_free(heap);

    /* we lways sync compacted sstable files regardless of sync_mode
     * new sstable durability is required before we can delete old sstables */
    block_manager_escalate_fsync(klog_bm);
    block_manager_escalate_fsync(vlog_bm);

    block_manager_close(klog_bm);
    block_manager_close(vlog_bm);

    /* ensure all writes are visible before making sstable discoverable */
    atomic_thread_fence(memory_order_seq_cst);

    /* save metadata for logging before potentially freeing sstable */
    uint64_t sst_id = new_sst->id;
    uint64_t num_entries = new_sst->num_entries;
    uint64_t num_klog_blocks = new_sst->num_klog_blocks;
    uint64_t num_vlog_blocks = new_sst->num_vlog_blocks;

    /* only add sstable if it has entries -- empty sstables cause corruption */
    if (num_entries > 0)
    {
        /* wait for any DCA operation to complete before accessing levels */
        tidesdb_wait_for_dca(cf);

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
            TDB_DEBUG_LOG(
                "Full preemptive merge: Target level %d not found (current_num_levels=%d)",
                target_level_num, num_levels);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
        else
        {
            TDB_DEBUG_LOG("Full preemptive merge: Adding merged SSTable %" PRIu64
                          " to level %d (array index %d)",
                          new_sst->id, cf->levels[target_idx]->level_num, target_idx);
            tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
    }
    else
    {
        TDB_DEBUG_LOG("Full preemptive merge: Skipping empty SSTable %" PRIu64 " (0 entries)",
                      sst_id);
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

        /* wait for any DCA operation to complete before accessing levels */
        tidesdb_wait_for_dca(cf);

        /* reload levels for removal */
        num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

        /* mark for deletion before removing from levels to avoid use-after-free */
        atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

        /* find which level this sst belongs to and remove it -- break on first success */
        int removed = 0;
        for (int level = start_level; level <= target_level && level < num_levels; level++)
        {
            tidesdb_level_t *lvl = cf->levels[level];
            int result = tidesdb_level_remove_sstable(cf->db, lvl, sst);
            if (result == TDB_SUCCESS)
            {
                TDB_DEBUG_LOG("Full preemptive merge: Removed SSTable %" PRIu64 " from level %d",
                              sst->id, lvl->level_num);
                removed = 1;
                break; /* found and removed, no need to check other levels */
            }
        }
        if (!removed)
        {
            TDB_DEBUG_LOG("Full preemptive merge: WARNING - SSTable %" PRIu64
                          " not found in any level!",
                          sst->id);
        }

        /* release the reference we took when collecting sstables */
        tidesdb_sstable_unref(cf->db, sst);
    }

    queue_free(sstables_to_delete);

    TDB_DEBUG_LOG("Full preemptive merge complete: CF '%s', created SSTable %" PRIu64
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

    TDB_DEBUG_LOG("Starting dividing merge: CF '%s', target_level=%d", cf->name, target_level + 1);

    if (target_level >= num_levels - 1)
    {
        TDB_DEBUG_LOG("Target level %d is the largest level, need to add new level before merge",
                      target_level);

        /* ensure there's a level to merge into */
        if (target_level + 1 >= num_levels)
        {
            int add_result = tidesdb_add_level(cf);
            if (add_result != TDB_SUCCESS)
            {
                TDB_DEBUG_LOG("Failed to add level before merge, error: %d", add_result);
                return add_result;
            }

            num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

            TDB_DEBUG_LOG("Added level, now have %d levels", num_levels);
        }

        return tidesdb_full_preemptive_merge(cf, 0, target_level);
    }

    tidesdb_wait_for_dca(cf);

    tidesdb_level_t *target = cf->levels[target_level];
    /** dividing merge:
     * use boundaries from target_level+1 (the level we're merging into) */
    tidesdb_level_t *next_level = cf->levels[target_level + 1];

    tidesdb_level_update_boundaries(target, next_level);

    /* Load count before array to prevent TOCTOU race */
    int next_level_num_ssts = atomic_load_explicit(&next_level->num_sstables, memory_order_acquire);
    TDB_DEBUG_LOG("Dividing merge: next_level (L%d) has %d SSTables", next_level->level_num,
                  next_level_num_ssts);
    tidesdb_sstable_t **next_level_ssts =
        atomic_load_explicit(&next_level->sstables, memory_order_acquire);
    for (int i = 0; i < next_level_num_ssts; i++)
    {
        tidesdb_sstable_t *sst = next_level_ssts[i];
        if (sst)
        {
            TDB_DEBUG_LOG("Dividing merge: next_level SSTable %" PRIu64 " min=%s max=%s", sst->id,
                          sst->min_key ? (char *)sst->min_key : "NULL",
                          sst->max_key ? (char *)sst->max_key : "NULL");
        }
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    queue_t *sstables_to_delete = queue_new();

    tidesdb_wait_for_dca(cf);

    /* collect all sstables to delete (take references) */
    TDB_DEBUG_LOG("Dividing merge: collecting SSTables from levels 0-%d", target_level);
    for (int level = 0; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        TDB_DEBUG_LOG("Dividing merge: L%d has %d SSTables", level, num_ssts);
        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            if (!sst) continue;

            TDB_DEBUG_LOG("Dividing merge: collecting SSTable %" PRIu64
                          " from L%d (min=%s, max=%s)",
                          sst->id, level, sst->min_key ? (char *)sst->min_key : "NULL",
                          sst->max_key ? (char *)sst->max_key : "NULL");
            tidesdb_sstable_ref(sst);
            queue_enqueue(sstables_to_delete, sst);
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
    if (partition_estimated_entries < 100) partition_estimated_entries = 100;

    for (int partition = 0; partition < num_partitions; partition++)
    {
        /* create separate heap for this partition to avoid data loss */
        tidesdb_merge_heap_t *partition_heap =
            tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
        if (!partition_heap)
        {
            TDB_DEBUG_LOG("Dividing merge: Failed to create heap for partition %d", partition);
            continue;
        }

        /* determine key range for this partition */
        uint8_t *range_start = (partition > 0) ? file_boundaries[partition - 1] : NULL;
        size_t range_start_size = (partition > 0) ? boundary_sizes[partition - 1] : 0;
        uint8_t *range_end = (partition < num_boundaries) ? file_boundaries[partition] : NULL;
        size_t range_end_size = (partition < num_boundaries) ? boundary_sizes[partition] : 0;

        TDB_DEBUG_LOG("Dividing merge partition %d: range [%s, %s)", partition,
                      range_start ? (char *)range_start : "NULL",
                      range_end ? (char *)range_end : "NULL");

        /* add only overlapping sstables to this partition's heap */
        uint64_t partition_estimated_entries = 0;
        size_t num_sstables_to_merge = queue_size(sstables_to_delete);
        for (size_t i = 0; i < num_sstables_to_merge; i++)
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
                TDB_DEBUG_LOG("Dividing merge partition %d: SSTable %" PRIu64
                              " overlaps (min=%s, max=%s)",
                              partition, sst->id, sst->min_key ? (char *)sst->min_key : "NULL",
                              sst->max_key ? (char *)sst->max_key : "NULL");
                tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
                if (source)
                {
                    if (source->current_kv)
                    {
                        if (tidesdb_merge_heap_add_source(partition_heap, source) == TDB_SUCCESS)
                        {
                            partition_estimated_entries += sst->num_entries;
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

        if (partition_estimated_entries < 100) partition_estimated_entries = 100;

        if (tidesdb_merge_heap_empty(partition_heap))
        {
            TDB_DEBUG_LOG(
                "Dividing merge partition %d: Skipping empty partition (no overlapping SSTables)",
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
        tidesdb_vlog_block_t *vlog_block = tidesdb_vlog_block_create();

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
            if (bloom_filter_new(&bloom, cf->config.bloom_fpr, partition_estimated_entries) == 0)
            {
                TDB_DEBUG_LOG(
                    "Dividing merge partition %d: Bloom filter created (estimated entries: %" PRIu64
                    ")",
                    partition, partition_estimated_entries);
            }
            else
            {
                TDB_DEBUG_LOG("Dividing merge partition %d: Bloom filter creation failed",
                              partition);
                bloom = NULL;
            }
        }

        if (cf->config.enable_block_indexes)
        {
            block_indexes = compact_block_index_create(partition_estimated_entries, comparator_fn,
                                                       comparator_ctx);
        }

        /* process entries from partition-specific heap -- all keys are guaranteed to be in range */
        while (!tidesdb_merge_heap_empty(partition_heap))
        {
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(partition_heap);
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
            if (kv->entry.ttl > 0 && kv->entry.ttl < time(NULL))
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

            /* handle large values in vlog */
            if (kv->entry.value_size >= cf->config.value_threshold &&
                !(kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) && kv->value)
            {
                /* check if vlog block is full */
                if (tidesdb_vlog_block_is_full(vlog_block, cf->config.vlog_block_size))
                {
                    /* serialize and write vlog block */
                    uint8_t *vlog_data;
                    size_t vlog_size;
                    if (tidesdb_vlog_block_serialize(vlog_block, &vlog_data, &vlog_size) == 0)
                    {
                        block_manager_block_t *vblock =
                            block_manager_block_create(vlog_size, vlog_data);
                        if (vblock)
                        {
                            block_manager_block_write(vlog_bm, vblock);
                            block_manager_block_release(vblock);
                            vlog_block_num++;
                        }
                        free(vlog_data);
                    }

                    /* create new vlog block */
                    tidesdb_vlog_block_free(vlog_block);
                    vlog_block = tidesdb_vlog_block_create();
                }

                uint64_t offset_in_block;
                tidesdb_vlog_block_add_value(vlog_block, kv->value, kv->entry.value_size,
                                             &offset_in_block);
                kv->entry.vlog_offset =
                    offset_in_block; /* will be adjusted with file offset later */
            }

            if (tidesdb_klog_block_is_full(klog_block, cf->config.klog_block_size))
            {
                /* add completed block to index before writing */
                if (block_indexes && block_first_key && block_last_key)
                {
                    if (cf->config.index_sample_ratio <= 1 ||
                        (klog_block_num % cf->config.index_sample_ratio == 0))
                    {
                        compact_block_index_add(block_indexes, block_first_key,
                                                block_first_key_size, block_last_key,
                                                block_last_key_size, klog_block_num);
                    }
                }

                /* serialize and write klog block */
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

                    block_manager_block_t *kblock =
                        block_manager_block_create(final_klog_size, final_klog_data);
                    if (kblock)
                    {
                        block_manager_block_write(klog_bm, kblock);
                        block_manager_block_release(kblock);
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

            /* check if this is the first entry in a new block */
            int is_first_entry_in_block = (klog_block->num_entries == 0);

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

            tidesdb_kv_pair_free(kv);
        }

        /* free partition heap */
        tidesdb_merge_heap_free(partition_heap);

        /* write remaining vlog block if it has data */
        if (vlog_block->num_values > 0)
        {
            uint8_t *vlog_data;
            size_t vlog_size;
            if (tidesdb_vlog_block_serialize(vlog_block, &vlog_data, &vlog_size) == 0)
            {
                uint8_t *final_vlog_data = vlog_data;
                size_t final_vlog_size = vlog_size;

                if (cf->config.compression_algorithm != NO_COMPRESSION)
                {
                    size_t compressed_size;
                    uint8_t *compressed = compress_data(vlog_data, vlog_size, &compressed_size,
                                                        cf->config.compression_algorithm);
                    if (compressed)
                    {
                        free(vlog_data);
                        final_vlog_data = compressed;
                        final_vlog_size = compressed_size;
                    }
                }

                block_manager_block_t *vblock =
                    block_manager_block_create(final_vlog_size, final_vlog_data);
                if (vblock)
                {
                    block_manager_block_write(vlog_bm, vblock);
                    block_manager_block_release(vblock);
                    vlog_block_num++;
                }
                free(final_vlog_data);
            }
        }

        tidesdb_vlog_block_free(vlog_block);

        /* write remaining klog block if it has data */
        if (klog_block->num_entries > 0)
        {
            /* add final block to index */
            if (block_indexes && block_first_key && block_last_key)
            {
                if (cf->config.index_sample_ratio <= 1 ||
                    (klog_block_num % cf->config.index_sample_ratio == 0))
                {
                    compact_block_index_add(block_indexes, block_first_key, block_first_key_size,
                                            block_last_key, block_last_key_size, klog_block_num);
                }
            }

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
                    block_manager_block_write(klog_bm, block);
                    block_manager_block_release(block);
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

        /* write index - only if we have entries */
        if (entry_count > 0 && block_indexes)
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

        if (entry_count > 0 && bloom)
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

        block_manager_get_size(klog_bm, &new_sst->klog_size);
        block_manager_get_size(vlog_bm, &new_sst->vlog_size);

        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);

        /* ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* add to target level */
        TDB_DEBUG_LOG("Dividing merge partition %d: Merged %" PRIu64 " entries", partition,
                      entry_count);

        if (entry_count > 0)
        {
            /* wait for any DCA operation to complete before accessing levels */
            tidesdb_wait_for_dca(cf);

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
                TDB_DEBUG_LOG(
                    "Dividing merge partition %d: Target level %d not found "
                    "(current_num_levels=%d)",
                    partition, target_level_num, current_num_levels);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
            else
            {
                TDB_DEBUG_LOG("Dividing merge partition %d: Adding merged SSTable %" PRIu64
                              " to level %d (array index %d)",
                              partition, new_sst->id, cf->levels[target_idx]->level_num,
                              target_idx);
                tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }
        else
        {
            TDB_DEBUG_LOG("Dividing merge partition %d: Skipping empty SSTable %" PRIu64
                          " (0 entries)",
                          partition, new_sst->id);

            /* free bloom and block_indexes since they won't be freed by sstable_unref */
            if (bloom) bloom_filter_free(bloom);
            if (block_indexes) compact_block_index_free(block_indexes);

            /* delete the empty sstable files */
            remove(new_sst->klog_path);
            remove(new_sst->vlog_path);
            tidesdb_sstable_unref(cf->db, new_sst);
        }
    }

    tidesdb_wait_for_dca(cf);

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
            for (int level = 0; level <= target_level && level < current_num_levels; level++)
            {
                int result = tidesdb_level_remove_sstable(cf->db, cf->levels[level], sst);
                if (result == TDB_SUCCESS)
                {
                    break; /* found and removed, no need to check other levels */
                }
            }

            /* release the reference we took when collecting sstables */
            tidesdb_sstable_unref(cf->db, sst);
        }
    }

    queue_free(sstables_to_delete);

    TDB_DEBUG_LOG("Completed dividing merge for CF '%s'", cf->name);
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

    TDB_DEBUG_LOG("Starting partitioned merge: CF '%s', levels %d->%d (array indices %d->%d)",
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

    /* now collect sstables to delete after merge completes */
    queue_t *sstables_to_delete = queue_new();

    for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
    {
        tidesdb_level_t *lvl = cf->levels[level_idx];
        int num_ssts = atomic_load_explicit(&lvl->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&lvl->sstables, memory_order_acquire);

        for (int i = 0; i < num_ssts; i++)
        {
            if (!sstables[i]) continue;

            tidesdb_sstable_ref(sstables[i]);
            queue_enqueue(sstables_to_delete, sstables[i]);
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
        TDB_DEBUG_LOG("Partitioned merge: Processing partition %d/%d", partition + 1,
                      num_partitions);

        skip_list_comparator_fn comparator_fn = NULL;
        void *comparator_ctx = NULL;
        tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

        tidesdb_merge_heap_t *heap = tidesdb_merge_heap_create(comparator_fn, comparator_ctx);
        if (!heap)
        {
            TDB_DEBUG_LOG("Partitioned merge: Failed to create merge heap for partition %d",
                          partition);
            continue;
        }

        uint8_t *range_start = boundaries[partition];
        size_t range_start_size = boundary_sizes[partition];
        uint8_t *range_end = (partition + 1 < num_partitions) ? boundaries[partition + 1] : NULL;
        size_t range_end_size =
            (partition + 1 < num_partitions) ? boundary_sizes[partition + 1] : 0;

        /* add overlapping ssts as sources and calculate estimated entries */
        uint64_t estimated_entries = 0;

        /* wait for any DCA operation to complete before accessing levels */
        tidesdb_wait_for_dca(cf);

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
                /* if sstable doesn't overlap, we don't need to do anything */
            }
        }

        /* use a minimum of 100 entries to avoid degenerate bloom filters */
        if (estimated_entries < 100) estimated_entries = 100;

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
                        "Partitioned merge partition %d: Bloom filter created (estimated entries: "
                        "%" PRIu64 ")",
                        partition, estimated_entries);
                }
                else
                {
                    TDB_DEBUG_LOG("Partitioned merge partition %d: Bloom filter creation failed",
                                  partition);
                    bloom = NULL;
                }
            }

            if (cf->config.enable_block_indexes)
            {
                /* reuse comparator_fn and comparator_ctx from outer scope */
                block_indexes =
                    compact_block_index_create(estimated_entries, comparator_fn, comparator_ctx);
            }

            /* merge and write entries in partition range */
            tidesdb_klog_block_t *klog_block = tidesdb_klog_block_create();
            tidesdb_vlog_block_t *vlog_block = tidesdb_vlog_block_create();
            uint64_t entry_count = 0;
            uint64_t vlog_file_offset = 0;
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
                tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap);
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

                if (kv->entry.ttl > 0 && kv->entry.ttl < time(NULL))
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

                if (kv->entry.value_size >= cf->config.value_threshold && kv->value)
                {
                    if (tidesdb_vlog_block_is_full(vlog_block, cf->config.vlog_block_size))
                    {
                        uint8_t *vlog_data;
                        size_t vlog_size;
                        if (tidesdb_vlog_block_serialize(vlog_block, &vlog_data, &vlog_size) == 0)
                        {
                            uint8_t *final_data = vlog_data;
                            size_t final_size = vlog_size;

                            if (cf->config.compression_algorithm != NO_COMPRESSION)
                            {
                                size_t compressed_size;
                                uint8_t *compressed =
                                    compress_data(vlog_data, vlog_size, &compressed_size,
                                                  cf->config.compression_algorithm);
                                if (compressed)
                                {
                                    free(vlog_data);
                                    final_data = compressed;
                                    final_size = compressed_size;
                                }
                            }

                            block_manager_block_t *vblock =
                                block_manager_block_create(final_size, final_data);
                            if (vblock)
                            {
                                block_manager_block_write(vlog_bm, vblock);
                                block_manager_block_release(vblock);
                                vlog_file_offset += vlog_size;
                                vlog_block_num++;
                            }
                            free(final_data);
                        }

                        tidesdb_vlog_block_free(vlog_block);
                        vlog_block = tidesdb_vlog_block_create();
                    }

                    uint64_t offset_in_block;
                    tidesdb_vlog_block_add_value(vlog_block, kv->value, kv->entry.value_size,
                                                 &offset_in_block);
                    kv->entry.vlog_offset =
                        vlog_file_offset +
                        offset_in_block; /* will be adjusted with file offset later */
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
                if (tidesdb_klog_block_is_full(klog_block, cf->config.klog_block_size))
                {
                    /* add completed block to index before writing */
                    if (block_indexes && block_first_key && block_last_key)
                    {
                        if (cf->config.index_sample_ratio <= 1 ||
                            (klog_block_num % cf->config.index_sample_ratio == 0))
                        {
                            compact_block_index_add(block_indexes, block_first_key,
                                                    block_first_key_size, block_last_key,
                                                    block_last_key_size, klog_block_num);
                        }
                    }

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
                            int64_t offset = block_manager_block_write(klog_bm, block);
                            (void)offset; /* unused but kept for debugging */
                            block_manager_block_release(block);
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

            /* write remaining vlog block */
            if (vlog_block->num_values > 0)
            {
                uint8_t *vlog_data;
                size_t vlog_size;
                if (tidesdb_vlog_block_serialize(vlog_block, &vlog_data, &vlog_size) == 0)
                {
                    uint8_t *final_data = vlog_data;
                    size_t final_size = vlog_size;

                    if (new_sst->config->compression_algorithm != NO_COMPRESSION)
                    {
                        size_t compressed_size;
                        uint8_t *compressed = compress_data(vlog_data, vlog_size, &compressed_size,
                                                            new_sst->config->compression_algorithm);
                        if (compressed)
                        {
                            free(vlog_data);
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *vblock =
                        block_manager_block_create(final_size, final_data);
                    if (vblock)
                    {
                        block_manager_block_write(vlog_bm, vblock);
                        block_manager_block_release(vblock);
                        vlog_block_num++;
                    }
                    free(final_data);
                }
            }
            tidesdb_vlog_block_free(vlog_block);

            /* write remaining block */
            if (klog_block->num_entries > 0)
            {
                /* add final block to index */
                if (block_indexes && block_first_key && block_last_key)
                {
                    if (cf->config.index_sample_ratio <= 1 ||
                        (klog_block_num % cf->config.index_sample_ratio == 0))
                    {
                        compact_block_index_add(block_indexes, block_first_key,
                                                block_first_key_size, block_last_key,
                                                block_last_key_size, klog_block_num);
                    }
                }

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
                        block_manager_block_write(klog_bm, block);
                        block_manager_block_release(block);
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

            /* write index -- only if we have entries */
            if (entry_count > 0 && block_indexes)
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

            if (entry_count > 0 && bloom)
            {
                size_t bloom_size;
                uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
                if (bloom_data)
                {
                    TDB_DEBUG_LOG(
                        "Partitioned merge partition %d: Bloom filter serialized to %zu bytes",
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
                        "Partitioned merge partition %d: Bloom filter serialization failed",
                        partition);
                }
            }

            new_sst->bloom_filter = bloom;

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

            block_manager_get_size(klog_bm, &new_sst->klog_size);
            block_manager_get_size(vlog_bm, &new_sst->vlog_size);

            block_manager_close(klog_bm);
            block_manager_close(vlog_bm);

            /* ensure all writes are visible before making sstable discoverable */
            atomic_thread_fence(memory_order_seq_cst);

            /* add to level if not empty */
            if (entry_count > 0)
            {
                /* wait for any DCA operation to complete before accessing levels */
                tidesdb_wait_for_dca(cf);

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
                    TDB_DEBUG_LOG(
                        "Partitioned merge partition %d: Target level %d not found "
                        "(current_num_levels=%d), data would be lost!",
                        partition, target_level_num, current_num_levels);
                    tidesdb_sstable_unref(cf->db, new_sst);
                    tidesdb_merge_heap_free(heap);
                    continue;
                }

                tidesdb_level_add_sstable(cf->levels[target_idx], new_sst);

                TDB_DEBUG_LOG("Partitioned merge partition %d complete: Created SSTable %" PRIu64
                              " with %" PRIu64 " entries, %" PRIu64 " klog blocks, %" PRIu64
                              " vlog blocks",
                              partition, new_sst->id, new_sst->num_entries,
                              new_sst->num_klog_blocks, new_sst->num_vlog_blocks);

                tidesdb_sstable_unref(cf->db, new_sst);
            }
            else
            {
                TDB_DEBUG_LOG(
                    "Partitioned merge partition %d: No entries, skipping SSTable creation",
                    partition);
                /* delete the empty sstable files */
                remove(new_sst->klog_path);
                remove(new_sst->vlog_path);
                tidesdb_sstable_unref(cf->db, new_sst);
            }
        }

        tidesdb_merge_heap_free(heap);
    }

    /* wait for any DCA operation to complete before accessing levels */
    tidesdb_wait_for_dca(cf);

    /* reload for removal */

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        /* mark for deletion before removing from levels to avoid use-after-free */
        atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);

        /* try to remove from each level -- break on first success since each sst is only in one
         * level */
        for (int level_idx = start_idx; level_idx <= end_idx; level_idx++)
        {
            int result = tidesdb_level_remove_sstable(cf->db, cf->levels[level_idx], sst);
            if (result == TDB_SUCCESS)
            {
                break; /* found and removed, no need to check other levels */
            }
        }

        /* release the reference we took when collecting sstables */
        tidesdb_sstable_unref(cf->db, sst);
    }

    queue_free(sstables_to_delete);

    for (int i = 0; i < num_partitions; i++)
    {
        free(boundaries[i]);
    }
    free(boundaries);
    free(boundary_sizes);

    TDB_DEBUG_LOG("Partitioned merge complete: CF '%s', processed %d partitions", cf->name,
                  num_partitions);

    return TDB_SUCCESS;
}

/**
 * tidesdb_trigger_compaction
 * trigger compaction for a column family using the spooky algorithm
 *
 * spooky implementation notes:
 * - we implement the generalized spooky algorithm (section 4.2 of the paper)
 * - parameter X (dividing level) is configurable via dividing_level_offset
 * - we perform full preemptive merge at levels 0 to X-1
 * - we perform dividing merge into level X (partitioned by largest level boundaries)
 * - we perform partitioned preemptive merge at levels X to L when level X is full
 * - we use spooky algo 2 to find target levels (smallest level that cannot accommodate)
 *
 * key differences from paper:
 * - we use 0-based level indexing (paper uses 1-based)
 * - level 0 is memtable in paper, but we treat it as first disk level
 * - we don't implement file size balancing during partitioned merge yet
 * - we don't implement skew optimization (section 4.3) yet
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

    /* wait for any DCA operation to complete before accessing levels */
    tidesdb_wait_for_dca(cf);

    /* load num_levels atomically */
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG("Triggering compaction for column family: %s (levels: %d)", cf->name, num_levels);

    /* calculate X (dividing level) */
    int X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    TDB_DEBUG_LOG("Target compaction X %d", X);

    int target_lvl = X; /* default to X if no suitable level found */

    TDB_DEBUG_LOG("Calculating target compaction level (X=%d)", X);

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
            TDB_DEBUG_LOG("Target level %d: capacity=%zu < cumulative_size=%zu", q,
                          level_q_capacity, cumulative_size);
            break;
        }
    }

    TDB_DEBUG_LOG("Final target compaction level: %d", target_lvl);

    int result = TDB_SUCCESS;
    if (target_lvl < X)
    {
        TDB_DEBUG_LOG("Full preemptive merge: levels 0 to %d", target_lvl);
        result = tidesdb_full_preemptive_merge(cf, 0, target_lvl - 1); /* convert to 0-indexed */
    }
    else if (target_lvl == X)
    {
        TDB_DEBUG_LOG("Dividing merge at level %d", X);
        result = tidesdb_dividing_merge(cf, X - 1); /* convert to 0-indexed */
    }
    else
    {
        TDB_DEBUG_LOG("Warning: target_lvl > X, defaulting to dividing merge");
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
                    TDB_DEBUG_LOG("Partitioned merge target z=%d: capacity=%zu < cumulative=%zu",
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
        TDB_DEBUG_LOG("Level %d is full, triggering partitioned preemptive merge", X);
        TDB_DEBUG_LOG("Partitioned preemptive merge: levels %d to %d", X, z);
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
        TDB_DEBUG_LOG("Largest size: %zu Largest capacity %zu Number of levels %d", largest_size,
                      largest_capacity, num_levels);
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
     * we don't remove a level we just added in this same compaction cycle!
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
        int level0_sstables =
            (cf->levels[0] != NULL)
                ? atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire)
                : 0;

        if (pending_flushes == 0 && level0_sstables == 0)
        {
            TDB_DEBUG_LOG("Largest level is empty, removing level for CF '%s'", cf->name);
            tidesdb_remove_level(cf);
            num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        }
        else
        {
            TDB_DEBUG_LOG(
                "Largest level is empty but work pending (flushes: %zu, L0 sstables: %d), keeping "
                "level for CF '%s'",
                pending_flushes, level0_sstables, cf->name);
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
    block_manager_t *wal;
    if (block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        return TDB_ERR_IO;
    }

    /* resolve comparator for recovered memtable */
    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    if (tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx) != 0)
    {
        /* comparator not found, use default memcmp */
        comparator_fn = skip_list_comparator_memcmp;
        comparator_ctx = NULL;
    }

    if (skip_list_new_with_comparator(memtable, 32, 0.25f, comparator_fn, comparator_ctx) != 0)
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

    if (block_manager_cursor_goto_first(cursor) == 0)
    {
        do
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (!block) break;

            const uint8_t *ptr = block->data;
            size_t remaining = block->size;

            /* we check for multi-CF transaction metadata */
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
                            TDB_DEBUG_LOG(
                                "CF '%s': Multi-CF metadata checksum mismatch (expected: %" PRIu64
                                ", got: %" PRIu64 ") - skipping entry",
                                cf->name, peek_checksum, computed_checksum);
                            block_manager_block_release(block);
                            continue;
                        }
                    }
                    else
                    {
                        TDB_DEBUG_LOG(
                            "CF '%s': Failed to allocate memory for checksum verification - "
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

            if (remaining < sizeof(tidesdb_klog_entry_t))
            {
                block_manager_block_release(block);
                continue;
            }

            /* deserialize entry with proper endianness */
            tidesdb_klog_entry_t entry;
            entry.version = *ptr++;
            entry.flags = *ptr++;
            entry.key_size = decode_uint32_le_compat(ptr);
            ptr += sizeof(uint32_t);
            entry.value_size = decode_uint32_le_compat(ptr);
            ptr += sizeof(uint32_t);
            entry.ttl = decode_int64_le_compat(ptr);
            ptr += sizeof(int64_t);
            entry.seq = decode_uint64_le_compat(ptr);
            ptr += sizeof(uint64_t);
            entry.vlog_offset = decode_uint64_le_compat(ptr);
            ptr += sizeof(uint64_t);
            remaining -= sizeof(tidesdb_klog_entry_t);

            if (remaining < entry.key_size)
            {
                block_manager_block_release(block);
                continue;
            }

            uint8_t *key = (uint8_t *)ptr;
            ptr += entry.key_size;
            remaining -= entry.key_size;

            uint8_t *value = NULL;
            if (entry.value_size > 0)
            {
                if (remaining < entry.value_size)
                {
                    block_manager_block_release(block);
                    continue;
                }
                value = (uint8_t *)ptr;
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
                    skip_list_put_with_seq(*memtable, key, entry.key_size, NULL, 0, 0, entry.seq,
                                           1);
                }
                else
                {
                    skip_list_put_with_seq(*memtable, key, entry.key_size, value, entry.value_size,
                                           entry.ttl, entry.seq, 0);
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
            TDB_DEBUG_LOG("CF '%s': Cleaning immutable with refcount=%d", cf->name, refcount);
            tidesdb_immutable_memtable_unref(immutable);
            immutable_count++;
        }
    }
    if (immutable_count > 0)
    {
        TDB_DEBUG_LOG("CF '%s': Freed %d immutable memtables in CF cleanup", cf->name,
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

    TDB_DEBUG_LOG("Flush worker thread started");

    while (1)
    {
        /* check if database is closing before blocking on queue */
        if (!atomic_load(&db->is_open))
        {
            TDB_DEBUG_LOG("Flush worker: database closing, exiting loop");
            break;
        }

        TDB_DEBUG_LOG("Flush worker: waiting for work (queue size: %zu)",
                      queue_size(db->flush_queue));
        /* wait for work (blocking dequeue) */
        tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue_wait(db->flush_queue);

        if (!work)
        {
            /* NULL sentinel signals shutdown */
            TDB_DEBUG_LOG("Flush worker: received NULL work, exiting");
            break;
        }

        TDB_DEBUG_LOG("Flush worker: received work for SSTable %" PRIu64, work->sst_id);

        tidesdb_column_family_t *cf = work->cf;
        tidesdb_immutable_memtable_t *imm = work->imm;
        skip_list_t *memtable = imm->memtable;
        block_manager_t *wal = imm->wal;

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG("CF '%s': Insufficient disk space for flush (required: %" PRIu64
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
            TDB_DEBUG_LOG("CF '%s': SSTable %" PRIu64 " creation FAILED", cf->name, work->sst_id);

            /* clear is_flushing to allow retries */
            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

            /* cleanup WAL and immutable memtable on ssts creation failure */
            if (wal)
            {
                char *wal_path_to_delete = tdb_strdup(wal->file_path);
                block_manager_close(wal);
                imm->wal = NULL;
                unlink(wal_path_to_delete);
                free(wal_path_to_delete);
            }

            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        int write_result = tidesdb_sstable_write_from_memtable(db, sst, memtable);
        if (write_result != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG("CF '%s': SSTable %" PRIu64 " write FAILED (error: %d)", cf->name,
                          work->sst_id, write_result);

            /* clear is_flushing to allow retries */
            atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

            tidesdb_sstable_unref(cf->db, sst);

            if (wal)
            {
                char *wal_path_to_delete = tdb_strdup(wal->file_path);
                block_manager_close(wal);
                imm->wal = NULL;
                unlink(wal_path_to_delete);
                free(wal_path_to_delete);
            }

            tidesdb_immutable_memtable_unref(imm);
            free(work);
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

        /* add sstable to level 0 -- load levels atomically */
        tidesdb_wait_for_dca(cf);
        /* levels array is fixed, access directly */
        tidesdb_level_add_sstable(cf->levels[0], sst);

        atomic_thread_fence(memory_order_seq_cst);

        TDB_DEBUG_LOG("CF '%s': Flushed SSTable %" PRIu64 " to level %d (array index 0)", cf->name,
                      work->sst_id, cf->levels[0]->level_num);

        /* release our reference -- the level now owns it */
        tidesdb_sstable_unref(cf->db, sst);

        if (wal)
        {
            char *wal_path_to_delete = tdb_strdup(wal->file_path);
            block_manager_close(wal);
            imm->wal = NULL;
            unlink(wal_path_to_delete);
            free(wal_path_to_delete);
        }

        atomic_thread_fence(memory_order_seq_cst);

        atomic_store_explicit(&imm->flushed, 1, memory_order_release);

        /* release the work item's reference now that flush is complete */
        tidesdb_immutable_memtable_unref(imm);

        /* cleanup flushed immutables from queue if they have no active readers
         * we need to keep them in queue until all reads complete to maintain MVCC correctness */
        queue_t *temp_queue = queue_new();
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
                    int refcount =
                        atomic_load_explicit(&queued_imm->refcount, memory_order_acquire);

                    /* only remove if flushed and refcount is 1 (only queue holds reference)
                     * if refcount > 1, there are active reads -- must keep in queue */
                    if (is_flushed && refcount == 1)
                    {
                        /* safe to remove -- unref will free it */
                        tidesdb_immutable_memtable_unref(queued_imm);
                        cleaned++;
                    }
                    else
                    {
                        /* keep in queue -- either not flushed or has active readers */
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
                TDB_DEBUG_LOG("CF '%s': Cleaned up %d flushed immutable(s) with no active readers",
                              cf->name, cleaned);
            }
        }

        /* clear is_flushing flag now that flush is complete
         * this allows new flushes to be triggered */
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);

        tidesdb_wait_for_dca(cf);
        /* load num_levels first to match store order */
        int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

        if (num_levels > 0 && cf->levels[0])
        {
            size_t level0_size =
                atomic_load_explicit(&cf->levels[0]->current_size, memory_order_acquire);
            size_t level0_capacity =
                atomic_load_explicit(&cf->levels[0]->capacity, memory_order_acquire);

            /* trigger compaction if level 0 is at or above capacity */
            if (level0_size >= level0_capacity)
            {
                TDB_DEBUG_LOG(
                    "CF '%s': Level 0 full (size=%zu >= capacity=%zu), triggering compaction",
                    cf->name, level0_size, level0_capacity);
                tidesdb_compact(cf);
            }
        }

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

    TDB_DEBUG_LOG("Compaction worker thread started");

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

        if (cf == NULL) continue;

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG("CF '%s': Insufficient disk space for compaction (required: %" PRIu64
                          " bytes)",
                          cf->name, cf->config.min_disk_space);
            free(work);
            continue;
        }

        TDB_DEBUG_LOG("Compacting CF '%s'", cf->name);
        tidesdb_trigger_compaction(cf);

        free(work);
    }

    return NULL;
}

/**
 * tidesdb_sync_worker_thread
 * background thread that periodically syncs WAL files for CFs with TDB_SYNC_INTERVAL mode
 */
static void *tidesdb_sync_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;
    TDB_DEBUG_LOG("Sync worker thread started");

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

        if (min_interval == UINT64_MAX)
        {
            /* no CFs need interval syncing, sleep longer */
            usleep(NO_CF_SYNC_SLEEP_US);
            continue;
        }

        /* sleep for the minimum interval */
        usleep(min_interval);

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

    TDB_DEBUG_LOG("Sync worker thread stopped");
    return NULL;
}

int tidesdb_register_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn fn,
                                const char *ctx_str, void *ctx)
{
    if (!db || !name || !fn) return TDB_ERR_INVALID_ARGS;
    if (strlen(name) >= TDB_MAX_COMPARATOR_NAME) return TDB_ERR_INVALID_ARGS;

    pthread_mutex_lock(&db->comparators_lock);

    /* check for duplicate name */
    for (int i = 0; i < db->num_comparators; i++)
    {
        if (strcmp(db->comparators[i].name, name) == 0)
        {
            pthread_mutex_unlock(&db->comparators_lock);
            return TDB_ERR_INVALID_ARGS; /* duplicate name */
        }
    }

    /* expand capacity if needed */
    if (db->num_comparators >= db->comparators_capacity)
    {
        int new_capacity = db->comparators_capacity * 2;
        tidesdb_comparator_entry_t *new_array =
            realloc(db->comparators, new_capacity * sizeof(tidesdb_comparator_entry_t));
        if (!new_array)
        {
            pthread_mutex_unlock(&db->comparators_lock);
            return TDB_ERR_MEMORY;
        }
        db->comparators = new_array;
        db->comparators_capacity = new_capacity;
    }

    /* add new comparator */
    tidesdb_comparator_entry_t *entry = &db->comparators[db->num_comparators];
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

    db->num_comparators++;

    pthread_mutex_unlock(&db->comparators_lock);
    return TDB_SUCCESS;
}

int tidesdb_get_comparator(tidesdb_t *db, const char *name, skip_list_comparator_fn *fn, void **ctx)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    pthread_mutex_lock(&db->comparators_lock);

    for (int i = 0; i < db->num_comparators; i++)
    {
        if (strcmp(db->comparators[i].name, name) == 0)
        {
            if (fn) *fn = db->comparators[i].fn;
            if (ctx) *ctx = db->comparators[i].ctx;
            pthread_mutex_unlock(&db->comparators_lock);
            return TDB_SUCCESS;
        }
    }

    pthread_mutex_unlock(&db->comparators_lock);
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

    _tidesdb_debug_enabled = config->enable_debug_logging;
    TDB_DEBUG_LOG("Opening TidesDB: path=%s, debug=%s, workers=%d", config->db_path,
                  config->enable_debug_logging ? "on" : "off", config->num_compaction_threads);

    mkdir((*db)->db_path, 0755);

    (*db)->cf_capacity = 16;
    tidesdb_column_family_t **cfs = calloc((*db)->cf_capacity, sizeof(tidesdb_column_family_t *));
    if (!cfs)
    {
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    (*db)->column_families = cfs;
    (*db)->num_column_families = 0;

    if (pthread_rwlock_init(&(*db)->cf_list_lock, NULL) != 0)
    {
        free(cfs);
        queue_free((*db)->compaction_queue);
        queue_free((*db)->flush_queue);
        free((*db)->compaction_threads);
        free((*db)->flush_threads);
        lru_cache_free((*db)->sstable_cache);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    /* initialize comparator registry */
    (*db)->comparators_capacity = 8;
    (*db)->comparators = calloc((*db)->comparators_capacity, sizeof(tidesdb_comparator_entry_t));
    if (!(*db)->comparators)
    {
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    (*db)->num_comparators = 0;
    if (pthread_mutex_init(&(*db)->comparators_lock, NULL) != 0)
    {
        free((*db)->comparators);
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

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

    atomic_init(&(*db)->global_txn_seq, 0); /* global sequence for multi-CF transactions */
    atomic_init(&(*db)->next_txn_id, 1);    /* transaction ID counter (start at 1) */
    atomic_init(&(*db)->is_open, 1);        /* set to 1 before starting workers */

    uint64_t initial_space = 0;
    if (tdb_get_available_disk_space((*db)->db_path, &initial_space) == 0)
    {
        atomic_init(&(*db)->cached_available_disk_space, initial_space);
        TDB_DEBUG_LOG("Initial available disk space: %" PRIu64 " bytes", initial_space);
    }
    else
    {
        /* failed to get disk space, set to 0 to trigger checks */
        atomic_init(&(*db)->cached_available_disk_space, 0);
        TDB_DEBUG_LOG("Warning: Failed to get initial disk space");
    }
    atomic_init(&(*db)->last_disk_space_check, time(NULL));

    (*db)->total_memory = get_total_memory();
    (*db)->available_memory = get_available_memory();
    if ((*db)->total_memory > 0 && (*db)->available_memory > 0)
    {
        TDB_DEBUG_LOG("System memory: total=%" PRIu64 " bytes, available=%" PRIu64 " bytes",
                      (uint64_t)(*db)->total_memory, (uint64_t)(*db)->available_memory);
    }
    else
    {
        TDB_DEBUG_LOG("Failed to get system memory information");
        return TDB_ERR_MEMORY;
    }

    (*db)->sstable_cache = lru_cache_new(config->max_open_sstables);
    if (!(*db)->sstable_cache)
    {
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    if (config->block_cache_size > 0)
    {
        (*db)->block_cache = lru_cache_new(config->block_cache_size);
        if (!(*db)->block_cache)
        {
            lru_cache_free((*db)->sstable_cache);
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free((*db)->column_families);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
    }

    tidesdb_recover_database(*db);

    /* now start background workers;  they will wait for recovery_complete signal */
    (*db)->flush_threads = malloc(config->num_flush_threads * sizeof(pthread_t));
    if (!(*db)->flush_threads)
    {
        lru_cache_free((*db)->block_cache);
        lru_cache_free((*db)->sstable_cache);
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
            lru_cache_free((*db)->block_cache);
            lru_cache_free((*db)->sstable_cache);
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
        lru_cache_free((*db)->block_cache);
        lru_cache_free((*db)->sstable_cache);
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
            lru_cache_free((*db)->block_cache);
            lru_cache_free((*db)->sstable_cache);
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

    if (needs_sync_thread)
    {
        atomic_store(&(*db)->sync_thread_active, 1);
        pthread_mutex_init(&(*db)->sync_lock, NULL);
        if (pthread_create(&(*db)->sync_thread, NULL, tidesdb_sync_worker_thread, *db) != 0)
        {
            TDB_DEBUG_LOG("Failed to create sync worker thread");
            atomic_store(&(*db)->sync_thread_active, 0);
            pthread_mutex_destroy(&(*db)->sync_lock);
            /* non-fatal, continue without sync thread */
        }
        else
        {
            TDB_DEBUG_LOG("Sync worker thread created");
        }
    }
    else
    {
        atomic_store(&(*db)->sync_thread_active, 0);
    }

    /* database is already marked as open (set before worker thread creation)
     * recovery has queued all immutable memtables and flush work
     * workers are now running and will process the queued work
     * data in immutable memtables is immediately readable */
    TDB_DEBUG_LOG("Database is now open and ready for operations");

    return TDB_SUCCESS;
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Closing TidesDB at path: %s", db->db_path);

    atomic_store(&db->is_open, 0);

    if (db->flush_queue)
    {
        pthread_mutex_lock(&db->flush_queue->lock);
        atomic_store(&db->flush_queue->shutdown, 1);
        pthread_cond_broadcast(&db->flush_queue->not_empty);
        pthread_mutex_unlock(&db->flush_queue->lock);
    }

    if (db->compaction_queue)
    {
        pthread_mutex_lock(&db->compaction_queue->lock);
        atomic_store(&db->compaction_queue->shutdown, 1);
        pthread_cond_broadcast(&db->compaction_queue->not_empty);
        pthread_mutex_unlock(&db->compaction_queue->lock);
    }

    TDB_DEBUG_LOG("Waiting for %d flush threads to finish", db->config.num_flush_threads);
    if (db->flush_threads)
    {
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
            pthread_join(db->flush_threads[i], NULL);
        }
        free(db->flush_threads);
    }
    TDB_DEBUG_LOG("Flush threads finished");

    TDB_DEBUG_LOG("Waiting for %d compaction threads to finish", db->config.num_compaction_threads);
    if (db->compaction_threads)
    {
        for (int i = 0; i < db->config.num_compaction_threads; i++)
        {
            TDB_DEBUG_LOG("Joining compaction thread %d", i);
            pthread_join(db->compaction_threads[i], NULL);
            TDB_DEBUG_LOG("Compaction thread %d joined", i);
        }
        free(db->compaction_threads);
    }
    TDB_DEBUG_LOG("Compaction threads finished");

    /* stop sync worker thread if running */
    if (atomic_load(&db->sync_thread_active))
    {
        TDB_DEBUG_LOG("Stopping sync worker thread");
        atomic_store(&db->sync_thread_active, 0);
        pthread_join(db->sync_thread, NULL);
        pthread_mutex_destroy(&db->sync_lock);
        TDB_DEBUG_LOG("Sync worker thread stopped");
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
            TDB_DEBUG_LOG("CF '%s': %d immutables in queue before shutdown cleanup", cf->name,
                          queue_count);
            int cleaned = 0;
            while (!queue_is_empty(cf->immutable_memtables))
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
                if (imm)
                {
                    int refcount = atomic_load_explicit(&imm->refcount, memory_order_acquire);
                    TDB_DEBUG_LOG("CF '%s': Dequeuing immutable with refcount=%d", cf->name,
                                  refcount);
                    tidesdb_immutable_memtable_unref(imm);
                    cleaned++;
                }
            }
            if (cleaned > 0)
            {
                TDB_DEBUG_LOG("CF '%s': Cleaned up %d immutable memtables during shutdown",
                              cf->name, cleaned);
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
        free(db->comparators);
    }
    pthread_mutex_destroy(&db->comparators_lock);

    free(db->db_path);
    TDB_DEBUG_LOG("Freeing SSTable cache (size: %zu)", lru_cache_size(db->sstable_cache));
    lru_cache_free(db->sstable_cache);
    TDB_DEBUG_LOG("SSTable cache freed");

    TDB_DEBUG_LOG("Freeing block cache (size: %zu)", lru_cache_size(db->block_cache));
    lru_cache_free(db->block_cache);
    TDB_DEBUG_LOG("Block cache freed");

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

    /* validate sync configuration */
    if (config->sync_mode == TDB_SYNC_INTERVAL && config->sync_interval_us == 0)
    {
        TDB_DEBUG_LOG("Invalid config: TDB_SYNC_INTERVAL requires sync_interval_us > 0");
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Creating column family: %s", name);

    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (db->column_families[i] && strcmp(db->column_families[i]->name, name) == 0)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            TDB_DEBUG_LOG("Column family already exists: %s", name);
            return TDB_ERR_EXISTS;
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    tidesdb_column_family_t *cf = calloc(1, sizeof(tidesdb_column_family_t));
    if (!cf)
    {
        TDB_DEBUG_LOG("Failed to allocate memory for column family structure");
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
        if (mkdir(dir_path, 0755) != 0)
        {
            free(cf->name);
            free(cf);
            return TDB_ERR_IO;
        }
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

    skip_list_t *new_memtable = NULL;

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    if (tidesdb_get_comparator(db, config->comparator_name, &comparator_fn, &comparator_ctx) !=
        TDB_SUCCESS)
    {
        /* comparator not found, use default memcmp */
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
            if (strstr(entry->d_name, ".klog") != NULL)
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

    /* validate we don't exceed max levels */
    if (min_levels > TDB_MAX_LEVELS)
    {
        TDB_DEBUG_LOG("Cannot create CF: requires %d levels but max is %d", min_levels,
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

    /* initialize fixed levels array - create min_levels, rest are NULL */
    for (int i = 0; i < min_levels; i++)
    {
        size_t level_capacity = base_capacity;
        /* calculate capacity: C_i = write_buffer_size * T^i */
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
        TDB_DEBUG_LOG("Creating level %d with capacity %zu", i + 1, level_capacity);
    }

    /* initialize remaining slots to NULL */
    for (int i = min_levels; i < TDB_MAX_LEVELS; i++)
    {
        cf->levels[i] = NULL;
    }

    atomic_init(&cf->num_active_levels, min_levels);

    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->next_seq_num, 0);
    atomic_init(&cf->commit_seq, 0);
    atomic_init(&cf->memtable_id, 0);
    atomic_init(&cf->is_compacting, 0);
    atomic_init(&cf->is_flushing, 0);
    atomic_init(&cf->memtable_generation, 0);
    atomic_init(&cf->commit_ticket, 0);
    atomic_init(&cf->commit_serving, 0);

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

    TDB_DEBUG_LOG("Created CF '%s' (total: %d)", name, db->num_column_families);

    return TDB_SUCCESS;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;
    if (!atomic_load_explicit(&db->is_open, memory_order_acquire)) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Dropping column family: %s", name);

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
    TDB_DEBUG_LOG("Deleted column family directory: %s (result: %d)", cf_to_drop->directory,
                  result);

    tidesdb_column_family_free(cf_to_drop);

    return TDB_SUCCESS;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

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
    if (!cf) return TDB_ERR_INVALID_ARGS;

    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&cf->is_flushing, &expected, 1,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        /* another flush is already running, skip this one */
        return TDB_SUCCESS;
    }

    skip_list_t *old_memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    size_t current_size = (size_t)skip_list_get_size(old_memtable);
    int current_entries = skip_list_count_entries(old_memtable);

    if (current_entries == 0)
    {
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    if (current_size < cf->config.write_buffer_size)
    {
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_SUCCESS;
    }

    TDB_DEBUG_LOG(
        "CF '%s': Flushing memtable (entries: %d, size: %zu bytes / %.2f MB, threshold: %zu bytes "
        "/ %.2f MB)",
        cf->name, current_entries, current_size, current_size / (1024.0 * 1024.0),
        cf->config.write_buffer_size, cf->config.write_buffer_size / (1024.0 * 1024.0));

    block_manager_t *old_wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);
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

    skip_list_t *new_memtable;
    if (skip_list_new_with_comparator(&new_memtable, 32, 0.25f, comparator_fn, comparator_ctx) != 0)
    {
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
        skip_list_free(new_memtable);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_IO;
    }

    tidesdb_immutable_memtable_t *immutable = malloc(sizeof(tidesdb_immutable_memtable_t));
    if (!immutable)
    {
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

    /* swap active memtable with new empty one */
    atomic_store_explicit(&cf->active_memtable, new_memtable, memory_order_release);
    atomic_store_explicit(&cf->active_wal, new_wal, memory_order_release);
    atomic_fetch_add_explicit(&cf->memtable_generation, 1, memory_order_release);

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
    TDB_DEBUG_LOG("CF '%s': Enqueueing flush work for SSTable %" PRIu64 " (queue size before: %zu)",
                  cf->name, sst_id, queue_size_before);

    if (queue_enqueue(cf->db->flush_queue, work) != 0)
    {
        TDB_DEBUG_LOG("CF '%s': FAILED to enqueue flush work for SSTable %" PRIu64, cf->name,
                      sst_id);
        tidesdb_immutable_memtable_unref(immutable); /* remove work ref */
        tidesdb_immutable_memtable_unref(immutable); /* remove queue ref, triggers cleanup */
        free(work);
        atomic_store_explicit(&cf->is_flushing, 0, memory_order_release);
        return TDB_ERR_MEMORY;
    }

    size_t queue_size_after = queue_size(cf->db->flush_queue);
    TDB_DEBUG_LOG("CF '%s': Successfully enqueued flush work for SSTable %" PRIu64
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
 * MVCC transaction isolation levels implementation
 *
 * READ_UNCOMMITTED (level 0)
 * -- sees all versions including uncommitted changes
 * -- no snapshot isolation, uses UINT64_MAX to bypass filtering
 * -- fastest but allows dirty reads, non-repeatable reads, and phantom reads
 * -- no conflict detection
 *
 * READ_COMMITTED (level 1)
 * -- refreshes snapshot on each read operation
 * -- prevents dirty reads by only seeing committed data
 * -- allows non-repeatable reads (same key may return different values)
 * -- allows phantom reads (range queries may see different rows)
 * -- no conflict detection
 *
 * REPEATABLE_READ (level 2)
 * -- consistent snapshot taken at transaction start
 * -- prevents dirty reads and non-repeatable reads
 * -- still allows phantom reads (new rows can appear in range queries)
 * -- uses read-write conflict detection to ensure consistency
 * -- aborts on conflicts
 *
 * SNAPSHOT (level 3)
 * -- consistent snapshot with first-committer-wins semantics
 * -- prevents dirty reads, non-repeatable reads
 * -- uses read-write and write-write conflict detection
 * -- aborts on conflicts
 * -- similar to REPEATABLE_READ but with stricter write conflict detection
 *
 * SERIALIZABLE (level 4)
 * -- full serializability using SSI (serializable snapshot isolation)
 * -- prevents dirty reads, non-repeatable reads, and phantom reads
 * -- uses read-write, write-write, and rw-antidependency conflict detection
 * -- tracks active transactions for dangerous structure detection
 * -- highest isolation but lowest concurrency
 *
 * multi-CF transactions
 * -- all isolation levels support multi-CF transactions
 * -- each CF gets its own snapshot based on its commit_seq
 * -- global_snapshot_seq ensures cross-CF consistency
 * -- conflict detection is CF-aware
 */

/**
 * tidesdb_txn_add_cf_internal
 * internal helper to add a CF to transaction and take snapshot
 * @param txn the transaction
 * @param cf the column family
 */
static int tidesdb_txn_add_cf_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf);

/**
 * tidesdb_txn_register
 * register transaction in CF's active transaction buffer
 * @param cf the column family
 * @param txn_id the transaction ID
 * @param snapshot_seq the snapshot sequence
 * @param isolation isolation level
 * @param slot_id output slot ID for later unregistration
 * @return 0 on success, -1 on failure
 */
static int tidesdb_txn_register(tidesdb_column_family_t *cf, uint64_t txn_id, uint64_t snapshot_seq,
                                tidesdb_isolation_level_t isolation, uint32_t *slot_id)
{
    if (!cf || !cf->active_txn_buffer || !slot_id) return -1;

    tidesdb_txn_entry_t *entry = malloc(sizeof(tidesdb_txn_entry_t));
    if (!entry) return -1;

    entry->txn_id = txn_id;
    entry->snapshot_seq = snapshot_seq;
    entry->isolation = isolation;
    entry->buffer_slot_id = BUFFER_INVALID_ID;
    entry->generation = 0;

    if (buffer_acquire(cf->active_txn_buffer, entry, slot_id) != 0)
    {
        free(entry);
        return -1;
    }

    /* store slot ID and generation in entry for validation */
    entry->buffer_slot_id = *slot_id;
    if (buffer_get_generation(cf->active_txn_buffer, *slot_id, &entry->generation) != 0)
    {
        entry->generation = 0;
    }

    return 0;
}

/**
 * tidesdb_txn_unregister
 * unregister transaction from CF's active transaction buffer
 * @param cf the column family
 * @param slot_id slot ID from registration
 */
static void tidesdb_txn_unregister(tidesdb_column_family_t *cf, uint32_t slot_id)
{
    if (!cf || !cf->active_txn_buffer || slot_id == BUFFER_INVALID_ID) return;

    buffer_release(cf->active_txn_buffer, slot_id);
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
    if (txn->isolation_level != TDB_ISOLATION_SNAPSHOT &&
        txn->isolation_level != TDB_ISOLATION_SERIALIZABLE)
    {
        return 0;
    }

    /* resize if needed */
    if (txn->read_set_count >= txn->read_set_capacity)
    {
        int new_cap = txn->read_set_capacity * 2;
        uint8_t **new_keys = realloc(txn->read_keys, new_cap * sizeof(uint8_t *));
        size_t *new_sizes = realloc(txn->read_key_sizes, new_cap * sizeof(size_t));
        uint64_t *new_seqs = realloc(txn->read_seqs, new_cap * sizeof(uint64_t));
        tidesdb_column_family_t **new_cfs =
            realloc(txn->read_cfs, new_cap * sizeof(tidesdb_column_family_t *));

        if (!new_keys || !new_sizes || !new_seqs || !new_cfs)
        {
            free(new_keys);
            free(new_sizes);
            free(new_seqs);
            free(new_cfs);
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

    return 0;
}

int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    *txn = calloc(1, sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->isolation_level = isolation;

    /* we assign unique tx ID from database counter */
    (*txn)->txn_id = atomic_fetch_add_explicit(&db->next_txn_id, 1, memory_order_relaxed);

    (*txn)->ops_capacity = 16;
    (*txn)->ops = malloc((*txn)->ops_capacity * sizeof(tidesdb_txn_op_t));
    if (!(*txn)->ops)
    {
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    /* allocations*/
    (*txn)->read_set_capacity = 16;
    (*txn)->read_keys = malloc((*txn)->read_set_capacity * sizeof(uint8_t *));
    (*txn)->read_key_sizes = malloc((*txn)->read_set_capacity * sizeof(size_t));
    (*txn)->read_seqs = malloc((*txn)->read_set_capacity * sizeof(uint64_t));
    (*txn)->read_cfs = malloc((*txn)->read_set_capacity * sizeof(tidesdb_column_family_t *));

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

    (*txn)->write_set_capacity = 16;
    (*txn)->write_keys = malloc((*txn)->write_set_capacity * sizeof(uint8_t *));
    (*txn)->write_key_sizes = malloc((*txn)->write_set_capacity * sizeof(size_t));
    (*txn)->write_cfs = malloc((*txn)->write_set_capacity * sizeof(tidesdb_column_family_t *));

    if (!(*txn)->write_keys || !(*txn)->write_key_sizes || !(*txn)->write_cfs)
    {
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->write_cfs);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->read_cfs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->cf_capacity = 4;
    (*txn)->cfs = malloc((*txn)->cf_capacity * sizeof(tidesdb_column_family_t *));
    (*txn)->cf_snapshots = malloc((*txn)->cf_capacity * sizeof(uint64_t));
    (*txn)->cf_txn_slots = malloc((*txn)->cf_capacity * sizeof(uint32_t));

    if (!(*txn)->cfs || !(*txn)->cf_snapshots || !(*txn)->cf_txn_slots)
    {
        free((*txn)->cfs);
        free((*txn)->cf_snapshots);
        free((*txn)->cf_txn_slots);
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->write_cfs);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->read_cfs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->savepoints_capacity = 4;
    (*txn)->savepoints = malloc((*txn)->savepoints_capacity * sizeof(tidesdb_txn_t *));
    (*txn)->savepoint_names = malloc((*txn)->savepoints_capacity * sizeof(char *));

    if (!(*txn)->savepoints || !(*txn)->savepoint_names)
    {
        free((*txn)->savepoints);
        free((*txn)->savepoint_names);
        free((*txn)->cfs);
        free((*txn)->cf_snapshots);
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->write_cfs);
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
    (*txn)->is_read_only = 1; /* assume read-only until first write */

    (*txn)->global_snapshot_seq = atomic_load_explicit(&db->global_txn_seq, memory_order_acquire);

    return TDB_SUCCESS;
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn)
{
    return tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, txn);
}

/**
 * tidesdb_txn_add_cf_internal
 *
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
        if (txn->cfs[i] == cf) return i; /* already added, return index */
    }

    /* grow arrays if needed */
    if (txn->num_cfs >= txn->cf_capacity)
    {
        int new_cap = txn->cf_capacity * 2;
        tidesdb_column_family_t **new_cfs =
            realloc(txn->cfs, new_cap * sizeof(tidesdb_column_family_t *));
        uint64_t *new_snapshots = realloc(txn->cf_snapshots, new_cap * sizeof(uint64_t));
        uint32_t *new_slots = realloc(txn->cf_txn_slots, new_cap * sizeof(uint32_t));

        if (!new_cfs || !new_snapshots || !new_slots)
        {
            free(new_cfs);
            free(new_snapshots);
            free(new_slots);
            return -1;
        }

        txn->cfs = new_cfs;
        txn->cf_snapshots = new_snapshots;
        txn->cf_txn_slots = new_slots;
        txn->cf_capacity = new_cap;
    }

    /* take snapshot for this CF based on isolation level */
    uint64_t cf_snapshot;

    if (txn->isolation_level == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        /* read uncommitted sees all versions, no filtering */
        cf_snapshot = UINT64_MAX;
    }
    else if (txn->isolation_level == TDB_ISOLATION_READ_COMMITTED)
    {
        /* read committed refreshes on each read, snapshot taken at read time
         * we use 0 here as placeholder, actual snapshot taken in txn_get */
        cf_snapshot = 0;
    }
    else if (txn->isolation_level == TDB_ISOLATION_REPEATABLE_READ ||
             txn->isolation_level == TDB_ISOLATION_SNAPSHOT ||
             txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        /* repeatable read, snapshot, and serializable all use consistent snapshot
         * taken at transaction start */
        uint64_t cf_commit_seq = atomic_load_explicit(&cf->commit_seq, memory_order_acquire);

        if (txn->global_snapshot_seq == 0)
        {
            /* no multi-CF transactions yet, use CF's own sequence */
            cf_snapshot = cf_commit_seq;
        }
        else
        {
            /* use min for cross-CF consistency */
            cf_snapshot = (txn->global_snapshot_seq < cf_commit_seq) ? txn->global_snapshot_seq
                                                                     : cf_commit_seq;
        }
    }
    else
    {
        /* unknown isolation level, default to snapshot */
        cf_snapshot = atomic_load_explicit(&cf->commit_seq, memory_order_acquire);
    }

    int cf_index = txn->num_cfs;
    txn->cfs[cf_index] = cf;
    txn->cf_snapshots[cf_index] = cf_snapshot;

    /* register transaction in CF's active buffer for conflict detection */
    uint32_t txn_slot = BUFFER_INVALID_ID;
    if (txn->isolation_level == TDB_ISOLATION_REPEATABLE_READ ||
        txn->isolation_level == TDB_ISOLATION_SNAPSHOT ||
        txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        /* register in CF's active transaction buffer */
        if (tidesdb_txn_register(cf, txn->txn_id, cf_snapshot, txn->isolation_level, &txn_slot) !=
            0)
        {
            /* registration failed -- buffer exhausted
             * we cannot proceed without tracking this transaction as it would break
             * isolation guarantees (SSI conflict detection requires tracking all active txns)
             * fail the transaction to preserve correctness */
            TDB_DEBUG_LOG("CF '%s': Failed to register txn %" PRIu64
                          " - active_txn_buffer exhausted",
                          cf->name, txn->txn_id);
            return -1;
        }
    }
    txn->cf_txn_slots[cf_index] = txn_slot;
    txn->num_cfs++;

    return cf_index;
}

int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf || !key || key_size == 0 || !value) return TDB_ERR_INVALID_ARGS;

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

        /* ensure we don't exceed max even with doubling */
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
    txn->is_read_only = 0;

    /* track in write set for conflict detection */
    if (txn->write_set_count >= txn->write_set_capacity)
    {
        int new_cap = txn->write_set_capacity * 2;
        uint8_t **new_keys = realloc(txn->write_keys, new_cap * sizeof(uint8_t *));
        size_t *new_sizes = realloc(txn->write_key_sizes, new_cap * sizeof(size_t));
        tidesdb_column_family_t **new_cfs =
            realloc(txn->write_cfs, new_cap * sizeof(tidesdb_column_family_t *));

        if (!new_keys || !new_sizes || !new_cfs)
        {
            free(new_keys);
            free(new_sizes);
            free(new_cfs);
            return TDB_ERR_MEMORY;
        }

        txn->write_keys = new_keys;
        txn->write_key_sizes = new_sizes;
        txn->write_cfs = new_cfs;
        txn->write_set_capacity = new_cap;
    }

    txn->write_keys[txn->write_set_count] = malloc(key_size);
    if (!txn->write_keys[txn->write_set_count]) return TDB_ERR_MEMORY;

    memcpy(txn->write_keys[txn->write_set_count], key, key_size);
    txn->write_key_sizes[txn->write_set_count] = key_size;
    txn->write_cfs[txn->write_set_count] = cf; /* track which CF this write belongs to */
    txn->write_set_count++;

    return TDB_SUCCESS;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf || !key || key_size == 0 || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    /* add CF to transaction if not already added */
    int cf_index = tidesdb_txn_add_cf_internal(txn, cf);
    if (cf_index < 0) return TDB_ERR_MEMORY;

    /* get snapshot for this CF based on isolation level */
    uint64_t snapshot_seq = txn->cf_snapshots[cf_index];

    /* for READ_COMMITTED, refresh snapshot on each read to see latest committed data
     * this prevents dirty reads but allows non-repeatable reads */
    if (txn->isolation_level == TDB_ISOLATION_READ_COMMITTED)
    {
        snapshot_seq = atomic_load_explicit(&cf->commit_seq, memory_order_seq_cst);
        txn->cf_snapshots[cf_index] = snapshot_seq;
    }
    else if (txn->isolation_level == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        /* read uncommitted sees all versions */
        snapshot_seq = UINT64_MAX;
    }

    /* check write set first (read your own writes) */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        if (txn->ops[i].cf == cf && txn->ops[i].key_size == key_size &&
            memcmp(txn->ops[i].key, key, key_size) == 0)
        {
            if (txn->ops[i].is_delete)
            {
                return TDB_ERR_NOT_FOUND;
            }
            *value = malloc(txn->ops[i].value_size);
            if (!*value) return TDB_ERR_MEMORY;
            memcpy(*value, txn->ops[i].value, txn->ops[i].value_size);
            *value_size = txn->ops[i].value_size;
            return TDB_SUCCESS;
        }
    }

    /* search active memtable */
    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    uint8_t *temp_value;
    size_t temp_value_size;
    time_t ttl;
    uint8_t deleted;
    uint64_t found_seq = 0;

    int memtable_result =
        skip_list_get_with_seq(active_mt, key, key_size, &temp_value, &temp_value_size, &ttl,
                               &deleted, &found_seq, snapshot_seq);

    if (memtable_result == 0)
    {
        if (deleted)
        {
            /* found a tombstone in active memtable, key is deleted */
            free(temp_value);
            return TDB_ERR_NOT_FOUND;
        }

        if (ttl == 0 || ttl > time(NULL))
        {
            *value = temp_value;
            *value_size = temp_value_size;

            tidesdb_txn_add_to_read_set(txn, cf, key, key_size, found_seq);

            return TDB_SUCCESS;
        }

        /* TTL expired */
        free(temp_value);
        return TDB_ERR_NOT_FOUND;
    }

    int immutable_count = (int)queue_size(cf->immutable_memtables);
    tidesdb_immutable_memtable_t **immutable_refs = NULL;

    if (immutable_count > 0)
    {
        immutable_refs = malloc(immutable_count * sizeof(tidesdb_immutable_memtable_t *));
        if (immutable_refs)
        {
            for (int i = 0; i < immutable_count; i++)
            {
                tidesdb_immutable_memtable_t *imm =
                    (tidesdb_immutable_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                if (imm)
                {
                    tidesdb_immutable_memtable_ref(imm);
                    immutable_refs[i] = imm;
                }
                else
                {
                    immutable_refs[i] = NULL;
                }
            }
        }
    }

    /* now search immutable memtables safely with references held
     * search in REVERSE order (newest first) to find most recent version */
    if (immutable_refs)
    {
        for (int i = immutable_count - 1; i >= 0; i--)
        {
            tidesdb_immutable_memtable_t *immutable = immutable_refs[i];
            if (immutable && immutable->memtable)
            {
                if (skip_list_get_with_seq(immutable->memtable, key, key_size, &temp_value,
                                           &temp_value_size, &ttl, &deleted, &found_seq,
                                           snapshot_seq) == 0)
                {
                    if (deleted)
                    {
                        /* found a tombstone in immutable memtable, key is deleted */
                        free(temp_value);

                        for (int j = 0; j < immutable_count; j++)
                        {
                            if (immutable_refs[j])
                                tidesdb_immutable_memtable_unref(immutable_refs[j]);
                        }
                        free(immutable_refs);
                        return TDB_ERR_NOT_FOUND;
                    }

                    if (ttl == 0 || ttl > time(NULL))
                    {
                        *value = temp_value;
                        *value_size = temp_value_size;

                        tidesdb_txn_add_to_read_set(txn, cf, key, key_size, found_seq);

                        for (int j = 0; j < immutable_count; j++)
                        {
                            if (immutable_refs[j])
                                tidesdb_immutable_memtable_unref(immutable_refs[j]);
                        }
                        free(immutable_refs);
                        return TDB_SUCCESS;
                    }

                    free(temp_value);

                    for (int j = 0; j < immutable_count; j++)
                    {
                        if (immutable_refs[j]) tidesdb_immutable_memtable_unref(immutable_refs[j]);
                    }
                    free(immutable_refs);
                    return TDB_ERR_NOT_FOUND;
                }
            }
        }

        for (int i = 0; i < immutable_count; i++)
        {
            if (immutable_refs[i]) tidesdb_immutable_memtable_unref(immutable_refs[i]);
        }
        free(immutable_refs);
    }

    /* we wait for DCA to complete before accessing levels.
     * The levels array is fixed-size, so we only need to load num_active_levels. */
    tidesdb_wait_for_dca(cf);
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* collect sstable pointers with references held */
    typedef struct
    {
        tidesdb_sstable_t *sst;
        int level;
        int index;
    } sst_ref_t;

    sst_ref_t stack_ssts[TDB_STACK_SSTS];
    sst_ref_t *ssts_array = stack_ssts;
    int ssts_capacity = TDB_STACK_SSTS;
    int sst_count = 0;

    /* iterate through levels and take refs immediately to minimize race window */
    for (int i = 0; i < num_levels; i++)
    {
        tidesdb_level_t *level = cf->levels[i];

        /* CRITICAL: load count BEFORE array pointer to prevent TOCTOU race.
         * If we load array first, compaction could remove an SSTable and decrement count,
         * causing us to skip the last entry. Loading count first ensures we check
         * at least the SSTables that existed when we started. */
        int num_ssts = atomic_load_explicit(&level->num_sstables, memory_order_acquire);
        tidesdb_sstable_t **sstables = atomic_load_explicit(&level->sstables, memory_order_acquire);

        for (int j = 0; j < num_ssts; j++)
        {
            tidesdb_sstable_t *sst = sstables[j];
            if (!sst) continue;

            /* expand array if needed */
            if (sst_count >= ssts_capacity)
            {
                int new_capacity = ssts_capacity * 2;
                sst_ref_t *new_array = malloc(new_capacity * sizeof(sst_ref_t));
                if (!new_array)
                {
                    /* cleanup refs taken so far */
                    for (int k = 0; k < sst_count; k++)
                    {
                        tidesdb_sstable_unref(cf->db, ssts_array[k].sst);
                    }
                    if (ssts_array != stack_ssts) free(ssts_array);

                    return TDB_ERR_MEMORY;
                }
                memcpy(new_array, ssts_array, sst_count * sizeof(sst_ref_t));
                if (ssts_array != stack_ssts) free(ssts_array);
                ssts_array = new_array;
                ssts_capacity = new_capacity;
            }

            /* acquire reference to protect against concurrent deletion */
            tidesdb_sstable_ref(sst);
            ssts_array[sst_count].sst = sst;
            ssts_array[sst_count].level = i;
            ssts_array[sst_count].index = j;
            sst_count++;
        }
    }

    skip_list_comparator_fn comparator_fn = NULL;
    void *comparator_ctx = NULL;
    tidesdb_resolve_comparator(cf->db, &cf->config, &comparator_fn, &comparator_ctx);

    tidesdb_kv_pair_t *best_kv = NULL;
    uint64_t best_seq = UINT64_MAX;
    int found_any = 0;

    if (ssts_array)
    {
        for (int idx = 0; idx < sst_count; idx++)
        {
            tidesdb_sstable_t *sst = ssts_array[idx].sst;
            int level = ssts_array[idx].level;

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
                    tidesdb_sstable_unref(cf->db, sst);
                    continue;
                }
            }

            tidesdb_kv_pair_t *candidate_kv = NULL;
            if (tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv) == TDB_SUCCESS &&
                candidate_kv)
            {
                uint64_t candidate_seq = candidate_kv->entry.seq;
                int accept = (snapshot_seq == UINT64_MAX) ? 1 : (candidate_seq <= snapshot_seq);

                /* keep the version with highest sequence number (or first if no best yet) */
                if (accept && (best_seq == UINT64_MAX || candidate_seq > best_seq))
                {
                    if (best_kv) tidesdb_kv_pair_free(best_kv);
                    best_kv = candidate_kv;
                    best_seq = candidate_seq;
                    found_any = 1;

                    if (level == 0)
                    {
                        tidesdb_sstable_unref(cf->db, sst);
                        /* release remaining references */
                        for (int k = idx + 1; k < sst_count; k++)
                        {
                            tidesdb_sstable_unref(cf->db, ssts_array[k].sst);
                        }
                        if (ssts_array != stack_ssts) free(ssts_array);
                        goto check_found_result;
                    }
                }
                else
                {
                    tidesdb_kv_pair_free(candidate_kv);
                }
            }

            tidesdb_sstable_unref(cf->db, sst);

            /* early exit if we found a match in level 0 */
            if (level == 0 && found_any)
            {
                /* release remaining references */
                for (int k = idx + 1; k < sst_count; k++)
                {
                    tidesdb_sstable_unref(cf->db, ssts_array[k].sst);
                }
                break;
            }
        }

        if (ssts_array != stack_ssts) free(ssts_array);
    }

check_found_result:

    /* check if we found a valid (non-deleted, non-expired) version */
    if (found_any && best_kv)
    {
        if (!(best_kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) &&
            (best_kv->entry.ttl == 0 || best_kv->entry.ttl > time(NULL)))
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
    txn->is_read_only = 0;

    /* track in write set for conflict detection */
    if (txn->write_set_count >= txn->write_set_capacity)
    {
        int new_cap = txn->write_set_capacity * 2;
        uint8_t **new_keys = realloc(txn->write_keys, new_cap * sizeof(uint8_t *));
        size_t *new_sizes = realloc(txn->write_key_sizes, new_cap * sizeof(size_t));
        tidesdb_column_family_t **new_cfs =
            realloc(txn->write_cfs, new_cap * sizeof(tidesdb_column_family_t *));

        if (!new_keys || !new_sizes || !new_cfs)
        {
            free(new_keys);
            free(new_sizes);
            free(new_cfs);
            return TDB_ERR_MEMORY;
        }

        txn->write_keys = new_keys;
        txn->write_key_sizes = new_sizes;
        txn->write_cfs = new_cfs;
        txn->write_set_capacity = new_cap;
    }

    txn->write_keys[txn->write_set_count] = malloc(key_size);
    if (!txn->write_keys[txn->write_set_count]) return TDB_ERR_MEMORY;

    memcpy(txn->write_keys[txn->write_set_count], key, key_size);
    txn->write_key_sizes[txn->write_set_count] = key_size;
    txn->write_cfs[txn->write_set_count] = cf; /* track which CF this write belongs to */
    txn->write_set_count++;

    return TDB_SUCCESS;
}

/**
 * ssi_check_ctx_t
 * context for SSI conflict detection
 */
typedef struct
{
    tidesdb_txn_t *txn;
    int conflict_found;
} ssi_check_ctx_t;

/**
 * check_rw_conflict
 * callback to check for read-write conflicts in SSI
 */
static void check_rw_conflict(uint32_t id, void *data, void *ctx)
{
    (void)id;
    ssi_check_ctx_t *check_ctx = (ssi_check_ctx_t *)ctx;
    tidesdb_txn_entry_t *active = (tidesdb_txn_entry_t *)data;

    if (!active || check_ctx->conflict_found) return;

    /* skip ourselves */
    if (active->txn_id == check_ctx->txn->txn_id) return;

    /* check if this active transaction's snapshot overlaps with our writes
     * if they started before we commit and we're writing keys, we have a potential
     * rw-conflict (they might have read data we're about to overwrite) */
    for (int cf_idx = 0; cf_idx < check_ctx->txn->num_cfs; cf_idx++)
    {
        if (active->snapshot_seq <= check_ctx->txn->cf_snapshots[cf_idx])
        {
            /* abort to prevent potential write-skew */
            TDB_DEBUG_LOG("SSI: rw-conflict detected, aborting txn %" PRIu64,
                          check_ctx->txn->txn_id);
            check_ctx->conflict_found = 1;
            return;
        }
    }
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;
    if (txn->num_cfs <= 0) return TDB_ERR_INVALID_ARGS;

    if (txn->num_ops > TDB_MAX_TXN_OPS)
    {
        TDB_DEBUG_LOG("Transaction too large: %d ops (max: %d)", txn->num_ops, TDB_MAX_TXN_OPS);
        return TDB_ERR_INVALID_ARGS;
    }

    if (txn->isolation_level == TDB_ISOLATION_REPEATABLE_READ ||
        txn->isolation_level == TDB_ISOLATION_SNAPSHOT ||
        txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        for (int i = 0; i < txn->read_set_count; i++)
        {
            tidesdb_column_family_t *key_cf = txn->read_cfs[i];
            uint64_t key_read_seq = txn->read_seqs[i];

            /* check if this key was modified since we read it */
            uint8_t *temp_value;
            size_t temp_value_size;
            time_t ttl;
            uint8_t deleted;
            uint64_t found_seq = 0;

            skip_list_t *active_mt =
                atomic_load_explicit(&key_cf->active_memtable, memory_order_acquire);
            if (skip_list_get_with_seq(active_mt, txn->read_keys[i], txn->read_key_sizes[i],
                                       &temp_value, &temp_value_size, &ttl, &deleted, &found_seq,
                                       UINT64_MAX) == 0)
            {
                /* conflict if the current version is newer than what we read */
                if (found_seq > key_read_seq)
                {
                    free(temp_value);
                    return TDB_ERR_CONFLICT;
                }
                free(temp_value);
            }
        }

        /* check write-write conflicts to prevent lost updates
         * applies to REPEATABLE_READ, SNAPSHOT and SERIALIZABLE
         * ensures first-committer-wins semantics */
        for (int i = 0; i < txn->write_set_count; i++)
        {
            tidesdb_column_family_t *key_cf = txn->write_cfs[i];

            /* find this key's CF snapshot */
            uint64_t cf_snapshot = 0;
            for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
            {
                if (txn->cfs[cf_idx] == key_cf)
                {
                    cf_snapshot = txn->cf_snapshots[cf_idx];
                    break;
                }
            }

            /* check if this key was modified by another transaction */
            uint8_t *temp_value;
            size_t temp_value_size;
            time_t ttl;
            uint8_t deleted;
            uint64_t found_seq = 0;

            skip_list_t *active_mt =
                atomic_load_explicit(&key_cf->active_memtable, memory_order_acquire);
            if (skip_list_get_with_seq(active_mt, txn->write_keys[i], txn->write_key_sizes[i],
                                       &temp_value, &temp_value_size, &ttl, &deleted, &found_seq,
                                       UINT64_MAX) == 0)
            {
                if (found_seq > cf_snapshot)
                {
                    free(temp_value);
                    return TDB_ERR_CONFLICT;
                }
                free(temp_value);
            }
        }

        if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
        {
            /* check if any concurrent transaction read keys we're writing
             * this is the rw-antidependency check for SSI using per-CF buffers */

            /* check each CF's active transaction buffer */
            for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
            {
                tidesdb_column_family_t *cf = txn->cfs[cf_idx];
                if (!cf->active_txn_buffer) continue;

                ssi_check_ctx_t ctx = {.txn = txn, .conflict_found = 0};
                buffer_foreach(cf->active_txn_buffer, check_rw_conflict, &ctx);

                if (ctx.conflict_found)
                {
                    return TDB_ERR_CONFLICT;
                }
            }
        }
    }

    /**
     * cf_commit_ctx_t
     * context for committing operations to a single column family
     * @param cf column family
     * @param op_count number of operations for this cf
     * @param wal_size size of wal batch
     * @param wal_batch serialized wal entries
     * @param seq_numbers assigned sequence numbers
     * @param committed flag indicating if cf commit succeeded
     */
    typedef struct
    {
        tidesdb_column_family_t *cf;
        int op_count;
        size_t wal_size;
        uint8_t *wal_batch;
        uint64_t *seq_numbers;
        int committed;
    } cf_commit_ctx_t;

    if (txn->num_cfs <= 0 || txn->num_cfs > TDB_MAX_TXN_CFS)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    cf_commit_ctx_t *cf_contexts = calloc((size_t)txn->num_cfs, sizeof(cf_commit_ctx_t));
    if (!cf_contexts)
    {
        return TDB_ERR_MEMORY;
    }

    uint64_t global_seq = 0;
    int is_multi_cf = (txn->num_cfs > 1) ? 1 : 0;

    if (is_multi_cf)
    {
        global_seq = atomic_fetch_add(&txn->db->global_txn_seq, 1);
        /* set high bit to mark as multi-CF sequence */
        global_seq |= TDB_MULTI_CF_SEQ_FLAG;

        /* check overflow on global counter (lower 63 bits) */
        if ((global_seq & ~TDB_MULTI_CF_SEQ_FLAG) >= (UINT64_MAX >> 1) - 1000000)
        {
            free(cf_contexts);
            return TDB_ERR_INVALID_ARGS;
        }
    }

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];
        cf_contexts[cf_idx].cf = cf;
        cf_contexts[cf_idx].committed = 0;

        /* count operations for this CF and calculate WAL size */
        int cf_op_count = 0;
        size_t cf_wal_size = 0;
        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf == cf)
            {
                cf_op_count++;
                cf_wal_size += sizeof(tidesdb_klog_entry_t) + op->key_size;
                if (op->value_size > 0) cf_wal_size += op->value_size;

                /* add space for multi-CF metadata (written before first entry only) */
                if (is_multi_cf && cf_op_count == 1)
                {
                    cf_wal_size += sizeof(tidesdb_multi_cf_txn_metadata_t);
                    cf_wal_size += txn->num_cfs * TDB_MAX_CF_NAME_LEN; /* CF names */
                }
            }
        }

        cf_contexts[cf_idx].op_count = cf_op_count;
        cf_contexts[cf_idx].wal_size = cf_wal_size;

        if (cf_op_count == 0)
        {
            continue; /* no operations for this CF */
        }

        cf_contexts[cf_idx].wal_batch = malloc(cf_wal_size);
        if (!cf_contexts[cf_idx].wal_batch)
        {
            for (int j = 0; j < cf_idx; j++)
            {
                free(cf_contexts[j].wal_batch);
                free(cf_contexts[j].seq_numbers);
            }
            free(cf_contexts);
            return TDB_ERR_MEMORY;
        }

        cf_contexts[cf_idx].seq_numbers = malloc(cf_op_count * sizeof(uint64_t));
        if (!cf_contexts[cf_idx].seq_numbers)
        {
            free(cf_contexts[cf_idx].wal_batch);
            for (int j = 0; j < cf_idx; j++)
            {
                free(cf_contexts[j].wal_batch);
                free(cf_contexts[j].seq_numbers);
            }
            free(cf_contexts);
            return TDB_ERR_MEMORY;
        }

        /* assign sequence numbers and serialize to WAL batch */
        uint8_t *wal_ptr = cf_contexts[cf_idx].wal_batch;
        int seq_idx = 0;
        int first_entry_for_cf = 1;

        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            uint64_t seq = 0;
            if (is_multi_cf)
            {
                /* multi-CF we use shared global sequence */
                seq = global_seq;

                /* write multi-CF metadata before first entry */
                if (first_entry_for_cf)
                {
                    uint8_t num_participant_cfs = (uint8_t)txn->num_cfs;
                    size_t cf_names_size = txn->num_cfs * TDB_MAX_CF_NAME_LEN;

                    /* write CF names first (we'll write metadata header after computing checksum)
                     */
                    uint8_t *cf_names_start =
                        wal_ptr + 1 + sizeof(uint64_t); /* after num + checksum */
                    uint8_t *name_ptr = cf_names_start;
                    for (int cf_i = 0; cf_i < txn->num_cfs; cf_i++)
                    {
                        strncpy((char *)name_ptr, txn->cfs[cf_i]->name, TDB_MAX_CF_NAME_LEN - 1);
                        name_ptr[TDB_MAX_CF_NAME_LEN - 1] = '\0';
                        name_ptr += TDB_MAX_CF_NAME_LEN;
                    }

                    /* compute checksum over num_participant_cfs + cf_names */
                    size_t checksum_data_size = sizeof(uint8_t) + cf_names_size;
                    uint8_t *checksum_data = malloc(checksum_data_size);
                    uint64_t checksum;
                    if (checksum_data)
                    {
                        checksum_data[0] = num_participant_cfs;
                        memcpy(checksum_data + 1, cf_names_start, cf_names_size);
                        checksum = XXH64(checksum_data, checksum_data_size, 0);
                        free(checksum_data);
                    }
                    else
                    {
                        checksum = XXH64(&num_participant_cfs, sizeof(uint8_t), 0);
                    }

                    /* now serialize metadata header with proper endianness */
                    *wal_ptr++ = num_participant_cfs;
                    encode_uint64_le_compat(wal_ptr, checksum);
                    wal_ptr += sizeof(uint64_t);
                    wal_ptr += cf_names_size; /* skip past CF names we already wrote */

                    first_entry_for_cf = 0;
                }
            }
            else
            {
                seq = 0;
            }

            cf_contexts[cf_idx].seq_numbers[seq_idx] = seq; /* placeholder for single-CF */
            seq_idx++;

            /* serialize entry fields with proper endianness for WAL portability */
            *wal_ptr++ = 0;                                         /* version */
            *wal_ptr++ = op->is_delete ? TDB_KV_FLAG_TOMBSTONE : 0; /* flags */
            encode_uint32_le_compat(wal_ptr, (uint32_t)op->key_size);
            wal_ptr += sizeof(uint32_t);
            encode_uint32_le_compat(wal_ptr, (uint32_t)op->value_size);
            wal_ptr += sizeof(uint32_t);
            encode_int64_le_compat(wal_ptr, op->ttl);
            wal_ptr += sizeof(int64_t);
            encode_uint64_le_compat(wal_ptr,
                                    seq); /* placeholder for single-CF, real for multi-CF */
            wal_ptr += sizeof(uint64_t);
            encode_uint64_le_compat(wal_ptr, 0); /* vlog_offset */
            wal_ptr += sizeof(uint64_t);

            memcpy(wal_ptr, op->key, op->key_size);
            wal_ptr += op->key_size;

            if (op->value_size > 0 && op->value)
            {
                memcpy(wal_ptr, op->value, op->value_size);
                wal_ptr += op->value_size;
            }
        }
    }

    int commit_failed_at = -1;
    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        cf_commit_ctx_t *ctx = &cf_contexts[cf_idx];
        if (ctx->op_count == 0)
        {
            continue; /* no operations for this CF */
        }

        tidesdb_column_family_t *cf = ctx->cf;

        block_manager_block_t *batch_block =
            block_manager_block_create(ctx->wal_size, ctx->wal_batch);
        if (!batch_block)
        {
            commit_failed_at = cf_idx;
            break;
        }

        int is_single_cf = (txn->num_cfs == 1) ? 1 : 0;
        if (is_single_cf && ctx->op_count > 0)
        {
            uint8_t *wal_ptr = ctx->wal_batch;
            for (int seq_i = 0; seq_i < ctx->op_count; seq_i++)
            {
                tidesdb_klog_entry_t *entry = (tidesdb_klog_entry_t *)wal_ptr;
                entry->seq = ctx->seq_numbers[seq_i];

                wal_ptr += sizeof(tidesdb_klog_entry_t);
                wal_ptr += entry->key_size;
                wal_ptr += entry->value_size;
            }
        }

        block_manager_t *target_wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);
        int64_t wal_offset = block_manager_block_write(target_wal, batch_block);
        block_manager_block_release(batch_block);

        if (wal_offset < 0)
        {
            commit_failed_at = cf_idx;
            break;
        }

        uint64_t my_ticket = atomic_fetch_add_explicit(&cf->commit_ticket, 1, memory_order_relaxed);

        /* wait for our turn */
        uint64_t spin_count = 0;
        while (atomic_load_explicit(&cf->commit_serving, memory_order_acquire) != my_ticket)
        {
            if (spin_count < TDB_TXN_SPIN_COUNT)
            {
                cpu_pause();
                spin_count++;
            }
            else
            {
                cpu_yield();
                spin_count = 0;
            }
        }

        skip_list_t *target_memtable =
            atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

        int seq_idx = 0;
        int ops_written = 0;
        uint64_t max_seq_written = 0;

        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            uint64_t op_seq = atomic_fetch_add_explicit(&cf->next_seq_num, 1, memory_order_relaxed);
            ctx->seq_numbers[seq_idx++] = op_seq;

            skip_list_put_with_seq(target_memtable, op->key, op->key_size, op->value,
                                   op->value_size, op->ttl, op_seq, op->is_delete);

            if (op_seq > max_seq_written) max_seq_written = op_seq;
            ops_written++;
        }

        if (ops_written > 0)
        {
            atomic_thread_fence(memory_order_release);
            atomic_store_explicit(&cf->commit_seq, max_seq_written, memory_order_release);
        }

        ctx->committed = 1;

        size_t current_memtable_size = (size_t)skip_list_get_size(target_memtable);
        int should_flush = (current_memtable_size >= cf->config.write_buffer_size) ? 1 : 0;

        /* block if flush queue exceeds threshold before triggering a new flush
         * this provides backpressure to prevent memory exhaustion from too many
         * immutable memtables waiting to be flushed */
        if (should_flush && cf->db->config.flush_queue_threshold > 0)
        {
            int wait_count = 0;
            int current_queue_size;

            while ((current_queue_size = queue_size(cf->db->flush_queue)) >=
                   cf->db->config.flush_queue_threshold)
            {
                if (wait_count == 0)
                {
                    TDB_DEBUG_LOG(
                        "CF '%s': Flush queue full (%d >= %d), blocking commit until flushes "
                        "complete",
                        cf->name, current_queue_size, cf->db->config.flush_queue_threshold);
                }
                wait_count++;

                /* release commit ticket temporarily to allow other commits to proceed */
                atomic_store_explicit(&cf->commit_serving, my_ticket + 1, memory_order_release);

                /* sleep briefly to avoid busy-waiting (L0_QUEUE_CHECK_BACKOFF_MICRO_SECONDS) */
                usleep(L0_QUEUE_CHECK_BACKOFF_MICRO_SECONDS);

                /* re-acquire commit ticket */
                my_ticket = atomic_fetch_add_explicit(&cf->commit_ticket, 1, memory_order_relaxed);
                while (atomic_load_explicit(&cf->commit_serving, memory_order_acquire) != my_ticket)
                {
                    cpu_pause();
                }
            }

            if (wait_count > 0)
            {
                TDB_DEBUG_LOG(
                    "CF '%s': Flush queue drained after %d waits (now %d), proceeding with commit",
                    cf->name, wait_count, current_queue_size);
            }
        }

        atomic_store_explicit(&cf->commit_serving, my_ticket + 1, memory_order_release);

        if (should_flush)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    if (commit_failed_at >= 0)
    {
        TDB_DEBUG_LOG("Multi-CF commit failed at CF %d, rolling back", commit_failed_at);

        /* rollback all committed CFs by writing compensating tombstones */
        for (int cf_idx = 0; cf_idx < commit_failed_at; cf_idx++)
        {
            cf_commit_ctx_t *ctx = &cf_contexts[cf_idx];
            if (!ctx->committed) continue;

            tidesdb_column_family_t *cf = ctx->cf;

            uint64_t rollback_ticket =
                atomic_fetch_add_explicit(&cf->commit_ticket, 1, memory_order_relaxed);
            while (atomic_load_explicit(&cf->commit_serving, memory_order_acquire) !=
                   rollback_ticket)
            {
                cpu_pause();
            }

            skip_list_t *memtable =
                atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

            /* write tombstones for all operations in this CF */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_txn_op_t *op = &txn->ops[i];
                if (op->cf != cf) continue;

                /* write tombstone with new sequence number to undo the operation */
                uint64_t rollback_seq =
                    atomic_fetch_add_explicit(&cf->next_seq_num, 1, memory_order_relaxed);
                skip_list_put_with_seq(memtable, op->key, op->key_size, NULL, 0, 0, rollback_seq,
                                       1);
            }

            /* update commit_seq and release ticket */
            uint64_t max_rollback_seq =
                atomic_load_explicit(&cf->next_seq_num, memory_order_acquire) - 1;
            atomic_thread_fence(memory_order_release);
            atomic_store_explicit(&cf->commit_seq, max_rollback_seq, memory_order_release);
            atomic_store_explicit(&cf->commit_serving, rollback_ticket + 1, memory_order_release);
        }

        for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
        {
            free(cf_contexts[cf_idx].wal_batch);
            free(cf_contexts[cf_idx].seq_numbers);
        }
        free(cf_contexts);

        return TDB_ERR_IO;
    }

    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        free(cf_contexts[cf_idx].wal_batch);
        free(cf_contexts[cf_idx].seq_numbers);
    }
    free(cf_contexts);

    txn->is_committed = 1;

    /* unregister from all CF active transaction buffers */
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cf_txn_slots[i] != BUFFER_INVALID_ID)
        {
            tidesdb_txn_unregister(txn->cfs[i], txn->cf_txn_slots[i]);
            txn->cf_txn_slots[i] = BUFFER_INVALID_ID;
        }
    }

    return TDB_SUCCESS;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed) return TDB_ERR_INVALID_ARGS;

    /* simply mark as aborted; operations never applied */
    txn->is_aborted = 1;

    /* unregister from all CF active transaction buffers */
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cf_txn_slots[i] != BUFFER_INVALID_ID)
        {
            tidesdb_txn_unregister(txn->cfs[i], txn->cf_txn_slots[i]);
            txn->cf_txn_slots[i] = BUFFER_INVALID_ID;
        }
    }

    /* if nested, merge back to parent */
    if (txn->parent)
    {
        /* don't apply operations to parent on rollback */
    }

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

    for (int i = 0; i < txn->write_set_count; i++)
    {
        free(txn->write_keys[i]);
    }
    free(txn->write_keys);
    free(txn->write_key_sizes);
    free(txn->write_cfs);

    for (int i = 0; i < txn->num_savepoints; i++)
    {
        free(txn->savepoint_names[i]);
        tidesdb_txn_free(txn->savepoints[i]);
    }
    free(txn->savepoints);
    free(txn->savepoint_names);

    free(txn->cfs);
    free(txn->cf_snapshots);
    free(txn->cf_txn_slots);
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
    savepoint->isolation_level = txn->isolation_level;
    savepoint->txn_id = txn->txn_id;
    savepoint->parent = txn;

    savepoint->num_cfs = txn->num_cfs;
    savepoint->cf_capacity = txn->num_cfs;
    if (txn->num_cfs > 0)
    {
        savepoint->cfs = malloc(txn->num_cfs * sizeof(tidesdb_column_family_t *));
        savepoint->cf_snapshots = malloc(txn->num_cfs * sizeof(uint64_t));
        if (!savepoint->cfs || !savepoint->cf_snapshots)
        {
            free(savepoint->cfs);
            free(savepoint->cf_snapshots);
            free(savepoint);
            return TDB_ERR_MEMORY;
        }
        memcpy(savepoint->cfs, txn->cfs, txn->num_cfs * sizeof(tidesdb_column_family_t *));
        memcpy(savepoint->cf_snapshots, txn->cf_snapshots, txn->num_cfs * sizeof(uint64_t));
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

    /* check isolation level visibility */
    switch (iter->txn->isolation_level)
    {
        case TDB_ISOLATION_READ_UNCOMMITTED:
        case TDB_ISOLATION_READ_COMMITTED:
            /* accept any committed version (all versions in iterator are committed) */
            return 1;

        case TDB_ISOLATION_SNAPSHOT:
            /* only accept versions <= CF snapshot sequence */
            return (kv->entry.seq <= iter->cf_snapshot);

        default:
            return 1;
    }
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
    (*iter)->snapshot_time = time(NULL);
    (*iter)->cf_snapshot = txn->cf_snapshots[cf_index]; /* use per-CF snapshot */

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

    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    size_t imm_count = queue_size(cf->immutable_memtables);

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

    for (size_t i = 0; i < imm_count; i++)
    {
        tidesdb_immutable_memtable_t *imm =
            (tidesdb_immutable_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
        if (imm && imm->memtable)
        {
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
        }
    }

    tidesdb_wait_for_dca(cf);
    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    /* collect sstable pointers with references held
     * use dynamic array that grows as needed */
    int ssts_capacity = 64;
    tidesdb_sstable_t **ssts_array = malloc(ssts_capacity * sizeof(tidesdb_sstable_t *));
    int sst_count = 0;

    if (ssts_array)
    {
        /* iterate through levels and take refs immediately to minimize race window */
        for (int i = 0; i < num_levels; i++)
        {
            tidesdb_level_t *level = cf->levels[i];

            /* CRITICAL: load count BEFORE array pointer to prevent TOCTOU race.
             * If we load array first, compaction could remove an SSTable and decrement count,
             * causing us to skip the last entry. Loading count first ensures we iterate
             * through at least the SSTables that existed when we started. */
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

            /* clean up previous state */
            tidesdb_klog_block_free(source->source.sstable.current_block);
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

            block_manager_cursor_goto_first(cursor);

            if (sst->block_indexes && sst->block_indexes->count > 0)
            {
                int64_t block_num = 0;
                /* find predecessor largest indexed block where first_key <= target */
                int lookup_result = compact_block_index_find_predecessor(sst->block_indexes, key,
                                                                         key_size, &block_num);

                if (lookup_result == 0 && block_num > 0)
                {
                    for (int64_t i = 0; i < block_num; i++)
                    {
                        if (block_manager_cursor_next(cursor) != 0)
                        {
                            TDB_DEBUG_LOG("Seek: failed to advance to block %" PRId64
                                          ", stopping at block %" PRId64,
                                          block_num, i);
                            break;
                        }
                    }
                }
            }

            skip_list_comparator_fn comparator_fn = NULL;
            void *comparator_ctx = NULL;
            tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

            /* manually load and scan blocks to find target (advance() won't work here) */
            source->source.sstable.current_entry_idx = 0;

            int blocks_scanned = 0;
            while (1)
            {
                /* check if cursor is past data end offset */
                if (sst->klog_data_end_offset > 0 &&
                    cursor->current_pos >= sst->klog_data_end_offset)
                {
                    break;
                }

                /* read current block */
                block_manager_block_t *bmblock = block_manager_cursor_read(cursor);
                if (!bmblock)
                {
                    TDB_DEBUG_LOG("Seek: failed to read block after %d blocks", blocks_scanned);
                    break;
                }
                blocks_scanned++;

                uint8_t *data = bmblock->data;
                size_t data_size = bmblock->size;
                uint8_t *decompressed = NULL;

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

                tidesdb_klog_block_t *kb = NULL;
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

                /* check if target could be in this block -- check both min and max */
                int cmp_first = comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size,
                                              comparator_ctx);
                int cmp_last = comparator_fn(kb->keys[kb->num_entries - 1],
                                             kb->entries[kb->num_entries - 1].key_size, key,
                                             key_size, comparator_ctx);

                /* if first key > target, we've gone past it -- stop searching */
                if (cmp_first > 0)
                {
                    tidesdb_klog_block_free(kb);
                    source->source.sstable.current_block = NULL;
                    if (decompressed)
                    {
                        free(decompressed);
                        source->source.sstable.decompressed_data = NULL;
                    }
                    block_manager_block_release(bmblock);
                    break; /* target not in sst */
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
                        /* found target entry, now safe to store block */
                        source->source.sstable.current_block_data = bmblock;
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
                        break; /* found, exit loop */
                    }
                }

                /* target not in this block, clean up and try next */
                tidesdb_klog_block_free(kb);
                source->source.sstable.current_block = NULL;
                if (decompressed)
                {
                    free(decompressed);
                    source->source.sstable.decompressed_data = NULL;
                }
                block_manager_block_release(bmblock);

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

    /* peek at first visible entry (don't pop yet, sources are already positioned) */
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

            /* clean up previous state */
            tidesdb_klog_block_free(source->source.sstable.current_block);
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

            block_manager_cursor_goto_first(cursor);

            if (sst->block_indexes && sst->block_indexes->count > 0)
            {
                int64_t block_num = 0;
                if (compact_block_index_find_predecessor(sst->block_indexes, key, key_size,
                                                         &block_num) == 0 &&
                    block_num > 0)
                {
                    /* we skip to the predecessor block by advancing cursor */
                    for (int64_t i = 0; i < block_num; i++)
                    {
                        if (block_manager_cursor_next(cursor) != 0) break;
                    }
                }
            }

            /* manually scan blocks to find last entry <= target */
            source->source.sstable.current_entry_idx = 0;
            tidesdb_klog_block_t *last_valid_block = NULL;
            int last_valid_idx = -1;
            block_manager_block_t *last_valid_bmblock = NULL;
            uint8_t *last_valid_decompressed = NULL;

            while (1)
            {
                /* check if cursor is past data end offset */
                if (sst->klog_data_end_offset > 0 &&
                    cursor->current_pos >= sst->klog_data_end_offset)
                {
                    break;
                }

                /* read current block */
                block_manager_block_t *bmblock = block_manager_cursor_read(cursor);
                if (!bmblock) break;

                /* block is owned by us */

                uint8_t *data = bmblock->data;
                size_t data_size = bmblock->size;
                uint8_t *decompressed = NULL;

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

                tidesdb_klog_block_t *kb = NULL;
                if (tidesdb_klog_block_deserialize(data, data_size, &kb) != 0 || !kb)
                {
                    if (decompressed) free(decompressed);
                    block_manager_block_release(bmblock);
                    break;
                }

                skip_list_comparator_fn comparator_fn = NULL;
                void *comparator_ctx = NULL;
                tidesdb_resolve_comparator(sst->db, sst->config, &comparator_fn, &comparator_ctx);

                /* check if first key in this block is > target */
                int cmp_first = comparator_fn(kb->keys[0], kb->entries[0].key_size, key, key_size,
                                              comparator_ctx);

                if (cmp_first > 0)
                {
                    /* this block's first key is beyond target, use previous block */
                    tidesdb_klog_block_free(kb);
                    if (decompressed) free(decompressed);
                    block_manager_block_release(bmblock);
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
                    if (last_valid_block) tidesdb_klog_block_free(last_valid_block);
                    if (last_valid_decompressed) free(last_valid_decompressed);
                    if (last_valid_bmblock) block_manager_block_release(last_valid_bmblock);

                    last_valid_block = kb;
                    last_valid_idx = result_idx;
                    last_valid_bmblock = bmblock;
                    last_valid_decompressed = decompressed;
                }
                else
                {
                    /* no valid entry in this block */
                    tidesdb_klog_block_free(kb);
                    if (decompressed) free(decompressed);
                    block_manager_block_release(bmblock);
                }

                /* try next block */
                if (block_manager_cursor_next(cursor) != 0) break;
            }

            /* use the last valid entry we found */
            if (last_valid_block && last_valid_idx >= 0)
            {
                source->source.sstable.current_block = last_valid_block;
                source->source.sstable.current_block_data = last_valid_bmblock;
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
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap);
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

                    /* don't free decompressed or release block if we're still using the
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

            if (iter->txn->isolation_level == TDB_ISOLATION_SNAPSHOT)
            {
                tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                            kv->entry.seq);
            }

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
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap);
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

            if (iter->txn->isolation_level == TDB_ISOLATION_SNAPSHOT)
            {
                tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                            kv->entry.seq);
            }

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

            if (iter->txn->isolation_level == TDB_ISOLATION_SNAPSHOT)
            {
                tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                            kv->entry.seq);
            }

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

        if (iter->txn->isolation_level == TDB_ISOLATION_SNAPSHOT)
        {
            tidesdb_txn_add_to_read_set(iter->txn, iter->cf, kv->key, kv->entry.key_size,
                                        kv->entry.seq);
        }

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

    multi_cf_txn_tracker_t *tracker = multi_cf_tracker_create(1024);
    if (!tracker)
    {
        TDB_DEBUG_LOG("CF '%s': Failed to create multi-CF tracker, proceeding without validation",
                      cf->name);
    }

    /* we scan all WALs to collect multi-CF transaction info */
    if (tracker)
    {
        size_t wal_count = queue_size(wal_files);
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

    /* we recover from each WAL file, applying only complete transactions */
    while (!queue_is_empty(wal_files))
    {
        char *wal_path = queue_dequeue(wal_files);
        if (!wal_path) continue;

        skip_list_t *recovered_memtable = NULL;
        int recover_result = tidesdb_wal_recover(cf, wal_path, &recovered_memtable, tracker);

        if (recover_result == TDB_SUCCESS && recovered_memtable)
        {
            if (skip_list_count_entries(recovered_memtable) > 0)
            {
                block_manager_t *wal_bm = NULL;

                if (block_manager_open(&wal_bm, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0)
                {
                    TDB_DEBUG_LOG("CF '%s': Failed to reopen WAL for flush tracking: %s", cf->name,
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
                            "CF '%s': Queued recovered memtable for async flush (WAL: %s)",
                            cf->name, wal_path);

                        tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
                        if (work)
                        {
                            work->cf = cf;
                            work->imm = imm;
                            work->sst_id = atomic_fetch_add_explicit(&cf->next_sstable_id, 1,
                                                                     memory_order_relaxed);
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
                        TDB_DEBUG_LOG("CF '%s': Failed to enqueue recovered memtable", cf->name);
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
                skip_list_free(recovered_memtable);
                TDB_DEBUG_LOG("CF '%s': Empty recovered memtable, deleting WAL: %s", cf->name,
                              wal_path);
                unlink(wal_path);
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

    TDB_DEBUG_LOG("Recovering SSTables from directory: %s", cf->directory);
    dir = opendir(cf->directory);
    if (!dir) return TDB_ERR_IO;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, ".klog") != NULL)
        {
            TDB_DEBUG_LOG("Found .klog file: %s", entry->d_name);
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
                TDB_DEBUG_LOG("Parsed partitioned SSTable: level=%d, partition=%d, id=%llu",
                              level_num, partition_num, sst_id_ull);
            }
            /** try non-partitioned format:
             * L{level}_{id}.klog */
            else if (sscanf(entry->d_name, TDB_LEVEL_PREFIX "%d_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT,
                            &level_num, &sst_id_ull) == 2)
            {
                snprintf(sst_base, sizeof(sst_base), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d",
                         cf->directory, level_num);
                parsed = 1;
                TDB_DEBUG_LOG("Parsed non-partitioned SSTable: level=%d, id=%llu", level_num,
                              sst_id_ull);
            }

            if (parsed)
            {
                uint64_t sst_id = (uint64_t)sst_id_ull;
                tidesdb_sstable_t *sst =
                    tidesdb_sstable_create(cf->db, sst_base, sst_id, &cf->config);
                if (sst)
                {
                    TDB_DEBUG_LOG("CF '%s': Recovering SSTable %" PRIu64 " at level %d", cf->name,
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
                        TDB_DEBUG_LOG("CF '%s': SSTable %" PRIu64
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

    tidesdb_wait_for_dca(cf);

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    TDB_DEBUG_LOG("CF '%s': Scanning sources for max_seq", cf->name);

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

        for (size_t i = 0; i < imm_count; i++)
        {
            tidesdb_immutable_memtable_t *imm = queue_peek_at(cf->immutable_memtables, i);
            if (imm && imm->memtable)
            {
                skip_list_cursor_t *cursor;
                if (skip_list_cursor_init(&cursor, imm->memtable) == 0)
                {
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

    uint64_t next_seq = global_max_seq + 1;
    atomic_store(&cf->next_seq_num, next_seq);
    atomic_store(&cf->commit_seq, next_seq);
    TDB_DEBUG_LOG("CF '%s': Recovery complete, global_max_seq=%" PRIu64 ", next_seq=%" PRIu64,
                  cf->name, global_max_seq, next_seq);

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

    TDB_DEBUG_LOG("Starting database recovery from: %s", db->db_path);

    DIR *dir = opendir(db->db_path);
    if (!dir)
    {
        TDB_DEBUG_LOG("No existing database directory found (fresh start)");
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
            TDB_DEBUG_LOG("Found CF directory: %s", entry->d_name);
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, entry->d_name);

            if (!cf)
            {
                tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
                int create_result = tidesdb_create_column_family(db, entry->d_name, &config);

                if (create_result == TDB_SUCCESS)
                {
                    cf = tidesdb_get_column_family(db, entry->d_name);
                }
                else if (create_result == TDB_ERR_EXISTS)
                {
                    /* CF already exists in memory, try to get it again */
                    cf = tidesdb_get_column_family(db, entry->d_name);
                    TDB_DEBUG_LOG("CF already exists during recovery: %s", entry->d_name);
                }
                else
                {
                    TDB_DEBUG_LOG("Failed to create CF during recovery: %s (error code: %d)",
                                  entry->d_name, create_result);
                }
            }

            if (cf)
            {
                TDB_DEBUG_LOG("Recovering CF: %s", entry->d_name);
                tidesdb_recover_column_family(cf);
            }
            else
            {
                TDB_DEBUG_LOG("Failed to get/create CF: %s", entry->d_name);
            }
        }
    }
    closedir(dir);

    TDB_DEBUG_LOG("Database recovery completed successfully");
    return TDB_SUCCESS;
}

int tidesdb_get_stats(tidesdb_column_family_t *cf, tidesdb_stats_t **stats)
{
    if (!cf || !stats) return TDB_ERR_INVALID_ARGS;

    *stats = calloc(1, sizeof(tidesdb_stats_t));
    if (!*stats) return TDB_ERR_MEMORY;

    tidesdb_wait_for_dca(cf);

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
    else if (strcmp(name, "klog_block_size") == 0)
    {
        ctx->config->klog_block_size = (size_t)atoll(value);
    }
    else if (strcmp(name, "vlog_block_size") == 0)
    {
        ctx->config->vlog_block_size = (size_t)atoll(value);
    }
    else if (strcmp(name, "value_threshold") == 0)
    {
        ctx->config->value_threshold = (size_t)atoll(value);
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
        if (strcmp(value, "READ_UNCOMMITTED") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;
        else if (strcmp(value, "READ_COMMITTED") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_READ_COMMITTED;
        else if (strcmp(value, "REPEATABLE_READ") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_REPEATABLE_READ;
        else if (strcmp(value, "SNAPSHOT") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_SNAPSHOT;
        else if (strcmp(value, "SERIALIZABLE") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_SERIALIZABLE;
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
    fprintf(fp, "klog_block_size = %zu\n", config->klog_block_size);
    fprintf(fp, "vlog_block_size = %zu\n", config->vlog_block_size);
    fprintf(fp, "value_threshold = %zu\n", config->value_threshold);

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
    fprintf(fp, "sync_mode = %d\n", config->sync_mode);
    fprintf(fp, "sync_interval_us = %" PRIu64 "\n", config->sync_interval_us);
    fprintf(fp, "skip_list_max_level = %d\n", config->skip_list_max_level);
    fprintf(fp, "skip_list_probability = %f\n", config->skip_list_probability);

    const char *isolation_str = "READ_COMMITTED";
    switch (config->default_isolation_level)
    {
        case TDB_ISOLATION_READ_UNCOMMITTED:
            isolation_str = "READ_UNCOMMITTED";
            break;
        case TDB_ISOLATION_READ_COMMITTED:
            isolation_str = "READ_COMMITTED";
            break;
        case TDB_ISOLATION_REPEATABLE_READ:
            isolation_str = "REPEATABLE_READ";
            break;
        case TDB_ISOLATION_SNAPSHOT:
            isolation_str = "SNAPSHOT";
            break;
        case TDB_ISOLATION_SERIALIZABLE:
            isolation_str = "SERIALIZABLE";
            break;
    }
    fprintf(fp, "default_isolation_level = %s\n", isolation_str);

    fprintf(fp, "comparator_name = %s\n", config->comparator_name);
    if (config->comparator_ctx_str[0] != '\0')
    {
        fprintf(fp, "comparator_ctx_str = %s\n", config->comparator_ctx_str);
    }

    fclose(fp);
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
    cf->config.compression_algorithm = new_config->compression_algorithm;
    cf->config.write_buffer_size = new_config->write_buffer_size;
    cf->config.level_size_ratio = new_config->level_size_ratio;
    cf->config.min_levels = new_config->min_levels;
    cf->config.dividing_level_offset = new_config->dividing_level_offset;
    cf->config.sync_mode = new_config->sync_mode;
    cf->config.sync_interval_us = new_config->sync_interval_us;
    cf->config.default_isolation_level = new_config->default_isolation_level;
    cf->config.value_threshold = new_config->value_threshold;

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
                                                         tidesdb_comparator_fn comparator,
                                                         void *comparator_ctx)
{
    if (initial_capacity == 0) initial_capacity = 16;

    tidesdb_block_index_t *index = calloc(1, sizeof(tidesdb_block_index_t));
    if (!index) return NULL;

    index->min_key_prefixes = malloc(initial_capacity * TDB_BLOCK_INDEX_PREFIX_LEN);
    index->max_key_prefixes = malloc(initial_capacity * TDB_BLOCK_INDEX_PREFIX_LEN);
    index->block_nums = malloc(initial_capacity * sizeof(int64_t));

    if (!index->min_key_prefixes || !index->max_key_prefixes || !index->block_nums)
    {
        compact_block_index_free(index);
        return NULL;
    }

    index->capacity = initial_capacity;
    index->count = 0;
    index->prefix_len = TDB_BLOCK_INDEX_PREFIX_LEN;
    index->comparator = comparator;
    index->comparator_ctx = comparator_ctx;

    return index;
}

/**
 * encode_varint
 * encodes a 64-bit unsigned integer using variable-length encoding
 * small values use fewer bytes (1-9 bytes depending on magnitude)
 * @param value the value to encode
 * @param buffer the buffer to write to (must have at least 10 bytes)
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
 * decodes a variable-length encoded 64-bit unsigned integer
 * @param buffer the buffer to read from
 * @param bytes_read output parameter for number of bytes consumed
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

/**
 * encode_signed_varint
 * encodes a signed 64-bit integer using zigzag encoding + varint
 * zigzag maps signed integers to unsigned: 0,-1,1,-2,2... -> 0,1,2,3,4...
 * @param value the signed value to encode
 * @param buffer the buffer to write to (must have at least 10 bytes)
 * @return number of bytes written
 */
static inline size_t encode_signed_varint(int64_t value, uint8_t *buffer)
{
    /* (n << 1) ^ (n >> 63) */
    uint64_t zigzag = ((uint64_t)value << 1) ^ (uint64_t)(value >> 63);
    return encode_varint(zigzag, buffer);
}

/**
 * decode_signed_varint
 * decodes a zigzag-encoded signed 64-bit integer
 * @param buffer the buffer to read from
 * @param bytes_read output parameter for number of bytes consumed
 * @return the decoded signed value
 */
static inline int64_t decode_signed_varint(const uint8_t *buffer, size_t *bytes_read)
{
    uint64_t zigzag = decode_varint(buffer, bytes_read);
    /* (n >> 1) ^ -(n & 1) */
    return (int64_t)((zigzag >> 1) ^ (-(int64_t)(zigzag & 1)));
}

static uint8_t *compact_block_index_serialize(const tidesdb_block_index_t *index, size_t *out_size)
{
    if (!index || !out_size) return NULL;

    /* header: count (4) + prefix_len (1) + block_nums (varint) + min/max prefixes */
    size_t max_size = sizeof(uint32_t) + sizeof(uint8_t) +
                      index->count * 10 +                   /* block_nums (varint) */
                      index->count * index->prefix_len * 2; /* min + max prefixes */

    uint8_t *data = malloc(max_size);
    if (!data) return NULL;

    uint8_t *ptr = data;

    /* header: count + prefix_len */
    encode_uint32_le_compat(ptr, index->count);
    ptr += sizeof(uint32_t);
    *ptr++ = index->prefix_len;

    /* delta encode + varint compress block_nums */
    if (index->count > 0)
    {
        /* first block number stored as-is */
        ptr += encode_signed_varint(index->block_nums[0], ptr);

        /* remaining block numbers stored as deltas */
        for (uint32_t i = 1; i < index->count; i++)
        {
            int64_t delta = index->block_nums[i] - index->block_nums[i - 1];
            ptr += encode_signed_varint(delta, ptr);
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

    if (prefix_len != TDB_BLOCK_INDEX_PREFIX_LEN)
    {
        return NULL; /* incompatible format */
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
        index->block_nums = NULL;
        return index;
    }

    index->min_key_prefixes = malloc(count * prefix_len);
    index->max_key_prefixes = malloc(count * prefix_len);
    index->block_nums = malloc(count * sizeof(int64_t));

    if (!index->min_key_prefixes || !index->max_key_prefixes || !index->block_nums)
    {
        compact_block_index_free(index);
        return NULL;
    }

    /* decode delta-encoded varint block_nums */
    if (count > 0)
    {
        size_t bytes_read;

        /* first block number */
        if (ptr >= end) goto error;
        index->block_nums[0] = decode_signed_varint(ptr, &bytes_read);
        ptr += bytes_read;

        /* remaining block numbers (deltas) */
        for (uint32_t i = 1; i < count; i++)
        {
            if (ptr >= end) goto error;
            int64_t delta = decode_signed_varint(ptr, &bytes_read);
            ptr += bytes_read;
            index->block_nums[i] = index->block_nums[i - 1] + delta;
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
    index->comparator = NULL; /* set by caller */
    index->comparator_ctx = NULL;

    return index;

error:
    compact_block_index_free(index);
    return NULL;
}

static int compact_block_index_add(tidesdb_block_index_t *index, const uint8_t *min_key,
                                   size_t min_key_len, const uint8_t *max_key, size_t max_key_len,
                                   int64_t block_num)
{
    if (!index || !min_key || !max_key || min_key_len == 0 || max_key_len == 0) return -1;

    /* resize arrays if needed */
    if (index->count >= index->capacity)
    {
        uint32_t new_cap = index->capacity * 2;
        uint8_t *new_min_prefixes = realloc(index->min_key_prefixes, new_cap * index->prefix_len);
        uint8_t *new_max_prefixes = realloc(index->max_key_prefixes, new_cap * index->prefix_len);
        int64_t *new_block_nums = realloc(index->block_nums, new_cap * sizeof(int64_t));

        if (!new_min_prefixes || !new_max_prefixes || !new_block_nums)
        {
            return -1;
        }

        index->min_key_prefixes = new_min_prefixes;
        index->max_key_prefixes = new_max_prefixes;
        index->block_nums = new_block_nums;
        index->capacity = new_cap;
    }

    /* store fixed-length prefixes (zero-padded if key is shorter) */
    uint8_t *min_dest = index->min_key_prefixes + (index->count * index->prefix_len);
    uint8_t *max_dest = index->max_key_prefixes + (index->count * index->prefix_len);

    /* copy min key prefix (zero-pad if shorter) */
    size_t min_copy_len = (min_key_len < index->prefix_len) ? min_key_len : index->prefix_len;
    memcpy(min_dest, min_key, min_copy_len);
    if (min_copy_len < index->prefix_len)
    {
        memset(min_dest + min_copy_len, 0, index->prefix_len - min_copy_len);
    }

    /* copy max key prefix (zero-pad if shorter) */
    size_t max_copy_len = (max_key_len < index->prefix_len) ? max_key_len : index->prefix_len;
    memcpy(max_dest, max_key, max_copy_len);
    if (max_copy_len < index->prefix_len)
    {
        memset(max_dest + max_copy_len, 0, index->prefix_len - max_copy_len);
    }

    index->block_nums[index->count] = block_num;
    index->count++;

    return 0;
}

static int compact_block_index_find_predecessor(const tidesdb_block_index_t *index,
                                                const uint8_t *key, size_t key_len,
                                                int64_t *block_num)
{
    if (!index || !key || index->count == 0) return -1;

    /* create prefix of search key for comparison */
    uint8_t search_prefix[TDB_BLOCK_INDEX_PREFIX_LEN];
    size_t copy_len = (key_len < index->prefix_len) ? key_len : index->prefix_len;
    memcpy(search_prefix, key, copy_len);
    if (copy_len < index->prefix_len)
    {
        memset(search_prefix + copy_len, 0, index->prefix_len - copy_len);
    }

    /* binary search to find rightmost block where min_key <= search_key */
    int64_t left = 0, right = index->count - 1, result = -1;

    while (left <= right)
    {
        int64_t mid = left + (right - left) / 2;
        const uint8_t *mid_min_prefix = index->min_key_prefixes + (mid * index->prefix_len);

        /* compare search key with block's min key */
        int cmp;
        if (index->comparator)
        {
            cmp = index->comparator(mid_min_prefix, index->prefix_len, search_prefix,
                                    index->prefix_len, index->comparator_ctx);
        }
        else
        {
            cmp = memcmp(mid_min_prefix, search_prefix, index->prefix_len);
        }

        /* find rightmost block where min_key <= search_key */
        if (cmp <= 0)
        {
            result = mid;
            left = mid + 1; /* continue searching right */
        }
        else
        {
            right = mid - 1; /* search left */
        }
    }

    if (result >= 0)
    {
        *block_num = index->block_nums[result];
        return 0;
    }

    return -1; /* no predecessor found */
}

static void compact_block_index_free(tidesdb_block_index_t *index)
{
    if (!index) return;
    free(index->min_key_prefixes);
    free(index->max_key_prefixes);
    free(index->block_nums);
    free(index);
}
