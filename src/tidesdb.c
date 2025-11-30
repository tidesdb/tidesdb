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

    int bucket = (int)(seq % tracker->num_buckets);
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
                                        tidesdb_column_family_config_t *config);
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
static tidesdb_sstable_t *tidesdb_sstable_create(const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config);
static void tidesdb_sstable_free(tidesdb_sstable_t *sst);
static void tidesdb_sstable_ref(tidesdb_sstable_t *sst);
static void tidesdb_sstable_unref(tidesdb_sstable_t *sst);
static int tidesdb_sstable_write_from_memtable(tidesdb_t *db, tidesdb_sstable_t *sst,
                                               skip_list_t *memtable);
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               size_t key_size, tidesdb_kv_pair_t **kv);
static int tidesdb_sstable_load(tidesdb_t *db, tidesdb_sstable_t *sst);
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity);
static void tidesdb_level_free(tidesdb_level_t *level);
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
static int tidesdb_add_level(tidesdb_column_family_t *cf);
static int tidesdb_remove_level(tidesdb_column_family_t *cf);
static int tidesdb_apply_dca(tidesdb_column_family_t *cf);
static int tidesdb_recover_database(tidesdb_t *db);
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf);
static void tidesdb_column_family_free(tidesdb_column_family_t *cf);
static void *tidesdb_flush_worker_thread(void *arg);
static void *tidesdb_compaction_worker_thread(void *arg);
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
 * Check if there's enough free disk space using cached value
 * Refreshes cache every 10 seconds to avoid expensive statvfs calls
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

    if (now - last_check >= 10)
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
 * tidesdb_check_write_stall
 * Check if writes should be stalled due to backpressure
 * Implements soft and hard limits on immutable memtable queue depth
 * @param cf column family
 * @return 0 if OK to write, 1 if should slow down, 2 if must stall
 */
static int tidesdb_check_write_stall(tidesdb_column_family_t *cf)
{
    if (!cf) return 0;

    size_t queue_depth = queue_size(cf->immutable_memtables);

    /* hard limit, we block writes completely */
    if (queue_depth >= (size_t)cf->config.write_stall_threshold)
    {
        TDB_DEBUG_LOG("CF '%s': Write stall (queue depth: %zu >= threshold: %d)", cf->name,
                      queue_depth, cf->config.write_stall_threshold);
        return 2;
    }

    /* soft limit, we slow down writes */
    if (queue_depth >= (size_t)cf->config.max_immutable_memtables)
    {
        TDB_DEBUG_LOG("CF '%s': Write slowdown (queue depth: %zu >= max: %d)", cf->name,
                      queue_depth, cf->config.max_immutable_memtables);
        return 1;
    }

    return 0;
}

/* sstable metadata structure */
#define SSTABLE_METADATA_MAGIC 0x5353544D /* SSTM */

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
 * @param min_key min key
 * @param max_key max key
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
    uint32_t reserved; /* padding for alignment */
    uint64_t checksum; /* xxHash64 checksum of all fields except checksum itself */
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

    /* calculate size: all fields + keys */
    size_t header_size = 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4; /* fixed 84 bytes */
    size_t total_size = header_size + sst->min_key_size + sst->max_key_size;

    uint8_t *data = malloc(total_size);
    if (!data) return -1;

    uint8_t *ptr = data;

    /* serialize fields with explicit little-endian encoding */
    encode_uint32_le_compat(ptr, SSTABLE_METADATA_MAGIC);
    ptr += 4;
    encode_uint64_le_compat(ptr, sst->num_entries);
    ptr += 8;
    encode_uint64_le_compat(ptr, atomic_load(&sst->num_klog_blocks));
    ptr += 8;
    encode_uint64_le_compat(ptr, atomic_load(&sst->num_vlog_blocks));
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
    }

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
    atomic_store(&sst->num_klog_blocks, num_klog_blocks);
    atomic_store(&sst->num_vlog_blocks, num_vlog_blocks);
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

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    tidesdb_column_family_config_t config = {
        .write_buffer_size = TDB_DEFAULT_WRITE_BUFFER_SIZE,
        .level_size_ratio = TDB_DEFAULT_LEVEL_SIZE_RATIO,
        .max_levels = TDB_DEFAULT_MAX_LEVELS,
        .dividing_level_offset = TDB_DEFAULT_DIVIDING_LEVEL_OFFSET,
        .klog_block_size = TDB_DEFAULT_KLOG_BLOCK_SIZE,
        .vlog_block_size = TDB_DEFAULT_VLOG_BLOCK_SIZE,
        .value_threshold = TDB_DEFAULT_VALUE_THRESHOLD,
        .compression_algorithm = LZ4_COMPRESSION,
        .enable_bloom_filter = 1,
        .bloom_fpr = TDB_DEFAULT_BLOOM_FPR,
        .enable_block_indexes = 1,
        .index_sample_ratio = TDB_DEFAULT_INDEX_SAMPLE_RATIO,
        .block_manager_cache_size = 32 * 1024 * 1024,
        .sync_mode = TDB_SYNC_NONE,
        .comparator = skip_list_comparator_memcmp,
        .comparator_ctx = NULL,
        .compaction_interval_ms = TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL,
        .enable_background_compaction = 1,
        .skip_list_max_level = 12,
        .skip_list_probability = 0.25f,
        .default_isolation_level = TDB_ISOLATION_READ_COMMITTED,
        .min_disk_space = TDB_DEFAULT_MIN_DISK_SPACE,
        .max_immutable_memtables = TDB_DEFAULT_MAX_IMMUTABLE_MEMTABLES,
        .write_stall_threshold = TDB_DEFAULT_WRITE_STALL_THRESHOLD};
    return config;
}

tidesdb_config_t tidesdb_default_config(void)
{
    tidesdb_config_t config = {.db_path = "./tidesdb",
                               .enable_debug_logging = 0,
                               .num_flush_threads = TDB_DEFAULT_THREAD_POOL_SIZE,
                               .num_compaction_threads = TDB_DEFAULT_THREAD_POOL_SIZE,
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
 * @param config column family config
 * @return 0 on success, -1 on error
 */
static int tidesdb_klog_block_add_entry(tidesdb_klog_block_t *block, const tidesdb_kv_pair_t *kv,
                                        tidesdb_column_family_config_t *config)
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

    /* update max_key for seek optimization
     * keep track of largest key in this block */
    if (block->num_entries == 1 ||
        config->comparator(kv->key, kv->entry.key_size, block->max_key, block->max_key_size,
                           config->comparator_ctx) > 0)
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
        memcpy(ptr, &block->entries[i], sizeof(tidesdb_klog_entry_t));
        ptr += sizeof(tidesdb_klog_entry_t);

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

        memcpy(&(*block)->entries[i], ptr, sizeof(tidesdb_klog_entry_t));
        ptr += sizeof(tidesdb_klog_entry_t);

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

    /* acquire block to prevent eviction during decompression */
    if (!block_manager_block_acquire(block))
    {
        block_manager_block_release(block);
        block_manager_cursor_free(cursor);
        return TDB_ERR_IO;
    }

    /* release the cursor's reference, keep our acquired reference */
    block_manager_block_release(block);

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
 * tidesdb_sstable_contains_key_range
 * check if a key falls within an sstable's range
 * @param sst sstable to check
 * @param key key to check
 * @param key_size size of key
 * @param comparator comparator function
 * @param comparator_ctx comparator context
 * @return 1 if key is within range, 0 otherwise
 */
static int tidesdb_sstable_contains_key_range(tidesdb_sstable_t *sst, const uint8_t *key,
                                              size_t key_size, skip_list_comparator_fn comparator,
                                              void *comparator_ctx)
{
    if (!sst->min_key || !sst->max_key) return 1; /* no range info, must check */
    if (!comparator) return 1;                    /* no comparator, must check */

    int cmp_min = comparator(key, key_size, sst->min_key, sst->min_key_size, comparator_ctx);
    if (cmp_min < 0) return 0; /* key < min, not in range */

    int cmp_max = comparator(key, key_size, sst->max_key, sst->max_key_size, comparator_ctx);
    if (cmp_max > 0) return 0; /* key > max, not in range */
    return 1;                  /* key is within [min, max] */
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

    /* ensure sstable is in cache and block managers are open */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        return TDB_ERR_IO;
    }

    /* get block managers from cache using sstable ID-based keys */
    char klog_cache_key[TDB_CACHE_KEY_LEN];
    char vlog_cache_key[TDB_CACHE_KEY_LEN];
    snprintf(klog_cache_key, sizeof(klog_cache_key), "bm:" TDB_U64_FMT ":klog",
             TDB_U64_CAST(sst->id));
    snprintf(vlog_cache_key, sizeof(vlog_cache_key), "bm:" TDB_U64_FMT ":vlog",
             TDB_U64_CAST(sst->id));

    bms->klog_bm = (block_manager_t *)fifo_cache_get(db->sstable_cache, klog_cache_key);
    bms->vlog_bm = (block_manager_t *)fifo_cache_get(db->sstable_cache, vlog_cache_key);

    if (!bms->klog_bm || !bms->vlog_bm)
    {
        return TDB_ERR_IO;
    }

    return TDB_SUCCESS;
}

/**
 * tidesdb_block_manager_cache_evict_cb
 * callback when a block manager is evicted from cache
 * closes the block manager to free file descriptors
 */
static void tidesdb_block_manager_cache_evict_cb(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    block_manager_t *bm = (block_manager_t *)value;

    if (bm)
    {
        block_manager_close(bm);
    }
}

/**
 * tidesdb_sstable_cache_evict_cb
 * callback when an sstable is evicted from cache
 * releases the sstable reference
 */
static void tidesdb_sstable_cache_evict_cb(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    tidesdb_sstable_t *sst = (tidesdb_sstable_t *)value;

    if (!sst) return;

    /* release the cache's reference to the sstable */
    tidesdb_sstable_unref(sst);
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
    char cache_key[TDB_CACHE_KEY_LEN];
    snprintf(cache_key, sizeof(cache_key), TDB_SSTABLE_CACHE_PREFIX "%" PRIu64, sst->id);

    /* check if already in cache */
    void *cached = fifo_cache_get(db->sstable_cache, cache_key);
    if (!cached)
    {
        /* increment refcount before adding to cache -- cache now owns a reference */
        tidesdb_sstable_ref(sst);

        /* add to cache, which will evict old entries if needed */
        if (fifo_cache_put(db->sstable_cache, cache_key, sst, tidesdb_sstable_cache_evict_cb,
                           NULL) != 0)
        {
            tidesdb_sstable_unref(sst); /* release ref if cache add failed */
            return -1;
        }
    }

    int expected_state = 2; /* check if already open */
    if (atomic_load_explicit(&sst->bm_open_state, memory_order_acquire) == 2)
    {
        return 0; /* already open */
    }

    /* try to transition from closed (0) to opening (1) */
    expected_state = 0;
    if (!atomic_compare_exchange_strong_explicit(&sst->bm_open_state, &expected_state, 1,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        /* someone else is opening or already opened */
        if (expected_state == 2) return 0; /* now open */

        /* wait for opening to complete (spin briefly, then yield) */
        int spin_count = 0;
        while (atomic_load_explicit(&sst->bm_open_state, memory_order_acquire) == 1)
        {
            if (++spin_count > 100)
            {
                usleep(1000); /* 1ms */
                spin_count = 0;
            }
        }
        return atomic_load_explicit(&sst->bm_open_state, memory_order_acquire) == 2 ? 0 : -1;
    }

    /* we won the race, open block managers and cache them */
    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open_with_cache(&klog_bm, sst->klog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        atomic_store_explicit(&sst->bm_open_state, 0, memory_order_release);
        return -1;
    }

    if (block_manager_open_with_cache(&vlog_bm, sst->vlog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        block_manager_close(klog_bm);
        atomic_store_explicit(&sst->bm_open_state, 0, memory_order_release);
        return -1;
    }

    /* add block managers to cache */
    char klog_cache_key[TDB_CACHE_KEY_LEN];
    char vlog_cache_key[TDB_CACHE_KEY_LEN];
    snprintf(klog_cache_key, sizeof(klog_cache_key), "bm:" TDB_U64_FMT ":klog",
             TDB_U64_CAST(sst->id));
    snprintf(vlog_cache_key, sizeof(vlog_cache_key), "bm:" TDB_U64_FMT ":vlog",
             TDB_U64_CAST(sst->id));

    if (fifo_cache_put(db->sstable_cache, klog_cache_key, klog_bm,
                       tidesdb_block_manager_cache_evict_cb, NULL) != 0)
    {
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        atomic_store_explicit(&sst->bm_open_state, 0, memory_order_release);
        return -1;
    }

    if (fifo_cache_put(db->sstable_cache, vlog_cache_key, vlog_bm,
                       tidesdb_block_manager_cache_evict_cb, NULL) != 0)
    {
        /* remove klog from cache since we're failing */
        fifo_cache_remove(db->sstable_cache, klog_cache_key);
        block_manager_close(vlog_bm);
        atomic_store_explicit(&sst->bm_open_state, 0, memory_order_release);
        return -1;
    }

    /* successfully opened, transition to open state */
    atomic_store_explicit(&sst->bm_open_state, 2, memory_order_release);
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
static tidesdb_sstable_t *tidesdb_sstable_create(const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config)
{
    tidesdb_sstable_t *sst = calloc(1, sizeof(tidesdb_sstable_t));
    if (!sst) return NULL;

    sst->config = malloc(sizeof(tidesdb_column_family_config_t));
    if (!sst->config)
    {
        free(sst);
        return NULL;
    }
    memcpy(sst->config, config, sizeof(tidesdb_column_family_config_t));

    sst->id = id;
    atomic_init(&sst->refcount, 1);
    atomic_init(&sst->num_klog_blocks, 0);
    atomic_init(&sst->num_vlog_blocks, 0);
    sst->klog_data_end_offset = 0;
    atomic_init(&sst->bm_open_state, 0);

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
 * @param sst sstable to free
 */
static void tidesdb_sstable_free(tidesdb_sstable_t *sst)
{
    if (!sst) return;

    free(sst->klog_path);
    free(sst->vlog_path);
    free(sst->min_key);
    free(sst->max_key);
    free(sst->config);

    if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
    if (sst->block_index) succinct_trie_free(sst->block_index);
    /* block managers are managed by cache, not freed here */

    free(sst);
}

/**
 * tidesdb_sstable_ref
 * increment reference count of an sstable
 * @param sst sstable to reference
 */
static void tidesdb_sstable_ref(tidesdb_sstable_t *sst)
{
    if (sst) atomic_fetch_add(&sst->refcount, 1);
}

/**
 * tidesdb_sstable_unref
 * decrement reference count of an sstable
 * @param sst sstable to unreference
 */
static void tidesdb_sstable_unref(tidesdb_sstable_t *sst)
{
    if (!sst) return;
    if (atomic_fetch_sub(&sst->refcount, 1) == 1)
    {
        tidesdb_sstable_free(sst);
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
    /* ensure sstable is in cache and get block managers */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        return TDB_ERR_IO;
    }

    tidesdb_block_managers_t bms;
    if (tidesdb_sstable_get_block_managers(db, sst, &bms) != TDB_SUCCESS)
    {
        return TDB_ERR_IO;
    }

    /* create bloom filter and index builder */
    bloom_filter_t *bloom = NULL;
    succinct_trie_builder_t *index_builder = NULL;

    int num_entries = skip_list_count_entries(memtable);

    if (sst->config->enable_bloom_filter)
    {
        if (bloom_filter_new(&bloom, sst->config->bloom_fpr, num_entries) != 0)
        {
            return TDB_ERR_MEMORY;
        }
    }

    if (sst->config->enable_block_indexes)
    {
        index_builder =
            succinct_trie_builder_new(NULL, sst->config->comparator, sst->config->comparator_ctx);
        if (!index_builder)
        {
            if (bloom) bloom_filter_free(bloom);
            return TDB_ERR_MEMORY;
        }
    }

    /* init blocks */
    tidesdb_klog_block_t *current_klog_block = tidesdb_klog_block_create();
    tidesdb_vlog_block_t *current_vlog_block = tidesdb_vlog_block_create();

    if (!current_klog_block || !current_vlog_block)
    {
        if (bloom) bloom_filter_free(bloom);
        if (index_builder) succinct_trie_builder_free(index_builder);
        tidesdb_klog_block_free(current_klog_block);
        tidesdb_vlog_block_free(current_vlog_block);
        return TDB_ERR_MEMORY;
    }

    skip_list_cursor_t *cursor;
    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        if (bloom) bloom_filter_free(bloom);
        if (index_builder) succinct_trie_builder_free(index_builder);
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
                                if (index_builder) succinct_trie_builder_free(index_builder);
                                return TDB_ERR_CORRUPTION;
                            }
                        }

                        block_manager_block_t *vlog_block =
                            block_manager_block_create(final_vlog_size, final_vlog_data);
                        if (vlog_block)
                        {
                            block_manager_block_write(bms.vlog_bm, vlog_block);
                            block_manager_block_free(vlog_block);

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
                            if (index_builder) succinct_trie_builder_free(index_builder);
                            return TDB_ERR_CORRUPTION;
                        }
                    }

                    block_manager_block_t *klog_block =
                        block_manager_block_create(final_klog_size, final_klog_data);
                    if (klog_block)
                    {
                        block_manager_block_write(bms.klog_bm, klog_block);
                        block_manager_block_free(klog_block);
                        klog_block_num++;
                    }
                    free(final_klog_data);
                }

                tidesdb_klog_block_free(current_klog_block);
                current_klog_block = tidesdb_klog_block_create();
            }

            tidesdb_klog_block_add_entry(current_klog_block, kv, sst->config);

            /* track maximum sequence number */
            if (seq > max_seq)
            {
                max_seq = seq;
            }

            if (bloom)
            {
                bloom_filter_add(bloom, key, key_size);
            }

            if (index_builder && (entry_count % sst->config->index_sample_ratio == 0))
            {
                succinct_trie_builder_add(index_builder, key, key_size, klog_block_num);
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
                    if (index_builder) succinct_trie_builder_free(index_builder);
                    return TDB_ERR_CORRUPTION;
                }
            }

            block_manager_block_t *klog_block = block_manager_block_create(klog_size, klog_data);
            if (klog_block)
            {
                block_manager_block_write(bms.klog_bm, klog_block);
                block_manager_block_free(klog_block);
                klog_block_num++;
            }
            free(klog_data);
        }
    }

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
                    if (index_builder) succinct_trie_builder_free(index_builder);
                    return TDB_ERR_CORRUPTION;
                }
            }

            block_manager_block_t *vlog_block = block_manager_block_create(vlog_size, vlog_data);
            if (vlog_block)
            {
                block_manager_block_write(bms.vlog_bm, vlog_block);
                block_manager_block_free(vlog_block);
                vlog_block_num++;
            }
            free(vlog_data);
        }
    }

    tidesdb_klog_block_free(current_klog_block);
    tidesdb_vlog_block_free(current_vlog_block);

    atomic_store(&sst->num_klog_blocks, klog_block_num);
    atomic_store(&sst->num_vlog_blocks, vlog_block_num);
    sst->min_key = first_key;
    sst->min_key_size = first_key_size;
    sst->max_key = last_key;
    sst->max_key_size = last_key_size;
    sst->max_seq = max_seq; /* store maximum sequence number */

    /* capture klog file offset where data blocks end (before writing index/bloom/metadata) */
    block_manager_get_size(bms.klog_bm, &sst->klog_data_end_offset);

    /* build and write index */
    if (index_builder)
    {
        sst->block_index = succinct_trie_builder_build(index_builder, NULL);
        if (sst->block_index)
        {
            size_t index_size;
            uint8_t *index_data = succinct_trie_serialize(sst->block_index, &index_size);
            if (index_data)
            {
                block_manager_block_t *index_block =
                    block_manager_block_create(index_size, index_data);
                if (index_block)
                {
                    block_manager_block_write(bms.klog_bm, index_block);
                    block_manager_block_free(index_block);
                }
                free(index_data);
            }
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
                block_manager_block_free(bloom_block);
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
            block_manager_block_free(metadata_block);
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
        return TDB_ERR_IO;
    }

    if (!sst->min_key || !sst->max_key)
    {
        return TDB_ERR_NOT_FOUND;
    }

    int min_cmp = sst->config->comparator(key, key_size, sst->min_key, sst->min_key_size,
                                          sst->config->comparator_ctx);
    int max_cmp = sst->config->comparator(key, key_size, sst->max_key, sst->max_key_size,
                                          sst->config->comparator_ctx);

    if (min_cmp < 0 || max_cmp > 0)
    {
        return TDB_ERR_NOT_FOUND;
    }

    if (sst->bloom_filter && !bloom_filter_contains(sst->bloom_filter, key, key_size))
    {
        return TDB_ERR_NOT_FOUND;
    }

    /* use block index to find starting klog block */
    int64_t start_block = 0;
    if (sst->block_index)
    {
        if (succinct_trie_find_predecessor(sst->block_index, key, key_size, &start_block) != 0)
        {
            start_block = 0;
        }
    }

    /* search klog blocks using block manager cursor */
    block_manager_cursor_t *klog_cursor;
    if (block_manager_cursor_init(&klog_cursor, bms.klog_bm) != 0)
    {
        return TDB_ERR_IO;
    }

    if (block_manager_cursor_goto_first(klog_cursor) != 0)
    {
        block_manager_cursor_free(klog_cursor);
        return TDB_ERR_NOT_FOUND;
    }

    /* navigate to starting block */
    for (int64_t i = 0; i < start_block && block_manager_cursor_has_next(klog_cursor); i++)
    {
        block_manager_cursor_next(klog_cursor);
    }

    int result = TDB_ERR_NOT_FOUND;
    uint64_t block_num = 0;

    while (block_manager_cursor_has_next(klog_cursor) &&
           block_num < atomic_load(&sst->num_klog_blocks))
    {
        block_manager_block_t *block = block_manager_cursor_read(klog_cursor);
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

        block_num++;

        tidesdb_klog_block_t *klog_block;
        int deser_result = tidesdb_klog_block_deserialize(data, data_size, &klog_block);

        if (deser_result == 0)
        {
            /* search entries in this block */
            for (uint32_t i = 0; i < klog_block->num_entries; i++)
            {
                int cmp = sst->config->comparator(key, key_size, klog_block->keys[i],
                                                  klog_block->entries[i].key_size,
                                                  sst->config->comparator_ctx);

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
                    free(decompressed);
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
    /* open block managers temporarily for loading; they'll be managed by cache later */
    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open_with_cache(&klog_bm, sst->klog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        return -1;
    }

    if (block_manager_open_with_cache(&vlog_bm, sst->vlog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        block_manager_close(klog_bm);
        return -1;
    }

    block_manager_get_size(klog_bm, &sst->klog_size);
    block_manager_get_size(vlog_bm, &sst->vlog_size);

    /* read metadata from last block */
    block_manager_cursor_t *metadata_cursor;
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
                block_manager_block_release(metadata_block);
            }
        }
        block_manager_cursor_free(metadata_cursor);
    }

    /* read min/max keys from first and last klog blocks (for old sstables without
     * metadata) */
    atomic_store(&sst->num_klog_blocks, 0);

    /* read min/max keys from first and last klog blocks */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, klog_bm) != 0)
    {
        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);
        return TDB_ERR_IO;
    }

    /* read first block for min key */
    if (block_manager_cursor_goto_first(cursor) == 0)
    {
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (block)
        {
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

            tidesdb_klog_block_t *klog_block;
            if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) == 0)
            {
                if (klog_block->num_entries > 0)
                {
                    sst->min_key_size = klog_block->entries[0].key_size;
                    sst->min_key = malloc(sst->min_key_size);
                    if (sst->min_key)
                    {
                        memcpy(sst->min_key, klog_block->keys[0], sst->min_key_size);
                    }
                }
                tidesdb_klog_block_free(klog_block);
            }

            free(decompressed);
            block_manager_block_release(block);
        }
    }

    /* read last block for max key (skip metadata blocks) */
    if (block_manager_cursor_goto_last(cursor) == 0)
    {
        /* skip bloom and index blocks -- go back 2 blocks */
        if (block_manager_cursor_prev(cursor) == 0)
        {
            if (block_manager_cursor_prev(cursor) == 0)
            {
                block_manager_block_t *block = block_manager_cursor_read(cursor);
                if (block)
                {
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

                    tidesdb_klog_block_t *klog_block;
                    if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) == 0)
                    {
                        if (klog_block->num_entries > 0)
                        {
                            uint32_t last_idx = klog_block->num_entries - 1;
                            sst->max_key_size = klog_block->entries[last_idx].key_size;
                            sst->max_key = malloc(sst->max_key_size);
                            if (sst->max_key)
                            {
                                memcpy(sst->max_key, klog_block->keys[last_idx], sst->max_key_size);
                            }
                        }
                        tidesdb_klog_block_free(klog_block);
                    }

                    free(decompressed);
                    block_manager_block_release(block);
                }
            }
        }
    }

    block_manager_cursor_free(cursor);

load_bloom_and_index:
    /* load bloom filter and index from last blocks */
    /* [klog blocks...] [index block] [bloom filter block] [metadata block] */

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
            if (bloom_block && bloom_block->size > 0)
            {
                sst->bloom_filter = bloom_filter_deserialize(bloom_block->data);
                block_manager_block_release(bloom_block);
            }

            /* go to index block */
            if (block_manager_cursor_prev(cursor) == 0)
            {
                block_manager_block_t *index_block = block_manager_cursor_read(cursor);
                if (index_block && index_block->size > 0)
                {
                    sst->block_index =
                        succinct_trie_deserialize(index_block->data, index_block->size);
                    block_manager_block_release(index_block);
                }
            }
        }
    }

    block_manager_cursor_free(cursor);

    /* close temporary block managers - they'll be reopened through cache when needed */
    block_manager_close(klog_bm);
    block_manager_close(vlog_bm);

    /* mark as successfully loaded (not opened yet) */
    atomic_store_explicit(&sst->bm_open_state, 0, memory_order_release);

    return TDB_SUCCESS;
}

/**
 * tidesdb_sstable_array_create
 * create a new reference-counted sstable array
 */
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
    level->capacity = capacity;
    level->current_size = 0;

    tidesdb_sstable_t **sstables = calloc(16, sizeof(tidesdb_sstable_t *));
    if (!sstables)
    {
        free(level);
        return NULL;
    }

    level->sstables = sstables;
    level->num_sstables = 0;
    level->sstables_capacity = 16;
    level->num_boundaries = 0;

    return level;
}

/**
 * tidesdb_level_free
 * free a level
 * @param level level to free
 */
static void tidesdb_level_free(tidesdb_level_t *level)
{
    if (!level) return;

    for (int i = 0; i < level->num_sstables; i++)
    {
        if (level->sstables[i])
        {
            tidesdb_sstable_unref(level->sstables[i]);
        }
    }
    free(level->sstables);

    /* free boundaries */
    for (int i = 0; i < level->num_boundaries; i++)
    {
        free(level->file_boundaries[i]);
    }
    free(level->file_boundaries);
    free(level->boundary_sizes);

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
    /* check if we need to grow the array */
    if (level->num_sstables >= level->sstables_capacity)
    {
        int new_capacity = level->sstables_capacity == 0 ? 8 : level->sstables_capacity * 2;
        tidesdb_sstable_t **new_arr =
            realloc(level->sstables, new_capacity * sizeof(tidesdb_sstable_t *));
        if (!new_arr)
        {
            return TDB_ERR_MEMORY;
        }
        level->sstables = new_arr;
        level->sstables_capacity = new_capacity;
    }

    /* add sstable and take reference */
    tidesdb_sstable_ref(sst);
    level->sstables[level->num_sstables] = sst;
    level->num_sstables++;
    level->current_size += sst->klog_size + sst->vlog_size;

    return TDB_SUCCESS;
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

        /* try to swap in new array */
        if (atomic_compare_exchange_strong_explicit(&level->sstables, &old_arr, new_arr,
                                                    memory_order_release, memory_order_acquire))
        {
            /* success! update counts */
            atomic_store_explicit(&level->num_sstables, new_idx, memory_order_release);
            atomic_fetch_sub_explicit(&level->current_size, sst->klog_size + sst->vlog_size,
                                      memory_order_relaxed);

            /* unref old array's sstables */
            for (int i = 0; i < old_num; i++)
            {
                tidesdb_sstable_unref(old_arr[i]);
            }

            /* always free old array after unreffing contents */
            free(old_arr);

            /* remove from cache if present to avoid stale cache entries */
            if (db && db->sstable_cache)
            {
                char cache_key[TDB_CACHE_KEY_LEN];
                snprintf(cache_key, sizeof(cache_key), TDB_SSTABLE_CACHE_PREFIX "%" PRIu64,
                         sst->id);
                fifo_cache_remove(db->sstable_cache, cache_key);
            }

            return TDB_SUCCESS;
        }
        /* CAS failed, cleanup and retry */
        for (int i = 0; i < new_idx; i++)
        {
            tidesdb_sstable_unref(new_arr[i]);
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
    /* free old boundaries */
    for (int i = 0; i < level->num_boundaries; i++)
    {
        free(level->file_boundaries[i]);
    }
    free(level->file_boundaries);
    free(level->boundary_sizes);

    tidesdb_sstable_t **sstables = largest_level->sstables;
    int num_ssts = largest_level->num_sstables;

    if (num_ssts > 0)
    {
        level->file_boundaries = malloc(num_ssts * sizeof(uint8_t *));
        level->boundary_sizes = malloc(num_ssts * sizeof(size_t));

        if (!level->file_boundaries || !level->boundary_sizes)
        {
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            level->boundary_sizes[i] = sst->min_key_size;
            level->file_boundaries[i] = malloc(sst->min_key_size);
            if (!level->file_boundaries[i])
            {
                return TDB_ERR_MEMORY;
            }
            memcpy(level->file_boundaries[i], sst->min_key, sst->min_key_size);
        }
    }

    level->num_boundaries = num_ssts;
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
        tidesdb_sstable_unref(sst);
        free(source);
        return NULL;
    }

    if (block_manager_cursor_init(&source->source.sstable.klog_cursor, bms.klog_bm) != 0)
    {
        tidesdb_sstable_unref(sst);
        free(source);
        return NULL;
    }

    /* ensure sstable is open through cache */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        tidesdb_sstable_unref(sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        free(source);
        return NULL;
    }

    source->source.sstable.current_block_data = NULL; /* no block data yet */
    source->source.sstable.decompressed_data = NULL;  /* no decompressed data yet */
    source->config = sst->config;

    /* only read data blocks, not the metadata block at the end */
    if (atomic_load(&sst->num_klog_blocks) == 0)
    {
        /* empty sstable, no data blocks to read */
        tidesdb_sstable_unref(sst);
        block_manager_cursor_free(source->source.sstable.klog_cursor);
        free(source);
        return NULL;
    }

    /* build position cache for fast seeks when block index is enabled */
    if (sst->block_index && sst->klog_data_end_offset > 0)
    {
        if (block_manager_cursor_build_cache(source->source.sstable.klog_cursor,
                                             sst->klog_data_end_offset) != 0)
        {
            /* cache build failed, but we can still proceed without it */
            /* seeks will just be slower (linear scan instead of index jump) */
        }
    }

    if (block_manager_cursor_goto_first(source->source.sstable.klog_cursor) == 0)
    {
        /* check cursor is within data region (before index/bloom/metadata blocks) */
        if (sst->klog_data_end_offset > 0 &&
            source->source.sstable.klog_cursor->current_pos >= sst->klog_data_end_offset)
        {
            /* cursor is at or past data end offset */
            tidesdb_sstable_unref(sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            free(source);
            return NULL;
        }

        /* read first block and first entry */
        block_manager_block_t *block =
            block_manager_cursor_read(source->source.sstable.klog_cursor);
        if (!block)
        {
            /* no block available */
            tidesdb_sstable_unref(sst);
            block_manager_cursor_free(source->source.sstable.klog_cursor);
            free(source);
            return NULL;
        }

        /* cursor_read returns block with ref_count from cache
         * we keep this reference to prevent cache eviction during iteration
         * no need to acquire again, cursor_read already gave us a reference */
        source->source.sstable.current_block_data = block;

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

                source->source.sstable.decompressed_data = decompressed;
            }
        }

        if (tidesdb_klog_block_deserialize(data, data_size,
                                           &source->source.sstable.current_block) == 0)
        {
            if (source->source.sstable.current_block->num_entries > 0)
            {
                source->source.sstable.current_entry_idx = 0;

                /* create KV pair from first entry */
                tidesdb_klog_block_t *kb = source->source.sstable.current_block;
                uint8_t *value = kb->inline_values[0];

                /* if not inline, read from vlog */
                uint8_t *vlog_value = NULL;
                if (kb->entries[0].vlog_offset > 0)
                {
                    tidesdb_vlog_read_value(source->source.sstable.db, sst,
                                            kb->entries[0].vlog_offset, kb->entries[0].value_size,
                                            &vlog_value);
                    value = vlog_value;
                }

                source->current_kv = tidesdb_kv_pair_create(
                    kb->keys[0], kb->entries[0].key_size, value, kb->entries[0].value_size,
                    kb->entries[0].ttl, kb->entries[0].seq,
                    kb->entries[0].flags & TDB_KV_FLAG_TOMBSTONE);

                free(vlog_value);
            }
        }

        /* don't free decompressed or release block,we're still using the deserialized data */
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
        tidesdb_sstable_unref(source->source.sstable.sst);
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
        else
        {
            /* move to next block, cursor will handle position tracking */

            /* release previous decompressed data and block before moving to next */
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
                    /* acquire block to prevent eviction during decompression */
                    if (!block_manager_block_acquire(block))
                    {
                        block_manager_block_release(block);
                        return TDB_ERR_IO;
                    }

                    /* release cursor's reference, keep our acquired reference */
                    block_manager_block_release(block);
                    source->source.sstable.current_block_data = block;

                    uint8_t *data = block->data;
                    size_t data_size = block->size;
                    uint8_t *decompressed = NULL;

                    if (block->size >= 8 && source->config->compression_algorithm != NO_COMPRESSION)
                    {
                        uint64_t header_value = 0;
                        memcpy(&header_value, block->data, sizeof(uint64_t));
                    }

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
                                tidesdb_vlog_read_value(
                                    source->source.sstable.db, source->source.sstable.sst,
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
        source->source.sstable.current_entry_idx--;

        tidesdb_klog_block_t *kb = source->source.sstable.current_block;
        if (kb && source->source.sstable.current_entry_idx >= 0)
        {
            /* get previous entry from current block */
            int idx = source->source.sstable.current_entry_idx;
            uint8_t *value = kb->inline_values[idx];

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
        else
        {
            /* check if we can move to a previous block */
            if (!block_manager_cursor_has_prev(source->source.sstable.klog_cursor))
            {
                /* already at first block, can't go back */
                return TDB_ERR_NOT_FOUND;
            }

            /* release previous decompressed data and block before moving to prior block */
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
                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
                    /* acquire block to prevent eviction during decompression */
                    if (!block_manager_block_acquire(block))
                    {
                        block_manager_block_release(block);
                        return TDB_ERR_IO;
                    }

                    /* release cursor's reference, keep our acquired reference */
                    block_manager_block_release(block);
                    source->source.sstable.current_block_data = block;

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
                            /* start at last entry of previous block */
                            source->source.sstable.current_entry_idx =
                                source->source.sstable.current_block->num_entries - 1;

                            tidesdb_klog_block_t *current_kb = source->source.sstable.current_block;
                            int idx = source->source.sstable.current_entry_idx;
                            uint8_t *value = current_kb->inline_values[idx];

                            uint8_t *vlog_value = NULL;
                            if (current_kb->entries[idx].vlog_offset > 0)
                            {
                                tidesdb_vlog_read_value(
                                    source->source.sstable.db, source->source.sstable.sst,
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
                    source->source.sstable.current_block_data = NULL;
                }
            }
        }
    }

    return TDB_ERR_NOT_FOUND;
}

/**
 * tidesdb_calculate_level_capacity
 * calculate the capacity of a level based on the level number, base capacity, and ratio
 * @param level_num the level number
 * @param base_capacity the base capacity
 * @param ratio the ratio
 * @return the capacity of the level
 */
static size_t tidesdb_calculate_level_capacity(int level_num, size_t base_capacity, size_t ratio)
{
    /* capacity formula C_i = base * T^(i-1) for level i */
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
    pthread_rwlock_wrlock(&cf->levels_rwlock);

    int num_levels = cf->num_levels;

    /* verify we still need to add a level after acquiring lock */
    if (num_levels >= cf->config.max_levels)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_SUCCESS;
    }

    tidesdb_level_t **levels = cf->levels;
    tidesdb_level_t *largest = levels[num_levels - 1];
    size_t largest_size = largest->current_size;

    /* recheck if largest level is still at capacity */
    if (largest_size < largest->capacity)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_SUCCESS; /* no longer at capacity, another thread handled it */
    }

    size_t new_capacity = tidesdb_calculate_level_capacity(
        num_levels + 1, cf->config.write_buffer_size, cf->config.level_size_ratio);

    tidesdb_level_t *new_level = tidesdb_level_create(num_levels + 1, new_capacity);
    if (!new_level)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_ERR_MEMORY;
    }

    tidesdb_level_t **new_levels =
        realloc(cf->levels, (num_levels + 1) * sizeof(tidesdb_level_t *));
    if (!new_levels)
    {
        tidesdb_level_free(new_level);
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_ERR_MEMORY;
    }

    new_levels[num_levels] = new_level;
    cf->levels = new_levels;
    cf->num_levels = num_levels + 1;

    pthread_rwlock_unlock(&cf->levels_rwlock);

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
    pthread_rwlock_wrlock(&cf->levels_rwlock);

    int num_levels = cf->num_levels;
    if (num_levels <= 1)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_ERR_INVALID_ARGS;
    }

    tidesdb_level_t **levels = cf->levels;
    tidesdb_level_t *largest = levels[num_levels - 1];
    size_t largest_size = largest->current_size;

    if (largest_size > 0)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_SUCCESS;
    }

    tidesdb_level_free(levels[num_levels - 1]);

    int new_num_levels = num_levels - 1;
    tidesdb_level_t **new_levels = realloc(levels, new_num_levels * sizeof(tidesdb_level_t *));

    if (new_levels != NULL)
    {
        cf->levels = new_levels;
    }

    cf->num_levels = new_num_levels;

    pthread_rwlock_unlock(&cf->levels_rwlock);

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
    int num_levels = atomic_load(&cf->num_levels);
    if (num_levels < 2) return TDB_SUCCESS;

    tidesdb_level_t **levels = atomic_load_explicit(&cf->levels, memory_order_acquire);

    /* get data size at largest level */
    tidesdb_level_t *largest = levels[num_levels - 1];
    size_t N_L = atomic_load(&largest->current_size);

    /* update capacities C_i = N_L / T^(L-i) */
    for (int i = 0; i < num_levels - 1; i++)
    {
        size_t power = num_levels - 1 - i;
        size_t divisor = 1;
        for (size_t p = 0; p < power; p++)
        {
            divisor *= cf->config.level_size_ratio;
        }

        size_t old_capacity = levels[i]->capacity;
        size_t new_capacity;

        if (divisor > 0)
        {
            new_capacity = N_L / divisor;

            if (new_capacity == 0 && old_capacity > 0)
            {
                new_capacity = old_capacity;
            }
            else
            {
                levels[i]->capacity = new_capacity;
            }
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
    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    pthread_rwlock_unlock(&cf->levels_rwlock);

    if (start_level < 0 || target_level >= num_levels)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Starting full preemptive merge: CF '%s', levels %d->%d", cf->name, start_level,
                  target_level);

    tidesdb_merge_heap_t *heap =
        tidesdb_merge_heap_create(cf->config.comparator, cf->config.comparator_ctx);
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

    /* add all ssts from start_level to target_level as merge sources */
    pthread_rwlock_rdlock(&cf->levels_rwlock);

    tidesdb_level_t **levels = cf->levels;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = levels[level];
        tidesdb_sstable_t **sstables = lvl->sstables;
        int num_ssts = lvl->num_sstables;

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            tidesdb_sstable_ref(sst);

            tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
            if (source)
            {
                /* only add source if it has valid data */
                if (source->current_kv)
                {
                    tidesdb_merge_heap_add_source(heap, source);
                }
                else
                {
                    /* source has no data, free it */
                    tidesdb_merge_source_free(source);
                }
            }

            queue_enqueue(sstables_to_delete, sst);
        }
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

    /* create new sst for merged output */
    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char path[MAX_FILE_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d", cf->directory,
             target_level + 1);

    tidesdb_sstable_t *new_sst = tidesdb_sstable_create(path, new_id, &cf->config);
    if (!new_sst)
    {
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_MEMORY;
    }

    /* open block managers for writing new sstable */
    block_manager_t *klog_bm = NULL;
    block_manager_t *vlog_bm = NULL;

    if (block_manager_open_with_cache(&klog_bm, new_sst->klog_path,
                                      convert_sync_mode(cf->config.sync_mode),
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
    {
        tidesdb_sstable_unref(new_sst);
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_IO;
    }

    if (block_manager_open_with_cache(&vlog_bm, new_sst->vlog_path,
                                      convert_sync_mode(cf->config.sync_mode),
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
    {
        block_manager_close(klog_bm);
        tidesdb_sstable_unref(new_sst);
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_IO;
    }

    /* calc expected number of entries for bloom filter sizing
     * during merge, duplicates are eliminated and tombstones may be removed,
     * so the actual count will be lower. we use the sum as an upper bound to ensure
     * the bloom filter is adequately sized. */
    uint64_t estimated_entries = 0;
    pthread_rwlock_rdlock(&cf->levels_rwlock);

    levels = cf->levels;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = levels[level];
        tidesdb_sstable_t **sstables = lvl->sstables;
        int num_ssts = lvl->num_sstables;

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            estimated_entries += sst->num_entries;
        }
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

    if (estimated_entries < 100) estimated_entries = 100;

    bloom_filter_t *bloom = NULL;
    succinct_trie_builder_t *index_builder = NULL;

    if (cf->config.enable_bloom_filter)
    {
        bloom_filter_new(&bloom, cf->config.bloom_fpr, estimated_entries);
    }

    if (cf->config.enable_block_indexes)
    {
        index_builder =
            succinct_trie_builder_new(NULL, cf->config.comparator, cf->config.comparator_ctx);
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
                        block_manager_block_free(vlog_block);
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
                    block_manager_block_free(klog_block);
                    klog_block_num++;
                }
                free(final_data);
            }

            tidesdb_klog_block_free(current_klog_block);
            current_klog_block = tidesdb_klog_block_create();
        }

        tidesdb_klog_block_add_entry(current_klog_block, kv, &cf->config);

        if (kv->entry.seq > max_seq)
        {
            max_seq = kv->entry.seq;
        }

        if (bloom)
        {
            bloom_filter_add(bloom, kv->key, kv->entry.key_size);
        }

        if (index_builder && (entry_count % cf->config.index_sample_ratio == 0))
        {
            succinct_trie_builder_add(index_builder, kv->key, kv->entry.key_size, klog_block_num);
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
                block_manager_block_free(klog_block);
                klog_block_num++;
            }
            free(klog_data);
        }
    }

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
                block_manager_block_free(vlog_block);
                vlog_block_num++;
            }
            free(vlog_data);
        }
    }

    tidesdb_klog_block_free(current_klog_block);
    tidesdb_vlog_block_free(current_vlog_block);

    atomic_store(&new_sst->num_klog_blocks, klog_block_num);
    atomic_store(&new_sst->num_vlog_blocks, vlog_block_num);

    block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

    if (index_builder)
    {
        TDB_DEBUG_LOG("Full preemptive merge: building index from builder");
        new_sst->block_index = succinct_trie_builder_build(index_builder, NULL);
        TDB_DEBUG_LOG("Full preemptive merge: index build %s",
                      new_sst->block_index ? "succeeded" : "failed");
        if (new_sst->block_index)
        {
            size_t index_size;
            uint8_t *index_data = succinct_trie_serialize(new_sst->block_index, &index_size);
            if (index_data)
            {
                block_manager_block_t *index_block =
                    block_manager_block_create(index_size, index_data);
                if (index_block)
                {
                    block_manager_block_write(klog_bm, index_block);
                    block_manager_block_free(index_block);
                }
                free(index_data);
            }
        }
    }

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
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }
        new_sst->bloom_filter = bloom;
    }

    block_manager_get_size(klog_bm, &new_sst->klog_size);
    block_manager_get_size(vlog_bm, &new_sst->vlog_size);

    tidesdb_merge_heap_free(heap);

    /* close block managers after writing so readers can properly reopen them */
    /* close block managers after writing */
    block_manager_close(klog_bm);
    block_manager_close(vlog_bm);

    /* ensure all writes are visible before making sstable discoverable */
    atomic_thread_fence(memory_order_seq_cst);

    pthread_rwlock_wrlock(&cf->levels_rwlock);

    levels = cf->levels;
    tidesdb_level_add_sstable(levels[target_level], new_sst);

    tidesdb_sstable_unref(new_sst);

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        /* find which level this sst belongs to and remove it */
        for (int level = start_level; level <= target_level && level < cf->num_levels; level++)
        {
            tidesdb_level_t *lvl = levels[level];
            tidesdb_level_remove_sstable(cf->db, lvl, sst);
        }

        unlink(sst->klog_path);
        unlink(sst->vlog_path);

        tidesdb_sstable_unref(sst);
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

    queue_free(sstables_to_delete);

    atomic_fetch_add(&cf->compaction_count, 1);

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
    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    pthread_rwlock_unlock(&cf->levels_rwlock);

    if (target_level >= num_levels || target_level < 1)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Starting dividing merge: CF '%s', target_level=%d", cf->name, target_level);

    if (target_level >= num_levels - 1)
    {
        TDB_DEBUG_LOG("Target level %d is the largest level, falling back to full merge",
                      target_level);
        return tidesdb_full_preemptive_merge(cf, 0, target_level);
    }

    pthread_rwlock_rdlock(&cf->levels_rwlock);
    tidesdb_level_t **levels = cf->levels;
    tidesdb_level_t *largest = levels[num_levels - 1];
    tidesdb_level_update_boundaries(levels[target_level], largest);
    pthread_rwlock_unlock(&cf->levels_rwlock);

    tidesdb_merge_heap_t *heap =
        tidesdb_merge_heap_create(cf->config.comparator, cf->config.comparator_ctx);
    if (!heap)
    {
        return TDB_ERR_MEMORY;
    }

    queue_t *sstables_to_delete = queue_new();

    pthread_rwlock_rdlock(&cf->levels_rwlock);
    levels = cf->levels;

    for (int level = 0; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = levels[level];
        tidesdb_sstable_t **sstables = lvl->sstables;
        int num_ssts = lvl->num_sstables;

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = sstables[i];
            tidesdb_sstable_ref(sst);

            tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
            if (source)
            {
                /* only add source if it has valid data */
                if (source->current_kv)
                {
                    tidesdb_merge_heap_add_source(heap, source);
                }
                else
                {
                    /* source has no data, free it */
                    tidesdb_merge_source_free(source);
                }
            }

            queue_enqueue(sstables_to_delete, sst);
        }
    }

    /* get partition boundaries from target level */
    tidesdb_level_t *target = levels[target_level];
    pthread_rwlock_unlock(&cf->levels_rwlock);

    /* if no boundaries, do a simple full merge */
    if (target->num_boundaries == 0)
    {
        int result = tidesdb_full_preemptive_merge(cf, 0, target_level);
        tidesdb_merge_heap_free(heap);

        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(sst);
        }
        queue_free(sstables_to_delete);

        return result;
    }

    /* partitioned merge create one sstable per partition */
    int num_partitions = target->num_boundaries + 1;

    for (int partition = 0; partition < num_partitions; partition++)
    {
        /* determine key range for this partition */
        uint8_t *start_key = NULL;
        size_t start_key_size = 0;
        uint8_t *end_key = NULL;
        size_t end_key_size = 0;

        if (partition > 0)
        {
            start_key = target->file_boundaries[partition - 1];
            start_key_size = target->boundary_sizes[partition - 1];
        }

        if (partition < target->num_boundaries)
        {
            end_key = target->file_boundaries[partition];
            end_key_size = target->boundary_sizes[partition];
        }

        /* create new sst for this partition */
        uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char sst_path[MAX_FILE_PATH_LENGTH];
        snprintf(sst_path, sizeof(sst_path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d",
                 cf->directory, target_level + 1);

        tidesdb_sstable_t *new_sst = tidesdb_sstable_create(sst_path, sst_id, &cf->config);
        if (!new_sst) continue;

        block_manager_t *klog_bm = NULL;
        block_manager_t *vlog_bm = NULL;

        if (block_manager_open_with_cache(&klog_bm, new_sst->klog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size) != 0)
        {
            tidesdb_sstable_unref(new_sst);
            continue;
        }

        if (block_manager_open_with_cache(&vlog_bm, new_sst->vlog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size) != 0)
        {
            block_manager_close(klog_bm);
            tidesdb_sstable_unref(new_sst);
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
        succinct_trie_builder_t *index_builder = NULL;

        if (cf->config.enable_bloom_filter)
        {
            if (bloom_filter_new(&bloom, cf->config.bloom_fpr, 10000) != 0)
            {
                bloom = NULL;
            }
        }

        if (cf->config.enable_block_indexes)
        {
            index_builder =
                succinct_trie_builder_new(NULL, cf->config.comparator, cf->config.comparator_ctx);
        }

        /* pop entries from heap that fall in this partition */
        while (!tidesdb_merge_heap_empty(heap))
        {
            tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap);
            if (!kv) break;

            /* check if key is in this partition's range */
            int in_range = 1;

            if (start_key)
            {
                int cmp = cf->config.comparator(kv->key, kv->entry.key_size, start_key,
                                                start_key_size, cf->config.comparator_ctx);
                if (cmp < 0) in_range = 0;
            }

            if (in_range && end_key)
            {
                int cmp = cf->config.comparator(kv->key, kv->entry.key_size, end_key, end_key_size,
                                                cf->config.comparator_ctx);
                if (cmp >= 0) in_range = 0;
            }

            if (!in_range)
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

            /* add to block index periodically */
            if (index_builder && (entry_count % cf->config.index_sample_ratio == 0))
            {
                succinct_trie_builder_add(index_builder, kv->key, kv->entry.key_size,
                                          klog_block_num);
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
                            block_manager_block_free(vblock);
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
                /* serialize and write klog block */
                uint8_t *klog_data;
                size_t klog_size;
                if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
                {
                    block_manager_block_t *kblock =
                        block_manager_block_create(klog_size, klog_data);
                    if (kblock)
                    {
                        block_manager_block_write(klog_bm, kblock);
                        block_manager_block_free(kblock);
                        klog_block_num++;
                    }
                    free(klog_data);
                }

                tidesdb_klog_block_free(klog_block);
                klog_block = tidesdb_klog_block_create();
            }
            tidesdb_klog_block_add_entry(klog_block, kv, &cf->config);

            /* track maximum sequence number */
            if (kv->entry.seq > max_seq)
            {
                max_seq = kv->entry.seq;
            }

            entry_count++;

            tidesdb_kv_pair_free(kv);
        }

        /* write remaining vlog block if it has data */
        if (vlog_block->num_values > 0)
        {
            uint8_t *vlog_data;
            size_t vlog_size;
            if (tidesdb_vlog_block_serialize(vlog_block, &vlog_data, &vlog_size) == 0)
            {
                block_manager_block_t *vblock = block_manager_block_create(vlog_size, vlog_data);
                if (vblock)
                {
                    block_manager_block_write(vlog_bm, vblock);
                    block_manager_block_free(vblock);
                }
                free(vlog_data);
            }
        }

        /* write remaining klog block if it has data */
        if (klog_block->num_entries > 0)
        {
            uint8_t *klog_data;
            size_t klog_size;
            if (tidesdb_klog_block_serialize(klog_block, &klog_data, &klog_size) == 0)
            {
                block_manager_block_t *block = block_manager_block_create(klog_size, klog_data);
                if (block)
                {
                    block_manager_block_write(klog_bm, block);
                    block_manager_block_free(block);
                    klog_block_num++;
                }
                free(klog_data);
            }
        }

        tidesdb_klog_block_free(klog_block);
        tidesdb_vlog_block_free(vlog_block);

        atomic_store(&new_sst->num_klog_blocks, klog_block_num);
        atomic_store(&new_sst->num_vlog_blocks, vlog_block_num);

        new_sst->num_entries = entry_count;
        new_sst->max_seq = max_seq;
        new_sst->min_key = first_key;
        new_sst->min_key_size = first_key_size;
        new_sst->max_key = last_key;
        new_sst->max_key_size = last_key_size;

        /* capture klog file offset where data blocks end (before writing index/bloom/metadata) */
        block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

        /* write index */
        if (index_builder)
        {
            /* succinct_trie_builder_build with NULL frees the builder internally */
            succinct_trie_t *trie = succinct_trie_builder_build(index_builder, NULL);
            if (trie)
            {
                size_t trie_size;
                uint8_t *trie_data = succinct_trie_serialize(trie, &trie_size);
                if (trie_data)
                {
                    block_manager_block_t *trie_block =
                        block_manager_block_create(trie_size, trie_data);
                    if (trie_block)
                    {
                        block_manager_block_write(klog_bm, trie_block);
                        block_manager_block_free(trie_block);
                    }
                    free(trie_data);
                }
                succinct_trie_free(trie);
            }
        }

        if (bloom)
        {
            size_t bloom_size;
            uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
            if (bloom_data)
            {
                block_manager_block_t *bloom_block =
                    block_manager_block_create(bloom_size, bloom_data);
                if (bloom_block)
                {
                    block_manager_block_write(klog_bm, bloom_block);
                    block_manager_block_free(bloom_block);
                }
                free(bloom_data);
            }
            bloom_filter_free(bloom);
        }

        block_manager_get_size(klog_bm, &new_sst->klog_size);
        block_manager_get_size(vlog_bm, &new_sst->vlog_size);

        block_manager_close(klog_bm);
        block_manager_close(vlog_bm);

        /* ensure all writes are visible before making sstable discoverable */
        atomic_thread_fence(memory_order_seq_cst);

        /* add to target level */
        if (entry_count > 0)
        {
            pthread_rwlock_wrlock(&cf->levels_rwlock);
            tidesdb_level_add_sstable(target, new_sst);
            pthread_rwlock_unlock(&cf->levels_rwlock);
            tidesdb_sstable_unref(new_sst);
        }
        else
        {
            tidesdb_sstable_unref(new_sst);
        }
    }

    tidesdb_merge_heap_free(heap);

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (sst)
        {
            /* reload levels array in case it was reallocated */
            levels = atomic_load_explicit(&cf->levels, memory_order_acquire);
            int current_num_levels = atomic_load(&cf->num_levels);

            for (int level = 0; level <= target_level && level < current_num_levels; level++)
            {
                tidesdb_level_remove_sstable(cf->db, levels[level], sst);
            }
            /* unref our reference from the merge */
            tidesdb_sstable_unref(sst);
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
    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    if (start_level >= num_levels || end_level >= num_levels)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Starting partitioned merge: CF '%s', levels %d->%d", cf->name, start_level,
                  end_level);

    tidesdb_level_t **levels = cf->levels;

    queue_t *sstables_to_delete = queue_new();
    for (int level = start_level; level < end_level; level++)
    {
        tidesdb_level_t *lvl = levels[level];
        tidesdb_sstable_t **sstables = lvl->sstables;
        int num_ssts = lvl->num_sstables;

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_ref(sstables[i]);
            queue_enqueue(sstables_to_delete, sstables[i]);
        }
    }
    tidesdb_level_t *largest = levels[num_levels - 1];

    /* get file boundaries from largest level */
    tidesdb_sstable_t **largest_sstables = largest->sstables;
    int num_partitions = largest->num_sstables;

    if (num_partitions == 0)
    {
        pthread_rwlock_unlock(&cf->levels_rwlock);

        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(sst);
        }
        queue_free(sstables_to_delete);

        return tidesdb_full_preemptive_merge(cf, start_level, end_level - 1);
    }

    uint8_t **boundaries = malloc(num_partitions * sizeof(uint8_t *));
    size_t *boundary_sizes = malloc(num_partitions * sizeof(size_t));

    for (int i = 0; i < num_partitions; i++)
    {
        boundaries[i] = malloc(largest_sstables[i]->min_key_size);
        boundary_sizes[i] = largest_sstables[i]->min_key_size;
        memcpy(boundaries[i], largest_sstables[i]->min_key, boundary_sizes[i]);
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

    /* merge one partition at a time */
    for (int partition = 0; partition < num_partitions; partition++)
    {
        tidesdb_merge_heap_t *heap =
            tidesdb_merge_heap_create(cf->config.comparator, cf->config.comparator_ctx);
        if (!heap) continue;

        uint8_t *range_start = boundaries[partition];
        size_t range_start_size = boundary_sizes[partition];
        uint8_t *range_end = (partition + 1 < num_partitions) ? boundaries[partition + 1] : NULL;
        size_t range_end_size =
            (partition + 1 < num_partitions) ? boundary_sizes[partition + 1] : 0;

        /* add overlapping ssts as sources and calculate estimated entries */
        uint64_t estimated_entries = 0;
        pthread_rwlock_rdlock(&cf->levels_rwlock);
        levels = cf->levels;

        for (int level = start_level; level <= end_level; level++)
        {
            tidesdb_level_t *lvl = levels[level];
            tidesdb_sstable_t **sstables = lvl->sstables;
            int num_ssts = lvl->num_sstables;

            for (int i = 0; i < num_ssts; i++)
            {
                tidesdb_sstable_t *sst = sstables[i];
                tidesdb_sstable_ref(sst);

                int overlaps = 1;

                if (cf->config.comparator(sst->max_key, sst->max_key_size, range_start,
                                          range_start_size, cf->config.comparator_ctx) < 0)
                {
                    overlaps = 0;
                }

                if (range_end &&
                    cf->config.comparator(sst->min_key, sst->min_key_size, range_end,
                                          range_end_size, cf->config.comparator_ctx) >= 0)
                {
                    overlaps = 0;
                }

                if (overlaps)
                {
                    tidesdb_merge_source_t *source = tidesdb_merge_source_from_sstable(cf->db, sst);
                    if (source)
                    {
                        tidesdb_merge_heap_add_source(heap, source);
                        estimated_entries += sst->num_entries;
                    }
                }
            }
        }

        pthread_rwlock_unlock(&cf->levels_rwlock);

        /* use a minimum of 100 entries to avoid degenerate bloom filters */
        if (estimated_entries < 100) estimated_entries = 100;

        /* create output sst for this partition */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char path[MAX_FILE_PATH_LENGTH];
        snprintf(path, sizeof(path),
                 "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                 cf->directory, end_level + 1, partition);

        tidesdb_sstable_t *new_sst = tidesdb_sstable_create(path, new_id, &cf->config);
        if (new_sst)
        {
            block_manager_t *klog_bm = NULL;
            block_manager_t *vlog_bm = NULL;

            block_manager_open_with_cache(&klog_bm, new_sst->klog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size);
            block_manager_open_with_cache(&vlog_bm, new_sst->vlog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size);

            bloom_filter_t *bloom = NULL;
            succinct_trie_builder_t *index_builder = NULL;

            if (cf->config.enable_bloom_filter)
            {
                bloom_filter_new(&bloom, cf->config.bloom_fpr, estimated_entries);
            }

            if (cf->config.enable_block_indexes)
            {
                index_builder = succinct_trie_builder_new(NULL, cf->config.comparator,
                                                          cf->config.comparator_ctx);
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

            while (!tidesdb_merge_heap_empty(heap))
            {
                tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(heap);
                if (!kv) break;

                /* check if key is in partition range */
                if (cf->config.comparator(kv->key, kv->entry.key_size, range_start,
                                          range_start_size, cf->config.comparator_ctx) < 0)
                {
                    tidesdb_kv_pair_free(kv);
                    continue;
                }

                if (range_end &&
                    cf->config.comparator(kv->key, kv->entry.key_size, range_end, range_end_size,
                                          cf->config.comparator_ctx) >= 0)
                {
                    tidesdb_kv_pair_free(kv);
                    break;
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
                                block_manager_block_free(vblock);
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

                /* sample for index */
                if (index_builder && (entry_count % cf->config.index_sample_ratio == 0))
                {
                    succinct_trie_builder_add(index_builder, kv->key, kv->entry.key_size,
                                              klog_block_num);
                }

                /* add to klog block */
                tidesdb_klog_block_add_entry(klog_block, kv, &cf->config);

                /* track maximum sequence number */
                if (kv->entry.seq > max_seq)
                {
                    max_seq = kv->entry.seq;
                }

                entry_count++;

                /* flush klog block if full */
                if (tidesdb_klog_block_is_full(klog_block, cf->config.klog_block_size))
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
                            int64_t offset = block_manager_block_write(klog_bm, block);
                            (void)offset; /* unused but kept for debugging */
                            block_manager_block_free(block);
                            klog_block_num++;
                        }
                        free(final_data);
                    }
                    tidesdb_klog_block_free(klog_block);
                    klog_block = tidesdb_klog_block_create();
                }

                tidesdb_kv_pair_free(kv);
            }

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
                        block_manager_block_free(vblock);
                        vlog_block_num++;
                    }
                    free(final_data);
                }
            }
            tidesdb_vlog_block_free(vlog_block);

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
                        block_manager_block_write(klog_bm, block);
                        block_manager_block_free(block);
                        klog_block_num++;
                    }
                    free(final_data);
                }
            }

            tidesdb_klog_block_free(klog_block);

            /* capture klog file offset where data blocks end (before writing index/bloom/metadata)
             */
            block_manager_get_size(klog_bm, &new_sst->klog_data_end_offset);

            /* write index */
            if (index_builder)
            {
                new_sst->block_index = succinct_trie_builder_build(index_builder, NULL);
                if (new_sst->block_index)
                {
                    size_t index_size;
                    uint8_t *index_data =
                        succinct_trie_serialize(new_sst->block_index, &index_size);
                    if (index_data)
                    {
                        block_manager_block_t *index_block =
                            block_manager_block_create(index_size, index_data);
                        if (index_block)
                        {
                            block_manager_block_write(klog_bm, index_block);
                            block_manager_block_free(index_block);
                        }
                        free(index_data);
                    }
                }
            }

            if (bloom)
            {
                size_t bloom_size;
                uint8_t *bloom_data = bloom_filter_serialize(bloom, &bloom_size);
                if (bloom_data)
                {
                    block_manager_block_t *bloom_block =
                        block_manager_block_create(bloom_size, bloom_data);
                    if (bloom_block)
                    {
                        block_manager_block_write(klog_bm, bloom_block);
                        block_manager_block_free(bloom_block);
                    }
                    free(bloom_data);
                }
                new_sst->bloom_filter = bloom;
            }

            new_sst->num_entries = entry_count;
            new_sst->max_seq = max_seq;
            atomic_store(&new_sst->num_klog_blocks, klog_block_num);
            atomic_store(&new_sst->num_vlog_blocks, vlog_block_num);
            new_sst->min_key = first_key;
            new_sst->min_key_size = first_key_size;
            new_sst->max_key = last_key;
            new_sst->max_key_size = last_key_size;

            block_manager_get_size(klog_bm, &new_sst->klog_size);
            block_manager_get_size(vlog_bm, &new_sst->vlog_size);

            block_manager_close(klog_bm);
            block_manager_close(vlog_bm);

            /* ensure all writes are visible before making sstable discoverable */
            atomic_thread_fence(memory_order_seq_cst);

            /* add to level if not empty */
            if (entry_count > 0)
            {
                pthread_rwlock_wrlock(&cf->levels_rwlock);
                levels = cf->levels;
                tidesdb_level_add_sstable(levels[end_level], new_sst);
                pthread_rwlock_unlock(&cf->levels_rwlock);
                tidesdb_sstable_unref(new_sst);
            }
            else
            {
                tidesdb_sstable_unref(new_sst);
            }
        }

        tidesdb_merge_heap_free(heap);
    }

    pthread_rwlock_wrlock(&cf->levels_rwlock);
    levels = cf->levels;

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        for (int level = start_level; level < end_level; level++)
        {
            tidesdb_level_remove_sstable(cf->db, levels[level], sst);
        }

        unlink(sst->klog_path);
        unlink(sst->vlog_path);

        tidesdb_sstable_unref(sst);
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);
    queue_free(sstables_to_delete);

    for (int i = 0; i < num_partitions; i++)
    {
        free(boundaries[i]);
    }
    free(boundaries);
    free(boundary_sizes);

    atomic_fetch_add(&cf->compaction_count, 1);

    return TDB_SUCCESS;
}

int tidesdb_trigger_compaction(tidesdb_column_family_t *cf)
{
    int num_levels = atomic_load(&cf->num_levels);

    if (num_levels == 1)
    {
        tidesdb_level_t **levels = atomic_load_explicit(&cf->levels, memory_order_acquire);
        tidesdb_level_t *level0 = levels[0];
        size_t current_size = atomic_load(&level0->current_size);
        size_t capacity = level0->capacity;

        if (current_size >= capacity)
        {
            tidesdb_add_level(cf);
            num_levels = atomic_load(&cf->num_levels);
        }
        else
        {
            return TDB_SUCCESS;
        }
    }

    TDB_DEBUG_LOG("Triggering compaction for column family: %s (levels: %d)", cf->name, num_levels);

    /* calculate X (dividing level) - Algorithm 2 */
    int X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    tidesdb_level_t **levels = atomic_load_explicit(&cf->levels, memory_order_acquire);

    int target_lvl = X; /* default to X if no suitable level found */

    for (int q = 1; q <= X && q < num_levels; q++)
    {
        size_t cumulative_size = 0;

        for (int i = 0; i <= q; i++)
        {
            cumulative_size += atomic_load(&levels[i]->current_size);
        }

        /* check if C_q >= cumulative_size (level can accommodate the merge) */
        if (levels[q]->capacity >= cumulative_size)
        {
            /* found smallest level that can accommodate the merge */
            target_lvl = q;
            break;
        }
    }

    int result = TDB_SUCCESS;
    if (target_lvl < X)
    {
        TDB_DEBUG_LOG("Full preemptive merge: levels 0 to %d", target_lvl);
        result = tidesdb_full_preemptive_merge(cf, 0, target_lvl);
    }
    else if (target_lvl == X)
    {
        TDB_DEBUG_LOG("Dividing merge at level %d", X);
        result = tidesdb_dividing_merge(cf, X);
    }
    else
    {
        TDB_DEBUG_LOG("Warning: target_lvl > X, defaulting to dividing merge");
        result = tidesdb_dividing_merge(cf, X);
    }

    num_levels = atomic_load(&cf->num_levels);
    levels = atomic_load_explicit(&cf->levels, memory_order_acquire);

    if (X < num_levels)
    {
        size_t level_x_size = atomic_load(&levels[X - 1]->current_size);
        size_t level_x_capacity = levels[X - 1]->capacity;

        if (level_x_size >= level_x_capacity)
        {
            TDB_DEBUG_LOG("Level %d is full, triggering partitioned preemptive merge", X);

            int z = -1; /* no suitable level found yet */

            for (int candidate_z = X + 1; candidate_z <= num_levels - 1; candidate_z++)
            {
                size_t cumulative = 0;
                for (int i = X; i <= candidate_z; i++)
                {
                    cumulative += atomic_load(&levels[i - 1]->current_size);
                }

                if (levels[candidate_z - 1]->capacity >= cumulative)
                {
                    z = candidate_z;
                    break;
                }
            }

            if (z == -1 || z <= X)
            {
                z = num_levels - 1; /* merge into the current largest level */
                TDB_DEBUG_LOG(
                    "No suitable level found for partitioned merge, using largest level %d", z);
            }

            TDB_DEBUG_LOG("Partitioned preemptive merge: levels %d to %d", X, z);

            result = tidesdb_partitioned_merge(cf, X, z);
        }
    }

    num_levels = atomic_load(&cf->num_levels);
    levels = atomic_load_explicit(&cf->levels, memory_order_acquire);
    tidesdb_level_t *largest = levels[num_levels - 1];
    size_t largest_size = atomic_load(&largest->current_size);

    if (largest_size >= largest->capacity && num_levels < cf->config.max_levels)
    {
        tidesdb_add_level(cf);
        num_levels = atomic_load(&cf->num_levels);
    }

    else if (num_levels > 1 && largest_size == 0)
    {
        TDB_DEBUG_LOG("Largest level is empty, removing level for CF '%s'", cf->name);
        tidesdb_remove_level(cf);
        num_levels = atomic_load(&cf->num_levels);
    }

    tidesdb_apply_dca(cf);

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
    if (block_manager_open_with_cache(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE, 0) != 0)
    {
        return TDB_ERR_IO;
    }

    if (skip_list_new(memtable, 32, 0.25f) != 0)
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
                /* peek at potential metadata header */
                tidesdb_multi_cf_txn_metadata_t peek_metadata;
                memcpy(&peek_metadata, ptr, sizeof(tidesdb_multi_cf_txn_metadata_t));

                /* if num_participant_cfs > 1, this is multi-CF metadata */
                if (peek_metadata.num_participant_cfs > 1 &&
                    peek_metadata.num_participant_cfs < 255)
                {
                    is_multi_cf_entry = 1;
                    num_participant_cfs = peek_metadata.num_participant_cfs;

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
                        checksum_data[0] = peek_metadata.num_participant_cfs;
                        memcpy(checksum_data + 1, cf_names_ptr, cf_names_size);
                        uint64_t computed_checksum = XXH64(checksum_data, checksum_data_size, 0);
                        free(checksum_data);

                        if (computed_checksum != peek_metadata.checksum)
                        {
                            TDB_DEBUG_LOG(
                                "CF '%s': Multi-CF metadata checksum mismatch (expected: %" PRIu64
                                ", got: %" PRIu64 ") - skipping entry",
                                cf->name, peek_metadata.checksum, computed_checksum);
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

            tidesdb_klog_entry_t entry;
            memcpy(&entry, ptr, sizeof(tidesdb_klog_entry_t));
            ptr += sizeof(tidesdb_klog_entry_t);
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

                if (!should_apply)
                {
                    TDB_DEBUG_LOG("WAL recovery: Skipping incomplete multi-CF txn seq=%" PRIu64
                                  " for CF '%s'",
                                  entry.seq, cf->name);
                }
                else
                {
                    TDB_DEBUG_LOG("WAL recovery: Applying complete multi-CF txn seq=%" PRIu64
                                  " for CF '%s'",
                                  entry.seq, cf->name);
                }
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
 * tidesdb_background_compaction_thread
 * background compaction thread
 * @param arg the column family
 * @return NULL
 */
static void *tidesdb_background_compaction_thread(void *arg)
{
    tidesdb_column_family_t *cf = (tidesdb_column_family_t *)arg;

    while (!atomic_load(&cf->compaction_should_stop))
    {
        usleep(cf->config.compaction_interval_ms * 1000);

        if (atomic_load(&cf->compaction_should_stop)) break;

        int num_levels = atomic_load(&cf->num_levels);
        int needs_compaction = 0;
        int needs_flush = 0;

        skip_list_t *memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
        size_t memtable_size = (size_t)skip_list_get_size(memtable);

        if (memtable_size >= cf->config.write_buffer_size)
        {
            needs_flush = 1;
            needs_compaction = 1;
        }

        tidesdb_level_t **levels = atomic_load_explicit(&cf->levels, memory_order_acquire);
        for (int i = 0; i < num_levels; i++)
        {
            size_t current = atomic_load(&levels[i]->current_size);
            if (current >= levels[i]->capacity)
            {
                needs_compaction = 1;
                break;
            }
        }

        if (needs_compaction)
        {
            if (needs_flush)
            {
                tidesdb_flush_memtable(cf);
            }

            /* enqueue compaction work for thread pool to process */
            tidesdb_compaction_work_t *work = malloc(sizeof(tidesdb_compaction_work_t));
            if (work)
            {
                work->cf = cf;
                if (queue_enqueue(cf->db->compaction_queue, work) != 0)
                {
                    free(work);
                }
            }
        }
    }

    return NULL;
}

/**
 * remove_directory
 * safely removes a directory and all its contents iteratively
 * @param path the directory path to remove
 * @return 0 on success, -1 on failure
 */
static int remove_directory(const char *path)
{
    /* simple two-pass approach: first remove all files, then remove directories bottom-up */

    /* pass 1 collect all paths (files and directories) */
    char **paths = NULL;
    int *is_dir = NULL;
    int path_count = 0;
    int path_capacity = MAX_FILE_PATH_LENGTH;

    paths = malloc(path_capacity * sizeof(char *));
    is_dir = malloc(path_capacity * sizeof(int));
    if (!paths || !is_dir)
    {
        free(paths);
        free(is_dir);
        return -1;
    }

    /* stack for iterative traversal */
    char **stack = malloc(path_capacity * sizeof(char *));
    if (!stack)
    {
        free(paths);
        free(is_dir);
        return -1;
    }

    int stack_size = 0;
    stack[stack_size++] = tdb_strdup(path);

    /* traverse directory tree iteratively */
    while (stack_size > 0)
    {
        char *current = stack[--stack_size];
        DIR *dir = opendir(current);

        if (!dir)
        {
            /* it's a file, add to list */
            if (path_count >= path_capacity)
            {
                path_capacity *= 2;
                char **new_paths = realloc(paths, path_capacity * sizeof(char *));
                int *new_is_dir = realloc(is_dir, path_capacity * sizeof(int));
                if (!new_paths || !new_is_dir)
                {
                    free(new_paths);
                    free(new_is_dir);
                    free(current);
                    goto cleanup_error;
                }
                paths = new_paths;
                is_dir = new_is_dir;
            }
            paths[path_count] = current;
            is_dir[path_count] = 0;
            path_count++;
            continue;
        }

        /* add directory to list */
        if (path_count >= path_capacity)
        {
            path_capacity *= 2;
            char **new_paths = realloc(paths, path_capacity * sizeof(char *));
            int *new_is_dir = realloc(is_dir, path_capacity * sizeof(int));
            if (!new_paths || !new_is_dir)
            {
                free(new_paths);
                free(new_is_dir);
                closedir(dir);
                free(current);
                goto cleanup_error;
            }
            paths = new_paths;
            is_dir = new_is_dir;
        }
        paths[path_count] = current;
        is_dir[path_count] = 1;
        path_count++;

        /* add children to stack */
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            char full_path[MAX_FILE_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s%s%s", current, PATH_SEPARATOR,
                     entry->d_name);

            if (stack_size >= path_capacity)
            {
                path_capacity *= 2;
                char **new_stack = realloc(stack, path_capacity * sizeof(char *));
                if (!new_stack)
                {
                    closedir(dir);
                    goto cleanup_error;
                }
                stack = new_stack;
            }
            stack[stack_size++] = tdb_strdup(full_path);
        }
        closedir(dir);
    }

    /* pass 2 remove in reverse order (files first, then directories bottom-up) */
    int result = 0;
    for (int i = path_count - 1; i >= 0; i--)
    {
        if (is_dir[i])
        {
            if (rmdir(paths[i]) != 0) result = -1;
        }
        else
        {
            if (unlink(paths[i]) != 0) result = -1;
        }
        free(paths[i]);
    }

    free(paths);
    free(is_dir);
    free(stack);
    return result;

cleanup_error:
    for (int i = 0; i < stack_size; i++) free(stack[i]);
    for (int i = 0; i < path_count; i++) free(paths[i]);
    free(paths);
    free(is_dir);
    free(stack);
    return -1;
}

/**
 * tidesdb_column_family_free
 * free column family
 * @param cf the column family
 */
static void tidesdb_column_family_free(tidesdb_column_family_t *cf)
{
    if (!cf) return;

    if (cf->config.enable_background_compaction)
    {
        atomic_store(&cf->compaction_should_stop, 1);
    }

    skip_list_t *memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    block_manager_t *wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);

    skip_list_free(memtable);
    block_manager_close(wal);

    while (!queue_is_empty(cf->immutable_memtables))
    {
        tidesdb_immutable_memtable_t *immutable =
            (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
        if (immutable)
        {
            tidesdb_immutable_memtable_unref(immutable);
        }
    }
    queue_free(cf->immutable_memtables);

    int num = cf->num_levels;
    tidesdb_level_t **levels = cf->levels;
    TDB_DEBUG_LOG("CF '%s': Freeing %d levels, levels array=%p", cf->name, num, (void *)levels);
    for (int i = 0; i < num; i++)
    {
        tidesdb_level_t *lvl = levels[i];
        TDB_DEBUG_LOG("CF '%s': Level[%d] ptr=%p, level_num=%d, num_sstables=%d", cf->name, i,
                      (void *)lvl, lvl->level_num, lvl->num_sstables);
        tidesdb_level_free(lvl);
    }
    free(levels);

    if (cf->active_txn_buffer)
    {
        buffer_free(cf->active_txn_buffer);
    }

    /* destroy rwlocks */
    pthread_rwlock_destroy(&cf->compaction_rwlock);
    pthread_rwlock_destroy(&cf->flush_rwlock);
    pthread_rwlock_destroy(&cf->levels_rwlock);

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

    while (!atomic_load(&db->flush_should_stop))
    {
        /* wait for work (blocking dequeue) */
        TDB_DEBUG_LOG("Flush worker waiting for work...");
        tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue_wait(db->flush_queue);
        TDB_DEBUG_LOG("Flush worker got work: %p", (void *)work);

        if (!work)
        {
            /* NULL work item means shutdown */
            TDB_DEBUG_LOG("Flush worker received NULL, exiting");
            break;
        }

        /* check shutdown after getting work -- if stopping, clean up and exit */
        if (atomic_load(&db->flush_should_stop))
        {
            tidesdb_immutable_memtable_unref(work->imm);
            free(work);
            break;
        }

        tidesdb_column_family_t *cf = work->cf;
        /* CF reference is already held by the work item (added when queued) */
        tidesdb_immutable_memtable_t *imm = work->imm;
        skip_list_t *memtable = imm->memtable;
        block_manager_t *wal = imm->wal;

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG("CF '%s': Insufficient disk space for flush (required: %" PRIu64
                          " bytes)",
                          cf->name, cf->config.min_disk_space);

            /* we release work and skip flush the memtable stays in memory */
            tidesdb_immutable_memtable_unref(imm);
            free(work);
            continue;
        }

        char sst_path[MAX_FILE_PATH_LENGTH];
        snprintf(sst_path, sizeof(sst_path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "1",
                 cf->directory);

        tidesdb_sstable_t *sst = tidesdb_sstable_create(sst_path, work->sst_id, &cf->config);
        if (sst)
        {
            int write_result = tidesdb_sstable_write_from_memtable(db, sst, memtable);
            if (write_result == TDB_SUCCESS)
            {
                /* block managers are managed by cache, no explicit close needed */

                /* ensure all writes are visible before making sstable discoverable */
                atomic_thread_fence(memory_order_seq_cst);

                /* acquire lock only for the brief moment of adding sstable to level */
                pthread_rwlock_wrlock(&cf->levels_rwlock);
                tidesdb_level_t **levels = cf->levels;
                tidesdb_level_add_sstable(levels[0], sst);
                pthread_rwlock_unlock(&cf->levels_rwlock);

                atomic_thread_fence(memory_order_seq_cst);

                TDB_DEBUG_LOG("CF '%s': Flushed SSTable %" PRIu64 " to level 0", cf->name,
                              work->sst_id);
                /* release our reference the level now owns it */
                tidesdb_sstable_unref(sst);

                if (wal)
                {
                    char *wal_path_to_delete = tdb_strdup(wal->file_path);
                    block_manager_close(wal);
                    imm->wal = NULL; /* WAL closed, prevent double-free */
                    unlink(wal_path_to_delete);
                    free(wal_path_to_delete);
                }

                atomic_thread_fence(memory_order_seq_cst);

                atomic_store_explicit(&imm->flushed, 1, memory_order_release);

                while (!queue_is_empty(cf->immutable_memtables))
                {
                    tidesdb_immutable_memtable_t *front =
                        (tidesdb_immutable_memtable_t *)queue_peek(cf->immutable_memtables);
                    if (!front) break;

                    int is_flushed = atomic_load_explicit(&front->flushed, memory_order_acquire);
                    int refcount = atomic_load_explicit(&front->refcount, memory_order_acquire);

                    if (is_flushed && refcount == 1)
                    {
                        queue_dequeue(cf->immutable_memtables);
                        tidesdb_immutable_memtable_unref(front); /* releases queue's reference */
                    }
                    else
                    {
                        /* front is either not flushed or has active readers, stop */
                        break;
                    }
                }

                /* check if L0 has too many sstables
                 * this ensures read amplification stays bounded and prevents write stalls */
                tidesdb_level_t *level0 = cf->levels[0];
                if (level0)
                {
                    int l0_count =
                        atomic_load_explicit(&level0->num_sstables, memory_order_acquire);

                    /* trigger compaction if L0 has more than 4 sstables
                     * this is independent of level capacity, we want to keep L0 small
                     * to minimize read amplification (L0 sstables have overlapping keys) */
                    if (l0_count > 4)
                    {
                        TDB_DEBUG_LOG(
                            "CF '%s': L0 has %d SSTables (threshold: 4), triggering compaction",
                            cf->name, l0_count);

                        tidesdb_compaction_work_t *compaction_work =
                            calloc(1, sizeof(tidesdb_compaction_work_t));
                        if (compaction_work)
                        {
                            compaction_work->cf = cf;
                            if (queue_enqueue(db->compaction_queue, compaction_work) != 0)
                            {
                                free(compaction_work);
                            }
                        }
                    }
                }
            }
            else
            {
                TDB_DEBUG_LOG("CF '%s': SSTable %" PRIu64 " write FAILED (error %d)", cf->name,
                              work->sst_id, write_result);
                tidesdb_sstable_unref(sst);
            }
        }
        else
        {
            TDB_DEBUG_LOG("CF '%s': SSTable %" PRIu64 " creation FAILED", cf->name, work->sst_id);
        }

        free(work);
    }

    TDB_DEBUG_LOG("Flush worker thread exiting");
    return NULL;
}

/**
 * tidesdb_compaction_worker_thread
 * worker thread that processes compaction work items from the queue
 *
 * this allows parallel compaction across multiple column families.
 * the compaction_lock ensures only one compaction per CF at a time,
 * but multiple workers can compact different CFs concurrently.
 */
static void *tidesdb_compaction_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;

    TDB_DEBUG_LOG("Compaction worker thread started");

    while (!atomic_load(&db->compaction_should_stop))
    {
        TDB_DEBUG_LOG("Compaction worker waiting for work...");
        /* wait for work (blocking dequeue) */
        tidesdb_compaction_work_t *work =
            (tidesdb_compaction_work_t *)queue_dequeue_wait(db->compaction_queue);
        TDB_DEBUG_LOG("Compaction worker got work: %p", (void *)work);

        if (!work || atomic_load(&db->compaction_should_stop))
        {
            /* NULL work item or shutdown signal */
            break;
        }

        tidesdb_column_family_t *cf = work->cf;

        int space_check = tidesdb_check_disk_space(db, cf->directory, cf->config.min_disk_space);
        if (space_check <= 0)
        {
            TDB_DEBUG_LOG("CF '%s': Insufficient disk space for compaction (required: %" PRIu64
                          " bytes)",
                          cf->name, cf->config.min_disk_space);
            free(work);
            continue;
        }

        /* try to acquire compaction lock, skip if already compacting */
        if (pthread_rwlock_trywrlock(&cf->compaction_rwlock) == 0)
        {
            TDB_DEBUG_LOG("Compacting CF '%s'", cf->name);
            tidesdb_trigger_compaction(cf);
            pthread_rwlock_unlock(&cf->compaction_rwlock);
        }

        free(work);
    }

    return NULL;
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
    atomic_init(&(*db)->column_families, cfs);
    atomic_init(&(*db)->num_column_families, 0);
    atomic_init(&(*db)->cf_list_state, 0); /* 0=idle, 1=modifying */

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

    atomic_init(&(*db)->flush_should_stop, 0);
    atomic_init(&(*db)->compaction_should_stop, 0);
    atomic_init(&(*db)->global_txn_seq, 0); /* global sequence for multi-CF transactions */
    atomic_init(&(*db)->next_txn_id, 1);    /* transaction ID counter (start at 1) */
    atomic_init(&(*db)->is_open, 0);

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

    (*db)->sstable_cache = fifo_cache_new(config->max_open_sstables);
    if (!(*db)->sstable_cache)
    {
        queue_free((*db)->flush_queue);
        queue_free((*db)->compaction_queue);
        free((*db)->column_families);
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    (*db)->flush_threads = malloc(config->num_flush_threads * sizeof(pthread_t));
    if (!(*db)->flush_threads)
    {
        fifo_cache_free((*db)->sstable_cache);
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
            atomic_store(&(*db)->flush_should_stop, 1);
            for (int j = 0; j < i; j++)
            {
                pthread_join((*db)->flush_threads[j], NULL);
            }
            free((*db)->flush_threads);
            fifo_cache_free((*db)->sstable_cache);
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
        atomic_store(&(*db)->flush_should_stop, 1);
        for (int i = 0; i < config->num_flush_threads; i++)
        {
            pthread_join((*db)->flush_threads[i], NULL);
        }
        free((*db)->flush_threads);
        fifo_cache_free((*db)->sstable_cache);
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
            atomic_store(&(*db)->compaction_should_stop, 1);
            for (int j = 0; j < i; j++)
            {
                pthread_join((*db)->compaction_threads[j], NULL);
            }
            free((*db)->compaction_threads);
            atomic_store(&(*db)->flush_should_stop, 1);
            for (int k = 0; k < config->num_flush_threads; k++)
            {
                pthread_join((*db)->flush_threads[k], NULL);
            }
            free((*db)->flush_threads);
            fifo_cache_free((*db)->sstable_cache);
            queue_free((*db)->flush_queue);
            queue_free((*db)->compaction_queue);
            free((*db)->column_families);
            free((*db)->db_path);
            free(*db);
            return TDB_ERR_MEMORY;
        }
    }

    (*db)->is_open = 1;

    tidesdb_recover_database(*db);

    return TDB_SUCCESS;
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Closing TidesDB at path: %s", db->db_path);

    atomic_store(&db->flush_should_stop, 1);
    atomic_store(&db->compaction_should_stop, 1);

    if (db->flush_queue)
    {
        atomic_store(&db->flush_queue->shutdown, 1);
        pthread_mutex_lock(&db->flush_queue->wait_lock);
        pthread_cond_broadcast(&db->flush_queue->not_empty);
        pthread_mutex_unlock(&db->flush_queue->wait_lock);
    }

    if (db->compaction_queue)
    {
        atomic_store(&db->compaction_queue->shutdown, 1);
        pthread_mutex_lock(&db->compaction_queue->wait_lock);
        pthread_cond_broadcast(&db->compaction_queue->not_empty);
        pthread_mutex_unlock(&db->compaction_queue->wait_lock);
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

    if (db->flush_queue)
    {
        while (!queue_is_empty(db->flush_queue))
        {
            tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue(db->flush_queue);
            if (work)
            {
                if (work->imm) tidesdb_immutable_memtable_unref(work->imm);
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
            if (work)
            {
                free(work);
            }
        }
        queue_free(db->compaction_queue);
    }

    int num_cfs = atomic_load_explicit(&db->num_column_families, memory_order_acquire);
    tidesdb_column_family_t **cfs =
        atomic_load_explicit(&db->column_families, memory_order_acquire);

    for (int i = 0; i < num_cfs; i++)
    {
        tidesdb_column_family_t *cf = cfs[i];
        if (cf->config.enable_background_compaction)
        {
            atomic_store(&cf->compaction_should_stop, 1);
        }
    }

    for (int i = 0; i < num_cfs; i++)
    {
        tidesdb_column_family_t *cf = cfs[i];
        if (cf->config.enable_background_compaction)
        {
            pthread_join(cf->compaction_thread, NULL);
        }
    }

    for (int i = 0; i < num_cfs; i++)
    {
        tidesdb_column_family_free(cfs[i]);
    }
    free(cfs);

    fifo_cache_free(db->sstable_cache);

    free(db->db_path);
    atomic_store_explicit(&db->is_open, 0, memory_order_release);
    free(db);

    return TDB_SUCCESS;
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name || !config) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Creating column family: %s", name);

    int num_cfs = atomic_load_explicit(&db->num_column_families, memory_order_acquire);
    tidesdb_column_family_t **cfs =
        atomic_load_explicit(&db->column_families, memory_order_acquire);

    for (int i = 0; i < num_cfs; i++)
    {
        if (strcmp(cfs[i]->name, name) == 0)
        {
            TDB_DEBUG_LOG("Column family already exists: %s", name);
            return TDB_ERR_EXISTS;
        }
    }

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

    /* initialize rwlocks */
    if (pthread_rwlock_init(&cf->levels_rwlock, NULL) != 0)
    {
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    if (pthread_rwlock_init(&cf->flush_rwlock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->levels_rwlock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    if (pthread_rwlock_init(&cf->compaction_rwlock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->flush_rwlock);
        pthread_rwlock_destroy(&cf->levels_rwlock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    skip_list_t *new_memtable = NULL;
    if (skip_list_new_with_comparator(&new_memtable, config->skip_list_max_level,
                                      config->skip_list_probability, config->comparator,
                                      config->comparator_ctx) != 0)
    {
        pthread_rwlock_destroy(&cf->compaction_rwlock);
        pthread_rwlock_destroy(&cf->flush_rwlock);
        pthread_rwlock_destroy(&cf->levels_rwlock);
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
        pthread_rwlock_destroy(&cf->compaction_rwlock);
        pthread_rwlock_destroy(&cf->flush_rwlock);
        pthread_rwlock_destroy(&cf->levels_rwlock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    char wal_path[TDB_MAX_PATH_LEN];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(time(NULL)));

    block_manager_t *new_wal = NULL;
    if (block_manager_open_with_cache(&new_wal, wal_path, BLOCK_MANAGER_SYNC_NONE, 0) != 0)
    {
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        pthread_rwlock_destroy(&cf->compaction_rwlock);
        pthread_rwlock_destroy(&cf->flush_rwlock);
        pthread_rwlock_destroy(&cf->levels_rwlock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_IO;
    }
    atomic_init(&cf->active_wal, new_wal);

    atomic_init(&cf->num_levels, 1);
    size_t base_capacity = config->write_buffer_size * config->level_size_ratio;
    tidesdb_level_t **new_levels = malloc(config->max_levels * sizeof(tidesdb_level_t *));
    if (!new_levels)
    {
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }
    atomic_init(&cf->levels, new_levels);

    tidesdb_level_t **levels_ptr = atomic_load(&cf->levels);
    levels_ptr[0] = tidesdb_level_create(1, base_capacity);
    if (!levels_ptr[0])
    {
        free(levels_ptr);
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->next_seq_num, 0);
    atomic_init(&cf->commit_seq, 0);
    atomic_init(&cf->memtable_id, 0);
    atomic_init(&cf->memtable_generation, 0);
    atomic_init(&cf->compaction_should_stop, 0);
    atomic_init(&cf->commit_ticket, 0);
    atomic_init(&cf->commit_serving, 0);

    void txn_entry_evict(void *data, void *ctx)
    {
        (void)ctx;
        if (data) free(data);
    }

    if (buffer_new_with_eviction(&cf->active_txn_buffer, TDB_DEFAULT_ACTIVE_TXN_BUFFER_SIZE,
                                 txn_entry_evict, NULL) != 0)
    {
        free(levels_ptr);
        block_manager_close(atomic_load(&cf->active_wal));
        queue_free(cf->immutable_memtables);
        skip_list_free(atomic_load(&cf->active_memtable));
        free(cf->directory);
        free(cf->name);
        free(cf);
        return TDB_ERR_MEMORY;
    }

    /* start background compaction thread if enabled */
    if (config->enable_background_compaction)
    {
        if (pthread_create(&cf->compaction_thread, NULL, tidesdb_background_compaction_thread,
                           cf) != 0)
        {
            /* non-fatal, continue without background compaction */
        }
    }

    while (1)
    {
        int current_num = atomic_load_explicit(&db->num_column_families, memory_order_acquire);
        int current_cap = atomic_load_explicit(&db->cf_capacity, memory_order_acquire);
        tidesdb_column_family_t **current_array =
            atomic_load_explicit(&db->column_families, memory_order_acquire);

        /* check if we need to grow the array */
        if (current_num >= current_cap)
        {
            int new_cap = current_cap * 2;
            tidesdb_column_family_t **new_array =
                malloc(new_cap * sizeof(tidesdb_column_family_t *));
            if (!new_array)
            {
                tidesdb_column_family_free(cf);
                return TDB_ERR_MEMORY;
            }

            for (int i = 0; i < current_num; i++)
            {
                new_array[i] = current_array[i];
            }
            new_array[current_num] = cf;

            /* try to swap in new array */
            if (atomic_compare_exchange_strong_explicit(&db->column_families, &current_array,
                                                        new_array, memory_order_release,
                                                        memory_order_acquire))
            {
                atomic_store_explicit(&db->num_column_families, current_num + 1,
                                      memory_order_release);
                atomic_store_explicit(&db->cf_capacity, new_cap, memory_order_release);
                free(current_array);
                break;
            }
            /* CAS failed, retry */
            free(new_array);
        }
        else
        {
            /* no need to grow we just add to existing array */
            tidesdb_column_family_t **new_array =
                malloc(current_cap * sizeof(tidesdb_column_family_t *));
            if (!new_array)
            {
                tidesdb_column_family_free(cf);
                return TDB_ERR_MEMORY;
            }

            for (int i = 0; i < current_num; i++)
            {
                new_array[i] = current_array[i];
            }
            new_array[current_num] = cf;

            if (atomic_compare_exchange_strong_explicit(&db->column_families, &current_array,
                                                        new_array, memory_order_release,
                                                        memory_order_acquire))
            {
                atomic_store_explicit(&db->num_column_families, current_num + 1,
                                      memory_order_release);
                free(current_array);
                break;
            }
            free(new_array);
        }
    }

    TDB_DEBUG_LOG("Created CF '%s' (total: %d)", name, atomic_load(&db->num_column_families));

    return TDB_SUCCESS;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;
    if (!atomic_load_explicit(&db->is_open, memory_order_acquire)) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Dropping column family: %s", name);

    tidesdb_column_family_t *cf_to_drop = NULL;

    while (1)
    {
        int current_num = atomic_load_explicit(&db->num_column_families, memory_order_acquire);
        int current_cap = atomic_load_explicit(&db->cf_capacity, memory_order_acquire);
        tidesdb_column_family_t **current_array =
            atomic_load_explicit(&db->column_families, memory_order_acquire);

        /* find the CF to drop */
        int found_idx = -1;
        for (int i = 0; i < current_num; i++)
        {
            if (strcmp(current_array[i]->name, name) == 0)
            {
                found_idx = i;
                cf_to_drop = current_array[i];
                break;
            }
        }

        if (found_idx == -1)
        {
            return TDB_ERR_NOT_FOUND;
        }

        /* create new array without the dropped CF */
        tidesdb_column_family_t **new_array =
            malloc(current_cap * sizeof(tidesdb_column_family_t *));
        if (!new_array)
        {
            return TDB_ERR_MEMORY;
        }

        int new_idx = 0;
        for (int i = 0; i < current_num; i++)
        {
            if (i != found_idx)
            {
                new_array[new_idx++] = current_array[i];
            }
        }

        /* try to swap in new array */
        if (atomic_compare_exchange_strong_explicit(&db->column_families, &current_array, new_array,
                                                    memory_order_release, memory_order_acquire))
        {
            atomic_store_explicit(&db->num_column_families, current_num - 1, memory_order_release);
            free(current_array);
            break;
        }
        /* CAS failed, retry */
        free(new_array);
        cf_to_drop = NULL; /* will be found again in next iteration */
    }

    if (cf_to_drop->config.enable_background_compaction)
    {
        atomic_store(&cf_to_drop->compaction_should_stop, 1);
        pthread_join(cf_to_drop->compaction_thread, NULL);
    }

    int result = remove_directory(cf_to_drop->directory);
    TDB_DEBUG_LOG("Deleted column family directory: %s (result: %d)", cf_to_drop->directory,
                  result);

    tidesdb_column_family_free(cf_to_drop);

    return TDB_SUCCESS;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

    int num_cfs = atomic_load_explicit(&db->num_column_families, memory_order_acquire);
    tidesdb_column_family_t **cfs =
        atomic_load_explicit(&db->column_families, memory_order_acquire);

    for (int i = 0; i < num_cfs; i++)
    {
        if (strcmp(cfs[i]->name, name) == 0)
        {
            return cfs[i];
        }
    }

    return NULL;
}

int tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* try to acquire flush lock, return if another thread is already flushing */
    if (pthread_rwlock_trywrlock(&cf->flush_rwlock) != 0)
    {
        /* another thread is already flushing */
        return TDB_SUCCESS;
    }

    skip_list_t *current_memtable =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    size_t current_size = (size_t)skip_list_get_size(current_memtable);
    int current_entries = skip_list_count_entries(current_memtable);

    if (current_entries == 0)
    {
        pthread_rwlock_unlock(&cf->flush_rwlock);
        return TDB_SUCCESS;
    }

    if (current_size < cf->config.write_buffer_size)
    {
        pthread_rwlock_unlock(&cf->flush_rwlock);
        return TDB_SUCCESS;
    }

    TDB_DEBUG_LOG("Flushing memtable for column family: %s (entries: %d)", cf->name,
                  current_entries);

    skip_list_t *old_memtable = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    block_manager_t *old_wal = atomic_load_explicit(&cf->active_wal, memory_order_acquire);
    uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);

    skip_list_t *new_memtable;
    if (skip_list_new(&new_memtable, 32, 0.25f) != 0)
    {
        pthread_rwlock_unlock(&cf->flush_rwlock);
        return TDB_ERR_MEMORY;
    }

    uint64_t wal_id = atomic_fetch_add(&cf->memtable_id, 1);
    char wal_path[MAX_FILE_PATH_LENGTH];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(wal_id));

    block_manager_t *new_wal;

    if (block_manager_open_with_cache(&new_wal, wal_path, convert_sync_mode(cf->config.sync_mode),
                                      0) != 0)
    {
        skip_list_free(new_memtable);
        pthread_rwlock_unlock(&cf->flush_rwlock);
        return TDB_ERR_IO;
    }

    tidesdb_immutable_memtable_t *immutable = malloc(sizeof(tidesdb_immutable_memtable_t));
    if (!immutable)
    {
        skip_list_free(new_memtable);
        block_manager_close(new_wal);
        pthread_rwlock_unlock(&cf->flush_rwlock);
        return TDB_ERR_MEMORY;
    }

    immutable->memtable = old_memtable;
    immutable->wal = old_wal;
    atomic_init(&immutable->refcount, 1); /* starts with refcount = 1 */
    immutable->flushed = 0;               /* not yet flushed */
    queue_enqueue(cf->immutable_memtables, immutable);

    atomic_store_explicit(&cf->active_memtable, new_memtable, memory_order_release);
    atomic_store_explicit(&cf->active_wal, new_wal, memory_order_release);
    atomic_fetch_add_explicit(&cf->memtable_generation, 1, memory_order_release);

    pthread_rwlock_unlock(&cf->flush_rwlock);

    tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
    if (!work)
    {
        return TDB_ERR_MEMORY;
    }

    work->cf = cf;
    work->imm = immutable;
    work->sst_id = sst_id;

    if (queue_enqueue(cf->db->flush_queue, work) != 0)
    {
        free(work);
        return TDB_ERR_MEMORY;
    }

    /* return immediately, flush happens in background */
    return TDB_SUCCESS;
}

int tidesdb_compact(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    tidesdb_compaction_work_t *work = malloc(sizeof(tidesdb_compaction_work_t));
    if (!work) return TDB_ERR_MEMORY;

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
            /* registration failed, but continue (best-effort) */
            txn_slot = BUFFER_INVALID_ID;
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

    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    tidesdb_level_t **levels = cf->levels;

    tidesdb_kv_pair_t *best_kv = NULL;
    uint64_t best_seq = UINT64_MAX;
    int found_any = 0;

    for (int i = 0; i < num_levels; i++)
    {
        tidesdb_level_t *level = levels[i];
        tidesdb_sstable_t **sstables = level->sstables;
        int num_ssts = level->num_sstables;

        if (num_ssts == 0)
        {
            continue;
        }

        /* for level 0, search in reverse order (newest ssts first)
         * for other levels, normal order is fine */
        int start = (i == 0) ? num_ssts - 1 : 0;
        int end = (i == 0) ? -1 : num_ssts;
        int step = (i == 0) ? -1 : 1;

        for (int j = start; j != end; j += step)
        {
            tidesdb_sstable_t *sst = sstables[j];

            /* acquire reference to protect against concurrent deletion */
            tidesdb_sstable_ref(sst);

            /* skip ssts whose key range doesn't contain our key */
            int in_range = tidesdb_sstable_contains_key_range(
                sst, key, key_size, cf->config.comparator, cf->config.comparator_ctx);
            if (!in_range)
            {
                tidesdb_sstable_unref(sst);
                continue;
            }

            tidesdb_kv_pair_t *candidate_kv = NULL;
            if (tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv) == TDB_SUCCESS)
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

                    /* early exit for level 0
                     * l0 ssts are ordered newest-first, so first match is most recent */
                    if (i == 0)
                    {
                        tidesdb_sstable_unref(sst);
                        pthread_rwlock_unlock(&cf->levels_rwlock);
                        goto check_found_result;
                    }
                }
                else
                {
                    tidesdb_kv_pair_free(candidate_kv);
                }
            }

            tidesdb_sstable_unref(sst);
        }

        if (i == 0 && found_any)
        {
            break;
        }
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

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

            if (skip_list_get_with_seq(key_cf->active_memtable, txn->read_keys[i],
                                       txn->read_key_sizes[i], &temp_value, &temp_value_size, &ttl,
                                       &deleted, &found_seq, UINT64_MAX) == 0)
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

            if (skip_list_get_with_seq(key_cf->active_memtable, txn->write_keys[i],
                                       txn->write_key_sizes[i], &temp_value, &temp_value_size, &ttl,
                                       &deleted, &found_seq, UINT64_MAX) == 0)
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

            /* context for conflict detection */
            typedef struct
            {
                tidesdb_txn_t *txn;
                int conflict_found;
            } ssi_check_ctx_t;

            void check_rw_conflict(uint32_t id, void *data, void *ctx)
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

    /* check compaction debt and slow writes if needed
     * this prevents writes from outpacing compaction */
    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        tidesdb_column_family_t *cf = txn->cfs[cf_idx];

        /* check L0 sstable count, if too many, apply backpressure */
        int num_levels = atomic_load(&cf->num_levels);
        if (num_levels > 0)
        {
            tidesdb_level_t **levels = atomic_load_explicit(&cf->levels, memory_order_acquire);
            tidesdb_level_t *level0 = levels[0];
            if (level0)
            {
                int l0_sstable_count =
                    atomic_load_explicit(&level0->num_sstables, memory_order_acquire);

                /* throttle if L0 has too many sstables (indicates compaction falling behind) */
                if (l0_sstable_count > 8)
                {
                    /* exponential backoff sleep more as count increases */
                    int sleep_ms = (l0_sstable_count - 8) * 10; /* 10ms per extra sstable */
                    if (sleep_ms > 500) sleep_ms = 500;         /* cap at 500ms */
                    usleep(sleep_ms * 1000);
                    TDB_DEBUG_LOG("CF '%s': Write throttled %dms (L0 SSTables: %d)", cf->name,
                                  sleep_ms, l0_sstable_count);
                }
            }
        }

        /* check immutable memtable queue depth for backpressure */
        int stall_level = tidesdb_check_write_stall(cf);
        if (stall_level == 2)
        {
            /* hard limit, we stall until queue drains */
            TDB_DEBUG_LOG("CF '%s': Hard write stall - waiting for flush", cf->name);
            while (tidesdb_check_write_stall(cf) == 2)
            {
                usleep(100000); /* 100ms */
            }
        }
        else if (stall_level == 1)
        {
            /* soft limit, we slow down writes */
            size_t queue_depth = queue_size(cf->immutable_memtables);
            int sleep_ms = (int)(queue_depth - cf->config.max_immutable_memtables) * 50;
            if (sleep_ms > 500) sleep_ms = 500;
            usleep(sleep_ms * 1000);
            TDB_DEBUG_LOG("CF '%s': Write slowdown %dms (queue depth: %zu)", cf->name, sleep_ms,
                          queue_depth);
        }
    }

    /* prepare context for each CF */
    typedef struct
    {
        tidesdb_column_family_t *cf;
        int op_count;
        size_t wal_size;
        uint8_t *wal_batch;
        uint64_t *seq_numbers;
        int committed;
    } cf_commit_ctx_t;

    /* defensive check to satisfy static analysis */
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
                    /* we prep metadata header */
                    tidesdb_multi_cf_txn_metadata_t metadata;
                    metadata.num_participant_cfs = (uint8_t)txn->num_cfs;

                    /* we prep CF names buffer for checksum computation */
                    size_t cf_names_size = txn->num_cfs * TDB_MAX_CF_NAME_LEN;
                    uint8_t *cf_names_buf = wal_ptr + sizeof(tidesdb_multi_cf_txn_metadata_t);

                    uint8_t *name_ptr = cf_names_buf;
                    for (int cf_i = 0; cf_i < txn->num_cfs; cf_i++)
                    {
                        strncpy((char *)name_ptr, txn->cfs[cf_i]->name, TDB_MAX_CF_NAME_LEN - 1);
                        name_ptr[TDB_MAX_CF_NAME_LEN - 1] = '\0';
                        name_ptr += TDB_MAX_CF_NAME_LEN;
                    }

                    /* compute checksum over num_participant_cfs + cf_names */
                    size_t checksum_data_size = sizeof(uint8_t) + cf_names_size;
                    uint8_t *checksum_data = malloc(checksum_data_size);
                    if (checksum_data)
                    {
                        checksum_data[0] = metadata.num_participant_cfs;
                        memcpy(checksum_data + 1, cf_names_buf, cf_names_size);
                        metadata.checksum = XXH64(checksum_data, checksum_data_size, 0);
                        free(checksum_data);
                    }
                    else
                    {
                        /* fallback is checksum just the count if malloc fails */
                        metadata.checksum =
                            XXH64(&metadata.num_participant_cfs, sizeof(uint8_t), 0);
                    }

                    memcpy(wal_ptr, &metadata, sizeof(tidesdb_multi_cf_txn_metadata_t));
                    wal_ptr += sizeof(tidesdb_multi_cf_txn_metadata_t);
                    wal_ptr += cf_names_size; /* we skip past CF names we already wrote */

                    first_entry_for_cf = 0;
                }
            }
            else
            {
                seq = 0;
            }

            cf_contexts[cf_idx].seq_numbers[seq_idx] = seq; /* placeholder for single-CF */
            seq_idx++;

            tidesdb_klog_entry_t entry = {
                .key_size = (uint32_t)op->key_size,
                .value_size = (uint32_t)op->value_size,
                .ttl = op->ttl,
                .seq = seq, /* placeholder for single-CF, real for multi-CF */
                .flags = op->is_delete ? TDB_KV_FLAG_TOMBSTONE : 0,
                .vlog_offset = 0};

            memcpy(wal_ptr, &entry, sizeof(tidesdb_klog_entry_t));
            wal_ptr += sizeof(tidesdb_klog_entry_t);

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
        block_manager_block_free(batch_block);

        if (wal_offset < 0)
        {
            commit_failed_at = cf_idx;
            break;
        }

        uint64_t my_ticket = atomic_fetch_add_explicit(&cf->commit_ticket, 1, memory_order_relaxed);

        uint64_t current_serving;
        while ((current_serving =
                    atomic_load_explicit(&cf->commit_serving, memory_order_acquire)) != my_ticket)
        {
            cpu_pause();
        }

        skip_list_t *target_memtable =
            atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

        int seq_idx = 0;
        int ops_written = 0;
        uint64_t max_seq_written = 0;
        uint64_t min_seq_written = UINT64_MAX;

        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            uint64_t op_seq = atomic_fetch_add_explicit(&cf->next_seq_num, 1, memory_order_relaxed);
            ctx->seq_numbers[seq_idx++] = op_seq;

            skip_list_put_with_seq(target_memtable, op->key, op->key_size, op->value,
                                   op->value_size, op->ttl, op_seq, op->is_delete);

            if (op_seq > max_seq_written) max_seq_written = op_seq;
            if (op_seq < min_seq_written) min_seq_written = op_seq;
            ops_written++;
        }

        if (ops_written > 0)
        {
            uint64_t old_commit = atomic_load_explicit(&cf->commit_seq, memory_order_relaxed);
            atomic_store_explicit(&cf->commit_seq, max_seq_written, memory_order_release);
        }

        atomic_store_explicit(&cf->commit_serving, my_ticket + 1, memory_order_release);

        ctx->committed = 1;

        /* check if flush needed */
        skip_list_t *current_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
        size_t current_memtable_size = (size_t)skip_list_get_size(current_mt);
        if (current_memtable_size >= cf->config.write_buffer_size)
        {
            TDB_DEBUG_LOG("CF '%s': Triggering flush (size %zu >= threshold %zu)", cf->name,
                          current_memtable_size, cf->config.write_buffer_size);
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
            skip_list_t *memtable =
                atomic_load_explicit(&cf->active_memtable, memory_order_acquire);

            /* write tombstones for all operations in this CF */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_txn_op_t *op = &txn->ops[i];
                if (op->cf != cf) continue;

                /* write tombstone with new sequence number to undo the operation */
                uint64_t rollback_seq = atomic_fetch_add(&cf->next_seq_num, 1);
                skip_list_put_with_seq(memtable, op->key, op->key_size, NULL, 0, 0, rollback_seq,
                                       1);
            }
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
    (*iter)->heap = tidesdb_merge_heap_create(cf->config.comparator, cf->config.comparator_ctx);
    if (!(*iter)->heap)
    {
        free(*iter);
        return TDB_ERR_MEMORY;
    }

    skip_list_t *active_mt = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    tidesdb_merge_source_t *memtable_source =
        tidesdb_merge_source_from_memtable(active_mt, &cf->config, NULL);
    if (memtable_source && memtable_source->current_kv != NULL)
    {
        tidesdb_merge_heap_add_source((*iter)->heap, memtable_source);
    }
    else if (memtable_source)
    {
        tidesdb_merge_source_free(memtable_source);
    }

    size_t imm_count = queue_size(cf->immutable_memtables);
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
                tidesdb_merge_heap_add_source((*iter)->heap, source);
            }
            else if (source)
            {
                tidesdb_merge_source_free(source);
            }
        }
    }

    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    tidesdb_level_t **levels = cf->levels;

    for (int i = 0; i < num_levels; i++)
    {
        tidesdb_level_t *level = levels[i];
        tidesdb_sstable_t **sstables = level->sstables;
        int num_ssts = level->num_sstables;

        for (int j = 0; j < num_ssts; j++)
        {
            tidesdb_sstable_t *sst = sstables[j];
            tidesdb_merge_source_t *sst_source = tidesdb_merge_source_from_sstable(cf->db, sst);
            if (sst_source && sst_source->current_kv != NULL)
            {
                tidesdb_merge_heap_add_source((*iter)->heap, sst_source);
            }
            else if (sst_source)
            {
                tidesdb_merge_source_free(sst_source);
            }
        }
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

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
            if (skip_list_cursor_seek(cursor, (uint8_t *)key, key_size) == 0)
            {
                skip_list_cursor_next(cursor);
            }
            tidesdb_merge_source_advance(source);
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

            /* use block index to jump to target */
            if (sst->block_index && cursor->position_cache)
            {
                int64_t block_num = 0;
                if (succinct_trie_prefix_get(sst->block_index, key, key_size, &block_num) == 0 &&
                    block_num < cursor->cache_size)
                {
                    cursor->cache_index = block_num;
                    cursor->current_pos = cursor->position_cache[block_num];
                    cursor->current_block_size = cursor->size_cache[block_num];
                }
                else
                {
                    block_manager_cursor_goto_first(cursor);
                }
            }
            else
            {
                block_manager_cursor_goto_first(cursor);
            }

            /* let advance() read the block */
            if (tidesdb_merge_source_advance(source) == TDB_SUCCESS)
            {
                /* binary search within the block to find first entry >= target */
                tidesdb_klog_block_t *block = source->source.sstable.current_block;
                if (block && block->num_entries > 0)
                {
                    int left = 0;
                    int right = block->num_entries - 1;
                    int result_idx = 0;

                    while (left <= right)
                    {
                        int mid = left + (right - left) / 2;
                        int cmp =
                            sst->config->comparator(block->keys[mid], block->entries[mid].key_size,
                                                    key, key_size, sst->config->comparator_ctx);

                        if (cmp >= 0)
                        {
                            result_idx = mid;
                            right = mid - 1;
                        }
                        else
                        {
                            left = mid + 1;
                            result_idx = left;
                        }
                    }

                    /* update to the found entry */
                    if (result_idx < block->num_entries)
                    {
                        source->source.sstable.current_entry_idx = result_idx;

                        /* update current_kv to point to the right entry */
                        tidesdb_kv_pair_free(source->current_kv);

                        uint8_t *value = block->inline_values[result_idx];
                        uint8_t *vlog_value = NULL;
                        if (block->entries[result_idx].vlog_offset > 0)
                        {
                            tidesdb_vlog_read_value(
                                iter->cf->db, sst, block->entries[result_idx].vlog_offset,
                                block->entries[result_idx].value_size, &vlog_value);
                            value = vlog_value;
                        }

                        source->current_kv = tidesdb_kv_pair_create(
                            block->keys[result_idx], block->entries[result_idx].key_size, value,
                            block->entries[result_idx].value_size, block->entries[result_idx].ttl,
                            block->entries[result_idx].seq,
                            block->entries[result_idx].flags & TDB_KV_FLAG_TOMBSTONE);

                        free(vlog_value);
                    }
                }
            }
        }
    }

    /* rebuild heap as min-heap */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        heap_sift_down(iter->heap, i);
    }

    /* pop first visible entry */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap);
        if (!kv) break;

        if (!tidesdb_iter_kv_visible(iter, kv))
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
            if (skip_list_cursor_seek_for_prev(cursor, (uint8_t *)key, key_size) == 0)
            {
                /* cursor already positioned at target or predecessor */
                tidesdb_merge_source_advance(source);
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

            /* use block index to jump to predecessor */
            if (sst->block_index && cursor->position_cache)
            {
                int64_t block_num = 0;
                if (succinct_trie_find_predecessor(sst->block_index, key, key_size, &block_num) ==
                        0 &&
                    block_num < cursor->cache_size)
                {
                    cursor->cache_index = block_num;
                    cursor->current_pos = cursor->position_cache[block_num];
                    cursor->current_block_size = cursor->size_cache[block_num];
                }
                else
                {
                    block_manager_cursor_goto_first(cursor);
                }
            }
            else
            {
                block_manager_cursor_goto_first(cursor);
            }

            /* let advance() read and find the right entry */
            tidesdb_merge_source_advance(source);
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
            /* seek to last block in sstable */
            if (block_manager_cursor_goto_last(source->source.sstable.klog_cursor) == 0)
            {
                /* read last data block (skip metadata blocks) */
                uint64_t num_blocks = atomic_load(&source->source.sstable.sst->num_klog_blocks);

                /* navigate to last data block */
                block_manager_cursor_goto_first(source->source.sstable.klog_cursor);
                for (uint64_t b = 1; b < num_blocks; b++)
                {
                    block_manager_cursor_next(source->source.sstable.klog_cursor);
                }

                /* release any previous decompressed data and block */
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

                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block && block_manager_block_acquire(block))
                {
                    /* release original reference from cursor_read, keep acquired reference */
                    block_manager_block_release(block);

                    /* keep reference to block data (acquired to prevent cache eviction) */
                    source->source.sstable.current_block_data = block;

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
                            /* position at last entry */
                            int idx = source->source.sstable.current_block->num_entries - 1;
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
                    }

                    /* don't free decompressed or release block as we're still using the
                     * deserialized data */
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

    /* save current key to skip duplicates */
    uint8_t *current_key = NULL;
    size_t current_key_size = 0;

    if (iter->current)
    {
        current_key = malloc(iter->current->entry.key_size);
        if (current_key)
        {
            memcpy(current_key, iter->current->key, iter->current->entry.key_size);
            current_key_size = iter->current->entry.key_size;
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

    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap);
        if (!kv) break;

        /* skip if same key as current */
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

        free(current_key);
        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    free(current_key);
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

    /* save current key to skip duplicates */
    uint8_t *current_key = NULL;
    size_t current_key_size = 0;

    if (iter->current)
    {
        current_key = malloc(iter->current->entry.key_size);
        if (current_key)
        {
            memcpy(current_key, iter->current->key, iter->current->entry.key_size);
            current_key_size = iter->current->entry.key_size;
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

        free(current_key);
        iter->current = kv;
        iter->valid = 1;
        return TDB_SUCCESS;
    }

    free(current_key);
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

                if (block_manager_open_with_cache(&wal_bm, wal_path, BLOCK_MANAGER_SYNC_NONE, 0) !=
                    0)
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

                            if (queue_enqueue(cf->db->flush_queue, work) != 0)
                            {
                                free(work);
                            }
                        }
                    }
                    else
                    {
                        TDB_DEBUG_LOG("CF '%s': Flush queue full, flushing immediately", cf->name);
                        skip_list_free(recovered_memtable);
                        free(imm);
                    }
                }
                else
                {
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
            unsigned long long sst_id_ull = 0;

            if (sscanf(entry->d_name, TDB_LEVEL_PREFIX "%d_" TDB_U64_FMT TDB_SSTABLE_KLOG_EXT,
                       &level_num, &sst_id_ull) == 2)
            {
                char sst_base[TDB_MAX_PATH_LEN];
                snprintf(sst_base, sizeof(sst_base), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d",
                         cf->directory, level_num);

                uint64_t sst_id = (uint64_t)sst_id_ull;
                TDB_DEBUG_LOG("Parsed SSTable: level=%d, id=%" PRIu64, level_num, sst_id);
                tidesdb_sstable_t *sst = tidesdb_sstable_create(sst_base, sst_id, &cf->config);
                if (sst)
                {
                    TDB_DEBUG_LOG("CF '%s': Recovering SSTable %" PRIu64 " at level %d", cf->name,
                                  sst_id, level_num);
                    if (tidesdb_sstable_load(cf->db, sst) == TDB_SUCCESS)
                    {
                        int current_levels = atomic_load(&cf->num_levels);
                        while (current_levels < level_num)
                        {
                            if (tidesdb_add_level(cf) != TDB_SUCCESS) break;
                            current_levels = atomic_load(&cf->num_levels);
                        }

                        if (level_num <= current_levels)
                        {
                            pthread_rwlock_wrlock(&cf->levels_rwlock);
                            tidesdb_level_add_sstable(cf->levels[level_num - 1], sst);
                            pthread_rwlock_unlock(&cf->levels_rwlock);

                            tidesdb_sstable_unref(sst);
                        }
                        else
                        {
                            tidesdb_sstable_unref(sst);
                        }
                    }
                    else
                    {
                        tidesdb_sstable_unref(sst);
                    }
                }
            }
        }
    }
    closedir(dir);

    uint64_t global_max_seq = 0;

    pthread_rwlock_rdlock(&cf->levels_rwlock);
    int num_levels = cf->num_levels;
    tidesdb_level_t **levels = cf->levels;

    TDB_DEBUG_LOG("CF '%s': Scanning %d levels for max_seq", cf->name, num_levels);

    for (int level_idx = 0; level_idx < num_levels; level_idx++)
    {
        tidesdb_level_t *level = levels[level_idx];
        if (!level) continue;

        tidesdb_sstable_t **sstables = level->sstables;
        int num_ssts = level->num_sstables;

        TDB_DEBUG_LOG("CF '%s': Level %d has %d sstables", cf->name, level_idx, num_ssts);

        for (int sst_idx = 0; sst_idx < num_ssts; sst_idx++)
        {
            tidesdb_sstable_t *sst = sstables[sst_idx];
            if (sst)
            {
                TDB_DEBUG_LOG("CF '%s': SSTable %d has max_seq=%" PRIu64, cf->name, sst_idx,
                              sst->max_seq);
                if (sst->max_seq > global_max_seq)
                {
                    global_max_seq = sst->max_seq;
                }
            }
        }
    }

    pthread_rwlock_unlock(&cf->levels_rwlock);

    if (cf->immutable_memtables)
    {
        size_t imm_count = queue_size(cf->immutable_memtables);
        TDB_DEBUG_LOG("CF '%s': Scanning %zu immutable memtables for max_seq", cf->name, imm_count);

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
                TDB_DEBUG_LOG("CF '%s': Immutable memtable %zu scanned", cf->name, i);
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
    if (!db || !db->is_open) return TDB_ERR_INVALID_ARGS;

    DIR *dir = opendir(db->db_path);
    if (!dir) return TDB_ERR_IO;

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
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, entry->d_name);

            if (!cf)
            {
                tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
                if (tidesdb_create_column_family(db, entry->d_name, &config) == TDB_SUCCESS)
                {
                    cf = tidesdb_get_column_family(db, entry->d_name);
                }
            }

            if (cf)
            {
                tidesdb_recover_column_family(cf);
            }
        }
    }
    closedir(dir);

    return TDB_SUCCESS;
}

int tidesdb_get_stats(tidesdb_column_family_t *cf, tidesdb_stats_t **stats)
{
    if (!cf || !stats) return TDB_ERR_INVALID_ARGS;

    *stats = calloc(1, sizeof(tidesdb_stats_t));
    if (!*stats) return TDB_ERR_MEMORY;

    (*stats)->num_levels = atomic_load(&cf->num_levels);
    (*stats)->memtable_size = skip_list_get_size(cf->active_memtable);

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
    else if (strcmp(name, "max_levels") == 0)
    {
        ctx->config->max_levels = atoi(value);
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
        else if (strcmp(value, "SNAPPY") == 0)
            ctx->config->compression_algorithm = SNAPPY_COMPRESSION;
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
    else if (strcmp(name, "block_manager_cache_size") == 0)
    {
        ctx->config->block_manager_cache_size = (size_t)atoll(value);
    }
    else if (strcmp(name, "sync_mode") == 0)
    {
        ctx->config->sync_mode = atoi(value);
    }
    else if (strcmp(name, "compaction_interval_ms") == 0)
    {
        ctx->config->compaction_interval_ms = (unsigned int)atoi(value);
    }
    else if (strcmp(name, "enable_background_compaction") == 0)
    {
        ctx->config->enable_background_compaction = atoi(value);
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
    fprintf(fp, "max_levels = %d\n", config->max_levels);
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
        case SNAPPY_COMPRESSION:
            compression_str = "SNAPPY";
            break;
    }
    fprintf(fp, "compression_algorithm = %s\n", compression_str);

    fprintf(fp, "enable_bloom_filter = %d\n", config->enable_bloom_filter);
    fprintf(fp, "bloom_fpr = %f\n", config->bloom_fpr);
    fprintf(fp, "enable_block_indexes = %d\n", config->enable_block_indexes);
    fprintf(fp, "index_sample_ratio = %d\n", config->index_sample_ratio);
    fprintf(fp, "block_manager_cache_size = %zu\n", config->block_manager_cache_size);
    fprintf(fp, "sync_mode = %d\n", config->sync_mode);
    fprintf(fp, "compaction_interval_ms = %u\n", config->compaction_interval_ms);
    fprintf(fp, "enable_background_compaction = %d\n", config->enable_background_compaction);
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

    fclose(fp);
    return TDB_SUCCESS;
}

int tidesdb_cf_update_runtime_config(tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk)
{
    if (!cf || !new_config) return TDB_ERR_INVALID_ARGS;

    cf->config.compaction_interval_ms = new_config->compaction_interval_ms;
    cf->config.enable_background_compaction = new_config->enable_background_compaction;
    cf->config.enable_bloom_filter = new_config->enable_bloom_filter;
    cf->config.bloom_fpr = new_config->bloom_fpr;
    cf->config.enable_block_indexes = new_config->enable_block_indexes;
    cf->config.index_sample_ratio = new_config->index_sample_ratio;
    cf->config.compression_algorithm = new_config->compression_algorithm;
    cf->config.write_buffer_size = new_config->write_buffer_size;
    cf->config.level_size_ratio = new_config->level_size_ratio;
    cf->config.dividing_level_offset = new_config->dividing_level_offset;
    cf->config.sync_mode = new_config->sync_mode;
    cf->config.default_isolation_level = new_config->default_isolation_level;
    cf->config.value_threshold = new_config->value_threshold;

    /* what cannot be changed at runtime?
     * -- skip_list_max_level, skip_list_probability -- would affect active memtable structure
     * -- klog_block_size, vlog_block_size -- would break existing sstable format
     * -- block_manager_cache_size -- would require recreating cache
     * -- comparator -- would break key ordering in existing data
     * these settings are fixed at column family creation time */

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
