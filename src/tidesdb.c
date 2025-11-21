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

#include "ini.h"

/* global debug flag definition */
int _tidesdb_debug_enabled = 0;

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
static int tidesdb_vlog_read_value(tidesdb_sstable_t *sst, uint64_t vlog_offset, size_t value_size,
                                   uint8_t **value);
static tidesdb_sstable_t *tidesdb_sstable_create(const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config);
static void tidesdb_sstable_free(tidesdb_sstable_t *sst);
static void tidesdb_sstable_ref(tidesdb_sstable_t *sst);
static void tidesdb_sstable_unref(tidesdb_sstable_t *sst);
static int tidesdb_sstable_write_from_memtable(tidesdb_sstable_t *sst, skip_list_t *memtable);
static int tidesdb_sstable_get(tidesdb_t *db, tidesdb_sstable_t *sst, const uint8_t *key,
                               size_t key_size, tidesdb_kv_pair_t **kv);
static int tidesdb_sstable_load(tidesdb_sstable_t *sst);
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity);
static void tidesdb_level_free(tidesdb_level_t *level);
static int tidesdb_level_add_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst);
static int tidesdb_level_remove_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst);
static int tidesdb_level_update_boundaries(tidesdb_level_t *level, tidesdb_level_t *largest_level);
static tidesdb_merge_heap_t *tidesdb_merge_heap_create(skip_list_comparator_fn comparator,
                                                       void *comparator_ctx);
static void tidesdb_merge_heap_free(tidesdb_merge_heap_t *heap);
static int tidesdb_merge_heap_add_source(tidesdb_merge_heap_t *heap,
                                         tidesdb_merge_source_t *source);
static tidesdb_kv_pair_t *tidesdb_merge_heap_pop(tidesdb_merge_heap_t *heap);
static int tidesdb_merge_heap_empty(tidesdb_merge_heap_t *heap);
static tidesdb_merge_source_t *tidesdb_merge_source_from_memtable(
    skip_list_t *memtable, tidesdb_column_family_config_t *config);
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
static int tidesdb_wal_append(block_manager_t *wal, const tidesdb_kv_pair_t *kv);
static int tidesdb_wal_recover(tidesdb_column_family_t *cf, const char *wal_path,
                               skip_list_t **memtable);
static size_t tidesdb_calculate_level_capacity(int level_num, size_t base_capacity, size_t ratio);
static int tidesdb_should_add_level(tidesdb_column_family_t *cf);
static int tidesdb_should_remove_level(tidesdb_column_family_t *cf);
static int tidesdb_add_level(tidesdb_column_family_t *cf);
static int tidesdb_remove_level(tidesdb_column_family_t *cf);
static int tidesdb_apply_dca(tidesdb_column_family_t *cf);
static int tidesdb_recover_database(tidesdb_t *db);
static int tidesdb_recover_column_family(tidesdb_column_family_t *cf);
static void *tidesdb_flush_worker_thread(void *arg);
static void *tidesdb_compaction_worker_thread(void *arg);
static tidesdb_kv_pair_t *tidesdb_kv_pair_create(const uint8_t *key, size_t key_size,
                                                 const uint8_t *value, size_t value_size,
                                                 time_t ttl, uint64_t seq, int is_tombstone);
static void tidesdb_kv_pair_free(tidesdb_kv_pair_t *kv);
static tidesdb_kv_pair_t *tidesdb_kv_pair_clone(const tidesdb_kv_pair_t *kv);
static int tidesdb_iter_kv_visible(tidesdb_iter_t *iter, tidesdb_kv_pair_t *kv);

/* sstable cache helpers */
static void tidesdb_sstable_cache_evict_cb(const char *key, void *value, void *user_data);
static int tidesdb_sstable_ensure_open(tidesdb_t *db, tidesdb_sstable_t *sst);

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
    size_t header_size = 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4; /* fixed 68 bytes */
    size_t total_size = header_size + sst->min_key_size + sst->max_key_size;

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
    encode_uint64_le_compat(ptr, sst->klog_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->vlog_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->min_key_size);
    ptr += 8;
    encode_uint64_le_compat(ptr, sst->max_key_size);
    ptr += 8;
    encode_uint32_le_compat(ptr, sst->config->compression_algorithm);
    ptr += 4;
    encode_uint32_le_compat(ptr, 0); /* reserved */
    ptr += 4;

    /* copy keys */
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
    /* minimum size is 68 bytes for header */
    if (!data || !sst || data_size < 68) return -1;

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
    uint64_t klog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t vlog_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t min_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint64_t max_key_size = decode_uint64_le_compat(ptr);
    ptr += 8;
    uint32_t compression_algorithm = decode_uint32_le_compat(ptr);
    ptr += 4;
    /* skip reserved field */
    ptr += 4;

    /* validate size */
    size_t expected_size = 68 + min_key_size + max_key_size;
    if (data_size < expected_size)
    {
        TDB_DEBUG_LOG("SSTable metadata: Size mismatch (expected %zu, got %zu)", expected_size,
                      data_size);
        return -1;
    }

    /* assign values */
    sst->num_entries = num_entries;
    sst->num_klog_blocks = num_klog_blocks;
    sst->num_vlog_blocks = num_vlog_blocks;
    sst->klog_size = klog_size;
    sst->vlog_size = vlog_size;

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
        .skip_list_max_level = 32,
        .skip_list_probability = 0.25f,
        .default_isolation_level = TDB_ISOLATION_READ_COMMITTED};
    return config;
}

tidesdb_config_t tidesdb_default_config(void)
{
    tidesdb_config_t config = {.db_path = "./tidesdb",
                               .enable_debug_logging = 1,
                               .num_flush_threads = TDB_DEFAULT_THREAD_POOL_SIZE,
                               .num_compaction_threads = TDB_DEFAULT_THREAD_POOL_SIZE,
                               .max_open_sstables = 100};
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
            TDB_DEBUG_LOG("[klog_deserialize] CORRUPTION: Entry header exceeds bounds at entry %u",
                          i);
            tidesdb_klog_block_free(*block);
            *block = NULL;
            return TDB_ERR_CORRUPTION;
        }

        memcpy(&(*block)->entries[i], ptr, sizeof(tidesdb_klog_entry_t));
        ptr += sizeof(tidesdb_klog_entry_t);

        if (ptr + (*block)->entries[i].key_size > data + data_size)
        {
            TDB_DEBUG_LOG("[klog_deserialize] Key data exceeds bounds at entry %u (key_size=%u)", i,
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
                    "[klog_deserialize] CORRUPTION: Inline value exceeds bounds at entry %u "
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
static int tidesdb_vlog_read_value(tidesdb_sstable_t *sst, uint64_t vlog_offset, size_t value_size,
                                   uint8_t **value)
{
    if (!sst->vlog_bm) return TDB_ERR_IO;

    /* calculate which vlog block contains this offset */
    uint64_t block_num = vlog_offset / sst->config->vlog_block_size;
    uint64_t offset_in_block = vlog_offset % sst->config->vlog_block_size;

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, sst->vlog_bm) != 0)
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
                TDB_DEBUG_LOG("VLog: Value size mismatch at entry %d (expected %zu, got %u)", i,
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
 * check if a key falls within an SSTable's range
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
 * tidesdb_sstable_cache_evict_cb
 * callback when an sstable is evicted from cache
 * closes the block managers to free file descriptors
 */
static void tidesdb_sstable_cache_evict_cb(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    tidesdb_sstable_t *sst = (tidesdb_sstable_t *)value;

    /* only close block managers if SSTable is still valid */
    if (!sst) return;

    /* close block managers if they're open */
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

    /* release the cache's reference to the SSTable */
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

    /* if already open, return success */
    if (sst->klog_bm && sst->vlog_bm) return 0;

    /* open block managers if not already open */
    if (!sst->klog_bm)
    {
        if (block_manager_open_with_cache(&sst->klog_bm, sst->klog_path,
                                          convert_sync_mode(sst->config->sync_mode),
                                          (uint32_t)sst->config->block_manager_cache_size) != 0)
        {
            return -1;
        }
    }

    if (!sst->vlog_bm)
    {
        if (block_manager_open_with_cache(&sst->vlog_bm, sst->vlog_path,
                                          convert_sync_mode(sst->config->sync_mode),
                                          (uint32_t)sst->config->block_manager_cache_size) != 0)
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
static tidesdb_sstable_t *tidesdb_sstable_create(const char *base_path, uint64_t id,
                                                 const tidesdb_column_family_config_t *config)
{
    tidesdb_sstable_t *sst = calloc(1, sizeof(tidesdb_sstable_t));
    if (!sst) return NULL;

    /* allocate and copy config so each SSTable has its own */
    sst->config = malloc(sizeof(tidesdb_column_family_config_t));
    if (!sst->config)
    {
        free(sst);
        return NULL;
    }
    memcpy(sst->config, config, sizeof(tidesdb_column_family_config_t));

    sst->id = id;
    sst->created_at = time(NULL);
    atomic_init(&sst->refcount, 1);

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
    free(sst->config); /* free the allocated config copy */

    if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
    if (sst->block_index) succinct_trie_free(sst->block_index);
    if (sst->klog_bm)
    {
        block_manager_close(sst->klog_bm);
    }
    if (sst->vlog_bm)
    {
        block_manager_close(sst->vlog_bm);
    }

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
 * tidesdb_sstable_write_from_memtable
 * write a memtable to an sstable
 * @param sst sstable to write to
 * @param memtable memtable to write from
 * @return 0 on success, -1 on error
 */
static int tidesdb_sstable_write_from_memtable(tidesdb_sstable_t *sst, skip_list_t *memtable)
{
    if (block_manager_open_with_cache(&sst->klog_bm, sst->klog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        return TDB_ERR_IO;
    }

    if (block_manager_open_with_cache(&sst->vlog_bm, sst->vlog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        block_manager_close(sst->klog_bm);
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
            block_manager_close(sst->klog_bm);
            block_manager_close(sst->vlog_bm);
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
            block_manager_close(sst->klog_bm);
            block_manager_close(sst->vlog_bm);
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
        block_manager_close(sst->klog_bm);
        block_manager_close(sst->vlog_bm);
        return TDB_ERR_MEMORY;
    }

    skip_list_cursor_t *cursor;
    if (skip_list_cursor_init(&cursor, memtable) != 0)
    {
        if (bloom) bloom_filter_free(bloom);
        if (index_builder) succinct_trie_builder_free(index_builder);
        tidesdb_klog_block_free(current_klog_block);
        tidesdb_vlog_block_free(current_vlog_block);
        block_manager_close(sst->klog_bm);
        block_manager_close(sst->vlog_bm);
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

    if (skip_list_cursor_goto_first(cursor) == 0)
    {
        do
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            time_t ttl;
            uint8_t deleted;

            if (skip_list_cursor_get(cursor, &key, &key_size, &value, &value_size, &ttl,
                                     &deleted) != 0)
            {
                continue;
            }

            tidesdb_kv_pair_t *kv =
                tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, 0, deleted);
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
                            block_manager_block_write(sst->vlog_bm, vlog_block);
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
                        block_manager_block_write(sst->klog_bm, klog_block);
                        block_manager_block_free(klog_block);
                        klog_block_num++;
                    }
                    free(final_klog_data);
                }

                tidesdb_klog_block_free(current_klog_block);
                current_klog_block = tidesdb_klog_block_create();
            }

            tidesdb_klog_block_add_entry(current_klog_block, kv, sst->config);

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
                block_manager_block_write(sst->klog_bm, klog_block);
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
                block_manager_block_write(sst->vlog_bm, vlog_block);
                block_manager_block_free(vlog_block);
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
                    block_manager_block_write(sst->klog_bm, index_block);
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
                block_manager_block_write(sst->klog_bm, bloom_block);
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }
        sst->bloom_filter = bloom;
    }

    /* get file sizes before writing metadata */
    block_manager_get_size(sst->klog_bm, &sst->klog_size);
    block_manager_get_size(sst->vlog_bm, &sst->vlog_size);

    /* write metadata block as the last block */
    uint8_t *metadata_data = NULL;
    size_t metadata_size = 0;
    if (sstable_metadata_serialize(sst, &metadata_data, &metadata_size) == 0)
    {
        block_manager_block_t *metadata_block =
            block_manager_block_create(metadata_size, metadata_data);
        if (metadata_block)
        {
            block_manager_block_write(sst->klog_bm, metadata_block);
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
    /* ensure SSTable is open through cache */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        TDB_DEBUG_LOG("SSTable " TDB_U64_FMT " ensure_open FAILED", TDB_U64_CAST(sst->id));
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
    if (block_manager_cursor_init(&klog_cursor, sst->klog_bm) != 0)
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

    while (block_manager_cursor_has_next(klog_cursor) && block_num < sst->num_klog_blocks)
    {
        block_manager_block_t *block = block_manager_cursor_read(klog_cursor);
        if (!block)
        {
            break;
        }

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
                            tidesdb_vlog_read_value(sst, klog_block->entries[i].vlog_offset,
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
                    free(decompressed);
                    block_manager_block_release(block);
                    goto cleanup;
                }
            }

            tidesdb_klog_block_free(klog_block);
        }

        free(decompressed);
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
 * @param sst the sstable to load
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_sstable_load(tidesdb_sstable_t *sst)
{
    if (block_manager_open_with_cache(&sst->klog_bm, sst->klog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        return TDB_ERR_IO;
    }

    if (block_manager_open_with_cache(&sst->vlog_bm, sst->vlog_path,
                                      convert_sync_mode(sst->config->sync_mode),
                                      (uint32_t)sst->config->block_manager_cache_size) != 0)
    {
        block_manager_close(sst->klog_bm);
        return TDB_ERR_IO;
    }

    block_manager_get_size(sst->klog_bm, &sst->klog_size);
    block_manager_get_size(sst->vlog_bm, &sst->vlog_size);

    /* read metadata from last block */
    block_manager_cursor_t *metadata_cursor;
    if (block_manager_cursor_init(&metadata_cursor, sst->klog_bm) == 0)
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

    /* read min/max keys from first and last klog blocks (for old SSTables without
     * metadata) */
    sst->num_klog_blocks = 0;

    /* read min/max keys from first and last klog blocks */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, sst->klog_bm) != 0)
    {
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

    if (block_manager_cursor_init(&cursor, sst->klog_bm) != 0)
    {
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

    return TDB_SUCCESS;
}

/**
 * tidesdb_level_create
 * create a new level
 * @param level_num level number
 * @param capacity capacity of the level
 * @return pointer to the new level
 */
static tidesdb_level_t *tidesdb_level_create(int level_num, size_t capacity)
{
    tidesdb_level_t *level = calloc(1, sizeof(tidesdb_level_t));
    if (!level) return NULL;

    level->level_num = level_num;
    level->capacity = capacity;
    atomic_init(&level->current_size, 0);

    level->sstables_capacity = 16;
    level->sstables = calloc(level->sstables_capacity, sizeof(tidesdb_sstable_t *));
    if (!level->sstables)
    {
        free(level);
        return NULL;
    }

    atomic_init(&level->num_sstables, 0);
    pthread_mutex_init(&level->level_lock, NULL);

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

    int num = atomic_load(&level->num_sstables);
    for (int i = 0; i < num; i++)
    {
        tidesdb_sstable_unref(level->sstables[i]);
    }
    free(level->sstables);

    for (int i = 0; i < level->num_boundaries; i++)
    {
        free(level->file_boundaries[i]);
    }
    free(level->file_boundaries);
    free(level->boundary_sizes);

    pthread_mutex_destroy(&level->level_lock);
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
    pthread_mutex_lock(&level->level_lock);

    int num = atomic_load(&level->num_sstables);

    if (num >= level->sstables_capacity)
    {
        int new_capacity = level->sstables_capacity * 2;
        tidesdb_sstable_t **new_array =
            realloc(level->sstables, new_capacity * sizeof(tidesdb_sstable_t *));
        if (!new_array)
        {
            pthread_mutex_unlock(&level->level_lock);
            return TDB_ERR_MEMORY;
        }
        level->sstables = new_array;
        level->sstables_capacity = new_capacity;
    }

    tidesdb_sstable_ref(sst);
    level->sstables[num] = sst;
    atomic_store(&level->num_sstables, num + 1);

    size_t current = atomic_load(&level->current_size);
    atomic_store(&level->current_size, current + sst->klog_size + sst->vlog_size);

    pthread_mutex_unlock(&level->level_lock);
    return TDB_SUCCESS;
}

/**
 * tidesdb_level_remove_sstable
 * remove an sstable from a level
 * @param level level to remove sstable from
 * @param sst sstable to remove
 * @return 0 on success, non-zero on failure
 */
static int tidesdb_level_remove_sstable(tidesdb_level_t *level, tidesdb_sstable_t *sst)
{
    pthread_mutex_lock(&level->level_lock);

    int num = atomic_load(&level->num_sstables);

    for (int i = 0; i < num; i++)
    {
        if (level->sstables[i] == sst)
        {
            size_t current = atomic_load(&level->current_size);
            atomic_store(&level->current_size, current - (sst->klog_size + sst->vlog_size));

            memmove(&level->sstables[i], &level->sstables[i + 1],
                    (num - i - 1) * sizeof(tidesdb_sstable_t *));
            atomic_store(&level->num_sstables, num - 1);

            tidesdb_sstable_unref(sst);
            pthread_mutex_unlock(&level->level_lock);
            return TDB_SUCCESS;
        }
    }

    pthread_mutex_unlock(&level->level_lock);
    return TDB_ERR_NOT_FOUND;
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
    /* if they're the same level, only lock once */
    int same_level = (level == largest_level);

    pthread_mutex_lock(&level->level_lock);
    if (!same_level)
    {
        pthread_mutex_lock(&largest_level->level_lock);
    }

    for (int i = 0; i < level->num_boundaries; i++)
    {
        free(level->file_boundaries[i]);
    }
    free(level->file_boundaries);
    free(level->boundary_sizes);

    int num_ssts = atomic_load(&largest_level->num_sstables);
    level->num_boundaries = num_ssts;

    if (num_ssts > 0)
    {
        level->file_boundaries = malloc(num_ssts * sizeof(uint8_t *));
        level->boundary_sizes = malloc(num_ssts * sizeof(size_t));

        if (!level->file_boundaries || !level->boundary_sizes)
        {
            if (!same_level) pthread_mutex_unlock(&largest_level->level_lock);
            pthread_mutex_unlock(&level->level_lock);
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            tidesdb_sstable_t *sst = largest_level->sstables[i];
            level->boundary_sizes[i] = sst->min_key_size;
            level->file_boundaries[i] = malloc(sst->min_key_size);
            if (!level->file_boundaries[i])
            {
                if (!same_level) pthread_mutex_unlock(&largest_level->level_lock);
                pthread_mutex_unlock(&level->level_lock);
                return TDB_ERR_MEMORY;
            }
            memcpy(level->file_boundaries[i], sst->min_key, sst->min_key_size);
        }
    }

    if (!same_level) pthread_mutex_unlock(&largest_level->level_lock);
    pthread_mutex_unlock(&level->level_lock);
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
 * @return merge source
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_memtable(
    skip_list_t *memtable, tidesdb_column_family_config_t *config)
{
    tidesdb_merge_source_t *source = calloc(1, sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_MEMTABLE;
    source->config = config;

    if (skip_list_cursor_init(&source->source.memtable.cursor, memtable) != 0)
    {
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

        if (skip_list_cursor_get(source->source.memtable.cursor, &key, &key_size, &value,
                                 &value_size, &ttl, &deleted) == 0)
        {
            source->current_kv =
                tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, 0, deleted);
        }
    }

    return source;
}

/**
 * tidesdb_merge_source_from_sstable
 * create a merge source from an sstable
 * @param db database instance
 * @param sst sstable to create merge source from
 * @return merge source
 */
static tidesdb_merge_source_t *tidesdb_merge_source_from_sstable(tidesdb_t *db,
                                                                 tidesdb_sstable_t *sst)
{
    tidesdb_merge_source_t *source = calloc(1, sizeof(tidesdb_merge_source_t));
    if (!source) return NULL;

    source->type = MERGE_SOURCE_SSTABLE;
    source->source.sstable.sst = sst;
    source->source.sstable.current_block_num = 0; /* start at first block */
    source->config = sst->config;

    /* ensure SSTable is open through cache */
    if (tidesdb_sstable_ensure_open(db, sst) != 0)
    {
        free(source);
        return NULL;
    }

    tidesdb_sstable_ref(sst);

    if (block_manager_cursor_init(&source->source.sstable.klog_cursor, sst->klog_bm) != 0)
    {
        tidesdb_sstable_unref(sst);
        free(source);
        return NULL;
    }

    if (block_manager_cursor_goto_first(source->source.sstable.klog_cursor) == 0)
    {
        /* read first block and first entry */
        block_manager_block_t *block =
            block_manager_cursor_read(source->source.sstable.klog_cursor);
        if (block)
        {
            uint8_t *data = block->data;
            size_t data_size = block->size;
            uint8_t *decompressed = NULL;

            if (block->size >= 8 && sst->config->compression_algorithm != NO_COMPRESSION)
            {
                uint64_t header_value = 0;
                memcpy(&header_value, block->data, sizeof(uint64_t));
            }

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
                        tidesdb_vlog_read_value(sst, kb->entries[0].vlog_offset,
                                                kb->entries[0].value_size, &vlog_value);
                        value = vlog_value;
                    }

                    source->current_kv = tidesdb_kv_pair_create(
                        kb->keys[0], kb->entries[0].key_size, value, kb->entries[0].value_size,
                        kb->entries[0].ttl, kb->entries[0].seq,
                        kb->entries[0].flags & TDB_KV_FLAG_TOMBSTONE);

                    free(vlog_value);
                }
            }

            free(decompressed);
            block_manager_block_release(block);
        }
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
    }
    else
    {
        if (source->source.sstable.current_block)
        {
            tidesdb_klog_block_free(source->source.sstable.current_block);
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

            if (skip_list_cursor_get(source->source.memtable.cursor, &key, &key_size, &value,
                                     &value_size, &ttl, &deleted) == 0)
            {
                source->current_kv =
                    tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, 0, deleted);
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
                tidesdb_vlog_read_value(source->source.sstable.sst, kb->entries[idx].vlog_offset,
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
            /* check if we've exhausted all klog blocks */
            source->source.sstable.current_block_num++;
            if (source->source.sstable.current_block_num >=
                source->source.sstable.sst->num_klog_blocks)
            {
                /* no more klog blocks */
                return TDB_ERR_NOT_FOUND;
            }

            /* move to next block */
            if (block_manager_cursor_next(source->source.sstable.klog_cursor) == 0)
            {
                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
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
                                    source->source.sstable.sst, current_kb->entries[0].vlog_offset,
                                    current_kb->entries[0].value_size, &vlog_value);
                                value = vlog_value;
                            }

                            source->current_kv = tidesdb_kv_pair_create(
                                current_kb->keys[0], current_kb->entries[0].key_size, value,
                                current_kb->entries[0].value_size, current_kb->entries[0].ttl,
                                current_kb->entries[0].seq,
                                (current_kb->entries[0].flags & TDB_KV_FLAG_TOMBSTONE) != 0);

                            free(vlog_value);
                            free(decompressed);
                            block_manager_block_release(block);
                            return TDB_SUCCESS;
                        }
                    }

                    free(decompressed);
                    block_manager_block_release(block);
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

            if (skip_list_cursor_get(source->source.memtable.cursor, &key, &key_size, &value,
                                     &value_size, &ttl, &deleted) == 0)
            {
                source->current_kv =
                    tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, 0, deleted);
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
                tidesdb_vlog_read_value(source->source.sstable.sst, kb->entries[idx].vlog_offset,
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
            /* move to previous block */
            if (block_manager_cursor_prev(source->source.sstable.klog_cursor) == 0)
            {
                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
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
                                tidesdb_vlog_read_value(source->source.sstable.sst,
                                                        current_kb->entries[idx].vlog_offset,
                                                        current_kb->entries[idx].value_size,
                                                        &vlog_value);
                                value = vlog_value;
                            }

                            source->current_kv = tidesdb_kv_pair_create(
                                current_kb->keys[idx], current_kb->entries[idx].key_size, value,
                                current_kb->entries[idx].value_size, current_kb->entries[idx].ttl,
                                current_kb->entries[idx].seq,
                                (current_kb->entries[idx].flags & TDB_KV_FLAG_TOMBSTONE) != 0);

                            free(vlog_value);
                            free(decompressed);
                            block_manager_block_release(block);
                            return TDB_SUCCESS;
                        }
                    }

                    free(decompressed);
                    block_manager_block_release(block);
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
 * tidesdb_should_add_level
 * determine if a new level should be added based on the current level count and max levels
 * @param cf the column family
 * @return 1 if a new level should be added, 0 otherwise
 */
static int tidesdb_should_add_level(tidesdb_column_family_t *cf)
{
    int num_levels = atomic_load(&cf->num_levels);
    if (num_levels == 0) return 0;
    if (num_levels >= cf->config.max_levels) return 0;

    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t current_size = atomic_load(&largest->current_size);

    return current_size >= largest->capacity;
}

/**
 * tidesdb_should_remove_level
 * determine if a level should be removed based on the current level count and max levels
 * @param cf the column family
 * @return 1 if a level should be removed, 0 otherwise
 */
static int tidesdb_should_remove_level(tidesdb_column_family_t *cf)
{
    int num_levels = atomic_load(&cf->num_levels);
    if (num_levels <= 2) return 0;

    tidesdb_level_t *largest = cf->levels[num_levels - 1];
    size_t current_size = atomic_load(&largest->current_size);

    /* remove level if data size < capacity/T */
    return current_size < (largest->capacity / cf->config.level_size_ratio);
}

/**
 * tidesdb_add_level
 * add a new level to the column family
 * @param cf the column family
 * @return TDB_SUCCESS on success, TDB_ERR_MEMORY on failure
 */
static int tidesdb_add_level(tidesdb_column_family_t *cf)
{
    int num_levels = atomic_load(&cf->num_levels);

    size_t new_capacity = tidesdb_calculate_level_capacity(
        num_levels + 1, cf->config.write_buffer_size, cf->config.level_size_ratio);

    tidesdb_level_t *new_level = tidesdb_level_create(num_levels + 1, new_capacity);
    if (!new_level) return TDB_ERR_MEMORY;

    tidesdb_level_t **new_levels =
        realloc(cf->levels, (num_levels + 1) * sizeof(tidesdb_level_t *));
    if (!new_levels)
    {
        tidesdb_level_free(new_level);
        return TDB_ERR_MEMORY;
    }

    cf->levels = new_levels;
    cf->levels[num_levels] = new_level;
    atomic_store(&cf->num_levels, num_levels + 1);

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
    int num_levels = atomic_load(&cf->num_levels);
    if (num_levels <= 1) return TDB_ERR_INVALID_ARGS;

    tidesdb_level_free(cf->levels[num_levels - 1]);
    atomic_store(&cf->num_levels, num_levels - 1);

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

    /* get data size at largest level */
    tidesdb_level_t *largest = cf->levels[num_levels - 1];
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

        if (divisor > 0)
        {
            cf->levels[i]->capacity = N_L / divisor;
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
    if (start_level < 0 || target_level >= atomic_load(&cf->num_levels))
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
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        pthread_mutex_lock(&lvl->level_lock);

        int num = atomic_load(&lvl->num_sstables);
        for (int i = 0; i < num; i++)
        {
            tidesdb_sstable_t *sst = lvl->sstables[i];
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

        pthread_mutex_unlock(&lvl->level_lock);
    }

    /* create new sst for merged output */
    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char path[MAX_FILE_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d", cf->directory,
             target_level);

    tidesdb_sstable_t *new_sst = tidesdb_sstable_create(path, new_id, &cf->config);
    if (!new_sst)
    {
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_MEMORY;
    }

    /* open block managers for writing */
    if (block_manager_open_with_cache(&new_sst->klog_bm, new_sst->klog_path,
                                      convert_sync_mode(cf->config.sync_mode),
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
    {
        tidesdb_sstable_unref(new_sst);
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_IO;
    }

    if (block_manager_open_with_cache(&new_sst->vlog_bm, new_sst->vlog_path,
                                      convert_sync_mode(cf->config.sync_mode),
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
    {
        block_manager_close(new_sst->klog_bm);
        tidesdb_sstable_unref(new_sst);
        tidesdb_merge_heap_free(heap);
        queue_free_with_data(sstables_to_delete, (void (*)(void *))tidesdb_sstable_unref);
        return TDB_ERR_IO;
    }

    /* calc expected number of entries for bloom filter sizing
     * curing merge, duplicates are eliminated and tombstones may be removed,
     * so the actual count will be lower. we use the sum as an upper bound to ensure
     * the bloom filter is adequately sized. */
    uint64_t estimated_entries = 0;
    for (int level = start_level; level <= target_level; level++)
    {
        tidesdb_level_t *lvl = cf->levels[level];
        pthread_mutex_lock(&lvl->level_lock);
        int num = atomic_load(&lvl->num_sstables);
        for (int i = 0; i < num; i++)
        {
            tidesdb_sstable_t *sst = lvl->sstables[i];
            estimated_entries += sst->num_entries;
        }
        pthread_mutex_unlock(&lvl->level_lock);
    }

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

        /* handle large values  */
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
                        block_manager_block_write(new_sst->vlog_bm, vlog_block);
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
                    block_manager_block_write(new_sst->klog_bm, klog_block);
                    block_manager_block_free(klog_block);
                    klog_block_num++;
                }
                free(final_data);
            }

            tidesdb_klog_block_free(current_klog_block);
            current_klog_block = tidesdb_klog_block_create();
        }

        tidesdb_klog_block_add_entry(current_klog_block, kv, &cf->config);

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
                block_manager_block_write(new_sst->klog_bm, klog_block);
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
                block_manager_block_write(new_sst->vlog_bm, vlog_block);
                block_manager_block_free(vlog_block);
                vlog_block_num++;
            }
            free(vlog_data);
        }
    }

    tidesdb_klog_block_free(current_klog_block);
    tidesdb_vlog_block_free(current_vlog_block);

    new_sst->num_klog_blocks = klog_block_num;
    new_sst->num_vlog_blocks = vlog_block_num;

    /* wrute index */
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
                    block_manager_block_write(new_sst->klog_bm, index_block);
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
                block_manager_block_write(new_sst->klog_bm, bloom_block);
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }
        new_sst->bloom_filter = bloom;
    }

    block_manager_get_size(new_sst->klog_bm, &new_sst->klog_size);
    block_manager_get_size(new_sst->vlog_bm, &new_sst->vlog_size);

    tidesdb_merge_heap_free(heap);

    tidesdb_level_add_sstable(cf->levels[target_level], new_sst);

    tidesdb_sstable_unref(new_sst);

    while (!queue_is_empty(sstables_to_delete))
    {
        tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
        if (!sst) continue;

        /* find which level this sst belongs to */
        for (int level = start_level; level <= target_level; level++)
        {
            tidesdb_level_t *lvl = cf->levels[level];

            tidesdb_level_remove_sstable(lvl, sst);
        }

        unlink(sst->klog_path);
        unlink(sst->vlog_path);

        tidesdb_sstable_unref(sst);
    }

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
    int num_levels = atomic_load(&cf->num_levels);
    if (target_level >= num_levels || target_level < 1)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Starting dividing merge: CF '%s', target_level=%d", cf->name, target_level);

    /* update file boundaries from largest level */
    tidesdb_level_t *largest = cf->levels[num_levels - 1];

    tidesdb_level_update_boundaries(cf->levels[target_level], largest);

    tidesdb_merge_heap_t *heap =
        tidesdb_merge_heap_create(cf->config.comparator, cf->config.comparator_ctx);
    if (!heap)
    {
        return TDB_ERR_MEMORY;
    }

    /* add sources from levels 0 to target_level */
    queue_t *sstables_to_delete = queue_new();

    for (int level = 0; level < target_level; level++)
    {
        if (level == 0)
        {
            /* add memtable as source */
            pthread_mutex_lock(&cf->flush_lock);
            tidesdb_merge_source_t *source =
                tidesdb_merge_source_from_memtable(cf->active_memtable, &cf->config);
            if (source)
            {
                /* only add source if it has valid data */
                if (source->current_kv)
                {
                    tidesdb_merge_heap_add_source(heap, source);
                }
                else
                {
                    /* empty memtable, free the source */
                    tidesdb_merge_source_free(source);
                }
            }
            pthread_mutex_unlock(&cf->flush_lock);
        }
        else
        {
            tidesdb_level_t *lvl = cf->levels[level];
            pthread_mutex_lock(&lvl->level_lock);

            int num = atomic_load(&lvl->num_sstables);
            for (int i = 0; i < num; i++)
            {
                tidesdb_sstable_t *sst = lvl->sstables[i];
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

            pthread_mutex_unlock(&lvl->level_lock);
        }
    }

    /* get partition boundaries from target level */
    tidesdb_level_t *target = cf->levels[target_level];

    /* if no boundaries, do a simple full merge */
    if (target->num_boundaries == 0)
    {
        int result = tidesdb_full_preemptive_merge(cf, 0, target_level);
        tidesdb_merge_heap_free(heap);

        /* delete old ssts */
        while (!queue_is_empty(sstables_to_delete))
        {
            tidesdb_sstable_t *sst = queue_dequeue(sstables_to_delete);
            if (sst) tidesdb_sstable_unref(sst);
        }
        queue_free(sstables_to_delete);

        return result;
    }

    /* partitioned merge: create one SSTable per partition */
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

        if (block_manager_open_with_cache(&new_sst->klog_bm, new_sst->klog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size) != 0)
        {
            tidesdb_sstable_unref(new_sst);
            continue;
        }

        if (block_manager_open_with_cache(&new_sst->vlog_bm, new_sst->vlog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size) != 0)
        {
            block_manager_close(new_sst->klog_bm);
            tidesdb_sstable_unref(new_sst);
            continue;
        }

        /* merge keys in this partition's range */
        tidesdb_klog_block_t *klog_block = tidesdb_klog_block_create();
        tidesdb_vlog_block_t *vlog_block = tidesdb_vlog_block_create();

        uint64_t entry_count = 0;
        uint8_t *first_key = NULL;
        size_t first_key_size = 0;
        uint8_t *last_key = NULL;
        size_t last_key_size = 0;

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
                            block_manager_block_write(new_sst->vlog_bm, vblock);
                            block_manager_block_free(vblock);
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
                        block_manager_block_write(new_sst->klog_bm, kblock);
                        block_manager_block_free(kblock);
                    }
                    free(klog_data);
                }

                tidesdb_klog_block_free(klog_block);
                klog_block = tidesdb_klog_block_create();
            }
            tidesdb_klog_block_add_entry(klog_block, kv, &cf->config);
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
                    block_manager_block_write(new_sst->vlog_bm, vblock);
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
                    block_manager_block_write(new_sst->klog_bm, block);
                    block_manager_block_free(block);
                }
                free(klog_data);
            }
        }

        tidesdb_klog_block_free(klog_block);
        tidesdb_vlog_block_free(vlog_block);

        new_sst->num_entries = entry_count;
        new_sst->min_key = first_key;
        new_sst->min_key_size = first_key_size;
        new_sst->max_key = last_key;
        new_sst->max_key_size = last_key_size;

        /* get sizes before closing */
        block_manager_get_size(new_sst->klog_bm, &new_sst->klog_size);
        block_manager_get_size(new_sst->vlog_bm, &new_sst->vlog_size);

        /* close block managers after writing */
        block_manager_close(new_sst->klog_bm);
        block_manager_close(new_sst->vlog_bm);
        new_sst->klog_bm = NULL;
        new_sst->vlog_bm = NULL;

        /* add to target level */
        if (entry_count > 0)
        {
            tidesdb_level_add_sstable(target, new_sst);
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
            /* remove from level and unref */
            for (int level = 0; level < target_level; level++)
            {
                tidesdb_level_remove_sstable(cf->levels[level], sst);
            }
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
    int num_levels = atomic_load(&cf->num_levels);
    if (start_level >= num_levels || end_level >= num_levels)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    TDB_DEBUG_LOG("Starting partitioned merge: CF '%s', levels %d->%d", cf->name, start_level,
                  end_level);

    tidesdb_level_t *largest = cf->levels[num_levels - 1];

    /* get file boundaries */
    pthread_mutex_lock(&largest->level_lock);
    int num_partitions = atomic_load(&largest->num_sstables);

    uint8_t **boundaries = malloc(num_partitions * sizeof(uint8_t *));
    size_t *boundary_sizes = malloc(num_partitions * sizeof(size_t));

    for (int i = 0; i < num_partitions; i++)
    {
        boundaries[i] = malloc(largest->sstables[i]->min_key_size);
        boundary_sizes[i] = largest->sstables[i]->min_key_size;
        memcpy(boundaries[i], largest->sstables[i]->min_key, boundary_sizes[i]);
    }
    pthread_mutex_unlock(&largest->level_lock);

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
        for (int level = start_level; level <= end_level; level++)
        {
            tidesdb_level_t *lvl = cf->levels[level];
            pthread_mutex_lock(&lvl->level_lock);

            int num = atomic_load(&lvl->num_sstables);
            for (int i = 0; i < num; i++)
            {
                tidesdb_sstable_t *sst = lvl->sstables[i];

                /* check if sst overlaps with partition range */
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

            pthread_mutex_unlock(&lvl->level_lock);
        }

        /* use a minimum of 100 entries to avoid degenerate bloom filters */
        if (estimated_entries < 100) estimated_entries = 100;

        /* create output sst for this partition */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char path[MAX_FILE_PATH_LENGTH];
        snprintf(path, sizeof(path),
                 "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "%d" TDB_LEVEL_PARTITION_PREFIX "%d",
                 cf->directory, end_level, partition);

        tidesdb_sstable_t *new_sst = tidesdb_sstable_create(path, new_id, &cf->config);
        if (new_sst)
        {
            block_manager_open_with_cache(&new_sst->klog_bm, new_sst->klog_path,
                                          convert_sync_mode(cf->config.sync_mode),
                                          (uint32_t)cf->config.block_manager_cache_size);
            block_manager_open_with_cache(&new_sst->vlog_bm, new_sst->vlog_path,
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
                                block_manager_block_write(new_sst->vlog_bm, vblock);
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

                /* add to bloom filter */
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
                            int64_t offset = block_manager_block_write(new_sst->klog_bm, block);
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
                        block_manager_block_write(new_sst->vlog_bm, vblock);
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
                        block_manager_block_write(new_sst->klog_bm, block);
                        block_manager_block_free(block);
                        klog_block_num++;
                    }
                    free(final_data);
                }
            }

            tidesdb_klog_block_free(klog_block);

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
                            block_manager_block_write(new_sst->klog_bm, index_block);
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
                    block_manager_block_t *bloom_block =
                        block_manager_block_create(bloom_size, bloom_data);
                    if (bloom_block)
                    {
                        block_manager_block_write(new_sst->klog_bm, bloom_block);
                        block_manager_block_free(bloom_block);
                    }
                    free(bloom_data);
                }
                new_sst->bloom_filter = bloom;
            }

            /* set sst metadata */
            new_sst->num_entries = entry_count;
            new_sst->num_klog_blocks = klog_block_num;
            new_sst->num_vlog_blocks = vlog_block_num;
            new_sst->min_key = first_key;
            new_sst->min_key_size = first_key_size;
            new_sst->max_key = last_key;
            new_sst->max_key_size = last_key_size;

            block_manager_get_size(new_sst->klog_bm, &new_sst->klog_size);
            block_manager_get_size(new_sst->vlog_bm, &new_sst->vlog_size);

            block_manager_close(new_sst->klog_bm);
            block_manager_close(new_sst->vlog_bm);
            new_sst->klog_bm = NULL;
            new_sst->vlog_bm = NULL;

            /* add to level if not empty */
            if (entry_count > 0)
            {
                tidesdb_level_add_sstable(cf->levels[end_level], new_sst);
                tidesdb_sstable_unref(new_sst);
            }
            else
            {
                tidesdb_sstable_unref(new_sst);
            }
        }

        tidesdb_merge_heap_free(heap);
    }

    /* cleanup boundaries */
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

    /* check if we need to add a level (even with just 1 level) */
    if (tidesdb_should_add_level(cf))
    {
        TDB_DEBUG_LOG("Adding new level for CF '%s' (current levels: %d)", cf->name, num_levels);
        tidesdb_add_level(cf);
        num_levels = atomic_load(&cf->num_levels);
    }

    if (num_levels < 2)
    {
        TDB_DEBUG_LOG("Compaction skipped for CF '%s': only %d level(s), need >= 2", cf->name,
                      num_levels);
        return TDB_SUCCESS;
    }

    TDB_DEBUG_LOG("Triggering compaction for column family: %s (levels: %d)", cf->name, num_levels);

    /* calculate X (dividing level) */
    int X = num_levels - 1 - cf->config.dividing_level_offset;
    if (X < 1) X = 1;

    /* find smallest level q where we can merge without overflow */
    size_t cumulative_size = skip_list_get_size(cf->active_memtable);
    int target_lvl = X;

    for (int q = 1; q <= X && q < num_levels; q++)
    {
        size_t level_sizes = 0;
        for (int i = 1; i < q; i++)
        {
            level_sizes += atomic_load(&cf->levels[i]->current_size);
        }

        if (cf->levels[q]->capacity >= cumulative_size + level_sizes)
        {
            target_lvl = q;
            break;
        }
    }

    if (tidesdb_should_add_level(cf))
    {
        tidesdb_add_level(cf);
    }
    else if (tidesdb_should_remove_level(cf))
    {
        tidesdb_remove_level(cf);
    }

    /* apply DCA */
    tidesdb_apply_dca(cf);

    /* decide compaction strategy based on target level */
    if (target_lvl < X)
    {
        /* full preemptive merge to target_lvl */
        return tidesdb_full_preemptive_merge(cf, 0, target_lvl);
    }
    else if (target_lvl == X)
    {
        /* dividing merge at X */
        return tidesdb_dividing_merge(cf, X);
    }
    else
    {
        /* partitioned merge from X to L */
        return tidesdb_partitioned_merge(cf, X, num_levels - 1);
    }
}

/**
 * tidesdb_wal_append
 * append a key-value pair to the WAL
 * @param wal the WAL
 * @param kv the key-value pair
 * @return TDB_SUCCESS on success, TDB_ERR_INVALID_ARGS on failure
 */
UNUSED static int tidesdb_wal_append(block_manager_t *wal, const tidesdb_kv_pair_t *kv)
{
    if (!wal || !kv) return TDB_ERR_INVALID_ARGS;

    /* serialize KV pair for WAL */
    size_t entry_size = sizeof(tidesdb_klog_entry_t) + kv->entry.key_size;
    if (kv->entry.value_size > 0)
    {
        entry_size += kv->entry.value_size;
    }

    uint8_t *data = malloc(entry_size);
    if (!data) return TDB_ERR_MEMORY;

    uint8_t *ptr = data;

    /* write entry header */
    memcpy(ptr, &kv->entry, sizeof(tidesdb_klog_entry_t));
    ptr += sizeof(tidesdb_klog_entry_t);

    /* write key */
    memcpy(ptr, kv->key, kv->entry.key_size);
    ptr += kv->entry.key_size;

    /* write value if present */
    if (kv->entry.value_size > 0 && kv->value)
    {
        memcpy(ptr, kv->value, kv->entry.value_size);
        ptr += kv->entry.value_size;
    }

    /* create block and write */
    block_manager_block_t *block = block_manager_block_create(entry_size, data);
    if (!block)
    {
        free(data);
        return TDB_ERR_MEMORY;
    }

    int result = block_manager_block_write(wal, block);

    block_manager_block_free(block);
    free(data);

    return result == 0 ? TDB_SUCCESS : TDB_ERR_IO;
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
    /* open WAL file */
    block_manager_t *wal;
    if (block_manager_open_with_cache(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE,
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
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

            if (remaining < sizeof(tidesdb_klog_entry_t))
            {
                block_manager_block_release(block);
                continue;
            }

            /* parse entry */
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

            /* put in memtable */
            if (entry.flags & TDB_KV_FLAG_TOMBSTONE)
            {
                skip_list_delete(*memtable, key, entry.key_size);
            }
            else
            {
                skip_list_put(*memtable, key, entry.key_size, value, entry.value_size, entry.ttl);
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
        /* sleep for compaction interval */
        usleep(cf->config.compaction_interval_ms * 1000);

        if (atomic_load(&cf->compaction_should_stop)) break;

        /* check if compaction is needed */
        int num_levels = atomic_load(&cf->num_levels);
        int needs_compaction = 0;
        int needs_flush = 0;

        /* check memtable size -- take snapshot while holding flush_lock */
        pthread_mutex_lock(&cf->flush_lock);
        size_t memtable_size = (size_t)skip_list_get_size(cf->active_memtable);
        pthread_mutex_unlock(&cf->flush_lock);

        if (memtable_size >= cf->config.write_buffer_size)
        {
            needs_flush = 1;
            needs_compaction = 1;
        }

        /* check level sizes */
        for (int i = 0; i < num_levels; i++)
        {
            size_t current = atomic_load(&cf->levels[i]->current_size);
            if (current >= cf->levels[i]->capacity)
            {
                needs_compaction = 1;
                break;
            }
        }

        if (needs_compaction)
        {
            /* flush memtable first if needed */
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
                    /* queue full or error free work and skip this cycle */
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

    /* background compaction thread should already be stopped and joined by caller
     * (see tidesdb_close), but set flag defensively */
    if (cf->config.enable_background_compaction)
    {
        atomic_store(&cf->compaction_should_stop, 1);
    }

    skip_list_free(cf->active_memtable);
    block_manager_close(cf->active_wal);

    while (!queue_is_empty(cf->immutable_memtables))
    {
        tidesdb_immutable_memtable_t *immutable =
            (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);
        if (immutable)
        {
            skip_list_free(immutable->memtable);
            if (immutable->wal)
            {
                block_manager_close(immutable->wal);
            }
            free(immutable);
        }
    }
    queue_free(cf->immutable_memtables);

    int num = atomic_load(&cf->num_levels);
    for (int i = 0; i < num; i++)
    {
        tidesdb_level_free(cf->levels[i]);
    }
    free(cf->levels);

    pthread_mutex_destroy(&cf->flush_lock);
    pthread_mutex_destroy(&cf->compaction_lock);
    pthread_rwlock_destroy(&cf->cf_lock);

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

    while (!atomic_load(&db->flush_should_stop))
    {
        /* wait for work (blocking dequeue) */
        tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue_wait(db->flush_queue);

        if (!work)
        {
            /* NULL work item means shutdown */
            break;
        }

        /* check shutdown after getting work -- if stopping, clean up and exit */
        if (atomic_load(&db->flush_should_stop))
        {
            /* dequeue corresponding immutable entry to prevent double-free */
            tidesdb_immutable_memtable_t *to_free =
                (tidesdb_immutable_memtable_t *)queue_dequeue(work->cf->immutable_memtables);
            if (to_free)
            {
                free(to_free);
            }

            /* clean up work item before exiting */
            skip_list_free(work->memtable);
            if (work->wal)
            {
                char *wal_path_to_delete = tdb_strdup(work->wal->file_path);
                block_manager_close(work->wal);
                unlink(wal_path_to_delete);
                free(wal_path_to_delete);
            }
            free(work);
            break;
        }

        tidesdb_column_family_t *cf = work->cf;

        skip_list_t *memtable = work->memtable;
        block_manager_t *wal = work->wal;

        char sst_path[MAX_FILE_PATH_LENGTH];
        snprintf(sst_path, sizeof(sst_path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "1",
                 cf->directory);

        tidesdb_sstable_t *sst = tidesdb_sstable_create(sst_path, work->sst_id, &cf->config);
        if (sst)
        {
            int write_result = tidesdb_sstable_write_from_memtable(sst, memtable);
            if (write_result == TDB_SUCCESS)
            {
                /* add to level 1 atomically, this increments ref count */
                tidesdb_level_add_sstable(cf->levels[0], sst);
                TDB_DEBUG_LOG("CF '%s': Flushed SSTable %" PRIu64 " to level 0", cf->name,
                              work->sst_id);
                /* release our reference the level now owns it */
                tidesdb_sstable_unref(sst);
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

        tidesdb_immutable_memtable_t *to_free =
            (tidesdb_immutable_memtable_t *)queue_dequeue(cf->immutable_memtables);

        skip_list_free(memtable);
        if (wal)
        {
            char *wal_path_to_delete = tdb_strdup(wal->file_path);
            block_manager_close(wal);
            unlink(wal_path_to_delete);
            free(wal_path_to_delete);
        }

        if (to_free)
        {
            free(to_free);
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
 * the compaction_lock ensures only one compaction per CF at a time,
 * but multiple workers can compact different CFs concurrently.
 */
static void *tidesdb_compaction_worker_thread(void *arg)
{
    tidesdb_t *db = (tidesdb_t *)arg;

    while (!atomic_load(&db->compaction_should_stop))
    {
        /* wait for work (blocking dequeue) */
        tidesdb_compaction_work_t *work =
            (tidesdb_compaction_work_t *)queue_dequeue_wait(db->compaction_queue);

        if (!work || atomic_load(&db->compaction_should_stop))
        {
            /* NULL work item or shutdown signal */
            break;
        }

        tidesdb_column_family_t *cf = work->cf;

        /* try to acquire compaction lock, skip if already compacting */
        if (pthread_mutex_trylock(&cf->compaction_lock) == 0)
        {
            /* perform compaction */
            TDB_DEBUG_LOG("Compacting CF '%s'", cf->name);
            tidesdb_trigger_compaction(cf);
            pthread_mutex_unlock(&cf->compaction_lock);
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
    (*db)->column_families = calloc((*db)->cf_capacity, sizeof(tidesdb_column_family_t *));
    if (!(*db)->column_families)
    {
        free((*db)->db_path);
        free(*db);
        return TDB_ERR_MEMORY;
    }

    pthread_rwlock_init(&(*db)->cf_list_lock, NULL);

    /* init thread pools */
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

    /* init sst cache */
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

    /* start flush worker threads */
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
            /* cleanup already started threads */
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

    /* start compaction worker threads */
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
            /* cleanup already started threads */
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

    /* first, stop accepting new work */
    atomic_store(&db->flush_should_stop, 1);
    atomic_store(&db->compaction_should_stop, 1);

    /* wait for all pending work to drain */
    if (db->flush_queue)
    {
        while (queue_size(db->flush_queue) > 0)
        {
            usleep(10000);
        }
    }

    if (db->compaction_queue)
    {
        while (queue_size(db->compaction_queue) > 0)
        {
            usleep(10000);
        }
    }

    if (db->flush_queue)
    {
        for (int i = 0; i < db->config.num_flush_threads; i++)
        {
            queue_enqueue(db->flush_queue, NULL);
        }
    }

    if (db->compaction_queue)
    {
        for (int i = 0; i < db->config.num_compaction_threads; i++)
        {
            queue_enqueue(db->compaction_queue, NULL);
        }
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

    /* drain and free any remaining work items before freeing queues */
    if (db->flush_queue)
    {
        while (!queue_is_empty(db->flush_queue))
        {
            tidesdb_flush_work_t *work = (tidesdb_flush_work_t *)queue_dequeue(db->flush_queue);
            if (work) free(work);
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

    /* clear cache before freeing column families to avoid use-after-free */
    fifo_cache_clear(db->sstable_cache);

    /* stop all background compaction threads BEFORE acquiring cf_list_lock
     * to avoid deadlock (threads might need cf_list_lock) */
    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (cf && cf->config.enable_background_compaction)
        {
            atomic_store(&cf->compaction_should_stop, 1);
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    /* now join all compaction threads without holding any locks */
    pthread_rwlock_rdlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (cf && cf->config.enable_background_compaction)
        {
            pthread_join(cf->compaction_thread, NULL);
        }
    }
    pthread_rwlock_unlock(&db->cf_list_lock);

    /* now safe to free column families */
    pthread_rwlock_wrlock(&db->cf_list_lock);
    for (int i = 0; i < db->num_column_families; i++)
    {
        tidesdb_column_family_free(db->column_families[i]);
    }
    free(db->column_families);
    pthread_rwlock_unlock(&db->cf_list_lock);

    /* use destroy instead of free to avoid calling eviction callbacks twice
     * (we already called fifo_cache_clear above) */
    fifo_cache_destroy(db->sstable_cache);

    pthread_rwlock_destroy(&db->cf_list_lock);

    free(db->db_path);
    db->is_open = 0;
    free(db);

    return TDB_SUCCESS;
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name || !config) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Creating column family: %s", name);

    pthread_rwlock_wrlock(&db->cf_list_lock);

    /* check if column family already exists */
    for (int i = 0; i < db->num_column_families; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            TDB_DEBUG_LOG("Column family already exists: %s", name);
            pthread_rwlock_unlock(&db->cf_list_lock);
            return TDB_ERR_EXISTS;
        }
    }

    /* expand array if needed */
    if (db->num_column_families >= db->cf_capacity)
    {
        int new_capacity = db->cf_capacity * 2;
        tidesdb_column_family_t **new_array =
            realloc(db->column_families, new_capacity * sizeof(tidesdb_column_family_t *));
        if (!new_array)
        {
            pthread_rwlock_unlock(&db->cf_list_lock);
            return TDB_ERR_MEMORY;
        }
        db->column_families = new_array;
        db->cf_capacity = new_capacity;
    }

    tidesdb_column_family_t *cf = calloc(1, sizeof(tidesdb_column_family_t));
    if (!cf)
    {
        TDB_DEBUG_LOG("Failed to allocate memory for column family structure");
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    cf->name = tdb_strdup(name);
    if (!cf->name)
    {
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
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
            pthread_rwlock_unlock(&db->cf_list_lock);
            return TDB_ERR_IO;
        }
    }

    cf->directory = tdb_strdup(dir_path);
    if (!cf->directory)
    {
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    cf->config = *config;
    cf->db = db;

    if (pthread_mutex_init(&cf->flush_lock, NULL) != 0 ||
        pthread_mutex_init(&cf->compaction_lock, NULL) != 0 ||
        pthread_rwlock_init(&cf->cf_lock, NULL) != 0)
    {
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_LOCK;
    }

    /* initialize memtable */
    if (skip_list_new_with_comparator(&cf->active_memtable, config->skip_list_max_level,
                                      config->skip_list_probability, config->comparator,
                                      config->comparator_ctx) != 0)
    {
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    /* initialize immutable memtables queue */
    cf->immutable_memtables = queue_new();
    if (!cf->immutable_memtables)
    {
        skip_list_free(cf->active_memtable);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    /* initialize WAL */
    char wal_path[TDB_MAX_PATH_LEN];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(time(NULL)));
    if (block_manager_open_with_cache(&cf->active_wal, wal_path, BLOCK_MANAGER_SYNC_NONE,
                                      (uint32_t)config->block_manager_cache_size) != 0)
    {
        queue_free(cf->immutable_memtables);
        skip_list_free(cf->active_memtable);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_IO;
    }

    /* initialize levels */
    atomic_init(&cf->num_levels, 1);
    size_t base_capacity = config->write_buffer_size * config->level_size_ratio;
    cf->levels = malloc(config->max_levels * sizeof(tidesdb_level_t *));
    if (!cf->levels)
    {
        block_manager_close(cf->active_wal);
        queue_free(cf->immutable_memtables);
        skip_list_free(cf->active_memtable);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    cf->levels[0] = tidesdb_level_create(1, base_capacity);
    if (!cf->levels[0])
    {
        free(cf->levels);
        block_manager_close(cf->active_wal);
        queue_free(cf->immutable_memtables);
        skip_list_free(cf->active_memtable);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf->directory);
        free(cf->name);
        free(cf);
        pthread_rwlock_unlock(&db->cf_list_lock);
        return TDB_ERR_MEMORY;
    }

    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->next_seq_num, 0);
    atomic_init(&cf->commit_seq, 0);
    atomic_init(&cf->total_writes, 0);
    atomic_init(&cf->total_reads, 0);
    atomic_init(&cf->compaction_count, 0);
    atomic_init(&cf->memtable_id, 0);
    atomic_init(&cf->compaction_should_stop, 0);

    /* start background compaction thread if enabled */
    if (config->enable_background_compaction)
    {
        if (pthread_create(&cf->compaction_thread, NULL, tidesdb_background_compaction_thread,
                           cf) != 0)
        {
            /* non-fatal, continue without background compaction */
        }
    }

    /* add to database's list */
    db->column_families[db->num_column_families++] = cf;

    TDB_DEBUG_LOG("Created CF '%s' (total: %d)", name, db->num_column_families);

    /* release lock only after everything is complete */
    pthread_rwlock_unlock(&db->cf_list_lock);

    return TDB_SUCCESS;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Dropping column family: %s", name);

    pthread_rwlock_wrlock(&db->cf_list_lock);

    for (int i = 0; i < db->num_column_families; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            tidesdb_column_family_t *cf = db->column_families[i];

            memmove(&db->column_families[i], &db->column_families[i + 1],
                    (db->num_column_families - i - 1) * sizeof(tidesdb_column_family_t *));
            db->num_column_families--;

            pthread_rwlock_unlock(&db->cf_list_lock);

            /* stop and join background compaction thread before freeing */
            if (cf->config.enable_background_compaction)
            {
                atomic_store(&cf->compaction_should_stop, 1);
                pthread_join(cf->compaction_thread, NULL);
            }

            /* safely remove directory */
            int result = remove_directory(cf->directory);
            TDB_DEBUG_LOG("Deleted column family directory: %s (result: %d)", cf->directory,
                          result);

            tidesdb_column_family_free(cf);

            return TDB_SUCCESS;
        }
    }

    pthread_rwlock_unlock(&db->cf_list_lock);
    return TDB_ERR_NOT_FOUND;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

    pthread_rwlock_rdlock(&db->cf_list_lock);

    for (int i = 0; i < db->num_column_families; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            pthread_rwlock_unlock(&db->cf_list_lock);
            return cf;
        }
    }

    pthread_rwlock_unlock(&db->cf_list_lock);
    return NULL;
}

int tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    pthread_mutex_lock(&cf->flush_lock);

    /* check if memtable is empty */
    if (skip_list_count_entries(cf->active_memtable) == 0)
    {
        pthread_mutex_unlock(&cf->flush_lock);
        return TDB_SUCCESS;
    }

    TDB_DEBUG_LOG("Flushing memtable for column family: %s (entries: %d)", cf->name,
                  skip_list_count_entries(cf->active_memtable));

    /* save references to old memtable and WAL */
    skip_list_t *old_memtable = cf->active_memtable;
    block_manager_t *old_wal = cf->active_wal;
    uint64_t sst_id = atomic_fetch_add(&cf->next_sstable_id, 1);

    skip_list_t *new_memtable;
    if (skip_list_new(&new_memtable, 32, 0.25f) != 0)
    {
        pthread_mutex_unlock(&cf->flush_lock);
        return TDB_ERR_MEMORY;
    }

    uint64_t wal_id = atomic_fetch_add(&cf->memtable_id, 1);
    char wal_path[MAX_FILE_PATH_LENGTH];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR TDB_WAL_PREFIX TDB_U64_FMT TDB_WAL_EXT,
             cf->directory, TDB_U64_CAST(wal_id));

    block_manager_t *new_wal;
    if (block_manager_open_with_cache(&new_wal, wal_path, convert_sync_mode(cf->config.sync_mode),
                                      (uint32_t)cf->config.block_manager_cache_size) != 0)
    {
        skip_list_free(new_memtable);
        pthread_mutex_unlock(&cf->flush_lock);
        return TDB_ERR_IO;
    }

    /* add old memtable to immutable queue before swapping  */
    tidesdb_immutable_memtable_t *immutable = malloc(sizeof(tidesdb_immutable_memtable_t));
    if (!immutable)
    {
        /* cannot proceed without immutable structure, data would be lost */
        skip_list_free(new_memtable);
        block_manager_close(new_wal);
        pthread_mutex_unlock(&cf->flush_lock);
        return TDB_ERR_MEMORY;
    }

    immutable->memtable = old_memtable;
    immutable->wal = old_wal;
    queue_enqueue(cf->immutable_memtables, immutable);

    /* atomically swap memtables, this is the only blocking point for writes */
    cf->active_memtable = new_memtable;
    cf->active_wal = new_wal;

    pthread_mutex_unlock(&cf->flush_lock);

    /* create flush work item and enqueue it (non-blocking from here) */
    tidesdb_flush_work_t *work = malloc(sizeof(tidesdb_flush_work_t));
    if (!work)
    {
        /* work allocation failed, immutable is already in queue and will be flushed eventually
         * or cleaned up on shutdown. this is safe, no data loss. */
        return TDB_ERR_MEMORY;
    }

    work->cf = cf;
    work->memtable = old_memtable;
    work->wal = old_wal;
    work->sst_id = sst_id;

    /* enqueue work for background flush */
    if (queue_enqueue(cf->db->flush_queue, work) != 0)
    {
        /* fallback free the work and memtable */
        skip_list_free(old_memtable);
        if (old_wal)
        {
            char *wal_path_to_delete = tdb_strdup(old_wal->file_path);
            block_manager_close(old_wal);
            unlink(wal_path_to_delete);
            free(wal_path_to_delete);
        }
        free(work);
        return TDB_ERR_MEMORY;
    }

    /* return immediately, flush happens in background */
    return TDB_SUCCESS;
}

int tidesdb_compact(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* enqueue compaction work for thread pool */
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
 * MVCC transaction model *********
 *
 * sequence numbers **
 * -- next_seq_num -- atomically incremented for each write operation
 * -- commit_seq -- updated to next_seq_num after transaction commits
 * -- start_seq -- snapshot taken at transaction begin (from commit_seq)
 *
 * isolation levels **
 * -- READ_UNCOMMITTED -- start_seq=UINT64_MAX, sees all versions including uncommitted
 * -- READ_COMMITTED -- start_seq=commit_seq, sees only committed data at txn start
 * -- REPEATABLE_READ -- start_seq=commit_seq, consistent snapshot throughout txn
 * -- SERIALIZABLE -- start_seq=commit_seq + conflict detection on commit
 *
 * conflict detection (SERIALIZABLE only) **
 * -- read-writ e -- check if any read key was modified (seq >= start_seq)
 * -- write-write -- check if any write key was modified (seq >= start_seq)
 * -- only checks active memtable (flushed data is immutable)
 *
 * visibility **
 * -- reads use skip_list_get_with_seq(snapshot_seq=start_seq)
 * -- only versions with seq < start_seq are visible
 * -- lockless skip list provides atomic version chain traversal
 */
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_column_family_t *cf,
                                     tidesdb_isolation_level_t isolation, tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;
    if (!db->is_open) return TDB_ERR_INVALID_ARGS;

    *txn = calloc(1, sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->cf = cf;
    (*txn)->isolation_level = isolation;
    (*txn)->ops_capacity = 16;
    (*txn)->ops = malloc((*txn)->ops_capacity * sizeof(tidesdb_txn_op_t));

    if (!(*txn)->ops)
    {
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    /* atomically acquire snapshot with proper memory barriers */
    if (cf)
    {
        /* for SERIALIZABLE, acquire exclusive access momentarily */
        if (isolation == TDB_ISOLATION_SERIALIZABLE)
        {
            pthread_rwlock_rdlock(&cf->cf_lock);
        }

        /* all isolation levels snapshot from last committed state
         * READ_UNCOMMITTED: sees all committed data (start_seq = 0 means see everything)
         * READ_COMMITTED: sees data committed before txn start
         * REPEATABLE_READ: sees consistent snapshot from txn start
         * SERIALIZABLE: sees consistent snapshot + conflict detection */
        if (isolation == TDB_ISOLATION_READ_UNCOMMITTED)
        {
            (*txn)->start_seq = UINT64_MAX; /* see all versions */
        }
        else
        {
            (*txn)->start_seq = atomic_load_explicit(&cf->commit_seq, memory_order_seq_cst);
        }

        if (isolation == TDB_ISOLATION_SERIALIZABLE)
        {
            atomic_thread_fence(memory_order_seq_cst);
            pthread_rwlock_unlock(&cf->cf_lock);
        }
    }
    else
    {
        (*txn)->start_seq = 0;
    }

    static _Atomic(uint64_t) global_txn_id = 0;
    (*txn)->txn_id = atomic_fetch_add_explicit(&global_txn_id, 1, memory_order_relaxed);

    (*txn)->read_set_capacity = 16;
    (*txn)->read_keys = malloc((*txn)->read_set_capacity * sizeof(uint8_t *));
    (*txn)->read_key_sizes = malloc((*txn)->read_set_capacity * sizeof(size_t));
    (*txn)->read_seqs = malloc((*txn)->read_set_capacity * sizeof(uint64_t));

    if (!(*txn)->read_keys || !(*txn)->read_key_sizes || !(*txn)->read_seqs)
    {
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->write_set_capacity = 16;
    (*txn)->write_keys = malloc((*txn)->write_set_capacity * sizeof(uint8_t *));
    (*txn)->write_key_sizes = malloc((*txn)->write_set_capacity * sizeof(size_t));

    if (!(*txn)->write_keys || !(*txn)->write_key_sizes)
    {
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    (*txn)->cf_capacity = 4;
    (*txn)->cfs = malloc((*txn)->cf_capacity * sizeof(tidesdb_column_family_t *));
    (*txn)->start_seqs = malloc((*txn)->cf_capacity * sizeof(uint64_t));

    if (!(*txn)->cfs || !(*txn)->start_seqs)
    {
        free((*txn)->cfs);
        free((*txn)->start_seqs);
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
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
        free((*txn)->write_keys);
        free((*txn)->write_key_sizes);
        free((*txn)->read_keys);
        free((*txn)->read_key_sizes);
        free((*txn)->read_seqs);
        free((*txn)->ops);
        free(*txn);
        *txn = NULL;
        return TDB_ERR_MEMORY;
    }

    if (cf)
    {
        (*txn)->cfs[0] = cf;
        (*txn)->start_seqs[0] = (*txn)->start_seq; /* store snapshot for primary CF */
        (*txn)->num_cfs = 1;
    }
    else
    {
        (*txn)->num_cfs = 0;
    }

    (*txn)->is_read_only = 1; /* assume read-only until first write */

    return TDB_SUCCESS;
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn)
{
    tidesdb_isolation_level_t default_isolation =
        cf ? cf->config.default_isolation_level : TDB_ISOLATION_READ_COMMITTED;
    return tidesdb_txn_begin_with_isolation(db, cf, default_isolation, txn);
}

int tidesdb_txn_add_cf(tidesdb_txn_t *txn, tidesdb_column_family_t *cf)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* check if CF already in transaction */
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf) return TDB_SUCCESS; /* already added */
    }

    /* grow arrays if needed */
    if (txn->num_cfs >= txn->cf_capacity)
    {
        int new_cap = txn->cf_capacity * 2;
        tidesdb_column_family_t **new_cfs =
            realloc(txn->cfs, new_cap * sizeof(tidesdb_column_family_t *));
        uint64_t *new_seqs = realloc(txn->start_seqs, new_cap * sizeof(uint64_t));

        if (!new_cfs || !new_seqs)
        {
            free(new_cfs);
            free(new_seqs);
            return TDB_ERR_MEMORY;
        }

        txn->cfs = new_cfs;
        txn->start_seqs = new_seqs;
        txn->cf_capacity = new_cap;
    }

    /* take snapshot for this CF */
    uint64_t cf_start_seq;
    if (txn->isolation_level == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        cf_start_seq = UINT64_MAX;
    }
    else
    {
        cf_start_seq = atomic_load_explicit(&cf->commit_seq, memory_order_seq_cst);
    }

    /* add CF to transaction */
    txn->cfs[txn->num_cfs] = cf;
    txn->start_seqs[txn->num_cfs] = cf_start_seq;
    txn->num_cfs++;

    return TDB_SUCCESS;
}

int tidesdb_txn_put(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, const uint8_t *value,
                    size_t value_size, time_t ttl)
{
    if (!txn || !key || key_size == 0 || !value) return TDB_ERR_INVALID_ARGS;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

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
    op->cf = txn->cf;

    txn->num_ops++;
    txn->is_read_only = 0;

    /* track in write set for conflict detection */
    if (txn->write_set_count >= txn->write_set_capacity)
    {
        int new_cap = txn->write_set_capacity * 2;
        uint8_t **new_keys = realloc(txn->write_keys, new_cap * sizeof(uint8_t *));
        size_t *new_sizes = realloc(txn->write_key_sizes, new_cap * sizeof(size_t));

        if (!new_keys || !new_sizes)
        {
            free(new_keys);
            free(new_sizes);
            return TDB_ERR_MEMORY;
        }

        txn->write_keys = new_keys;
        txn->write_key_sizes = new_sizes;
        txn->write_set_capacity = new_cap;
    }

    txn->write_keys[txn->write_set_count] = malloc(key_size);
    if (!txn->write_keys[txn->write_set_count]) return TDB_ERR_MEMORY;

    memcpy(txn->write_keys[txn->write_set_count], key, key_size);
    txn->write_key_sizes[txn->write_set_count] = key_size;
    txn->write_set_count++;

    return TDB_SUCCESS;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, uint8_t **value,
                    size_t *value_size)
{
    if (!txn || !key || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = txn->cf;
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* check write set first (read your own writes) */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        if (txn->ops[i].key_size == key_size && memcmp(txn->ops[i].key, key, key_size) == 0)
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

    /* search memtable */
    pthread_mutex_lock(&cf->flush_lock);
    uint8_t *temp_value;
    size_t temp_value_size;
    time_t ttl;
    uint8_t deleted;
    uint64_t found_seq = 0;

    /* use snapshot sequence for isolation */
    uint64_t snapshot_seq = 0;
    switch (txn->isolation_level)
    {
        case TDB_ISOLATION_READ_UNCOMMITTED:
            snapshot_seq = 0; /* read latest */
            break;
        case TDB_ISOLATION_READ_COMMITTED:
            snapshot_seq = atomic_load(&cf->commit_seq);
            break;
        case TDB_ISOLATION_REPEATABLE_READ:
        case TDB_ISOLATION_SERIALIZABLE:
            snapshot_seq = txn->start_seq;
            break;
    }

    if (skip_list_get_with_seq(cf->active_memtable, key, key_size, &temp_value, &temp_value_size,
                               &ttl, &deleted, &found_seq, snapshot_seq) == 0)
    {
        if (!deleted && (ttl == 0 || ttl > time(NULL)))
        {
            *value = temp_value;
            *value_size = temp_value_size;

            /* add to read set for SERIALIZABLE */
            if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
            {
                /* resize if needed */
                if (txn->read_set_count >= txn->read_set_capacity)
                {
                    int new_capacity = txn->read_set_capacity * 2;
                    uint8_t **new_keys = realloc(txn->read_keys, new_capacity * sizeof(uint8_t *));
                    size_t *new_sizes = realloc(txn->read_key_sizes, new_capacity * sizeof(size_t));
                    uint64_t *new_seqs = realloc(txn->read_seqs, new_capacity * sizeof(uint64_t));

                    if (new_keys && new_sizes && new_seqs)
                    {
                        txn->read_keys = new_keys;
                        txn->read_key_sizes = new_sizes;
                        txn->read_seqs = new_seqs;
                        txn->read_set_capacity = new_capacity;
                    }
                }

                if (txn->read_set_count < txn->read_set_capacity)
                {
                    txn->read_keys[txn->read_set_count] = malloc(key_size);
                    if (txn->read_keys[txn->read_set_count])
                    {
                        memcpy(txn->read_keys[txn->read_set_count], key, key_size);
                        txn->read_key_sizes[txn->read_set_count] = key_size;
                        txn->read_seqs[txn->read_set_count] = found_seq;
                        txn->read_set_count++;
                    }
                }
            }

            pthread_mutex_unlock(&cf->flush_lock);
            return TDB_SUCCESS;
        }

        free(temp_value);
    }

    pthread_mutex_unlock(&cf->flush_lock);

    int immutable_count = (int)queue_size(cf->immutable_memtables);
    for (int i = 0; i < immutable_count; i++)
    {
        tidesdb_immutable_memtable_t *immutable =
            (tidesdb_immutable_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
        if (immutable && immutable->memtable)
        {
            if (skip_list_get_with_seq(immutable->memtable, key, key_size, &temp_value,
                                       &temp_value_size, &ttl, &deleted, &found_seq,
                                       snapshot_seq) == 0)
            {
                if (!deleted && (ttl == 0 || ttl > time(NULL)))
                {
                    *value = temp_value;
                    *value_size = temp_value_size;
                    return TDB_SUCCESS;
                }
                free(temp_value);
            }
        }
    }

    /* search SSTables with isolation checks; find newest version across all ssts */
    int num_levels = atomic_load(&cf->num_levels);
    tidesdb_kv_pair_t *best_kv = NULL;
    uint64_t best_seq = UINT64_MAX; /* use max value so any real seq is better */
    int found_any = 0;

    for (int i = 0; i < num_levels; i++)
    {
        tidesdb_level_t *level = cf->levels[i];
        pthread_mutex_lock(&level->level_lock);

        int num_ssts = atomic_load(&level->num_sstables);

        /* for level 0, search in reverse order (newest ssts first)
         * for other levels, normal order is fine */
        int start = (i == 0) ? num_ssts - 1 : 0;
        int end = (i == 0) ? -1 : num_ssts;
        int step = (i == 0) ? -1 : 1;

        for (int j = start; j != end; j += step)
        {
            tidesdb_sstable_t *sst = level->sstables[j];

            /* skip ssts whose key range doesn't contain our key */
            int in_range = tidesdb_sstable_contains_key_range(
                sst, key, key_size, cf->config.comparator, cf->config.comparator_ctx);
            if (!in_range)
            {
                continue;
            }

            tidesdb_kv_pair_t *candidate_kv = NULL;
            if (tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv) == TDB_SUCCESS)
            {
                /* check isolation */
                int accept = 0;
                uint64_t candidate_seq = candidate_kv->entry.seq;

                switch (txn->isolation_level)
                {
                    case TDB_ISOLATION_READ_UNCOMMITTED:
                        accept = 1;
                        break;
                    case TDB_ISOLATION_READ_COMMITTED:
                        accept = (candidate_seq <= atomic_load(&cf->commit_seq));
                        break;
                    case TDB_ISOLATION_REPEATABLE_READ:
                    case TDB_ISOLATION_SERIALIZABLE:
                        accept = (candidate_seq < txn->start_seq);
                        break;
                }

                /* keep the version with highest sequence number (or first if no best yet) */
                if (accept && (best_seq == UINT64_MAX || candidate_seq > best_seq))
                {
                    if (best_kv) tidesdb_kv_pair_free(best_kv);
                    best_kv = candidate_kv;
                    best_seq = candidate_seq;
                    found_any = 1;
                }
                else
                {
                    tidesdb_kv_pair_free(candidate_kv);
                }
            }
        }

        pthread_mutex_unlock(&level->level_lock);
    }

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

                /* add to read set */
                if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
                {
                    if (txn->read_set_count < txn->read_set_capacity)
                    {
                        txn->read_keys[txn->read_set_count] = malloc(key_size);
                        if (txn->read_keys[txn->read_set_count])
                        {
                            memcpy(txn->read_keys[txn->read_set_count], key, key_size);
                            txn->read_key_sizes[txn->read_set_count] = key_size;
                            txn->read_seqs[txn->read_set_count] = best_seq;
                            txn->read_set_count++;
                        }
                    }
                }

                tidesdb_kv_pair_free(best_kv);
                return TDB_SUCCESS;
            }
        }
        tidesdb_kv_pair_free(best_kv);
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size)
{
    return tidesdb_txn_delete_cf(txn, txn->cf, key, key_size);
}

int tidesdb_txn_put_cf(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf || !key || key_size == 0 || !value) return TDB_ERR_INVALID_ARGS;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* ensure CF is in transaction */
    int cf_found = 0;
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf)
        {
            cf_found = 1;
            break;
        }
    }
    if (!cf_found)
    {
        int result = tidesdb_txn_add_cf(txn, cf);
        if (result != TDB_SUCCESS) return result;
    }

    if (txn->num_ops >= TDB_MAX_TXN_OPS) return TDB_ERR_TOO_LARGE;

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

    op->ttl = ttl;
    op->is_delete = 0;
    op->cf = cf;

    txn->num_ops++;
    txn->is_read_only = 0;

    /* track in write set */
    if (txn->write_set_count >= txn->write_set_capacity)
    {
        int new_cap = txn->write_set_capacity * 2;
        uint8_t **new_keys = realloc(txn->write_keys, new_cap * sizeof(uint8_t *));
        size_t *new_sizes = realloc(txn->write_key_sizes, new_cap * sizeof(size_t));

        if (!new_keys || !new_sizes)
        {
            free(new_keys);
            free(new_sizes);
            return TDB_ERR_MEMORY;
        }

        txn->write_keys = new_keys;
        txn->write_key_sizes = new_sizes;
        txn->write_set_capacity = new_cap;
    }

    txn->write_keys[txn->write_set_count] = malloc(key_size);
    if (!txn->write_keys[txn->write_set_count]) return TDB_ERR_MEMORY;

    memcpy(txn->write_keys[txn->write_set_count], key, key_size);
    txn->write_key_sizes[txn->write_set_count] = key_size;
    txn->write_set_count++;

    return TDB_SUCCESS;
}

int tidesdb_txn_get_cf(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf || !key || key_size == 0 || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    /* find CF snapshot */
    uint64_t cf_snapshot = 0;
    int cf_found = 0;
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf)
        {
            cf_snapshot = txn->start_seqs[i];
            cf_found = 1;
            break;
        }
    }

    if (!cf_found)
    {
        /* CF not in transaction, add it and take snapshot */
        int result = tidesdb_txn_add_cf(txn, cf);
        if (result != TDB_SUCCESS) return result;
        cf_snapshot = txn->start_seqs[txn->num_cfs - 1];
    }

    /* check write set first */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        tidesdb_txn_op_t *op = &txn->ops[i];
        if (op->cf == cf && op->key_size == key_size && memcmp(op->key, key, key_size) == 0)
        {
            if (op->is_delete) return TDB_ERR_NOT_FOUND;

            *value = malloc(op->value_size);
            if (!*value) return TDB_ERR_MEMORY;
            memcpy(*value, op->value, op->value_size);
            *value_size = op->value_size;
            return TDB_SUCCESS;
        }
    }

    /* read from CF with snapshot isolation */
    uint8_t *temp_value = NULL;
    size_t temp_value_size = 0;
    time_t ttl;
    uint8_t deleted;
    uint64_t seq;

    int result = skip_list_get_with_seq(cf->active_memtable, key, key_size, &temp_value,
                                        &temp_value_size, &ttl, &deleted, &seq, cf_snapshot);

    if (result == 0)
    {
        if (deleted)
        {
            free(temp_value);
            return TDB_ERR_NOT_FOUND;
        }

        /* track in read set */
        if (txn->read_set_count >= txn->read_set_capacity)
        {
            int new_cap = txn->read_set_capacity * 2;
            uint8_t **new_keys = realloc(txn->read_keys, new_cap * sizeof(uint8_t *));
            size_t *new_sizes = realloc(txn->read_key_sizes, new_cap * sizeof(size_t));
            uint64_t *new_seqs = realloc(txn->read_seqs, new_cap * sizeof(uint64_t));

            if (!new_keys || !new_sizes || !new_seqs)
            {
                free(new_keys);
                free(new_sizes);
                free(new_seqs);
                free(temp_value);
                return TDB_ERR_MEMORY;
            }

            txn->read_keys = new_keys;
            txn->read_key_sizes = new_sizes;
            txn->read_seqs = new_seqs;
            txn->read_set_capacity = new_cap;
        }

        txn->read_keys[txn->read_set_count] = malloc(key_size);
        if (!txn->read_keys[txn->read_set_count])
        {
            free(temp_value);
            return TDB_ERR_MEMORY;
        }

        memcpy(txn->read_keys[txn->read_set_count], key, key_size);
        txn->read_key_sizes[txn->read_set_count] = key_size;
        txn->read_seqs[txn->read_set_count] = seq;
        txn->read_set_count++;

        *value = temp_value;
        *value_size = temp_value_size;
        return TDB_SUCCESS;
    }

    /* search SSTables with snapshot isolation */
    int num_levels = atomic_load(&cf->num_levels);
    tidesdb_kv_pair_t *best_kv = NULL;
    uint64_t best_seq = UINT64_MAX;

    for (int i = 0; i < num_levels; i++)
    {
        tidesdb_level_t *level = cf->levels[i];
        pthread_mutex_lock(&level->level_lock);

        int num_ssts = atomic_load(&level->num_sstables);
        int start = (i == 0) ? num_ssts - 1 : 0;
        int end = (i == 0) ? -1 : num_ssts;
        int step = (i == 0) ? -1 : 1;

        for (int j = start; j != end; j += step)
        {
            tidesdb_sstable_t *sst = level->sstables[j];

            int in_range = tidesdb_sstable_contains_key_range(
                sst, key, key_size, cf->config.comparator, cf->config.comparator_ctx);
            if (!in_range) continue;

            tidesdb_kv_pair_t *candidate_kv = NULL;
            if (tidesdb_sstable_get(cf->db, sst, key, key_size, &candidate_kv) == TDB_SUCCESS)
            {
                if (candidate_kv->entry.seq < cf_snapshot && candidate_kv->entry.seq < best_seq)
                {
                    if (best_kv) tidesdb_kv_pair_free(best_kv);
                    best_kv = candidate_kv;
                    best_seq = candidate_kv->entry.seq;
                }
                else
                {
                    tidesdb_kv_pair_free(candidate_kv);
                }
            }
        }

        pthread_mutex_unlock(&level->level_lock);
    }

    if (best_kv)
    {
        if (best_kv->entry.flags & TDB_KV_FLAG_TOMBSTONE)
        {
            tidesdb_kv_pair_free(best_kv);
            return TDB_ERR_NOT_FOUND;
        }

        *value = malloc(best_kv->entry.value_size);
        if (!*value)
        {
            tidesdb_kv_pair_free(best_kv);
            return TDB_ERR_MEMORY;
        }
        memcpy(*value, best_kv->value, best_kv->entry.value_size);
        *value_size = best_kv->entry.value_size;
        tidesdb_kv_pair_free(best_kv);
        return TDB_SUCCESS;
    }

    return TDB_ERR_NOT_FOUND;
}

int tidesdb_txn_delete_cf(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                          size_t key_size)
{
    if (!txn || !cf || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;
    if (txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;

    /* ensure CF is in transaction */
    int cf_found = 0;
    for (int i = 0; i < txn->num_cfs; i++)
    {
        if (txn->cfs[i] == cf)
        {
            cf_found = 1;
            break;
        }
    }
    if (!cf_found)
    {
        int result = tidesdb_txn_add_cf(txn, cf);
        if (result != TDB_SUCCESS) return result;
    }

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

        if (!new_keys || !new_sizes)
        {
            free(new_keys);
            free(new_sizes);
            return TDB_ERR_MEMORY;
        }

        txn->write_keys = new_keys;
        txn->write_key_sizes = new_sizes;
        txn->write_set_capacity = new_cap;
    }

    txn->write_keys[txn->write_set_count] = malloc(key_size);
    if (!txn->write_keys[txn->write_set_count]) return TDB_ERR_MEMORY;

    memcpy(txn->write_keys[txn->write_set_count], key, key_size);
    txn->write_key_sizes[txn->write_set_count] = key_size;
    txn->write_set_count++;

    return TDB_SUCCESS;
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed || txn->is_aborted) return TDB_ERR_INVALID_ARGS;
    if (txn->num_cfs <= 0) return TDB_ERR_INVALID_ARGS;

    /* prepare ~~ conflict detection across all CFs (for SERIALIZABLE) */

    /* for SERIALIZABLE, check for conflicts across all CFs */
    if (txn->isolation_level == TDB_ISOLATION_SERIALIZABLE)
    {
        /* check read-write conflicts in all CFs */
        for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
        {
            tidesdb_column_family_t *cf = txn->cfs[cf_idx];
            uint64_t cf_snapshot = txn->start_seqs[cf_idx];

            for (int i = 0; i < txn->read_set_count; i++)
            {
                uint8_t *temp_value;
                size_t temp_value_size;
                time_t ttl;
                uint8_t deleted;
                uint64_t found_seq = 0;

                if (skip_list_get_with_seq(cf->active_memtable, txn->read_keys[i],
                                           txn->read_key_sizes[i], &temp_value, &temp_value_size,
                                           &ttl, &deleted, &found_seq, 0) == 0)
                {
                    if (found_seq >= cf_snapshot)
                    {
                        free(temp_value);
                        return TDB_ERR_CONFLICT;
                    }
                    free(temp_value);
                }
            }
        }

        /* check write-write conflicts in all CFs */
        for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
        {
            tidesdb_column_family_t *cf = txn->cfs[cf_idx];
            uint64_t cf_snapshot = txn->start_seqs[cf_idx];

            for (int i = 0; i < txn->write_set_count; i++)
            {
                uint8_t *temp_value;
                size_t temp_value_size;
                time_t ttl;
                uint8_t deleted;
                uint64_t found_seq = 0;

                if (skip_list_get_with_seq(cf->active_memtable, txn->write_keys[i],
                                           txn->write_key_sizes[i], &temp_value, &temp_value_size,
                                           &ttl, &deleted, &found_seq, 0) == 0)
                {
                    if (found_seq >= cf_snapshot)
                    {
                        free(temp_value);
                        return TDB_ERR_CONFLICT;
                    }
                    free(temp_value);
                }
            }
        }
    }

    /* commit ~~ two-phase commit for atomicity across multiple CFs */

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

    /* PHASE 1
     * PREPARE -- allocate all resources and assign sequence numbers */
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
            }
        }

        cf_contexts[cf_idx].op_count = cf_op_count;
        cf_contexts[cf_idx].wal_size = cf_wal_size;

        if (cf_op_count == 0)
        {
            continue; /* no operations for this CF */
        }

        /* pre-allocate WAL batch buffer */
        cf_contexts[cf_idx].wal_batch = malloc(cf_wal_size);
        if (!cf_contexts[cf_idx].wal_batch)
        {
            /* cleanup and fail */
            for (int j = 0; j < cf_idx; j++)
            {
                free(cf_contexts[j].wal_batch);
                free(cf_contexts[j].seq_numbers);
            }
            free(cf_contexts);
            return TDB_ERR_MEMORY;
        }

        /* pre-allocate sequence number array */
        cf_contexts[cf_idx].seq_numbers = malloc(cf_op_count * sizeof(uint64_t));
        if (!cf_contexts[cf_idx].seq_numbers)
        {
            /* cleanup and fail */
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
        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            uint64_t seq = atomic_fetch_add(&cf->next_seq_num, 1);
            cf_contexts[cf_idx].seq_numbers[seq_idx++] = seq;

            /* serialize to WAL batch buffer */
            tidesdb_klog_entry_t entry = {.key_size = (uint32_t)op->key_size,
                                          .value_size = (uint32_t)op->value_size,
                                          .ttl = op->ttl,
                                          .seq = seq,
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

    /* PHASE 2
     * COMMIT -- apply all operations (resources pre-allocated, cannot fail on memory) */
    int commit_failed_at = -1;
    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        cf_commit_ctx_t *ctx = &cf_contexts[cf_idx];
        if (ctx->op_count == 0)
        {
            continue; /* no operations for this CF */
        }

        tidesdb_column_family_t *cf = ctx->cf;
        pthread_rwlock_rdlock(&cf->cf_lock);

        /* apply all operations to memtable with flush_lock held */
        pthread_mutex_lock(&cf->flush_lock);
        int seq_idx = 0;
        for (int i = 0; i < txn->num_ops; i++)
        {
            tidesdb_txn_op_t *op = &txn->ops[i];
            if (op->cf != cf) continue;

            skip_list_put_with_seq(cf->active_memtable, op->key, op->key_size, op->value,
                                   op->value_size, op->ttl, ctx->seq_numbers[seq_idx++],
                                   op->is_delete);

            atomic_fetch_add(&cf->total_writes, 1);
        }
        pthread_mutex_unlock(&cf->flush_lock);

        /* single batched WAL write for this CF */
        block_manager_block_t *batch_block =
            block_manager_block_create(ctx->wal_size, ctx->wal_batch);
        if (batch_block)
        {
            block_manager_block_write(cf->active_wal, batch_block);
            block_manager_block_free(batch_block);
        }
        else
        {
            /* WAL write failed -- need to rollback */
            pthread_rwlock_unlock(&cf->cf_lock);
            commit_failed_at = cf_idx;
            break;
        }

        /* update commit sequence for this CF */
        uint64_t cf_commit_seq = atomic_load(&cf->next_seq_num);
        atomic_store(&cf->commit_seq, cf_commit_seq);

        /* check if flush needed */
        if ((size_t)skip_list_get_size(cf->active_memtable) >= cf->config.write_buffer_size)
        {
            tidesdb_flush_memtable(cf);
        }

        ctx->committed = 1;
        pthread_rwlock_unlock(&cf->cf_lock);
    }

    /* PHASE 3
     * ROLLBACK -- if any CF failed */
    if (commit_failed_at >= 0)
    {
        TDB_DEBUG_LOG("Multi-CF commit failed at CF %d, rolling back", commit_failed_at);

        /* rollback all committed CFs by writing compensating tombstones */
        for (int cf_idx = 0; cf_idx < commit_failed_at; cf_idx++)
        {
            cf_commit_ctx_t *ctx = &cf_contexts[cf_idx];
            if (!ctx->committed) continue;

            tidesdb_column_family_t *cf = ctx->cf;
            pthread_rwlock_rdlock(&cf->cf_lock);
            pthread_mutex_lock(&cf->flush_lock);

            /* write tombstones for all operations in this CF */
            for (int i = 0; i < txn->num_ops; i++)
            {
                tidesdb_txn_op_t *op = &txn->ops[i];
                if (op->cf != cf) continue;

                /* write tombstone with new sequence number to undo the operation */
                uint64_t rollback_seq = atomic_fetch_add(&cf->next_seq_num, 1);
                skip_list_put_with_seq(cf->active_memtable, op->key, op->key_size, NULL, 0, 0,
                                       rollback_seq, 1); /* tombstone */
            }

            pthread_mutex_unlock(&cf->flush_lock);
            pthread_rwlock_unlock(&cf->cf_lock);
        }

        /* cleanup */
        for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
        {
            free(cf_contexts[cf_idx].wal_batch);
            free(cf_contexts[cf_idx].seq_numbers);
        }
        free(cf_contexts);

        return TDB_ERR_IO;
    }

    /* cleanup pre-allocated resources */
    for (int cf_idx = 0; cf_idx < txn->num_cfs; cf_idx++)
    {
        free(cf_contexts[cf_idx].wal_batch);
        free(cf_contexts[cf_idx].seq_numbers);
    }
    free(cf_contexts);

    txn->is_committed = 1;

    return TDB_SUCCESS;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn || txn->is_committed) return TDB_ERR_INVALID_ARGS;

    /* simply mark as aborted; operations never applied */
    txn->is_aborted = 1;

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

    for (int i = 0; i < txn->write_set_count; i++)
    {
        free(txn->write_keys[i]);
    }
    free(txn->write_keys);
    free(txn->write_key_sizes);

    for (int i = 0; i < txn->num_savepoints; i++)
    {
        free(txn->savepoint_names[i]);
        tidesdb_txn_free(txn->savepoints[i]);
    }
    free(txn->savepoints);
    free(txn->savepoint_names);

    free(txn->cfs);
    free(txn->start_seqs);
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

            /* create new savepoint snapshot */
            tidesdb_txn_t *savepoint = calloc(1, sizeof(tidesdb_txn_t));
            if (!savepoint) return TDB_ERR_MEMORY;

            /* copy current transaction state */
            savepoint->num_ops = txn->num_ops;
            savepoint->ops = malloc(txn->num_ops * sizeof(tidesdb_txn_op_t));
            if (!savepoint->ops && txn->num_ops > 0)
            {
                free(savepoint);
                return TDB_ERR_MEMORY;
            }
            memcpy(savepoint->ops, txn->ops, txn->num_ops * sizeof(tidesdb_txn_op_t));

            /* free old savepoint and replace */
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
    savepoint->cf = txn->cf;
    savepoint->isolation_level = txn->isolation_level;
    savepoint->txn_id = txn->txn_id;
    savepoint->start_seq = txn->start_seq;
    savepoint->parent = txn;

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

    /* free current operations after savepoint */
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

        case TDB_ISOLATION_REPEATABLE_READ:
        case TDB_ISOLATION_SERIALIZABLE:
            /* only accept versions <= transaction start sequence */
            return (kv->entry.seq <= iter->txn->start_seq);

        default:
            return 1;
    }
}

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_iter_t **iter)
{
    return tidesdb_iter_new_cf(txn, txn->cf, iter);
}

int tidesdb_iter_new_cf(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter)
{
    if (!txn || !iter) return TDB_ERR_INVALID_ARGS;

    /* if cf is NULL, iterate all CFs in transaction */
    if (!cf && txn->num_cfs == 0) return TDB_ERR_INVALID_ARGS;

    *iter = calloc(1, sizeof(tidesdb_iter_t));
    if (!*iter) return TDB_ERR_MEMORY;

    (*iter)->cf = cf;
    (*iter)->txn = txn;
    (*iter)->valid = 0;
    (*iter)->direction = 0;
    (*iter)->snapshot_time = time(NULL);
    (*iter)->cf_index = cf ? 0 : -1; /* -1 means iterate all CFs */

    /* use comparator from first CF (all CFs should have compatible comparators) */
    tidesdb_column_family_t *first_cf = cf ? cf : txn->cfs[0];
    (*iter)->heap =
        tidesdb_merge_heap_create(first_cf->config.comparator, first_cf->config.comparator_ctx);
    if (!(*iter)->heap)
    {
        free(*iter);
        return TDB_ERR_MEMORY;
    }

    /* determine which CFs to iterate */
    int start_cf_idx = 0;
    int end_cf_idx = 0;
    if (cf)
    {
        /* single CF iteration -- find CF index */
        for (int i = 0; i < txn->num_cfs; i++)
        {
            if (txn->cfs[i] == cf)
            {
                start_cf_idx = i;
                end_cf_idx = i;
                break;
            }
        }
    }
    else
    {
        /* multi-CF iteration -- iterate all CFs */
        start_cf_idx = 0;
        end_cf_idx = txn->num_cfs - 1;
    }

    /* add merge sources from each CF */
    for (int cf_idx = start_cf_idx; cf_idx <= end_cf_idx; cf_idx++)
    {
        tidesdb_column_family_t *current_cf = txn->cfs[cf_idx];
        pthread_rwlock_rdlock(&current_cf->cf_lock);

        /* add memtable as source */
        pthread_mutex_lock(&current_cf->flush_lock);
        tidesdb_merge_source_t *memtable_source =
            tidesdb_merge_source_from_memtable(current_cf->active_memtable, &current_cf->config);
        if (memtable_source)
        {
            /* only add source if it has data */
            if (memtable_source->current_kv != NULL)
            {
                tidesdb_merge_heap_add_source((*iter)->heap, memtable_source);
            }
            else
            {
                tidesdb_merge_source_free(memtable_source);
            }
        }

        /* we add immutable memtables */
        size_t imm_count = queue_size(current_cf->immutable_memtables);
        for (size_t i = 0; i < imm_count; i++)
        {
            skip_list_t *imm = (skip_list_t *)queue_peek_at(current_cf->immutable_memtables, i);
            if (imm)
            {
                tidesdb_merge_source_t *source =
                    tidesdb_merge_source_from_memtable(imm, &current_cf->config);
                if (source)
                {
                    /* only add source if it has data */
                    if (source->current_kv != NULL)
                    {
                        tidesdb_merge_heap_add_source((*iter)->heap, source);
                    }
                    else
                    {
                        tidesdb_merge_source_free(source);
                    }
                }
            }
        }
        pthread_mutex_unlock(&current_cf->flush_lock);

        /* add sstables */
        int num_levels = atomic_load(&current_cf->num_levels);
        for (int i = 0; i < num_levels; i++)
        {
            tidesdb_level_t *level = current_cf->levels[i];
            pthread_mutex_lock(&level->level_lock);

            int num_ssts = atomic_load(&level->num_sstables);
            for (int j = 0; j < num_ssts; j++)
            {
                tidesdb_sstable_t *sst = level->sstables[j];
                tidesdb_merge_source_t *sst_source = tidesdb_merge_source_from_sstable(cf->db, sst);
                if (sst_source)
                {
                    /* only add source if it has data */
                    if (sst_source->current_kv != NULL)
                    {
                        tidesdb_merge_heap_add_source((*iter)->heap, sst_source);
                    }
                    else
                    {
                        tidesdb_merge_source_free(sst_source);
                    }
                }
            }

            pthread_mutex_unlock(&level->level_lock);
        }

        pthread_rwlock_unlock(&current_cf->cf_lock);
    } /* end CF loop */

    return TDB_SUCCESS;
}

int tidesdb_iter_new_all_cfs(tidesdb_txn_t *txn, tidesdb_iter_t **iter)
{
    return tidesdb_iter_new_cf(txn, NULL, iter);
}

int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_kv_pair_free(iter->current);
    iter->current = NULL;
    iter->valid = 0;
    iter->direction = 1; /* forward direction */

    /* seek each source individually to the target key */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[i];

        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            /* seek in skip list to key >= target */
            skip_list_cursor_t *cursor = source->source.memtable.cursor;

            /* skip_list_cursor_seek positions BEFORE target, so advance to get >= target */
            if (skip_list_cursor_seek(cursor, (uint8_t *)key, key_size) == 0)
            {
                /* advance to the actual target or next key */
                if (skip_list_cursor_next(cursor) == 0)
                {
                    uint8_t *found_key, *found_value;
                    size_t found_key_size, found_value_size;
                    time_t ttl;
                    uint8_t deleted;

                    if (skip_list_cursor_get(cursor, &found_key, &found_key_size, &found_value,
                                             &found_value_size, &ttl, &deleted) == 0)
                    {
                        source->current_kv =
                            tidesdb_kv_pair_create(found_key, found_key_size, found_value,
                                                   found_value_size, ttl, 0, deleted);
                    }
                }
            }
        }
        else /* MERGE_SOURCE_SSTABLE */
        {
            tidesdb_sstable_t *sst = source->source.sstable.sst;

            /* use block index to find starting block (if available) */
            int64_t start_block = 0;
            if (sst->block_index)
            {
                /* find predecessor block the block with largest key <= target */
                if (succinct_trie_find_predecessor(sst->block_index, key, key_size, &start_block) !=
                    0)
                {
                    start_block = 0; /* start from beginning if not found */
                }
            }

            /* position cursor at the starting block -- use cache if available */
            block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;
            if (cursor->position_cache && start_block < cursor->cache_size)
            {
                /* jump directly using cached position */
                cursor->cache_index = start_block;
                cursor->current_pos = cursor->position_cache[start_block];
                cursor->current_block_size = cursor->size_cache[start_block];
            }
            else
            {
                /* fallback to linear scan if no cache */
                block_manager_cursor_goto_first(cursor);
                for (int64_t b = 0; b < start_block; b++)
                {
                    if (block_manager_cursor_next(cursor) != 0) break;
                }
            }

            /* scan blocks to find first entry >= key */
            tidesdb_klog_block_free(source->source.sstable.current_block);
            source->source.sstable.current_block = NULL;

            int found = 0;
            while (block_manager_cursor_has_next(source->source.sstable.klog_cursor))
            {
                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (!block) break;

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

                tidesdb_klog_block_t *klog_block = NULL;
                if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) == 0)
                {
                    /* find first entry >= key in this block */
                    for (uint32_t j = 0; j < klog_block->num_entries; j++)
                    {
                        int cmp = sst->config->comparator(klog_block->keys[j],
                                                          klog_block->entries[j].key_size, key,
                                                          key_size, sst->config->comparator_ctx);

                        if (cmp >= 0)
                        {
                            /* found! */
                            source->source.sstable.current_block = klog_block;
                            source->source.sstable.current_entry_idx = j;

                            uint8_t *value = klog_block->inline_values[j];
                            uint8_t *vlog_value = NULL;

                            if (klog_block->entries[j].vlog_offset > 0)
                            {
                                tidesdb_vlog_read_value(sst, klog_block->entries[j].vlog_offset,
                                                        klog_block->entries[j].value_size,
                                                        &vlog_value);
                                value = vlog_value;
                            }

                            source->current_kv = tidesdb_kv_pair_create(
                                klog_block->keys[j], klog_block->entries[j].key_size, value,
                                klog_block->entries[j].value_size, klog_block->entries[j].ttl,
                                klog_block->entries[j].seq,
                                klog_block->entries[j].flags & TDB_KV_FLAG_TOMBSTONE);

                            free(vlog_value);
                            found = 1;
                            break;
                        }
                    }

                    if (!found)
                    {
                        tidesdb_klog_block_free(klog_block);
                    }
                }

                free(decompressed);
                block_manager_block_release(block);

                if (found) break;

                block_manager_cursor_next(source->source.sstable.klog_cursor);
            }
        }
    }

    /* rebuild heap with repositioned sources */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        heap_sift_down(iter->heap, i);
    }

    /* pop the first visible entry */
    while (!tidesdb_merge_heap_empty(iter->heap))
    {
        tidesdb_kv_pair_t *kv = tidesdb_merge_heap_pop(iter->heap);
        if (!kv) break;

        /* check visibility */
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
    iter->direction = -1; /* backward direction */

    /* use block indexes to find predecessor block for sst sources */
    for (int i = 0; i < iter->heap->num_sources; i++)
    {
        tidesdb_merge_source_t *source = iter->heap->sources[i];
        tidesdb_kv_pair_free(source->current_kv);
        source->current_kv = NULL;

        if (source->type == MERGE_SOURCE_MEMTABLE)
        {
            /* seek in skip list to key <= target */
            skip_list_cursor_t *cursor = source->source.memtable.cursor;
            if (skip_list_cursor_seek_for_prev(cursor, (uint8_t *)key, key_size) == 0)
            {
                uint8_t *found_key, *found_value;
                size_t found_key_size, found_value_size;
                time_t ttl;
                uint8_t deleted;

                if (skip_list_cursor_get(cursor, &found_key, &found_key_size, &found_value,
                                         &found_value_size, &ttl, &deleted) == 0)
                {
                    /* skip_list_cursor_seek_for_prev already positioned us correctly */
                    /* cursor is at target or largest key < target */
                    source->current_kv = tidesdb_kv_pair_create(
                        found_key, found_key_size, found_value, found_value_size, ttl, 0, deleted);
                }
            }
        }
        else /* MERGE_SOURCE_SSTABLE */
        {
            tidesdb_sstable_t *sst = source->source.sstable.sst;

            int64_t start_block = 0;
            if (sst->block_index)
            {
                /* find_predecessor returns the block with largest key <= target */
                if (succinct_trie_find_predecessor(sst->block_index, key, key_size, &start_block) !=
                    0)
                {
                    /* no predecessor found, start from beginning */
                    start_block = 0;
                }
            }

            /* position cursor at the starting block -- use cache if available */
            block_manager_cursor_t *cursor = source->source.sstable.klog_cursor;
            if (cursor->position_cache && start_block < cursor->cache_size)
            {
                /* jump directly using cached position */
                cursor->cache_index = start_block;
                cursor->current_pos = cursor->position_cache[start_block];
                cursor->current_block_size = cursor->size_cache[start_block];
            }
            else
            {
                /* fallback to linear scan if no cache */
                block_manager_cursor_goto_first(cursor);
                for (int64_t b = 0; b < start_block; b++)
                {
                    if (block_manager_cursor_next(cursor) != 0) break;
                }
            }

            /* scan blocks to find last entry <= key */
            tidesdb_klog_block_free(source->source.sstable.current_block);
            source->source.sstable.current_block = NULL;

            tidesdb_kv_pair_t *best_match = NULL;
            int found_in_block = -1;
            (void)found_in_block; /* unused but kept for potential debugging */
            int64_t current_block_num = start_block;

            while (block_manager_cursor_has_next(source->source.sstable.klog_cursor) &&
                   current_block_num < (int64_t)sst->num_klog_blocks)
            {
                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (!block) break;

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

                tidesdb_klog_block_t *klog_block = NULL;
                if (tidesdb_klog_block_deserialize(data, data_size, &klog_block) == 0)
                {
                    /* early exit: if we have a match and first entry > target, stop */
                    if (best_match && klog_block->num_entries > 0)
                    {
                        int first_cmp = sst->config->comparator(
                            klog_block->keys[0], klog_block->entries[0].key_size, key, key_size,
                            sst->config->comparator_ctx);
                        if (first_cmp > 0)
                        {
                            tidesdb_klog_block_free(klog_block);
                            free(decompressed);
                            block_manager_block_release(block);
                            goto found_predecessor;
                        }
                    }

                    /* binary search to find last entry <= key */
                    int left = 0;
                    int right = klog_block->num_entries - 1;
                    int best_idx = -1;

                    while (left <= right)
                    {
                        int mid = left + (right - left) / 2;
                        int cmp = sst->config->comparator(klog_block->keys[mid],
                                                          klog_block->entries[mid].key_size, key,
                                                          key_size, sst->config->comparator_ctx);

                        if (cmp <= 0)
                        {
                            /* this entry is <= target, it's a candidate */
                            best_idx = mid;
                            left = mid + 1; /* search right half for potentially better match */
                        }
                        else
                        {
                            /* this entry is > target, search left half */
                            right = mid - 1;
                        }
                    }

                    /* if we found a match in this block, use it */
                    if (best_idx >= 0)
                    {
                        if (best_match) tidesdb_kv_pair_free(best_match);

                        uint8_t *value = klog_block->inline_values[best_idx];
                        uint8_t *vlog_value = NULL;

                        if (klog_block->entries[best_idx].vlog_offset > 0)
                        {
                            tidesdb_vlog_read_value(sst, klog_block->entries[best_idx].vlog_offset,
                                                    klog_block->entries[best_idx].value_size,
                                                    &vlog_value);
                            value = vlog_value;
                        }

                        best_match = tidesdb_kv_pair_create(
                            klog_block->keys[best_idx], klog_block->entries[best_idx].key_size,
                            value, klog_block->entries[best_idx].value_size,
                            klog_block->entries[best_idx].ttl, klog_block->entries[best_idx].seq,
                            klog_block->entries[best_idx].flags & TDB_KV_FLAG_TOMBSTONE);

                        free(vlog_value);
                        found_in_block = current_block_num;

                        /* we found a valid predecessor, stop here */
                        /* (early termination will catch if next block has better match) */
                        tidesdb_klog_block_free(klog_block);
                        free(decompressed);
                        block_manager_block_release(block);
                        goto found_predecessor;
                    }
                    else if (best_match)
                    {
                        /* all entries in this block are > target, stop */
                        tidesdb_klog_block_free(klog_block);
                        free(decompressed);
                        block_manager_block_release(block);
                        goto found_predecessor;
                    }

                    tidesdb_klog_block_free(klog_block);
                }

                free(decompressed);
                block_manager_block_release(block);
                current_block_num++;

                /* if we found a predecessor that's not the last entry in its block, we're done */
                /* (already handled by goto in binary search above) */
            }

        found_predecessor:
            if (best_match)
            {
                source->current_kv = best_match;
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

    /* get the largest (predecessor) key, skipping invisible entries */
    while (iter->heap->num_sources > 0 && iter->heap->sources[0]->current_kv)
    {
        tidesdb_kv_pair_t *kv = iter->heap->sources[0]->current_kv;

        /* check visibility */
        if (tidesdb_iter_kv_visible(iter, kv))
        {
            /* visible entry found */
            iter->current = tidesdb_kv_pair_create(
                kv->key, kv->entry.key_size, kv->value, kv->entry.value_size, kv->entry.ttl,
                kv->entry.seq, kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);
            iter->valid = 1;
            return TDB_SUCCESS;
        }

        /* not visible, retreat top source and re-heapify */
        tidesdb_merge_source_t *top = iter->heap->sources[0];
        if (tidesdb_merge_source_retreat(top) != TDB_SUCCESS)
        {
            /* source exhausted, remove it */
            top->current_kv = NULL;
        }

        /* sift down from root */
        int current = 0;
        while (current * 2 + 1 < iter->heap->num_sources)
        {
            int largest = current;
            int left = 2 * current + 1;
            int right = 2 * current + 2;

            if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv)
            {
                if (!iter->heap->sources[largest]->current_kv ||
                    iter->heap->comparator(iter->heap->sources[left]->current_kv->key,
                                           iter->heap->sources[left]->current_kv->entry.key_size,
                                           iter->heap->sources[largest]->current_kv->key,
                                           iter->heap->sources[largest]->current_kv->entry.key_size,
                                           iter->heap->comparator_ctx) > 0)
                {
                    largest = left;
                }
            }

            if (right < iter->heap->num_sources && iter->heap->sources[right]->current_kv)
            {
                if (!iter->heap->sources[largest]->current_kv ||
                    iter->heap->comparator(iter->heap->sources[right]->current_kv->key,
                                           iter->heap->sources[right]->current_kv->entry.key_size,
                                           iter->heap->sources[largest]->current_kv->key,
                                           iter->heap->sources[largest]->current_kv->entry.key_size,
                                           iter->heap->comparator_ctx) > 0)
                {
                    largest = right;
                }
            }

            if (largest == current) break;

            tidesdb_merge_source_t *temp = iter->heap->sources[current];
            iter->heap->sources[current] = iter->heap->sources[largest];
            iter->heap->sources[largest] = temp;
            current = largest;
        }

        /* remove exhausted source if needed */
        if (!iter->heap->sources[0]->current_kv)
        {
            tidesdb_merge_source_free(iter->heap->sources[0]);
            iter->heap->sources[0] = iter->heap->sources[iter->heap->num_sources - 1];
            iter->heap->num_sources--;

            /* re-heapify after removal */
            current = 0;
            while (current * 2 + 1 < iter->heap->num_sources)
            {
                int largest = current;
                int left = 2 * current + 1;
                int right = 2 * current + 2;

                if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv)
                {
                    if (!iter->heap->sources[largest]->current_kv ||
                        iter->heap->comparator(
                            iter->heap->sources[left]->current_kv->key,
                            iter->heap->sources[left]->current_kv->entry.key_size,
                            iter->heap->sources[largest]->current_kv->key,
                            iter->heap->sources[largest]->current_kv->entry.key_size,
                            iter->heap->comparator_ctx) > 0)
                    {
                        largest = left;
                    }
                }

                if (right < iter->heap->num_sources && iter->heap->sources[right]->current_kv)
                {
                    if (!iter->heap->sources[largest]->current_kv ||
                        iter->heap->comparator(
                            iter->heap->sources[right]->current_kv->key,
                            iter->heap->sources[right]->current_kv->entry.key_size,
                            iter->heap->sources[largest]->current_kv->key,
                            iter->heap->sources[largest]->current_kv->entry.key_size,
                            iter->heap->comparator_ctx) > 0)
                    {
                        largest = right;
                    }
                }

                if (largest == current) break;

                tidesdb_merge_source_t *temp = iter->heap->sources[current];
                iter->heap->sources[current] = iter->heap->sources[largest];
                iter->heap->sources[largest] = temp;
                current = largest;
            }
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

        /* skip tombstones and expired entries */
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

        iter->current = kv;
        iter->valid = 1;
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
            /* seek to last in skip list */
            if (skip_list_cursor_goto_last(source->source.memtable.cursor) == 0)
            {
                uint8_t *key, *value;
                size_t key_size, value_size;
                time_t ttl;
                uint8_t deleted;

                if (skip_list_cursor_get(source->source.memtable.cursor, &key, &key_size, &value,
                                         &value_size, &ttl, &deleted) == 0)
                {
                    tidesdb_kv_pair_free(source->current_kv);
                    source->current_kv =
                        tidesdb_kv_pair_create(key, key_size, value, value_size, ttl, 0, deleted);
                }
            }
        }
        else
        {
            /* seek to last block in sstable */
            if (block_manager_cursor_goto_last(source->source.sstable.klog_cursor) == 0)
            {
                /* read last data block (skip metadata blocks) */
                uint64_t num_blocks = source->source.sstable.sst->num_klog_blocks;

                /* navigate to last data block */
                block_manager_cursor_goto_first(source->source.sstable.klog_cursor);
                for (uint64_t b = 1; b < num_blocks; b++)
                {
                    block_manager_cursor_next(source->source.sstable.klog_cursor);
                }

                block_manager_block_t *block =
                    block_manager_cursor_read(source->source.sstable.klog_cursor);
                if (block)
                {
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
                                tidesdb_vlog_read_value(source->source.sstable.sst,
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

                    free(decompressed);
                    block_manager_block_release(block);
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

        /* skip tombstones and expired */
        if (!(kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) &&
            (kv->entry.ttl == 0 || kv->entry.ttl >= time(NULL)))
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

    /* get next entry, skipping duplicates of current key */
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

        /* check visibility (isolation, TTL, tombstones) */
        if (!tidesdb_iter_kv_visible(iter, kv))
        {
            tidesdb_kv_pair_free(kv);
            continue;
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
    (void)direction_changed; /* unused but kept for potential logic */

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

    /* retreat only the top source (the one we just returned) */
    if (iter->heap->num_sources > 0)
    {
        tidesdb_merge_source_t *top = iter->heap->sources[0];
        if (tidesdb_merge_source_retreat(top) != TDB_SUCCESS)
        {
            /* source exhausted, mark for removal */
            top->current_kv = NULL;
        }
    }

    /* rebuild heap as max-heap (only if direction changed or always for backward) */
    for (int i = (iter->heap->num_sources / 2) - 1; i >= 0; i--)
    {
        int current = i;
        while (current < iter->heap->num_sources)
        {
            int largest = current;
            int left = 2 * current + 1;
            int right = 2 * current + 2;

            /* for backward iteration, we want MAX heap (largest key first) */
            /* sources with NULL current_kv should sink to bottom */
            if (left < iter->heap->num_sources && iter->heap->sources[left]->current_kv)
            {
                if (!iter->heap->sources[largest]->current_kv)
                {
                    /* left has valid key, largest doesn't -- left is larger */
                    largest = left;
                }
                else
                {
                    /* both have valid keys, compare them */
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
                    /* right has valid key, largest doesn't -- right is larger */
                    largest = right;
                }
                else
                {
                    /* both have valid keys, compare them */
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

    /* get the largest (previous) key */
    while (iter->heap->num_sources > 0)
    {
        tidesdb_merge_source_t *top = iter->heap->sources[0];

        if (!top->current_kv)
        {
            tidesdb_merge_source_free(top);
            iter->heap->sources[0] = iter->heap->sources[iter->heap->num_sources - 1];
            iter->heap->num_sources--;
            continue;
        }

        tidesdb_kv_pair_t *kv = top->current_kv;

        /* skip if same key as current */
        if (current_key && current_key_size == kv->entry.key_size &&
            memcmp(current_key, kv->key, current_key_size) == 0)
        {
            tidesdb_merge_source_retreat(top);
            /* re-heapify */
            int current = 0;
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
            continue;
        }

        /* skip tombstones and expired entries */
        if ((kv->entry.flags & TDB_KV_FLAG_TOMBSTONE) ||
            (kv->entry.ttl > 0 && kv->entry.ttl < time(NULL)))
        {
            tidesdb_merge_source_retreat(top);
            /* re-heapify */
            int current = 0;
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
            continue;
        }

        /* found valid entry */
        free(current_key);
        iter->current = tidesdb_kv_pair_create(kv->key, kv->entry.key_size, kv->value,
                                               kv->entry.value_size, kv->entry.ttl, kv->entry.seq,
                                               kv->entry.flags & TDB_KV_FLAG_TOMBSTONE);

        iter->valid = 1;
        return TDB_SUCCESS;
    }

    free(current_key);
    iter->valid = 0;
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

    *key_size = iter->current->entry.key_size;

    if (*key_size == 0)
    {
        *key = NULL;
        return TDB_SUCCESS;
    }

    *key = malloc(*key_size);
    if (!*key) return TDB_ERR_MEMORY;

    memcpy(*key, iter->current->key, *key_size);

    return TDB_SUCCESS;
}

int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    if (!iter->valid || !iter->current) return TDB_ERR_INVALID_ARGS;

    *value_size = iter->current->entry.value_size;

    if (*value_size == 0)
    {
        *value = NULL;
        return TDB_SUCCESS;
    }

    *value = malloc(*value_size);
    if (!*value) return TDB_ERR_MEMORY;

    memcpy(*value, iter->current->value, *value_size);

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

    /* recover from each WAL file */
    while (!queue_is_empty(wal_files))
    {
        char *wal_path = queue_dequeue(wal_files);
        if (!wal_path) continue;

        skip_list_t *recovered_memtable = NULL;
        int recover_result = tidesdb_wal_recover(cf, wal_path, &recovered_memtable);

        if (recover_result == TDB_SUCCESS && recovered_memtable)
        {
            if (skip_list_count_entries(recovered_memtable) > 0)
            {
                uint64_t sst_id =
                    atomic_fetch_add_explicit(&cf->next_sstable_id, 1, memory_order_relaxed);
                char sst_path[TDB_MAX_PATH_LEN];
                snprintf(sst_path, sizeof(sst_path), "%s" PATH_SEPARATOR TDB_LEVEL_PREFIX "1",
                         cf->directory);

                tidesdb_sstable_t *sst = tidesdb_sstable_create(sst_path, sst_id, &cf->config);
                if (sst)
                {
                    if (tidesdb_sstable_write_from_memtable(sst, recovered_memtable) == TDB_SUCCESS)
                    {
                        tidesdb_level_add_sstable(cf->levels[0], sst);
                        /* release our reference, the level now owns it */
                        tidesdb_sstable_unref(sst);
                    }
                    else
                    {
                        tidesdb_sstable_unref(sst);
                    }
                }
            }

            skip_list_free(recovered_memtable);
        }
        else if (recovered_memtable)
        {
            /* recovery failed but memtable was allocated */
            skip_list_free(recovered_memtable);
        }

        /* delete WAL only if recovery succeeded */
        if (recover_result == TDB_SUCCESS)
        {
            unlink(wal_path);
        }
        free(wal_path);
    }

    queue_free(wal_files);

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
                    if (tidesdb_sstable_load(sst) == TDB_SUCCESS)
                    {
                        /* ensure level exists */
                        int current_levels = atomic_load(&cf->num_levels);
                        while (current_levels < level_num)
                        {
                            if (tidesdb_add_level(cf) != TDB_SUCCESS) break;
                            current_levels = atomic_load(&cf->num_levels);
                        }

                        if (level_num <= current_levels)
                        {
                            tidesdb_level_add_sstable(cf->levels[level_num - 1], sst);
                            /* release our reference, the level now owns it */
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

    /* scan database directory for column family directories */
    DIR *dir = opendir(db->db_path);
    if (!dir) return TDB_ERR_IO;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        /* skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        /* check if entry is a directory using stat() for Windows compatibility */
        char full_path[MAX_FILE_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s%s%s", db->db_path, PATH_SEPARATOR,
                 entry->d_name);

        struct STAT_STRUCT st;
        if (STAT_FUNC(full_path, &st) == 0 && S_ISDIR(st.st_mode))
        {
            /* found a potential column family directory */
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, entry->d_name);

            /* if CF doesn't exist yet, create it */
            if (!cf)
            {
                tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
                if (tidesdb_create_column_family(db, entry->d_name, &config) == TDB_SUCCESS)
                {
                    cf = tidesdb_get_column_family(db, entry->d_name);
                }
            }

            /* recover the column family if we have it */
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

    (*stats)->total_writes = atomic_load(&cf->total_writes);
    (*stats)->total_reads = atomic_load(&cf->total_reads);
    (*stats)->compaction_count = atomic_load(&cf->compaction_count);
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
        (*stats)->level_num_sstables[i] = atomic_load(&cf->levels[i]->num_sstables);
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
        else if (strcmp(value, "SERIALIZABLE") == 0)
            ctx->config->default_isolation_level = TDB_ISOLATION_SERIALIZABLE;
    }

    return 1; /* continue parsing */
}

int tidesdb_cf_config_load_from_ini(const char *ini_file, const char *section_name,
                                    tidesdb_column_family_config_t *config)
{
    if (!ini_file || !section_name || !config) return TDB_ERR_INVALID_ARGS;

    /* start with defaults */
    *config = tidesdb_default_column_family_config();

    /* parse INI file */
    ini_config_context_t ctx = {.config = config, .target_section = section_name};

    int result = ini_parse(ini_file, ini_config_handler, &ctx);
    if (result < 0)
    {
        return TDB_ERR_IO; /* failed to open or parse */
    }
    else if (result > 0)
    {
        return TDB_ERR_CORRUPTION; /* parse error on line <result> */
    }

    return TDB_SUCCESS;
}

int tidesdb_cf_config_save_to_ini(const char *ini_file, const char *section_name,
                                  const tidesdb_column_family_config_t *config)
{
    if (!ini_file || !section_name || !config) return TDB_ERR_INVALID_ARGS;

    FILE *fp = fopen(ini_file, "w");
    if (!fp) return TDB_ERR_IO;

    /* write section header */
    fprintf(fp, "[%s]\n", section_name);

    /* write all configuration fields */
    fprintf(fp, "write_buffer_size = %zu\n", config->write_buffer_size);
    fprintf(fp, "level_size_ratio = %zu\n", config->level_size_ratio);
    fprintf(fp, "max_levels = %d\n", config->max_levels);
    fprintf(fp, "dividing_level_offset = %d\n", config->dividing_level_offset);
    fprintf(fp, "klog_block_size = %zu\n", config->klog_block_size);
    fprintf(fp, "vlog_block_size = %zu\n", config->vlog_block_size);
    fprintf(fp, "value_threshold = %zu\n", config->value_threshold);

    /* write compression algorithm */
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

    /* write isolation level */
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

    pthread_rwlock_wrlock(&cf->cf_lock);

    /* compaction settings, can be changed at runtime */
    cf->config.compaction_interval_ms = new_config->compaction_interval_ms;
    cf->config.enable_background_compaction = new_config->enable_background_compaction;

    /* bloom filter settings affects new ssts only */
    cf->config.enable_bloom_filter = new_config->enable_bloom_filter;
    cf->config.bloom_fpr = new_config->bloom_fpr;

    /* block index settings affects new ssts only */
    cf->config.enable_block_indexes = new_config->enable_block_indexes;
    cf->config.index_sample_ratio = new_config->index_sample_ratio;

    /* compression affects new writes */
    cf->config.compression_algorithm = new_config->compression_algorithm;

    /* write buffer size affects when next flush happens */
    cf->config.write_buffer_size = new_config->write_buffer_size;

    /* level configuration affects future compactions */
    cf->config.level_size_ratio = new_config->level_size_ratio;
    cf->config.dividing_level_offset = new_config->dividing_level_offset;

    /* sync mode affects new writes */
    cf->config.sync_mode = new_config->sync_mode;

    /* transaction isolation default */
    cf->config.default_isolation_level = new_config->default_isolation_level;

    /* value threshold affects future writes */
    cf->config.value_threshold = new_config->value_threshold;

    /* what cannot be changed at runtime?
     * -- skip_list_max_level, skip_list_probability -- would affect active memtable structure
     * -- klog_block_size, vlog_block_size -- would break existing SSTable format
     * -- block_manager_cache_size -- would require recreating cache
     * -- comparator -- would break key ordering in existing data
     * these settings are fixed at column family creation time */

    pthread_rwlock_unlock(&cf->cf_lock);

    /* persist to disk if requested */
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
