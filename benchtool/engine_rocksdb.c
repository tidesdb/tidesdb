/*
 * Copyright 2024 Alex Gaetano Padula (TidesDB)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include <string.h>

#include "benchmark.h"

#ifdef HAVE_ROCKSDB
#include <rocksdb/c.h>
typedef struct
{
    rocksdb_t *db;
    rocksdb_options_t *options;
    rocksdb_readoptions_t *roptions;
    rocksdb_writeoptions_t *woptions;
    rocksdb_cache_t *cache;
    rocksdb_block_based_table_options_t *table_options;
    rocksdb_filterpolicy_t *filter_policy;
} rocksdb_handle_t;

typedef struct
{
    rocksdb_writebatch_t *batch;
    rocksdb_handle_t *handle;
} rocksdb_batch_context_t;

static const storage_engine_ops_t rocksdb_ops;

static int rocksdb_open_impl(storage_engine_t **engine, const char *path,
                             const benchmark_config_t *config)
{
    *engine = malloc(sizeof(storage_engine_t));
    if (!*engine) return -1;

    rocksdb_handle_t *handle = malloc(sizeof(rocksdb_handle_t));
    if (!handle)
    {
        free(*engine);
        return -1;
    }

    handle->options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(handle->options, 1);

    /* match TidesDB compression settings */
    rocksdb_options_set_compression(handle->options, rocksdb_lz4_compression);

    /* use configurable block cache size or default to 64 MB */
    size_t cache_size =
        config->block_cache_size > 0 ? config->block_cache_size : 64 * (1024 * 1024);
    handle->cache = rocksdb_cache_create_hyper_clock(cache_size, 0);
    handle->table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(handle->table_options, handle->cache);

    /* use configurable bloom filter setting or default to enabled */
    int use_bloom = config->enable_bloom_filter >= 0 ? config->enable_bloom_filter : 1;
    if (use_bloom)
    {
        handle->filter_policy = rocksdb_filterpolicy_create_bloom(10);
        rocksdb_block_based_options_set_filter_policy(handle->table_options, handle->filter_policy);
    }
    else
    {
        handle->filter_policy = NULL;
    }

    /* use configurable block indexes setting or default to binary search */
    int use_indexes = config->enable_block_indexes >= 0 ? config->enable_block_indexes : 1;
    if (use_indexes)
    {
        rocksdb_block_based_options_set_index_type(
            handle->table_options, rocksdb_block_based_table_index_type_binary_search);
    }

    /* pin L0 index and filter blocks in cache for faster access */
    rocksdb_block_based_options_set_pin_l0_filter_and_index_blocks_in_cache(handle->table_options,
                                                                            1);

    rocksdb_options_set_block_based_table_factory(handle->options, handle->table_options);

    /* use configurable memtable size or default to 64 MB */
    size_t memtable_size = config->memtable_size > 0 ? config->memtable_size : 64 * (1024 * 1024);
    rocksdb_options_set_write_buffer_size(handle->options, memtable_size);

    /* match TidesDB thread configuration */
    rocksdb_options_set_max_background_jobs(handle->options, 8); /* 4 flush + 4 compaction */

    /* use configurable BlobDB setting or default to disabled */
    int use_blobdb = config->enable_blobdb >= 0 ? config->enable_blobdb : 0;
    if (use_blobdb)
    {
        rocksdb_options_set_enable_blob_files(handle->options, 1);
        rocksdb_options_set_min_blob_size(handle->options, config->klog_value_threshold);
        rocksdb_options_set_blob_file_size(handle->options,
                                           256 * 1024 * 1024); /* 256MB blob files */
        rocksdb_options_set_blob_compression_type(handle->options, rocksdb_lz4_compression);
        rocksdb_options_set_enable_blob_gc(handle->options, 1);
        rocksdb_options_set_blob_gc_age_cutoff(handle->options, 0.25); /* GC blobs older than 25% */
    }

    handle->roptions = rocksdb_readoptions_create();
    handle->woptions = rocksdb_writeoptions_create();

    /* sync mode will be set based on benchmark config */
    rocksdb_writeoptions_set_sync(handle->woptions, 0);

    char *err = NULL;
    handle->db = rocksdb_open(handle->options, path, &err);
    if (err)
    {
        free(err);
        rocksdb_options_destroy(handle->options);
        rocksdb_readoptions_destroy(handle->roptions);
        rocksdb_writeoptions_destroy(handle->woptions);
        free(handle);
        free(*engine);
        return -1;
    }

    (*engine)->handle = handle;
    (*engine)->ops = &rocksdb_ops;
    return 0;
}

static int rocksdb_close_impl(storage_engine_t *engine)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    rocksdb_close(handle->db);
    rocksdb_options_destroy(handle->options);
    rocksdb_readoptions_destroy(handle->roptions);
    rocksdb_writeoptions_destroy(handle->woptions);
    /* table_options owns cache and filter_policy, so destroying it will clean them up */
    if (handle->table_options) rocksdb_block_based_options_destroy(handle->table_options);
    free(handle);
    free(engine);
    return 0;
}

/* helper to set sync mode dynamically */
static void rocksdb_set_sync_mode(storage_engine_t *engine, int sync_enabled)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    rocksdb_writeoptions_set_sync(handle->woptions, sync_enabled);
}

static int rocksdb_put_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size,
                            const uint8_t *value, size_t value_size)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    char *err = NULL;

    rocksdb_put(handle->db, handle->woptions, (const char *)key, key_size, (const char *)value,
                value_size, &err);

    if (err)
    {
        free(err);
        return -1;
    }
    return 0;
}

static int rocksdb_get_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size,
                            uint8_t **value, size_t *value_size)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    char *err = NULL;

    char *val =
        rocksdb_get(handle->db, handle->roptions, (const char *)key, key_size, value_size, &err);

    if (err)
    {
        free(err);
        return -1;
    }

    if (!val) return -1;

    *value = (uint8_t *)val;
    return 0;
}

static int rocksdb_del_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    char *err = NULL;

    rocksdb_delete(handle->db, handle->woptions, (const char *)key, key_size, &err);

    if (err)
    {
        free(err);
        return -1;
    }
    return 0;
}

static int rocksdb_batch_begin_impl(storage_engine_t *engine, void **batch_ctx)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;

    rocksdb_batch_context_t *ctx = malloc(sizeof(rocksdb_batch_context_t));
    if (!ctx) return -1;

    ctx->batch = rocksdb_writebatch_create();
    if (!ctx->batch)
    {
        free(ctx);
        return -1;
    }

    ctx->handle = handle;
    *batch_ctx = ctx;
    return 0;
}

static int rocksdb_batch_put_impl(void *batch_ctx, storage_engine_t *engine, const uint8_t *key,
                                  size_t key_size, const uint8_t *value, size_t value_size)
{
    (void)engine; /* unused - we have it in ctx */
    rocksdb_batch_context_t *ctx = (rocksdb_batch_context_t *)batch_ctx;
    rocksdb_writebatch_put(ctx->batch, (const char *)key, key_size, (const char *)value,
                           value_size);
    return 0;
}

static int rocksdb_batch_delete_impl(void *batch_ctx, storage_engine_t *engine, const uint8_t *key,
                                     size_t key_size)
{
    (void)engine; /* unused - we have it in ctx */
    rocksdb_batch_context_t *ctx = (rocksdb_batch_context_t *)batch_ctx;
    rocksdb_writebatch_delete(ctx->batch, (const char *)key, key_size);
    return 0;
}

static int rocksdb_batch_commit_impl(void *batch_ctx)
{
    rocksdb_batch_context_t *ctx = (rocksdb_batch_context_t *)batch_ctx;
    char *err = NULL;

    rocksdb_write(ctx->handle->db, ctx->handle->woptions, ctx->batch, &err);

    rocksdb_writebatch_destroy(ctx->batch);
    free(ctx);

    if (err)
    {
        free(err);
        return -1;
    }
    return 0;
}

static int rocksdb_iter_new_impl(storage_engine_t *engine, void **iter)
{
    rocksdb_handle_t *handle = (rocksdb_handle_t *)engine->handle;
    *iter = rocksdb_create_iterator(handle->db, handle->roptions);
    return *iter ? 0 : -1;
}

static int rocksdb_iter_seek_to_first_impl(void *iter)
{
    rocksdb_iter_seek_to_first((rocksdb_iterator_t *)iter);
    return 0;
}

static int rocksdb_iter_seek_impl(void *iter, const uint8_t *key, size_t key_size)
{
    rocksdb_iter_seek((rocksdb_iterator_t *)iter, (const char *)key, key_size);
    return 0;
}

static int rocksdb_iter_valid_impl(void *iter)
{
    return rocksdb_iter_valid((rocksdb_iterator_t *)iter) ? 1 : 0;
}

static int rocksdb_iter_next_impl(void *iter)
{
    rocksdb_iter_next((rocksdb_iterator_t *)iter);
    return 0;
}

static int rocksdb_iter_key_impl(void *iter, uint8_t **key, size_t *key_size)
{
    *key = (uint8_t *)rocksdb_iter_key((rocksdb_iterator_t *)iter, key_size);
    return 0;
}

static int rocksdb_iter_value_impl(void *iter, uint8_t **value, size_t *value_size)
{
    *value = (uint8_t *)rocksdb_iter_value((rocksdb_iterator_t *)iter, value_size);
    return 0;
}

static int rocksdb_iter_free_impl(void *iter)
{
    rocksdb_iter_destroy((rocksdb_iterator_t *)iter);
    return 0;
}

static const storage_engine_ops_t rocksdb_ops = {
    .open = rocksdb_open_impl,
    .close = rocksdb_close_impl,
    .put = rocksdb_put_impl,
    .get = rocksdb_get_impl,
    .del = rocksdb_del_impl,
    .batch_begin = rocksdb_batch_begin_impl,
    .batch_put = rocksdb_batch_put_impl,
    .batch_delete = rocksdb_batch_delete_impl,
    .batch_commit = rocksdb_batch_commit_impl,
    .iter_new = rocksdb_iter_new_impl,
    .iter_seek_to_first = rocksdb_iter_seek_to_first_impl,
    .iter_seek = rocksdb_iter_seek_impl,
    .iter_valid = rocksdb_iter_valid_impl,
    .iter_next = rocksdb_iter_next_impl,
    .iter_key = rocksdb_iter_key_impl,
    .iter_value = rocksdb_iter_value_impl,
    .iter_free = rocksdb_iter_free_impl,
    .set_sync = rocksdb_set_sync_mode,
    .name = "RocksDB"};

const storage_engine_ops_t *get_rocksdb_ops(void)
{
    return &rocksdb_ops;
}

#else

/* stubski */
const storage_engine_ops_t *get_rocksdb_ops(void)
{
    return NULL;
}

#endif /* HAVE_ROCKSDB */
