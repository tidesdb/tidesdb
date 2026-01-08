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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tidesdb/tidesdb.h>

#include "benchmark.h"

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    tidesdb_sync_mode_t sync_mode;
    tidesdb_column_family_config_t cf_config; /* store config to avoid duplication */
} tidesdb_handle_t;

typedef struct
{
    tidesdb_iter_t *iter;
    tidesdb_txn_t *txn; /* read-only transaction for consistent iteration */
} tidesdb_iter_wrapper_t;

static const storage_engine_ops_t tidesdb_ops;

static int tidesdb_open_impl(storage_engine_t **engine, const char *path,
                             const benchmark_config_t *config)
{
    *engine = malloc(sizeof(storage_engine_t));
    if (!*engine) return -1;

    tidesdb_handle_t *handle = malloc(sizeof(tidesdb_handle_t));
    if (!handle)
    {
        free(*engine);
        return -1;
    }

    tidesdb_config_t tdb_config = tidesdb_default_config();
    tdb_config.db_path = (char *)path; /* tidesdb_open makes its own copy */

    /** because we are using 1 column family, we don't really need many threads as flushes and
    compactions are done serially, the only time it parallelizes is when there are many column
    families flushing and compacting */
    tdb_config.num_flush_threads = 1;
    tdb_config.num_compaction_threads = 1;
    tdb_config.log_level = TDB_LOG_NONE;

    tdb_config.block_cache_size =
        config->block_cache_size > 0 ? config->block_cache_size : 64 * (1024 * 1024);

    if (tidesdb_open(&tdb_config, &handle->db) != 0)
    {
        free(handle);
        free(*engine);
        return -1;
    }

    handle->cf_config = tidesdb_default_column_family_config();
    handle->cf_config.compression_algorithm = LZ4_COMPRESSION;
    handle->cf_config.bloom_fpr = config->bloom_fpr;
    handle->cf_config.l0_queue_stall_threshold = config->l0_queue_stall_threshold;
    handle->cf_config.l1_file_count_trigger = config->l1_file_count_trigger;
    handle->cf_config.dividing_level_offset = config->dividing_level_offset;
    handle->cf_config.min_levels = config->min_levels;
    handle->cf_config.index_sample_ratio = config->index_sample_ratio;
    handle->cf_config.block_index_prefix_len = config->block_index_prefix_len;
    handle->cf_config.klog_value_threshold = config->klog_value_threshold;

    /* use configurable bloom filter setting or default to enabled */
    handle->cf_config.enable_bloom_filter =
        config->enable_bloom_filter >= 0 ? config->enable_bloom_filter : 1;

    /* use configurable block indexes setting or default to enabled */
    handle->cf_config.enable_block_indexes =
        config->enable_block_indexes >= 0 ? config->enable_block_indexes : 1;

    handle->cf_config.index_sample_ratio = 1;

    handle->cf_config.sync_mode = TDB_SYNC_NONE; /* default */

    handle->cf_config.write_buffer_size =
        config->memtable_size > 0 ? config->memtable_size : (size_t)64 * (1024 * 1024);
    if (tidesdb_create_column_family(handle->db, "default", &handle->cf_config) != 0)
    {
        /* column family might already exist, which is fine */
    }

    handle->cf = tidesdb_get_column_family(handle->db, "default");
    if (!handle->cf)
    {
        tidesdb_close(handle->db);
        free(handle);
        free(*engine);
        return -1;
    }

    (*engine)->handle = handle;
    (*engine)->ops = &tidesdb_ops;

    return 0;
}

/* helper to set sync mode dynamically */
static void tidesdb_set_sync_mode(storage_engine_t *engine, int sync_enabled)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    handle->sync_mode = sync_enabled ? TDB_SYNC_FULL : TDB_SYNC_NONE;

    /* update column family config with new sync mode */
    handle->cf_config.sync_mode = handle->sync_mode;

    int result = tidesdb_cf_update_runtime_config(handle->cf, &handle->cf_config, 0);
    if (result != 0)
    {
        fprintf(stderr, "Warning: Failed to update sync mode to %s\n",
                sync_enabled ? "FULL" : "NONE");
    }
}

static int tidesdb_close_impl(storage_engine_t *engine)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    /* tidesdb_close() frees db_path internally, so we don't free it here */
    tidesdb_close(handle->db);
    free(handle);
    free(engine);
    return 0;
}

static int tidesdb_put_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size,
                            const uint8_t *value, size_t value_size)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(handle->db, &txn) != 0) return -1;
    int result = tidesdb_txn_put(txn, handle->cf, key, key_size, value, value_size, 0);
    if (result == 0) result = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    return result;
}

static int tidesdb_get_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size,
                            uint8_t **value, size_t *value_size)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(handle->db, &txn) != 0) return -1;
    int result = tidesdb_txn_get(txn, handle->cf, key, key_size, value, value_size);
    tidesdb_txn_free(txn);

    return result;
}

static int tidesdb_del_impl(storage_engine_t *engine, const uint8_t *key, size_t key_size)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(handle->db, &txn) != 0) return -1;
    int result = tidesdb_txn_delete(txn, handle->cf, key, key_size);
    if (result == 0) result = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    return result;
}

static int tidesdb_batch_begin_impl(storage_engine_t *engine, void **batch_ctx)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = NULL;

    if (tidesdb_txn_begin(handle->db, &txn) != 0) return -1;

    *batch_ctx = txn;
    return 0;
}

static int tidesdb_batch_put_impl(void *batch_ctx, storage_engine_t *engine, const uint8_t *key,
                                  size_t key_size, const uint8_t *value, size_t value_size)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = (tidesdb_txn_t *)batch_ctx;

    return tidesdb_txn_put(txn, handle->cf, key, key_size, value, value_size, 0);
}

static int tidesdb_batch_commit_impl(void *batch_ctx)
{
    tidesdb_txn_t *txn = (tidesdb_txn_t *)batch_ctx;

    int result = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    return result;
}

static int tidesdb_batch_delete_impl(void *batch_ctx, storage_engine_t *engine, const uint8_t *key,
                                     size_t key_size)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;
    tidesdb_txn_t *txn = (tidesdb_txn_t *)batch_ctx;

    return tidesdb_txn_delete(txn, handle->cf, key, key_size);
}

static int tidesdb_iter_new_impl(storage_engine_t *engine, void **iter)
{
    tidesdb_handle_t *handle = (tidesdb_handle_t *)engine->handle;

    /* allocate wrapper to hold both iterator and transaction */
    tidesdb_iter_wrapper_t *wrapper = malloc(sizeof(tidesdb_iter_wrapper_t));
    if (!wrapper) return -1;

    /* create a fresh read-only transaction for this iteration */
    if (tidesdb_txn_begin(handle->db, &wrapper->txn) != 0)
    {
        free(wrapper);
        return -1;
    }

    /* create iterator from the transaction for the specific CF */
    if (tidesdb_iter_new(wrapper->txn, handle->cf, &wrapper->iter) != 0)
    {
        tidesdb_txn_free(wrapper->txn);
        free(wrapper);
        return -1;
    }

    *iter = wrapper;
    return 0;
}

static int tidesdb_iter_seek_to_first_impl(void *iter)
{
    if (!iter) return -1;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return -1;
    return tidesdb_iter_seek_to_first(wrapper->iter);
}

static int tidesdb_iter_seek_impl(void *iter, const uint8_t *key, size_t key_size)
{
    if (!iter) return -1;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return -1;
    return tidesdb_iter_seek(wrapper->iter, key, key_size);
}

static int tidesdb_iter_valid_impl(void *iter)
{
    if (!iter) return 0;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return 0;
    return tidesdb_iter_valid(wrapper->iter);
}

static int tidesdb_iter_next_impl(void *iter)
{
    if (!iter) return -1;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return -1;
    return tidesdb_iter_next(wrapper->iter);
}

static int tidesdb_iter_key_impl(void *iter, uint8_t **key, size_t *key_size)
{
    if (!iter || !key || !key_size) return -1;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return -1;
    return tidesdb_iter_key(wrapper->iter, key, key_size);
}

static int tidesdb_iter_value_impl(void *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !value || !value_size) return -1;
    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;
    if (!wrapper->iter) return -1;
    return tidesdb_iter_value(wrapper->iter, value, value_size);
}

static int tidesdb_iter_free_impl(void *iter)
{
    if (!iter) return 0;

    tidesdb_iter_wrapper_t *wrapper = (tidesdb_iter_wrapper_t *)iter;

    if (wrapper->iter)
    {
        tidesdb_iter_free(wrapper->iter);
        wrapper->iter = NULL;
    }

    if (wrapper->txn)
    {
        tidesdb_txn_free(wrapper->txn);
        wrapper->txn = NULL;
    }

    free(wrapper);

    return 0;
}

static const storage_engine_ops_t tidesdb_ops = {
    .open = tidesdb_open_impl,
    .close = tidesdb_close_impl,
    .put = tidesdb_put_impl,
    .get = tidesdb_get_impl,
    .del = tidesdb_del_impl,
    .batch_begin = tidesdb_batch_begin_impl,
    .batch_put = tidesdb_batch_put_impl,
    .batch_delete = tidesdb_batch_delete_impl,
    .batch_commit = tidesdb_batch_commit_impl,
    .iter_new = tidesdb_iter_new_impl,
    .iter_seek_to_first = tidesdb_iter_seek_to_first_impl,
    .iter_seek = tidesdb_iter_seek_impl,
    .iter_valid = tidesdb_iter_valid_impl,
    .iter_next = tidesdb_iter_next_impl,
    .iter_key = tidesdb_iter_key_impl,
    .iter_value = tidesdb_iter_value_impl,
    .iter_free = tidesdb_iter_free_impl,
    .set_sync = tidesdb_set_sync_mode,
    .name = "TidesDB"};

const storage_engine_ops_t *get_tidesdb_ops(void)
{
    return &tidesdb_ops;
}
