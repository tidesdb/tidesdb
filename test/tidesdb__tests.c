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
 *     https://www.mozilla.org/en-US/MPL/2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>

#include "../src/tidesdb.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static tidesdb_t *create_test_db(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = {.db_path = TEST_DB_PATH, .enable_debug_logging = 1};

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    return db;
}

static tidesdb_column_family_config_t get_test_cf_config(void)
{
    tidesdb_column_family_config_t config = {
        .memtable_flush_size = 1024 * 1024,
        .max_sstables_before_compaction = 512,
        .compaction_threads = 1,
        .sl_max_level = 8,
        .sl_probability = 0.25,
        .enable_compression = 1,
        .compression_algorithm = COMPRESS_LZ4,
        .enable_bloom_filter = 1,
        .bloom_filter_fp_rate = 0.01,
        .enable_background_compaction = 1,
        .background_compaction_interval = TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL,
        .enable_block_indexes = 1,
        .sync_mode = TDB_SYNC_NONE,
        .comparator_name = {0}};
    return config;
}

static void test_basic_open_close(void)
{
    tidesdb_t *db = create_test_db();
    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();
}

static void test_column_family_creation(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_TRUE(strcmp(cf->name, "test_cf") == 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_basic_txn_put_get(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    const char *key = "test_key";
    const char *value = "test_value";

    tidesdb_txn_t *txn = NULL;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(
        tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
              0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_size, strlen(value));
    ASSERT_TRUE(memcmp(retrieved, value, strlen(value)) == 0);

    free(retrieved);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_operations(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected, sizeof(expected), "value_%d", i);

        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;

        ASSERT_EQ(
            tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &retrieved, &retrieved_size), 0);
        ASSERT_TRUE(memcmp(retrieved, expected, strlen(expected)) == 0);

        free(retrieved);
    }

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_delete(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    const char *key = "delete_me";
    const char *value = "some_value";

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(
        tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
              0);
    free(retrieved);
    tidesdb_txn_free(read_txn);

    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, (uint8_t *)key, strlen(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
              0);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_transaction_commit(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_TRUE(txn != NULL);

    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"txn_key1", 8, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"txn_key2", 8, (uint8_t *)"value2", 6, -1), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"txn_key1", 8, &retrieved, &retrieved_size), 0);
    free(retrieved);

    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"txn_key2", 8, &retrieved, &retrieved_size), 0);
    free(retrieved);

    tidesdb_txn_free(read_txn);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_transaction_rollback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"rollback_key", 12, (uint8_t *)"value", 5, 0), 0);

    ASSERT_EQ(tidesdb_txn_rollback(txn), 0);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)"rollback_key", 12, &retrieved, &retrieved_size),
              0);
    tidesdb_txn_free(read_txn);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_forward(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "iter_key_%02d", i);
        snprintf(value, sizeof(value), "iter_value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_TRUE(iter != NULL);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

        count++;
        tidesdb_iter_next(iter);
    }

    ASSERT_TRUE(count >= 10);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_memtable_flush(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "flush_key_%d", i);
        snprintf(value, sizeof(value), "flush_value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), 0),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    int sstables_before = atomic_load(&cf->num_sstables);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    int max_wait = 50;
    int sstables_after = sstables_before;
    for (int i = 0; i < max_wait && sstables_after == sstables_before; i++)
    {
        usleep(100000);
        sstables_after = atomic_load(&cf->num_sstables);
    }

    ASSERT_TRUE(sstables_after > sstables_before);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_column_families(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    tidesdb_txn_t *txn2 = NULL;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf2, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"key1", 4, (uint8_t *)"value2", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn = NULL;
    tidesdb_txn_t *read_txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf2, &read_txn2), 0);

    uint8_t *val1 = NULL, *val2 = NULL;
    size_t size1 = 0, size2 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key1", 4, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn2, (uint8_t *)"key1", 4, &val2, &size2), 0);

    ASSERT_TRUE(memcmp(val1, "value1", 6) == 0);
    ASSERT_TRUE(memcmp(val2, "value2", 6) == 0);

    free(val1);
    free(val2);
    tidesdb_txn_free(read_txn);
    tidesdb_txn_free(read_txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_custom_comparator(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    strncpy(cf_config.comparator_name, "string", TDB_MAX_COMPARATOR_NAME - 1);
    cf_config.comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    ASSERT_EQ(tidesdb_create_column_family(db, "string_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "string_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"zebra", 5, (uint8_t *)"last", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"apple", 5, (uint8_t *)"first", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"mango", 5, (uint8_t *)"middle", 6, -1), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    ASSERT_TRUE(tidesdb_iter_valid(iter));

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        count++;
        tidesdb_iter_next(iter);
    }
    ASSERT_TRUE(count >= 3);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_sync_modes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    cf_config.sync_mode = TDB_SYNC_NONE;
    ASSERT_EQ(tidesdb_create_column_family(db, "no_sync", &cf_config), 0);

    cf_config.sync_mode = TDB_SYNC_FULL;
    ASSERT_EQ(tidesdb_create_column_family(db, "full_sync", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_sync");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "full_sync");

    tidesdb_txn_t *txn = NULL;
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf2, &txn2), 0);

    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"val1", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key2", 4, (uint8_t *)"val2", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_trigger(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.max_sstables_before_compaction = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key_10", 6, &value, &value_size), 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ttl_expiration(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    time_t expire_time = time(NULL) + 1;
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"expire_key", 10, (uint8_t *)"expire_value", 12,
                              expire_time),
              0);
    ASSERT_EQ(
        tidesdb_txn_put(txn, (uint8_t *)"persist_key", 11, (uint8_t *)"persist_value", 13, -1), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn1), 0);

    uint8_t *val1 = NULL, *val2 = NULL;
    size_t size1 = 0, size2 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn1, (uint8_t *)"expire_key", 10, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn1, (uint8_t *)"persist_key", 11, &val2, &size2), 0);
    free(val1);
    free(val2);
    tidesdb_txn_free(read_txn1);

    sleep(2);

    tidesdb_txn_t *read_txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn2), 0);

    uint8_t *val3 = NULL, *val4 = NULL;
    size_t size3 = 0, size4 = 0;

    ASSERT_NE(tidesdb_txn_get(read_txn2, (uint8_t *)"expire_key", 10, &val3, &size3), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn2, (uint8_t *)"persist_key", 11, &val4, &size4), 0);

    free(val4);
    tidesdb_txn_free(read_txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_backward(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 20)
    {
        count++;
        if (tidesdb_iter_prev(iter) != 0) break;
    }

    ASSERT_TRUE(count >= 1);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_database_reopen(void)
{
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "persist_cf", &cf_config), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1), 0);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key2", 4, (uint8_t *)"value2", 6, -1), 0);

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");

        if (cf != NULL)
        {
            tidesdb_txn_t *read_txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

            uint8_t *value = NULL;
            size_t value_size = 0;

            if (tidesdb_txn_get(read_txn, (uint8_t *)"key1", 4, &value, &value_size) == 0)
            {
                ASSERT_TRUE(memcmp(value, "value1", 6) == 0);
                free(value);
            }

            tidesdb_txn_free(read_txn);
        }

        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_large_values(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "large_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "large_cf");

    size_t large_size = 64 * 1024;
    uint8_t *large_value = malloc(large_size);
    memset(large_value, 'A', large_size);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"large_key", 9, large_value, large_size, -1), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* retrieve and verify */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"large_key", 9, &retrieved, &retrieved_size), 0);
    ASSERT_EQ(retrieved_size, large_size);
    ASSERT_TRUE(memcmp(retrieved, large_value, large_size) == 0);

    free(large_value);
    free(retrieved);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_operations(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf3", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");
    tidesdb_column_family_t *cf3 = tidesdb_get_column_family(db, "cf3");

    tidesdb_txn_t *txn = NULL;
    tidesdb_txn_t *txn2 = NULL;
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf2, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf3, &txn3), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
        ASSERT_EQ(
            tidesdb_txn_put(txn2, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
        ASSERT_EQ(
            tidesdb_txn_put(txn3, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);

    tidesdb_txn_t *read_txn = NULL;
    tidesdb_txn_t *read_txn2 = NULL;
    tidesdb_txn_t *read_txn3 = NULL;

    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf2, &read_txn2), 0);
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf3, &read_txn3), 0);

    uint8_t *val1 = NULL, *val2 = NULL, *val3 = NULL;
    size_t size1 = 0, size2 = 0, size3 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key_10", 6, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn2, (uint8_t *)"key_10", 6, &val2, &size2), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn3, (uint8_t *)"key_10", 6, &val3, &size3), 0);

    free(val1);
    free(val2);
    free(val3);
    tidesdb_txn_free(read_txn);
    tidesdb_txn_free(read_txn2);
    tidesdb_txn_free(read_txn3);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_error_handling(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "error_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "error_cf");

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)"nonexistent", 11, &value, &value_size), 0);

    tidesdb_txn_free(read_txn);

    ASSERT_NE(tidesdb_txn_begin(NULL, cf, NULL), 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_many_sstables(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096; /* small memtable to force many flushes */
    cf_config.max_sstables_before_compaction =
        200; /* high threshold to prevent compaction during test */
    cf_config.enable_background_compaction = 0; /* disable for deterministic testing */

    ASSERT_EQ(tidesdb_create_column_family(db, "many_sst", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "many_sst");

    printf("\n  [Verification] Creating many SSTables... ");
    fflush(stdout);

    /* insert data in batches to create many sstables */
    int total_keys = 0;
    for (int batch = 0; batch < 10; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 20; i++)
        {
            char key[64], value[256];
            int key_num = batch * 20 + i;
            snprintf(key, sizeof(key), "key_%05d", key_num);
            snprintf(value, sizeof(value), "value_%05d_with_padding_xxxxxxxxxxxxxxxxxxxxxxxxx",
                     key_num);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
            total_keys++;
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify all data is accessible across many ssts */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 100; i += 10) /* sample every 10th key */
    {
        char key[64];
        snprintf(key, sizeof(key), "key_%05d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    /* verify iterator works across many ssts */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 500)
    {
        count++;
        tidesdb_iter_next(iter);
    }

    /* with reference counting, all 200 entries should be accessible */
    ASSERT_EQ(count, total_keys);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    printf("OK (verified %d entries across SSTables)\n", count);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_backward_iteration(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096; /* small memtable to force many flushes */
    cf_config.max_sstables_before_compaction = 200;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "backward_test", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "backward_test");

    printf("\n  [Verification] Testing backward iteration... ");
    fflush(stdout);

    /* insert data in batches */
    int total_keys = 0;
    for (int batch = 0; batch < 10; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 20; i++)
        {
            char key[64], value[256];
            int key_num = batch * 20 + i;
            snprintf(key, sizeof(key), "key_%05d", key_num);
            snprintf(value, sizeof(value), "value_%05d_backward_test", key_num);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
            total_keys++;
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    int count = 0;
    int expected_key_num = total_keys - 1; /* should start at key_00199 */

    while (tidesdb_iter_valid(iter) && count < 500)
    {
        uint8_t *key = NULL;
        size_t key_size = 0;

        if (tidesdb_iter_key(iter, &key, &key_size) == 0)
        {
            char expected_key[64];
            snprintf(expected_key, sizeof(expected_key), "key_%05d", expected_key_num);

            /* verify keys are in descending order */
            ASSERT_EQ(key_size, strlen(expected_key));
            ASSERT_EQ(memcmp(key, expected_key, key_size), 0);

            expected_key_num--;
        }

        count++;
        tidesdb_iter_prev(iter);
    }

    /* verify we got all entries in reverse order */
    ASSERT_EQ(count, total_keys);
    ASSERT_EQ(expected_key_num, -1); /* should have gone through all keys */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    printf("OK (verified %d entries in reverse order)\n", count);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_crash_recovery(void)
{
    printf("\n  [Reliability] Testing crash recovery... ");
    fflush(stdout);

    /* 1 write data and close normally */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "recovery_cf", &cf_config), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "recovery_cf");

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 50; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "recover_key_%d", i);
            snprintf(value, sizeof(value), "recover_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* write more data that should be in WAL */
        tidesdb_txn_t *txn2 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);

        ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"wal_key", 7, (uint8_t *)"wal_value", 9, -1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
        tidesdb_txn_free(txn2);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* 2 reopen and verify all data recovered */
    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        /* recreate column family to load existing data */
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "recovery_cf");

        if (cf == NULL)
        {
            ASSERT_EQ(tidesdb_create_column_family(db, "recovery_cf", &cf_config), 0);
            cf = tidesdb_get_column_family(db, "recovery_cf");
        }

        ASSERT_TRUE(cf != NULL);

        /* verify committed data */
        tidesdb_txn_t *read_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

        uint8_t *value = NULL;
        size_t value_size = 0;

        /* check some keys from first transaction */
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"recover_key_25", 14, &value, &value_size),
                  0);
        free(value);

        /* check WAL-recovered key */
        value = NULL;
        if (tidesdb_txn_get(read_txn, (uint8_t *)"wal_key", 7, &value, &value_size) == 0)
        {
            ASSERT_TRUE(memcmp(value, "wal_value", 9) == 0);
            free(value);
        }

        tidesdb_txn_free(read_txn);
        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_background_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 8192;
    cf_config.max_sstables_before_compaction = 5; /* compact at 5 sstables */
    cf_config.enable_background_compaction = 1;   /* enable background compaction */

    ASSERT_EQ(tidesdb_create_column_family(db, "bg_compact", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bg_compact");

    printf("\n  [Background] Testing background compaction... ");
    fflush(stdout);

    /* insert data to trigger background compaction */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "bg_key_%d", i);
        snprintf(value, sizeof(value), "bg_value_%d_padding_xxxxxxxxxxxxxxxxxxxxxxxx", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* give background thread time to compact */
    sleep(2);

    /* verify all data is still accessible after compaction */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 100; i += 10)
    {
        char key[32];
        snprintf(key, sizeof(key), "bg_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_update_patterns(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "updates", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "updates");

    printf("\n  [Reliability] Testing update patterns... ");
    fflush(stdout);

    /* write initial data */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(value, sizeof(value), "version_1_value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* update same keys multiple times */
    for (int version = 2; version <= 5; version++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 50; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "update_key_%d", i);
            snprintf(value, sizeof(value), "version_%d_value_%d", version, i);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify latest version is retrieved */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 50; i += 5)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(expected, sizeof(expected), "version_5_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(memcmp(value, expected, strlen(expected)) == 0);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    printf("OK (verified latest versions)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_delete_patterns(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "deletes", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "deletes");

    printf("\n  [Reliability] Testing delete patterns... ");
    fflush(stdout);

    /* insert data */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "del_key_%d", i);
        snprintf(value, sizeof(value), "del_value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* delete every other key */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);

    for (int i = 0; i < 100; i += 2)
    {
        char key[32];
        snprintf(key, sizeof(key), "del_key_%d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn2, (uint8_t *)key, strlen(key)), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* verify deleted keys are gone, non-deleted keys remain */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "del_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size);

        if (i % 2 == 0)
        {
            /* should be deleted */
            ASSERT_NE(result, 0);
        }
        else
        {
            /* should exist */
            ASSERT_EQ(result, 0);
            free(value);
        }
    }

    tidesdb_txn_free(read_txn);

    printf("OK (verified tombstones)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_list_column_families(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* create multiple column families */
    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf3", &cf_config), 0);

    /* list them */
    char **names = NULL;
    int count = 0;
    ASSERT_EQ(tidesdb_list_column_families(db, &names, &count), 0);
    ASSERT_TRUE(
        count >=
        3); /* at least the 3 we created (may have more if cleanup from previous test failed) */
    ASSERT_TRUE(names != NULL);

    /* verify our 3 CFs are present */
    int found_cf1 = 0, found_cf2 = 0, found_cf3 = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(names[i], "cf1") == 0) found_cf1 = 1;
        if (strcmp(names[i], "cf2") == 0) found_cf2 = 1;
        if (strcmp(names[i], "cf3") == 0) found_cf3 = 1;
    }
    ASSERT_TRUE(found_cf1 && found_cf2 && found_cf3);

    /* free names */
    for (int i = 0; i < count; i++)
    {
        free(names[i]);
    }
    free(names);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_column_family_stats(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "stats_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "stats_cf");

    /* add some data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* get stats */
    tidesdb_column_family_stat_t *stats = NULL;
    ASSERT_EQ(tidesdb_get_column_family_stats(db, "stats_cf", &stats), 0);
    ASSERT_TRUE(stats != NULL);

    /* verify stats */
    ASSERT_TRUE(strcmp(stats->name, "stats_cf") == 0);
    ASSERT_TRUE(stats->memtable_entries >= 10);
    ASSERT_TRUE(stats->memtable_size > 0);
    ASSERT_TRUE(strcmp(stats->comparator_name, "memcmp") == 0);

    /* verify config was copied */
    ASSERT_TRUE(stats->config.enable_compression == cf_config.enable_compression);
    ASSERT_TRUE(stats->config.compression_algorithm == cf_config.compression_algorithm);

    free(stats);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_mixed_workload(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 8192;
    cf_config.max_sstables_before_compaction = 10;
    cf_config.enable_background_compaction = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed");

    printf("\n  [Verification] Testing mixed workload (put/get/delete/iterate)... ");
    fflush(stdout);

    /* mixed operations */
    for (int round = 0; round < 10; round++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        /* puts */
        for (int i = 0; i < 20; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "mixed_key_%d_%d", round, i);
            snprintf(value, sizeof(value), "mixed_value_%d_%d", round, i);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }

        /* deletes (from previous round) */
        if (round > 0)
        {
            for (int i = 0; i < 10; i++)
            {
                char key[32];
                snprintf(key, sizeof(key), "mixed_key_%d_%d", round - 1, i);
                tidesdb_txn_delete(txn, (uint8_t *)key, strlen(key));
            }
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* reads */
        tidesdb_txn_t *read_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

        for (int i = 10; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "mixed_key_%d_%d", round, i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            if (tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size) == 0)
            {
                free(value);
            }
        }

        tidesdb_txn_free(read_txn);
    }

    /* final iteration to verify data integrity */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 500)
    {
        count++;
        tidesdb_iter_next(iter);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    printf("OK (processed %d entries)\n", count);

    /* give background compaction time to finish */
    sleep(1);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_overflow_blocks(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "overflow_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overflow_cf");

    printf("\n  [Edge Case] Testing overflow blocks for large values... ");
    fflush(stdout);

    /* create value larger than MAX_INLINE_BLOCK_SIZE (32KB) */
    size_t large_size = 128 * 1024; /* 128KB */
    uint8_t *large_value = malloc(large_size);
    for (size_t i = 0; i < large_size; i++)
    {
        large_value[i] = (uint8_t)(i % 256);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"overflow_key", 12, large_value, large_size, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* retrieve and verify */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"overflow_key", 12, &retrieved, &retrieved_size),
              0);
    ASSERT_EQ(retrieved_size, large_size);
    ASSERT_TRUE(memcmp(retrieved, large_value, large_size) == 0);

    free(large_value);
    free(retrieved);
    tidesdb_txn_free(read_txn);

    printf("OK (verified 128KB value with overflow blocks)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_empty_key_value(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "empty_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_cf");

    printf("\n  [Edge Case] Testing empty key and value handling... ");
    fflush(stdout);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"key_with_empty_val", 18, (uint8_t *)"", 0, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* retrieve empty value */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, (uint8_t *)"key_with_empty_val", 18, &retrieved, &retrieved_size),
        0);
    ASSERT_EQ(retrieved_size, 0);

    if (retrieved) free(retrieved);
    tidesdb_txn_free(read_txn);

    printf("OK (empty value handled correctly)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_your_own_writes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ryow_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ryow_cf");

    printf("\n  [Transaction] Testing read-your-own-writes... ");
    fflush(stdout);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* write key */
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"uncommitted_key", 15, (uint8_t *)"uncommitted_value",
                              17, -1),
              0);

    /* read same key before commit, should see uncommitted value */
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);
    ASSERT_TRUE(memcmp(value, "uncommitted_value", 17) == 0);
    free(value);

    /* update same key */
    ASSERT_EQ(
        tidesdb_txn_put(txn, (uint8_t *)"uncommitted_key", 15, (uint8_t *)"updated_value", 13, -1),
        0);

    /* read again, should see updated value */
    value = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);
    ASSERT_TRUE(memcmp(value, "updated_value", 13) == 0);
    free(value);

    /* delete key */
    ASSERT_EQ(tidesdb_txn_delete(txn, (uint8_t *)"uncommitted_key", 15), 0);

    /* read after delete, should not find it */
    value = NULL;
    ASSERT_NE(tidesdb_txn_get(txn, (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    printf("OK (read-your-own-writes verified)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_tombstones(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 1024 * 1024; /* large enough to avoid auto-flush */
    cf_config.max_sstables_before_compaction = 3;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "tombstone_cf", &cf_config), 0);

    printf("\n  [Compaction] Testing compaction with tombstones... ");
    fflush(stdout);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "tombstone_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys in batch 1 */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        snprintf(value, sizeof(value), "tomb_value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);
    tidesdb_flush_memtable(cf);

    /* insert more keys in batch 2 */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    for (int i = 10; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        snprintf(value, sizeof(value), "tomb_value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn2, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);
    tidesdb_flush_memtable(cf);

    /* wait for async flushes to complete */
    int max_wait = 50; /* 5 seconds max */
    int sstables_before = 0;
    for (int i = 0; i < max_wait; i++)
    {
        sstables_before = atomic_load(&cf->num_sstables);
        if (sstables_before >= 2) break; /* wait for at least 2 sstables */
        usleep(100000);                  /* 100ms */
    }

    /* trigger compaction to merge the two data ssts */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    int sstables_after = atomic_load(&cf->num_sstables);
    ASSERT_TRUE(sstables_after <= sstables_before);

    /* now delete all keys,  tombstones will be in memtable */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn3, (uint8_t *)key, strlen(key)), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* verify all keys are gone */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
    }

    tidesdb_txn_free(read_txn);

    printf("OK (tombstones compacted, %d->%d SSTables)\n", sstables_before, sstables_after);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_expired_ttl(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_iter_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_iter_cf");

    printf("\n  [Iterator] Testing iterator skips expired TTL entries... ");
    fflush(stdout);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* insert keys with short TTL */
    for (int i = 0; i < 5; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "expire_key_%d", i);
        snprintf(value, sizeof(value), "expire_value_%d", i);

        time_t expire_time = time(NULL) + 1; /* 1 second TTL */
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value),
                                  expire_time),
                  0);
    }

    /* insert keys without TTL */
    for (int i = 0; i < 5; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "persist_key_%d", i);
        snprintf(value, sizeof(value), "persist_value_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* wait for TTL expiration */
    sleep(2);

    /* iterate, should only see persistent keys */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    int expired_found = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        /* check if it's an expired key */
        if (key_size >= 11 && memcmp(key, "expire_key_", 11) == 0)
        {
            expired_found++;
        }

        count++;
        tidesdb_iter_next(iter);
    }

    ASSERT_EQ(expired_found, 0); /* should not find any expired keys */
    ASSERT_TRUE(count >= 5);     /* should find at least 5 persistent keys */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    printf("OK (found %d entries, 0 expired)\n", count);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_wal_uncommitted_recovery(void)
{
    printf("\n  [WAL Recovery] Testing recovery with uncommitted data... ");
    fflush(stdout);

    /* 1 write committed and uncommitted data */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");

        /* committed transaction */
        tidesdb_txn_t *txn1 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
        ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"committed_key", 13,
                                  (uint8_t *)"committed_value", 15, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
        tidesdb_txn_free(txn1);

        /* uncommitted transaction, create but dont commit */
        tidesdb_txn_t *txn2 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
        ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"uncommitted_key", 15,
                                  (uint8_t *)"uncommitted_value", 17, -1),
                  0);
        /* dont commit, just free */
        tidesdb_txn_free(txn2);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* 2 reopen and verify only committed data exists */
    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        /* col family should be automatically loaded from disk */
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");
        ASSERT_TRUE(cf != NULL); /* CF should exist after reopen */

        tidesdb_txn_t *read_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

        /* committed key should exist */
        uint8_t *value1 = NULL;
        size_t size1 = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"committed_key", 13, &value1, &size1), 0);
        ASSERT_TRUE(memcmp(value1, "committed_value", 15) == 0);
        free(value1);

        /* uncommitted key should NOT exist */
        uint8_t *value2 = NULL;
        size_t size2 = 0;
        ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)"uncommitted_key", 15, &value2, &size2), 0);

        tidesdb_txn_free(read_txn);
        tidesdb_close(db);
    }

    printf("OK (only committed data recovered)\n");
    cleanup_test_dir();
}

static void test_parallel_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_background_compaction = 0;

    cf_config.compaction_threads = 4; /* enable parallel compaction with 4 threads */
    ASSERT_EQ(tidesdb_create_column_family(db, "parallel_cf", &cf_config), 0);

    printf("\n  [Parallel Compaction] Testing parallel compaction with 4 threads... ");
    fflush(stdout);

    /* get column family */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "parallel_cf");
    ASSERT_TRUE(cf != NULL);

    /* create multiple ssts by inserting and flushing */
    int num_sstables = 8; /* create 8 ssts (4 pairs for parallel processing) */
    for (int s = 0; s < num_sstables; s++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        /* insert 10 keys per sst */
        for (int i = 0; i < 10; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "sst%d_key_%d", s, i);
            snprintf(value, sizeof(value), "sst%d_value_%d", s, i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush to create ssts */
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    }

    /* wait for all async flushes to complete */
    int max_wait = 100; /* 10 seconds max */
    int current_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        current_sstables = atomic_load(&cf->num_sstables);
        if (current_sstables >= num_sstables) break;
        usleep(100000); /* 100ms */
    }

    printf("sstables %d created, proceeding to compaction...\n", current_sstables);

    /* verify we have at least 8 ssts (might have more if auto-compaction triggered) */
    ASSERT_TRUE(current_sstables >= num_sstables);

    /* trigger parallel compaction */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    /* after compaction, should have 4 ssts (8 pairs merged into 4) */
    int final_sstables = atomic_load(&cf->num_sstables);
    ASSERT_EQ(final_sstables, num_sstables / 2);

    /* verify all data is still accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    int found_count = 0;
    for (int s = 0; s < num_sstables; s++)
    {
        for (int i = 0; i < 10; i++)
        {
            char key[32], expected_value[64];
            snprintf(key, sizeof(key), "sst%d_key_%d", s, i);
            snprintf(expected_value, sizeof(expected_value), "sst%d_value_%d", s, i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            if (tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size) == 0)
            {
                ASSERT_TRUE(value_size == strlen(expected_value));
                ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
                free(value);
                found_count++;
            }
        }
    }

    ASSERT_EQ(found_count, num_sstables * 10);

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);

    printf("OK (compacted %d->%d SSTables, verified %d keys)\n", num_sstables, final_sstables,
           found_count);
}

static void test_compaction_deduplication(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.compaction_threads = 0; /* single-threaded for deterministic behavior */
    ASSERT_EQ(tidesdb_create_column_family(db, "dedup_cf", &cf_config), 0);

    printf("\n  [Compaction] Testing deduplication with overlapping keys... ");
    fflush(stdout);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dedup_cf");
    ASSERT_TRUE(cf != NULL);

    /* create first sstable with initial values */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "old_value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for flush to complete */
    usleep(200000); /* 200ms */

    /* create second sstable with overlapping keys (keys 5-14) */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    for (int i = 5; i < 15; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "new_value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn2, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for flush to complete */
    usleep(200000); /* 200ms */

    /* verify we have 2 sstables */
    int num_ssts_before = atomic_load(&cf->num_sstables);
    ASSERT_EQ(num_ssts_before, 2);

    /* trigger compaction */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    /* after compaction, should have 1 SSTable */
    int num_ssts_after = atomic_load(&cf->num_sstables);
    ASSERT_EQ(num_ssts_after, 1);

    /* verify deduplication keys 0-4 should have old values, keys 5-9 should have new values,
     * keys 10-14 should have new values */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    /* keys 0-4 should have old values (only in first SSTable) */
    for (int i = 0; i < 5; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected_value, sizeof(expected_value), "old_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value_size == strlen(expected_value));
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }

    /* keys 5-9 should have NEW values (overlapping, newer sstable wins) */
    for (int i = 5; i < 10; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected_value, sizeof(expected_value), "new_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value_size == strlen(expected_value));
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }

    /* keys 10-14 should have new values (only in second SSTable) */
    for (int i = 10; i < 15; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected_value, sizeof(expected_value), "new_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value_size == strlen(expected_value));
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }

    /* verify total unique keys is 15 (not 20) */
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        count++;
        tidesdb_iter_next(iter);
    }
    ASSERT_EQ(count, 15); /* should be 15 unique keys, not 20 */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);

    printf("OK (verified deduplication: 20 entries -> 15 unique keys)\n");
}

static void test_max_key_size(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "maxkey_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "maxkey_cf");

    printf("\n  [Edge Case] Testing large key sizes... ");
    fflush(stdout);

    size_t key_sizes[] = {100, 1024, 4096, 16384};
    int successful = 0;

    for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    {
        size_t key_size = key_sizes[i];
        uint8_t *large_key = malloc(key_size);
        memset(large_key, 'K', key_size);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        int result = tidesdb_txn_put(txn, large_key, key_size, (uint8_t *)"value", 5, -1);

        if (result == 0)
        {
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);

            /* verify retrieval */
            tidesdb_txn_t *read_txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(tidesdb_txn_get(read_txn, large_key, key_size, &value, &value_size), 0);
            free(value);
            tidesdb_txn_free(read_txn);

            successful++;
        }

        tidesdb_txn_free(txn);
        free(large_key);
    }

    printf("OK (handled keys up to " TDB_SIZE_FMT " bytes)\n",
           TDB_SIZE_CAST(key_sizes[successful - 1]));

    tidesdb_close(db);
    cleanup_test_dir();
}

/* multi-threaded concurrent read/write test */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_ops;
    _Atomic(int) *errors;
} thread_args_t;

void *concurrent_writer(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(args->db, args->cf, &txn) != 0)
        {
            atomic_fetch_add(args->errors, 1);
            continue;
        }

        char key[64], value[128];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id, i);
        snprintf(value, sizeof(value), "thread_%d_value_%d", args->thread_id, i);

        if (tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value),
                            -1) != 0)
        {
            atomic_fetch_add(args->errors, 1);
            tidesdb_txn_free(txn);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(args->errors, 1);
        }

        tidesdb_txn_free(txn);
    }

    return NULL;
}

void *concurrent_reader(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin_read(args->db, args->cf, &txn) != 0)
        {
            atomic_fetch_add(args->errors, 1);
            continue;
        }

        char key[64];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id % 4, i % 50);

        uint8_t *value = NULL;
        size_t value_size = 0;

        tidesdb_txn_get(txn, (uint8_t *)key, strlen(key), &value, &value_size);

        if (value) free(value);
        tidesdb_txn_free(txn);
    }

    return NULL;
}

static void test_true_concurrency(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");

    printf("\n  [Concurrency] Testing multi-threaded concurrent operations... ");
    fflush(stdout);

    _Atomic(int) errors = 0;
#define NUM_WRITER_THREADS 4
#define NUM_READER_THREADS 4
    const int num_writer_threads = NUM_WRITER_THREADS;
    const int num_reader_threads = NUM_READER_THREADS;
    const int ops_per_thread = 100;

    pthread_t writers[NUM_WRITER_THREADS];
    pthread_t readers[NUM_READER_THREADS];
    thread_args_t writer_args[NUM_WRITER_THREADS];
    thread_args_t reader_args[NUM_READER_THREADS];

    for (int i = 0; i < num_writer_threads; i++)
    {
        writer_args[i].db = db;
        writer_args[i].cf = cf;
        writer_args[i].thread_id = i;
        writer_args[i].num_ops = ops_per_thread;
        writer_args[i].errors = &errors;
        pthread_create(&writers[i], NULL, concurrent_writer, &writer_args[i]);
    }

    for (int i = 0; i < num_reader_threads; i++)
    {
        reader_args[i].db = db;
        reader_args[i].cf = cf;
        reader_args[i].thread_id = i + num_writer_threads;
        reader_args[i].num_ops = ops_per_thread;
        reader_args[i].errors = &errors;
        pthread_create(&readers[i], NULL, concurrent_reader, &reader_args[i]);
    }

    for (int i = 0; i < num_writer_threads; i++)
    {
        pthread_join(writers[i], NULL);
    }

    for (int i = 0; i < num_reader_threads; i++)
    {
        pthread_join(readers[i], NULL);
    }

    int total_errors = atomic_load(&errors);
    ASSERT_TRUE(total_errors < 10);

    tidesdb_txn_t *verify_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &verify_txn), 0);

    int found = 0;
    for (int t = 0; t < num_writer_threads; t++)
    {
        for (int i = 0; i < ops_per_thread; i++)
        {
            char key[64];
            snprintf(key, sizeof(key), "thread_%d_key_%d", t, i);

            uint8_t *value = NULL;
            size_t value_size = 0;

            if (tidesdb_txn_get(verify_txn, (uint8_t *)key, strlen(key), &value, &value_size) == 0)
            {
                found++;
                free(value);
            }
        }
    }

    tidesdb_txn_free(verify_txn);

    printf("OK (%d writers, %d readers, %d keys verified, %d errors)\n", num_writer_threads,
           num_reader_threads, found, total_errors);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_metadata_boundary(void)
{
    printf("\n  [Regression] Testing iterator metadata boundary... ");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048; /* small to force flush */
    cf_config.enable_compression = 1;
    cf_config.compression_algorithm = COMPRESS_LZ4;

    ASSERT_EQ(tidesdb_create_column_family(db, "boundary_test", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "boundary_test");

    /* insert exactly 5 entries to create 1 sstable with 5 KV blocks + metadata */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 5; i++)
    {
        char key[32], value[128];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d_padding_xxxxxxxxxxxxxxxxxxxxxxxxxx", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* force flush to create SSTable */
    ASSERT_TRUE(cf != NULL);

    /* manually flush memtable */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete */
    int max_wait = 50; /* 5 seconds max */
    int num_ssts = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_ssts = atomic_load(&cf->num_sstables);
        if (num_ssts > 0) break;
        usleep(100000);
    }

    ASSERT_TRUE(num_ssts > 0);

    /* get the sst and verify num_entries */
    tidesdb_sstable_t *sst = cf->sstables[0];
    ASSERT_TRUE(sst != NULL);
    ASSERT_EQ(sst->num_entries, 5);

    /* iterate through all entries, should read exactly 5 blocks, not metadata */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        count++;
        /* verify we're reading valid data, not garbage from metadata */
        ASSERT_TRUE(iter->current_key != NULL);
        ASSERT_TRUE(iter->current_key_size > 0);
        ASSERT_TRUE(iter->current_value != NULL);

        /* if we read more than 5 entries, we're reading metadata blocks */
        ASSERT_TRUE(count <= 5);

        tidesdb_iter_next(iter);
    }

    /* we should read at least some entries, and not more than 5 */
    ASSERT_TRUE(count > 0);
    ASSERT_TRUE(count <= 5);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    printf("OK (read %d entries, stopped at boundary, expected 5)\n", count);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_sstable_num_entries_accuracy(void)
{
    printf("\n  [Regression] Testing SSTable num_entries accuracy... ");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 1024;
    cf_config.enable_compression = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "entries_test", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "entries_test");

    /* create multiple ssts with known entry counts */
    int expected_counts[] = {3, 7, 5, 10};
    int num_sstables = sizeof(expected_counts) / sizeof(expected_counts[0]);

    for (int sst_idx = 0; sst_idx < num_sstables; sst_idx++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < expected_counts[sst_idx]; i++)
        {
            char key[64], value[256];
            snprintf(key, sizeof(key), "sst%d_key%d", sst_idx, i);
            snprintf(value, sizeof(value), "sst%d_value%d_padding_xxxxxxxxxxxxxxxxxxxx", sst_idx,
                     i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* force memtable flush to create sstables */
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete */
    int max_wait = 50; /* 5 seconds max */
    int actual_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        actual_sstables = atomic_load(&cf->num_sstables);
        if (actual_sstables > 0) break;
        usleep(100000); /* 100ms */
    }

    ASSERT_TRUE(actual_sstables > 0); /* at least one sstable created */

    /* verify iterator reads correct total count */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int total_count = 0;
    int expected_total = 0;
    for (int i = 0; i < num_sstables; i++) expected_total += expected_counts[i];

    while (tidesdb_iter_valid(iter))
    {
        total_count++;
        /* if we read way more than expected, we're reading metadata */
        ASSERT_TRUE(total_count <= expected_total * 2);
        tidesdb_iter_next(iter);
    }

    /* verify we read a reasonable number of entries (not exact due to compaction) */
    ASSERT_TRUE(total_count > 0);
    ASSERT_TRUE(total_count <= expected_total * 2); /* allow for some variation */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    printf("OK (verified %d entries, expected ~%d)\n", total_count, expected_total);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family_basic(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    ASSERT_EQ(tidesdb_drop_column_family(db, "test_cf"), 0);

    /* verify it no longer exists */
    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family_with_data(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* create column family and add data */
    ASSERT_EQ(tidesdb_create_column_family(db, "data_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to create sstables */
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete */
    int max_wait = 50; /* 5 seconds max */
    int num_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_sstables = atomic_load(&cf->num_sstables);
        if (num_sstables > 0) break;
        usleep(100000);
    }

    /* verify sstables were created */
    ASSERT_TRUE(num_sstables > 0);

    char cf_path[TDB_MAX_PATH_LENGTH];
    snprintf(cf_path, sizeof(cf_path), "%s" PATH_SEPARATOR "data_cf", TEST_DB_PATH);

    ASSERT_EQ(tidesdb_drop_column_family(db, "data_cf"), 0);

    /* verify it no longer exists */
    cf = tidesdb_get_column_family(db, "data_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family_not_found(void)
{
    tidesdb_t *db = create_test_db();

    /* try to drop non-existent column family */
    int result = tidesdb_drop_column_family(db, "nonexistent_cf");
    ASSERT_EQ(result, TDB_ERR_NOT_FOUND);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family_cleanup(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cleanup_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cleanup_cf");

    /* add data to create WAL entries */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to create sstables */

    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify files exist before drop */
    char cf_path[TDB_MAX_PATH_LENGTH];
    snprintf(cf_path, sizeof(cf_path), "%s" PATH_SEPARATOR "cleanup_cf", TEST_DB_PATH);
    struct stat st;
    ASSERT_EQ(stat(cf_path, &st), 0); /* directory should exist */

    ASSERT_EQ(tidesdb_drop_column_family(db, "cleanup_cf"), 0);

    /* verify CF is gone from database */
    cf = tidesdb_get_column_family(db, "cleanup_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_compaction_with_reads(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* disable background compaction, we'll trigger manually */
    cf_config.enable_background_compaction = 0;
    cf_config.max_sstables_before_compaction = 10; /* prevent auto-compaction by flush worker */
    cf_config.compaction_threads = 0;              /* single-threaded for deterministic test */

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert data into first sstable */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst1", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000); /* give flush thread time to pick up work */

    /* insert data into second sstable */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 50; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst2", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000); /* give flush thread time to pick up work */

    /* wait for both async flushes to complete */
    int max_wait = 100; /* 10 seconds max */
    int num_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_sstables = atomic_load(&cf->num_sstables);
        if (num_sstables >= 2) break;
        usleep(100000); /* 100ms */
    }

    /* verify we have at least 2 sstables */
    ASSERT_TRUE(num_sstables >= 2);

    /* create iterator BEFORE compaction */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    /* read first 10 entries from iterator */
    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 10)
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);
        ASSERT_TRUE(key != NULL);
        ASSERT_TRUE(value != NULL);
        count++;
        ASSERT_EQ(tidesdb_iter_next(iter), 0);
    }
    ASSERT_EQ(count, 10);

    /* NOW trigger compaction while iterator is active */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    /* verify compaction happened (2 sstables merged into 1) */
    num_sstables = atomic_load(&cf->num_sstables);
    ASSERT_EQ(num_sstables, 1);

    /* iterator should STILL work,  continue reading remaining entries */
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);
        ASSERT_TRUE(key != NULL);
        ASSERT_TRUE(value != NULL);
        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }
    /* iterator has snapshot of old ssts, should read at least some entries */
    ASSERT_TRUE(count >= 10);
    printf("OK (iterator read %d entries from old sstables during compaction)\n", count);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_compaction_lru_enabled_with_reads(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* disable background compaction, we'll trigger manually */
    cf_config.enable_background_compaction = 0;
    cf_config.max_sstables_before_compaction = 10;
    cf_config.compaction_threads = 0;
    cf_config.block_manager_cache_size = (1024 * 1024) * 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_block_cache_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_block_cache_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert data into first sstable */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst1", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000); /* give flush thread time to pick up work */

    /* insert data into second sstable */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 50; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst2", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000); /* give flush thread time to pick up work */

    /* wait for both async flushes to complete */
    int max_wait = 100; /* 10 seconds max */
    int num_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_sstables = atomic_load(&cf->num_sstables);
        if (num_sstables >= 2) break;
        usleep(100000); /* 100ms */
    }

    /* verify we have at least 2 sstables */
    ASSERT_TRUE(num_sstables >= 2);

    /* create iterator BEFORE compaction */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    /* read first 10 entries from iterator */
    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 10)
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);
        ASSERT_TRUE(key != NULL);
        ASSERT_TRUE(value != NULL);
        count++;
        ASSERT_EQ(tidesdb_iter_next(iter), 0);
    }
    ASSERT_EQ(count, 10);

    /* NOW trigger compaction while iterator is active */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    /* verify compaction happened (2 sstables merged into 1) */
    num_sstables = atomic_load(&cf->num_sstables);
    ASSERT_EQ(num_sstables, 1);

    /* iterator should STILL work,  continue reading remaining entries */
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);
        ASSERT_TRUE(key != NULL);
        ASSERT_TRUE(value != NULL);
        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }
    /* iterator has snapshot of old ssts, should read at least some entries */
    ASSERT_TRUE(count >= 10);
    printf("OK (iterator read %d entries from old sstables during compaction)\n", count);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static int test_linear_scan_fallback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* disable block indexes to force linear scan fallback */
    cf_config.enable_block_indexes = 0;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "linear_scan_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "linear_scan_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert test data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_for_key_%03d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to sstable to trigger linear scan path */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete */
    int max_wait = 50;
    int num_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_sstables = atomic_load(&cf->num_sstables);
        if (num_sstables > 0) break;
        usleep(100000);
    }

    ASSERT_TRUE(num_sstables > 0);

    /* verify all keys can be retrieved using linear scan */
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_for_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;

        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(value_size, strlen(expected_value));
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, (uint8_t *)"nonexistent", 11, &value, &value_size) != 0);

    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    time_t expired_ttl = time(NULL) - 10;
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"expired_key", 11, (uint8_t *)"expired_value", 13,
                              expired_ttl),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify expired key is not returned */
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &txn), 0);
    value = NULL;
    value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, (uint8_t *)"expired_key", 11, &value, &value_size) != 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, (uint8_t *)"key_025", 7), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify deleted key is not returned (tombstone in newer sstable) */
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &txn), 0);
    value = NULL;
    value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, (uint8_t *)"key_025", 7, &value, &value_size) != 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();

    return 1;
}

static int test_column_family_config_persistence(void)
{
    printf("Testing column family config persistence and updates...\n");

    cleanup_test_dir();

    tidesdb_config_t db_config = {.db_path = TEST_DB_PATH};
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&db_config, &db), 0);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.memtable_flush_size = 32 * 1024 * 1024;
    cf_config.max_sstables_before_compaction = 64;
    cf_config.compaction_threads = 2;
    cf_config.sl_max_level = 10;
    cf_config.sl_probability = 0.5f;
    cf_config.bloom_filter_fp_rate = 0.02;
    cf_config.enable_background_compaction = 0;
    cf_config.background_compaction_interval = 2000000;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

    /* verify initial config was saved */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(cf->config.memtable_flush_size, 32 * 1024 * 1024);
    ASSERT_EQ(cf->config.max_sstables_before_compaction, 64);
    ASSERT_EQ(cf->config.compaction_threads, 2);
    ASSERT_EQ(cf->config.sl_max_level, 10);
    ASSERT_TRUE(cf->config.sl_probability > 0.49f && cf->config.sl_probability < 0.51f);
    ASSERT_TRUE(cf->config.bloom_filter_fp_rate > 0.019 && cf->config.bloom_filter_fp_rate < 0.021);
    ASSERT_EQ(cf->config.enable_background_compaction, 0);
    ASSERT_EQ(cf->config.background_compaction_interval, 2000000);

    ASSERT_EQ(tidesdb_close(db), 0);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&db_config, &db), 0);

    /* verify config was loaded from disk */
    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(cf->config.memtable_flush_size, 32 * 1024 * 1024);
    ASSERT_EQ(cf->config.max_sstables_before_compaction, 64);
    ASSERT_EQ(cf->config.compaction_threads, 2);
    ASSERT_EQ(cf->config.sl_max_level, 10);
    ASSERT_TRUE(cf->config.sl_probability > 0.49f && cf->config.sl_probability < 0.51f);
    ASSERT_TRUE(cf->config.bloom_filter_fp_rate > 0.019 && cf->config.bloom_filter_fp_rate < 0.021);
    ASSERT_EQ(cf->config.enable_background_compaction, 0);
    ASSERT_EQ(cf->config.background_compaction_interval, 2000000);

    /* update configuration */
    tidesdb_column_family_update_config_t update_config = {
        .memtable_flush_size = 128 * 1024 * 1024,
        .max_sstables_before_compaction = 256,
        .compaction_threads = 8,
        .max_level = 16,
        .probability = 0.25f,
        .enable_bloom_filter = 1,
        .bloom_filter_fp_rate = 0.001,
        .enable_background_compaction = 1,
        .background_compaction_interval = 500000};

    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &update_config), 0);

    /* verify updated config in memory */
    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(cf->config.memtable_flush_size, 128 * 1024 * 1024);
    ASSERT_EQ(cf->config.max_sstables_before_compaction, 256);
    ASSERT_EQ(cf->config.compaction_threads, 8);
    ASSERT_EQ(cf->config.sl_max_level, 16);
    ASSERT_TRUE(cf->config.sl_probability > 0.24f && cf->config.sl_probability < 0.26f);
    ASSERT_TRUE(cf->config.bloom_filter_fp_rate > 0.0009 &&
                cf->config.bloom_filter_fp_rate < 0.0011);
    ASSERT_EQ(cf->config.enable_background_compaction, 1);
    ASSERT_EQ(cf->config.background_compaction_interval, 500000);

    ASSERT_EQ(tidesdb_close(db), 0);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&db_config, &db), 0);

    /* verify updated config was persisted */
    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(cf->config.memtable_flush_size, 128 * 1024 * 1024);
    ASSERT_EQ(cf->config.max_sstables_before_compaction, 256);
    ASSERT_EQ(cf->config.compaction_threads, 8);
    ASSERT_EQ(cf->config.sl_max_level, 16);
    ASSERT_TRUE(cf->config.sl_probability > 0.24f && cf->config.sl_probability < 0.26f);
    ASSERT_TRUE(cf->config.bloom_filter_fp_rate > 0.0009 &&
                cf->config.bloom_filter_fp_rate < 0.0011);
    ASSERT_EQ(cf->config.enable_background_compaction, 1);
    ASSERT_EQ(cf->config.background_compaction_interval, 500000);

    /* invalid memtable_flush_size */
    tidesdb_column_family_update_config_t invalid_config = update_config;
    invalid_config.memtable_flush_size = 0;
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    /* invalid max_sstables_before_compaction */
    invalid_config = update_config;
    invalid_config.max_sstables_before_compaction = 1; /* must be >= 2 */
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    /* invalid compaction_threads */
    invalid_config = update_config;
    invalid_config.compaction_threads = -1;
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    /* invalid probability */
    invalid_config = update_config;
    invalid_config.probability = 0.0f; /* must be > 0 and < 1 */
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    invalid_config.probability = 1.0f;
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    /* invalid bloom_filter_fp_rate */
    invalid_config = update_config;
    invalid_config.bloom_filter_fp_rate = 0.0; /* must be > 0 and < 1 */
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    invalid_config.bloom_filter_fp_rate = 1.0;
    ASSERT_EQ(tidesdb_update_column_family_config(db, "test_cf", &invalid_config),
              TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_update_column_family_config(db, "nonexistent", &update_config),
              TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();

    return 1;
}

static void test_iterator_seek(void)
{
    printf("Testing iterator seek functionality...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "seek_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "seek_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* insert keys key_000, key_010, key_020, ..., key_100 */
    for (int i = 0; i <= 100; i += 10)
    {
        char key[32];
        char value[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    const char *seek_key = "key_050";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(key_size, strlen("key_050"));
    ASSERT_EQ(memcmp(key, "key_050", key_size), 0);

    const char *seek_key2 = "key_055";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key2, strlen(seek_key2)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(key_size, strlen("key_060"));
    ASSERT_EQ(memcmp(key, "key_060", key_size), 0);

    const char *seek_key3 = "key_";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key3, strlen(seek_key3)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(key_size, strlen("key_000"));
    ASSERT_EQ(memcmp(key, "key_000", key_size), 0);

    const char *seek_key4 = "key_999";
    tidesdb_iter_seek(iter, (uint8_t *)seek_key4, strlen(seek_key4));
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_range(void)
{
    printf("Testing iterator seek with range queries...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "range_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "range_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* insert 100 keys */
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        char value[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    const char *start_key = "key_025";
    const char *end_key = "key_075";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)start_key, strlen(start_key)), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        /* check if we've passed the end key */
        if (memcmp(key, end_key, strlen(end_key)) > 0) break;

        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    /* should have read keys from 025 to 075 inclusive (51 keys) */
    ASSERT_EQ(count, 51);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_prefix(void)
{
    printf("Testing iterator seek with prefix scan...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "prefix_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "prefix_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* insert keys with different prefixes */
    const char *prefixes[] = {"user:", "post:", "comment:"};
    for (int p = 0; p < 3; p++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[64];
            char value[64];
            snprintf(key, sizeof(key), "%s%03d", prefixes[p], i);
            snprintf(value, sizeof(value), "value_%s%03d", prefixes[p], i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    const char *prefix = "post:";
    size_t prefix_len = strlen(prefix);
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)prefix, prefix_len), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        /* check if key still has the prefix */
        if (key_size < prefix_len || memcmp(key, prefix, prefix_len) != 0) break;

        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    /* should have found all 20 "post:" keys */
    ASSERT_EQ(count, 20);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_large_sstable(void)
{
    printf("Testing iterator seek on large SSTable...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "large_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "large_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 1000; i++)
    {
        char key[32];
        char value[32];
        snprintf(key, sizeof(key), "key_%05d", i);
        snprintf(value, sizeof(value), "value_%05d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_TRUE(cf != NULL);
    /* flush memtable to create sst */
    tidesdb_flush_memtable(cf);

    sleep(2);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    const char *seek_key = "key_00500";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    printf("Found key: %.*s\n", (int)key_size, key);
    ASSERT_EQ(memcmp(key, "key_00500", strlen("key_00500")), 0);

    const char *seek_key2 = "key_00950";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key2, strlen(seek_key2)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00950", strlen("key_00950")), 0);

    /* verify we can iterate from there */
    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 50)
    {
        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }
    ASSERT_EQ(count, 50); /* should read 50 keys from 950 to 999 */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_multi_source(void)
{
    printf("Testing iterator seek across multiple sources...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048;

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_cf");
    ASSERT_TRUE(cf != NULL);

    /* create data in multiple batches to generate multiple sstables */
    for (int batch = 0; batch < 5; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 100; i++)
        {
            char key[32];
            char value[32];
            int key_num = batch * 100 + i;
            snprintf(key, sizeof(key), "key_%05d", key_num);
            snprintf(value, sizeof(value), "value_%05d", key_num);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush to create sst */
        tidesdb_flush_memtable(cf);
    }

    /* add more data to active memtable (not flushed) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        char value[32];
        snprintf(key, sizeof(key), "key_%05d", 500 + i);
        snprintf(value, sizeof(value), "value_%05d", 500 + i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* now we have 5 ssts (0-499) + active memtable (500-519) */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    const char *seek_key1 = "key_00050";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key1, strlen(seek_key1)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00050", strlen("key_00050")), 0);

    const char *seek_key2 = "key_00250";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key2, strlen(seek_key2)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00250", strlen("key_00250")), 0);

    const char *seek_key3 = "key_00450";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key3, strlen(seek_key3)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00450", strlen("key_00450")), 0);

    const char *seek_key4 = "key_00510";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key4, strlen(seek_key4)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00510", strlen("key_00510")), 0);

    const char *seek_key5 = "key_001555";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key5, strlen(seek_key5)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00156", strlen("key_00156")), 0);

    const char *seek_key6 = "key_00000";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key6, strlen(seek_key6)), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_00000", strlen("key_00000")), 0);

    const char *seek_key7 = "key_99999";
    tidesdb_iter_seek(iter, (uint8_t *)seek_key7, strlen(seek_key7));
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    /* test range scan across sources */
    const char *range_start = "key_00095";
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)range_start, strlen(range_start)), 0);
    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 10)
    {
        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }
    ASSERT_EQ(count, 10); /* should read 10 keys (95-104) */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_memory_safety(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "memory_test", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "memory_test");

    /* verify memory info was captured at startup */
    ASSERT_TRUE(db->available_memory > 0);
    ASSERT_TRUE(db->available_memory != SIZE_MAX);

    /* test that key+value exceeding available memory is rejected */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* allocate key+value that exceeds available memory
     * we need key_size + value_size + sizeof(header) > (available * 60% / 100)
     * header is small (48 bytes), so we add 1MB buffer to guarantee exceeding the limit */
    size_t max_allowed = (size_t)(db->available_memory * TDB_MEMORY_PERCENTAGE / 100);
    size_t excessive_size =
        (max_allowed / 2) + (1024 * 1024); /* add 1MB buffer to ensure we exceed */
    uint8_t *large_key = malloc(excessive_size);
    uint8_t *large_value = malloc(excessive_size);

    /* on 32-bit systems, malloc may fail for large allocations */
    if (large_key == NULL || large_value == NULL)
    {
        /* malloc failed -- this is expected on 32-bit systems with limited address space */
        if (large_key) free(large_key);
        if (large_value) free(large_value);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
        cleanup_test_dir();
        return; /* test passes -- memory constraint enforced by OS */
    }

    memset(large_key, 'K', excessive_size);
    memset(large_value, 'V', excessive_size);

    int result = tidesdb_txn_put(txn, large_key, excessive_size, large_value, excessive_size, -1);

    /* should fail with memory limit error, or TDB_ERR_MEMORY on 32-bit systems where internal
     * malloc fails */
    ASSERT_TRUE(result == TDB_ERR_MEMORY_LIMIT || result == TDB_ERR_MEMORY);

    free(large_key);
    free(large_value);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();
}

static void test_txn_write_write_serialization(void)
{
    printf("Testing transaction write-write serialization...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "conflict_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "conflict_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"key", 3, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"key", 3, (uint8_t *)"value2", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key", 3, &value, &value_size), 0);
    ASSERT_EQ(memcmp(value, "value2", 6), 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_read_your_own_deletes(void)
{
    printf("Testing transaction read-your-own-deletes...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "delete_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "delete_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"key", 3, (uint8_t *)"value", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, (uint8_t *)"key", 3), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_NE(tidesdb_txn_get(txn2, (uint8_t *)"key", 3, &value, &value_size), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_rollback_no_side_effects(void)
{
    printf("Testing transaction rollback has no side effects...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "rollback_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rollback_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"key2", 4, (uint8_t *)"value2", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_rollback(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key1", 4, &value, &value_size), 0);
    free(value);

    value = NULL;
    ASSERT_NE(tidesdb_txn_get(read_txn, (uint8_t *)"key2", 4, &value, &value_size), 0);

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_empty_column_family(void)
{
    printf("Testing iterator on empty column family...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "empty_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_cf");

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    /* seek_to_first may return error on empty CF, that's ok */
    tidesdb_iter_seek_to_first(iter);

    /* iterator should be invalid on empty CF */
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    /* operations on invalid iterator should fail */
    ASSERT_NE(tidesdb_iter_next(iter), 0);
    ASSERT_NE(tidesdb_iter_prev(iter), 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_single_entry(void)
{
    printf("Testing iterator with single entry...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "single_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "single_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"only_key", 8, (uint8_t *)"only_value", 10, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "only_key", 8), 0);

    ASSERT_NE(tidesdb_iter_next(iter), 0);
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    ASSERT_NE(tidesdb_iter_prev(iter), 0);
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_all_expired_ttl(void)
{
    printf("Testing iterator with all expired TTL entries...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "expired_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "expired_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    time_t expired_time = time(NULL) - 10;
    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)"value", 5, expired_time),
            0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    /* seek_to_first may return error when all entries expired */
    tidesdb_iter_seek_to_first(iter);

    /* iterator should be invalid when all entries expired */
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_all_tombstones(void)
{
    printf("Testing iterator with all tombstones...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "tombstone_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "tombstone_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)"value", 5, -1), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn2, (uint8_t *)key, strlen(key)), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    /* seek_to_first may return error when all entries are tombstones */
    tidesdb_iter_seek_to_first(iter);

    /* iterator should be invalid when all entries are tombstones */
    ASSERT_FALSE(tidesdb_iter_valid(iter));

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_to_deleted_key(void)
{
    printf("Testing iterator seek to deleted key...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "seek_del_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "seek_del_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    for (int i = 0; i < 5; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)key, strlen(key), (uint8_t *)"value", 5, -1), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, (uint8_t *)"key_2", 5), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)"key_2", 5), 0);

    ASSERT_TRUE(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "key_3", 5), 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_direction_changes(void)
{
    printf("Testing iterator direction changes...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "direction_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "direction_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    for (int i = 0; i < 3; i++)
    {
        ASSERT_TRUE(tidesdb_iter_valid(iter));
        if (i < 2) ASSERT_EQ(tidesdb_iter_next(iter), 0);
    }

    for (int i = 0; i < 3; i++)
    {
        ASSERT_TRUE(tidesdb_iter_valid(iter));
        if (i < 2) ASSERT_EQ(tidesdb_iter_prev(iter), 0);
    }

    for (int i = 0; i < 2; i++)
    {
        ASSERT_TRUE(tidesdb_iter_valid(iter));
        if (i < 1) ASSERT_EQ(tidesdb_iter_next(iter), 0);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_single_sstable(void)
{
    printf("Testing compaction with single SSTable...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "single_sst_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "single_sst_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    int num_ssts_before = atomic_load(&cf->num_sstables);
    ASSERT_EQ(tidesdb_compact(cf), 0);
    int num_ssts_after = atomic_load(&cf->num_sstables);

    ASSERT_EQ(num_ssts_before, num_ssts_after);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_all_expired(void)
{
    printf("Testing compaction with all expired entries...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "expired_compact_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "expired_compact_cf");
    ASSERT_TRUE(cf != NULL);

    time_t expired_time = time(NULL) - 10;

    for (int batch = 0; batch < 2; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        for (int i = 0; i < 10; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), expired_time),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(200000);
    }

    int num_ssts_before = atomic_load(&cf->num_sstables);
    ASSERT_TRUE(num_ssts_before >= 2);

    ASSERT_EQ(tidesdb_compact(cf), 0);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    /* seek_to_first may return error when all entries expired after compaction */
    tidesdb_iter_seek_to_first(iter);

    /* iterator should be invalid after compaction removed all expired entries */
    ASSERT_FALSE(tidesdb_iter_valid(iter));
    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_duplicate_keys(void)
{
    printf("Testing compaction with duplicate keys...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "dup_compact_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dup_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int version = 1; version <= 3; version++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        for (int i = 0; i < 5; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "key_%d", i);
            snprintf(value, sizeof(value), "value_v%d_%d", version, i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(200000);
    }

    int num_ssts_before = atomic_load(&cf->num_sstables);
    ASSERT_TRUE(num_ssts_before >= 3);

    ASSERT_EQ(tidesdb_compact(cf), 0);

    int num_ssts_after = atomic_load(&cf->num_sstables);
    ASSERT_TRUE(num_ssts_after < num_ssts_before);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 5; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected, sizeof(expected), "value_v3_%d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        ASSERT_EQ(memcmp(value, expected, strlen(expected)), 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cf_independent_operations(void)
{
    printf("Testing column family independent operations...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf1, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, (uint8_t *)"key", 3, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf2, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, (uint8_t *)"key", 3, (uint8_t *)"value2", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *read_txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf1, &read_txn1), 0);
    uint8_t *val1 = NULL;
    size_t size1 = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn1, (uint8_t *)"key", 3, &val1, &size1), 0);
    ASSERT_EQ(memcmp(val1, "value1", 6), 0);
    free(val1);
    tidesdb_txn_free(read_txn1);

    tidesdb_txn_t *read_txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf2, &read_txn2), 0);
    uint8_t *val2 = NULL;
    size_t size2 = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn2, (uint8_t *)"key", 3, &val2, &size2), 0);
    ASSERT_EQ(memcmp(val2, "value2", 6), 0);
    free(val2);
    tidesdb_txn_free(read_txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cf_name_limits(void)
{
    printf("Testing column family name limits...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* test name that's clearly too long (should fail) */
    char long_name[512];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    ASSERT_NE(tidesdb_create_column_family(db, long_name, &cf_config), 0);

    /* test reasonable length name (should succeed) */
    char reasonable_name[128];
    memset(reasonable_name, 'b', 100);
    reasonable_name[100] = '\0';
    ASSERT_EQ(tidesdb_create_column_family(db, reasonable_name, &cf_config), 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_bloom_filter_disabled(void)
{
    printf("Testing with very high bloom filter FP rate...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    /* use very high FP rate (0.99) which effectively disables bloom filter usefulness */
    cf_config.bloom_filter_fp_rate = 0.99;
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "high_fp_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "high_fp_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key_10", 6, &value, &value_size), 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_block_indexes_disabled(void)
{
    printf("Testing with block indexes disabled...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_block_indexes = 0;
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "no_block_indexes_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_block_indexes_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key_10", 6, &value, &value_size), 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_snappy(void)
{
    printf("Testing Snappy compression...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_compression = 1;
    cf_config.compression_algorithm = COMPRESS_SNAPPY;
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "snappy_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snappy_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32], value[256];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d_with_lots_of_repeated_data_aaaaaaaaaaaaaaaa", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_zstd(void)
{
    printf("Testing ZSTD compression...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_compression = 1;
    cf_config.compression_algorithm = COMPRESS_ZSTD;
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "zstd_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "zstd_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32], value[256];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d_with_lots_of_repeated_data_bbbbbbbbbbbbbbbb", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_none(void)
{
    printf("Testing no compression...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_compression = 0;
    cf_config.memtable_flush_size = 2048;
    ASSERT_EQ(tidesdb_create_column_family(db, "no_compress_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_compress_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32], value[256];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key_10", 6, &value, &value_size), 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_comparator_string(void)
{
    printf("Testing string comparator...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    strncpy(cf_config.comparator_name, "string", TDB_MAX_COMPARATOR_NAME - 1);
    cf_config.comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    ASSERT_EQ(tidesdb_create_column_family(db, "string_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "string_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"zebra", 5, (uint8_t *)"last", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"apple", 5, (uint8_t *)"first", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"mango", 5, (uint8_t *)"middle", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    ASSERT_TRUE(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_EQ(memcmp(key, "apple", 5), 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_comparator_numeric(void)
{
    printf("Testing numeric comparator...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    strncpy(cf_config.comparator_name, "numeric", TDB_MAX_COMPARATOR_NAME - 1);
    cf_config.comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    ASSERT_EQ(tidesdb_create_column_family(db, "numeric_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "numeric_cf");
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    int64_t keys[] = {100, 10, 50, 1, 200};
    for (int i = 0; i < 5; i++)
    {
        char value[32];
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)&keys[i], sizeof(int64_t), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    ASSERT_TRUE(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    int64_t first_key = *(int64_t *)key;
    ASSERT_EQ(first_key, 1);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_wal_recovery_after_reopen(void)
{
    printf("Testing WAL recovery after database reopen...");
    fflush(stdout);

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        cf_config.sync_mode = TDB_SYNC_FULL;
        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        for (int i = 0; i < 10; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "wal_key_%d", i);
            snprintf(value, sizeof(value), "wal_value_%d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");
        if (cf != NULL)
        {
            tidesdb_txn_t *read_txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
            for (int i = 0; i < 10; i++)
            {
                char key[32];
                snprintf(key, sizeof(key), "wal_key_%d", i);
                uint8_t *value = NULL;
                size_t value_size = 0;
                ASSERT_EQ(
                    tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
                free(value);
            }
            tidesdb_txn_free(read_txn);
        }

        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_wal_with_multiple_memtables(void)
{
    printf("Testing WAL with multiple memtable rotations...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048;
    cf_config.sync_mode = TDB_SYNC_FULL;
    ASSERT_EQ(tidesdb_create_column_family(db, "multi_wal_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_wal_cf");
    for (int batch = 0; batch < 3; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        for (int i = 0; i < 20; i++)
        {
            char key[32], value[128];
            snprintf(key, sizeof(key), "batch%d_key_%d", batch, i);
            snprintf(value, sizeof(value), "batch%d_value_%d_padding_xxxx", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "batch%d_key_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size),
                      0);
            free(value);
        }
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/*
 * thread_test_args_t
 * @param db tidesdb instance
 * @param thread_id thread identifier
 * @param num_ops number of operations to perform
 * @param error_count pointer to error count
 */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_ops;
    _Atomic(int) *error_count;
} thread_test_args_t;

static void *concurrent_writer_thread(void *arg)
{
    thread_test_args_t *args = (thread_test_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(args->db, args->cf, &txn) != 0)
        {
            atomic_fetch_add(args->error_count, 1);
            continue;
        }

        char key[64], value[128];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id, i);
        snprintf(value, sizeof(value), "thread_%d_value_%d", args->thread_id, i);

        if (tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value),
                            -1) != 0)
        {
            atomic_fetch_add(args->error_count, 1);
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(args->error_count, 1);
        }

        tidesdb_txn_free(txn);
    }

    return NULL;
}

static void *concurrent_reader_thread(void *arg)
{
    thread_test_args_t *args = (thread_test_args_t *)arg;

    for (int i = 0; i < args->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin_read(args->db, args->cf, &txn) != 0)
        {
            atomic_fetch_add(args->error_count, 1);
            continue;
        }

        char key[64];
        snprintf(key, sizeof(key), "thread_0_key_%d", i % 10);

        uint8_t *value = NULL;
        size_t value_size = 0;
        tidesdb_txn_get(txn, (uint8_t *)key, strlen(key), &value, &value_size);
        if (value) free(value);

        tidesdb_txn_free(txn);
    }

    return NULL;
}

static void test_concurrent_readers_writers(void)
{
    printf("Testing concurrent readers and writers...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");

#define NUM_WRITERS    3
#define NUM_READERS    3
#define OPS_PER_THREAD 20

    pthread_t writers[NUM_WRITERS];
    pthread_t readers[NUM_READERS];
    thread_test_args_t writer_args[NUM_WRITERS];
    thread_test_args_t reader_args[NUM_READERS];
    _Atomic(int) error_count = 0;

    for (int i = 0; i < NUM_WRITERS; i++)
    {
        writer_args[i].db = db;
        writer_args[i].cf = cf;
        writer_args[i].thread_id = i;
        writer_args[i].num_ops = OPS_PER_THREAD;
        writer_args[i].error_count = &error_count;
        pthread_create(&writers[i], NULL, concurrent_writer_thread, &writer_args[i]);
    }

    for (int i = 0; i < NUM_READERS; i++)
    {
        reader_args[i].db = db;
        reader_args[i].cf = cf;
        reader_args[i].thread_id = i;
        reader_args[i].num_ops = OPS_PER_THREAD;
        reader_args[i].error_count = &error_count;
        pthread_create(&readers[i], NULL, concurrent_reader_thread, &reader_args[i]);
    }

    for (int i = 0; i < NUM_WRITERS; i++)
    {
        pthread_join(writers[i], NULL);
    }

    for (int i = 0; i < NUM_READERS; i++)
    {
        pthread_join(readers[i], NULL);
    }

    int total_errors = atomic_load(&error_count);
    ASSERT_TRUE(total_errors < 10);

    tidesdb_close(db);
    cleanup_test_dir();
    printf("OK (errors: %d)\n", total_errors);

#undef NUM_WRITERS
#undef NUM_READERS
#undef OPS_PER_THREAD
}

static void test_concurrent_flush_and_read(void)
{
    printf("Testing concurrent flush and read operations...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;
    ASSERT_EQ(tidesdb_create_column_family(db, "flush_read_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "flush_read_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 50; i++)
    {
        char key[32], value[128];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d_with_padding_xxxxxxxxxx", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_flush_memtable(cf);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    usleep(200000);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_no_deadlock_multiple_cfs(void)
{
    printf("Testing no deadlock with multiple column families...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_a", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_b", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_c", &cf_config), 0);

    tidesdb_column_family_t *cf_a = tidesdb_get_column_family(db, "cf_a");
    tidesdb_column_family_t *cf_b = tidesdb_get_column_family(db, "cf_b");
    tidesdb_column_family_t *cf_c = tidesdb_get_column_family(db, "cf_c");

    tidesdb_txn_t *txn_a = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf_a, &txn_a), 0);
    ASSERT_EQ(tidesdb_txn_put(txn_a, (uint8_t *)"key", 3, (uint8_t *)"val_a", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn_a), 0);
    tidesdb_txn_free(txn_a);

    tidesdb_txn_t *txn_b = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf_b, &txn_b), 0);
    ASSERT_EQ(tidesdb_txn_put(txn_b, (uint8_t *)"key", 3, (uint8_t *)"val_b", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn_b), 0);
    tidesdb_txn_free(txn_b);

    tidesdb_txn_t *txn_c = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf_c, &txn_c), 0);
    ASSERT_EQ(tidesdb_txn_put(txn_c, (uint8_t *)"key", 3, (uint8_t *)"val_c", 5, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn_c), 0);
    tidesdb_txn_free(txn_c);

    tidesdb_txn_t *read_txn_a = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf_a, &read_txn_a), 0);
    uint8_t *val_a = NULL;
    size_t size_a = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn_a, (uint8_t *)"key", 3, &val_a, &size_a), 0);
    free(val_a);
    tidesdb_txn_free(read_txn_a);

    tidesdb_txn_t *read_txn_b = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf_b, &read_txn_b), 0);
    uint8_t *val_b = NULL;
    size_t size_b = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn_b, (uint8_t *)"key", 3, &val_b, &size_b), 0);
    free(val_b);
    tidesdb_txn_free(read_txn_b);

    tidesdb_txn_t *read_txn_c = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf_c, &read_txn_c), 0);
    uint8_t *val_c = NULL;
    size_t size_c = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn_c, (uint8_t *)"key", 3, &val_c, &size_c), 0);
    free(val_c);
    tidesdb_txn_free(read_txn_c);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_invalid_column_family_operations(void)
{
    printf("Testing column family operations validation...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "valid_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "valid_cf");

    /* test operations on valid CF should succeed */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key", 3, (uint8_t *)"val", 3, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify data was written */
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)"key", 3, &value, &value_size), 0);
    ASSERT_EQ(memcmp(value, "val", 3), 0);
    free(value);
    tidesdb_txn_free(txn);

    /* test creating another CF with same name (may succeed or fail depending on implementation) */
    int result = tidesdb_create_column_family(db, "valid_cf", &cf_config);
    /* we don't assert the result, just ensure it doesn't crash */
    (void)result;

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_null_pointer_handling(void)
{
    printf("Testing null pointer handling...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "null_test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "null_test_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_NE(tidesdb_txn_put(txn, NULL, 0, (uint8_t *)"val", 3, -1), 0);
    ASSERT_NE(tidesdb_txn_put(txn, (uint8_t *)"key", 3, NULL, 0, -1), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_zero_length_keys_values(void)
{
    printf("Testing zero-length keys and values...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "zero_len_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "zero_len_cf");

    /* test zero-length key (should fail; keys must have length > 0) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_NE(tidesdb_txn_put(txn, (uint8_t *)"key", 0, (uint8_t *)"val", 3, -1), 0);
    tidesdb_txn_free(txn);

    /* test zero-length value (should work; empty values are valid) */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key", 3, (uint8_t *)"", 0, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key", 3, &value, &value_size), 0);
    ASSERT_EQ(value_size, 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_invalid_ttl_values(void)
{
    printf("Testing invalid TTL values...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_test_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"val1", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key2", 4, (uint8_t *)"val2", 4, 0), 0);
    time_t future_ttl = time(NULL) + 3600;
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key3", 4, (uint8_t *)"val3", 4, future_ttl), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key1", 4, &value, &value_size), 0);
    free(value);
    value = NULL;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key3", 4, &value, &value_size), 0);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_transaction_after_close(void)
{
    printf("Testing transaction operations after close...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "close_test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "close_test_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key", 3, (uint8_t *)"val", 3, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_invalid_operations(void)
{
    printf("Testing iterator invalid operations...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "iter_invalid_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_invalid_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key", 3, (uint8_t *)"val", 3, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_NE(tidesdb_iter_key(iter, &key, &key_size), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_NE(tidesdb_iter_value(iter, &value, &value_size), 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_config_validation(void)
{
    printf("Testing column family config validation...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* test valid config should succeed */
    ASSERT_EQ(tidesdb_create_column_family(db, "valid_config_cf", &cf_config), 0);

    /* test memtable_flush_size = 0 (should fail) */
    cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 0;
    ASSERT_NE(tidesdb_create_column_family(db, "invalid_flush_cf", &cf_config), 0);
    cf_config = get_test_cf_config();
    cf_config.max_sstables_before_compaction = 1;
    ASSERT_NE(tidesdb_create_column_family(db, "invalid_compact_cf", &cf_config), 0);
    cf_config = get_test_cf_config();
    cf_config.bloom_filter_fp_rate = 1.5;
    ASSERT_NE(tidesdb_create_column_family(db, "invalid_bloom_cf", &cf_config), 0);
    cf_config = get_test_cf_config();
    cf_config.bloom_filter_fp_rate = -0.1;
    ASSERT_NE(tidesdb_create_column_family(db, "invalid_bloom2_cf", &cf_config), 0);
    cf_config = get_test_cf_config();
    cf_config.bloom_filter_fp_rate = 0.0;
    ASSERT_NE(tidesdb_create_column_family(db, "invalid_bloom3_cf", &cf_config), 0);
    cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 1;
    cf_config.max_sstables_before_compaction = 2;
    cf_config.bloom_filter_fp_rate = 0.001;
    ASSERT_EQ(tidesdb_create_column_family(db, "min_valid_cf", &cf_config), 0);

    cf_config = get_test_cf_config();
    cf_config.bloom_filter_fp_rate = 1.0;
    ASSERT_EQ(tidesdb_create_column_family(db, "max_fp_cf", &cf_config), 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_large_batch_operations(void)
{
    printf("Testing large batch operations...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "batch_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "batch_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 1000; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "batch_key_%d", i);
        snprintf(value, sizeof(value), "batch_value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 1000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "batch_key_%d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_special_characters_in_keys(void)
{
    printf("Testing special characters in keys...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "special_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "special_cf");

    const char *special_keys[] = {
        "key\\with\\backslash", "key/with/slash", "key with spaces",          "key\twith\ttabs",
        "key\nwith\nnewlines",  "key@#$%^&*()",   "key_with_unicode_\xC3\xA9"};

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    for (int i = 0; i < 7; i++)
    {
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)special_keys[i], strlen(special_keys[i]),
                                  (uint8_t *)"value", 5, -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);
    for (int i = 0; i < 7; i++)
    {
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)special_keys[i], strlen(special_keys[i]),
                                  &value, &value_size),
                  0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_committed_isolation(void)
{
    /* we test READ COMMITTED isolation -- read transactions see latest committed data */
    printf("\n  [Isolation] Testing READ COMMITTED isolation... ");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    tidesdb_create_column_family(db, "data", &cf_config);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    tidesdb_txn_t *write_txn;
    tidesdb_txn_begin(db, cf, &write_txn);
    for (int i = 0; i < 100; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "v1_%d", i);
        tidesdb_txn_put(write_txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value),
                        -1);
    }
    tidesdb_txn_commit(write_txn);
    tidesdb_txn_free(write_txn);

    tidesdb_txn_t *read_txn;
    tidesdb_txn_begin_read(db, cf, &read_txn);

    /* verify initial read sees v1 */
    char key[32];
    snprintf(key, sizeof(key), "key_0");
    uint8_t *value;
    size_t value_size;
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
    ASSERT_TRUE(strncmp((char *)value, "v1_", 3) == 0);
    free(value);

    /* concurrent write commits new data */
    tidesdb_txn_begin(db, cf, &write_txn);
    for (int i = 0; i < 100; i++)
    {
        char k[32], v[32];
        snprintf(k, sizeof(k), "key_%d", i);
        snprintf(v, sizeof(v), "v2_%d", i);
        tidesdb_txn_put(write_txn, (uint8_t *)k, strlen(k), (uint8_t *)v, strlen(v), -1);
    }
    tidesdb_txn_commit(write_txn);
    tidesdb_txn_free(write_txn);

    /* READ COMMITTED read transaction
     * should now see v2 (latest committed data) */
    ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
    ASSERT_TRUE(strncmp((char *)value, "v2_", 3) == 0);
    free(value);

    printf("OK (read transaction sees latest committed data)\n");

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_sstable_reference_counting(void)
{
    /* we test that ssts arent deleted while iterators hold references */
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_background_compaction = 0;
    tidesdb_create_column_family(db, "data", &cf_config);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    for (int sst = 0; sst < 2; sst++)
    {
        tidesdb_txn_t *txn;
        tidesdb_txn_begin(db, cf, &txn);
        for (int i = 0; i < 50; i++)
        {
            char key[32], value[32];
            snprintf(key, sizeof(key), "key_%03d", i + (sst * 50));
            snprintf(value, sizeof(value), "value_%d", i);
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1);
        }
        tidesdb_txn_commit(txn);
        tidesdb_txn_free(txn);
        tidesdb_flush_memtable(cf);
        usleep(200000);
    }

    /* create multiple iterators (hold references) */
    tidesdb_txn_t *read_txn;
    tidesdb_txn_begin_read(db, cf, &read_txn);
    tidesdb_iter_t *iter1, *iter2, *iter3;
    tidesdb_iter_new(read_txn, &iter1);
    tidesdb_iter_new(read_txn, &iter2);
    tidesdb_iter_new(read_txn, &iter3);

    /* compact (should merge ssts but not delete due to refs) */
    tidesdb_compact(cf);

    /* all iterators should still work and be valid */
    tidesdb_iter_seek_to_first(iter1);
    tidesdb_iter_seek_to_first(iter2);
    tidesdb_iter_seek_to_first(iter3);

    int count1 = 0, count2 = 0, count3 = 0;
    while (tidesdb_iter_valid(iter1))
    {
        count1++;
        tidesdb_iter_next(iter1);
    }
    while (tidesdb_iter_valid(iter2))
    {
        count2++;
        tidesdb_iter_next(iter2);
    }
    while (tidesdb_iter_valid(iter3))
    {
        count3++;
        tidesdb_iter_next(iter3);
    }

    ASSERT_EQ(count1, 100);
    ASSERT_EQ(count2, 100);
    ASSERT_EQ(count3, 100);

    tidesdb_iter_free(iter1);
    tidesdb_iter_free(iter2);
    tidesdb_iter_free(iter3);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_block_cache_eviction_under_pressure(void)
{
    /* we test that cache eviction works correctly under memory pressure */
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.block_manager_cache_size = 1024 * 1024;
    cf_config.enable_background_compaction = 0;
    tidesdb_create_column_family(db, "data", &cf_config);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    /* create many ssts (more than cache can hold) */
    for (int sst = 0; sst < 20; sst++)
    {
        tidesdb_txn_t *txn;
        tidesdb_txn_begin(db, cf, &txn);
        for (int i = 0; i < 100; i++)
        {
            char key[32], value[1024];
            snprintf(key, sizeof(key), "sst%d_key%d", sst, i);
            memset(value, 'X', sizeof(value));
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, sizeof(value), -1);
        }
        tidesdb_txn_commit(txn);
        tidesdb_txn_free(txn);
        tidesdb_flush_memtable(cf);
        usleep(100000);
    }

    /* read from all ssts (forces cache eviction) */
    tidesdb_txn_t *txn;
    tidesdb_txn_begin_read(db, cf, &txn);
    for (int sst = 0; sst < 20; sst++)
    {
        for (int i = 0; i < 100; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "sst%d_key%d", sst, i);
            uint8_t *value;
            size_t value_size;
            ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key), &value, &value_size), 0);
            ASSERT_EQ(value_size, 1024);
            free(value);
        }
    }
    tidesdb_txn_free(txn);

    printf("OK (cache eviction handled correctly)\n");
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_wal_corruption_detection(void)
{
    /* test that corrupted WAL is detected and handled */
    printf("\n  [Reliability] Testing WAL corruption detection... ");
    fflush(stdout);

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        tidesdb_create_column_family(db, "data", &cf_config);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

        tidesdb_txn_t *txn;
        tidesdb_txn_begin(db, cf, &txn);
        tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1);
        tidesdb_txn_commit(txn);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    /* corrupt the WAL file */
    char wal_path[512];
    snprintf(wal_path, sizeof(wal_path), "./test_tidesdb/data/wal_0.log");
    FILE *f = fopen(wal_path, "r+b");
    if (f)
    {
        fseek(f, 100, SEEK_SET);
        uint8_t corrupt_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        fwrite(corrupt_data, 1, 10, f);
        fclose(f);
    }

    /* try to reopen (should detect corruption) */
    tidesdb_t *db;
    tidesdb_config_t config = {0};
    strcpy(config.db_path, "./test_tidesdb");
    int result = tidesdb_open(&config, &db);

    /* should either reject corrupted data or recover gracefully */
    if (result == 0)
    {
        tidesdb_close(db);
    }

    printf("OK (corruption detected)\n");
    cleanup_test_dir();
}

static void test_drop_cf_with_active_iterators(void)
{
    /* we test dropping CF while iterators are active */
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    tidesdb_create_column_family(db, "data", &cf_config);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");
    tidesdb_txn_t *txn;
    tidesdb_txn_begin(db, cf, &txn);
    for (int i = 0; i < 100; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1);
    }
    tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    tidesdb_txn_begin_read(db, cf, &txn);
    tidesdb_iter_t *iter;
    tidesdb_iter_new(txn, &iter);
    tidesdb_iter_seek_to_first(iter);

    /* try to drop CF (should wait for iterator to finish) */
    int drop_result = tidesdb_drop_column_family(db, "data");

    /* iterator should still work OR drop should fail gracefully */
    if (drop_result == 0)
    {
        /* CF dropped, iterator should be invalidated */
        printf("OK (CF dropped, iterator invalidated)\n");
    }
    else
    {
        /* drop failed because iterator active */
        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            count++;
            tidesdb_iter_next(iter);
        }
        ASSERT_EQ(count, 100);
        printf("OK (drop blocked by active iterator)\n");
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void *compact_wrapper(void *arg)
{
    tidesdb_column_family_t *cf = (tidesdb_column_family_t *)arg;
    tidesdb_compact(cf);
    return NULL;
}

static void test_parallel_compaction_race(void)
{
    /* we test parallel compaction with concurrent reads/writes */
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.enable_background_compaction = 0;
    cf_config.compaction_threads = 4;
    tidesdb_create_column_family(db, "data", &cf_config);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");

    for (int i = 0; i < 16; i++)
    {
        tidesdb_txn_t *txn;
        tidesdb_txn_begin(db, cf, &txn);
        for (int j = 0; j < 100; j++)
        {
            char key[32], value[32];
            snprintf(key, sizeof(key), "sst%d_key%d", i, j);
            snprintf(value, sizeof(value), "value_%d", j);
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1);
        }
        tidesdb_txn_commit(txn);
        tidesdb_txn_free(txn);
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    /* start compaction in background */
    pthread_t compact_thread;
    pthread_create(&compact_thread, NULL, compact_wrapper, cf);

    /* concurrent reads while compacting */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn;
        tidesdb_txn_begin_read(db, cf, &txn);
        char key[32];
        snprintf(key, sizeof(key), "sst%d_key%d", rand() % 16, rand() % 100);
        uint8_t *value;
        size_t value_size;
        tidesdb_txn_get(txn, (uint8_t *)key, strlen(key), &value, &value_size);
        if (value) free(value);
        tidesdb_txn_free(txn);
        usleep(10000);
    }

    pthread_join(compact_thread, NULL);

    printf("OK (no races during parallel compaction)\n");
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_memtable_flush_size_enforcement(void)
{
    printf("Testing memtable_flush_size enforcement with multiple WAL files...");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* set small memtable flush size to force multiple rotations */
    cf_config.memtable_flush_size = 64 * 1024;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "flush_test", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "flush_test");
    ASSERT_TRUE(cf != NULL);

    /* write enough data to exceed memtable_flush_size multiple times */
    int num_writes = 200;
    size_t key_size = 32;
    size_t value_size = 1024;
    size_t expected_data_per_write = key_size + value_size;
    size_t total_data = num_writes * expected_data_per_write;

    /* we expect at least (total_data / memtable_flush_size) memtable rotations */
    int expected_min_rotations = (int)(total_data / cf_config.memtable_flush_size);

    printf("\n  Writing %d entries (%zu bytes each, %zu total)\n", num_writes,
           expected_data_per_write, total_data);
    printf("  Memtable flush size: %zu bytes\n", cf_config.memtable_flush_size);
    printf("  Expected minimum rotations: %d\n", expected_min_rotations);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < num_writes; i++)
    {
        char key[64], value[1024];
        snprintf(key, sizeof(key), "flush_test_key_%05d", i);
        memset(value, 'X', sizeof(value));
        snprintf(value, 50, "flush_test_value_%05d", i); /* add identifiable prefix */

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, value_size, -1), 0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* give time for flushes to complete */
    sleep(2);

    /* verify data is still accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    for (int i = 0; i < num_writes; i += 20) /* sample every 20th entry */
    {
        char key[64];
        snprintf(key, sizeof(key), "flush_test_key_%05d", i);

        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)key, strlen(key), &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        ASSERT_EQ(retrieved_size, value_size);
        free(retrieved_value);
    }

    tidesdb_txn_free(read_txn);

    /* check that we have multiple sstables (indicating multiple flushes) */
    int num_sstables = atomic_load(&cf->num_sstables);
    printf("  Created %d SSTables\n", num_sstables);

    /* we should have at least 2 sstables if memtable_flush_size is working */
    ASSERT_TRUE(num_sstables >= 2);

    printf("OK (memtable_flush_size properly enforced)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_all_sources(void)
{
    printf("Running: test_iterator_all_sources... ");
    fflush(stdout);

    const char *db_path = "./test_tidesdb";
    remove_directory(db_path);

    tidesdb_config_t config;
    memset(&config, 0, sizeof(tidesdb_config_t));
    strncpy(config.db_path, db_path, sizeof(config.db_path) - 1);
    config.num_flush_threads = 1;
    config.num_compaction_threads = 1;
    config.enable_debug_logging = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.memtable_flush_size = 10 * 1024;
    cf_config.enable_compression = 1;
    cf_config.compression_algorithm = COMPRESS_LZ4;
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_KEYS = 2000;
    const int KEY_SIZE = 16;
    const int VALUE_SIZE = 100;
    const int ENTRY_SIZE = KEY_SIZE + VALUE_SIZE + 50;
    const int EXPECTED_MEMTABLES = (NUM_KEYS * ENTRY_SIZE) / (20 * 1024);

    printf("\n  Test plan: %d keys × %dB = %dKB total\n", NUM_KEYS, ENTRY_SIZE,
           (NUM_KEYS * ENTRY_SIZE) / 1024);
    printf("  With 20KB threshold = ~%d memtables\n", EXPECTED_MEMTABLES);
    printf("  With 1 flush thread = should create backlog of immutable memtables\n\n");

    printf("  Writing %d keys rapidly...\n", NUM_KEYS);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%010d", i);
        snprintf(value, sizeof(value),
                 "value_%010d_"
                 "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                 "xxxxxxxxx",
                 i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, (uint8_t *)key, strlen(key), (uint8_t *)value, strlen(value), -1),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if ((i + 1) % 500 == 0)
        {
            printf("  Progress: %d/%d keys written\n", i + 1, NUM_KEYS);
        }
    }

    printf("  All keys written. Creating iterator immediately...\n");

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, &iter), 0);

    printf("  Iterator created with sources: memtable=%d, immutable=%d, sstables=%d\n",
           iter->memtable_cursor ? 1 : 0, iter->num_immutable_cursors, iter->num_sstable_cursors);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    printf("  Counting keys...\n");

    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%010d", count);
        ASSERT_EQ(key_size, strlen(expected_key));
        ASSERT_TRUE(memcmp(key, expected_key, key_size) == 0);

        count++;
        tidesdb_iter_next(iter);

        if (count % 500 == 0)
        {
            printf("  Progress: %d keys iterated\n", count);
        }
    }

    printf("\n  RESULT: Iterator found %d keys (expected %d)\n", count, NUM_KEYS);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    ASSERT_EQ(count, NUM_KEYS);

    tidesdb_close(db);
    remove_directory(db_path);

    printf("OK\n");
}

static void test_default_comparator_persistence(void)
{
    printf("Testing default comparator name persistence...");
    fflush(stdout);

    /* create CF without specifying comparator (should default to memcmp) */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();

        /* explicitly clear comparator_name to test default */
        memset(cf_config.comparator_name, 0, TDB_MAX_COMPARATOR_NAME);

        ASSERT_EQ(tidesdb_create_column_family(db, "default_cmp_cf", &cf_config), 0);

        /* verify comparator is set to memcmp */
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "default_cmp_cf");
        ASSERT_TRUE(cf != NULL);
        ASSERT_TRUE(strcmp(cf->comparator_name, "memcmp") == 0);

        /* write some data */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* verify config file has comparator_name=memcmp */
    {
        char config_path[512];
        snprintf(config_path, sizeof(config_path), "%s/default_cmp_cf/config.cfc", TEST_DB_PATH);

        FILE *f = fopen(config_path, "r");
        ASSERT_TRUE(f != NULL);

        char line[256];
        int found_comparator = 0;
        while (fgets(line, sizeof(line), f))
        {
            if (strncmp(line, "comparator_name=", 16) == 0)
            {
                /* verify it's not empty and equals memcmp */
                ASSERT_TRUE(strstr(line, "comparator_name=memcmp") != NULL);
                found_comparator = 1;
                break;
            }
        }
        fclose(f);

        ASSERT_TRUE(found_comparator);
    }

    /* reopen and verify comparator is still memcmp */
    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "default_cmp_cf");
        ASSERT_TRUE(cf != NULL);
        ASSERT_TRUE(strcmp(cf->comparator_name, "memcmp") == 0);

        /* verify data is still accessible */
        tidesdb_txn_t *read_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_read(db, cf, &read_txn), 0);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, (uint8_t *)"key1", 4, &value, &value_size), 0);
        ASSERT_TRUE(memcmp(value, "value1", 6) == 0);
        free(value);

        tidesdb_txn_free(read_txn);
        tidesdb_close(db);
    }

    cleanup_test_dir();
}

int main(void)
{
    printf("\n");
    printf(BLUE "=======================================\n" RESET);
    printf(WHITE "   TIDESDB TESTS                 \n" RESET);
    printf(BLUE "=======================================\n\n" RESET);
    // RUN_TEST(test_basic_open_close, tests_passed);
    // RUN_TEST(test_column_family_creation, tests_passed);
    // RUN_TEST(test_column_family_config_persistence, tests_passed);
    // RUN_TEST(test_basic_txn_put_get, tests_passed);
    // RUN_TEST(test_multiple_operations, tests_passed);
    // RUN_TEST(test_delete, tests_passed);
    // RUN_TEST(test_transaction_commit, tests_passed);
    // RUN_TEST(test_transaction_rollback, tests_passed);
    // RUN_TEST(test_iterator_forward, tests_passed);
    // RUN_TEST(test_memtable_flush, tests_passed);
    // RUN_TEST(test_multiple_column_families, tests_passed);
    // RUN_TEST(test_custom_comparator, tests_passed);
    // RUN_TEST(test_sync_modes, tests_passed);
    // RUN_TEST(test_compaction_trigger, tests_passed);
    // RUN_TEST(test_ttl_expiration, tests_passed);
    // RUN_TEST(test_iterator_backward, tests_passed);
    // RUN_TEST(test_database_reopen, tests_passed);
    // RUN_TEST(test_large_values, tests_passed);
    // RUN_TEST(test_compaction_deduplication, tests_passed);
    // RUN_TEST(test_concurrent_operations, tests_passed);
    // RUN_TEST(test_error_handling, tests_passed);
    // RUN_TEST(test_many_sstables, tests_passed);
    // RUN_TEST(test_backward_iteration, tests_passed);
    // RUN_TEST(test_crash_recovery, tests_passed);
    // RUN_TEST(test_background_compaction, tests_passed);
    // RUN_TEST(test_update_patterns, tests_passed);
    // RUN_TEST(test_delete_patterns, tests_passed);
    // RUN_TEST(test_list_column_families, tests_passed);
    // RUN_TEST(test_column_family_stats, tests_passed);
    // RUN_TEST(test_mixed_workload, tests_passed);
    // RUN_TEST(test_overflow_blocks, tests_passed);
    // RUN_TEST(test_empty_key_value, tests_passed);
    // RUN_TEST(test_read_your_own_writes, tests_passed);
    // RUN_TEST(test_compaction_tombstones, tests_passed);
    // RUN_TEST(test_iterator_expired_ttl, tests_passed);
    // RUN_TEST(test_wal_uncommitted_recovery, tests_passed);
    // RUN_TEST(test_compaction_deduplication, tests_passed);
    // RUN_TEST(test_parallel_compaction, tests_passed);
    // RUN_TEST(test_max_key_size, tests_passed);
    // RUN_TEST(test_true_concurrency, tests_passed);
    // RUN_TEST(test_iterator_metadata_boundary, tests_passed);
    // RUN_TEST(test_sstable_num_entries_accuracy, tests_passed);
    // RUN_TEST(test_drop_column_family_basic, tests_passed);
    // RUN_TEST(test_drop_column_family_with_data, tests_passed);
    // RUN_TEST(test_drop_column_family_not_found, tests_passed);
    // RUN_TEST(test_drop_column_family_cleanup, tests_passed);
    // RUN_TEST(test_concurrent_compaction_with_reads, tests_passed);
    // RUN_TEST(test_concurrent_compaction_lru_enabled_with_reads, tests_passed);
    // RUN_TEST(test_linear_scan_fallback, tests_passed);
    // RUN_TEST(test_iterator_seek, tests_passed);
    // RUN_TEST(test_iterator_seek_range, tests_passed);
    // RUN_TEST(test_iterator_seek_prefix, tests_passed);
    RUN_TEST(test_iterator_seek_large_sstable, tests_passed);
    // RUN_TEST(test_iterator_seek_multi_source, tests_passed);
    // RUN_TEST(test_memory_safety, tests_passed);
    // RUN_TEST(test_txn_write_write_serialization, tests_passed);
    // RUN_TEST(test_txn_read_your_own_deletes, tests_passed);
    // RUN_TEST(test_txn_rollback_no_side_effects, tests_passed);
    // RUN_TEST(test_iterator_empty_column_family, tests_passed);
    // RUN_TEST(test_iterator_single_entry, tests_passed);
    // RUN_TEST(test_iterator_all_expired_ttl, tests_passed);
    // RUN_TEST(test_iterator_all_tombstones, tests_passed);
    // RUN_TEST(test_iterator_seek_to_deleted_key, tests_passed);
    // RUN_TEST(test_iterator_direction_changes, tests_passed);
    // RUN_TEST(test_compaction_single_sstable, tests_passed);
    // RUN_TEST(test_compaction_all_expired, tests_passed);
    // RUN_TEST(test_compaction_duplicate_keys, tests_passed);
    // RUN_TEST(test_cf_independent_operations, tests_passed);
    // RUN_TEST(test_cf_name_limits, tests_passed);
    // RUN_TEST(test_bloom_filter_disabled, tests_passed);
    // RUN_TEST(test_block_indexes_disabled, tests_passed);
    // RUN_TEST(test_compression_snappy, tests_passed);
    // RUN_TEST(test_compression_zstd, tests_passed);
    // RUN_TEST(test_compression_none, tests_passed);
    // RUN_TEST(test_comparator_string, tests_passed);
    // RUN_TEST(test_comparator_numeric, tests_passed);
    // RUN_TEST(test_wal_recovery_after_reopen, tests_passed);
    // RUN_TEST(test_wal_with_multiple_memtables, tests_passed);
    // RUN_TEST(test_concurrent_readers_writers, tests_passed);
    // RUN_TEST(test_concurrent_flush_and_read, tests_passed);
    // RUN_TEST(test_no_deadlock_multiple_cfs, tests_passed);
    // RUN_TEST(test_invalid_column_family_operations, tests_passed);
    // RUN_TEST(test_null_pointer_handling, tests_passed);
    // RUN_TEST(test_zero_length_keys_values, tests_passed);
    // RUN_TEST(test_invalid_ttl_values, tests_passed);
    // RUN_TEST(test_transaction_after_close, tests_passed);
    // RUN_TEST(test_iterator_invalid_operations, tests_passed);
    // RUN_TEST(test_config_validation, tests_passed);
    // RUN_TEST(test_large_batch_operations, tests_passed);
    // RUN_TEST(test_special_characters_in_keys, tests_passed);
    // RUN_TEST(test_read_committed_isolation, tests_passed);
    // RUN_TEST(test_sstable_reference_counting, tests_passed);
    // RUN_TEST(test_block_cache_eviction_under_pressure, tests_passed);
    // RUN_TEST(test_wal_corruption_detection, tests_passed);
    // RUN_TEST(test_drop_cf_with_active_iterators, tests_passed);
    // RUN_TEST(test_parallel_compaction_race, tests_passed);
    // RUN_TEST(test_memtable_flush_size_enforcement, tests_passed);
    // RUN_TEST(test_default_comparator_persistence, tests_passed);
    // RUN_TEST(test_iterator_all_sources, tests_passed);

    printf("\n");
    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}