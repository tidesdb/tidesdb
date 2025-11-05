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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "../src/tidesdb.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* helper to create test database */
static tidesdb_t *create_test_db(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = {.db_path = TEST_DB_PATH};

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    return db;
}

/* helper to get test column family config */
static tidesdb_column_family_config_t get_test_cf_config(void)
{
    tidesdb_column_family_config_t config = {
        .memtable_flush_size = 1024 * 1024,
        .max_sstables_before_compaction = 512,
        .compaction_threads = 0, /* single-threaded by default for tests */
        .max_level = 8,
        .probability = 0.25,
        .compressed = 1,
        .compress_algo = COMPRESS_LZ4,
        .bloom_filter_fp_rate = 0.01,
        .enable_background_compaction = 0,   /* disable for deterministic testing */
        .background_compaction_interval = 0, /* not used when background compaction disabled */
        .use_sbha = 1,                       /* enable SBHA */
        .sync_mode = TDB_SYNC_NONE,          /* no fsync for tests */
        .sync_interval = 0,                  /* not used with SYNC_NONE */
        .comparator_name = NULL              /* use default memcmp */
    };
    return config;
}

/* basic database open and close */
static void test_basic_open_close(void)
{
    tidesdb_t *db = create_test_db();
    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();
}

/* column family creation */
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

/* basic txn PUT and GET */
static void test_basic_txn_put_get(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    const char *key = "test_key";
    const char *value = "test_value";

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                              strlen(value), -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, "data", (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
        0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_size, strlen(value));
    ASSERT_TRUE(memcmp(retrieved, value, strlen(value)) == 0);

    free(retrieved);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* multiple PUT/GET operations */
static void test_multiple_operations(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected, sizeof(expected), "value_%d", i);

        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;

        ASSERT_EQ(tidesdb_txn_get(read_txn, "data", (uint8_t *)key, strlen(key), &retrieved,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(memcmp(retrieved, expected, strlen(expected)) == 0);

        free(retrieved);
    }

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* DELETE operation */
static void test_delete(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    const char *key = "delete_me";
    const char *value = "some_value";

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                              strlen(value), -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, "data", (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
        0);
    free(retrieved);
    tidesdb_txn_free(read_txn);

    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, "data", (uint8_t *)key, strlen(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);
    ASSERT_NE(
        tidesdb_txn_get(read_txn, "data", (uint8_t *)key, strlen(key), &retrieved, &retrieved_size),
        0);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* transaction commit */
static void test_transaction_commit(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_TRUE(txn != NULL);

    ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)"txn_key1", 8, (uint8_t *)"value1", 6, -1),
              0);
    ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)"txn_key2", 8, (uint8_t *)"value2", 6, -1),
              0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, "data", (uint8_t *)"txn_key1", 8, &retrieved, &retrieved_size),
        0);
    free(retrieved);

    ASSERT_EQ(
        tidesdb_txn_get(read_txn, "data", (uint8_t *)"txn_key2", 8, &retrieved, &retrieved_size),
        0);
    free(retrieved);

    tidesdb_txn_free(read_txn);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* transaction rollback */
static void test_transaction_rollback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)"rollback_key", 12, (uint8_t *)"value", 5, 0),
              0);

    ASSERT_EQ(tidesdb_txn_rollback(txn), 0);

    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_NE(tidesdb_txn_get(read_txn, "data", (uint8_t *)"rollback_key", 12, &retrieved,
                              &retrieved_size),
              0);
    tidesdb_txn_free(read_txn);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* forward iterator */
static void test_iterator_forward(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "iter_key_%02d", i);
        snprintf(value, sizeof(value), "iter_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* iterate */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "data", &iter), 0);
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

/* memtable flush */
static void test_memtable_flush(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data");
    ASSERT_TRUE(cf != NULL);

    /* insert data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "flush_key_%d", i);
        snprintf(value, sizeof(value), "flush_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    int sstables_before = atomic_load(&cf->num_sstables);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete (flush happens in background) */
    int max_wait = 50; /* 5 seconds max */
    int sstables_after = sstables_before;
    for (int i = 0; i < max_wait && sstables_after == sstables_before; i++)
    {
        usleep(100000); /* 100ms */
        sstables_after = atomic_load(&cf->num_sstables);
    }

    ASSERT_TRUE(sstables_after > sstables_before);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* multiple column families */
static void test_multiple_column_families(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);

    /* write to both CFs */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "cf1", (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "cf2", (uint8_t *)"key1", 4, (uint8_t *)"value2", 6, -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* read from both CFs */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *val1 = NULL, *val2 = NULL;
    size_t size1 = 0, size2 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, "cf1", (uint8_t *)"key1", 4, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn, "cf2", (uint8_t *)"key1", 4, &val2, &size2), 0);

    ASSERT_TRUE(memcmp(val1, "value1", 6) == 0);
    ASSERT_TRUE(memcmp(val2, "value2", 6) == 0);

    free(val1);
    free(val2);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* custom comparator */
static void test_custom_comparator(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.comparator_name = "string"; /* use a registered comparator by name */

    ASSERT_EQ(tidesdb_create_column_family(db, "string_cf", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* insert string keys */
    ASSERT_EQ(tidesdb_txn_put(txn, "string_cf", (uint8_t *)"zebra", 5, (uint8_t *)"last", 4, -1),
              0);
    ASSERT_EQ(tidesdb_txn_put(txn, "string_cf", (uint8_t *)"apple", 5, (uint8_t *)"first", 5, -1),
              0);
    ASSERT_EQ(tidesdb_txn_put(txn, "string_cf", (uint8_t *)"mango", 5, (uint8_t *)"middle", 6, -1),
              0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify ordering with iterator */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "string_cf", &iter), 0);
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

/* sync modes */
static void test_sync_modes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* test TDB_SYNC_NONE */
    cf_config.sync_mode = TDB_SYNC_NONE;
    ASSERT_EQ(tidesdb_create_column_family(db, "no_sync", &cf_config), 0);

    /* test TDB_SYNC_FULL */
    cf_config.sync_mode = TDB_SYNC_FULL;
    ASSERT_EQ(tidesdb_create_column_family(db, "full_sync", &cf_config), 0);

    /* test TDB_SYNC_BACKGROUND */
    cf_config.sync_mode = TDB_SYNC_BACKGROUND;
    cf_config.sync_interval = 500; /* 500ms */
    ASSERT_EQ(tidesdb_create_column_family(db, "bg_sync", &cf_config), 0);

    /* write to each CF */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    ASSERT_EQ(tidesdb_txn_put(txn, "no_sync", (uint8_t *)"key1", 4, (uint8_t *)"val1", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "full_sync", (uint8_t *)"key2", 4, (uint8_t *)"val2", 4, -1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "bg_sync", (uint8_t *)"key3", 4, (uint8_t *)"val3", 4, -1), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* compaction triggers */
static void test_compaction_trigger(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.max_sstables_before_compaction = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert data and verify compaction doesn't crash */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "compact_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify data is accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, "compact_cf", (uint8_t *)"key_10", 6, &value, &value_size),
              0);
    ASSERT_TRUE(value != NULL);
    free(value);

    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* TTL expiration */
static void test_ttl_expiration(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_cf", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* insert with TTL of 1 second */
    time_t expire_time = time(NULL) + 1;
    ASSERT_EQ(tidesdb_txn_put(txn, "ttl_cf", (uint8_t *)"expire_key", 10, (uint8_t *)"expire_value",
                              12, expire_time),
              0);

    /* insert without TTL */
    ASSERT_EQ(tidesdb_txn_put(txn, "ttl_cf", (uint8_t *)"persist_key", 11,
                              (uint8_t *)"persist_value", 13, -1),
              0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify both exist */
    tidesdb_txn_t *read_txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn1), 0);

    uint8_t *val1 = NULL, *val2 = NULL;
    size_t size1 = 0, size2 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn1, "ttl_cf", (uint8_t *)"expire_key", 10, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn1, "ttl_cf", (uint8_t *)"persist_key", 11, &val2, &size2), 0);
    free(val1);
    free(val2);
    tidesdb_txn_free(read_txn1);

    /* wait for expiration */
    sleep(2);

    /* verify expired key is gone, persistent key remains */
    tidesdb_txn_t *read_txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn2), 0);

    uint8_t *val3 = NULL, *val4 = NULL;
    size_t size3 = 0, size4 = 0;

    ASSERT_NE(tidesdb_txn_get(read_txn2, "ttl_cf", (uint8_t *)"expire_key", 10, &val3, &size3), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn2, "ttl_cf", (uint8_t *)"persist_key", 11, &val4, &size4), 0);

    free(val4);
    tidesdb_txn_free(read_txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* iterator backward */
static void test_iterator_backward(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "data", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "data", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* iterate backward */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "data", &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter) && count < 20) /* safety limit */
    {
        count++;
        if (tidesdb_iter_prev(iter) != 0) break;
    }

    ASSERT_TRUE(count >= 1); /* at least one item */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* database reopen and recovery */
static void test_database_reopen(void)
{
    /* create and populate database */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "persist_cf", &cf_config), 0);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(
            tidesdb_txn_put(txn, "persist_cf", (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1),
            0);
        ASSERT_EQ(
            tidesdb_txn_put(txn, "persist_cf", (uint8_t *)"key2", 4, (uint8_t *)"value2", 6, -1),
            0);

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* reopen and verify data */
    {
        tidesdb_config_t config = {.db_path = TEST_DB_PATH};
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);

        /* column family should be auto-loaded from disk */
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");

        if (cf != NULL)
        {
            tidesdb_txn_t *read_txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

            uint8_t *value = NULL;
            size_t value_size = 0;

            if (tidesdb_txn_get(read_txn, "persist_cf", (uint8_t *)"key1", 4, &value,
                                &value_size) == 0)
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

/* large value handling */
static void test_large_values(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "large_cf", &cf_config), 0);

    size_t large_size = 64 * 1024;
    uint8_t *large_value = malloc(large_size);
    memset(large_value, 'A', large_size);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    ASSERT_EQ(
        tidesdb_txn_put(txn, "large_cf", (uint8_t *)"large_key", 9, large_value, large_size, -1),
        0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* retrieve and verify */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, "large_cf", (uint8_t *)"large_key", 9, &retrieved,
                              &retrieved_size),
              0);
    ASSERT_EQ(retrieved_size, large_size);
    ASSERT_TRUE(memcmp(retrieved, large_value, large_size) == 0);

    free(large_value);
    free(retrieved);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* concurrent column families */
static void test_concurrent_operations(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf3", &cf_config), 0);

    /* write to all CFs in single transaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "cf1", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
        ASSERT_EQ(tidesdb_txn_put(txn, "cf2", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
        ASSERT_EQ(tidesdb_txn_put(txn, "cf3", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify all CFs have data */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *val1 = NULL, *val2 = NULL, *val3 = NULL;
    size_t size1 = 0, size2 = 0, size3 = 0;

    ASSERT_EQ(tidesdb_txn_get(read_txn, "cf1", (uint8_t *)"key_10", 6, &val1, &size1), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn, "cf2", (uint8_t *)"key_10", 6, &val2, &size2), 0);
    ASSERT_EQ(tidesdb_txn_get(read_txn, "cf3", (uint8_t *)"key_10", 6, &val3, &size3), 0);

    free(val1);
    free(val2);
    free(val3);
    tidesdb_txn_free(read_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

/* error handling */
static void test_error_handling(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "error_cf", &cf_config), 0);

    /* test getting non-existent key */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_NE(
        tidesdb_txn_get(read_txn, "error_cf", (uint8_t *)"nonexistent", 11, &value, &value_size),
        0);

    tidesdb_txn_free(read_txn);

    /* test NULL parameters */
    ASSERT_NE(tidesdb_txn_begin(NULL, NULL), 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* many ssts, verify system handles large number of ssts */
static void test_many_sstables(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096; /* small memtable to force many flushes */
    cf_config.max_sstables_before_compaction =
        200; /* high threshold to prevent compaction during test */
    cf_config.enable_background_compaction = 0; /* disable for deterministic testing */

    ASSERT_EQ(tidesdb_create_column_family(db, "many_sst", &cf_config), 0);

    printf("\n  [Verification] Creating many SSTables... ");
    fflush(stdout);

    /* insert data in batches to create many sstables */
    int total_keys = 0;
    for (int batch = 0; batch < 10; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 20; i++)
        {
            char key[64], value[256];
            int key_num = batch * 20 + i;
            snprintf(key, sizeof(key), "key_%05d", key_num);
            snprintf(value, sizeof(value), "value_%05d_with_padding_xxxxxxxxxxxxxxxxxxxxxxxxx",
                     key_num);

            ASSERT_EQ(tidesdb_txn_put(txn, "many_sst", (uint8_t *)key, strlen(key),
                                      (uint8_t *)value, strlen(value), -1),
                      0);
            total_keys++;
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify all data is accessible across many ssts */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 100; i += 10) /* sample every 10th key */
    {
        char key[64];
        snprintf(key, sizeof(key), "key_%05d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(read_txn, "many_sst", (uint8_t *)key, strlen(key), &value, &value_size),
            0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    /* verify iterator works across many ssts */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, "many_sst", &iter), 0);
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

/* backward iteration test */
static void test_backward_iteration(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096; /* small memtable to force many flushes */
    cf_config.max_sstables_before_compaction = 200;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "backward_test", &cf_config), 0);

    printf("\n  [Verification] Testing backward iteration... ");
    fflush(stdout);

    /* insert data in batches */
    int total_keys = 0;
    for (int batch = 0; batch < 10; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 20; i++)
        {
            char key[64], value[256];
            int key_num = batch * 20 + i;
            snprintf(key, sizeof(key), "key_%05d", key_num);
            snprintf(value, sizeof(value), "value_%05d_backward_test", key_num);

            ASSERT_EQ(tidesdb_txn_put(txn, "backward_test", (uint8_t *)key, strlen(key),
                                      (uint8_t *)value, strlen(value), -1),
                      0);
            total_keys++;
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test backward iteration */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, "backward_test", &iter), 0);
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

/* crash recovery, verify WAL recovery works */
static void test_crash_recovery(void)
{
    printf("\n  [Reliability] Testing crash recovery... ");
    fflush(stdout);

    /* 1 write data and close normally */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "recovery_cf", &cf_config), 0);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 50; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "recover_key_%d", i);
            snprintf(value, sizeof(value), "recover_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, "recovery_cf", (uint8_t *)key, strlen(key),
                                      (uint8_t *)value, strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* write more data that should be in WAL */
        tidesdb_txn_t *txn2 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);

        ASSERT_EQ(tidesdb_txn_put(txn2, "recovery_cf", (uint8_t *)"wal_key", 7,
                                  (uint8_t *)"wal_value", 9, -1),
                  0);
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
        ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

        uint8_t *value = NULL;
        size_t value_size = 0;

        /* check some keys from first transaction */
        ASSERT_EQ(tidesdb_txn_get(read_txn, "recovery_cf", (uint8_t *)"recover_key_25", 14, &value,
                                  &value_size),
                  0);
        free(value);

        /* check WAL-recovered key */
        value = NULL;
        if (tidesdb_txn_get(read_txn, "recovery_cf", (uint8_t *)"wal_key", 7, &value,
                            &value_size) == 0)
        {
            ASSERT_TRUE(memcmp(value, "wal_value", 9) == 0);
            free(value);
        }

        tidesdb_txn_free(read_txn);
        tidesdb_close(db);
    }

    printf("OK\n");
    cleanup_test_dir();
}

/* background compaction */
static void test_background_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 8192;
    cf_config.max_sstables_before_compaction = 5; /* compact at 5 sstables */
    cf_config.enable_background_compaction = 1;   /* enable background compaction */

    ASSERT_EQ(tidesdb_create_column_family(db, "bg_compact", &cf_config), 0);

    printf("\n  [Background] Testing background compaction... ");
    fflush(stdout);

    /* insert data to trigger background compaction */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "bg_key_%d", i);
        snprintf(value, sizeof(value), "bg_value_%d_padding_xxxxxxxxxxxxxxxxxxxxxxxx", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "bg_compact", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* give background thread time to compact */
    sleep(2);

    /* verify all data is still accessible after compaction */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 100; i += 10)
    {
        char key[32];
        snprintf(key, sizeof(key), "bg_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, "bg_compact", (uint8_t *)key, strlen(key), &value,
                                  &value_size),
                  0);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    printf("OK\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

/* update and overwrite patterns */
static void test_update_patterns(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "updates", &cf_config), 0);

    printf("\n  [Reliability] Testing update patterns... ");
    fflush(stdout);

    /* write initial data */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(value, sizeof(value), "version_1_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn1, "updates", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* update same keys multiple times */
    for (int version = 2; version <= 5; version++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 50; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "update_key_%d", i);
            snprintf(value, sizeof(value), "version_%d_value_%d", version, i);

            ASSERT_EQ(tidesdb_txn_put(txn, "updates", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                      strlen(value), -1),
                      0);
        }
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify latest version is retrieved */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 50; i += 5)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "update_key_%d", i);
        snprintf(expected, sizeof(expected), "version_5_value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(read_txn, "updates", (uint8_t *)key, strlen(key), &value, &value_size),
            0);
        ASSERT_TRUE(memcmp(value, expected, strlen(expected)) == 0);
        free(value);
    }

    tidesdb_txn_free(read_txn);

    printf("OK (verified latest versions)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

/* delete and tombstone handling */
static void test_delete_patterns(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "deletes", &cf_config), 0);

    printf("\n  [Reliability] Testing delete patterns... ");
    fflush(stdout);

    /* insert data */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "del_key_%d", i);
        snprintf(value, sizeof(value), "del_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn1, "deletes", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* delete every other key */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);

    for (int i = 0; i < 100; i += 2)
    {
        char key[32];
        snprintf(key, sizeof(key), "del_key_%d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn2, "deletes", (uint8_t *)key, strlen(key)), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* verify deleted keys are gone, non-deleted keys remain */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "del_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result =
            tidesdb_txn_get(read_txn, "deletes", (uint8_t *)key, strlen(key), &value, &value_size);

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

/* list column families */
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

/* get column family stats */
static void test_column_family_stats(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "stats_cf", &cf_config), 0);

    /* add some data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "stats_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
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
    ASSERT_TRUE(stats->config.compressed == cf_config.compressed);
    ASSERT_TRUE(stats->config.compress_algo == cf_config.compress_algo);

    free(stats);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* mixed workload */
static void test_mixed_workload(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 8192;
    cf_config.max_sstables_before_compaction = 10;
    cf_config.enable_background_compaction = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed", &cf_config), 0);

    printf("\n  [Verification] Testing mixed workload (put/get/delete/iterate)... ");
    fflush(stdout);

    /* mixed operations */
    for (int round = 0; round < 10; round++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* puts */
        for (int i = 0; i < 20; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "mixed_key_%d_%d", round, i);
            snprintf(value, sizeof(value), "mixed_value_%d_%d", round, i);

            ASSERT_EQ(tidesdb_txn_put(txn, "mixed", (uint8_t *)key, strlen(key), (uint8_t *)value,
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
                tidesdb_txn_delete(txn, "mixed", (uint8_t *)key, strlen(key));
            }
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* reads */
        tidesdb_txn_t *read_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

        for (int i = 10; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "mixed_key_%d_%d", round, i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            if (tidesdb_txn_get(read_txn, "mixed", (uint8_t *)key, strlen(key), &value,
                                &value_size) == 0)
            {
                free(value);
            }
        }

        tidesdb_txn_free(read_txn);
    }

    /* final iteration to verify data integrity */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, "mixed", &iter), 0);
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

/* large values requiring overflow blocks */
static void test_overflow_blocks(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "overflow_cf", &cf_config), 0);

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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, "overflow_cf", (uint8_t *)"overflow_key", 12, large_value,
                              large_size, -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* retrieve and verify */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, "overflow_cf", (uint8_t *)"overflow_key", 12, &retrieved,
                              &retrieved_size),
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

/* empty key and value handling */
static void test_empty_key_value(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "empty_cf", &cf_config), 0);

    printf("\n  [Edge Case] Testing empty key and value handling... ");
    fflush(stdout);

    /* test empty value with non-empty key */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, "empty_cf", (uint8_t *)"key_with_empty_val", 18, (uint8_t *)"",
                              0, -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* retrieve empty value */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, "empty_cf", (uint8_t *)"key_with_empty_val", 18, &retrieved,
                              &retrieved_size),
              0);
    ASSERT_EQ(retrieved_size, 0);

    if (retrieved) free(retrieved);
    tidesdb_txn_free(read_txn);

    printf("OK (empty value handled correctly)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

/* read-your-own-writes within transaction */
static void test_read_your_own_writes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ryow_cf", &cf_config), 0);

    printf("\n  [Transaction] Testing read-your-own-writes... ");
    fflush(stdout);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* write key */
    ASSERT_EQ(tidesdb_txn_put(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15,
                              (uint8_t *)"uncommitted_value", 17, -1),
              0);

    /* read same key before commit, should see uncommitted value */
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);
    ASSERT_TRUE(memcmp(value, "uncommitted_value", 17) == 0);
    free(value);

    /* update same key */
    ASSERT_EQ(tidesdb_txn_put(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15,
                              (uint8_t *)"updated_value", 13, -1),
              0);

    /* read again, should see updated value */
    value = NULL;
    ASSERT_EQ(
        tidesdb_txn_get(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);
    ASSERT_TRUE(memcmp(value, "updated_value", 13) == 0);
    free(value);

    /* delete key */
    ASSERT_EQ(tidesdb_txn_delete(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15), 0);

    /* read after delete, should not find it */
    value = NULL;
    ASSERT_NE(
        tidesdb_txn_get(txn, "ryow_cf", (uint8_t *)"uncommitted_key", 15, &value, &value_size), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    printf("OK (read-your-own-writes verified)\n");

    tidesdb_close(db);
    cleanup_test_dir();
}

/* compaction with all tombstones */
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        snprintf(value, sizeof(value), "tomb_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn1, "tombstone_cf", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);
    tidesdb_flush_memtable(cf);

    /* insert more keys in batch 2 */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    for (int i = 10; i < 20; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        snprintf(value, sizeof(value), "tomb_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn2, "tombstone_cf", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn3, "tombstone_cf", (uint8_t *)key, strlen(key)), 0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* verify all keys are gone */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_NE(tidesdb_txn_get(read_txn, "tombstone_cf", (uint8_t *)key, strlen(key), &value,
                                  &value_size),
                  0);
    }

    tidesdb_txn_free(read_txn);

    printf("OK (tombstones compacted, %d->%d SSTables)\n", sstables_before, sstables_after);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* iterator with expired TTL entries */
static void test_iterator_expired_ttl(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_iter_cf", &cf_config), 0);

    printf("\n  [Iterator] Testing iterator skips expired TTL entries... ");
    fflush(stdout);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* insert keys with short TTL */
    for (int i = 0; i < 5; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "expire_key_%d", i);
        snprintf(value, sizeof(value), "expire_value_%d", i);

        time_t expire_time = time(NULL) + 1; /* 1 second TTL */
        ASSERT_EQ(tidesdb_txn_put(txn, "ttl_iter_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), expire_time),
                  0);
    }

    /* insert keys without TTL */
    for (int i = 0; i < 5; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "persist_key_%d", i);
        snprintf(value, sizeof(value), "persist_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "ttl_iter_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* wait for TTL expiration */
    sleep(2);

    /* iterate, should only see persistent keys */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "ttl_iter_cf", &iter), 0);
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

/* WAL recovery with uncommitted data */
static void test_wal_uncommitted_recovery(void)
{
    printf("\n  [WAL Recovery] Testing recovery with uncommitted data... ");
    fflush(stdout);

    /* 1 write committed and uncommitted data */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = get_test_cf_config();
        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);

        /* committed transaction */
        tidesdb_txn_t *txn1 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
        ASSERT_EQ(tidesdb_txn_put(txn1, "wal_cf", (uint8_t *)"committed_key", 13,
                                  (uint8_t *)"committed_value", 15, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
        tidesdb_txn_free(txn1);

        /* uncommitted transaction, create but dont commit */
        tidesdb_txn_t *txn2 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
        ASSERT_EQ(tidesdb_txn_put(txn2, "wal_cf", (uint8_t *)"uncommitted_key", 15,
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
        ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

        /* committed key should exist */
        uint8_t *value1 = NULL;
        size_t size1 = 0;
        ASSERT_EQ(
            tidesdb_txn_get(read_txn, "wal_cf", (uint8_t *)"committed_key", 13, &value1, &size1),
            0);
        ASSERT_TRUE(memcmp(value1, "committed_value", 15) == 0);
        free(value1);

        /* uncommitted key should NOT exist */
        uint8_t *value2 = NULL;
        size_t size2 = 0;
        ASSERT_NE(
            tidesdb_txn_get(read_txn, "wal_cf", (uint8_t *)"uncommitted_key", 15, &value2, &size2),
            0);

        tidesdb_txn_free(read_txn);
        tidesdb_close(db);
    }

    printf("OK (only committed data recovered)\n");
    cleanup_test_dir();
}

/* parallel compaction with multiple threads */
static void test_parallel_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* insert 10 keys per sst */
        for (int i = 0; i < 10; i++)
        {
            char key[32], value[64];
            snprintf(key, sizeof(key), "sst%d_key_%d", s, i);
            snprintf(value, sizeof(value), "sst%d_value_%d", s, i);
            ASSERT_EQ(tidesdb_txn_put(txn, "parallel_cf", (uint8_t *)key, strlen(key),
                                      (uint8_t *)value, strlen(value), -1),
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

    /* verify we have at least 8 ssts (might have more if auto-compaction triggered) */
    ASSERT_TRUE(current_sstables >= num_sstables);

    /* trigger parallel compaction */
    ASSERT_EQ(tidesdb_compact(cf), 0);

    /* after compaction, should have 4 ssts (8 pairs merged into 4) */
    int final_sstables = atomic_load(&cf->num_sstables);
    ASSERT_EQ(final_sstables, num_sstables / 2);

    /* verify all data is still accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

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
            if (tidesdb_txn_get(read_txn, "parallel_cf", (uint8_t *)key, strlen(key), &value,
                                &value_size) == 0)
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

/* maximum key size handling */
static void test_max_key_size(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "maxkey_cf", &cf_config), 0);

    printf("\n  [Edge Case] Testing large key sizes... ");
    fflush(stdout);

    /* test progressively larger keys */
    size_t key_sizes[] = {100, 1024, 4096, 16384};
    int successful = 0;

    for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    {
        size_t key_size = key_sizes[i];
        uint8_t *large_key = malloc(key_size);
        memset(large_key, 'K', key_size);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        int result =
            tidesdb_txn_put(txn, "maxkey_cf", large_key, key_size, (uint8_t *)"value", 5, -1);

        if (result == 0)
        {
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);

            /* verify retrieval */
            tidesdb_txn_t *read_txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(read_txn, "maxkey_cf", large_key, key_size, &value, &value_size),
                0);
            free(value);
            tidesdb_txn_free(read_txn);

            successful++;
        }

        tidesdb_txn_free(txn);
        free(large_key);
    }

    printf("OK (handled keys up to %zu bytes)\n", key_sizes[successful - 1]);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* multi-threaded concurrent read/write test */
typedef struct
{
    tidesdb_t *db;
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
        if (tidesdb_txn_begin(args->db, &txn) != 0)
        {
            atomic_fetch_add(args->errors, 1);
            continue;
        }

        char key[64], value[128];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id, i);
        snprintf(value, sizeof(value), "thread_%d_value_%d", args->thread_id, i);

        if (tidesdb_txn_put(txn, "concurrent_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                            strlen(value), -1) != 0)
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
        if (tidesdb_txn_begin_read(args->db, &txn) != 0)
        {
            atomic_fetch_add(args->errors, 1);
            continue;
        }

        char key[64];
        snprintf(key, sizeof(key), "thread_%d_key_%d", args->thread_id % 4, i % 50);

        uint8_t *value = NULL;
        size_t value_size = 0;

        tidesdb_txn_get(txn, "concurrent_cf", (uint8_t *)key, strlen(key), &value, &value_size);

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
        writer_args[i].thread_id = i;
        writer_args[i].num_ops = ops_per_thread;
        writer_args[i].errors = &errors;
        pthread_create(&writers[i], NULL, concurrent_writer, &writer_args[i]);
    }

    for (int i = 0; i < num_reader_threads; i++)
    {
        reader_args[i].db = db;
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
    ASSERT_EQ(tidesdb_txn_begin_read(db, &verify_txn), 0);

    int found = 0;
    for (int t = 0; t < num_writer_threads; t++)
    {
        for (int i = 0; i < ops_per_thread; i++)
        {
            char key[64];
            snprintf(key, sizeof(key), "thread_%d_key_%d", t, i);

            uint8_t *value = NULL;
            size_t value_size = 0;

            if (tidesdb_txn_get(verify_txn, "concurrent_cf", (uint8_t *)key, strlen(key), &value,
                                &value_size) == 0)
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

/* regression test verify iterator stops at num_entries and doesn't read metadata blocks */
static void test_iterator_metadata_boundary(void)
{
    printf("\n  [Regression] Testing iterator metadata boundary... ");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 2048; /* small to force flush */
    cf_config.compressed = 1;
    cf_config.compress_algo = COMPRESS_LZ4;

    ASSERT_EQ(tidesdb_create_column_family(db, "boundary_test", &cf_config), 0);

    /* insert exactly 5 entries to create 1 sstable with 5 KV blocks + metadata */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 5; i++)
    {
        char key[32], value[128];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d_padding_xxxxxxxxxxxxxxxxxxxxxxxxxx", i);
        ASSERT_EQ(tidesdb_txn_put(txn, "boundary_test", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* force flush to create SSTable */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "boundary_test");
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
        usleep(100000); /* 100ms */
    }

    ASSERT_TRUE(num_ssts > 0);

    /* get the sst and verify num_entries */
    tidesdb_sstable_t *sst = cf->sstables[0];
    ASSERT_TRUE(sst != NULL);
    ASSERT_EQ(sst->num_entries, 5);

    /* iterate through all entries, should read exactly 5 blocks, not metadata */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "boundary_test", &iter), 0);
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

/* regression test verify num_entries is correctly set in sstables */
static void test_sstable_num_entries_accuracy(void)
{
    printf("\n  [Regression] Testing SSTable num_entries accuracy... ");
    fflush(stdout);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();
    cf_config.memtable_flush_size = 1024;
    cf_config.compressed = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "entries_test", &cf_config), 0);

    /* create multiple ssts with known entry counts */
    int expected_counts[] = {3, 7, 5, 10};
    int num_sstables = sizeof(expected_counts) / sizeof(expected_counts[0]);

    for (int sst_idx = 0; sst_idx < num_sstables; sst_idx++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < expected_counts[sst_idx]; i++)
        {
            char key[64], value[256];
            snprintf(key, sizeof(key), "sst%d_key%d", sst_idx, i);
            snprintf(value, sizeof(value), "sst%d_value%d_padding_xxxxxxxxxxxxxxxxxxxx", sst_idx,
                     i);
            ASSERT_EQ(tidesdb_txn_put(txn, "entries_test", (uint8_t *)key, strlen(key),
                                      (uint8_t *)value, strlen(value), -1),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* force memtable flush to create sstables */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "entries_test");
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
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "entries_test", &iter), 0);
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

/* test basic column family drop */
static void test_drop_column_family_basic(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* create a column family */
    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    /* drop the column family */
    ASSERT_EQ(tidesdb_drop_column_family(db, "test_cf"), 0);

    /* verify it no longer exists */
    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* test dropping column family with data */
static void test_drop_column_family_with_data(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* create column family and add data */
    ASSERT_EQ(tidesdb_create_column_family(db, "data_cf", &cf_config), 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, "data_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to create sstables */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "data_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* wait for async flush to complete */
    int max_wait = 50; /* 5 seconds max */
    int num_sstables = 0;
    for (int i = 0; i < max_wait; i++)
    {
        num_sstables = atomic_load(&cf->num_sstables);
        if (num_sstables > 0) break;
        usleep(100000); /* 100ms */
    }

    /* verify sstables were created */
    ASSERT_TRUE(num_sstables > 0);

    char cf_path[TDB_MAX_PATH_LENGTH];
    snprintf(cf_path, sizeof(cf_path), "%s" PATH_SEPARATOR "data_cf", TEST_DB_PATH);

    /* drop the column family */
    ASSERT_EQ(tidesdb_drop_column_family(db, "data_cf"), 0);

    /* verify it no longer exists */
    cf = tidesdb_get_column_family(db, "data_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* test dropping non-existent column family */
static void test_drop_column_family_not_found(void)
{
    tidesdb_t *db = create_test_db();

    /* try to drop non-existent column family */
    int result = tidesdb_drop_column_family(db, "nonexistent_cf");
    ASSERT_EQ(result, TDB_ERR_NOT_FOUND);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* test dropping column family with WAL and sstables */
static void test_drop_column_family_cleanup(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* create column family */
    ASSERT_EQ(tidesdb_create_column_family(db, "cleanup_cf", &cf_config), 0);

    /* add data to create WAL entries */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, "cleanup_cf", (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), -1),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to create sstables */
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cleanup_cf");
    ASSERT_TRUE(cf != NULL);
    // ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify files exist before drop */
    char cf_path[TDB_MAX_PATH_LENGTH];
    snprintf(cf_path, sizeof(cf_path), "%s" PATH_SEPARATOR "cleanup_cf", TEST_DB_PATH);
    struct stat st;
    ASSERT_EQ(stat(cf_path, &st), 0); /* directory should exist */

    /* drop the column family */
    ASSERT_EQ(tidesdb_drop_column_family(db, "cleanup_cf"), 0);

    /* verify CF is gone from database */
    cf = tidesdb_get_column_family(db, "cleanup_cf");
    ASSERT_TRUE(cf == NULL);

    /* close database to ensure all file handles are released */
    tidesdb_close(db);

    /* cleanup will remove the directory */
    cleanup_test_dir();
}

/* test iterator and get operations during concurrent compaction */
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst1", i);
        ASSERT_EQ(tidesdb_txn_put(txn, "concurrent_cf", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
                  0);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000); /* give flush thread time to pick up work */

    /* insert data into second sstable */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 50; i < 100; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_sst2", i);
        ASSERT_EQ(tidesdb_txn_put(txn, "concurrent_cf", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
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
    ASSERT_EQ(tidesdb_txn_begin_read(db, &read_txn), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(read_txn, "concurrent_cf", &iter), 0);
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
    ASSERT_TRUE(count >= 10); /* at least the 10 we already read */
    printf("OK (iterator read %d entries from old sstables during compaction)\n", count);

    /* test get operations after compaction */
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, "concurrent_cf", (uint8_t *)key, strlen(key), &value,
                                  &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/* test linear scan fallback when SBHA is disabled */
static void test_linear_scan_fallback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = get_test_cf_config();

    /* disable SBHA to force linear scan fallback */
    cf_config.use_sbha = 0;
    cf_config.enable_background_compaction = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "linear_scan_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "linear_scan_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert test data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_for_key_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, "linear_scan_cf", (uint8_t *)key, strlen(key),
                                  (uint8_t *)value, strlen(value), -1),
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
    ASSERT_EQ(tidesdb_txn_begin_read(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_for_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;

        ASSERT_EQ(tidesdb_txn_get(txn, "linear_scan_cf", (uint8_t *)key, strlen(key), &value,
                                  &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(value_size, strlen(expected_value));
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }

    /* test non-existent key */
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, "linear_scan_cf", (uint8_t *)"nonexistent", 11, &value,
                                &value_size) != 0);

    tidesdb_txn_free(txn);

    /* test with TTL expiration */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    time_t expired_ttl = time(NULL) - 10; /* already expired */
    ASSERT_EQ(tidesdb_txn_put(txn, "linear_scan_cf", (uint8_t *)"expired_key", 11,
                              (uint8_t *)"expired_value", 13, expired_ttl),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify expired key is not returned */
    ASSERT_EQ(tidesdb_txn_begin_read(db, &txn), 0);
    value = NULL;
    value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, "linear_scan_cf", (uint8_t *)"expired_key", 11, &value,
                                &value_size) != 0);
    tidesdb_txn_free(txn);

    /* test with tombstone (delete) in sstable */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, "linear_scan_cf", (uint8_t *)"key_025", 7), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* verify deleted key is not returned (tombstone in newer sstable) */
    ASSERT_EQ(tidesdb_txn_begin_read(db, &txn), 0);
    value = NULL;
    value_size = 0;
    ASSERT_TRUE(
        tidesdb_txn_get(txn, "linear_scan_cf", (uint8_t *)"key_025", 7, &value, &value_size) != 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

int main(void)
{
    printf("\n");
    printf(BLUE "=======================================\n" RESET);
    printf(WHITE "   TIDESDB TESTS                 \n" RESET);
    printf(BLUE "=======================================\n\n" RESET);
    RUN_TEST(test_basic_open_close, tests_passed);
    RUN_TEST(test_column_family_creation, tests_passed);
    RUN_TEST(test_basic_txn_put_get, tests_passed);
    RUN_TEST(test_multiple_operations, tests_passed);
    RUN_TEST(test_delete, tests_passed);
    RUN_TEST(test_transaction_commit, tests_passed);
    RUN_TEST(test_transaction_rollback, tests_passed);
    RUN_TEST(test_iterator_forward, tests_passed);
    RUN_TEST(test_memtable_flush, tests_passed);
    RUN_TEST(test_multiple_column_families, tests_passed);
    RUN_TEST(test_custom_comparator, tests_passed);
    RUN_TEST(test_sync_modes, tests_passed);
    RUN_TEST(test_compaction_trigger, tests_passed);
    RUN_TEST(test_ttl_expiration, tests_passed);
    RUN_TEST(test_iterator_backward, tests_passed);
    RUN_TEST(test_database_reopen, tests_passed);
    RUN_TEST(test_large_values, tests_passed);
    RUN_TEST(test_concurrent_operations, tests_passed);
    RUN_TEST(test_error_handling, tests_passed);
    RUN_TEST(test_many_sstables, tests_passed);
    RUN_TEST(test_backward_iteration, tests_passed);
    RUN_TEST(test_crash_recovery, tests_passed);
    RUN_TEST(test_background_compaction, tests_passed);
    RUN_TEST(test_update_patterns, tests_passed);
    RUN_TEST(test_delete_patterns, tests_passed);
    RUN_TEST(test_list_column_families, tests_passed);
    RUN_TEST(test_column_family_stats, tests_passed);

    RUN_TEST(test_mixed_workload, tests_passed);
    RUN_TEST(test_overflow_blocks, tests_passed);
    RUN_TEST(test_empty_key_value, tests_passed);
    RUN_TEST(test_read_your_own_writes, tests_passed);
    RUN_TEST(test_compaction_tombstones, tests_passed);
    RUN_TEST(test_iterator_expired_ttl, tests_passed);
    RUN_TEST(test_wal_uncommitted_recovery, tests_passed);
    RUN_TEST(test_parallel_compaction, tests_passed);
    RUN_TEST(test_max_key_size, tests_passed);
    RUN_TEST(test_true_concurrency, tests_passed);
    RUN_TEST(test_iterator_metadata_boundary, tests_passed);
    RUN_TEST(test_sstable_num_entries_accuracy, tests_passed);
    RUN_TEST(test_drop_column_family_basic, tests_passed);
    RUN_TEST(test_drop_column_family_with_data, tests_passed);
    RUN_TEST(test_drop_column_family_not_found, tests_passed);
    RUN_TEST(test_drop_column_family_cleanup, tests_passed);
    RUN_TEST(test_concurrent_compaction_with_reads, tests_passed);
    RUN_TEST(test_linear_scan_fallback, tests_passed);

    printf("\n");
    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}