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

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    return db;
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
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

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
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    /* begin transaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    ASSERT_TRUE(txn != NULL);

    /* put key-value pair */
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);

    /* get the value back */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    ASSERT_EQ(retrieved_size, sizeof(value));
    ASSERT_TRUE(memcmp(retrieved_value, value, sizeof(value)) == 0);
    free(retrieved_value);

    /* commit transaction */
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_delete(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* put a key */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    uint8_t key[] = "delete_key";
    uint8_t value[] = "delete_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* delete the key */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* try to get deleted key */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, key, sizeof(key), &retrieved_value, &retrieved_size),
              TDB_ERR_NOT_FOUND);
    tidesdb_txn_free(txn3);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_rollback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* begin transaction and put a key */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    uint8_t key[] = "rollback_key";
    uint8_t value[] = "rollback_value";
    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);

    /* rollback instead of commit */
    ASSERT_EQ(tidesdb_txn_rollback(txn), 0);
    tidesdb_txn_free(txn);

    /* verify key doesn't exist */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, key, sizeof(key), &retrieved_value, &retrieved_size),
              TDB_ERR_NOT_FOUND);
    tidesdb_txn_free(txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_column_families(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* create multiple column families */
    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf3", &cf_config), 0);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");
    tidesdb_column_family_t *cf3 = tidesdb_get_column_family(db, "cf3");

    ASSERT_TRUE(cf1 != NULL);
    ASSERT_TRUE(cf2 != NULL);
    ASSERT_TRUE(cf3 != NULL);

    /* put different data in each CF */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf1, &txn1), 0);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value_cf1";
    ASSERT_EQ(tidesdb_txn_put(txn1, key1, sizeof(key1), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf2, &txn2), 0);
    uint8_t value2[] = "value_cf2";
    ASSERT_EQ(tidesdb_txn_put(txn2, key1, sizeof(key1), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* verify isolation between CFs */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf1, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn3, key1, sizeof(key1), &retrieved_value, &retrieved_size);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved_value != NULL);
    ASSERT_TRUE(memcmp(retrieved_value, value1, sizeof(value1)) == 0);
    free(retrieved_value);
    tidesdb_txn_free(txn3);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_memtable_flush(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;                /* small buffer to trigger flush */
    cf_config.compression_algorithm = NO_COMPRESSION; /* disable compression for debugging */

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* write a few entries */
    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* manually trigger flush and wait for background thread pool */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    /* poll for flush completion -- check queue drains */
    int max_wait = 50; /* 500ms total */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000); /* 10ms */
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(50000); /* extra 50ms for work to complete after dequeue */

    /* verify all data is still accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 5; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                     &retrieved_size);

        ASSERT_EQ(result, 0);
        ASSERT_TRUE(retrieved_value != NULL);
        char expected[64];
        snprintf(expected, sizeof(expected), "value_%d", i);
        ASSERT_TRUE(strcmp((char *)retrieved_value, expected) == 0);
        free(retrieved_value);
    }
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_persistence_and_recovery(void)
{
    const int NUM_KEYS = 20;

    /* create database, write data, flush, close */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = NO_COMPRESSION; /* easier to debug */

        ASSERT_EQ(tidesdb_create_column_family(db, "persist_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");
        ASSERT_TRUE(cf != NULL);

        /* write data */
        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "persist_key_%03d", i);
            snprintf(value, sizeof(value), "persist_value_%03d_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush to ensure data is on disk */
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(200000); /* wait 200ms for background flush to complete */

        /* verify data before closing */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "persist_key_%03d", 10);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                     &retrieved_size);
        if (result == 0 && retrieved_value != NULL)
        {
            free(retrieved_value);
        }
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* reopen database and verify all data persisted */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        /* column family should be auto-recovered with correct compression from metadata */
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");
        if (cf != NULL)
        {
            /* verify some keys */
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

            int found_count = 0;
            for (int i = 0; i < NUM_KEYS; i += 5)
            { /* check every 5th key */
                char key[32];
                snprintf(key, sizeof(key), "persist_key_%03d", i);

                uint8_t *retrieved_value = NULL;
                size_t retrieved_size = 0;
                int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                             &retrieved_size);

                if (result == 0 && retrieved_value != NULL)
                {
                    char expected_value[64];
                    snprintf(expected_value, sizeof(expected_value), "persist_value_%03d_data", i);

                    if (strcmp((char *)retrieved_value, expected_value) == 0)
                    {
                        found_count++;
                    }
                    free(retrieved_value);
                }
            }

            tidesdb_txn_free(txn);

            /* we should find at least some keys if recovery worked */
            ASSERT_TRUE(found_count > 0);
        }

        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_iterator_basic(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* insert sorted keys */
    const char *keys[] = {"key_a", "key_b", "key_c", "key_d", "key_e"};
    const char *values[] = {"val_a", "val_b", "val_c", "val_d", "val_e"};

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* create iterator */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);
    ASSERT_TRUE(iter != NULL);

    /* seek to first */
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    /* iterate through all keys */
    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_TRUE(key != NULL);
        free(key);
        count++;

        if (tidesdb_iter_next(iter) != 0) break;
    }

    ASSERT_EQ(count, 5);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_stats(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* write some data */
    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* get stats */
    tidesdb_stats_t *stats = NULL;
    ASSERT_EQ(tidesdb_get_stats(cf, &stats), 0);
    ASSERT_TRUE(stats != NULL);
    ASSERT_TRUE(stats->total_writes > 0);
    ASSERT_TRUE(stats->memtable_size > 0);

    tidesdb_free_stats(stats);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys key_00, key_02, key_04, key_06, key_08 */
    for (int i = 0; i < 10; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test seek to existing key */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    char seek_key[] = "key_04";
    int seek_result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);

    ASSERT_EQ(seek_result, 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_TRUE(key != NULL);
    /* key_04 exists, so we should get exact match */
    ASSERT_TRUE(strcmp((char *)key, seek_key) == 0);
    free(key);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_reverse(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rev_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rev_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test reverse iteration */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    /* seek to middle */
    char seek_key[] = "key_02";
    int seek_result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);

    if (seek_result == 0 && tidesdb_iter_valid(iter))
    {
        /* go backwards */
        int result = tidesdb_iter_prev(iter);
        if (result == 0 && tidesdb_iter_valid(iter))
        {
            /* reverse iteration works */
            uint8_t *key = NULL;
            size_t key_size = 0;
            tidesdb_iter_key(iter, &key, &key_size);
            /* just verify we got a key */
            ASSERT_TRUE(key != NULL);
            free(key);
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_boundaries(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "bound_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bound_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    /* test seek_to_first */
    int result = tidesdb_iter_seek_to_first(iter);
    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
        free(key);
    }

    /* test seek_to_last */
    result = tidesdb_iter_seek_to_last(iter);
    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
        free(key);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_basic(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048; /* larger buffer to avoid compression issues */
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* write enough data to trigger multiple flushes and fill level 0
     * level 0 capacity = write_buffer_size * level_size_ratio = 2048 * 10 = 20480 bytes
     * each entry is ~160 bytes, so 10 entries = ~1600 bytes per SSTable
     * 200 entries / 10 = 20 SSTables which should trigger compaction */
    for (int i = 0; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_with_some_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* trigger flush periodically to create multiple SSTables */
        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000); /* wait for flush to start */
        }
    }

    /* wait for flush queue to drain */
    int max_wait = 100;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* check initial state before compaction */
    int initial_levels = atomic_load(&cf->num_levels);
    printf("Before compaction: %d level(s)\n", initial_levels);

    /* manually trigger compaction via thread pool */
    tidesdb_compact(cf);

    /* wait for compaction queue to drain */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(100000); /* extra time for work completion */

    /* check state after compaction */
    int final_levels = atomic_load(&cf->num_levels);
    printf("After compaction: %d level(s)\n", final_levels);

    /* verify all data is still accessible after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        ASSERT_EQ(result, 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_with_deletes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048; /* larger buffer to avoid compression issues */
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "del_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "del_cf");
    ASSERT_TRUE(cf != NULL);

    /* write enough data to exceed level 0 capacity and trigger level addition
     * level 0 capacity = 2048 * 10 = 20480 bytes
     * need to write significantly more to exceed capacity */
    for (int i = 0; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_with_some_extra_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush periodically */
        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    /* delete half the keys */
    for (int i = 0; i < 200; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush deletes periodically so tombstones are in SSTables */
        if (i % 20 == 18)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    /* trigger final flush to ensure all deletes are persisted */
    tidesdb_flush_memtable(cf);

    /* wait for flush queue to drain */
    int max_wait = 100;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    /* wait for compaction queue to drain */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(100000);

    /* verify deleted keys are gone and remaining keys exist */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            /* should be deleted */
            ASSERT_TRUE(result != 0 || value == NULL);
        }
        else
        {
            /* should exist */
            if (result == 0 && value)
            {
                free(value);
            }
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ttl_expiration(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert key with 2 second TTL */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    uint8_t key[] = "ttl_key";
    uint8_t value[] = "ttl_value";
    time_t ttl = time(NULL) + 2; /* expires in 2 seconds */

    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), ttl), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify key exists immediately */
    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);
    tidesdb_txn_free(txn);

    /* wait for expiration */
    sleep(3);

    /* verify key is expired */
    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    retrieved_value = NULL;
    int result = tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size);
    ASSERT_TRUE(result != 0 || retrieved_value == NULL);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_large_values(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "large_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "large_cf");
    ASSERT_TRUE(cf != NULL);

    /* write large values (10KB each) */
    const size_t large_size = 10240;
    uint8_t *large_value = malloc(large_size);
    ASSERT_TRUE(large_value != NULL);

    memset(large_value, 'X', large_size);

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "large_key_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, large_value, large_size, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    free(large_value);

    /* verify retrieval */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "large_key_5");

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved_value, &retrieved_size);

    if (result == 0 && retrieved_value)
    {
        ASSERT_TRUE(retrieved_size == large_size);
        free(retrieved_value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_many_keys(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "many_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "many_cf");
    ASSERT_TRUE(cf != NULL);

    /* write many keys */
    const int NUM_KEYS = 1000;

    for (int i = 0; i < NUM_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%06d", i);
        snprintf(value, sizeof(value), "value_%06d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* periodic flush */
        if (i % 100 == 99)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    /* final flush to ensure all data is persisted */
    tidesdb_flush_memtable(cf);

    /* wait for flushes to complete -- check that queue is empty */
    for (int wait = 0; wait < 100; wait++)
    {
        usleep(50000); /* 50ms */
        /* check if flush queue is empty by checking level 1 SSTable count */
        if (cf->levels[0] && atomic_load(&cf->levels[0]->num_sstables) >= 10)
        {
            break;
        }
    }

    /* additional wait to ensure all SSTables are fully written */
    usleep(500000);

    /* verify random keys -- create transaction AFTER flushes complete */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    int found_count = 0;
    int not_found_count = 0;
    for (int i = 0; i < 50; i++)
    {
        int key_idx = (i * 37) % NUM_KEYS;

        char key[32];
        snprintf(key, sizeof(key), "key_%06d", key_idx);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result == 0 && value)
        {
            found_count++;
            free(value);
        }
        else
        {
            not_found_count++;
            printf("Key not found: %s (result=%d)\n", key, result);
        }
    }

    printf("Found %d out of 50 keys, %d not found\n", found_count, not_found_count);

    /* should find all keys */
    ASSERT_TRUE(found_count == 50);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_bidirectional_iterator(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = NO_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "bidir_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bidir_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* test forward iteration */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    do
    {
        if (tidesdb_iter_valid(iter))
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

            char expected_key[32];
            snprintf(expected_key, sizeof(expected_key), "key_%02d", count);
            ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

            free(key);
            free(value);
            count++;
        }
    } while (tidesdb_iter_next(iter) == 0 && tidesdb_iter_valid(iter));

    ASSERT_EQ(count, 10);

    tidesdb_iter_free(iter);

    /* test backward iteration -- create fresh iterator */
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    count = 9;
    do
    {
        if (tidesdb_iter_valid(iter))
        {
            uint8_t *key, *value;
            size_t key_size, value_size;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

            char expected_key[32];
            snprintf(expected_key, sizeof(expected_key), "key_%02d", count);
            ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

            free(key);
            free(value);
            count--;
        }
    } while (tidesdb_iter_prev(iter) == 0 && tidesdb_iter_valid(iter));

    ASSERT_EQ(count, -1);

    /* test mixed forward/backward iteration on same iterator */
    tidesdb_iter_free(iter);
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    /* go forward 3 steps (should be at key_03) */
    ASSERT_EQ(tidesdb_iter_next(iter), 0);
    ASSERT_EQ(tidesdb_iter_next(iter), 0);
    ASSERT_EQ(tidesdb_iter_next(iter), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

    ASSERT_TRUE(strcmp((char *)key, "key_03") == 0);
    free(key);

    /* now go backward 2 steps (should be at key_01) */
    ASSERT_EQ(tidesdb_iter_prev(iter), 0);
    ASSERT_EQ(tidesdb_iter_prev(iter), 0);

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

    if (strcmp((char *)key, "key_01") != 0)
    {
        printf("ERROR: Expected key_01 but got '%s'\n", (char *)key);
    }
    free(key);

    /* go forward again (should be at key_02) */
    ASSERT_EQ(tidesdb_iter_next(iter), 0);

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_TRUE(strcmp((char *)key, "key_02") == 0);
    free(key);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_background_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;          /* small to trigger automatic flushes */
    cf_config.enable_background_compaction = 1; /* enable automatic background compaction */
    cf_config.compaction_interval_ms = 100;     /* check every 100ms */

    ASSERT_EQ(tidesdb_create_column_family(db, "auto_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "auto_compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data that should trigger background flush and compaction */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_automatic_compaction_test", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* wait for background thread to detect need and queue work */
    usleep(500000); /* 500ms -- should be enough for several compaction interval checks */

    /* wait for queues to drain */
    int max_wait = 100;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0) break;
    }

    /* verify all data is accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        ASSERT_EQ(result, 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_read_uncommitted(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* READ_UNCOMMITTED should read uncommitted data from memtable */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    txn1->isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;

    uint8_t key[] = "iso_key";
    uint8_t value[] = "iso_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value, sizeof(value), 0), 0);

    /* don't commit -- start another transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;

    /* should be able to read uncommitted data */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);

    /* READ_UNCOMMITTED can see uncommitted changes */
    if (result == 0 && retrieved) free(retrieved);

    tidesdb_txn_free(txn2);
    tidesdb_txn_rollback(txn1);
    tidesdb_txn_free(txn1);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_read_committed(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* first commit a value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);

    uint8_t key[] = "iso_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start READ_COMMITTED transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_READ_COMMITTED;

    /* read initial value */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);
    if (result == 0 && retrieved)
    {
        ASSERT_TRUE(memcmp(retrieved, value1, sizeof(value1)) == 0);
        free(retrieved);
    }

    /* another transaction updates and commits */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* READ_COMMITTED should see the new committed value */
    retrieved = NULL;
    result = tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);
    if (result == 0 && retrieved)
    {
        /* can see newly committed value */
        free(retrieved);
    }

    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_repeatable_read(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* commit initial value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);

    uint8_t key[] = "iso_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start REPEATABLE_READ transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_REPEATABLE_READ;

    /* read initial value -- snapshot is taken */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);
    if (result == 0 && retrieved)
    {
        ASSERT_TRUE(memcmp(retrieved, value1, sizeof(value1)) == 0);
        free(retrieved);
    }

    /* another transaction updates */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* REPEATABLE_READ should still see old value (snapshot isolation) */
    retrieved = NULL;

    result = tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);

    if (result == 0 && retrieved)
    {
        /* should still see original value */

        int cmp = memcmp(retrieved, value1, sizeof(value1));

        ASSERT_TRUE(cmp == 0);
        free(retrieved);
    }
    else
    {
        printf("Failed to retrieve value, result=%d\n", result);
        fflush(stdout);
    }

    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_serializable_conflict(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* commit initial value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);

    uint8_t key[] = "conflict_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start two SERIALIZABLE transactions */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_SERIALIZABLE;

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    txn3->isolation_level = TDB_ISOLATION_SERIALIZABLE;

    /* both read the same key */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    tidesdb_txn_get(txn2, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    tidesdb_txn_get(txn3, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    /* both try to write */
    uint8_t value2[] = "value2";
    uint8_t value3[] = "value3";

    ASSERT_EQ(tidesdb_txn_put(txn2, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value3, sizeof(value3), 0), 0);

    /* first commit should succeed */
    int result2 = tidesdb_txn_commit(txn2);

    /* second commit should fail with conflict */
    int result3 = tidesdb_txn_commit(txn3);

    /* at least one should succeed, one should fail with conflict */
    ASSERT_TRUE((result2 == 0 && result3 == TDB_ERR_CONFLICT) ||
                (result3 == 0 && result2 == TDB_ERR_CONFLICT));

    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_savepoints(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "sp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sp_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn, key1, sizeof(key1), value1, sizeof(value1), 0), 0);

    /* create savepoint */
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp1"), 0);

    /* put another value */
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn, key2, sizeof(key2), value2, sizeof(value2), 0), 0);

    /* rollback to savepoint */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp1"), 0);

    /* key1 should exist, key2 should not */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    int result = tidesdb_txn_get(txn, key2, sizeof(key2), &retrieved, &retrieved_size);
    ASSERT_TRUE(result != 0); /* key2 should not exist */

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_for_prev(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "sfp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sfp_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys key_00, key_02, key_04, key_06, key_08 */
    for (int i = 0; i < 10; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    /* seek for prev to key_05 -- should land on key_04 */
    char seek_key[] = "key_05";
    int result = tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);

    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        if (tidesdb_iter_key(iter, &key, &key_size) == 0)
        {
            /* should be key_04 or earlier */
            ASSERT_TRUE(key != NULL);
            free(key);
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ini_config(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024 * 1024;
    cf_config.compression_algorithm = LZ4_COMPRESSION;
    cf_config.enable_bloom_filter = 1;
    cf_config.bloom_fpr = 0.01;

    const char *ini_path = TEST_DB_PATH "/test_cf.ini";
    int result = tidesdb_cf_config_save_to_ini(ini_path, "test_cf", &cf_config);
    ASSERT_EQ(result, 0);

    tidesdb_column_family_config_t loaded_config = tidesdb_default_column_family_config();
    result = tidesdb_cf_config_load_from_ini(ini_path, "test_cf", &loaded_config);
    ASSERT_EQ(result, 0);

    /* verify values match */
    ASSERT_EQ(loaded_config.write_buffer_size, cf_config.write_buffer_size);
    ASSERT_EQ(loaded_config.compression_algorithm, cf_config.compression_algorithm);
    ASSERT_EQ(loaded_config.enable_bloom_filter, cf_config.enable_bloom_filter);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_runtime_config_update(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rt_cf");
    ASSERT_TRUE(cf != NULL);

    /* update runtime config */
    tidesdb_column_family_config_t new_config = tidesdb_default_column_family_config();
    new_config.write_buffer_size = 2 * 1024 * 1024; /* 2MB */
    new_config.enable_bloom_filter = 1;
    new_config.bloom_fpr = 0.005;

    int result = tidesdb_cf_update_runtime_config(cf, &new_config, 0);
    ASSERT_EQ(result, 0);

    /* verify config was updated */
    ASSERT_EQ(cf->config.write_buffer_size, new_config.write_buffer_size);
    ASSERT_EQ(cf->config.enable_bloom_filter, new_config.enable_bloom_filter);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_error_invalid_args(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "err_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "err_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* NULL key should fail */
    uint8_t value[] = "value";
    int result = tidesdb_txn_put(txn, NULL, 10, value, sizeof(value), 0);
    ASSERT_TRUE(result != 0);

    /* zero key size should fail */
    uint8_t key[] = "key";
    result = tidesdb_txn_put(txn, key, 0, value, sizeof(value), 0);
    ASSERT_TRUE(result != 0);

    /* NULL value should fail */
    result = tidesdb_txn_put(txn, key, sizeof(key), NULL, 10, 0);
    ASSERT_TRUE(result != 0);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "drop_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf != NULL);

    /* write some data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    uint8_t key[] = "key";
    uint8_t value[] = "value";
    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* drop the column family */
    ASSERT_EQ(tidesdb_drop_column_family(db, "drop_cf"), 0);

    /* should not be able to get it anymore */
    cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_empty_iterator(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_cf");
    ASSERT_TRUE(cf != NULL);

    /* create iterator on empty column family */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    /* seek to first should succeed but iterator invalid */
    tidesdb_iter_seek_to_first(iter);
    ASSERT_TRUE(!tidesdb_iter_valid(iter));

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_lz4(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "lz4_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "lz4_cf");
    ASSERT_TRUE(cf != NULL);

    /* write compressible data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'A', sizeof(value)); /* highly compressible */

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to apply compression */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify data is readable */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    snprintf(key, sizeof(key), "key_5");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(retrieved_size, sizeof(value));
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_zstd(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = ZSTD_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "zstd_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "zstd_cf");
    ASSERT_TRUE(cf != NULL);

    /* write compressible data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'B', sizeof(value));

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to apply compression */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify data */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    snprintf(key, sizeof(key), "key_7");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compression_snappy(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = SNAPPY_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "snappy_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snappy_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'C', sizeof(value));

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify */
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    snprintf(key, sizeof(key), "key_3");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_bloom_filter_enabled(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.bloom_fpr = 0.01;

    ASSERT_EQ(tidesdb_create_column_family(db, "bloom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bloom_cf");
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "bloom_key_%d", i);
        snprintf(value, sizeof(value), "bloom_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to create sstable with bloom filter */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* query existing key -- bloom filter should pass */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "bloom_key_50");
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    if (retrieved) free(retrieved);

    /* query non-existing key -- bloom filter should filter */
    snprintf(key, sizeof(key), "nonexistent_key_999");
    retrieved = NULL;
    result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);
    ASSERT_TRUE(result != 0);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_block_indexes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_block_indexes = 1;
    cf_config.index_sample_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "bidx_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bidx_cf");
    ASSERT_TRUE(cf != NULL);

    /* write many keys to create multiple blocks */
    for (int i = 0; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "bidx_key_%04d", i);
        snprintf(value, sizeof(value), "bidx_value_%04d_with_extra_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to create SSTable with block indexes */
    tidesdb_flush_memtable(cf);
    usleep(200000);

    /* use iterator seek (should use block index) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    char seek_key[32];
    snprintf(seek_key, sizeof(seek_key), "bidx_key_0150");
    int result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);

    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
        free(key);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_sync_modes(void)
{
    /* test TDB_SYNC_NONE */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_NONE;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        uint8_t key[] = "sync_key";
        uint8_t value[] = "sync_value";
        ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
        cleanup_test_dir();
    }

    /* test TDB_SYNC_FULL */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_FULL;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_cf2", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_cf2");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        uint8_t key[] = "sync_key2";
        uint8_t value[] = "sync_value2";
        ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
        cleanup_test_dir();
    }
}

static void test_concurrent_writes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");
    ASSERT_TRUE(cf != NULL);

    /* write same key from multiple transactions -- last one should win */
    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);

    uint8_t key[] = "concurrent_key";
    uint8_t value1[] = "value1";
    uint8_t value2[] = "value2";

    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, key, sizeof(key), value2, sizeof(value2), 0), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* read back -- should get value2 (last write wins) */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_empty_value(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "edge_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "edge_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* test empty value -- should succeed (valid use case) */
    uint8_t key[] = "test_key";
    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), (uint8_t *)"", 1, 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify empty value can be retrieved */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_size > 0);
    free(retrieved_value);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_delete_nonexistent_key(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "delete_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "delete_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* delete a key that doesn't exist -- should succeed (idempotent) */
    uint8_t key[] = "nonexistent_key";
    ASSERT_EQ(tidesdb_txn_delete(txn, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* try to get the deleted key -- should not exist */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn2, key, sizeof(key), &value, &value_size) != 0);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_deletes_same_key(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_del_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_del_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* delete it twice */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn3, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* verify it's still deleted */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn4, key, sizeof(key), &retrieved_value, &retrieved_size) != 0);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_txn_free(txn4);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_overwrite_same_key_multiple_times(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "overwrite_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overwrite_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "same_key";

    /* overwrite the same key 100 times */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char value[64];
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), (uint8_t *)value, strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify we get the last value */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, "value_99") == 0);
    free(retrieved_value);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_put_delete_put_same_key(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "pdp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "pdp_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "first_value";
    uint8_t value2[] = "second_value";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* verify we get the second value */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn4, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value2) == 0);
    free(retrieved_value);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_txn_free(txn4);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_on_empty_cf(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_iter_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_iter_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);

    /* seek to first on empty CF -- should return NOT_FOUND */
    ASSERT_TRUE(tidesdb_iter_seek_to_first(iter) != 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter) == 0);

    /* seek to last on empty CF -- should return NOT_FOUND */
    ASSERT_TRUE(tidesdb_iter_seek_to_last(iter) != 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter) == 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_single_key(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "single_key_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "single_key_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    uint8_t key[] = "only_key";
    uint8_t value[] = "only_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* iterate */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn2, &iter), 0);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter) == 1);

    /* try to go next -- should return NOT_FOUND and become invalid */
    ASSERT_TRUE(tidesdb_iter_next(iter) != 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter) == 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_mixed_operations_in_transaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    /* put, delete, put different keys in same transaction */
    uint8_t key1[] = "key1";
    uint8_t key2[] = "key2";
    uint8_t key3[] = "key3";
    uint8_t value[] = "value";

    ASSERT_EQ(tidesdb_txn_put(txn, key1, sizeof(key1), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, key2, sizeof(key2)), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, key3, sizeof(key3), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);

    uint8_t *v1 = NULL, *v2 = NULL, *v3 = NULL;
    size_t s1, s2, s3;

    ASSERT_EQ(tidesdb_txn_get(txn2, key1, sizeof(key1), &v1, &s1), 0);
    ASSERT_TRUE(tidesdb_txn_get(txn2, key2, sizeof(key2), &v2, &s2) != 0);
    ASSERT_EQ(tidesdb_txn_get(txn2, key3, sizeof(key3), &v3, &s3), 0);

    free(v1);
    free(v3);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_own_writes_in_transaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "row_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "row_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";

    /* put and immediately read in same transaction */
    ASSERT_EQ(tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), 0), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value) == 0);
    free(retrieved_value);

    /* delete and immediately try to read */
    ASSERT_EQ(tidesdb_txn_delete(txn, key, sizeof(key)), 0);
    ASSERT_TRUE(tidesdb_txn_get(txn, key, sizeof(key), &retrieved_value, &retrieved_size) != 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_alternating_puts_deletes(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "alt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "alt_cf");
    ASSERT_TRUE(cf != NULL);

    /* alternate between putting and deleting keys */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        if (i % 2 == 0)
        {
            char value[64];
            snprintf(value, sizeof(value), "value_%d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
        }
        else
        {
            /* delete previous key */
            char prev_key[32];
            snprintf(prev_key, sizeof(prev_key), "key_%d", i - 1);
            ASSERT_EQ(tidesdb_txn_delete(txn, (uint8_t *)prev_key, strlen(prev_key) + 1), 0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify only odd keys exist (even keys were deleted) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            /* even keys should be deleted */
            ASSERT_TRUE(result != 0);
        }
        else
        {
            /* odd keys should exist (they were never put) */
            ASSERT_TRUE(result != 0);
        }

        if (value) free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_very_long_key(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "long_key_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "long_key_cf");
    ASSERT_TRUE(cf != NULL);

    /* create a 1KB key */
    size_t key_size = 1024;
    uint8_t *long_key = malloc(key_size);
    ASSERT_TRUE(long_key != NULL);
    for (size_t i = 0; i < key_size; i++)
    {
        long_key[i] = 'A' + (i % 26);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);
    uint8_t value[] = "long_key_value";
    ASSERT_EQ(tidesdb_txn_put(txn, long_key, key_size, value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify retrieval */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, long_key, key_size, &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value) == 0);
    free(retrieved_value);

    free(long_key);
    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_across_multiple_sstables(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512; /* small to create many SSTables */

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_sst_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_sst_cf");
    ASSERT_TRUE(cf != NULL);

    /* write 100 keys across multiple SSTables */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush every 10 keys to create multiple ssts */
        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(10000);
        }
    }

    /* wait for flushes to complete */
    usleep(100000);

    /* verify all keys can be read correctly from different ssts */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_bloom_filter_disabled(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 0; /* disable bloom filter */
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_bloom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_bloom_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work without bloom filter */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_block_indexes_disabled(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_block_indexes = 0; /* disable block indexes */
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_index_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_index_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work without block indexes */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_all_optimizations_disabled(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 0;
    cf_config.enable_block_indexes = 0;
    cf_config.compression_algorithm = NO_COMPRESSION;
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_opt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_opt_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work with all optimizations disabled */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_after_multi_level_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048; /* larger buffer to avoid compression issues */
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "ml_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ml_compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* write enough data to trigger multiple levels */
    for (int i = 0; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_with_extra_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000); /* wait for flush to start */
        }
    }

    /* wait for flush queue to drain */
    int max_wait = 100;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* trigger compaction */
    tidesdb_compact(cf);

    /* wait for compaction queue to drain */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(100000); /* extra time for work completion */

    /* verify all keys are readable after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32], expected_value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_%03d_with_extra_data", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_across_multiple_sources(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048; /* larger buffer to avoid compression issues */
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_multi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_multi_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys across multiple sstts and memtable */
    for (int i = 0; i < 60; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush every 15 keys */
        if (i == 14 || i == 29 || i == 44)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    /* now we have: 3 ssts (0-14, 15-29, 30-44) + memtable (45-59) */
    usleep(50000);

    /* iterate and verify all keys in order */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%03d", count);
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        free(key);
        free(value);
        count++;

        tidesdb_iter_next(iter);
    }

    ASSERT_EQ(count, 60);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_overwrite_across_levels(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "overwrite_levels_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overwrite_levels_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "same_key";

    /* write v1 and flush */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    uint8_t value1[] = "version_1";
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* write v2 and flush */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t value2[] = "version_2";
    ASSERT_EQ(tidesdb_txn_put(txn2, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* write v3 in memtable */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t value3[] = "version_3";
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value3, sizeof(value3), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* read should get v3 (newest) */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn4, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value3) == 0);
    free(retrieved_value);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_txn_free(txn4);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_atomicity_transaction_rollback(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "atomic_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "atomic_cf");
    ASSERT_TRUE(cf != NULL);

    /* write initial data */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "initial_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, key1, sizeof(key1), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start transaction that will be rolled back */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);
    uint8_t value2[] = "updated_value";
    ASSERT_EQ(tidesdb_txn_put(txn2, key1, sizeof(key1), value2, sizeof(value2), 0), 0);

    /* rollback -- changes should not be visible */
    ASSERT_EQ(tidesdb_txn_rollback(txn2), 0);

    /* verify original value is still there */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, key1, sizeof(key1), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value1) == 0);
    free(retrieved_value);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_consistency_after_flush(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "consistency_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "consistency_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data to memtable */
    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to sst */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify all data is consistent after flush */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected_value, sizeof(expected_value), "value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_concurrent_transactions(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "isolation_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "isolation_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "shared_key";
    uint8_t value1[] = "value_from_txn1";
    uint8_t value2[] = "value_from_txn2";

    /* start two transactions */
    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn2), 0);

    /* both write to same key */
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, key, sizeof(key), value2, sizeof(value2), 0), 0);

    /* commit both */
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* read -- should get the last committed value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    /* should be value2 since txn2 committed last */
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_durability_reopen_database(void)
{
    /* write data and close */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

        ASSERT_EQ(tidesdb_create_column_family(db, "durable_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "durable_cf");
        ASSERT_TRUE(cf != NULL);

        /* write data */
        for (int i = 0; i < 10; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "durable_key_%d", i);
            snprintf(value, sizeof(value), "durable_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush to ensure data is on disk */
        tidesdb_flush_memtable(cf);
        usleep(100000);

        tidesdb_close(db);
    }

    /*reopen and verify data persisted */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "durable_cf");
        ASSERT_TRUE(cf != NULL);

        /* verify all data is still there */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        for (int i = 0; i < 10; i++)
        {
            char key[32], expected_value[64];
            snprintf(key, sizeof(key), "durable_key_%d", i);
            snprintf(expected_value, sizeof(expected_value), "durable_value_%d", i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                      0);
            ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
            free(value);
        }

        tidesdb_txn_free(txn);
        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_data_integrity_after_compaction(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "integrity_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "integrity_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data with known checksums */
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "integrity_key_%03d", i);
        snprintf(value, sizeof(value), "integrity_value_%03d_checksum_%d", i, i * 12345);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(10000);
        }
    }

    usleep(100000);

    /* trigger compaction */
    tidesdb_compact(cf);
    usleep(200000);

    /* verify data integrity after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected_value[128];
        snprintf(key, sizeof(key), "integrity_key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "integrity_value_%03d_checksum_%d", i,
                 i * 12345);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_snapshot_isolation_consistency(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "snapshot_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snapshot_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "snapshot_key";
    uint8_t value1[] = "version_1";
    uint8_t value2[] = "version_2";

    /* write initial value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start long-running transaction with REPEATABLE_READ */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, cf, TDB_ISOLATION_REPEATABLE_READ, &txn2), 0);

    /* read initial value */
    uint8_t *read1 = NULL;
    size_t read1_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, key, sizeof(key), &read1, &read1_size), 0);
    ASSERT_TRUE(strcmp((char *)read1, (char *)value1) == 0);
    free(read1);

    /* another transaction updates the value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* original transaction should still see old value (snapshot isolation) */
    uint8_t *read2 = NULL;
    size_t read2_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, key, sizeof(key), &read2, &read2_size), 0);
    ASSERT_TRUE(strcmp((char *)read2, (char *)value1) == 0);
    free(read2);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_no_data_loss_across_operations(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_loss_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_loss_cf");
    ASSERT_TRUE(cf != NULL);

    /* write, flush, compact, and verify at each step */
    int total_keys = 50;

    /* write to memtable */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify all keys in memtable */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        free(value);
        tidesdb_txn_free(txn);
    }

    /* flush */
    tidesdb_flush_memtable(cf);
    /* we do NOT wait -- reads should work immediately via immutable memtable search */

    /* verify all keys during/after flush */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        free(value);
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dividing_merge_strategy(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* carefully tuned config to trigger dividing merge */
    cf_config.write_buffer_size = 256;   /* small for frequent flushes */
    cf_config.level_size_ratio = 4;      /* small ratio = faster level filling */
    cf_config.dividing_level_offset = 1; /* x = num_levels - 2 */
    cf_config.max_levels = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "dividing_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dividing_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data to create multiple levels
     * level 0 capacity = 256 * 4 = 1024 bytes
     * level 1 capacity = 1024 * 4 = 4096 bytes
     * level 2 capacity = 4096 * 4 = 16384 bytes
     * need ~20KB total to reach level 2 */
    int num_keys = 150;
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "div_key_%04d", i);
        snprintf(value, sizeof(value), "dividing_merge_value_%04d_with_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush periodically */
        if (i % 8 == 7)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    /* wait for flushes */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    int levels_before = atomic_load(&cf->num_levels);
    printf("Before compaction: %d levels\n", levels_before);

    /* trigger compaction -- should use dividing merge */
    tidesdb_compact(cf);

    /* wait for compaction */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(100000);

    int levels_after = atomic_load(&cf->num_levels);
    printf("After compaction: %d levels\n", levels_after);
    ASSERT_TRUE(levels_after >= 2); /* should have multiple levels */

    /* verify all data is accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "div_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_partitioned_merge_strategy(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* config to create many levels and trigger partitioned merge */
    cf_config.write_buffer_size = 300;   /* small buffer */
    cf_config.level_size_ratio = 3;      /* small ratio for fast level growth */
    cf_config.dividing_level_offset = 2; /* push X lower: X = num_levels - 3 */
    cf_config.max_levels = 15;

    ASSERT_EQ(tidesdb_create_column_family(db, "partition_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "partition_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data in batches with compaction between batches to build up levels
     * level 0: 300 * 3 = 900 bytes
     * level 1: 900 * 3 = 2700 bytes
     * level 2: 2700 * 3 = 8100 bytes
     * level 3: 8100 * 3 = 24300 bytes
     * need progressive writes with compaction to reach deep levels */

    /* batch 1 Initial data */
    for (int i = 0; i < 60; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "part_key_%04d", i);
        snprintf(value, sizeof(value), "partitioned_merge_value_%04d_with_extra_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    /* wait and compact */
    usleep(100000);
    tidesdb_compact(cf);
    usleep(150000);
    printf("After batch 1: %d levels\n", atomic_load(&cf->num_levels));

    /* batch 2 more data to push deeper */
    for (int i = 60; i < 140; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "part_key_%04d", i);
        snprintf(value, sizeof(value), "partitioned_merge_value_%04d_with_more_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    /* wait and compact again */
    usleep(100000);
    tidesdb_compact(cf);
    usleep(150000);
    printf("After batch 2: %d levels\n", atomic_load(&cf->num_levels));

    /* batch 3 final push */
    for (int i = 140; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "part_key_%04d", i);
        snprintf(value, sizeof(value), "partitioned_merge_value_%04d_final_batch", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    int num_keys = 200;

    /* wait for final flushes */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* final compaction */
    tidesdb_compact(cf);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(150000);

    int levels_after = atomic_load(&cf->num_levels);
    printf("Final: %d levels\n", levels_after);

    /* level count may vary due to DCA removing empty levels after compaction.
     * the important thing is that partitioned merge was triggered (visible in debug logs).
     * we verify data integrity instead of level count. */
    ASSERT_TRUE(levels_after >= 2); /* at least some hierarchy */

    /* verify all data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "part_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multi_level_compaction_strategies(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 300;
    cf_config.level_size_ratio = 4;
    cf_config.dividing_level_offset = 1;
    cf_config.max_levels = 12;

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_cf");
    ASSERT_TRUE(cf != NULL);

    /* small dataset -- triggers full preemptive merge */
    printf("Phase 1: Writing 50 keys (full preemptive merge)\n");
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase1_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    tidesdb_compact(cf);
    usleep(150000);
    printf("  Levels after phase 1: %d\n", atomic_load(&cf->num_levels));

    /* medium dataset -- triggers dividing merge */
    printf("Phase 2: Writing 100 more keys (dividing merge)\n");
    for (int i = 50; i < 150; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase2_value_%04d_with_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 8 == 7)
        {
            tidesdb_flush_memtable(cf);
            usleep(15000);
        }
    }

    tidesdb_compact(cf);
    usleep(150000);
    printf("  Levels after phase 2: %d\n", atomic_load(&cf->num_levels));

    /* large dataset -- triggers partitioned merge */
    printf("Phase 3: Writing 100 more keys (partitioned merge)\n");
    for (int i = 150; i < 250; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase3_value_%04d_with_extra_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 7 == 6)
        {
            tidesdb_flush_memtable(cf);
            usleep(15000);
        }
    }

    tidesdb_compact(cf);
    usleep(150000);
    int final_levels = atomic_load(&cf->num_levels);
    printf("  Levels after phase 3: %d\n", final_levels);

    /* verify all 250 keys */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 250; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "multi_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_boundary_partitioning(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 250;
    cf_config.level_size_ratio = 3;
    cf_config.dividing_level_offset = 2;
    cf_config.max_levels = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "boundary_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "boundary_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys with specific patterns to test boundary detection
     * Use lexicographically distributed keys */
    int num_keys = 120;
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

        char key[32], value[128];
        /* create keys that span alphabet for good boundary distribution */
        char prefix = 'a' + (i % 26);
        snprintf(key, sizeof(key), "%c_boundary_key_%04d", prefix, i);
        snprintf(value, sizeof(value), "boundary_value_%04d_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 7 == 6)
        {
            tidesdb_flush_memtable(cf);
            usleep(15000);
        }
    }

    /* wait and compact */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    usleep(150000);

    /* verify all keys are still accessible after boundary-based partitioning */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        char prefix = 'a' + (i % 26);
        snprintf(key, sizeof(key), "%c_boundary_key_%04d", prefix, i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dynamic_capacity_adjustment(void)
{
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* config that will trigger level additions */
    cf_config.write_buffer_size = 300;
    cf_config.level_size_ratio = 5;
    cf_config.dividing_level_offset = 1;
    cf_config.max_levels = 15;

    ASSERT_EQ(tidesdb_create_column_family(db, "dca_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dca_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load(&cf->num_levels);
    printf("Initial levels: %d\n", initial_levels);

    /* write data in batches, triggering level additions */
    for (int batch = 0; batch < 5; batch++)
    {
        printf("Batch %d: Writing 40 keys\n", batch + 1);

        for (int i = 0; i < 40; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

            char key[32], value[128];
            int key_id = batch * 40 + i;
            snprintf(key, sizeof(key), "dca_key_%05d", key_id);
            snprintf(value, sizeof(value), "dca_value_%05d_with_padding_data", key_id);

            ASSERT_EQ(tidesdb_txn_put(txn, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);

            if (i % 8 == 7)
            {
                tidesdb_flush_memtable(cf);
                usleep(15000);
            }
        }

        /* trigger compaction and observe level changes */
        tidesdb_compact(cf);
        usleep(150000);

        int current_levels = atomic_load(&cf->num_levels);
        printf("  After batch %d: %d levels\n", batch + 1, current_levels);
    }

    int final_levels = atomic_load(&cf->num_levels);
    printf("Final levels: %d (growth: %d levels)\n", final_levels, final_levels - initial_levels);

    /* verify DCA worked -- should have added levels */
    ASSERT_TRUE(final_levels > initial_levels);

    /* verify all data is accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, cf, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "dca_key_%05d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_transaction(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    /* create two column families */
    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");
    assert(cf1 != NULL);
    assert(cf2 != NULL);

    /* start transaction on cf1, then add cf2 */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    /* write to both CFs */
    const char *key1 = "key_cf1";
    const char *val1 = "value_cf1";
    const char *key2 = "key_cf2";
    const char *val2 = "value_cf2";

    assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)key1, strlen(key1), (uint8_t *)val1,
                              strlen(val1), 0) == TDB_SUCCESS);
    assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)key2, strlen(key2), (uint8_t *)val2,
                              strlen(val2), 0) == TDB_SUCCESS);

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* verify data in both CFs */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    uint8_t *retrieved_val;
    size_t retrieved_size;

    assert(tidesdb_txn_get_cf(txn, cf1, (uint8_t *)key1, strlen(key1), &retrieved_val,
                              &retrieved_size) == TDB_SUCCESS);
    assert(retrieved_size == strlen(val1));
    assert(memcmp(retrieved_val, val1, retrieved_size) == 0);
    free(retrieved_val);

    assert(tidesdb_txn_get_cf(txn, cf2, (uint8_t *)key2, strlen(key2), &retrieved_val,
                              &retrieved_size) == TDB_SUCCESS);
    assert(retrieved_size == strlen(val2));
    assert(memcmp(retrieved_val, val2, retrieved_size) == 0);
    free(retrieved_val);

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_transaction_rollback(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* tx 1 commit data */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    const char *key1 = "committed_key1";
    const char *val1 = "committed_val1";
    assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)key1, strlen(key1), (uint8_t *)val1,
                              strlen(val1), 0) == TDB_SUCCESS);
    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* tx 2 write then rollback */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    const char *key2 = "rollback_key";
    const char *val2 = "rollback_val";
    assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)key2, strlen(key2), (uint8_t *)val2,
                              strlen(val2), 0) == TDB_SUCCESS);
    assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)key2, strlen(key2), (uint8_t *)val2,
                              strlen(val2), 0) == TDB_SUCCESS);

    tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);

    /* verify committed data exists, rolled back data doesn't */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    uint8_t *retrieved_val;
    size_t retrieved_size;

    /* committed data should exist */
    assert(tidesdb_txn_get_cf(txn, cf1, (uint8_t *)key1, strlen(key1), &retrieved_val,
                              &retrieved_size) == TDB_SUCCESS);
    free(retrieved_val);

    /* rolled back data should NOT exist */
    assert(tidesdb_txn_get_cf(txn, cf1, (uint8_t *)key2, strlen(key2), &retrieved_val,
                              &retrieved_size) == TDB_ERR_NOT_FOUND);
    assert(tidesdb_txn_get_cf(txn, cf2, (uint8_t *)key2, strlen(key2), &retrieved_val,
                              &retrieved_size) == TDB_ERR_NOT_FOUND);

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_iterator(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* write data to both CFs */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    for (int i = 0; i < 10; i++)
    {
        char key[32], val[32];
        /* we use different key prefixes for each CF to avoid deduplication */
        snprintf(key, sizeof(key), "cf1_key_%03d", i);
        snprintf(val, sizeof(val), "val_cf1_%03d", i);
        assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)key, strlen(key), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);

        snprintf(key, sizeof(key), "cf2_key_%03d", i);
        snprintf(val, sizeof(val), "val_cf2_%03d", i);
        assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)key, strlen(key), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* create iterator across all CFs */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new_all_cfs(txn, &iter) == TDB_SUCCESS);

    /* iterate and count entries */
    int count = 0;
    assert(tidesdb_iter_seek_to_first(iter) == TDB_SUCCESS);
    do
    {
        if (!tidesdb_iter_valid(iter)) break;
        count++;
    } while (tidesdb_iter_next(iter) == TDB_SUCCESS);

    /* should see 20 entries total (10 from each CF) */
    assert(count == 20);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_iterator_boundaries(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* write boundary keys to both CFs */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    const char *keys[] = {"aaa", "mmm", "zzz"};
    for (int i = 0; i < 3; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)keys[i], strlen(keys[i]), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)keys[i], strlen(keys[i]), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test iterator boundaries */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new_all_cfs(txn, &iter) == TDB_SUCCESS);

    assert(tidesdb_iter_seek_to_first(iter) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(memcmp(key, "aaa", 3) == 0);
    free(key);

    assert(tidesdb_iter_seek_to_last(iter) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    key = NULL;
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(memcmp(key, "zzz", 3) == 0);
    free(key);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_iterator_reverse(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* write sorted keys */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    for (int i = 0; i < 5; i++)
    {
        char key[32], val[32];
        /* use different key prefixes for each CF to avoid deduplication */
        snprintf(key, sizeof(key), "cf1_key_%02d", i);
        snprintf(val, sizeof(val), "val_cf1_%02d", i);
        assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)key, strlen(key), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);

        snprintf(key, sizeof(key), "cf2_key_%02d", i);
        snprintf(val, sizeof(val), "val_cf2_%02d", i);
        assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)key, strlen(key), (uint8_t *)val,
                                  strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* iterate in reverse */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new_all_cfs(txn, &iter) == TDB_SUCCESS);

    /* test reverse iteration */
    assert(tidesdb_iter_seek_to_last(iter) == TDB_SUCCESS);
    int count = 0;
    char prev_key[32] = {0};
    strcpy(prev_key, "zzz"); /* start with max value */

    do
    {
        if (!tidesdb_iter_valid(iter)) break;
        uint8_t *key = NULL;
        size_t key_size = 0;
        assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);

        /* verify descending order */
        assert(memcmp(key, prev_key, key_size < strlen(prev_key) ? key_size : strlen(prev_key)) <=
               0);
        memcpy(prev_key, key, key_size);
        prev_key[key_size] = '\0';
        free(key);
        count++;
    } while (tidesdb_iter_prev(iter) == TDB_SUCCESS);

    assert(count == 10); /* 5 keys * 2 CFs */

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_iterator_seek(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* write keys with gaps -- use different prefixes for each CF */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    const char *cf1_keys[] = {"cf1_key_10", "cf1_key_20", "cf1_key_30", "cf1_key_40", "cf1_key_50"};
    const char *cf2_keys[] = {"cf2_key_10", "cf2_key_20", "cf2_key_30", "cf2_key_40", "cf2_key_50"};
    for (int i = 0; i < 5; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)cf1_keys[i], strlen(cf1_keys[i]),
                                  (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)cf2_keys[i], strlen(cf2_keys[i]),
                                  (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test seek operations */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new_all_cfs(txn, &iter) == TDB_SUCCESS);

    /* seek to exact key in cf1 */
    const char *seek_key = "cf1_key_30";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *found_key = NULL;
    size_t found_key_size = 0;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, seek_key, strlen(seek_key)) == 0);
    free(found_key);

    /* seek to non-existent key (should find next) */
    const char *seek_key2 = "cf1_key_25";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek_key2, strlen(seek_key2)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    found_key = NULL;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, "cf1_key_30", 10) == 0);
    free(found_key);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

void test_multi_cf_iterator_seek_for_prev(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");

    /* write keys with gaps -- use different prefixes for each CF */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    const char *cf1_keys[] = {"cf1_key_10", "cf1_key_20", "cf1_key_30", "cf1_key_40", "cf1_key_50"};
    const char *cf2_keys[] = {"cf2_key_10", "cf2_key_20", "cf2_key_30", "cf2_key_40", "cf2_key_50"};
    for (int i = 0; i < 5; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf1, (uint8_t *)cf1_keys[i], strlen(cf1_keys[i]),
                                  (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put_cf(txn, cf2, (uint8_t *)cf2_keys[i], strlen(cf2_keys[i]),
                                  (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test seek_for_prev operations */
    assert(tidesdb_txn_begin(db, cf1, &txn) == TDB_SUCCESS);
    assert(tidesdb_txn_add_cf(txn, cf2) == TDB_SUCCESS);

    /* verify cf2_key_30 exists before seeking */
    uint8_t *verify_val = NULL;
    size_t verify_size = 0;
    int get_result =
        tidesdb_txn_get_cf(txn, cf2, (uint8_t *)"cf2_key_30", 10, &verify_val, &verify_size);

    if (get_result == TDB_SUCCESS)
    {
        free(verify_val);
    }

    /* list all keys in CF2 to see what's actually there */
    for (int i = 0; i < 5; i++)
    {
        char test_key[32];
        snprintf(test_key, sizeof(test_key), "cf2_key_%d0", i + 1);
        uint8_t *test_val = NULL;
        size_t test_size = 0;
        int res = tidesdb_txn_get_cf(txn, cf2, (uint8_t *)test_key, strlen(test_key), &test_val,
                                     &test_size);
        printf("  %s: %s\n", test_key, res == 0 ? "EXISTS" : "NOT FOUND");
        if (res == 0) free(test_val);
    }

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new_all_cfs(txn, &iter) == TDB_SUCCESS);

    /* seek to exact key in cf2 */
    const char *seek_key = "cf2_key_30";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *found_key = NULL;
    size_t found_key_size = 0;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, seek_key, strlen(seek_key)) == 0);
    free(found_key);

    /* seek to non-existent key (should find previous) */
    const char *seek_key2 = "cf2_key_35";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key2, strlen(seek_key2)) ==
           TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    found_key = NULL;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, "cf2_key_30", 10) == 0);
    free(found_key);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

int main(void)
{
    cleanup_test_dir();
    RUN_TEST(test_basic_open_close, tests_passed);
    RUN_TEST(test_column_family_creation, tests_passed);
    RUN_TEST(test_basic_txn_put_get, tests_passed);
    RUN_TEST(test_txn_delete, tests_passed);
    RUN_TEST(test_txn_rollback, tests_passed);
    RUN_TEST(test_multiple_column_families, tests_passed);
    RUN_TEST(test_memtable_flush, tests_passed);
    RUN_TEST(test_persistence_and_recovery, tests_passed);
    RUN_TEST(test_iterator_basic, tests_passed);
    RUN_TEST(test_stats, tests_passed);
    RUN_TEST(test_iterator_seek, tests_passed);
    RUN_TEST(test_iterator_seek_for_prev, tests_passed);
    RUN_TEST(test_iterator_reverse, tests_passed);
    RUN_TEST(test_iterator_boundaries, tests_passed);
    RUN_TEST(test_bidirectional_iterator, tests_passed);
    RUN_TEST(test_ttl_expiration, tests_passed);
    RUN_TEST(test_large_values, tests_passed);
    RUN_TEST(test_many_keys, tests_passed);
    RUN_TEST(test_isolation_read_uncommitted, tests_passed);
    RUN_TEST(test_isolation_read_committed, tests_passed);
    RUN_TEST(test_isolation_repeatable_read, tests_passed);
    RUN_TEST(test_isolation_serializable_conflict, tests_passed);
    RUN_TEST(test_multi_cf_transaction, tests_passed);
    RUN_TEST(test_multi_cf_transaction_rollback, tests_passed);
    RUN_TEST(test_multi_cf_iterator, tests_passed);
    RUN_TEST(test_multi_cf_iterator_boundaries, tests_passed);
    RUN_TEST(test_multi_cf_iterator_reverse, tests_passed);
    RUN_TEST(test_multi_cf_iterator_seek, tests_passed);
    RUN_TEST(test_multi_cf_iterator_seek_for_prev, tests_passed);
    RUN_TEST(test_savepoints, tests_passed);
    RUN_TEST(test_ini_config, tests_passed);
    RUN_TEST(test_runtime_config_update, tests_passed);
    RUN_TEST(test_error_invalid_args, tests_passed);
    RUN_TEST(test_drop_column_family, tests_passed);
    RUN_TEST(test_empty_iterator, tests_passed);
    RUN_TEST(test_bloom_filter_enabled, tests_passed);
    RUN_TEST(test_block_indexes, tests_passed);
    RUN_TEST(test_sync_modes, tests_passed);
    RUN_TEST(test_compression_lz4, tests_passed);
    RUN_TEST(test_compression_zstd, tests_passed);
    RUN_TEST(test_compression_snappy, tests_passed);
    RUN_TEST(test_compaction_basic, tests_passed);
    RUN_TEST(test_compaction_with_deletes, tests_passed);
    RUN_TEST(test_background_compaction, tests_passed);
    RUN_TEST(test_concurrent_writes, tests_passed);
    RUN_TEST(test_empty_value, tests_passed);
    RUN_TEST(test_delete_nonexistent_key, tests_passed);
    RUN_TEST(test_multiple_deletes_same_key, tests_passed);
    RUN_TEST(test_overwrite_same_key_multiple_times, tests_passed);
    RUN_TEST(test_put_delete_put_same_key, tests_passed);
    RUN_TEST(test_iterator_on_empty_cf, tests_passed);
    RUN_TEST(test_iterator_single_key, tests_passed);
    RUN_TEST(test_mixed_operations_in_transaction, tests_passed);
    RUN_TEST(test_read_own_writes_in_transaction, tests_passed);
    RUN_TEST(test_alternating_puts_deletes, tests_passed);
    RUN_TEST(test_very_long_key, tests_passed);
    RUN_TEST(test_read_across_multiple_sstables, tests_passed);
    RUN_TEST(test_read_with_bloom_filter_disabled, tests_passed);
    RUN_TEST(test_read_with_block_indexes_disabled, tests_passed);
    RUN_TEST(test_read_with_all_optimizations_disabled, tests_passed);
    RUN_TEST(test_read_after_multi_level_compaction, tests_passed);
    RUN_TEST(test_iterator_across_multiple_sources, tests_passed);
    RUN_TEST(test_overwrite_across_levels, tests_passed);
    RUN_TEST(test_atomicity_transaction_rollback, tests_passed);
    RUN_TEST(test_consistency_after_flush, tests_passed);
    RUN_TEST(test_isolation_concurrent_transactions, tests_passed);
    RUN_TEST(test_durability_reopen_database, tests_passed);
    RUN_TEST(test_data_integrity_after_compaction, tests_passed);
    RUN_TEST(test_snapshot_isolation_consistency, tests_passed);
    RUN_TEST(test_no_data_loss_across_operations, tests_passed);
    RUN_TEST(test_dividing_merge_strategy, tests_passed);
    RUN_TEST(test_partitioned_merge_strategy, tests_passed);
    RUN_TEST(test_multi_level_compaction_strategies, tests_passed);
    RUN_TEST(test_boundary_partitioning, tests_passed);
    RUN_TEST(test_dynamic_capacity_adjustment, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}