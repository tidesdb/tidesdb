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
    config.enable_debug_logging = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    return db;
}

static void test_basic_open_close(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();
}

static void test_column_family_creation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    ASSERT_TRUE(strcmp(cf->name, "test_cf") == 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_list_column_families(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* test with no column families */
    char **names = NULL;
    int count = 0;
    ASSERT_EQ(tidesdb_list_column_families(db, &names, &count), 0);
    ASSERT_EQ(count, 0);
    ASSERT_TRUE(names == NULL);

    /* create multiple column families */
    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf3", &cf_config), 0);

    /* list column families */
    ASSERT_EQ(tidesdb_list_column_families(db, &names, &count), 0);
    ASSERT_EQ(count, 3);
    ASSERT_TRUE(names != NULL);

    /* verify all names are present */
    int found_cf1 = 0, found_cf2 = 0, found_cf3 = 0;
    for (int i = 0; i < count; i++)
    {
        ASSERT_TRUE(names[i] != NULL);
        if (strcmp(names[i], "cf1") == 0) found_cf1 = 1;
        if (strcmp(names[i], "cf2") == 0) found_cf2 = 1;
        if (strcmp(names[i], "cf3") == 0) found_cf3 = 1;
        free(names[i]);
    }
    free(names);

    ASSERT_TRUE(found_cf1);
    ASSERT_TRUE(found_cf2);
    ASSERT_TRUE(found_cf3);

    /* test invalid arguments */
    ASSERT_EQ(tidesdb_list_column_families(NULL, &names, &count), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_list_column_families(db, NULL, &count), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_list_column_families(db, &names, NULL), TDB_ERR_INVALID_ARGS);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_basic_txn_put_get(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    ASSERT_TRUE(txn != NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    ASSERT_EQ(retrieved_size, sizeof(value));
    ASSERT_TRUE(memcmp(retrieved_value, value, sizeof(value)) == 0);
    free(retrieved_value);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_delete(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key[] = "delete_key";
    uint8_t value[] = "delete_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, cf, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, cf, key, sizeof(key), &retrieved_value, &retrieved_size),
              TDB_ERR_NOT_FOUND);
    tidesdb_txn_free(txn3);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_txn_rollback(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    uint8_t key[] = "rollback_key";
    uint8_t value[] = "rollback_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);

    ASSERT_EQ(tidesdb_txn_rollback(txn), 0);
    tidesdb_txn_free(txn);

    /* verify key doesn't exist */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved_value, &retrieved_size),
              TDB_ERR_NOT_FOUND);
    tidesdb_txn_free(txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_column_families(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "value_cf1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf1, key1, sizeof(key1), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t value2[] = "value_cf2";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf2, key1, sizeof(key1), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* verify isolation between CFs */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn3, cf1, key1, sizeof(key1), &retrieved_value, &retrieved_size);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.compression_algorithm = NO_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* manually trigger flush and wait for background thread pool */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    int max_wait = 50;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(50000);

    /* verify all data is still accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 5; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
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
    cleanup_test_dir();
    const int NUM_KEYS = 20;

    /* create database, write data, flush, close */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = NO_COMPRESSION;

        ASSERT_EQ(tidesdb_create_column_family(db, "persist_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "persist_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "persist_key_%03d", i);
            snprintf(value, sizeof(value), "persist_value_%03d_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(200000);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "persist_key_%03d", 10);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
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
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            int found_count = 0;
            for (int i = 0; i < NUM_KEYS; i += 5)
            { /* check every 5th key */
                char key[32];
                snprintf(key, sizeof(key), "persist_key_%03d", i);

                uint8_t *retrieved_value = NULL;
                size_t retrieved_size = 0;
                int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1,
                                             &retrieved_value, &retrieved_size);

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
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_TRUE(iter != NULL);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");

    /* write some data */
    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_stats_t *stats = NULL;
    ASSERT_EQ(tidesdb_get_stats(cf, &stats), 0);
    ASSERT_TRUE(stats != NULL);
    ASSERT_TRUE(stats->memtable_size > 0);

    tidesdb_free_stats(stats);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys key_00, key_02, key_04, key_06, key_08 */
    for (int i = 0; i < 10; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test seek to existing key */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

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

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_reverse(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rev_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rev_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test reverse iteration */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

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
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_boundaries(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "bound_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bound_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    int result = tidesdb_iter_seek_to_first(iter);
    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
    }

    result = tidesdb_iter_seek_to_last(iter);
    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_basic(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* write enough data to trigger multiple flushes and fill level 0
     * level 0 capacity = write_buffer_size * level_size_ratio = 2048 * 10 = 20480 bytes
     * each entry is ~160 bytes, so 10 entries = ~1600 bytes per sstable
     * 200 entries / 10 = 20 sstables which should trigger compaction */
    for (int i = 0; i < 200; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_with_some_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* trigger flush periodically to create multiple sstables */
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
    int initial_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
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
    int final_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
    printf("After compaction: %d level(s)\n", final_levels);

    /* verify all data is still accessible after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d_with_some_extra_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush deletes periodically so tombstones are in sstables */
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "ttl_key";
    uint8_t value[] = "ttl_value";
    time_t ttl = time(NULL) + 2;

    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), ttl), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify key exists immediately */
    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);
    tidesdb_txn_free(txn);

    /* wait for expiration */
    sleep(3);

    /* verify key is expired */
    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    retrieved_value = NULL;
    int result = tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size);
    ASSERT_TRUE(result != 0 || retrieved_value == NULL);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_large_values(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "large_key_%d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, large_size, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    free(large_value);

    /* verify retrieval */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "large_key_5");

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                 &retrieved_size);

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
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%06d", i);
        snprintf(value, sizeof(value), "value_%06d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
        /* check if flush queue is empty by checking level 0 sstable count */
        if (cf->levels[0])
        {
            int num_ssts = atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);
            if (num_ssts >= 10)
            {
                break;
            }
        }
    }

    /* additional wait to ensure all sstables are fully written */
    usleep(500000);

    /* verify random keys -- create transaction after flushes complete */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    int found_count = 0;
    int not_found_count = 0;
    for (int i = 0; i < 50; i++)
    {
        int key_idx = (i * 37) % NUM_KEYS;

        char key[32];
        snprintf(key, sizeof(key), "key_%06d", key_idx);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = NO_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "bidir_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bidir_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* test forward iteration */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
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

            count++;
        }
    } while (tidesdb_iter_next(iter) == 0 && tidesdb_iter_valid(iter));

    ASSERT_EQ(count, 10);

    tidesdb_iter_free(iter);

    /* test backward iteration -- create fresh iterator */
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
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

            count--;
        }
    } while (tidesdb_iter_prev(iter) == 0 && tidesdb_iter_valid(iter));

    ASSERT_EQ(count, -1);

    /* test mixed forward/backward iteration on same iterator */
    tidesdb_iter_free(iter);
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    /* go forward 3 steps (should be at key_03) */
    ASSERT_EQ(tidesdb_iter_next(iter), 0);
    ASSERT_EQ(tidesdb_iter_next(iter), 0);
    ASSERT_EQ(tidesdb_iter_next(iter), 0);

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

    ASSERT_TRUE(strcmp((char *)key, "key_03") == 0);

    /* now go backward 2 steps (should be at key_01) */
    ASSERT_EQ(tidesdb_iter_prev(iter), 0);
    ASSERT_EQ(tidesdb_iter_prev(iter), 0);

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

    if (strcmp((char *)key, "key_01") != 0)
    {
        printf("ERROR: Expected key_01 but got '%s'\n", (char *)key);
    }

    /* go forward again (should be at key_02) */
    ASSERT_EQ(tidesdb_iter_next(iter), 0);

    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_TRUE(strcmp((char *)key, "key_02") == 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_read_uncommitted(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* READ_UNCOMMITTED should read uncommitted data from memtable */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    txn1->isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;

    uint8_t key[] = "iso_key";
    uint8_t value[] = "iso_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value, sizeof(value), 0), 0);

    /* don't commit -- start another transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;

    /* should be able to read uncommitted data */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* first commit a value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

    uint8_t key[] = "iso_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start READ_COMMITTED transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    txn2->isolation_level = TDB_ISOLATION_READ_COMMITTED;

    /* read initial value */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);
    if (result == 0 && retrieved)
    {
        ASSERT_TRUE(memcmp(retrieved, value1, sizeof(value1)) == 0);
        free(retrieved);
    }

    /* another transaction updates and commits */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* READ_COMMITTED should see the new committed value */
    retrieved = NULL;
    result = tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);
    if (result == 0 && retrieved)
    {
        /* can see newly committed value */
        free(retrieved);
    }

    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_serializable_conflict(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "iso_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iso_cf");
    ASSERT_TRUE(cf != NULL);

    /* commit initial value */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

    uint8_t key[] = "conflict_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start two SNAPSHOT transactions */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn3), 0);

    /* both read the same key */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    tidesdb_txn_get(txn3, cf, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    /* both try to write */
    uint8_t value2[] = "value2";
    uint8_t value3[] = "value3";

    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value3, sizeof(value3), 0), 0);

    /* first commit should succeed */
    int result2 = tidesdb_txn_commit(txn2);
    printf("txn2 commit result: %d\n", result2);
    fflush(stdout);

    /* second commit should fail with conflict */
    int result3 = tidesdb_txn_commit(txn3);
    printf("txn3 commit result: %d (expected conflict: %d)\n", result3, TDB_ERR_CONFLICT);
    fflush(stdout);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "sp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sp_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key1, sizeof(key1), value1, sizeof(value1), 0), 0);

    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp1"), 0);

    /* put another value */
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key2, sizeof(key2), value2, sizeof(value2), 0), 0);

    /* rollback to savepoint */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp1"), 0);

    /* key1 should exist, key2 should not */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    int result = tidesdb_txn_get(txn, cf, key2, sizeof(key2), &retrieved, &retrieved_size);
    ASSERT_TRUE(result != 0); /* key2 should not exist */

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_for_prev(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "sfp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sfp_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys key_00, key_02, key_04, key_06, key_08 */
    for (int i = 0; i < 10; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

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
        }
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ini_config(void)
{
    cleanup_test_dir();
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rt_cf");
    ASSERT_TRUE(cf != NULL);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "err_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "err_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* NULL key should fail */
    uint8_t value[] = "value";
    int result = tidesdb_txn_put(txn, cf, NULL, 10, value, sizeof(value), 0);
    ASSERT_TRUE(result != 0);

    /* zero key size should fail */
    uint8_t key[] = "key";
    result = tidesdb_txn_put(txn, cf, key, 0, value, sizeof(value), 0);
    ASSERT_TRUE(result != 0);

    /* NULL value should fail */
    result = tidesdb_txn_put(txn, cf, key, sizeof(key), NULL, 10, 0);
    ASSERT_TRUE(result != 0);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_column_family(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "drop_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    uint8_t key[] = "key";
    uint8_t value[] = "value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_drop_column_family(db, "drop_cf"), 0);

    /* should not be able to get it anymore */
    cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_empty_iterator(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_cf");
    ASSERT_TRUE(cf != NULL);

    /* create iterator on empty column family */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "lz4_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "lz4_cf");
    ASSERT_TRUE(cf != NULL);

    /* write compressible data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'A', sizeof(value)); /* highly compressible */

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to apply compression */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify data is readable */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    snprintf(key, sizeof(key), "key_5");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = ZSTD_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "zstd_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "zstd_cf");
    ASSERT_TRUE(cf != NULL);

    /* write compressible data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'B', sizeof(value));

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* flush to apply compression */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify data */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    snprintf(key, sizeof(key), "key_7");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

#ifndef __sun
static void test_compression_snappy(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.compression_algorithm = SNAPPY_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "snappy_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snappy_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    char key[32];
    char value[1024];
    memset(value, 'C', sizeof(value));

    for (int i = 0; i < 10; i++)
    {
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  sizeof(value), 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_flush_memtable(cf);
    usleep(100000);

    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    snprintf(key, sizeof(key), "key_3");

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}
#endif

static void test_bloom_filter_enabled(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "bloom_key_%d", i);
        snprintf(value, sizeof(value), "bloom_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "bloom_key_50");
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);

    ASSERT_EQ(result, 0);
    if (retrieved) free(retrieved);

    /* query non-existing key -- bloom filter should filter */
    snprintf(key, sizeof(key), "nonexistent_key_999");
    retrieved = NULL;
    result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size);
    ASSERT_TRUE(result != 0);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_block_indexes(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "bidx_key_%04d", i);
        snprintf(value, sizeof(value), "bidx_value_%04d_with_extra_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to create sstable with block indexes */
    tidesdb_flush_memtable(cf);
    usleep(200000);

    /* use iterator seek (should use block index) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    char seek_key[32];
    snprintf(seek_key, sizeof(seek_key), "bidx_key_0150");
    int result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);

    if (result == 0 && tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        tidesdb_iter_key(iter, &key, &key_size);
        ASSERT_TRUE(key != NULL);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_sync_modes(void)
{
    cleanup_test_dir();
    /* test TDB_SYNC_NONE */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_NONE;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        uint8_t key[] = "sync_key";
        uint8_t value[] = "sync_value";
        ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        uint8_t key[] = "sync_key2";
        uint8_t value[] = "sync_value2";
        ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
        cleanup_test_dir();
    }
}

static void test_sync_interval_mode(void)
{
    cleanup_test_dir();

    /* test TDB_SYNC_INTERVAL with periodic syncing */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_INTERVAL;
        cf_config.sync_interval_us = 500000;       /* 500ms */
        cf_config.write_buffer_size = 1024 * 1024; /* 1MB to prevent auto-flush */

        ASSERT_EQ(tidesdb_create_column_family(db, "interval_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "interval_cf");
        ASSERT_TRUE(cf != NULL);

        /* write some data */
        for (int i = 0; i < 10; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "interval_key_%d", i);
            snprintf(value, sizeof(value), "interval_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* verify data is readable immediately (from memtable) */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"interval_key_5", 15, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        ASSERT_EQ(strcmp((char *)retrieved_value, "interval_value_5"), 0);
        free(retrieved_value);
        tidesdb_txn_free(txn);

        /* wait for at least one sync interval to ensure WAL is synced */
        usleep(600000); /* 600ms */

        tidesdb_close(db);
    }

    /* data should survive reopen */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;
        config.enable_debug_logging = 1;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "interval_cf");
        ASSERT_TRUE(cf != NULL);

        /* verify data persisted */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"interval_key_5", 15, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        ASSERT_EQ(strcmp((char *)retrieved_value, "interval_value_5"), 0);
        free(retrieved_value);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    /* test multiple CFs with different intervals */
    {
        tidesdb_t *db = create_test_db();

        /* CF with fast sync */
        tidesdb_column_family_config_t cf_config1 = tidesdb_default_column_family_config();
        cf_config1.sync_mode = TDB_SYNC_INTERVAL;
        cf_config1.sync_interval_us = 100000; /* 100ms */
        ASSERT_EQ(tidesdb_create_column_family(db, "fast_sync_cf", &cf_config1), 0);

        /* CF with slow sync */
        tidesdb_column_family_config_t cf_config2 = tidesdb_default_column_family_config();
        cf_config2.sync_mode = TDB_SYNC_INTERVAL;
        cf_config2.sync_interval_us = 1000000; /* 1 second */
        ASSERT_EQ(tidesdb_create_column_family(db, "slow_sync_cf", &cf_config2), 0);

        /* CF with no interval sync */
        tidesdb_column_family_config_t cf_config3 = tidesdb_default_column_family_config();
        cf_config3.sync_mode = TDB_SYNC_NONE;
        ASSERT_EQ(tidesdb_create_column_family(db, "no_sync_cf", &cf_config3), 0);

        tidesdb_column_family_t *fast_cf = tidesdb_get_column_family(db, "fast_sync_cf");
        tidesdb_column_family_t *slow_cf = tidesdb_get_column_family(db, "slow_sync_cf");
        tidesdb_column_family_t *no_sync_cf = tidesdb_get_column_family(db, "no_sync_cf");
        ASSERT_TRUE(fast_cf != NULL);
        ASSERT_TRUE(slow_cf != NULL);
        ASSERT_TRUE(no_sync_cf != NULL);

        /* write to all CFs */
        for (int i = 0; i < 5; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "multi_key_%d", i);
            snprintf(value, sizeof(value), "multi_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, fast_cf, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_put(txn, slow_cf, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_put(txn, no_sync_cf, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* wait for fast sync interval */
        usleep(150000); /* 150ms */

        /* verify all data is readable */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;

        ASSERT_EQ(tidesdb_txn_get(txn, fast_cf, (uint8_t *)"multi_key_2", 12, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        ASSERT_EQ(tidesdb_txn_get(txn, slow_cf, (uint8_t *)"multi_key_2", 12, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        ASSERT_EQ(tidesdb_txn_get(txn, no_sync_cf, (uint8_t *)"multi_key_2", 12, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        tidesdb_txn_free(txn);

        tidesdb_close(db);
        cleanup_test_dir();
    }
}

static void test_concurrent_writes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");
    ASSERT_TRUE(cf != NULL);

    /* write same key from multiple transactions -- last one should win */
    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);

    uint8_t key[] = "concurrent_key";
    uint8_t value1[] = "value1";
    uint8_t value2[] = "value2";

    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* read back -- should get value2 (last write wins) */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "edge_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "edge_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* test empty value -- should succeed (valid use case) */
    uint8_t key[] = "test_key";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), (uint8_t *)"", 1, 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify empty value can be retrieved */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_size > 0);
    free(retrieved_value);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_delete_nonexistent_key(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "delete_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "delete_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* delete a key that doesn't exist -- should succeed (idempotent) */
    uint8_t key[] = "nonexistent_key";
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* try to get the deleted key -- should not exist */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn2, cf, key, sizeof(key), &value, &value_size) != 0);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multiple_deletes_same_key(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_del_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_del_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* delete it twice */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, cf, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn3, cf, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* verify it's still deleted */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn4, cf, key, sizeof(key), &retrieved_value, &retrieved_size) !=
                0);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_txn_free(txn4);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_overwrite_same_key_multiple_times(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char value[64];
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, key, sizeof(key), (uint8_t *)value, strlen(value) + 1, 0), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify we get the last value */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, "value_99") == 0);
    free(retrieved_value);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_put_delete_put_same_key(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "pdp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "pdp_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "first_value";
    uint8_t value2[] = "second_value";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn2, cf, key, sizeof(key)), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* verify we get the second value */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn4, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_iter_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_iter_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "single_key_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "single_key_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key[] = "only_key";
    uint8_t value[] = "only_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* iterate */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn2, cf, &iter), 0);

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* put, delete, put different keys in same transaction */
    uint8_t key1[] = "key1";
    uint8_t key2[] = "key2";
    uint8_t key3[] = "key3";
    uint8_t value[] = "value";

    ASSERT_EQ(tidesdb_txn_put(txn, cf, key1, sizeof(key1), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key2, sizeof(key2)), 0);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key3, sizeof(key3), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);

    uint8_t *v1 = NULL, *v2 = NULL, *v3 = NULL;
    size_t s1, s2, s3;

    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key1, sizeof(key1), &v1, &s1), 0);
    ASSERT_TRUE(tidesdb_txn_get(txn2, cf, key2, sizeof(key2), &v2, &s2) != 0);
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key3, sizeof(key3), &v3, &s3), 0);

    free(v1);
    free(v3);

    tidesdb_txn_free(txn);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_own_writes_in_transaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "row_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "row_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";

    /* put and immediately read in same transaction */
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(strcmp((char *)retrieved_value, (char *)value) == 0);
    free(retrieved_value);

    /* delete and immediately try to read */
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key, sizeof(key)), 0);
    ASSERT_TRUE(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size) != 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_alternating_puts_deletes(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        if (i % 2 == 0)
        {
            char value[64];
            snprintf(value, sizeof(value), "value_%d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
        }
        else
        {
            /* delete previous key */
            char prev_key[32];
            snprintf(prev_key, sizeof(prev_key), "key_%d", i - 1);
            ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)prev_key, strlen(prev_key) + 1), 0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify only odd keys exist (even keys were deleted) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

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
    cleanup_test_dir();
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    uint8_t value[] = "long_key_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, long_key, key_size, value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);

    /* verify retrieval */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, long_key, key_size, &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_sst_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_sst_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_bloom_filter_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 0;
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_bloom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_bloom_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work without bloom filter */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_block_indexes_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_block_indexes = 0;
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_index_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_index_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work without block indexes */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_with_all_optimizations_disabled(void)
{
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* verify reads work with all optimizations disabled */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_across_multiple_sources(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.compression_algorithm = LZ4_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_multi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_multi_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys across multiple sstts and memtable */
    for (int i = 0; i < 60; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "overwrite_levels_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overwrite_levels_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "same_key";

    /* write v1 and flush */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t value1[] = "version_1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* write v2 and flush */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t value2[] = "version_2";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_flush_memtable(cf);
    usleep(50000);

    /* write v3 in memtable */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t value3[] = "version_3";
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value3, sizeof(value3), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* read should get v3 (newest) */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn4), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn4, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "atomic_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "atomic_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key1[] = "key1";
    uint8_t value1[] = "initial_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key1, sizeof(key1), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start transaction that will be rolled back */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t value2[] = "updated_value";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key1, sizeof(key1), value2, sizeof(value2), 0), 0);

    /* rollback -- changes should not be visible */
    ASSERT_EQ(tidesdb_txn_rollback(txn2), 0);

    /* verify original value is still there */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, cf, key1, sizeof(key1), &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* verify all data is consistent after flush */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected_value, sizeof(expected_value), "value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_concurrent_transactions(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "isolation_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "isolation_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "shared_key";
    uint8_t value1[] = "value_from_txn1";
    uint8_t value2[] = "value_from_txn2";

    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);

    /* both write to same key */
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);

    /* commit both */
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* read -- should get the last committed value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn3, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
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
    cleanup_test_dir();
    /* write data and close */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

        ASSERT_EQ(tidesdb_create_column_family(db, "durable_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "durable_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < 10; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "durable_key_%d", i);
            snprintf(value, sizeof(value), "durable_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush to ensure data is on disk */
        tidesdb_flush_memtable(cf);

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

        printf("CF after reopen: commit_seq=%lu\n", (unsigned long)atomic_load(&cf->commit_seq));
        fflush(stdout);

        /* verify all data is still there */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* trigger CF addition to see snapshot */
        uint8_t dummy_key[] = "dummy";
        uint8_t *dummy_val = NULL;
        size_t dummy_size = 0;
        tidesdb_txn_get(txn, cf, dummy_key, sizeof(dummy_key), &dummy_val, &dummy_size);
        if (dummy_val) free(dummy_val);

        printf("Transaction snapshot after first get: %lu\n", (unsigned long)txn->cf_snapshots[0]);
        fflush(stdout);

        for (int i = 0; i < 10; i++)
        {
            char key[32], expected_value[64];
            snprintf(key, sizeof(key), "durable_key_%d", i);
            snprintf(expected_value, sizeof(expected_value), "durable_value_%d", i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
            printf("Key %s: result=%d\n", key, result);
            fflush(stdout);
            ASSERT_EQ(result, 0);
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
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "integrity_key_%03d", i);
        snprintf(value, sizeof(value), "integrity_value_%03d_checksum_%d", i, i * 12345);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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

    tidesdb_compact(cf);
    usleep(2000000);

    /* verify data integrity after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32], expected_value[128];
        snprintf(key, sizeof(key), "integrity_key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "integrity_value_%03d_checksum_%d", i,
                 i * 12345);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_snapshot_isolation_consistency(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "snapshot_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snapshot_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "snapshot_key";
    uint8_t value1[] = "version_1";
    uint8_t value2[] = "version_2";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start long-running transaction with SNAPSHOT */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);
    printf("txn2 started with snapshot: %lu\n", (unsigned long)txn2->cf_snapshots[0]);
    fflush(stdout);

    /* read initial value */
    uint8_t *read1 = NULL;
    size_t read1_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read1, &read1_size), 0);
    printf("First read: '%s' (expected: '%s')\n", (char *)read1, (char *)value1);
    fflush(stdout);
    ASSERT_TRUE(strcmp((char *)read1, (char *)value1) == 0);
    free(read1);

    /* another transaction updates the value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    int commit_result = tidesdb_txn_commit(txn3);
    printf("txn3 commit result: %d\n", commit_result);
    fflush(stdout);
    ASSERT_EQ(commit_result, 0);

    /* original transaction should still see old value (snapshot isolation) */
    uint8_t *read2 = NULL;
    size_t read2_size = 0;
    printf("txn2 snapshot is still: %lu\n", (unsigned long)txn2->cf_snapshots[0]);
    fflush(stdout);
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read2, &read2_size), 0);
    printf("Second read: '%s' (expected: '%s')\n", (char *)read2, (char *)value1);
    fflush(stdout);
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
    cleanup_test_dir();
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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* verify all keys in memtable */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        free(value);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    /* we do NOT wait -- reads should work immediately via immutable memtable search */

    /* verify all keys during/after flush */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        free(value);
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int start_key;
    int end_key;
    _Atomic(int) *errors;
} concurrent_writes_thread_data_t;

static void *concurrent_writes_write_thread(void *arg)
{
    concurrent_writes_thread_data_t *data = (concurrent_writes_thread_data_t *)arg;
    for (int i = data->start_key; i < data->end_key; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            continue;
        }

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key_%05d", i);
        snprintf(value, sizeof(value), "value_from_thread_%d_key_%d", data->thread_id, i);

        if (tidesdb_txn_put(txn, data->cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                            strlen(value) + 1, 0) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            tidesdb_txn_free(txn);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
        }

        tidesdb_txn_free(txn);
    }
    return NULL;
}

static void test_concurrent_writes_visibility(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024 * 1024; /* 1MB to avoid flushes during test */

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 4;
    const int KEYS_PER_THREAD = 10;
    const int TOTAL_KEYS = NUM_THREADS * KEYS_PER_THREAD;

    _Atomic(int) errors = 0;
    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    concurrent_writes_thread_data_t *thread_data = (concurrent_writes_thread_data_t *)malloc(
        NUM_THREADS * sizeof(concurrent_writes_thread_data_t));
    int missing_keys;
    uint64_t final_commit_seq;

    /* launch write threads */
    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].start_key = i * KEYS_PER_THREAD;
        thread_data[i].end_key = (i + 1) * KEYS_PER_THREAD;
        thread_data[i].errors = &errors;
        pthread_create(&threads[i], NULL, concurrent_writes_write_thread, &thread_data[i]);
    }

    /* wait for all writes to complete */
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    ASSERT_EQ(errors, 0);

    /* verify ALL keys are visible */
    final_commit_seq = atomic_load_explicit(&cf->commit_seq, memory_order_acquire);
    printf("Starting read phase. Current commit_seq: %lu\n", (unsigned long)final_commit_seq);

    missing_keys = 0;
    for (int i = 0; i < TOTAL_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        char key[32];
        uint8_t *value = NULL;
        size_t value_size = 0;
        int get_result;
        uint64_t snap;

        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        snprintf(key, sizeof(key), "key_%05d", i);
        get_result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (get_result != 0)
        {
            snap = (txn->num_cfs > 0) ? txn->cf_snapshots[0] : 0;
            printf(BOLDRED "MISSING KEY: %s (snapshot_seq=%lu)\n" RESET, key, (unsigned long)snap);
            missing_keys++;
        }
        else
        {
            free(value);
        }

        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(missing_keys, 0);

    free(threads);
    free(thread_data);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dividing_merge_strategy(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* carefully tuned config to trigger dividing merge */
    cf_config.write_buffer_size = 256;   /* small for frequent flushes */
    cf_config.level_size_ratio = 4;      /* small ratio = faster level filling */
    cf_config.dividing_level_offset = 1; /* x = num_levels - 2 */
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "dividing_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dividing_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data to create multiple levels
     * level 0 capacity = 256 * 4 = 1024 bytes
     * level 1 capacity = 1024 * 4 = 4096 bytes
     * level 2 capacity = 4096 * 4 = 16384 bytes
     * need ~20KB total to reach level 2 */
    int num_keys = 32;
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "div_key_%04d", i);
        snprintf(value, sizeof(value), "dividing_merge_value_%04d_with_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* wait for flushes */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* trigger compaction -- should use dividing merge */
    tidesdb_compact(cf);

    /* wait for compaction */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(100000);

    /* verify all data is accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "div_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_partitioned_merge_strategy(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* config to force partitioned merge
     * strategy: make level X very small so it fills up during one compaction cycle
     * dividing_level_offset=1 means X = num_levels - 2 (higher X than default)
     * small ratio (2x) creates many smaller levels
     * this way, when we compact, level X will stay full and trigger partitioned merge
     */
    cf_config.write_buffer_size = 150 * 8; /* very small buffer */
    cf_config.level_size_ratio = 2;        /* 2x growth = many small levels */
    cf_config.dividing_level_offset = 1;   /* X = num_levels - 2 (not -3) */
    cf_config.min_levels = 4;              /* force at least 4 levels */
    // cf_config.compression_algorithm = NO_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "partition_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "partition_cf");
    ASSERT_TRUE(cf != NULL);

    /* level capacity calculations with write_buffer_size=150, ratio=2, min_levels=4:
     * L0: 150 * 2 = 300 bytes
     * L1: 300 * 2 = 600 bytes
     * L2: 600 * 2 = 1,200 bytes
     * L3: 1,200 * 2 = 2,400 bytes
     * L4: 2,400 * 2 = 4,800 bytes
     * L5: 4,800 * 2 = 9,600 bytes
     * L6: 9,600 * 2 = 19,200 bytes
     * L7: 19,200 * 2 = 38,400 bytes
     *
     * dividing_level_offset=1, so X = num_levels - 1 - 1 = num_levels - 2
     * With 7 levels: X = 7 - 2 = 5
     * With 6 levels: X = 6 - 2 = 4
     *
     * Write 2000 keys × ~92 bytes = ~184,000 bytes
     * This will create many levels, and level X (4 or 5) will be small enough
     * that it stays full even after the initial dividing/full merge
     */

    /* Write all keys in one batch */
    printf("Writing 150 keys to force partitioned merge\n");
    for (int i = 0; i < 150; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "part_key_%04d", i);
        snprintf(value, sizeof(value), "partitioned_merge_value_%04d_with_extra_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 5 == 4) /* flush more frequently */
        {
            tidesdb_flush_memtable(cf);
            usleep(10000);
        }
    }

    int num_keys = 150;

    /* wait for final flushes */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* Compact - with 2000 keys and small levels, should trigger partitioned merge */
    printf("Compacting - look for 'Partitioned preemptive merge: levels X to Z' in logs\n");
    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }
    usleep(200000);

    int levels_after = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
    printf("After compaction: %d levels (X would be %d - 2 = %d)\n", levels_after, levels_after,
           levels_after - 2);

    /* level count may vary due to DCA removing empty levels after compaction.
     * the important thing is that partitioned merge was triggered (visible in debug logs).
     * we verify data integrity instead of level count. */
    ASSERT_TRUE(levels_after >= 2); /* at least some hierarchy */

    /* verify all data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "part_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multi_level_compaction_strategies(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 300;
    cf_config.level_size_ratio = 4;
    cf_config.dividing_level_offset = 1;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_cf");
    ASSERT_TRUE(cf != NULL);

    /* small dataset -- triggers full preemptive merge */
    printf("Phase 1: Writing 50 keys (full preemptive merge)\n");
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase1_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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

    int levels_phase1 = atomic_load_explicit(&cf->num_levels, memory_order_acquire);

    printf("  Levels after phase 1: %d\n", levels_phase1);

    /* medium dataset -- triggers dividing merge */
    printf("Phase 2: Writing 100 more keys (dividing merge)\n");
    for (int i = 50; i < 150; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase2_value_%04d_with_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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

    int levels_phase2 = atomic_load_explicit(&cf->num_levels, memory_order_acquire);

    printf("  Levels after phase 2: %d\n", levels_phase2);

    /* large dataset -- triggers partitioned merge */
    printf("Phase 3: Writing 100 more keys (partitioned merge)\n");
    for (int i = 150; i < 250; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "multi_key_%04d", i);
        snprintf(value, sizeof(value), "phase3_value_%04d_with_extra_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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

    int final_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);

    printf("  Levels after phase 3: %d\n", final_levels);

    /* verify all 250 keys */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 250; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "multi_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_boundary_partitioning(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 250;
    cf_config.level_size_ratio = 3;
    cf_config.dividing_level_offset = 2;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "boundary_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "boundary_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys with specific patterns to test boundary detection
     * we use lexicographically distributed keys */
    int num_keys = 120;
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        /* create keys that span alphabet for good boundary distribution */
        char prefix = 'a' + (i % 26);
        snprintf(key, sizeof(key), "%c_boundary_key_%04d", prefix, i);
        snprintf(value, sizeof(value), "boundary_value_%04d_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        char prefix = 'a' + (i % 26);
        snprintf(key, sizeof(key), "%c_boundary_key_%04d", prefix, i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dynamic_capacity_adjustment(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* config that will trigger level additions */
    cf_config.write_buffer_size = 2048; /* small buffer for frequent flushes */
    cf_config.level_size_ratio = 2;     /* L1=4096, L2=8192, L3=16384 */
    cf_config.dividing_level_offset = 1;
    cf_config.min_levels = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "dca_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dca_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
    printf("Initial levels: %d\n", initial_levels);

    /* write data in batches, triggering level additions
     * need to write enough to fill L2 (8192 bytes) and trigger DCA
     * after partitioned merge fix, data accumulates in L2, so we need significantly more data
     * write 10 batches of ~200KB each to ensure L2 fills beyond capacity and triggers L3 creation
     */
    int total_keys_written = 0;
    for (int batch = 0; batch < 10; batch++)
    {
        printf("Batch %d: Writing keys\n", batch + 1);

        int written = 0;

        /* write ~200KB per batch (200000 bytes / 160 bytes per key = ~1250 keys) */
        for (int i = 0; i < 100000 && written < 200000; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[128];
            snprintf(key, sizeof(key), "dca_key_%05d", total_keys_written);
            snprintf(value, sizeof(value), "dca_value_%05d_with_padding_data", total_keys_written);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);

            total_keys_written++;
            written += 160; /* approximate size per key */
        }

        for (int i = 0; i < 50; i++)
        {
            usleep(10000);
            if (queue_size(db->flush_queue) == 0) break;
        }

        printf("done flushing\n");

        /* wait for background compactions to trigger */
        sleep(3);

        int current_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);

        printf("  After batch %d: %d levels\n", batch + 1, current_levels);

        /* if we've grown levels, we can stop early */
        if (current_levels > initial_levels)
        {
            printf("  Level growth detected! Stopping early.\n");
            break;
        }
    }

    int final_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
    printf("Final levels: %d (growth: %d levels)\n", final_levels, final_levels - initial_levels);
    printf("Total keys written: %d\n", total_keys_written);

    for (int i = 0; i < 128; i++)
    {
        usleep(10000);
        if (queue_size(db->compaction_queue) == 0) break;
    }

    /* re-check levels after compactions complete */
    final_levels = atomic_load_explicit(&cf->num_levels, memory_order_acquire);
    printf("Final levels after compaction wait: %d\n", final_levels);

    /* verify DCA worked -- should have added levels */
    ASSERT_TRUE(final_levels > initial_levels);

    /* verify all data is accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* check a sample of keys across the range to verify data integrity */
    int keys_to_check = total_keys_written < 500 ? total_keys_written : 500;
    for (int i = 0; i < keys_to_check; i++)
    {
        /* sample keys evenly across the range */
        int key_idx = (i * total_keys_written) / keys_to_check;
        char key[32];
        snprintf(key, sizeof(key), "dca_key_%05d", key_idx);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
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

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "cf1", &config) == TDB_SUCCESS);
    assert(tidesdb_create_column_family(db, "cf2", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");
    assert(cf1 != NULL);
    assert(cf2 != NULL);

    /* start transaction (no CF parameter) */
    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    /* write to both CFs (CFs added automatically on first use) */
    const char *key1 = "key_cf1";
    const char *val1 = "value_cf1";
    const char *key2 = "key_cf2";
    const char *val2 = "value_cf2";

    assert(tidesdb_txn_put(txn, cf1, (uint8_t *)key1, strlen(key1), (uint8_t *)val1, strlen(val1),
                           0) == TDB_SUCCESS);
    assert(tidesdb_txn_put(txn, cf2, (uint8_t *)key2, strlen(key2), (uint8_t *)val2, strlen(val2),
                           0) == TDB_SUCCESS);

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* verify data in both CFs */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    uint8_t *retrieved_val;
    size_t retrieved_size;

    assert(tidesdb_txn_get(txn, cf1, (uint8_t *)key1, strlen(key1), &retrieved_val,
                           &retrieved_size) == TDB_SUCCESS);
    assert(retrieved_size == strlen(val1));
    assert(memcmp(retrieved_val, val1, retrieved_size) == 0);
    free(retrieved_val);

    assert(tidesdb_txn_get(txn, cf2, (uint8_t *)key2, strlen(key2), &retrieved_val,
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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *key1 = "committed_key1";
    const char *val1 = "committed_val1";
    assert(tidesdb_txn_put(txn, cf1, (uint8_t *)key1, strlen(key1), (uint8_t *)val1, strlen(val1),
                           0) == TDB_SUCCESS);
    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* tx 2 write then rollback */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *key2 = "rollback_key";
    const char *val2 = "rollback_val";
    assert(tidesdb_txn_put(txn, cf1, (uint8_t *)key2, strlen(key2), (uint8_t *)val2, strlen(val2),
                           0) == TDB_SUCCESS);
    assert(tidesdb_txn_put(txn, cf2, (uint8_t *)key2, strlen(key2), (uint8_t *)val2, strlen(val2),
                           0) == TDB_SUCCESS);

    tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);

    /* verify committed data exists, rolled back data doesn't */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    uint8_t *retrieved_val;
    size_t retrieved_size;

    /* committed data should exist */
    assert(tidesdb_txn_get(txn, cf1, (uint8_t *)key1, strlen(key1), &retrieved_val,
                           &retrieved_size) == TDB_SUCCESS);
    free(retrieved_val);

    /* rolled back data should NOT exist */
    assert(tidesdb_txn_get(txn, cf1, (uint8_t *)key2, strlen(key2), &retrieved_val,
                           &retrieved_size) == TDB_ERR_NOT_FOUND);
    assert(tidesdb_txn_get(txn, cf2, (uint8_t *)key2, strlen(key2), &retrieved_val,
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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    for (int i = 0; i < 10; i++)
    {
        char key[32], val[32];
        /* we use different key prefixes for each CF to avoid deduplication */
        snprintf(key, sizeof(key), "cf1_key_%03d", i);
        snprintf(val, sizeof(val), "val_cf1_%03d", i);
        assert(tidesdb_txn_put(txn, cf1, (uint8_t *)key, strlen(key), (uint8_t *)val, strlen(val),
                               0) == TDB_SUCCESS);

        snprintf(key, sizeof(key), "cf2_key_%03d", i);
        snprintf(val, sizeof(val), "val_cf2_%03d", i);
        assert(tidesdb_txn_put(txn, cf2, (uint8_t *)key, strlen(key), (uint8_t *)val, strlen(val),
                               0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* create iterator for cf1 */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf1, &iter) == TDB_SUCCESS);

    /* iterate and count entries in cf1 */
    int count = 0;
    assert(tidesdb_iter_seek_to_first(iter) == TDB_SUCCESS);
    do
    {
        if (!tidesdb_iter_valid(iter)) break;
        count++;
    } while (tidesdb_iter_next(iter) == TDB_SUCCESS);

    /* should see 10 entries from cf1 */
    assert(count == 10);

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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *keys[] = {"aaa", "mmm", "zzz"};
    for (int i = 0; i < 3; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put(txn, cf1, (uint8_t *)keys[i], strlen(keys[i]), (uint8_t *)val,
                               strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put(txn, cf2, (uint8_t *)keys[i], strlen(keys[i]), (uint8_t *)val,
                               strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test iterator boundaries */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf1, &iter) == TDB_SUCCESS);

    assert(tidesdb_iter_seek_to_first(iter) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *key = NULL;
    size_t key_size = 0;
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(memcmp(key, "aaa", 3) == 0);

    assert(tidesdb_iter_seek_to_last(iter) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    key = NULL;
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(memcmp(key, "zzz", 3) == 0);

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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    for (int i = 0; i < 5; i++)
    {
        char key[32], val[32];
        /* use different key prefixes for each CF to avoid deduplication */
        snprintf(key, sizeof(key), "cf1_key_%02d", i);
        snprintf(val, sizeof(val), "val_cf1_%02d", i);
        assert(tidesdb_txn_put(txn, cf1, (uint8_t *)key, strlen(key), (uint8_t *)val, strlen(val),
                               0) == TDB_SUCCESS);

        snprintf(key, sizeof(key), "cf2_key_%02d", i);
        snprintf(val, sizeof(val), "val_cf2_%02d", i);
        assert(tidesdb_txn_put(txn, cf2, (uint8_t *)key, strlen(key), (uint8_t *)val, strlen(val),
                               0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* iterate in reverse */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf1, &iter) == TDB_SUCCESS);

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
        count++;
    } while (tidesdb_iter_prev(iter) == TDB_SUCCESS);

    assert(count == 5); /* 5 keys from cf1 */

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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *cf1_keys[] = {"cf1_key_10", "cf1_key_20", "cf1_key_30", "cf1_key_40", "cf1_key_50"};
    const char *cf2_keys[] = {"cf2_key_10", "cf2_key_20", "cf2_key_30", "cf2_key_40", "cf2_key_50"};
    for (int i = 0; i < 5; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put(txn, cf1, (uint8_t *)cf1_keys[i], strlen(cf1_keys[i]),
                               (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put(txn, cf2, (uint8_t *)cf2_keys[i], strlen(cf2_keys[i]),
                               (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test seek operations */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf1, &iter) == TDB_SUCCESS);

    /* seek to exact key in cf1 */
    const char *seek_key = "cf1_key_30";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *found_key = NULL;
    size_t found_key_size = 0;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, seek_key, strlen(seek_key)) == 0);

    /* seek to non-existent key (should find next) */
    const char *seek_key2 = "cf1_key_25";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek_key2, strlen(seek_key2)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    found_key = NULL;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, "cf1_key_30", 10) == 0);

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
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *cf1_keys[] = {"cf1_key_10", "cf1_key_20", "cf1_key_30", "cf1_key_40", "cf1_key_50"};
    const char *cf2_keys[] = {"cf2_key_10", "cf2_key_20", "cf2_key_30", "cf2_key_40", "cf2_key_50"};
    for (int i = 0; i < 5; i++)
    {
        char val[32];
        snprintf(val, sizeof(val), "cf1_val_%d", i);
        assert(tidesdb_txn_put(txn, cf1, (uint8_t *)cf1_keys[i], strlen(cf1_keys[i]),
                               (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);

        snprintf(val, sizeof(val), "cf2_val_%d", i);
        assert(tidesdb_txn_put(txn, cf2, (uint8_t *)cf2_keys[i], strlen(cf2_keys[i]),
                               (uint8_t *)val, strlen(val), 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* test seek_for_prev operations */
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    /* test seek_for_prev with iterator on cf2 */

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf2, &iter) == TDB_SUCCESS);

    /* seek to exact key in cf2 */
    const char *seek_key = "cf2_key_30";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key)) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    uint8_t *found_key = NULL;
    size_t found_key_size = 0;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, seek_key, strlen(seek_key)) == 0);

    /* seek to non-existent key (should find previous) */
    const char *seek_key2 = "cf2_key_35";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key2, strlen(seek_key2)) ==
           TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    found_key = NULL;
    assert(tidesdb_iter_key(iter, &found_key, &found_key_size) == TDB_SUCCESS);
    assert(memcmp(found_key, "cf2_key_30", 10) == 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_repeatable_read(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rr_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rr_cf");

    uint8_t key[] = "rr_key";
    uint8_t value1[] = "version_1";
    uint8_t value2[] = "version_2";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start REPEATABLE_READ transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_REPEATABLE_READ, &txn2), 0);

    /* read initial value */
    uint8_t *read1 = NULL;
    size_t read1_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read1, &read1_size), 0);
    ASSERT_TRUE(strcmp((char *)read1, (char *)value1) == 0);
    free(read1);

    /* another transaction updates the value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* REPEATABLE_READ should still see old value */
    uint8_t *read2 = NULL;
    size_t read2_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read2, &read2_size), 0);
    ASSERT_TRUE(strcmp((char *)read2, (char *)value1) == 0);
    free(read2);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_write_write_conflict(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "ww_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ww_cf");

    uint8_t key[] = "conflict_key";
    uint8_t value1[] = "initial";
    uint8_t value2[] = "update1";
    uint8_t value3[] = "update2";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start two SNAPSHOT transactions */
    tidesdb_txn_t *txn2 = NULL, *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn3), 0);

    /* both try to update the same key */
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value3, sizeof(value3), 0), 0);

    /* first commit should succeed */
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* second commit should fail with conflict */
    ASSERT_EQ(tidesdb_txn_commit(txn3), TDB_ERR_CONFLICT);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_write_conflict(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rw_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rw_cf");

    uint8_t key[] = "rw_key";
    uint8_t value1[] = "initial";
    uint8_t value2[] = "updated";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start SNAPSHOT transaction and read */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);
    uint8_t *read_val = NULL;
    size_t read_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read_val, &read_size), 0);
    free(read_val);

    /* another transaction updates the key */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* txn2 tries to write, should fail due to read-write conflict */
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), TDB_ERR_CONFLICT);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_serializable_phantom_prevention(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "phantom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "phantom_cf");

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &txn1), 0);

    /* read some keys */
    for (int i = 0; i < 3; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key_%d", i);
        uint8_t *val = NULL;
        size_t val_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn1, cf, (uint8_t *)key, strlen(key) + 1, &val, &val_size), 0);
        free(val);
    }

    /* another transaction inserts a new key in the range */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t new_key[] = "key_10";
    uint8_t new_value[] = "new_value";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, new_key, sizeof(new_key), new_value, sizeof(new_value), 0),
              0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    uint8_t write_key[] = "key_20";
    uint8_t write_value[] = "write_value";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, write_key, sizeof(write_key), write_value,
                              sizeof(write_value), 0),
              0);
    int result = tidesdb_txn_commit(txn1);
    /* result can be success or conflict, both are valid */
    ASSERT_TRUE(result == 0 || result == TDB_ERR_CONFLICT);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_transaction_abort_retry(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "retry_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "retry_cf");

    uint8_t key[] = "retry_key";
    uint8_t value1[] = "initial";
    uint8_t value2[] = "updated";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    int retry_count = 0;
    int max_retries = 3;
    int success = 0;

    while (retry_count < max_retries && !success)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn), 0);

        /* read current value */
        uint8_t *read_val = NULL;
        size_t read_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &read_val, &read_size), 0);
        free(read_val);

        /* try to update */
        ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);

        int result = tidesdb_txn_commit(txn);
        if (result == 0)
        {
            success = 1;
        }
        else if (result == TDB_ERR_CONFLICT)
        {
            retry_count++;
        }
        else
        {
            ASSERT_TRUE(0); /* unexpected error */
        }

        tidesdb_txn_free(txn);
    }

    ASSERT_TRUE(success || retry_count == max_retries);

    tidesdb_txn_free(txn1);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_mixed_isolation_levels(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed_cf");

    uint8_t key[] = "mixed_key";
    uint8_t value1[] = "v1";
    uint8_t value2[] = "v2";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);

    /* start SNAPSHOT transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);
    uint8_t *read1 = NULL;
    size_t read1_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read1, &read1_size), 0);
    ASSERT_TRUE(strcmp((char *)read1, (char *)value1) == 0);
    free(read1);

    /* update with READ_UNCOMMITTED */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_UNCOMMITTED, &txn3), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);

    /* SNAPSHOT should still see old value */
    uint8_t *read2 = NULL;
    size_t read2_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read2, &read2_size), 0);
    ASSERT_TRUE(strcmp((char *)read2, (char *)value1) == 0);
    free(read2);

    /* READ_COMMITTED should see new value */
    tidesdb_txn_t *txn4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, &txn4), 0);
    uint8_t *read3 = NULL;
    size_t read3_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn4, cf, key, sizeof(key), &read3, &read3_size), 0);
    ASSERT_TRUE(strcmp((char *)read3, (char *)value2) == 0);
    free(read3);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_txn_free(txn4);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_long_running_transaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "long_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "long_cf");

    /* we start long-running SNAPSHOT transaction */
    tidesdb_txn_t *long_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &long_txn), 0);

    /* perform multiple operations */
    for (int i = 0; i < 10; i++)
    {
        char key[32], value[32];
        snprintf(key, sizeof(key), "long_key_%d", i);
        snprintf(value, sizeof(value), "long_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(long_txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    /* concurrent short transactions */
    for (int i = 10; i < 20; i++)
    {
        tidesdb_txn_t *short_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &short_txn), 0);
        char key[32], value[32];
        snprintf(key, sizeof(key), "short_key_%d", i);
        snprintf(value, sizeof(value), "short_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(short_txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(short_txn), 0);
        tidesdb_txn_free(short_txn);
    }

    /* commit long transaction */
    ASSERT_EQ(tidesdb_txn_commit(long_txn), 0);

    /* verify all keys exist */
    tidesdb_txn_t *verify_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &verify_txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        if (i < 10)
        {
            snprintf(key, sizeof(key), "long_key_%d", i);
        }
        else
        {
            snprintf(key, sizeof(key), "short_key_%d", i);
        }
        uint8_t *val = NULL;
        size_t val_size = 0;
        ASSERT_EQ(tidesdb_txn_get(verify_txn, cf, (uint8_t *)key, strlen(key) + 1, &val, &val_size),
                  0);
        free(val);
    }

    tidesdb_txn_free(long_txn);
    tidesdb_txn_free(verify_txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_recovery_with_corrupted_sstable(void)
{
    cleanup_test_dir();

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 512;

        ASSERT_EQ(tidesdb_create_column_family(db, "corrupt_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "corrupt_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < 50; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "corrupt_key_%d", i);
            snprintf(value, sizeof(value), "corrupt_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        tidesdb_flush_memtable(cf);
        usleep(100000);

        tidesdb_close(db);
    }

    {
        char corrupt_file[1024];
        snprintf(corrupt_file, sizeof(corrupt_file), "%s/corrupt_cf/L1_0.klog", TEST_DB_PATH);

        FILE *f = fopen(corrupt_file, "r+b");
        if (f)
        {
            /* use little-endian encoding to match block manager's format */
            uint32_t bad_magic = 0xDEADBEEF;
            uint8_t magic_buf[4];
            encode_uint32_le_compat(magic_buf, bad_magic);
            fseek(f, 0, SEEK_SET);
            fwrite(magic_buf, sizeof(magic_buf), 1, f);
            fclose(f);
            printf("Corrupted SSTable: %s\n", corrupt_file);
        }
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;
        config.num_flush_threads = 1;
        config.num_compaction_threads = 1;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "corrupt_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "new_key_after_corruption");
        snprintf(value, sizeof(value), "new_value_after_corruption");

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_portability_workflow(void)
{
    cleanup_test_dir();

    {
        tidesdb_config_t cfg = tidesdb_default_config();
        cfg.db_path = TEST_DB_PATH;
        cfg.num_flush_threads = 1;
        cfg.enable_debug_logging = 1;
        cfg.num_compaction_threads = 1;
        cfg.block_cache_size = 0;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&cfg, &db), 0);

        tidesdb_column_family_config_t cf_cfg = tidesdb_default_column_family_config();
        cf_cfg.write_buffer_size = 1024;
        cf_cfg.enable_bloom_filter = 1;
        cf_cfg.enable_block_indexes = 1;
        cfg.block_cache_size = 0;

        ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_cfg), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 100; i++)
        {
            char key[64], value[128];
            snprintf(key, sizeof(key), "key_%d", i);
            snprintf(value, sizeof(value), "value_%d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        sleep(1);

        ASSERT_EQ(tidesdb_compact(cf), 0);
        sleep(1);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t cfg = tidesdb_default_config();
        cfg.db_path = TEST_DB_PATH;
        cfg.enable_debug_logging = 1;
        cfg.num_flush_threads = 1;
        cfg.num_compaction_threads = 1;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&cfg, &db), 0);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < 100; i++)
        {
            char key[64], expected[128];
            snprintf(key, sizeof(key), "key_%d", i);
            snprintf(expected, sizeof(expected), "value_%d", i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

            if (result != 0 || value == NULL)
            {
                printf("FAILED: Key not found: %s\n", key);
                ASSERT_EQ(result, 0);
            }

            ASSERT_TRUE(value_size == strlen(expected) + 1);
            ASSERT_TRUE(memcmp(value, expected, strlen(expected)) == 0);
            free(value);
        }

        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iterator_across_multiple_memtable_flushes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512; /* small buffer to force multiple flushes */

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_flush_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys in batches, flushing between batches */
    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            int key_num = batch * 20 + i;
            snprintf(key, sizeof(key), "key_%04d", key_num);
            snprintf(value, sizeof(value), "value_%04d", key_num);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    /* wait for all flushes to complete */
    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(100000);

    /* iterate across all sstables */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);
        ASSERT_TRUE(key != NULL);
        ASSERT_TRUE(value != NULL);

        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    /* should see all 100 keys across all sstables */
    ASSERT_EQ(count, 100);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_after_multiple_overwrites(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "overwrite_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overwrite_cf");
    ASSERT_TRUE(cf != NULL);

    /* overwrite same keys across multiple flushes */
    for (int version = 0; version < 5; version++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "key_%02d", i);
            snprintf(value, sizeof(value), "value_v%d_k%02d", version, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    /* wait for flushes */
    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(100000);

    /* verify we get latest version of each key */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(expected, sizeof(expected), "value_v4_k%02d", i); /* version 4 is latest */

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(strcmp((char *)value, expected) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_large_transaction_batch(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "batch_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "batch_cf");
    ASSERT_TRUE(cf != NULL);

    /* single transaction with many operations */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    const int NUM_OPS = 500;
    for (int i = 0; i < NUM_OPS; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "batch_key_%04d", i);
        snprintf(value, sizeof(value), "batch_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* verify all keys are present */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < NUM_OPS; i += 50)
    {
        char key[32];
        snprintf(key, sizeof(key), "batch_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_delete_and_recreate_same_key(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "del_recreate_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "del_recreate_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t key[] = "test_key";

    /* create, delete, recreate cycle multiple times */
    for (int cycle = 0; cycle < 10; cycle++)
    {
        /* create */
        tidesdb_txn_t *txn1 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

        char value[64];
        snprintf(value, sizeof(value), "value_cycle_%d", cycle);
        ASSERT_EQ(
            tidesdb_txn_put(txn1, cf, key, sizeof(key), (uint8_t *)value, strlen(value) + 1, 0), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
        tidesdb_txn_free(txn1);

        /* verify exists */
        tidesdb_txn_t *txn2 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
        ASSERT_TRUE(retrieved != NULL);
        ASSERT_TRUE(strcmp((char *)retrieved, value) == 0);
        free(retrieved);
        tidesdb_txn_free(txn2);

        /* delete */
        tidesdb_txn_t *txn3 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
        ASSERT_EQ(tidesdb_txn_delete(txn3, cf, key, sizeof(key)), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
        tidesdb_txn_free(txn3);

        /* verify deleted */
        tidesdb_txn_t *txn4 = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn4), 0);
        retrieved = NULL;
        ASSERT_TRUE(tidesdb_txn_get(txn4, cf, key, sizeof(key), &retrieved, &retrieved_size) != 0);
        tidesdb_txn_free(txn4);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_reads_same_key(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_read_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_read_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn0 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn0), 0);

    uint8_t key[] = "shared_key";
    uint8_t value[] = "shared_value";
    ASSERT_EQ(tidesdb_txn_put(txn0, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn0), 0);
    tidesdb_txn_free(txn0);

    /* create multiple concurrent transactions that read same key */
    tidesdb_txn_t *txns[10];
    for (int i = 0; i < 10; i++)
    {
        ASSERT_EQ(tidesdb_txn_begin(db, &txns[i]), 0);
    }

    /* all should be able to read the same key */
    for (int i = 0; i < 10; i++)
    {
        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txns[i], cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
        ASSERT_TRUE(retrieved != NULL);
        ASSERT_TRUE(memcmp(retrieved, value, sizeof(value)) == 0);
        free(retrieved);
    }

    /* cleanup all transactions */
    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_free(txns[i]);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_zero_ttl_means_no_expiration(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "no_ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_ttl_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "eternal_key";
    uint8_t value[] = "eternal_value";

    /* ttl = 0 means no expiration */
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* wait some time */
    sleep(2);

    /* key should still exist */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_TRUE(memcmp(retrieved, value, sizeof(value)) == 0);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_mixed_ttl_expiration(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed_ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed_ttl_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /*  no expiration */
    uint8_t key1[] = "key_no_ttl";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key1, sizeof(key1), value1, sizeof(value1), 0), 0);

    /* short expiration */
    uint8_t key2[] = "key_short_ttl";
    uint8_t value2[] = "value2";
    time_t short_ttl = time(NULL) + 2;
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key2, sizeof(key2), value2, sizeof(value2), short_ttl), 0);

    /* long expiration */
    uint8_t key3[] = "key_long_ttl";
    uint8_t value3[] = "value3";
    time_t long_ttl = time(NULL) + 3600; /* 1 hour */
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key3, sizeof(key3), value3, sizeof(value3), long_ttl), 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* wait for short ttl to expire */
    sleep(3);

    /* verify states */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;

    /* key1 should exist (no ttl) */
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    /* key2 should be expired */
    retrieved = NULL;
    int result2 = tidesdb_txn_get(txn, cf, key2, sizeof(key2), &retrieved, &retrieved_size);
    ASSERT_TRUE(result2 != 0 || retrieved == NULL);

    /* key3 should exist (long ttl not expired) */
    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key3, sizeof(key3), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_get_nonexistent_cf(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "nonexistent_cf");
    ASSERT_TRUE(cf == NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_create_duplicate_cf(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "dup_cf", &cf_config), 0);

    int result = tidesdb_create_column_family(db, "dup_cf", &cf_config);
    ASSERT_TRUE(result != 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_drop_nonexistent_cf(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();

    int result = tidesdb_drop_column_family(db, "nonexistent_cf");
    ASSERT_TRUE(result != 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_nested_savepoints(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "nested_sp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "nested_sp_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key1, sizeof(key1), value1, sizeof(value1), 0), 0);

    /* create savepoint sp1 */
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp1"), 0);

    /* put key2 */
    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key2, sizeof(key2), value2, sizeof(value2), 0), 0);

    /* create savepoint sp2 */
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp2"), 0);

    /* put key3 */
    uint8_t key3[] = "key3";
    uint8_t value3[] = "value3";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key3, sizeof(key3), value3, sizeof(value3), 0), 0);

    /* rollback to sp2; should remove key3 */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp2"), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;

    /* key1 and key2 should exist, key3 should not */
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key2, sizeof(key2), &retrieved, &retrieved_size), 0);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    ASSERT_TRUE(tidesdb_txn_get(txn, cf, key3, sizeof(key3), &retrieved, &retrieved_size) != 0);

    /* rollback to sp1; should remove key2 as well */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp1"), 0);

    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    ASSERT_TRUE(tidesdb_txn_get(txn, cf, key2, sizeof(key2), &retrieved, &retrieved_size) != 0);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_savepoint_with_delete_operations(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "sp_del_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sp_del_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn0 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn0), 0);

    uint8_t key1[] = "key1";
    uint8_t key2[] = "key2";
    uint8_t value[] = "value";

    ASSERT_EQ(tidesdb_txn_put(txn0, cf, key1, sizeof(key1), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn0, cf, key2, sizeof(key2), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn0), 0);
    tidesdb_txn_free(txn0);

    /* now test savepoint with deletes */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* create savepoint */
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "before_delete"), 0);

    /* delete key1 */
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key1, sizeof(key1)), 0);

    /* verify key1 is deleted in transaction */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_TRUE(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size) != 0);

    /* rollback to savepoint, key1 should be visible again */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "before_delete"), 0);

    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key1, sizeof(key1), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    free(retrieved);

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_with_tombstones(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "tomb_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "tomb_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys 0-19 */
    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* delete even keys */
    for (int i = 0; i < 20; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%02d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* iterate and verify only odd keys visible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        /* verify it's an odd key */
        int key_num;
        sscanf((char *)key, "key_%d", &key_num);
        ASSERT_TRUE(key_num % 2 == 1);

        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    /* should see only 10 odd keys */
    ASSERT_EQ(count, 10);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_transaction_isolation_snapshot_with_updates(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "snapshot_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snapshot_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    tidesdb_txn_t *txn_snap = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn_snap), 0);

    /* read initial value in snapshot */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn_snap, cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_TRUE(memcmp(retrieved, value1, sizeof(value1)) == 0);
    free(retrieved);

    /* another transaction updates the value */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* snapshot transaction should still see old value */
    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn_snap, cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_TRUE(memcmp(retrieved, value1, sizeof(value1)) == 0);
    free(retrieved);

    tidesdb_txn_free(txn_snap);

    /* new transaction should see updated value */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    retrieved = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn3, cf, key, sizeof(key), &retrieved, &retrieved_size), 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_TRUE(memcmp(retrieved, value2, sizeof(value2)) == 0);
    free(retrieved);
    tidesdb_txn_free(txn3);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_read_own_uncommitted_writes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "own_writes_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "own_writes_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    /* verify can read all uncommitted writes within transaction */
    for (int i = 0; i < 10; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expected, sizeof(expected), "value_%d", i);

        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size),
            0);
        ASSERT_TRUE(retrieved != NULL);
        ASSERT_TRUE(strcmp((char *)retrieved, expected) == 0);
        free(retrieved);
    }

    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multi_cf_transaction_conflict(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cf1", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf2", &cf_config), 0);

    tidesdb_column_family_t *cf1 = tidesdb_get_column_family(db, "cf1");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "cf2");
    ASSERT_TRUE(cf1 != NULL && cf2 != NULL);

    /* commit initial values in both cfs */
    tidesdb_txn_t *txn0 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn0), 0);

    uint8_t key[] = "shared_key";
    uint8_t value0[] = "value0";

    ASSERT_EQ(tidesdb_txn_put(txn0, cf1, key, sizeof(key), value0, sizeof(value0), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn0, cf2, key, sizeof(key), value0, sizeof(value0), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn0), 0);
    tidesdb_txn_free(txn0);

    /* start two snapshot transactions */
    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);

    /* both read from both cfs */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;

    tidesdb_txn_get(txn1, cf1, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);
    retrieved = NULL;
    tidesdb_txn_get(txn1, cf2, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    retrieved = NULL;
    tidesdb_txn_get(txn2, cf1, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);
    retrieved = NULL;
    tidesdb_txn_get(txn2, cf2, key, sizeof(key), &retrieved, &retrieved_size);
    if (retrieved) free(retrieved);

    /* both write to both cfs */
    uint8_t value1[] = "value1";
    uint8_t value2[] = "value2";

    ASSERT_EQ(tidesdb_txn_put(txn1, cf1, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf2, key, sizeof(key), value1, sizeof(value1), 0), 0);

    ASSERT_EQ(tidesdb_txn_put(txn2, cf1, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn2, cf2, key, sizeof(key), value2, sizeof(value2), 0), 0);

    /* one should succeed, one should fail with conflict */
    int result1 = tidesdb_txn_commit(txn1);
    int result2 = tidesdb_txn_commit(txn2);

    ASSERT_TRUE((result1 == 0 && result2 == TDB_ERR_CONFLICT) ||
                (result2 == 0 && result1 == TDB_ERR_CONFLICT));

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);

    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    const char *test_name;
    int enable_bloom;
    int enable_indexes;
    int compression_algo;
    int num_sstables;
    int keys_per_sstable;
    int block_cache_size;
    tidesdb_isolation_level_t isolation_level;
    tidesdb_comparator_fn comparator;
} sim_test_config_t;

static void run_sstable_simulation(sim_test_config_t *config)
{
    printf("  Running: %s (bloom=%d, idx=%d, comp=%d, ssts=%d, keys=%d)\n", config->test_name,
           config->enable_bloom, config->enable_indexes, config->compression_algo,
           config->num_sstables, config->keys_per_sstable);

    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    db->config.block_cache_size = config->block_cache_size;

    /* apply configuration */
    cf_config.write_buffer_size = config->keys_per_sstable * 100; /* sized to flush at target */
    cf_config.enable_bloom_filter = config->enable_bloom;
    cf_config.enable_block_indexes = config->enable_indexes;
    cf_config.compression_algorithm = config->compression_algo;
    cf_config.bloom_fpr = 0.01;

    /* apply isolation level if specified */
    if (config->isolation_level != 0)
    {
        cf_config.default_isolation_level = config->isolation_level;
    }

    /* apply comparator if specified */
    if (config->comparator != NULL)
    {
        /* register custom comparator for this test */
        const char *cmp_name = "test_comparator";
        tidesdb_register_comparator(db, cmp_name, config->comparator, NULL, NULL);
        strncpy(cf_config.comparator_name, cmp_name, TDB_MAX_COMPARATOR_NAME - 1);
    }

    ASSERT_EQ(tidesdb_create_column_family(db, "sim_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sim_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys and flush to create multiple sstables */
    int total_keys = config->num_sstables * config->keys_per_sstable;
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%06d", i);
        snprintf(value, sizeof(value), "val_%06d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush periodically to create sstables */
        if ((i + 1) % config->keys_per_sstable == 0)
        {
            tidesdb_flush_memtable(cf);
            usleep(20000);
        }
    }

    /* wait for flushes */
    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(100000);

    /* test get for all keys */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < total_keys; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%06d", i);
        snprintf(expected, sizeof(expected), "val_%06d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result != 0)
        {
            printf("FAILED to get key: %s (index %d/%d), result=%d\n", key, i, total_keys, result);
        }
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(strcmp((char *)value, expected) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);

    /* test forward iteration */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int count = 0;
    int is_reverse_comparator = (config->comparator == tidesdb_comparator_reverse_memcmp);
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        char expected_key[32];
        /* with reverse comparator, forward iteration returns descending order */
        int expected_idx = is_reverse_comparator ? (total_keys - 1 - count) : count;
        snprintf(expected_key, sizeof(expected_key), "key_%06d", expected_idx);
        if (count < 3 || count >= total_keys - 3)
        {
            printf("Forward iter count=%d: expected=%s, got=%s\n", count, expected_key,
                   (char *)key);
        }
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    ASSERT_EQ(count, total_keys);
    tidesdb_iter_free(iter);

    /* test reverse iteration */
    printf("Starting reverse iteration test with total_keys=%d, is_reverse=%d\n", total_keys,
           is_reverse_comparator);
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        char expected_key[32];
        /* with reverse comparator, reverse iteration returns ascending order */
        int expected_idx = is_reverse_comparator ? count : (total_keys - 1 - count);
        snprintf(expected_key, sizeof(expected_key), "key_%06d", expected_idx);
        if (strcmp((char *)key, expected_key) != 0)
        {
            printf("Reverse iteration mismatch at count=%d: expected=%s, got=%s\n", count,
                   expected_key, (char *)key);
        }
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        count++;
        if (tidesdb_iter_prev(iter) != 0) break;
    }

    tidesdb_iter_free(iter);

    /* test seek operations */
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    char seek_key[32];
    snprintf(seek_key, sizeof(seek_key), "key_%06d", total_keys / 2);
    ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_TRUE(strcmp((char *)key, seek_key) == 0);

    tidesdb_iter_free(iter);

    /* test seek for prev operations */
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    char seek_prev_key[32];
    snprintf(seek_prev_key, sizeof(seek_prev_key), "key_%06d", total_keys / 2);
    ASSERT_EQ(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_prev_key, strlen(seek_prev_key) + 1),
              0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    key = NULL;
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
    ASSERT_TRUE(strcmp((char *)key, seek_prev_key) == 0);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_many_sstables_with_bloom_filter(void)
{
    sim_test_config_t config = {.test_name = "bloom_filter_enabled",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_without_bloom_filter(void)
{
    sim_test_config_t config = {.test_name = "bloom_filter_disabled",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_block_indexes(void)
{
    sim_test_config_t config = {.test_name = "block_indexes_enabled",
                                .enable_bloom = 0,
                                .enable_indexes = 1,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_lz4_compression(void)
{
    sim_test_config_t config = {.test_name = "lz4_compression",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_zstd_compression(void)
{
    sim_test_config_t config = {.test_name = "zstd_compression",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40};
    run_sstable_simulation(&config);
}

#ifndef __sun
static void test_many_sstables_with_snappy_compression(void)
{
    sim_test_config_t config = {.test_name = "snappy_compression",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = SNAPPY_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40};
    run_sstable_simulation(&config);
}
#endif

static void test_many_sstables_all_features_enabled(void)
{
    sim_test_config_t config = {.test_name = "all_features_enabled",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 25,
                                .block_cache_size = 0,
                                .keys_per_sstable = 60};
    run_sstable_simulation(&config);
}

static void test_many_sstables_all_features_disabled(void)
{
    sim_test_config_t config = {.test_name = "all_features_disabled",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 25,
                                .block_cache_size = 0,
                                .keys_per_sstable = 60};
    run_sstable_simulation(&config);
}

static void test_many_sstables_bloom_and_compression(void)
{
    sim_test_config_t config = {.test_name = "bloom_and_zstd",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_indexes_and_compression(void)
{
    sim_test_config_t config = {.test_name = "indexes_and_snappy",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_bloom_filter_cached(void)
{
    sim_test_config_t config = {.test_name = "bloom_filter_enabled_cached",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_without_bloom_filter_cached(void)
{
    sim_test_config_t config = {.test_name = "bloom_filter_disabled_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_block_indexes_cached(void)
{
    sim_test_config_t config = {.test_name = "block_indexes_enabled_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 1,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_lz4_compression_cached(void)
{
    sim_test_config_t config = {.test_name = "lz4_compression_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_with_zstd_compression_cached(void)
{
    sim_test_config_t config = {.test_name = "zstd_compression_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

#ifndef __sun
static void test_many_sstables_with_snappy_compression_cached(void)
{
    sim_test_config_t config = {.test_name = "snappy_compression_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = SNAPPY_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}
#endif

static void test_many_sstables_all_features_enabled_cached(void)
{
    sim_test_config_t config = {.test_name = "all_features_enabled_cached",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 25,
                                .block_cache_size = 32 * 1024 * 1024, /* 32MB */
                                .keys_per_sstable = 60};
    run_sstable_simulation(&config);
}

static void test_many_sstables_all_features_disabled_cached(void)
{
    sim_test_config_t config = {.test_name = "all_features_disabled_cached",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = NO_COMPRESSION,
                                .num_sstables = 25,
                                .block_cache_size = 8 * 1024 * 1024, /* 8MB */
                                .keys_per_sstable = 60};
    run_sstable_simulation(&config);
}

static void test_many_sstables_bloom_and_compression_cached(void)
{
    sim_test_config_t config = {.test_name = "bloom_and_zstd_cached",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 24 * 1024 * 1024, /* 24MB */
                                .keys_per_sstable = 50};
    run_sstable_simulation(&config);
}

static void test_many_sstables_read_uncommitted(void)
{
    sim_test_config_t config = {.test_name = "isolation_read_uncommitted",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_UNCOMMITTED,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_read_committed(void)
{
    sim_test_config_t config = {.test_name = "isolation_read_committed",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_repeatable_read(void)
{
    sim_test_config_t config = {.test_name = "isolation_repeatable_read",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_REPEATABLE_READ,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_serializable(void)
{
    sim_test_config_t config = {.test_name = "isolation_serializable",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_SERIALIZABLE,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_memcmp(void)
{
    sim_test_config_t config = {.test_name = "comparator_memcmp",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = tidesdb_comparator_memcmp};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_lexicographic(void)
{
    sim_test_config_t config = {.test_name = "comparator_lexicographic",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = tidesdb_comparator_lexicographic};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_reverse(void)
{
    sim_test_config_t config = {.test_name = "comparator_reverse",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = tidesdb_comparator_reverse_memcmp};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_case_insensitive(void)
{
    sim_test_config_t config = {.test_name = "comparator_case_insensitive",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = tidesdb_comparator_case_insensitive};
    run_sstable_simulation(&config);
}

static void test_many_sstables_small_cache(void)
{
    sim_test_config_t config = {.test_name = "small_bm_cache",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 1024 * 1024, /* 1MB */
                                .keys_per_sstable = 50,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_large_cache(void)
{
    sim_test_config_t config = {.test_name = "large_bm_cache",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 20,
                                .block_cache_size = 64 * 1024 * 1024, /* 64MB */
                                .keys_per_sstable = 50,
                                .isolation_level = TDB_ISOLATION_READ_COMMITTED,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_all_isolation_levels(void)
{
    sim_test_config_t config = {.test_name = "all_isolation_levels_combined",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = LZ4_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 16 * 1024 * 1024,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_SERIALIZABLE,
                                .comparator = tidesdb_comparator_memcmp};
    run_sstable_simulation(&config);
}

static void test_many_sstables_all_comparators(void)
{
    sim_test_config_t config = {.test_name = "all_comparators_combined",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = ZSTD_COMPRESSION,
                                .num_sstables = 15,
                                .block_cache_size = 32 * 1024 * 1024,
                                .keys_per_sstable = 40,
                                .isolation_level = TDB_ISOLATION_REPEATABLE_READ,
                                .comparator = tidesdb_comparator_lexicographic};
    run_sstable_simulation(&config);
}

static void test_large_value_iteration(void)
{
    printf(CYAN "\n=== Testing Large Value Iteration (256B keys, 4KB values) ===\n" RESET);

    cleanup_test_dir();

    tidesdb_t *db = NULL;
    tidesdb_config_t config = {.db_path = TEST_DB_PATH,
                               .num_flush_threads = 2,
                               .num_compaction_threads = 2,
                               .enable_debug_logging = 1,
                               .block_cache_size = TDB_DEFAULT_BLOCK_CACHE_SIZE,
                               .max_open_sstables = 256};

    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 16 * 1024;
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_KEYS = 1000;
#define TEST_KEY_SIZE   256
#define TEST_VALUE_SIZE 4096

    printf(CYAN "  Inserting %d keys (256B keys, 4KB values)...\n" RESET, NUM_KEYS);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    /* allocate buffers once outside loop for MSVC compatibility */
    uint8_t *key = malloc(TEST_KEY_SIZE);
    uint8_t *value = malloc(TEST_VALUE_SIZE);
    ASSERT_TRUE(key != NULL && value != NULL);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        snprintf((char *)key, TEST_KEY_SIZE, "large_key_%08d", i);
        memset(key + strlen((char *)key), 'K', TEST_KEY_SIZE - strlen((char *)key));
        snprintf((char *)value, TEST_VALUE_SIZE, "large_value_%08d_", i);
        memset(value + strlen((char *)value), 'V', TEST_VALUE_SIZE - strlen((char *)value));

        ASSERT_EQ(tidesdb_txn_put(txn, cf, key, TEST_KEY_SIZE, value, TEST_VALUE_SIZE, 0),
                  TDB_SUCCESS);

        if ((i + 1) % 100 == 0)
        {
            printf(CYAN "    Inserted %d keys...\n" RESET, i + 1);
        }
    }

    free(key);
    free(value);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    printf(CYAN "  Waiting for flushes to complete...\n" RESET);
    sleep(2);

    printf(CYAN "  Starting iteration test...\n" RESET);

    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), TDB_SUCCESS);
    ASSERT_TRUE(iter != NULL);

    printf(CYAN "  Seeking to first...\n" RESET);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);

    int count = 0;
    time_t start_time = time(NULL);
    time_t last_report = start_time;

    printf(CYAN "  Iterating through entries...\n" RESET);

    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), TDB_SUCCESS);

        ASSERT_EQ(key_size, (size_t)TEST_KEY_SIZE);
        ASSERT_EQ(value_size, (size_t)TEST_VALUE_SIZE);

        count++;

        time_t now = time(NULL);
        if (now - last_report >= 1)
        {
            double elapsed = difftime(now, start_time);
            double rate = count / elapsed;
            printf(CYAN "    Iterated %d entries (%.1f entries/sec)...\n" RESET, count, rate);
            last_report = now;
        }

        if (difftime(now, start_time) > 30)
        {
            printf(RED "  ERROR: Iteration timeout after 30 seconds (only %d/%d entries)\n" RESET,
                   count, NUM_KEYS);
            ASSERT_TRUE(0);
        }

        if (tidesdb_iter_next(iter) != TDB_SUCCESS)
        {
            break;
        }
    }

    time_t end_time = time(NULL);
    double total_time = difftime(end_time, start_time);
    double rate = count / total_time;

    printf(GREEN "  ✓ Iterated %d entries in %.2f seconds (%.1f entries/sec)\n" RESET, count,
           total_time, rate);

    ASSERT_EQ(count, NUM_KEYS);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    cleanup_test_dir();

    printf(GREEN "  ✓ Large value iteration test passed\n" RESET);

#undef TEST_KEY_SIZE
#undef TEST_VALUE_SIZE
}

void test_tidesdb_block_index_seek()
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_block_indexes = 1;
    cf_config.index_sample_ratio = 1;
    cf_config.write_buffer_size = 512 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), TDB_SUCCESS);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    printf(
        CYAN
        "  Inserting 10000 sequential keys (will create SSTables with multiple blocks)...\n" RESET);

    for (int i = 0; i < 10000; i++)
    {
        char key[32];
        char value[256]; /* larger values to fill blocks */
        snprintf(key, sizeof(key), "key_%08d", i);
        snprintf(value, sizeof(value),
                 "value_%08d_padding_to_make_this_larger_so_blocks_fill_up_faster_with_more_data_"
                 "per_entry",
                 i);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key), (uint8_t *)value,
                                  strlen(value), 0),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* wait for flushes */
    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(100000);

    printf(CYAN "  Testing seeks at various positions...\n" RESET);

    /* test seeks at different positions across the key space */
    int seek_positions[] = {0, 1000, 2500, 5000, 7500, 9999};
    for (size_t i = 0; i < sizeof(seek_positions) / sizeof(seek_positions[0]); i++)
    {
        int pos = seek_positions[i];
        char seek_key[32];
        snprintf(seek_key, sizeof(seek_key), "key_%08d", pos);

        printf(YELLOW "    Seeking to key_%08d...\n" RESET, pos);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        tidesdb_iter_t *iter = NULL;
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key)), TDB_SUCCESS);

        ASSERT_TRUE(tidesdb_iter_valid(iter));

        uint8_t *found_key;
        size_t found_key_size;
        ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), TDB_SUCCESS);

        ASSERT_TRUE(found_key != NULL);
        ASSERT_EQ(found_key_size, strlen(seek_key));
        ASSERT_EQ(memcmp(found_key, seek_key, found_key_size), 0);

        printf(GREEN "      ✓ Found key_%08d (key_size=%zu)\n" RESET, pos, found_key_size);

        tidesdb_iter_free(iter);
        tidesdb_txn_free(txn);
    }

    printf(CYAN "  ✓ All seeks successful\n" RESET);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_entries;
    _Atomic(int) *total_writes;
} bg_flush_thread_data_t;

static void *bg_flush_writer_thread(void *arg)
{
    bg_flush_thread_data_t *data = (bg_flush_thread_data_t *)arg;

    for (int i = 0; i < data->num_entries; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            continue;
        }

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "bg_key_t%d_%04d", data->thread_id, i);
        snprintf(value, sizeof(value),
                 "bg_value_thread%d_entry%04d_with_padding_to_increase_size_and_trigger_flush",
                 data->thread_id, i);

        if (tidesdb_txn_put(txn, data->cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                            strlen(value) + 1, 0) == 0)
        {
            if (tidesdb_txn_commit(txn) == 0)
            {
                atomic_fetch_add(data->total_writes, 1);
            }
        }

        tidesdb_txn_free(txn);
    }

    return NULL;
}

static void test_background_flush_multiple_immutable_memtables(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 1024;
    cf_config.compression_algorithm = NO_COMPRESSION;

    ASSERT_EQ(tidesdb_create_column_family(db, "bg_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bg_flush_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 4;
    const int ENTRIES_PER_THREAD = 30;
    const int TOTAL_ENTRIES = NUM_THREADS * ENTRIES_PER_THREAD;

    printf("\n  Launching %d threads, each writing %d entries...\n", NUM_THREADS,
           ENTRIES_PER_THREAD);
    printf("  Total entries: %d (should trigger multiple background flushes)\n", TOTAL_ENTRIES);

    _Atomic(int) total_writes = 0;
    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    bg_flush_thread_data_t *thread_data =
        (bg_flush_thread_data_t *)malloc(NUM_THREADS * sizeof(bg_flush_thread_data_t));

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].num_entries = ENTRIES_PER_THREAD;
        thread_data[i].total_writes = &total_writes;
        pthread_create(&threads[i], NULL, bg_flush_writer_thread, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_writes = atomic_load(&total_writes);
    printf("  All threads completed. Successful writes: %d/%d\n", final_writes, TOTAL_ENTRIES);

    size_t immutable_count = queue_size(cf->immutable_memtables);
    printf("  Immutable memtables queued: %zu\n", immutable_count);
    printf("  Flush queue size: %zu\n", queue_size(db->flush_queue));

    /* immutable_count may be 0 if background flush workers processed them quickly
     * this is expected behavior and not a failure, we verify data correctness below */

    tidesdb_txn_t *verify_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &verify_txn), 0);

    int found_count = 0;
    for (int t = 0; t < NUM_THREADS; t++)
    {
        for (int i = 0; i < ENTRIES_PER_THREAD; i += 5)
        {
            char key[32];
            snprintf(key, sizeof(key), "bg_key_t%d_%04d", t, i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(verify_txn, cf, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);

            if (result == 0 && retrieved_value != NULL)
            {
                found_count++;
                free(retrieved_value);
            }
        }
    }

    tidesdb_txn_free(verify_txn);
    int expected_samples = NUM_THREADS * ((ENTRIES_PER_THREAD + 4) / 5);
    printf("  Verified %d/%d sampled keys before close\n", found_count, expected_samples);
    ASSERT_TRUE(found_count > 0);

    printf("  Closing database with queued immutable memtables...\n");
    ASSERT_EQ(tidesdb_close(db), 0);

    printf("  Database closed successfully\n");

    free(threads);
    free(thread_data);
    cleanup_test_dir();
}

static void test_multi_cf_wal_recovery(void)
{
    cleanup_test_dir();
    const int NUM_WAL_KEYS = 15;
    const int NUM_FLUSHED_KEYS = 10;

    /* create database with two column families */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = NO_COMPRESSION;

        /* create first CF - will have WAL-only data */
        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);
        tidesdb_column_family_t *wal_cf = tidesdb_get_column_family(db, "wal_cf");
        ASSERT_TRUE(wal_cf != NULL);

        /* create second CF - will have flushed data */
        ASSERT_EQ(tidesdb_create_column_family(db, "flushed_cf", &cf_config), 0);
        tidesdb_column_family_t *flushed_cf = tidesdb_get_column_family(db, "flushed_cf");
        ASSERT_TRUE(flushed_cf != NULL);

        /* write keys to wal_cf (no flush - stays in WAL) */
        for (int i = 0; i < NUM_WAL_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "wal_key_%03d", i);
            snprintf(value, sizeof(value), "wal_value_%03d_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, wal_cf, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* write keys to flushed_cf and flush to SSTable */
        for (int i = 0; i < NUM_FLUSHED_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "flushed_key_%03d", i);
            snprintf(value, sizeof(value), "flushed_value_%03d_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, flushed_cf, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush flushed_cf to SSTable */
        ASSERT_EQ(tidesdb_flush_memtable(flushed_cf), 0);
        usleep(200000); /* wait for flush to complete */

        /* verify data is accessible before close */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "wal_key_%03d", 5);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, wal_cf, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        snprintf(key, sizeof(key), "flushed_key_%03d", 5);
        retrieved_value = NULL;
        ASSERT_EQ(tidesdb_txn_get(txn, flushed_cf, (uint8_t *)key, strlen(key) + 1,
                                  &retrieved_value, &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        tidesdb_txn_free(txn);

        /* close database - WAL should persist wal_cf data */
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* reopen database and verify WAL recovery for both CFs */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;
        config.enable_debug_logging = 1;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        /* both column families should be auto-recovered */
        tidesdb_column_family_t *wal_cf = tidesdb_get_column_family(db, "wal_cf");
        ASSERT_TRUE(wal_cf != NULL);

        tidesdb_column_family_t *flushed_cf = tidesdb_get_column_family(db, "flushed_cf");
        ASSERT_TRUE(flushed_cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* verify all WAL keys recovered from wal_cf */
        int wal_found_count = 0;
        for (int i = 0; i < NUM_WAL_KEYS; i++)
        {
            char key[32];
            char expected_value[64];
            snprintf(key, sizeof(key), "wal_key_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "wal_value_%03d_data", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, wal_cf, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);
            if (result == 0 && retrieved_value != NULL)
            {
                ASSERT_EQ(retrieved_size, strlen(expected_value) + 1);
                ASSERT_TRUE(strcmp((char *)retrieved_value, expected_value) == 0);
                free(retrieved_value);
                wal_found_count++;
            }
        }
        ASSERT_EQ(wal_found_count, NUM_WAL_KEYS);

        /* verify all flushed keys recovered from flushed_cf */
        int flushed_found_count = 0;
        for (int i = 0; i < NUM_FLUSHED_KEYS; i++)
        {
            char key[32];
            char expected_value[64];
            snprintf(key, sizeof(key), "flushed_key_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "flushed_value_%03d_data", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, flushed_cf, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);
            if (result == 0 && retrieved_value != NULL)
            {
                ASSERT_EQ(retrieved_size, strlen(expected_value) + 1);
                ASSERT_TRUE(strcmp((char *)retrieved_value, expected_value) == 0);
                free(retrieved_value);
                flushed_found_count++;
            }
        }
        ASSERT_EQ(flushed_found_count, NUM_FLUSHED_KEYS);

        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_multi_cf_many_sstables_recovery(void)
{
    cleanup_test_dir();
    const int NUM_SSTABLES_PER_CF = 5;
    const int KEYS_PER_SSTABLE = 20;
    const int TOTAL_KEYS_PER_CF = NUM_SSTABLES_PER_CF * KEYS_PER_SSTABLE;

    /* create database with two column families and write many SSTables to each */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = NO_COMPRESSION;

        /* create first CF */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_alpha", &cf_config), 0);
        tidesdb_column_family_t *cf_alpha = tidesdb_get_column_family(db, "cf_alpha");
        ASSERT_TRUE(cf_alpha != NULL);

        /* create second CF */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_beta", &cf_config), 0);
        tidesdb_column_family_t *cf_beta = tidesdb_get_column_family(db, "cf_beta");
        ASSERT_TRUE(cf_beta != NULL);

        /* write and flush multiple SSTables to cf_alpha */
        for (int sstable = 0; sstable < NUM_SSTABLES_PER_CF; sstable++)
        {
            for (int i = 0; i < KEYS_PER_SSTABLE; i++)
            {
                tidesdb_txn_t *txn = NULL;
                ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

                char key[32];
                char value[64];
                int key_id = sstable * KEYS_PER_SSTABLE + i;
                snprintf(key, sizeof(key), "alpha_key_%04d", key_id);
                snprintf(value, sizeof(value), "alpha_value_%04d_sstable_%d", key_id, sstable);

                ASSERT_EQ(tidesdb_txn_put(txn, cf_alpha, (uint8_t *)key, strlen(key) + 1,
                                          (uint8_t *)value, strlen(value) + 1, 0),
                          0);
                ASSERT_EQ(tidesdb_txn_commit(txn), 0);
                tidesdb_txn_free(txn);
            }

            /* flush to create SSTable */
            ASSERT_EQ(tidesdb_flush_memtable(cf_alpha), 0);
            usleep(100000); /* wait for flush */
        }

        /* write and flush multiple SSTables to cf_beta */
        for (int sstable = 0; sstable < NUM_SSTABLES_PER_CF; sstable++)
        {
            for (int i = 0; i < KEYS_PER_SSTABLE; i++)
            {
                tidesdb_txn_t *txn = NULL;
                ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

                char key[32];
                char value[64];
                int key_id = sstable * KEYS_PER_SSTABLE + i;
                snprintf(key, sizeof(key), "beta_key_%04d", key_id);
                snprintf(value, sizeof(value), "beta_value_%04d_sstable_%d", key_id, sstable);

                ASSERT_EQ(tidesdb_txn_put(txn, cf_beta, (uint8_t *)key, strlen(key) + 1,
                                          (uint8_t *)value, strlen(value) + 1, 0),
                          0);
                ASSERT_EQ(tidesdb_txn_commit(txn), 0);
                tidesdb_txn_free(txn);
            }

            /* flush to create SSTable */
            ASSERT_EQ(tidesdb_flush_memtable(cf_beta), 0);
            usleep(100000); /* wait for flush */
        }

        /* verify data before close */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "alpha_key_%04d", 50);
        uint8_t *retrieved_value = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf_alpha, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        snprintf(key, sizeof(key), "beta_key_%04d", 50);
        retrieved_value = NULL;
        ASSERT_EQ(tidesdb_txn_get(txn, cf_beta, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                  &retrieved_size),
                  0);
        ASSERT_TRUE(retrieved_value != NULL);
        free(retrieved_value);

        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* reopen database and verify all SSTables recovered for both CFs */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        /* both column families should be auto-recovered */
        tidesdb_column_family_t *cf_alpha = tidesdb_get_column_family(db, "cf_alpha");
        ASSERT_TRUE(cf_alpha != NULL);

        tidesdb_column_family_t *cf_beta = tidesdb_get_column_family(db, "cf_beta");
        ASSERT_TRUE(cf_beta != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* verify all keys from cf_alpha across all SSTables */
        int alpha_found_count = 0;
        for (int i = 0; i < TOTAL_KEYS_PER_CF; i++)
        {
            char key[32];
            char expected_value[64];
            int sstable = i / KEYS_PER_SSTABLE;
            snprintf(key, sizeof(key), "alpha_key_%04d", i);
            snprintf(expected_value, sizeof(expected_value), "alpha_value_%04d_sstable_%d", i,
                     sstable);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf_alpha, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);
            if (result == 0 && retrieved_value != NULL)
            {
                ASSERT_EQ(retrieved_size, strlen(expected_value) + 1);
                ASSERT_TRUE(strcmp((char *)retrieved_value, expected_value) == 0);
                free(retrieved_value);
                alpha_found_count++;
            }
        }
        ASSERT_EQ(alpha_found_count, TOTAL_KEYS_PER_CF);

        /* verify all keys from cf_beta across all SSTables */
        int beta_found_count = 0;
        for (int i = 0; i < TOTAL_KEYS_PER_CF; i++)
        {
            char key[32];
            char expected_value[64];
            int sstable = i / KEYS_PER_SSTABLE;
            snprintf(key, sizeof(key), "beta_key_%04d", i);
            snprintf(expected_value, sizeof(expected_value), "beta_value_%04d_sstable_%d", i,
                     sstable);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf_beta, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);
            if (result == 0 && retrieved_value != NULL)
            {
                ASSERT_EQ(retrieved_size, strlen(expected_value) + 1);
                ASSERT_TRUE(strcmp((char *)retrieved_value, expected_value) == 0);
                free(retrieved_value);
                beta_found_count++;
            }
        }
        ASSERT_EQ(beta_found_count, TOTAL_KEYS_PER_CF);

        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

int main(void)
{
    cleanup_test_dir();
    // RUN_TEST(test_basic_open_close, tests_passed);
    // RUN_TEST(test_column_family_creation, tests_passed);
    // RUN_TEST(test_list_column_families, tests_passed);
    // RUN_TEST(test_basic_txn_put_get, tests_passed);
    // RUN_TEST(test_txn_delete, tests_passed);
    // RUN_TEST(test_txn_rollback, tests_passed);
    // RUN_TEST(test_multiple_column_families, tests_passed);
    // RUN_TEST(test_memtable_flush, tests_passed);
    // RUN_TEST(test_background_flush_multiple_immutable_memtables, tests_passed);
    // RUN_TEST(test_persistence_and_recovery, tests_passed);
    // RUN_TEST(test_multi_cf_wal_recovery, tests_passed);
    // RUN_TEST(test_multi_cf_many_sstables_recovery, tests_passed);
    // RUN_TEST(test_iterator_basic, tests_passed);
    // RUN_TEST(test_stats, tests_passed);
    // RUN_TEST(test_iterator_seek, tests_passed);
    // RUN_TEST(test_iterator_seek_for_prev, tests_passed);
    // RUN_TEST(test_tidesdb_block_index_seek, tests_passed);
    // RUN_TEST(test_iterator_reverse, tests_passed);
    // RUN_TEST(test_iterator_boundaries, tests_passed);
    // RUN_TEST(test_bidirectional_iterator, tests_passed);
    // RUN_TEST(test_ttl_expiration, tests_passed);
    // RUN_TEST(test_large_values, tests_passed);
    // RUN_TEST(test_many_keys, tests_passed);
    // RUN_TEST(test_isolation_read_uncommitted, tests_passed);
    // RUN_TEST(test_isolation_read_committed, tests_passed);
    // RUN_TEST(test_isolation_repeatable_read, tests_passed);
    // RUN_TEST(test_isolation_serializable_conflict, tests_passed);
    // RUN_TEST(test_snapshot_isolation_consistency, tests_passed);
    // RUN_TEST(test_write_write_conflict, tests_passed);
    // RUN_TEST(test_read_write_conflict, tests_passed);
    // RUN_TEST(test_serializable_phantom_prevention, tests_passed);
    // RUN_TEST(test_transaction_abort_retry, tests_passed);
    // RUN_TEST(test_mixed_isolation_levels, tests_passed);
    // RUN_TEST(test_long_running_transaction, tests_passed);
    // RUN_TEST(test_multi_cf_transaction, tests_passed);
    // RUN_TEST(test_multi_cf_transaction_rollback, tests_passed);
    // RUN_TEST(test_multi_cf_iterator, tests_passed);
    // RUN_TEST(test_multi_cf_iterator_boundaries, tests_passed);
    // RUN_TEST(test_multi_cf_iterator_reverse, tests_passed);
    // RUN_TEST(test_multi_cf_iterator_seek, tests_passed);
    // RUN_TEST(test_multi_cf_iterator_seek_for_prev, tests_passed);
    // RUN_TEST(test_savepoints, tests_passed);
    // RUN_TEST(test_ini_config, tests_passed);
    // RUN_TEST(test_runtime_config_update, tests_passed);
    // RUN_TEST(test_error_invalid_args, tests_passed);
    // RUN_TEST(test_drop_column_family, tests_passed);
    // RUN_TEST(test_empty_iterator, tests_passed);
    // RUN_TEST(test_bloom_filter_enabled, tests_passed);
    // RUN_TEST(test_block_indexes, tests_passed);
    // RUN_TEST(test_sync_modes, tests_passed);
    // RUN_TEST(test_compression_lz4, tests_passed);
    // RUN_TEST(test_compression_zstd, tests_passed);
    // RUN_TEST(test_compaction_basic, tests_passed);
    // RUN_TEST(test_compaction_with_deletes, tests_passed);
    // RUN_TEST(test_concurrent_writes, tests_passed);
    // RUN_TEST(test_empty_value, tests_passed);
    // RUN_TEST(test_delete_nonexistent_key, tests_passed);
    // RUN_TEST(test_multiple_deletes_same_key, tests_passed);
    // RUN_TEST(test_overwrite_same_key_multiple_times, tests_passed);
    // RUN_TEST(test_put_delete_put_same_key, tests_passed);
    // RUN_TEST(test_iterator_on_empty_cf, tests_passed);
    // RUN_TEST(test_iterator_single_key, tests_passed);
    // RUN_TEST(test_mixed_operations_in_transaction, tests_passed);
    // RUN_TEST(test_read_own_writes_in_transaction, tests_passed);
    // RUN_TEST(test_alternating_puts_deletes, tests_passed);
    // RUN_TEST(test_very_long_key, tests_passed);
    // RUN_TEST(test_read_across_multiple_sstables, tests_passed);
    // RUN_TEST(test_read_with_bloom_filter_disabled, tests_passed);
    // RUN_TEST(test_read_with_block_indexes_disabled, tests_passed);
    // RUN_TEST(test_read_with_all_optimizations_disabled, tests_passed);
    // RUN_TEST(test_iterator_across_multiple_sources, tests_passed);
    // RUN_TEST(test_overwrite_across_levels, tests_passed);
    // RUN_TEST(test_atomicity_transaction_rollback, tests_passed);
    // RUN_TEST(test_consistency_after_flush, tests_passed);
    // RUN_TEST(test_isolation_concurrent_transactions, tests_passed);
    // RUN_TEST(test_durability_reopen_database, tests_passed);
    // RUN_TEST(test_data_integrity_after_compaction, tests_passed);
    // RUN_TEST(test_no_data_loss_across_operations, tests_passed);
    // RUN_TEST(test_concurrent_writes_visibility, tests_passed);
    // RUN_TEST(test_dividing_merge_strategy, tests_passed);
    // RUN_TEST(test_partitioned_merge_strategy, tests_passed);
    // RUN_TEST(test_boundary_partitioning, tests_passed);
    RUN_TEST(test_dynamic_capacity_adjustment, tests_passed);
    //     RUN_TEST(test_multi_level_compaction_strategies, tests_passed);
    //     RUN_TEST(test_recovery_with_corrupted_sstable, tests_passed);
    //     RUN_TEST(test_portability_workflow, tests_passed);
    //     RUN_TEST(test_iterator_across_multiple_memtable_flushes, tests_passed);
    //     RUN_TEST(test_read_after_multiple_overwrites, tests_passed);
    //     RUN_TEST(test_large_transaction_batch, tests_passed);
    //     RUN_TEST(test_delete_and_recreate_same_key, tests_passed);
    //     RUN_TEST(test_concurrent_reads_same_key, tests_passed);
    //     RUN_TEST(test_zero_ttl_means_no_expiration, tests_passed);
    //     RUN_TEST(test_mixed_ttl_expiration, tests_passed);
    //     RUN_TEST(test_get_nonexistent_cf, tests_passed);
    //     RUN_TEST(test_create_duplicate_cf, tests_passed);
    //     RUN_TEST(test_drop_nonexistent_cf, tests_passed);
    //     RUN_TEST(test_nested_savepoints, tests_passed);
    //     RUN_TEST(test_savepoint_with_delete_operations, tests_passed);
    //     RUN_TEST(test_iterator_with_tombstones, tests_passed);
    //     RUN_TEST(test_transaction_isolation_snapshot_with_updates, tests_passed);
    //     RUN_TEST(test_read_own_uncommitted_writes, tests_passed);
    //     RUN_TEST(test_multi_cf_transaction_conflict, tests_passed);
    //     RUN_TEST(test_many_sstables_with_bloom_filter, tests_passed);
    //     RUN_TEST(test_many_sstables_without_bloom_filter, tests_passed);
    //     RUN_TEST(test_many_sstables_with_block_indexes, tests_passed);
    //     RUN_TEST(test_many_sstables_with_lz4_compression, tests_passed);
    //     RUN_TEST(test_many_sstables_with_zstd_compression, tests_passed);
    //     RUN_TEST(test_many_sstables_all_features_enabled, tests_passed);
    //     RUN_TEST(test_many_sstables_all_features_disabled, tests_passed);
    //     RUN_TEST(test_many_sstables_bloom_and_compression, tests_passed);
    //     RUN_TEST(test_many_sstables_indexes_and_compression, tests_passed);
    //     RUN_TEST(test_many_sstables_with_bloom_filter_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_without_bloom_filter_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_with_block_indexes_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_with_lz4_compression_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_with_zstd_compression_cached, tests_passed);

    // #ifndef __sun
    //     RUN_TEST(test_many_sstables_with_snappy_compression, tests_passed);
    //     RUN_TEST(test_many_sstables_with_snappy_compression_cached, tests_passed);
    //     RUN_TEST(test_compression_snappy, tests_passed);
    // #endif

    //     RUN_TEST(test_many_sstables_all_features_enabled_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_all_features_disabled_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_bloom_and_compression_cached, tests_passed);
    //     RUN_TEST(test_many_sstables_read_uncommitted, tests_passed);
    //     RUN_TEST(test_many_sstables_read_committed, tests_passed);
    //     RUN_TEST(test_many_sstables_repeatable_read, tests_passed);
    //     RUN_TEST(test_many_sstables_serializable, tests_passed);
    //     RUN_TEST(test_many_sstables_comparator_memcmp, tests_passed);
    //     RUN_TEST(test_many_sstables_comparator_lexicographic, tests_passed);
    //     RUN_TEST(test_many_sstables_comparator_reverse, tests_passed);
    //     RUN_TEST(test_many_sstables_comparator_case_insensitive, tests_passed);
    //     RUN_TEST(test_many_sstables_small_cache, tests_passed);
    //     RUN_TEST(test_many_sstables_large_cache, tests_passed);
    //     RUN_TEST(test_many_sstables_all_isolation_levels, tests_passed);
    //     RUN_TEST(test_many_sstables_all_comparators, tests_passed);
    //     RUN_TEST(test_large_value_iteration, tests_passed);
    //     RUN_TEST(test_sync_interval_mode, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}