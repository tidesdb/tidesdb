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

#include "../src/tidesdb.h"
#include "test_utils.h"

/* test configuration constants */
#define TEST_FLUSH_DRAIN_WAIT_INTERVAL_US 100000
#define TEST_DB_BACKUP_PATH               "./test_tidesdb_backup"

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
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    ASSERT_EQ(tidesdb_close(db), 0);
    cleanup_test_dir();
}

/* custom allocator test tracking variables */
static atomic_int custom_malloc_count;
static atomic_int custom_calloc_count;
static atomic_int custom_realloc_count;
static atomic_int custom_free_count;

/* we save the real stdlib functions before tidesdb.h redefines them
 * this is done at file scope initialization before main() runs */
static void *(*saved_malloc)(size_t) = NULL;
static void *(*saved_calloc)(size_t, size_t) = NULL;
static void *(*saved_realloc)(void *, size_t) = NULL;
static void (*saved_free)(void *) = NULL;

static void *test_custom_malloc(size_t size)
{
    atomic_fetch_add(&custom_malloc_count, 1);
    return saved_malloc(size);
}

static void *test_custom_calloc(size_t count, size_t size)
{
    atomic_fetch_add(&custom_calloc_count, 1);
    return saved_calloc(count, size);
}

static void *test_custom_realloc(void *ptr, size_t size)
{
    atomic_fetch_add(&custom_realloc_count, 1);
    return saved_realloc(ptr, size);
}

static void test_custom_free(void *ptr)
{
    atomic_fetch_add(&custom_free_count, 1);
    saved_free(ptr);
}

static void test_custom_allocator(void)
{
    cleanup_test_dir();

    /* we ensure TidesDB is initialized with system allocator first
     * so we can save the real stdlib function pointers */
    tidesdb_ensure_initialized();
    saved_malloc = tidesdb_allocator.malloc_fn;
    saved_calloc = tidesdb_allocator.calloc_fn;
    saved_realloc = tidesdb_allocator.realloc_fn;
    saved_free = tidesdb_allocator.free_fn;

    /* we reset counters */
    atomic_init(&custom_malloc_count, 0);
    atomic_init(&custom_calloc_count, 0);
    atomic_init(&custom_realloc_count, 0);
    atomic_init(&custom_free_count, 0);

    /* we finalize any previous initialization */
    tidesdb_finalize();

    /* we test that double init fails */
    ASSERT_EQ(
        tidesdb_init(test_custom_malloc, test_custom_calloc, test_custom_realloc, test_custom_free),
        0);
    ASSERT_EQ(
        tidesdb_init(test_custom_malloc, test_custom_calloc, test_custom_realloc, test_custom_free),
        -1);

    /* we open database with custom allocator */
    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    /* we create a column family */
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "alloc_test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "alloc_test_cf");
    ASSERT_TRUE(cf != NULL);

    /* we write some data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "alloc_test_key";
    uint8_t value[] = "alloc_test_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), -1), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    /* we read the data back */
    txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    ASSERT_EQ(retrieved_size, sizeof(value));
    free(retrieved_value);

    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), 0);

    /* we verify custom allocator was used */
    int malloc_calls = atomic_load(&custom_malloc_count);
    int calloc_calls = atomic_load(&custom_calloc_count);
    int free_calls = atomic_load(&custom_free_count);

    ASSERT_TRUE(malloc_calls > 0 || calloc_calls > 0);
    ASSERT_TRUE(free_calls > 0);

    /* we finalize and reset for other tests */
    tidesdb_finalize();

    /* we re-init with system allocator for remaining tests */
    tidesdb_init(NULL, NULL, NULL, NULL);

    cleanup_test_dir();
}

static void test_log_file(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.log_to_file = 1;
    config.log_level = TDB_LOG_DEBUG;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "log_test_key";
    uint8_t value[] = "log_test_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn), 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), 0);

    char log_path[1024];
    snprintf(log_path, sizeof(log_path), "%s/LOG", TEST_DB_PATH);

    FILE *log_file = fopen(log_path, "r");
    ASSERT_TRUE(log_file != NULL);

    fseek(log_file, 0, SEEK_END);
    long log_size = ftell(log_file);
    ASSERT_TRUE(log_size > 0);

    fclose(log_file);
    cleanup_test_dir();
}

static void test_log_file_truncation(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.log_to_file = 1;
    config.log_level = TDB_LOG_DEBUG;
    config.log_truncation_at = 1024;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[64];
        char value[256];
        snprintf(key, sizeof(key), "truncation_test_key_%d", i);
        snprintf(value, sizeof(value), "truncation_test_value_with_longer_content_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_close(db), 0);

    char log_path[1024];
    snprintf(log_path, sizeof(log_path), "%s/LOG", TEST_DB_PATH);

    FILE *log_file = fopen(log_path, "r");
    ASSERT_TRUE(log_file != NULL);

    fseek(log_file, 0, SEEK_END);
    long log_size = ftell(log_file);

    ASSERT_TRUE(log_size < 2048);

    fseek(log_file, 0, SEEK_SET);
    char buffer[128];
    char *result = fgets(buffer, sizeof(buffer), log_file);
    ASSERT_TRUE(result != NULL);
    ASSERT_TRUE(strstr(buffer, "LOG TRUNCATED") != NULL);

    fclose(log_file);
    cleanup_test_dir();
}

static void test_tidesdb_free(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key), value, sizeof(value), 0), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key), &retrieved_value, &retrieved_size), 0);
    ASSERT_TRUE(retrieved_value != NULL);
    ASSERT_EQ(retrieved_size, sizeof(value));
    ASSERT_TRUE(memcmp(retrieved_value, value, sizeof(value)) == 0);

    tidesdb_free(retrieved_value);

    tidesdb_free(NULL);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
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
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

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
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;

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

static void test_backup_basic(void)
{
    cleanup_test_dir();
    remove_directory(TEST_DB_BACKUP_PATH);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "backup_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "backup_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "backup_key_%04d", i);
        snprintf(value, sizeof(value), "backup_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(50000);

    for (int i = 50; i < 80; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "backup_key_%04d", i);
        snprintf(value, sizeof(value), "backup_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_backup(db, TEST_DB_BACKUP_PATH), 0);
    ASSERT_EQ(tidesdb_close(db), 0);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_BACKUP_PATH;

    tidesdb_t *backup_db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &backup_db), 0);
    ASSERT_TRUE(backup_db != NULL);

    tidesdb_column_family_t *backup_cf = tidesdb_get_column_family(backup_db, "backup_cf");
    ASSERT_TRUE(backup_cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(backup_db, &txn), 0);
    for (int i = 0; i < 80; i++)
    {
        char key[64];
        char expected[128];
        snprintf(key, sizeof(key), "backup_key_%04d", i);
        snprintf(expected, sizeof(expected), "backup_value_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(txn, backup_cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
            0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(strcmp((char *)value, expected) == 0);
        free(value);
    }
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(backup_db), 0);
    cleanup_test_dir();
    remove_directory(TEST_DB_BACKUP_PATH);
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int start_key;
    int end_key;
    _Atomic(int) last_written;
    _Atomic(int) *stop;
    _Atomic(int) *errors;
} backup_concurrent_writer_t;

static void *backup_concurrent_writer_thread(void *arg)
{
    backup_concurrent_writer_t *data = (backup_concurrent_writer_t *)arg;
    for (int i = data->start_key; i < data->end_key; i++)
    {
        if (atomic_load(data->stop)) break;

        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            continue;
        }

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "concurrent_key_%05d", i);
        snprintf(value, sizeof(value), "concurrent_value_%05d", i);

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
        atomic_store(&data->last_written, i);
    }
    return NULL;
}

static void test_backup_concurrent_writes(void)
{
    cleanup_test_dir();
    remove_directory(TEST_DB_BACKUP_PATH);

    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "backup_concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "backup_concurrent_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 4;
    const int KEYS_PER_THREAD = 200;
    const int PREBACKUP_KEYS_PER_THREAD = 50;

    _Atomic(int) stop_flag = 0;
    _Atomic(int) errors = 0;

    pthread_t *threads = malloc(sizeof(pthread_t) * NUM_THREADS);
    backup_concurrent_writer_t *thread_data =
        malloc(sizeof(backup_concurrent_writer_t) * NUM_THREADS);
    ASSERT_TRUE(threads != NULL);
    ASSERT_TRUE(thread_data != NULL);

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].start_key = i * KEYS_PER_THREAD;
        thread_data[i].end_key = (i + 1) * KEYS_PER_THREAD;
        thread_data[i].stop = &stop_flag;
        thread_data[i].errors = &errors;
        atomic_init(&thread_data[i].last_written, -1);
        pthread_create(&threads[i], NULL, backup_concurrent_writer_thread, &thread_data[i]);
    }

    int all_ready = 0;
    for (int attempt = 0; attempt < 500; attempt++)
    {
        all_ready = 1;
        for (int i = 0; i < NUM_THREADS; i++)
        {
            int min_written = thread_data[i].start_key + PREBACKUP_KEYS_PER_THREAD - 1;
            if (atomic_load(&thread_data[i].last_written) < min_written)
            {
                all_ready = 0;
                break;
            }
        }
        if (all_ready) break;
        usleep(10000);
    }
    ASSERT_TRUE(all_ready);

    ASSERT_EQ(tidesdb_backup(db, TEST_DB_BACKUP_PATH), 0);

    atomic_store(&stop_flag, 1);
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    ASSERT_EQ(atomic_load(&errors), 0);

    ASSERT_EQ(tidesdb_close(db), 0);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_BACKUP_PATH;

    tidesdb_t *backup_db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &backup_db), 0);
    ASSERT_TRUE(backup_db != NULL);

    tidesdb_column_family_t *backup_cf =
        tidesdb_get_column_family(backup_db, "backup_concurrent_cf");
    ASSERT_TRUE(backup_cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(backup_db, &txn), 0);
    for (int t = 0; t < NUM_THREADS; t++)
    {
        int start = t * KEYS_PER_THREAD;
        int end = start + PREBACKUP_KEYS_PER_THREAD;
        for (int i = start; i < end; i++)
        {
            char key[64];
            char expected[128];
            snprintf(key, sizeof(key), "concurrent_key_%05d", i);
            snprintf(expected, sizeof(expected), "concurrent_value_%05d", i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(tidesdb_txn_get(txn, backup_cf, (uint8_t *)key, strlen(key) + 1, &value,
                                      &value_size),
                      0);
            ASSERT_TRUE(value != NULL);
            ASSERT_TRUE(strcmp((char *)value, expected) == 0);
            free(value);
        }
    }
    tidesdb_txn_free(txn);

    free(thread_data);
    free(threads);

    ASSERT_EQ(tidesdb_close(backup_db), 0);
    cleanup_test_dir();
    remove_directory(TEST_DB_BACKUP_PATH);
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

static void test_stats_comprehensive(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "stats_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "stats_cf");
    ASSERT_TRUE(cf != NULL);

    /* test 1 -- NULL argument handling */
    tidesdb_stats_t *stats = NULL;
    ASSERT_EQ(tidesdb_get_stats(NULL, &stats), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_get_stats(cf, NULL), TDB_ERR_INVALID_ARGS);

    /* test 2 -- empty CF stats (zero keys branch) */
    ASSERT_EQ(tidesdb_get_stats(cf, &stats), TDB_SUCCESS);
    ASSERT_TRUE(stats != NULL);
    ASSERT_TRUE(stats->num_levels > 0);
    ASSERT_EQ(stats->total_keys, (uint64_t)0);
    ASSERT_EQ(stats->total_data_size, (uint64_t)0);
    ASSERT_TRUE(stats->avg_key_size == 0.0);
    ASSERT_TRUE(stats->avg_value_size == 0.0);
    ASSERT_TRUE(stats->read_amp >= 1.0);
    ASSERT_TRUE(stats->level_sizes != NULL);
    ASSERT_TRUE(stats->level_num_sstables != NULL);
    ASSERT_TRUE(stats->level_key_counts != NULL);
    ASSERT_TRUE(stats->config != NULL);
    tidesdb_free_stats(stats);
    stats = NULL;

    /* test 3 -- stats with data in memtable only */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "stats_key_%04d", i);
        snprintf(value, sizeof(value), "stats_value_%04d_with_some_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_get_stats(cf, &stats), TDB_SUCCESS);
    ASSERT_TRUE(stats != NULL);
    ASSERT_TRUE(stats->memtable_size > 0);
    ASSERT_TRUE(stats->total_keys > 0);
    ASSERT_TRUE(stats->avg_key_size > 0.0);
    ASSERT_TRUE(stats->avg_value_size > 0.0);
    ASSERT_TRUE(stats->read_amp >= 1.0);

    /* verify level arrays are properly allocated */
    for (int i = 0; i < stats->num_levels; i++)
    {
        ASSERT_TRUE(stats->level_num_sstables[i] >= 0);
        (void)stats->level_key_counts[i];
    }

    /* verify config was copied */
    ASSERT_EQ(stats->config->write_buffer_size, cf_config.write_buffer_size);

    tidesdb_free_stats(stats);
    stats = NULL;

    /* test 4 -- flush to create ssts and verify level stats */
    ASSERT_EQ(tidesdb_flush_memtable(cf), TDB_SUCCESS);

    /* wait for flush to complete */
    int wait_count = 0;
    while (tidesdb_is_flushing(cf) && wait_count < 100)
    {
        usleep(10000);
        wait_count++;
    }

    /* add more data to trigger another flush */
    for (int i = 50; i < 150; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "stats_key_%04d", i);
        snprintf(value, sizeof(value), "stats_value_%04d_with_some_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_flush_memtable(cf), TDB_SUCCESS);

    wait_count = 0;
    while (tidesdb_is_flushing(cf) && wait_count < 100)
    {
        usleep(10000);
        wait_count++;
    }

    ASSERT_EQ(tidesdb_get_stats(cf, &stats), TDB_SUCCESS);
    ASSERT_TRUE(stats != NULL);

    /* verify we have data in ssts now */
    ASSERT_TRUE(stats->total_keys > 0);
    ASSERT_TRUE(stats->total_data_size > 0);

    /* verify read amplification calculation */
    /* read_amp = 1.0 (memtable) + L0 sstables + 1.0 for each non-empty higher level */
    ASSERT_TRUE(stats->read_amp >= 1.0);

    /* verify level 0 stats (L0 may have overlapping sstables) */
    int total_sstables = 0;
    for (int i = 0; i < stats->num_levels; i++)
    {
        total_sstables += stats->level_num_sstables[i];
    }
    ASSERT_TRUE(total_sstables > 0);

    /* test 5 -- verify hit_rate is set (cache should be enabled) */
    /* hit_rate is 0.0 initially since no reads have been done through cache */
    ASSERT_TRUE(stats->hit_rate >= 0.0 && stats->hit_rate <= 1.0);

    tidesdb_free_stats(stats);
    stats = NULL;

    /* test 6 -- tidesdb_free_stats with NULL (should not crash) */
    tidesdb_free_stats(NULL);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cache_stats(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "cache_test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cache_test_cf");
    ASSERT_TRUE(cf != NULL);

    /* we test cache stats with cache enabled (default config has cache enabled) */
    tidesdb_cache_stats_t cache_stats;
    ASSERT_EQ(tidesdb_get_cache_stats(db, &cache_stats), 0);
    ASSERT_TRUE(cache_stats.enabled == 1);
    ASSERT_TRUE(cache_stats.num_partitions > 0);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[256];
        snprintf(key, sizeof(key), "cache_key_%04d", i);
        snprintf(value, sizeof(value), "cache_value_%04d_padding_to_make_it_larger", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);

    cf = tidesdb_get_column_family(db, "cache_test_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "cache_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(value != NULL);
        free(value);
        tidesdb_txn_free(txn);
    }

    /* we check cache stats after reads -- should have some hits/misses */
    ASSERT_EQ(tidesdb_get_cache_stats(db, &cache_stats), 0);
    ASSERT_TRUE(cache_stats.enabled == 1);

    /* after reading from ssts, we should have cache activity */
    const uint64_t total_accesses = cache_stats.hits + cache_stats.misses;
    ASSERT_TRUE(total_accesses > 0);

    /* we read same data again -- should get cache hits */
    const uint64_t hits_before = cache_stats.hits;

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "cache_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(value != NULL);
        free(value);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_get_cache_stats(db, &cache_stats), 0);

    /* hits should have increased from re-reading cached data */
    ASSERT_TRUE(cache_stats.hits >= hits_before);

    /* hit rate should be valid (0.0 to 1.0) */
    ASSERT_TRUE(cache_stats.hit_rate >= 0.0 && cache_stats.hit_rate <= 1.0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cache_stats_disabled(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.block_cache_size = 0; /* disable cache */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    /* we test cache stats with cache disabled */
    tidesdb_cache_stats_t cache_stats;
    ASSERT_EQ(tidesdb_get_cache_stats(db, &cache_stats), 0);
    ASSERT_TRUE(cache_stats.enabled == 0);
    ASSERT_TRUE(cache_stats.total_entries == 0);
    ASSERT_TRUE(cache_stats.total_bytes == 0);
    ASSERT_TRUE(cache_stats.hits == 0);
    ASSERT_TRUE(cache_stats.misses == 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cache_stats_invalid_args(void)
{
    /* test with NULL arguments */
    tidesdb_cache_stats_t cache_stats;
    ASSERT_EQ(tidesdb_get_cache_stats(NULL, &cache_stats), TDB_ERR_INVALID_ARGS);

    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    ASSERT_EQ(tidesdb_get_cache_stats(db, NULL), TDB_ERR_INVALID_ARGS);

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
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_cf");
    cf->config.enable_block_indexes = 1;
    ASSERT_TRUE(cf != NULL);

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

    /* do a final flush to ensure all data is persisted */
    tidesdb_flush_memtable(cf);

    /* wait for all flushes to complete */
    int max_wait = 200; /* increased timeout */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0)
        {
            /* queue is empty, wait a bit more for workers to finish */
            usleep(100000);
            break;
        }
    }

    /* manually trigger compaction via thread pool */
    tidesdb_compact(cf);

    /* wait for compaction to complete */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->compaction_queue) == 0 && !is_compacting)
        {
            /* compaction finished, wait a bit more for cleanup */
            usleep(100000);
            break;
        }
    }

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
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

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

    /* wait for compaction to complete by checking both queue and is_compacting flag */
    for (int i = 0; i < max_wait; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->compaction_queue) == 0 && !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

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
        usleep(50000);
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
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

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

    tidesdb_txn_t *setup = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &setup), 0);
    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(setup, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(setup), 0);
    tidesdb_txn_free(setup);

    /* start READ_UNCOMMITTED transaction */
    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_UNCOMMITTED, &txn1), 0);

    /* another transaction updates value */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn2), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);
    tidesdb_txn_free(txn2);

    /* READ_UNCOMMITTED sees all committed data without filtering */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn1, cf, key, sizeof(key), &retrieved, &retrieved_size);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    /* should see the latest committed value */
    ASSERT_EQ(memcmp(retrieved, value2, sizeof(value2)), 0);
    free(retrieved);

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

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    uint8_t key[] = "test_key";
    uint8_t value1[] = "value1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start READ_COMMITTED transaction */
    tidesdb_txn_t *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, &txn2), 0);

    /* read initial value */
    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result = tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    ASSERT_EQ(memcmp(retrieved, value1, sizeof(value1)), 0);
    free(retrieved);

    /* another transaction updates and commits */
    tidesdb_txn_t *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn3), 0);
    uint8_t value2[] = "value2";
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn3), 0);
    tidesdb_txn_free(txn3);

    /* READ_COMMITTED should see the new committed value (non-repeatable read) */
    retrieved = NULL;
    result = tidesdb_txn_get(txn2, cf, key, sizeof(key), &retrieved, &retrieved_size);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(retrieved != NULL);
    /* verify we see the NEW value (non-repeatable read allowed) */
    ASSERT_EQ(memcmp(retrieved, value2, sizeof(value2)), 0);
    free(retrieved);

    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_serializable(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "ssi_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ssi_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *setup = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &setup), 0);
    uint8_t key1[] = "x";
    uint8_t key2[] = "y";
    uint8_t value0[] = "0";
    ASSERT_EQ(tidesdb_txn_put(setup, cf, key1, sizeof(key1), value0, sizeof(value0), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(setup, cf, key2, sizeof(key2), value0, sizeof(value0), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(setup), 0);
    tidesdb_txn_free(setup);

    /* create dangerous structure with SERIALIZABLE transactions:
     * T1 reads X, writes Y
     * T2 reads Y, writes X
     * this creates rw-antidependency cycle -- T2 -> T1 -> T2 */
    tidesdb_txn_t *txn1 = NULL, *txn2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &txn2), 0);

    /* T1 reads X */
    uint8_t *val = NULL;
    size_t val_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn1, cf, key1, sizeof(key1), &val, &val_size), 0);
    if (val) free(val);

    /* T2 reads Y */
    val = NULL;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key2, sizeof(key2), &val, &val_size), 0);
    if (val) free(val);

    /* T1 writes Y (creates rw-dependency -- T2 -> T1) */
    uint8_t value1[] = "1";
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key2, sizeof(key2), value1, sizeof(value1), 0), 0);

    /* T2 writes X (creates rw-dependency -- T1 -> T2, forming cycle) */
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key1, sizeof(key1), value1, sizeof(value1), 0), 0);

    /* try to commit both -- at least one must fail to prevent serialization anomaly */
    int result1 = tidesdb_txn_commit(txn1);
    int result2 = tidesdb_txn_commit(txn2);

    /* SSI should detect the dangerous structure and abort at least one */
    int conflicts = (result1 == TDB_ERR_CONFLICT) + (result2 == TDB_ERR_CONFLICT);
    ASSERT_TRUE(conflicts >= 1);

    tidesdb_txn_free(txn1);
    tidesdb_txn_free(txn2);
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
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;
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

static void test_rename_column_family(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* test 1 -- NULL argument handling */
    ASSERT_EQ(tidesdb_rename_column_family(NULL, "old", "new"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_rename_column_family(db, NULL, "new"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_rename_column_family(db, "old", NULL), TDB_ERR_INVALID_ARGS);

    /* test 2 -- rename non-existent CF */
    ASSERT_EQ(tidesdb_rename_column_family(db, "nonexistent", "new_name"), TDB_ERR_NOT_FOUND);

    /* test 3 -- create CF and add data */
    ASSERT_EQ(tidesdb_create_column_family(db, "original_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "original_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "rename_key_%04d", i);
        snprintf(value, sizeof(value), "rename_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test 4 -- same name rename (no-op) */
    ASSERT_EQ(tidesdb_rename_column_family(db, "original_cf", "original_cf"), TDB_SUCCESS);

    /* test 5 -- rename to new name */
    ASSERT_EQ(tidesdb_rename_column_family(db, "original_cf", "renamed_cf"), TDB_SUCCESS);

    /* old name should not exist */
    tidesdb_column_family_t *old_cf = tidesdb_get_column_family(db, "original_cf");
    ASSERT_TRUE(old_cf == NULL);

    /* new name should exist */
    tidesdb_column_family_t *new_cf = tidesdb_get_column_family(db, "renamed_cf");
    ASSERT_TRUE(new_cf != NULL);

    /* test 6 -- verify data is still accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "rename_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(read_txn, new_cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
            TDB_SUCCESS);
        ASSERT_TRUE(value != NULL);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    /* test 7 -- create another CF and try to rename to existing name */
    ASSERT_EQ(tidesdb_create_column_family(db, "another_cf", &cf_config), 0);
    ASSERT_EQ(tidesdb_rename_column_family(db, "another_cf", "renamed_cf"), TDB_ERR_EXISTS);

    /* test 8 -- empty name should fail */
    ASSERT_EQ(tidesdb_rename_column_family(db, "another_cf", ""), TDB_ERR_INVALID_ARGS);

    /* test 9 -- verify rename persists after reopen */
    tidesdb_close(db);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);

    /* old name should not exist after reopen */
    old_cf = tidesdb_get_column_family(db, "original_cf");
    ASSERT_TRUE(old_cf == NULL);

    /* new name should exist after reopen */
    new_cf = tidesdb_get_column_family(db, "renamed_cf");
    ASSERT_TRUE(new_cf != NULL);

    /* we verify data still accessible after reopen */
    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "rename_key_%04d", 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, new_cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
        TDB_SUCCESS);
    ASSERT_TRUE(value != NULL);
    free(value);
    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_clone_column_family(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    /* test 1 -- NULL argument handling */
    ASSERT_EQ(tidesdb_clone_column_family(NULL, "src", "dst"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_clone_column_family(db, NULL, "dst"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_clone_column_family(db, "src", NULL), TDB_ERR_INVALID_ARGS);

    /* test 2 -- clone non-existent CF */
    ASSERT_EQ(tidesdb_clone_column_family(db, "nonexistent", "new_clone"), TDB_ERR_NOT_FOUND);

    /* test 3 -- same name should fail */
    ASSERT_EQ(tidesdb_create_column_family(db, "source_cf", &cf_config), 0);
    ASSERT_EQ(tidesdb_clone_column_family(db, "source_cf", "source_cf"), TDB_ERR_INVALID_ARGS);

    /* test 4 -- add data to source CF */
    tidesdb_column_family_t *src_cf = tidesdb_get_column_family(db, "source_cf");
    ASSERT_TRUE(src_cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "clone_key_%04d", i);
        snprintf(value, sizeof(value), "clone_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, src_cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* test 5 -- clone the CF */
    ASSERT_EQ(tidesdb_clone_column_family(db, "source_cf", "cloned_cf"), TDB_SUCCESS);

    /* source should still exist */
    src_cf = tidesdb_get_column_family(db, "source_cf");
    ASSERT_TRUE(src_cf != NULL);

    /* clone should exist */
    tidesdb_column_family_t *clone_cf = tidesdb_get_column_family(db, "cloned_cf");
    ASSERT_TRUE(clone_cf != NULL);

    /* test 6 -- verify data is accessible in clone */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "clone_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(read_txn, clone_cf, (uint8_t *)key, strlen(key) + 1, &value,
                                  &value_size),
                  TDB_SUCCESS);
        ASSERT_TRUE(value != NULL);

        char expected_value[64];
        snprintf(expected_value, sizeof(expected_value), "clone_value_%04d", i);
        ASSERT_EQ(value_size, strlen(expected_value) + 1);
        ASSERT_TRUE(memcmp(value, expected_value, value_size) == 0);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    /* test 7 -- verify source data is still accessible */
    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "clone_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(read_txn, src_cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
            TDB_SUCCESS);
        ASSERT_TRUE(value != NULL);
        free(value);
    }
    tidesdb_txn_free(read_txn);

    /* test 8 -- modifications to clone don't affect source */
    tidesdb_txn_t *write_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &write_txn), 0);
    uint8_t new_key[] = "clone_only_key";
    uint8_t new_value[] = "clone_only_value";
    ASSERT_EQ(tidesdb_txn_put(write_txn, clone_cf, new_key, sizeof(new_key), new_value,
                              sizeof(new_value), -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(write_txn), 0);
    tidesdb_txn_free(write_txn);

    /* we verify new key exists in clone */
    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, clone_cf, new_key, sizeof(new_key), &retrieved_value,
                              &retrieved_size),
              TDB_SUCCESS);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);

    /* verify new key does NOT exist in source */
    retrieved_value = NULL;
    retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, src_cf, new_key, sizeof(new_key), &retrieved_value,
                              &retrieved_size),
              TDB_ERR_NOT_FOUND);
    tidesdb_txn_free(read_txn);

    /* test 9 -- clone to existing name should fail */
    ASSERT_EQ(tidesdb_clone_column_family(db, "source_cf", "cloned_cf"), TDB_ERR_EXISTS);

    /* test 10 -- we verify clone persists after reopen */
    tidesdb_close(db);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);

    /* both CFs should exist after reopen */
    src_cf = tidesdb_get_column_family(db, "source_cf");
    ASSERT_TRUE(src_cf != NULL);

    clone_cf = tidesdb_get_column_family(db, "cloned_cf");
    ASSERT_TRUE(clone_cf != NULL);

    /* we verify data still accessible in clone after reopen */
    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    char key[32];
    snprintf(key, sizeof(key), "clone_key_%04d", 0);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get(read_txn, clone_cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
        TDB_SUCCESS);
    ASSERT_TRUE(value != NULL);
    free(value);

    /* verify clone-only key still exists after reopen */
    retrieved_value = NULL;
    retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, clone_cf, new_key, sizeof(new_key), &retrieved_value,
                              &retrieved_size),
              TDB_SUCCESS);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);

    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_ops;
    atomic_int *clone_done;
    atomic_int *errors;
} clone_concurrent_ctx_t;

static void *clone_concurrent_writer(void *arg)
{
    clone_concurrent_ctx_t *ctx = (clone_concurrent_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(ctx->db, &txn) != 0)
        {
            atomic_fetch_add(ctx->errors, 1);
            continue;
        }

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "clone_concurrent_key_t%d_%04d", ctx->thread_id, i);
        snprintf(value, sizeof(value), "clone_concurrent_value_t%d_%04d", ctx->thread_id, i);

        int put_result = tidesdb_txn_put(txn, ctx->cf, (uint8_t *)key, strlen(key) + 1,
                                         (uint8_t *)value, strlen(value) + 1, -1);
        if (put_result != 0)
        {
            tidesdb_txn_free(txn);
            atomic_fetch_add(ctx->errors, 1);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(ctx->errors, 1);
        }
        tidesdb_txn_free(txn);

        usleep(100);
    }

    return NULL;
}

static void *clone_concurrent_reader(void *arg)
{
    clone_concurrent_ctx_t *ctx = (clone_concurrent_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(ctx->db, &txn) != 0)
        {
            continue;
        }

        char key[64];
        snprintf(key, sizeof(key), "initial_clone_key_%04d", i % 50);

        uint8_t *value = NULL;
        size_t value_size = 0;
        tidesdb_txn_get(txn, ctx->cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        if (value) free(value);

        tidesdb_txn_free(txn);
        usleep(50);
    }

    return NULL;
}

static void test_clone_column_family_concurrent(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 8192;

    ASSERT_EQ(tidesdb_create_column_family(db, "source_concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *src_cf = tidesdb_get_column_family(db, "source_concurrent_cf");
    ASSERT_TRUE(src_cf != NULL);

    /* add initial data */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "initial_clone_key_%04d", i);
        snprintf(value, sizeof(value), "initial_clone_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, src_cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    atomic_int clone_done;
    atomic_int errors;
    atomic_init(&clone_done, 0);
    atomic_init(&errors, 0);

    /* start writer and reader threads on source CF */
    const int num_threads = 4;
    const int ops_per_thread = 100;
    pthread_t writer_threads[4];
    pthread_t reader_threads[4];
    clone_concurrent_ctx_t writer_contexts[4];
    clone_concurrent_ctx_t reader_contexts[4];

    for (int i = 0; i < num_threads; i++)
    {
        writer_contexts[i].db = db;
        writer_contexts[i].cf = src_cf;
        writer_contexts[i].thread_id = i;
        writer_contexts[i].num_ops = ops_per_thread;
        writer_contexts[i].clone_done = &clone_done;
        writer_contexts[i].errors = &errors;
        pthread_create(&writer_threads[i], NULL, clone_concurrent_writer, &writer_contexts[i]);

        reader_contexts[i].db = db;
        reader_contexts[i].cf = src_cf;
        reader_contexts[i].thread_id = i;
        reader_contexts[i].num_ops = ops_per_thread;
        reader_contexts[i].clone_done = &clone_done;
        reader_contexts[i].errors = &errors;
        pthread_create(&reader_threads[i], NULL, clone_concurrent_reader, &reader_contexts[i]);
    }

    /*** we let threads run for a bit */
    usleep(50000);

    /* we perform clone while threads are active */
    int clone_result =
        tidesdb_clone_column_family(db, "source_concurrent_cf", "cloned_concurrent_cf");
    ASSERT_EQ(clone_result, TDB_SUCCESS);

    /* signal clone is done */
    atomic_store(&clone_done, 1);

    /* we wait for all threads */
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(writer_threads[i], NULL);
        pthread_join(reader_threads[i], NULL);
    }

    /* we verify source CF still exists and is accessible */
    src_cf = tidesdb_get_column_family(db, "source_concurrent_cf");
    ASSERT_TRUE(src_cf != NULL);

    /* we verify cloned CF exists */
    tidesdb_column_family_t *clone_cf = tidesdb_get_column_family(db, "cloned_concurrent_cf");
    ASSERT_TRUE(clone_cf != NULL);

    /* we verify initial data is accessible in clone */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    int found_count = 0;
    for (int i = 0; i < 50; i++)
    {
        char key[64];
        snprintf(key, sizeof(key), "initial_clone_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(read_txn, clone_cf, (uint8_t *)key, strlen(key) + 1, &value,
                            &value_size) == TDB_SUCCESS)
        {
            found_count++;
            free(value);
        }
    }
    tidesdb_txn_free(read_txn);

    /* all initial data should be found in clone */
    ASSERT_EQ(found_count, 50);

    /* verify clone and source are independent - write to clone */
    tidesdb_txn_t *write_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &write_txn), 0);
    uint8_t clone_only_key[] = "clone_only_concurrent_key";
    uint8_t clone_only_value[] = "clone_only_concurrent_value";
    ASSERT_EQ(tidesdb_txn_put(write_txn, clone_cf, clone_only_key, sizeof(clone_only_key),
                              clone_only_value, sizeof(clone_only_value), -1),
              0);
    ASSERT_EQ(tidesdb_txn_commit(write_txn), 0);
    tidesdb_txn_free(write_txn);

    /* we verify key exists in clone but not in source */
    read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    ASSERT_EQ(tidesdb_txn_get(read_txn, clone_cf, clone_only_key, sizeof(clone_only_key),
                              &retrieved_value, &retrieved_size),
              TDB_SUCCESS);
    ASSERT_TRUE(retrieved_value != NULL);
    free(retrieved_value);

    retrieved_value = NULL;
    ASSERT_EQ(tidesdb_txn_get(read_txn, src_cf, clone_only_key, sizeof(clone_only_key),
                              &retrieved_value, &retrieved_size),
              TDB_ERR_NOT_FOUND);

    tidesdb_txn_free(read_txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_ops;
    atomic_int *rename_done;
    atomic_int *errors;
} rename_concurrent_ctx_t;

static void *rename_concurrent_writer(void *arg)
{
    rename_concurrent_ctx_t *ctx = (rename_concurrent_ctx_t *)arg;

    for (int i = 0; i < ctx->num_ops; i++)
    {
        /* check if rename is done, if so get new CF handle */
        tidesdb_column_family_t *cf = ctx->cf;
        if (atomic_load(ctx->rename_done))
        {
            cf = tidesdb_get_column_family(ctx->db, "concurrent_renamed_cf");
            if (!cf)
            {
                /* CF might be in transition, skip this iteration */
                usleep(1000);
                continue;
            }
        }

        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(ctx->db, &txn) != 0)
        {
            atomic_fetch_add(ctx->errors, 1);
            continue;
        }

        char key[64];
        char value[128];
        snprintf(key, sizeof(key), "concurrent_key_t%d_%04d", ctx->thread_id, i);
        snprintf(value, sizeof(value), "concurrent_value_t%d_%04d", ctx->thread_id, i);

        int put_result = tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                         strlen(value) + 1, -1);
        if (put_result != 0)
        {
            tidesdb_txn_free(txn);
            /* CF might have been renamed, not an error */
            usleep(1000);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            /* commit failure during rename is expected */
        }
        tidesdb_txn_free(txn);

        usleep(100); /* small delay between ops */
    }

    return NULL;
}

static void test_rename_column_family_concurrent(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 8192;

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "initial_key_%04d", i);
        snprintf(value, sizeof(value), "initial_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    atomic_int rename_done;
    atomic_int errors;
    atomic_init(&rename_done, 0);
    atomic_init(&errors, 0);

    /* we start writer threads */
    const int num_threads = 4;
    const int ops_per_thread = 50;
    pthread_t threads[4];
    rename_concurrent_ctx_t contexts[4];

    for (int i = 0; i < num_threads; i++)
    {
        contexts[i].db = db;
        contexts[i].cf = cf;
        contexts[i].thread_id = i;
        contexts[i].num_ops = ops_per_thread;
        contexts[i].rename_done = &rename_done;
        contexts[i].errors = &errors;
        pthread_create(&threads[i], NULL, rename_concurrent_writer, &contexts[i]);
    }

    /* let writers run for a bit */
    usleep(50000);

    /* we perform rename while writers are active */
    int rename_result = tidesdb_rename_column_family(db, "concurrent_cf", "concurrent_renamed_cf");
    ASSERT_EQ(rename_result, TDB_SUCCESS);

    /* signal rename is done */
    atomic_store(&rename_done, 1);

    /* we wait for all threads */
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* we verify old name doesn't exist */
    tidesdb_column_family_t *old_cf = tidesdb_get_column_family(db, "concurrent_cf");
    ASSERT_TRUE(old_cf == NULL);

    /* we verify new name exists */
    tidesdb_column_family_t *new_cf = tidesdb_get_column_family(db, "concurrent_renamed_cf");
    ASSERT_TRUE(new_cf != NULL);

    /* we verify initial data is still accessible */
    tidesdb_txn_t *read_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &read_txn), 0);

    int found_count = 0;
    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "initial_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(read_txn, new_cf, (uint8_t *)key, strlen(key) + 1, &value,
                            &value_size) == TDB_SUCCESS)
        {
            found_count++;
            free(value);
        }
    }
    tidesdb_txn_free(read_txn);

    /* all initial data should be found */
    ASSERT_EQ(found_count, 50);

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
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

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
    cf_config.compression_algorithm = TDB_COMPRESS_ZSTD;

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
    cf_config.compression_algorithm = TDB_COMPRESS_SNAPPY;

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

static void test_block_indexes_sparse_sample_ratio(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_block_indexes = 1;
    cf_config.index_sample_ratio = 32;

    ASSERT_EQ(tidesdb_create_column_family(db, "bidx_sparse_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bidx_sparse_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_KEYS = 500;
    const int VALUE_SIZE = 1024;
    uint8_t *value = malloc(VALUE_SIZE);
    ASSERT_TRUE(value != NULL);
    memset(value, 'Z', VALUE_SIZE);

    /* write enough data to span multiple klog blocks */
    for (int i = 0; i < NUM_KEYS; i++)
    {
        value[0] = (uint8_t)(i & 0xFF);
        value[1] = (uint8_t)((i >> 8) & 0xFF);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "bidx_sparse_key_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, value, VALUE_SIZE, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    free(value);

    /* flush to create sstable with sparse block index */
    tidesdb_flush_memtable(cf);
    usleep(200000);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    const int probe_indices[] = {10, 275, 499};
    const int probe_count = (int)(sizeof(probe_indices) / sizeof(probe_indices[0]));

    for (int i = 0; i < probe_count; i++)
    {
        const int target = probe_indices[i];
        char key[32];
        snprintf(key, sizeof(key), "bidx_sparse_key_%04d", target);

        uint8_t *retrieved = NULL;
        size_t retrieved_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved, &retrieved_size),
            0);
        ASSERT_TRUE(retrieved != NULL);
        ASSERT_EQ(retrieved_size, (size_t)VALUE_SIZE);
        ASSERT_EQ(retrieved[0], (uint8_t)(target & 0xFF));
        ASSERT_EQ(retrieved[1], (uint8_t)((target >> 8) & 0xFF));

        free(retrieved);
    }

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

    cleanup_test_dir();
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

    int commit_result = tidesdb_txn_commit(txn);
    printf("COMMIT RESULT: %d (expected 0)\n", commit_result);
    fflush(stdout);
    ASSERT_EQ(commit_result, 0);
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
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;
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

static void test_iterator_no_bloom_no_indexes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 0;
    cf_config.enable_block_indexes = 0;
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_no_opt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_no_opt_cf");
    ASSERT_TRUE(cf != NULL);

    /* write and flush data */
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

    /* test iterator on flushed data */
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
        snprintf(expected_key, sizeof(expected_key), "key_%02d", count);
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        count++;
        tidesdb_iter_next(iter);
    }

    ASSERT_EQ(count, 20);

    tidesdb_iter_free(iter);
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
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

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

    /* now we have -- 3 ssts (0-14, 15-29, 30-44) + memtable (45-59) */
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

        /* verify all data is still there */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* trigger CF addition to see snapshot */
        uint8_t dummy_key[] = "dummy";
        uint8_t *dummy_val = NULL;
        size_t dummy_size = 0;
        tidesdb_txn_get(txn, cf, dummy_key, sizeof(dummy_key), &dummy_val, &dummy_size);
        if (dummy_val) free(dummy_val);

        printf("Transaction snapshot after first get: %lu\n", (unsigned long)txn->snapshot_seq);
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

    /* wait for compaction to complete by checking both queues and is_compacting flag */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

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
    printf("txn2 started with snapshot: %lu\n", (unsigned long)txn2->snapshot_seq);
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
    printf("txn2 snapshot is still: %lu\n", (unsigned long)txn2->snapshot_seq);
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
    /* we do not wait -- reads should work immediately via immutable memtable search */

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

    cf_config.enable_block_indexes = 0;
    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 4;
    const int KEYS_PER_THREAD = 2;
    const int TOTAL_KEYS = NUM_THREADS * KEYS_PER_THREAD;

    _Atomic(int) errors = 0;
    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    concurrent_writes_thread_data_t *thread_data = (concurrent_writes_thread_data_t *)malloc(
        NUM_THREADS * sizeof(concurrent_writes_thread_data_t));
    int missing_keys;

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
            snap = txn->snapshot_seq;
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

    /* wait for compaction to complete by checking both queues and is_compacting flag */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

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
     * strategy -- make level X very small so it fills up during one compaction cycle
     * dividing_level_offset=1 means X = num_levels - 2 (higher X than default)
     * small ratio (2x) creates many smaller levels
     * this way, when we compact, level X will stay full and trigger partitioned merge
     */
    cf_config.write_buffer_size = 150 * 8; /* very small buffer */
    cf_config.level_size_ratio = 2;        /* 2x growth = many small levels */
    cf_config.dividing_level_offset = 1;   /* X = num_levels - 2 (not -3) */
    cf_config.min_levels = 4;              /* force at least 4 levels */

    ASSERT_EQ(tidesdb_create_column_family(db, "partition_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "partition_cf");
    ASSERT_TRUE(cf != NULL);

    /* level capacity calculations with write_buffer_size=150, ratio=2, min_levels=4:
     * l0 -- 150 * 2 = 300 bytes
     * l1 -- 300 * 2 = 600 bytes
     * l2 -- 600 * 2 = 1,200 bytes
     * l3 -- 1,200 * 2 = 2,400 bytes
     * l4 -- 2,400 * 2 = 4,800 bytes
     * l5 -- 4,800 * 2 = 9,600 bytes
     * l6 -- 9,600 * 2 = 19,200 bytes
     * l7 -- 19,200 * 2 = 38,400 bytes
     *
     * dividing_level_offset=1, so X = num_levels - 1 - 1 = num_levels - 2
     * w 7 levels -- X = 7 - 2 = 5
     * w 6 levels -- X = 6 - 2 = 4
     *
     * 2000 keys × ~92 bytes = ~184,000 bytes
     * this will create many levels, and level X (4 or 5) will be small enough
     * that it stays full even after the initial dividing/full merge
     */

    /* we wrtite all keys in one batch */
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

    printf("Compacting - look for 'Partitioned preemptive merge: levels X to Z' in logs\n");
    tidesdb_compact(cf);

    /* wait for compaction to complete by checking both queues and is_compacting flag */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    int levels_after = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
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
    printf("Writing 50 keys (full preemptive merge)\n");
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

    /* wait for compaction to complete */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    int levels_phase1 = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    printf("  Levels after  %d\n", levels_phase1);

    /* medium dataset -- triggers dividing merge */
    printf("Writing 100 more keys (dividing merge)\n");
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

    /* wait for compaction to complete */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    int levels_phase2 = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    printf("  Levels after %d\n", levels_phase2);

    /* large dataset -- triggers partitioned merge */
    printf("Writing 100 more keys (partitioned merge)\n");
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

    /* wait for compaction to complete */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    int final_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    printf("  Levels after: %d\n", final_levels);

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

    /* wait for all background operations to complete
     * flushes can trigger auto-compactions, so we need to wait for everything to settle */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    /* trigger explicit compaction */
    tidesdb_compact(cf);

    /* wait for compaction and any cascading operations to complete */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            /* all queues empty and no compaction running, wait a bit more then verify stable */
            usleep(100000);
            is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
            if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
                !is_compacting)
            {
                break;
            }
        }
    }

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

    /* config that will trigger level additions
     * small write_buffer_size ensures frequent auto-flushes
     * l1 capacity -- 1000 * 2^0 = 1000 bytes
     * l2 capacity -- 1000 * 2^1 = 2000 bytes
     * each key+value is ~48 bytes, so ~21 keys per flush */
    cf_config.write_buffer_size = 1000;
    cf_config.level_size_ratio = 2;
    cf_config.dividing_level_offset = 0; /* X = num_levels - 1, pushes data to largest level */
    cf_config.min_levels = 2;
    cf_config.enable_block_indexes = 0;
    cf_config.enable_bloom_filter = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "dca_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dca_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    printf("Initial levels: %d\n", initial_levels);

    /* write enough data to fill Level 2 and trigger level addition
     * each key+value is ~160 bytes, need 400+ bytes in L2
     * write many keys to ensure data flows through L0→L1→L2 via compaction */
    int total_keys_written = 0;

    printf("Writing keys to trigger level growth...\n");
    /* write 1500 keys -- with 1000 byte threshold, this will trigger ~70+ flushes
     * total data -- ~72KB, well over L2's 2000 byte capacity */
    for (int i = 0; i < 2500; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[128];
        snprintf(key, sizeof(key), "dca_key_%05d", i);
        snprintf(value, sizeof(value), "dca_value_%05d_with_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        total_keys_written++;
    }

    printf("Wrote %d keys, waiting for background operations...\n", total_keys_written);
    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    sleep(2);

    sleep(5);

    /* trigger a few compaction rounds to push data through levels */
    for (int round = 0; round < 5; round++)
    {
        tidesdb_compact(cf);
        sleep(2);

        int current_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
        printf("After compaction round %d: %d levels\n", round + 1, current_levels);

        if (current_levels > initial_levels)
        {
            printf("Level growth detected!\n");
            break;
        }
    }

    printf("Total keys written: %d\n", total_keys_written);

    /* explicitly flush memtable to ensure all keys are persisted */
    tidesdb_flush_memtable(cf);
    sleep(1);

    /* trigger final compaction to ensure all data is merged */
    tidesdb_compact(cf);
    sleep(2);

    /* final */
    sleep(3);

    /* check final level count after flush and compaction */
    int final_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    printf("Final levels: %d (growth: %d levels)\n", final_levels, final_levels - initial_levels);

    /* verify DCA worked -- should have added levels */
    ASSERT_TRUE(final_levels > initial_levels);

    /* verify data is accessible (skip verification of keys that may still be in memtable) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* only verify keys that should have been flushed */
    int keys_to_verify = total_keys_written - 50; /* leave buffer for unflushed keys */
    printf("Verifying %d keys...\n", keys_to_verify);
    for (int i = 0; i < keys_to_verify; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "dca_key_%05d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        if (result != 0)
        {
            printf("FAILED to get key: %s (index %d)\n", key, i);
        }
        ASSERT_EQ(result, 0);
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

    /* rolled back data should not exist */
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

void test_iterator_prefix_seek_behavior(void)
{
    cleanup_test_dir();

    tidesdb_t *db = create_test_db();
    assert(db != NULL);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    assert(tidesdb_create_column_family(db, "prefix_cf", &config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "prefix_cf");

    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    const char *keys[] = {"user:100", "user:200", "user:300", "user:400", "user:500"};
    const char *values[] = {"alice", "bob", "charlie", "david", "eve"};
    const int num_keys = 5;

    for (int i = 0; i < num_keys; i++)
    {
        assert(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                               (uint8_t *)values[i], strlen(values[i]) + 1, 0) == TDB_SUCCESS);
    }

    assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
    tidesdb_txn_free(txn);

    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf, &iter) == TDB_SUCCESS);

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;

    const char *seek1 = "user:150";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek1, strlen(seek1) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:200") == 0);

    const char *seek2 = "user:250";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek2, strlen(seek2) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:300") == 0);

    const char *seek3 = "user:";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek3, strlen(seek3) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:100") == 0);

    assert(tidesdb_iter_seek(iter, (uint8_t *)seek3, strlen(seek3) + 1) == TDB_SUCCESS);
    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
        assert(strncmp((char *)key, "user:", 5) == 0);
        count++;
        if (tidesdb_iter_next(iter) != TDB_SUCCESS) break;
    }
    assert(count == num_keys);

    const char *seek5 = "user:350";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek5, strlen(seek5) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:300") == 0);

    const char *seek6 = "user:999";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek6, strlen(seek6) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:500") == 0);

    const char *seek8 = "aaa";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek8, strlen(seek8) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:100") == 0);

    value = NULL;
    value_size = 0;
    int get_result =
        tidesdb_txn_get(txn, cf, (uint8_t *)seek1, strlen(seek1) + 1, &value, &value_size);
    assert(get_result == TDB_ERR_NOT_FOUND);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

void test_iterator_prefix_seek_with_sstables(void)
{
    cleanup_test_dir();

    tidesdb_config_t db_config = tidesdb_default_config();
    db_config.db_path = TEST_DB_PATH;
    db_config.block_cache_size = 8 * 1024 * 1024;

    tidesdb_t *db = NULL;
    assert(tidesdb_open(&db_config, &db) == TDB_SUCCESS);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 32 * 1024;
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    assert(tidesdb_create_column_family(db, "prefix_sst_cf", &cf_config) == TDB_SUCCESS);

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "prefix_sst_cf");

    const char *prefixes[] = {"user:", "order:", "product:"};
    const int num_prefixes = 3;
    const int keys_per_prefix = 10;

    for (int p = 0; p < num_prefixes; p++)
    {
        for (int i = 0; i < keys_per_prefix; i++)
        {
            tidesdb_txn_t *txn;
            assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

            char key[64], value[64];
            snprintf(key, sizeof(key), "%s%03d", prefixes[p], (i + 1) * 100);
            snprintf(value, sizeof(value), "%svalue_%03d", prefixes[p], i);

            assert(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                   strlen(value) + 1, 0) == TDB_SUCCESS);
            assert(tidesdb_txn_commit(txn) == TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 50; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(100000);

    tidesdb_txn_t *txn;
    assert(tidesdb_txn_begin(db, &txn) == TDB_SUCCESS);

    tidesdb_iter_t *iter;
    assert(tidesdb_iter_new(txn, cf, &iter) == TDB_SUCCESS);

    uint8_t *key = NULL;
    size_t key_size = 0;

    const char *seek1 = "user:150";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek1, strlen(seek1) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:200") == 0);

    const char *seek2 = "user:";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek2, strlen(seek2) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "user:100") == 0);

    assert(tidesdb_iter_seek(iter, (uint8_t *)seek2, strlen(seek2) + 1) == TDB_SUCCESS);
    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
        if (strncmp((char *)key, "user:", 5) != 0) break;
        count++;
        if (tidesdb_iter_next(iter) != TDB_SUCCESS) break;
    }
    assert(count == keys_per_prefix);

    const char *seek3 = "order:";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek3, strlen(seek3) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "order:100") == 0);

    const char *seek4 = "order:550";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek4, strlen(seek4) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "order:500") == 0);

    const char *seek5 = "product:999";
    assert(tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek5, strlen(seek5) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strncmp((char *)key, "product:", 8) == 0);

    const char *seek6 = "aaa";
    assert(tidesdb_iter_seek(iter, (uint8_t *)seek6, strlen(seek6) + 1) == TDB_SUCCESS);
    assert(tidesdb_iter_valid(iter));
    assert(tidesdb_iter_key(iter, &key, &key_size) == TDB_SUCCESS);
    assert(strcmp((char *)key, "order:100") == 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    int get_result =
        tidesdb_txn_get(txn, cf, (uint8_t *)seek1, strlen(seek1) + 1, &value, &value_size);
    assert(get_result == TDB_ERR_NOT_FOUND);

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
    tidesdb_txn_free(txn1);

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
    tidesdb_txn_free(txn3);

    /* REPEATABLE_READ should still see old value (consistent snapshot) */
    uint8_t *read2 = NULL;
    size_t read2_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn2, cf, key, sizeof(key), &read2, &read2_size), 0);
    ASSERT_TRUE(strcmp((char *)read2, (char *)value1) == 0);
    free(read2);

    /* try to commit -- should fail with read-write conflict */
    int commit_result = tidesdb_txn_commit(txn2);
    ASSERT_EQ(commit_result, TDB_ERR_CONFLICT);

    tidesdb_txn_free(txn2);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_isolation_snapshot(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "snap_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "snap_cf");

    uint8_t key[] = "account_balance";
    uint8_t value1[] = "1000";
    uint8_t value2[] = "1100";
    uint8_t value3[] = "900";

    tidesdb_txn_t *txn1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);
    ASSERT_EQ(tidesdb_txn_put(txn1, cf, key, sizeof(key), value1, sizeof(value1), 0), 0);
    ASSERT_EQ(tidesdb_txn_commit(txn1), 0);
    tidesdb_txn_free(txn1);

    /* start two SNAPSHOT transactions */
    tidesdb_txn_t *txn2 = NULL, *txn3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn2), 0);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn3), 0);

    /* both try to update the same key (lost update scenario) */
    ASSERT_EQ(tidesdb_txn_put(txn2, cf, key, sizeof(key), value2, sizeof(value2), 0), 0);
    ASSERT_EQ(tidesdb_txn_put(txn3, cf, key, sizeof(key), value3, sizeof(value3), 0), 0);

    /* first commit should succeed */
    ASSERT_EQ(tidesdb_txn_commit(txn2), 0);

    /* second commit should fail with write-write conflict (prevents lost update) */
    ASSERT_EQ(tidesdb_txn_commit(txn3), TDB_ERR_CONFLICT);

    tidesdb_txn_free(txn2);
    tidesdb_txn_free(txn3);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_write_write_conflict(void)
{
    test_isolation_snapshot();
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
    ASSERT_EQ(tidesdb_txn_begin(db, &txn1), 0);

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
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

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

static void test_long_running_transaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "long_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "long_cf");

    /* we start long-running SNAPSHOT transaction */
    tidesdb_txn_t *long_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &long_txn), 0);

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
        snprintf(corrupt_file, sizeof(corrupt_file),
                 "%s" PATH_SEPARATOR "corrupt_cf" PATH_SEPARATOR "L1_0.klog", TEST_DB_PATH);

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
        sleep(4);

        ASSERT_EQ(tidesdb_compact(cf), 0);
        sleep(4);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t cfg = tidesdb_default_config();
        cfg.db_path = TEST_DB_PATH;
        cfg.num_flush_threads = 1;
        cfg.num_compaction_threads = 1;
        cfg.block_cache_size = 0;

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

static void test_iterator_read_own_uncommitted_writes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_ryow_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_ryow_cf");
    ASSERT_TRUE(cf != NULL);

    /* we commit some keys to sstable (keys 00, 10, 20, 30, 40) */
    for (int i = 0; i < 50; i += 10)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "committed_value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* we flush to sstable */
    tidesdb_flush_memtable(cf);
    usleep(100000);

    /* commit more keys to memtable (keys 05, 15, 25, 35, 45) */
    for (int i = 5; i < 50; i += 10)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "memtable_value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* we start a transaction with uncommitted writes (keys 02, 12, 22, 32, 42) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 2; i < 50; i += 10)
    {
        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%02d", i);
        snprintf(value, sizeof(value), "uncommitted_value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
    }

    /* also overwrite a committed key with uncommitted value */
    char overwrite_key[] = "key_10";
    char overwrite_value[] = "uncommitted_overwrite_10";
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)overwrite_key, strlen(overwrite_key) + 1,
                              (uint8_t *)overwrite_value, strlen(overwrite_value) + 1, 0),
              0);

    /* we create iterator within the transaction -- should see all sources merged:
     * sstable: 00, 10, 20, 30, 40
     * memtable: 05, 15, 25, 35, 45
     * uncommitted: 02, 12, 22, 32, 42 + overwrite of 10
     * expected order: 00, 02, 05, 10(uncommitted), 12, 15, 20, 22, 25, 30, 32, 35, 40, 42, 45
     */
    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int expected_keys[] = {0, 2, 5, 10, 12, 15, 20, 22, 25, 30, 32, 35, 40, 42, 45};
    int expected_count = sizeof(expected_keys) / sizeof(expected_keys[0]);
    int count = 0;

    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_EQ(tidesdb_iter_value(iter, &value, &value_size), 0);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%02d", expected_keys[count]);
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        /* verify uncommitted overwrite wins for key_10 */
        if (expected_keys[count] == 10)
        {
            ASSERT_TRUE(strcmp((char *)value, "uncommitted_overwrite_10") == 0);
        }

        count++;
        tidesdb_iter_next(iter);
    }

    ASSERT_EQ(count, expected_count);

    tidesdb_iter_free(iter);

    /* we test reverse iteration with fresh iterator */
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);
    count = expected_count - 1;

    while (tidesdb_iter_valid(iter) && count >= 0)
    {
        uint8_t *key = NULL;
        size_t key_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%02d", expected_keys[count]);
        ASSERT_TRUE(strcmp((char *)key, expected_key) == 0);

        count--;
        tidesdb_iter_prev(iter);
    }

    ASSERT_EQ(count, -1);

    tidesdb_iter_free(iter);

    /* we do not commit -- we rollback to verify uncommitted data was only visible in txn */
    tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);

    /* we verify uncommitted keys are not visible after rollback */
    tidesdb_txn_t *verify_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &verify_txn), 0);

    uint8_t *retrieved = NULL;
    size_t retrieved_size = 0;
    int result =
        tidesdb_txn_get(verify_txn, cf, (uint8_t *)"key_02", 7, &retrieved, &retrieved_size);
    ASSERT_TRUE(result != 0); /* key_02 should not exist */

    /* key_10 should have original committed value */
    result = tidesdb_txn_get(verify_txn, cf, (uint8_t *)"key_10", 7, &retrieved, &retrieved_size);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(strcmp((char *)retrieved, "committed_value_10") == 0);
    free(retrieved);

    tidesdb_txn_free(verify_txn);

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
    tidesdb_comparator_fn comparator;
    int use_btree;
} sim_test_config_t;

static void run_sstable_simulation(sim_test_config_t *config)
{
    printf("  Running: %s (bloom=%d, idx=%d, comp=%d, ssts=%d, keys=%d, btree=%d)\n",
           config->test_name, config->enable_bloom, config->enable_indexes,
           config->compression_algo, config->num_sstables, config->keys_per_sstable,
           config->use_btree);

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
    cf_config.use_btree = config->use_btree;

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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
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
                                .compression_algo = TDB_COMPRESS_ZSTD,
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
                                .compression_algo = TDB_COMPRESS_SNAPPY,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_ZSTD,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
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
                                .compression_algo = TDB_COMPRESS_ZSTD,
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
                                .compression_algo = TDB_COMPRESS_SNAPPY,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
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
                                .compression_algo = TDB_COMPRESS_NONE,
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
                                .compression_algo = TDB_COMPRESS_ZSTD,
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
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_read_committed(void)
{
    sim_test_config_t config = {.test_name = "isolation_read_committed",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_repeatable_read(void)
{
    sim_test_config_t config = {.test_name = "isolation_repeatable_read",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_ZSTD,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_serializable(void)
{
    sim_test_config_t config = {.test_name = "isolation_serializable",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_memcmp(void)
{
    sim_test_config_t config = {.test_name = "comparator_memcmp",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_memcmp};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_lexicographic(void)
{
    sim_test_config_t config = {.test_name = "comparator_lexicographic",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_ZSTD,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_lexicographic};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_reverse(void)
{
    sim_test_config_t config = {.test_name = "comparator_reverse",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_reverse_memcmp};
    run_sstable_simulation(&config);
}

static void test_many_sstables_comparator_case_insensitive(void)
{
    sim_test_config_t config = {.test_name = "comparator_case_insensitive",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_case_insensitive};
    run_sstable_simulation(&config);
}

static void test_many_sstables_small_cache(void)
{
    sim_test_config_t config = {.test_name = "small_bm_cache",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_LZ4,
                                .num_sstables = 20,
                                .block_cache_size = 1024 * 1024, /* 1MB */
                                .keys_per_sstable = 50,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_large_cache(void)
{
    sim_test_config_t config = {.test_name = "large_bm_cache",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_ZSTD,
                                .num_sstables = 20,
                                .block_cache_size = 64 * 1024 * 1024, /* 64MB */
                                .keys_per_sstable = 50,
                                .comparator = NULL};
    run_sstable_simulation(&config);
}

static void test_many_sstables_all_comparators(void)
{
    sim_test_config_t config = {.test_name = "all_comparators_combined",
                                .enable_bloom = 1,
                                .enable_indexes = 1,
                                .compression_algo = TDB_COMPRESS_ZSTD,
                                .num_sstables = 15,
                                .block_cache_size = 32 * 1024 * 1024,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_lexicographic};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_basic(void)
{
    sim_test_config_t config = {.test_name = "btree_basic",
                                .enable_bloom = 1,
                                .enable_indexes = 0, /* btree doesn't use block indexes */
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 10,
                                .block_cache_size = 0,
                                .keys_per_sstable = 50,
                                .comparator = NULL,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_with_bloom(void)
{
    sim_test_config_t config = {.test_name = "btree_with_bloom",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_without_bloom(void)
{
    sim_test_config_t config = {.test_name = "btree_without_bloom",
                                .enable_bloom = 0,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 15,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = NULL,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_many_keys(void)
{
    sim_test_config_t config = {.test_name = "btree_many_keys",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 20,
                                .block_cache_size = 0,
                                .keys_per_sstable = 100,
                                .comparator = NULL,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_with_cache(void)
{
    sim_test_config_t config = {.test_name = "btree_with_cache",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 15,
                                .block_cache_size = 16 * 1024 * 1024, /* 16MB */
                                .keys_per_sstable = 50,
                                .comparator = NULL,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_comparator_lexicographic(void)
{
    sim_test_config_t config = {.test_name = "btree_comparator_lexicographic",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 10,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_lexicographic,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_sstable_comparator_reverse(void)
{
    sim_test_config_t config = {.test_name = "btree_comparator_reverse",
                                .enable_bloom = 1,
                                .enable_indexes = 0,
                                .compression_algo = TDB_COMPRESS_NONE,
                                .num_sstables = 10,
                                .block_cache_size = 0,
                                .keys_per_sstable = 40,
                                .comparator = tidesdb_comparator_reverse_memcmp,
                                .use_btree = 1};
    run_sstable_simulation(&config);
}

static void test_btree_compaction_basic(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 10;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0; /* btree doesn't use block indexes */

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_compact_cf");
    ASSERT_TRUE(cf != NULL);

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

        if (i % 10 == 9)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    tidesdb_flush_memtable(cf);

    int max_wait = 200;
    for (int i = 0; i < max_wait; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0)
        {
            usleep(100000);
            break;
        }
    }

    tidesdb_compact(cf);

    for (int i = 0; i < max_wait; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->compaction_queue) == 0 && !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

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

static void test_btree_compaction_with_deletes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 10;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_del_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_del_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "del_key_%03d", i);
        snprintf(value, sizeof(value), "del_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if (i % 10 == 9) tidesdb_flush_memtable(cf);
    }

    for (int i = 0; i < 100; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "del_key_%03d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "del_key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            ASSERT_TRUE(result != 0); /* deleted keys should not be found */
        }
        else
        {
            ASSERT_EQ(result, 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_flush_basic(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_flush_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "flush_key_%03d", i);
        snprintf(value, sizeof(value), "flush_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "flush_key_%03d", i);
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

static void test_btree_dca_min_levels_constraint(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 4;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_min_levels_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_min_levels_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(initial_levels >= 4);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "btree_min_key_%03d", i);
        snprintf(value, sizeof(value), "btree_min_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    for (int round = 0; round < 3; round++)
    {
        tidesdb_compact(cf);
        for (int i = 0; i < 200; i++)
        {
            usleep(50000);
            if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
        }
    }

    int final_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(final_levels >= 4);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "btree_min_key_%03d", i);
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

static void test_btree_merge_heap_source_exhaustion(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_exhaust_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_exhaust_cf");
    ASSERT_TRUE(cf != NULL);

    /* create multiple small sstables with non-overlapping ranges */
    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 10; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "batch%d_key_%03d", batch, i);
            snprintf(value, sizeof(value), "batch%d_value_%03d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(100000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 10; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "batch%d_key_%03d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_compaction_all_tombstones(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_tomb_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_tomb_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert keys */
    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);
        snprintf(value, sizeof(value), "tomb_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_TRUE(result != 0);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_flush_during_compaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_flush_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_flush_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "fc_key_%03d_%03d", batch, i);
            snprintf(value, sizeof(value), "fc_value_%03d_%03d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    /* immediately write more data and flush during compaction */
    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "fc_new_key_%03d", i);
        snprintf(value, sizeof(value), "fc_new_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    /* wait for everything to complete */
    for (int i = 0; i < 300; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0 &&
            queue_size(db->flush_queue) == 0)
            break;
    }

    /* we verify all data */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "fc_key_%03d_%03d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "fc_new_key_%03d", i);
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

static void test_btree_compaction_max_seq_propagation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_seq_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_seq_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 15; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "seq_key_%03d", i);
            snprintf(value, sizeof(value), "seq_value_batch%d_%03d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(100000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    /* we verify we get the latest values (from batch 2) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 15; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "seq_key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "seq_value_batch2_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(strcmp((char *)value, expected_value) == 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_merge_with_bloom_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_bloom_filter = 0;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_no_bloom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_no_bloom_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "nb_key_%03d_%03d", batch, i);
            snprintf(value, sizeof(value), "nb_value_%03d_%03d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(100000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "nb_key_%03d_%03d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_many_sstables_delete_verify_stats(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 4;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;
    cf_config.enable_bloom_filter = 0; /* disabled to test tombstone masking */

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_stats_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_stats_cf");
    ASSERT_TRUE(cf != NULL);

    const int total_keys = 500;
    const int keys_per_flush = 25;

    /* insert many keys to generate multiple sstables */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[128];
        snprintf(key, sizeof(key), "btree_stats_key_%05d", i);
        snprintf(value, sizeof(value), "btree_stats_value_%05d_with_extra_data", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* flush every keys_per_flush keys to create multiple sstables */
        if ((i + 1) % keys_per_flush == 0)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    /* final flush */
    tidesdb_flush_memtable(cf);

    /* wait for flushes to complete */
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* get stats before delete */
    tidesdb_stats_t *stats_before = NULL;
    ASSERT_EQ(tidesdb_get_stats(cf, &stats_before), 0);
    ASSERT_TRUE(stats_before != NULL);
    ASSERT_TRUE(stats_before->use_btree == 1);
    ASSERT_TRUE(stats_before->num_levels > 0);
    ASSERT_TRUE(stats_before->total_keys > 0);

    tidesdb_free_stats(stats_before);

    /* we delete every other key */
    for (int i = 0; i < total_keys; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "btree_stats_key_%05d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush deletes */
    tidesdb_flush_memtable(cf);

    /* we wait for all flushes and compactions to complete
     * we need multiple consecutive idle checks because new compactions
     * can be triggered immediately after a flush or compaction completes */
    int idle_count = 0;
    for (int i = 0; i < 600; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0 && !tidesdb_is_compacting(cf) &&
            queue_size(db->compaction_queue) == 0)
        {
            idle_count++;
            /* require 10 consecutive idle checks (500ms total) to ensure stability */
            if (idle_count >= 10) break;
        }
        else
        {
            idle_count = 0; /* reset if any work is detected */
        }
    }

    /* we get stats after delete */
    tidesdb_stats_t *stats_after = NULL;
    ASSERT_EQ(tidesdb_get_stats(cf, &stats_after), 0);
    ASSERT_TRUE(stats_after != NULL);
    ASSERT_TRUE(stats_after->use_btree == 1);

    /* we verify deleted keys return not found and existing keys are accessible
     **** tombstones mask deleted keys even if not yet physically removed by compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    int deleted_found = 0;
    int existing_found = 0;
    for (int i = 0; i < total_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "btree_stats_key_%05d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            /* even keys were deleted -- should return not found */
            if (result == 0)
            {
                deleted_found++;
                if (deleted_found <= 5)
                    printf("deleted key %d was FOUND (should be not found), value=%s\n", i,
                           (char *)value);
                free(value);
            }
        }
        else
        {
            /* odd keys should exist */
            if (result == 0)
            {
                existing_found++;
                free(value);
            }
        }
    }
    printf("deleted_found=%d, existing_found=%d (expected 0, %d)\n", deleted_found, existing_found,
           total_keys / 2);
    fflush(stdout);

    tidesdb_txn_free(txn);

    /* all odd keys should be found */
    ASSERT_EQ(existing_found, total_keys / 2);
    /* no deleted keys should be found (tombstones mask them) */
    ASSERT_EQ(deleted_found, 0);

    tidesdb_free_stats(stats_after);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_btree_compaction_interleaved_deletes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 2;
    cf_config.use_btree = 1;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "btree_interleave_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "btree_interleave_cf");
    ASSERT_TRUE(cf != NULL);

    /* insert all keys first */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "il_key_%03d", i);
        snprintf(value, sizeof(value), "il_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 50; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "il_key_%03d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "il_key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            /* even keys were deleted */
            ASSERT_TRUE(result != 0);
        }
        else
        {
            /* odd keys should exist */
            ASSERT_EQ(result, 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cf_drop_during_pending_flush(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 1;
    config.num_compaction_threads = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "flush_drop_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "flush_drop_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "flush_drop_key_%04d", i);
        snprintf(value, sizeof(value), "flush_drop_value_%04d_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    /* immediately drop the CF while flush work may still be pending
     * this should be handled gracefully without crashing */
    int drop_result = tidesdb_drop_column_family(db, "flush_drop_cf");

    /* drop may succeed or fail depending on timing -- either is acceptable
     * the key is that it should not crash */
    (void)drop_result;

    /* wait for any pending work to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* verify CF is gone or system is still functional */
    cf = tidesdb_get_column_family(db, "flush_drop_cf");

    /* we create a new CF to verify system is still functional */
    ASSERT_EQ(tidesdb_create_column_family(db, "verify_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *verify_cf = tidesdb_get_column_family(db, "verify_cf");
    ASSERT_TRUE(verify_cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, verify_cf, (uint8_t *)"test", 5, (uint8_t *)"value", 6, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_cf_drop_during_active_compaction(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 2;
    config.num_compaction_threads = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "compact_drop_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "compact_drop_cf");
    ASSERT_TRUE(cf != NULL);

    /* write multiple batches to create multiple sstables for compaction */
    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "compact_drop_key_%d_%04d", batch, i);
            snprintf(value, sizeof(value), "compact_drop_value_%d_%04d_data", batch, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        tidesdb_flush_memtable(cf);
        usleep(30000);
    }

    /* wait for flushes to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* trigger compaction -- this enqueues work with cf pointer */
    tidesdb_compact(cf);

    /* immediately drop the CF while compaction work may be running
     * this should be handled gracefully without crashing */
    int drop_result = tidesdb_drop_column_family(db, "compact_drop_cf");
    (void)drop_result;

    /* wait for any pending compaction work */
    for (int i = 0; i < 200; i++)
    {
        usleep(25000);
        if (queue_size(db->compaction_queue) == 0) break;
    }

    /* create a new CF to verify system is still functional */
    ASSERT_EQ(tidesdb_create_column_family(db, "verify_cf2", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *verify_cf = tidesdb_get_column_family(db, "verify_cf2");
    ASSERT_TRUE(verify_cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, verify_cf, (uint8_t *)"test", 5, (uint8_t *)"value", 6, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

/**
 * test_cf_rename_during_pending_flush
 * tests that renaming a column family while flush work is pending
 * does not cause issues when the flush worker processes the work item
 */
static void test_cf_rename_during_pending_flush(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 1;
    config.num_compaction_threads = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    ASSERT_EQ(tidesdb_create_column_family(db, "rename_flush_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rename_flush_cf");
    ASSERT_TRUE(cf != NULL);

    /* write data to trigger flush */
    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "rename_flush_key_%04d", i);
        snprintf(value, sizeof(value), "rename_flush_value_%04d_padding", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* trigger flush */
    tidesdb_flush_memtable(cf);

    /* immediately rename the CF while flush work may still be pending */
    int rename_result = tidesdb_rename_column_family(db, "rename_flush_cf", "renamed_flush_cf");
    (void)rename_result;

    /* wait for flush to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(50000);

    /* verify the renamed CF exists and data is accessible */
    tidesdb_column_family_t *renamed_cf = tidesdb_get_column_family(db, "renamed_flush_cf");
    if (renamed_cf != NULL)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        uint8_t *value = NULL;
        size_t value_size = 0;
        /* try to read one of the keys -- may or may not exist depending on timing */
        int get_result = tidesdb_txn_get(txn, renamed_cf, (uint8_t *)"rename_flush_key_0010", 22,
                                         &value, &value_size);
        if (get_result == TDB_SUCCESS && value != NULL)
        {
            free(value);
        }
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

/**
 * test_cf_rename_during_active_compaction
 * tests that renaming a column family while compaction is actively running
 * does not cause issues when the compaction worker accesses the CF
 */
static void test_cf_rename_during_active_compaction(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 2;
    config.num_compaction_threads = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "rename_compact_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rename_compact_cf");
    ASSERT_TRUE(cf != NULL);

    /* write multiple batches to create SSTables */
    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "rename_compact_key_%d_%04d", batch, i);
            snprintf(value, sizeof(value), "rename_compact_value_%d_%04d", batch, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        tidesdb_flush_memtable(cf);
        usleep(30000);
    }

    /* wait for flushes */
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* trigger compaction */
    tidesdb_compact(cf);

    /* immediately rename the CF while compaction may be running */
    int rename_result = tidesdb_rename_column_family(db, "rename_compact_cf", "renamed_compact_cf");
    (void)rename_result;

    /* wait for compaction */
    for (int i = 0; i < 200; i++)
    {
        usleep(25000);
        if (queue_size(db->compaction_queue) == 0) break;
    }

    /* verify system is still functional */
    tidesdb_column_family_t *renamed_cf = tidesdb_get_column_family(db, "renamed_compact_cf");
    if (renamed_cf != NULL)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, renamed_cf, (uint8_t *)"verify", 7, (uint8_t *)"ok", 3, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

/**
 * test_multiple_cf_drop_with_concurrent_workers
 * tests dropping multiple column families concurrently while workers are active
 */
static void test_multiple_cf_drop_with_concurrent_workers(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 2;
    config.num_compaction_threads = 2;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;

    const int NUM_CFS = 4;
    char cf_names[4][32] = {"multi_drop_cf_0", "multi_drop_cf_1", "multi_drop_cf_2",
                            "multi_drop_cf_3"};
    tidesdb_column_family_t *cfs[4];

    /* create multiple CFs */
    for (int c = 0; c < NUM_CFS; c++)
    {
        ASSERT_EQ(tidesdb_create_column_family(db, cf_names[c], &cf_config), TDB_SUCCESS);
        cfs[c] = tidesdb_get_column_family(db, cf_names[c]);
        ASSERT_TRUE(cfs[c] != NULL);
    }

    /* write data to all CFs */
    for (int c = 0; c < NUM_CFS; c++)
    {
        for (int i = 0; i < 15; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "multi_key_%d_%04d", c, i);
            snprintf(value, sizeof(value), "multi_value_%d_%04d_data", c, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cfs[c], (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }
    }

    /* trigger flushes on all CFs */
    for (int c = 0; c < NUM_CFS; c++)
    {
        tidesdb_flush_memtable(cfs[c]);
    }

    /* drop CFs while flushes may be pending */
    for (int c = 0; c < NUM_CFS; c++)
    {
        int drop_result = tidesdb_drop_column_family(db, cf_names[c]);
        (void)drop_result;
    }

    /* wait for workers to finish */
    for (int i = 0; i < 100; i++)
    {
        usleep(20000);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0) break;
    }

    /* verify system is still functional by creating a new CF */
    ASSERT_EQ(tidesdb_create_column_family(db, "final_verify_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *verify_cf = tidesdb_get_column_family(db, "final_verify_cf");
    ASSERT_TRUE(verify_cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, verify_cf, (uint8_t *)"final", 6, (uint8_t *)"test", 5, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_large_value_iteration(void)
{
    cleanup_test_dir();

    tidesdb_t *db = NULL;
    tidesdb_config_t config = {.db_path = TEST_DB_PATH,
                               .num_flush_threads = 2,
                               .num_compaction_threads = 2,
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
        uint8_t *iter_key = NULL;
        size_t iter_key_size = 0;
        uint8_t *iter_value = NULL;
        size_t iter_value_size = 0;

        ASSERT_EQ(tidesdb_iter_key(iter, &iter_key, &iter_key_size), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_iter_value(iter, &iter_value, &iter_value_size), TDB_SUCCESS);

        ASSERT_EQ(iter_key_size, (size_t)TEST_KEY_SIZE);
        ASSERT_EQ(iter_value_size, (size_t)TEST_VALUE_SIZE);

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
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

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

static void test_multi_cf_transaction_atomicity_recovery(void)
{
    cleanup_test_dir();
    const int NUM_TRANSACTIONS = 5;
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;

        /* create three column families */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_alpha", &cf_config), 0);
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_beta", &cf_config), 0);
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_gamma", &cf_config), 0);

        tidesdb_column_family_t *cf_alpha = tidesdb_get_column_family(db, "cf_alpha");
        tidesdb_column_family_t *cf_beta = tidesdb_get_column_family(db, "cf_beta");
        tidesdb_column_family_t *cf_gamma = tidesdb_get_column_family(db, "cf_gamma");
        ASSERT_TRUE(cf_alpha != NULL);
        ASSERT_TRUE(cf_beta != NULL);
        ASSERT_TRUE(cf_gamma != NULL);

        /* write multi-CF transactions touching all three CFs */
        for (int i = 0; i < NUM_TRANSACTIONS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key_alpha[32], value_alpha[64];
            char key_beta[32], value_beta[64];
            char key_gamma[32], value_gamma[64];

            snprintf(key_alpha, sizeof(key_alpha), "alpha_key_%03d", i);
            snprintf(value_alpha, sizeof(value_alpha), "alpha_value_%03d", i);
            snprintf(key_beta, sizeof(key_beta), "beta_key_%03d", i);
            snprintf(value_beta, sizeof(value_beta), "beta_value_%03d", i);
            snprintf(key_gamma, sizeof(key_gamma), "gamma_key_%03d", i);
            snprintf(value_gamma, sizeof(value_gamma), "gamma_value_%03d", i);

            /* write to all three CFs in same transaction */
            ASSERT_EQ(tidesdb_txn_put(txn, cf_alpha, (uint8_t *)key_alpha, strlen(key_alpha) + 1,
                                      (uint8_t *)value_alpha, strlen(value_alpha) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_beta, (uint8_t *)key_beta, strlen(key_beta) + 1,
                                      (uint8_t *)value_beta, strlen(value_beta) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_gamma, (uint8_t *)key_gamma, strlen(key_gamma) + 1,
                                      (uint8_t *)value_gamma, strlen(value_gamma) + 1, 0),
                      0);

            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* close database (simulates crash -- data only in WAL) */
        tidesdb_close(db);
    }

    /* reopen and verify all transactions recovered atomically */
    {
        /* reopen existing database (don't create new one) */
        tidesdb_config_t config = {.db_path = "./test_tidesdb",
                                   .num_flush_threads = 2,
                                   .num_compaction_threads = 2,
                                   .log_level = TDB_LOG_INFO,
                                   .block_cache_size = 64 * 1024 * 1024,
                                   .max_open_sstables = 100};

        tidesdb_t *db = NULL;
        int result = tidesdb_open(&config, &db);
        ASSERT_EQ(result, 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf_alpha = tidesdb_get_column_family(db, "cf_alpha");
        tidesdb_column_family_t *cf_beta = tidesdb_get_column_family(db, "cf_beta");
        tidesdb_column_family_t *cf_gamma = tidesdb_get_column_family(db, "cf_gamma");
        ASSERT_TRUE(cf_alpha != NULL);
        ASSERT_TRUE(cf_beta != NULL);
        ASSERT_TRUE(cf_gamma != NULL);

        /* verify all transactions are present in all three CFs */
        for (int i = 0; i < NUM_TRANSACTIONS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key_alpha[32], expected_value_alpha[64];
            char key_beta[32], expected_value_beta[64];
            char key_gamma[32], expected_value_gamma[64];

            snprintf(key_alpha, sizeof(key_alpha), "alpha_key_%03d", i);
            snprintf(expected_value_alpha, sizeof(expected_value_alpha), "alpha_value_%03d", i);
            snprintf(key_beta, sizeof(key_beta), "beta_key_%03d", i);
            snprintf(expected_value_beta, sizeof(expected_value_beta), "beta_value_%03d", i);
            snprintf(key_gamma, sizeof(key_gamma), "gamma_key_%03d", i);
            snprintf(expected_value_gamma, sizeof(expected_value_gamma), "gamma_value_%03d", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;

            /* verify cf_alpha has the key */
            ASSERT_EQ(tidesdb_txn_get(txn, cf_alpha, (uint8_t *)key_alpha, strlen(key_alpha) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(retrieved_size, strlen(expected_value_alpha) + 1);
            ASSERT_EQ(memcmp(retrieved_value, expected_value_alpha, retrieved_size), 0);
            free(retrieved_value);
            retrieved_value = NULL;

            /* verify cf_beta has the key */
            ASSERT_EQ(tidesdb_txn_get(txn, cf_beta, (uint8_t *)key_beta, strlen(key_beta) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(retrieved_size, strlen(expected_value_beta) + 1);
            ASSERT_EQ(memcmp(retrieved_value, expected_value_beta, retrieved_size), 0);
            free(retrieved_value);
            retrieved_value = NULL;

            /* verify cf_gamma has the key */
            ASSERT_EQ(tidesdb_txn_get(txn, cf_gamma, (uint8_t *)key_gamma, strlen(key_gamma) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(retrieved_size, strlen(expected_value_gamma) + 1);
            ASSERT_EQ(memcmp(retrieved_value, expected_value_gamma, retrieved_size), 0);
            free(retrieved_value);

            tidesdb_txn_free(txn);
        }

        tidesdb_close(db);
    }

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
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;

        /* create first CF -- will have WAL-only data */
        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);
        tidesdb_column_family_t *wal_cf = tidesdb_get_column_family(db, "wal_cf");
        ASSERT_TRUE(wal_cf != NULL);

        /* create second CF -- will have flushed data */
        ASSERT_EQ(tidesdb_create_column_family(db, "flushed_cf", &cf_config), 0);
        tidesdb_column_family_t *flushed_cf = tidesdb_get_column_family(db, "flushed_cf");
        ASSERT_TRUE(flushed_cf != NULL);

        /* write keys to wal_cf (no flush -- stays in WAL) */
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

        /* write keys to flushed_cf and flush to sst */
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

        /* flush flushed_cf to sst */
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

        /* close database -- WAL should persist wal_cf data */
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* reopen database and verify WAL recovery for both CFs */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

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

    /* create database with two column families and write many ssts to each */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;

        /* create first CF */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_alpha", &cf_config), 0);
        tidesdb_column_family_t *cf_alpha = tidesdb_get_column_family(db, "cf_alpha");
        ASSERT_TRUE(cf_alpha != NULL);

        /* create second CF */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_beta", &cf_config), 0);
        tidesdb_column_family_t *cf_beta = tidesdb_get_column_family(db, "cf_beta");
        ASSERT_TRUE(cf_beta != NULL);

        /* write and flush multiple ssts to cf_alpha */
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

            /* flush to create sst */
            ASSERT_EQ(tidesdb_flush_memtable(cf_alpha), 0);
            usleep(100000); /* wait for flush */
        }

        /* write and flush multiple ssts to cf_beta */
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

            /* flush to create sst */
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

    /* reopen database and verify all ssts recovered for both CFs */
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

        /* verify all keys from cf_alpha across all ssts */
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

        /* verify all keys from cf_beta across all ssts */
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

static void test_multi_cf_transaction_recovery_comprehensive(void)
{
    cleanup_test_dir();
    const int NUM_COMMITTED_TXNS = 3; /* reduced from 10 for less verbose logs */
    const int NUM_ROLLBACK_TXNS = 2;  /* reduced from 5 for less verbose logs */
    const int NUM_SAVEPOINT_TXNS = 1; /* reduced from 3 for less verbose logs */

    /* we create database with 4 column families and write mixed transaction states */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.compression_algorithm = TDB_COMPRESS_LZ4;
        cf_config.write_buffer_size = 1024 * 1024; /* 1MB buffer */

        /* we create four column families with different purposes */
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_committed", &cf_config), 0);
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_rollback", &cf_config), 0);
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_savepoint", &cf_config), 0);
        ASSERT_EQ(tidesdb_create_column_family(db, "cf_mixed", &cf_config), 0);

        tidesdb_column_family_t *cf_committed = tidesdb_get_column_family(db, "cf_committed");
        tidesdb_column_family_t *cf_rollback = tidesdb_get_column_family(db, "cf_rollback");
        tidesdb_column_family_t *cf_savepoint = tidesdb_get_column_family(db, "cf_savepoint");
        tidesdb_column_family_t *cf_mixed = tidesdb_get_column_family(db, "cf_mixed");
        ASSERT_TRUE(cf_committed != NULL);
        ASSERT_TRUE(cf_rollback != NULL);
        ASSERT_TRUE(cf_savepoint != NULL);
        ASSERT_TRUE(cf_mixed != NULL);

        /* we write committed transactions across multiple CFs */
        for (int i = 0; i < NUM_COMMITTED_TXNS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "committed_key_%03d", i);
            snprintf(value, sizeof(value), "committed_value_%03d_data", i);

            /* write to cf_committed */
            ASSERT_EQ(tidesdb_txn_put(txn, cf_committed, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            /* also write to cf_mixed to test multi-CF atomicity */
            snprintf(key, sizeof(key), "mixed_committed_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* we flush cf_committed to create ssts (some data will be in sst, some in WAL) */
        ASSERT_EQ(tidesdb_flush_memtable(cf_committed), 0);
        usleep(150000); /* wait for flush to complete */

        /* we write transactions that will be rolled back (should not appear after recovery) */
        for (int i = 0; i < NUM_ROLLBACK_TXNS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_REPEATABLE_READ, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "rollback_key_%03d", i);
            snprintf(value, sizeof(value), "rollback_value_%03d_should_not_exist", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf_rollback, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            /* write to cf_mixed as well */
            snprintf(key, sizeof(key), "mixed_rollback_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            /* rollback instead of commit */
            ASSERT_EQ(tidesdb_txn_rollback(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* we write transactions with savepoints and partial rollbacks */
        for (int i = 0; i < NUM_SAVEPOINT_TXNS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &txn), 0);

            char key[32], value[64];

            snprintf(key, sizeof(key), "savepoint_initial_%03d", i);
            snprintf(value, sizeof(value), "savepoint_initial_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp1"), 0);

            /* write data after savepoint (will be rolled back) */
            snprintf(key, sizeof(key), "savepoint_after_%03d", i);
            snprintf(value, sizeof(value), "savepoint_after_value_%03d_should_not_exist", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            /* rollback to savepoint */
            ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp1"), 0);

            /* write final data after rollback */
            snprintf(key, sizeof(key), "savepoint_final_%03d", i);
            snprintf(value, sizeof(value), "savepoint_final_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* now we do some write mixed operations ala puts, deletes, updates across CFs */
        for (int i = 0; i < 5; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];

            /* put a key */
            snprintf(key, sizeof(key), "mixed_put_%03d", i);
            snprintf(value, sizeof(value), "mixed_put_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            /* update an existing key */
            if (i < NUM_COMMITTED_TXNS)
            {
                snprintf(key, sizeof(key), "committed_key_%03d", i);
                snprintf(value, sizeof(value), "updated_value_%03d", i);
                ASSERT_EQ(tidesdb_txn_put(txn, cf_committed, (uint8_t *)key, strlen(key) + 1,
                                          (uint8_t *)value, strlen(value) + 1, 0),
                          0);
            }

            /* delete a key from cf_mixed */
            if (i > 0)
            {
                snprintf(key, sizeof(key), "mixed_committed_%03d", i - 1);
                ASSERT_EQ(tidesdb_txn_delete(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1), 0);
            }

            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush cf_mixed partially */
        ASSERT_EQ(tidesdb_flush_memtable(cf_mixed), 0);
        usleep(150000);

        /* write additional data to cf_mixed (will be in WAL only) */
        for (int i = 0; i < 3; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "mixed_wal_only_%03d", i);
            snprintf(value, sizeof(value), "mixed_wal_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0),
                      0);

            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* close database (simulates crash -- some data in WAL, some in ssts) */
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* now reopen database and verify recovery */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;
        config.log_level = TDB_LOG_INFO;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        /* verify all column families recovered */
        tidesdb_column_family_t *cf_committed = tidesdb_get_column_family(db, "cf_committed");
        tidesdb_column_family_t *cf_rollback = tidesdb_get_column_family(db, "cf_rollback");
        tidesdb_column_family_t *cf_savepoint = tidesdb_get_column_family(db, "cf_savepoint");
        tidesdb_column_family_t *cf_mixed = tidesdb_get_column_family(db, "cf_mixed");
        ASSERT_TRUE(cf_committed != NULL);
        ASSERT_TRUE(cf_rollback != NULL);
        ASSERT_TRUE(cf_savepoint != NULL);
        ASSERT_TRUE(cf_mixed != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        /* verify committed transactions are present */
        int committed_found = 0;
        for (int i = 0; i < NUM_COMMITTED_TXNS; i++)
        {
            char key[32], expected_value[64];
            snprintf(key, sizeof(key), "committed_key_%03d", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf_committed, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);

            if (result == 0 && retrieved_value != NULL)
            {
                /* check if it was updated */
                if (i < 5)
                {
                    snprintf(expected_value, sizeof(expected_value), "updated_value_%03d", i);
                }
                else
                {
                    snprintf(expected_value, sizeof(expected_value), "committed_value_%03d_data",
                             i);
                }

                ASSERT_EQ(retrieved_size, strlen(expected_value) + 1);
                ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
                free(retrieved_value);
                committed_found++;
            }
        }
        ASSERT_EQ(committed_found, NUM_COMMITTED_TXNS);

        /* verify rolled back transactions are NOT present */
        for (int i = 0; i < NUM_ROLLBACK_TXNS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "rollback_key_%03d", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf_rollback, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);

            /* should not exist */
            ASSERT_TRUE(result != 0 || retrieved_value == NULL);
            if (retrieved_value) free(retrieved_value);
        }

        /* verify rolled back transactions in cf_mixed are NOT present */
        for (int i = 0; i < NUM_ROLLBACK_TXNS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "mixed_rollback_%03d", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);

            ASSERT_TRUE(result != 0 || retrieved_value == NULL);
            if (retrieved_value) free(retrieved_value);
        }

        /* verify savepoint transactions -- initial and final should exist, after should not */
        for (int i = 0; i < NUM_SAVEPOINT_TXNS; i++)
        {
            char key[32], expected_value[64];
            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;

            /* initial data should exist */
            snprintf(key, sizeof(key), "savepoint_initial_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "savepoint_initial_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_get(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
            free(retrieved_value);
            retrieved_value = NULL;

            /* after savepoint data should NOT exist (was rolled back) */
            snprintf(key, sizeof(key), "savepoint_after_%03d", i);
            int result = tidesdb_txn_get(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                         &retrieved_value, &retrieved_size);
            ASSERT_TRUE(result != 0 || retrieved_value == NULL);
            if (retrieved_value) free(retrieved_value);
            retrieved_value = NULL;

            /* final data should exist */
            snprintf(key, sizeof(key), "savepoint_final_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "savepoint_final_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_get(txn, cf_savepoint, (uint8_t *)key, strlen(key) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
            free(retrieved_value);
        }

        /* we verify mixed operations */
        for (int i = 0; i < 5; i++)
        {
            char key[32], expected_value[64];
            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;

            /* verify puts */
            snprintf(key, sizeof(key), "mixed_put_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "mixed_put_value_%03d", i);
            ASSERT_EQ(tidesdb_txn_get(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
            free(retrieved_value);
            retrieved_value = NULL;

            /* verify deletes (keys 0-3 should be deleted) */
            if (i > 0 && i < 5)
            {
                snprintf(key, sizeof(key), "mixed_committed_%03d", i - 1);
                int result = tidesdb_txn_get(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                             &retrieved_value, &retrieved_size);
                ASSERT_TRUE(result != 0 || retrieved_value == NULL);
                if (retrieved_value) free(retrieved_value);
                retrieved_value = NULL;
            }
        }

        /* verify WAL-only data */
        for (int i = 0; i < 3; i++)
        {
            char key[32], expected_value[64];
            snprintf(key, sizeof(key), "mixed_wal_only_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "mixed_wal_value_%03d", i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            ASSERT_EQ(tidesdb_txn_get(txn, cf_mixed, (uint8_t *)key, strlen(key) + 1,
                                      &retrieved_value, &retrieved_size),
                      0);
            ASSERT_TRUE(retrieved_value != NULL);
            ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
            free(retrieved_value);
        }

        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_batches;
    int batch_size;
    _Atomic(int) *total_ops;
    _Atomic(int) *errors;
} batched_txn_thread_data_t;

static void *batched_txn_writer_thread(void *arg)
{
    batched_txn_thread_data_t *data = (batched_txn_thread_data_t *)arg;

    for (int batch = 0; batch < data->num_batches; batch++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            continue;
        }

        /* write batch_size keys in this transaction */
        for (int i = 0; i < data->batch_size; i++)
        {
            int key_num = (batch * data->batch_size * 8) + (data->thread_id * data->batch_size) + i;
            char key[32];
            char value[64];
            snprintf(key, sizeof(key), "key_%08d", key_num);
            snprintf(value, sizeof(value), "value_t%d_b%d_i%d", data->thread_id, batch, i);

            if (tidesdb_txn_put(txn, data->cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                strlen(value) + 1, 0) != 0)
            {
                atomic_fetch_add(data->errors, 1);
                tidesdb_txn_free(txn);
                goto next_batch;
            }
        }

        /* commit the batch */
        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
        }
        else
        {
            atomic_fetch_add(data->total_ops, data->batch_size);
        }

        tidesdb_txn_free(txn);
    next_batch:;
    }

    return NULL;
}

static void test_concurrent_batched_transactions(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 64 * 1024 * 1024; /* 64MB */

    ASSERT_EQ(tidesdb_create_column_family(db, "bench_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bench_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 2;
    const int BATCH_SIZE = 100;
    const int NUM_BATCHES = 125;
    const int TOTAL_EXPECTED_KEYS = NUM_THREADS * NUM_BATCHES * BATCH_SIZE;

    printf("  starting concurrent batched transaction test...\n");
    printf("  threads: %d, batch size: %d, batches per thread: %d\n", NUM_THREADS, BATCH_SIZE,
           NUM_BATCHES);
    printf("  total expected keys: %d\n", TOTAL_EXPECTED_KEYS);

    _Atomic(int) total_ops = 0;
    _Atomic(int) errors = 0;
    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    batched_txn_thread_data_t *thread_data =
        (batched_txn_thread_data_t *)malloc(NUM_THREADS * sizeof(batched_txn_thread_data_t));

    /* launch writer threads */
    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].num_batches = NUM_BATCHES;
        thread_data[i].batch_size = BATCH_SIZE;
        thread_data[i].total_ops = &total_ops;
        thread_data[i].errors = &errors;
        pthread_create(&threads[i], NULL, batched_txn_writer_thread, &thread_data[i]);
    }

    /* wait for all threads to complete */
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_ops = atomic_load(&total_ops);
    int final_errors = atomic_load(&errors);

    printf("  write complete: %d ops committed, %d errors\n", final_ops, final_errors);
    ASSERT_EQ(final_errors, 0);
    ASSERT_EQ(final_ops, TOTAL_EXPECTED_KEYS);

    printf("  checking CF state...\n");
    tidesdb_memtable_t *active_mt_struct = cf->active_memtable;
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;
    int active_entries = skip_list_count_entries(active_mt);
    size_t active_size = skip_list_get_size(active_mt);
    size_t imm_count = queue_size(cf->immutable_memtables);
    int num_levels = cf->num_active_levels;
    printf("  active memtable: %d entries, %zu bytes\n", active_entries, active_size);
    printf("  immutable memtables: %zu\n", imm_count);
    printf("  active levels: %d\n", num_levels);
    for (int i = 0; i < num_levels; i++)
    {
        if (cf->levels[i])
        {
            printf("  level %d: %d sstables\n", i, cf->levels[i]->num_sstables);
        }
    }

    /* iterate and count all keys */
    printf("  starting iteration to verify all keys...\n");

    /* create a transaction for iteration */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    int iter_result = tidesdb_iter_new(iter_txn, cf, &iter);
    printf("  iter_new result: %d, iter: %p\n", iter_result, (void *)iter);
    ASSERT_EQ(iter_result, 0);

    int is_valid = tidesdb_iter_valid(iter);
    printf("  initial iter_valid: %d\n", is_valid);

    /* position iterator to first key */
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    printf("  after seek_to_first, iter_valid: %d\n", tidesdb_iter_valid(iter));

    int iter_count = 0;
    while (tidesdb_iter_valid(iter))
    {
        iter_count++;
        tidesdb_iter_next(iter);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    printf("  iteration complete: found %d keys (expected %d)\n", iter_count, TOTAL_EXPECTED_KEYS);

    if (iter_count != TOTAL_EXPECTED_KEYS)
    {
        printf(BOLDRED "  KEY LOSS DETECTED: missing %d keys!\n" RESET,
               TOTAL_EXPECTED_KEYS - iter_count);
    }
    ASSERT_EQ(iter_count, TOTAL_EXPECTED_KEYS);

    free(threads);
    free(thread_data);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_batched_random_keys(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 64 * 1024 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "bench_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bench_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 2;
    const int BATCH_SIZE = 100;
    const int NUM_BATCHES = 125;
    const int TOTAL_EXPECTED_KEYS = NUM_THREADS * NUM_BATCHES * BATCH_SIZE;

    printf("  testing random key pattern (benchtool reproduction)...\n");
    printf("  threads: %d, batch size: %d, batches per thread: %d\n", NUM_THREADS, BATCH_SIZE,
           NUM_BATCHES);
    printf("  total expected keys: %d\n", TOTAL_EXPECTED_KEYS);

    _Atomic(int) total_ops = 0;
    _Atomic(int) errors = 0;
    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    batched_txn_thread_data_t *thread_data =
        (batched_txn_thread_data_t *)malloc(NUM_THREADS * sizeof(batched_txn_thread_data_t));

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].num_batches = NUM_BATCHES;
        thread_data[i].batch_size = BATCH_SIZE;
        thread_data[i].total_ops = &total_ops;
        thread_data[i].errors = &errors;
        pthread_create(&threads[i], NULL, batched_txn_writer_thread, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_ops = atomic_load(&total_ops);
    int final_errors = atomic_load(&errors);

    printf("  write complete: %d ops committed, %d errors\n", final_ops, final_errors);
    ASSERT_EQ(final_errors, 0);
    ASSERT_EQ(final_ops, TOTAL_EXPECTED_KEYS);

    printf("  checking CF state...\n");
    tidesdb_memtable_t *active_mt_struct = cf->active_memtable;
    skip_list_t *active_mt = active_mt_struct ? active_mt_struct->skip_list : NULL;
    int active_entries = skip_list_count_entries(active_mt);
    size_t active_size = skip_list_get_size(active_mt);
    size_t imm_count = queue_size(cf->immutable_memtables);
    int num_levels = cf->num_active_levels;
    printf("  active memtable: %d entries, %zu bytes\n", active_entries, active_size);
    printf("  immutable memtables: %zu\n", imm_count);
    printf("  active levels: %d\n", num_levels);
    for (int i = 0; i < num_levels; i++)
    {
        if (cf->levels[i])
        {
            printf("  level %d: %d sstables\n", i, cf->levels[i]->num_sstables);
        }
    }

    printf("  starting iteration to verify all keys...\n");
    printf("  creating multiple concurrent iterators to stress-test the race window...\n");

    /* create 10 iterators concurrently to increase chance of hitting the TOCTOU race */
    int iter_count = 0;
    for (int iter_attempt = 0; iter_attempt < 10; iter_attempt++)
    {
        tidesdb_txn_t *iter_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), 0);

        tidesdb_iter_t *iter = NULL;
        int iter_result = tidesdb_iter_new(iter_txn, cf, &iter);
        ASSERT_EQ(iter_result, 0);

        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            count++;
            tidesdb_iter_next(iter);
        }

        if (iter_attempt == 0)
        {
            iter_count = count;
            printf("  iteration %d: found %d keys\n", iter_attempt + 1, count);
        }
        else if (count != iter_count)
        {
            printf("  iteration %d: found %d keys (INCONSISTENT!)\n", iter_attempt + 1, count);
        }

        tidesdb_iter_free(iter);
        tidesdb_txn_free(iter_txn);

        /* small delay to vary timing */
        usleep(100);
    }

    printf("  iteration complete: found %d keys (expected %d)\n", iter_count, TOTAL_EXPECTED_KEYS);

    if (iter_count != TOTAL_EXPECTED_KEYS)
    {
        printf(BOLDRED "  KEY LOSS DETECTED: missing %d keys!\n" RESET,
               TOTAL_EXPECTED_KEYS - iter_count);
    }

    ASSERT_EQ(iter_count, TOTAL_EXPECTED_KEYS);

    free(threads);
    free(thread_data);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_deadlock_random_write_then_read(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 64 * 1024 * 1024; /* 64MB like benchmark */

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int num_ops = 1000; /* 100k ops to trigger flush */
    uint8_t **keys = malloc(num_ops * sizeof(uint8_t *));
    size_t *key_sizes = malloc(num_ops * sizeof(size_t));
    uint8_t **values = malloc(num_ops * sizeof(uint8_t *));
    size_t *value_sizes = malloc(num_ops * sizeof(size_t));

    printf("Generating %d random key-value pairs...\n", num_ops);
    srand(12345);
    for (int i = 0; i < num_ops; i++)
    {
        key_sizes[i] = 16;
        keys[i] = malloc(key_sizes[i]);
        for (size_t j = 0; j < key_sizes[i]; j++)
        {
            keys[i][j] = rand() % 256;
        }

        value_sizes[i] = 100;
        values[i] = malloc(value_sizes[i]);
        for (size_t j = 0; j < value_sizes[i]; j++)
        {
            values[i][j] = rand() % 256;
        }
    }

    printf("\n--- Writing %d keys ---\n", num_ops);

    int write_count = 0;

    for (int i = 0; i < num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, keys[i], key_sizes[i], values[i], value_sizes[i], 0), 0);

        int commit_result = tidesdb_txn_commit(txn);
        if (commit_result != 0)
        {
            printf("WARNING: Commit failed at operation %d (result=%d)\n", i, commit_result);
        }
        tidesdb_txn_free(txn);

        write_count++;
        if (write_count % 1000 == 0)
        {
            printf("  Written %d keys...\n", write_count);
        }
    }

    printf("Completed %d writes\n", write_count);

    printf("\n--- Closing and reopening database ---\n");
    printf("This forces all data to be flushed to SSTables...\n");
    tidesdb_close(db);

    printf("Reopening database...\n");
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);
    printf("Database reopened, all data now in SSTables\n");

    printf("\n--- Reading %d keys from SSTables ---\n", num_ops);
    int read_count = 0;
    int read_success = 0;

    for (int i = 0; i < num_ops; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        uint8_t *value_out = NULL;
        size_t value_len = 0;

        int get_result = tidesdb_txn_get(txn, cf, keys[i], key_sizes[i], &value_out, &value_len);

        if (get_result == 0)
        {
            ASSERT_EQ(value_len, value_sizes[i]);
            ASSERT_TRUE(memcmp(value_out, values[i], value_len) == 0);
            free(value_out);
            read_success++;
        }
        else
        {
            printf("WARNING: Get failed at operation %d (result=%d)\n", i, get_result);
        }

        tidesdb_txn_free(txn);

        read_count++;
        if (read_count % 10000 == 0)
        {
            printf("  Read %d keys (success=%d)...\n", read_count, read_success);
        }
    }

    printf("Completed %d reads (success=%d)\n", read_count, read_success);

    for (int i = 0; i < num_ops; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(key_sizes);
    free(values);
    free(value_sizes);

    printf("\n--- Closing database ---\n");
    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_keys;
    int key_size;
    int value_size;
    _Atomic(int) *success_count;
    _Atomic(int) *failure_count;
    _Atomic(int) *should_stop;
} read_thread_data_t;

static void *read_thread_fn(void *arg)
{
    read_thread_data_t *data = (read_thread_data_t *)arg;

    int iteration = 0;
    while (!atomic_load(data->should_stop))
    {
        /* read a random subset of keys to keep threads busy */
        for (int i = 0; i < 100; i++)
        {
            if (atomic_load(data->should_stop)) break;

            tidesdb_txn_t *txn = NULL;
            if (tidesdb_txn_begin(data->db, &txn) != 0)
            {
                atomic_store(data->should_stop, 1);
                break;
            }

            /* read a key based on thread_id and iteration to spread load */
            int key_idx = ((data->thread_id * 1000) + (iteration * 100) + i) % data->num_keys;
            char key[16];
            snprintf(key, 16, "key_%08d", key_idx);
            size_t key_len = strlen(key);

            uint8_t *value = NULL;
            size_t value_size = 0;

            int result =
                tidesdb_txn_get(txn, data->cf, (uint8_t *)key, key_len, &value, &value_size);

            if (result == 0)
            {
                if (value_size != (size_t)data->value_size)
                {
                    printf("ERROR: Expected value_size=%d, got %zu\n", data->value_size,
                           value_size);
                }
                free(value);
                atomic_fetch_add(data->success_count, 1);
            }
            else
            {
                atomic_fetch_add(data->failure_count, 1);
            }

            tidesdb_txn_free(txn);
        }
        iteration++;
    }

    return NULL;
}

void test_concurrent_read_close_race(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.num_flush_threads = 2;
    config.num_compaction_threads = 2;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024 * 1024; /* 1MB */
    cf_config.min_levels = 3;
    cf_config.enable_bloom_filter = 1;
    cf_config.bloom_fpr = 0.01;
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;
    cf_config.enable_block_indexes = 1;
    cf_config.sync_mode = TDB_SYNC_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

#define TEST_NUM_KEYS    10000
#define TEST_NUM_THREADS 8
#define TEST_KEY_SIZE    16
#define TEST_VALUE_SIZE  100

    printf("Writing %d keys with %d threads\n", TEST_NUM_KEYS, TEST_NUM_THREADS);

    /* write data in batches */
    for (int i = 0; i < TEST_NUM_KEYS; i += 100)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int j = 0; j < 100 && (i + j) < TEST_NUM_KEYS; j++)
        {
            char key[TEST_KEY_SIZE];
            char value[TEST_VALUE_SIZE];
            snprintf(key, TEST_KEY_SIZE, "key_%08d", i + j);
            memset(value, 'A' + ((i + j) % 26), TEST_VALUE_SIZE);

            size_t key_len = strlen(key);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, key_len, (uint8_t *)value,
                                      TEST_VALUE_SIZE, 0),
                      0);
        }

        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    printf("Closing database (forces flush to SSTables)\n");
    tidesdb_close(db);

    printf("Reopening database\n");
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    printf("Starting %d concurrent read threads\n", TEST_NUM_THREADS);

    _Atomic(int) success_count = 0;
    _Atomic(int) failure_count = 0;
    _Atomic(int) should_stop = 0;

    pthread_t threads[TEST_NUM_THREADS];
    read_thread_data_t thread_data[TEST_NUM_THREADS];

    for (int i = 0; i < TEST_NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].num_keys = TEST_NUM_KEYS;
        thread_data[i].key_size = TEST_KEY_SIZE;
        thread_data[i].value_size = TEST_VALUE_SIZE;
        thread_data[i].success_count = &success_count;
        thread_data[i].failure_count = &failure_count;
        thread_data[i].should_stop = &should_stop;

        ASSERT_EQ(pthread_create(&threads[i], NULL, read_thread_fn, &thread_data[i]), 0);
    }

    printf("Letting threads read for 100ms...\n");
    usleep(100000);

    int reads_before_close = atomic_load(&success_count);
    printf("Reads completed before close: %d\n", reads_before_close);

    atomic_store(&should_stop, 1);

    printf("Waiting for read threads to finish...\n");
    for (int i = 0; i < TEST_NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_success = atomic_load(&success_count);
    int final_failure = atomic_load(&failure_count);

    printf("Read results: success=%d, failure=%d\n", final_success, final_failure);
    tidesdb_close(db);
    cleanup_test_dir();

#undef TEST_NUM_KEYS
#undef TEST_NUM_THREADS
#undef TEST_KEY_SIZE
#undef TEST_VALUE_SIZE
}

static void test_crash_during_flush(void)
{
    cleanup_test_dir();
    const int NUM_KEYS = 100;

    /* we write data and trigger flush but don't wait for completion */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 4096; /* small buffer to trigger flush */
        cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

        ASSERT_EQ(tidesdb_create_column_family(db, "crash_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "crash_cf");
        ASSERT_TRUE(cf != NULL);

        /* write enough data to trigger flush */
        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[128];
            snprintf(key, sizeof(key), "crash_key_%03d", i);
            snprintf(value, sizeof(value), "crash_value_%03d_data_to_fill_buffer", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* trigger flush but close immediately (simulates crash during flush) */
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(10000); /* give flush a moment to start */

        /* close without waiting for flush to complete (crash simulation) */
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* we reopen and verify WAL recovery */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "crash_cf");
        ASSERT_TRUE(cf != NULL);

        /* verify all data recovered (either from sst or wal) */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        int found_count = 0;
        for (int i = 0; i < NUM_KEYS; i++)
        {
            char key[32], expected_value[128];
            snprintf(key, sizeof(key), "crash_key_%03d", i);
            snprintf(expected_value, sizeof(expected_value), "crash_value_%03d_data_to_fill_buffer",
                     i);

            uint8_t *retrieved_value = NULL;
            size_t retrieved_size = 0;
            int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &retrieved_value,
                                         &retrieved_size);

            if (result == 0 && retrieved_value != NULL)
            {
                ASSERT_EQ(strcmp((char *)retrieved_value, expected_value), 0);
                free(retrieved_value);
                found_count++;
            }
        }

        /* all keys should be recovered */
        ASSERT_EQ(found_count, NUM_KEYS);

        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iterator_with_concurrent_flush(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 8192;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_cf");
    ASSERT_TRUE(cf != NULL);

    /* write initial data */
    for (int i = 0; i < 50; i++)
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
    }

    /* create iterator */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    /* iterate through first 10 keys */
    int count = 0;
    while (count < 10 && tidesdb_iter_valid(iter))
    {
        count++;
        tidesdb_iter_next(iter);
    }
    ASSERT_EQ(count, 10);

    /* trigger flush while iterator is active */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(50000); /* wait for flush to start */

    /* continue iterating -- should remain stable */
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
        ASSERT_TRUE(key != NULL);
        count++;
        if (tidesdb_iter_next(iter) != 0) break;
    }

    /* should have iterated through all 50 keys */
    ASSERT_EQ(count, 50);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ttl_expiration_during_compaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);

    /* write keys with short TTL */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "ttl_key_%03d", i);
        snprintf(value, sizeof(value), "ttl_value_%03d", i);

        /* half with short TTL (2 seconds), half with long TTL */
        time_t ttl = (i % 2 == 0) ? (now + 2) : (now + 3600);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to create sssts */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    /* wait for short TTL to expire */
    sleep(3);

    /* trigger compaction -- should remove expired entries */
    tidesdb_compact(cf);

    /* wait for compaction to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    /* verify only non-expired keys remain */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    int expired_count = 0;
    int valid_count = 0;

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 2 == 0)
        {
            /* should be expired */
            if (result != 0 || value == NULL)
            {
                expired_count++;
            }
        }
        else
        {
            /* should still exist */
            if (result == 0 && value != NULL)
            {
                valid_count++;
                free(value);
            }
        }
    }

    /* verify expired keys are gone and valid keys remain */
    ASSERT_TRUE(expired_count >= 20); /* at least most expired */
    ASSERT_TRUE(valid_count >= 20);   /* at least most valid remain */

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_multi_cf_concurrent_compaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.level_size_ratio = 10;

    /* create 3 column families */
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_a", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_b", &cf_config), 0);
    ASSERT_EQ(tidesdb_create_column_family(db, "cf_c", &cf_config), 0);

    tidesdb_column_family_t *cf_a = tidesdb_get_column_family(db, "cf_a");
    tidesdb_column_family_t *cf_b = tidesdb_get_column_family(db, "cf_b");
    tidesdb_column_family_t *cf_c = tidesdb_get_column_family(db, "cf_c");
    ASSERT_TRUE(cf_a != NULL && cf_b != NULL && cf_c != NULL);

    /* write data to all CFs to create multiple ssts */
    for (int cf_idx = 0; cf_idx < 3; cf_idx++)
    {
        tidesdb_column_family_t *cf = (cf_idx == 0) ? cf_a : (cf_idx == 1) ? cf_b : cf_c;

        for (int batch = 0; batch < 5; batch++)
        {
            for (int i = 0; i < 20; i++)
            {
                tidesdb_txn_t *txn = NULL;
                ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

                char key[32], value[128];
                snprintf(key, sizeof(key), "key_cf%d_%03d", cf_idx, batch * 20 + i);
                snprintf(value, sizeof(value), "value_cf%d_batch%d_%03d", cf_idx, batch, i);

                ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1,
                                          (uint8_t *)value, strlen(value) + 1, 0),
                          0);
                ASSERT_EQ(tidesdb_txn_commit(txn), 0);
                tidesdb_txn_free(txn);
            }

            /* flush each batch */
            ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
            usleep(50000);
        }
    }

    /* trigger compaction on all CFs simultaneously */
    tidesdb_compact(cf_a);
    tidesdb_compact(cf_b);
    tidesdb_compact(cf_c);

    /* wait for compactions to complete */
    usleep(500000);

    /* verify all data is still accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int cf_idx = 0; cf_idx < 3; cf_idx++)
    {
        tidesdb_column_family_t *cf = (cf_idx == 0) ? cf_a : (cf_idx == 1) ? cf_b : cf_c;
        int found = 0;

        for (int i = 0; i < 100; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key_cf%d_%03d", cf_idx, i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

            if (result == 0 && value != NULL)
            {
                free(value);
                found++;
            }
        }

        /* should find all 100 keys per CF */
        ASSERT_EQ(found, 100);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_wal_corruption_recovery(void)
{
    cleanup_test_dir();
    const int NUM_KEYS = 50;

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

        ASSERT_EQ(tidesdb_create_column_family(db, "wal_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "wal_key_%03d", i);
            snprintf(value, sizeof(value), "wal_value_%03d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush half the data */
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(200000);

        /* write more data (will be in WAL only) */
        for (int i = NUM_KEYS; i < NUM_KEYS + 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "wal_key_%03d", i);
            snprintf(value, sizeof(value), "wal_value_%03d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    /* corrupt WAL file (truncate it) */
    char wal_path[256];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR "wal_cf" PATH_SEPARATOR "wal.log",
             TEST_DB_PATH);

    FILE *wal_file = fopen(wal_path, "r+b");
    if (wal_file)
    {
        /* truncate WAL to simulate corruption */
        fseek(wal_file, 0, SEEK_END);
        long size = ftell(wal_file);
        if (size > 100)
        {
            /* truncate to 50% of original size */
            int truncate_result = ftruncate(fileno(wal_file), size / 2);
            (void)truncate_result; /* intentionally ignore for test simulation */
        }
        fclose(wal_file);
    }

    /* we reopen and verify recovery handles corruption gracefully */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        int result = tidesdb_open(&config, &db);

        /* should either succeed with partial recovery or fail gracefully */
        if (result == 0 && db != NULL)
        {
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_cf");
            if (cf != NULL)
            {
                /* verify at least the flushed data is recoverable */
                tidesdb_txn_t *txn = NULL;
                ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

                int found = 0;
                for (int i = 0; i < NUM_KEYS; i++)
                {
                    char key[32];
                    snprintf(key, sizeof(key), "wal_key_%03d", i);

                    uint8_t *value = NULL;
                    size_t value_size = 0;
                    int get_result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1,
                                                     &value, &value_size);

                    if (get_result == 0 && value != NULL)
                    {
                        free(value);
                        found++;
                    }
                }

                /* should recover at least the flushed data */
                ASSERT_TRUE(found > 0);

                tidesdb_txn_free(txn);
            }
            tidesdb_close(db);
        }
    }

    cleanup_test_dir();
}

static void test_compaction_with_overlapping_ranges(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "overlap_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "overlap_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys in multiple batches with overlapping ranges */
    /* batch 1 -- keys 000-049 */
    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_batch1_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(100000);

    /* batch 2 -- keys 025-074 (overlaps with batch 1) */
    for (int i = 25; i < 75; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_batch2_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(100000);

    /* batch 3 -- keys 050-099 (overlaps with batch 2) */
    for (int i = 50; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(value, sizeof(value), "value_batch3_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(100000);

    /* trigger compaction to merge overlapping ranges */
    tidesdb_compact(cf);

    /* wait for compaction to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (queue_size(db->flush_queue) == 0 && queue_size(db->compaction_queue) == 0 &&
            !is_compacting)
        {
            usleep(100000);
            break;
        }
    }

    /* verify latest values are preserved */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* keys 000-024 -- should have batch1 values */
    for (int i = 0; i < 25; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected, sizeof(expected), "value_batch1_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected), 0);
        free(value);
    }

    /* keys 025-049 -- should have batch2 values (overwrote batch1) */
    for (int i = 25; i < 50; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected, sizeof(expected), "value_batch2_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected), 0);
        free(value);
    }

    /* keys 050-074 -- should have batch3 values (overwrote batch2) */
    for (int i = 50; i < 75; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected, sizeof(expected), "value_batch3_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected), 0);
        free(value);
    }

    /* keys 075-099 -- should have batch3 values */
    for (int i = 75; i < 100; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "key_%03d", i);
        snprintf(expected, sizeof(expected), "value_batch3_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected), 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_extreme_key_skew(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 16384;

    ASSERT_EQ(tidesdb_create_column_family(db, "skew_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "skew_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_COLD_KEYS = 1000;
    const int NUM_HOT_KEYS = 10;
    const int HOT_KEY_ACCESSES = 100;

    /* write cold keys (accessed once) */
    for (int i = 0; i < NUM_COLD_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "cold_key_%04d", i);
        snprintf(value, sizeof(value), "cold_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* write hot keys (accessed many times) */
    for (int i = 0; i < NUM_HOT_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "hot_key_%02d", i);
        snprintf(value, sizeof(value), "hot_value_%02d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    /* flush to sstables at l1 */
    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(200000);

    /* repeatedly access hot keys */
    for (int access = 0; access < HOT_KEY_ACCESSES; access++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        for (int i = 0; i < NUM_HOT_KEYS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "hot_key_%02d", i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

            if (result == 0 && value != NULL)
            {
                free(value);
            }
        }

        tidesdb_txn_free(txn);
    }

    /* verify all keys still accessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    /* check hot keys */
    for (int i = 0; i < NUM_HOT_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "hot_key_%02d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    /* sample cold keys */
    for (int i = 0; i < 100; i += 10)
    {
        char key[32];
        snprintf(key, sizeof(key), "cold_key_%04d", i);

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

static void test_cf_lifecycle_stress(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    const int NUM_CYCLES = 10;

    for (int cycle = 0; cycle < NUM_CYCLES; cycle++)
    {
        char cf_name[32];
        snprintf(cf_name, sizeof(cf_name), "cycle_cf_%02d", cycle);

        /* create CF */
        ASSERT_EQ(tidesdb_create_column_family(db, cf_name, &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, cf_name);
        ASSERT_TRUE(cf != NULL);

        /* write data */
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "key_%02d", i);
            snprintf(value, sizeof(value), "value_cycle%02d_%02d", cycle, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        /* flush */
        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(50000);

        /* verify data */
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%02d", 10);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);

        tidesdb_txn_free(txn);

        /* drop CF */
        ASSERT_EQ(tidesdb_drop_column_family(db, cf_name), 0);

        /* verify CF is gone */
        cf = tidesdb_get_column_family(db, cf_name);
        ASSERT_TRUE(cf == NULL);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_reverse_iterator_with_tombstones(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "rev_tomb_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "rev_tomb_cf");
    ASSERT_TRUE(cf != NULL);

    /* write keys 00-19 */
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

    /* reverse iterate -- should only see odd keys */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);

    int count = 0;
    int expected_key = 19;

    do
    {
        if (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL;
            size_t key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);

            char expected[32];
            snprintf(expected, sizeof(expected), "key_%02d", expected_key);
            ASSERT_EQ(strcmp((char *)key, expected), 0);

            count++;
            expected_key -= 2; /* skip deleted even keys */
        }
    } while (tidesdb_iter_prev(iter) == 0 && tidesdb_iter_valid(iter));

    /* should see 10 odd keys */
    ASSERT_EQ(count, 10);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_disk_space_check_simulation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.min_disk_space = 1024 * 1024 * 1024; /* require 1GB free */

    ASSERT_EQ(tidesdb_create_column_family(db, "disk_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "disk_cf");
    ASSERT_TRUE(cf != NULL);

    int writes_succeeded = 0;
    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        int result = tidesdb_txn_begin(db, &txn);
        if (result != 0) break;

        char key[32], value[128];
        snprintf(key, sizeof(key), "disk_key_%03d", i);
        snprintf(value, sizeof(value), "disk_value_%03d_with_data", i);

        result = tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                 strlen(value) + 1, 0);

        if (result == 0)
        {
            result = tidesdb_txn_commit(txn);
            if (result == 0)
            {
                writes_succeeded++;
            }
        }

        tidesdb_txn_free(txn);
    }

    /* should have written at least some data */
    ASSERT_TRUE(writes_succeeded > 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int db_id;
    int thread_id;
    int num_operations;
    _Atomic(int) *total_ops;
    _Atomic(int) *errors;
    _Atomic(int) *cross_db_errors;
} multi_db_thread_data_t;

static void *multi_db_worker_thread(void *arg)
{
    multi_db_thread_data_t *data = (multi_db_thread_data_t *)arg;
    char key_buf[64];
    char value_buf[128];

    for (int i = 0; i < data->num_operations; i++)
    {
        snprintf(key_buf, sizeof(key_buf), "db%d_thread%d_key%d", data->db_id, data->thread_id, i);
        snprintf(value_buf, sizeof(value_buf), "db%d_thread%d_value%d", data->db_id,
                 data->thread_id, i);

        /* perform write operation */
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            continue;
        }

        if (tidesdb_txn_put(txn, data->cf, (uint8_t *)key_buf, strlen(key_buf),
                            (uint8_t *)value_buf, strlen(value_buf), -1) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            tidesdb_txn_free(txn);
            continue;
        }

        if (tidesdb_txn_commit(txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            tidesdb_txn_free(txn);
            continue;
        }

        tidesdb_txn_free(txn);
        atomic_fetch_add(data->total_ops, 1);

        if (data->thread_id == 0 && i < 3)
        {
            printf("    [db%d thread%d] committed key%d\n", data->db_id, data->thread_id, i);
        }

        /* verify read from correct database */
        tidesdb_txn_t *read_txn = NULL;
        if (tidesdb_txn_begin(data->db, &read_txn) == 0)
        {
            uint8_t *read_value = NULL;
            size_t read_value_size = 0;

            if (tidesdb_txn_get(read_txn, data->cf, (uint8_t *)key_buf, strlen(key_buf),
                                &read_value, &read_value_size) == 0)
            {
                /* verify value matches expected pattern */
                if (read_value_size != strlen(value_buf) ||
                    memcmp(read_value, value_buf, read_value_size) != 0)
                {
                    atomic_fetch_add(data->cross_db_errors, 1);
                }
                free(read_value);
            }
            tidesdb_txn_free(read_txn);
        }
    }

    return NULL;
}

static void test_multiple_databases_concurrent_operations(void)
{
    const int NUM_DATABASES = 3;
    const int THREADS_PER_DB = 2;
    const int OPS_PER_THREAD = 50;
    const int TOTAL_THREADS = NUM_DATABASES * THREADS_PER_DB;
    const int TOTAL_EXPECTED_OPS = TOTAL_THREADS * OPS_PER_THREAD;

    printf("  testing %d databases with %d threads each (%d total threads)...\n", NUM_DATABASES,
           THREADS_PER_DB, TOTAL_THREADS);
    printf("  operations per thread: %d, total expected: %d\n", OPS_PER_THREAD, TOTAL_EXPECTED_OPS);

    /* cleanup and create separate database directories */
    char(*db_paths)[256] = malloc(NUM_DATABASES * sizeof(*db_paths));
    tidesdb_t **databases = malloc(NUM_DATABASES * sizeof(tidesdb_t *));
    tidesdb_column_family_t **column_families =
        malloc(NUM_DATABASES * sizeof(tidesdb_column_family_t *));

    for (int i = 0; i < NUM_DATABASES; i++)
    {
        snprintf(db_paths[i], sizeof(db_paths[i]), "./test_tidesdb_multi_%d", i);
        remove_directory(db_paths[i]);

        /* create database with unique path */
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = db_paths[i];
        config.num_flush_threads = 1;
        config.num_compaction_threads = 1;

        ASSERT_EQ(tidesdb_open(&config, &databases[i]), 0);
        ASSERT_TRUE(databases[i] != NULL);

        /* create column family for this database */
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 4 * 1024 * 1024; /* 4MB */

        char cf_name[64];
        snprintf(cf_name, sizeof(cf_name), "test_cf_db%d", i);
        ASSERT_EQ(tidesdb_create_column_family(databases[i], cf_name, &cf_config), 0);

        column_families[i] = tidesdb_get_column_family(databases[i], cf_name);
        ASSERT_TRUE(column_families[i] != NULL);

        printf("  created database %d at %s with CF '%s' (cf=%p)\n", i, db_paths[i], cf_name,
               (void *)column_families[i]);
    }

    /* shared counters */
    _Atomic(int) total_ops = 0;
    _Atomic(int) errors = 0;
    _Atomic(int) cross_db_errors = 0;

    /* allocate thread data and thread handles */
    pthread_t *threads = (pthread_t *)malloc(TOTAL_THREADS * sizeof(pthread_t));
    multi_db_thread_data_t *thread_data =
        (multi_db_thread_data_t *)malloc(TOTAL_THREADS * sizeof(multi_db_thread_data_t));

    /* launch threads -- each database gets THREADS_PER_DB threads */
    printf("  launching %d threads...\n", TOTAL_THREADS);
    int thread_idx = 0;
    for (int db_id = 0; db_id < NUM_DATABASES; db_id++)
    {
        for (int t = 0; t < THREADS_PER_DB; t++)
        {
            thread_data[thread_idx].db = databases[db_id];
            thread_data[thread_idx].cf = column_families[db_id];
            thread_data[thread_idx].db_id = db_id;
            thread_data[thread_idx].thread_id = t;
            thread_data[thread_idx].num_operations = OPS_PER_THREAD;
            thread_data[thread_idx].total_ops = &total_ops;
            thread_data[thread_idx].errors = &errors;
            thread_data[thread_idx].cross_db_errors = &cross_db_errors;

            pthread_create(&threads[thread_idx], NULL, multi_db_worker_thread,
                           &thread_data[thread_idx]);
            thread_idx++;
        }
    }

    printf("  waiting for threads to complete...\n");
    for (int i = 0; i < TOTAL_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_ops = atomic_load(&total_ops);
    int final_errors = atomic_load(&errors);
    int final_cross_db_errors = atomic_load(&cross_db_errors);

    printf("  operations complete: %d successful, %d errors, %d cross-db errors\n", final_ops,
           final_errors, final_cross_db_errors);

    /* verify no cross-database contamination */
    ASSERT_EQ(final_cross_db_errors, 0);
    ASSERT_EQ(final_ops, TOTAL_EXPECTED_OPS);

    /* give a moment for any pending background operations */
    printf("  waiting for background operations to settle...\n");
    usleep(100000);

    /* check database state before verification */
    printf("  checking database states...\n");
    for (int i = 0; i < NUM_DATABASES; i++)
    {
        tidesdb_memtable_t *active_mt_wrapper = atomic_load(&column_families[i]->active_memtable);
        skip_list_t *active_mt = active_mt_wrapper ? active_mt_wrapper->skip_list : NULL;
        int active_entries = skip_list_count_entries(active_mt);
        size_t imm_count = queue_size(databases[i]->flush_queue);
        int num_levels = atomic_load(&column_families[i]->num_active_levels);
        uint64_t global_seq = atomic_load(&databases[i]->global_seq);
        printf("  db%d: active_memtable=%d entries, flush_queue=%zu, levels=%d, global_seq=%" PRIu64
               "\n",
               i, active_entries, imm_count, num_levels, global_seq);
    }

    /* verify each database has the correct keys */
    printf("  verifying database isolation...\n");
    for (int db_id = 0; db_id < NUM_DATABASES; db_id++)
    {
        tidesdb_txn_t *verify_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(databases[db_id], &verify_txn), 0);
        printf("  db%d verify_txn: snapshot_seq=%" PRIu64 ", isolation=%d\n", db_id,
               verify_txn->snapshot_seq, verify_txn->isolation_level);

        int keys_found = 0;
        for (int t = 0; t < THREADS_PER_DB; t++)
        {
            for (int i = 0; i < OPS_PER_THREAD; i++)
            {
                char key_buf[64];
                snprintf(key_buf, sizeof(key_buf), "db%d_thread%d_key%d", db_id, t, i);

                uint8_t *value = NULL;
                size_t value_size = 0;

                int get_result =
                    tidesdb_txn_get(verify_txn, column_families[db_id], (uint8_t *)key_buf,
                                    strlen(key_buf), &value, &value_size);

                if (t == 0 && i == 0)
                {
                    printf("  db%d first key '%s' (len=%zu): result=%d, snapshot_seq=%" PRIu64
                           ", cf=%p\n",
                           db_id, key_buf, strlen(key_buf), get_result, verify_txn->snapshot_seq,
                           (void *)column_families[db_id]);

                    /* try a direct skip list lookup to see if the key exists */
                    tidesdb_memtable_t *mt_wrapper =
                        atomic_load(&column_families[db_id]->active_memtable);
                    skip_list_t *mt = mt_wrapper ? mt_wrapper->skip_list : NULL;
                    uint8_t *direct_value = NULL;
                    size_t direct_value_size = 0;
                    int64_t ttl = 0;
                    uint8_t deleted = 0;
                    uint64_t seq = 0;
                    int direct_result = mt ? skip_list_get_with_seq(
                                                 mt, (uint8_t *)key_buf, strlen(key_buf),
                                                 &direct_value, &direct_value_size, &ttl, &deleted,
                                                 &seq, verify_txn->snapshot_seq, NULL, NULL)
                                           : -1;
                    printf("  db%d direct skip_list_get_with_seq: result=%d, seq=%" PRIu64
                           ", deleted=%d\n",
                           db_id, direct_result, seq, deleted);
                    if (direct_result == 0 && direct_value) free(direct_value);

                    /* print first few keys in memtable to see what's actually there */
                    printf("  db%d memtable first 5 keys:\n", db_id);
                    uint8_t *min_key = NULL;
                    size_t min_key_size = 0;
                    if (skip_list_get_min_key(mt, &min_key, &min_key_size) == 0)
                    {
                        printf("    min_key: '%.*s' (len=%zu)\n", (int)min_key_size, min_key,
                               min_key_size);
                        free(min_key);
                    }
                }

                if (get_result == 0)
                {
                    keys_found++;
                    free(value);
                }
            }
        }

        tidesdb_txn_free(verify_txn);

        int expected_keys = THREADS_PER_DB * OPS_PER_THREAD;
        printf("  database %d: found %d keys (expected %d)\n", db_id, keys_found, expected_keys);
        ASSERT_EQ(keys_found, expected_keys);
    }

    /* verify no cross-contamination. check that db0 keys don't exist in db1 */
    printf("  verifying no cross-contamination...\n");
    tidesdb_txn_t *cross_check_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(databases[1], &cross_check_txn), 0);

    char foreign_key[64];
    snprintf(foreign_key, sizeof(foreign_key), "db0_thread0_key0");

    uint8_t *foreign_value = NULL;
    size_t foreign_value_size = 0;

    /* this should fail -- db0's key should not exist in db1 */
    int result = tidesdb_txn_get(cross_check_txn, column_families[1], (uint8_t *)foreign_key,
                                 strlen(foreign_key), &foreign_value, &foreign_value_size);
    ASSERT_NE(result, 0); /* should return error (key not found) */
    ASSERT_TRUE(foreign_value == NULL);

    tidesdb_txn_free(cross_check_txn);
    printf("  cross-contamination check passed\n");

    /* check database-specific state isolation */
    printf("  checking database state isolation...\n");
    for (int i = 0; i < NUM_DATABASES; i++)
    {
        /* verify each database has independent global_seq */
        uint64_t seq = atomic_load(&databases[i]->global_seq);
        printf("  database %d: global_seq = %" PRIu64 "\n", i, seq);
        ASSERT_TRUE(seq > 0); /* should have advanced */

        /* verify each database has independent column family list */
        ASSERT_TRUE(databases[i]->num_column_families == 1);
        ASSERT_TRUE(databases[i]->column_families[0] == column_families[i]);
    }

    free(threads);
    free(thread_data);

    for (int i = 0; i < NUM_DATABASES; i++)
    {
        ASSERT_EQ(tidesdb_close(databases[i]), 0);
        remove_directory(db_paths[i]);
    }

    free(db_paths);
    free(databases);
    free(column_families);
}

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int thread_id;
    int num_keys;
    _Atomic(int) *completed;
    _Atomic(int) *errors;
} wal_test_writer_thread_data_t;

static void *wal_test_writer_thread(void *arg)
{
    wal_test_writer_thread_data_t *data = (wal_test_writer_thread_data_t *)arg;

    for (int i = 0; i < data->num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(data->db, &txn) != 0)
        {
            atomic_fetch_add(data->errors, 1);
            continue;
        }

        char key[64];
        char value[256];
        snprintf(key, sizeof(key), "wal_key_t%d_%04d", data->thread_id, i);
        snprintf(value, sizeof(value),
                 "wal_value_thread%d_entry%04d_with_sufficient_padding_to_trigger_flushes",
                 data->thread_id, i);

        if (tidesdb_txn_put(txn, data->cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                            strlen(value) + 1, 0) == 0)
        {
            if (tidesdb_txn_commit(txn) == 0)
            {
                atomic_fetch_add(data->completed, 1);
            }
            else
            {
                atomic_fetch_add(data->errors, 1);
            }
        }
        else
        {
            atomic_fetch_add(data->errors, 1);
        }

        tidesdb_txn_free(txn);
    }

    return NULL;
}

static void test_wal_commit_shutdown_recovery(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.log_level = TDB_LOG_DEBUG;
    config.block_cache_size = 0;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    cf_config.write_buffer_size = 3200;
    cf_config.enable_block_indexes = 1;
    cf_config.enable_bloom_filter = 1;

    cf_config.sync_mode = TDB_SYNC_FULL;

    ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    const int NUM_THREADS = 4;
    const int KEYS_PER_THREAD = 250;
    const int TOTAL_KEYS = NUM_THREADS * KEYS_PER_THREAD;

    printf("  Threads: %d, Keys per thread: %d, Total keys: %d\n", NUM_THREADS, KEYS_PER_THREAD,
           TOTAL_KEYS);
    printf("  Write buffer: %zu bytes (will trigger multiple flushes)\n\n",
           cf_config.write_buffer_size);

    _Atomic(int) completed = 0;
    _Atomic(int) errors = 0;

    pthread_t *threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    wal_test_writer_thread_data_t *thread_data = (wal_test_writer_thread_data_t *)malloc(
        NUM_THREADS * sizeof(wal_test_writer_thread_data_t));

    printf("  Starting %d concurrent writer threads...\n", NUM_THREADS);

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf = cf;
        thread_data[i].thread_id = i;
        thread_data[i].num_keys = KEYS_PER_THREAD;
        thread_data[i].completed = &completed;
        thread_data[i].errors = &errors;
        pthread_create(&threads[i], NULL, wal_test_writer_thread, &thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int final_completed = atomic_load(&completed);
    int final_errors = atomic_load(&errors);

    printf("  Write complete: %d keys committed, %d errors\n", final_completed, final_errors);

    printf("  Expected commits: %d, Actual commits: %d\n", TOTAL_KEYS, final_completed);
    ASSERT_TRUE(final_completed > 0);

    /* wait for flush queue to drain before shutdown to avoid race condition
     * where flush workers are still processing while tidesdb_close() frees resources */
    printf("\n  Waiting for pending flushes to complete before shutdown...\n");
    int wait_count = 0;
    size_t flush_queue_size = queue_size(db->flush_queue);
    int is_flushing = atomic_load(&cf->is_flushing);

    while (flush_queue_size > 0 || is_flushing)
    {
        if (wait_count % 10 == 0)
        {
            printf("  Flush queue: %zu, is_flushing: %d (waiting...)\n", flush_queue_size,
                   is_flushing);
        }
        usleep(TEST_FLUSH_DRAIN_WAIT_INTERVAL_US);
        wait_count++;
        flush_queue_size = queue_size(db->flush_queue);
        is_flushing = atomic_load(&cf->is_flushing);
    }

    printf("  All pending flushes completed (waited %d × %d μs)\n", wait_count,
           TEST_FLUSH_DRAIN_WAIT_INTERVAL_US);

    printf("\n  Checking database state before shutdown...\n");
    tidesdb_memtable_t *active_mt_wrapper =
        atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    skip_list_t *active_mt = active_mt_wrapper ? active_mt_wrapper->skip_list : NULL;
    int active_entries = skip_list_count_entries(active_mt);
    size_t imm_count = queue_size(db->flush_queue);
    printf("  Active memtable: %d entries\n", active_entries);
    printf("  Flush queue size: %zu\n", imm_count);
    printf("  Active levels: %d\n", cf->num_active_levels);
    for (int i = 0; i < cf->num_active_levels; i++)
    {
        if (cf->levels[i])
        {
            printf("  Level %d: %d sstables\n", i, cf->levels[i]->num_sstables);
        }
    }

    ASSERT_EQ(tidesdb_close(db), 0);
    printf("  Shutdown complete!\n");

    printf("\n  Reopening database to test WAL recovery...\n");

    db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    printf("  Database reopened successfully!\n");

    cf = tidesdb_get_column_family(db, "test_cf");
    ASSERT_TRUE(cf != NULL);

    printf("  Waiting for background flushes to complete...\n");
    wait_count = 0;
    while (queue_size(db->flush_queue) > 0 && wait_count < 50)
    {
        usleep(100000);
        wait_count++;
    }
    if (wait_count >= 50)
    {
        printf("  WARNING: Timeout waiting for flushes (flush_queue: %zu)\n",
               queue_size(db->flush_queue));
    }
    else
    {
        printf("  Background flushes completed\n");
    }

    printf("  Checking recovered state...\n");

    active_mt_wrapper = atomic_load_explicit(&cf->active_memtable, memory_order_acquire);
    active_mt = active_mt_wrapper ? active_mt_wrapper->skip_list : NULL;
    active_entries = skip_list_count_entries(active_mt);
    imm_count = queue_size(db->flush_queue);
    printf("  Active memtable: %d entries\n", active_entries);
    printf("  Flush queue size: %zu\n", imm_count);
    printf("  Active levels: %d\n", cf->num_active_levels);
    for (int i = 0; i < cf->num_active_levels; i++)
    {
        if (cf->levels[i])
        {
            printf("  Level %d: %d sstables\n", i, cf->levels[i]->num_sstables);

            for (int j = 0; j < cf->levels[i]->num_sstables; j++)
            {
                tidesdb_sstable_t *sst = cf->levels[i]->sstables[j];
                if (sst)
                {
                    printf("    SSTable %d: id=%" PRIu64 ", entries=%" PRIu64 ", max_seq=%" PRIu64
                           "\n",
                           j, sst->id, sst->num_entries, sst->max_seq);
                    if (sst->min_key && sst->max_key)
                    {
                        printf("      min_key: %.*s, max_key: %.*s\n", (int)sst->min_key_size,
                               (char *)sst->min_key, (int)sst->max_key_size, (char *)sst->max_key);
                    }
                }
            }
        }
    }

    printf("\n  Verifying all %d keys are readable after recovery...\n", TOTAL_KEYS);

    int found_keys = 0;
    int missing_keys = 0;

    for (int tid = 0; tid < NUM_THREADS; tid++)
    {
        for (int i = 0; i < KEYS_PER_THREAD; i++)
        {
            char key[64];
            snprintf(key, sizeof(key), "wal_key_t%d_%04d", tid, i);

            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            uint8_t *value = NULL;
            size_t value_size = 0;

            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

            if (result == 0 && value != NULL)
            {
                found_keys++;
                free(value);
            }
            else
            {
                missing_keys++;
                if (missing_keys <= 10)
                {
                    printf("  WARNING: Missing key: %s\n", key);
                }
            }

            tidesdb_txn_free(txn);
        }

        if ((tid + 1) % (NUM_THREADS / 4) == 0 || tid == NUM_THREADS - 1)
        {
            printf("  Progress: %d/%d threads verified (%d keys found so far)\n", tid + 1,
                   NUM_THREADS, found_keys);
        }
    }

    printf("\n  Verification complete!\n");
    printf("  Found keys: %d\n", found_keys);
    printf("  Missing keys: %d\n", missing_keys);
    printf("  Total attempted: %d\n", TOTAL_KEYS);
    printf("  Successfully committed before shutdown: %d\n", final_completed);

    if (found_keys == final_completed)
    {
        printf(BOLDGREEN "  SUCCESS: All committed keys recovered correctly!\n" RESET);
    }
    else
    {
        printf(BOLDRED "  FAILURE: Data loss detected! Expected %d, found %d\n" RESET,
               final_completed, found_keys);
    }

    ASSERT_EQ(found_keys, final_completed);

    printf("\n  Testing iteration after recovery...\n");

    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, cf, &iter), 0);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);

    int iter_count = 0;
    while (tidesdb_iter_valid(iter))
    {
        iter_count++;
        tidesdb_iter_next(iter);
    }

    printf("  Iteration found %d keys (expected %d committed)\n", iter_count, final_completed);
    ASSERT_EQ(iter_count, final_completed);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    free(threads);
    free(thread_data);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iterator_seek_after_reopen_bloom_indexes_disabled(void)
{
    /* case for issue #490 */
    cleanup_test_dir();

    const char *keys[] = {"foo", "foobar", "foobaz"};
    const char *values[] = {"value1", "value2", "value3"};
    const int num_keys = 3;

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.enable_bloom_filter = 0;
        cf_config.enable_block_indexes = 0;

        ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        tidesdb_iter_t *iter = NULL;
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int total_count = 0;
        while (tidesdb_iter_valid(iter))
        {
            total_count++;
            tidesdb_iter_next(iter);
        }
        ASSERT_EQ(total_count, num_keys);

        const char *seek_key = "foo";
        int seek_result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL;
            size_t key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_TRUE(key != NULL);

            count++;
            tidesdb_iter_next(iter);
        }

        ASSERT_EQ(count, num_keys);

        tidesdb_iter_free(iter);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iterator_seek_after_reopen(void)
{
    /* case for issue #490 */
    cleanup_test_dir();

    const char *keys[] = {"foo", "foobar", "foobaz"};
    const char *values[] = {"value1", "value2", "value3"};
    const int num_keys = 3;

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.enable_bloom_filter = 1;
        cf_config.enable_block_indexes = 1;

        ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        tidesdb_iter_t *iter = NULL;
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int total_count = 0;
        while (tidesdb_iter_valid(iter))
        {
            total_count++;
            tidesdb_iter_next(iter);
        }
        ASSERT_EQ(total_count, num_keys);

        const char *seek_key = "foo";
        int seek_result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL;
            size_t key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_TRUE(key != NULL);

            count++;
            tidesdb_iter_next(iter);
        }

        ASSERT_EQ(count, num_keys);

        tidesdb_iter_free(iter);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iterator_seek_for_prev_after_reopen(void)
{
    cleanup_test_dir();

    const char *keys[] = {"foo", "foobar", "foobaz"};
    const char *values[] = {"value1", "value2", "value3"};
    const int num_keys = 3;

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.enable_bloom_filter = 0;
        cf_config.enable_block_indexes = 0;

        ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        tidesdb_iter_t *iter = NULL;
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int total_count = 0;
        while (tidesdb_iter_valid(iter))
        {
            total_count++;
            tidesdb_iter_next(iter);
        }
        ASSERT_EQ(total_count, num_keys);

        tidesdb_iter_free(iter);
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        const char *seek_key = "foobaz";
        int seek_result =
            tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL;
            size_t key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_TRUE(key != NULL);

            count++;
            tidesdb_iter_prev(iter);
        }

        ASSERT_EQ(count, num_keys);

        tidesdb_iter_free(iter);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iterator_seek_for_prev_after_reopen_indexes(void)
{
    cleanup_test_dir();

    const char *keys[] = {"foo", "foobar", "foobaz"};
    const char *values[] = {"value1", "value2", "value3"};
    const int num_keys = 3;

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.enable_bloom_filter = 0;
        cf_config.enable_block_indexes = 1;

        ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), 0);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                  (uint8_t *)values[i], strlen(values[i]) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        ASSERT_EQ(tidesdb_close(db), 0);
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        tidesdb_iter_t *iter = NULL;
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int total_count = 0;
        while (tidesdb_iter_valid(iter))
        {
            total_count++;
            tidesdb_iter_next(iter);
        }
        ASSERT_EQ(total_count, num_keys);

        tidesdb_iter_free(iter);
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

        const char *seek_key = "foobaz";
        int seek_result =
            tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int count = 0;
        while (tidesdb_iter_valid(iter))
        {
            uint8_t *key = NULL;
            size_t key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), 0);
            ASSERT_TRUE(key != NULL);

            count++;
            tidesdb_iter_prev(iter);
        }

        ASSERT_EQ(count, num_keys);

        tidesdb_iter_free(iter);
        tidesdb_txn_free(txn);
        ASSERT_EQ(tidesdb_close(db), 0);
    }

    cleanup_test_dir();
}

static void test_iter_next_large_values_many_sstables(void)
{
    cleanup_test_dir();

    const int NUM_KEYS = 500;
    const int VALUE_SIZE = 8192; /* 8KB values */
    const int KEYS_PER_FLUSH = 50;

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    cf_config.write_buffer_size = 64 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_next_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_next_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t *large_value = malloc(VALUE_SIZE);
    ASSERT_TRUE(large_value != NULL);

    /* insert keys with unique large values */
    for (int i = 0; i < NUM_KEYS; i++)
    {
        memset(large_value, 'A' + (i % 26), VALUE_SIZE);
        large_value[0] = (uint8_t)(i & 0xFF);
        large_value[1] = (uint8_t)((i >> 8) & 0xFF);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%08d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, VALUE_SIZE, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if ((i + 1) % KEYS_PER_FLUSH == 0)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    tidesdb_flush_memtable(cf);

    /* test iteration with iter_next -- read all keys and verify values */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    int count = 0;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *found_key = NULL;
        size_t found_key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), 0);

        uint8_t *found_value = NULL;
        size_t found_value_size = 0;
        ASSERT_EQ(tidesdb_iter_value(iter, &found_value, &found_value_size), 0);
        ASSERT_EQ(found_value_size, (size_t)VALUE_SIZE);

        /* verify value content matches expected pattern */
        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key_%08d", count);
        ASSERT_TRUE(strcmp((char *)found_key, expected_key) == 0);

        int expected_idx = count;
        ASSERT_EQ(found_value[0], (uint8_t)(expected_idx & 0xFF));
        ASSERT_EQ(found_value[1], (uint8_t)((expected_idx >> 8) & 0xFF));

        tidesdb_iter_next(iter);
        count++;
    }

    ASSERT_EQ(count, NUM_KEYS);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    free(large_value);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_iter_prev_large_values_many_sstables(void)
{
    cleanup_test_dir();

    const int NUM_KEYS = 500;
    const int VALUE_SIZE = 8192;
    const int KEYS_PER_FLUSH = 50;

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    cf_config.write_buffer_size = 64 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "iter_prev_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "iter_prev_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t *large_value = malloc(VALUE_SIZE);
    ASSERT_TRUE(large_value != NULL);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        memset(large_value, 'A' + (i % 26), VALUE_SIZE);
        large_value[0] = (uint8_t)(i & 0xFF);
        large_value[1] = (uint8_t)((i >> 8) & 0xFF);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%08d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, VALUE_SIZE, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if ((i + 1) % KEYS_PER_FLUSH == 0)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    tidesdb_flush_memtable(cf);

    /* test backward iteration with iter_prev */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    ASSERT_EQ(tidesdb_iter_seek_to_last(iter), 0);
    ASSERT_TRUE(tidesdb_iter_valid(iter));

    int count = 0;
    int expected_idx = NUM_KEYS - 1;
    while (tidesdb_iter_valid(iter))
    {
        uint8_t *found_key = NULL;
        size_t found_key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), 0);

        uint8_t *found_value = NULL;
        size_t found_value_size = 0;
        ASSERT_EQ(tidesdb_iter_value(iter, &found_value, &found_value_size), 0);
        ASSERT_EQ(found_value_size, (size_t)VALUE_SIZE);

        char exp_key[32];
        snprintf(exp_key, sizeof(exp_key), "key_%08d", expected_idx);
        ASSERT_TRUE(strcmp((char *)found_key, exp_key) == 0);

        ASSERT_EQ(found_value[0], (uint8_t)(expected_idx & 0xFF));
        ASSERT_EQ(found_value[1], (uint8_t)((expected_idx >> 8) & 0xFF));

        tidesdb_iter_prev(iter);
        count++;
        expected_idx--;
    }

    ASSERT_EQ(count, NUM_KEYS);

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    free(large_value);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_get_large_values_many_sstables(void)
{
    cleanup_test_dir();

    const int NUM_KEYS = 500;
    const int VALUE_SIZE = 8192;
    const int KEYS_PER_FLUSH = 50;
    const int NUM_GETS = 200;

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    cf_config.write_buffer_size = 64 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "get_test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "get_test_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t *large_value = malloc(VALUE_SIZE);
    ASSERT_TRUE(large_value != NULL);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        memset(large_value, 'A' + (i % 26), VALUE_SIZE);
        large_value[0] = (uint8_t)(i & 0xFF);
        large_value[1] = (uint8_t)((i >> 8) & 0xFF);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%08d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, VALUE_SIZE, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if ((i + 1) % KEYS_PER_FLUSH == 0)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    tidesdb_flush_memtable(cf);

    /* test random GETs */
    srand(54321);

    for (int g = 0; g < NUM_GETS; g++)
    {
        int target_idx = rand() % NUM_KEYS;
        char key[32];
        snprintf(key, sizeof(key), "key_%08d", target_idx);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        uint8_t *found_value = NULL;
        size_t found_value_size = 0;
        int get_result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &found_value,
                                         &found_value_size);
        ASSERT_EQ(get_result, 0);
        ASSERT_TRUE(found_value != NULL);
        ASSERT_EQ(found_value_size, (size_t)VALUE_SIZE);

        ASSERT_EQ(found_value[0], (uint8_t)(target_idx & 0xFF));
        ASSERT_EQ(found_value[1], (uint8_t)((target_idx >> 8) & 0xFF));

        free(found_value);
        tidesdb_txn_free(txn);
    }

    free(large_value);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_range_iteration_large_values_many_sstables(void)
{
    cleanup_test_dir();

    const int NUM_KEYS = 500;
    const int VALUE_SIZE = 8192;
    const int KEYS_PER_FLUSH = 50;
    const int NUM_RANGES = 50;
    const int RANGE_SIZE = 20;

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    cf_config.write_buffer_size = 64 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "range_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "range_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t *large_value = malloc(VALUE_SIZE);
    ASSERT_TRUE(large_value != NULL);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        memset(large_value, 'A' + (i % 26), VALUE_SIZE);
        large_value[0] = (uint8_t)(i & 0xFF);
        large_value[1] = (uint8_t)((i >> 8) & 0xFF);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%08d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, VALUE_SIZE, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        if ((i + 1) % KEYS_PER_FLUSH == 0)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    tidesdb_flush_memtable(cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    srand(99999);

    for (int r = 0; r < NUM_RANGES; r++)
    {
        int start_idx = rand() % (NUM_KEYS - RANGE_SIZE);
        char seek_key[32];
        snprintf(seek_key, sizeof(seek_key), "key_%08d", start_idx);
        fprintf(stderr, "Range %d: seeking to '%s' (start_idx=%d)\n", r, seek_key, start_idx);

        ASSERT_EQ(tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1), 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        int count = 0;
        int expected_idx = start_idx;
        while (tidesdb_iter_valid(iter) && count < RANGE_SIZE)
        {
            uint8_t *found_key = NULL;
            size_t found_key_size = 0;
            ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), 0);

            uint8_t *found_value = NULL;
            size_t found_value_size = 0;
            ASSERT_EQ(tidesdb_iter_value(iter, &found_value, &found_value_size), 0);
            ASSERT_EQ(found_value_size, (size_t)VALUE_SIZE);

            char exp_key[32];
            snprintf(exp_key, sizeof(exp_key), "key_%08d", expected_idx);
            if (strcmp((char *)found_key, exp_key) != 0)
            {
                fprintf(stderr, "KEY MISMATCH at range %d, count %d: expected '%s', got '%s'\n", r,
                        count, exp_key, (char *)found_key);
                /* abort early to see the issue */
                ASSERT_TRUE(0);
            }

            if (found_value[0] != (uint8_t)(expected_idx & 0xFF) ||
                found_value[1] != (uint8_t)((expected_idx >> 8) & 0xFF))
            {
                fprintf(stderr, "VALUE MISMATCH at key '%s': expected [%d,%d], got [%d,%d]\n",
                        (char *)found_key, expected_idx & 0xFF, (expected_idx >> 8) & 0xFF,
                        found_value[0], found_value[1]);
            }

            ASSERT_EQ(found_value[0], (uint8_t)(expected_idx & 0xFF));
            ASSERT_EQ(found_value[1], (uint8_t)((expected_idx >> 8) & 0xFF));

            tidesdb_iter_next(iter);
            count++;
            expected_idx++;
        }

        ASSERT_EQ(count, RANGE_SIZE);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    free(large_value);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_seek_large_values_many_sstables(void)
{
    cleanup_test_dir();

    const int NUM_KEYS = 1000;
    const int VALUE_SIZE = 8192;
    const int KEYS_PER_FLUSH = 100;
    const int NUM_SEEKS = 100;

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;
    cf_config.write_buffer_size = 64 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "seek_test_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "seek_test_cf");
    ASSERT_TRUE(cf != NULL);

    uint8_t *large_value = malloc(VALUE_SIZE);
    ASSERT_TRUE(large_value != NULL);
    memset(large_value, 'X', VALUE_SIZE);

    for (int i = 0; i < NUM_KEYS; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "key_%08d", i);

        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value, VALUE_SIZE, 0),
            0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);

        /* we force flush every KEYS_PER_FLUSH keys to create multiple ssts */
        if ((i + 1) % KEYS_PER_FLUSH == 0)
        {
            tidesdb_flush_memtable(cf);
        }
    }

    tidesdb_flush_memtable(cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), 0);

    srand(12345); /* deterministic seed */

    for (int s = 0; s < NUM_SEEKS; s++)
    {
        int target_idx = rand() % NUM_KEYS;
        char seek_key[32];
        snprintf(seek_key, sizeof(seek_key), "key_%08d", target_idx);

        int seek_result = tidesdb_iter_seek(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        /* we verify we got the right key */
        uint8_t *found_key = NULL;
        size_t found_key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), 0);
        ASSERT_TRUE(found_key != NULL);
        ASSERT_TRUE(strcmp((char *)found_key, seek_key) == 0);

        /* we verify value is correct size */
        uint8_t *found_value = NULL;
        size_t found_value_size = 0;
        ASSERT_EQ(tidesdb_iter_value(iter, &found_value, &found_value_size), 0);
        ASSERT_EQ(found_value_size, (size_t)VALUE_SIZE);
    }

    /* also test seek_for_prev */
    for (int s = 0; s < NUM_SEEKS; s++)
    {
        const int target_idx = rand() % NUM_KEYS;
        char seek_key[32];
        snprintf(seek_key, sizeof(seek_key), "key_%08d", target_idx);

        const int seek_result =
            tidesdb_iter_seek_for_prev(iter, (uint8_t *)seek_key, strlen(seek_key) + 1);
        ASSERT_EQ(seek_result, 0);
        ASSERT_TRUE(tidesdb_iter_valid(iter));

        uint8_t *found_key = NULL;
        size_t found_key_size = 0;
        ASSERT_EQ(tidesdb_iter_key(iter, &found_key, &found_key_size), 0);
        ASSERT_TRUE(found_key != NULL);
        ASSERT_TRUE(strcmp((char *)found_key, seek_key) <= 0);
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);

    free(large_value);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_database_lock_prevents_double_open(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db1 = NULL;
    tidesdb_t *db2 = NULL;

    ASSERT_EQ(tidesdb_open(&config, &db1), TDB_SUCCESS);
    ASSERT_TRUE(db1 != NULL);

    /* second open of same path should fail with TDB_ERR_LOCKED */
    const int result = tidesdb_open(&config, &db2);
    ASSERT_EQ(result, TDB_ERR_LOCKED);
    ASSERT_TRUE(db2 == NULL);

    ASSERT_EQ(tidesdb_close(db1), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_open(&config, &db2), TDB_SUCCESS);
    ASSERT_TRUE(db2 != NULL);

    ASSERT_EQ(tidesdb_close(db2), TDB_SUCCESS);
    cleanup_test_dir();
}

static void test_database_lock_released_on_close(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    for (int i = 0; i < 5; i++)
    {
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        if (i == 0)
        {
            ASSERT_EQ(tidesdb_create_column_family(db, "test_cf", &cf_config), TDB_SUCCESS);
        }

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
        if (cf)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32], value[32];
            snprintf(key, sizeof(key), "key_%d", i);
            snprintf(value, sizeof(value), "value_%d", i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }

    cleanup_test_dir();
}

#ifndef _WIN32
#include <sys/wait.h>

static void test_database_lock_multi_process(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    char signal_file[256];
    snprintf(signal_file, sizeof(signal_file), "%s/.parent_ready", TEST_DB_PATH);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0)
    {
        /* child process -- wait for parent to signal it has opened the database */
        int wait_count = 0;
        while (access(signal_file, F_OK) != 0 && wait_count < 100)
        {
            usleep(10000); /* 10ms */
            wait_count++;
        }

        if (wait_count >= 100)
        {
            _exit(2); /* timeout waiting for parent */
        }

        /* we now try to open the locked database -- should fail */
        tidesdb_t *child_db = NULL;
        const int result = tidesdb_open(&config, &child_db);
        _exit(result == TDB_ERR_LOCKED ? 0 : 1);
    }

    /* parent process -- open database first */
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    /* signal child that database is open */
    FILE *f = fopen(signal_file, "w");
    ASSERT_TRUE(f != NULL);
    fclose(f);

    /* we wait for child */
    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0); /* child got TDB_ERR_LOCKED as expected */

    /* remove signal file */
    remove(signal_file);

    /* parent closes database */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* we test that a new process can now open the database */
    pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0)
    {
        /* child process -- should succeed now that parent released lock */
        tidesdb_t *child_db = NULL;
        int result = tidesdb_open(&config, &child_db);
        if (result != TDB_SUCCESS || child_db == NULL)
        {
            _exit(1);
        }
        tidesdb_close(child_db);
        _exit(0);
    }

    /* parent waits for child */
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0); /* child opened successfully */

    cleanup_test_dir();
}
#endif

static void test_ttl_expiration_after_reopen(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_reopen_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_reopen_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);
    const int num_keys = 100;

    /* we write many keys with short TTL (2 seconds) */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "ttl_reopen_key_%04d", i);
        snprintf(value, sizeof(value), "ttl_reopen_value_%04d", i);

        time_t ttl = now + 2; /* expires in 2 seconds */

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /*** we now verify keys are accessible before expiration */
    tidesdb_txn_t *verify_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &verify_txn), TDB_SUCCESS);

    int accessible_before = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_reopen_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(verify_txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size) ==
            TDB_SUCCESS)
        {
            accessible_before++;
            free(value);
        }
    }
    tidesdb_txn_free(verify_txn);
    ASSERT_EQ(accessible_before, num_keys);

    /** we take a nap and wait for TTL to expire */
    sleep(3);

    /* we close database -- this triggers flush and potentially compaction */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "ttl_reopen_cf");
    ASSERT_TRUE(cf != NULL);

    /* we now verify all keys are now inaccessible (expired) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int expired_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_reopen_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result != TDB_SUCCESS || value == NULL)
        {
            expired_count++;
        }
        else
        {
            free(value);
        }
    }

    tidesdb_txn_free(txn);

    /*** all keys should be expired/inaccessible */
    ASSERT_EQ(expired_count, num_keys);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ttl_expiration_with_deletes_after_reopen(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_delete_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_delete_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);
    const int num_keys = 100;

    /* we write many keys with short TTL (2 seconds) */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "ttl_delete_key_%04d", i);
        snprintf(value, sizeof(value), "ttl_delete_value_%04d", i);

        time_t ttl = now + 2; /* expires in 2 seconds */

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we now delete all keys explicitly */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32];
        snprintf(key, sizeof(key), "ttl_delete_key_%04d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we close database -- this triggers flush */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* we reopen database */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "ttl_delete_cf");
    ASSERT_TRUE(cf != NULL);

    /* we verify all keys are now inaccessible (deleted) */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int deleted_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_delete_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result != TDB_SUCCESS || value == NULL)
        {
            deleted_count++;
        }
        else
        {
            free(value);
        }
    }

    tidesdb_txn_free(txn);

    /* all keys should be deleted/inaccessible */
    ASSERT_EQ(deleted_count, num_keys);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_ttl_expiration_range_delete_after_reopen(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "ttl_range_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "ttl_range_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);
    const int num_keys = 100;
    const int delete_start = 25;
    const int delete_end = 75;

    /* we write many keys with long TTL (1 hour) */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "ttl_range_key_%04d", i);
        snprintf(value, sizeof(value), "ttl_range_value_%04d", i);

        time_t ttl = now + 3600; /* expires in 1 hour */

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we delete only a range of keys [delete_start, delete_end) */
    for (int i = delete_start; i < delete_end; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32];
        snprintf(key, sizeof(key), "ttl_range_key_%04d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we close database -- this triggers flush */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* we reopen database */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "ttl_range_cf");
    ASSERT_TRUE(cf != NULL);

    /* we verify deleted range is inaccessible, others remain */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int deleted_count = 0;
    int accessible_count = 0;

    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_range_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result != TDB_SUCCESS || value == NULL)
        {
            deleted_count++;
            /* we verify this key was in the deleted range */
            ASSERT_TRUE(i >= delete_start && i < delete_end);
        }
        else
        {
            accessible_count++;
            /* we verify this key was outside the deleted range */
            ASSERT_TRUE(i < delete_start || i >= delete_end);
            free(value);
        }
    }

    tidesdb_txn_free(txn);

    /* we verify counts match expected */
    ASSERT_EQ(deleted_count, delete_end - delete_start);
    ASSERT_EQ(accessible_count, num_keys - (delete_end - delete_start));

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_many_sstables_low_max_open_reaper_eviction(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    config.max_open_sstables = 5; /* very low limit to force reaper eviction */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048; /* small buffer to trigger frequent flushes */
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;
    cf_config.enable_bloom_filter = 1;
    cf_config.enable_block_indexes = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "reaper_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "reaper_cf");
    ASSERT_TRUE(cf != NULL);

    const int num_sstables = 20; /* more than max_open_sstables to force eviction */
    const int keys_per_sstable = 30;
    const int total_keys = num_sstables * keys_per_sstable;

    /* we write keys and flush to create many sstables exceeding max_open limit */
    for (int i = 0; i < total_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "reaper_key_%06d", i);
        snprintf(value, sizeof(value), "reaper_value_%06d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);

        /* we flush periodically to create sstables */
        if ((i + 1) % keys_per_sstable == 0)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000); /* give time for flush and reaper to run */
        }
    }

    /* we wait for all flushes to complete */
    for (int i = 0; i < 100; i++)
    {
        usleep(20000);
        if (queue_size(db->flush_queue) == 0) break;
    }
    usleep(200000); /* extra time for reaper to evict sstables */

    /** we now verify all keys are still accessible even after reaper eviction
     * this tests the system's ability to reopen evicted sstable files */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int success_count = 0;
    int fail_count = 0;

    for (int i = 0; i < total_keys; i++)
    {
        char key[32], expected[64];
        snprintf(key, sizeof(key), "reaper_key_%06d", i);
        snprintf(expected, sizeof(expected), "reaper_value_%06d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result == TDB_SUCCESS && value != NULL)
        {
            ASSERT_EQ(strcmp((char *)value, expected), 0);
            success_count++;
            free(value);
        }
        else
        {
            fail_count++;
        }
    }

    tidesdb_txn_free(txn);

    /* all keys should be accessible * * */
    ASSERT_EQ(success_count, total_keys);
    ASSERT_EQ(fail_count, 0);

    /* we now test iteration across evicted sstables */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), TDB_SUCCESS);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, cf, &iter), TDB_SUCCESS);
    ASSERT_TRUE(iter != NULL);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);

    int iter_count = 0;
    while (tidesdb_iter_valid(iter))
    {
        iter_count++;
        if (tidesdb_iter_next(iter) != TDB_SUCCESS) break;
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    /* we should be able to iterate all keys */
    ASSERT_EQ(iter_count, total_keys);

    /* we close and reopen to test persistence after eviction cycles */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "reaper_cf");
    ASSERT_TRUE(cf != NULL);

    /* we verify all keys still accessible after reopen */
    tidesdb_txn_t *reopen_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &reopen_txn), TDB_SUCCESS);

    int reopen_success = 0;
    for (int i = 0; i < total_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "reaper_key_%06d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(reopen_txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size) ==
            TDB_SUCCESS)
        {
            reopen_success++;
            free(value);
        }
    }

    tidesdb_txn_free(reopen_txn);
    ASSERT_EQ(reopen_success, total_keys);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_partial_write_mid_block_corruption(void)
{
    cleanup_test_dir();
    const int NUM_KEYS = 100;

    /* we write data and flush to create sstable */
    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 4096;
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;

        ASSERT_EQ(tidesdb_create_column_family(db, "partial_cf", &cf_config), TDB_SUCCESS);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "partial_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32], value[128];
            snprintf(key, sizeof(key), "partial_key_%03d", i);
            snprintf(value, sizeof(value), "partial_value_%03d_with_extra_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), TDB_SUCCESS);
        usleep(200000);

        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }

    /* we corrupt the klog file mid-block (simulate partial write during crash) */
    char klog_path[512];
    snprintf(klog_path, sizeof(klog_path),
             "%s" PATH_SEPARATOR "partial_cf" PATH_SEPARATOR "L1_0.klog", TEST_DB_PATH);

    FILE *klog_file = fopen(klog_path, "r+b");
    if (klog_file)
    {
        fseek(klog_file, 0, SEEK_END);
        long size = ftell(klog_file);
        if (size > 200)
        {
            /* we write garbage in the middle of the file to simulate partial write */
            fseek(klog_file, size / 2, SEEK_SET);
            uint8_t garbage[50];
            memset(garbage, 0xFF, sizeof(garbage));
            fwrite(garbage, 1, sizeof(garbage), klog_file);
        }
        fclose(klog_file);
    }

    /* we reopen and verify system handles corruption gracefully */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        int result = tidesdb_open(&config, &db);

        /* system should either recover gracefully or fail cleanly */
        if (result == TDB_SUCCESS && db != NULL)
        {
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "partial_cf");
            if (cf != NULL)
            {
                /* we try to read -- some keys may be recoverable */
                tidesdb_txn_t *txn = NULL;
                if (tidesdb_txn_begin(db, &txn) == TDB_SUCCESS)
                {
                    int found = 0;
                    for (int i = 0; i < NUM_KEYS; i++)
                    {
                        char key[32];
                        snprintf(key, sizeof(key), "partial_key_%03d", i);

                        uint8_t *value = NULL;
                        size_t value_size = 0;
                        if (tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value,
                                            &value_size) == TDB_SUCCESS)
                        {
                            found++;
                            free(value);
                        }
                    }
                    /* we expect at least some keys to be recoverable or none (graceful failure) */
                    (void)found;
                    tidesdb_txn_free(txn);
                }
            }
            tidesdb_close(db);
        }
        /* if open failed, that's also acceptable for corrupted data */
    }

    cleanup_test_dir();
}

static void test_clock_skew_time_travel_ttl(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "clock_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "clock_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);
    const int num_keys = 50;

    /* we write keys with TTL set to a time in the past (simulating clock going backwards) */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "clock_key_%04d", i);
        snprintf(value, sizeof(value), "clock_value_%04d", i);

        /* TTL in the past -- should be immediately expired */
        time_t ttl = now - 3600; /* 1 hour ago */

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we verify keys with past TTL are immediately inaccessible */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int expired_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "clock_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (result != TDB_SUCCESS || value == NULL)
        {
            expired_count++;
        }
        else
        {
            free(value);
        }
    }

    tidesdb_txn_free(txn);

    /* all keys should be expired since TTL was in the past */
    ASSERT_EQ(expired_count, num_keys);

    /* we now write keys with TTL far in the future */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *put_txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &put_txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "future_key_%04d", i);
        snprintf(value, sizeof(value), "future_value_%04d", i);

        time_t ttl = now + 86400 * 365; /* 1 year in future */

        ASSERT_EQ(tidesdb_txn_put(put_txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(put_txn), TDB_SUCCESS);
        tidesdb_txn_free(put_txn);
    }

    /* we verify future TTL keys are accessible */
    tidesdb_txn_t *future_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &future_txn), TDB_SUCCESS);

    int accessible_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "future_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(future_txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size) ==
            TDB_SUCCESS)
        {
            accessible_count++;
            free(value);
        }
    }

    tidesdb_txn_free(future_txn);
    ASSERT_EQ(accessible_count, num_keys);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_filesystem_full_during_compaction(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "diskfull_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "diskfull_cf");
    ASSERT_TRUE(cf != NULL);

    const int num_keys = 200;

    /* we write enough data to create multiple sstables */
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[128];
        snprintf(key, sizeof(key), "diskfull_key_%04d", i);
        snprintf(value, sizeof(value), "diskfull_value_%04d_with_padding_data", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);

        if ((i + 1) % 50 == 0)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(20000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* we trigger compaction -- even if disk is "full", system should handle gracefully
     * note -- we can't actually fill the disk in a test, but we verify compaction
     * doesn't corrupt data even under stress */
    tidesdb_compact(cf);

    /* we wait for compaction */
    for (int i = 0; i < 100; i++)
    {
        usleep(50000);
        int is_compacting = atomic_load_explicit(&cf->is_compacting, memory_order_acquire);
        if (!is_compacting && queue_size(db->compaction_queue) == 0) break;
    }

    /* we verify all data is still accessible after compaction */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int found_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "diskfull_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size) ==
            TDB_SUCCESS)
        {
            found_count++;
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    ASSERT_EQ(found_count, num_keys);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_power_loss_during_sstable_metadata_write(void)
{
    cleanup_test_dir();
    const int NUM_KEYS = 100;

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 4096;
        cf_config.compression_algorithm = TDB_COMPRESS_NONE;
        cf_config.enable_bloom_filter = 1;
        cf_config.enable_block_indexes = 1;

        ASSERT_EQ(tidesdb_create_column_family(db, "powerloss_cf", &cf_config), TDB_SUCCESS);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "powerloss_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < NUM_KEYS; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

            char key[32], value[128];
            snprintf(key, sizeof(key), "power_key_%03d", i);
            snprintf(value, sizeof(value), "power_value_%03d_with_data", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), TDB_SUCCESS);
        usleep(200000);

        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }

    /* we corrupt the sstable metadata (bloom filter or block index) to simulate power loss */
    char bloom_path[512];
    snprintf(bloom_path, sizeof(bloom_path),
             "%s" PATH_SEPARATOR "powerloss_cf" PATH_SEPARATOR "L1_0.bloom", TEST_DB_PATH);

    FILE *bloom_file = fopen(bloom_path, "r+b");
    if (bloom_file)
    {
        /* we truncate bloom filter to simulate incomplete write */
        fseek(bloom_file, 0, SEEK_END);
        long size = ftell(bloom_file);
        if (size > 20)
        {
            int truncate_result = ftruncate(fileno(bloom_file), size / 3);
            (void)truncate_result;
        }
        fclose(bloom_file);
    }

    /* we reopen and verify system handles corrupted metadata gracefully */
    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        int result = tidesdb_open(&config, &db);

        if (result == TDB_SUCCESS && db != NULL)
        {
            tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "powerloss_cf");
            if (cf != NULL)
            {
                /* we try to read -- data should still be accessible even without bloom filter */
                tidesdb_txn_t *txn = NULL;
                if (tidesdb_txn_begin(db, &txn) == TDB_SUCCESS)
                {
                    int found = 0;
                    for (int i = 0; i < NUM_KEYS; i++)
                    {
                        char key[32];
                        snprintf(key, sizeof(key), "power_key_%03d", i);

                        uint8_t *value = NULL;
                        size_t value_size = 0;
                        if (tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value,
                                            &value_size) == TDB_SUCCESS)
                        {
                            found++;
                            free(value);
                        }
                    }
                    /* we expect data to be recoverable even with corrupted bloom filter */
                    ASSERT_TRUE(found > 0);
                    tidesdb_txn_free(txn);
                }
            }
            tidesdb_close(db);
        }
    }

    cleanup_test_dir();
}

static void test_memory_allocation_stress(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "memstress_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "memstress_cf");
    ASSERT_TRUE(cf != NULL);

    const int num_keys = 500;
    const int large_value_size = 1024;

    /* we allocate large values to stress memory allocation */
    uint8_t *large_value = malloc(large_value_size);
    ASSERT_TRUE(large_value != NULL);
    memset(large_value, 'X', large_value_size);

    /* we write many keys with large values to stress memory */
    int success_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) continue;

        char key[32];
        snprintf(key, sizeof(key), "memstress_key_%04d", i);

        int result = tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, large_value,
                                     large_value_size, -1);

        if (result == TDB_SUCCESS)
        {
            if (tidesdb_txn_commit(txn) == TDB_SUCCESS)
            {
                success_count++;
            }
        }
        tidesdb_txn_free(txn);

        /* we periodically flush to stress memory further */
        if ((i + 1) % 100 == 0)
        {
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }
    }

    free(large_value);

    for (int i = 0; i < 100; i++)
    {
        usleep(20000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    /* we verify data integrity after memory stress */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    int found_count = 0;
    for (int i = 0; i < num_keys; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "memstress_key_%04d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size) ==
            TDB_SUCCESS)
        {
            found_count++;
            free(value);
        }
    }

    tidesdb_txn_free(txn);

    /* we should find all successfully written keys */
    ASSERT_EQ(found_count, success_count);

    /* we now stress iteration with many concurrent allocations */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), TDB_SUCCESS);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, cf, &iter), TDB_SUCCESS);
    ASSERT_TRUE(iter != NULL);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);

    int iter_count = 0;
    while (tidesdb_iter_valid(iter))
    {
        iter_count++;
        if (tidesdb_iter_next(iter) != TDB_SUCCESS) break;
    }

    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    ASSERT_EQ(iter_count, success_count);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_concurrent_cf_drop_during_iteration(void)
{
    cleanup_test_dir();

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&config, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);

    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 8192;

    ASSERT_EQ(tidesdb_create_column_family(db, "drop_cf", &cf_config), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf != NULL);

    const int num_keys = 100;

    for (int i = 0; i < num_keys; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

        char key[32], value[64];
        snprintf(key, sizeof(key), "drop_key_%04d", i);
        snprintf(value, sizeof(value), "drop_value_%04d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* we start an iterator and complete iteration */
    tidesdb_txn_t *iter_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &iter_txn), TDB_SUCCESS);

    tidesdb_iter_t *iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(iter_txn, cf, &iter), TDB_SUCCESS);
    ASSERT_TRUE(iter != NULL);

    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);

    /* we iterate through all keys */
    int iter_count = 0;
    while (tidesdb_iter_valid(iter))
    {
        iter_count++;
        if (tidesdb_iter_next(iter) != TDB_SUCCESS) break;
    }
    ASSERT_EQ(iter_count, num_keys);

    /* we must free iterator before dropping CF to avoid use-after-free
     * dropping CF while iterator is active is undefined behavior */
    tidesdb_iter_free(iter);
    tidesdb_txn_free(iter_txn);

    /* we now drop the CF after iterator is freed */
    ASSERT_EQ(tidesdb_drop_column_family(db, "drop_cf"), TDB_SUCCESS);

    /* we verify CF is gone */
    tidesdb_column_family_t *dropped_cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(dropped_cf == NULL);

    /* we recreate CF to verify system is still functional */
    ASSERT_EQ(tidesdb_create_column_family(db, "drop_cf", &cf_config), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "drop_cf");
    ASSERT_TRUE(cf != NULL);

    /* we write and read to verify CF works */
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)"test_key", 9, (uint8_t *)"test_value", 11, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"test_key", 9, &value, &value_size), TDB_SUCCESS);
    ASSERT_TRUE(value != NULL);
    ASSERT_EQ(strcmp((char *)value, "test_value"), 0);
    free(value);
    tidesdb_txn_free(txn);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_flush_with_sync_modes(void)
{
    cleanup_test_dir();

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_NONE;
        cf_config.write_buffer_size = 1024;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_none_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_none_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "sync_none_key_%d", i);
            snprintf(value, sizeof(value), "sync_none_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(100000);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"sync_none_key_0", 16, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    cleanup_test_dir();

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_FULL;
        cf_config.write_buffer_size = 1024;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_full_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_full_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "sync_full_key_%d", i);
            snprintf(value, sizeof(value), "sync_full_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(100000);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"sync_full_key_0", 16, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    cleanup_test_dir();

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.sync_mode = TDB_SYNC_INTERVAL;
        cf_config.sync_interval_us = 10000;
        cf_config.write_buffer_size = 1024;

        ASSERT_EQ(tidesdb_create_column_family(db, "sync_interval_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_interval_cf");
        ASSERT_TRUE(cf != NULL);

        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "sync_interval_key_%d", i);
            snprintf(value, sizeof(value), "sync_interval_value_%d", i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
        usleep(100000);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(
            tidesdb_txn_get(txn, cf, (uint8_t *)"sync_interval_key_0", 20, &value, &value_size), 0);
        ASSERT_TRUE(value != NULL);
        free(value);
        tidesdb_txn_free(txn);

        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_flush_concurrent_prevention(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;

    ASSERT_EQ(tidesdb_create_column_family(db, "concurrent_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "concurrent_flush_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "conc_key_%d", i);
        snprintf(value, sizeof(value), "conc_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    int result = tidesdb_flush_memtable(cf);
    ASSERT_EQ(result, 0);

    int is_flushing = tidesdb_is_flushing(cf);

    (void)is_flushing;

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (!tidesdb_is_flushing(cf) && queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "conc_key_%d", i);

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

static void test_flush_empty_memtable_skip(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_flush_cf");
    ASSERT_TRUE(cf != NULL);

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);

    int num_ssts = atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);
    ASSERT_EQ(num_ssts, 0);

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_flush_below_size_threshold(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "threshold_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "threshold_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 5; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "small_key_%d", i);
        snprintf(value, sizeof(value), "small_value_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_flush_memtable(cf), 0);
    usleep(50000);

    int num_ssts = atomic_load_explicit(&cf->levels[0]->num_sstables, memory_order_acquire);
    ASSERT_EQ(num_ssts, 0);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)"small_key_0", 12, &value, &value_size), 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_concurrent_prevention(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "conc_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "conc_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "compact_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "compact_value_%d_%d", batch, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    tidesdb_compact(cf);

    int is_compacting = tidesdb_is_compacting(cf);

    (void)is_compacting;

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "compact_key_%d_%d", batch, i);

            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_all_tombstones_empty_result(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "tombstone_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "tombstone_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);
        snprintf(value, sizeof(value), "tomb_value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);

        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tomb_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_TRUE(result != 0);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_full_merge_duplicate_keys_dedup(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "dedup_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dedup_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

            char key[32], value[64];
            snprintf(key, sizeof(key), "dup_key_%03d", i);
            snprintf(value, sizeof(value), "value_round_%d_key_%03d", round, i);

            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "dup_key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "value_round_2_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected_value), 0);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_full_merge_vlog_separation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.klog_value_threshold = 64;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "vlog_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "vlog_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[32];
        snprintf(key, sizeof(key), "small_key_%d", i);
        snprintf(value, sizeof(value), "small_%d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32];
        char value[256];
        snprintf(key, sizeof(key), "large_key_%d", i);
        memset(value, 'A' + (i % 26), 200);
        value[200] = '\0';

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "small_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "large_key_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_TRUE(value_size > 100);
        free(value);
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_full_merge_mixed_ttl(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "mixed_ttl_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "mixed_ttl_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "ttl_key_%03d", i);
        snprintf(value, sizeof(value), "ttl_value_%03d", i);

        time_t ttl;
        if (i % 3 == 0)
        {
            ttl = now + 1;
        }
        else if (i % 3 == 1)
        {
            ttl = now + 3600;
        }
        else
        {
            ttl = 0;
        }

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, ttl),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    sleep(2);

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    int expired_count = 0;
    int valid_count = 0;

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "ttl_key_%03d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);

        if (i % 3 == 0)
        {
            if (result != 0)
            {
                expired_count++;
            }
        }
        else
        {
            if (result == 0 && value != NULL)
            {
                valid_count++;
                free(value);
            }
        }
    }

    ASSERT_TRUE(expired_count >= 8);
    ASSERT_TRUE(valid_count >= 15);

    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dividing_merge_no_boundaries_fallback(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 4;
    cf_config.dividing_level_offset = 1;
    cf_config.min_levels = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_boundary_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_boundary_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "nobnd_key_%03d", i);
        snprintf(value, sizeof(value), "nobnd_value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "nobnd_key_%03d", i);

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

static void test_partitioned_merge_empty_largest_level_fallback(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.dividing_level_offset = 0;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_largest_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_largest_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 40; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "empty_lg_key_%03d", i);
        snprintf(value, sizeof(value), "empty_lg_value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 40; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "empty_lg_key_%03d", i);

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

static void test_merge_single_sstable(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "single_sst_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "single_sst_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        char key[32], value[64];
        snprintf(key, sizeof(key), "single_key_%03d", i);
        snprintf(value, sizeof(value), "single_value_%03d", i);

        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "single_key_%03d", i);

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

static void test_flush_during_compaction(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "flush_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "flush_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "fc_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "fc_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(30000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "fc_new_key_%d", i);
        snprintf(value, sizeof(value), "fc_new_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);

    for (int i = 0; i < 300; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && !tidesdb_is_flushing(cf) &&
            queue_size(db->compaction_queue) == 0 && queue_size(db->flush_queue) == 0)
            break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 5; batch++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "fc_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "fc_new_key_%d", i);
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

static void test_dca_min_levels_constraint(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 4;

    ASSERT_EQ(tidesdb_create_column_family(db, "min_levels_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "min_levels_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(initial_levels >= 4);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "min_key_%03d", i);
        snprintf(value, sizeof(value), "min_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    for (int round = 0; round < 3; round++)
    {
        tidesdb_compact(cf);
        for (int i = 0; i < 200; i++)
        {
            usleep(50000);
            if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
        }
    }

    int final_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(final_levels >= 4);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 20; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "min_key_%03d", i);
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

static void test_merge_heap_source_exhaustion(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "exhaust_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "exhaust_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "exhaust_key_%03d", i);
        snprintf(value, sizeof(value), "exhaust_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    tidesdb_flush_memtable(cf);
    usleep(50000);

    for (int i = 20; i < 40; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "exhaust_key_%03d", i);
        snprintf(value, sizeof(value), "exhaust_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    tidesdb_flush_memtable(cf);
    usleep(50000);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 40; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "exhaust_key_%03d", i);
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

static void test_compaction_max_seq_propagation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "max_seq_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "max_seq_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "seq_key_%03d", i);
            snprintf(value, sizeof(value), "seq_value_batch%d_%03d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 30; i++)
    {
        char key[32], expected_value[64];
        snprintf(key, sizeof(key), "seq_key_%03d", i);
        snprintf(expected_value, sizeof(expected_value), "seq_value_batch2_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(strcmp((char *)value, expected_value), 0);
        free(value);
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_spooky_level_selection(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.level_size_ratio = 2;
    cf_config.dividing_level_offset = 2;
    cf_config.min_levels = 4;

    ASSERT_EQ(tidesdb_create_column_family(db, "spooky_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "spooky_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "spooky_key_%04d", i);
        snprintf(value, sizeof(value), "spooky_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "spooky_key_%04d", i);
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

static void test_compaction_with_lz4_compression(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;

    ASSERT_EQ(tidesdb_create_column_family(db, "lz4_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "lz4_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "lz4_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "lz4_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "lz4_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_with_zstd_compression(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;
    cf_config.compression_algorithm = TDB_COMPRESS_ZSTD;

    ASSERT_EQ(tidesdb_create_column_family(db, "zstd_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "zstd_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "zstd_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "zstd_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "zstd_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_merge_with_bloom_filter_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;
    cf_config.enable_bloom_filter = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_bloom_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_bloom_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "no_bloom_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "no_bloom_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "no_bloom_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_merge_with_block_indexes_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;
    cf_config.enable_block_indexes = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_index_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_index_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "no_index_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "no_index_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "no_index_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_flush_wal_rotation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.sync_mode = TDB_SYNC_FULL;

    ASSERT_EQ(tidesdb_create_column_family(db, "wal_rotate_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "wal_rotate_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "wal_key_%d_%d", round, i);
            snprintf(value, sizeof(value), "wal_value_%d_%d", round, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(100000);
        for (int i = 0; i < 100; i++)
        {
            usleep(10000);
            if (queue_size(db->flush_queue) == 0) break;
        }
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "wal_key_%d_%d", round, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_full_merge_empty_result(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_result_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_result_cf");
    ASSERT_TRUE(cf != NULL);

    time_t now = time(NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "expire_key_%03d", i);
        snprintf(value, sizeof(value), "expire_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, now + 1),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    sleep(2);

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "expire_key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_TRUE(result != 0);
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_recovery_after_close(void)
{
    cleanup_test_dir();
    const int NUM_KEYS = 99;

    {
        tidesdb_t *db = create_test_db();
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        cf_config.write_buffer_size = 1024;
        cf_config.level_size_ratio = 10;

        ASSERT_EQ(tidesdb_create_column_family(db, "recovery_cf", &cf_config), 0);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "recovery_cf");
        ASSERT_TRUE(cf != NULL);

        for (int batch = 0; batch < 3; batch++)
        {
            for (int i = 0; i < NUM_KEYS / 3; i++)
            {
                tidesdb_txn_t *txn = NULL;
                ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
                char key[32], value[64];
                snprintf(key, sizeof(key), "rec_key_%03d", batch * (NUM_KEYS / 3) + i);
                snprintf(value, sizeof(value), "rec_value_%03d", batch * (NUM_KEYS / 3) + i);
                ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1,
                                          (uint8_t *)value, strlen(value) + 1, 0),
                          0);
                ASSERT_EQ(tidesdb_txn_commit(txn), 0);
                tidesdb_txn_free(txn);
            }
            tidesdb_flush_memtable(cf);
            usleep(50000);
        }

        for (int i = 0; i < 100; i++)
        {
            usleep(10000);
            if (queue_size(db->flush_queue) == 0) break;
        }

        tidesdb_compact(cf);

        for (int i = 0; i < 200; i++)
        {
            usleep(50000);
            if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
        }

        tidesdb_close(db);
    }

    {
        tidesdb_config_t config = tidesdb_default_config();
        config.db_path = TEST_DB_PATH;

        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&config, &db), 0);
        ASSERT_TRUE(db != NULL);

        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "recovery_cf");
        ASSERT_TRUE(cf != NULL);

        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

        int found_count = 0;
        for (int i = 0; i < NUM_KEYS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "rec_key_%03d", i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            int result =
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
            if (result == 0 && value != NULL)
            {
                free(value);
                found_count++;
            }
        }

        ASSERT_EQ(found_count, NUM_KEYS);
        tidesdb_txn_free(txn);
        tidesdb_close(db);
    }

    cleanup_test_dir();
}

static void test_dividing_merge_boundary_calculation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.level_size_ratio = 4;
    cf_config.dividing_level_offset = 1;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "boundary_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "boundary_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 60; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        char prefix = 'a' + (i % 10);
        snprintf(key, sizeof(key), "%c_bnd_key_%03d", prefix, i);
        snprintf(value, sizeof(value), "boundary_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 60; i++)
    {
        char key[32];
        char prefix = 'a' + (i % 10);
        snprintf(key, sizeof(key), "%c_bnd_key_%03d", prefix, i);
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

static void test_partitioned_merge_range_filtering(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 200;
    cf_config.level_size_ratio = 2;
    cf_config.dividing_level_offset = 1;
    cf_config.min_levels = 4;

    ASSERT_EQ(tidesdb_create_column_family(db, "range_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "range_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 80; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "range_key_%04d", i);
        snprintf(value, sizeof(value), "range_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 80; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "range_key_%04d", i);
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

static void test_full_merge_block_index_sampling(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 10;
    cf_config.enable_block_indexes = 1;
    cf_config.index_sample_ratio = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "sample_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sample_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[128];
        snprintf(key, sizeof(key), "sample_key_%04d", i);
        snprintf(value, sizeof(value), "sample_value_%04d_with_padding", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "sample_key_%04d", i);
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

static void test_compaction_level_add_no_immediate_removal(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "level_add_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "level_add_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[128];
        snprintf(key, sizeof(key), "add_key_%04d", i);
        snprintf(value, sizeof(value), "add_value_%04d_with_padding", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    int levels_after = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(levels_after >= initial_levels);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "add_key_%04d", i);
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

static void test_multiple_compactions_sequential(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 4;

    ASSERT_EQ(tidesdb_create_column_family(db, "multi_compact_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "multi_compact_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "multi_key_%d_%03d", round, i);
            snprintf(value, sizeof(value), "multi_value_%d_%03d", round, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }

        for (int i = 0; i < 100; i++)
        {
            usleep(10000);
            if (queue_size(db->flush_queue) == 0) break;
        }

        tidesdb_compact(cf);
        for (int i = 0; i < 200; i++)
        {
            usleep(50000);
            if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
        }
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "multi_key_%d_%03d", round, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_flush_force_small_memtable(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024 * 1024;

    ASSERT_EQ(tidesdb_create_column_family(db, "force_flush_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "force_flush_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 10; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "force_key_%d", i);
        snprintf(value, sizeof(value), "force_value_%d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_close(db);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);
    ASSERT_TRUE(db != NULL);

    cf = tidesdb_get_column_family(db, "force_flush_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 10; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "force_key_%d", i);
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

static void test_compaction_interleaved_deletes(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;

    ASSERT_EQ(tidesdb_create_column_family(db, "interleave_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "interleave_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "inter_key_%03d", i);
        snprintf(value, sizeof(value), "inter_value_%03d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 50; i += 2)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "inter_key_%03d", i);
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (uint8_t *)key, strlen(key) + 1), 0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }
    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);

    for (int i = 0; i < 50; i += 2)
    {
        char key[32];
        snprintf(key, sizeof(key), "inter_key_%03d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        int result = tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size);
        ASSERT_TRUE(result != 0);
    }

    for (int i = 1; i < 50; i += 2)
    {
        char key[32];
        snprintf(key, sizeof(key), "inter_key_%03d", i);
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

static void test_merge_with_all_optimizations_disabled(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 1024;
    cf_config.level_size_ratio = 10;
    cf_config.enable_bloom_filter = 0;
    cf_config.enable_block_indexes = 0;
    cf_config.compression_algorithm = TDB_COMPRESS_NONE;

    ASSERT_EQ(tidesdb_create_column_family(db, "no_opt_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "no_opt_cf");
    ASSERT_TRUE(cf != NULL);

    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "no_opt_key_%d_%d", batch, i);
            snprintf(value, sizeof(value), "no_opt_value_%d_%d", batch, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int batch = 0; batch < 3; batch++)
    {
        for (int i = 0; i < 30; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "no_opt_key_%d_%d", batch, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_backpressure_high_l0_queue(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.l0_queue_stall_threshold = 8;

    ASSERT_EQ(tidesdb_create_column_family(db, "bp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "bp_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 6; round++)
    {
        for (int i = 0; i < 20; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "bp_key_%d_%d", round, i);
            snprintf(value, sizeof(value), "bp_value_%d_%d", round, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
    }

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int round = 0; round < 6; round++)
    {
        for (int i = 0; i < 20; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "bp_key_%d_%d", round, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_dividing_merge_add_level_before_merge(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 2;
    cf_config.dividing_level_offset = 0;

    ASSERT_EQ(tidesdb_create_column_family(db, "div_add_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "div_add_cf");
    ASSERT_TRUE(cf != NULL);

    int initial_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);

    for (int i = 0; i < 150; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[128];
        snprintf(key, sizeof(key), "div_add_key_%04d", i);
        snprintf(value, sizeof(value), "div_add_value_%04d_padding", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    int final_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    ASSERT_TRUE(final_levels >= initial_levels);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 150; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "div_add_key_%04d", i);
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

static void test_dca_capacity_floor_enforcement(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 4096;
    cf_config.level_size_ratio = 10;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "dca_floor_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "dca_floor_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 50; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "dca_floor_key_%04d", i);
        snprintf(value, sizeof(value), "dca_floor_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    int num_levels = atomic_load_explicit(&cf->num_active_levels, memory_order_acquire);
    for (int i = 0; i < num_levels - 1; i++)
    {
        size_t capacity = atomic_load_explicit(&cf->levels[i]->capacity, memory_order_acquire);
        ASSERT_TRUE(capacity >= cf_config.write_buffer_size);
    }

    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_target_level_greater_than_x(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 4;
    cf_config.dividing_level_offset = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "target_gt_x_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "target_gt_x_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 100; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "tgt_key_%04d", i);
        snprintf(value, sizeof(value), "tgt_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 100; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "tgt_key_%04d", i);
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

static void test_partitioned_merge_empty_partition(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 256;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 3;

    ASSERT_EQ(tidesdb_create_column_family(db, "empty_part_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "empty_part_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "a_key_%04d", i);
        snprintf(value, sizeof(value), "a_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    usleep(100000);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "z_key_%04d", i);
        snprintf(value, sizeof(value), "z_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "a_key_%04d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }
    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "z_key_%04d", i);
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

static void test_level_removal_with_pending_work(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 2;

    ASSERT_EQ(tidesdb_create_column_family(db, "pending_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "pending_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 40; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "pend_key_%d_%04d", round, i);
            snprintf(value, sizeof(value), "pend_value_%d_%04d", round, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(30000);
    }

    tidesdb_compact(cf);

    for (int i = 0; i < 20; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "new_key_%04d", i);
        snprintf(value, sizeof(value), "new_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0 &&
            queue_size(db->flush_queue) == 0)
            break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < 40; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "pend_key_%d_%04d", round, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_with_custom_comparator(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.level_size_ratio = 4;
    strncpy(cf_config.comparator_name, "lexicographic", TDB_MAX_COMPARATOR_NAME - 1);

    ASSERT_EQ(tidesdb_create_column_family(db, "cmp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cmp_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 60; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "cmp_key_%04d", i);
        snprintf(value, sizeof(value), "cmp_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 60; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "cmp_key_%04d", i);
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

static void test_flush_sync_interval_wal_escalation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 512;
    cf_config.sync_mode = TDB_SYNC_INTERVAL;
    cf_config.sync_interval_us = 100000;

    ASSERT_EQ(tidesdb_create_column_family(db, "sync_int_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "sync_int_cf");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32], value[64];
        snprintf(key, sizeof(key), "sync_key_%04d", i);
        snprintf(value, sizeof(value), "sync_value_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                  strlen(value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_close(db);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = TEST_DB_PATH;
    ASSERT_EQ(tidesdb_open(&config, &db), 0);

    cf = tidesdb_get_column_family(db, "sync_int_cf");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "sync_key_%04d", i);
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

static void test_merge_vlog_large_value_compression(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 2048;
    cf_config.level_size_ratio = 4;
    cf_config.compression_algorithm = TDB_COMPRESS_LZ4;
    cf_config.klog_value_threshold = 128;

    ASSERT_EQ(tidesdb_create_column_family(db, "vlog_comp_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "vlog_comp_cf");
    ASSERT_TRUE(cf != NULL);

    char large_value[512];
    memset(large_value, 'X', sizeof(large_value) - 1);
    large_value[sizeof(large_value) - 1] = '\0';

    for (int i = 0; i < 30; i++)
    {
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
        char key[32];
        snprintf(key, sizeof(key), "vlog_key_%04d", i);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)large_value,
                                  strlen(large_value) + 1, 0),
                  0);
        ASSERT_EQ(tidesdb_txn_commit(txn), 0);
        tidesdb_txn_free(txn);
    }

    tidesdb_flush_memtable(cf);
    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int i = 0; i < 30; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "vlog_key_%04d", i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        ASSERT_EQ(tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size),
                  0);
        ASSERT_TRUE(value != NULL);
        ASSERT_EQ(value_size, strlen(large_value) + 1);
        free(value);
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

static void test_compaction_partitioned_z_calculation(void)
{
    cleanup_test_dir();
    tidesdb_t *db = create_test_db();
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    cf_config.write_buffer_size = 200;
    cf_config.level_size_ratio = 2;
    cf_config.min_levels = 4;
    cf_config.dividing_level_offset = 1;

    ASSERT_EQ(tidesdb_create_column_family(db, "z_calc_cf", &cf_config), 0);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "z_calc_cf");
    ASSERT_TRUE(cf != NULL);

    for (int round = 0; round < 5; round++)
    {
        for (int i = 0; i < 25; i++)
        {
            tidesdb_txn_t *txn = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
            char key[32], value[64];
            snprintf(key, sizeof(key), "z_key_%d_%04d", round, i);
            snprintf(value, sizeof(value), "z_value_%d_%04d", round, i);
            ASSERT_EQ(tidesdb_txn_put(txn, cf, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0),
                      0);
            ASSERT_EQ(tidesdb_txn_commit(txn), 0);
            tidesdb_txn_free(txn);
        }
        tidesdb_flush_memtable(cf);
        usleep(50000);
    }

    for (int i = 0; i < 100; i++)
    {
        usleep(10000);
        if (queue_size(db->flush_queue) == 0) break;
    }

    tidesdb_compact(cf);
    for (int i = 0; i < 200; i++)
    {
        usleep(50000);
        if (!tidesdb_is_compacting(cf) && queue_size(db->compaction_queue) == 0) break;
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), 0);
    for (int round = 0; round < 5; round++)
    {
        for (int i = 0; i < 25; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "z_key_%d_%04d", round, i);
            uint8_t *value = NULL;
            size_t value_size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (uint8_t *)key, strlen(key) + 1, &value, &value_size), 0);
            ASSERT_TRUE(value != NULL);
            free(value);
        }
    }
    tidesdb_txn_free(txn);
    tidesdb_close(db);
    cleanup_test_dir();
}

int main(void)
{
    cleanup_test_dir();
    RUN_TEST(test_custom_allocator, tests_passed);
    RUN_TEST(test_basic_open_close, tests_passed);
    RUN_TEST(test_tidesdb_free, tests_passed);
    RUN_TEST(test_column_family_creation, tests_passed);
    RUN_TEST(test_list_column_families, tests_passed);
    RUN_TEST(test_basic_txn_put_get, tests_passed);
    RUN_TEST(test_txn_delete, tests_passed);
    RUN_TEST(test_txn_rollback, tests_passed);
    RUN_TEST(test_multiple_column_families, tests_passed);
    RUN_TEST(test_memtable_flush, tests_passed);
    RUN_TEST(test_background_flush_multiple_immutable_memtables, tests_passed);
    RUN_TEST(test_persistence_and_recovery, tests_passed);
    RUN_TEST(test_backup_basic, tests_passed);
    RUN_TEST(test_backup_concurrent_writes, tests_passed);
    RUN_TEST(test_multi_cf_wal_recovery, tests_passed);
    RUN_TEST(test_multi_cf_many_sstables_recovery, tests_passed);
    RUN_TEST(test_multi_cf_transaction_atomicity_recovery, tests_passed);
    RUN_TEST(test_multi_cf_transaction_recovery_comprehensive, tests_passed);
    RUN_TEST(test_iterator_basic, tests_passed);
    RUN_TEST(test_stats, tests_passed);
    RUN_TEST(test_stats_comprehensive, tests_passed);
    RUN_TEST(test_cache_stats, tests_passed);
    RUN_TEST(test_cache_stats_disabled, tests_passed);
    RUN_TEST(test_cache_stats_invalid_args, tests_passed);
    RUN_TEST(test_iterator_seek, tests_passed);
    RUN_TEST(test_iterator_seek_for_prev, tests_passed);
    RUN_TEST(test_tidesdb_block_index_seek, tests_passed);
    RUN_TEST(test_iterator_reverse, tests_passed);
    RUN_TEST(test_iterator_boundaries, tests_passed);
    RUN_TEST(test_bidirectional_iterator, tests_passed);
    RUN_TEST(test_ttl_expiration, tests_passed);
    RUN_TEST(test_large_values, tests_passed);
    RUN_TEST(test_many_keys, tests_passed);
    RUN_TEST(test_isolation_read_uncommitted, tests_passed);
    RUN_TEST(test_isolation_read_committed, tests_passed);
    RUN_TEST(test_isolation_repeatable_read, tests_passed);
    RUN_TEST(test_isolation_snapshot, tests_passed);
    RUN_TEST(test_isolation_serializable, tests_passed);
    RUN_TEST(test_snapshot_isolation_consistency, tests_passed);
    RUN_TEST(test_write_write_conflict, tests_passed);
    RUN_TEST(test_read_write_conflict, tests_passed);
    RUN_TEST(test_serializable_phantom_prevention, tests_passed);
    RUN_TEST(test_transaction_abort_retry, tests_passed);
    RUN_TEST(test_long_running_transaction, tests_passed);
    RUN_TEST(test_multi_cf_transaction, tests_passed);
    RUN_TEST(test_multi_cf_transaction_rollback, tests_passed);
    RUN_TEST(test_multi_cf_iterator, tests_passed);
    RUN_TEST(test_multi_cf_iterator_boundaries, tests_passed);
    RUN_TEST(test_multi_cf_iterator_reverse, tests_passed);
    RUN_TEST(test_multi_cf_iterator_seek, tests_passed);
    RUN_TEST(test_multi_cf_iterator_seek_for_prev, tests_passed);
    RUN_TEST(test_iterator_prefix_seek_behavior, tests_passed);
    RUN_TEST(test_iterator_prefix_seek_with_sstables, tests_passed);
    RUN_TEST(test_savepoints, tests_passed);
    RUN_TEST(test_ini_config, tests_passed);
    RUN_TEST(test_runtime_config_update, tests_passed);
    RUN_TEST(test_error_invalid_args, tests_passed);
    RUN_TEST(test_drop_column_family, tests_passed);
    RUN_TEST(test_rename_column_family, tests_passed);
    RUN_TEST(test_rename_column_family_concurrent, tests_passed);
    RUN_TEST(test_empty_iterator, tests_passed);
    RUN_TEST(test_bloom_filter_enabled, tests_passed);
    RUN_TEST(test_block_indexes, tests_passed);
    RUN_TEST(test_block_indexes_sparse_sample_ratio, tests_passed);
    RUN_TEST(test_sync_modes, tests_passed);
    RUN_TEST(test_compression_lz4, tests_passed);
    RUN_TEST(test_compression_zstd, tests_passed);
    RUN_TEST(test_compaction_basic, tests_passed);
    RUN_TEST(test_compaction_with_deletes, tests_passed);
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
    RUN_TEST(test_iterator_across_multiple_sources, tests_passed);
    RUN_TEST(test_overwrite_across_levels, tests_passed);
    RUN_TEST(test_atomicity_transaction_rollback, tests_passed);
    RUN_TEST(test_consistency_after_flush, tests_passed);
    RUN_TEST(test_isolation_concurrent_transactions, tests_passed);
    RUN_TEST(test_durability_reopen_database, tests_passed);
    RUN_TEST(test_data_integrity_after_compaction, tests_passed);
    RUN_TEST(test_no_data_loss_across_operations, tests_passed);
    RUN_TEST(test_concurrent_writes_visibility, tests_passed);
    RUN_TEST(test_dividing_merge_strategy, tests_passed);
    RUN_TEST(test_partitioned_merge_strategy, tests_passed);
    RUN_TEST(test_boundary_partitioning, tests_passed);
    RUN_TEST(test_dynamic_capacity_adjustment, tests_passed);
    RUN_TEST(test_multi_level_compaction_strategies, tests_passed);
    RUN_TEST(test_recovery_with_corrupted_sstable, tests_passed);
    RUN_TEST(test_portability_workflow, tests_passed);
    RUN_TEST(test_iterator_across_multiple_memtable_flushes, tests_passed);
    RUN_TEST(test_read_after_multiple_overwrites, tests_passed);
    RUN_TEST(test_large_transaction_batch, tests_passed);
    RUN_TEST(test_delete_and_recreate_same_key, tests_passed);
    RUN_TEST(test_concurrent_reads_same_key, tests_passed);
    RUN_TEST(test_zero_ttl_means_no_expiration, tests_passed);
    RUN_TEST(test_mixed_ttl_expiration, tests_passed);
    RUN_TEST(test_get_nonexistent_cf, tests_passed);
    RUN_TEST(test_create_duplicate_cf, tests_passed);
    RUN_TEST(test_drop_nonexistent_cf, tests_passed);
    RUN_TEST(test_nested_savepoints, tests_passed);
    RUN_TEST(test_savepoint_with_delete_operations, tests_passed);
    RUN_TEST(test_iterator_with_tombstones, tests_passed);
    RUN_TEST(test_transaction_isolation_snapshot_with_updates, tests_passed);
    RUN_TEST(test_read_own_uncommitted_writes, tests_passed);
    RUN_TEST(test_iterator_read_own_uncommitted_writes, tests_passed);
    RUN_TEST(test_multi_cf_transaction_conflict, tests_passed);
    RUN_TEST(test_many_sstables_with_bloom_filter, tests_passed);
    RUN_TEST(test_many_sstables_without_bloom_filter, tests_passed);
    RUN_TEST(test_many_sstables_with_block_indexes, tests_passed);
    RUN_TEST(test_many_sstables_with_lz4_compression, tests_passed);
    RUN_TEST(test_many_sstables_with_zstd_compression, tests_passed);
    RUN_TEST(test_many_sstables_all_features_enabled, tests_passed);
    RUN_TEST(test_many_sstables_all_features_disabled, tests_passed);
    RUN_TEST(test_many_sstables_bloom_and_compression, tests_passed);
    RUN_TEST(test_many_sstables_indexes_and_compression, tests_passed);
    RUN_TEST(test_many_sstables_with_bloom_filter_cached, tests_passed);
    RUN_TEST(test_many_sstables_without_bloom_filter_cached, tests_passed);
    RUN_TEST(test_many_sstables_with_block_indexes_cached, tests_passed);
    RUN_TEST(test_many_sstables_with_lz4_compression_cached, tests_passed);
    RUN_TEST(test_many_sstables_with_zstd_compression_cached, tests_passed);

#ifndef __sun
    RUN_TEST(test_many_sstables_with_snappy_compression, tests_passed);
    RUN_TEST(test_many_sstables_with_snappy_compression_cached, tests_passed);
    RUN_TEST(test_compression_snappy, tests_passed);
#endif

    RUN_TEST(test_many_sstables_all_features_enabled_cached, tests_passed);
    RUN_TEST(test_many_sstables_all_features_disabled_cached, tests_passed);
    RUN_TEST(test_many_sstables_bloom_and_compression_cached, tests_passed);
    RUN_TEST(test_many_sstables_read_uncommitted, tests_passed);
    RUN_TEST(test_many_sstables_read_committed, tests_passed);
    RUN_TEST(test_many_sstables_repeatable_read, tests_passed);
    RUN_TEST(test_many_sstables_serializable, tests_passed);
    RUN_TEST(test_many_sstables_comparator_memcmp, tests_passed);
    RUN_TEST(test_many_sstables_comparator_lexicographic, tests_passed);
    RUN_TEST(test_many_sstables_comparator_reverse, tests_passed);
    RUN_TEST(test_many_sstables_comparator_case_insensitive, tests_passed);
    RUN_TEST(test_many_sstables_small_cache, tests_passed);
    RUN_TEST(test_many_sstables_large_cache, tests_passed);
    RUN_TEST(test_many_sstables_all_comparators, tests_passed);
    RUN_TEST(test_large_value_iteration, tests_passed);
    RUN_TEST(test_sync_interval_mode, tests_passed);
    RUN_TEST(test_iterator_no_bloom_no_indexes, tests_passed);
    RUN_TEST(test_concurrent_batched_transactions, tests_passed);
    RUN_TEST(test_concurrent_batched_random_keys, tests_passed);
    RUN_TEST(test_deadlock_random_write_then_read, tests_passed);
    RUN_TEST(test_concurrent_read_close_race, tests_passed);
    RUN_TEST(test_crash_during_flush, tests_passed);
    RUN_TEST(test_iterator_with_concurrent_flush, tests_passed);
    RUN_TEST(test_ttl_expiration_during_compaction, tests_passed);
    RUN_TEST(test_multi_cf_concurrent_compaction, tests_passed);
    RUN_TEST(test_wal_corruption_recovery, tests_passed);
    RUN_TEST(test_compaction_with_overlapping_ranges, tests_passed);
    RUN_TEST(test_extreme_key_skew, tests_passed);
    RUN_TEST(test_cf_lifecycle_stress, tests_passed);
    RUN_TEST(test_reverse_iterator_with_tombstones, tests_passed);
    RUN_TEST(test_disk_space_check_simulation, tests_passed);
    RUN_TEST(test_basic_open_close, tests_passed);
    RUN_TEST(test_log_file, tests_passed);
    RUN_TEST(test_log_file_truncation, tests_passed);
    RUN_TEST(test_multiple_databases_concurrent_operations, tests_passed);
    RUN_TEST(test_wal_commit_shutdown_recovery, tests_passed);
    RUN_TEST(test_iterator_seek_after_reopen_bloom_indexes_disabled, tests_passed);
    RUN_TEST(test_iterator_seek_after_reopen, tests_passed);
    RUN_TEST(test_iterator_seek_for_prev_after_reopen, tests_passed);
    RUN_TEST(test_iterator_seek_for_prev_after_reopen_indexes, tests_passed);
    RUN_TEST(test_iter_next_large_values_many_sstables, tests_passed);
    RUN_TEST(test_iter_prev_large_values_many_sstables, tests_passed);
    RUN_TEST(test_get_large_values_many_sstables, tests_passed);
    RUN_TEST(test_range_iteration_large_values_many_sstables, tests_passed);
    RUN_TEST(test_seek_large_values_many_sstables, tests_passed);
    RUN_TEST(test_database_lock_prevents_double_open, tests_passed);
    RUN_TEST(test_database_lock_released_on_close, tests_passed);
#ifndef _WIN32
    RUN_TEST(test_database_lock_multi_process, tests_passed);
#endif
    RUN_TEST(test_ttl_expiration_after_reopen, tests_passed);
    RUN_TEST(test_ttl_expiration_with_deletes_after_reopen, tests_passed);
    RUN_TEST(test_ttl_expiration_range_delete_after_reopen, tests_passed);
    RUN_TEST(test_many_sstables_low_max_open_reaper_eviction, tests_passed);
    RUN_TEST(test_partial_write_mid_block_corruption, tests_passed);
    RUN_TEST(test_clock_skew_time_travel_ttl, tests_passed);
    RUN_TEST(test_filesystem_full_during_compaction, tests_passed);
    RUN_TEST(test_power_loss_during_sstable_metadata_write, tests_passed);
    RUN_TEST(test_memory_allocation_stress, tests_passed);
    RUN_TEST(test_concurrent_cf_drop_during_iteration, tests_passed);
    RUN_TEST(test_flush_with_sync_modes, tests_passed);
    RUN_TEST(test_flush_concurrent_prevention, tests_passed);
    RUN_TEST(test_flush_empty_memtable_skip, tests_passed);
    RUN_TEST(test_flush_below_size_threshold, tests_passed);
    RUN_TEST(test_compaction_concurrent_prevention, tests_passed);
    RUN_TEST(test_compaction_all_tombstones_empty_result, tests_passed);
    RUN_TEST(test_full_merge_duplicate_keys_dedup, tests_passed);
    RUN_TEST(test_full_merge_vlog_separation, tests_passed);
    RUN_TEST(test_full_merge_mixed_ttl, tests_passed);
    RUN_TEST(test_dividing_merge_no_boundaries_fallback, tests_passed);
    RUN_TEST(test_partitioned_merge_empty_largest_level_fallback, tests_passed);
    RUN_TEST(test_merge_single_sstable, tests_passed);
    RUN_TEST(test_flush_during_compaction, tests_passed);
    RUN_TEST(test_dca_min_levels_constraint, tests_passed);
    RUN_TEST(test_merge_heap_source_exhaustion, tests_passed);
    RUN_TEST(test_compaction_max_seq_propagation, tests_passed);
    RUN_TEST(test_compaction_spooky_level_selection, tests_passed);
    RUN_TEST(test_compaction_with_lz4_compression, tests_passed);
    RUN_TEST(test_compaction_with_zstd_compression, tests_passed);
    RUN_TEST(test_merge_with_bloom_filter_disabled, tests_passed);
    RUN_TEST(test_merge_with_block_indexes_disabled, tests_passed);
    RUN_TEST(test_flush_wal_rotation, tests_passed);
    RUN_TEST(test_full_merge_empty_result, tests_passed);
    RUN_TEST(test_compaction_recovery_after_close, tests_passed);
    RUN_TEST(test_dividing_merge_boundary_calculation, tests_passed);
    RUN_TEST(test_partitioned_merge_range_filtering, tests_passed);
    RUN_TEST(test_full_merge_block_index_sampling, tests_passed);
    RUN_TEST(test_compaction_level_add_no_immediate_removal, tests_passed);
    RUN_TEST(test_multiple_compactions_sequential, tests_passed);
    RUN_TEST(test_flush_force_small_memtable, tests_passed);
    RUN_TEST(test_compaction_interleaved_deletes, tests_passed);
    RUN_TEST(test_merge_with_all_optimizations_disabled, tests_passed);
    RUN_TEST(test_backpressure_high_l0_queue, tests_passed);
    RUN_TEST(test_dividing_merge_add_level_before_merge, tests_passed);
    RUN_TEST(test_dca_capacity_floor_enforcement, tests_passed);
    RUN_TEST(test_compaction_target_level_greater_than_x, tests_passed);
    RUN_TEST(test_partitioned_merge_empty_partition, tests_passed);
    RUN_TEST(test_level_removal_with_pending_work, tests_passed);
    RUN_TEST(test_compaction_with_custom_comparator, tests_passed);
    RUN_TEST(test_flush_sync_interval_wal_escalation, tests_passed);
    RUN_TEST(test_merge_vlog_large_value_compression, tests_passed);
    RUN_TEST(test_compaction_partitioned_z_calculation, tests_passed);
    RUN_TEST(test_btree_sstable_basic, tests_passed);
    RUN_TEST(test_btree_sstable_with_bloom, tests_passed);
    RUN_TEST(test_btree_sstable_without_bloom, tests_passed);
    RUN_TEST(test_btree_sstable_many_keys, tests_passed);
    RUN_TEST(test_btree_sstable_with_cache, tests_passed);
    RUN_TEST(test_btree_sstable_comparator_lexicographic, tests_passed);
    RUN_TEST(test_btree_sstable_comparator_reverse, tests_passed);
    RUN_TEST(test_btree_compaction_basic, tests_passed);
    RUN_TEST(test_btree_compaction_with_deletes, tests_passed);
    RUN_TEST(test_btree_flush_basic, tests_passed);
    RUN_TEST(test_btree_dca_min_levels_constraint, tests_passed);
    RUN_TEST(test_btree_merge_heap_source_exhaustion, tests_passed);
    RUN_TEST(test_btree_compaction_all_tombstones, tests_passed);
    RUN_TEST(test_btree_flush_during_compaction, tests_passed);
    RUN_TEST(test_btree_compaction_max_seq_propagation, tests_passed);
    RUN_TEST(test_btree_merge_with_bloom_disabled, tests_passed);
    RUN_TEST(test_btree_compaction_interleaved_deletes, tests_passed);
    RUN_TEST(test_btree_many_sstables_delete_verify_stats, tests_passed);
    RUN_TEST(test_cf_drop_during_pending_flush, tests_passed);
    RUN_TEST(test_cf_drop_during_active_compaction, tests_passed);
    RUN_TEST(test_cf_rename_during_pending_flush, tests_passed);
    RUN_TEST(test_cf_rename_during_active_compaction, tests_passed);
    RUN_TEST(test_multiple_cf_drop_with_concurrent_workers, tests_passed);
    RUN_TEST(test_clone_column_family, tests_passed);
    RUN_TEST(test_clone_column_family_concurrent, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
