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
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>

#include "../src/tidesdb.h"
#include "test_macros.h"
#include "test_utils.h"

#define TEST_DIR           "testdb"
#define TEST_COLUMN_FAMILY "cf"

void test_open_close()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL)
    {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_open_close passed\n" RESET);
}

void test_create_column_family()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    free(tdb_config);

    remove_directory(TEST_DIR);

    printf(GREEN "test_create_column_family passed\n" RESET);
}

void test_drop_column_family()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* drop the column family */
    e = tidesdb_drop_column_family(tdb, TEST_COLUMN_FAMILY);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    /* we should not be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == -1);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_drop_column_family passed\n" RESET);
}

void test_put()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 24000 key-value pairs */
    for (int i = 0; i < 24000; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put passed\n" RESET);
}

void test_put_get()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 240 key-value pairs */
    for (int i = 0; i < 240; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }
    }

    /* we get the key-value pairs */
    for (int i = 0; i < 240; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
        }

        assert(e == NULL);
        assert(value_len == strlen((uint8_t*)value));
        assert(strncmp((uint8_t*)value_out, (uint8_t*)value, value_len) == 0);
        free(value_out);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_get passed\n" RESET);
}

void test_put_flush_get()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, (1024 * 1024), 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 24000 key-value pairs
     * this creates 1 SST file and some in-memory data in the column family memtable on most systems
     */
    for (int i = 0; i < 24000; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }
    }

    sleep(5); /* wait for the SST file to be written */

    /* we get the key-value pairs */
    for (int i = 0; i < 24000 / 12;
         i++) /* remove division by 12 to test all key-value pairs for a slower test.. */
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        assert(e == NULL);
        tidesdb_err_free(e);
        assert(value_len == strlen((uint8_t*)value));
        assert(strncmp((uint8_t*)value_out, (uint8_t*)value, value_len) == 0);
        free(value_out);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_flush_get passed\n" RESET);
}

/* this test puts 50 key-value pairs, closes the database, reopens it, and gets the key-value pairs
 * by doing this we are testing the WAL recovery as we are not hitting the flush threshold, we are
 * replaying the WAL and populate the memtable with the key-value pairs */
void test_put_reopen_get()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL)
    {
        printf(RED "Error: %s\n" RESET, e->message);
        tidesdb_err_free(e);
        free(tdb_config);
        return;
    }
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 50 key-value pairs */
    for (int i = 0; i < 50; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    tdb = NULL;

    /* reopen recovers from the WAL as no flush was triggered */
    e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL)
    {
        printf(RED "Error: %s\n" RESET, e->message);
        tidesdb_err_free(e);
        free(tdb_config);
        return;
    }

    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* we get the key-value pairs */
    for (int i = 0; i < 50; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, TEST_COLUMN_FAMILY, key, strlen(key), &value_out, &value_len);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            continue;
        }

        assert(e == NULL);
        assert(value_len == strlen((uint8_t*)value));
        assert(strncmp((uint8_t*)value_out, (uint8_t*)value, value_len) == 0);
        free(value_out);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_get_reopen passed\n" RESET);
}

void test_put_get_delete()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 240 key-value pairs */
    for (int i = 0; i < 240; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    /* we delete the key-value pairs */
    for (int i = 0; i < 240; i++)
    {
        uint8_t key[48];
        snprintf(key, sizeof(key), "key%d", i);

        e = tidesdb_delete(tdb, cf->config.name, key, strlen(key));
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
        }
    }

    /* we get the key-value pairs */
    for (int i = 0; i < 240; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);

        free(value_out);
        /* we should get an error as the key-value pairs have been deleted */
        assert(e != NULL);

        tidesdb_err_free(e);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_get_delete passed\n" RESET);
}

void test_txn_put_delete_get()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    tidesdb_txn_t* transaction;
    e = tidesdb_txn_begin(&transaction, TEST_COLUMN_FAMILY);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    const uint8_t key[] = "example_key";
    const uint8_t value[] = "example_value";
    const uint8_t key2[] = "example_key2";
    const uint8_t value2[] = "example_value2";
    const uint8_t key3[] = "example_key3";
    const uint8_t value3[] = "example_value3";

    e = tidesdb_txn_put(transaction, key, sizeof(key), value, sizeof(value), -1);

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_txn_put(transaction, key2, sizeof(key2), value2, sizeof(value2), -1);

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_txn_put(transaction, key3, sizeof(key3), value3, sizeof(value3), -1);

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_txn_delete(transaction, key2, sizeof(key2));

    assert(e == NULL);

    tidesdb_err_free(e);

    /* commit the transaction */
    e = tidesdb_txn_commit(tdb, transaction);

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_txn_free(transaction);

    assert(e == NULL);
    tidesdb_err_free(e);

    /* get the key-value pairs */
    size_t value_len = 0;
    uint8_t* value_out = NULL;

    e = tidesdb_get(tdb, TEST_COLUMN_FAMILY, key, sizeof(key), &value_out, &value_len);
    if (e != NULL)
    {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    else
    {
        free(value_out);
    }

    assert(e == NULL);
    tidesdb_err_free(e);

    e = tidesdb_get(tdb, TEST_COLUMN_FAMILY, key2, sizeof(key), &value_out, &value_len);

    assert(e != NULL);

    tidesdb_err_free(e);

    e = tidesdb_get(tdb, TEST_COLUMN_FAMILY, key3, sizeof(key3), &value_out, &value_len);
    if (e != NULL)
    {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    else
    {
        free(value_out);
    }

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_txn_put_delete_get passed\n" RESET);
}

void test_put_compact()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 100k key-value pairs */
    for (int i = 0; i < 100000; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    sleep(5); /* wait for the SST files to be written */

    /* we compact */
    e = tidesdb_compact_sstables(tdb, cf, 2);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_compact passed\n" RESET);
}

void test_put_compact_get()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 100k key-value pairs */
    for (int i = 0; i < 100000; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    sleep(5); /* wait for the SST files to be written */

    /* we compact */
    e = tidesdb_compact_sstables(tdb, cf, 4);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    /* get the key-value pairs */
    for (int i = 0; i < 100000 / 390.625; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            continue;
        }

        assert(e == NULL);

        assert(value_len == strlen((uint8_t*)value));
        assert(strncmp((uint8_t*)value_out, (uint8_t*)value, value_len) == 0);

        free(value_out); /* free the value_out pointer */
        value_out = NULL;
        value_len = 0;
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_put_compact_get passed\n" RESET);
}

void test_put_compact_reopen_get()
{
    tidesdb_config_t* tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* put 100k key-value pairs */
    for (int i = 0; i < 100000; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }

        assert(e == NULL);
    }

    sleep(5); /* wait for the SST files to be written */

    /* we compact */
    e = tidesdb_compact_sstables(tdb, cf, 2);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    tidesdb_err_free(e);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);
    free(tdb_config);

    /* reopen the database */
    tdb = NULL;

    tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* re-fetch the column family */
    cf = NULL;
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    /* get the key-value pairs */
    for (int i = 0; i < 100000 / 390.625; i++)
    {
        uint8_t key[38];
        uint8_t value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            continue;
        }

        assert(e == NULL);
        assert(value_len == strlen((uint8_t*)value));
        assert(strncmp((uint8_t*)value_out, (uint8_t*)value, value_len) == 0);

        free(value_out); /* free the value_out pointer */
        value_out = NULL;
        value_len = 0;
        tidesdb_err_free(e);
    }

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);
    free(tdb_config);
    remove_directory(TEST_DIR);

    printf(GREEN "test_put_compact_get_reopen passed\n" RESET);
}

void* put_thread(void* arg)
{
    tidesdb_t* tdb = (tidesdb_t*)arg;
    column_family_t* cf = NULL;
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    for (int i = 0; i < 1200; i++)
    {
        uint8_t key[48];
        uint8_t value[48];
        snprintf(key, sizeof(key), "key_put%03d", i);
        snprintf(value, sizeof(value), "value_put%03d", i);

        tidesdb_err_t* e =
            tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL)
        {
            printf(RED "Error: %s\n" RESET, e->message);
            tidesdb_err_free(e);
            break;
        }
    }

    return NULL;
}

/* helper for test_concurrent_put_get */
void* get_thread(void* arg)
{
    tidesdb_t* tdb = (tidesdb_t*)arg;
    column_family_t* cf = NULL;
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    for (int i = 0; i < 1200; i++)
    {
        uint8_t key[48];
        snprintf(key, sizeof(key), "key_put%03d", i);

        size_t value_len = 0;
        uint8_t* value_out = NULL;
        tidesdb_err_t* e = NULL;

        while (true)
        {
            e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
            if (e == NULL)
            {
                break;
            }
            else
            {
                printf(MAGENTA "Retrying concurrent get operation %s\n" RESET, e->message);
                tidesdb_err_free(e);
                free(value_out);
                sleep(1); /* wait for a second before retrying **/
            }
        }

        assert(e == NULL);
        free(value_out); /* free the value_out pointer */
    }

    return NULL;
}

void test_concurrent_put_get()
{
    tidesdb_config_t* tdb_config = malloc(sizeof(tidesdb_config_t));
    if (tdb_config == NULL)
    {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = TEST_DIR;
    tdb_config->compressed_wal = false;

    tidesdb_t* tdb = NULL;

    tidesdb_err_t* e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);
    assert(e == NULL);
    assert(tdb != NULL);

    tidesdb_err_free(e);

    /* create a column family */
    e = tidesdb_create_column_family(tdb, TEST_COLUMN_FAMILY, 1024 * 1024, 12, 0.24f, false);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    assert(e == NULL);

    tidesdb_err_free(e);

    column_family_t* cf = NULL;

    /* we should be able to get the column family */
    assert(_get_column_family(tdb, TEST_COLUMN_FAMILY, &cf) == 0);

    pthread_t put_tid, get_tid;

    pthread_create(&put_tid, NULL, put_thread, tdb);
    pthread_create(&get_tid, NULL, get_thread, tdb);

    pthread_join(put_tid, NULL);
    pthread_join(get_tid, NULL);

    e = tidesdb_close(tdb);
    if (e != NULL) printf(RED "Error: %s\n" RESET, e->message);

    tidesdb_err_free(e);

    remove_directory(TEST_DIR);

    free(tdb_config);

    printf(GREEN "test_concurrent_put_get passed\n" RESET);
}

/** cc -g3 -fsanitize=address,undefined src/*.c external/*.c test/tidesdb__tests.c -lzstd
 * **/
int main(void)
{
    remove_directory(TEST_DIR);
    test_open_close();
    test_create_column_family();
    test_drop_column_family();
    test_put();
    test_put_get();
    test_put_flush_get();
    test_put_reopen_get();
    test_put_get_delete();
    test_concurrent_put_get();
    test_put_compact();
    test_put_compact_get();
    test_put_compact_reopen_get();
    test_txn_put_delete_get();

    return 0;
}