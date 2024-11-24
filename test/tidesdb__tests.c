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

void test_open_close() {
    tidesdb_config* tdb_config = (malloc(sizeof(tidesdb_config)));

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    const tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);

    assert(tdb != NULL);
    tidesdb_close(tdb);

    remove_directory("testdb");

    printf(GREEN "test_open_close passed\n" RESET);
}

void test_create_column_family() {
    tidesdb_config* tdb_config = (malloc(sizeof(tidesdb_config)));

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);

    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    tidesdb_close(tdb);

    remove_directory("testdb");

    printf(GREEN "test_create_column_family passed\n" RESET);
}

void test_drop_column_family() {
    tidesdb_config* tdb_config = (malloc(sizeof(tidesdb_config)));

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);

    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // drop the column family
    e = tidesdb_drop_column_family(tdb, "test_cf");
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    free(e);
    e = NULL;

    // we should not be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 0);

    tidesdb_close(tdb);

    remove_directory("testdb");

    printf(GREEN "test_drop_column_family passed\n" RESET);
}

void test_put() {
    tidesdb_config* tdb_config = (malloc(sizeof(tidesdb_config)));

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);

    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 24000 key-value pairs
    for (int i = 0; i < 24000; i++) {
        char key[24];
        char value[24];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);

    remove_directory("testdb");

    printf(GREEN "test_put passed\n" RESET);
}

void test_put_get() {
    tidesdb_config* tdb_config = (tidesdb_config*)malloc(sizeof(tidesdb_config));
    if (tdb_config == NULL) {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 240 key-value pairs
    for (int i = 0; i < 240; i++) {
        char key[48];
        char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    // we get the key-value pairs
    for (int i = 0; i < 240; i++) {
        unsigned char key[48];
        unsigned char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        unsigned char* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            free(e);
            e = NULL;
            continue;
        }

        assert(e == NULL);
        assert(value_len == strlen((char*)value));
        assert(strncmp((char*)value_out, (char*)value, value_len) == 0);

        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);
    free(tdb_config);

    remove_directory("testdb");

    printf(GREEN "test_put_get passed\n" RESET);
}

void test_put_flush_get() {
    tidesdb_config* tdb_config = (tidesdb_config*)malloc(sizeof(tidesdb_config));
    if (tdb_config == NULL) {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 24000 key-value pairs
    // this creates 1 SST file and some in-memory data in the column family memtable
    for (int i = 0; i < 24000; i++) {
        char key[48];
        char value[48];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    sleep(3);  // wait for the SST file to be written

    // we get the key-value pairs
    for (int i = 0; i < 100; i++) {
        unsigned char key[48];
        unsigned char value[48];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d", i);

        size_t value_len = 0;
        unsigned char* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            free(e);
            e = NULL;
            continue;
        }

        assert(e == NULL);
        assert(value_len == strlen((char*)value));
        assert(strncmp((char*)value_out, (char*)value, value_len) == 0);

        free(value_out);  // Free the value_out pointer
        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);
    free(tdb_config);

    remove_directory("testdb");

    printf(GREEN "test_put_flush_get passed\n" RESET);
}

// this test puts 50 key-value pairs, closes the database, reopens it, and gets the key-value pairs
// by doing this we are testing the WAL recovery as we are not hitting the flush threshold, we are
// replaying the WAL and populate the memtable with the key-value pairs
void test_put_reopen_get() {
    tidesdb_config* tdb_config = (tidesdb_config*)malloc(sizeof(tidesdb_config));
    if (tdb_config == NULL) {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 50 key-value pairs
    for (int i = 0; i < 50; i++) {
        char key[48];
        char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);

    tdb = NULL;

    e = tidesdb_open(tdb_config, &tdb);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // we get the key-value pairs
    for (int i = 0; i < 50; i++) {
        unsigned char key[48];
        unsigned char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        unsigned char* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            free(e);
            e = NULL;
            continue;
        }

        assert(e == NULL);
        assert(value_len == strlen((char*)value));
        assert(strncmp((char*)value_out, (char*)value, value_len) == 0);

        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);
    free(tdb_config);

    remove_directory("testdb");

    printf(GREEN "test_put_get_reopen passed\n" RESET);
}

void test_put_get_delete() {
    tidesdb_config* tdb_config = (tidesdb_config*)malloc(sizeof(tidesdb_config));
    if (tdb_config == NULL) {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 240 key-value pairs
    for (int i = 0; i < 240; i++) {
        char key[48];
        char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    // we delete the key-value pairs
    for (int i = 0; i < 240; i++) {
        unsigned char key[48];
        snprintf(key, sizeof(key), "key%d", i);

        e = tidesdb_delete(tdb, cf->config.name, key, strlen(key));
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            free(e);
            e = NULL;
            continue;
        }
    }

    // we get the key-value pairs
    for (int i = 0; i < 240; i++) {
        unsigned char key[48];
        unsigned char value[48];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        size_t value_len = 0;
        unsigned char* value_out = NULL;

        e = tidesdb_get(tdb, cf->config.name, key, strlen(key), &value_out, &value_len);

        // we should get an error as the key-value pairs have been deleted
        assert(e != NULL);

        free(e);
        e = NULL;
    }

    tidesdb_close(tdb);
    free(tdb_config);

    remove_directory("testdb");

    printf(GREEN "test_put_get_delete passed\n" RESET);
}

void test_txn_put_delete_get() {
    tidesdb_config* tdb_config = (tidesdb_config*)malloc(sizeof(tidesdb_config));
    if (tdb_config == NULL) {
        printf(RED "Error: Failed to allocate memory for tdb_config\n" RESET);
        return;
    }

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);
    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    txn* txn = NULL;
    e = tidesdb_txn_begin(&txn, cf->config.name);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    // we add some put operations to the transaction and a final delete operation
    e = tidesdb_txn_put(txn, "key1", 4, "value1", 6, -1);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    e = tidesdb_txn_put(txn, "key2", 4, "value2", 6, -1);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    e = tidesdb_txn_put(txn, "key3", 4, "value3", 6, -1);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    e = tidesdb_txn_delete(txn, "key1", 4);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    // we expect key2 and key3 to be the result of the transaction

    // commit the transaction
    e = tidesdb_txn_commit(tdb, txn);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    tidesdb_txn_free(txn);

    unsigned char* value2 = NULL;
    unsigned char* value3 = NULL;
    size_t value_len2 = 0;
    size_t value_len3 = 0;

    e = tidesdb_get(tdb, cf->config.name, "key2", 4, &value2, &value_len2);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    e = tidesdb_get(tdb, cf->config.name, "key3", 4, &value3, &value_len3);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    unsigned char* value1 = NULL;
    size_t value_len1 = 0;

    // we try to get key1
    e = tidesdb_get(tdb, cf->config.name, "key1", 4, &value1, &value_len1);
    // we expect an error as key1 was deleted
    assert(e != NULL);

    tidesdb_close(tdb);
    free(tdb_config);

    remove_directory("testdb");

    printf(GREEN "test_txn_put_delete_get passed\n" RESET);
}

void test_put_compact() {
    tidesdb_config* tdb_config = (malloc(sizeof(tidesdb_config)));

    tdb_config->db_path = "testdb";
    tdb_config->compressed_wal = false;

    tidesdb* tdb = NULL;

    tidesdb_err* e = tidesdb_open(tdb_config, &tdb);
    assert(e == NULL);

    assert(tdb != NULL);

    free(e);
    e = NULL;

    // Create a column family
    e = tidesdb_create_column_family(tdb, "test_cf", 1024 * 1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family* cf = NULL;

    // we should be able to get the column family
    assert(_get_column_family(tdb, "test_cf", &cf) == 1);

    // put 100k key-value pairs
    for (int i = 0; i < 100000; i++) {
        char key[38];
        char value[38];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);

        e = tidesdb_put(tdb, cf->config.name, key, strlen(key), value, strlen(value), -1);
        if (e != NULL) {
            printf(RED "Error: %s\n" RESET, e->message);
            break;
        }

        assert(e == NULL);
        free(e);
        e = NULL;
    }

    // we compact
    e = tidesdb_compact_sstables(tdb, cf, 2);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }

    assert(e == NULL);

    tidesdb_close(tdb);

    remove_directory("testdb");

    printf(GREEN "test_put_compact passed\n" RESET);
}

int main(void) {
    test_open_close();
    test_create_column_family();
    test_drop_column_family();
    test_put();
    test_put_get();
    test_put_flush_get();
    test_put_reopen_get();
    test_put_get_delete();
    test_txn_put_delete_get();
    test_put_compact();
    // @todo test_put_compact_get();
    // @todo test_put_compact_get_reopen
    // @todo test_cursor
    // @todo test_concurrent_put_get

    return 0;
}