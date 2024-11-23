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
    e = tidesdb_create_column_family(tdb, "test_cf", 1024*1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    column_family *cf = NULL;


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
    e = tidesdb_create_column_family(tdb, "test_cf", 1024*1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family *cf = NULL;

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
    e = tidesdb_create_column_family(tdb, "test_cf", 1024*1024, 12, 0.24f);
    if (e != NULL) {
        printf(RED "Error: %s\n" RESET, e->message);
    }
    assert(e == NULL);

    free(e);
    e = NULL;

    column_family *cf = NULL;

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

int main(void) {
    // test_open_close();
    // test_create_column_family();
    // test_drop_column_family();
    test_put();
    return 0;
}