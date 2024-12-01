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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/tidesdb.h"
#include "../test/test_macros.h"
#include "../test/test_utils.h"

#define NUM_OPERATIONS 1000 /* number of operations per thread */
#define NUM_THREADS    1    /* you can increase this to test with more threads, usually slower */

/* benchmarker puts 2MB keys and 2MB values into the database then gets them back, then deletes them
 */

/*
 * thread_arg_t
 * @param tdb the tidesdb instance
 * @param column_family_name the column family name
 * @param thread_id the thread id
 */
typedef struct
{
    tidesdb_t *tdb;
    const char *column_family_name;
    int thread_id;
} thread_arg_t;

void pad_key_with_nines(uint8_t *key, size_t key_len, size_t target_len)
{
    size_t current_len = strlen((char *)key);
    if (current_len < target_len)
    {
        memset(key + current_len, '9', target_len - current_len);
        key[target_len] = '\0';
    }
}

void *benchmark_put(void *arg)
{
    thread_arg_t *targ = arg;
    tidesdb_t *tdb = targ->tdb;
    const char *cf_name = targ->column_family_name;
    int thread_id = targ->thread_id;

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        uint8_t key[(1024 * 1024) * 2];
        uint8_t value[(1024 * 1024) * 2];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d_%d", i, thread_id);
        pad_key_with_nines(key, strlen((char *)key), (1024 * 1024) * 2 - 1);
        pad_key_with_nines(value, strlen((char *)value), (1024 * 1024) * 2 - 1);

        tidesdb_err_t *err = tidesdb_put(tdb, cf_name, key, strlen(key), value, strlen(value), -1);
        if (err != NULL)
        {
            printf(RED "Error: %s\n" RESET, err->message);
            tidesdb_err_free(err);
        }
    }
    return NULL;
}

void *benchmark_get(void *arg)
{
    thread_arg_t *targ = arg;
    tidesdb_t *tdb = targ->tdb;
    const char *cf_name = targ->column_family_name;
    int thread_id = targ->thread_id;

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        uint8_t key[(1024 * 1024) * 2];
        snprintf(key, sizeof(key), "key%03d", i);
        pad_key_with_nines(key, strlen(key), (1024 * 1024) * 2 - 1);

        uint8_t *value = NULL;
        size_t value_size = 0;
        tidesdb_err_t *err = tidesdb_get(tdb, cf_name, key, strlen(key), &value, &value_size);
        if (err != NULL)
        {
            printf(RED "Error: %s\n" RESET, err->message);
            tidesdb_err_free(err);
            continue;
        }
        if (value != NULL)
        {
            free(value);
            value = NULL;
        }
    }
    return NULL;
}

void *benchmark_delete(void *arg)
{
    thread_arg_t *targ = arg;
    tidesdb_t *tdb = targ->tdb;
    const char *cf_name = targ->column_family_name;
    int thread_id = targ->thread_id;

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        uint8_t key[(1024 * 1024) * 2];
        snprintf(key, sizeof(key), "key%03d", i);
        pad_key_with_nines(key, strlen(key), (1024 * 1024) * 2 - 1);

        tidesdb_err_t *err = tidesdb_delete(tdb, cf_name, key, strlen(key));
        if (err != NULL)
        {
            printf(RED "Error: %s\n" RESET, err->message);
            tidesdb_err_free(err);
        }
    }
    return NULL;
}

void run_benchmark(void *(*benchmark_func)(void *), tidesdb_t *tdb, const char *cf_name)
{
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++)
    {
        args[i].tdb = tdb;
        args[i].column_family_name = cf_name;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, benchmark_func, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
}

int main()
{
    remove_directory("benchmarktdb");

    tidesdb_t *tdb = NULL;

    tidesdb_config_t *tdb_config = (malloc(sizeof(tidesdb_config_t)));
    if (tdb_config == NULL)
    {
        return -1;
    }

    tdb_config->db_path = "benchmarktdb";
    tdb_config->compressed_wal = false;

    tidesdb_err_t *err = tidesdb_open(tdb_config, &tdb);
    if (err != NULL)
    {
        printf(RED "Error opening database: %s\n" RESET, err->message);
        tidesdb_err_free(err);
        free(tdb_config);
        return -1;
    }

    const char *cf_name = "benchmark_cf";
    err = tidesdb_create_column_family(tdb, cf_name, (1024 * 1024) * 64, 12, 0.25f, false);
    if (err != NULL)
    {
        printf(RED "Error creating column family: %s\n" RESET, err->message);
        tidesdb_err_free(err);
        tidesdb_close(tdb);
        free(tdb_config);
        return -1;
    }

    printf(BOLDCYAN "Running PUT benchmark...\n" RESET);
    clock_t start = clock();
    run_benchmark(benchmark_put, tdb, cf_name);
    clock_t end = clock();
    printf(BOLDGREEN "PUT benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    sleep(10); /* wait for flushes to complete */

    printf(BOLDCYAN "Running GET benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_get, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "GET benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running DELETE benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_delete, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "DELETE benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    tidesdb_close(tdb);
    free(tdb_config);
    return 0;
}