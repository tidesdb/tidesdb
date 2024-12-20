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

/* test constants */
#define NUM_OPERATIONS         500000 /* number of operations per thread */
#define NUM_THREADS            2 /* you can increase this to test with more threads, usually slower */
#define SIZE                   (1024 * 1024) /* key and value size, 1MB */
#define DIR                    "benchmark_db"
#define FLUSH_THRESHOLD        ((1024 * 1024) * 64)
#define THREADS_FOR_COMPACTION 2

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

void pad_key_with_nines(uint8_t *key, size_t target_len)
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
        uint8_t key[SIZE];
        uint8_t value[SIZE];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d_%d", i, thread_id);
        pad_key_with_nines(key, SIZE - 1);
        pad_key_with_nines(value, SIZE - 1);

        tidesdb_err_t *err = tidesdb_put(tdb, cf_name, key, strlen(key), value, strlen(value), -1);
        if (err != NULL)
        {
            printf(RED "Error: %s\n" RESET, err->message);
            tidesdb_err_free(err);
        }
    }
    return NULL;
}

void *benchmark_put_compact(void *arg)
{
    thread_arg_t *targ = arg;
    tidesdb_t *tdb = targ->tdb;
    const char *cf_name = targ->column_family_name;
    int thread_id = targ->thread_id;

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        uint8_t key[SIZE];
        uint8_t value[SIZE];
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(value, sizeof(value), "value%03d_%d", i, thread_id);
        pad_key_with_nines(key, SIZE - 1);
        pad_key_with_nines(value, SIZE - 1);

        tidesdb_err_t *err = tidesdb_put(tdb, cf_name, key, strlen(key), value, strlen(value), -1);
        if (err != NULL)
        {
            printf(RED "Error: %s\n" RESET, err->message);
            tidesdb_err_free(err);
        }

        /* compact sstables in the middle of the benchmark */
        if (i == (NUM_OPERATIONS / 2))
        {
            err = tidesdb_compact_sstables(tdb, cf_name, THREADS_FOR_COMPACTION);
            if (err != NULL)
            {
                printf(RED "Error: %s\n" RESET, err->message);
                tidesdb_err_free(err);
            }
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
        uint8_t key[SIZE];
        snprintf(key, sizeof(key), "key%03d", i);
        pad_key_with_nines(key, SIZE - 1);

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
    int thread_id = targ->thread_id; /* could be used for debugging if need be */

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        uint8_t key[SIZE];
        snprintf(key, sizeof(key), "key%03d", i);
        pad_key_with_nines(key, SIZE - 1);

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

/* benchmarks put with many flushes, put with compaction triggered in the middle of write operations
 * get, delete operations
 *
 * We also benchmark with different column family configurations with compression and bloom filter
 * and without
 */
int main(void)
{
    (void)_tidesdb_remove_directory(DIR);

    tidesdb_t *tdb = NULL;

    tidesdb_err_t *err = tidesdb_open(DIR, &tdb);
    if (err != NULL)
    {
        printf(RED "Error opening database: %s\n" RESET, err->message);
        tidesdb_err_free(err);
        return -1;
    }

    /* we can run one more benchmark with different column family configurations */

    const char *cf_name = "cf1";
    err = tidesdb_create_column_family(tdb, cf_name, FLUSH_THRESHOLD, 12, 0.24f, false,
                                       TDB_NO_COMPRESSION, false, TDB_MEMTABLE_SKIP_LIST);
    if (err != NULL)
    {
        printf(RED "Error creating column family: %s\n" RESET, err->message);
        tidesdb_err_free(err);
        tidesdb_close(tdb);
        return -1;
    }

    const char *cf_name2 = "cf2";
    err = tidesdb_create_column_family(tdb, cf_name2, FLUSH_THRESHOLD, 12, 0.24f, false,
                                       TDB_COMPRESS_SNAPPY, true, TDB_MEMTABLE_SKIP_LIST);
    if (err != NULL)
    {
        printf(RED "Error creating column family: %s\n" RESET, err->message);
        tidesdb_err_free(err);
        tidesdb_close(tdb);
        return -1;
    }

    printf(BOLDCYAN "Running PUT (no compression, bloom filter) benchmark...\n" RESET);
    clock_t start = clock();
    run_benchmark(benchmark_put, tdb, cf_name);
    clock_t end = clock();
    printf(BOLDGREEN "PUT (no compression, bloom filter) benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running PUT (no compression, bloom filter) compact benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_put_compact, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN
           "PUT (no compression, bloom filter) compact benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running GET (no compression, bloom filter) benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_get, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "GET (no compression, bloom filter) benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running DELETE (no compression, bloom filter) benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_delete, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN
           "DELETE (no compression, bloom filter) benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    /* with snappy compression and bloom filter */
    printf(BOLDCYAN "Running PUT (compression, bloom filter) benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_put, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "PUT benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running PUT (compression, bloom filter) compact benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_put_compact, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN
           "PUT (compression, bloom filter) compact benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running GET (compression, bloom filter) benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_get, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "GET (compression, bloom filter) benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    printf(BOLDCYAN "Running DELETE (compression, bloom filter) benchmark...\n" RESET);
    start = clock();
    run_benchmark(benchmark_delete, tdb, cf_name);
    end = clock();
    printf(BOLDGREEN "DELETE (compression, bloom filter) benchmark completed in %f seconds\n" RESET,
           (double)(end - start) / CLOCKS_PER_SEC);

    (void)tidesdb_close(tdb);
    (void)_tidesdb_remove_directory(DIR);
    return 0;
}
