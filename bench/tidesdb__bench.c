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
#include "../src/tidesdb.h"
#include "../test/test_macros.h"

#define NUM_OPERATIONS 1000000
#define KEY_SIZE       16
#define VALUE_SIZE     100
#define CF_NAME        "benchmark_cf"
#define NUM_THREADS    4

/*
 * thread_data_t struct is used to pass data to the thread functions
 */
typedef struct
{
    tidesdb_t *tdb;
    char **keys;
    char **values;
    int start;
    int end;
} thread_data_t;

void generate_random_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; i++)
    {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[size - 1] = '\0';
}

double get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

void *thread_put(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    tidesdb_err_t *err = NULL;
    for (int i = data->start; i < data->end; i++)
    {
        err = tidesdb_put(data->tdb, CF_NAME, (uint8_t *)data->keys[i], strlen(data->keys[i]),
                          (uint8_t *)data->values[i], strlen(data->values[i]), -1);
        if (err != NULL)
        {
            printf(BOLDRED "Put operation failed: %s\n" RESET, err->message);
            (void)tidesdb_err_free(err);
            (void)pthread_exit(NULL);
        }
    }
    (void)pthread_exit(NULL);
}

void *thread_get(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    tidesdb_err_t *err = NULL;
    for (int i = data->start; i < data->end; i++)
    {
        uint8_t *value_out;
        size_t value_len;
        err = tidesdb_get(data->tdb, CF_NAME, (uint8_t *)data->keys[i], strlen(data->keys[i]),
                          &value_out, &value_len);
        if (err != NULL)
        {
            printf(BOLDRED "Get operation failed: %s\n" RESET, err->message);
            (void)tidesdb_err_free(err);
            (void)pthread_exit(NULL);
        }
        free(value_out);
    }
    (void)pthread_exit(NULL);
}

void *thread_delete(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    tidesdb_err_t *err = NULL;
    for (int i = data->start; i < data->end; i++)
    {
        err = tidesdb_delete(data->tdb, CF_NAME, (uint8_t *)data->keys[i], strlen(data->keys[i]));
        if (err != NULL)
        {
            printf(BOLDRED "Delete operation failed: %s\n" RESET, err->message);
            (void)tidesdb_err_free(err);
            (void)pthread_exit(NULL);
        }
    }
    (void)pthread_exit(NULL);
}

int main()
{
    tidesdb_t *tdb = NULL;
    tidesdb_err_t *err = NULL;
    double start_time, end_time;
    char **keys = malloc(NUM_OPERATIONS * sizeof(char *));
    if (keys == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for keys\n" RESET);
        return 1;
    }

    char **values = malloc(NUM_OPERATIONS * sizeof(char *));
    if (values == NULL)
    {
        printf(BOLDRED "Failed to allocate memory for values\n" RESET);
        free(keys);
        return 1;
    }

    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];

    srand(time(NULL));

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        keys[i] = malloc(KEY_SIZE);
        values[i] = malloc(VALUE_SIZE);
        (void)generate_random_string(keys[i], KEY_SIZE);
        (void)generate_random_string(values[i], VALUE_SIZE);
    }

    err = tidesdb_open("benchmark_db", &tdb);
    if (err != NULL)
    {
        printf(BOLDRED "Failed to open database: %s\n" RESET, err->message);
        (void)tidesdb_err_free(err);
        free(keys);
        free(values);
        return 1;
    }

    err = tidesdb_create_column_family(tdb, CF_NAME, (1024 * 1024) * 128, TDB_USING_HT_MAX_LEVEL,
                                       TDB_USING_HT_PROBABILITY, false, TDB_NO_COMPRESSION, true,
                                       TDB_MEMTABLE_HASH_TABLE);
    if (err != NULL)
    {
        printf(BOLDRED "Failed to create column family: %s\n" RESET, err->message);
        (void)tidesdb_err_free(err);
        free(keys);
        free(values);
        return 1;
    }

    printf(BOLDGREEN "\nBenchmarking Put operations...\n" RESET);
    start_time = get_time_ms();
    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].tdb = tdb;
        thread_data[i].keys = keys;
        thread_data[i].values = values;
        thread_data[i].start = i * (NUM_OPERATIONS / NUM_THREADS);
        thread_data[i].end = (i + 1) * (NUM_OPERATIONS / NUM_THREADS);
        (void)pthread_create(&threads[i], NULL, thread_put, &thread_data[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }
    end_time = get_time_ms();
    printf(BOLDGREEN "Put: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Get operations...\n" RESET);
    start_time = get_time_ms();
    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_get, &thread_data[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }
    end_time = get_time_ms();
    printf(BOLDGREEN "Get: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    printf(BOLDGREEN "\nBenchmarking Delete operations...\n" RESET);
    start_time = get_time_ms();
    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_create(&threads[i], NULL, thread_delete, &thread_data[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++)
    {
        (void)pthread_join(threads[i], NULL);
    }
    end_time = get_time_ms();
    printf(BOLDGREEN "Delete: %d operations in %.2f ms (%.2f ops/sec)\n" RESET, NUM_OPERATIONS,
           end_time - start_time, (NUM_OPERATIONS / (end_time - start_time)) * 1000);

    for (int i = 0; i < NUM_OPERATIONS; i++)
    {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);

    err = tidesdb_drop_column_family(tdb, CF_NAME);
    if (err != NULL)
    {
        printf(BOLDRED "Failed to drop column family: %s\n" RESET, err->message);
        tidesdb_err_free(err);
    }

    err = tidesdb_close(tdb);
    if (err != NULL)
    {
        printf(BOLDRED "Failed to close database: %s\n" RESET, err->message);
        (void)tidesdb_err_free(err);
        return 1;
    }

    (void)_tidesdb_remove_directory("benchmark_db");
    printf(MAGENTA "\nCleanup completed\n" RESET);

    return 0;
}