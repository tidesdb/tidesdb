/**
 * Copyright 2024 Alex Gaetano Padula (TidesDB)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "benchmark.h"

#include <dirent.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <tidesdb/tidesdb_version.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_ROCKSDB
#include <rocksdb/c.h>
#endif

const char *get_engine_version(const char *engine_name)
{
    if (strcmp(engine_name, "tidesdb") == 0)
    {
        return TIDESDB_VERSION;
    }
    return "unknown";
}

static double zipfian_next(int n, double theta)
{
    static double alpha = 0.0;
    static double zetan = 0.0;
    static double eta = 0.0;

    if (alpha != theta || zetan == 0.0)
    {
        alpha = theta;
        zetan = 0.0;
        for (int i = 1; i <= n; i++)
        {
            zetan += 1.0 / pow(i, theta);
        }
        eta = (1.0 - pow(2.0 / n, 1.0 - theta)) / (1.0 - 1.0 / zetan);
    }

    double u = (double)rand() / RAND_MAX;
    double uz = u * zetan;

    if (uz < 1.0) return 1;
    if (uz < 1.0 + pow(0.5, theta)) return 2;

    return 1 + (int)(n * pow(eta * u - eta + 1.0, alpha));
}

static void generate_key(uint8_t *key, size_t key_size, int index, key_pattern_t pattern,
                         int max_operations)
{
    uint64_t key_num = 0;

    /* ensure we have space for null terminator */
    int available_digits = (int)(key_size - 1); /* -1 for null terminator */

    switch (pattern)
    {
        case KEY_PATTERN_SEQUENTIAL:
            /* sequential use index directly for uniqueness */
            snprintf((char *)key, key_size, "%0*d", available_digits, index);
            break;

        case KEY_PATTERN_RANDOM:
            /* use index directly in hex format to ensure uniqueness */
            /* shuffle bits for randomness while preserving uniqueness */
            key_num = index;
            /* bit-reverse for pseudo-random distribution */
            key_num = ((key_num & 0xFFFF0000) >> 16) | ((key_num & 0x0000FFFF) << 16);
            key_num = ((key_num & 0xFF00FF00) >> 8) | ((key_num & 0x00FF00FF) << 8);
            snprintf((char *)key, key_size, "%0*llx", available_digits,
                     (unsigned long long)key_num);
            break;

        case KEY_PATTERN_ZIPFIAN:
            /* zipfian distribution -- 80% of accesses to 20% of keys */
            /* intentionally creates duplicates for hot-key simulation */
            key_num = (uint64_t)zipfian_next(max_operations, 0.99);
            snprintf((char *)key, key_size, "%0*llu", available_digits,
                     (unsigned long long)key_num);
            break;

        case KEY_PATTERN_UNIFORM:
            /* true uniform random, may have collisions */
            key_num = ((uint64_t)rand() << 32) | rand();
            snprintf((char *)key, key_size, "%0*llx", available_digits,
                     (unsigned long long)key_num);
            break;

        case KEY_PATTERN_TIMESTAMP:
            /* monotonically increasing timestamp-like keys */
            key_num = ((uint64_t)time(NULL) << 32) | index;
            snprintf((char *)key, key_size, "%0*llx", available_digits,
                     (unsigned long long)key_num);
            break;

        case KEY_PATTERN_REVERSE:
            /* reverse sequential */
            key_num = max_operations - index;
            snprintf((char *)key, key_size, "%0*llu", available_digits,
                     (unsigned long long)key_num);
            break;

        default:
            /* fallback to sequential */
            snprintf((char *)key, key_size, "%0*d", available_digits, index);
            break;
    }
}

typedef struct
{
    benchmark_config_t *config;
    storage_engine_t *engine;
    int thread_id;
    int ops_per_thread;
    double *latencies;
    int latency_count;
} thread_context_t;

static double get_time_microseconds(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

/* get memory usage from /proc/self/status */
static void get_memory_usage(size_t *rss_bytes, size_t *vms_bytes)
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp)
    {
        *rss_bytes = 0;
        *vms_bytes = 0;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "VmRSS:", 6) == 0)
        {
            sscanf(line + 6, "%zu", rss_bytes);
            *rss_bytes *= 1024; /* convert KB to bytes */
        }
        else if (strncmp(line, "VmSize:", 7) == 0)
        {
            sscanf(line + 7, "%zu", vms_bytes);
            *vms_bytes *= 1024; /* convert KB to bytes */
        }
    }
    fclose(fp);
}

/* get I/O statistics from /proc/self/io */
static void get_io_stats(size_t *bytes_read, size_t *bytes_written)
{
    FILE *fp = fopen("/proc/self/io", "r");
    if (!fp)
    {
        *bytes_read = 0;
        *bytes_written = 0;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "read_bytes:", 11) == 0)
        {
            sscanf(line + 11, "%zu", bytes_read);
        }
        else if (strncmp(line, "write_bytes:", 12) == 0)
        {
            sscanf(line + 12, "%zu", bytes_written);
        }
    }
    fclose(fp);
}

/* get CPU usage statistics */
static void get_cpu_stats(double *user_time, double *system_time)
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0)
    {
        *user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
        *system_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
    }
    else
    {
        *user_time = 0.0;
        *system_time = 0.0;
    }
}

/* helper to check if we're in a column family directory */
static int is_column_family_dir(const char *path)
{
    const char *last_slash = strrchr(path, '/');
    if (!last_slash) return 0;

    return 1;
}

/* recursive calculate directory size, excluding temp files in column family dirs */
static size_t get_directory_size_recursive(const char *path, int is_cf_dir)
{
    DIR *dir = opendir(path);
    if (!dir) return 0;

    size_t total_size = 0;
    struct dirent *entry;
    char filepath[1024];

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        /* only skip temp files if we're in a column family directory */
        if (is_cf_dir)
        {
            size_t name_len = strlen(entry->d_name);

            /* skip TidesDB temporary index files (trie_ prefix) */
            if (strncmp(entry->d_name, "trie_", 5) == 0) continue;

            /* skip TidesDB temporary sstable files (sstable_*.sst.tmp) */
            if (strncmp(entry->d_name, "sstable_", 8) == 0 && name_len > 8 &&
                strcmp(entry->d_name + name_len - 4, ".tmp") == 0)
                continue;

            /* skip files ending with .tmp */
            if (name_len > 4 && strcmp(entry->d_name + name_len - 4, ".tmp") == 0) continue;

            /* skip files starting with temp_ */
            if (strncmp(entry->d_name, "temp_", 5) == 0) continue;

            /* skip LOCK file */
            if (strcmp(entry->d_name, "LOCK") == 0) continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(filepath, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                /* subdirectories of db_path are column families */
                total_size += get_directory_size_recursive(filepath, 1);
            }
            else if (S_ISREG(st.st_mode))
            {
                total_size += st.st_size;
            }
        }
    }

    closedir(dir);
    return total_size;
}

static size_t get_directory_size(const char *path)
{
    /* start at db_path level (is_cf_dir = 0), subdirectories will be column families */
    return get_directory_size_recursive(path, 0);
}

static void generate_value(uint8_t *value, size_t value_size, int index)
{
    for (size_t i = 0; i < value_size; i++)
    {
        value[i] = (uint8_t)((index + i) % 256);
    }
}

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void calculate_stats(double *latencies, int count, operation_stats_t *stats)
{
    if (count == 0) return;

    qsort(latencies, count, sizeof(double), compare_double);

    double sum = 0.0;
    stats->min_latency_us = latencies[0];
    stats->max_latency_us = latencies[count - 1];

    for (int i = 0; i < count; i++)
    {
        sum += latencies[i];
    }

    stats->avg_latency_us = sum / count;
    stats->p50_latency_us = latencies[(int)(count * 0.50)];
    stats->p95_latency_us = latencies[(int)(count * 0.95)];
    stats->p99_latency_us = latencies[(int)(count * 0.99)];
}

static void *benchmark_put_thread(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    uint8_t *key = malloc(ctx->config->key_size);
    uint8_t *value = malloc(ctx->config->value_size);

    int start_index = ctx->thread_id * ctx->ops_per_thread;
    int batch_size = ctx->config->batch_size;

    /* we use use batched API if available, otherwise fall back to single operations */
    if (ctx->engine->ops->batch_begin && ctx->engine->ops->batch_put &&
        ctx->engine->ops->batch_commit && batch_size > 1)
    {
        /* batched path -- group operations into transactions */
        for (int i = 0; i < ctx->ops_per_thread; i += batch_size)
        {
            void *batch_ctx = NULL;
            double batch_start = get_time_microseconds();

            if (ctx->engine->ops->batch_begin(ctx->engine, &batch_ctx) != 0) continue;

            int batch_end =
                (i + batch_size < ctx->ops_per_thread) ? i + batch_size : ctx->ops_per_thread;

            for (int j = i; j < batch_end; j++)
            {
                generate_key(key, ctx->config->key_size, start_index + j, ctx->config->key_pattern,
                             ctx->config->num_operations);
                generate_value(value, ctx->config->value_size, start_index + j);

                ctx->engine->ops->batch_put(batch_ctx, ctx->engine, key, ctx->config->key_size,
                                            value, ctx->config->value_size);
            }

            ctx->engine->ops->batch_commit(batch_ctx);
            double batch_end_time = get_time_microseconds();

            /* we record record latency for the entire batch */
            double batch_latency = batch_end_time - batch_start;
            ctx->latencies[ctx->latency_count++] = batch_latency;
        }
    }
    else
    {
        /* single operation path (legacy) */
        for (int i = 0; i < ctx->ops_per_thread; i++)
        {
            generate_key(key, ctx->config->key_size, start_index + i, ctx->config->key_pattern,
                         ctx->config->num_operations);
            generate_value(value, ctx->config->value_size, start_index + i);

            double start = get_time_microseconds();
            ctx->engine->ops->put(ctx->engine, key, ctx->config->key_size, value,
                                  ctx->config->value_size);
            double end = get_time_microseconds();

            ctx->latencies[ctx->latency_count++] = end - start;
        }
    }

    free(key);
    free(value);
    return NULL;
}

static void *benchmark_get_thread(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    uint8_t *key = malloc(ctx->config->key_size);

    int start_index = ctx->thread_id * ctx->ops_per_thread;

    for (int i = 0; i < ctx->ops_per_thread; i++)
    {
        generate_key(key, ctx->config->key_size, start_index + i, ctx->config->key_pattern,
                     ctx->config->num_operations);

        uint8_t *value = NULL;
        size_t value_size = 0;

        double start = get_time_microseconds();
        ctx->engine->ops->get(ctx->engine, key, ctx->config->key_size, &value, &value_size);
        double end = get_time_microseconds();

        if (value) free(value);
        ctx->latencies[ctx->latency_count++] = end - start;
    }

    free(key);
    return NULL;
}

static void *benchmark_delete_thread(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    uint8_t *key = malloc(ctx->config->key_size);

    int start_index = ctx->thread_id * ctx->ops_per_thread;
    int batch_size = ctx->config->batch_size;

    /* we use batched API if available, otherwise fall back to single operations */
    if (ctx->engine->ops->batch_begin && ctx->engine->ops->batch_delete &&
        ctx->engine->ops->batch_commit && batch_size > 1)
    {
        /* batched path -- group operations into transactions */
        for (int i = 0; i < ctx->ops_per_thread; i += batch_size)
        {
            void *batch_ctx = NULL;
            double batch_start = get_time_microseconds();

            if (ctx->engine->ops->batch_begin(ctx->engine, &batch_ctx) != 0) continue;

            int batch_end =
                (i + batch_size < ctx->ops_per_thread) ? i + batch_size : ctx->ops_per_thread;

            for (int j = i; j < batch_end; j++)
            {
                generate_key(key, ctx->config->key_size, start_index + j, ctx->config->key_pattern,
                             ctx->config->num_operations);

                ctx->engine->ops->batch_delete(batch_ctx, ctx->engine, key, ctx->config->key_size);
            }

            ctx->engine->ops->batch_commit(batch_ctx);
            double batch_end_time = get_time_microseconds();

            /* record latency for the entire batch */
            double batch_latency = batch_end_time - batch_start;
            ctx->latencies[ctx->latency_count++] = batch_latency;

            /* progress indicator every 10K ops for debugging */
            if ((i + batch_size) % 10000 < batch_size && ctx->thread_id == 0)
            {
                fprintf(stderr, ".");
                fflush(stderr);
            }
        }
    }
    else
    {
        /* single operation path (legacy) */
        for (int i = 0; i < ctx->ops_per_thread; i++)
        {
            generate_key(key, ctx->config->key_size, start_index + i, ctx->config->key_pattern,
                         ctx->config->num_operations);

            double start = get_time_microseconds();
            int del_result = ctx->engine->ops->del(ctx->engine, key, ctx->config->key_size);
            double end = get_time_microseconds();

            /* track latency even if delete fails (key not found is OK) */
            ctx->latencies[ctx->latency_count++] = end - start;

            /* progress indicator every 10K ops for debugging */
            if ((i + 1) % 10000 == 0 && ctx->thread_id == 0)
            {
                fprintf(stderr, ".");
                fflush(stderr);
            }
        }
    }

    free(key);
    return NULL;
}

static void *benchmark_seek_thread(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    uint8_t *key = malloc(ctx->config->key_size);

    int start_index = ctx->thread_id * ctx->ops_per_thread;

    /* create iterator once per thread, reuse for all seeks */
    void *iter = NULL;
    if (ctx->engine->ops->iter_new(ctx->engine, &iter) != 0)
    {
        free(key);
        return NULL;
    }

    for (int i = 0; i < ctx->ops_per_thread; i++)
    {
        generate_key(key, ctx->config->key_size, start_index + i, ctx->config->key_pattern,
                     ctx->config->num_operations);

        double start = get_time_microseconds();

        ctx->engine->ops->iter_seek(iter, key, ctx->config->key_size);

        /* check if seek was successful */
        if (ctx->engine->ops->iter_valid(iter))
        {
            /* read the key to simulate real usage */
            /* note: iterator owns this memory, don't free it */
            uint8_t *found_key = NULL;
            size_t found_key_size = 0;
            ctx->engine->ops->iter_key(iter, &found_key, &found_key_size);
        }

        double end = get_time_microseconds();
        ctx->latencies[ctx->latency_count++] = end - start;
    }

    /* cleanup iterator once at the end */
    ctx->engine->ops->iter_free(iter);
    free(key);
    return NULL;
}

static void *benchmark_range_thread(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    uint8_t *key = malloc(ctx->config->key_size);

    int start_index = ctx->thread_id * ctx->ops_per_thread;
    int range_size = ctx->config->range_size;

    /* create iterator once per thread, reuse for all range queries */
    void *iter = NULL;
    if (ctx->engine->ops->iter_new(ctx->engine, &iter) != 0)
    {
        fprintf(stderr, "[T%d iter_new failed] ", ctx->thread_id);
        fflush(stderr);
        free(key);
        return NULL;
    }

    for (int i = 0; i < ctx->ops_per_thread; i++)
    {
        generate_key(key, ctx->config->key_size, start_index + i, ctx->config->key_pattern,
                     ctx->config->num_operations);

        double start = get_time_microseconds();

        /* seek to starting key */
        ctx->engine->ops->iter_seek(iter, key, ctx->config->key_size);

        /* iterate through range_size keys */
        int count = 0;
        while (ctx->engine->ops->iter_valid(iter) && count < range_size)
        {
            /* read key and value to simulate real range query */
            /* note: iterator owns this memory, don't free it */
            uint8_t *found_key = NULL;
            uint8_t *found_value = NULL;
            size_t found_key_size = 0;
            size_t found_value_size = 0;

            ctx->engine->ops->iter_key(iter, &found_key, &found_key_size);
            ctx->engine->ops->iter_value(iter, &found_value, &found_value_size);

            ctx->engine->ops->iter_next(iter);
            count++;
        }

        double end = get_time_microseconds();
        ctx->latencies[ctx->latency_count++] = end - start;
    }

    /* cleanup iterator once at the end */
    ctx->engine->ops->iter_free(iter);
    free(key);
    return NULL;
}

int run_benchmark(benchmark_config_t *config, benchmark_results_t **results)
{
    *results = calloc(1, sizeof(benchmark_results_t));
    if (!*results) return -1;

    (*results)->engine_name = config->engine_name;
    (*results)->config = *config;

    const storage_engine_ops_t *ops = get_engine_ops(config->engine_name);
    if (!ops)
    {
        fprintf(stderr, "Unknown engine: %s\n", config->engine_name);
        free(*results);
        return -1;
    }

    storage_engine_t *engine = NULL;
    if (ops->open(&engine, config->db_path, config) != 0)
    {
        fprintf(stderr, "Failed to open engine\n");
        free(*results);
        return -1;
    }

    /* apply sync mode if supported */
    if (engine->ops->set_sync)
    {
        engine->ops->set_sync(engine, config->sync_enabled);
    }

    printf("Running %s benchmark...\n", ops->name);

    /* baseline captured after first thread allocation to exclude benchmark infrastructure */
    size_t baseline_rss = 0, baseline_vms = 0, baseline_io_read = 0, baseline_io_write = 0;
    double baseline_cpu_user = 0.0, baseline_cpu_system = 0.0;
    double benchmark_start_time = get_time_microseconds();
    int baseline_captured = 0;

    if (config->workload_type == WORKLOAD_WRITE || config->workload_type == WORKLOAD_MIXED)
    {
        printf("  PUT: ");
        fflush(stdout);

        pthread_t *threads = malloc(config->num_threads * sizeof(pthread_t));
        thread_context_t *contexts = calloc(config->num_threads, sizeof(thread_context_t));

        int ops_per_thread = config->num_operations / config->num_threads;

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].latencies = malloc(ops_per_thread * sizeof(double));
        }

        if (!baseline_captured)
        {
            get_memory_usage(&baseline_rss, &baseline_vms);
            get_io_stats(&baseline_io_read, &baseline_io_write);
            get_cpu_stats(&baseline_cpu_user, &baseline_cpu_system);
            baseline_captured = 1;
        }

        double start_time = get_time_microseconds();

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].config = config;
            contexts[i].engine = engine;
            contexts[i].thread_id = i;
            contexts[i].ops_per_thread = ops_per_thread;
            contexts[i].latency_count = 0;
            pthread_create(&threads[i], NULL, benchmark_put_thread, &contexts[i]);
        }

        for (int i = 0; i < config->num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        double end_time = get_time_microseconds();
        (*results)->put_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        (*results)->put_stats.ops_per_second =
            config->num_operations / (*results)->put_stats.duration_seconds;

        int total_latencies = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            total_latencies += contexts[i].latency_count;
        }

        double *all_latencies = malloc(total_latencies * sizeof(double));
        int offset = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            memcpy(all_latencies + offset, contexts[i].latencies,
                   contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
            free(contexts[i].latencies);
        }

        calculate_stats(all_latencies, total_latencies, &(*results)->put_stats);
        free(all_latencies);
        free(threads);
        free(contexts);

        size_t data_size = (size_t)config->num_operations * (config->key_size + config->value_size);
        (*results)->total_bytes_written += data_size;
        (*results)->net_logical_data_size += data_size;

        printf("%.2f ops/sec\n", (*results)->put_stats.ops_per_second);
    }

    if (config->workload_type == WORKLOAD_READ || config->workload_type == WORKLOAD_MIXED)
    {
        printf("  GET: ");
        fflush(stdout);

        pthread_t *threads = malloc(config->num_threads * sizeof(pthread_t));
        thread_context_t *contexts = calloc(config->num_threads, sizeof(thread_context_t));

        int ops_per_thread = config->num_operations / config->num_threads;

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].latencies = malloc(ops_per_thread * sizeof(double));
        }

        if (!baseline_captured)
        {
            get_memory_usage(&baseline_rss, &baseline_vms);
            get_io_stats(&baseline_io_read, &baseline_io_write);
            get_cpu_stats(&baseline_cpu_user, &baseline_cpu_system);
            baseline_captured = 1;
        }

        double start_time = get_time_microseconds();

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].config = config;
            contexts[i].engine = engine;
            contexts[i].thread_id = i;
            contexts[i].ops_per_thread = ops_per_thread;
            contexts[i].latency_count = 0;
            pthread_create(&threads[i], NULL, benchmark_get_thread, &contexts[i]);
        }

        for (int i = 0; i < config->num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        double end_time = get_time_microseconds();
        (*results)->get_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        (*results)->get_stats.ops_per_second =
            config->num_operations / (*results)->get_stats.duration_seconds;

        int total_latencies = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            total_latencies += contexts[i].latency_count;
        }

        double *all_latencies = malloc(total_latencies * sizeof(double));
        int offset = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            memcpy(all_latencies + offset, contexts[i].latencies,
                   contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
            free(contexts[i].latencies);
        }

        calculate_stats(all_latencies, total_latencies, &(*results)->get_stats);
        free(all_latencies);
        free(threads);
        free(contexts);

        (*results)->total_bytes_read =
            (size_t)config->num_operations * (config->key_size + config->value_size);

        printf("%.2f ops/sec\n", (*results)->get_stats.ops_per_second);
    }

    if (config->workload_type == WORKLOAD_DELETE)
    {
        printf("  DELETE: ");
        fflush(stdout);

        pthread_t *threads = malloc(config->num_threads * sizeof(pthread_t));
        thread_context_t *contexts = calloc(config->num_threads, sizeof(thread_context_t));

        int ops_per_thread = config->num_operations / config->num_threads;

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].latencies = malloc(ops_per_thread * sizeof(double));
        }

        if (!baseline_captured)
        {
            get_memory_usage(&baseline_rss, &baseline_vms);
            get_io_stats(&baseline_io_read, &baseline_io_write);
            get_cpu_stats(&baseline_cpu_user, &baseline_cpu_system);
            baseline_captured = 1;
        }

        double start_time = get_time_microseconds();

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].config = config;
            contexts[i].engine = engine;
            contexts[i].thread_id = i;
            contexts[i].ops_per_thread = ops_per_thread;
            contexts[i].latency_count = 0;
            int rc = pthread_create(&threads[i], NULL, benchmark_delete_thread, &contexts[i]);
            if (rc != 0)
            {
                fprintf(stderr, "Failed to create thread %d\n", i);
            }
        }

        fprintf(stderr, "[%d threads started] ", config->num_threads);
        fflush(stderr);

        for (int i = 0; i < config->num_threads; i++)
        {
            pthread_join(threads[i], NULL);
            fprintf(stderr, "[T%d done] ", i);
            fflush(stderr);
        }

        double end_time = get_time_microseconds();
        (*results)->delete_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        (*results)->delete_stats.ops_per_second =
            config->num_operations / (*results)->delete_stats.duration_seconds;

        int total_latencies = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            total_latencies += contexts[i].latency_count;
        }

        double *all_latencies = malloc(total_latencies * sizeof(double));
        int offset = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            memcpy(all_latencies + offset, contexts[i].latencies,
                   contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
            free(contexts[i].latencies);
        }

        calculate_stats(all_latencies, total_latencies, &(*results)->delete_stats);
        free(all_latencies);
        free(threads);
        free(contexts);

        size_t data_size = (size_t)config->num_operations * (config->key_size + config->value_size);
        (*results)->total_bytes_written += data_size;
        if ((*results)->net_logical_data_size >= data_size)
        {
            (*results)->net_logical_data_size -= data_size;
        }
        else
        {
            (*results)->net_logical_data_size = 0;
        }

        printf("%.2f ops/sec\n", (*results)->delete_stats.ops_per_second);
    }

    if (config->workload_type == WORKLOAD_SEEK)
    {
        printf("  SEEK: ");
        fflush(stdout);

        pthread_t *threads = malloc(config->num_threads * sizeof(pthread_t));
        thread_context_t *contexts = calloc(config->num_threads, sizeof(thread_context_t));

        int ops_per_thread = config->num_operations / config->num_threads;

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].latencies = malloc(ops_per_thread * sizeof(double));
        }

        if (!baseline_captured)
        {
            get_memory_usage(&baseline_rss, &baseline_vms);
            get_io_stats(&baseline_io_read, &baseline_io_write);
            get_cpu_stats(&baseline_cpu_user, &baseline_cpu_system);
            baseline_captured = 1;
        }

        double start_time = get_time_microseconds();

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].config = config;
            contexts[i].engine = engine;
            contexts[i].thread_id = i;
            contexts[i].ops_per_thread = ops_per_thread;
            contexts[i].latency_count = 0;
            int rc = pthread_create(&threads[i], NULL, benchmark_seek_thread, &contexts[i]);
            if (rc != 0)
            {
                fprintf(stderr, "Failed to create thread %d\n", i);
            }
        }

        fprintf(stderr, "[%d threads started] ", config->num_threads);
        fflush(stderr);

        for (int i = 0; i < config->num_threads; i++)
        {
            pthread_join(threads[i], NULL);
            fprintf(stderr, "[T%d done] ", i);
            fflush(stderr);
        }

        double end_time = get_time_microseconds();
        fprintf(stderr, "\n");

        (*results)->seek_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        (*results)->seek_stats.ops_per_second =
            config->num_operations / (*results)->seek_stats.duration_seconds;

        int total_latencies = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            total_latencies += contexts[i].latency_count;
        }

        double *all_latencies = malloc(total_latencies * sizeof(double));
        int offset = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            memcpy(all_latencies + offset, contexts[i].latencies,
                   contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
            free(contexts[i].latencies);
        }

        calculate_stats(all_latencies, total_latencies, &(*results)->seek_stats);
        free(all_latencies);
        free(threads);
        free(contexts);

        (*results)->total_bytes_read +=
            (size_t)config->num_operations * (config->key_size + config->value_size);

        printf("%.2f ops/sec\n", (*results)->seek_stats.ops_per_second);
    }

    if (config->workload_type == WORKLOAD_RANGE)
    {
        printf("  RANGE: ");
        fflush(stdout);

        pthread_t *threads = malloc(config->num_threads * sizeof(pthread_t));
        thread_context_t *contexts = calloc(config->num_threads, sizeof(thread_context_t));

        int ops_per_thread = config->num_operations / config->num_threads;

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].latencies = malloc(ops_per_thread * sizeof(double));
        }

        if (!baseline_captured)
        {
            get_memory_usage(&baseline_rss, &baseline_vms);
            get_io_stats(&baseline_io_read, &baseline_io_write);
            get_cpu_stats(&baseline_cpu_user, &baseline_cpu_system);
            baseline_captured = 1;
        }

        double start_time = get_time_microseconds();

        for (int i = 0; i < config->num_threads; i++)
        {
            contexts[i].config = config;
            contexts[i].engine = engine;
            contexts[i].thread_id = i;
            contexts[i].ops_per_thread = ops_per_thread;
            contexts[i].latency_count = 0;
            int rc = pthread_create(&threads[i], NULL, benchmark_range_thread, &contexts[i]);
            if (rc != 0)
            {
                fprintf(stderr, "Failed to create thread %d\n", i);
            }
        }

        fprintf(stderr, "[%d threads started] ", config->num_threads);
        fflush(stderr);

        for (int i = 0; i < config->num_threads; i++)
        {
            pthread_join(threads[i], NULL);
            fprintf(stderr, "[T%d done] ", i);
            fflush(stderr);
        }

        double end_time = get_time_microseconds();
        fprintf(stderr, "\n");

        (*results)->range_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        (*results)->range_stats.ops_per_second =
            config->num_operations / (*results)->range_stats.duration_seconds;

        int total_latencies = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            total_latencies += contexts[i].latency_count;
        }

        double *all_latencies = malloc(total_latencies * sizeof(double));
        int offset = 0;
        for (int i = 0; i < config->num_threads; i++)
        {
            memcpy(all_latencies + offset, contexts[i].latencies,
                   contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
            free(contexts[i].latencies);
        }

        calculate_stats(all_latencies, total_latencies, &(*results)->range_stats);
        free(all_latencies);
        free(threads);
        free(contexts);

        /* range queries read range_size keys per operation */
        (*results)->total_bytes_read += (size_t)config->num_operations * config->range_size *
                                        (config->key_size + config->value_size);

        printf("%.2f ops/sec\n", (*results)->range_stats.ops_per_second);
    }

    printf("  ITER: ");
    fflush(stdout);

    void *iter = NULL;
    if (engine->ops->iter_new(engine, &iter) == 0)
    {
        double start_time = get_time_microseconds();
        int count = 0;

        engine->ops->iter_seek_to_first(iter);
        while (engine->ops->iter_valid(iter))
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            engine->ops->iter_key(iter, &key, &key_size);
            engine->ops->iter_value(iter, &value, &value_size);
            engine->ops->iter_next(iter);
            count++;
        }

        double end_time = get_time_microseconds();
        (*results)->iteration_stats.duration_seconds = (end_time - start_time) / 1000000.0;
        if (count > 0)
        {
            (*results)->iteration_stats.ops_per_second =
                count / (*results)->iteration_stats.duration_seconds;
        }

        engine->ops->iter_free(iter);
        printf("%.2f ops/sec (%d keys)\n", (*results)->iteration_stats.ops_per_second, count);
    }
    else
    {
        printf("not supported\n");
    }

    /* capture final resource metrics */
    size_t final_rss, final_vms, final_io_read, final_io_write;
    double final_cpu_user, final_cpu_system;
    double benchmark_end_time = get_time_microseconds();

    get_memory_usage(&final_rss, &final_vms);
    get_io_stats(&final_io_read, &final_io_write);
    get_cpu_stats(&final_cpu_user, &final_cpu_system);

    /* calc resource deltas */
    (*results)->resources.peak_rss_bytes = final_rss > baseline_rss ? final_rss : baseline_rss;
    (*results)->resources.peak_vms_bytes = final_vms > baseline_vms ? final_vms : baseline_vms;
    (*results)->resources.bytes_read = final_io_read - baseline_io_read;
    (*results)->resources.bytes_written = final_io_write - baseline_io_write;
    (*results)->resources.cpu_user_time = final_cpu_user - baseline_cpu_user;
    (*results)->resources.cpu_system_time = final_cpu_system - baseline_cpu_system;

    /* calc CPU percentage */
    double total_wall_time = (benchmark_end_time - benchmark_start_time) / 1000000.0;
    double total_cpu_time =
        (*results)->resources.cpu_user_time + (*results)->resources.cpu_system_time;
    (*results)->resources.cpu_percent = (total_cpu_time / total_wall_time) * 100.0;

    /* calc write and read amplification factors (before close) */
    size_t logical_data_written = (*results)->total_bytes_written;
    size_t logical_data_read = (*results)->total_bytes_read;

    if (logical_data_written > 0 && (*results)->resources.bytes_written > 0)
    {
        (*results)->resources.write_amplification =
            (double)(*results)->resources.bytes_written / (double)logical_data_written;
    }

    if (logical_data_read > 0 && (*results)->resources.bytes_read > 0)
    {
        (*results)->resources.read_amplification =
            (double)(*results)->resources.bytes_read / (double)logical_data_read;
    }

    /* close database to ensure all data is flushed and compacted */
    ops->close(engine);

    /* get storage size after close for accurate space amplification */
    (*results)->resources.storage_size_bytes = get_directory_size(config->db_path);

    /* calc space amplification after close */
    if ((*results)->net_logical_data_size > 0 && (*results)->resources.storage_size_bytes > 0)
    {
        (*results)->resources.space_amplification =
            (double)(*results)->resources.storage_size_bytes /
            (double)(*results)->net_logical_data_size;
    }
    return 0;
}

void generate_report(FILE *fp, benchmark_results_t *results, benchmark_results_t *baseline)
{
    fprintf(fp, "\n**=== Benchmark Results ===**\n\n");
    const char *version = get_engine_version(results->engine_name);
    fprintf(fp, "Engine: %s (v%s)\n", results->engine_name, version);
    fprintf(fp, "Operations: %d\n", results->config.num_operations);
    fprintf(fp, "Threads: %d\n", results->config.num_threads);
    fprintf(fp, "Key Size: %d bytes\n", results->config.key_size);
    fprintf(fp, "Value Size: %d bytes\n\n", results->config.value_size);

    if (results->put_stats.ops_per_second > 0)
    {
        fprintf(fp, "PUT Operations:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->put_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n", results->put_stats.duration_seconds);
        fprintf(fp, "  Latency (avg): %.2f μs\n", results->put_stats.avg_latency_us);
        fprintf(fp, "  Latency (p50): %.2f μs\n", results->put_stats.p50_latency_us);
        fprintf(fp, "  Latency (p95): %.2f μs\n", results->put_stats.p95_latency_us);
        fprintf(fp, "  Latency (p99): %.2f μs\n", results->put_stats.p99_latency_us);
        fprintf(fp, "  Latency (min): %.2f μs\n", results->put_stats.min_latency_us);
        fprintf(fp, "  Latency (max): %.2f μs\n\n", results->put_stats.max_latency_us);
    }

    if (results->get_stats.ops_per_second > 0)
    {
        fprintf(fp, "GET Operations:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->get_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n", results->get_stats.duration_seconds);
        fprintf(fp, "  Latency (avg): %.2f μs\n", results->get_stats.avg_latency_us);
        fprintf(fp, "  Latency (p50): %.2f μs\n", results->get_stats.p50_latency_us);
        fprintf(fp, "  Latency (p95): %.2f μs\n", results->get_stats.p95_latency_us);
        fprintf(fp, "  Latency (p99): %.2f μs\n", results->get_stats.p99_latency_us);
        fprintf(fp, "  Latency (min): %.2f μs\n", results->get_stats.min_latency_us);
        fprintf(fp, "  Latency (max): %.2f μs\n\n", results->get_stats.max_latency_us);
    }

    if (results->delete_stats.ops_per_second > 0)
    {
        fprintf(fp, "DELETE Operations:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->delete_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n", results->delete_stats.duration_seconds);
        fprintf(fp, "  Latency (avg): %.2f μs\n", results->delete_stats.avg_latency_us);
        fprintf(fp, "  Latency (p50): %.2f μs\n", results->delete_stats.p50_latency_us);
        fprintf(fp, "  Latency (p95): %.2f μs\n", results->delete_stats.p95_latency_us);
        fprintf(fp, "  Latency (p99): %.2f μs\n", results->delete_stats.p99_latency_us);
        fprintf(fp, "  Latency (min): %.2f μs\n", results->delete_stats.min_latency_us);
        fprintf(fp, "  Latency (max): %.2f μs\n\n", results->delete_stats.max_latency_us);
    }

    if (results->seek_stats.ops_per_second > 0)
    {
        fprintf(fp, "SEEK Operations:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->seek_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n", results->seek_stats.duration_seconds);
        fprintf(fp, "  Latency (avg): %.2f μs\n", results->seek_stats.avg_latency_us);
        fprintf(fp, "  Latency (p50): %.2f μs\n", results->seek_stats.p50_latency_us);
        fprintf(fp, "  Latency (p95): %.2f μs\n", results->seek_stats.p95_latency_us);
        fprintf(fp, "  Latency (p99): %.2f μs\n", results->seek_stats.p99_latency_us);
        fprintf(fp, "  Latency (min): %.2f μs\n", results->seek_stats.min_latency_us);
        fprintf(fp, "  Latency (max): %.2f μs\n\n", results->seek_stats.max_latency_us);
    }

    if (results->range_stats.ops_per_second > 0)
    {
        fprintf(fp, "RANGE Query Operations:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->range_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n", results->range_stats.duration_seconds);
        fprintf(fp, "  Latency (avg): %.2f μs\n", results->range_stats.avg_latency_us);
        fprintf(fp, "  Latency (p50): %.2f μs\n", results->range_stats.p50_latency_us);
        fprintf(fp, "  Latency (p95): %.2f μs\n", results->range_stats.p95_latency_us);
        fprintf(fp, "  Latency (p99): %.2f μs\n", results->range_stats.p99_latency_us);
        fprintf(fp, "  Latency (min): %.2f μs\n", results->range_stats.min_latency_us);
        fprintf(fp, "  Latency (max): %.2f μs\n", results->range_stats.max_latency_us);
        fprintf(fp, "  Keys per range: %d\n\n", results->config.range_size);
    }

    if (results->iteration_stats.ops_per_second > 0)
    {
        fprintf(fp, "ITERATION:\n");
        fprintf(fp, "  Throughput: %.2f ops/sec\n", results->iteration_stats.ops_per_second);
        fprintf(fp, "  Duration: %.3f seconds\n\n", results->iteration_stats.duration_seconds);
    }

    /* resource usage section */
    fprintf(fp, "Resource Usage:\n");
    fprintf(fp, "  Peak RSS: %.2f MB\n", results->resources.peak_rss_bytes / (1024.0 * 1024.0));
    fprintf(fp, "  Peak VMS: %.2f MB\n", results->resources.peak_vms_bytes / (1024.0 * 1024.0));
    fprintf(fp, "  Disk Reads: %.2f MB\n", results->resources.bytes_read / (1024.0 * 1024.0));
    fprintf(fp, "  Disk Writes: %.2f MB\n", results->resources.bytes_written / (1024.0 * 1024.0));
    fprintf(fp, "  CPU User Time: %.3f seconds\n", results->resources.cpu_user_time);
    fprintf(fp, "  CPU System Time: %.3f seconds\n", results->resources.cpu_system_time);
    fprintf(fp, "  CPU Utilization: %.1f%%\n", results->resources.cpu_percent);
    fprintf(fp, "  Database Size: %.2f MB\n\n",
            results->resources.storage_size_bytes / (1024.0 * 1024.0));

    /* amplification factors section */
    fprintf(fp, "Amplification Factors:\n");
    if (results->resources.write_amplification > 0)
    {
        fprintf(fp, "  Write Amplification: %.2fx\n", results->resources.write_amplification);
    }
    if (results->resources.read_amplification > 0)
    {
        fprintf(fp, "  Read Amplification: %.2fx\n", results->resources.read_amplification);
    }
    if (results->resources.space_amplification > 0)
    {
        fprintf(fp, "  Space Amplification: %.2fx\n", results->resources.space_amplification);
    }
    fprintf(fp, "\n");

    if (baseline)
    {
        fprintf(fp, "=== Comparison vs %s ===\n\n", baseline->engine_name);

        if (results->put_stats.ops_per_second > 0 && baseline->put_stats.ops_per_second > 0)
        {
            double speedup = results->put_stats.ops_per_second / baseline->put_stats.ops_per_second;
            fprintf(fp, "PUT: %.2fx %s\n", speedup, speedup > 1.0 ? "faster" : "slower");
        }

        if (results->get_stats.ops_per_second > 0 && baseline->get_stats.ops_per_second > 0)
        {
            double speedup = results->get_stats.ops_per_second / baseline->get_stats.ops_per_second;
            fprintf(fp, "GET: %.2fx %s\n", speedup, speedup > 1.0 ? "faster" : "slower");
        }

        if (results->delete_stats.ops_per_second > 0 && baseline->delete_stats.ops_per_second > 0)
        {
            double speedup =
                results->delete_stats.ops_per_second / baseline->delete_stats.ops_per_second;
            fprintf(fp, "DELETE: %.2fx %s\n", speedup, speedup > 1.0 ? "faster" : "slower");
        }

        if (results->iteration_stats.ops_per_second > 0 &&
            baseline->iteration_stats.ops_per_second > 0)
        {
            double speedup =
                results->iteration_stats.ops_per_second / baseline->iteration_stats.ops_per_second;
            fprintf(fp, "ITER: %.2fx %s\n", speedup, speedup > 1.0 ? "faster" : "slower");
        }

        /* resource comparison */
        fprintf(fp, "\nResource Comparison:\n");
        fprintf(fp, "  Peak RSS: %.2f MB vs %.2f MB\n",
                results->resources.peak_rss_bytes / (1024.0 * 1024.0),
                baseline->resources.peak_rss_bytes / (1024.0 * 1024.0));
        fprintf(fp, "  Peak VMS: %.2f MB vs %.2f MB\n",
                results->resources.peak_vms_bytes / (1024.0 * 1024.0),
                baseline->resources.peak_vms_bytes / (1024.0 * 1024.0));
        fprintf(fp, "  Disk Reads: %.2f MB vs %.2f MB\n",
                results->resources.bytes_read / (1024.0 * 1024.0),
                baseline->resources.bytes_read / (1024.0 * 1024.0));
        fprintf(fp, "  Disk Writes: %.2f MB vs %.2f MB\n",
                results->resources.bytes_written / (1024.0 * 1024.0),
                baseline->resources.bytes_written / (1024.0 * 1024.0));
        fprintf(fp, "  CPU User Time: %.3f s vs %.3f s\n", results->resources.cpu_user_time,
                baseline->resources.cpu_user_time);
        fprintf(fp, "  CPU System Time: %.3f s vs %.3f s\n", results->resources.cpu_system_time,
                baseline->resources.cpu_system_time);
        fprintf(fp, "  CPU Utilization: %.1f%% vs %.1f%%\n", results->resources.cpu_percent,
                baseline->resources.cpu_percent);
        fprintf(fp, "  Database Size: %.2f MB vs %.2f MB\n\n",
                results->resources.storage_size_bytes / (1024.0 * 1024.0),
                baseline->resources.storage_size_bytes / (1024.0 * 1024.0));

        /* amplification comparison */
        fprintf(fp, "Amplification Comparison:\n");
        if (results->resources.write_amplification > 0 &&
            baseline->resources.write_amplification > 0)
        {
            fprintf(fp, "  Write Amplification: %.2fx vs %.2fx\n",
                    results->resources.write_amplification,
                    baseline->resources.write_amplification);
        }
        if (results->resources.read_amplification > 0 && baseline->resources.read_amplification > 0)
        {
            fprintf(fp, "  Read Amplification: %.2fx vs %.2fx\n",
                    results->resources.read_amplification, baseline->resources.read_amplification);
        }
        if (results->resources.space_amplification > 0 &&
            baseline->resources.space_amplification > 0)
        {
            fprintf(fp, "  Space Amplification: %.2fx vs %.2fx\n",
                    results->resources.space_amplification,
                    baseline->resources.space_amplification);
        }
    }
}

void free_results(benchmark_results_t *results)
{
    if (results) free(results);
}