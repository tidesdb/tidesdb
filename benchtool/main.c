/*
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
#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "benchmark.h"

static void print_usage(const char *prog)
{
    printf("TidesDB Storage Engine Benchmarker\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf(
        "  -e, --engine <name>       Storage engine to benchmark (tidesdb, "
        "rocksdb)\n");
    printf("  -o, --operations <num>    Number of operations (default: 100000)\n");
    printf("  -k, --key-size <bytes>    Key size in bytes (default: 16)\n");
    printf("  -v, --value-size <bytes>  Value size in bytes (default: 100)\n");
    printf("  -t, --threads <num>       Number of threads (default: 1)\n");
    printf("  -b, --batch-size <num>    Batch size for operations (default: 1)\n");
    printf("  -d, --db-path <path>      Database path (default: ./bench_db)\n");
    printf("  -c, --compare             Compare against RocksDB baseline\n");
    printf("  -r, --report <file>       Output report to file (default: stdout)\n");
    printf("  -s, --sequential          Use sequential keys instead of random\n");
    printf(
        "  -p, --pattern <type>      Key pattern: seq, random, zipfian, "
        "uniform, timestamp, "
        "reverse (default: random)\n");
    printf(
        "  -w, --workload <type>     Workload type: write, read, mixed, "
        "delete, seek, range (default: mixed)\n");
    printf("  --sync                    Enable fsync for durable writes (slower)\n");
    printf("  --range-size <num>        Number of keys per range query (default: 100)\n");
    printf("  --memtable-size <bytes>   Memtable/write buffer size in bytes (0 = default)\n");
    printf("  --block-cache-size <bytes> Block cache size in bytes (0 = default)\n");
    printf("  --rocksdb-blobdb          Enable RocksDB BlobDB for large values\n");
    printf("  --no-rocksdb-blobdb       Disable RocksDB BlobDB\n");
    printf("  --bloom-fp <fp>           Bloom filter false positive rate (0.01 = default)\n");
    printf(
        "  --l0_queue_stall_threshold <num> L0 queue stall threshold (10 = default) (TidesDB) \n");
    printf("  --l1_file_count_trigger <num> L1 file count trigger (4 = default) (TidesDB) \n");
    printf("  --bloom-filters           Enable bloom filters\n");
    printf("  --klog_value_threshold <bytes> Klog value threshold (512 bytes = default)\n");
    printf("  --dividing_level_offset <num> Dividing level offset (TidesDB) (2 = default)\n");
    printf("  --min_levels <num> Minimum levels (TidesDB) (5 = default)\n");
    printf("  --index_sample_ratio <num> Sample ratio for block indexes (TidesDB) (1 = default)\n");
    printf(
        "  --block_index_prefix_len <num> Sample prefix length for min-max block indexes (TidesDB) "
        "(16 = default)\n");
    printf("  --no-bloom-filters        Disable bloom filters\n");
    printf("  --block-indexes           Enable block indexes\n");
    printf("  --no-block-indexes        Disable block indexes\n");
    printf("  -h, --help                Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s -e tidesdb -o 1000000 -k 16 -v 100\n", prog);
    printf("  %s -e tidesdb -c -o 500000 -t 4\n", prog);
    printf("  %s -e rocksdb -w write -o 1000000\n", prog);
}

int main(int argc, char **argv)
{
    benchmark_config_t config = {.engine_name = "tidesdb",
                                 .num_operations = 10000000,
                                 .key_size = 16,
                                 .value_size = 100,
                                 .num_threads = 4,
                                 .batch_size = 1,
                                 .db_path = "./bench_db",
                                 .compare_mode = 0,
                                 .report_file = NULL,
                                 .key_pattern = KEY_PATTERN_RANDOM,
                                 .workload_type = WORKLOAD_MIXED,
                                 .sync_enabled = 0,
                                 .range_size = 100,
                                 .memtable_size = 0,
                                 .block_cache_size = 0,
                                 .enable_blobdb = -1,
                                 .enable_bloom_filter = -1,
                                 .enable_block_indexes = -1,
                                 .bloom_fpr = 0.01,
                                 .l0_queue_stall_threshold = 10,
                                 .l1_file_count_trigger = 4,
                                 .dividing_level_offset = 2,
                                 .min_levels = 5,
                                 .index_sample_ratio = 1,
                                 .block_index_prefix_len = 16,
                                 .klog_value_threshold = 512};

    enum
    {
        OPT_BLOOM_FPR = 1000,
        OPT_L0_QUEUE_STALL_THRESHOLD,
        OPT_L1_FILE_COUNT_TRIGGER,
        OPT_DIVIDING_LEVEL_OFFSET,
        OPT_MIN_LEVELS,
        OPT_INDEX_SAMPLE_RATIO,
        OPT_BLOCK_INDEX_PREFIX_LEN,
        OPT_KLOG_VALUE_THRESHOLD
    };

    static struct option long_options[] = {
        {"engine", required_argument, 0, 'e'},
        {"operations", required_argument, 0, 'o'},
        {"key-size", required_argument, 0, 'k'},
        {"value-size", required_argument, 0, 'v'},
        {"threads", required_argument, 0, 't'},
        {"batch-size", required_argument, 0, 'b'},
        {"db-path", required_argument, 0, 'd'},
        {"compare", no_argument, 0, 'c'},
        {"report", required_argument, 0, 'r'},
        {"pattern", required_argument, 0, 'p'},
        {"workload", required_argument, 0, 'w'},
        {"sync", no_argument, 0, 'S'},
        {"range-size", required_argument, 0, 'R'},
        {"memtable-size", required_argument, 0, 'M'},
        {"block-cache-size", required_argument, 0, 'C'},
        {"rocksdb-blobdb", no_argument, 0, 'B'},
        {"no-rocksdb-blobdb", no_argument, 0, 'N'},
        {"bloom-filters", no_argument, 0, 'F'},
        {"no-bloom-filters", no_argument, 0, 'G'},
        {"block-indexes", no_argument, 0, 'I'},
        {"no-block-indexes", no_argument, 0, 'J'},
        {"bloom-fpr", required_argument, 0, OPT_BLOOM_FPR},
        {"l0_queue_stall_threshold", required_argument, 0, OPT_L0_QUEUE_STALL_THRESHOLD},
        {"l1_file_count_trigger", required_argument, 0, OPT_L1_FILE_COUNT_TRIGGER},
        {"dividing_level_offset", required_argument, 0, OPT_DIVIDING_LEVEL_OFFSET},
        {"min_levels", required_argument, 0, OPT_MIN_LEVELS},
        {"index_sample_ratio", required_argument, 0, OPT_INDEX_SAMPLE_RATIO},
        {"block_index_prefix_len", required_argument, 0, OPT_BLOCK_INDEX_PREFIX_LEN},
        {"klog_value_threshold", required_argument, 0, OPT_KLOG_VALUE_THRESHOLD},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "e:o:k:v:t:b:d:cr:sp:w:R:M:C:h", long_options,
                              &option_index)) != -1)
    {
        switch (opt)
        {
            case 'e':
                config.engine_name = optarg;
                break;
            case 'o':
                config.num_operations = atoi(optarg);
                break;
            case 'k':
                config.key_size = atoi(optarg);
                break;
            case 'v':
                config.value_size = atoi(optarg);
                break;
            case 't':
                config.num_threads = atoi(optarg);
                break;
            case 'b':
                config.batch_size = atoi(optarg);
                break;
            case 'd':
                config.db_path = optarg;
                break;
            case 's':
                config.key_pattern = KEY_PATTERN_SEQUENTIAL;
                break;
            case 'c':
                config.compare_mode = 1;
                break;
            case 'r':
                config.report_file = optarg;
                break;
            case 'p':
                if (strcmp(optarg, "seq") == 0 || strcmp(optarg, "sequential") == 0)
                    config.key_pattern = KEY_PATTERN_SEQUENTIAL;
                else if (strcmp(optarg, "random") == 0)
                    config.key_pattern = KEY_PATTERN_RANDOM;
                else if (strcmp(optarg, "zipfian") == 0)
                    config.key_pattern = KEY_PATTERN_ZIPFIAN;
                else if (strcmp(optarg, "uniform") == 0)
                    config.key_pattern = KEY_PATTERN_UNIFORM;
                else if (strcmp(optarg, "timestamp") == 0)
                    config.key_pattern = KEY_PATTERN_TIMESTAMP;
                else if (strcmp(optarg, "reverse") == 0)
                    config.key_pattern = KEY_PATTERN_REVERSE;
                else
                {
                    fprintf(stderr, "Invalid key pattern: %s\n", optarg);
                    return 1;
                }
                break;
            case 'w':
                if (strcmp(optarg, "write") == 0)
                    config.workload_type = WORKLOAD_WRITE;
                else if (strcmp(optarg, "read") == 0)
                    config.workload_type = WORKLOAD_READ;
                else if (strcmp(optarg, "mixed") == 0)
                    config.workload_type = WORKLOAD_MIXED;
                else if (strcmp(optarg, "delete") == 0)
                    config.workload_type = WORKLOAD_DELETE;
                else if (strcmp(optarg, "seek") == 0)
                    config.workload_type = WORKLOAD_SEEK;
                else if (strcmp(optarg, "range") == 0)
                    config.workload_type = WORKLOAD_RANGE;
                else
                {
                    fprintf(stderr, "Invalid workload type: %s\n", optarg);
                    return 1;
                }
                break;
            case 'S':
                config.sync_enabled = 1;
                break;
            case 'R':
                config.range_size = atoi(optarg);
                break;
            case 'M':
                config.memtable_size = (size_t)atoll(optarg);
                break;
            case 'C':
                config.block_cache_size = (size_t)atoll(optarg);
                break;
            case 'B':
                config.enable_blobdb = 1;
                break;
            case 'N':
                config.enable_blobdb = 0;
                break;
            case 'F':
                config.enable_bloom_filter = 1;
                break;
            case 'G':
                config.enable_bloom_filter = 0;
                break;
            case 'I':
                config.enable_block_indexes = 1;
                break;
            case 'J':
                config.enable_block_indexes = 0;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case OPT_BLOOM_FPR:
                config.bloom_fpr = atof(optarg);
                break;
            case OPT_L0_QUEUE_STALL_THRESHOLD:
                config.l0_queue_stall_threshold = atoi(optarg);
                break;
            case OPT_L1_FILE_COUNT_TRIGGER:
                config.l1_file_count_trigger = atoi(optarg);
                break;
            case OPT_DIVIDING_LEVEL_OFFSET:
                config.dividing_level_offset = atoi(optarg);
                break;
            case OPT_MIN_LEVELS:
                config.min_levels = atoi(optarg);
                break;
            case OPT_INDEX_SAMPLE_RATIO:
                config.index_sample_ratio = atoi(optarg);
                break;
            case OPT_BLOCK_INDEX_PREFIX_LEN:
                config.block_index_prefix_len = atoi(optarg);
                break;
            case OPT_KLOG_VALUE_THRESHOLD:
                config.klog_value_threshold = (size_t)atoll(optarg);
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (config.num_operations <= 0 || config.key_size <= 0 || config.value_size <= 0 ||
        config.num_threads <= 0 || config.batch_size <= 0)
    {
        fprintf(stderr, "Error: All numeric parameters must be positive\n");
        return 1;
    }

    printf("=== TidesDB Storage Engine Benchmarker ===\n\n");
    printf("Configuration:\n");
    const char *version = get_engine_version(config.engine_name);
    printf("  Engine: %s (v%s)\n", config.engine_name, version);
    printf("  Operations: %d\n", config.num_operations);
    printf("  Key Size: %d bytes\n", config.key_size);
    printf("  Value Size: %d bytes\n", config.value_size);
    printf("  Threads: %d\n", config.num_threads);
    printf("  Batch Size: %d\n", config.batch_size);
    const char *pattern_name;
    switch (config.key_pattern)
    {
        case KEY_PATTERN_SEQUENTIAL:
            pattern_name = "Sequential";
            break;
        case KEY_PATTERN_RANDOM:
            pattern_name = "Random";
            break;
        case KEY_PATTERN_ZIPFIAN:
            pattern_name = "Zipfian (hot keys)";
            break;
        case KEY_PATTERN_UNIFORM:
            pattern_name = "Uniform Random";
            break;
        case KEY_PATTERN_TIMESTAMP:
            pattern_name = "Timestamp";
            break;
        case KEY_PATTERN_REVERSE:
            pattern_name = "Reverse Sequential";
            break;
        default:
            pattern_name = "Unknown";
            break;
    }
    printf("  Key Pattern: %s\n", pattern_name);
    printf("  Workload: %s\n", config.workload_type == WORKLOAD_WRITE    ? "Write-only"
                               : config.workload_type == WORKLOAD_READ   ? "Read-only"
                               : config.workload_type == WORKLOAD_DELETE ? "Delete-only"
                               : config.workload_type == WORKLOAD_SEEK   ? "Seek"
                               : config.workload_type == WORKLOAD_RANGE  ? "Range Query"
                                                                         : "Mixed");
    printf("  Sync Mode: %s\n", config.sync_enabled ? "Enabled (durable)" : "Disabled (fast)");
    printf("\n");

    benchmark_results_t *results = NULL;
    benchmark_results_t *baseline_results = NULL;

    if (run_benchmark(&config, &results) != 0)
    {
        fprintf(stderr, "Benchmark failed\n");
        return 1;
    }

    if (config.compare_mode && strcmp(config.engine_name, "rocksdb") != 0)
    {
        printf("\n=== Cleaning database for baseline comparison ===\n");

        char rm_cmd[2048];
        snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", config.db_path);
        int rm_result = system(rm_cmd);
        if (rm_result != 0)
        {
            fprintf(stderr, "Warning: Failed to clean database path for baseline\n");
        }

        printf("\n=== Running RocksDB Baseline ===\n\n");
        benchmark_config_t baseline_config = config;
        baseline_config.engine_name = "rocksdb";

        if (run_benchmark(&baseline_config, &baseline_results) != 0)
        {
            fprintf(stderr, "Baseline benchmark failed\n");
        }
    }

    FILE *report_fp = stdout;
    if (config.report_file)
    {
        report_fp = fopen(config.report_file, "w");
        if (!report_fp)
        {
            fprintf(stderr, "Failed to open report file: %s\n", config.report_file);
            report_fp = stdout;
        }
    }

    printf("\n");   /* ensure newline before report */
    fflush(stdout); /* flush any buffered output */
    generate_report(report_fp, results, baseline_results);
    fflush(report_fp); /* ensure report is written */

    if (report_fp != stdout)
    {
        fclose(report_fp);
        printf("\nReport written to: %s\n", config.report_file);
    }

    free_results(results);
    if (baseline_results) free_results(baseline_results);

    return 0;
}