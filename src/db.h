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
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __TIDESDB_DB_H__
#define __TIDESDB_DB_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/** opaque types for FFI bindings (Java, etc.) */
struct tidesdb_t
{
    int _opaque;
};
struct tidesdb_column_family_t
{
    int _opaque;
};
struct tidesdb_txn_t
{
    int _opaque;
};
struct tidesdb_iter_t
{
    int _opaque;
};

typedef struct tidesdb_t tidesdb_t;
typedef struct tidesdb_column_family_t tidesdb_column_family_t;
typedef struct tidesdb_txn_t tidesdb_txn_t;
typedef struct tidesdb_iter_t tidesdb_iter_t;

/** debug logging levels */
typedef enum
{
    TDB_LOG_DEBUG = 0,
    TDB_LOG_INFO = 1,
    TDB_LOG_WARN = 2,
    TDB_LOG_ERROR = 3,
    TDB_LOG_FATAL = 4,
    TDB_LOG_NONE = 99
} tidesdb_log_level_t;

/** txn isolation levels */
typedef enum
{
    TDB_ISOLATION_READ_UNCOMMITTED = 0,
    TDB_ISOLATION_READ_COMMITTED = 1,
    TDB_ISOLATION_REPEATABLE_READ = 2,
    TDB_ISOLATION_SNAPSHOT = 3,
    TDB_ISOLATION_SERIALIZABLE = 4
} tidesdb_isolation_level_t;

/** compression algorithms */
typedef enum
{
    TDB_COMPRESS_NONE = 0,
#ifndef __sun
    TDB_COMPRESS_SNAPPY = 1,
#endif
    TDB_COMPRESS_LZ4 = 2,
    TDB_COMPRESS_ZSTD = 3,
    TDB_COMPRESS_LZ4_FAST = 4
} compression_algorithm;

/** column family sync modes */
typedef enum
{
    TDB_SYNC_NONE = 0,
    TDB_SYNC_FULL = 1,
    TDB_SYNC_INTERVAL = 2
} tidesdb_sync_mode_t;

/** system error codes */
#define TDB_SUCCESS          0
#define TDB_ERR_MEMORY       -1
#define TDB_ERR_INVALID_ARGS -2
#define TDB_ERR_NOT_FOUND    -3
#define TDB_ERR_IO           -4
#define TDB_ERR_CORRUPTION   -5
#define TDB_ERR_EXISTS       -6
#define TDB_ERR_CONFLICT     -7
#define TDB_ERR_TOO_LARGE    -8
#define TDB_ERR_MEMORY_LIMIT -9
#define TDB_ERR_INVALID_DB   -10
#define TDB_ERR_UNKNOWN      -11
#define TDB_ERR_LOCKED       -12

/** configuration limits */
#define TDB_MAX_COMPARATOR_NAME 64
#define TDB_MAX_COMPARATOR_CTX  256

/** comparator function type */
typedef int (*tidesdb_comparator_fn)(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx);

/**
 * tidesdb_column_family_config_t
 * configuration for a column family
 * @param write_buffer_size size of write buffer
 * @param level_size_ratio ratio of level sizes
 * @param min_levels minimum number of levels
 * @param dividing_level_offset offset for dividing level
 * @param klog_value_threshold threshold for klog value
 * @param compression_algorithm compression algorithm
 * @param enable_bloom_filter enable bloom filter
 * @param bloom_fpr bloom filter false positive rate
 * @param enable_block_indexes enable block indexes
 * @param index_sample_ratio index sample ratio
 * @param block_index_prefix_len block index prefix length
 * @param sync_mode sync mode
 * @param sync_interval_us sync interval in microseconds
 * @param comparator_name name of comparator
 * @param comparator_ctx_str comparator context string
 * @param comparator_fn_cached cached comparator function
 * @param comparator_ctx_cached cached comparator context
 * @param skip_list_max_level skip list max level
 * @param skip_list_probability skip list probability
 * @param default_isolation_level default isolation level
 * @param min_disk_space minimum free disk space required (bytes)
 * @param l1_file_count_trigger trigger for L1 file count, utilized for compaction triggering
 * @param l0_queue_stall_threshold threshold for L0 queue stall, utilized for backpressure
 */
typedef struct tidesdb_column_family_config_t
{
    size_t write_buffer_size;
    size_t level_size_ratio;
    int min_levels;
    int dividing_level_offset;
    size_t klog_value_threshold;
    compression_algorithm compression_algorithm;
    int enable_bloom_filter;
    double bloom_fpr;
    int enable_block_indexes;
    int index_sample_ratio;
    int block_index_prefix_len;
    int sync_mode;
    uint64_t sync_interval_us;
    char comparator_name[TDB_MAX_COMPARATOR_NAME];
    char comparator_ctx_str[TDB_MAX_COMPARATOR_CTX];
    void *comparator_fn_cached;
    void *comparator_ctx_cached;
    int skip_list_max_level;
    float skip_list_probability;
    tidesdb_isolation_level_t default_isolation_level;
    uint64_t min_disk_space;
    int l1_file_count_trigger;
    int l0_queue_stall_threshold;
} tidesdb_column_family_config_t;

/**
 * tidesdb_config_t
 * configuration for the database
 * @param db_path path to the database
 * @param num_flush_threads number of flush threads
 * @param num_compaction_threads number of compaction threads
 * @param log_level minimum log level to display (TDB_LOG_DEBUG, TDB_LOG_INFO, TDB_LOG_WARN,
 * TDB_LOG_ERROR, TDB_LOG_FATAL, TDB_LOG_NONE)
 * @param block_cache_size size of clock cache for hot sstable blocks
 * @param max_open_sstables maximum number of open sstables
 */
typedef struct tidesdb_config_t
{
    char *db_path;
    int num_flush_threads;
    int num_compaction_threads;
    tidesdb_log_level_t log_level;
    size_t block_cache_size;
    size_t max_open_sstables;
} tidesdb_config_t;

/**
 * tidesdb_stats_t
 * statistics for database column family
 * @param num_levels number of levels
 * @param memtable_size size of memtable
 * @param level_sizes sizes of each level
 * @param level_num_sstables number of sstables in each level
 * @param config column family configuration
 * @param total_keys total number of keys across memtable and all sstables
 * @param total_data_size total data size (klog + vlog) across all sstables
 * @param avg_key_size average key size in bytes
 * @param avg_value_size average value size in bytes
 * @param level_key_counts number of keys per level
 * @param read_amp read amplification (point lookup cost multiplier)
 * @param hit_rate cache hit rate (0.0 if cache disabled)
 */
typedef struct tidesdb_stats_t
{
    int num_levels;
    size_t memtable_size;
    size_t *level_sizes;
    int *level_num_sstables;
    tidesdb_column_family_config_t *config;
    uint64_t total_keys;
    uint64_t total_data_size;
    double avg_key_size;
    double avg_value_size;
    uint64_t *level_key_counts;
    double read_amp;
    double hit_rate;
} tidesdb_stats_t;

/**
 * tidesdb_cache_stats_t
 * statistics for database block cache
 * @param enabled whether block cache is enabled
 * @param total_entries total number of cached entries
 * @param total_bytes total bytes used by cache
 * @param hits cache hits
 * @param misses cache misses
 * @param hit_rate hit rate (hits / (hits + misses))
 * @param num_partitions number of cache partitions
 */
typedef struct tidesdb_cache_stats_t
{
    int enabled;
    size_t total_entries;
    size_t total_bytes;
    uint64_t hits;
    uint64_t misses;
    double hit_rate;
    size_t num_partitions;
} tidesdb_cache_stats_t;

/**** system default configuration functions */
tidesdb_column_family_config_t tidesdb_default_column_family_config(void);
tidesdb_config_t tidesdb_default_config(void);

/**** database operations */
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);
int tidesdb_close(tidesdb_t *db);

/**** comparator operations */
int tidesdb_register_comparator(tidesdb_t *db, const char *name, tidesdb_comparator_fn fn,
                                const char *ctx_str, void *ctx);
int tidesdb_get_comparator(tidesdb_t *db, const char *name, tidesdb_comparator_fn *fn, void **ctx);

/**** column family operations */
int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config);
int tidesdb_drop_column_family(tidesdb_t *db, const char *name);
int tidesdb_rename_column_family(tidesdb_t *db, const char *old_name, const char *new_name);
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);
int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count);

/**** transaction operations */
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn);
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn);
int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl);
int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size);
int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size);
int tidesdb_txn_commit(tidesdb_txn_t *txn);
int tidesdb_txn_rollback(tidesdb_txn_t *txn);
void tidesdb_txn_free(tidesdb_txn_t *txn);

/**** savepoint operations */
int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name);
int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name);
int tidesdb_txn_release_savepoint(tidesdb_txn_t *txn, const char *name);

/**** iterator operations */
int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter);
int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);
int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);
int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter);
int tidesdb_iter_next(tidesdb_iter_t *iter);
int tidesdb_iter_prev(tidesdb_iter_t *iter);
int tidesdb_iter_valid(tidesdb_iter_t *iter);
int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size);
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);
void tidesdb_iter_free(tidesdb_iter_t *iter);

/**** comparator functions */
int tidesdb_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx);
int tidesdb_comparator_lexicographic(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                     size_t key2_size, void *ctx);
int tidesdb_comparator_uint64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                              size_t key2_size, void *ctx);
int tidesdb_comparator_int64(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                             size_t key2_size, void *ctx);
int tidesdb_comparator_reverse_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                      size_t key2_size, void *ctx);
int tidesdb_comparator_case_insensitive(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                        size_t key2_size, void *ctx);

/**** maintenance operations */
int tidesdb_compact(tidesdb_column_family_t *cf);
int tidesdb_flush_memtable(tidesdb_column_family_t *cf);
int tidesdb_is_flushing(tidesdb_column_family_t *cf);
int tidesdb_is_compacting(tidesdb_column_family_t *cf);
int tidesdb_backup(tidesdb_t *db, char *dir);

/**** configuration operations */
int tidesdb_cf_config_load_from_ini(const char *ini_file, const char *section_name,
                                    tidesdb_column_family_config_t *config);
int tidesdb_cf_config_save_to_ini(const char *ini_file, const char *section_name,
                                  const tidesdb_column_family_config_t *config);
int tidesdb_cf_update_runtime_config(tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk);

/**** statistics operations */
int tidesdb_get_stats(tidesdb_column_family_t *cf, tidesdb_stats_t **stats);
void tidesdb_free_stats(tidesdb_stats_t *stats);
int tidesdb_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *stats);

void tidesdb_free(void *ptr);

#endif /* __TIDESDB_DB_H__ */
