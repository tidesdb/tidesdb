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
#include "tidesdb.h"

const char *_tidesdb_get_path_seperator()
{
/* windows and unix (posix) path separator differences */
#ifdef _WIN32
    return "\\";
#else
    return "/";
#endif
}

uint8_t *_tidesdb_serialize_key_value_pair(tidesdb_key_value_pair_t *kv, size_t *out_size,
                                           bool compress, tidesdb_compression_algo_t compress_algo)
{
    /* calculate the size of the serialized data */
    *out_size =
        sizeof(uint32_t) + kv->key_size + sizeof(uint32_t) + kv->value_size + sizeof(int64_t);

    /* allocate memory for the serialized data */
    uint8_t *serialized_data = malloc(*out_size);
    if (serialized_data == NULL) return NULL;

    uint8_t *ptr = serialized_data;

    /* serialize key_size */
    uint32_t key_size = kv->key_size;
    memcpy(ptr, &key_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* serialize key */
    memcpy(ptr, kv->key, kv->key_size);
    ptr += kv->key_size;

    /* serialize value_size */
    uint32_t value_size = kv->value_size;
    memcpy(ptr, &value_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* serialize value */
    memcpy(ptr, kv->value, kv->value_size);
    ptr += kv->value_size;

    /* serialize ttl */
    memcpy(ptr, &kv->ttl, sizeof(int64_t));

    if (compress)
    {
        /* compress the serialized data */
        uint8_t *compressed_data = NULL;
        size_t compressed_size = 0;
        compressed_data = compress_data(serialized_data, *out_size, &compressed_size,
                                        _tidesdb_map_compression_algo(compress_algo));

        free(serialized_data);
        serialized_data = compressed_data;
        *out_size = compressed_size;
    }

    return serialized_data;
}

tidesdb_key_value_pair_t *_tidesdb_deserialize_key_value_pair(
    uint8_t *data, size_t data_size, bool decompress, tidesdb_compression_algo_t compress_algo)
{
    uint8_t *decompressed_data = NULL;

    /* if we are to decompress the data */
    if (decompress)
    {
        size_t decompressed_size = 0;
        decompressed_data = decompress_data(data, data_size, &decompressed_size,
                                            _tidesdb_map_compression_algo(compress_algo));

        if (decompressed_data == NULL) return NULL;
        data = decompressed_data;
        data_size = decompressed_size;
    }

    const uint8_t *ptr = data;

    /* deserialize key_size */
    uint32_t key_size;
    memcpy(&key_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* deserialize key */
    uint8_t *key = malloc(key_size);
    if (key == NULL)
    {
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }
    memcpy(key, ptr, key_size);
    ptr += key_size;

    /* deserialize value_size */
    uint32_t value_size;
    memcpy(&value_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* deserialize value */
    uint8_t *value = malloc(value_size);
    if (value == NULL)
    {
        free(key);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* check for heap buffer overflow */
    if (ptr + value_size > data + data_size)
    {
        free(key);
        free(value);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    memcpy(value, ptr, value_size);
    ptr += value_size;

    /* deserialize ttl */
    int64_t ttl;
    memcpy(&ttl, ptr, sizeof(int64_t));

    /* create the key-value pair */
    tidesdb_key_value_pair_t *kv =
        _tidesdb_key_value_pair_new(key, key_size, value, value_size, ttl);

    /* free temporary allocations */
    free(key);
    free(value);
    if (decompressed_data) free(decompressed_data);

    return kv;
}

tidesdb_key_value_pair_t *_tidesdb_key_value_pair_new(const uint8_t *key, size_t key_size,
                                                      const uint8_t *value, size_t value_size,
                                                      int64_t ttl)
{
    tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
    if (kv == NULL) return NULL;

    /* we set the key */
    kv->key = malloc(key_size);
    if (kv->key == NULL)
    {
        free(kv);
        return NULL;
    }
    /* we copy the key */
    memcpy(kv->key, key, key_size);

    /* we set the key size */
    kv->key_size = key_size;

    /* we set the value */
    kv->value = malloc(value_size);
    if (kv->value == NULL)
    {
        free(kv->key);
        free(kv);
        return NULL;
    }

    /* we copy the value */
    memcpy(kv->value, value, value_size);

    /* we set the value size */
    kv->value_size = value_size;

    /* we set the ttl */
    kv->ttl = ttl;

    /* we return the key value pair */
    return kv;
}

void _tidesdb_free_key_value_pair(tidesdb_key_value_pair_t *kv)
{
    if (kv == NULL) return;

    /* we free the key */
    if (kv->key)
    {
        free(kv->key);
        kv->key = NULL;
    }

    /* we free the value */
    if (kv->value)
    {
        free(kv->value);
        kv->value = NULL;
    }

    /* we free the key value pair */
    free(kv);
    kv = NULL;
}

uint8_t *_tidesdb_serialize_sst_min_max(const uint8_t *min_key, size_t min_key_size,
                                        const uint8_t *max_key, size_t max_key_size,
                                        size_t *out_size)
{
    /* calculate the size of the serialized data */
    *out_size = sizeof(size_t) + min_key_size + sizeof(size_t) + max_key_size;

    /* allocate memory for the serialized data */
    uint8_t *serialized_data = malloc(*out_size);
    if (serialized_data == NULL) return NULL;

    uint8_t *ptr = serialized_data;

    /* serialize min_key_size and min_key */
    memcpy(ptr, &min_key_size, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, min_key, min_key_size);
    ptr += min_key_size;

    /* serialize max_key_size and max_key */
    memcpy(ptr, &max_key_size, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, max_key, max_key_size);
    ptr += max_key_size;

    return serialized_data;
}

tidesdb_sst_min_max_t *_tidesdb_deserialize_sst_min_max(const uint8_t *data)
{
    const uint8_t *ptr = data;

    /* deserialize min_key_size */
    size_t min_key_size;
    memcpy(&min_key_size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    /* deserialize min_key */
    uint8_t *min_key = malloc(min_key_size);
    if (min_key == NULL) return NULL;
    memcpy(min_key, ptr, min_key_size);
    ptr += min_key_size;

    /* deserialize max_key_size */
    size_t max_key_size;
    memcpy(&max_key_size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    /* deserialize max_key */
    uint8_t *max_key = malloc(max_key_size);
    if (max_key == NULL)
    {
        free(min_key);
        return NULL;
    }
    memcpy(max_key, ptr, max_key_size);
    ptr += max_key_size;

    /* create the sst min max struct */
    tidesdb_sst_min_max_t *min_max = malloc(sizeof(tidesdb_sst_min_max_t));
    if (min_max == NULL)
    {
        free(min_key);
        free(max_key);
        return NULL;
    }

    /* set the values */
    min_max->min_key = min_key;
    min_max->min_key_size = min_key_size;
    min_max->max_key = max_key;
    min_max->max_key_size = max_key_size;

    return min_max;
}

uint8_t *_tidesdb_serialize_column_family_config(tidesdb_column_family_config_t *config,
                                                 size_t *out_size)
{
    /* calculate the size of the serialized data */
    *out_size = sizeof(uint32_t) + strlen(config->name) + 1 + sizeof(int32_t) * 2 + sizeof(float) +
                sizeof(uint8_t) * 2 + sizeof(tidesdb_compression_algo_t);

    /* allocate memory for the serialized data */
    uint8_t *serialized_data = malloc(*out_size);
    if (serialized_data == NULL) return NULL;

    uint8_t *ptr = serialized_data;

    /* serialize name size and name */
    uint32_t name_size = strlen(config->name) + 1;
    memcpy(ptr, &name_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, config->name, name_size);
    ptr += name_size;

    /* serialize flush_threshold */
    memcpy(ptr, &config->flush_threshold, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* serialize max_level */
    memcpy(ptr, &config->max_level, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* serialize probability */
    memcpy(ptr, &config->probability, sizeof(float));
    ptr += sizeof(float);

    /* serialize compressed */
    uint8_t compressed = config->compressed;
    memcpy(ptr, &compressed, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* serialize bloom_filter */
    uint8_t bloom_filter = config->bloom_filter;
    memcpy(ptr, &bloom_filter, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* serialize compression_algo */
    memcpy(ptr, &config->compress_algo, sizeof(tidesdb_compression_algo_t));
    ptr += sizeof(tidesdb_compression_algo_t);

    return serialized_data;
}

tidesdb_column_family_config_t *_tidesdb_deserialize_column_family_config(const uint8_t *data)
{
    const uint8_t *ptr = data;

    /* deserialize name size */
    uint32_t name_size;
    memcpy(&name_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* deserialize name */
    char *name = malloc(name_size);
    if (name == NULL) return NULL;
    memcpy(name, ptr, name_size);
    ptr += name_size;

    /* deserialize flush_threshold */
    int32_t flush_threshold;
    memcpy(&flush_threshold, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* deserialize max_level */
    int32_t max_level;
    memcpy(&max_level, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* deserialize probability */
    float probability;
    memcpy(&probability, ptr, sizeof(float));
    ptr += sizeof(float);

    /* deserialize compressed */
    uint8_t compressed;
    memcpy(&compressed, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* deserialize bloom_filter */
    uint8_t bloom_filter;
    memcpy(&bloom_filter, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* deserialize compression_algo */
    tidesdb_compression_algo_t compress_algo;
    memcpy(&compress_algo, ptr, sizeof(tidesdb_compression_algo_t));
    ptr += sizeof(tidesdb_compression_algo_t);

    /* create the column family config */
    tidesdb_column_family_config_t *config = malloc(sizeof(tidesdb_column_family_config_t));
    if (config == NULL)
    {
        free(name);
        return NULL;
    }

    /* set the values */
    config->name = name;
    config->flush_threshold = flush_threshold;
    config->max_level = max_level;
    config->probability = probability;
    config->compressed = (bool)compressed;
    config->bloom_filter = (bool)bloom_filter;
    config->compress_algo = compress_algo;

    /* return the column family config */
    return config;
}

uint8_t *_tidesdb_serialize_operation(tidesdb_operation_t *op, size_t *out_size, bool compress,
                                      tidesdb_compression_algo_t compress_algo)
{
    if (op == NULL) return NULL;

    /* calculate the size of the serialized data */
    size_t cf_name_size = strlen(op->cf_name) + 1;
    size_t kv_size;
    uint8_t *kv_serialized =
        _tidesdb_serialize_key_value_pair(op->kv, &kv_size, false, TDB_NO_COMPRESSION);
    if (kv_serialized == NULL) return NULL;

    /* include the size of kv_size in the total size calculation */
    *out_size =
        sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t) + cf_name_size + sizeof(size_t) + kv_size;

    /* allocate memory for the serialized data */
    uint8_t *serialized_data = malloc(*out_size);
    if (serialized_data == NULL)
    {
        free(kv_serialized);
        return NULL;
    }

    uint8_t *ptr = serialized_data;

    /* serialize op_code */
    memcpy(ptr, &op->op_code, sizeof(TIDESDB_OP_CODE));
    ptr += sizeof(TIDESDB_OP_CODE);

    /* serialize cf_name size and cf_name */
    uint32_t cf_name_len = (uint32_t)cf_name_size;
    memcpy(ptr, &cf_name_len, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, op->cf_name, cf_name_size);
    ptr += cf_name_size;

    /* serialize kv_size first, then the key-value pair */
    memcpy(ptr, &kv_size, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, kv_serialized, kv_size);

    free(kv_serialized);

    if (compress)
    {
        /* compress the serialized data */
        uint8_t *compressed_data = NULL;
        size_t compressed_size = 0;
        compressed_data = compress_data(serialized_data, *out_size, &compressed_size,
                                        _tidesdb_map_compression_algo(compress_algo));

        free(serialized_data);
        serialized_data = compressed_data;
        *out_size = compressed_size;
    }

    return serialized_data;
}

tidesdb_operation_t *_tidesdb_deserialize_operation(uint8_t *data, size_t data_size,
                                                    bool decompress,
                                                    tidesdb_compression_algo_t compress_algo)
{
    uint8_t *decompressed_data = NULL;

    if (decompress)
    {
        size_t decompressed_size = 0;
        decompressed_data = decompress_data(data, data_size, &decompressed_size,
                                            _tidesdb_map_compression_algo(compress_algo));

        if (decompressed_data == NULL) return NULL;
        data = decompressed_data;
        data_size = decompressed_size;
    }

    /* we check if data is large enough for basic header */
    if (data_size < sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t))
    {
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    uint8_t *ptr = data;

    /* deserialize op_code */
    TIDESDB_OP_CODE op_code;
    memcpy(&op_code, ptr, sizeof(TIDESDB_OP_CODE));
    ptr += sizeof(TIDESDB_OP_CODE);

    /* deserialize cf_name size */
    uint32_t cf_name_size;
    memcpy(&cf_name_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* we check if data is large enough for cf_name */
    if (data_size < sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t) + cf_name_size)
    {
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* deserialize cf_name */
    char *cf_name = malloc(cf_name_size);
    if (cf_name == NULL)
    {
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }
    memcpy(cf_name, ptr, cf_name_size);
    ptr += cf_name_size;

    /* Check if data is large enough for kv_size */
    if (data_size < sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t) + cf_name_size + sizeof(size_t))
    {
        free(cf_name);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* deserialize kv_size */
    size_t kv_size;
    memcpy(&kv_size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    /* we check if data is large enough for key-value pair */
    if (data_size <
        sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t) + cf_name_size + sizeof(size_t) + kv_size)
    {
        free(cf_name);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* deserialize key-value pair */
    tidesdb_key_value_pair_t *kv =
        _tidesdb_deserialize_key_value_pair(ptr, kv_size, false, TDB_NO_COMPRESSION);
    if (kv == NULL)
    {
        free(cf_name);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* create the op */
    tidesdb_operation_t *op = malloc(sizeof(tidesdb_operation_t));
    if (op == NULL)
    {
        free(cf_name);
        (void)_tidesdb_free_key_value_pair(kv);
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }

    /* set the values */
    op->op_code = op_code;
    op->cf_name = cf_name;
    op->kv = kv;

    if (decompressed_data) free(decompressed_data);

    return op;
}

void _tidesdb_free_operation(tidesdb_operation_t *op)
{
    if (op == NULL) return;

    /* free the cf_name */
    if (op->cf_name)
    {
        free(op->cf_name);
        op->cf_name = NULL;
    }

    /* free the key-value pair */
    (void)_tidesdb_free_key_value_pair(op->kv);

    /* free the operation */
    free(op);
    op = NULL;
}

tidesdb_err_t *tidesdb_open(const char *directory, tidesdb_t **tdb)
{
    /* we check if the provided tidesdb instance is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check the configured db path */
    if (directory == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB_DIR);

    /* first we allocate memory for the tidesdb struct */
    *tdb = malloc(sizeof(tidesdb_t));

    /* we check if allocation was successful */
    if (*tdb == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "tidesdb_t");
    }

    /* we make sure the db path is not too long
     * we use block manager MAX_FILE_PATH_LENGTH to check against */
    if (strlen(directory) > MAX_FILE_PATH_LENGTH)
    {
        free(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_PATH_TOO_LONG, "directory");
    }

    /* we set the db path */
    (*tdb)->directory = strdup(directory);
    if ((*tdb)->directory == NULL)
    {
        free(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "db path");
    }

    /* set column families */
    (*tdb)->column_families = NULL;
    (*tdb)->num_column_families = 0; /* 0 for now until we read db path */

    /* initialize the db lock */
    if (pthread_rwlock_init(&(*tdb)->rwlock, NULL) != 0)
    {
        free((*tdb)->directory);
        free(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_LOCK, "tidesdb_t");
    }

    int new_instance = 0; /* local variable to check if db is new or not */

    /* we check to see if the db path exists
     * if not we create it */
    if (access(directory, F_OK) == -1) /* we create the directory **/
    {
        new_instance = 1;
        if (mkdir(directory, 0777) == -1)
        {
            free((*tdb)->directory);
            free(*tdb);
            return tidesdb_err_from_code(TIDESDB_ERR_MKDIR, directory);
        }
    }

    if (TDB_DEBUG_LOG == 1)
    {
        char log_path[MAX_FILE_PATH_LENGTH];
        (void)snprintf(log_path, sizeof(log_path), "%s%s%s", directory,
                       _tidesdb_get_path_seperator(), TDB_LOG_EXT);

        /* we set up the log file */
        if (log_init(&(*tdb)->log, log_path, TDB_DEBUG_LOG_TRUNCATE_AT) == -1)
        {
            free((*tdb)->directory);
            free(*tdb);
            return tidesdb_err_from_code(TIDESDB_ERR_LOG_INIT_FAILED);
        }
    }

    if (TDB_BLOCK_INDICES == 1)
    {
        (void)log_write((*tdb)->log,
                        _tidesdb_get_debug_log_format(TIDESDB_DEBUG_BLOCK_INDICES_ENABLED));
    }

    if (new_instance)
        (void)log_write((*tdb)->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_INIT_NEW_DATABASE),
                        directory);
    else
        (void)log_write((*tdb)->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_REOPEN_DATABASE),
                        directory);

    /* now we load the column families */
    if (_tidesdb_load_column_families(*tdb) == -1)
    {
        free((*tdb)->directory);
        (void)tidesdb_close(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_LOAD_COLUMN_FAMILIES);
    }

    (*tdb)->available_mem = _tidesdb_get_available_mem();
    (*tdb)->available_mem =
        (size_t)((double)(*tdb)->available_mem * TDB_AVAILABLE_MEMORY_THRESHOLD);

    if ((*tdb)->available_mem == 0)
    {
        (void)log_write((*tdb)->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_SYSTEM_MEMORY)->message);
        (void)tidesdb_close(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_SYSTEM_MEMORY);
    }

    /* we get available system threads */
    (*tdb)->avail_threads = _tidesdb_get_max_sys_threads();
    if ((*tdb)->avail_threads == 0 || (*tdb)->avail_threads == -1)
    {
        (void)log_write((*tdb)->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_SYSTEM_THREADS)->message);
        (void)tidesdb_close(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_SYSTEM_THREADS);
    }

    (void)log_write((*tdb)->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_AVAIL_MEMORY),
                    (*tdb)->available_mem);

    (void)log_write((*tdb)->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_AVAIL_THREADS),
                    (*tdb)->avail_threads);

    (void)log_write((*tdb)->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_OPENED_SUCCESS),
                    directory);

    return NULL;
}

int _tidesdb_load_column_families(tidesdb_t *tdb)
{
    /* check if tdb is NULL */
    if (tdb == NULL) return -1;

    /* open the db directory */
    DIR *tdb_dir = opendir(tdb->directory);
    if (tdb_dir == NULL)
    {
        (void)log_write(
            tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_DIRECTORY, tdb->directory)->message);
        return -1;
    }

    struct dirent *tdb_entry; /* create a dirent struct for the db directory */

    /* we iterate over the db directory */
    while ((tdb_entry = readdir(tdb_dir)) != NULL)
    {
        /* we skip the . and .. directories */
        if (strcmp(tdb_entry->d_name, ".") == 0 || strcmp(tdb_entry->d_name, "..") == 0) continue;

        /* each directory is a column family */
        char cf_path[MAX_FILE_PATH_LENGTH];
        (void)snprintf(cf_path, sizeof(cf_path), "%s%s%s", tdb->directory,
                       _tidesdb_get_path_seperator(), tdb_entry->d_name);

        /* we open the column family directory */
        DIR *cf_dir = opendir(cf_path);
        if (cf_dir == NULL) continue;

        struct dirent *cf_entry; /* create a dirent struct for the column family directory */

        /* we iterate over the column family directory */
        while ((cf_entry = readdir(cf_dir)) != NULL)
        {
            if (strstr(cf_entry->d_name, TDB_COLUMN_FAMILY_CONFIG_FILE_EXT) != NULL)
            { /* if the file is a column family config file */

                char config_file_path[MAX_FILE_PATH_LENGTH];
                if (snprintf(config_file_path, sizeof(config_file_path), "%s%s%s", cf_path,
                             _tidesdb_get_path_seperator(),
                             cf_entry->d_name) >= (long)sizeof(config_file_path))
                {
                    (void)closedir(cf_dir);
                    continue;
                }

                /* load the config file into memory */
                FILE *config_file = fopen(config_file_path, "rb");
                if (config_file == NULL)
                {
                    (void)closedir(cf_dir);
                    continue;
                }

                (void)fseek(config_file, 0, SEEK_END);   /* seek to end of file */
                size_t config_size = ftell(config_file); /* get size of file */
                (void)fseek(config_file, 0, SEEK_SET);   /* seek back to beginning of file */

                uint8_t *buffer = malloc(config_size);
                if (fread(buffer, 1, config_size, config_file) != config_size)
                {
                    free(buffer);
                    (void)fclose(config_file);
                    (void)closedir(cf_dir);
                    continue;
                }

                (void)fclose(config_file);

                /* deserialize the cf config */
                tidesdb_column_family_config_t *config =
                    _tidesdb_deserialize_column_family_config(buffer);
                if (config == NULL)
                {
                    free(buffer);
                    (void)closedir(cf_dir);
                    continue;
                }

                free(buffer);

                /* initialize the column family and add it to tidesdb */
                tidesdb_column_family_t *cf = malloc(sizeof(tidesdb_column_family_t));
                if (cf == NULL)
                {
                    free(config->name);
                    free(config);
                    (void)closedir(cf_dir);
                    continue;
                }

                cf->config = *config;
                cf->path = strdup(cf_path);
                cf->sstables = NULL;
                cf->num_sstables = 0;
                cf->incremental_merging = false;
                cf->tdb = tdb;
                cf->require_sst_shift = false;

                (void)log_write(
                    tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_COLUMN_FAMILY_SETTING_UP),
                    cf->config.name);

                cf->memtable = NULL;
                if (skip_list_new(&cf->memtable, cf->config.max_level, cf->config.probability) ==
                    -1)
                {
                    (void)log_write(
                        tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "memtable")->message);
                    free(cf->path);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                free(config);

                cf->wal = malloc(sizeof(tidesdb_wal_t));
                if (cf->wal == NULL) /* could not allocate memory for wal */
                {
                    free(cf->path);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                /* initialize read-write lock */
                if (pthread_rwlock_init(&cf->rwlock, NULL) != 0)
                {
                    free(cf->path);
                    free(cf->wal);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                /* now we open the wal */
                if (_tidesdb_open_wal(cf->path, &cf->wal, cf->config.compressed,
                                      cf->config.compress_algo) == -1)
                {
                    (void)log_write(tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_WAL,
                                                                    cf->config.name)
                                                  ->message);
                    free(cf->path);
                    free(cf->wal);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                (void)log_write(tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_OPENED_WAL),
                                cf->config.name);

                /* we add the column family to tidesdb arr */
                if (_tidesdb_add_column_family(tdb, cf) == -1)
                {
                    (void)log_write(
                        tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_ADD_COLUMN_FAMILY, cf->config.name)
                            ->message);
                    (void)_tidesdb_close_wal(cf->wal);
                    free(cf->path);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                /* we load the sstable files into memory */
                (void)_tidesdb_load_sstables(cf);

                (void)log_write(
                    tdb->log,
                    _tidesdb_get_debug_log_format(TIDESDB_DEBUG_LOADED_COLUMN_FAMILY_SSTABLES),
                    cf->config.name);

                /* we sort sstables if any, don't worry about the return here */
                (void)_tidesdb_sort_sstables(cf);

                /* now we replay from the wal and populate column family memtable */
                if (_tidesdb_replay_from_wal(cf) == -1)
                {
                    (void)log_write(
                        tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_COLUMN_FAMILY_WAL_REPLAY,
                                                        cf->config.name)
                                      ->message);
                }
                else
                {
                    (void)log_write(
                        tdb->log,
                        _tidesdb_get_debug_log_format(TIDESDB_DEBUG_REPLAYED_COLUMN_FAMILY_WAL),
                        cf->config.name);
                }
            }
        }

        /* we free up resources */
        if (closedir(cf_dir) == -1)
        {
            (void)log_write(
                tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY, cf_path)->message);
        }
    }

    /* we free up resources */
    if (closedir(tdb_dir) == -1)
    {
        (void)log_write(
            tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY, tdb->directory)->message);
    }

    return 0;
}

tidesdb_err_t *tidesdb_close(tidesdb_t *tdb)
{
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    (void)log_write(tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_CLOSING_DATABASE),
                    tdb->directory);

    (void)_tidesdb_free_column_families(tdb);

    /* we destroy the db lock */
    if (pthread_rwlock_destroy(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_DESTROY_LOCK, "tidesdb_t");

    free(tdb->directory);

    /* we close the log if configured */
    if (TDB_DEBUG_LOG == 1)
    {
        (void)log_close(tdb->log);
    }

    /* we free the tidesdb */
    free(tdb);

    tdb = NULL;

    return NULL;
}

void _tidesdb_free_column_families(tidesdb_t *tdb)
{
    /* we check if we have column families */
    if (tdb->num_column_families > 0)
    {
        /* we iterate over the column families and free them */
        for (int i = 0; i < tdb->num_column_families; i++)
        {
            if (tdb->column_families[i]->incremental_merging)
            {
                tdb->column_families[i]->incremental_merging = false;
                /* wait for thread to finish */
                (void)pthread_join(tdb->column_families[i]->incremental_merge_thread, NULL);
            }

            if (tdb->column_families[i]->config.name != NULL)
                free(tdb->column_families[i]->config.name);

            if (tdb->column_families[i]->path != NULL) free(tdb->column_families[i]->path);

            (void)skip_list_free(tdb->column_families[i]->memtable);
            tdb->column_families[i]->memtable = NULL;

            /* we free the sstables, closing them as well */
            if (tdb->column_families[i]->sstables != NULL)
            {
                for (int j = 0; j < tdb->column_families[i]->num_sstables; j++)
                    (void)_tidesdb_free_sstable(tdb->column_families[i]->sstables[j]);

                free(tdb->column_families[i]->sstables);
                tdb->column_families[i]->sstables = NULL;
            }

            /* we close the wal */
            if (tdb->column_families[i]->wal != NULL)
            {
                (void)_tidesdb_close_wal(tdb->column_families[i]->wal);
                tdb->column_families[i]->wal = NULL;
            }

            /* we free the column family */
            free(tdb->column_families[i]);
            tdb->column_families[i] = NULL;
        }

        /* we free the column families */
        free(tdb->column_families);
        tdb->column_families = NULL;
    }
}

int _tidesdb_free_sstable(tidesdb_sstable_t *sst)
{
    /* we check if the sstable is NULL */
    if (sst == NULL) return -1;

    /* we close the block manager */
    if (sst->block_manager != NULL)
    {
        (void)block_manager_close(sst->block_manager);
        sst->block_manager = NULL;
    }

    /* we free the sstable */
    free(sst);

    sst = NULL;

    return 0;
}

void _tidesdb_close_wal(tidesdb_wal_t *wal)
{
    /* we check if the wal is NULL */
    if (wal == NULL) return;

    /* we close the block manager */
    if (wal->block_manager != NULL)
    {
        (void)block_manager_close(wal->block_manager);
        wal->block_manager = NULL;
    }

    /* we free the wal */
    free(wal);

    wal = NULL;
}

int _tidesdb_load_sstables(tidesdb_column_family_t *cf)
{
    /* we check if cf is NULL */
    if (cf == NULL)
    {
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY)->message);
        return -1;
    }

    if (cf->path == NULL)
    {
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY)->message);
        return -1;
    }

    /* we open the column family directory */
    DIR *cf_dir = opendir(cf->path);
    if (cf_dir == NULL)
    { /* we check if the directory was opened */
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_DIRECTORY, cf->path)->message);
        return -1;
    }

    struct dirent *entry;

    /* we iterate over the column family directory */
    while ((entry = readdir(cf_dir)) != NULL)
    {
        /* we skip the . and .. directories */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        /* if the file ends with TDB_TEMP_EXT, we remove it as this is possibly unfinished merge
         * which did not complete prior to shutdown */
        if (strstr(entry->d_name, TDB_TEMP_EXT) != NULL)
        {
            char temp_file_path[MAX_FILE_PATH_LENGTH]; /* we construct the path to the temp file we
                                                          identified */
            (void)snprintf(temp_file_path, sizeof(temp_file_path), "%s%s%s", cf->path,
                           _tidesdb_get_path_seperator(), entry->d_name);

            /* we remove the temp file */
            if (remove(temp_file_path) == -1)
            {
                (void)log_write(
                    cf->tdb->log,
                    tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_REMOVE_TEMP_FILE, temp_file_path)
                        ->message);
                return -1;
            }
        }
        /* we check if the file ends with SSTABLE_EXT or contains */
        if (strstr(entry->d_name, TDB_SSTABLE_EXT) == NULL) continue;

        /* we construct the path to the sstable */
        char sstable_path[MAX_FILE_PATH_LENGTH];
        (void)snprintf(sstable_path, sizeof(sstable_path), "%s%s%s", cf->path,
                       _tidesdb_get_path_seperator(), entry->d_name);

        /* we open the sstable */
        block_manager_t *sstable_block_manager = NULL;

        if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_SSTABLE, sstable_path)->message);
            /* free up resources */
            (void)closedir(cf_dir);

            return -1;
        }

        /* we create/alloc the sstable struct */
        tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
        if (sst == NULL)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "tidesdb_sstable_t")->message);
            return -1;
        }

        /* we set the block manager */
        sst->block_manager = sstable_block_manager;

        /* check if sstables is NULL */
        if (cf->sstables == NULL)
        {
            cf->sstables = malloc(sizeof(tidesdb_sstable_t));
            if (cf->sstables == NULL)
            {
                (void)_tidesdb_free_sstable(sst);
                (void)closedir(cf_dir);
                (void)log_write(
                    cf->tdb->log,
                    tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "tidesdb_sstable_t")->message);
                return -1;
            }
        }
        else
        {
            /* we add the sstable to the column family */
            tidesdb_sstable_t **temp_sstables =
                realloc(cf->sstables, sizeof(tidesdb_sstable_t) * (cf->num_sstables + 1));
            if (temp_sstables == NULL)
            {
                (void)_tidesdb_free_sstable(sst);
                (void)closedir(cf_dir);
                (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                                    "temp tidesdb_sstable_t")
                                                  ->message);
                return -1;
            }

            cf->sstables = temp_sstables;
        }

        cf->sstables[cf->num_sstables] = sst;

        /* we increment the number of sstables */
        cf->num_sstables++;
    }

    /* we free up resources */
    if (closedir(cf_dir) == -1)
    {
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY, cf->path)->message);
        return -1;
    }

    /* we return -1 if no sstables were found */
    return -1;
}

int _tidesdb_open_wal(const char *cf_path, tidesdb_wal_t **w, bool compress,
                      tidesdb_compression_algo_t compress_algo)
{
    if (cf_path == NULL) return -1;

    /* we check if wal is NULL */
    if (w == NULL) return -1;

    char wal_path[MAX_FILE_PATH_LENGTH];
    (void)snprintf(wal_path, sizeof(wal_path), "%s%s%s", cf_path, _tidesdb_get_path_seperator(),
                   TDB_WAL_EXT);

    block_manager_t *wal_block_manager = NULL;
    if (block_manager_open(&wal_block_manager, wal_path, TDB_SYNC_INTERVAL) == -1)
    {
        return -1;
    }
    (*w)->compress = compress;
    (*w)->compress_algo = compress_algo;

    (*w)->block_manager = wal_block_manager;

    return 0;
}

int _tidesdb_add_column_family(tidesdb_t *tdb, tidesdb_column_family_t *cf)
{
    /* we get write lock */
    if (pthread_rwlock_wrlock(&tdb->rwlock) != 0) return -1;

    /* we check if tdb or cf is NULL */
    if (tdb == NULL || cf == NULL) return -1;

    if (tdb->column_families == NULL)
    {
        tdb->column_families = malloc(sizeof(tidesdb_column_family_t *));
        if (tdb->column_families == NULL)
        {
            (void)pthread_rwlock_unlock(&tdb->rwlock);
            return -1;
        }
    }
    else
    {
        tidesdb_column_family_t **temp_families =
            realloc(tdb->column_families,
                    sizeof(tidesdb_column_family_t *) * (tdb->num_column_families + 1));
        /* we check if the reallocation was successful */
        if (temp_families == NULL)
        {
            (void)pthread_rwlock_unlock(&tdb->rwlock);
            (void)log_write(tdb->log, tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED,
                                                            "temp tidesdb_column_family_t")
                                          ->message);
            return -1;
        }

        tdb->column_families = temp_families;
    }

    /* we increment the number of column families */
    tdb->num_column_families++;

    /* we add the column family */
    tdb->column_families[tdb->num_column_families - 1] = cf;

    /* we release the write lock */
    (void)pthread_rwlock_unlock(&tdb->rwlock);

    return 0;
}

int _tidesdb_sort_sstables(const tidesdb_column_family_t *cf)
{
    /* we check if the column family is NULL */
    if (cf == NULL) return -1;

    /* if we have more than 1 sstable we sort them by last modified time */
    if (cf->num_sstables > 1)
    {
        qsort(cf->sstables, cf->num_sstables, sizeof(tidesdb_sstable_t), _tidesdb_compare_sstables);
        return 0;
    }

    return -1;
}

int _tidesdb_compare_sstables(const void *a, const void *b)
{
    if (a == NULL || b == NULL) return 0;

    tidesdb_sstable_t *s1 = (tidesdb_sstable_t *)a;
    tidesdb_sstable_t *s2 = (tidesdb_sstable_t *)b;

    time_t last_modified_s1 = block_manager_last_modified(s1->block_manager);
    time_t last_modified_s2 = block_manager_last_modified(s2->block_manager);

    switch ((last_modified_s1 < last_modified_s2) - (last_modified_s1 > last_modified_s2))
    {
        case -1:
            return -1;
        case 1:
            return 1;
        default:
            return 0;
    }
}

int _tidesdb_replay_from_wal(tidesdb_column_family_t *cf)
{
    /* we simply create a block manager cursor, deserialize operations and replay them on the
     * memtable */
    block_manager_cursor_t *cursor = NULL;

    /* initialize the cursor */
    if (block_manager_cursor_init(&cursor, cf->wal->block_manager) == -1)
    {
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_WAL_CURSOR, cf->config.name)->message);
        return -1;
    }

    do /* we iterate over the wal */
    {
        /* we read the block */
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (block == NULL) break;

        /* we deserialize the operation */
        tidesdb_operation_t *op = _tidesdb_deserialize_operation(
            block->data, block->size, cf->config.compressed, cf->config.compress_algo);
        if (op == NULL)
        {
            free(block);
            break;
        }

        switch (op->op_code)
        {
            case TIDESDB_OP_PUT:

                (void)skip_list_put(cf->memtable, op->kv->key, op->kv->key_size, op->kv->value,
                                    op->kv->value_size, op->kv->ttl);

                break;
            case TIDESDB_OP_DELETE:
            {
                uint8_t *tombstone = malloc(4);
                if (tombstone == NULL) continue;

                uint32_t tombstone_value = TOMBSTONE;
                memcpy(tombstone, &tombstone_value, sizeof(uint32_t));

                (void)skip_list_put(cf->memtable, op->kv->key, op->kv->key_size, tombstone, 4,
                                    op->kv->ttl);

                free(tombstone);
            }
            break;
            default:
                break;
        }

        (void)block_manager_block_free(block);

        /* we free the operation */
        (void)_tidesdb_free_operation(op);

    } while (block_manager_cursor_next(cursor) != -1);

    (void)block_manager_cursor_free(cursor);

    return 0;
}

tidesdb_err_t *tidesdb_create_column_family(tidesdb_t *tdb, const char *name, int flush_threshold,
                                            int max_level, float probability, bool compressed,
                                            tidesdb_compression_algo_t compression_algo,
                                            bool bloom_filter)
{
    /* verify the compression algorithm */
    if (compressed && compression_algo == TDB_NO_COMPRESSION)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COMPRESSION_ALGO);

    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the name is NULL */
    if (name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if the column family name is greater than 2 */
    if (strlen(name) < 2) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we check flush threshold
     * the system expects at least TDB_FLUSH_THRESHOLD threshold */
    if (flush_threshold < TDB_FLUSH_THRESHOLD)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_FLUSH_THRESHOLD);

    /* don't allow flush threshold greater than available memory */
    if ((size_t)flush_threshold > tdb->available_mem)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_FLUSH_THRESHOLD);

    /* we check max level
     * the system expects at least a level of TDB_MIN_MAX_LEVEL */
    if (max_level < TDB_MIN_MAX_LEVEL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_MAX_LEVEL);

    /* we check probability
     * the system expects at least a probability of TDB_MIN_PROBABILITY */
    if (probability < TDB_MIN_PROBABILITY)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_PROBABILITY);

    /* we check the compression algorithm */
    switch (compression_algo)
    {
        case TDB_NO_COMPRESSION:
        case TDB_COMPRESS_SNAPPY:
        case TDB_COMPRESS_ZSTD:
        case TDB_COMPRESS_LZ4:
            break;
        default:
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COMPRESSION_ALGO);
    }

    /* check if column family already exists */

    /* we acquire read lock */
    if (pthread_rwlock_wrlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "tidesdb_t");
    }

    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i]->config.name, name) == 0)
        {
            /* we release the lock */
            if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
            {
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
            }

            return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_ALREADY_EXISTS);
        }
    }

    /* we release the lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
    }

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_new_column_family(tdb, name, flush_threshold, max_level, probability, &cf,
                                   compressed, compression_algo, bloom_filter) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CREATE_COLUMN_FAMILY);

    /* now we add the column family */
    if (_tidesdb_add_column_family(tdb, cf) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ADD_COLUMN_FAMILY);

    /* we log to debug log that new column family was created */
    (void)log_write(tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_NEW_COLUMN_FAMILY), name);

    return NULL;
}

tidesdb_err_t *tidesdb_drop_column_family(tidesdb_t *tdb, const char *name)
{
    /* check if either tdb or name is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the name is NULL */
    if (name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if the column family name is greater than 2 */
    if (strlen(name) < 2) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we acquire read lock */
    if (pthread_rwlock_wrlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "tidesdb_t");
    }

    /* check if column family exists */
    bool found = false;
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i]->config.name, name) == 0)
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        /* we release the lock */
        if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        {
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
        }

        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* we releas read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
    }

    /* we acquire write lock */
    if (pthread_rwlock_wrlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "tidesdb_t");
    }

    /* now we remove the column family */

    /* iterate over the column families to find the one to remove */
    int index = -1;
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i]->config.name, name) == 0)
        {
            index = i;
            break;
        }
    }

    if (index == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* free the resources associated with the column family */
    free(tdb->column_families[index]->config.name);

    /* check if the column family has sstables */
    if (tdb->column_families[index]->num_sstables > 0)
    {
        /* iterate over the sstables and free the resources */
        for (int i = 0; i < tdb->column_families[index]->num_sstables; i++)
            (void)_tidesdb_free_sstable(tdb->column_families[index]->sstables[i]);

        /* free the sstables array */
        free(tdb->column_families[index]->sstables);
    }

    /* close the wal */
    (void)_tidesdb_close_wal(tdb->column_families[index]->wal);

    /* wal path */
    char wal_path[MAX_FILE_PATH_LENGTH];

    snprintf(wal_path, sizeof(wal_path), "%s%s%s", tdb->column_families[index]->path,
             _tidesdb_get_path_seperator(), TDB_WAL_EXT);

    /* remove the wal file */
    if (unlink(wal_path) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_RM_FAILED, wal_path);
    }

    (void)remove(wal_path); /*in case */

    (void)skip_list_free(tdb->column_families[index]->memtable);

    /* remove all files in the column family directory */
    if (_tidesdb_remove_directory(tdb->column_families[index]->path) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_RM_FAILED, tdb->column_families[index]->path);
    }

    free(tdb->column_families[index]->path);

    free(tdb->column_families[index]);

    /* reallocate memory for the column families array */
    if (tdb->num_column_families > 1)
    {
        for (int i = index; i < tdb->num_column_families - 1; i++)
            tdb->column_families[i] = tdb->column_families[i + 1];

        tdb->num_column_families--;
        tidesdb_column_family_t **temp_families = realloc(
            tdb->column_families, tdb->num_column_families * sizeof(tidesdb_column_family_t *));
        if (temp_families == NULL)
        {
            (void)pthread_rwlock_unlock(&tdb->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "column families");
        }

        tdb->column_families = temp_families;
    }
    else
    {
        /* free the column families array */
        free(tdb->column_families);
        tdb->num_column_families = 0;
        tdb->column_families = NULL;
    }

    /* we release the lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
    }

    /* we log to debug log that column family was dropped */
    (void)log_write(tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_DROP_COLUMN_FAMILY),
                    name);

    return NULL;
}

int _tidesdb_remove_directory(const char *path)
{
    /* we could rework to remove recursion and use a stack-iterative approach */
    struct dirent *entry;
    struct stat statbuf;
    char fullpath[MAX_FILE_PATH_LENGTH];
    DIR *dir;

    dir = opendir(path);
    if (!dir)
    {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(fullpath, sizeof(fullpath), "%s%s%s", path, _tidesdb_get_path_seperator(),
                 entry->d_name);
        if (stat(fullpath, &statbuf) == -1)
        {
            (void)closedir(dir);
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode))
        {
            /* should maybe try to avoid recursion :) */
            if (_tidesdb_remove_directory(fullpath) == -1)
            {
                (void)closedir(dir);
                return -1;
            }
            /* remove the directory */
            (void)rmdir(fullpath);
        }
        else
        {
            if (unlink(fullpath) == -1)
            {
                (void)closedir(dir);
                return -1;
            }
        }
    }

    (void)closedir(dir);
    (void)rmdir(path); /* in case */
    return 0;
}

int _tidesdb_new_column_family(tidesdb_t *tdb, const char *name, int flush_threshold, int max_level,
                               float probability, tidesdb_column_family_t **cf, bool compressed,
                               tidesdb_compression_algo_t compress_algo, bool bloom_filter)
{
    /* we allocate memory for the column family */
    *cf = malloc(sizeof(tidesdb_column_family_t));

    /* we check if allocation was successful */
    if (*cf == NULL) return -1;

    /* we copy the name */
    (*cf)->config.name = strdup(name);

    /* we check if the name was copied */
    if ((*cf)->config.name == NULL)
    {
        free(*cf);
        return -1;
    }

    /* we set the flush threshold */
    (*cf)->config.flush_threshold = flush_threshold;

    /* we set the compression algorithm */
    (*cf)->config.compress_algo = compress_algo;

    /* we set the max level */
    (*cf)->config.max_level = max_level;

    /* we set the probability */
    (*cf)->config.probability = probability;

    /* set compressed to false */
    (*cf)->config.compressed = compressed;

    /* set bloom filter to false */
    (*cf)->config.bloom_filter = bloom_filter;

    (*cf)->incremental_merging = false;

    (*cf)->tdb = tdb;

    (*cf)->memtable = NULL;

    (*cf)->require_sst_shift = false;

    if (pthread_rwlock_init(&(*cf)->rwlock, NULL) != 0)
    {
        free((*cf)->config.name);
        free(*cf);
        return -1;
    }

    /* we construct the path to the column family */
    char cf_path[MAX_FILE_PATH_LENGTH];

    /* we use snprintf to construct the path */
    (void)snprintf(cf_path, sizeof(cf_path), "%s%s%s", tdb->directory,
                   _tidesdb_get_path_seperator(), name);

    /* we check if the column family path exists */
    if (access(cf_path, F_OK) == -1)
    {
        /* we create the directory */
        if (mkdir(cf_path, 0777) == -1)
        {
            free((*cf)->config.name);
            free(*cf);
            return -1;
        }
    }

    /* we create config file name
     * each column family has a config file
     * this contains a serialized version of the column family struct */
    char config_file_name[MAX_FILE_PATH_LENGTH];

    (void)snprintf(config_file_name, sizeof(config_file_name), "%s%s%s%s%s%s", tdb->directory,
                   _tidesdb_get_path_seperator(), name, _tidesdb_get_path_seperator(), name,
                   TDB_COLUMN_FAMILY_CONFIG_FILE_EXT);

    /* now we serialize the column family struct */
    size_t serialized_size;
    uint8_t *serialized_cf =
        _tidesdb_serialize_column_family_config(&(*cf)->config, &serialized_size);
    if (serialized_cf == NULL)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        return -1;
    }

    /* we open the config file (new file) */
    FILE *config_file = fopen(config_file_name, "wb");
    if (config_file == NULL)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        return -1;
    }

    /* we write the serialized column family struct to the config file */
    if (fwrite(serialized_cf, serialized_size, 1, config_file) != 1)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        (void)fclose(config_file);
        return -1;
    }

    /* sync the file */
    (void)fflush(config_file);

    /* we set the path */
    (*cf)->path = strdup(cf_path);

    /* we check if the path was copied */
    if ((*cf)->path == NULL)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        (void)fclose(config_file);
        return -1;
    }

    /* we init sstables array and len */
    (*cf)->num_sstables = 0;
    (*cf)->sstables = NULL;

    (*cf)->memtable = NULL;
    if (skip_list_new(&(*cf)->memtable, (*cf)->config.max_level, (*cf)->config.probability) == -1)
    {
        (void)log_write(tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "cf memtable")->message);
        free((*cf)->config.name);
        free((*cf)->path);
        free(*cf);
        free(serialized_cf);
        (void)fclose(config_file);
        return -1;
    }

    /* we check if the memtable was created */
    if ((*cf)->memtable == NULL)
    {
        free((*cf)->config.name);
        free((*cf)->path);
        free(*cf);
        free(serialized_cf);
        (void)fclose(config_file);
        return -1;
    }

    /* we free what we must */
    free(serialized_cf);
    (void)fclose(config_file);

    (*cf)->wal = malloc(sizeof(tidesdb_wal_t));
    if ((*cf)->wal == NULL)
    {
        free((*cf)->config.name);
        free((*cf)->path);
        free(*cf);
        return -1;
    }

    /* create wal */
    if (_tidesdb_open_wal(cf_path, &(*cf)->wal, compressed, compress_algo) == -1)
    {
        free((*cf)->config.name);
        free((*cf)->path);
        free(*cf);
        return -1;
    }

    return 0;
}

int _tidesdb_get_column_family(tidesdb_t *tdb, const char *name, tidesdb_column_family_t **cf)
{
    /* we check if tdb or name is NULL */
    if (tdb == NULL || name == NULL) return -1;

    if (tdb->num_column_families == 0)
    {
        return -1;
    }

    /* we iterate over the column families and return the one with the matching name */
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i]->config.name, name) == 0)
        {
            /* match on name we return the column family */
            *cf = tdb->column_families[i];

            return 0;
        }
    }

    return -1; /* no column family with that name */
}

tidesdb_err_t *tidesdb_list_column_families(tidesdb_t *tdb, char **list)
{
    if (tdb == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    }

    /* get read lock for database */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "tidesdb_t");
    }

    size_t total_size = 1; /* +1 for null terminator */
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        total_size += strlen(tdb->column_families[i]->config.name) + 1; /* +1 for newline */
    }

    *list = malloc(total_size);
    if (list == NULL)
    {
        /* failed to allocate memory */
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "list");
    }

    (*list)[0] = '\0'; /* null terminate the string */

    for (int i = 0; i < tdb->num_column_families; i++)
    {
        strcat(*list, tdb->column_families[i]->config.name);
        strcat(*list, "\n");
    }

    /* release the db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        free(*list);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "tidesdb_t");
    }

    return NULL;
}

tidesdb_err_t *tidesdb_put(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                           size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    /* we check if the value is NULL */
    if (value == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_VALUE);

    /* we check if the key and value size exceed available system memory */
    if (key_size + value_size > tdb->available_mem)
        return tidesdb_err_from_code(TIDESDB_ERR_PUT_MEMORY_OVERFLOW);

    /* we check if value is a tombstone, a user cannot put a tombstone value */
    if (value_size == 4)
    {
        uint32_t tombstone_value;
        memcpy(&tombstone_value, value, sizeof(uint32_t));

        if (tombstone_value == TOMBSTONE) return tidesdb_err_from_code(TIDESDB_ERR_PUT_TOMBSTONE);
    }

    return _tidesdb_put(tdb, column_family_name, key, key_size, value, value_size, ttl);
}

tidesdb_err_t *_tidesdb_put(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                            size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* get db read lock for column family */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* get column family */
    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* release db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    /* get column family write lock */
    if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we append to the wal */
    if (_tidesdb_append_to_wal(cf->wal, key, key_size, value, value_size, ttl, TIDESDB_OP_PUT,
                               column_family_name) == -1)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL);
    }

    /* put in memtable */
    if (skip_list_put(cf->memtable, key, key_size, value, value_size, ttl) == -1)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_TO_MEMTABLE);
    }

    /* we check if the memtable has reached the flush threshold */
    if ((int)(cf->memtable)->total_size >= cf->config.flush_threshold)
    {
        if (_tidesdb_flush_memtable(cf) == -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
        }
    }

    /* release column family write lock */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    return NULL;
}

tidesdb_err_t *tidesdb_get(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                           size_t key_size, uint8_t **value, size_t *value_size)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    /* we check if key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* get db read lock to get column family */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* get column family */
    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* release db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    /* get column family read lock */
    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we check if the key exists in the memtable */

    if (skip_list_get(cf->memtable, key, key_size, value, value_size) != -1)
    {
        /* we found the key in the memtable
         * we check if the value is a tombstone */
        if (_tidesdb_is_tombstone(*value, *value_size))
        {
            free(*value);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
        }

        (void)pthread_rwlock_unlock(&cf->rwlock);

        return NULL;
    }

    /* we check if any sstables */
    if (cf->num_sstables == 0)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
    }

    /* now we check sstables from latest to oldest using iteration */
    for (int i = cf->num_sstables - 1; i >= 0; i--)
    {
        /* we get the sstable */
        tidesdb_sstable_t *sst = cf->sstables[i];

        /* we create a block manager cursor */
        block_manager_cursor_t *cursor = NULL;

        /* we initialize the cursor */
        if (block_manager_cursor_init(&cursor, sst->block_manager) == -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* we skip min-max block */
        if (block_manager_cursor_next(cursor) == -1)
        {
            (void)block_manager_cursor_free(cursor);
            continue;
        }

        /* if the column family has bloom filters enabled then, well we read
         * the first block which contains the bloom filter and check if the key exists */
        if (cf->config.bloom_filter)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block == NULL)
            {
                (void)block_manager_cursor_free(cursor);
                continue;
            }

            /* we deserialize the bloom filter */
            bloom_filter_t *bf = bloom_filter_deserialize(block->data);
            if (bf == NULL)
            {
                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                continue;
            }

            /* we check if the key exists in the bloom filter */
            if (!bloom_filter_contains(bf, key, key_size))
            {
                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                (void)bloom_filter_free(bf);
                /* we go onto the next sstable */
                continue;
            }

            (void)bloom_filter_free(bf);
            (void)block_manager_block_free(block);

            /* go next block */
            if (block_manager_cursor_next(cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor);
                continue;
            }
        }
        block_manager_block_t *block;

        /* we check if block indices are enabled */
        if (TDB_BLOCK_INDICES == 1)
        {
            /* we seek to last block */
            if (block_manager_cursor_goto_last(cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor);
                continue;
            }

            /* we deserialize the block into a binary hash array */
            block = block_manager_cursor_read(cursor);
            if (block == NULL)
            {
                (void)block_manager_cursor_free(cursor);
                continue;
            }

            /* we deserialize the binary hash array */
            binary_hash_array_t *bha = binary_hash_array_deserialize(block->data);

            int64_t offset = binary_hash_array_contains(bha, (uint8_t *)key, key_size);
            if (offset == -1)
            {
                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                (void)binary_hash_array_free(bha);
                /* we go onto the next sstable */
                continue;
            }

            if (block_manager_cursor_goto(cursor, offset) == -1)
            {
                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                (void)binary_hash_array_free(bha);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
            }
            /* we free the binary hash array */
            (void)binary_hash_array_free(bha);

            (void)block_manager_block_free(block);
        }

        block = block_manager_cursor_read(cursor);

        do
        {
            if (block == NULL) break;
            /* we deserialize the kv */
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);
            if (kv == NULL)
            {
                (void)block_manager_block_free(block);
                break;
            }

            /* we check if the key matches */
            if (_tidesdb_compare_keys(kv->key, kv->key_size, key, key_size) == 0)
            {
                /* check if value is a tombstone */
                if (_tidesdb_is_tombstone(kv->value, kv->value_size))
                {
                    (void)block_manager_cursor_free(cursor);
                    (void)block_manager_block_free(block);
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
                }

                /* check if the key has expired */
                if (_tidesdb_is_expired(kv->ttl))
                {
                    (void)block_manager_cursor_free(cursor);
                    (void)block_manager_block_free(block);
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
                }

                /* we found the key */
                *value = malloc(kv->value_size);
                if (*value == NULL)
                {
                    (void)block_manager_cursor_free(cursor);
                    (void)block_manager_block_free(block);
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
                }

                /* we copy the value */
                memcpy(*value, kv->value, kv->value_size);

                *value_size = kv->value_size;

                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                (void)_tidesdb_free_key_value_pair(kv);
                (void)pthread_rwlock_unlock(&cf->rwlock);

                return NULL;
            }

            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);

            if (block_manager_cursor_next(cursor) != 0) break;
        } while ((block = block_manager_cursor_read(cursor)) != NULL);

        (void)block_manager_cursor_free(cursor);
    }

    /* unlock column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }
    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
}

int _tidesdb_key_exists(const uint8_t *key, size_t key_size, tidesdb_key_value_pair_t **result,
                        size_t result_size)
{
    for (size_t i = 0; i < result_size; i++)
    {
        if (_tidesdb_compare_keys(key, key_size, result[i]->key, result[i]->key_size) == 0)
            return 1;
    }
    return 0;
}

tidesdb_err_t *tidesdb_range(tidesdb_t *tdb, const char *column_family_name,
                             const uint8_t *start_key, size_t start_key_size,
                             const uint8_t *end_key, size_t end_key_size,
                             tidesdb_key_value_pair_t ***result, size_t *result_size)
{
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);
    if (start_key == NULL || end_key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);
    if (strlen(column_family_name) < 2 ||
        strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* Release database read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");

    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we initialize result array */
    size_t capacity = 10;
    *result = malloc(capacity * sizeof(tidesdb_key_value_pair_t *));
    if (*result == NULL)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
    }
    *result_size = 0;

    /* we first check memtable for keys in range */
    skip_list_cursor_t *sl_cursor = NULL;
    sl_cursor = skip_list_cursor_init(cf->memtable);
    if (sl_cursor != NULL)
    {
        do
        {
            uint8_t *retrieved_key;
            size_t key_size;
            uint8_t *retrieved_value;
            size_t value_size;
            time_t ttl;
            if (skip_list_cursor_get(sl_cursor, &retrieved_key, &key_size, &retrieved_value,
                                     &value_size, &ttl) == -1)
            {
                (void)skip_list_cursor_free(sl_cursor);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                free(*result);
                continue;
            }

            /* check if key is in range and not already in result */
            if (_tidesdb_compare_keys(retrieved_key, key_size, start_key, start_key_size) >= 0 &&
                _tidesdb_compare_keys(retrieved_key, key_size, end_key, end_key_size) <= 0 &&
                !_tidesdb_key_exists(retrieved_key, key_size, *result, *result_size) &&
                !_tidesdb_is_tombstone(retrieved_value, value_size) && !_tidesdb_is_expired(ttl))
            {
                /* check if we need to expand the result array */
                if (*result_size >= capacity)
                {
                    capacity *= 2;
                    tidesdb_key_value_pair_t **new_result =
                        realloc(*result, capacity * sizeof(tidesdb_key_value_pair_t *));
                    if (new_result == NULL)
                    {
                        (void)skip_list_cursor_free(sl_cursor);
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        free(*result);
                        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "result");
                    }
                    *result = new_result;
                }

                /* allocate and copy key-value pair to result */
                (*result)[*result_size] = malloc(sizeof(tidesdb_key_value_pair_t));
                if ((*result)[*result_size] == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    for (size_t i = 0; i < *result_size; i++)
                    {
                        free((*result)[i]->key);
                        free((*result)[i]->value);
                        free((*result)[i]);
                    }
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                (*result)[*result_size]->key = malloc(key_size);
                if ((*result)[*result_size]->key == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    free((*result)[*result_size]);
                    for (size_t i = 0; i < *result_size; i++)
                    {
                        free((*result)[i]->key);
                        free((*result)[i]->value);
                        free((*result)[i]);
                    }
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                (*result)[*result_size]->value = malloc(value_size);
                if ((*result)[*result_size]->value == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    free((*result)[*result_size]->key);
                    free((*result)[*result_size]);
                    for (size_t i = 0; i < *result_size; i++)
                    {
                        free((*result)[i]->key);
                        free((*result)[i]->value);
                        free((*result)[i]);
                    }
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                memcpy((*result)[*result_size]->key, retrieved_key, key_size);
                (*result)[*result_size]->key_size = key_size;
                memcpy((*result)[*result_size]->value, retrieved_value, value_size);
                (*result)[*result_size]->value_size = value_size;
                (*result)[*result_size]->ttl = ttl;

                (*result_size)++;
            }

        } while (skip_list_cursor_next(sl_cursor) != -1);

        (void)skip_list_cursor_free(sl_cursor);
    }

    /* check sstables from newest to oldest */
    for (int i = cf->num_sstables - 1; i >= 0; i--)
    {
        tidesdb_sstable_t *sst = cf->sstables[i];
        block_manager_cursor_t *cursor = NULL;

        /* initialize cursor for current sstable */
        if (block_manager_cursor_init(&cursor, sst->block_manager) == -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            for (size_t j = 0; j < *result_size; j++)
            {
                free((*result)[j]->key);
                free((*result)[j]->value);
                free((*result)[j]);
            }
            free(*result);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* read min-max block from sstable */
        block_manager_block_t *min_max_block = block_manager_cursor_read(cursor);
        if (min_max_block == NULL)
        {
            (void)block_manager_cursor_free(cursor);
            continue;
        }

        /* deserialize min-max block */
        tidesdb_sst_min_max_t *min_max = _tidesdb_deserialize_sst_min_max(min_max_block->data);
        if (min_max == NULL)
        {
            (void)block_manager_block_free(min_max_block);
            (void)block_manager_cursor_free(cursor);
            continue;
        }

        bool might_contain = true;

        /* if min key of SSTable > end key, then SSTable doesn't contain keys in range */
        if (_tidesdb_compare_keys(min_max->min_key, min_max->min_key_size, end_key, end_key_size) >
            0)
            might_contain = false;

        /* if max key of SSTable < start key, then SSTable doesn't contain keys in range */
        if (_tidesdb_compare_keys(min_max->max_key, min_max->max_key_size, start_key,
                                  start_key_size) < 0)
            might_contain = false;

        /* free min-max resources */
        (void)_tidesdb_free_sst_min_max(min_max);
        (void)block_manager_block_free(min_max_block);

        /* skip this sstable if it doesn't contain keys in range */
        if (!might_contain)
        {
            (void)block_manager_cursor_free(cursor);
            continue;
        }

        /* skip to next block (after min-max block) */
        if (block_manager_cursor_next(cursor) == -1)
        {
            (void)block_manager_cursor_free(cursor);
            continue;
        }

        /* if bloom filter is enabled, skip it */
        if (cf->config.bloom_filter)
        {
            if (block_manager_cursor_next(cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor);
                continue;
            }
        }

        /* read each key-value pair and check if in range */
        block_manager_block_t *block;

        while ((block = block_manager_cursor_read(cursor)) != NULL)
        {
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);

            if (kv == NULL)
            {
                (void)block_manager_block_free(block);
                break;
            }

            /* check if key is in range, not a tombstone, not expired, and not already in result */
            if (_tidesdb_compare_keys(kv->key, kv->key_size, start_key, start_key_size) >= 0 &&
                _tidesdb_compare_keys(kv->key, kv->key_size, end_key, end_key_size) <= 0 &&
                !_tidesdb_key_exists(kv->key, kv->key_size, *result, *result_size) &&
                !_tidesdb_is_tombstone(kv->value, kv->value_size) && !_tidesdb_is_expired(kv->ttl))
            {
                /* check if we need to expand the result array */
                if (*result_size >= capacity)
                {
                    capacity *= 2;
                    tidesdb_key_value_pair_t **new_result =
                        realloc(*result, capacity * sizeof(tidesdb_key_value_pair_t *));
                    if (new_result == NULL)
                    {
                        (void)block_manager_cursor_free(cursor);
                        (void)block_manager_block_free(block);
                        (void)_tidesdb_free_key_value_pair(kv);
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        for (size_t i = 0; i < *result_size; i++)
                        {
                            free((*result)[i]->key);
                            free((*result)[i]->value);
                            free((*result)[i]);
                        }
                        free(*result);
                        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "result");
                    }
                    *result = new_result;
                }

                /* add kv pair to result */
                (*result)[*result_size] = kv;
                (*result_size)++;
            }
            else
            {
                (void)_tidesdb_free_key_value_pair(kv);
            }

            (void)block_manager_block_free(block);

            if (block_manager_cursor_next(cursor) != 0) break;
        }

        (void)block_manager_cursor_free(cursor);
    }

    /* release column family read lock */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        for (size_t i = 0; i < *result_size; i++)
        {
            free((*result)[i]->key);
            free((*result)[i]->value);
            free((*result)[i]);
        }
        free(*result);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    return NULL;
}

tidesdb_err_t *tidesdb_filter(tidesdb_t *tdb, const char *column_family_name,
                              bool (*comparison_method)(const tidesdb_key_value_pair_t *),
                              tidesdb_key_value_pair_t ***result, size_t *result_size)
{
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);
    if (comparison_method == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COMPARISON_METHOD);

    if (strlen(column_family_name) < 2 ||
        strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");

    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    size_t capacity = 10;
    *result = malloc(capacity * sizeof(tidesdb_key_value_pair_t *));
    if (*result == NULL)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
    }
    *result_size = 0;

    skip_list_cursor_t *sl_cursor = NULL;

    sl_cursor = skip_list_cursor_init(cf->memtable);
    if (sl_cursor != NULL)
    {
        do
        {
            uint8_t *retrieved_key;
            size_t key_size;
            uint8_t *retrieved_value;
            size_t value_size;
            time_t ttl;
            if (skip_list_cursor_get(sl_cursor, &retrieved_key, &key_size, &retrieved_value,
                                     &value_size, &ttl) == -1)
            {
                (void)skip_list_cursor_free(sl_cursor);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                free(*result);
                continue;
            }

            tidesdb_key_value_pair_t kv = {retrieved_key, key_size, retrieved_value, value_size,
                                           ttl};
            if (comparison_method(&kv) &&
                !_tidesdb_key_exists(retrieved_key, key_size, *result, *result_size))
            {
                if (*result_size >= capacity)
                {
                    capacity *= 2;
                    tidesdb_key_value_pair_t **new_result =
                        realloc(*result, capacity * sizeof(tidesdb_key_value_pair_t *));
                    if (new_result == NULL)
                    {
                        (void)skip_list_cursor_free(sl_cursor);
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        free(*result);
                        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "result");
                    }
                    *result = new_result;
                }

                (*result)[*result_size] = malloc(sizeof(tidesdb_key_value_pair_t));
                if ((*result)[*result_size] == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                (*result)[*result_size]->key = malloc(key_size);
                if ((*result)[*result_size]->key == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    free((*result)[*result_size]);
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                (*result)[*result_size]->value = malloc(value_size);
                if ((*result)[*result_size]->value == NULL)
                {
                    (void)skip_list_cursor_free(sl_cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    free((*result)[*result_size]->key);
                    free((*result)[*result_size]);
                    free(*result);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "result");
                }

                memcpy((*result)[*result_size]->key, retrieved_key, key_size);
                (*result)[*result_size]->key_size = key_size;
                memcpy((*result)[*result_size]->value, retrieved_value, value_size);
                (*result)[*result_size]->value_size = value_size;

                (*result_size)++;
            }

        } while (skip_list_cursor_next(sl_cursor) != -1);

        (void)skip_list_cursor_free(sl_cursor);
    }

    for (int i = cf->num_sstables - 1; i >= 0; i--)
    {
        tidesdb_sstable_t *sst = cf->sstables[i];
        block_manager_cursor_t *cursor = NULL;
        if (block_manager_cursor_init(&cursor, sst->block_manager) == -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            free(*result);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* we skip min-max block */
        if (block_manager_cursor_next(cursor) == -1)
        {
            (void)block_manager_cursor_free(cursor);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            continue;
        }

        /* check if bloom filter is enabled */
        if (cf->config.bloom_filter)
        {
            (void)block_manager_cursor_next(cursor);
        }

        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (block == NULL)
        {
            (void)block_manager_cursor_free(cursor);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            continue;
        }

        while (block != NULL)
        {
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);
            if (kv == NULL)
            {
                break;
            }

            if (comparison_method(kv) &&
                !_tidesdb_key_exists(kv->key, kv->key_size, *result, *result_size))
            {
                if (*result_size >= capacity)
                {
                    capacity *= 2;
                    tidesdb_key_value_pair_t **new_result =
                        realloc(*result, capacity * sizeof(tidesdb_key_value_pair_t *));
                    if (new_result == NULL)
                    {
                        (void)block_manager_cursor_free(cursor);
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        free(*result);
                        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "result");
                    }
                    *result = new_result;
                }

                (*result)[*result_size] = kv;
                (*result_size)++;
            }
            else
            {
                (void)_tidesdb_free_key_value_pair(kv);
            }

            (void)block_manager_block_free(block);
            if (block_manager_cursor_next(cursor) != 0) break;
            block = block_manager_cursor_read(cursor);
        }
        if (block != NULL) (void)block_manager_block_free(block);

        (void)block_manager_cursor_free(cursor);
    }

    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return NULL;
}

tidesdb_err_t *tidesdb_delete(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                              size_t key_size)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    uint8_t *tombstone = malloc(4);
    if (tombstone == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "tombstone");

    uint32_t tombstone_value = TOMBSTONE;
    memcpy(tombstone, &tombstone_value, sizeof(uint32_t));

    /* we use _tidesdb_put to delete the key */
    tidesdb_err_t *err = _tidesdb_put(tdb, column_family_name, key, key_size, tombstone, 4, -1);
    if (err != NULL)
    {
        free(tombstone);
        return err;
    }

    free(tombstone);

    return NULL;
}

int _tidesdb_is_tombstone(const uint8_t *value, size_t value_size)
{
    return value_size == 4 && *(uint32_t *)value == TOMBSTONE;
}

int _tidesdb_append_to_wal(tidesdb_wal_t *wal, const uint8_t *key, size_t key_size,
                           const uint8_t *value, size_t value_size, time_t ttl,
                           TIDESDB_OP_CODE op_code, const char *cf)
{
    /* we append operation to column families write ahead log */

    /* we create an operation struct */
    tidesdb_operation_t *op = malloc(sizeof(tidesdb_operation_t));
    if (op == NULL) return -1;

    op->cf_name = strdup(cf);
    op->kv = malloc(sizeof(tidesdb_key_value_pair_t));
    if (op->kv == NULL)
    {
        (void)_tidesdb_free_operation(op);
        return -1;
    }

    op->kv->key = malloc(key_size);
    if (op->kv->key == NULL)
    {
        (void)_tidesdb_free_operation(op);
        return -1;
    }

    /* we copy the key */
    memcpy(op->kv->key, key, key_size);

    op->kv->value = malloc(value_size);
    if (op->kv->value == NULL)
    {
        (void)_tidesdb_free_operation(op);
        return -1;
    }

    /* we copy the value */
    memcpy(op->kv->value, value, value_size);

    op->kv->key_size = key_size;

    op->kv->value_size = value_size;

    op->kv->ttl = ttl;

    op->op_code = op_code;

    /* now we serialize the operation */
    size_t serialized_size;
    uint8_t *serialized_op =
        _tidesdb_serialize_operation(op, &serialized_size, wal->compress, wal->compress_algo);
    if (serialized_op == NULL)
    {
        (void)_tidesdb_free_operation(op);
        return -1;
    }

    /* we create a new block with the serialize operation */
    block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_op);
    if (block == NULL)
    {
        (void)_tidesdb_free_operation(op);
        free(serialized_op);
        return -1;
    }

    /* we append to the wal */
    if (block_manager_block_write(wal->block_manager, block, 0) == -1)
    {
        (void)block_manager_block_free(block);
        (void)_tidesdb_free_operation(op);
        free(serialized_op);
        return -1;
    }

    (void)_tidesdb_free_operation(op);
    (void)block_manager_block_free(block);
    free(serialized_op);

    return 0;
}

int _tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    (void)log_write(cf->tdb->log,
                    _tidesdb_get_debug_log_format(TIDESDB_DEBUG_FLUSHING_COLUMN_FAMILY),
                    cf->config.name, cf->memtable->total_size);

    /* we create a new sstable struct */
    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (sst == NULL) return -1;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH];
    (void)snprintf(sstable_path, sizeof(sstable_path), "%s%s%s%d%s", cf->path,
                   _tidesdb_get_path_seperator(), TDB_SSTABLE_PREFIX, cf->num_sstables,
                   TDB_SSTABLE_EXT);

    /* we create a new block manager for the new sstable */
    block_manager_t *sstable_block_manager = NULL;

    if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        free(sst);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_FLUSH,
                                              cf->config.name)
                            ->message);
        return -1;
    }

    /* depending on column family configuration, the second block in the sstable could be a bloom
     * filter so we initiate one */
    bloom_filter_t *bf = NULL;

    /* we allocate a new bloom filter if the column family configuration has bloom filter enabled */
    if (cf->config.bloom_filter)
    {
        int bloom_filter_size = skip_list_count_entries(
            cf->memtable); /* we determine the size of
                            * the bloom filter by counting entries in the memory table */

        /* we create a new bloom filter with the size and default p value */
        if (bloom_filter_new(&bf, TDB_BLOOM_FILTER_P, bloom_filter_size) == -1)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "bloom filter")->message);
            return -1;
        }
    }

    /* we set the block manager */
    sst->block_manager = sstable_block_manager;

    /* we create a new skip list cursor and populate the sstable
     * with serialized key value pairs. Prior to creating serialized key value blocks
     * we create a tidesdb_sst_min_max structure which is the 1st block (block 0 in the sstable
     * file) */
    skip_list_cursor_t *cursor = skip_list_cursor_init(cf->memtable);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR_FOR_FLUSH, cf->config.name)
                ->message);
        return -1;
    }

    /* we get min key from skip list */
    uint8_t *min_key;
    size_t min_key_size;
    if (skip_list_get_min_key(cf->memtable, &min_key, &min_key_size) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        (void)skip_list_cursor_free(cursor);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_MIN_KEY_FOR_FLUSH, cf->config.name)
                ->message);
        return -1;
    }

    /* we get max key from skip list */
    uint8_t *max_key;
    size_t max_key_size;

    if (skip_list_get_max_key(cf->memtable, &max_key, &max_key_size) == -1)
    {
        free(sst);
        free(min_key);
        (void)remove(sstable_path);
        (void)skip_list_cursor_free(cursor);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_MAX_KEY_FOR_FLUSH, cf->config.name)
                ->message);
        return -1;
    }

    /* we will now serialize the sst min max structure and write to the sstable */
    size_t min_max_serialized_size;
    uint8_t *min_max_serialized = _tidesdb_serialize_sst_min_max(
        min_key, min_key_size, max_key, max_key_size, &min_max_serialized_size);

    /* we create a new block */
    block_manager_block_t *min_max_block =
        block_manager_block_create(min_max_serialized_size, min_max_serialized);
    if (min_max_block == NULL)
    {
        free(sst);
        free(min_max_serialized);
        free(min_key);
        free(max_key);
        (void)remove(sstable_path);
        (void)skip_list_cursor_free(cursor);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "min max block")->message);
        return -1;
    }

    free(min_key);
    free(max_key);

    /* we write the block to the sstable */
    if (block_manager_block_write(sst->block_manager, min_max_block, 0) == -1)
    {
        (void)block_manager_block_free(min_max_block);
        free(sst);
        free(min_max_serialized);
        (void)remove(sstable_path);
        (void)skip_list_cursor_free(cursor);
        (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                            "min max", cf->config.name)
                                          ->message);
        return -1;
    }

    (void)block_manager_block_free(min_max_block);
    free(min_max_serialized);

    /* we have a placeholder here for block indices for each key value pair */
    binary_hash_array_t *bha = NULL;

    /* we check if block indices are enabled */
    if (TDB_BLOCK_INDICES == 1)
    {
        /* we get count of key value pairs and use for sbha */
        bha = binary_hash_array_new(skip_list_count_entries(cf->memtable));
        if (bha == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                                "sorted binary hash array")
                                              ->message);
            return -1;
        }
    }

    /* if a bloom filter is enabled for column family
     * we have to run a forward iteration to populate the bloom filter and serialize
     * prior to key value pair blocks */
    if (cf->config.bloom_filter)
    {
        do
        {
            uint8_t *retrieved_key;
            size_t key_size;
            uint8_t *retrieved_value;
            size_t value_size;
            time_t ttl;
            if (skip_list_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value,
                                     &value_size, &ttl) == -1)
            {
                free(retrieved_key);
                free(retrieved_value);
                free(sst);
                (void)remove(sstable_path);
                (void)skip_list_cursor_free(cursor);
                continue;
            }

            /* add to bloom filter */
            (void)bloom_filter_add(bf, retrieved_key, key_size);

        } while (skip_list_cursor_next(cursor) != -1);

        /* we free the cursor, well reset it.. */
        (void)skip_list_cursor_free(cursor);
        cursor = NULL;

        size_t serialized_bf_size;
        uint8_t *serialized_bf = bloom_filter_serialize(bf, &serialized_bf_size);
        if (serialized_bf == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_SERIALIZE,
                                                                "bloom filter", cf->config.name)
                                              ->message);
            return -1;
        }

        /* we free the bloom filter we no longer need it */
        (void)bloom_filter_free(bf);

        /* we write the bloom filter to the sstable */
        block_manager_block_t *bf_block =
            block_manager_block_create(serialized_bf_size, serialized_bf);
        if (bf_block == NULL)
        {
            free(sst);
            free(serialized_bf);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC)->message,
                            "bloom filter block");
            return -1;
        }

        free(serialized_bf);

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, bf_block, 0) == -1)
        {
            (void)block_manager_block_free(bf_block);
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                                "bloom filter", cf->config.name)
                                              ->message);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(bf_block);

        /* we reinitialize the cursor to populate the sstable with key value pairs after bloom
         * filter in this process we also populate the sorted binary hash array if block indices are
         * enabled */
        cursor = skip_list_cursor_init(cf->memtable);
        if (cursor == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR_FOR_FLUSH, cf->config.name)
                    ->message);
            return -1;
        }
    }

    /* we iterate over the memtable and write to the sstable block manager in order */
    do
    {
        /* we get the key value pair */
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key value pair")->message);
            return -1;
        }

        /* we get the key */

        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (skip_list_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size,
                                 &ttl) == -1)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            continue;
        }

        /* we copy the key */
        kv->key = malloc(key_size);
        if (kv->key == NULL)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key")->message);
            return -1;
        }
        memcpy(kv->key, retrieved_key, key_size);

        /* we copy the value */
        kv->value = malloc(value_size);
        if (kv->value == NULL)
        {
            free(kv->key);
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value")->message);
            return -1;
        }

        memcpy(kv->value, retrieved_value, value_size);

        /* we set the key size */
        kv->key_size = key_size;
        /* we set the value size */
        kv->value_size = value_size;
        /* we set the ttl */
        kv->ttl = ttl;

        /* we serialize the key value pair */
        size_t serialized_size;
        uint8_t *serialized_kv = _tidesdb_serialize_key_value_pair(
            kv, &serialized_size, cf->config.compressed, cf->config.compress_algo);
        if (serialized_kv == NULL)
        {
            (void)_tidesdb_free_key_value_pair(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_SERIALIZE, "key-value pair",
                                                  cf->config.name)
                                ->message,
                            cf->config.name);
            return -1;
        }

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)_tidesdb_free_key_value_pair(kv);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC)->message,
                            cf->config.name);
            return -1;
        }

        long offset = -1; /* blocks offset in the sstable */

        /* we write the block to the sstable */
        if (((offset = block_manager_block_write(sst->block_manager, block, 0))) && offset == -1)
        {
            (void)block_manager_block_free(block);
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)_tidesdb_free_key_value_pair(kv);
            (void)skip_list_cursor_free(cursor);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK, "key-value",
                                                  cf->config.name)
                                ->message,
                            cf->config.name);
            return -1;
        }

        if (TDB_BLOCK_INDICES == 1)
        {
            /* we add the block index */
            (void)binary_hash_array_add(bha, kv->key, kv->key_size, offset);
        }

        (void)_tidesdb_free_key_value_pair(kv);

        /* we free the resources */
        (void)block_manager_block_free(block);
        free(serialized_kv);

    } while (skip_list_cursor_next(cursor) != -1);

    /* we free the skip list cursor, we are done with it */
    (void)skip_list_cursor_free(cursor);

    /* if block indices enabled we write to end of sstable */
    if (TDB_BLOCK_INDICES == 1)
    {
        /* we serialize the block indices */
        size_t serialized_size;
        uint8_t *serialized_bha = binary_hash_array_serialize(bha, &serialized_size);
        if (serialized_bha == NULL)
        {
            (void)binary_hash_array_free(bha);
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_SERIALIZE,
                                                  "sorted binary hash array", cf->config.name)
                                ->message,
                            cf->config.name);
            return -1;
        }

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_bha);
        if (block == NULL)
        {
            (void)binary_hash_array_free(bha);
            free(sst);
            free(serialized_bha);
            (void)remove(sstable_path);
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "sorted binary hash array block")
                    ->message,
                cf->config.name);
            return -1;
        }

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, block, 0) == -1)
        {
            (void)block_manager_block_free(block);
            (void)binary_hash_array_free(bha);
            free(sst);
            free(serialized_bha);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                  "sorted binary hash array", cf->config.name)
                                ->message,
                            cf->config.name);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(block);
        (void)binary_hash_array_free(bha);
        free(serialized_bha);
    }

    /* we add the sstable to the column family */
    if (cf->sstables == NULL)
    {
        cf->sstables = malloc(sizeof(tidesdb_sstable_t));
        if (cf->sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "sstables")->message);
        }
    }
    else
    {
        tidesdb_sstable_t **temp_sstables =
            realloc(cf->sstables, sizeof(tidesdb_sstable_t) * (cf->num_sstables + 1));
        if (temp_sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "flush temp sstables")->message);
            return -1;
        }

        cf->sstables = temp_sstables;
    }

    /* we increment the number of sstables
     * and set the sstable
     */
    cf->sstables[cf->num_sstables] = sst;
    cf->num_sstables++;

    /* clear memtable */
    if (skip_list_clear(cf->memtable) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CLEAR_MEMTABLE)->message);
        return -1;
    }

    /* truncate the wal */
    if (block_manager_truncate(cf->wal->block_manager) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_TRUNCATE_WAL)->message);
        return -1;
    }
    else
    {
        (void)log_write(cf->tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_WAL_TRUNCATED),
                        cf->config.name, sstable_path);
    }

    (void)log_write(cf->tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_FLUSHED_MEMTABLE),
                    cf->config.name, sstable_path);

    return 0;
}

tidesdb_err_t *tidesdb_compact_sstables(tidesdb_t *tdb, const char *column_family_name,
                                        int max_threads)
{
    /* we check prerequisites */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    if (max_threads < 1) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MAX_THREADS);

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* get db read lock */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* we check if provided max_threads exceeds system available threads */
    if (max_threads > tdb->avail_threads)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock); /* release db read lock */
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MAX_THREADS);
    }

    /* get column family */
    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);

    /* we check if column family has incremental merge started */
    if (cf->incremental_merging)
    {
        /* release db read lock */
        if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        {
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
        }

        return tidesdb_err_from_code(TIDESDB_ERR_INCREMENTAL_MERGE_ALREADY_STARTED,
                                     column_family_name);
    }

    /* release db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    /* acquire the lock for column family */
    if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* check if enough sstables to run a compaction */
    int num_sstables = cf->num_sstables;
    if (num_sstables < 2)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_SSTABLES_FOR_COMPACTION);
    }

    /* give er a sort */
    qsort(cf->sstables, num_sstables, sizeof(tidesdb_sstable_t *), _tidesdb_compare_sstables);

    sem_t sem;
    (void)sem_init(&sem, 0, max_threads); /* initialize the semaphore */

    /* we create a temp lock which is shared between threads for sstable path creation */
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    /* we iterate over the sstables pairing and merging them */
    for (int i = 0; i < num_sstables - 1; i += 2)
    {
        (void)sem_wait(&sem); /* we wait if the maximum number of threads is reached */

        tidesdb_compact_thread_args_t *args = malloc(sizeof(tidesdb_compact_thread_args_t));
        args->cf = cf;
        args->start = i;
        args->end = i + 1;
        args->sem = &sem;
        args->lock = &lock;

        pthread_t thread;
        (void)pthread_create(&thread, NULL, _tidesdb_compact_sstables_thread, args);
        (void)pthread_detach(thread);
    }

    /* wait for all compaction threads to finish */
    for (int i = 0; i < max_threads; i++)
    {
        (void)sem_wait(&sem);
    }

    (void)sem_destroy(&sem); /* destroy the semaphore */

    /* remove the sstables that were compacted
     * the ones that are NULL; one would be null the ith+1 sstable
     */
    int j = 0;
    for (int i = 0; i < num_sstables; i++)
    {
        if (cf->sstables[i] != NULL) cf->sstables[j++] = cf->sstables[i];
    }

    cf->num_sstables = j;

    /* destroy shared lock */
    if (pthread_mutex_destroy(&lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_DESTROY_LOCK, "shared compaction lock");

    /* unlock the column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return NULL;
}

void *_tidesdb_compact_sstables_thread(void *arg)
{
    tidesdb_compact_thread_args_t *args = arg;
    tidesdb_column_family_t *cf = args->cf;
    int start = args->start;
    int end = args->end;

    (void)log_write(cf->tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_COMPACTING_SSTABLES),
                    start, end, cf->config.name);

    tidesdb_sstable_t *merged_sstable = NULL;

    merged_sstable =
        _tidesdb_merge_sstables(cf->sstables[start], cf->sstables[end], cf, args->lock);

    /* check if the merged sstable is NULL */
    if (merged_sstable == NULL)
    {
        free(args);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES, cf->config.name)->message);
        return NULL;
    }

    /* remove old sstable files */
    char sstable_path1[MAX_FILE_PATH_LENGTH];
    char sstable_path2[MAX_FILE_PATH_LENGTH];

    /* get the sstable paths */
    if (snprintf(sstable_path1, MAX_FILE_PATH_LENGTH, "%s",
                 cf->sstables[start]->block_manager->file_path) < 0 ||
        snprintf(sstable_path2, MAX_FILE_PATH_LENGTH, "%s",
                 cf->sstables[end]->block_manager->file_path) < 0)
    {
        free(args);
        return NULL;
    }

    /* free the old sstables */
    (void)_tidesdb_free_sstable(cf->sstables[start]);
    (void)_tidesdb_free_sstable(cf->sstables[end]);

    /* remove the sstable files */
    if (remove(sstable_path1) == -1 || remove(sstable_path2) == -1)
    {
        free(args);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_REMOVE_SSTABLES_ON_COMPACTION,
                                              cf->config.name)
                            ->message);
        return NULL;
    }

    /* close the merged sstable as it has TDB_TEMP_EXT extension */
    char merged_sstable_path[MAX_FILE_PATH_LENGTH];
    if (snprintf(merged_sstable_path, MAX_FILE_PATH_LENGTH, "%s",
                 merged_sstable->block_manager->file_path) < 0)
    {
        free(args);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_MERGED_SSTABLE_PATH, cf->config.name)
                ->message);
        return NULL;
    }

    /* close and rename the merged sstable */
    if (block_manager_close(merged_sstable->block_manager) == -1 ||
        rename(merged_sstable_path, sstable_path1) == -1)
    {
        free(args);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CLOSE_RENAME_MERGED_SSTABLE,
                                              cf->config.name)
                            ->message);
        return NULL;
    }

    /* reopen the sstable */
    if (block_manager_open(&merged_sstable->block_manager, sstable_path1, TDB_SYNC_INTERVAL) == -1)
    {
        free(args);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGED_SSTABLE,
                                  cf->config.name)
                ->message);
        return NULL;
    }

    /* replace the old sstables with the new one */
    cf->sstables[start] = merged_sstable;
    cf->sstables[end] = NULL;

    (void)sem_post(args->sem); /* signal compaction thread is done */

    (void)log_write(cf->tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_COMPACTED_SSTABLES),
                    start, end, cf->config.name);

    free(args); /* free the args */

    return NULL;
}

tidesdb_sstable_t *_tidesdb_merge_sstables(tidesdb_sstable_t *sst1, tidesdb_sstable_t *sst2,
                                           tidesdb_column_family_t *cf,
                                           pthread_mutex_t *shared_lock)
{
    (void)log_write(cf->tdb->log,
                    _tidesdb_get_debug_log_format(TIDESDB_DEBUG_MERGING_PAIR_SSTABLES),
                    sst1->block_manager->file_path, sst2->block_manager->file_path);
    /* we initialize a new sstable */
    tidesdb_sstable_t *merged_sstable = malloc(sizeof(tidesdb_sstable_t));
    if (merged_sstable == NULL) return NULL;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH * 2];

    /* lock to make sure path is unique */
    if (pthread_mutex_lock(shared_lock) != 0)
    {
        free(merged_sstable);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK_FOR_MERGE, cf->config.name)
                ->message);
        return NULL;
    }

    (void)snprintf(sstable_path, sizeof(sstable_path), "%s%s", sst1->block_manager->file_path,
                   TDB_TEMP_EXT);

    /* unlock the shared lock */
    if (pthread_mutex_unlock(shared_lock) != 0)
    {
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "shared lock")->message);
        free(merged_sstable);
        return NULL;
    }

    /* we open a new block manager for the merged sstable */
    if (block_manager_open(&merged_sstable->block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        free(merged_sstable);
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGE,
                                              cf->config.name)
                            ->message);
        return NULL;
    }

    if (_tidesdb_merge_sort(cf, sst1->block_manager, sst2->block_manager,
                            merged_sstable->block_manager) == -1)
    {
        (void)block_manager_close(merged_sstable->block_manager);
        (void)remove(sstable_path);
        free(merged_sstable);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES, cf->config.name)->message);
        return NULL;
    }

    if (merged_sstable == NULL)
    {
        (void)block_manager_close(merged_sstable->block_manager);
        (void)remove(sstable_path);
        free(merged_sstable);
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES, cf->config.name)->message);
        return NULL;
    }

    (void)log_write(cf->tdb->log, _tidesdb_get_debug_log_format(TIDESDB_DEBUG_MERGED_PAIR_SSTABLES),
                    sst1->block_manager->file_path, sst2->block_manager->file_path,
                    cf->config.name);

    return merged_sstable;
}

int _tidesdb_compare_keys(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                          size_t key2_size)
{
    if (key1 == NULL || key2 == NULL) return 0; /* we check if the keys are NULL */

    size_t min_size = key1_size < key2_size ? key1_size : key2_size; /* we get the min size */

    /* we iterate over the keys */
    for (size_t i = 0; i < min_size; i++)
    {
        if (key1[i] != key2[i]) /* chck if the keys are different */
        {
            return (key1[i] < key2[i]) ? -1 : 1; /* return the comparison */
        }
    }

    if (key1_size != key2_size) /* check if the keys have different sizes */
    {
        return (key1_size < key2_size) ? -1 : 1; /* return the comparison */
    }

    return 0;
}

tidesdb_err_t *tidesdb_txn_begin(tidesdb_t *tdb, tidesdb_txn_t **txn,
                                 const char *column_family_name)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if column family is NULL */
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we check if transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* allocate memory for the transaction */
    *txn = malloc(sizeof(tidesdb_txn_t));
    if (*txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "transaction");

    /* get db read lock */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        free(*txn);
        *txn = NULL;
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* check if column family exists and get it */
    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        free(*txn);
        *txn = NULL;
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* unlock the db */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        free(*txn);
        *txn = NULL;
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    /* initialize the transaction */
    (*txn)->ops = NULL;
    (*txn)->num_ops = 0; /* 0 operations */
    (*txn)->cf = cf;

    /* initialize the transaction lock */
    if (pthread_mutex_init(&(*txn)->lock, NULL) != 0)
    {
        free(*txn);
        *txn = NULL;
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_LOCK, "transaction");
    }

    (*txn)->tdb = tdb;

    return NULL;
}

tidesdb_err_t *tidesdb_txn_put(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size,
                               const uint8_t *value, size_t value_size, time_t ttl)
{
    /* we check if the transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* we check if the value is NULL */
    if (value == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_VALUE);

    /* we check if the key and value exceed the system memory */
    if (key_size + value_size > txn->tdb->available_mem)
        return tidesdb_err_from_code(TIDESDB_ERR_PUT_MEMORY_OVERFLOW);

    /* lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");

    /* reallocate memory for operations */
    tidesdb_txn_op_t *temp_ops = realloc(txn->ops, (txn->num_ops + 1) * sizeof(tidesdb_txn_op_t));
    if (temp_ops == NULL)
    {
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "transaction operations");
    }
    txn->ops = temp_ops;

    txn->ops[txn->num_ops].op = malloc(sizeof(tidesdb_operation_t));
    if (txn->ops[txn->num_ops].op == NULL)
    {
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "operation");
    }

    txn->ops[txn->num_ops].op->op_code = TIDESDB_OP_PUT;
    txn->ops[txn->num_ops].op->cf_name = strdup(txn->cf->config.name);
    if (txn->ops[txn->num_ops].op->cf_name == NULL)
    {
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "column family name");
    }

    /* allocate memory for key-value pair */
    txn->ops[txn->num_ops].op->kv = malloc(sizeof(tidesdb_key_value_pair_t));
    if (txn->ops[txn->num_ops].op->kv == NULL)
    {
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key-value pair");
    }

    txn->ops[txn->num_ops].op->kv->key_size = key_size;
    /* allocate memory for key */
    txn->ops[txn->num_ops].op->kv->key = malloc(key_size);
    if (txn->ops[txn->num_ops].op->kv->key == NULL)
    {
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
    }
    /* copy the key */
    memcpy(txn->ops[txn->num_ops].op->kv->key, key, key_size);

    txn->ops[txn->num_ops].op->kv->value_size = value_size;
    txn->ops[txn->num_ops].op->kv->value = malloc(value_size); /* allocate memory for value */
    if (txn->ops[txn->num_ops].op->kv->value == NULL)
    {
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
    }
    memcpy(txn->ops[txn->num_ops].op->kv->value, value, value_size);

    txn->ops[txn->num_ops].op->kv->ttl = ttl;
    txn->ops[txn->num_ops].committed = false;

    txn->ops[txn->num_ops].rollback_op =
        malloc(sizeof(tidesdb_operation_t)); /* allocate memory for rollback operation */
    if (txn->ops[txn->num_ops].rollback_op == NULL)
    {
        free(txn->ops[txn->num_ops].op->kv->value);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback operation");
    }

    /* a rollback for put is a delete */
    txn->ops[txn->num_ops].rollback_op->op_code = TIDESDB_OP_DELETE;
    txn->ops[txn->num_ops].rollback_op->cf_name = strdup(txn->cf->config.name);
    if (txn->ops[txn->num_ops].rollback_op->cf_name == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->value);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback column family name");
    }

    txn->ops[txn->num_ops].rollback_op->kv =
        malloc(sizeof(tidesdb_key_value_pair_t)); /* allocate memory for rollback key-value pair */
    if (txn->ops[txn->num_ops].rollback_op->kv == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->value);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback key-value pair");
    }

    txn->ops[txn->num_ops].rollback_op->kv->key_size = key_size;
    txn->ops[txn->num_ops].rollback_op->kv->key =
        malloc(key_size); /* allocate memory for rollback key */
    if (txn->ops[txn->num_ops].rollback_op->kv->key == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op->kv);
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->value);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback key");
    }
    memcpy(txn->ops[txn->num_ops].rollback_op->kv->key, key, key_size);
    /* put tombstone value */
    uint8_t *tombstone = malloc(4);
    if (tombstone != NULL)
    {
        uint32_t tombstone_value = TOMBSTONE;
        memcpy(tombstone, &tombstone_value, sizeof(uint32_t));
    }

    /* allocate memory for rollback value */
    txn->ops[txn->num_ops].rollback_op->kv->value_size = 4;

    txn->ops[txn->num_ops].rollback_op->kv->value = tombstone;

    txn->num_ops++;

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    return NULL;
}

tidesdb_err_t *tidesdb_txn_delete(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size)
{
    /* we check if the transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");

    tidesdb_txn_op_t *temp_ops = realloc(txn->ops, (txn->num_ops + 1) * sizeof(tidesdb_txn_op_t));
    if (temp_ops == NULL)
    {
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_REALLOC_FAILED, "transaction operations");
    }
    txn->ops = temp_ops;

    txn->ops[txn->num_ops].op = malloc(sizeof(tidesdb_operation_t));
    if (txn->ops[txn->num_ops].op == NULL)
    {
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "operation");
    }

    txn->ops[txn->num_ops].op->op_code = TIDESDB_OP_DELETE;
    txn->ops[txn->num_ops].op->cf_name = strdup(txn->cf->config.name);
    if (txn->ops[txn->num_ops].op->cf_name == NULL)
    {
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "column family name");
    }

    txn->ops[txn->num_ops].op->kv = malloc(sizeof(tidesdb_key_value_pair_t));
    if (txn->ops[txn->num_ops].op->kv == NULL)
    {
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key-value pair");
    }

    txn->ops[txn->num_ops].op->kv->key_size = key_size;
    txn->ops[txn->num_ops].op->kv->key = malloc(key_size);
    if (txn->ops[txn->num_ops].op->kv->key == NULL)
    {
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
    }
    memcpy(txn->ops[txn->num_ops].op->kv->key, key, key_size);

    /* put tombstone value */
    uint8_t *tombstone = malloc(4);
    if (tombstone != NULL)
    {
        uint32_t tombstone_value = TOMBSTONE;
        memcpy(tombstone, &tombstone_value, sizeof(uint32_t));
    }
    txn->ops[txn->num_ops].op->kv->value_size = 4;
    txn->ops[txn->num_ops].op->kv->value = tombstone;
    txn->ops[txn->num_ops].op->kv->ttl = -1;
    txn->ops[txn->num_ops].committed = false;

    txn->ops[txn->num_ops].rollback_op = malloc(sizeof(tidesdb_operation_t));
    if (txn->ops[txn->num_ops].rollback_op == NULL)
    {
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback operation");
    }

    /* a rollback for delete is a put */
    txn->ops[txn->num_ops].rollback_op->op_code = TIDESDB_OP_PUT;
    txn->ops[txn->num_ops].rollback_op->cf_name = strdup(txn->cf->config.name);
    if (txn->ops[txn->num_ops].rollback_op->cf_name == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback column family name");
    }

    txn->ops[txn->num_ops].rollback_op->kv = malloc(sizeof(tidesdb_key_value_pair_t));
    if (txn->ops[txn->num_ops].rollback_op->kv == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback key-value pair");
    }

    txn->ops[txn->num_ops].rollback_op->kv->key_size = key_size;
    txn->ops[txn->num_ops].rollback_op->kv->key = malloc(key_size);
    if (txn->ops[txn->num_ops].rollback_op->kv->key == NULL)
    {
        free(txn->ops[txn->num_ops].rollback_op->kv);
        free(txn->ops[txn->num_ops].rollback_op);
        free(txn->ops[txn->num_ops].op->kv->key);
        free(txn->ops[txn->num_ops].op->kv);
        free(txn->ops[txn->num_ops].op);
        /* unlock the transaction */
        (void)pthread_mutex_unlock(&txn->lock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "rollback key");
    }
    memcpy(txn->ops[txn->num_ops].rollback_op->kv->key, key, key_size);

    /* we get the value */
    uint8_t *value;
    size_t value_size;
    tidesdb_err_t *err =
        tidesdb_get(txn->tdb, txn->cf->config.name, key, key_size, &value, &value_size);
    if (err == NULL)
    {
        txn->ops[txn->num_ops].rollback_op->kv->value_size = value_size;
        txn->ops[txn->num_ops].rollback_op->kv->value = value;
        txn->ops[txn->num_ops].rollback_op->kv->ttl = -1;
    }
    else
    {
        (void)tidesdb_err_free(err);
        txn->ops[txn->num_ops].rollback_op->kv->value_size = 0;
        txn->ops[txn->num_ops].rollback_op->kv->value = NULL;
        txn->ops[txn->num_ops].rollback_op->kv->ttl = -1;
    }

    txn->num_ops++;

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    return NULL;
}

tidesdb_err_t *tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    /* we check if the db is NULL */
    if (txn->tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* we lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");
    }

    /* we write lock the column family */
    if (pthread_rwlock_wrlock(&txn->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we run the operations */
    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t op = *txn->ops[i].op;
        if (txn->ops[i].committed) continue; /* skip committed operations */

        switch (op.op_code)
        {
            case TIDESDB_OP_PUT:
                /* append to wal */

                if (_tidesdb_append_to_wal(txn->cf->wal, op.kv->key, op.kv->key_size, op.kv->value,
                                           op.kv->value_size, op.kv->ttl, TIDESDB_OP_PUT,
                                           op.cf_name) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                /* escalate fsync */
                if (block_manager_escalate_fsync(txn->cf->wal->block_manager) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                if (skip_list_put(txn->cf->memtable, op.kv->key, op.kv->key_size, op.kv->value,
                                  op.kv->value_size, op.kv->ttl) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                /* mark op committed */
                txn->ops[i].committed = true;
                break;
            case TIDESDB_OP_DELETE:
                if (_tidesdb_append_to_wal(txn->cf->wal, op.kv->key, op.kv->key_size, op.kv->value,
                                           4, op.kv->ttl, TIDESDB_OP_PUT, op.cf_name) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                /* escalate fsync */
                if (block_manager_escalate_fsync(txn->cf->wal->block_manager) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                if (skip_list_put(txn->cf->memtable, op.kv->key, op.kv->key_size, op.kv->value, 4,
                                  0) == -1)
                {
                    /* unlock the column family */
                    (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                    /* unlock the transaction */
                    (void)pthread_mutex_unlock(&txn->lock);

                    /* we rollback the transaction */
                    return tidesdb_txn_rollback(txn);
                }

                /* mark op committed */
                txn->ops[i].committed = true;
                break;
            default:
                break;
        }
    }

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    /* we check if the memtable needs to be flushed */

    if (((int)((skip_list_t *)txn->cf->memtable)->total_size >= txn->cf->config.flush_threshold))
    {
        if (_tidesdb_flush_memtable(txn->cf) == -1)
        {
            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
        }
    }

    /* unlock the column family */
    if (pthread_rwlock_unlock(&txn->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return NULL;
}

tidesdb_err_t *tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    /* we check if the db is NULL */
    if (txn->tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");

    /* lock the column family */
    if (pthread_rwlock_wrlock(&txn->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we iterate over the operations and rollback */
    for (int i = 0; i < txn->num_ops; i++)
    {
        if (txn->ops[i].committed)
        {
            tidesdb_operation_t op = *txn->ops[i].rollback_op;

            /* append to wal */
            if (_tidesdb_append_to_wal(txn->cf->wal, op.kv->key, op.kv->key_size, op.kv->value,
                                       op.kv->value_size, op.kv->ttl, TIDESDB_OP_PUT,
                                       op.cf_name) == -1)
            {
                /* unlock the column family */
                (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                /* unlock the transaction */
                (void)pthread_mutex_unlock(&txn->lock);

                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL);
            }

            if (block_manager_escalate_fsync(txn->cf->wal->block_manager) == -1)
            {
                /* unlock the column family */
                (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                /* unlock the transaction */
                (void)pthread_mutex_unlock(&txn->lock);

                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ESCALATE_FSYNC);
            }

            /* we put back the key-value pair */
            (void)skip_list_put(txn->cf->memtable, op.kv->key, op.kv->key_size, op.kv->value,
                                op.kv->value_size, op.kv->ttl);
            break;
        }
    }

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    /* we check if the memtable needs to be flushed */

    if (((int)((skip_list_t *)txn->cf->memtable)->total_size >= txn->cf->config.flush_threshold))
    {
        if (txn->cf->config.bloom_filter)
        {
            if (_tidesdb_flush_memtable(txn->cf) == -1)
            {
                (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
            }
        }
    }

    /* unlock the column family */
    if (pthread_rwlock_unlock(&txn->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return NULL;
}

tidesdb_err_t *tidesdb_txn_free(tidesdb_txn_t *txn)
{
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");

    for (int i = 0; i < txn->num_ops; i++)
    {
        (void)_tidesdb_free_operation(txn->ops[i].rollback_op);
        (void)_tidesdb_free_operation(txn->ops[i].op);
    }

    free(txn->ops);

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    /* destroy the transaction lock */
    if (pthread_mutex_destroy(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_DESTROY_LOCK, "transaction");

    free(txn);

    txn = NULL;

    return NULL;
}

tidesdb_err_t *tidesdb_cursor_init(tidesdb_t *tdb, const char *column_family_name,
                                   tidesdb_cursor_t **cursor)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    /* we create the column family variable and set it to be null initially */
    tidesdb_column_family_t *cf = NULL;

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we need to get read lock for the db */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");

    /* we get column family */
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* we unlock the db */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");

    /* we allocate memory for the new cursor */
    *cursor = malloc(sizeof(tidesdb_cursor_t));
    if (*cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "cursor");

    /* we setup defaults */
    (*cursor)->tdb = tdb;
    (*cursor)->cf = cf;
    (*cursor)->sstable_cursor = NULL;
    (*cursor)->memtable_cursor = NULL;
    (*cursor)->direction = TIDESDB_CURSOR_FORWARD;

    /* get column family read lock */
    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
    {
        free(*cursor);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    (*cursor)->sstable_index =
        cf->num_sstables - 1; /* we start at the last sstable, the latest sstable */

    (*cursor)->memtable_cursor = skip_list_cursor_init(cf->memtable);
    if ((*cursor)->memtable_cursor == NULL)
    {
        /* unlock column family */
        (void)pthread_rwlock_unlock(&cf->rwlock);
        free(*cursor);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
    }

    /* we get current sstable cursor
     * if there are any sstables
     */
    if (cf->num_sstables > 0)
    {
        /* we initialize the sstable cursor */
        if (block_manager_cursor_init(&(*cursor)->sstable_cursor,
                                      cf->sstables[(*cursor)->sstable_index]->block_manager) == -1)
        {
            /* unlock column family */
            (void)pthread_rwlock_unlock(&cf->rwlock);
            (void)skip_list_cursor_free((*cursor)->memtable_cursor);
            free(*cursor);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* we skip the min-max block only if we have sstables and memtable entries */
        if (skip_list_cursor_has_next((*cursor)->memtable_cursor) != 1 && cf->num_sstables > 0)
        {
            if (block_manager_cursor_next((*cursor)->sstable_cursor) == -1)
            {
                (void)block_manager_cursor_free((*cursor)->sstable_cursor);
                (*cursor)->sstable_cursor = NULL;
            }
        }

        /* if column family has bloom filter set we skip second block */
        if (cf->config.bloom_filter)
        {
            if ((*cursor)->sstable_cursor != NULL)
            {
                if (block_manager_cursor_next((*cursor)->sstable_cursor) != 0)
                {
                    (void)block_manager_cursor_free((*cursor)->sstable_cursor);
                    (*cursor)->sstable_cursor = NULL;
                }
            }
        }
    }

    /* unlock column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        (void)skip_list_cursor_free((*cursor)->memtable_cursor);
        (void)block_manager_cursor_free((*cursor)->sstable_cursor);
        free(*cursor);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    return NULL;
}

tidesdb_err_t *tidesdb_cursor_next(tidesdb_cursor_t *cursor)
{
    tidesdb_err_t *err = NULL;

    /* we check if cursor is NULL */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* we get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we check if cursor is not set to forward, if not we set it to forward */
    if (cursor->direction != TIDESDB_CURSOR_FORWARD) cursor->direction = TIDESDB_CURSOR_FORWARD;

    if (cursor->cf->require_sst_shift)
    {
        cursor->cf->require_sst_shift = false;

        /* we reset the index to the first sstable */
        cursor->sstable_index = cursor->cf->num_sstables - 1;

        /* we must reopen the sstable cursor */
        if (cursor->sstable_cursor != NULL)
        {
            (void)block_manager_cursor_free(cursor->sstable_cursor);
            cursor->sstable_cursor = NULL;
        }

        /* we open new sstable cursor */
        if (block_manager_cursor_init(&cursor->sstable_cursor,
                                      cursor->cf->sstables[cursor->sstable_index]->block_manager) ==
            -1)
        {
            err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* we skip the bloom filter block if configured */
        if (cursor->cf->config.bloom_filter)
        {
            if (cursor->sstable_cursor != NULL)
            {
                if (block_manager_cursor_next(cursor->sstable_cursor) == -1)
                {
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;
                }
            }
        }
    }

    /* we ensure lock gets released in all cases by using a single point of exit */
    do
    {
        /* we check if we need to reset the sstable index */
        if (cursor->sstable_index == -1)
        {
            cursor->sstable_index = cursor->cf->num_sstables - 1;

            /* we reopen the sstable cursor */
            if (cursor->sstable_cursor != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }

            if (cursor->cf->num_sstables > 0)
            {
                /* we open new sstable cursor */
                if (block_manager_cursor_init(
                        &cursor->sstable_cursor,
                        cursor->cf->sstables[cursor->sstable_index]->block_manager) == -1)
                {
                    err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                    break;
                }

                /* we skip the min-max block */
                if (block_manager_cursor_next(cursor->sstable_cursor) == -1)
                {
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;
                }

                if (cursor->cf->config.bloom_filter)
                {
                    if (cursor->sstable_cursor != NULL)
                    {
                        /* skip the bloom filter block if configured */
                        if (block_manager_cursor_next(cursor->sstable_cursor) == -1)
                        {
                            (void)block_manager_cursor_free(cursor->sstable_cursor);
                            cursor->sstable_cursor = NULL;
                        }
                    }
                }
            }
        }

        /* try to advance memtable cursor first */
        if (cursor->memtable_cursor != NULL)
        {
            if (skip_list_cursor_has_next(cursor->memtable_cursor))
            {
                /* we advance the cursor */
                if (skip_list_cursor_next(cursor->memtable_cursor) == 0)
                {
                    /* successfully advanced memtable cursor */
                    break;
                }
            }

            /* end of memtable reached, free the cursor */
            (void)skip_list_cursor_free(cursor->memtable_cursor);
            cursor->memtable_cursor = NULL;
        }

        /* check if there is next block in the sstable */
        if (cursor->sstable_cursor != NULL)
        {
            /* we advance the cursor */
            if (block_manager_cursor_next(cursor->sstable_cursor) == 0)
            {
                /* check if at last block while still holding the lock */
                if (block_manager_cursor_at_last(cursor->sstable_cursor))
                {
                    /* end of SSTable reached, free the cursor */
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;

                    /* continue to try the next SSTable */
                }
                else
                {
                    /* successfully advanced SSTable cursor */
                    break;
                }
            }
            else
            {
                /* failed to advance, free the cursor */
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }
        }

        /* if we reach here, we need to move to the next SSTable */
        while (cursor->sstable_cursor == NULL && cursor->sstable_index > 0)
        {
            cursor->sstable_index--;

            if (block_manager_cursor_init(
                    &cursor->sstable_cursor,
                    cursor->cf->sstables[cursor->sstable_index]->block_manager) == -1)
            {
                err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                break;
            }

            /* we skip the min-max block */
            if (block_manager_cursor_next(cursor->sstable_cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
                continue;
            }

            /* we skip the bloom filter block if configured */
            if (cursor->cf->config.bloom_filter)
            {
                if (block_manager_cursor_next(cursor->sstable_cursor) == -1)
                {
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;
                    continue;
                }
            }

            /* we successfully initialized the next SSTable cursor */
            break;
        }

        /* if we couldn't initialize a cursor and broke out of the loop with an error */
        if (err != NULL) break;

        /* if we've exhausted all SSTables */
        if (cursor->sstable_cursor == NULL)
        {
            cursor->sstable_index = -1;
            /* we will reopen the cursor but leave index at -1, the get method will know to set it
             * to 0 */
            err = tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
        }

    } while (0);

    /* we always release the lock before returning */
    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
    return err;
}

tidesdb_err_t *tidesdb_cursor_prev(tidesdb_cursor_t *cursor)
{
    tidesdb_err_t *err = NULL;

    /* we check if cursor is NULL */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* we get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we check if cursor is not set to reverse, if not we set it to reverse */
    if (cursor->direction != TIDESDB_CURSOR_REVERSE) cursor->direction = TIDESDB_CURSOR_REVERSE;

    if (cursor->cf->require_sst_shift)
    {
        cursor->cf->require_sst_shift = false;
        /* we check if index exceeds number of sstables */

        /* we reset the index to the last sstable */
        cursor->sstable_index = cursor->cf->num_sstables - 1;

        /* we must reopen the sstable cursor */
        if (cursor->sstable_cursor != NULL)
        {
            (void)block_manager_cursor_free(cursor->sstable_cursor);
            cursor->sstable_cursor = NULL;
        }

        /* we open new sstable cursor */
        if (block_manager_cursor_init(&cursor->sstable_cursor,
                                      cursor->cf->sstables[cursor->sstable_index]->block_manager) ==
            -1)
        {
            err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* we go to the last block */
        if (block_manager_cursor_goto_last(cursor->sstable_cursor) == -1)
        {
            (void)block_manager_cursor_free(cursor->sstable_cursor);
            cursor->sstable_cursor = NULL;
        }

        /* we skip sbha block
         * we only skip if TDB_BLOCK_INDICES is set to 1
         */
        if (TDB_BLOCK_INDICES)
        {
            if (cursor->sstable_cursor != NULL &&
                block_manager_cursor_prev(cursor->sstable_cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }
        }
    }

    /* we ensure lock gets released in all cases by using a single point of exit */
    do
    {
        /* we check if we need to reset the sstable index */
        if (cursor->sstable_index == -1)
        {
            /* we start from the oldest SSTable for reverse traversal
             * this would be if a user made it to end of the cursor
             */
            cursor->sstable_index = 0;

            /* we reopen the sstable cursor */
            if (cursor->sstable_cursor != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }

            /* If no valid memtable cursor, try the newest SSTable */
            if (cursor->cf->num_sstables > 0)
            {
                if (cursor->sstable_cursor == NULL)
                {
                    /* we open new sstable cursor for the newest SSTable */
                    if (block_manager_cursor_init(
                            &cursor->sstable_cursor,
                            cursor->cf->sstables[cursor->sstable_index]->block_manager) == -1)
                    {
                        err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                        break;
                    }

                    /* Go to last block (skip metadata at the end) */
                    if (block_manager_cursor_goto_last(cursor->sstable_cursor) == -1)
                    {
                        (void)block_manager_cursor_free(cursor->sstable_cursor);
                        cursor->sstable_cursor = NULL;
                    }

                    /* we skip sorted binary hash array (last block)
                     * if enabled
                     */
                    if (TDB_BLOCK_INDICES)
                    {
                        if (cursor->sstable_cursor != NULL &&
                            block_manager_cursor_prev(cursor->sstable_cursor) == -1)
                        {
                            (void)block_manager_cursor_free(cursor->sstable_cursor);
                            cursor->sstable_cursor = NULL;
                        }
                    }
                }
            }
        }
        else
        {
            /* if we're here, we need to continue iteration from current position */

            /* try to move the current SSTable cursor backward */
            if (cursor->sstable_cursor != NULL)
            {
                if (block_manager_cursor_prev(cursor->sstable_cursor) == 0)
                {
                    /* check if we've reached the metadata blocks at the beginning */
                    if (block_manager_cursor_at_first(cursor->sstable_cursor) ||
                        (cursor->cf->config.bloom_filter &&
                         block_manager_cursor_at_second(cursor->sstable_cursor)))
                    {
                        /* at beginning of SSTable data blocks, free cursor */
                        (void)block_manager_cursor_free(cursor->sstable_cursor);
                        cursor->sstable_cursor = NULL;

                        /* continue to next SSTable */
                    }
                    else
                    {
                        /* successfully moved to previous block in current SSTable */
                        break;
                    }
                }
                else
                {
                    /* failed to move cursor, free it */
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;

                    /* continue to next SSTable */
                }
            }
        }

        /* if we reach here, we need to move to the next SSTable (older one) */
        while (cursor->sstable_cursor == NULL &&
               cursor->sstable_index < cursor->cf->num_sstables - 1)
        {
            cursor->sstable_index++;

            /* initialize cursor for the older SSTable */
            if (block_manager_cursor_init(
                    &cursor->sstable_cursor,
                    cursor->cf->sstables[cursor->sstable_index]->block_manager) == -1)
            {
                err = tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                break;
            }

            /* go to the last data block (skipping metadata at the end) */
            if (block_manager_cursor_goto_last(cursor->sstable_cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
                continue;
            }

            /* skip sorted binary hash array (last metadata block) if enabled */
            if (TDB_BLOCK_INDICES)
            {
                /* skip sorted binary hash array (last metadata block) */
                if (block_manager_cursor_prev(cursor->sstable_cursor) == -1)
                {
                    (void)block_manager_cursor_free(cursor->sstable_cursor);
                    cursor->sstable_cursor = NULL;
                    continue;
                }
            }

            /* successfully positioned at last data block of older SSTable */
            break;
        }

        /* if we still don't have a valid cursor and no error occurred yet */
        if (cursor->sstable_cursor == NULL && err == NULL)
        {
            /* check if we can initialize memtable cursor as a last resort */
            if (cursor->memtable_cursor == NULL && cursor->cf->memtable != NULL)
            {
                cursor->memtable_cursor = skip_list_cursor_init(cursor->cf->memtable);
                if (cursor->memtable_cursor == NULL)
                {
                    err = tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
                    break;
                }

                /* move to the last element in the memtable */
                if (skip_list_cursor_goto_last(cursor->memtable_cursor) == -1)
                {
                    (void)skip_list_cursor_free(cursor->memtable_cursor);
                    cursor->memtable_cursor = NULL;
                    err = tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
                    break;
                }

                return NULL;
            }
            else
            {
                /* get from memtable */
                if (skip_list_cursor_prev(cursor->memtable_cursor) == 0)
                {
                    /* successfully moved to previous element in memtable */
                    break;
                }
            }

            /* we've exhausted all SSTables and memtable */
            cursor->sstable_index = -1;
            err = tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
        }

    } while (0);

    /* we always release the lock before returning */
    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
    return err;
}

tidesdb_err_t *tidesdb_cursor_get(tidesdb_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size)
{
    /* we check if cursor is NULL */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* we validate output pointers */
    if (key == NULL || key_size == NULL || value == NULL || value_size == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_ARGUMENT);

    /* we get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    if (cursor->cf->require_sst_shift)
    {
        if (cursor->direction == TIDESDB_CURSOR_FORWARD)
        {
            /* we call next to shift to the next sstable */
            (void)tidesdb_cursor_next(cursor);

            /* we call get to get the key-value pair */
            if (tidesdb_cursor_get(cursor, key, key_size, value, value_size) == NULL)
            {
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return NULL;
            }

            /* we return invalid cursor */
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);

            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
        } /* else is TIDESDB_CURSOR_REVERSE */

        /* we call prev to shift to the previous sstable */
        (void)tidesdb_cursor_prev(cursor);

        if (tidesdb_cursor_get(cursor, key, key_size, value, value_size) == NULL)
        {
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return NULL;
        }

        /* we return invalid cursor */
        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    /* we try memtable first if it exists */
    if (cursor->memtable_cursor != NULL)
    {
        time_t ttl;
        uint8_t *k, *v;
        size_t k_size, v_size;
        if (skip_list_cursor_get(cursor->memtable_cursor, &k, &k_size, &v, &v_size, &ttl) == 0)
        {
            /* Check if the value is a tombstone or expired */
            if (_tidesdb_is_tombstone(v, v_size) || _tidesdb_is_expired(ttl))
            {
                free(*key);
                free(*value);
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
            }

            /* we allocate and copy the key */
            *key = malloc(k_size);
            if (*key == NULL)
            {
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
            }

            memcpy(*key, k, k_size); /* copy the key */

            /* we allocate and copy the value */
            *value = malloc(v_size);
            if (*value == NULL)
            {
                free(*key);
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
            }

            /* copy the value */
            memcpy(*value, v, v_size);

            /* set the key and value sizes */
            *key_size = k_size;
            *value_size = v_size;

            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return NULL; /* successfully retrieved from memtable */
        }
    }

    /* we try SSTable if memtable didn't have it */
    if (cursor->sstable_cursor != NULL)
    {
        block_manager_block_t *block = block_manager_cursor_read(cursor->sstable_cursor);
        if (block != NULL)
        {
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cursor->cf->config.compressed,
                cursor->cf->config.compress_algo);

            (void)block_manager_block_free(block);

            if (kv != NULL)
            {
                /* we check if the value is a tombstone or expired */
                if (_tidesdb_is_tombstone(kv->value, kv->value_size) ||
                    _tidesdb_is_expired(kv->ttl))
                {
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
                }

                /* we allocate and copy the key */
                *key = malloc(kv->key_size);
                if (*key == NULL)
                {
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
                }
                memcpy(*key, kv->key, kv->key_size);
                *key_size = kv->key_size;

                /* we allocate and copy the value */
                *value = malloc(kv->value_size);
                if (*value == NULL)
                {
                    free(*key);
                    (void)_tidesdb_free_key_value_pair(kv);
                    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
                }
                memcpy(*value, kv->value, kv->value_size);
                *value_size = kv->value_size;

                (void)_tidesdb_free_key_value_pair(kv);
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return NULL; /* successfully retrieved from SSTable */
            }
        }
    }

    /* no data found or position invalid */
    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);

    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
}

tidesdb_err_t *tidesdb_cursor_free(tidesdb_cursor_t *cursor)
{
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /*  we free memtable cursor if it exists */
    if (cursor->memtable_cursor != NULL)
    {
        (void)skip_list_cursor_free(cursor->memtable_cursor);
        cursor->memtable_cursor = NULL;
    }

    /* we free sstable cursor if it exists */
    if (cursor->sstable_cursor != NULL)
    {
        (void)block_manager_cursor_free(cursor->sstable_cursor);
        cursor->sstable_cursor = NULL;
    }

    /* we free the cursor structure */
    free(cursor);
    cursor = NULL;

    return NULL;
}

int _tidesdb_is_expired(int64_t ttl)
{
    if (ttl != -1 && ttl < time(NULL))
    {
        return 1; /* key is expired */
    }

    return 0; /* key either has no ttl or has not expired */
}

compress_type _tidesdb_map_compression_algo(tidesdb_compression_algo_t algo)
{
    switch (algo)
    {
        case TDB_COMPRESS_SNAPPY:
            return COMPRESS_SNAPPY;
        case TDB_COMPRESS_LZ4:
            return COMPRESS_LZ4;
        case TDB_COMPRESS_ZSTD:
            return COMPRESS_ZSTD;
        default:
            return COMPRESS_SNAPPY; /* default to snappy */
    }
}

tidesdb_err_t *tidesdb_start_incremental_merge(tidesdb_t *tdb, const char *column_family_name,
                                               int seconds, int min_sstables)
{
    /* we check if tidesdb is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check column family name */
    if (column_family_name == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if seconds is > 0 */
    if (seconds <= 0) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_INTERVAL);

    /* we check if min_sstables is at least 2 */
    if (min_sstables < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_INCREMENTAL_MERGE_MIN_SST);

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we get db read lock */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* we get column family */
    tidesdb_column_family_t *cf;

    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* we check if column family is already incrementally merging */
    if (cf->incremental_merging)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_INCREMENTAL_MERGE_ALREADY_STARTED,
                                     column_family_name);
    }

    /* we unlock the db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    tidesdb_incremental_merge_thread_args_t *args =
        malloc(sizeof(tidesdb_incremental_merge_thread_args_t));
    if (args == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);

    args->cf = cf;
    args->tdb = tdb;

    pthread_mutex_t *lock = malloc(sizeof(pthread_mutex_t)); /* shared lock for unique file names */
    if (lock == NULL)
    {
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);
    }
    if (pthread_mutex_init(lock, NULL) != 0)
    {
        free(args);
        free(lock);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_LOCK, "shared merge");
    }

    args->lock = lock;

    /* we lock column family for writes temporarily */
    if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
    {
        (void)pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* setup incremental merge on column family */
    cf->incremental_merge_interval = seconds;
    cf->incremental_merge_min_sstables = min_sstables;
    cf->incremental_merging = true;

    /* we unlock the column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        (void)pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    /* we create a new thread */
    if (pthread_create(&cf->incremental_merge_thread, NULL, _tidesdb_incremental_merge_thread,
                       args) != 0)
    {
        (void)pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_THREAD_CREATION_FAILED);
    }

    /* we return success */
    return NULL;
}

void *_tidesdb_incremental_merge_thread(void *arg)
{
    tidesdb_incremental_merge_thread_args_t *args = (tidesdb_incremental_merge_thread_args_t *)arg;
    tidesdb_column_family_t *cf = args->cf;

    (void)log_write(cf->tdb->log,
                    _tidesdb_get_debug_log_format(TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_STARTED),
                    cf->config.name);

    int sst_index = 0; /* what index we are on in the sstables */

    while (cf->incremental_merging)
    {
        sleep(cf->incremental_merge_interval); /* sleep for interval */
        (void)log_write(cf->tdb->log,
                        _tidesdb_get_debug_log_format(TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_AWOKE),
                        cf->config.name);

        /* we lock column family for reads temporarily */
        if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
        {
            continue;
        }

        /* we check if sstables is at minimum */
        if (cf->num_sstables < cf->incremental_merge_min_sstables)
        {
            (void)log_write(cf->tdb->log,
                            _tidesdb_get_debug_log_format(
                                TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_LIMIT_CONTINUE),
                            cf->config.name, cf->incremental_merge_min_sstables);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            continue;
        }

        /* we unlock the column family */
        (void)pthread_rwlock_unlock(&cf->rwlock);

        tidesdb_sstable_t *merged_sstable;
        /* merge SSTables i and j */

        (void)log_write(cf->tdb->log,
                        _tidesdb_get_debug_log_format(TIDESDB_DEBUG_COMPACTING_SSTABLES), sst_index,
                        sst_index + 1, cf->config.name);

        if (cf->sstables[sst_index] == NULL || cf->sstables[sst_index + 1] == NULL)
        {
            continue;
        }

        merged_sstable = _tidesdb_merge_sstables(cf->sstables[sst_index],
                                                 cf->sstables[sst_index + 1], cf, args->lock);

        /* lock column family for writes */
        if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
        {
            continue;
        }

        /* check if SSTables are still valid */
        if (cf->sstables[sst_index] == NULL || cf->sstables[sst_index + 1] == NULL)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            char sstable_path[MAX_FILE_PATH_LENGTH];
            (void)snprintf(sstable_path, MAX_FILE_PATH_LENGTH, "%s",
                           merged_sstable->block_manager->file_path);
            (void)_tidesdb_free_sstable(merged_sstable);
            (void)remove(sstable_path);
            continue;
        }

        /* remove old sstable files */
        char sstable_path1[MAX_FILE_PATH_LENGTH];
        char sstable_path2[MAX_FILE_PATH_LENGTH];

        /* get the sstable paths */
        (void)snprintf(sstable_path1, MAX_FILE_PATH_LENGTH, "%s",
                       cf->sstables[sst_index]->block_manager->file_path);
        (void)snprintf(sstable_path2, MAX_FILE_PATH_LENGTH, "%s",
                       cf->sstables[sst_index + 1]->block_manager->file_path);

        /* free the old sstables */
        (void)_tidesdb_free_sstable(cf->sstables[sst_index]);
        (void)_tidesdb_free_sstable(cf->sstables[sst_index + 1]);

        /* remove the sstable files */
        (void)remove(sstable_path1);
        (void)remove(sstable_path2);

        /* we close the merged sstable as it has TDB_TEMP_EXT extension
         * we must rename it and remove TDB_TEMP_EXT extension */

        char merged_sstable_path[MAX_FILE_PATH_LENGTH];

        (void)snprintf(merged_sstable_path, MAX_FILE_PATH_LENGTH, "%s",
                       merged_sstable->block_manager->file_path);

        /* the merged sstable path is the sst1 path */
        (void)block_manager_close(merged_sstable->block_manager);

        (void)rename(merged_sstable_path, sstable_path1);

        /* now we open the sstable */
        if (block_manager_open(&merged_sstable->block_manager, sstable_path1, TDB_SYNC_INTERVAL) ==
            -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            free(args);
            return NULL;
        }

        /* replace the old sstables with the new one */
        cf->sstables[sst_index] = merged_sstable;
        cf->sstables[sst_index + 1] = NULL;

        /* remove the sstables that were compacted
         * the ones that are NULL; one would be null the ith+1 sstable
         */
        int j = 0;
        for (int i = 0; i < cf->num_sstables; i++)
        {
            if (cf->sstables[i] != NULL) cf->sstables[j++] = cf->sstables[i];
        }

        cf->num_sstables = j;

        cf->require_sst_shift = true; /* for cursor */

        sst_index++;

        /* if the sst_index is at the end of the sstables we reset it */
        if (sst_index == cf->num_sstables - 1) sst_index = 0;

        /* we unlock the column family */
        (void)pthread_rwlock_unlock(&cf->rwlock);

        (void)log_write(cf->tdb->log,
                        _tidesdb_get_debug_log_format(TIDESDB_DEBUG_COMPACTED_SSTABLES), sst_index,
                        sst_index + 1, cf->config.name);
    }

    (void)pthread_mutex_destroy(args->lock);
    free(args->lock);
    free(args);
    return NULL;
}

size_t _tidesdb_get_available_mem()
{
#ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status))
    {
        return status.ullAvailPhys;
    }

    return 0;
#elif defined(__APPLE__)
    mach_port_t host_port = mach_host_self();
    vm_size_t page_size;
    kern_return_t kr;
    kr = host_page_size(host_port, &page_size);
    if (kr != KERN_SUCCESS)
    {
        return 0;
    }
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t host_size = sizeof(vm_statistics64_data_t) / sizeof(integer_t);
    kr = host_statistics64(host_port, HOST_VM_INFO64, (host_info_t)&vm_stat, &host_size);
    if (kr != KERN_SUCCESS)
    {
        return 0;
    }
    return (vm_stat.free_count + vm_stat.inactive_count) * page_size;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0)
    {
        return info.freeram;
    }
    else
    {
        return 0;
    }
#endif
}

int _tidesdb_merge_sort(tidesdb_column_family_t *cf, block_manager_t *bm1, block_manager_t *bm2,
                        block_manager_t *bm_out)
{
    /* we check if the block managers are NULL */
    if (bm1 == NULL || bm2 == NULL || bm_out == NULL)
    {
        (void)log_write(
            cf->tdb->log,
            tidesdb_err_from_code(TIDESDB_ERR_INVALID_BLOCK_MANAGER, "merge sort")->message);
        return -1;
    }

    /* initialize cursors for both input block managers */
    block_manager_cursor_t *cursor1 = NULL;
    block_manager_cursor_t *cursor2 = NULL;
    block_manager_block_t *block1 = NULL;
    block_manager_block_t *block2 = NULL;

    binary_hash_array_t *bha = NULL; /* in case configured */

    /* initialize cursors for both input block managers */
    if (block_manager_cursor_init(&cursor1, bm1) != 0)
    {
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor 1")->message);
        return -1;
    }

    if (block_manager_cursor_init(&cursor2, bm2) != 0)
    {
        (void)log_write(cf->tdb->log,
                        tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor 2")->message);
        (void)block_manager_cursor_free(cursor1);
        return -1;
    }

    if (TDB_BLOCK_INDICES)
    {
        int block_count1 = block_manager_count_blocks(bm1);
        int block_count2 = block_manager_count_blocks(bm2);
        bha = binary_hash_array_new(block_count1 + block_count2);
        if (bha == NULL)
        {
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                                "sorted binary hash array")
                                              ->message);
            (void)block_manager_cursor_free(cursor1);
            (void)block_manager_cursor_free(cursor2);
            return -1;
        }
    }

    /* we read min-max block from each block manager */
    block1 = block_manager_cursor_read(cursor1);
    block2 = block_manager_cursor_read(cursor2);

    /* we deserialize the blocks to get the tidesdb_sst_min_max_t */
    tidesdb_sst_min_max_t *min_max1 = _tidesdb_deserialize_sst_min_max(block1->data);

    tidesdb_sst_min_max_t *min_max2 = _tidesdb_deserialize_sst_min_max(block2->data);

    /* merge the min-max blocks */
    tidesdb_sst_min_max_t *min_max_out = _tidesdb_merge_min_max(min_max1, min_max2);

    /* serialize the min-max block */
    size_t min_max_size;
    uint8_t *min_max_serialized = _tidesdb_serialize_sst_min_max(
        min_max_out->min_key, min_max_out->min_key_size, min_max_out->max_key,
        min_max_out->max_key_size, &min_max_size);

    /* free the min-max blocks */
    (void)_tidesdb_free_sst_min_max(min_max1);
    (void)_tidesdb_free_sst_min_max(min_max2);
    (void)_tidesdb_free_sst_min_max(min_max_out);

    /* create a new block */
    block_manager_block_t *min_max_block =
        block_manager_block_create(min_max_size, min_max_serialized);

    /* write the min-max block to the output block manager */
    if (block_manager_block_write(bm_out, min_max_block, 0) == -1)
    {
        (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                            "min-max", cf->config.name)
                                          ->message);
        (void)block_manager_block_free(min_max_block);
        free(min_max_serialized);
        if (TDB_BLOCK_INDICES)
        {
            (void)binary_hash_array_free(bha);
        }
        (void)block_manager_cursor_free(cursor1);
        (void)block_manager_cursor_free(cursor2);
        return -1;
    }

    /* free the min-max block */
    (void)block_manager_block_free(min_max_block);
    free(min_max_serialized);

    /* free block1 and block2 */
    (void)block_manager_block_free(block1);
    (void)block_manager_block_free(block2);

    (void)block_manager_cursor_next(cursor1);
    (void)block_manager_cursor_next(cursor2);

    if (cf->config.bloom_filter)
    {
        /* skip the bloom blocks */
        (void)block_manager_cursor_next(cursor1);
        (void)block_manager_cursor_next(cursor2);

        /* we populate the merge table with the sstables and bloom filter */
        /* we create a bloom filter for the merged sstable */
        bloom_filter_t *bf;

        /* we block counts from sst1 and sst2 */
        int block_count1 = block_manager_count_blocks(bm1);
        int block_count2 = block_manager_count_blocks(bm2);

        if (bloom_filter_new(&bf, TDB_BLOOM_FILTER_P, block_count1 + block_count2) == -1)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "bloom filter")->message);
            (void)block_manager_cursor_free(cursor1);
            (void)block_manager_cursor_free(cursor2);
            return -1;
        }
        block_manager_block_t *block;
        do
        {
            block = block_manager_cursor_read(cursor1);
            if (block == NULL) break;
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);
            if (kv == NULL)
            {
                (void)block_manager_block_free(block);
                continue;
            }

            if (_tidesdb_is_tombstone(kv->value, kv->value_size))
            {
                (void)block_manager_block_free(block);
                (void)_tidesdb_free_key_value_pair(kv);
                continue;
            }

            if (_tidesdb_is_expired(kv->ttl))
            {
                (void)block_manager_block_free(block);
                (void)_tidesdb_free_key_value_pair(kv);
                continue;
            }

            /* add to bloom filter */
            (void)bloom_filter_add(bf, kv->key, kv->key_size);

            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);

        } while (block_manager_cursor_next(cursor1) != 0);

        block = NULL;

        (void)block_manager_cursor_free(cursor1);
        cursor1 = NULL;

        do
        {
            block = block_manager_cursor_read(cursor2);
            if (block == NULL) break;

            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);
            if (kv == NULL)
            {
                (void)block_manager_block_free(block);
                continue;
            }

            if (_tidesdb_is_tombstone(kv->value, kv->value_size))
            {
                (void)block_manager_block_free(block);
                (void)_tidesdb_free_key_value_pair(kv);
                continue;
            }

            if (_tidesdb_is_expired(kv->ttl))
            {
                (void)block_manager_block_free(block);
                (void)_tidesdb_free_key_value_pair(kv);
                continue;
            }

            (void)bloom_filter_add(bf, kv->key, kv->key_size);

            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);

        } while (block_manager_cursor_next(cursor2) != 0);

        (void)block_manager_cursor_free(cursor2);
        cursor2 = NULL;

        /* now we write the bloom filter to the merged sstable */
        size_t bf_size;
        uint8_t *bf_serialized = bloom_filter_serialize(bf, &bf_size);
        if (bf_serialized == NULL)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "bloom filter")->message);
            (void)bloom_filter_free(bf);
            return -1;
        }

        /* we create a new block */
        block_manager_block_t *bf_block = block_manager_block_create(bf_size, bf_serialized);
        if (bf_block == NULL)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "bloom filter block")->message);
            (void)bloom_filter_free(bf);
            free(bf_serialized);
            return -1;
        }

        /* we write the block to the merged sstable */
        if (block_manager_block_write(bm_out, bf_block, 0) == -1)
        {
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                                "bloom filter", cf->config.name)
                                              ->message);
            (void)block_manager_block_free(bf_block);
            (void)bloom_filter_free(bf);
            free(bf_serialized);
            return -1;
        }

        (void)block_manager_block_free(bf_block);
        free(bf_serialized);
        bloom_filter_free(bf);

        /* reintialize the cursors */
        if (block_manager_cursor_init(&cursor1, bm1) != 0)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor 1")->message);
            return -1;
        }

        if (block_manager_cursor_init(&cursor2, bm2) != 0)
        {
            (void)log_write(
                cf->tdb->log,
                tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor 2")->message);
            (void)block_manager_cursor_free(cursor1);
            return -1;
        }

        /* skip the min-max and bloom blocks */
        (void)block_manager_cursor_next(cursor1);
        (void)block_manager_cursor_next(cursor1);
        (void)block_manager_cursor_next(cursor2);
        (void)block_manager_cursor_next(cursor2);
    }

    /* read the first block from each block manager */
    block1 = block_manager_cursor_read(cursor1);
    block2 = block_manager_cursor_read(cursor2);

    while (block1 != NULL || block2 != NULL)
    {
        if (block1 == NULL)
        {
            /* write remaining blocks from bm2 */
            tidesdb_key_value_pair_t *kv2 = _tidesdb_deserialize_key_value_pair(
                block2->data, block2->size, cf->config.compressed, cf->config.compress_algo);
            if (!_tidesdb_is_tombstone(kv2->value, kv2->value_size) &&
                !_tidesdb_is_expired(kv2->ttl))
            {
                int64_t offset = block_manager_block_write(bm_out, block2, 0);
                if (offset != 0)
                {
                    (void)block_manager_block_free(block2);
                    if (TDB_BLOCK_INDICES)
                    {
                        (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                    }
                    (void)_tidesdb_free_key_value_pair(kv2);
                    break;
                }

                /* free resources as write failed */
                if (TDB_BLOCK_INDICES)
                {
                    (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                }

                /* free the key value pair */
                (void)_tidesdb_free_key_value_pair(kv2);

                /* free the block */
                (void)block_manager_block_free(block2);

                /* read the next block */
                block2 = block_manager_cursor_read(cursor2);

                /* continue to next iteration */
                continue;
            }
            else
            {
                /* free the key value pair */
                (void)_tidesdb_free_key_value_pair(kv2);
            }
            (void)block_manager_block_free(block2);
            block2 = block_manager_cursor_read(cursor2);
        }
        else if (block2 == NULL)
        {
            /* write remaining blocks from bm1 */
            tidesdb_key_value_pair_t *kv1 = _tidesdb_deserialize_key_value_pair(
                block1->data, block1->size, cf->config.compressed, cf->config.compress_algo);
            if (!_tidesdb_is_tombstone(kv1->value, kv1->value_size) &&
                !_tidesdb_is_expired(kv1->ttl))
            {
                int64_t offset = block_manager_block_write(bm_out, block1, 0);
                if (offset != 0)
                {
                    (void)block_manager_block_free(block1);
                    if (TDB_BLOCK_INDICES)
                    {
                        (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
                    }
                    (void)_tidesdb_free_key_value_pair(kv1);
                    break;
                }
                if (TDB_BLOCK_INDICES)
                {
                    (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
                }
            }
            else
            {
                /* free the key value pair */
                (void)_tidesdb_free_key_value_pair(kv1);
            }
            (void)block_manager_block_free(block1);
            block1 = block_manager_cursor_read(cursor1);
        }
        else
        {
            /* deserialize blocks */
            tidesdb_key_value_pair_t *kv1 = _tidesdb_deserialize_key_value_pair(
                block1->data, block1->size, cf->config.compressed, cf->config.compress_algo);
            tidesdb_key_value_pair_t *kv2 = _tidesdb_deserialize_key_value_pair(
                block2->data, block2->size, cf->config.compressed, cf->config.compress_algo);

            if (kv1 == NULL || kv2 == NULL)
            {
                (void)_tidesdb_free_key_value_pair(kv1);
                (void)_tidesdb_free_key_value_pair(kv2);
                (void)block_manager_block_free(block1);
                (void)block_manager_block_free(block2);
                break;
            }

            /* compare and merge blocks */
            if (_tidesdb_compare_keys(kv1->key, kv1->key_size, kv2->key, kv2->key_size) == 0)
            {
                /* always prefer the value from bm2 */
                if (!_tidesdb_is_tombstone(kv2->value, kv2->value_size) &&
                    !_tidesdb_is_expired(kv2->ttl))
                {
                    int64_t offset = block_manager_block_write(bm_out, block2, 0);
                    if (offset != 0)
                    {
                        if (TDB_BLOCK_INDICES)
                        {
                            (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                        }
                        (void)block_manager_block_free(block2);
                        (void)_tidesdb_free_key_value_pair(kv1);
                        (void)_tidesdb_free_key_value_pair(kv2);
                        (void)block_manager_block_free(block1); /* free block1 before breaking */
                        break;
                    }
                    if (TDB_BLOCK_INDICES)
                    {
                        (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                    }
                }
                (void)block_manager_block_free(block2);
                block2 = block_manager_cursor_read(cursor2);
            }
            else if (_tidesdb_compare_keys(kv1->key, kv1->key_size, kv2->key, kv2->key_size) < 0)
            {
                if (!_tidesdb_is_tombstone(block1->data, block1->size) &&
                    !_tidesdb_is_expired(kv1->ttl))
                {
                    int64_t offset = block_manager_block_write(bm_out, block1, 0);
                    if (offset != 0)
                    {
                        if (TDB_BLOCK_INDICES)
                        {
                            (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
                        }
                        (void)block_manager_block_free(block1);
                        (void)_tidesdb_free_key_value_pair(kv1);
                        (void)_tidesdb_free_key_value_pair(kv2);
                        (void)block_manager_block_free(block2); /* free block2 before breaking */
                        break;
                    }
                    if (TDB_BLOCK_INDICES)
                    {
                        (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
                    }
                }
                (void)block_manager_block_free(block1);
                block1 = block_manager_cursor_read(cursor1);
            }
            else
            {
                if (!_tidesdb_is_tombstone(kv2->value, kv2->value_size) &&
                    !_tidesdb_is_expired(kv2->ttl))
                {
                    int64_t offset = block_manager_block_write(bm_out, block2, 0);
                    if (offset != 0)
                    {
                        if (TDB_BLOCK_INDICES)
                        {
                            (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                        }
                        (void)block_manager_block_free(block2);
                        (void)_tidesdb_free_key_value_pair(kv1);
                        (void)_tidesdb_free_key_value_pair(kv2);
                        (void)block_manager_block_free(block1); /* free block1 before breaking */
                        break;
                    }
                    if (TDB_BLOCK_INDICES)
                    {
                        (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                    }
                }
                (void)block_manager_block_free(block2);
                block2 = block_manager_cursor_read(cursor2);
            }

            (void)_tidesdb_free_key_value_pair(kv1);
            (void)_tidesdb_free_key_value_pair(kv2);
        }
    }

    /* write remaining blocks from bm1 */
    while ((block1 = block_manager_cursor_read(cursor1)))
    {
        if (block1 == NULL) break;
        tidesdb_key_value_pair_t *kv1 = _tidesdb_deserialize_key_value_pair(
            block1->data, block1->size, cf->config.compressed, cf->config.compress_algo);
        if (!_tidesdb_is_tombstone(kv1->value, kv1->value_size) && !_tidesdb_is_expired(kv1->ttl))
        {
            int64_t offset = block_manager_block_write(bm_out, block1, 0);
            if (offset != 0)
            {
                if (TDB_BLOCK_INDICES)
                {
                    (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
                }
                (void)block_manager_block_free(block1);
                (void)_tidesdb_free_key_value_pair(kv1);
                break;
            }
            if (TDB_BLOCK_INDICES)
            {
                (void)binary_hash_array_add(bha, kv1->key, kv1->key_size, offset);
            }
        }
        else
        {
            /* free the key value pair */
            (void)_tidesdb_free_key_value_pair(kv1);
        }
        (void)block_manager_block_free(block1);
    }

    /* write remaining blocks from bm2 */
    while ((block2 = block_manager_cursor_read(cursor2)))
    {
        if (block2 == NULL) break;
        tidesdb_key_value_pair_t *kv2 = _tidesdb_deserialize_key_value_pair(
            block2->data, block2->size, cf->config.compressed, cf->config.compress_algo);
        if (kv2 == NULL)
        {
            (void)block_manager_block_free(block2);
            break;
        }
        if (!_tidesdb_is_tombstone(kv2->value, kv2->value_size) && !_tidesdb_is_expired(kv2->ttl))
        {
            int64_t offset = block_manager_block_write(bm_out, block2, 0);
            if (offset != 0)
            {
                if (TDB_BLOCK_INDICES)
                {
                    (void)binary_hash_array_add(bha, kv2->key, kv2->key_size, offset);
                }
                (void)block_manager_block_free(block2);
                (void)_tidesdb_free_key_value_pair(kv2);
                break;
            }
            /* we failed to write the block */
            /* free resources */
            (void)_tidesdb_free_key_value_pair(kv2);

            /* free the block */
            (void)block_manager_block_free(block2);

            /* free the input bm cursors */
            (void)block_manager_cursor_free(cursor1);

            /* free the input bm cursors */
            (void)block_manager_cursor_free(cursor2);

            /* free the binary hash array */
            if (TDB_BLOCK_INDICES)
            {
                (void)binary_hash_array_free(bha);
            }

            /* return error */
            (void)log_write(cf->tdb->log, tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                                "merged block", cf->config.name)
                                              ->message);

            return -1;
        }
        else
        {
            /* free the key value pair */
            (void)_tidesdb_free_key_value_pair(kv2);
        }
        (void)block_manager_block_free(block2);
    }

    /* free input bm cursors */
    (void)block_manager_cursor_free(cursor1);
    (void)block_manager_cursor_free(cursor2);

    if (TDB_BLOCK_INDICES)
    {
        /* write the binary hash array to the output block manager */
        size_t bha_size;
        uint8_t *bha_data = binary_hash_array_serialize(bha, &bha_size);
        if (bha_data == NULL)
        {
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_SERIALIZE,
                                                  "sorted binary hash array", cf->config.name)
                                ->message);
            (void)binary_hash_array_free(bha);
            return -1;
        }

        block_manager_block_t *bha_block = block_manager_block_create(bha_size, bha_data);
        if (bha_block == NULL)
        {
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                  "sorted binary hash array block", cf->config.name)
                                ->message);
            free(bha_data);
            (void)binary_hash_array_free(bha);
            return -1;
        }

        free(bha_data);

        if (block_manager_block_write(bm_out, bha_block, 0) == -1)
        {
            (void)log_write(cf->tdb->log,
                            tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_WRITE_BLOCK,
                                                  "sorted binary hash array", cf->config.name)
                                ->message);
            (void)block_manager_block_free(bha_block);
            (void)binary_hash_array_free(bha);
            return -1;
        }

        (void)block_manager_block_free(bha_block);
        (void)binary_hash_array_free(bha);
    }

    return 0;
}

char *_tidesdb_get_debug_log_format(tidesdb_debug_log_t log_type)
{
    /* we use a switch statement to get the format */
    switch (log_type)
    {
        case TIDESDB_DEBUG_INIT_NEW_DATABASE:
            return "Initialized new TidesDB instance at %s";
        case TIDESDB_DEBUG_BLOCK_INDICES_ENABLED:
            return "Block indices enabled";
        case TIDESDB_DEBUG_REOPEN_DATABASE:
            return "Reopening TidesDB instance at %s";
        case TIDESDB_DEBUG_AVAIL_MEMORY:
            return "Available memory: %zu bytes";
        case TIDESDB_DEBUG_AVAIL_THREADS:
            return "Available threads: %d";
        case TIDESDB_DEBUG_OPENED_SUCCESS:
            return "Opened TidesDB instance at %s";
        case TIDESDB_DEBUG_COLUMN_FAMILY_SETTING_UP:
            return "Setting up column family %s";
        case TIDESDB_DEBUG_OPENED_WAL:
            return "Opened WAL for column family %s";
        case TIDESDB_DEBUG_LOADED_COLUMN_FAMILY_SSTABLES:
            return "Loaded SSTables for column family %s";
        case TIDESDB_DEBUG_REPLAYED_COLUMN_FAMILY_WAL:
            return "Replayed WAL for column family %s";
        case TIDESDB_DEBUG_CLOSING_DATABASE:
            return "Closing TidesDB instance at %s";
        case TIDESDB_DEBUG_NEW_COLUMN_FAMILY:
            return "New column family created %s";
        case TIDESDB_DEBUG_DROP_COLUMN_FAMILY:
            return "Dropped column family %s";
        case TIDESDB_DEBUG_FLUSHING_COLUMN_FAMILY:
            return "Flushing column family %s at size %zu";
        case TIDESDB_DEBUG_WAL_TRUNCATED:
            return "WAL truncated for column family %s";
        case TIDESDB_DEBUG_FLUSHED_MEMTABLE:
            return "Flushed column family %s to sstable %s";
        case TIDESDB_DEBUG_COMPACTING_SSTABLES:
            return "Compacting sstables %d and %d for column family %s";
        case TIDESDB_DEBUG_COMPACTED_SSTABLES:
            return "Compacted sstables %d and %d for column family %s";
        case TIDESDB_DEBUG_MERGING_PAIR_SSTABLES:
            return "Merging sstables %s and %s for column family %s";
        case TIDESDB_DEBUG_MERGED_PAIR_SSTABLES:
            return "Merged sstables %s and %s for column family %s";
        case TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_AWOKE:
            return "Incremental merge thread woke up for column family %s";
        case TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_STARTED:
            return "Started incremental merge thread for column family %s";
        case TIDESDB_DEBUG_INCREMENTAL_MERGE_THREAD_LIMIT_CONTINUE:
            return "Column family %s has less than %d sstables";

        default:
            return "invalid log type";
    }
}

tidesdb_err_t *tidesdb_get_column_family_stat(tidesdb_t *tdb, const char *column_family_name,
                                              tidesdb_column_family_stat_t **stat)
{
    /* we check if db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if column family name is NULL */
    if (column_family_name == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if the column family name is greater than 2 */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if column name length exceeds TDB_MAX_COLUMN_FAMILY_NAME_LEN */
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* we get db read lock */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* we get column family */
    tidesdb_column_family_t *cf;

    /* we get column family */
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock); /* unlock db lock */
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    /* we unlock the db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    /* we get column family read lock */
    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we create a new column family stat */
    *stat = malloc(sizeof(tidesdb_column_family_stat_t));
    if (*stat == NULL)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock); /* unlock column family lock */
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);
    }

    /* we copy the column family config */
    (*stat)->config = cf->config;

    (*stat)->cf_name = strdup(cf->config.name); /* we copy the column family name */

    /* we copy the number of sstables */
    (*stat)->num_sstables = cf->num_sstables;

    /* we copy the number of memtable entries */
    (*stat)->memtable_entries_count = skip_list_count_entries(cf->memtable);

    /* set incremental merge started status */
    (*stat)->incremental_merging = cf->incremental_merging;
    (*stat)->incremental_merge_interval = cf->incremental_merge_interval;
    (*stat)->incremental_merge_min_sstables = cf->incremental_merge_min_sstables;

    /* create sstable stats */

    /* we allocate memory for the sstable stats */
    (*stat)->sstable_stats =
        malloc(sizeof(tidesdb_column_family_sstable_stat_t) * cf->num_sstables);
    if ((*stat)->sstable_stats == NULL)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock); /* unlock column family lock */
        free(*stat);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);
    }

    /* we iterate through the sstables populating the stats */
    for (int i = 0; i < cf->num_sstables; i++)
    {
        tidesdb_column_family_sstable_stat_t *sstat =
            malloc(sizeof(tidesdb_column_family_sstable_stat_t));
        if (sstat == NULL)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock); /* unlock column family lock */
            for (int j = 0; j < i; j++)
            {
                free((*stat)->sstable_stats[j]->sstable_path);
            }
            free((*stat)->sstable_stats);
            free(*stat);
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "sstable stat");
        }

        /* we copy the sstable path */
        sstat->sstable_path = strdup(cf->sstables[i]->block_manager->file_path);
        if (sstat->sstable_path == NULL)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock); /* unlock column family lock */
            for (int j = 0; j < i; j++)
            {
                free((*stat)->sstable_stats[j]->sstable_path);
            }
            free((*stat)->sstable_stats);
            free(*stat);
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);
        }

        /* we get the number of blocks */
        sstat->num_blocks = block_manager_count_blocks(cf->sstables[i]->block_manager);

        /* we check if bloom enabled if so -1 the number of blocks */
        if (cf->config.bloom_filter) sstat->num_blocks--;

        if (block_manager_get_size(cf->sstables[i]->block_manager, &sstat->size) == -1)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock); /* unlock column family lock */
            for (int j = 0; j < i; j++)
            {
                free((*stat)->sstable_stats[j]->sstable_path);
            }
            free((*stat)->sstable_stats);
            free(*stat);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_GET_SSTABLE_SIZE,
                                         sstat->sstable_path, cf->config.name);
        }

        /* we set the sstable stat */
        (*stat)->sstable_stats[i] = sstat;
    }

    /* now we mus release the column family lock */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        for (int i = 0; i < cf->num_sstables; i++)
        {
            free((*stat)->sstable_stats[i]->sstable_path);
        }
        free((*stat)->sstable_stats);
        free(*stat);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    return NULL;
}

tidesdb_err_t *tidesdb_free_column_family_stat(tidesdb_column_family_stat_t *stat)
{
    /* we check if stat is NULL */
    if (stat == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_STAT);

    /* we free the sstable stats */
    for (int i = 0; i < stat->num_sstables; i++)
    {
        free(stat->sstable_stats[i]->sstable_path);
        free(stat->sstable_stats[i]);
    }

    if (stat->cf_name != NULL) free(stat->cf_name);

    /* we free the sstable stats */
    free(stat->sstable_stats);

    /* we free the stat */
    free(stat);

    stat = NULL;

    return NULL;
}

int _tidesdb_get_max_sys_threads()
{
    int max_threads = 0;

#if defined(_WIN32) || defined(_WIN64)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    max_threads = sysInfo.dwNumberOfProcessors;

#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#if defined(__APPLE__) /* macOS specific */
    int mib[2] = {CTL_HW, HW_NCPU};
    size_t len = sizeof(max_threads);
    if (sysctl(mib, 2, &max_threads, &len, NULL, 0) != 0)
    {
        return -1; /* ret -1 on error, tidesdb_open will catch this */
    }
#else                  /* unix-posix specific */
    max_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif

#endif

    return max_threads;
}

tidesdb_sst_min_max_t *_tidesdb_merge_min_max(const tidesdb_sst_min_max_t *a,
                                              const tidesdb_sst_min_max_t *b)
{
    if (a == NULL || b == NULL) return NULL;

    tidesdb_sst_min_max_t *result = malloc(sizeof(tidesdb_sst_min_max_t));
    if (result == NULL) return NULL;

    if (memcmp(a->min_key, b->min_key,
               a->min_key_size < b->min_key_size ? a->min_key_size : b->min_key_size) <= 0)
    {
        result->min_key = malloc(a->min_key_size);
        if (result->min_key == NULL)
        {
            free(result);
            return NULL;
        }
        memcpy(result->min_key, a->min_key, a->min_key_size);
        result->min_key_size = a->min_key_size;
    }
    else
    {
        result->min_key = malloc(b->min_key_size);
        if (result->min_key == NULL)
        {
            free(result);
            return NULL;
        }
        memcpy(result->min_key, b->min_key, b->min_key_size);
        result->min_key_size = b->min_key_size;
    }

    if (memcmp(a->max_key, b->max_key,
               a->max_key_size < b->max_key_size ? a->max_key_size : b->max_key_size) >= 0)
    {
        result->max_key = malloc(a->max_key_size);
        if (result->max_key == NULL)
        {
            free(result->min_key);
            free(result);
            return NULL;
        }
        memcpy(result->max_key, a->max_key, a->max_key_size);
        result->max_key_size = a->max_key_size;
    }
    else
    {
        result->max_key = malloc(b->max_key_size);
        if (result->max_key == NULL)
        {
            free(result->min_key);
            free(result);
            return NULL;
        }
        memcpy(result->max_key, b->max_key, b->max_key_size);
        result->max_key_size = b->max_key_size;
    }

    return result;
}

void _tidesdb_free_sst_min_max(tidesdb_sst_min_max_t *min_max)
{
    if (min_max == NULL) return;

    if (min_max->min_key != NULL)
    {
        free(min_max->min_key);
    }

    if (min_max->max_key != NULL)
    {
        free(min_max->max_key);
    }

    free(min_max);

    min_max = NULL;
}

tidesdb_err_t *tidesdb_txn_get(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size,
                               uint8_t **value, size_t *value_size)
{
    /* we check if transaction is NULL */
    if (txn == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_TXN);

    /* we check if key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* we check if value or value_size pointers are NULL */
    if (value == NULL || value_size == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_ARGUMENT);

    /* we lock the transaction */
    if (pthread_mutex_lock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "transaction");

    /* first, check if the key exists in the transaction's operations */
    for (int i = txn->num_ops - 1; i >= 0; i--)
    {
        /* we search from newest to oldest operations */
        if (_tidesdb_compare_keys(txn->ops[i].op->kv->key, txn->ops[i].op->kv->key_size, key,
                                  key_size) == 0)
        {
            /* we found the key in the transaction */
            if (txn->ops[i].op->op_code == TIDESDB_OP_DELETE)
            {
                /* the key was deleted in this transaction */
                (void)pthread_mutex_unlock(&txn->lock);
                return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
            }

            if (txn->ops[i].op->op_code == TIDESDB_OP_PUT)
            {
                /* the key was put in this transaction */

                if (_tidesdb_is_tombstone(txn->ops[i].op->kv->value,
                                          txn->ops[i].op->kv->value_size))
                {
                    (void)pthread_mutex_unlock(&txn->lock);
                    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
                }

                /* we check for TTL expiration */
                if (_tidesdb_is_expired(txn->ops[i].op->kv->ttl))
                {
                    (void)pthread_mutex_unlock(&txn->lock);
                    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
                }

                /* we allocate memory for value and copy it */
                *value = malloc(txn->ops[i].op->kv->value_size);
                if (*value == NULL)
                {
                    (void)pthread_mutex_unlock(&txn->lock);
                    return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
                }

                memcpy(*value, txn->ops[i].op->kv->value, txn->ops[i].op->kv->value_size);
                *value_size = txn->ops[i].op->kv->value_size;

                (void)pthread_mutex_unlock(&txn->lock);
                return NULL; /* success */
            }
        }
    }

    /* unlock the transaction as we're about to access the database */
    (void)pthread_mutex_unlock(&txn->lock);

    /* if we get here, the key wasn't found in the transaction's operations.
     ** fall back to the database to get the value. */
    return tidesdb_get(txn->tdb, txn->cf->config.name, key, key_size, value, value_size);
}

tidesdb_err_t *tidesdb_delete_by_range(tidesdb_t *tdb, const char *column_family_name,
                                       const uint8_t *start_key, size_t start_key_size,
                                       const uint8_t *end_key, size_t end_key_size)
{
    /* check prereqs */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);
    if (start_key == NULL || end_key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* validate column family name */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;

    tidesdb_err_t *err = tidesdb_range(tdb, column_family_name, start_key, start_key_size, end_key,
                                       end_key_size, &result, &result_size);

    if (err != NULL)
    {
        return err; /* return the error from tidesdb_range */
    }

    /* no matches found - return success */
    if (result_size == 0)
    {
        free(result);
        return NULL;
    }

    /* begin a transaction for atomic deletion */
    tidesdb_txn_t *txn = NULL;
    err = tidesdb_txn_begin(tdb, &txn, column_family_name);
    if (err != NULL)
    {
        /* free the result array and its contents */
        for (size_t i = 0; i < result_size; i++)
        {
            free(result[i]->key);
            free(result[i]->value);
            free(result[i]);
        }
        free(result);
        return err;
    }

    /* delete each key-value pair in the range */
    for (size_t i = 0; i < result_size; i++)
    {
        err = tidesdb_txn_delete(txn, result[i]->key, result[i]->key_size);
        if (err != NULL)
        {
            /* rollback and clean up on error */
            (void)tidesdb_txn_rollback(txn);
            (void)tidesdb_txn_free(txn);

            for (size_t j = 0; j < result_size; j++)
            {
                free(result[j]->key);
                free(result[j]->value);
                free(result[j]);
            }
            free(result);

            return err;
        }
    }

    /* commit the transaction */
    err = tidesdb_txn_commit(txn);
    if (err != NULL)
    {
        /* rollback and clean up on error */
        (void)tidesdb_txn_rollback(txn);
        (void)tidesdb_txn_free(txn);

        for (size_t i = 0; i < result_size; i++)
        {
            free(result[i]->key);
            free(result[i]->value);
            free(result[i]);
        }
        free(result);

        return err;
    }

    (void)tidesdb_txn_free(txn);

    /* free the result array and its contents */
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    return err;
}

tidesdb_err_t *tidesdb_delete_by_filter(tidesdb_t *tdb, const char *column_family_name,
                                        bool (*filter_function)(const tidesdb_key_value_pair_t *))
{
    /* check prereqs*/
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);
    if (filter_function == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COMPARISON_METHOD);

    /* validate column family name */
    if (strlen(column_family_name) < 2)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");

    /* get the matching key-value pairs */
    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;

    tidesdb_err_t *err =
        tidesdb_filter(tdb, column_family_name, filter_function, &result, &result_size);

    if (err != NULL)
    {
        return err; /* return the error from tidesdb_filter */
    }

    /* no matches found - return success */
    if (result_size == 0)
    {
        free(result);
        return NULL;
    }

    /* begin a transaction for atomic deletion */
    tidesdb_txn_t *txn = NULL;
    err = tidesdb_txn_begin(tdb, &txn, column_family_name);
    if (err != NULL)
    {
        /* free the result array and its contents */
        for (size_t i = 0; i < result_size; i++)
        {
            free(result[i]->key);
            free(result[i]->value);
            free(result[i]);
        }
        free(result);
        return err;
    }

    /* delete each matching key-value pair */
    for (size_t i = 0; i < result_size; i++)
    {
        err = tidesdb_txn_delete(txn, result[i]->key, result[i]->key_size);
        if (err != NULL)
        {
            /* rollback and clean up on error */
            (void)tidesdb_txn_rollback(txn);
            (void)tidesdb_txn_free(txn);

            for (size_t j = 0; j < result_size; j++)
            {
                free(result[j]->key);
                free(result[j]->value);
                free(result[j]);
            }
            free(result);

            return err;
        }
    }

    /* commit the transaction */
    err = tidesdb_txn_commit(txn);
    if (err != NULL)
    {
        /* rollback and clean up on error */
        (void)tidesdb_txn_rollback(txn);
        (void)tidesdb_txn_free(txn);

        for (size_t i = 0; i < result_size; i++)
        {
            free(result[i]->key);
            free(result[i]->value);
            free(result[i]);
        }
        free(result);

        return err;
    }

    (void)tidesdb_txn_free(txn);

    /* free the result array and its contents */
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    return err;
}

/** mainly for debugging purposes */
int _tidesdb_print_keys_tree(tidesdb_t *tdb, const char *column_family_name)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return -1;

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return -1;

    /* we validate column family name length */
    if (strlen(column_family_name) < 2) return -1;
    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN) return -1;

    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0) return -1;

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return -1;
    }

    if (pthread_rwlock_unlock(&tdb->rwlock) != 0) return -1;

    if (pthread_rwlock_rdlock(&cf->rwlock) != 0) return -1;

    printf("Key Tree for Column Family: %s\n", column_family_name);
    printf("===========================================\n");

    printf("MemTable:\n");
    skip_list_cursor_t *memtable_cursor = skip_list_cursor_init(cf->memtable);
    if (memtable_cursor != NULL)
    {
        int indent = 2;
        int count = 0;

        do
        {
            uint8_t *key;
            size_t key_size;
            uint8_t *value;
            size_t value_size;
            time_t ttl;

            if (skip_list_cursor_get(memtable_cursor, &key, &key_size, &value, &value_size, &ttl) ==
                -1)
                break;

            if (_tidesdb_is_tombstone(value, value_size) || _tidesdb_is_expired(ttl)) continue;

            /* print the key with indentation */
            printf("%*s%.*s\n", indent, "├── ", (int)key_size, key);
            count++;

        } while (skip_list_cursor_next(memtable_cursor) != -1);

        (void)skip_list_cursor_free(memtable_cursor);

        if (count == 0)
        {
            printf("%*s(empty)\n", indent, "");
        }
    }
    else
    {
        printf("  (failed to create memtable cursor)\n");
    }

    for (int i = cf->num_sstables - 1; i >= 0; i--)
    {
        printf("\nSSTable %d: %s\n", i, cf->sstables[i]->block_manager->file_path);

        block_manager_cursor_t *cursor = NULL;
        if (block_manager_cursor_init(&cursor, cf->sstables[i]->block_manager) == -1)
        {
            printf("  (failed to create SSTable cursor)\n");
            continue;
        }

        /* we skip min-max block */
        if (block_manager_cursor_next(cursor) == -1)
        {
            (void)block_manager_cursor_free(cursor);
            printf("  (empty or failed to read)\n");
            continue;
        }

        /* we skip bloom filter block if configured */
        if (cf->config.bloom_filter)
        {
            if (block_manager_cursor_next(cursor) == -1)
            {
                (void)block_manager_cursor_free(cursor);
                printf("  (empty or failed to read after bloom filter)\n");
                continue;
            }
        }

        int indent = 2;
        int count = 0;

        block_manager_block_t *block;
        while ((block = block_manager_cursor_read(cursor)) != NULL)
        {
            if (TDB_BLOCK_INDICES && block_manager_cursor_at_last(cursor)) break;

            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cf->config.compressed, cf->config.compress_algo);

            if (kv == NULL)
            {
                (void)block_manager_block_free(block);
                continue;
            }

            if (!_tidesdb_is_tombstone(kv->value, kv->value_size) && !_tidesdb_is_expired(kv->ttl))
            {
                printf("%*s%.*s\n", indent, "├── ", (int)kv->key_size, kv->key);
                count++;
            }

            (void)_tidesdb_free_key_value_pair(kv);
            (void)block_manager_block_free(block);

            if (block_manager_cursor_next(cursor) != 0) break;
        }
        (void)block_manager_block_free(block);
        (void)block_manager_cursor_free(cursor);

        if (count == 0)
        {
            printf("%*s(empty or contains only deleted/expired keys)\n", indent, "");
        }
    }

    printf("===========================================\n");

    if (pthread_rwlock_unlock(&cf->rwlock) != 0) return -1;

    return 0;
}

void min_heap_swap(int *heap, int idx1, int idx2)
{
    int temp = heap[idx1];
    heap[idx1] = heap[idx2];
    heap[idx2] = temp;
}

void min_heap_sift_down(tidesdb_merge_cursor_t *cursor, int start, int end)
{
    int root = start;

    while (root * 2 + 1 <= end)
    {
        int child = root * 2 + 1;
        int swap_idx = root;

        /* we compare with left child */
        if (cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
            cursor->current_entries[cursor->min_heap[child]].valid)
        {
            if (_tidesdb_compare_keys(
                    cursor->current_entries[cursor->min_heap[swap_idx]].kv.key,
                    cursor->current_entries[cursor->min_heap[swap_idx]].kv.key_size,
                    cursor->current_entries[cursor->min_heap[child]].kv.key,
                    cursor->current_entries[cursor->min_heap[child]].kv.key_size) > 0)
            {
                swap_idx = child;
            }
        }
        else if (!cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                 cursor->current_entries[cursor->min_heap[child]].valid)
        {
            swap_idx = child;
        }

        /* we compare with right child */
        if (child + 1 <= end)
        {
            if (cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                cursor->current_entries[cursor->min_heap[child + 1]].valid)
            {
                if (_tidesdb_compare_keys(
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key,
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key_size,
                        cursor->current_entries[cursor->min_heap[child + 1]].kv.key,
                        cursor->current_entries[cursor->min_heap[child + 1]].kv.key_size) > 0)
                {
                    swap_idx = child + 1;
                }
            }
            else if (!cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                     cursor->current_entries[cursor->min_heap[child + 1]].valid)
            {
                swap_idx = child + 1;
            }
        }

        if (swap_idx == root)
        {
            /* root is already at the minimum */
            return;
        }

        (void)min_heap_swap(cursor->min_heap, root, swap_idx);
        root = swap_idx;
    }
}

void min_heap_heapify(tidesdb_merge_cursor_t *cursor)
{
    int count = cursor->min_heap_size;
    for (int i = (count - 2) / 2; i >= 0; i--)
    {
        (void)min_heap_sift_down(cursor, i, count - 1);
    }
}

void max_heap_sift_down(tidesdb_merge_cursor_t *cursor, int start, int end)
{
    int root = start;

    while (root * 2 + 1 <= end)
    {
        int child = root * 2 + 1;
        int swap_idx = root;

        /* we compare with left child
         ** in reverse direction larger keys have priority */
        if (child <= end)
        {
            /* if both entries are valid, compare keys */
            if (cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                cursor->current_entries[cursor->min_heap[child]].valid)
            {
                /* for max heap we want larger keys at the root */
                if (_tidesdb_compare_keys(
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key,
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key_size,
                        cursor->current_entries[cursor->min_heap[child]].kv.key,
                        cursor->current_entries[cursor->min_heap[child]].kv.key_size) < 0)
                {
                    swap_idx = child;
                }
            }
            /* only child is valid, do swap */
            else if (!cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                     cursor->current_entries[cursor->min_heap[child]].valid)
            {
                swap_idx = child;
            }
        }

        /* compare with right child */
        if (child + 1 <= end)
        {
            /* both entries are valid - compare keys */
            if (cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                cursor->current_entries[cursor->min_heap[child + 1]].valid)
            {
                /* for max heap, we want larger keys at the root */
                if (_tidesdb_compare_keys(
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key,
                        cursor->current_entries[cursor->min_heap[swap_idx]].kv.key_size,
                        cursor->current_entries[cursor->min_heap[child + 1]].kv.key,
                        cursor->current_entries[cursor->min_heap[child + 1]].kv.key_size) < 0)
                {
                    swap_idx = child + 1;
                }
            }
            /* only right child is valid, do swap */
            else if (!cursor->current_entries[cursor->min_heap[swap_idx]].valid &&
                     cursor->current_entries[cursor->min_heap[child + 1]].valid)
            {
                swap_idx = child + 1;
            }
        }

        if (swap_idx == root)
        {
            /* root is already the maximum */
            return;
        }

        (void)min_heap_swap(cursor->min_heap, root, swap_idx);
        root = swap_idx;
    }
}

void max_heap_heapify(tidesdb_merge_cursor_t *cursor)
{
    int count = cursor->min_heap_size;

    /* we build the max heap from the bottom up */
    for (int i = (count - 2) / 2; i >= 0; i--)
    {
        (void)max_heap_sift_down(cursor, i, count - 1);
    }
}

bool _tidesdb_merge_cursor_has_valid_entries(tidesdb_merge_cursor_t *cursor)
{
    for (int i = 0; i < cursor->min_heap_size; i++)
    {
        if (cursor->current_entries[i].valid)
        {
            return true;
        }
    }
    return false;
}

tidesdb_err_t *_tidesdb_merge_cursor_init_entries(tidesdb_merge_cursor_t *cursor)
{
    if (cursor->initialized)
    {
        return NULL;
    }

    /* we init a memtable entry if available */
    if (cursor->memtable_cursor != NULL)
    {
        uint8_t *key, *value;
        size_t key_size, value_size;
        time_t ttl;

        if (skip_list_cursor_get(cursor->memtable_cursor, &key, &key_size, &value, &value_size,
                                 &ttl) == 0)
        {
            /* alloc memory and copy key/value */
            cursor->current_entries[0].kv.key = malloc(key_size);
            if (cursor->current_entries[0].kv.key == NULL)
            {
                return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key in merge cursor");
            }

            memcpy(cursor->current_entries[0].kv.key, key, key_size);
            cursor->current_entries[0].kv.key_size = key_size;

            cursor->current_entries[0].kv.value = malloc(value_size);
            if (cursor->current_entries[0].kv.value == NULL)
            {
                free(cursor->current_entries[0].kv.key);
                return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value in merge cursor");
            }

            memcpy(cursor->current_entries[0].kv.value, value, value_size);
            cursor->current_entries[0].kv.value_size = value_size;
            cursor->current_entries[0].kv.ttl = ttl;
            cursor->current_entries[0].source_index = 0;
            cursor->current_entries[0].valid = true;

            /* we check if it's a tombstone or expired */
            if (_tidesdb_is_tombstone(value, value_size) || _tidesdb_is_expired(ttl))
            {
                cursor->current_entries[0].valid = false;
            }
        }
        else
        {
            cursor->current_entries[0].valid = false;
        }
    }
    else
    {
        cursor->current_entries[0].valid = false;
    }

    /* we init entries from each sst */
    for (int i = 0; i < cursor->num_sstables; i++)
    {
        if (cursor->sstable_cursors[i] != NULL)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor->sstable_cursors[i]);
            if (block != NULL)
            {
                tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                    block->data, block->size, cursor->cf->config.compressed,
                    cursor->cf->config.compress_algo);

                (void)block_manager_block_free(block);

                if (kv != NULL)
                {
                    /* we need our own copies of the key and value */
                    cursor->current_entries[i + 1].kv.key = malloc(kv->key_size);
                    if (cursor->current_entries[i + 1].kv.key == NULL)
                    {
                        (void)_tidesdb_free_key_value_pair(kv);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                     "key in merge cursor");
                    }

                    memcpy(cursor->current_entries[i + 1].kv.key, kv->key, kv->key_size);
                    cursor->current_entries[i + 1].kv.key_size = kv->key_size;

                    cursor->current_entries[i + 1].kv.value = malloc(kv->value_size);
                    if (cursor->current_entries[i + 1].kv.value == NULL)
                    {
                        free(cursor->current_entries[i + 1].kv.key);
                        (void)_tidesdb_free_key_value_pair(kv);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                     "value in merge cursor");
                    }

                    memcpy(cursor->current_entries[i + 1].kv.value, kv->value, kv->value_size);
                    cursor->current_entries[i + 1].kv.value_size = kv->value_size;
                    cursor->current_entries[i + 1].kv.ttl = kv->ttl;
                    cursor->current_entries[i + 1].source_index = i + 1;
                    cursor->current_entries[i + 1].valid = true;

                    /* we check if it's a tombstone or expired */
                    if (_tidesdb_is_tombstone(kv->value, kv->value_size) ||
                        _tidesdb_is_expired(kv->ttl))
                    {
                        cursor->current_entries[i + 1].valid = false;
                    }

                    (void)_tidesdb_free_key_value_pair(kv);
                }
                else
                {
                    cursor->current_entries[i + 1].valid = false;
                }
            }
            else
            {
                cursor->current_entries[i + 1].valid = false;
            }
        }
        else
        {
            cursor->current_entries[i + 1].valid = false;
        }
    }

    cursor->initialized = true;

    /* we init the min heap for merging */
    for (int i = 0; i < cursor->min_heap_size; i++)
    {
        cursor->min_heap[i] = i;
    }

    /* we build the heap */
    if (cursor->direction == TIDESDB_CURSOR_FORWARD)
    {
        (void)min_heap_heapify(cursor);
    }
    else
    {
        (void)max_heap_heapify(cursor);
    }

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_seek(tidesdb_merge_cursor_t *cursor, const uint8_t *key,
                                         size_t key_size)
{
    if (cursor == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    if (key == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);
    }

    /* we lock the column family for reading */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we reset the cursor */
    for (int i = 0; i < cursor->min_heap_size; i++)
    {
        if (cursor->current_entries[i].valid)
        {
            free(cursor->current_entries[i].kv.key);
            free(cursor->current_entries[i].kv.value);
            cursor->current_entries[i].valid = false;
        }
    }

    /* we clean up up existing cursors */
    if (cursor->memtable_cursor != NULL)
    {
        (void)skip_list_cursor_free(cursor->memtable_cursor);
    }

    for (int i = 0; i < cursor->num_sstables; i++)
    {
        if (cursor->sstable_cursors[i] != NULL)
        {
            (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
        }
    }

    /* we set direction to forward for seeking */
    cursor->direction = TIDESDB_CURSOR_FORWARD;

    /* we init new cursors at the appropriate positions */

    /* for memtable, we need to create a cursor and position it */
    cursor->memtable_cursor = skip_list_cursor_init(cursor->cf->memtable);
    if (cursor->memtable_cursor != NULL)
    {
        /* pos at first element greater than or equal to key */
        skip_list_node_t *x = cursor->cf->memtable->header;

        /* start from the highest level and work down */
        for (int i = cursor->cf->memtable->level - 1; i >= 0; i--)
        {
            while (x->forward[i] &&
                   skip_list_compare_keys(x->forward[i]->key, x->forward[i]->key_size, key,
                                          key_size) < 0)
            {
                x = x->forward[i];
            }
        }

        /* move to the node */
        x = x->forward[0];

        /* if x is NULL, we're at the end, so position at the start */
        if (x == NULL)
        {
            (void)skip_list_cursor_goto_first(cursor->memtable_cursor);
        }
        else
        {
            /* we gotta iterate until we find the node */
            (void)skip_list_cursor_goto_first(cursor->memtable_cursor);

            uint8_t *current_key;
            size_t current_key_size;
            uint8_t *value;
            size_t value_size;
            time_t ttl;

            while (skip_list_cursor_get(cursor->memtable_cursor, &current_key, &current_key_size,
                                        &value, &value_size, &ttl) == 0)
            {
                /* we check if this is the node we want */
                if (_tidesdb_compare_keys(current_key, current_key_size, x->key, x->key_size) == 0)
                {
                    break;
                }

                /** not the right node, try next */
                if (skip_list_cursor_next(cursor->memtable_cursor) != 0)
                {
                    /* we hit the end, reset to start */
                    (void)skip_list_cursor_goto_first(cursor->memtable_cursor);
                    break;
                }
            }
        }
    }

    for (int i = 0; i < cursor->num_sstables; i++)
    {
        if (block_manager_cursor_init(&cursor->sstable_cursors[i],
                                      cursor->cf->sstables[i]->block_manager) == -1)
        {
            cursor->sstable_cursors[i] = NULL;
            continue;
        }

        /* skip min-max block */
        if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
        {
            (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
            cursor->sstable_cursors[i] = NULL;
            continue;
        }

        /* skip bloom filter block if configured */
        if (cursor->cf->config.bloom_filter)
        {
            if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                cursor->sstable_cursors[i] = NULL;
                continue;
            }
        }

        /*** for block indices, we could potentially do a binary search here for sst data blocks
           to find the one containing our key.. for now, linear scan works fine... */

        /* we scan for the first key >= the seek key */
        block_manager_block_t *block;
        while ((block = block_manager_cursor_read(cursor->sstable_cursors[i])) != NULL)
        {
            tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                block->data, block->size, cursor->cf->config.compressed,
                cursor->cf->config.compress_algo);

            (void)block_manager_block_free(block);

            if (kv != NULL)
            {
                int cmp = _tidesdb_compare_keys(kv->key, kv->key_size, key, key_size);

                if (cmp >= 0)
                {
                    /* we found a key >= seek key, we're positioned correctly */
                    (void)_tidesdb_free_key_value_pair(kv);
                    break;
                }

                (void)_tidesdb_free_key_value_pair(kv);
            }

            /* next block */
            if (block_manager_cursor_next(cursor->sstable_cursors[i]) != 0)
            {
                /* if we reached the end, position at the first data block */
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);

                if (block_manager_cursor_init(&cursor->sstable_cursors[i],
                                              cursor->cf->sstables[i]->block_manager) == -1)
                {
                    cursor->sstable_cursors[i] = NULL;
                    break;
                }

                /* skip min-max block */
                if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
                {
                    (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                    cursor->sstable_cursors[i] = NULL;
                    break;
                }

                /* skip bloom filter block if configured */
                if (cursor->cf->config.bloom_filter)
                {
                    if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
                    {
                        (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                        cursor->sstable_cursors[i] = NULL;
                        break;
                    }
                }

                break;
            }
        }
    }

    /* reinit entries */
    cursor->initialized = false;
    tidesdb_err_t *err = _tidesdb_merge_cursor_init_entries(cursor);

    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);

    if (err != NULL)
    {
        return err;
    }

    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
    }

    /* find the closest next key */
    int idx = cursor->min_heap[0];
    while (!cursor->current_entries[idx].valid)
    {
        /* advance thhis current source */
        err = _tidesdb_merge_cursor_advance(cursor, idx);
        if (err != NULL)
        {
            return err;
        }

        /* we check if we're out of valid entries */
        if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
        {
            return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
        }

        /* get the new index */
        idx = cursor->min_heap[0];
    }

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_next(tidesdb_merge_cursor_t *cursor)
{
    if (cursor == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    if (!cursor->initialized)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    /* we set direction for forward traversal */
    if (cursor->direction != TIDESDB_CURSOR_FORWARD)
    {
        cursor->direction = TIDESDB_CURSOR_FORWARD;

        /* reinit entries in the correct direction */
        for (int i = 0; i < cursor->min_heap_size; i++)
        {
            if (cursor->current_entries[i].valid)
            {
                free(cursor->current_entries[i].kv.key);
                free(cursor->current_entries[i].kv.value);
                cursor->current_entries[i].valid = false;
            }
        }

        /* we close all cursors */
        if (cursor->memtable_cursor != NULL)
        {
            (void)skip_list_cursor_free(cursor->memtable_cursor);
            cursor->memtable_cursor = skip_list_cursor_init(cursor->cf->memtable);
        }

        for (int i = 0; i < cursor->num_sstables; i++)
        {
            if (cursor->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);

                if (block_manager_cursor_init(&cursor->sstable_cursors[i],
                                              cursor->cf->sstables[i]->block_manager) == -1)
                {
                    return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                }

                /* we skip min-max block */
                if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
                {
                    return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                }

                /* we skip bloom filter block if configured */
                if (cursor->cf->config.bloom_filter)
                {
                    if (block_manager_cursor_next(cursor->sstable_cursors[i]) == -1)
                    {
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                    }
                }
            }
        }

        /* reinit entries */
        cursor->initialized = false;
        tidesdb_err_t *err = _tidesdb_merge_cursor_init_entries(cursor);
        if (err != NULL)
        {
            return err;
        }
    }

    /* we check if there are any valid entries */
    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
    }

    /* we get the index of the current smallest entry from the min heap */
    int smallest_idx = cursor->min_heap[0];

    /* skip until we find a valid entry if the current smallest isn't valid */
    while (!cursor->current_entries[smallest_idx].valid)
    {
        /* we advance this source */
        tidesdb_err_t *err = _tidesdb_merge_cursor_advance(cursor, smallest_idx);
        if (err != NULL)
        {
            return err;
        }

        /* we check if we're out of valid entries */
        if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
        {
            return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
        }

        /* we get the new smallest index */
        smallest_idx = cursor->min_heap[0];
    }

    /* advance the source that had the smallest key */
    tidesdb_err_t *err = _tidesdb_merge_cursor_advance(cursor, smallest_idx);
    if (err != NULL)
    {
        return err;
    }

    /* we check if we're out of valid entries */
    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
    }

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_prev(tidesdb_merge_cursor_t *cursor)
{
    if (cursor == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    if (!cursor->initialized)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    /* we set direction for reverse traversal */
    if (cursor->direction != TIDESDB_CURSOR_REVERSE)
    {
        cursor->direction = TIDESDB_CURSOR_REVERSE;

        /* we get the column family read lock before we change cursor state */
        if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        {
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
        }

        /* reinit entries in the correct direction */
        for (int i = 0; i < cursor->min_heap_size; i++)
        {
            if (cursor->current_entries[i].valid)
            {
                free(cursor->current_entries[i].kv.key);
                free(cursor->current_entries[i].kv.value);
                cursor->current_entries[i].valid = false;
            }
        }

        /* re reset all cursors to start from the end */
        if (cursor->memtable_cursor != NULL)
        {
            (void)skip_list_cursor_free(cursor->memtable_cursor);
            cursor->memtable_cursor = skip_list_cursor_init(cursor->cf->memtable);

            /* we pos at the last element */
            if (cursor->memtable_cursor != NULL)
            {
                if (skip_list_cursor_goto_last(cursor->memtable_cursor) == -1)
                {
                    (void)skip_list_cursor_free(cursor->memtable_cursor);
                    cursor->memtable_cursor = NULL;
                }
            }
        }

        for (int i = 0; i < cursor->num_sstables; i++)
        {
            if (cursor->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                cursor->sstable_cursors[i] = NULL;
            }

            /* we try to reinitialize cursors for all ssts when switching direction */
            if (block_manager_cursor_init(&cursor->sstable_cursors[i],
                                          cursor->cf->sstables[i]->block_manager) == -1)
            {
                continue;
            }

            /* go to the last block */
            if (block_manager_cursor_goto_last(cursor->sstable_cursors[i]) == -1)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                cursor->sstable_cursors[i] = NULL;
                continue;
            }

            /* we skip binary hash array block if using block indices */
            if (TDB_BLOCK_INDICES)
            {
                /* we check if this is actually the last block and not just metadata */
                block_manager_block_t *block =
                    block_manager_cursor_read(cursor->sstable_cursors[i]);
                if (block != NULL)
                {
                    /* try to deserialize as a key-value pair to identify if it's data or metadata
                     */
                    tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                        block->data, block->size, cursor->cf->config.compressed,
                        cursor->cf->config.compress_algo);

                    (void)block_manager_block_free(block);

                    if (kv == NULL)
                    {
                        /* this is likely a metadata block, go back to the last data block */
                        if (block_manager_cursor_prev(cursor->sstable_cursors[i]) == -1)
                        {
                            (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                            cursor->sstable_cursors[i] = NULL;
                        }
                    }
                    else
                    {
                        /*  was a valid KV block, free the kv */
                        (void)_tidesdb_free_key_value_pair(kv);
                    }
                }
                else
                {
                    /* cannot read the block, free the cursor */
                    (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
                    cursor->sstable_cursors[i] = NULL;
                }
            }
        }

        /* reinit entries */
        cursor->initialized = false;
        tidesdb_err_t *err = _tidesdb_merge_cursor_init_entries(cursor);

        /* release the lock before checking for errors */
        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);

        if (err != NULL)
        {
            return err;
        }

        /* reheapify with max heap ordering */
        for (int i = 0; i < cursor->min_heap_size; i++)
        {
            cursor->min_heap[i] = i;
        }
        (void)max_heap_heapify(cursor);

        /* when we're switching directions, we don't need to advance.. just return the current entry
         * which should be at the end */
        return NULL;
    }

    /* check if there are any valid entries */
    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
    }

    /* we get the index of the current largest entry from the max heap */
    int largest_idx = cursor->min_heap[0];

    /* we skip until we find a valid entry if the current largest isn't valid */
    while (!cursor->current_entries[largest_idx].valid)
    {
        /* adv (prev) this source */
        tidesdb_err_t *err = _tidesdb_merge_cursor_advance(cursor, largest_idx);
        if (err != NULL)
        {
            return err;
        }

        /* we check if we're out of valid entries */
        if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
        {
            return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
        }

        /* we get the new largest index */
        largest_idx = cursor->min_heap[0];
    }

    /* we make a copy of the current key for duplicate checking */
    uint8_t *current_key = NULL;
    size_t current_key_size = 0;

    if (cursor->current_entries[largest_idx].valid)
    {
        current_key_size = cursor->current_entries[largest_idx].kv.key_size;
        current_key = malloc(current_key_size);
        if (current_key == NULL)
        {
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "duplicate key buffer");
        }
        memcpy(current_key, cursor->current_entries[largest_idx].kv.key, current_key_size);
    }

    /* adv (prev) the source that had the largest key */
    tidesdb_err_t *err = _tidesdb_merge_cursor_advance(cursor, largest_idx);
    if (err != NULL)
    {
        if (current_key != NULL)
        {
            free(current_key);
        }
        return err;
    }

    /* we check if we're out of valid entries */
    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        if (current_key != NULL)
        {
            free(current_key);
        }
        return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
    }

    /* after advancing, we need to ensure we don't produce duplicate keys */
    largest_idx = cursor->min_heap[0];

    /* we skip any keys that are the same as the one we just processed */
    if (current_key != NULL)
    {
        while (cursor->current_entries[largest_idx].valid &&
               _tidesdb_compare_keys(cursor->current_entries[largest_idx].kv.key,
                                     cursor->current_entries[largest_idx].kv.key_size, current_key,
                                     current_key_size) == 0)
        {
            /* adv this source */
            err = _tidesdb_merge_cursor_advance(cursor, largest_idx);
            if (err != NULL)
            {
                free(current_key);
                return err;
            }

            /* we check if we're out of valid entries */
            if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
            {
                free(current_key);
                return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
            }

            largest_idx = cursor->min_heap[0];
        }
        free(current_key);
    }

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_get(tidesdb_merge_cursor_t *cursor, uint8_t **key,
                                        size_t *key_size, uint8_t **value, size_t *value_size)
{
    if (cursor == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    if (!cursor->initialized)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    /* we check if there are any valid entries */
    if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
    {
        return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
    }

    /* we get the index of the min/max entry from the heap */
    int idx = cursor->min_heap[0];

    /* we skip any invalid entries */
    while (!cursor->current_entries[idx].valid)
    {
        /* adv this source */
        tidesdb_err_t *err = _tidesdb_merge_cursor_advance(cursor, idx);
        if (err != NULL)
        {
            return err;
        }

        /* we check if we're out of valid entries */
        if (!_tidesdb_merge_cursor_has_valid_entries(cursor))
        {
            return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
        }

        /* get the new index */
        idx = cursor->min_heap[0];
    }

    /* root of the heap is our next entry to return */
    tidesdb_merge_cursor_entry_t *entry = &cursor->current_entries[idx];

    /* alloc memory and copy key/value */
    *key = malloc(entry->kv.key_size);
    if (*key == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key in merge cursor get");
    }

    memcpy(*key, entry->kv.key, entry->kv.key_size);
    *key_size = entry->kv.key_size;

    *value = malloc(entry->kv.value_size);
    if (*value == NULL)
    {
        free(*key);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value in merge cursor get");
    }

    memcpy(*value, entry->kv.value, entry->kv.value_size);
    *value_size = entry->kv.value_size;

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_free(tidesdb_merge_cursor_t *cursor)
{
    if (cursor == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    }

    /* we free all entries */
    if (cursor->current_entries != NULL)
    {
        for (int i = 0; i < cursor->min_heap_size; i++)
        {
            if (cursor->current_entries[i].valid)
            {
                free(cursor->current_entries[i].kv.key);
                free(cursor->current_entries[i].kv.value);
            }
        }

        free(cursor->current_entries);
    }

    /* we free the min heap */
    if (cursor->min_heap != NULL)
    {
        free(cursor->min_heap);
    }

    /* we free all cursors */
    if (cursor->memtable_cursor != NULL)
    {
        (void)skip_list_cursor_free(cursor->memtable_cursor);
    }

    if (cursor->sstable_cursors != NULL)
    {
        for (int i = 0; i < cursor->num_sstables; i++)
        {
            if (cursor->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursors[i]);
            }
        }

        free(cursor->sstable_cursors);
    }

    free(cursor);
    cursor = NULL;

    return NULL;
}

tidesdb_err_t *_tidesdb_merge_cursor_advance(tidesdb_merge_cursor_t *cursor, int source_idx)
{
    /* we get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we free existing key/value in the entry */
    if (cursor->current_entries[source_idx].valid)
    {
        free(cursor->current_entries[source_idx].kv.key);
        free(cursor->current_entries[source_idx].kv.value);
        cursor->current_entries[source_idx].valid = false;
    }

    /* we get the next element
     * from the source */
    if (source_idx == 0)
    {
        /* memtable source */
        if (cursor->memtable_cursor != NULL)
        {
            int result;

            if (cursor->direction == TIDESDB_CURSOR_FORWARD)
            {
                result = skip_list_cursor_next(cursor->memtable_cursor);
            }
            else
            {
                result = skip_list_cursor_prev(cursor->memtable_cursor);
            }

            if (result == 0)
            {
                uint8_t *key, *value;
                size_t key_size, value_size;
                time_t ttl;

                if (skip_list_cursor_get(cursor->memtable_cursor, &key, &key_size, &value,
                                         &value_size, &ttl) == 0)
                {
                    /* we alloc memory and copy key/value */
                    cursor->current_entries[source_idx].kv.key = malloc(key_size);
                    if (cursor->current_entries[source_idx].kv.key == NULL)
                    {
                        cursor->current_entries[source_idx].valid = false;
                        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                     "key in merge cursor");
                    }

                    memcpy(cursor->current_entries[source_idx].kv.key, key, key_size);
                    cursor->current_entries[source_idx].kv.key_size = key_size;

                    cursor->current_entries[source_idx].kv.value = malloc(value_size);
                    if (cursor->current_entries[source_idx].kv.value == NULL)
                    {
                        free(cursor->current_entries[source_idx].kv.key);
                        cursor->current_entries[source_idx].valid = false;
                        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                     "value in merge cursor");
                    }

                    memcpy(cursor->current_entries[source_idx].kv.value, value, value_size);
                    cursor->current_entries[source_idx].kv.value_size = value_size;
                    cursor->current_entries[source_idx].kv.ttl = ttl;
                    cursor->current_entries[source_idx].source_index = source_idx;

                    /* we check if it's a tombstone or expired */
                    if (_tidesdb_is_tombstone(value, value_size) || _tidesdb_is_expired(ttl))
                    {
                        cursor->current_entries[source_idx].valid = false;
                    }
                    else
                    {
                        cursor->current_entries[source_idx].valid = true;
                    }
                }
                else
                {
                    cursor->current_entries[source_idx].valid = false;
                }
            }
            else
            {
                cursor->current_entries[source_idx].valid = false;
            }
        }
        else
        {
            cursor->current_entries[source_idx].valid = false;
        }
    }
    else
    {
        /* sst source */
        int sstable_idx = source_idx - 1;

        if (cursor->sstable_cursors[sstable_idx] != NULL)
        {
            int result;

            if (cursor->direction == TIDESDB_CURSOR_FORWARD)
            {
                result = block_manager_cursor_next(cursor->sstable_cursors[sstable_idx]);
            }
            else
            {
                result = block_manager_cursor_prev(cursor->sstable_cursors[sstable_idx]);
            }

            if (result == 0)
            {
                block_manager_block_t *block =
                    block_manager_cursor_read(cursor->sstable_cursors[sstable_idx]);
                if (block != NULL)
                {
                    /* we check if this is a valid data block,
                     * not a metadata block */
                    tidesdb_key_value_pair_t *kv = _tidesdb_deserialize_key_value_pair(
                        block->data, block->size, cursor->cf->config.compressed,
                        cursor->cf->config.compress_algo);

                    /* we free the block as we've read its data */
                    (void)block_manager_block_free(block);

                    if (kv != NULL)
                    {
                        /* we need our own copies of the key and value */
                        cursor->current_entries[source_idx].kv.key = malloc(kv->key_size);
                        if (cursor->current_entries[source_idx].kv.key == NULL)
                        {
                            (void)_tidesdb_free_key_value_pair(kv);
                            cursor->current_entries[source_idx].valid = false;
                            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                         "key in merge cursor");
                        }

                        memcpy(cursor->current_entries[source_idx].kv.key, kv->key, kv->key_size);
                        cursor->current_entries[source_idx].kv.key_size = kv->key_size;

                        cursor->current_entries[source_idx].kv.value = malloc(kv->value_size);
                        if (cursor->current_entries[source_idx].kv.value == NULL)
                        {
                            free(cursor->current_entries[source_idx].kv.key);
                            (void)_tidesdb_free_key_value_pair(kv);
                            cursor->current_entries[source_idx].valid = false;
                            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC,
                                                         "value in merge cursor");
                        }

                        memcpy(cursor->current_entries[source_idx].kv.value, kv->value,
                               kv->value_size);
                        cursor->current_entries[source_idx].kv.value_size = kv->value_size;
                        cursor->current_entries[source_idx].kv.ttl = kv->ttl;
                        cursor->current_entries[source_idx].source_index = source_idx;

                        /* we check if it's a tombstone or expired */
                        if (_tidesdb_is_tombstone(kv->value, kv->value_size) ||
                            _tidesdb_is_expired(kv->ttl))
                        {
                            cursor->current_entries[source_idx].valid = false;
                        }
                        else
                        {
                            cursor->current_entries[source_idx].valid = true;
                        }

                        (void)_tidesdb_free_key_value_pair(kv);
                    }
                    else
                    {
                        /* cannot deserialize
                         * could be a metadata block or corrupted */
                        cursor->current_entries[source_idx].valid = false;

                        /* we skip this block in reverse direction
                         * it might be a metadata block */
                        if (cursor->direction == TIDESDB_CURSOR_REVERSE)
                        {
                            if (block_manager_cursor_prev(cursor->sstable_cursors[sstable_idx]) ==
                                0)
                            {
                                /* we try the next block
                                 * recursive call with same source_idx */
                                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                                return _tidesdb_merge_cursor_advance(cursor, source_idx);
                            }
                        }
                    }
                }
                else
                {
                    cursor->current_entries[source_idx].valid = false;
                }
            }
            else
            {
                cursor->current_entries[source_idx].valid = false;
            }
        }
        else
        {
            cursor->current_entries[source_idx].valid = false;
        }
    }

    /* we release the column family lock */
    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);

    if (cursor->direction == TIDESDB_CURSOR_FORWARD)
    {
        (void)min_heap_heapify(cursor);
    }
    else
    {
        (void)max_heap_heapify(cursor);
    }

    return NULL;
}

tidesdb_err_t *tidesdb_merge_cursor_init(tidesdb_t *tdb, const char *column_family_name,
                                         tidesdb_merge_cursor_t **cursor)
{
    if (tdb == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    }

    if (column_family_name == NULL)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);
    }

    /* we validate column family name length */
    if (strlen(column_family_name) < 2)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");
    }

    if (strlen(column_family_name) > TDB_MAX_COLUMN_FAMILY_NAME_LEN)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME_LENGTH, "column family");
    }

    /* we get the column family */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);
    }

    (void)pthread_rwlock_unlock(&tdb->rwlock);

    /* we lock the column family for reading */
    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* we alloc memory for the merge cursor */
    *cursor = malloc(sizeof(tidesdb_merge_cursor_t));
    if (*cursor == NULL)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor");
    }

    /* we init the cursor */
    (*cursor)->tdb = tdb;
    (*cursor)->cf = cf;
    (*cursor)->direction = TIDESDB_CURSOR_FORWARD;
    (*cursor)->initialized = false;
    (*cursor)->num_sstables = cf->num_sstables;

    /* we init the memtable cursor */
    (*cursor)->memtable_cursor = skip_list_cursor_init(cf->memtable);

    /* we alloc memory for sstable cursors */
    (*cursor)->sstable_cursors = NULL;
    if (cf->num_sstables > 0)
    {
        (*cursor)->sstable_cursors = malloc(cf->num_sstables * sizeof(block_manager_cursor_t *));
        if ((*cursor)->sstable_cursors == NULL)
        {
            (void)skip_list_cursor_free((*cursor)->memtable_cursor);
            free(*cursor);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "sstable cursors");
        }

        /* calc size for current entries and min heap */
        (*cursor)->min_heap_size = cf->num_sstables + 1; /* +1 for the memtable */

        /* we init each sst cursor */
        for (int i = 0; i < cf->num_sstables; i++)
        {
            if (block_manager_cursor_init(&(*cursor)->sstable_cursors[i],
                                          cf->sstables[i]->block_manager) == -1)
            {
                /* we free previously allocated cursors */
                for (int j = 0; j < i; j++)
                {
                    (void)block_manager_cursor_free((*cursor)->sstable_cursors[j]);
                }

                free((*cursor)->sstable_cursors);
                (void)skip_list_cursor_free((*cursor)->memtable_cursor);
                free(*cursor);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
            }

            /* we skip min-max block */
            if (block_manager_cursor_next((*cursor)->sstable_cursors[i]) == -1)
            {
                /* we free previously allocated cursors */
                for (int j = 0; j < i; j++)
                {
                    (void)block_manager_cursor_free((*cursor)->sstable_cursors[j]);
                }

                free((*cursor)->sstable_cursors);
                (void)skip_list_cursor_free((*cursor)->memtable_cursor);
                free(*cursor);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
            }

            /* we skip bloom filter block if configured */
            if (cf->config.bloom_filter)
            {
                if (block_manager_cursor_next((*cursor)->sstable_cursors[i]) == -1)
                {
                    /* we free previously allocated cursors */
                    for (int j = 0; j <= i; j++)
                    {
                        (void)block_manager_cursor_free((*cursor)->sstable_cursors[j]);
                    }

                    free((*cursor)->sstable_cursors);
                    (void)skip_list_cursor_free((*cursor)->memtable_cursor);
                    free(*cursor);
                    (void)pthread_rwlock_unlock(&cf->rwlock);
                    return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
                }
            }

            /* if using block indices, ensure we're reading the data blocks, not the SBHA at the
             * end..
             */
            if (TDB_BLOCK_INDICES)
            {
                /* we check if this is the SBHA block at the end to avoid it */
                if (block_manager_cursor_at_last((*cursor)->sstable_cursors[i]))
                {
                    (void)block_manager_cursor_prev((*cursor)->sstable_cursors[i]);
                }
            }
        }
    }

    /* we alloc memory for current entries
     * one for memtable and one for each sstable */
    (*cursor)->current_entries =
        malloc((cf->num_sstables + 1) * sizeof(tidesdb_merge_cursor_entry_t));
    if ((*cursor)->current_entries == NULL)
    {
        /* we free all cursors */
        for (int i = 0; i < cf->num_sstables; i++)
        {
            if ((*cursor)->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free((*cursor)->sstable_cursors[i]);
            }
        }

        free((*cursor)->sstable_cursors);
        if ((*cursor)->memtable_cursor != NULL)
        {
            (void)skip_list_cursor_free((*cursor)->memtable_cursor);
        }

        free(*cursor);
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor entries");
    }

    /* we init entries to invalid */
    for (int i = 0; i < cf->num_sstables + 1; i++)
    {
        (*cursor)->current_entries[i].valid = false;
    }

    /* we alloc memory for min heap */
    (*cursor)->min_heap = malloc((*cursor)->min_heap_size * sizeof(int));
    if ((*cursor)->min_heap == NULL)
    {
        /* we free all cursors and entries */
        for (int i = 0; i < cf->num_sstables; i++)
        {
            if ((*cursor)->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free((*cursor)->sstable_cursors[i]);
            }
        }

        free((*cursor)->sstable_cursors);
        if ((*cursor)->memtable_cursor != NULL)
        {
            (void)skip_list_cursor_free((*cursor)->memtable_cursor);
        }

        free((*cursor)->current_entries);
        free(*cursor);
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "merge cursor min heap");
    }

    /* we init the entries */
    tidesdb_err_t *err = _tidesdb_merge_cursor_init_entries(*cursor);
    if (err != NULL)
    {
        /* we free all cursors and entries */
        for (int i = 0; i < cf->num_sstables; i++)
        {
            if ((*cursor)->sstable_cursors[i] != NULL)
            {
                (void)block_manager_cursor_free((*cursor)->sstable_cursors[i]);
            }
        }

        free((*cursor)->sstable_cursors);
        if ((*cursor)->memtable_cursor != NULL)
        {
            (void)skip_list_cursor_free((*cursor)->memtable_cursor);
        }

        free((*cursor)->current_entries);
        free((*cursor)->min_heap);
        free(*cursor);
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return err;
    }

    (void)pthread_rwlock_unlock(&cf->rwlock);

    return NULL;
}
