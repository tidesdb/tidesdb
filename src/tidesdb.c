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
/* windows and unix path separator differences */
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

uint8_t *_tidesdb_serialize_column_family_config(tidesdb_column_family_config_t *config,
                                                 size_t *out_size)
{
    /* calculate the size of the serialized data */
    *out_size = sizeof(uint32_t) + strlen(config->name) + 1 + sizeof(int32_t) * 2 + sizeof(float) +
                sizeof(uint8_t) * 2 + sizeof(tidesdb_compression_algo_t) +
                sizeof(tidesdb_memtable_ds_t);

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

    /* serialize memtable_ds */
    memcpy(ptr, &config->memtable_ds, sizeof(tidesdb_memtable_ds_t));

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

    /* deserialize memtable_ds */
    tidesdb_memtable_ds_t memtable_ds;
    memcpy(&memtable_ds, ptr, sizeof(tidesdb_memtable_ds_t));

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
    config->memtable_ds = memtable_ds;

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

    *out_size = sizeof(TIDESDB_OP_CODE) + sizeof(uint32_t) + cf_name_size + kv_size;

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

    /* serialize key-value pair */
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

    uint8_t *ptr = data;

    /* deserialize op_code */
    TIDESDB_OP_CODE op_code;
    memcpy(&op_code, ptr, sizeof(TIDESDB_OP_CODE));
    ptr += sizeof(TIDESDB_OP_CODE);

    /* deserialize cf_name size */
    uint32_t cf_name_size;
    memcpy(&cf_name_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* deserialize cf_name */
    char *cf_name = malloc(cf_name_size);
    if (cf_name == NULL)
    {
        if (decompressed_data) free(decompressed_data);
        return NULL;
    }
    memcpy(cf_name, ptr, cf_name_size);
    ptr += cf_name_size;

    /* deserialize key-value pair */
    tidesdb_key_value_pair_t *kv =
        _tidesdb_deserialize_key_value_pair(ptr, 0, false, TDB_NO_COMPRESSION);
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

    int new_instance = 0;

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

        /* we setup the log file */
        if (log_init(&(*tdb)->log, log_path, TDB_DEBUG_LOG_TRUNCATE_AT) == -1)
        {
            free((*tdb)->directory);
            free(*tdb);
            return tidesdb_err_from_code(TIDESDB_ERR_LOG_INIT_FAILED);
        }
    }

    if (new_instance)
        (void)log_write((*tdb)->log, "Initialized new TidesDB instance at %s", directory);
    else
        (void)log_write((*tdb)->log, "Reopening TidesDB instance at %s", directory);

    /* now we load the column families */
    if (_tidesdb_load_column_families(*tdb) == -1)
    {
        free((*tdb)->directory);
        free(*tdb);
        return tidesdb_err_from_code(TIDESDB_ERR_LOAD_COLUMN_FAMILIES);
    }

    (*tdb)->available_mem = _tidesdb_get_available_mem();
    (*tdb)->available_mem =
        (size_t)((double)(*tdb)->available_mem * TDB_AVAILABLE_MEMORY_THRESHOLD);

    (void)log_write((*tdb)->log, "Available memory: %zu bytes", (*tdb)->available_mem);

    (void)log_write((*tdb)->log, "Opened TidesDB instance at %s", directory);

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
        (void)log_write(tdb->log, "Failed to open db directory %s", tdb->directory);
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

                fseek(config_file, 0, SEEK_END);         /* seek to end of file */
                size_t config_size = ftell(config_file); /* get size of file */
                fseek(config_file, 0, SEEK_SET);         /* seek back to beginning of file */

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
                cf->partial_merging = false;
                cf->tdb = tdb;

                (void)log_write(tdb->log, "Setting up column family %s", cf->config.name);

                switch (cf->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                        cf->memtable_sl =
                            skip_list_new(cf->config.max_level, cf->config.probability);
                        break; /* create a skip list */
                    case TDB_MEMTABLE_HASH_TABLE:
                        cf->memtable_ht = hash_table_new();
                        break;
                }

                (void)log_write(
                    tdb->log, "Column family using %s memtable data structure",
                    cf->config.memtable_ds == TDB_MEMTABLE_SKIP_LIST ? "Skip List" : "Hash Table");

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
                    (void)log_write(tdb->log, "Failed to open WAL for column family %s",
                                    cf->config.name);
                    free(cf->path);
                    free(cf->wal);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                (void)log_write(tdb->log, "Opened WAL for column family %s", cf->config.name);

                /* we add the column family to tidesdb arr */
                if (_tidesdb_add_column_family(tdb, cf) == -1)
                {
                    (void)_tidesdb_close_wal(cf->wal);
                    free(cf->path);
                    free(cf);
                    (void)closedir(cf_dir);
                    continue;
                }

                /* we load the sstable files into memory */
                (void)_tidesdb_load_sstables(cf);

                (void)log_write(tdb->log, "Loaded SSTables for column family %s", cf->config.name);

                /* we sort sstables if any */
                (void)_tidesdb_sort_sstables(cf);

                /* now we replay from the wal and populate column family memtable */
                (void)_tidesdb_replay_from_wal(cf);

                (void)log_write(tdb->log, "Replayed WAL for column family %s", cf->config.name);
            }
        }

        /* we free up resources */
        (void)closedir(cf_dir);
    }

    /* we free up resources */
    (void)closedir(tdb_dir);

    return 0;
}

tidesdb_err_t *tidesdb_close(tidesdb_t *tdb)
{
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    (void)log_write(tdb->log, "Closing TidesDB instance at %s", tdb->directory);

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
            if (tdb->column_families[i]->partial_merging)
            {
                tdb->column_families[i]->partial_merging = false;
                /* wait for thread to finish */
                (void)pthread_join(tdb->column_families[i]->partial_merge_thread, NULL);
            }

            if (tdb->column_families[i]->config.name != NULL)
                free(tdb->column_families[i]->config.name);

            if (tdb->column_families[i]->path != NULL) free(tdb->column_families[i]->path);

            if (tdb->column_families[i]->memtable_ht != NULL ||
                tdb->column_families[i]->memtable_sl != NULL)
            {
                switch (tdb->column_families[i]->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                        (void)skip_list_free(tdb->column_families[i]->memtable_sl);
                        break;
                    case TDB_MEMTABLE_HASH_TABLE:
                        (void)hash_table_free(tdb->column_families[i]->memtable_ht);
                        break;
                    default:
                        break;
                }

                tdb->column_families[i]->memtable_ht = NULL;
                tdb->column_families[i]->memtable_sl = NULL;
            }

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
    if (cf == NULL) return -1;

    if (cf->path == NULL) return -1;

    /* we open the column family directory */
    DIR *cf_dir = opendir(cf->path);
    if (cf_dir == NULL)
    { /* we check if the directory was opened */
        return -1;
    }

    struct dirent *entry;

    /* we iterate over the column family directory */
    while ((entry = readdir(cf_dir)) != NULL)
    {
        /* we skip the . and .. directories */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

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
            /* free up resources */
            (void)closedir(cf_dir);

            return -1;
        }

        /* we create/alloc the sstable struct */
        tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
        if (sst == NULL) return -1;

        /* we set the block manager */
        sst->block_manager = sstable_block_manager;

        /* check if sstables is NULL */
        if (cf->sstables == NULL)
        {
            cf->sstables = malloc(sizeof(tidesdb_sstable_t));
            if (cf->sstables == NULL)
            {
                free(sst);
                return -1;
            }
        }
        else
        {
            /* we add the sstable to the column family */
            tidesdb_sstable_t **temp_sstables =
                realloc(cf->sstables, sizeof(tidesdb_sstable_t) * (cf->num_sstables + 1));
            if (temp_sstables == NULL) return -1;

            cf->sstables = temp_sstables;
        }

        cf->sstables[cf->num_sstables] = sst;

        /* we increment the number of sstables */
        cf->num_sstables++;

        /* we free up resources */
        (void)closedir(cf_dir);

        return 0;
    }

    /* we free up resources */
    (void)closedir(cf_dir);

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
                switch (cf->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                    {
                        (void)skip_list_put(cf->memtable_sl, op->kv->key, op->kv->key_size,
                                            op->kv->value, op->kv->value_size, op->kv->ttl);
                    }
                    break;
                    case TDB_MEMTABLE_HASH_TABLE:
                        (void)hash_table_put(&cf->memtable_ht, op->kv->key, op->kv->key_size,
                                             op->kv->value, op->kv->value_size, op->kv->ttl);
                        break;
                    default:
                        break;
                }

                break;
            case TIDESDB_OP_DELETE:
            {
                uint8_t *tombstone = malloc(4);
                if (tombstone == NULL) continue;

                uint32_t tombstone_value = TOMBSTONE;
                memcpy(tombstone, &tombstone_value, sizeof(uint32_t));

                switch (cf->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                    {
                        (void)skip_list_put(cf->memtable_sl, op->kv->key, op->kv->key_size,
                                            tombstone, 4, op->kv->ttl);
                    }
                    break;
                    case TDB_MEMTABLE_HASH_TABLE:
                        (void)hash_table_put(&cf->memtable_ht, op->kv->key, op->kv->key_size,
                                             tombstone, 4, op->kv->ttl);
                        break;
                    default:
                        break;
                }

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
                                            bool bloom_filter, tidesdb_memtable_ds_t memtable_ds)
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

    /* we check flush threshold
     * the system expects at least TDB_FLUSH_THRESHOLD threshold */
    if (flush_threshold < TDB_FLUSH_THRESHOLD)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_FLUSH_THRESHOLD);

    /* only if the memtable data structure is skip list
     * we check max level and probability.  We also check if valid ds */
    switch (memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            break;
            /* we check max level
             * the system expects at least a level of TDB_MIN_MAX_LEVEL */
            if (max_level < TDB_MIN_MAX_LEVEL)
                return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_MAX_LEVEL);

            /* we check probability
             * the system expects at least a probability of TDB_MIN_PROBABILITY */
            if (probability < TDB_MIN_PROBABILITY)
                return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_PROBABILITY);
        case TDB_MEMTABLE_HASH_TABLE:
            break;
        default: /* invalid memtable data structure */
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

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
                                   compressed, compression_algo, bloom_filter, memtable_ds) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_CREATE_COLUMN_FAMILY);

    /* now we add the column family */
    if (_tidesdb_add_column_family(tdb, cf) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ADD_COLUMN_FAMILY);

    return NULL;
}

tidesdb_err_t *tidesdb_drop_column_family(tidesdb_t *tdb, const char *name)
{
    /* check if either tdb or name is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the name is NULL */
    if (name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

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

    switch (tdb->column_families[index]->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            (void)skip_list_free(tdb->column_families[index]->memtable_sl);
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            (void)hash_table_free(tdb->column_families[index]->memtable_ht);
            break;
        default:
            break;
    }

    /* remove all files in the column family directory */
    (void)_tidesdb_remove_directory(tdb->column_families[index]->path);

    free(tdb->column_families[index]->sstables);
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
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "column families");
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
                               tidesdb_compression_algo_t compress_algo, bool bloom_filter,
                               tidesdb_memtable_ds_t memtable_ds)
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

    /* set memtable data structure */
    (*cf)->config.memtable_ds = memtable_ds;

    (*cf)->partial_merging = false;

    (*cf)->tdb = tdb;

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

    switch ((*cf)->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            (*cf)->memtable_sl = skip_list_new((*cf)->config.max_level, (*cf)->config.probability);
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            (*cf)->memtable_ht = hash_table_new();
            break;
    }

    /* we check if the memtable was created */
    if ((*cf)->memtable_sl == NULL || (*cf)->memtable_ht == NULL)
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
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

    /* we check if the value is NULL */
    if (value == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_VALUE);

    /* we check if the key and value size exceed available system memory */
    if (key_size + value_size > tdb->available_mem)
        return tidesdb_err_from_code(TIDESDB_ERR_PUT_MEMORY_OVERFLOW);

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

    /* we determine the data structure to use */
    switch (cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            /* put in memtable */
            if (skip_list_put(cf->memtable_sl, key, key_size, value, value_size, ttl) == -1)
            {
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE);
            }

            /* we check if the memtable has reached the flush threshold */
            if ((int)((skip_list_t *)cf->memtable_sl)->total_size >= cf->config.flush_threshold)
            {
                if (cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            /* put in memtable */
            if (hash_table_put(&cf->memtable_ht, key, key_size, value, value_size, ttl) == -1)
            {
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE);
            }

            /* we check if the memtable has reached the flush threshold */
            if ((int)((hash_table_t *)cf->memtable_ht)->total_size >= cf->config.flush_threshold)
            {
                if (cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter_f_hash_table(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable_f_hash_table(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
        default:
            if (pthread_rwlock_unlock(&cf->rwlock) != 0)
            {
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
            }

            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
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

    switch (cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            if (skip_list_get(cf->memtable_sl, key, key_size, value, value_size) != -1)
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
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if (hash_table_get((hash_table_t *)cf->memtable_ht, key, key_size, value, value_size) !=
                -1)
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
            break;

        default:
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

    /* now we check sstables from latest to oldest */

    /* we check if any sstables */
    if (cf->num_sstables == 0)
    {
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
    }

    /* we iterate over the sstables */
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

        /* if the column family has bloom filters enabled then, well we read
         * the first block which contains the bloom filter and check if the key exists */
        if (cf->config.bloom_filter)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block == NULL)
            {
                (void)block_manager_cursor_free(cursor);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
            }

            /* we deserialize the bloom filter */
            bloom_filter_t *bf = bloom_filter_deserialize(block->data);
            if (bf == NULL)
            {
                (void)block_manager_cursor_free(cursor);
                (void)block_manager_block_free(block);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_DESERIALIZE_BLOOM_FILTER);
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
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
            }
        }

        block_manager_block_t *block;
        while ((block = block_manager_cursor_read(cursor)) != NULL)
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
        };

        (void)block_manager_cursor_free(cursor);
    }

    /* unlock column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    return tidesdb_err_from_code(TIDESDB_ERR_KEY_NOT_FOUND);
}

tidesdb_err_t *tidesdb_delete(tidesdb_t *tdb, const char *column_family_name, const uint8_t *key,
                              size_t key_size)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    if (key == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_KEY);

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

    /* get column family write lock */
    if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    uint8_t *tombstone = malloc(4);
    if (tombstone == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "tombstone");

    uint32_t tombstone_value = TOMBSTONE;
    memcpy(tombstone, &tombstone_value, sizeof(uint32_t));

    /* append to wal */
    if (_tidesdb_append_to_wal(cf->wal, key, key_size, tombstone, 4, 0, TIDESDB_OP_DELETE,
                               column_family_name) == -1)
    {
        free(tombstone);
        (void)pthread_rwlock_unlock(&cf->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_APPEND_TO_WAL);
    }
    /* add to memtable */
    switch (cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            if (skip_list_put(cf->memtable_sl, key, key_size, tombstone, 4, -1) == -1)
            {
                free(tombstone);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE);
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if (hash_table_put(&cf->memtable_ht, key, key_size, tombstone, 4, -1) == -1)
            {
                free(tombstone);
                (void)pthread_rwlock_unlock(&cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_PUT_TO_MEMTABLE);
            }
            break;
        default:
            free(tombstone);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

    free(tombstone);

    /* we check if the memtable has reached the flush threshold */
    switch (cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            if ((int)((skip_list_t *)cf->memtable_sl)->total_size >= cf->config.flush_threshold)
            {
                if (cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if ((int)((hash_table_t *)cf->memtable_ht)->total_size >= cf->config.flush_threshold)
            {
                if (cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter_f_hash_table(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable_f_hash_table(cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
        default:
            if (pthread_rwlock_unlock(&cf->rwlock) != 0)
            {
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
            }

            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

    /* release column family write lock */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

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
    /* we append to column families write ahead log */

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

    block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_op);
    if (block == NULL)
    {
        (void)_tidesdb_free_operation(op);
        free(serialized_op);
        return -1;
    }

    /* we append to the wal */
    if (block_manager_block_write(wal->block_manager, block) == -1)
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
    (void)log_write(cf->tdb->log, "Flushing column family %s at size %zu", cf->config.name,
                    cf->memtable_sl->total_size);

    /* we create a new sstable struct */
    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (sst == NULL) return -1;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH];
    snprintf(sstable_path, sizeof(sstable_path), "%s%s%s%d%s", cf->path,
             _tidesdb_get_path_seperator(), TDB_SSTABLE_PREFIX, cf->num_sstables, TDB_SSTABLE_EXT);

    /* we create a new block manager */
    block_manager_t *sstable_block_manager = NULL;

    if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        free(sst);
        (void)log_write(cf->tdb->log, "Column family %s failed to open block manager for flush",
                        cf->config.name);
        return -1;
    }

    /* we set the block manager */
    sst->block_manager = sstable_block_manager;

    /* we create a new skip list cursor and populate the memtable
     * with serialized key value pairs */

    skip_list_cursor_t *cursor = skip_list_cursor_init(cf->memtable_sl);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        (void)log_write(cf->tdb->log, "Column family %s failed to init cursor for flush",
                        cf->config.name);
        return -1;
    }

    /* we iterate over the memtable and write to the sstable */
    do
    {
        /* we get the key value pair */
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
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
            return -1;
        }

        /* we copy the key */
        kv->key = malloc(key_size);
        if (kv->key == NULL)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
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
            remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        (void)_tidesdb_free_key_value_pair(kv);

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(block);
        free(serialized_kv);

    } while (skip_list_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)skip_list_cursor_free(cursor);

    /* we add the sstable to the column family */
    if (cf->sstables == NULL)
    {
        cf->sstables = malloc(sizeof(tidesdb_sstable_t));
        if (cf->sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            return -1;
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
    if (skip_list_clear(cf->memtable_sl) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* truncate the wal */
    if (block_manager_truncate(cf->wal->block_manager) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    (void)log_write(cf->tdb->log, "Flushed column family %s to sstable %s", cf->config.name,
                    sstable_path);

    return 0;
}

tidesdb_err_t *tidesdb_compact_sstables(tidesdb_t *tdb, const char *column_family_name,
                                        int max_threads)
{
    /* we check prerequisites */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    if (column_family_name == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

    if (max_threads < 1) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MAX_THREADS);

    /* get db read lock */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");
    }

    /* get column family */
    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(tdb, column_family_name, &cf) == -1)
        return tidesdb_err_from_code(TIDESDB_ERR_COLUMN_FAMILY_NOT_FOUND);

    /* we check if column family has partial merge started */
    if (cf->partial_merging)
    {
        /* release db read lock */
        if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
        {
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
        }

        return tidesdb_err_from_code(TIDESDB_ERR_PARTIAL_MERGE_ALREADY_STARTED, column_family_name);
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
    sem_init(&sem, 0, max_threads); /* initialize the semaphore */

    /* we create a temp lock which is shared between threads for sstable path creation */
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    /* we iterate over the sstables pairing and merging them */
    for (int i = 0; i < num_sstables - 1; i += 2)
    {
        sem_wait(&sem); /* we wait if the maximum number of threads is reached */

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
        sem_wait(&sem);
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

    tidesdb_sstable_t *merged_sstable = NULL;
    if (!cf->config.bloom_filter)
    {
        /* merge the current and ith+1 sstables */
        merged_sstable =
            _tidesdb_merge_sstables(cf->sstables[start], cf->sstables[end], cf, args->lock);
    }
    else
    {
        /* with bloom filter */
        merged_sstable = _tidesdb_merge_sstables_w_bloom_filter(cf->sstables[start],
                                                                cf->sstables[end], cf, args->lock);
    }

    /* we check if the merged is NULL */
    if (merged_sstable == NULL)
    {
        free(args);
        return NULL;
    }

    /* remove old sstable files */
    char sstable_path1[MAX_FILE_PATH_LENGTH];
    char sstable_path2[MAX_FILE_PATH_LENGTH];

    /* get the sstable paths */
    (void)snprintf(sstable_path1, MAX_FILE_PATH_LENGTH, "%s",
                   cf->sstables[start]->block_manager->file_path);
    (void)snprintf(sstable_path2, MAX_FILE_PATH_LENGTH, "%s",
                   cf->sstables[end]->block_manager->file_path);

    /* free the old sstables */
    (void)_tidesdb_free_sstable(cf->sstables[start]);
    (void)_tidesdb_free_sstable(cf->sstables[end]);

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
    if (block_manager_open(&merged_sstable->block_manager, sstable_path1, TDB_SYNC_INTERVAL) == -1)
    {
        free(args);
        return NULL;
    }

    /* replace the old sstables with the new one */
    cf->sstables[start] = merged_sstable;
    cf->sstables[end] = NULL;

    (void)sem_post(args->sem); /* signal compaction thread is done */
    free(args);                /* free the args */

    return NULL;
}

tidesdb_sstable_t *_tidesdb_merge_sstables(tidesdb_sstable_t *sst1, tidesdb_sstable_t *sst2,
                                           tidesdb_column_family_t *cf,
                                           pthread_mutex_t *shared_lock)
{
    /* we initialize a new sstable */
    tidesdb_sstable_t *merged_sstable = malloc(sizeof(tidesdb_sstable_t));
    if (merged_sstable == NULL) return NULL;

    /* we initialize a new skiplist as a mergetable with column family configurations */
    skip_list_t *mergetable = skip_list_new(cf->config.max_level, cf->config.probability);
    if (mergetable == NULL)
    {
        free(merged_sstable);
        return NULL;
    }

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH * 2];

    /* lock to make sure path is unique */
    if (pthread_mutex_lock(shared_lock) != 0)
    {
        (void)skip_list_free(mergetable);
        free(merged_sstable);
        return NULL;
    }

    snprintf(sstable_path, sizeof(sstable_path), "%s%s", sst1->block_manager->file_path,
             TDB_TEMP_EXT);

    /* unlock the shared lock */
    if (pthread_mutex_unlock(shared_lock) != 0)
    {
        (void)skip_list_free(mergetable);
        free(merged_sstable);
        return NULL;
    }

    /* we open a new block manager for the merged sstable */
    if (block_manager_open(&merged_sstable->block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        free(merged_sstable);
        return NULL;
    }

    /* we populate the merge table with the sstables */

    block_manager_cursor_t *cursor = NULL;

    /* init cursor for sstable 1 */
    if (block_manager_cursor_init(&cursor, sst1->block_manager) == -1)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    block_manager_block_t *block;
    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
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

        if (skip_list_put(mergetable, kv->key, kv->key_size, kv->value, kv->value_size, kv->ttl) ==
            -1)
        {
            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);
            continue;
        }

        (void)block_manager_block_free(block);
        (void)_tidesdb_free_key_value_pair(kv);

        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_block_free(block);
    block = NULL;
    (void)block_manager_cursor_free(cursor);
    cursor = NULL;

    /* init cursor for sstable 2 */
    if (block_manager_cursor_init(&cursor, sst2->block_manager) == -1)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
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

        if (skip_list_put(mergetable, kv->key, kv->key_size, kv->value, kv->value_size, kv->ttl) ==
            -1)
        {
            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);
            continue;
        }

        (void)block_manager_block_free(block);
        (void)_tidesdb_free_key_value_pair(kv);

        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_cursor_free(cursor);

    skip_list_cursor_t *mergetable_cursor = skip_list_cursor_init(mergetable);
    if (mergetable_cursor == NULL)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    do
    {
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            (void)skip_list_cursor_free(mergetable_cursor);
            (void)skip_list_free(mergetable);
            (void)remove(sstable_path);
            free(merged_sstable);
            return NULL;
        }

        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (skip_list_cursor_get(mergetable_cursor, &retrieved_key, &key_size, &retrieved_value,
                                 &value_size, &ttl) == -1)
        {
            free(kv);
            continue;
        }

        /* we copy the key */
        kv->key = malloc(key_size);
        if (kv->key == NULL)
        {
            free(kv);
            continue;
        }
        memcpy(kv->key, retrieved_key, key_size);

        /* we copy the value */
        kv->value = malloc(value_size);
        if (kv->value == NULL)
        {
            free(kv->key);
            free(kv);
            continue;
        }

        memcpy(kv->value, retrieved_value, value_size);

        /* we set the key size */
        kv->key_size = key_size;
        /* we set the value size */
        kv->value_size = value_size;
        /* we set the ttl */
        kv->ttl = ttl;

        size_t serialized_size;
        uint8_t *serialized_kv = _tidesdb_serialize_key_value_pair(
            kv, &serialized_size, cf->config.compressed, cf->config.compress_algo);
        if (serialized_kv == NULL)
        {
            free(kv);
            break;
        }

        block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(kv);
            free(serialized_kv);
            break;
        }

        if (block_manager_block_write(merged_sstable->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(kv);
            free(serialized_kv);
            break;
        }

        (void)block_manager_block_free(block);
        free(serialized_kv);
        (void)_tidesdb_free_key_value_pair(kv);

    } while (skip_list_cursor_next(mergetable_cursor) != -1);

    (void)skip_list_cursor_free(mergetable_cursor);
    (void)skip_list_clear(mergetable);
    (void)skip_list_free(mergetable);

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

tidesdb_err_t *tidesdb_txn_begin(tidesdb_t *tdb, tidesdb_txn_t **txn, const char *column_family)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check if column family is NULL */
    if (column_family == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_COLUMN_FAMILY);

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
    if (_tidesdb_get_column_family(tdb, column_family, &cf) == -1)
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

                switch (txn->cf->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                        if (skip_list_put(txn->cf->memtable_sl, op.kv->key, op.kv->key_size,
                                          op.kv->value, op.kv->value_size, op.kv->ttl) == -1)
                        {
                            /* unlock the column family */
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                            /* unlock the transaction */
                            (void)pthread_mutex_unlock(&txn->lock);

                            /* we rollback the transaction */
                            return tidesdb_txn_rollback(txn);
                        }
                        break;
                    case TDB_MEMTABLE_HASH_TABLE:
                        if (hash_table_put(&txn->cf->memtable_ht, op.kv->key, op.kv->key_size,
                                           op.kv->value, op.kv->value_size, op.kv->ttl) == -1)
                        {
                            /* unlock the column family */
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                            /* unlock the transaction */
                            (void)pthread_mutex_unlock(&txn->lock);

                            /* we rollback the transaction */
                            return tidesdb_txn_rollback(txn);
                        }
                        break;
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

                switch (txn->cf->config.memtable_ds)
                {
                    case TDB_MEMTABLE_SKIP_LIST:
                        if (skip_list_put(txn->cf->memtable_sl, op.kv->key, op.kv->key_size,
                                          op.kv->value, 4, 0) == -1)
                        {
                            /* unlock the column family */
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                            /* unlock the transaction */
                            (void)pthread_mutex_unlock(&txn->lock);

                            /* we rollback the transaction */
                            return tidesdb_txn_rollback(txn);
                        }
                        break;
                    case TDB_MEMTABLE_HASH_TABLE:
                        if (hash_table_put(&txn->cf->memtable_ht, op.kv->key, op.kv->key_size,
                                           op.kv->value, 4, 0) == -1)
                        {
                            /* unlock the column family */
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);

                            /* unlock the transaction */
                            (void)pthread_mutex_unlock(&txn->lock);

                            /* we rollback the transaction */
                            return tidesdb_txn_rollback(txn);
                        }
                        break;
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
    switch (txn->cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:

            if (((int)((skip_list_t *)txn->cf->memtable_sl)->total_size >=
                 txn->cf->config.flush_threshold))
            {
                if (txn->cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter(txn->cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable(txn->cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if (((int)((hash_table_t *)txn->cf->memtable_ht)->total_size >=
                 txn->cf->config.flush_threshold))
            {
                if (txn->cf->config.bloom_filter)
                {
                    if (_tidesdb_flush_memtable_w_bloom_filter_f_hash_table(txn->cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
                else
                {
                    if (_tidesdb_flush_memtable_f_hash_table(txn->cf) == -1)
                    {
                        (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                    }
                }
            }
            break;
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

            /* we put back the key-value pair */
            switch (txn->cf->config.memtable_ds)
            {
                case TDB_MEMTABLE_SKIP_LIST:
                    (void)skip_list_put(txn->cf->memtable_sl, op.kv->key, op.kv->key_size,
                                        op.kv->value, op.kv->value_size, op.kv->ttl);
                    break;
                case TDB_MEMTABLE_HASH_TABLE:
                    (void)hash_table_put(&txn->cf->memtable_ht, op.kv->key, op.kv->key_size,
                                         op.kv->value, op.kv->value_size, op.kv->ttl);
                    break;
                default:
                    return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
            }
        }
    }

    /* unlock the transaction */
    if (pthread_mutex_unlock(&txn->lock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "transaction");

    /* we check if the memtable needs to be flushed */
    switch (txn->cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            if (((int)((skip_list_t *)txn->cf->memtable_sl)->total_size >=
                 txn->cf->config.flush_threshold))
            {
                if (txn->cf->config.bloom_filter)
                {
                    if (txn->cf->config.memtable_ds == TDB_MEMTABLE_SKIP_LIST)
                    {
                        if (_tidesdb_flush_memtable_w_bloom_filter(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                    else
                    {
                        if (_tidesdb_flush_memtable_w_bloom_filter_f_hash_table(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                }
                else
                {
                    if (txn->cf->config.memtable_ds == TDB_MEMTABLE_SKIP_LIST)
                    {
                        if (_tidesdb_flush_memtable(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                    else
                    {
                        if (_tidesdb_flush_memtable_w_bloom_filter(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                }
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if (((int)((hash_table_t *)txn->cf->memtable_ht)->total_size >=
                 txn->cf->config.flush_threshold))
            {
                if (txn->cf->config.bloom_filter)
                {
                    if (txn->cf->config.memtable_ds == TDB_MEMTABLE_SKIP_LIST)
                    {
                        if (_tidesdb_flush_memtable_w_bloom_filter(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                    else
                    {
                        if (_tidesdb_flush_memtable_w_bloom_filter_f_hash_table(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                }
                else
                {
                    if (txn->cf->config.memtable_ds == TDB_MEMTABLE_SKIP_LIST)
                    {
                        if (_tidesdb_flush_memtable(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                    else
                    {
                        if (_tidesdb_flush_memtable_f_hash_table(txn->cf) == -1)
                        {
                            (void)pthread_rwlock_unlock(&txn->cf->rwlock);
                            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_FLUSH_MEMTABLE);
                        }
                    }
                }
            }
            break;
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

    /* we get the column family */
    tidesdb_column_family_t *cf = NULL;

    /* we need to get read lock for the db */
    if (pthread_rwlock_rdlock(&tdb->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "db");

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
    (*cursor)->tidesdb = tdb;
    (*cursor)->cf = cf;
    (*cursor)->sstable_cursor = NULL;
    (*cursor)->memtable_cursor = NULL;

    /* get column family read lock */
    if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
    {
        free(*cursor);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    (*cursor)->sstable_index =
        cf->num_sstables - 1; /* we start at the last sstable, the latest sstable */

    /* we check what data structure the column family is using */
    switch ((*cursor)->cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            (*cursor)->memtable_cursor = skip_list_cursor_init(cf->memtable_sl);
            if ((*cursor)->memtable_cursor == NULL)
            {
                /* unlock column family */
                (void)pthread_rwlock_unlock(&cf->rwlock);
                free(*cursor);
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            (*cursor)->memtable_cursor = hash_table_cursor_init(cf->memtable_ht);
            break;
        default:
            free(cursor);
            (void)pthread_rwlock_unlock(&cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
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

        /* if column family has bloom filter set we skip first block */
        if (cf->config.bloom_filter)
        {
            if (block_manager_cursor_next((*cursor)->sstable_cursor) == 0)
            {
                (void)block_manager_cursor_free((*cursor)->sstable_cursor);
                (*cursor)->sstable_cursor = NULL;
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
    /* we check if cursor is invalid */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* we get read lock for column family */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we check if memtable has a next kv */
    while (1)
    {
        switch (cursor->cf->config.memtable_ds)
        {
            case TDB_MEMTABLE_SKIP_LIST:
                if (cursor->memtable_cursor != NULL &&
                    skip_list_cursor_next(cursor->memtable_cursor) == 0)
                {
                    if (((skip_list_cursor_t *)cursor->memtable_cursor)->current !=
                        NULL) /* check if current is not NULL */
                    {
                        /* check if the value is not a tombstone */
                        if (!_tidesdb_is_tombstone(
                                ((skip_list_cursor_t *)cursor->memtable_cursor)->current->value,
                                ((skip_list_cursor_t *)cursor->memtable_cursor)
                                    ->current->value_size))
                        {
                            if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
                                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK,
                                                             "column family");

                            return NULL;
                        }
                    }
                }
                break;
            case TDB_MEMTABLE_HASH_TABLE:
                if (cursor->memtable_cursor != NULL &&
                    hash_table_cursor_next(cursor->memtable_cursor) == 0)
                {
                    uint8_t *retrieved_key;
                    size_t retrieved_key_size;
                    uint8_t *retrieved_value;
                    size_t retrieved_value_size;
                    time_t retrieved_ttl;
                    if (hash_table_cursor_get(cursor->memtable_cursor, &retrieved_key,
                                              &retrieved_key_size, &retrieved_value,
                                              &retrieved_value_size, &retrieved_ttl) == 0)
                    {
                        if (!_tidesdb_is_tombstone(retrieved_value, retrieved_value_size))
                        {
                            if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
                                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK,
                                                             "column family");

                            return NULL;
                        }
                    }
                }
                break;
            default:
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
        }

        break;
    }

    /* if memtable is exhausted we check sstables
     * starting at the most recent sstable
     */

    while (cursor->sstable_index >= 0)
    {
        /* we check if sstable cursor is valid and if it has a next block */
        if (cursor->sstable_cursor != NULL &&
            block_manager_cursor_next(cursor->sstable_cursor) == 0)
        {
            if (block_manager_cursor_has_next(cursor->sstable_cursor) == 1)
            {
                if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
                    return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK,
                                                 "column family");

                /* we return NULL as we have a next kv */
                return NULL;
            }
        }

        /* if sstable is exhausted we move to the next sstable */
        if (cursor->sstable_cursor != NULL)
        {
            /* we free the sstable cursor for current sstable */
            (void)block_manager_cursor_free(cursor->sstable_cursor);
            cursor->sstable_cursor = NULL;
        }

        cursor->sstable_index--; /* move to the next sstable */

        if (cursor->sstable_index < 0)
        {
            cursor->sstable_index = 0; /* reset to the first sstable */
            break;
        }

        /* we check if there are more sstables */
        if (block_manager_cursor_init(&cursor->sstable_cursor,
                                      cursor->cf->sstables[cursor->sstable_index]->block_manager) ==
            -1)
        {
            if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_INIT_CURSOR);
        }

        /* if bloom is set we skip first block */
        if (cursor->cf->config.bloom_filter)
        {
            if (block_manager_cursor_next(cursor->sstable_cursor) == 0)
            {
                block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }
        }

        if (cursor->sstable_cursor != NULL)
        {
            if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
                return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

            return NULL;
        }
    }

    if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return tidesdb_err_from_code(TIDESDB_ERR_AT_END_OF_CURSOR);
}

tidesdb_err_t *tidesdb_cursor_prev(tidesdb_cursor_t *cursor)
{
    /* we check if cursor is invalid */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    /* we check if memtable has a previous kv */
    while (1)
    {
        switch (cursor->cf->config.memtable_ds)
        {
            case TDB_MEMTABLE_SKIP_LIST:
                while (cursor->memtable_cursor != NULL &&
                       skip_list_cursor_prev(cursor->memtable_cursor) == 0)
                {
                    if (!_tidesdb_is_tombstone(
                            ((skip_list_cursor_t *)cursor->memtable_cursor)->current->value,
                            ((skip_list_cursor_t *)cursor->memtable_cursor)->current->value_size))
                    {
                        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                        return NULL;
                    }
                }
                break;
            case TDB_MEMTABLE_HASH_TABLE:
                while (cursor->memtable_cursor != NULL &&
                       hash_table_cursor_prev(cursor->memtable_cursor) == 0)
                {
                    uint8_t *retrieved_key;
                    size_t retrieved_key_size;
                    uint8_t *retrieved_value;
                    size_t retrieved_value_size;
                    time_t retrieved_ttl;

                    if (hash_table_cursor_get(cursor->memtable_cursor, &retrieved_key,
                                              &retrieved_key_size, &retrieved_value,
                                              &retrieved_value_size, &retrieved_ttl) == 0)
                    {
                        if (!_tidesdb_is_tombstone(retrieved_value, retrieved_value_size))
                        {
                            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                            return NULL;
                        }
                    }
                }
                break;
            default:
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
        }

        if (cursor->cf->num_sstables == 0)
        {
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
        }

        if (cursor->sstable_cursor == NULL)
        {
            /* reset to the first sstable */
            cursor->sstable_index = 0;
            (void)block_manager_cursor_goto_last(cursor->sstable_cursor);
        }

        if (cursor->sstable_cursor != NULL &&
            block_manager_cursor_prev(cursor->sstable_cursor) == 0)
        { /* go to the previous block */
            if (block_manager_cursor_has_prev(cursor->sstable_cursor) == 1)
            { /* check if there is a previous block after previous */
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                return NULL;
            }
        }

        /* if sstable is exhausted we move to the previous sstable */
        if ((size_t)cursor->sstable_index < (size_t)(cursor->cf->num_sstables - 1))
        {
            if (cursor->sstable_cursor != NULL)
            {
                (void)block_manager_cursor_free(cursor->sstable_cursor);
                cursor->sstable_cursor = NULL;
            }
            cursor->sstable_index++;
            if (block_manager_cursor_init(
                    &cursor->sstable_cursor,
                    cursor->cf->sstables[cursor->sstable_index]->block_manager) == -1)
            {
                (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                continue; /* retry */
            }
            /* go to the last block */
            (void)block_manager_cursor_goto_last(cursor->sstable_cursor);
        }

        (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
        break;
    }

    if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return tidesdb_err_from_code(TIDESDB_ERR_AT_START_OF_CURSOR);
}

tidesdb_err_t *tidesdb_cursor_get(tidesdb_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size)
{
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
    if (key == NULL || key_size == NULL || value == NULL || value_size == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_ARGUMENT);

    /* get column family read lock */
    if (pthread_rwlock_rdlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");

    block_manager_block_t *block;
    while ((block = block_manager_cursor_read(cursor->sstable_cursor)) != NULL)
    {
        tidesdb_key_value_pair_t *dkv = _tidesdb_deserialize_key_value_pair(
            block->data, block->size, cursor->cf->config.compressed,
            cursor->cf->config.compress_algo);
        if (dkv == NULL)
        {
            (void)block_manager_block_free(block);
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_COULD_NOT_GET_KEY_VALUE_FROM_CURSOR);
        }

        (void)block_manager_block_free(block);

        if (_tidesdb_is_tombstone(dkv->value, dkv->value_size) || _tidesdb_is_expired(dkv->ttl))
        {
            _tidesdb_free_key_value_pair(dkv);
            continue;
        }

        *key = malloc(dkv->key_size);
        if (*key == NULL)
        {
            (void)_tidesdb_free_key_value_pair(dkv);
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
        }
        memcpy(*key, dkv->key, dkv->key_size);

        *value = malloc(dkv->value_size);
        if (*value == NULL)
        {
            free(*key);
            (void)_tidesdb_free_key_value_pair(dkv);
            (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
            return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
        }
        memcpy(*value, dkv->value, dkv->value_size);

        *key_size = dkv->key_size;
        *value_size = dkv->value_size;
        /* unlock the column family */
        if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
        {
            free(*key);
            free(*value);
            (void)_tidesdb_free_key_value_pair(dkv);
            return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
        }
        (void)_tidesdb_free_key_value_pair(dkv);
        return NULL;
    }

    uint8_t *k;
    uint8_t *v;
    time_t ttl = time(NULL);

    switch (cursor->cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            while (skip_list_cursor_get(cursor->memtable_cursor, &k, key_size, &v, value_size,
                                        &ttl) == 0)
            {
                if (!_tidesdb_is_tombstone(v, *value_size))
                {
                    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                    *key = malloc(*key_size);
                    if (*key == NULL)
                    {
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
                    }

                    *value = malloc(*value_size);
                    if (*value == NULL)
                    {
                        free(*key);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
                    }

                    memcpy(*key, k, *key_size);
                    memcpy(*value, v, *value_size);
                    return NULL;
                }
            }
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            while (hash_table_cursor_get(cursor->memtable_cursor, &k, key_size, &v, value_size,
                                         &ttl) == 0)
            {
                if (!_tidesdb_is_tombstone(v, *value_size))
                {
                    (void)pthread_rwlock_unlock(&cursor->cf->rwlock);
                    *key = malloc(*key_size);
                    if (*key == NULL)
                    {
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "key");
                    }

                    *value = malloc(*value_size);
                    if (*value == NULL)
                    {
                        free(*key);
                        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC, "value");
                    }

                    memcpy(*key, k, *key_size);
                    memcpy(*value, v, *value_size);
                    return NULL;
                }
            }
            break;
        default:
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

    if (pthread_rwlock_unlock(&cursor->cf->rwlock) != 0)
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");

    return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);
}

tidesdb_err_t *tidesdb_cursor_free(tidesdb_cursor_t *cursor)
{
    /* we check if the cursor is NULL */
    if (cursor == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_CURSOR);

    /* we free the sstable cursor */
    if (cursor->sstable_cursor != NULL) block_manager_cursor_free(cursor->sstable_cursor);

    /* we free the memtable cursor */
    switch (cursor->cf->config.memtable_ds)
    {
        case TDB_MEMTABLE_SKIP_LIST:
            if (cursor->memtable_cursor != NULL) skip_list_cursor_free(cursor->memtable_cursor);
            break;
        case TDB_MEMTABLE_HASH_TABLE:
            if (cursor->memtable_cursor != NULL) hash_table_cursor_free(cursor->memtable_cursor);
            break;
        default:
            return tidesdb_err_from_code(TIDESDB_ERR_INVALID_MEMTABLE_DATA_STRUCTURE);
    }

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

tidesdb_sstable_t *_tidesdb_merge_sstables_w_bloom_filter(tidesdb_sstable_t *sst1,
                                                          tidesdb_sstable_t *sst2,
                                                          tidesdb_column_family_t *cf,
                                                          pthread_mutex_t *shared_lock)
{
    /*
     * similar to _tidesdb_merge_sstables but with bloom filter
     */

    /* we initialize a new sstable */
    tidesdb_sstable_t *merged_sstable = malloc(sizeof(tidesdb_sstable_t));
    if (merged_sstable == NULL) return NULL;

    /* we initialize a new skiplist as a mergetable with column family configurations */
    /* for merge we will set fixed 12 and 0.24f as a column family can use a hash table */
    skip_list_t *mergetable = skip_list_new(12, 0.24f);
    if (mergetable == NULL)
    {
        free(merged_sstable);
        return NULL;
    }

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH * 2];

    /* lock to make sure path is unique */
    if (pthread_mutex_lock(shared_lock) != 0)
    {
        (void)skip_list_free(mergetable);
        free(merged_sstable);
        return NULL;
    }

    snprintf(sstable_path, sizeof(sstable_path), "%s%s", sst1->block_manager->file_path,
             TDB_TEMP_EXT);

    /* unlock the shared lock */
    if (pthread_mutex_unlock(shared_lock) != 0)
    {
        (void)skip_list_free(mergetable);
        free(merged_sstable);
        return NULL;
    }

    /* we open a new block manager for the merged sstable */
    if (block_manager_open(&merged_sstable->block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        free(merged_sstable);
        return NULL;
    }

    /* we populate the merge table with the sstables and bloom filter */
    /* we create a bloom filter for the merged sstable */
    bloom_filter_t *bf;

    /* we block counts from sst1 and sst2 */
    int block_count1 = block_manager_count_blocks(sst1->block_manager);
    int block_count2 = block_manager_count_blocks(sst2->block_manager);

    if (bloom_filter_new(&bf, TDB_BLOOM_FILTER_P, block_count1 + block_count2) == -1)
    {
        (void)block_manager_close(merged_sstable->block_manager);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    block_manager_cursor_t *cursor = NULL;

    /* init cursor for sstable 1 */
    if (block_manager_cursor_init(&cursor, sst1->block_manager) == -1)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    /* skip block if bloom filter is set */
    if (cf->config.bloom_filter)
    {
        (void)block_manager_cursor_next(cursor);
    }

    block_manager_block_t *block;
    do
    {
        block = block_manager_cursor_read(cursor);
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

        if (skip_list_put(mergetable, kv->key, kv->key_size, kv->value, kv->value_size, kv->ttl) ==
            -1)
        {
            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);
            continue;
        }

        (void)block_manager_block_free(block);
        (void)_tidesdb_free_key_value_pair(kv);

    } while (block_manager_cursor_next(cursor) != 0);

    block = NULL;

    (void)block_manager_cursor_free(cursor);
    cursor = NULL;

    /* init cursor for sstable 2 */
    if (block_manager_cursor_init(&cursor, sst2->block_manager) == -1)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    /* skip block if bloom filter is set */
    if (cf->config.bloom_filter)
    {
        (void)block_manager_cursor_next(cursor);
    }

    do
    {
        block = block_manager_cursor_read(cursor);
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

        if (skip_list_put(mergetable, kv->key, kv->key_size, kv->value, kv->value_size, kv->ttl) ==
            -1)
        {
            (void)block_manager_block_free(block);
            (void)_tidesdb_free_key_value_pair(kv);
            continue;
        }

        (void)block_manager_block_free(block);
        (void)_tidesdb_free_key_value_pair(kv);

    } while (block_manager_cursor_next(cursor) != 0);

    (void)block_manager_cursor_free(cursor);

    skip_list_cursor_t *mergetable_cursor = skip_list_cursor_init(mergetable);
    if (mergetable_cursor == NULL)
    {
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    /* now we write the bloom filter to the merged sstable */
    size_t bf_size;
    uint8_t *bf_serialized = bloom_filter_serialize(bf, &bf_size);
    if (bf_serialized == NULL)
    {
        (void)skip_list_cursor_free(mergetable_cursor);
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    /* we create a new block */
    block_manager_block_t *bf_block = block_manager_block_create(bf_size, bf_serialized);
    if (bf_block == NULL)
    {
        free(bf_serialized);
        (void)skip_list_cursor_free(mergetable_cursor);
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    /* we write the block to the merged sstable */
    if (block_manager_block_write(merged_sstable->block_manager, bf_block) == -1)
    {
        (void)block_manager_block_free(bf_block);
        free(bf_serialized);
        (void)skip_list_cursor_free(mergetable_cursor);
        (void)skip_list_free(mergetable);
        (void)remove(sstable_path);
        free(merged_sstable);
        return NULL;
    }

    (void)block_manager_block_free(bf_block);
    free(bf_serialized);
    bloom_filter_free(bf);

    /* now we write the key-value pairs to the merged sstable
     * the mergetable will have keys sorted
     */

    do
    {
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            (void)skip_list_cursor_free(mergetable_cursor);
            (void)skip_list_free(mergetable);
            (void)remove(sstable_path);
            free(merged_sstable);
            return NULL;
        }

        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (skip_list_cursor_get(mergetable_cursor, &retrieved_key, &key_size, &retrieved_value,
                                 &value_size, &ttl) == -1)
        {
            free(kv);
            continue;
        }

        /* we copy the key */
        kv->key = malloc(key_size);
        if (kv->key == NULL)
        {
            free(kv);
            continue;
        }
        memcpy(kv->key, retrieved_key, key_size);

        /* we copy the value */
        kv->value = malloc(value_size);
        if (kv->value == NULL)
        {
            free(kv->key);
            free(kv);
            continue;
        }

        memcpy(kv->value, retrieved_value, value_size);

        /* we set the key size */
        kv->key_size = key_size;
        /* we set the value size */
        kv->value_size = value_size;
        /* we set the ttl */
        kv->ttl = ttl;

        size_t serialized_size;
        uint8_t *serialized_kv = _tidesdb_serialize_key_value_pair(
            kv, &serialized_size, cf->config.compressed, cf->config.compress_algo);
        if (serialized_kv == NULL)
        {
            free(kv);
            break;
        }

        block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(kv);
            free(serialized_kv);
            break;
        }

        if (block_manager_block_write(merged_sstable->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(kv);
            free(serialized_kv);
            break;
        }

        (void)block_manager_block_free(block);
        free(serialized_kv);
        (void)_tidesdb_free_key_value_pair(kv);

    } while (skip_list_cursor_next(mergetable_cursor) != -1);

    (void)skip_list_cursor_free(mergetable_cursor);
    (void)skip_list_clear(mergetable);
    (void)skip_list_free(mergetable);

    return merged_sstable;

    return NULL;
}

int _tidesdb_flush_memtable_w_bloom_filter(tidesdb_column_family_t *cf)
{
    (void)log_write(cf->tdb->log, "Flushing column family %s at size %zu", cf->config.name,
                    cf->memtable_sl->total_size);

    /* similar to _tidesdb_flush_memtable but with bloom filter */

    /* we create a new sstable struct */
    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (sst == NULL) return -1;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH];
    snprintf(sstable_path, sizeof(sstable_path), "%s%s%s%d%s", cf->path,
             _tidesdb_get_path_seperator(), TDB_SSTABLE_PREFIX, cf->num_sstables, TDB_SSTABLE_EXT);

    /* we create a new block manager */
    block_manager_t *sstable_block_manager = NULL;

    if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        (void)log_write(cf->tdb->log, "Column family %s failed to open block manager for flush",
                        cf->config.name);
        free(sst);
        return -1;
    }

    /* we set the block manager */
    sst->block_manager = sstable_block_manager;

    /* we figure out how large the bloom filter should be by getting amount of nodes in memtable */
    int bloom_filter_size = skip_list_count_entries(cf->memtable_sl);

    /* we initialize the bloom filter */
    bloom_filter_t *bf = NULL;
    if (bloom_filter_new(&bf, TDB_BLOOM_FILTER_P, bloom_filter_size) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we iterate over memtable and populate the bloom filter */
    skip_list_cursor_t *cursor = skip_list_cursor_init(cf->memtable_sl);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    do
    {
        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (skip_list_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size,
                                 &ttl) == -1)
        {
            free(retrieved_key);
            free(retrieved_value);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* add to bloom filter */
        (void)bloom_filter_add(bf, retrieved_key, key_size);

    } while (skip_list_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)skip_list_cursor_free(cursor);
    cursor = NULL;

    size_t serialized_bf_size;
    uint8_t *serialized_bf = bloom_filter_serialize(bf, &serialized_bf_size);
    if (serialized_bf == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    bloom_filter_free(bf);

    /* we write the bloom filter to the sstable */
    block_manager_block_t *bf_block = block_manager_block_create(serialized_bf_size, serialized_bf);
    if (bf_block == NULL)
    {
        free(sst);
        free(serialized_bf);
        (void)remove(sstable_path);
        return -1;
    }

    free(serialized_bf);

    /* we write the block to the sstable */
    if (block_manager_block_write(sst->block_manager, bf_block) == -1)
    {
        (void)block_manager_block_free(bf_block);
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we free the resources */
    (void)block_manager_block_free(bf_block);

    /* we reinitialize the cursor to populate the sstable with keyvalue pairs after bloom filter */
    cursor = skip_list_cursor_init(cf->memtable_sl);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we iterate over the memtable and write to the sstable */
    do
    {
        /* we get the key value pair */
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* we get the key */

        if (skip_list_cursor_get(cursor, &kv->key, (size_t *)&kv->key_size, &kv->value,
                                 (size_t *)&kv->value_size, &kv->ttl) == -1)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

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
            return -1;
        }

        free(kv);

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)skip_list_cursor_free(cursor);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(block);
        free(serialized_kv);

    } while (skip_list_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)skip_list_cursor_free(cursor);

    cursor = NULL;

    /* we add the sstable to the column family */
    if (cf->sstables == NULL)
    {
        cf->sstables = malloc(sizeof(tidesdb_sstable_t));
        if (cf->sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            return -1;
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
    if (skip_list_clear(cf->memtable_sl) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* truncate the wal */
    if (block_manager_truncate(cf->wal->block_manager) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    (void)log_write(cf->tdb->log, "Flushed column family %s", cf->config.name);

    return 0;
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

int _tidesdb_flush_memtable_w_bloom_filter_f_hash_table(tidesdb_column_family_t *cf)
{
    (void)log_write(cf->tdb->log, "Flushing column family %s at size %zu", cf->config.name,
                    cf->memtable_ht->total_size);

    /* similar to _tidesdb_flush_memtable but with bloom filter */

    /* we create a new sstable struct */
    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (sst == NULL) return -1;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH];
    snprintf(sstable_path, sizeof(sstable_path), "%s%s%s%d%s", cf->path,
             _tidesdb_get_path_seperator(), TDB_SSTABLE_PREFIX, cf->num_sstables, TDB_SSTABLE_EXT);

    /* we create a new block manager */
    block_manager_t *sstable_block_manager = NULL;

    if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        (void)log_write(cf->tdb->log, "Column family %s failed to open block manager for flush",
                        cf->config.name);
        free(sst);
        return -1;
    }

    /* we set the block manager */
    sst->block_manager = sstable_block_manager;

    /* we figure out how large the bloom filter should be by getting amount of nodes in memtable */
    size_t bloom_filter_size = cf->memtable_ht->count;

    /* we initialize the bloom filter */
    bloom_filter_t *bf = NULL;
    if (bloom_filter_new(&bf, TDB_BLOOM_FILTER_P, (int)bloom_filter_size) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we iterate over memtable and populate the bloom filter */
    hash_table_cursor_t *cursor = hash_table_cursor_init(cf->memtable_ht);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    do
    {
        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (hash_table_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size,
                                  &ttl) == -1)
        {
            free(retrieved_key);
            free(retrieved_value);
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* add to bloom filter */
        (void)bloom_filter_add(bf, retrieved_key, key_size);

    } while (hash_table_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)hash_table_cursor_free(cursor);
    cursor = NULL;

    size_t serialized_bf_size;
    uint8_t *serialized_bf = bloom_filter_serialize(bf, &serialized_bf_size);
    if (serialized_bf == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    bloom_filter_free(bf);

    /* we write the bloom filter to the sstable */
    block_manager_block_t *bf_block = block_manager_block_create(serialized_bf_size, serialized_bf);
    if (bf_block == NULL)
    {
        free(sst);
        free(serialized_bf);
        (void)remove(sstable_path);
        return -1;
    }

    free(serialized_bf);

    /* we write the block to the sstable */
    if (block_manager_block_write(sst->block_manager, bf_block) == -1)
    {
        (void)block_manager_block_free(bf_block);
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we free the resources */
    (void)block_manager_block_free(bf_block);

    /* we reinitialize the cursor to populate the sstable with keyvalue pairs after bloom filter */
    cursor = hash_table_cursor_init(cf->memtable_ht);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we iterate over the memtable and write to the sstable */
    do
    {
        /* we get the key value pair */
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we get the key */
        if (hash_table_cursor_get(cursor, &kv->key, (size_t *)&kv->key_size, &kv->value,
                                  (size_t *)&kv->value_size, &kv->ttl) == -1)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we serialize the key value pair */
        size_t serialized_size;
        uint8_t *serialized_kv = _tidesdb_serialize_key_value_pair(
            kv, &serialized_size, cf->config.compressed, cf->config.compress_algo);
        if (serialized_kv == NULL)
        {
            (void)_tidesdb_free_key_value_pair(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        free(kv);

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(block);
        free(serialized_kv);

    } while (hash_table_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)hash_table_cursor_free(cursor);

    cursor = NULL;

    /* we add the sstable to the column family */
    if (cf->sstables == NULL)
    {
        cf->sstables = malloc(sizeof(tidesdb_sstable_t));
        if (cf->sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            return -1;
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
    (void)hash_table_clear(cf->memtable_ht);

    /* truncate the wal */
    if (block_manager_truncate(cf->wal->block_manager) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    (void)log_write(cf->tdb->log, "Flushed column family %s", cf->config.name);

    return 0;
}

int _tidesdb_flush_memtable_f_hash_table(tidesdb_column_family_t *cf)
{
    (void)log_write(cf->tdb->log, "Flushing column family %s at size %zu", cf->config.name,
                    cf->memtable_ht->total_size);

    /* we create a new sstable struct */
    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (sst == NULL) return -1;

    /* we create a new sstable with a named based on the amount of sstables */
    char sstable_path[MAX_FILE_PATH_LENGTH];
    snprintf(sstable_path, sizeof(sstable_path), "%s%s%s%d%s", cf->path,
             _tidesdb_get_path_seperator(), TDB_SSTABLE_PREFIX, cf->num_sstables, TDB_SSTABLE_EXT);

    /* we create a new block manager */
    block_manager_t *sstable_block_manager = NULL;

    if (block_manager_open(&sstable_block_manager, sstable_path, TDB_SYNC_INTERVAL) == -1)
    {
        (void)log_write(cf->tdb->log, "Column family %s failed to open block manager for flush",
                        cf->config.name);
        free(sst);
        return -1;
    }

    /* we set the block manager */
    sst->block_manager = sstable_block_manager;

    /* we create a new hash table cursor and populate the memtable
     * with serialized key value pairs */

    hash_table_cursor_t *cursor = hash_table_cursor_init(cf->memtable_ht);
    if (cursor == NULL)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    /* we iterate over the memtable and write to the sstable */
    do
    {
        /* we get the key value pair */
        tidesdb_key_value_pair_t *kv = malloc(sizeof(tidesdb_key_value_pair_t));
        if (kv == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we get the key */

        uint8_t *retrieved_key;
        size_t key_size;
        uint8_t *retrieved_value;
        size_t value_size;
        time_t ttl;
        if (hash_table_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size,
                                  &ttl) == -1)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we copy the key */
        kv->key = malloc(key_size);
        if (kv->key == NULL)
        {
            free(kv);
            free(sst);
            (void)remove(sstable_path);
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
            remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        (void)_tidesdb_free_key_value_pair(kv);

        /* we create a new block */
        block_manager_block_t *block = block_manager_block_create(serialized_size, serialized_kv);
        if (block == NULL)
        {
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we write the block to the sstable */
        if (block_manager_block_write(sst->block_manager, block) == -1)
        {
            (void)block_manager_block_free(block);
            free(sst);
            free(serialized_kv);
            (void)remove(sstable_path);
            (void)hash_table_cursor_free(cursor);
            return -1;
        }

        /* we free the resources */
        (void)block_manager_block_free(block);
        free(serialized_kv);

    } while (hash_table_cursor_next(cursor) != -1);

    /* we free the cursor */
    (void)hash_table_cursor_free(cursor);

    /* we add the sstable to the column family */
    if (cf->sstables == NULL)
    {
        cf->sstables = malloc(sizeof(tidesdb_sstable_t));
        if (cf->sstables == NULL)
        {
            free(sst);
            (void)remove(sstable_path);
            return -1;
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
    (void)hash_table_clear(cf->memtable_ht);

    /* truncate the wal */
    if (block_manager_truncate(cf->wal->block_manager) == -1)
    {
        free(sst);
        (void)remove(sstable_path);
        return -1;
    }

    (void)log_write(cf->tdb->log, "Flushed column family %s", cf->config.name);

    return 0;
}

tidesdb_err_t *tidesdb_start_background_partial_merge(tidesdb_t *tdb,
                                                      const char *column_family_name, int seconds,
                                                      int min_sstables)
{
    /* we check if tidesdb is NULL */
    if (tdb == NULL) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);

    /* we check column family name */
    if (column_family_name == NULL)
        return tidesdb_err_from_code(TIDESDB_ERR_INVALID_NAME, "column family");

    /* we check if seconds is > 0 */
    if (seconds <= 0) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_PARTIAL_MERGE_INTERVAL);

    /* we check if min_sstables is at least 2 */
    if (min_sstables < 2) return tidesdb_err_from_code(TIDESDB_ERR_INVALID_PARTIAL_MERGE_MIN_SST);

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

    /* we check if column family is already partially merging */
    if (cf->partial_merging)
    {
        (void)pthread_rwlock_unlock(&tdb->rwlock);
        return tidesdb_err_from_code(TIDESDB_ERR_PARTIAL_MERGE_ALREADY_STARTED, column_family_name);
    }

    /* we unlock the db read lock */
    if (pthread_rwlock_unlock(&tdb->rwlock) != 0)
    {
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "db");
    }

    tidesdb_partial_merge_thread_args_t *args = malloc(sizeof(tidesdb_partial_merge_thread_args_t));
    if (args == NULL) return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);

    args->cf = cf;
    args->tdb = tdb;

    pthread_mutex_t *lock = malloc(sizeof(pthread_mutex_t)); /* shared lock for unique file names */
    if (lock == NULL)
    {
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_MEMORY_ALLOC);
    }
    pthread_mutex_init(lock, NULL);
    args->lock = lock;

    /* we lock column family for writes temporarily */
    if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
    {
        pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK, "column family");
    }

    /* setup partial merge on column family */
    cf->partial_merge_interval = seconds;
    cf->partial_merge_min_sstables = min_sstables;
    cf->partial_merging = true;

    /* we unlock the column family */
    if (pthread_rwlock_unlock(&cf->rwlock) != 0)
    {
        pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_FAILED_TO_RELEASE_LOCK, "column family");
    }

    /* we create a new thread */
    if (pthread_create(&cf->partial_merge_thread, NULL, _tidesdb_partial_merge_thread, args) != 0)
    {
        pthread_mutex_destroy(lock);
        free(lock);
        free(args);
        return tidesdb_err_from_code(TIDESDB_ERR_THREAD_CREATION_FAILED);
    }

    /* we return success */
    return NULL;
}

void *_tidesdb_partial_merge_thread(void *arg)
{
    tidesdb_partial_merge_thread_args_t *args = (tidesdb_partial_merge_thread_args_t *)arg;
    tidesdb_column_family_t *cf = args->cf;

    while (cf->partial_merging)
    {
        sleep(cf->partial_merge_interval); /* sleep for interval */

        /* we lock column family for reads temporarily */
        if (pthread_rwlock_rdlock(&cf->rwlock) != 0)
        {
            continue;
        }

        /* we check if sstables is at minimum */
        if (cf->num_sstables < cf->partial_merge_min_sstables)
        {
            (void)pthread_rwlock_unlock(&cf->rwlock);
            continue;
        }

        /* we unlock the column family */
        (void)pthread_rwlock_unlock(&cf->rwlock);

        for (int sst_idx = 0; sst_idx < cf->num_sstables - 1; sst_idx += 2)
        {
            tidesdb_sstable_t *merged_sstable;
            /* merge SSTables i and j */

            if (cf->config.bloom_filter == false)
            {
                merged_sstable = _tidesdb_merge_sstables(cf->sstables[sst_idx],
                                                         cf->sstables[sst_idx + 1], cf, args->lock);
            }
            else
            {
                merged_sstable = _tidesdb_merge_sstables_w_bloom_filter(
                    cf->sstables[sst_idx], cf->sstables[sst_idx + 1], cf, args->lock);
            }

            /* lock column family for writes */
            if (pthread_rwlock_wrlock(&cf->rwlock) != 0)
            {
                continue;
            }

            /* remove old sstable files */
            char sstable_path1[MAX_FILE_PATH_LENGTH];
            char sstable_path2[MAX_FILE_PATH_LENGTH];

            /* get the sstable paths */
            (void)snprintf(sstable_path1, MAX_FILE_PATH_LENGTH, "%s",
                           cf->sstables[sst_idx]->block_manager->file_path);
            (void)snprintf(sstable_path2, MAX_FILE_PATH_LENGTH, "%s",
                           cf->sstables[sst_idx + 1]->block_manager->file_path);

            /* free the old sstables */
            (void)_tidesdb_free_sstable(cf->sstables[sst_idx]);
            (void)_tidesdb_free_sstable(cf->sstables[sst_idx + 1]);

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
            if (block_manager_open(&merged_sstable->block_manager, sstable_path1,
                                   TDB_SYNC_INTERVAL) == -1)
            {
                (void)pthread_rwlock_unlock(&cf->rwlock);
                free(args);
                return NULL;
            }

            /* replace the old sstables with the new one */
            cf->sstables[sst_idx] = merged_sstable;
            cf->sstables[sst_idx + 1] = NULL;

            /* remove the sstables that were compacted
             * the ones that are NULL; one would be null the ith+1 sstable
             */
            int j = 0;
            for (int i = 0; i < cf->num_sstables; i++)
            {
                if (cf->sstables[i] != NULL) cf->sstables[j++] = cf->sstables[i];
            }

            cf->num_sstables = j;

            /* we unlock the column family */
            (void)pthread_rwlock_unlock(&cf->rwlock);
        }
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
    /* we create two cursors for the block managers */
    block_manager_cursor_t *cursor1, *cursor2;
    block_manager_block_t *block1 = NULL, *block2 = NULL;
    bool processed1 = false, processed2 = false;

    /* we initialize the cursors */
    if (block_manager_cursor_init(&cursor1, bm1) != 0) return -1;
    if (block_manager_cursor_init(&cursor2, bm2) != 0) return -1;

    /* we iterate over the blocks */
    while (block_manager_cursor_has_next(cursor1) || block_manager_cursor_has_next(cursor2))
    {
        /* read the blocks */
        if (!processed1 && block1 == NULL && block_manager_cursor_has_next(cursor1))
        {
            (void)block_manager_cursor_next(cursor1);
            block1 = block_manager_cursor_read(cursor1);
        }

        if (!processed2 && block2 == NULL && block_manager_cursor_has_next(cursor2))
        {
            (void)block_manager_cursor_next(cursor2);
            block2 = block_manager_cursor_read(cursor2);
        }

        /* deserialize the blocks into key value pairs */
        tidesdb_key_value_pair_t *kv1 =
            block1
                ? _tidesdb_deserialize_key_value_pair(
                      block1->data, block1->size, cf->config.compressed, cf->config.compress_algo)
                : NULL;

        tidesdb_key_value_pair_t *kv2 =
            block2
                ? _tidesdb_deserialize_key_value_pair(
                      block2->data, block2->size, cf->config.compressed, cf->config.compress_algo)
                : NULL;

        /* check if kv1 is a tombstone or expired */
        if (kv1 &&
            (_tidesdb_is_tombstone(kv1->value, kv1->value_size) || _tidesdb_is_expired(kv1->ttl)))
        {
            block_manager_block_free(block1);
            block1 = NULL;
            processed1 = false;
            continue;
        }

        /* check if kv2 is a tombstone or expired */
        if (kv2 &&
            (_tidesdb_is_tombstone(kv2->value, kv2->value_size) || _tidesdb_is_expired(kv2->ttl)))
        {
            block_manager_block_free(block2);
            block2 = NULL;
            processed2 = false;
            continue;
        }

        /* compare the key value pairs */
        if (block1 && (!block2 || memcmp(kv1->key, kv2->key, kv1->key_size) < 0))
        {
            if (block_manager_block_write(bm_out, block1) == -1)
            {
                block_manager_block_free(block1);
                block_manager_block_free(block2);
                (void)block_manager_cursor_free(cursor1);
                (void)block_manager_cursor_free(cursor2);
                return -1;
            }
            block_manager_block_free(block1);
            block1 = NULL;
            processed1 = false;
            processed2 = true;
        }
        else
        {
            if (block_manager_block_write(bm_out, block2) == -1)
            {
                block_manager_block_free(block1);
                block_manager_block_free(block2);
                (void)block_manager_cursor_free(cursor1);
                (void)block_manager_cursor_free(cursor2);
                return -1;
            }
            block_manager_block_free(block2);
            block2 = NULL;
            processed1 = true;
            processed2 = false;
        }
    }

    (void)block_manager_cursor_free(cursor1);
    (void)block_manager_cursor_free(cursor2);

    return 0;
}