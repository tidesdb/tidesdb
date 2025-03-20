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

void test_tidesdb_serialize_deserialize_key_value_pair(bool compress,
                                                       tidesdb_compression_algo_t algo)

{
    tidesdb_key_value_pair_t *kv = _tidesdb_key_value_pair_new(
        (const uint8_t *)"test_key", 8, (const uint8_t *)"test_value", 10, 1000);
    size_t serialized_size;
    uint8_t *serialized = _tidesdb_serialize_key_value_pair(kv, &serialized_size, compress, algo);
    assert(serialized != NULL);

    tidesdb_key_value_pair_t *deserialized =
        _tidesdb_deserialize_key_value_pair(serialized, serialized_size, compress, algo);
    assert(deserialized != NULL);

    assert(deserialized->key_size == kv->key_size);
    assert(deserialized->value_size == kv->value_size);
    assert(deserialized->ttl == kv->ttl);
    assert(memcmp(deserialized->key, kv->key, kv->key_size) == 0);
    assert(memcmp(deserialized->value, kv->value, kv->value_size) == 0);

    (void)_tidesdb_free_key_value_pair(kv);
    (void)_tidesdb_free_key_value_pair(deserialized);
    free(serialized);

    printf(GREEN "test_tidesdb_serialize_deserialize_key_value_pair %s passed\n" RESET,
           compress ? "with compression" : "");
}

void test_tidesdb_serialize_deserialize_column_family_config()
{
    tidesdb_column_family_config_t config = {
        .name = "test_family",
        .flush_threshold = 100,
        .max_level = 12,
        .probability = 0.24f,
        .compressed = true,
        .compress_algo = TDB_COMPRESS_LZ4,
        .bloom_filter = false,
    };

    size_t serialized_size;
    uint8_t *serialized = _tidesdb_serialize_column_family_config(&config, &serialized_size);
    assert(serialized != NULL);

    tidesdb_column_family_config_t *deserialized =
        _tidesdb_deserialize_column_family_config(serialized);
    assert(deserialized != NULL);

    assert(strcmp(deserialized->name, config.name) == 0);
    assert(deserialized->flush_threshold == config.flush_threshold);
    assert(deserialized->max_level == config.max_level);
    assert(deserialized->probability == config.probability);
    assert(deserialized->compressed == config.compressed);
    assert(deserialized->bloom_filter == config.bloom_filter);
    assert(deserialized->compress_algo == config.compress_algo);

    free(deserialized->name);
    free(deserialized);
    free(serialized);

    printf(GREEN "test_tidesdb_serialize_deserialize_column_family_config passed\n" RESET);
}

void test_tidesdb_serialize_deserialize_sst_min_max()
{
    const uint8_t min_key[] = {0x01, 0x02, 0x03, 0x04};
    size_t min_key_size = sizeof(min_key);
    const uint8_t max_key[] = {0x09, 0x08, 0x07, 0x06, 0x05};
    size_t max_key_size = sizeof(max_key);

    size_t serialized_size;
    uint8_t *serialized = _tidesdb_serialize_sst_min_max(min_key, min_key_size,
                                                        max_key, max_key_size,
                                                        &serialized_size);
    assert(serialized != NULL);

    size_t expected_size = sizeof(size_t) + min_key_size + sizeof(size_t) + max_key_size;
    assert(serialized_size == expected_size);

    tidesdb_sst_min_max *deserialized = _tidesdb_deserialize_sst_min_max(serialized);
    assert(deserialized != NULL);

    assert(deserialized->min_key_size == min_key_size);
    assert(deserialized->max_key_size == max_key_size);
    assert(memcmp(deserialized->min_key, min_key, min_key_size) == 0);
    assert(memcmp(deserialized->max_key, max_key, max_key_size) == 0);

    // Free allocated memory
    free(deserialized->min_key);
    free(deserialized->max_key);
    free(deserialized);
    free(serialized);

    printf(GREEN "test_tidesdb_serialize_deserialize_sst_min_max passed\n" RESET);
}

void test_tidesdb_serialize_deserialize_operation(bool compress, tidesdb_compression_algo_t algo)
{
    tidesdb_key_value_pair_t *kv = _tidesdb_key_value_pair_new(
        (const uint8_t *)"test_key", 8, (const uint8_t *)"test_value", 10, 1000);
    tidesdb_operation_t op = {.op_code = TIDESDB_OP_PUT, .kv = kv, .cf_name = "test_cf"};

    size_t serialized_size;
    uint8_t *serialized = _tidesdb_serialize_operation(&op, &serialized_size, compress, algo);
    assert(serialized != NULL);

    tidesdb_operation_t *deserialized =
        _tidesdb_deserialize_operation(serialized, serialized_size, compress, algo);
    assert(deserialized != NULL);

    assert(deserialized->op_code == op.op_code);
    assert(strcmp(deserialized->cf_name, op.cf_name) == 0);
    assert(deserialized->kv->key_size == kv->key_size);
    assert(deserialized->kv->value_size == kv->value_size);
    assert(deserialized->kv->ttl == kv->ttl);
    assert(memcmp(deserialized->kv->key, kv->key, kv->key_size) == 0);
    assert(memcmp(deserialized->kv->value, kv->value, kv->value_size) == 0);

    (void)_tidesdb_free_key_value_pair(kv);
    (void)_tidesdb_free_operation(deserialized);
    free(serialized);

    printf(GREEN "test_tidesdb_serialize_deserialize_operation %s passed\n" RESET,
           compress ? "with compression" : "");
}

void test_tidesdb_tidesdb_open_close()
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_tidesdb_open_close passed\n" RESET);
}

void test_tidesdb_create_drop_column_family(bool compress, tidesdb_compression_algo_t algo,
                                            bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_create_column_family(db, "test_cf2", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    tidesdb_column_family_t *cf = NULL;
    if (_tidesdb_get_column_family(db, "test_cf", &cf) != 0)
    {
        printf(RED "Failed to get column family\n" RESET);
    }

    assert(cf != NULL);

    tidesdb_column_family_t *cf2 = NULL;
    if (_tidesdb_get_column_family(db, "test_cf2", &cf2) != 0)
    {
        printf(RED "Failed to get column family\n" RESET);
    }

    assert(cf2 != NULL);

    err = tidesdb_drop_column_family(db, "test_cf");
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_drop_column_family(db, "test_cf2");
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_create_drop_column_family%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_get_memtable(bool compress, tidesdb_compression_algo_t algo,
                                   bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_create_column_family(db, "test_cf2", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we should be able to get the value */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    free(retrieved_value);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_get_memtable%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

/* we put a value, we close the db, we reopen it and we should be able to get the value as the write
 * ahead log for the column family should be replayed */
void test_tidesdb_put_close_replay_get(bool compress, tidesdb_compression_algo_t algo,
                                       bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }

    assert(err == NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }
    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }
    assert(err == NULL);

    db = NULL;

    err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }

    assert(err == NULL);

    /* now we should be able to get the value */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }
    assert(err == NULL);

    free(retrieved_value);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(err);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_close_replay_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_get(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we will put 2 large values in the memtable, the memtable will be flushed to disk and we
     * should be able to get the values */

    /* the set memtable size is 1MB, we will put 2 values of 512KB */
    uint8_t key[] = "test_key";
    uint8_t value[512 * 1024];

    /* we fill the value with random data */
    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key2[] = "test_key2";
    uint8_t value2[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we put one more key which should be in the memtable */

    uint8_t key3[] = "test_key2";
    uint8_t value3[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value3[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we should be able to get all the values */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_get(db, "test_cf", key2, sizeof(key2), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value2, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_get(db, "test_cf", key3, sizeof(key3), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value3, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_range(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    err = tidesdb_put(db, "test_cf", key1, sizeof(key1), value1, sizeof(value1), -1);
    assert(err == NULL);

    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    assert(err == NULL);

    uint8_t key3[] = "key3";
    uint8_t value3[] = "value3";
    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    assert(err == NULL);

    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;
    err =
        tidesdb_range(db, "test_cf", key1, sizeof(key1), key3, sizeof(key3), &result, &result_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    assert(result_size == 3);
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_range%s%s passed\n" RESET, compress ? " with compression" : "",
           bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_range_mem_disk(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key1[] = "key1";
    uint8_t value1[1024 * 1024] = "value1";
    err = tidesdb_put(db, "test_cf", key1, sizeof(key1), value1, sizeof(value1), -1);
    assert(err == NULL);

    uint8_t key2[] = "key2";
    uint8_t value2[1024 * 1024] = "value2";
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    assert(err == NULL);

    uint8_t key3[] = "key3";
    uint8_t value3[1024 * 1024] = "value3";
    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    assert(err == NULL);

    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;
    err =
        tidesdb_range(db, "test_cf", key1, sizeof(key1), key3, sizeof(key3), &result, &result_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    assert(result_size == 3);
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_range_mem_disk%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

/* for test_tidesdb_filter */
bool comparison_method(const tidesdb_key_value_pair_t *kv)
{
    uint8_t key2[] = "key2";
    return kv->key_size == sizeof(key2) && memcmp(kv->key, key2, sizeof(key2)) == 0;
}

void test_tidesdb_filter(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    err = tidesdb_put(db, "test_cf", key1, sizeof(key1), value1, sizeof(value1), -1);
    assert(err == NULL);

    uint8_t key2[] = "key2";
    uint8_t value2[] = "value2";
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    assert(err == NULL);

    uint8_t key3[] = "key3";
    uint8_t value3[] = "value3";
    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    assert(err == NULL);

    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;
    err = tidesdb_filter(db, "test_cf", comparison_method, &result, &result_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    assert(result_size == 1);
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_filter%s%s passed\n" RESET, compress ? " with compression" : "",
           bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_filter_mem_disk(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key1[] = "key1";
    uint8_t value1[1024 * 1024] = "value1";
    err = tidesdb_put(db, "test_cf", key1, sizeof(key1), value1, sizeof(value1), -1);
    assert(err == NULL);

    uint8_t key2[] = "key2";
    uint8_t value2[1024 * 1024] = "value2";
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    assert(err == NULL);

    uint8_t key3[] = "key3";
    uint8_t value3[1024 * 1024] = "value3";
    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    assert(err == NULL);

    tidesdb_key_value_pair_t **result = NULL;
    size_t result_size = 0;
    err = tidesdb_filter(db, "test_cf", comparison_method, &result, &result_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    assert(result_size == 1);
    for (size_t i = 0; i < result_size; i++)
    {
        free(result[i]->key);
        free(result[i]->value);
        free(result[i]);
    }
    free(result);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_filter_mem_disk%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_close_get(bool compress, tidesdb_compression_algo_t algo,
                                      bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we will put 2 large values in the memtable, the memtable will be flushed to disk and we
     * should be able to get the values */

    /* the set memtable size is 1MB, we will put 2 values of 512KB */
    uint8_t key[] = "test_key";
    uint8_t value[512 * 1024];

    /* we fill the value with random data */
    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key2[] = "test_key2";
    uint8_t value2[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we put one more key which should be in the memtable */

    uint8_t key3[] = "test_key2";
    uint8_t value3[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value3[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    db = NULL;

    err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we should be able to get all the values */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_get(db, "test_cf", key2, sizeof(key2), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value2, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_get(db, "test_cf", key3, sizeof(key3), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value3, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_close_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_delete_get(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_create_column_family(db, "test_cf2", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we should be able to get the value */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    free(retrieved_value);

    err = tidesdb_delete(db, "test_cf", key, sizeof(key));
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* the value should not be there anymore */
    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    assert(err != NULL), tidesdb_err_free(err);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_delete_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_delete_get(bool compress, tidesdb_compression_algo_t algo,
                                       bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we will put 2 large values in the memtable, the memtable will be flushed to disk and we
     * should be able to get the values */

    /* the set memtable size is 1MB, we will put 2 values of 512KB */
    uint8_t key[] = "test_key";
    uint8_t value[512 * 1024];

    /* we fill the value with random data */
    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key2[] = "test_key2";
    uint8_t value2[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we put one more key which should be in the memtable */

    uint8_t key3[] = "test_key2";
    uint8_t value3[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value3[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we should be able to get all the values */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value, retrieved_value, value_size);
    free(retrieved_value);

    err = tidesdb_get(db, "test_cf", key2, sizeof(key2), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    memcpy(value2, retrieved_value, value_size);
    free(retrieved_value);

    /* we will delete key3 */
    err = tidesdb_delete(db, "test_cf", key3, sizeof(key3));
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    err = tidesdb_get(db, "test_cf", key3, sizeof(key3), &retrieved_value, &value_size);
    assert(err != NULL), tidesdb_err_free(err);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_delete_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_many_flush_get(bool compress, tidesdb_compression_algo_t algo,
                                     bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[20];
    uint8_t value[1024 * 1024];

    /* Fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* Put 12 keys which would be 12 sstables */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
    }

    /* we will put one more key which should be in the memtable */
    snprintf((char *)key, sizeof(key), "key_%d", 12);
    uint8_t value2[128];
    for (size_t i = 0; i < sizeof(value2); i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we check all keys */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t value_size;

        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        free(retrieved_value);
    }

    /* check last key */
    snprintf((char *)key, sizeof(key), "key_%d", 12);

    uint8_t *retrieved_value2 = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value2, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    free(retrieved_value2);

    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_many_flush_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_compact_get(bool compress, tidesdb_compression_algo_t algo,
                                        bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[20];
    uint8_t value[1024 * 1024];

    /* fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* put 12 keys which would be 12 sstables */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
    }

    /* now we compact the column family */
    err = tidesdb_compact_sstables(db, "test_cf", 2);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we will put one more key which should be in the memtable */
    snprintf((char *)key, sizeof(key), "key_%d", 12);
    uint8_t value2[128];
    for (size_t i = 0; i < sizeof(value2); i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we check all keys */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t value_size;

        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        free(retrieved_value);
    }

    /* check last key */
    snprintf((char *)key, sizeof(key), "key_%d", 12);

    uint8_t *retrieved_value2 = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value2, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    free(retrieved_value2);

    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_compact_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_txn_put_get(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    tidesdb_txn_t *txn = NULL;
    err = tidesdb_txn_begin(db, &txn, "test_cf");
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    err = tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_commit(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_free(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* now we should be able to get the value */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    free(retrieved_value);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_txn_put_get%s%s passed\n" RESET, compress ? " with compression" : "",
           bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_txn_put_get_rollback_get(bool compress, tidesdb_compression_algo_t algo,
                                           bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    tidesdb_txn_t *txn = NULL;
    err = tidesdb_txn_begin(db, &txn, "test_cf");
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[] = "test_key";
    uint8_t value[] = "test_value";
    err = tidesdb_txn_put(txn, key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_commit(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* now we should be able to get the value */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    free(retrieved_value);

    /* now we rollback the transaction */
    err = tidesdb_txn_rollback(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we should not be able to get the value anymore */
    err = tidesdb_get(db, "test_cf", key, sizeof(key), &retrieved_value, &value_size);
    assert(err != NULL), tidesdb_err_free(err);

    err = tidesdb_txn_free(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_txn_put_get_rollback_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_txn_put_put_delete_get(bool compress, tidesdb_compression_algo_t algo,
                                         bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    tidesdb_txn_t *txn = NULL;
    err = tidesdb_txn_begin(db, &txn, "test_cf");
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key1[] = "test_key1";
    uint8_t value1[] = "test_value1";
    err = tidesdb_txn_put(txn, key1, sizeof(key1), value1, sizeof(value1), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key2[] = "test_key2";
    uint8_t value2[] = "test_value2";
    err = tidesdb_txn_put(txn, key2, sizeof(key2), value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_delete(txn, key1, sizeof(key1));
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_commit(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    err = tidesdb_txn_free(txn);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* now we should be able to get the value for key2 */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key2, sizeof(key2), &retrieved_value, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    free(retrieved_value);

    /* key1 should not be found */
    err = tidesdb_get(db, "test_cf", key1, sizeof(key1), &retrieved_value, &value_size);
    assert(err != NULL), tidesdb_err_free(err);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_txn_put_put_delete_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

/* mainly test going forward and backwards through column family memtable
 * no bloom filter or compression */
void test_tidesdb_cursor(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;
    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    assert(err == NULL);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024 * 4, 12, 0.24f, compress, algo,
                                       bloom_filter);
    assert(err == NULL);

    uint8_t keys[11][20];
    uint8_t values[11][256 * 1024];

    /* fill the values with random data */
    for (int i = 0; i < 11; i++)
    {
        for (size_t j = 0; j < sizeof(values[i]); j++)
        {
            values[i][j] = (uint8_t)(rand() % 256);
        }
    }

    /* put 11 keys to trigger flushes */
    for (int i = 0; i < 11; i++)
    {
        snprintf((char *)keys[i], sizeof(keys[i]), "test_key_%d", i);
        /*printf("putting key: %s\n", keys[i]);*/
        err =
            tidesdb_put(db, "test_cf", keys[i], sizeof(keys[i]), values[i], sizeof(values[i]), -1);
        assert(err == NULL);
    }

    /* create a cursor */
    tidesdb_cursor_t *cursor = NULL;
    err = tidesdb_cursor_init(db, "test_cf", &cursor);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* iterate through the keys using the cursor */
    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    bool found[11] = {false};

    do
    {
        err = tidesdb_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            assert(err == NULL);
        }

        if (retrieved_key != NULL)
        {
            /*printf("retrieved key: %s\n", retrieved_key);*/
            /* check if the key is one of the keys we put */
            bool key_found = false;
            for (int i = 0; i < 11; i++)
            {
                if (memcmp(retrieved_key, keys[i], key_size) == 0)
                {
                    key_found = true;
                    found[i] = true;
                    break;
                }
            }

            free(retrieved_key);
            free(retrieved_value);

            if (!key_found)
            {
                printf(RED "Key not found in the list: %s\n" RESET, retrieved_key);
            }

            assert(key_found);
        }
    } while ((err = tidesdb_cursor_next(cursor)) == NULL ||
             err->code != TIDESDB_ERR_AT_END_OF_CURSOR);

    if (err != NULL)
    {
        (void)tidesdb_err_free(err);
    }

    /* ensure all values were found */
    for (int i = 0; i < 11; i++)
    {
        if (!found[i])
        {
            printf(RED "Key not found: %s\n" RESET, keys[i]);
        }
        assert(found[i]);
    }

    /* now we go in reverse */
    /* we make sure to reset all found values to false */
    for (int i = 0; i < 11; i++)
    {
        found[i] = false;
    }

    /* we use prev */
    do
    {
        err = tidesdb_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            assert(err == NULL);
        }

        if (retrieved_key != NULL)
        {
            /* check if the key is one of the keys we put */
            bool key_found = false;
            for (int i = 0; i < 11; i++)
            {
                if (memcmp(retrieved_key, keys[i], key_size) == 0)
                {
                    key_found = true;
                    found[i] = true;
                    break;
                }
            }

            free(retrieved_key);
            free(retrieved_value);

            if (!key_found)
            {
                printf(RED "Key not found in the list: %s\n" RESET, retrieved_key);
            }

            assert(key_found);
        }
    } while ((err = tidesdb_cursor_prev(cursor)) == NULL ||
             err->code != TIDESDB_ERR_AT_START_OF_CURSOR);
    (void)tidesdb_err_free(err);

    /* ensure all values were found */
    for (int i = 0; i < 11; i++)
    {
        if (!found[i])
        {
            printf(RED "Key not found: %s\n" RESET, keys[i]);
        }
        assert(found[i]);
    }

    err = tidesdb_cursor_free(cursor);
    assert(err == NULL);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor%s%s passed\n" RESET, compress ? " with compression" : "",
           bloom_filter ? " with bloom filter" : "");
}

/* we flush multiple sstables and iterate through them
 * forward and backwards validating */
void test_tidesdb_cursor_memtable_sstables(bool compress, tidesdb_compression_algo_t algo,
                                           bool bloom_filter)
{
    tidesdb_t *db = NULL;
    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    assert(err == NULL);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    assert(err == NULL);

    uint8_t keys[11][20];
    uint8_t values[11][256];

    /* fill the values with random data */
    for (int i = 0; i < 11; i++)
    {
        for (size_t j = 0; j < sizeof(values[i]); j++)
        {
            values[i][j] = (uint8_t)(rand() % 256);
        }
    }

    /* put 11 keys to trigger flushes */
    for (int i = 0; i < 11; i++)
    {
        snprintf((char *)keys[i], sizeof(keys[i]), "test_key_%d", i);
        /*printf("putting key: %s\n", keys[i]);*/
        err =
            tidesdb_put(db, "test_cf", keys[i], sizeof(keys[i]), values[i], sizeof(values[i]), -1);
        assert(err == NULL);
    }

    /* create a cursor */
    tidesdb_cursor_t *cursor = NULL;
    err = tidesdb_cursor_init(db, "test_cf", &cursor);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* iterate through the keys using the cursor */
    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    bool found[11] = {false};

    do
    {
        err = tidesdb_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            assert(err == NULL);
        }

        if (retrieved_key != NULL)
        {
            /*printf("retrieved key: %s\n", retrieved_key);*/
            /* check if the key is one of the keys we put */
            bool key_found = false;
            for (int i = 0; i < 11; i++)
            {
                if (memcmp(retrieved_key, keys[i], key_size) == 0)
                {
                    key_found = true;
                    found[i] = true;
                    break;
                }
            }

            free(retrieved_key);
            free(retrieved_value);

            if (!key_found)
            {
                printf(RED "Key not found in the list: %s\n" RESET, retrieved_key);
            }

            assert(key_found);
        }
    } while ((err = tidesdb_cursor_next(cursor)) == NULL ||
             err->code != TIDESDB_ERR_AT_END_OF_CURSOR);

    (void)tidesdb_err_free(err);

    /* ensure all values were found */
    for (int i = 0; i < 11; i++)
    {
        if (!found[i])
        {
            printf(RED "Key not found: %s\n" RESET, keys[i]);
        }
        assert(found[i]);
    }

    /* now we go in reverse */
    /* we make sure to reset all found values to false */
    for (int i = 0; i < 11; i++)
    {
        found[i] = false;
    }

    /* we use prev */
    do
    {
        err = tidesdb_cursor_get(cursor, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            assert(err == NULL);
        }

        if (retrieved_key != NULL)
        {
            /*printf("retrieved key: %s\n", retrieved_key);*/
            /* check if the key is one of the keys we put */
            bool key_found = false;
            for (int i = 0; i < 11; i++)
            {
                if (memcmp(retrieved_key, keys[i], key_size) == 0)
                {
                    key_found = true;
                    found[i] = true;
                    break;
                }
            }

            if (!key_found)
            {
                printf(RED "Key not found in the list: %s\n" RESET, retrieved_key);
            }

            assert(key_found);

            free(retrieved_key);
            free(retrieved_value);
        }
    } while ((err = tidesdb_cursor_prev(cursor)) == NULL ||
             err->code != TIDESDB_ERR_AT_START_OF_CURSOR);

    /* ensure all values were found */
    for (int i = 0; i < 11; i++)
    {
        if (!found[i])
        {
            printf(RED "Key not found: %s\n" RESET, keys[i]);
        }
        assert(found[i]);
    }

    (void)tidesdb_err_free(err);

    err = tidesdb_cursor_free(cursor);
    assert(err == NULL);

    err = tidesdb_close(db);
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor_memtable_sstables%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_start_partial_merge(bool compress, tidesdb_compression_algo_t algo,
                                      bool bloom_filter)
{
    tidesdb_t *db = NULL;
    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    assert(err == NULL);
    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    assert(err == NULL);
    (void)tidesdb_err_free(err);

    /* start partial merging in background */
    err = tidesdb_start_background_partial_merge(db, "test_cf", 1, 10);
    assert(err == NULL);
    (void)tidesdb_err_free(err);

    uint8_t key[20];
    uint8_t value[1024 * 1024];

    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        assert(err == NULL);
        (void)tidesdb_err_free(err);
    }

    sleep(10);

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t value_size;
        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
        free(retrieved_value);
        (void)tidesdb_err_free(err);
    }

    err = tidesdb_close(db);
    assert(err == NULL);
    (void)tidesdb_err_free(err);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_start_partial_merge%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_stat(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we will put 2 large values in the memtable, the memtable will be flushed to disk and we
     * should be able to get the values */

    /* the set memtable size is 1MB, we will put 2 values of 512KB */
    uint8_t key[] = "test_key";
    uint8_t value[512 * 1024];

    /* we fill the value with random data */
    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key, sizeof(key), value, sizeof(value), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key2[] = "test_key2";
    uint8_t value2[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key2, sizeof(key2), value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we put one more key which should be in the memtable */

    uint8_t key3[] = "test_key2";
    uint8_t value3[512 * 1024];

    for (size_t i = 0; i < 512 * 1024; i++)
    {
        value3[i] = (uint8_t)(rand() % 256);
    }

    err = tidesdb_put(db, "test_cf", key3, sizeof(key3), value3, sizeof(value3), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    /* we get stat for column family */
    tidesdb_column_family_stat_t *stat = NULL;
    err = tidesdb_get_column_family_stat(db, "test_cf", &stat);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we check if stat is null */
    assert(stat != NULL);

    /* we should have 1 sstable */
    assert(stat->num_sstables == 1);

    /* we should have 1 memtable entry */
    assert(stat->memtable_entries_count == 1);
    (void)tidesdb_free_column_family_stat(stat);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_stat%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_put_flush_shutdown_compact_get(bool compress, tidesdb_compression_algo_t algo,
                                                 bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[20];
    uint8_t value[1024 * 1024];

    /* Fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* Put 12 keys which would be 12 sstables */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
    }

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we compact the column family */
    err = tidesdb_compact_sstables(db, "test_cf", 2);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we will put one more key which should be in the memtable */
    snprintf((char *)key, sizeof(key), "key_%d", 12);
    uint8_t value2[128];
    for (size_t i = 0; i < sizeof(value2); i++)
    {
        value2[i] = (uint8_t)(rand() % 256);
    }

    /* we put the second value */
    err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value2, sizeof(value2), -1);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* now we check all keys */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        uint8_t *retrieved_value = NULL;
        size_t value_size;

        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        free(retrieved_value);
    }

    /* check last key */
    snprintf((char *)key, sizeof(key), "key_%d", 12);

    uint8_t *retrieved_value2 = NULL;
    size_t value_size;

    err = tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value2, &value_size);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    free(retrieved_value2);

    assert(err == NULL);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_flush_shutdown_compact_get%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

/* for concurrency tests */
#define NUM_THREADS         4   /* n of threads */
#define NUM_KEYS_PER_THREAD 100 /* n of keys per thread */

/*
 * thread_data_t
 * used for concurrent tests
 */
typedef struct
{
    tidesdb_t *db;
    const char *cf_name;
    int thread_id;
} thread_data_t;

void *put_operation(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    char key[20];
    char value[20];
    tidesdb_err_t *err;

    for (int i = 0; i < NUM_KEYS_PER_THREAD; i++)
    {
        (void)snprintf(key, sizeof(key), "key_%d_%d", data->thread_id, i);
        (void)snprintf(value, sizeof(value), "value_%d_%d", data->thread_id, i);
        err = tidesdb_put(data->db, data->cf_name, (uint8_t *)key, strlen(key) + 1,
                          (uint8_t *)value, strlen(value) + 1, -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
    }

    (void)pthread_exit(NULL);
}

void *get_operation(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    char key[20];
    char expected_value[20];
    uint8_t *retrieved_value = NULL;
    size_t value_size;
    tidesdb_err_t *err;

    for (int i = 0; i < NUM_KEYS_PER_THREAD; i++)
    {
        (void)snprintf(key, sizeof(key), "key_%d_%d", data->thread_id, i);
        (void)snprintf(expected_value, sizeof(expected_value), "value_%d_%d", data->thread_id, i);
        err = tidesdb_get(data->db, data->cf_name, (uint8_t *)key, strlen(key) + 1,
                          &retrieved_value, &value_size);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            assert(err == NULL);
        }
        assert(memcmp(retrieved_value, expected_value, value_size) == 0);
        free(retrieved_value);
    }

    (void)pthread_exit(NULL);
}

void test_tidesdb_put_get_concurrent(bool compress, tidesdb_compression_algo_t algo,
                                     bool bloom_filter)
{
    tidesdb_t *db = NULL;
    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    pthread_t put_threads[NUM_THREADS];
    pthread_t get_threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_data[i].db = db;
        thread_data[i].cf_name = "test_cf";
        thread_data[i].thread_id = i;
        pthread_create(&put_threads[i], NULL, put_operation, (void *)&thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(put_threads[i], NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(&get_threads[i], NULL, get_operation, (void *)&thread_data[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(get_threads[i], NULL);
    }

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_put_get_concurrent%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

int main(void)
{
    test_tidesdb_serialize_deserialize_key_value_pair(false, TDB_NO_COMPRESSION);

    test_tidesdb_serialize_deserialize_column_family_config();

    test_tidesdb_serialize_deserialize_sst_min_max();

    test_tidesdb_serialize_deserialize_operation(false, TDB_NO_COMPRESSION);

    test_tidesdb_tidesdb_open_close();

    test_tidesdb_create_drop_column_family(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_get_memtable(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_close_replay_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_txn_put_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_txn_put_get_rollback_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_txn_put_put_delete_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_delete_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_stat(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_memtable_sstables(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_close_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_delete_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_many_flush_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_compact_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_shutdown_compact_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_get_concurrent(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_serialize_deserialize_key_value_pair(true, TDB_COMPRESS_SNAPPY);

    test_tidesdb_serialize_deserialize_operation(true, TDB_COMPRESS_SNAPPY);

    test_tidesdb_serialize_deserialize_key_value_pair(true, TDB_COMPRESS_LZ4);

    test_tidesdb_serialize_deserialize_operation(true, TDB_COMPRESS_LZ4);

    test_tidesdb_serialize_deserialize_key_value_pair(true, TDB_COMPRESS_ZSTD);

    test_tidesdb_serialize_deserialize_operation(true, TDB_COMPRESS_ZSTD);

    test_tidesdb_create_drop_column_family(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_get_memtable(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_close_replay_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_txn_put_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_txn_put_get_rollback_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_txn_put_put_delete_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_delete_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_flush_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_flush_close_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_flush_delete_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_cursor(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_cursor_memtable_sstables(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_many_flush_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_flush_compact_get(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_put_get_concurrent(true, TDB_COMPRESS_SNAPPY, true);

    test_tidesdb_start_partial_merge(false, TDB_NO_COMPRESSION, false);

    return 0;
}