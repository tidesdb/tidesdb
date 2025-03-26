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
    uint8_t *serialized = _tidesdb_serialize_sst_min_max(min_key, min_key_size, max_key,
                                                         max_key_size, &serialized_size);
    assert(serialized != NULL);

    size_t expected_size = sizeof(size_t) + min_key_size + sizeof(size_t) + max_key_size;
    assert(serialized_size == expected_size);

    tidesdb_sst_min_max_t *deserialized = _tidesdb_deserialize_sst_min_max(serialized);
    assert(deserialized != NULL);

    assert(deserialized->min_key_size == min_key_size);
    assert(deserialized->max_key_size == max_key_size);
    assert(memcmp(deserialized->min_key, min_key, min_key_size) == 0);
    assert(memcmp(deserialized->max_key, max_key, max_key_size) == 0);

    free(deserialized->min_key);
    free(deserialized->max_key);
    free(deserialized);
    free(serialized);

    printf(GREEN "test_tidesdb_serialize_deserialize_sst_min_max passed\n" RESET);
}

void test_tidesdb_serialize_deserialize_operation(bool compress, tidesdb_compression_algo_t algo)
{
    uint8_t key_str[10];
    uint8_t value_str[10];

    strncpy((char *)key_str, "username", sizeof(key_str));
    strncpy((char *)value_str, "johndoe", sizeof(value_str));

    tidesdb_key_value_pair_t *kv =
        _tidesdb_key_value_pair_new(key_str, sizeof(key_str), value_str, sizeof(value_str), 3600);

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

typedef struct
{
    uint8_t key[20];
    bool found;
} cursor_test_entry_t;

void test_tidesdb_cursor_memtable_only(bool compress, tidesdb_compression_algo_t algo,
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
    uint8_t value[20];

    cursor_test_entry_t entries[12];

    /* fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i].key, key, sizeof(key));
        entries[i].found = false;
    }

    tidesdb_cursor_t *c;
    tidesdb_err_t *e = tidesdb_cursor_init(db, "test_cf", &c);
    if (e != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(e);
        return;
    }

    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* iterate forward */
    do
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 12; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);
    } while ((e = tidesdb_cursor_next(c)) == NULL);

    if (e != NULL && e->code != TIDESDB_ERR_AT_END_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }
    tidesdb_err_free(e);

    /* check if all keys are found */
    for (int i = 0; i < 12; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
        }
    }

    /* reset the found flags */
    for (int i = 0; i < 12; i++)
    {
        entries[i].found = false;
    }

    /* iterate backward */
    while ((e = tidesdb_cursor_prev(c)) == NULL)
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 12; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);
    }

    if (e != NULL && e->code != TIDESDB_ERR_AT_START_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }

    /* check if all keys are found */
    for (int i = 0; i < 12; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
        }
    }

    tidesdb_err_free(e);

    tidesdb_cursor_free(c);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor_memtable_only%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_cursor_sstables_only(bool compress, tidesdb_compression_algo_t algo,
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

    cursor_test_entry_t entries[12];

    /* fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i].key, key, sizeof(key));
        entries[i].found = false;
    }

    tidesdb_cursor_t *c;
    tidesdb_err_t *e = tidesdb_cursor_init(db, "test_cf", &c);
    if (e != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(e);
        return;
    }

    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* iterate forward */
    do
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 12; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);

    } while ((e = tidesdb_cursor_next(c)) == NULL);

    if (e != NULL && e->code != TIDESDB_ERR_AT_END_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }
    tidesdb_err_free(e);

    /* check if all keys are found */
    for (int i = 0; i < 12; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
        }
    }

    /* reset the found flags */
    for (int i = 0; i < 12; i++)
    {
        entries[i].found = false;
    }

    /* iterate backward */
    while ((e = tidesdb_cursor_prev(c)) == NULL)
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 12; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);
    }

    if (e != NULL && e->code != TIDESDB_ERR_AT_START_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }

    tidesdb_err_free(e);

    tidesdb_cursor_free(c);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor_sstables_only%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_cursor_memtable_sstables(bool compress, tidesdb_compression_algo_t algo,
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
    uint8_t smaller_value[20];

    cursor_test_entry_t entries[24];

    /* fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* fill the smaller value with random data */
    for (size_t i = 0; i < sizeof(smaller_value); i++)
    {
        smaller_value[i] = (uint8_t)(rand() % 256);
    }

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i].key, key, sizeof(key));
        entries[i].found = false;
    }

    /* put 12 more keys with smaller values */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i + 12);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, smaller_value,
                          sizeof(smaller_value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i + 12].key, key, sizeof(key));
        entries[i + 12].found = false;
    }

    /** _tidesdb_print_keys_tree(db, "test_cf"); */

    tidesdb_cursor_t *c;
    tidesdb_err_t *e = tidesdb_cursor_init(db, "test_cf", &c);
    if (e != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(e);
        return;
    }

    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* iterate forward */
    do
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 24; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);

    } while ((e = tidesdb_cursor_next(c)) == NULL);

    if (e != NULL && e->code != TIDESDB_ERR_AT_END_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }
    tidesdb_err_free(e);

    /* check if all keys are found */
    for (int i = 0; i < 24; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
            assert(entries[i].found);
        }
    }

    /* reset the found flags */
    for (int i = 0; i < 24; i++)
    {
        entries[i].found = false;
    }

    /* iterate backward */
    while ((e = tidesdb_cursor_prev(c)) == NULL)
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 24; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);
    }

    if (e != NULL && e->code != TIDESDB_ERR_AT_START_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }

    /* check if all keys are found */
    for (int i = 0; i < 24; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
            assert(entries[i].found);
        }
    }

    tidesdb_err_free(e);

    tidesdb_cursor_free(c);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor_memtable_sstables%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_cursor_background_compaction_shift(bool compress, tidesdb_compression_algo_t algo,
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

    /* we start a background compaction */
    err = tidesdb_start_incremental_merge(db, "test_cf", 1, 2);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }

    assert(err == NULL);

    uint8_t key[20];
    uint8_t value[1024 * 1024];
    uint8_t smaller_value[20];

    cursor_test_entry_t entries[24];

    /* fill the value with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* fill the smaller value with random data */
    for (size_t i = 0; i < sizeof(smaller_value); i++)
    {
        smaller_value[i] = (uint8_t)(rand() % 256);
    }

    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i].key, key, sizeof(key));
        entries[i].found = false;
    }

    /* put 12 more keys with smaller values */
    for (int i = 0; i < 12; i++)
    {
        snprintf((char *)key, sizeof(key), "key_%d", i + 12);
        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, smaller_value,
                          sizeof(smaller_value), -1);
        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* add the key to the entries */
        memcpy(entries[i + 12].key, key, sizeof(key));
        entries[i + 12].found = false;
    }

    /** _tidesdb_print_keys_tree(db, "test_cf"); */

    tidesdb_cursor_t *c;
    tidesdb_err_t *e = tidesdb_cursor_init(db, "test_cf", &c);
    if (e != NULL)
    {
        printf(RED "%s" RESET, err->message);
        tidesdb_err_free(e);
        return;
    }

    uint8_t *retrieved_key = NULL;
    size_t key_size;
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* iterate forward */
    do
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 24; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);

        sleep(1);

    } while ((e = tidesdb_cursor_next(c)) == NULL);

    if (e != NULL && e->code != TIDESDB_ERR_AT_END_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }
    tidesdb_err_free(e);

    /* check if all keys are found */
    for (int i = 0; i < 24; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
            assert(entries[i].found);
        }
    }

    /* reset the found flags */
    for (int i = 0; i < 24; i++)
    {
        entries[i].found = false;
    }

    /* iterate backward */
    while ((e = tidesdb_cursor_prev(c)) == NULL)
    {
        e = tidesdb_cursor_get(c, &retrieved_key, &key_size, &retrieved_value, &value_size);
        if (e != NULL)
        {
            printf(RED "%s" RESET, err->message);
            tidesdb_err_free(e);
            break;
        }

        /* check if the key is in the entries */
        for (int i = 0; i < 24; i++)
        {
            if (memcmp(entries[i].key, retrieved_key, key_size) == 0)
            {
                entries[i].found = true;
                break;
            }
        }

        free(retrieved_key);
        free(retrieved_value);

        sleep(1);
    }

    if (e != NULL && e->code != TIDESDB_ERR_AT_START_OF_CURSOR)
    {
        printf(RED "%s" RESET, e->message);
    }

    /* check if all keys are found */
    for (int i = 0; i < 24; i++)
    {
        if (!entries[i].found)
        {
            printf(RED "key %s not found\n" RESET, entries[i].key);
            assert(entries[i].found);
        }
    }

    tidesdb_err_free(e);

    tidesdb_cursor_free(c);

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_cursor_background_compaction_shift%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_cursor_init_free(bool compress, tidesdb_compression_algo_t algo,
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

    tidesdb_cursor_t *cursor = NULL;
    err = tidesdb_cursor_init(db, "test_cf", &cursor);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);
    assert(cursor != NULL);

    err = tidesdb_cursor_free(cursor);
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
    printf(GREEN "test_tidesdb_cursor_init_free%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_cursor_empty(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
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

    /* w initialize a cursor on an empty CF */
    tidesdb_cursor_t *cursor = NULL;
    err = tidesdb_cursor_init(db, "test_cf", &cursor);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);
    assert(cursor != NULL);

    /* we try to get the first element, should return TIDESDB_ERR_AT_END_OF_CURSOR */
    err = tidesdb_cursor_next(cursor);
    assert(err != NULL);
    assert(err->code == TIDESDB_ERR_AT_END_OF_CURSOR);
    (void)tidesdb_err_free(err);

    /* we try to get the previous element, should return TIDESDB_ERR_AT_START_OF_CURSOR */
    err = tidesdb_cursor_prev(cursor);
    assert(err != NULL);

    assert(err->code == TIDESDB_ERR_AT_START_OF_CURSOR);
    (void)tidesdb_err_free(err);

    /* we free the cursor */
    err = tidesdb_cursor_free(cursor);
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
    printf(GREEN "test_tidesdb_cursor_empty%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_start_incremental_merge(bool compress, tidesdb_compression_algo_t algo,
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

    /* start incremental merging in background */
    err = tidesdb_start_incremental_merge(db, "test_cf", 1, 4);
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

    sleep(16);

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
    printf(GREEN "test_tidesdb_start_incremental_merge%s%s passed\n" RESET,
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

/* filter function for tidesdb_delete_by_filter */
bool delete_filter_function(const tidesdb_key_value_pair_t *kv)
{
    /* delete keys that contain "_even_" */
    return strstr((const char *)kv->key, "_even_") != NULL;
}

void test_tidesdb_delete_by_range(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    /* we create column family with minimum 1MB flush threshold as required */
    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /*  we insert keys with values large enough to trigger flushes */
    const size_t MAX_KEY_SIZE = 20;
    char key_buffer[MAX_KEY_SIZE];

    /* we use a value size that will allow us to control flushing */
    const size_t VALUE_SIZE = 300 * 1024; /** 300KB values (about 3-4 will exceed 1MB) */
    uint8_t *value_buffer = malloc(VALUE_SIZE);
    assert(value_buffer != NULL);

    /* we insert the keys in a pattern to create multiple SSTables */
    for (int batch = 0; batch < 5; batch++)
    {
        printf("Inserting batch %d (keys %d-%d)\n", batch, batch * 4, batch * 4 + 3);

        /* we insert 4 keys per batch, each with a large value */
        for (int i = 0; i < 4; i++)
        {
            int index = batch * 4 + i;

            /* we create the key with binary-safe handling */
            int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%02d", index);
            assert(key_length > 0 && key_length < (int)MAX_KEY_SIZE);

            /* we create a simple pattern in the value buffer */
            memset(value_buffer, index % 256, VALUE_SIZE);

            /* we add a readable marker at the beginning */
            snprintf((char *)value_buffer, 16, "value_%02d", index);

            /* insert the key-value pair */
            err = tidesdb_put(db, "test_cf", (uint8_t *)key_buffer, key_length, value_buffer,
                              VALUE_SIZE, -1);

            if (err != NULL)
            {
                printf(RED "%s" RESET, err->message);
            }
            assert(err == NULL);
        }

        /* after each batch, force a flush by adding extra keys until we exceed 1MB */
        printf("  Adding flush trigger keys...\n");
        for (int j = 0; j < 5; j++)
        {
            char extra_key[30];
            int extra_key_length =
                snprintf(extra_key, sizeof(extra_key), "flush_key_%d_%d", batch, j);

            /* Fill value with a pattern */
            memset(value_buffer, (batch + j) % 256, VALUE_SIZE);

            err = tidesdb_put(db, "test_cf", (uint8_t *)extra_key, extra_key_length, value_buffer,
                              VALUE_SIZE, -1);

            if (err != NULL)
            {
                printf(RED "%s" RESET, err->message);
            }
            assert(err == NULL);
        }
    }

    free(value_buffer);

    /* we get column family stat to verify we have multiple SSTs */
    tidesdb_column_family_stat_t *stat = NULL;
    err = tidesdb_get_column_family_stat(db, "test_cf", &stat);

    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we log and verify we have multiple SSTs */
    printf("Number of SSTs before delete: %d\n", stat->num_sstables);

    if (stat->num_sstables < 2)
    {
        printf(YELLOW
               "Warning: Expected multiple SSTables but only have %d. Test may not fully validate "
               "multi-SSTable deletion.\n" RESET,
               stat->num_sstables);
    }

    /* we print SSTable sizes to verify they contain data */
    for (int i = 0; i < stat->num_sstables; i++)
    {
        printf("SSTable %d: %zu bytes at %s\n", i, stat->sstable_stats[i]->size,
               stat->sstable_stats[i]->sstable_path);
    }

    (void)tidesdb_free_column_family_stat(stat);

    /* we define our range to delete (keys 00-09) */
    char start_key[] = "range_key_00";
    size_t start_key_length = strlen(start_key);
    char end_key[] = "range_key_09";
    size_t end_key_length = strlen(end_key);

    /* we delete the range */
    printf("Deleting range from %s to %s\n", start_key, end_key);
    err = tidesdb_delete_by_range(db, "test_cf", (uint8_t *)start_key, start_key_length,
                                  (uint8_t *)end_key, end_key_length);

    if (err != NULL)
    {
        printf(RED "Range delete failed: %s" RESET, err->message);
        (void)tidesdb_err_free(err);
        assert(err == NULL);
    }

    /* we verify the deleted keys are gone */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* we check that the deleted keys (00-09) are gone */
    for (int i = 0; i < 10; i++)
    {
        int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%02d", i);

        err = tidesdb_get(db, "test_cf", (uint8_t *)key_buffer, key_length, &retrieved_value,
                          &value_size);

        /* should return key not found error */
        if (err == NULL)
        {
            printf(RED "Key %s was found but should have been deleted! Value size: %zu\n" RESET,
                   key_buffer, value_size);
            free(retrieved_value);
        }
        else
        {
            printf("Key %s correctly not found\n", key_buffer);
            (void)tidesdb_err_free(err);
        }
        assert(err != NULL);
    }

    /* we check that the kept keys (10-19) still exist */
    for (int i = 10; i < 20; i++)
    {
        int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%02d", i);

        err = tidesdb_get(db, "test_cf", (uint8_t *)key_buffer, key_length, &retrieved_value,
                          &value_size);

        if (err != NULL)
        {
            printf(RED "Failed to find key %s: %s" RESET, key_buffer, err->message);
            (void)tidesdb_err_free(err);
        }
        else
        {
            printf("Key %s correctly found, value size: %zu\n", key_buffer, value_size);
            /* Verify value has expected pattern */
            char expected_marker[16];
            snprintf(expected_marker, sizeof(expected_marker), "value_%02d", i);
            if (memcmp(retrieved_value, expected_marker, strlen(expected_marker)) != 0)
            {
                printf(RED "Value for key %s has unexpected content\n" RESET, key_buffer);
            }
            free(retrieved_value);
        }
        assert(err == NULL);
    }

    /* we get column family stat again to verify sstables after deletion */
    err = tidesdb_get_column_family_stat(db, "test_cf", &stat);
    if (err == NULL)
    {
        printf("Number of SSTs after delete: %d\n", stat->num_sstables);
        (void)tidesdb_free_column_family_stat(stat);
    }

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_delete_by_range%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_delete_range(bool compress, tidesdb_compression_algo_t algo, bool bloom_filter)
{
    tidesdb_t *db = NULL;

    tidesdb_err_t *err = tidesdb_open("test_db", &db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)tidesdb_err_free(err);

    /* create column family with minimum 1MB flush threshold as required */
    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* use much smaller values but still enough to get multiple SSTables */
    const size_t MAX_KEY_SIZE = 20;
    char key_buffer[MAX_KEY_SIZE];

    /*use a small value size to avoid memory issues */
    const size_t VALUE_SIZE = 1024; /** 1KB values */
    uint8_t value_buffer[VALUE_SIZE];

    /* insert many small keys to generate multiple SSTables */
    printf("Inserting test keys...\n");

    /* insert a large number of keys with small values to generate multiple SSTables */
    for (int i = 0; i < 6000; i++)
    {
        /* create the key with binary-safe handling */
        int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%04d", i);

        /* create a simple pattern in the value buffer */
        memset(value_buffer, i % 256, VALUE_SIZE);

        /* add a readable marker at the beginning */
        snprintf((char *)value_buffer, 16, "value_%04d", i);

        /* insert the key-value pair */
        err = tidesdb_put(db, "test_cf", (uint8_t *)key_buffer, key_length, value_buffer,
                          VALUE_SIZE, -1);

        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
            (void)tidesdb_err_free(err);
            assert(err == NULL);
        }

        /* occasionally log progress */
        if (i % 500 == 0)
        {
            printf("  Inserted %d keys...\n", i);
        }
    }

    /* get column family stat to verify we have multiple SSTs */
    tidesdb_column_family_stat_t *stat = NULL;
    err = tidesdb_get_column_family_stat(db, "test_cf", &stat);

    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        (void)tidesdb_err_free(err);
    }
    assert(err == NULL);

    /* log and verify we have multiple SSTs */
    printf("Number of SSTs before delete: %d\n", stat->num_sstables);

    if (stat->num_sstables < 2)
    {
        printf(YELLOW
               "Warning: Expected multiple SSTables but only have %d. Test may not fully validate "
               "multi-SSTable deletion.\n" RESET,
               stat->num_sstables);
    }

    (void)tidesdb_free_column_family_stat(stat);

    /* define our range to delete (keys 0200-0299) */
    printf("Individually deleting keys 0200-0299\n");

    for (int i = 200; i <= 299; i++)
    {
        int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%04d", i);

        err = tidesdb_delete(db, "test_cf", (uint8_t *)key_buffer, key_length);

        if (err != NULL)
        {
            printf(RED "Failed to delete key %s: %s" RESET, key_buffer, err->message);
            (void)tidesdb_err_free(err);
        }
        else
        {
            if (i % 25 == 0)
            {
                printf("Deleted key %s\n", key_buffer);
            }
        }
        assert(err == NULL);
    }

    /* verify the deleted keys are gone */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* check that the deleted keys (0200-0299) are gone */
    printf("Verifying deleted keys are gone...\n");
    for (int i = 200; i <= 299; i++)
    {
        if (i % 25 == 0)
        { /* subset to keep output manageable */
            int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%04d", i);

            err = tidesdb_get(db, "test_cf", (uint8_t *)key_buffer, key_length, &retrieved_value,
                              &value_size);

            /* should return key not found error */
            if (err == NULL)
            {
                printf(RED "Key %s was found but should have been deleted! Value size: %zu\n" RESET,
                       key_buffer, value_size);
                free(retrieved_value);
            }
            else
            {
                printf("Key %s correctly not found\n", key_buffer);
                (void)tidesdb_err_free(err);
            }
            assert(err != NULL);
        }
    }

    /* check that other keys still exist */
    printf("Verifying other keys still exist...\n");
    for (int i = 100; i < 150; i++)
    {
        if (i % 25 == 0)
        { /* subset to keep output manageable */
            int key_length = snprintf(key_buffer, MAX_KEY_SIZE, "range_key_%04d", i);

            err = tidesdb_get(db, "test_cf", (uint8_t *)key_buffer, key_length, &retrieved_value,
                              &value_size);

            if (err != NULL)
            {
                printf(RED "Failed to find key %s: %s" RESET, key_buffer, err->message);
                (void)tidesdb_err_free(err);
            }
            else
            {
                printf("Key %s correctly found, value size: %zu\n", key_buffer, value_size);

                /* verify value has expected pattern */
                char expected_marker[16];
                snprintf(expected_marker, sizeof(expected_marker), "value_%04d", i);
                if (memcmp(retrieved_value, expected_marker, strlen(expected_marker)) != 0)
                {
                    printf(RED "Value for key %s has unexpected content\n" RESET, key_buffer);
                }
                free(retrieved_value);
            }
            assert(err == NULL);
        }
    }

    printf("Testing completed successfully without using range delete API\n");
    printf(
        "This suggests the issue is in the tidesdb_delete_by_range or tidesdb_range "
        "implementation\n");

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
        (void)tidesdb_err_free(err);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_delete_range%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

void test_tidesdb_delete_by_filter(bool compress, tidesdb_compression_algo_t algo,
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

    /* we create column family with 1MB flush threshold to ensure multiple flushes */
    err = tidesdb_create_column_family(db, "test_cf", 1024 * 1024, 12, 0.24f, compress, algo,
                                       bloom_filter);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we insert 20 keys with values of ~128KB each to trigger multiple flushes */

    /* these will be organized as:
     * - filter_key_even_00, filter_key_even_02, ...: even numbers (to delete)
     * - filter_key_odd_01, filter_key_odd_03, ...: odd numbers (to keep)
     */

    uint8_t key[30];
    uint8_t value[128 * 1024]; /* 128KB values */

    /* fill values with random data */
    for (size_t i = 0; i < sizeof(value); i++)
    {
        value[i] = (uint8_t)(rand() % 256);
    }

    /* insert 20 keys with large values to create multiple SSTs */
    for (int i = 0; i < 20; i++)
    {
        if (i % 2 == 0)
        {
            snprintf((char *)key, sizeof(key), "filter_key_even_%02d", i);
        }
        else
        {
            snprintf((char *)key, sizeof(key), "filter_key_odd_%02d", i);
        }

        /* put a marker in the value to identify it */
        snprintf((char *)value, 20, "value_%02d", i);

        err = tidesdb_put(db, "test_cf", key, strlen((char *)key) + 1, value, sizeof(value), -1);

        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);
    }

    /* we get column family stat to verify we have multiple SSTs */
    tidesdb_column_family_stat_t *stat = NULL;
    err = tidesdb_get_column_family_stat(db, "test_cf", &stat);

    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* ensure we have at least 2 SSTs */
    printf("Number of SSTs before delete: %d\n", stat->num_sstables);
    assert(stat->num_sstables >= 2);
    (void)tidesdb_free_column_family_stat(stat);

    /* delete keys containing "_even_" using our filter function */
    err = tidesdb_delete_by_filter(db, "test_cf", delete_filter_function);

    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    /* we verify the deleted keys are gone */
    uint8_t *retrieved_value = NULL;
    size_t value_size;

    /* we check that the even keys (with "_even_") are gone */
    for (int i = 0; i < 20; i += 2)
    {
        snprintf((char *)key, sizeof(key), "filter_key_even_%02d", i);

        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);

        if (err == NULL)
        {
            printf(RED "Key %s was found but should have been deleted! Value size: %zu\n" RESET,
                   key, value_size);
            free(retrieved_value);
        }

        /* should return key not found error */
        assert(err != NULL);
        (void)tidesdb_err_free(err);
    }

    /* check that the odd keys (with "_odd_") still exist */
    for (int i = 1; i < 20; i += 2)
    {
        snprintf((char *)key, sizeof(key), "filter_key_odd_%02d", i);

        err =
            tidesdb_get(db, "test_cf", key, strlen((char *)key) + 1, &retrieved_value, &value_size);

        if (err != NULL)
        {
            printf(RED "%s" RESET, err->message);
        }
        assert(err == NULL);

        /* verify value starts with correct marker */
        char expected_marker[20];
        snprintf(expected_marker, sizeof(expected_marker), "value_%02d", i);
        assert(memcmp(retrieved_value, expected_marker, strlen(expected_marker)) == 0);

        free(retrieved_value);
    }

    err = tidesdb_close(db);
    if (err != NULL)
    {
        printf(RED "%s" RESET, err->message);
    }
    assert(err == NULL);

    (void)_tidesdb_remove_directory("test_db");
    printf(GREEN "test_tidesdb_delete_by_filter%s%s passed\n" RESET,
           compress ? " with compression" : "", bloom_filter ? " with bloom filter" : "");
}

int main(void)
{
    (void)_tidesdb_remove_directory("test_db"); /* remove previous test database, if any */

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

    test_tidesdb_put_flush_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_close_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_delete_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_many_flush_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_init_free(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_empty(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_memtable_only(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_sstables_only(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_memtable_sstables(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_compact_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_flush_shutdown_compact_get(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_put_get_concurrent(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_delete_range(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_delete_by_range(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_delete_by_filter(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_start_incremental_merge(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_cursor_background_compaction_shift(false, TDB_NO_COMPRESSION, false);

    test_tidesdb_serialize_deserialize_key_value_pair(true, TDB_COMPRESS_ZSTD);

    test_tidesdb_serialize_deserialize_operation(true, TDB_COMPRESS_ZSTD);

    test_tidesdb_serialize_deserialize_key_value_pair(true, TDB_COMPRESS_LZ4);

    test_tidesdb_serialize_deserialize_operation(true, TDB_COMPRESS_LZ4);

    test_tidesdb_tidesdb_open_close();

    test_tidesdb_create_drop_column_family(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_get_memtable(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_close_replay_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_txn_put_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_txn_put_get_rollback_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_txn_put_put_delete_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_delete_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_stat(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_init_free(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_empty(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_memtable_only(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_sstables_only(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_memtable_sstables(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_close_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_delete_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_many_flush_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_compact_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_flush_shutdown_compact_get(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_put_get_concurrent(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_delete_range(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_delete_by_range(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_delete_by_filter(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_start_incremental_merge(true, TDB_COMPRESS_ZSTD, true);

    test_tidesdb_cursor_background_compaction_shift(true, TDB_COMPRESS_ZSTD, true);

    return 0;
}