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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/serialize.h"
#include "test_macros.h"

void test_serialize_key_value_pair_no_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_key_value_pair(&kvp, &buffer, &encoded_size, false) == true);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_key_value_pair_no_compression passed\n" RESET);
}

void test_deserialize_key_value_pair_no_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    serialize_key_value_pair(&kvp, &buffer, &encoded_size, false);

    key_value_pair *deserialized_kvp = NULL;
    assert(deserialize_key_value_pair((uint8_t *)buffer, encoded_size, &deserialized_kvp, false) ==
           true);
    assert(deserialized_kvp->key_size == kvp.key_size);
    assert(memcmp(deserialized_kvp->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_kvp->value_size == kvp.value_size);
    assert(memcmp(deserialized_kvp->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_kvp->ttl == kvp.ttl);

    free(buffer);
    free(deserialized_kvp->key);
    free(deserialized_kvp->value);

    printf(GREEN "test_deserialize_key_value_pair_no_compression passed\n" RESET);
}

void test_serialize_bloomfilter_no_compression()
{
    bloomfilter bf = {.size = 8, .count = 0, .set = (uint8_t *)calloc(1, 1)};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_bloomfilter(&bf, &buffer, &encoded_size, false) == true);
    assert(encoded_size > 0);
    free(buffer);
    free(bf.set);

    printf(GREEN "test_serialize_bloomfilter_no_compression passed\n" RESET);
}

void test_deserialize_bloomfilter_no_compression()
{
    bloomfilter bf = {.size = 8, .count = 0, .set = (uint8_t *)calloc(1, 1)};
    uint8_t *buffer;
    size_t encoded_size;

    serialize_bloomfilter(&bf, &buffer, &encoded_size, false);

    bloomfilter *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, false) == true);
    assert(deserialized_bf->size == bf.size);
    assert(deserialized_bf->count == bf.count);
    assert(memcmp(deserialized_bf->set, bf.set, (bf.size + 7) / 8) == 0);

    free(buffer);
    free(bf.set);
    free(deserialized_bf->set);

    printf(GREEN "test_deserialize_bloomfilter_no_compression passed\n" RESET);
}

void test_serialize_deserialize_full_bloomfilter_no_compression()
{
    bloomfilter *bf = bloomfilter_create(8); /* small size for testing */
    const uint8_t data1[] = "test1";
    const uint8_t data2[] = "test2";

    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        bloomfilter_add(bf, data, 1);
    }

    assert(bf->next != NULL);
    assert(bloomfilter_add(bf, data2, strlen((const char *)data2)) == 0);
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == true);

    /* check if all the data is in the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(bf, data, 1) == true);
    }

    /* serialize the bloom filter */
    uint8_t *buffer;
    size_t encoded_size;
    assert(serialize_bloomfilter(bf, &buffer, &encoded_size, false) == true);
    assert(encoded_size > 0);

    /* deserialize the bloom filter */
    bloomfilter *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, false) == true);

    /* verify the deserialized bloom filter */
    assert(deserialized_bf->size == bf->size);
    assert(deserialized_bf->count == bf->count);
    assert(memcmp(deserialized_bf->set, bf->set, (bf->size + 7) / 8) == 0);

    bloomfilter_destroy(bf);

    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(deserialized_bf, data, 1) == true);
    }
    assert(bloomfilter_check(deserialized_bf, data2, strlen((const char *)data2)) == true);

    /* clean up */
    free(buffer);

    bloomfilter_destroy(deserialized_bf);

    printf(GREEN "test_serialize_deserialize_full_bloomfilter_no_compression passed\n" RESET);
}

void test_serialize_key_value_pair_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_key_value_pair(&kvp, &buffer, &encoded_size, true) == true);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_key_value_pair_compression passed\n" RESET);
}

void test_deserialize_key_value_pair_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    serialize_key_value_pair(&kvp, &buffer, &encoded_size, true);

    key_value_pair *deserialized_kvp = NULL;
    assert(deserialize_key_value_pair((uint8_t *)buffer, encoded_size, &deserialized_kvp, true) ==
           true);
    assert(deserialized_kvp->key_size == kvp.key_size);
    assert(memcmp(deserialized_kvp->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_kvp->value_size == kvp.value_size);
    assert(memcmp(deserialized_kvp->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_kvp->ttl == kvp.ttl);

    free(buffer);
    free(deserialized_kvp->key);
    free(deserialized_kvp->value);

    printf(GREEN "test_deserialize_key_value_pair_compression passed\n" RESET);
}

void test_serialize_bloomfilter_compression()
{
    bloomfilter bf = {.size = 8, .count = 0, .set = (uint8_t *)calloc(1, 1)};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_bloomfilter(&bf, &buffer, &encoded_size, true) == true);
    assert(encoded_size > 0);
    free(buffer);
    free(bf.set);

    printf(GREEN "test_serialize_bloomfilter_compression passed\n" RESET);
}

void test_deserialize_bloomfilter_compression()
{
    bloomfilter bf = {.size = 8, .count = 0, .set = (uint8_t *)calloc(1, 1)};
    uint8_t *buffer;
    size_t encoded_size;

    serialize_bloomfilter(&bf, &buffer, &encoded_size, true);

    bloomfilter *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, true) == true);
    assert(deserialized_bf->size == bf.size);
    assert(deserialized_bf->count == bf.count);
    assert(memcmp(deserialized_bf->set, bf.set, (bf.size + 7) / 8) == 0);

    free(buffer);
    free(bf.set);
    free(deserialized_bf->set);

    printf(GREEN "test_deserialize_bloomfilter_compression passed\n" RESET);
}

void test_serialize_deserialize_full_bloomfilter_compression()
{
    bloomfilter *bf = bloomfilter_create(8); /* small size for testing */
    const uint8_t data1[] = "test1";
    const uint8_t data2[] = "test2";

    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        bloomfilter_add(bf, data, 1);
    }

    assert(bf->next != NULL);
    assert(bloomfilter_add(bf, data2, strlen((const char *)data2)) == 0);
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == true);

    /* check if all the data is in the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(bf, data, 1) == true);
    }

    /* serialize the bloom filter */
    uint8_t *buffer;
    size_t encoded_size;
    assert(serialize_bloomfilter(bf, &buffer, &encoded_size, true) == true);
    assert(encoded_size > 0);

    /* deserialize the bloom filter */
    bloomfilter *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, true) == true);

    /* verify the deserialized bloom filter */
    assert(deserialized_bf->size == bf->size);
    assert(deserialized_bf->count == bf->count);
    assert(memcmp(deserialized_bf->set, bf->set, (bf->size + 7) / 8) == 0);

    bloomfilter_destroy(bf);

    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(deserialized_bf, data, 1) == true);
    }
    assert(bloomfilter_check(deserialized_bf, data2, strlen((const char *)data2)) == true);

    /* clean up */
    free(buffer);

    bloomfilter_destroy(deserialized_bf);

    printf(GREEN "test_serialize_deserialize_full_bloomfilter_compression passed\n" RESET);
}

void test_serialize_operation_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    operation op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, true) == true);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_operation_compression passed\n" RESET);
}

void test_deserialize_operation_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    operation op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, true) == true);

    operation *deserialized_op = NULL;
    assert(deserialize_operation(buffer, encoded_size, &deserialized_op, true) == true);
    assert(deserialized_op->op_code == op.op_code);
    assert(deserialized_op->kv->key_size == kvp.key_size);
    assert(memcmp(deserialized_op->kv->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_op->kv->value_size == kvp.value_size);
    assert(memcmp(deserialized_op->kv->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_op->kv->ttl == kvp.ttl);
    assert(strcmp(deserialized_op->column_family, op.column_family) == 0);

    free(buffer);
    free(deserialized_op->kv->key);
    free(deserialized_op->kv->value);
    free(deserialized_op->kv);
    free(deserialized_op->column_family);
    free(deserialized_op);

    printf(GREEN "test_deserialize_operation_compression passed\n" RESET);
}

void test_serialize_column_family_config_no_compression()
{
    column_family_config config = {.name = "test_cf",
                                   .flush_threshold = 100,
                                   .max_level = 5,
                                   .probability = 0.01f,
                                   .compressed = true};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_column_family_config(&config, &buffer, &encoded_size) == true);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_column_family_config_no_compression passed\n" RESET);
}

void test_deserialize_column_family_config_no_compression()
{
    column_family_config config = {.name = "test_cf",
                                   .flush_threshold = 100,
                                   .max_level = 5,
                                   .probability = 0.01f,
                                   .compressed = true};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    serialize_column_family_config(&config, &buffer, &encoded_size);

    column_family_config *deserialized_config = NULL;
    assert(deserialize_column_family_config(buffer, encoded_size, &deserialized_config) == true);
    assert(strcmp(deserialized_config->name, config.name) == 0);
    assert(deserialized_config->flush_threshold == config.flush_threshold);
    assert(deserialized_config->max_level == config.max_level);
    assert(deserialized_config->probability == config.probability);
    assert(deserialized_config->compressed == config.compressed);

    free(buffer);
    free(deserialized_config->name);

    printf(GREEN "test_deserialize_column_family_config_no_compression passed\n" RESET);
}

void test_serialize_operation_no_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    operation op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, false) == true);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_operation_no_compression passed\n" RESET);
}

void test_deserialize_operation_no_compression()
{
    key_value_pair kvp = {.key = (uint8_t *)"key",
                          .key_size = 3,
                          .value = (uint8_t *)"value",
                          .value_size = 5,
                          .ttl = 12345};
    operation op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    serialize_operation(&op, &buffer, &encoded_size, false);

    operation *deserialized_op = NULL;
    assert(deserialize_operation(buffer, encoded_size, &deserialized_op, false) == true);
    assert(deserialized_op->op_code == op.op_code);
    assert(deserialized_op->kv->key_size == kvp.key_size);
    assert(memcmp(deserialized_op->kv->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_op->kv->value_size == kvp.value_size);
    assert(memcmp(deserialized_op->kv->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_op->kv->ttl == kvp.ttl);
    assert(strcmp(deserialized_op->column_family, op.column_family) == 0);

    free(buffer);
    free(deserialized_op->kv->key);
    free(deserialized_op->kv->value);
    free(deserialized_op->kv);
    free(deserialized_op->column_family);

    printf(GREEN "test_deserialize_operation_no_compression passed\n" RESET);
}

int main(void)
{
    test_serialize_key_value_pair_no_compression();
    test_deserialize_key_value_pair_no_compression();
    test_serialize_key_value_pair_compression();
    test_deserialize_key_value_pair_compression();
    test_serialize_operation_no_compression();
    test_deserialize_operation_no_compression();
    test_serialize_operation_compression();
    test_deserialize_operation_compression();
    test_serialize_column_family_config_no_compression();
    test_deserialize_column_family_config_no_compression();

    test_serialize_bloomfilter_no_compression();
    test_deserialize_bloomfilter_no_compression();
    test_serialize_bloomfilter_compression();
    test_deserialize_bloomfilter_compression();
    test_serialize_deserialize_full_bloomfilter_no_compression();
    test_serialize_deserialize_full_bloomfilter_compression();

    return 0;
}