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
    key_value_pair_t kvp;
    kvp.key = (uint8_t *)"test_key";
    kvp.key_size = strlen((char *)kvp.key);
    kvp.value = (uint8_t *)"test_value";
    kvp.value_size = strlen((char *)kvp.value);
    kvp.ttl = 123456789;

    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_key_value_pair(&kvp, &buffer, &encoded_size, false) == 0);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_key_value_pair_no_compression passed\n" RESET);
}

void test_deserialize_key_value_pair_no_compression()
{
    key_value_pair_t kvp;
    kvp.key = (uint8_t *)"test_key";
    kvp.key_size = strlen((char *)kvp.key);
    kvp.value = (uint8_t *)"test_value";
    kvp.value_size = strlen((char *)kvp.value);
    kvp.ttl = 123456789;

    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    serialize_key_value_pair(&kvp, &buffer, &encoded_size, false);

    key_value_pair_t *deserialized_kvp = NULL;
    assert(deserialize_key_value_pair((uint8_t *)buffer, encoded_size, &deserialized_kvp, false) ==
           0);
    assert(deserialized_kvp->key_size == kvp.key_size);
    assert(memcmp(deserialized_kvp->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_kvp->value_size == kvp.value_size);
    assert(memcmp(deserialized_kvp->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_kvp->ttl == kvp.ttl);

    free(buffer);
    free(deserialized_kvp->key);
    free(deserialized_kvp->value);
    free(deserialized_kvp);

    printf(GREEN "test_deserialize_key_value_pair_no_compression passed\n" RESET);
}

void test_serialize_key_value_pair_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_key_value_pair(&kvp, &buffer, &encoded_size, true) == 0);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_key_value_pair_compression passed\n" RESET);
}

void test_deserialize_key_value_pair_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    uint8_t *buffer;
    size_t encoded_size;

    serialize_key_value_pair(&kvp, &buffer, &encoded_size, true);

    key_value_pair_t *deserialized_kvp = NULL;
    assert(deserialize_key_value_pair((uint8_t *)buffer, encoded_size, &deserialized_kvp, true) ==
           0);
    assert(deserialized_kvp->key_size == kvp.key_size);
    assert(memcmp(deserialized_kvp->key, kvp.key, kvp.key_size) == 0);
    assert(deserialized_kvp->value_size == kvp.value_size);
    assert(memcmp(deserialized_kvp->value, kvp.value, kvp.value_size) == 0);
    assert(deserialized_kvp->ttl == kvp.ttl);

    free(buffer);
    free(deserialized_kvp->key);
    free(deserialized_kvp->value);
    free(deserialized_kvp);

    printf(GREEN "test_deserialize_key_value_pair_compression passed\n" RESET);
}

void test_serialize_operation_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    operation_t op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, true) == 0);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_operation_compression passed\n" RESET);
}

void test_deserialize_operation_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    operation_t op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, true) == 0);

    operation_t *deserialized_op = NULL;
    assert(deserialize_operation(buffer, encoded_size, &deserialized_op, true) == 0);
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
    column_family_config_t config = {.name = "test_cf",
                                     .flush_threshold = 100,
                                     .max_level = 5,
                                     .probability = 0.01f,
                                     .compressed = true};
    uint8_t *buffer;
    size_t encoded_size;

    assert(serialize_column_family_config(&config, &buffer, &encoded_size) == 0);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_column_family_config_no_compression passed\n" RESET);
}

void test_deserialize_column_family_config_no_compression()
{
    column_family_config_t config = {.name = "test_cf",
                                     .flush_threshold = 100,
                                     .max_level = 5,
                                     .probability = 0.01f,
                                     .compressed = true};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    serialize_column_family_config(&config, &buffer, &encoded_size);

    column_family_config_t *deserialized_config = NULL;
    assert(deserialize_column_family_config(buffer, encoded_size, &deserialized_config) == 0);
    assert(strcmp(deserialized_config->name, config.name) == 0);
    assert(deserialized_config->flush_threshold == config.flush_threshold);
    assert(deserialized_config->max_level == config.max_level);
    assert(deserialized_config->probability == config.probability);
    assert(deserialized_config->compressed == config.compressed);

    free(buffer);
    free(deserialized_config->name);
    free(deserialized_config);

    printf(GREEN "test_deserialize_column_family_config_no_compression passed\n" RESET);
}

void test_serialize_operation_no_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    operation_t op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    assert(serialize_operation(&op, &buffer, &encoded_size, false) == 0);
    assert(encoded_size > 0);
    free(buffer);

    printf(GREEN "test_serialize_operation_no_compression passed\n" RESET);
}

void test_deserialize_operation_no_compression()
{
    key_value_pair_t kvp = {.key = (uint8_t *)"key",
                            .key_size = 3,
                            .value = (uint8_t *)"value",
                            .value_size = 5,
                            .ttl = 12345};
    operation_t op = {.op_code = 1, .kv = &kvp, .column_family = "test_cf"};
    uint8_t *buffer = NULL;
    size_t encoded_size = 0;

    serialize_operation(&op, &buffer, &encoded_size, false);

    operation_t *deserialized_op = NULL;
    assert(deserialize_operation(buffer, encoded_size, &deserialized_op, false) == 0);
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

    printf(GREEN "test_deserialize_operation_no_compression passed\n" RESET);
}

void test_serialize_deserialize_full_bloomfilter_no_compression()
{
    /* create a bloom filter with an initial size of 8 */
    bloomfilter_t *bf = bloomfilter_create(8);
    assert(bf != NULL); /* assert creation success */

    const uint8_t data2[] = "test2";

    /* add 256 elements to the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_add(bf, data, 1) == 0); /* assert add success */
    }

    /* assert that the bloom filter has chained */
    assert(bf->next != NULL);

    /* add another element and check its presence */
    assert(bloomfilter_add(bf, data2, strlen((const char *)data2)) == 0);
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == 0);

    /* check if all the data is in the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(bf, data, 1) == 0);
    }

    /* serialize the bloom filter */
    uint8_t *buffer = NULL;
    size_t encoded_size;
    assert(serialize_bloomfilter(bf, &buffer, &encoded_size, false) == 0);
    assert(buffer != NULL);   /* assert buffer is not NULL */
    assert(encoded_size > 0); /*ssert encoded size is greater than 0*/

    /* deserialize the bloom filter */
    bloomfilter_t *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, false) == 0);
    assert(deserialized_bf != NULL);

    /* verify the deserialized bloom filter */
    assert(deserialized_bf->size == bf->size);
    assert(deserialized_bf->count == bf->count);
    assert(memcmp(deserialized_bf->set, bf->set, (bf->size + 7) / 8) == 0);

    /* destroy the original bloom filter */
    bloomfilter_destroy(bf);

    /* check if all the data is in the deserialized bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(deserialized_bf, data, 1) == 0);
    }
    assert(bloomfilter_check(deserialized_bf, data2, strlen((const char *)data2)) == 0);

    /* clean upp */
    free(buffer);
    bloomfilter_destroy(deserialized_bf);

    printf(GREEN "test_serialize_deserialize_full_bloomfilter_no_compression passed\n" RESET);
}

void test_serialize_deserialize_full_bloomfilter_compression()
{
    /* create a bloom filter with an initial size of 8 */
    bloomfilter_t *bf = bloomfilter_create(8);
    assert(bf != NULL); /* assert creation success */

    const uint8_t data2[] = "test2";

    /* add 256 elements to the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_add(bf, data, 1) == 0); /* assert add success */
    }

    /* assert that the bloom filter has chained */
    assert(bf->next != NULL);

    /* add another element and check its presence */
    assert(bloomfilter_add(bf, data2, strlen((const char *)data2)) == 0);
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == 0);

    /* check if all the data is in the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(bf, data, 1) == 0);
    }

    /* serialize the bloom filter */
    uint8_t *buffer = NULL;
    size_t encoded_size;
    assert(serialize_bloomfilter(bf, &buffer, &encoded_size, true) == 0);
    assert(buffer != NULL);   /* assert buffer is not NULL */
    assert(encoded_size > 0); /* assert encoded size is greater than 0 */

    /* deserialize the bloom filter */
    bloomfilter_t *deserialized_bf = NULL;
    assert(deserialize_bloomfilter(buffer, encoded_size, &deserialized_bf, true) == 0);
    assert(deserialized_bf != NULL); /* assert deserialization success */

    /* verify the deserialized bloom filter */
    assert(deserialized_bf->size == bf->size);
    assert(deserialized_bf->count == bf->count);
    assert(memcmp(deserialized_bf->set, bf->set, (bf->size + 7) / 8) == 0);

    /* destroy the original bloom filter */
    bloomfilter_destroy(bf);

    /* check if all the data is in the deserialized bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(deserialized_bf, data, 1) == 0);
    }
    assert(bloomfilter_check(deserialized_bf, data2, strlen((const char *)data2)) == 0);

    /* clean up */
    free(buffer);
    bloomfilter_destroy(deserialized_bf);

    printf(GREEN "test_serialize_deserialize_full_bloomfilter_compression passed\n" RESET);
}

/* cc -g3 -fsanitize=address,undefined src/*.c external/*.c test/serialize__tests.c -lzstd */
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

    test_serialize_deserialize_full_bloomfilter_no_compression();
    test_serialize_deserialize_full_bloomfilter_compression();

    return 0;
}