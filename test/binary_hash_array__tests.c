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

#include "../src/binary_hash_array.h"
#include "../src/compat.h"
#include "test_macros.h"

void test_binary_hash_array_new()
{
    binary_hash_array_t *bha = binary_hash_array_new(1000);
    assert(bha != NULL);
    assert(bha->entries != NULL);
    assert(bha->capacity == 1000);
    binary_hash_array_free(bha);
    printf(GREEN "test_binary_hash_array_new passed\n" RESET);
}

void test_binary_hash_array_add_and_contains()
{
    binary_hash_array_t *bha = binary_hash_array_new(1000);

    uint8_t key[] = "test_key";

    binary_hash_array_add(bha, key, sizeof(key), 42);

    size_t serialized_size;
    /* we serialize the entries to sort them */
    uint8_t *serialized_data = binary_hash_array_serialize(bha, &serialized_size);
    binary_hash_array_t *sorted_bha = binary_hash_array_deserialize(serialized_data);
    assert(binary_hash_array_contains(sorted_bha, key, sizeof(key)) == 42);

    uint8_t non_existent_key[] = "non_existent_key";
    size_t non_existent_key_len = strlen((const char *)non_existent_key);
    uint8_t non_existent_hash[16];
    binary_hash_array_hash_key(non_existent_key, non_existent_key_len, non_existent_hash);
    assert(binary_hash_array_contains(sorted_bha, non_existent_hash, non_existent_key_len) == -1);

    binary_hash_array_free(bha);
    binary_hash_array_free(sorted_bha);
    free(serialized_data);
    printf(GREEN "test_binary_hash_array_add_and_contains passed\n" RESET);
}

void benchmark_binary_hash_array()
{
    clock_t start, end;
    double cpu_time_used;

    binary_hash_array_t *bha = binary_hash_array_new(100000);
    assert(bha != NULL);

    start = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        binary_hash_array_add(bha, (uint8_t *)key, strlen(key), i);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to add entries: %f seconds\n" RESET, cpu_time_used);

    size_t serialized_size;
    uint8_t *serialized_data = binary_hash_array_serialize(bha, &serialized_size);
    assert(serialized_data != NULL);

    binary_hash_array_free(bha);

    /* we print the size of the serialized sorted binary hash array */
    printf(BOLDWHITE "Bloom filter size: %f MB\n" RESET, (float)serialized_size / 1000000);

    binary_hash_array_t *deserialized_bha = binary_hash_array_deserialize(serialized_data);
    free(serialized_data);
    assert(deserialized_bha != NULL);

    start = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        int64_t value = binary_hash_array_contains(deserialized_bha, (uint8_t *)key, strlen(key));
        assert(value == i);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to check entries: %f seconds\n" RESET, cpu_time_used);

    binary_hash_array_free(deserialized_bha);
    printf(GREEN "benchmark_binary_hash_array passed\n" RESET);
}

int main(void)
{
    test_binary_hash_array_new();
    test_binary_hash_array_add_and_contains();
    benchmark_binary_hash_array();
    return 0;
}