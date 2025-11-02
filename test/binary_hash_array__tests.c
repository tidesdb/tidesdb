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
#include "../src/binary_hash_array.h"
#include "../src/compat.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_binary_hash_array_compare()
{
    binary_hash_array_entry_t entry1, entry2;

    /* we test equal entries */
    memset(entry1.key, 0x01, sizeof(entry1.key));
    memset(entry2.key, 0x01, sizeof(entry2.key));

    ASSERT_TRUE(binary_hash_array_compare(&entry1, &entry2) == 0);

    /* we test entry1 < entry2 */
    memset(entry1.key, 0x01, sizeof(entry1.key));
    memset(entry2.key, 0x02, sizeof(entry2.key));

    ASSERT_TRUE(binary_hash_array_compare(&entry1, &entry2) < 0);

    /* we test entry1 > entry2 */
    memset(entry1.key, 0x02, sizeof(entry1.key));
    memset(entry2.key, 0x01, sizeof(entry2.key));

    ASSERT_TRUE(binary_hash_array_compare(&entry1, &entry2) > 0);

    /* test NULL handling */
    ASSERT_TRUE(binary_hash_array_compare(NULL, &entry2) < 0);
    ASSERT_TRUE(binary_hash_array_compare(&entry1, NULL) > 0);
    ASSERT_TRUE(binary_hash_array_compare(NULL, NULL) == 0);

    printf(GREEN "test_binary_hash_array_compare passed\n" RESET);
}

void test_binary_hash_array_new()
{
    binary_hash_array_t *bha = binary_hash_array_new(1000);
    ASSERT_TRUE(bha != NULL);
    ASSERT_NE(bha->entries, NULL);
    ASSERT_EQ(bha->capacity, 1000);
    (void)binary_hash_array_free(bha);
    printf(GREEN "test_binary_hash_array_new passed\n" RESET);
}

void test_binary_hash_array_add_and_contains()
{
    binary_hash_array_t *bha = binary_hash_array_new(1000);

    uint8_t key[] = "test_key";

    ASSERT_TRUE(binary_hash_array_add(bha, key, sizeof(key), 42) == 0); /* should return 0 */

    size_t serialized_size;
    /* we serialize the entries to sort them */
    uint8_t *serialized_data = binary_hash_array_serialize(bha, &serialized_size);
    binary_hash_array_t *sorted_bha = binary_hash_array_deserialize(serialized_data);
    ASSERT_TRUE(binary_hash_array_contains(sorted_bha, key, sizeof(key)) == 42);

    uint8_t non_existent_key[] = "non_existent_key";
    size_t non_existent_key_len = strlen((char *)non_existent_key);
    uint8_t non_existent_hash[16];
    (void)binary_hash_array_hash_key(non_existent_key, non_existent_key_len, non_existent_hash);
    ASSERT_TRUE(binary_hash_array_contains(sorted_bha, non_existent_hash, non_existent_key_len) ==
                -1);

    (void)binary_hash_array_free(bha);
    (void)binary_hash_array_free(sorted_bha);
    free(serialized_data);
    printf(GREEN "test_binary_hash_array_add_and_contains passed\n" RESET);
}

void test_binary_hash_array_edge_cases()
{
    /* empty array case */
    binary_hash_array_t *empty_bha = binary_hash_array_new(10);
    ASSERT_TRUE(empty_bha != NULL);

    /* serialize and deserialize empty array */
    size_t empty_size;
    uint8_t *empty_data = binary_hash_array_serialize(empty_bha, &empty_size);
    ASSERT_TRUE(empty_data != NULL);

    binary_hash_array_t *deserialized_empty = binary_hash_array_deserialize(empty_data);
    ASSERT_TRUE(deserialized_empty != NULL);
    ASSERT_EQ(deserialized_empty->size, 0);

    /* we try to search in empty array */
    uint8_t test_key[] = "test";
    ASSERT_TRUE(binary_hash_array_contains(empty_bha, test_key, sizeof(test_key)) == -1);

    (void)binary_hash_array_free(empty_bha);
    (void)binary_hash_array_free(deserialized_empty);
    free(empty_data);

    /* single element case */
    binary_hash_array_t *single_bha = binary_hash_array_new(5);
    uint8_t single_key[] = "single";
    ASSERT_TRUE(binary_hash_array_add(single_bha, single_key, sizeof(single_key), 100) == 0);

    size_t single_size;
    uint8_t *single_data = binary_hash_array_serialize(single_bha, &single_size);
    binary_hash_array_t *deserialized_single = binary_hash_array_deserialize(single_data);

    ASSERT_TRUE(binary_hash_array_contains(deserialized_single, single_key, sizeof(single_key)) ==
                100);

    (void)binary_hash_array_free(single_bha);
    (void)binary_hash_array_free(deserialized_single);
    free(single_data);

    printf(GREEN "test_binary_hash_array_edge_cases passed\n" RESET);
}

void test_binary_hash_array_duplicate_keys()
{
    binary_hash_array_t *bha = binary_hash_array_new(100);

    uint8_t key[] = "duplicate_key";

    /* add the same key twice with different values */
    ASSERT_TRUE(binary_hash_array_add(bha, key, sizeof(key), 42) == 0);
    ASSERT_TRUE(binary_hash_array_add(bha, key, sizeof(key), 84) == 0);

    size_t serialized_size;
    uint8_t *serialized_data = binary_hash_array_serialize(bha, &serialized_size);
    binary_hash_array_t *sorted_bha = binary_hash_array_deserialize(serialized_data);

    /* with current implementation, contains() will return the first value inserted, disregarding
     * the second. */
    int64_t result = binary_hash_array_contains(sorted_bha, key, sizeof(key));
    printf("Duplicate key test result: %ld\n", result);

    ASSERT_EQ(result, 42);

    (void)binary_hash_array_free(bha);
    (void)binary_hash_array_free(sorted_bha);
    free(serialized_data);

    printf(GREEN "test_binary_hash_array_duplicate_keys passed\n" RESET);
}

void test_binary_hash_array_resize()
{
    binary_hash_array_t *bha = binary_hash_array_new(10);
    ASSERT_TRUE(bha != NULL);
    ASSERT_EQ(bha->capacity, 10);

    /* we test manual resize */
    ASSERT_TRUE(binary_hash_array_resize(bha, 20) == 0);
    ASSERT_EQ(bha->capacity, 20);

    /* we test automatic resize by filling beyond capacity */
    for (int i = 0; i < 15; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        ASSERT_TRUE(binary_hash_array_add(bha, (uint8_t *)key, strlen(key), i) == 0);
    }
    ASSERT_EQ(bha->capacity, 20);
    ASSERT_EQ(bha->size, 15);

    (void)binary_hash_array_free(bha);
    printf(GREEN "test_binary_hash_array_resize passed\n" RESET);
}

void benchmark_binary_hash_array()
{
    clock_t start, end;
    double cpu_time_used;

    binary_hash_array_t *bha = binary_hash_array_new(100000);
    ASSERT_TRUE(bha != NULL);

    start = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        ASSERT_TRUE(binary_hash_array_add(bha, (uint8_t *)key, strlen(key), i) == 0);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to add %d entries: %f seconds\n" RESET, 1000000, cpu_time_used);

    size_t serialized_size;
    uint8_t *serialized_data = binary_hash_array_serialize(bha, &serialized_size);
    ASSERT_TRUE(serialized_data != NULL);

    (void)binary_hash_array_free(bha);

    /* we print the size of the serialized sorted binary hash array */
    printf(BOLDWHITE "Sorted binary hash array size: %f MB\n" RESET,
           (float)serialized_size / 1000000);

    binary_hash_array_t *deserialized_bha = binary_hash_array_deserialize(serialized_data);
    free(serialized_data);
    ASSERT_TRUE(deserialized_bha != NULL);

    start = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        int64_t value = binary_hash_array_contains(deserialized_bha, (uint8_t *)key, strlen(key));
        ASSERT_EQ(value, i);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf(CYAN "Time taken to check %d entries: %f seconds\n" RESET, 1000000, cpu_time_used);

    (void)binary_hash_array_free(deserialized_bha);
    printf(GREEN "benchmark_binary_hash_array passed\n" RESET);
}

int main(void)
{
    RUN_TEST(test_binary_hash_array_compare, tests_passed);
    RUN_TEST(test_binary_hash_array_new, tests_passed);
    RUN_TEST(test_binary_hash_array_add_and_contains, tests_passed);
    RUN_TEST(test_binary_hash_array_edge_cases, tests_passed);
    RUN_TEST(test_binary_hash_array_duplicate_keys, tests_passed);
    RUN_TEST(test_binary_hash_array_resize, tests_passed);
    RUN_TEST(benchmark_binary_hash_array, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}