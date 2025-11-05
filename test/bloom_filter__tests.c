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

#include "../src/bloom_filter.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_bloom_filter_new()
{
    bloom_filter_t *bf;
    int result = bloom_filter_new(&bf, 0.01, 1000);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(bf != NULL);
    ASSERT_TRUE(bf->m > 0);
    ASSERT_TRUE(bf->h > 0);
    (void)bloom_filter_free(bf);
}

void test_bloom_filter_add_and_contains()
{
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, 0.01, 1000);

    const char *key = "test_key";
    (void)bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)key, strlen(key)), 1);

    const char *non_existent_key = "non_existent_key";
    ASSERT_EQ(
        bloom_filter_contains(bf, (const uint8_t *)non_existent_key, strlen(non_existent_key)), 0);

    (void)bloom_filter_free(bf);
}

void test_bloom_filter_is_full()
{
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, 0.01, 10);

    const char *key = "test_key";
    for (int i = 0; i < 10; i++)
    {
        (void)bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }
    ASSERT_EQ(bloom_filter_is_full(bf), 0);

    (void)bloom_filter_free(bf);
    printf(GREEN "test_bloom_filter_is_full passed\n" RESET);
}

void test_bloom_filter_serialize_deserialize()
{
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, 0.01, 1000);

    const char *keys[] = {"key1", "key2", "key3", "key4", "key5"};
    for (int i = 0; i < 5; i++)
    {
        (void)bloom_filter_add(bf, (const uint8_t *)keys[i], strlen(keys[i]));
    }

    size_t serialized_size;
    uint8_t *serialized_data = bloom_filter_serialize(bf, &serialized_size);
    ASSERT_TRUE(serialized_data != NULL);

    bloom_filter_t *deserialized_bf = bloom_filter_deserialize(serialized_data);
    ASSERT_TRUE(deserialized_bf != NULL);

    ASSERT_EQ(deserialized_bf->m, bf->m);
    ASSERT_EQ(deserialized_bf->h, bf->h);

    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(bloom_filter_contains(deserialized_bf, (const uint8_t *)keys[i], strlen(keys[i])),
                  1);
    }

    ASSERT_EQ(bloom_filter_contains(deserialized_bf, (const uint8_t *)"nonexistent", 10), 0);

    free(serialized_data);
    (void)bloom_filter_free(bf);
    (void)bloom_filter_free(deserialized_bf);

    printf(GREEN "test_bloom_filter_serialize_deserialize passed\n" RESET);
}

void test_false_positive_rate()
{
    double p = 0.01;
    int n = 10000;
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, p, n);

    for (int i = 0; i < n; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "inserted_key_%d", i);
        (void)bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }

    /* with m different elements that were not inserted */
    int m = 10000;
    int false_positives = 0;
    for (int i = 0; i < m; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "test_key_%d", i + n); /** different from inserted keys */
        if (bloom_filter_contains(bf, (const uint8_t *)key, strlen(key)))
        {
            false_positives++;
        }
    }

    double actual_fp_rate = (double)false_positives / m;
    printf("Expected false positive rate: %f\n", p);
    printf("Actual false positive rate: %f\n", actual_fp_rate);

    /* some deviation since its a probabilistic data structure */
    ASSERT_TRUE(fabs(actual_fp_rate - p) < 0.01);

    (void)bloom_filter_free(bf);
    printf(GREEN "test_false_positive_rate passed\n" RESET);
}

void test_boundary_conditions()
{
    bloom_filter_t *bf;

    /* very low false positive rate */
    (void)bloom_filter_new(&bf, 0.0001, 1000);
    ASSERT_TRUE(bf != NULL);
    ASSERT_TRUE(bf->m > 0);
    ASSERT_TRUE(bf->h > 0);
    (void)bloom_filter_free(bf);

    /* very high false positive rate */
    (void)bloom_filter_new(&bf, 0.9, 1000);
    ASSERT_TRUE(bf != NULL);
    ASSERT_TRUE(bf->m > 0);
    ASSERT_TRUE(bf->h > 0);
    (void)bloom_filter_free(bf);

    /* empty key */
    (void)bloom_filter_new(&bf, 0.01, 1000);
    const char *empty_key = "";
    (void)bloom_filter_add(bf, (const uint8_t *)empty_key, strlen(empty_key));
    ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)empty_key, strlen(empty_key)), 1);
    (void)bloom_filter_free(bf);

    printf(GREEN "test_boundary_conditions passed\n" RESET);
}

void benchmark_bloom_filter()
{
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, 0.01, 1000000);

    clock_t start_add = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "key_%d", i);
        (void)bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }
    clock_t end_add = clock();
    double time_spent_add = (double)(end_add - start_add) / CLOCKS_PER_SEC;
    printf(CYAN "Adding 1,000,000 elements took %f seconds\n" RESET, time_spent_add);

    /* serializing and deserializing the bloom filter */
    size_t serialized_bf_size = 0;
    uint8_t *serialized_bf = bloom_filter_serialize(bf, &serialized_bf_size);
    ASSERT_TRUE(serialized_bf != NULL);
    free(serialized_bf);

    /* we print the size of the serialized bloom filter */
    printf(BOLDWHITE "Bloom filter size: %f MB\n" RESET, (float)serialized_bf_size / 1000000);

    clock_t start_check = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)key, strlen(key)), 1);
    }
    clock_t end_check = clock();
    double time_spent_check = (double)(end_check - start_check) / CLOCKS_PER_SEC;
    printf(CYAN "Checking 1,000,000 elements took %f seconds\n" RESET, time_spent_check);

    (void)bloom_filter_free(bf);
}

int main(void)
{
    RUN_TEST(test_bloom_filter_new, tests_passed);
    RUN_TEST(test_bloom_filter_add_and_contains, tests_passed);
    RUN_TEST(test_bloom_filter_serialize_deserialize, tests_passed);
    RUN_TEST(test_false_positive_rate, tests_passed);
    RUN_TEST(test_boundary_conditions, tests_passed);
    RUN_TEST(benchmark_bloom_filter, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}