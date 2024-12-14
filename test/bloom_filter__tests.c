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
#include <string.h>
#include <time.h>

#include "../src/bloom_filter.h"
#include "test_macros.h"

void test_bloom_filter_new()
{
    bloom_filter_t *bf;
    int result = bloom_filter_new(&bf, 0.01, 1000);
    assert(result == 0);
    assert(bf != NULL);
    assert(bf->m > 0);
    assert(bf->h > 0);
    bloom_filter_free(bf);
    printf(GREEN "test_bloom_filter_new passed\n" RESET);
}

void test_bloom_filter_add_and_contains()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 1000);

    const char *key = "test_key";
    bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    assert(bloom_filter_contains(bf, (const uint8_t *)key, strlen(key)) == 1);

    const char *non_existent_key = "non_existent_key";
    assert(bloom_filter_contains(bf, (const uint8_t *)non_existent_key, strlen(non_existent_key)) ==
           0);

    bloom_filter_free(bf);
    printf(GREEN "test_bloom_filter_add_and_contains passed\n" RESET);
}

void test_bloom_filter_is_full()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 10);

    const char *key = "test_key";
    for (int i = 0; i < 10; i++)
    {
        bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }
    assert(bloom_filter_is_full(bf) == 0);

    bloom_filter_free(bf);
    printf(GREEN "test_bloom_filter_is_full passed\n" RESET);
}

void benchmark_bloom_filter()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 1000000);

    clock_t start_add = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[20];
        sprintf(key, "key_%d", i);
        bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }
    clock_t end_add = clock();
    double time_spent_add = (double)(end_add - start_add) / CLOCKS_PER_SEC;
    printf(CYAN "Adding 1,000,000 elements took %f seconds\n" RESET, time_spent_add);

    clock_t start_check = clock();
    for (int i = 0; i < 1000000; i++)
    {
        char key[20];
        sprintf(key, "key_%d", i);
        assert(bloom_filter_contains(bf, (const uint8_t *)key, strlen(key)) == 1);
    }
    clock_t end_check = clock();
    double time_spent_check = (double)(end_check - start_check) / CLOCKS_PER_SEC;
    printf(CYAN "Checking 1,000,000 elements took %f seconds\n" RESET, time_spent_check);

    bloom_filter_free(bf);
}

int main(void)
{
    test_bloom_filter_new();
    test_bloom_filter_add_and_contains();
    test_bloom_filter_is_full();
    benchmark_bloom_filter();
    return 0;
}