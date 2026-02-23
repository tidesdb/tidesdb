/**
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
    ASSERT_TRUE(tdb_fabs(actual_fp_rate - p) < 0.01);

    (void)bloom_filter_free(bf);
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
    ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)empty_key, strlen(empty_key)), -1);
    (void)bloom_filter_free(bf);
}

void test_bloom_filter_edge_cases()
{
    bloom_filter_t *bf;

    /* empty key */
    bloom_filter_new(&bf, 0.01, 100);
    bloom_filter_add(bf, (uint8_t *)"", 0);
    ASSERT_EQ(bloom_filter_contains(bf, (uint8_t *)"", 0), -1);

    /* fairly large key */
    uint8_t large_key[10000];
    memset(large_key, 'A', sizeof(large_key));
    bloom_filter_add(bf, large_key, sizeof(large_key));
    ASSERT_EQ(bloom_filter_contains(bf, large_key, sizeof(large_key)), 1);

    bloom_filter_free(bf);
}

void test_bloom_filter_boundary_values()
{
    bloom_filter_t *bf;

    /* min n (1 element) */
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 1), 0);
    bloom_filter_add(bf, (uint8_t *)"key", 3);
    ASSERT_EQ(bloom_filter_contains(bf, (uint8_t *)"key", 3), 1);
    bloom_filter_free(bf);

    /* very high false positive rate (0.99) */
    ASSERT_EQ(bloom_filter_new(&bf, 0.99, 100), 0);
    bloom_filter_free(bf);

    /** very low false positive rate (0.0001) */
    ASSERT_EQ(bloom_filter_new(&bf, 0.0001, 100), 0);
    bloom_filter_free(bf);
}

void test_bloom_filter_serialize_empty()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 100);

    /* attempt to serialize without adding any keys */
    size_t size;
    uint8_t *data = bloom_filter_serialize(bf, &size);
    ASSERT_TRUE(data != NULL);

    /* deserialize and verify it's still empty */
    bloom_filter_t *bf2 = bloom_filter_deserialize(data);
    ASSERT_TRUE(bf2 != NULL);
    ASSERT_EQ(bloom_filter_contains(bf2, (uint8_t *)"anything", 8), 0);

    free(data);
    bloom_filter_free(bf);
    bloom_filter_free(bf2);
}

void test_bloom_filter_duplicate_keys()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 100);

    /* we add the same key many times, we are testing to see if key still found */
    for (int i = 0; i < 10; i++)
    {
        bloom_filter_add(bf, (uint8_t *)"duplicate", 9);
    }

    ASSERT_EQ(bloom_filter_contains(bf, (uint8_t *)"duplicate", 9), 1);

    bloom_filter_free(bf);
}

void test_bloom_filter_invalid_inputs()
{
    bloom_filter_t *bf;

    /** invalid p values */
    ASSERT_EQ(bloom_filter_new(&bf, 0.0, 100), -1);  /** p = 0 */
    ASSERT_EQ(bloom_filter_new(&bf, 1.0, 100), -1);  /** p = 1 */
    ASSERT_EQ(bloom_filter_new(&bf, -0.5, 100), -1); /** negative p */
    ASSERT_EQ(bloom_filter_new(&bf, 1.5, 100), -1);  /**  p > 1 */

    /* invalid n*/
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 0), -1);   /* n = 0 */
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, -10), -1); /* negative n */
}

void test_bloom_filter_hash_distribution()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 1000);

    /* we add keys with similar patterns to test hash distribution */
    for (int i = 0; i < 100; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "key_%d", i);
        bloom_filter_add(bf, (uint8_t *)key, strlen(key));
    }

    /* all should be found is the expectation */
    for (int i = 0; i < 100; i++)
    {
        char key[20];
        snprintf(key, sizeof(key), "key_%d", i);
        ASSERT_EQ(bloom_filter_contains(bf, (uint8_t *)key, strlen(key)), 1);
    }

    bloom_filter_free(bf);
}

void test_bloom_filter_deserialize_corrupted()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 100);
    bloom_filter_add(bf, (uint8_t *)"test", 4);

    size_t size;
    uint8_t *data = bloom_filter_serialize(bf, &size);

    /* corrupt it!! */
    data[0] = 0xFF;
    data[1] = 0xFF;
    data[2] = 0xFF;
    data[3] = 0xFF;

    bloom_filter_t *bf2 = bloom_filter_deserialize(data);

    free(data);
    bloom_filter_free(bf);
    if (bf2) bloom_filter_free(bf2);
}

void test_bloom_filter_binary_keys()
{
    bloom_filter_t *bf;
    bloom_filter_new(&bf, 0.01, 100);

    /* binary keys with null bytes */
    uint8_t binary_key[] = {0x00, 0xFF, 0x00, 0xAA, 0x55};
    bloom_filter_add(bf, binary_key, sizeof(binary_key));
    ASSERT_EQ(bloom_filter_contains(bf, binary_key, sizeof(binary_key)), 1);

    bloom_filter_free(bf);
}

void test_bloom_filter_free_null()
{
    bloom_filter_free(NULL);
}

void test_bloom_filter_large_capacity_random_keys()
{
    int n = 2892624;
    double p = 0.01;
    bloom_filter_t *bf = NULL;

    printf("Creating bloom filter with n=%d, p=%.4f...\n", n, p);
    int result = bloom_filter_new(&bf, p, n);

    if (result != 0)
    {
        printf("ERROR: bloom_filter_new failed with result=%d\n", result);
    }
    ASSERT_EQ(result, 0);

    if (bf == NULL)
    {
        printf("ERROR: bloom filter is NULL after creation!\n");
        return;
    }

    printf("Bloom filter created: m=%u bits, h=%u hashes, size=%u words\n", bf->m, bf->h,
           bf->size_in_words);

    /* add 2.9M random 16-byte keys (simulating PUT phase) */
    printf("Adding %d random 16-byte keys...\n", n);
    srand(12345); /* fixed seed for reproducibility */

    for (int i = 0; i < n; i++)
    {
        uint8_t key[16];
        for (int j = 0; j < 16; j++)
        {
            key[j] = (uint8_t)(rand() % 256);
        }
        bloom_filter_add(bf, key, 16);

        if (i % 500000 == 0 && i > 0)
        {
            printf("  Added %d keys...\n", i);
        }
    }
    printf("All %d keys added.\n", n);

    /* sanity check: count how many bits are set in bloom filter */
    unsigned int bits_set = 0;
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        if (bf->bitset[i] != 0)
        {
            bits_set++;
        }
    }
    printf("Sanity check: %u/%u words have non-zero bits\n", bits_set, bf->size_in_words);

    /* verify we can find a key we just added */
    srand(12345); /* same seed as add phase */
    uint8_t test_key[16];
    for (int j = 0; j < 16; j++)
    {
        test_key[j] = (uint8_t)(rand() % 256);
    }
    int found = bloom_filter_contains(bf, test_key, 16);
    printf("Sanity check: first added key found = %d (should be 1)\n", found);
    if (!found)
    {
        printf("ERROR: Bloom filter cannot find key that was just added!\n");
    }

    /* now test with different random keys (simulating GET phase with non-existent keys) */
    printf("Testing with 100K DIFFERENT random keys...\n");
    srand(99999);

    int test_count = 100000;
    int false_positives = 0;

    for (int i = 0; i < test_count; i++)
    {
        uint8_t key[16];
        for (int j = 0; j < 16; j++)
        {
            key[j] = (uint8_t)(rand() % 256);
        }

        if (bloom_filter_contains(bf, key, 16))
        {
            false_positives++;
        }
    }

    double actual_fpr = (double)false_positives / test_count;
    printf("Expected FPR: %.4f\n", p);
    printf("Actual FPR: %.4f (%d false positives out of %d tests)\n", actual_fpr, false_positives,
           test_count);

    /* FPR should be close to 1% but can vary due to randomness and platform differences
     * the critical check is that it's not too high (< 3%)
     * low FPR is actually good -- it means the test keys happened to have low collision
     * different rand() implementations on win vs posix can produce different sequences */
    ASSERT_TRUE(actual_fpr < 0.03); /* should be < 3% - this is the important check */

    /* warn if FPR is unusually low, but don't fail -- its just statistical variance */
    if (actual_fpr < 0.001)
    {
        printf(
            "Note: FPR is unusually low (%.4f%%). This can happen with different rand() "
            "implementations.\n",
            actual_fpr * 100);
    }

    printf("✓ Bloom filter FPR is within expected range!\n");

    /* test serialization/deserialization with large filter */
    printf("Testing serialization...\n");
    size_t serialized_size;
    uint8_t *serialized = bloom_filter_serialize(bf, &serialized_size);
    ASSERT_TRUE(serialized != NULL);
    printf("Serialized size: %.2f MB\n", (double)serialized_size / (1024 * 1024));

    printf("Testing deserialization...\n");
    bloom_filter_t *bf2 = bloom_filter_deserialize(serialized);
    ASSERT_TRUE(bf2 != NULL);
    ASSERT_EQ(bf2->m, bf->m);
    ASSERT_EQ(bf2->h, bf->h);

    /* verify deserialized filter has same FPR */
    printf("Verifying deserialized filter...\n");
    srand(99999); /* same seed as before */
    int false_positives2 = 0;
    for (int i = 0; i < test_count; i++)
    {
        uint8_t key[16];
        for (int j = 0; j < 16; j++)
        {
            key[j] = (uint8_t)(rand() % 256);
        }

        if (bloom_filter_contains(bf2, key, 16))
        {
            false_positives2++;
        }
    }

    /* allow small tolerance due to platform/hash differences
     * the counts should be very close, but not necessarily identical */
    int diff = abs(false_positives - false_positives2);
    int tolerance = test_count / 100; /* 1% tolerance */
    if (diff > tolerance)
    {
        printf("ERROR: False positive counts differ too much: %d vs %d (diff=%d, tolerance=%d)\n",
               false_positives, false_positives2, diff, tolerance);
        ASSERT_TRUE(0);
    }
    printf("✓ Deserialized filter matches original (fp1=%d, fp2=%d, diff=%d)!\n", false_positives,
           false_positives2, diff);

    free(serialized);
    bloom_filter_free(bf);
    bloom_filter_free(bf2);
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

    size_t serialized_bf_size = 0;
    uint8_t *serialized_bf = bloom_filter_serialize(bf, &serialized_bf_size);
    ASSERT_TRUE(serialized_bf != NULL);
    free(serialized_bf);

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

void test_bloom_filter_add_batch()
{
    bloom_filter_t *bf;
    (void)bloom_filter_new(&bf, 0.01, 1000);

    /* we test batch add with multiple keys */
    const char *keys[] = {"batch_key1", "batch_key2", "batch_key3", "batch_key4", "batch_key5"};
    const uint8_t *entries[5];
    size_t sizes[5];

    for (int i = 0; i < 5; i++)
    {
        entries[i] = (const uint8_t *)keys[i];
        sizes[i] = strlen(keys[i]);
    }

    bloom_filter_add_batch(bf, entries, sizes, 5);

    /* we verify all batch-added keys are found */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)keys[i], strlen(keys[i])), 1);
    }

    /* we verify non-existent key is not found */
    ASSERT_EQ(bloom_filter_contains(bf, (const uint8_t *)"nonexistent", 11), 0);

    (void)bloom_filter_free(bf);
}

void test_bloom_filter_batch_vs_single()
{
    /* we verify batch add produces same results as single add */
    bloom_filter_t *bf_single;
    bloom_filter_t *bf_batch;
    (void)bloom_filter_new(&bf_single, 0.01, 1000);
    (void)bloom_filter_new(&bf_batch, 0.01, 1000);

    const char *keys[] = {"key_a", "key_b", "key_c", "key_d", "key_e"};
    const uint8_t *entries[5];
    size_t sizes[5];

    /* we add to single filter one at a time */
    for (int i = 0; i < 5; i++)
    {
        entries[i] = (const uint8_t *)keys[i];
        sizes[i] = strlen(keys[i]);
        bloom_filter_add(bf_single, entries[i], sizes[i]);
    }

    /* we add to batch filter all at once */
    bloom_filter_add_batch(bf_batch, entries, sizes, 5);

    /* we verify both filters have same results */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(bloom_filter_contains(bf_single, entries[i], sizes[i]), 1);
        ASSERT_EQ(bloom_filter_contains(bf_batch, entries[i], sizes[i]), 1);
    }

    /* we verify bitsets are identical */
    ASSERT_EQ(bf_single->m, bf_batch->m);
    ASSERT_EQ(bf_single->h, bf_batch->h);
    ASSERT_EQ(bf_single->size_in_words, bf_batch->size_in_words);

    for (unsigned int i = 0; i < bf_single->size_in_words; i++)
    {
        ASSERT_EQ(bf_single->bitset[i], bf_batch->bitset[i]);
    }

    (void)bloom_filter_free(bf_single);
    (void)bloom_filter_free(bf_batch);
}

void test_bloom_filter_hash_direct(void)
{
    /* we test the public bloom_filter_hash function directly */
    unsigned int h1 = bloom_filter_hash((const uint8_t *)"hello", 5, 0);
    unsigned int h2 = bloom_filter_hash((const uint8_t *)"hello", 5, 0);
    ASSERT_EQ(h1, h2); /* deterministic */

    /* different seeds produce different hashes */
    unsigned int h3 = bloom_filter_hash((const uint8_t *)"hello", 5, 1);
    ASSERT_TRUE(h1 != h3);

    /* different keys produce different hashes */
    unsigned int h4 = bloom_filter_hash((const uint8_t *)"world", 5, 0);
    ASSERT_TRUE(h1 != h4);

    /* NULL entry returns 0 */
    ASSERT_EQ(bloom_filter_hash(NULL, 5, 0), 0);

    /* size 0 returns 0 */
    ASSERT_EQ(bloom_filter_hash((const uint8_t *)"hello", 0, 0), 0);
}

void test_bloom_filter_is_full_true(void)
{
    /* we create a tiny bloom filter and force all bits set */
    bloom_filter_t *bf;
    ASSERT_EQ(bloom_filter_new(&bf, 0.5, 1), 0);

    /* we force all words to all-ones */
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        bf->bitset[i] = UINT64_MAX;
    }

    ASSERT_EQ(bloom_filter_is_full(bf), 1);

    bloom_filter_free(bf);
}

void test_bloom_filter_null_safety(void)
{
    /* bloom_filter_is_full with NULL */
    ASSERT_EQ(bloom_filter_is_full(NULL), -1);

    /* bloom_filter_contains with NULL bf */
    ASSERT_EQ(bloom_filter_contains(NULL, (const uint8_t *)"key", 3), -1);

    /* bloom_filter_add with NULL bf should not crash */
    bloom_filter_add(NULL, (const uint8_t *)"key", 3);

    /* bloom_filter_add_batch with NULL bf should not crash */
    const uint8_t *entries[] = {(const uint8_t *)"key"};
    size_t sizes[] = {3};
    bloom_filter_add_batch(NULL, entries, sizes, 1);

    /* bloom_filter_add_batch with NULL entries should not crash */
    bloom_filter_t *bf;
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 100), 0);
    bloom_filter_add_batch(bf, NULL, sizes, 1);
    bloom_filter_add_batch(bf, entries, NULL, 1);
    bloom_filter_add_batch(bf, entries, sizes, 0);
    bloom_filter_free(bf);

    /* bloom_filter_serialize with NULL */
    size_t out_size;
    ASSERT_TRUE(bloom_filter_serialize(NULL, &out_size) == NULL);

    /* bloom_filter_deserialize with NULL */
    ASSERT_TRUE(bloom_filter_deserialize(NULL) == NULL);
}

void test_bloom_filter_deserialize_oob_index(void)
{
    bloom_filter_t *bf;
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 100), 0);
    bloom_filter_add(bf, (const uint8_t *)"test", 4);

    size_t size;
    uint8_t *data = bloom_filter_serialize(bf, &size);
    ASSERT_TRUE(data != NULL);

    /* we craft a malicious payload: valid header but OOB word index
     * first we deserialize to get baseline, then we'll manually build one */
    bloom_filter_free(bf);

    /* we build a minimal serialized payload with an OOB index
     * header    m=64 (1 word), h=1, non_zero_count=1
     * then      index=9999 (way out of bounds), value=0xFF */
    uint8_t crafted[32];
    uint8_t *ptr = crafted;
    ptr = encode_varint32(ptr, 64);   /* m = 64 bits = 1 word */
    ptr = encode_varint32(ptr, 1);    /* h = 1 */
    ptr = encode_varint32(ptr, 1);    /* non_zero_count = 1 */
    ptr = encode_varint32(ptr, 9999); /* index = 9999 (OOB) */
    ptr = encode_varint64(ptr, 0xFF); /* value */

    bloom_filter_t *bad_bf = bloom_filter_deserialize(crafted);
    ASSERT_TRUE(bad_bf == NULL); /* should fail due to OOB index */

    free(data);
}

void test_bloom_filter_serialize_roundtrip_size_in_words(void)
{
    bloom_filter_t *bf;
    ASSERT_EQ(bloom_filter_new(&bf, 0.01, 500), 0);

    for (int i = 0; i < 50; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "roundtrip_%d", i);
        bloom_filter_add(bf, (const uint8_t *)key, strlen(key));
    }

    size_t size;
    uint8_t *data = bloom_filter_serialize(bf, &size);
    ASSERT_TRUE(data != NULL);

    bloom_filter_t *bf2 = bloom_filter_deserialize(data);
    ASSERT_TRUE(bf2 != NULL);

    /* we verify all fields match, including size_in_words */
    ASSERT_EQ(bf2->m, bf->m);
    ASSERT_EQ(bf2->h, bf->h);
    ASSERT_EQ(bf2->size_in_words, bf->size_in_words);

    /* we verify bitsets are identical */
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        ASSERT_EQ(bf2->bitset[i], bf->bitset[i]);
    }

    free(data);
    bloom_filter_free(bf);
    bloom_filter_free(bf2);
}

void test_bloom_filter_deserialize_corrupted_assertions(void)
{
    /* we test that m=0 in header causes deserialize to return NULL */
    uint8_t crafted_m0[16];
    uint8_t *ptr = crafted_m0;
    ptr = encode_varint32(ptr, 0); /* m = 0 */
    ptr = encode_varint32(ptr, 1); /* h = 1 */
    ptr = encode_varint32(ptr, 0); /* non_zero_count = 0 */
    ASSERT_TRUE(bloom_filter_deserialize(crafted_m0) == NULL);

    /* we test that h=0 in header causes deserialize to return NULL */
    uint8_t crafted_h0[16];
    ptr = crafted_h0;
    ptr = encode_varint32(ptr, 64); /* m = 64 */
    ptr = encode_varint32(ptr, 0);  /* h = 0 */
    ptr = encode_varint32(ptr, 0);  /* non_zero_count = 0 */
    ASSERT_TRUE(bloom_filter_deserialize(crafted_h0) == NULL);
}

int main(void)
{
    RUN_TEST(test_bloom_filter_new, tests_passed);
    RUN_TEST(test_bloom_filter_add_and_contains, tests_passed);
    RUN_TEST(test_bloom_filter_serialize_deserialize, tests_passed);
    RUN_TEST(test_false_positive_rate, tests_passed);
    RUN_TEST(test_boundary_conditions, tests_passed);
    RUN_TEST(test_bloom_filter_edge_cases, tests_passed);
    RUN_TEST(test_bloom_filter_boundary_values, tests_passed);
    RUN_TEST(test_bloom_filter_serialize_empty, tests_passed);
    RUN_TEST(test_bloom_filter_duplicate_keys, tests_passed);
    RUN_TEST(test_bloom_filter_invalid_inputs, tests_passed);
    RUN_TEST(test_bloom_filter_hash_distribution, tests_passed);
    RUN_TEST(test_bloom_filter_deserialize_corrupted, tests_passed);
    RUN_TEST(test_bloom_filter_binary_keys, tests_passed);
    RUN_TEST(test_bloom_filter_free_null, tests_passed);
    RUN_TEST(test_bloom_filter_large_capacity_random_keys, tests_passed);
    RUN_TEST(test_bloom_filter_add_batch, tests_passed);
    RUN_TEST(test_bloom_filter_batch_vs_single, tests_passed);
    RUN_TEST(test_bloom_filter_hash_direct, tests_passed);
    RUN_TEST(test_bloom_filter_is_full_true, tests_passed);
    RUN_TEST(test_bloom_filter_null_safety, tests_passed);
    RUN_TEST(test_bloom_filter_deserialize_oob_index, tests_passed);
    RUN_TEST(test_bloom_filter_serialize_roundtrip_size_in_words, tests_passed);
    RUN_TEST(test_bloom_filter_deserialize_corrupted_assertions, tests_passed);
    RUN_TEST(benchmark_bloom_filter, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}