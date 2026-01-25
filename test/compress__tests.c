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

#include "../src/compress.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/**
 * test_compress_decompress_algorithm
 * compresses and decompresses data using the specified compression algorithm
 * @param algo the compression algorithm to use
 * @param algo_name the name of the compression algorithm
 * @param data the data to compress
 * @param data_size the size of the data
 */
static void test_compress_decompress_algorithm(compression_algorithm algo, const char *algo_name,
                                               uint8_t *data, size_t data_size)
{
    (void)algo_name; /* unused currently.. */
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, algo);
    ASSERT_TRUE(compressed_data != NULL);
    ASSERT_TRUE(compressed_size > 0);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, algo);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}

#ifndef __sun
void test_compress_decompress_snappy()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data =
        compress_data(data, data_size, &compressed_size, TDB_COMPRESS_SNAPPY);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, TDB_COMPRESS_SNAPPY);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}
#endif

void test_compress_decompress_lz4()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}

void test_compress_decompress_lz4_fast()
{
    uint8_t data[] = "test data for lz4 fast compression";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data =
        compress_data(data, data_size, &compressed_size, TDB_COMPRESS_LZ4_FAST);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data = decompress_data(compressed_data, compressed_size,
                                                 &decompressed_size, TDB_COMPRESS_LZ4_FAST);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}

void test_compress_decompress_zstd()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_ZSTD);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, TDB_COMPRESS_ZSTD);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}

void test_compress_empty_data()
{
    uint8_t data[] = "";
    size_t data_size = 1; /* just null terminator */
    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4, "LZ4", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4_FAST, "LZ4_FAST", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_ZSTD, "ZSTD", data, data_size);
#ifndef __sun
    test_compress_decompress_algorithm(TDB_COMPRESS_SNAPPY, "SNAPPY", data, data_size);
#endif
}

void test_compress_large_data()
{
    size_t data_size = 1024 * 1024;
    uint8_t *data = malloc(data_size);
    ASSERT_TRUE(data != NULL);

    /* fill with pattern to ensure compressibility */
    for (size_t i = 0; i < data_size; i++)
    {
        data[i] = (uint8_t)(i % 256);
    }

    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4, "LZ4", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4_FAST, "LZ4_FAST", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_ZSTD, "ZSTD", data, data_size);
#ifndef __sun
    test_compress_decompress_algorithm(TDB_COMPRESS_SNAPPY, "SNAPPY", data, data_size);
#endif

    free(data);
}

void test_compress_random_data()
{
    size_t data_size = 4096;
    uint8_t *data = malloc(data_size);
    ASSERT_TRUE(data != NULL);

    /* fill with random data */
    for (size_t i = 0; i < data_size; i++)
    {
        data[i] = (uint8_t)rand();
    }

    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4, "LZ4", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_LZ4_FAST, "LZ4_FAST", data, data_size);
    test_compress_decompress_algorithm(TDB_COMPRESS_ZSTD, "ZSTD", data, data_size);
#ifndef __sun
    test_compress_decompress_algorithm(TDB_COMPRESS_SNAPPY, "SNAPPY", data, data_size);
#endif

    free(data);
}

void test_decompress_corrupted_size_header()
{
    uint8_t data[] = "test data for corruption test";
    size_t data_size = sizeof(data);
    size_t compressed_size;

    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(compressed_data != NULL);

    /* corrupt the size header to exceed UINT32_MAX */
    uint64_t corrupted_size = (uint64_t)UINT32_MAX + 1;
    encode_uint64_le_compat(compressed_data, corrupted_size);

    /* decompression should fail */
    size_t decompressed_size;
    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(decompressed_data == NULL);

    free(compressed_data);
}

void test_decompress_insufficient_data()
{
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04}; /* less than sizeof(uint64_t) */
    size_t decompressed_size;

    /* should fail for all algorithms that use size header */
    uint8_t *result = decompress_data(data, 4, &decompressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(result == NULL);

    result = decompress_data(data, 4, &decompressed_size, TDB_COMPRESS_LZ4_FAST);
    ASSERT_TRUE(result == NULL);

    result = decompress_data(data, 4, &decompressed_size, TDB_COMPRESS_ZSTD);
    ASSERT_TRUE(result == NULL);

#ifndef __sun
    result = decompress_data(data, 4, &decompressed_size, TDB_COMPRESS_SNAPPY);
    ASSERT_TRUE(result == NULL);
#endif
}

void test_size_encoding_portability()
{
    uint8_t data[] = "portability test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;

    uint8_t *compressed_lz4 = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(compressed_lz4 != NULL);
    uint64_t decoded_size_lz4 = decode_uint64_le_compat(compressed_lz4);
    ASSERT_EQ(decoded_size_lz4, data_size);
    free(compressed_lz4);

    uint8_t *compressed_zstd = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_ZSTD);
    ASSERT_TRUE(compressed_zstd != NULL);
    uint64_t decoded_size_zstd = decode_uint64_le_compat(compressed_zstd);
    ASSERT_EQ(decoded_size_zstd, data_size);
    free(compressed_zstd);

#ifndef __sun
    /* test SNAPPY */
    uint8_t *compressed_snappy =
        compress_data(data, data_size, &compressed_size, TDB_COMPRESS_SNAPPY);
    ASSERT_TRUE(compressed_snappy != NULL);
    uint64_t decoded_size_snappy = decode_uint64_le_compat(compressed_snappy);
    ASSERT_EQ(decoded_size_snappy, data_size);
    free(compressed_snappy);
#endif
}

void test_uint32_max_boundary()
{
    /* test with size exactly at UINT32_MAX -- not practical to allocate,
     * so we test the header encoding/decoding logic */
    uint8_t header[8];
    uint64_t test_size = UINT32_MAX;

    /* encode UINT32_MAX */
    encode_uint64_le_compat(header, test_size);
    uint64_t decoded = decode_uint64_le_compat(header);
    ASSERT_EQ(decoded, test_size);

    /* encode UINT32_MAX + 1 (should be rejected during decompression) */
    encode_uint64_le_compat(header, test_size + 1);
    decoded = decode_uint64_le_compat(header);
    ASSERT_EQ(decoded, test_size + 1);
    ASSERT_TRUE(decoded > UINT32_MAX);
}

void test_compressed_size_includes_header()
{
    uint8_t data[] = "test";
    size_t data_size = sizeof(data);
    size_t compressed_size;

    uint8_t *compressed = compress_data(data, data_size, &compressed_size, TDB_COMPRESS_LZ4);
    ASSERT_TRUE(compressed != NULL);
    /* compressed size should be at least sizeof(uint64_t) for the header */
    ASSERT_TRUE(compressed_size >= sizeof(uint64_t));
    free(compressed);
}

void test_invalid_compression_algorithm()
{
    uint8_t data[] = "test";
    size_t data_size = sizeof(data);
    size_t compressed_size;

    /* use invalid algorithm value */
    uint8_t *result = compress_data(data, data_size, &compressed_size, (compression_algorithm)999);
    ASSERT_TRUE(result == NULL);

    /* test decompression with invalid algorithm */
    size_t decompressed_size;
    result = decompress_data(data, data_size, &decompressed_size, (compression_algorithm)999);
    ASSERT_TRUE(result == NULL);
}

int main(void)
{
#ifndef __sun
    RUN_TEST(test_compress_decompress_snappy, tests_passed);
#endif
    RUN_TEST(test_compress_decompress_lz4, tests_passed);
    RUN_TEST(test_compress_decompress_lz4_fast, tests_passed);
    RUN_TEST(test_compress_decompress_zstd, tests_passed);
    RUN_TEST(test_compress_empty_data, tests_passed);
    RUN_TEST(test_compress_large_data, tests_passed);
    RUN_TEST(test_compress_random_data, tests_passed);
    RUN_TEST(test_decompress_corrupted_size_header, tests_passed);
    RUN_TEST(test_decompress_insufficient_data, tests_passed);
    RUN_TEST(test_invalid_compression_algorithm, tests_passed);
    RUN_TEST(test_size_encoding_portability, tests_passed);
    RUN_TEST(test_uint32_max_boundary, tests_passed);
    RUN_TEST(test_compressed_size_includes_header, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}