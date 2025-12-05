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

#ifndef __sun
void test_compress_decompress_snappy()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, SNAPPY_COMPRESSION);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, SNAPPY_COMPRESSION);
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
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, LZ4_COMPRESSION);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, LZ4_COMPRESSION);
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
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, ZSTD_COMPRESSION);
    ASSERT_TRUE(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, ZSTD_COMPRESSION);
    ASSERT_TRUE(decompressed_data != NULL);
    ASSERT_EQ(decompressed_size, data_size);
    ASSERT_EQ(memcmp(data, decompressed_data, data_size), 0);
    free(compressed_data);
    free(decompressed_data);
}

int main(void)
{
#ifndef __sun
    RUN_TEST(test_compress_decompress_snappy, tests_passed);
#endif

    RUN_TEST(test_compress_decompress_lz4, tests_passed);
    RUN_TEST(test_compress_decompress_zstd, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}