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

#include "../src/compress.h"
#include "test_macros.h"

void test_compress_decompress_snappy()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, COMPRESS_SNAPPY);
    assert(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, COMPRESS_SNAPPY);
    assert(decompressed_data != NULL);
    assert(decompressed_size == data_size);
    assert(memcmp(data, decompressed_data, data_size) == 0);

    free(compressed_data);
    free(decompressed_data);
    printf(GREEN "test_compress_decompress_snappy passed\n" RESET);
}

void test_compress_decompress_lz4()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, COMPRESS_LZ4);
    assert(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, COMPRESS_LZ4);
    assert(decompressed_data != NULL);
    assert(decompressed_size == data_size);
    assert(memcmp(data, decompressed_data, data_size) == 0);

    free(compressed_data);
    free(decompressed_data);
    printf(GREEN "test_compress_decompress_lz4 passed\n" RESET);
}

void test_compress_decompress_zstd()
{
    uint8_t data[] = "test data";
    size_t data_size = sizeof(data);
    size_t compressed_size;
    size_t decompressed_size;
    uint8_t *compressed_data = compress_data(data, data_size, &compressed_size, COMPRESS_ZSTD);
    assert(compressed_data != NULL);

    uint8_t *decompressed_data =
        decompress_data(compressed_data, compressed_size, &decompressed_size, COMPRESS_ZSTD);
    assert(decompressed_data != NULL);
    assert(decompressed_size == data_size);
    assert(memcmp(data, decompressed_data, data_size) == 0);

    free(compressed_data);
    free(decompressed_data);
    printf(GREEN "test_compress_decompress_zstd passed\n" RESET);
}

int main(void)
{
    test_compress_decompress_snappy();
    test_compress_decompress_lz4();
    test_compress_decompress_zstd();
    return 0;
}