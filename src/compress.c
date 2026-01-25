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
#include "compress.h"

uint8_t *compress_data(const uint8_t *data, const size_t data_size, size_t *compressed_size,
                       const compression_algorithm type)
{
    uint8_t *compressed_data = NULL;

    if (TDB_UNLIKELY(!data))
    {
        return NULL;
    }

    switch (type)
    {
#ifndef __sun
        case TDB_COMPRESS_SNAPPY:
        {
            *compressed_size = snappy_max_compressed_length(data_size);
            const size_t total_size = *compressed_size + sizeof(uint64_t);
            compressed_data = malloc(total_size);
            if (TDB_UNLIKELY(!compressed_data)) return NULL;

            encode_uint64_le_compat(compressed_data, data_size);

            size_t actual_size = *compressed_size;
            if (TDB_UNLIKELY(snappy_compress((const char *)data, data_size,
                                             (char *)(compressed_data + sizeof(uint64_t)),
                                             &actual_size) != SNAPPY_OK))
            {
                free(compressed_data);
                return NULL;
            }

            *compressed_size = actual_size + sizeof(uint64_t);
            break;
        }
#endif

        case TDB_COMPRESS_LZ4:
        case TDB_COMPRESS_LZ4_FAST:
        case TDB_COMPRESS_ZSTD:
        {
            *compressed_size = (type == TDB_COMPRESS_LZ4 || type == TDB_COMPRESS_LZ4_FAST)
                                   ? (size_t)LZ4_compressBound((int)data_size)
                                   : ZSTD_compressBound(data_size);
            const size_t total_size = *compressed_size + sizeof(uint64_t);
            compressed_data = malloc(total_size);
            if (TDB_UNLIKELY(!compressed_data)) return NULL;

            encode_uint64_le_compat(compressed_data, data_size);

            size_t actual_size;
            if (type == TDB_COMPRESS_LZ4)
            {
                const int lz4_result = LZ4_compress_default(
                    (const char *)data, (char *)(compressed_data + sizeof(uint64_t)),
                    (int)data_size, (int)*compressed_size);
                if (TDB_UNLIKELY(lz4_result <= 0))
                {
                    free(compressed_data);
                    return NULL;
                }
                actual_size = (size_t)lz4_result;
            }
            else if (type == TDB_COMPRESS_LZ4_FAST)
            {
                const int lz4_result = LZ4_compress_fast(
                    (const char *)data, (char *)(compressed_data + sizeof(uint64_t)),
                    (int)data_size, (int)*compressed_size, 2);
                if (TDB_UNLIKELY(lz4_result <= 0))
                {
                    free(compressed_data);
                    return NULL;
                }
                actual_size = (size_t)lz4_result;
            }
            else
            {
                actual_size = ZSTD_compress(compressed_data + sizeof(uint64_t), *compressed_size,
                                            data, data_size, 1);
                if (TDB_UNLIKELY(ZSTD_isError(actual_size)))
                {
                    free(compressed_data);
                    return NULL;
                }
            }

            *compressed_size = actual_size + sizeof(uint64_t);
            break;
        }

        default:
            return NULL;
    }

    return compressed_data;
}

uint8_t *decompress_data(const uint8_t *data, const size_t data_size, size_t *decompressed_size,
                         const compression_algorithm type)
{
    uint8_t *decompressed_data = NULL;

    if (TDB_UNLIKELY(!data)) return NULL;

    switch (type)
    {
#ifndef __sun
        case TDB_COMPRESS_SNAPPY:
        {
            if (TDB_UNLIKELY(data_size < sizeof(uint64_t)))
            {
                return NULL;
            }

            const uint64_t original_size = decode_uint64_le_compat(data);

            if (TDB_UNLIKELY(original_size > UINT32_MAX))
            {
                return NULL;
            }

            *decompressed_size = (size_t)original_size;

            decompressed_data = malloc(*decompressed_size);
            if (TDB_UNLIKELY(!decompressed_data)) return NULL;

            if (TDB_UNLIKELY(snappy_uncompress((const char *)(data + sizeof(uint64_t)),
                                               data_size - sizeof(uint64_t),
                                               (char *)decompressed_data,
                                               decompressed_size) != SNAPPY_OK))
            {
                free(decompressed_data);
                return NULL;
            }
            break;
        }
#endif

        case TDB_COMPRESS_LZ4:
        case TDB_COMPRESS_LZ4_FAST:
        case TDB_COMPRESS_ZSTD:
        {
            if (TDB_UNLIKELY(data_size < sizeof(uint64_t)))
            {
                return NULL;
            }

            const uint64_t original_size = decode_uint64_le_compat(data);

            if (TDB_UNLIKELY(original_size > UINT32_MAX))
            {
                return NULL;
            }

            *decompressed_size = (size_t)original_size;

            decompressed_data = malloc(*decompressed_size);
            if (TDB_UNLIKELY(!decompressed_data)) return NULL;

            if (type == TDB_COMPRESS_LZ4 || type == TDB_COMPRESS_LZ4_FAST)
            {
                const int lz4_result = LZ4_decompress_safe(
                    (const char *)(data + sizeof(uint64_t)), (char *)decompressed_data,
                    (int)(data_size - sizeof(uint64_t)), (int)*decompressed_size);
                if (TDB_UNLIKELY(lz4_result < 0))
                {
                    free(decompressed_data);
                    return NULL;
                }
                if (TDB_UNLIKELY(lz4_result != (int)*decompressed_size))
                {
                    free(decompressed_data);
                    return NULL;
                }
            }
            else
            {
                const size_t zstd_result =
                    ZSTD_decompress(decompressed_data, *decompressed_size, data + sizeof(uint64_t),
                                    data_size - sizeof(uint64_t));
                if (TDB_UNLIKELY(ZSTD_isError(zstd_result)))
                {
                    free(decompressed_data);
                    return NULL;
                }
                if (TDB_UNLIKELY(zstd_result != *decompressed_size))
                {
                    free(decompressed_data);
                    return NULL;
                }
            }
            break;
        }

        default:
            return NULL;
    }

    return decompressed_data;
}