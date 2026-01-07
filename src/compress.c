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

uint8_t *compress_data(uint8_t *data, size_t data_size, size_t *compressed_size,
                       compression_algorithm type)
{
    uint8_t *compressed_data = NULL;

    switch (type)
    {
#ifndef __sun
        case SNAPPY_COMPRESSION:
        {
            *compressed_size = snappy_max_compressed_length(data_size);
            size_t total_size = *compressed_size + sizeof(uint64_t);
            compressed_data = malloc(total_size);
            if (!compressed_data) return NULL;

            /* store original size as uint64_t for cross-architecture portability */
            encode_uint64_le_compat(compressed_data, (uint64_t)data_size);

            size_t actual_size = *compressed_size;
            if (snappy_compress((const char *)data, data_size,
                                (char *)(compressed_data + sizeof(uint64_t)),
                                &actual_size) != SNAPPY_OK)
            {
                free(compressed_data);
                return NULL;
            }

            *compressed_size = actual_size + sizeof(uint64_t);
            break;
        }
#endif

        case LZ4_COMPRESSION:
        case ZSTD_COMPRESSION:
        {
            *compressed_size = (type == LZ4_COMPRESSION) ? (size_t)LZ4_compressBound((int)data_size)
                                                         : ZSTD_compressBound(data_size);
            size_t total_size = *compressed_size + sizeof(uint64_t);
            compressed_data = malloc(total_size);
            if (!compressed_data) return NULL;

            /* store original size as uint64_t for cross-architecture portability */
            encode_uint64_le_compat(compressed_data, (uint64_t)data_size);

            size_t actual_size;
            if (type == LZ4_COMPRESSION)
            {
                int lz4_result = LZ4_compress_default((const char *)data,
                                                      (char *)(compressed_data + sizeof(uint64_t)),
                                                      (int)data_size, (int)*compressed_size);
                if (lz4_result <= 0)
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
                if (ZSTD_isError(actual_size))
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

uint8_t *decompress_data(uint8_t *data, size_t data_size, size_t *decompressed_size,
                         compression_algorithm type)
{
    uint8_t *decompressed_data = NULL;

    switch (type)
    {
#ifndef __sun
        case SNAPPY_COMPRESSION:
        {
            if (data_size < sizeof(uint64_t))
            {
                return NULL;
            }

            /* decode original size from uint64_t for cross-architecture portability */
            uint64_t original_size = decode_uint64_le_compat(data);

            /* block manager only supports uint32_t sizes */
            if (original_size > UINT32_MAX)
            {
                return NULL;
            }

            *decompressed_size = (size_t)original_size;

            decompressed_data = malloc(*decompressed_size);
            if (!decompressed_data) return NULL;

            if (snappy_uncompress((const char *)(data + sizeof(uint64_t)),
                                  data_size - sizeof(uint64_t), (char *)decompressed_data,
                                  decompressed_size) != SNAPPY_OK)
            {
                free(decompressed_data);
                return NULL;
            }
            break;
        }
#endif

        case LZ4_COMPRESSION:
        case ZSTD_COMPRESSION:
        {
            if (data_size < sizeof(uint64_t))
            {
                return NULL;
            }

            /* decode original size from uint64_t for cross-architecture portability */
            uint64_t original_size = decode_uint64_le_compat(data);

            /* block manager only supports uint32_t sizes */
            if (original_size > UINT32_MAX)
            {
                return NULL;
            }

            *decompressed_size = (size_t)original_size;

            decompressed_data = malloc(*decompressed_size);
            if (!decompressed_data) return NULL;

            if (type == LZ4_COMPRESSION)
            {
                int lz4_result = LZ4_decompress_safe(
                    (const char *)(data + sizeof(uint64_t)), (char *)decompressed_data,
                    (int)(data_size - sizeof(uint64_t)), (int)*decompressed_size);
                if (lz4_result < 0)
                {
                    free(decompressed_data);
                    return NULL;
                }
                if (lz4_result != (int)*decompressed_size)
                {
                    free(decompressed_data);
                    return NULL;
                }
            }
            else
            {
                size_t zstd_result =
                    ZSTD_decompress(decompressed_data, *decompressed_size, data + sizeof(uint64_t),
                                    data_size - sizeof(uint64_t));
                if (ZSTD_isError(zstd_result))
                {
                    free(decompressed_data);
                    return NULL;
                }
                if (zstd_result != *decompressed_size)
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