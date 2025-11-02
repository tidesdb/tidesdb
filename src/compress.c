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
#include "compress.h"

uint8_t *compress_data(uint8_t *data, size_t data_size, size_t *compressed_size, compress_type type)
{
    uint8_t *compressed_data = NULL;

    switch (type)
    {
        case COMPRESS_SNAPPY:
        {
            *compressed_size = snappy_max_compressed_length(data_size);
            compressed_data = malloc(*compressed_size);
            if (!compressed_data) return NULL;

            snappy_compress((const char *)data, data_size, (char *)compressed_data,
                            compressed_size);
            break;
        }

        case COMPRESS_LZ4:
        case COMPRESS_ZSTD:
        {
            *compressed_size = (type == COMPRESS_LZ4) ? (size_t)LZ4_compressBound((int)data_size)
                                                      : ZSTD_compressBound(data_size);
            size_t total_size = *compressed_size + sizeof(size_t);
            compressed_data = malloc(total_size);
            if (!compressed_data) return NULL;

            memcpy(compressed_data, &data_size, sizeof(size_t));

            size_t actual_size =
                (type == COMPRESS_LZ4)
                    ? (size_t)LZ4_compress_default((const char *)data,
                                                   (char *)(compressed_data + sizeof(size_t)),
                                                   (int)data_size, (int)*compressed_size)
                    : ZSTD_compress(compressed_data + sizeof(size_t), *compressed_size, data,
                                    data_size, 1);

            if (actual_size <= 0 || (type == COMPRESS_ZSTD && ZSTD_isError(actual_size)))
            {
                free(compressed_data);
                return NULL;
            }

            *compressed_size = actual_size + sizeof(size_t);
            break;
        }

        default:
            return NULL;
    }

    return compressed_data;
}

uint8_t *decompress_data(uint8_t *data, size_t data_size, size_t *decompressed_size,
                         compress_type type)
{
    uint8_t *decompressed_data = NULL;

    switch (type)
    {
        case COMPRESS_SNAPPY:
        {
            if (snappy_uncompressed_length((const char *)data, data_size, decompressed_size) !=
                SNAPPY_OK)
                return NULL;


            decompressed_data = malloc(*decompressed_size);
            if (!decompressed_data) return NULL;

            if (snappy_uncompress((const char *)data, data_size, (char *)decompressed_data,
                                  decompressed_size) != SNAPPY_OK)
            {
                free(decompressed_data);
                return NULL;
            }
            break;
        }

        case COMPRESS_LZ4:
        case COMPRESS_ZSTD:
        {
            /* validate we have at least sizeof(size_t) bytes for the header */
            if (data_size < sizeof(size_t))
            {
                return NULL;
            }

            memcpy(decompressed_size, data, sizeof(size_t));

            const size_t MAX_DECOMPRESSED_SIZE = 1ULL << 30; /* 1GB */
            if (*decompressed_size == 0 || *decompressed_size > MAX_DECOMPRESSED_SIZE)
            {
                return NULL;
            }

            decompressed_data = malloc(*decompressed_size);
            if (!decompressed_data) return NULL;

            size_t actual_size =
                (type == COMPRESS_LZ4)
                    ? (size_t)LZ4_decompress_safe(
                          (const char *)(data + sizeof(size_t)), (char *)decompressed_data,
                          (int)(data_size - sizeof(size_t)), (int)*decompressed_size)
                    : ZSTD_decompress(decompressed_data, *decompressed_size, data + sizeof(size_t),
                                      data_size - sizeof(size_t));

            if ((type == COMPRESS_ZSTD && ZSTD_isError(actual_size)) ||
                (type == COMPRESS_LZ4 && actual_size <= 0))
            {
                free(decompressed_data);
                return NULL;
            }
            break;
        }

        default:
            return NULL;
    }

    return decompressed_data;
}