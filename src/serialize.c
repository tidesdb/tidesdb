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
#include "serialize.h"

bool serialize_key_value_pair(const key_value_pair* kvp, uint8_t** buffer, size_t* encoded_size,
                              bool compress)
{
    if (!kvp || !buffer || !encoded_size) return false;

    *encoded_size =
        sizeof(uint32_t) + kvp->key_size + sizeof(uint32_t) + kvp->value_size + sizeof(int64_t);
    uint8_t* temp_buffer = malloc(*encoded_size);
    if (!temp_buffer) return false;

    uint8_t* ptr = temp_buffer;

    memcpy(ptr, &kvp->key_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, kvp->key, kvp->key_size);
    ptr += kvp->key_size;

    memcpy(ptr, &kvp->value_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, kvp->value, kvp->value_size);
    ptr += kvp->value_size;

    memcpy(ptr, &kvp->ttl, sizeof(int64_t));

    if (compress)
    {
        size_t compressed_size = ZSTD_compressBound(*encoded_size);
        *buffer = (uint8_t*)malloc(compressed_size);
        if (!*buffer)
        {
            free(temp_buffer);
            return false;
        }

        compressed_size = ZSTD_compress(*buffer, compressed_size, temp_buffer, *encoded_size, 1);
        if (ZSTD_isError(compressed_size))
        {
            free(temp_buffer);
            free(*buffer);
            return false;
        }

        *encoded_size = compressed_size;
        free(temp_buffer);
    }
    else
        *buffer = temp_buffer;

    return true;
}

bool deserialize_key_value_pair(const uint8_t* buffer, size_t buffer_size, key_value_pair** kvp,
                                bool decompress)
{
    uint8_t* temp_buffer = NULL;

    if (!buffer || !kvp) return false;

    if (decompress)
    {
        size_t decompressed_size = ZSTD_getFrameContentSize(buffer, buffer_size);
        if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) return false;

        temp_buffer = malloc(decompressed_size);
        if (!temp_buffer) return false;

        decompressed_size = ZSTD_decompress(temp_buffer, decompressed_size, buffer, buffer_size);
        if (ZSTD_isError(decompressed_size))
        {
            free(temp_buffer);
            return false;
        }

        buffer = temp_buffer;
        buffer_size = decompressed_size;
    }

    *kvp = (key_value_pair*)malloc(sizeof(key_value_pair));
    if (!*kvp)
    {
        if (temp_buffer) free(temp_buffer);
        return false;
    }

    const uint8_t* ptr = buffer;

    memcpy(&(*kvp)->key_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    (*kvp)->key = (uint8_t*)malloc((*kvp)->key_size);
    if (!(*kvp)->key)
    {
        free(*kvp);
        if (temp_buffer) free(temp_buffer);
        return false;
    }
    memcpy((*kvp)->key, ptr, (*kvp)->key_size);
    ptr += (*kvp)->key_size;

    memcpy(&(*kvp)->value_size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    (*kvp)->value = (uint8_t*)malloc((*kvp)->value_size);
    if (!(*kvp)->value)
    {
        free((*kvp)->key);
        free(*kvp);
        if (temp_buffer) free(temp_buffer);
        return false;
    }
    memcpy((*kvp)->value, ptr, (*kvp)->value_size);
    ptr += (*kvp)->value_size;

    memcpy(&(*kvp)->ttl, ptr, sizeof(int64_t));

    if (temp_buffer) free(temp_buffer);

    return true;
}

bool serialize_operation(const operation* op, uint8_t** buffer, size_t* encoded_size, bool compress)
{
    if (!op || !buffer || !encoded_size) return false;

    size_t kvp_encoded_size;
    uint8_t* kvp_buffer;
    if (!serialize_key_value_pair(op->kv, &kvp_buffer, &kvp_encoded_size, false)) return false;

    size_t column_family_size = strlen(op->column_family) + 1;
    *encoded_size = sizeof(int) + kvp_encoded_size + column_family_size;

    uint8_t* temp_buffer = malloc(*encoded_size);
    if (!temp_buffer)
    {
        free(kvp_buffer);
        return false;
    }

    uint8_t* ptr = temp_buffer;
    memcpy(ptr, &op->op_code, sizeof(int));
    ptr += sizeof(int);
    memcpy(ptr, kvp_buffer, kvp_encoded_size);
    ptr += kvp_encoded_size;
    memcpy(ptr, op->column_family, column_family_size);

    free(kvp_buffer);

    if (compress)
    {
        size_t compressed_size = ZSTD_compressBound(*encoded_size);
        *buffer = (uint8_t*)malloc(compressed_size);
        if (!*buffer)
        {
            free(temp_buffer);
            return false;
        }

        compressed_size = ZSTD_compress(*buffer, compressed_size, temp_buffer, *encoded_size, 1);
        if (ZSTD_isError(compressed_size))
        {
            free(temp_buffer);
            free(*buffer);
            return false;
        }

        *encoded_size = compressed_size;
        free(temp_buffer);
    }
    else
        *buffer = temp_buffer;

    return true;
}

bool deserialize_operation(const uint8_t* buffer, size_t buffer_size, operation** op,
                           bool decompress)
{
    if (!buffer || !op) return false;

    uint8_t* temp_buffer = NULL;
    if (decompress)
    {
        size_t decompressed_size = ZSTD_getFrameContentSize(buffer, buffer_size);
        if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
            decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
        {
            return false;
        }

        temp_buffer = (uint8_t*)malloc(decompressed_size);
        if (!temp_buffer) return false;

        decompressed_size = ZSTD_decompress(temp_buffer, decompressed_size, buffer, buffer_size);
        if (ZSTD_isError(decompressed_size))
        {
            free(temp_buffer);
            return false;
        }

        buffer = temp_buffer;
        buffer_size = decompressed_size;
    }

    *op = (operation*)malloc(sizeof(operation));
    if (!*op)
    {
        if (temp_buffer) free(temp_buffer);
        return false;
    }

    const uint8_t* ptr = buffer;
    memcpy(&(*op)->op_code, ptr, sizeof(int));
    ptr += sizeof(int);

    if (!deserialize_key_value_pair(ptr, buffer_size - (ptr - buffer), &(*op)->kv, false))
    {
        free(*op);
        if (temp_buffer) free(temp_buffer);
        return false;
    }

    ptr += sizeof(uint32_t) + (*op)->kv->key_size + sizeof(uint32_t) + (*op)->kv->value_size +
           sizeof(int64_t);

    size_t column_family_size = strlen((char*)ptr) + 1;
    (*op)->column_family = (char*)malloc(column_family_size);
    if (!(*op)->column_family)
    {
        free((*op)->kv->key);
        free((*op)->kv->value);
        free((*op)->kv);
        free(*op);
        if (temp_buffer) free(temp_buffer);
        return false;
    }
    memcpy((*op)->column_family, ptr, column_family_size);

    if (temp_buffer) free(temp_buffer);

    return true;
}

bool serialize_column_family_config(const column_family_config* config, uint8_t** buffer,
                                    size_t* encoded_size)
{
    if (!config || !buffer || !encoded_size) return false;

    size_t name_size = strlen(config->name) + 1;
    *encoded_size = name_size + sizeof(int32_t) * 2 + sizeof(float) + sizeof(bool);

    uint8_t* temp_buffer = malloc(*encoded_size);
    if (!temp_buffer) return false;

    uint8_t* ptr = temp_buffer;
    memcpy(ptr, config->name, name_size);
    ptr += name_size;
    memcpy(ptr, &config->flush_threshold, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &config->max_level, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &config->probability, sizeof(float));
    ptr += sizeof(float);
    memcpy(ptr, &config->compressed, sizeof(bool));

    *buffer = temp_buffer;

    return true;
}

bool deserialize_column_family_config(const uint8_t* buffer, size_t buffer_size,
                                      column_family_config** config)
{
    if (!buffer || !config) return false;

    *config = (column_family_config*)malloc(sizeof(column_family_config));
    if (!*config) return false;

    const uint8_t* ptr = buffer;
    size_t name_size = strlen((char*)ptr) + 1;
    (*config)->name = (char*)malloc(name_size);
    if (!(*config)->name)
    {
        free(*config);
        return false;
    }
    memcpy((*config)->name, ptr, name_size);
    ptr += name_size;
    memcpy(&(*config)->flush_threshold, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(&(*config)->max_level, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(&(*config)->probability, ptr, sizeof(float));
    ptr += sizeof(float);
    memcpy(&(*config)->compressed, ptr, sizeof(bool));

    return true;
}

bool serialize_bloomfilter(const bloomfilter* bf, uint8_t** buffer, size_t* encoded_size,
                           bool compress)
{
    if (!bf || !buffer || !encoded_size) return false;

    *encoded_size = sizeof(uint32_t) * 2 + bf->size + sizeof(bool);
    uint8_t* temp_buffer = malloc(*encoded_size);
    if (!temp_buffer) return false;

    uint8_t* ptr = temp_buffer;
    memcpy(ptr, &bf->size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &bf->count, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, bf->set, bf->size);
    ptr += bf->size;
    bool has_next = (bf->next != NULL);
    memcpy(ptr, &has_next, sizeof(bool));

    if (compress)
    {
        size_t compressed_size = ZSTD_compressBound(*encoded_size);
        *buffer = (uint8_t*)malloc(compressed_size);
        if (!*buffer)
        {
            free(temp_buffer);
            return false;
        }

        compressed_size = ZSTD_compress(*buffer, compressed_size, temp_buffer, *encoded_size, 1);
        if (ZSTD_isError(compressed_size))
        {
            free(temp_buffer);
            free(*buffer);
            return false;
        }

        *encoded_size = compressed_size;
        free(temp_buffer);
    }
    else
        *buffer = temp_buffer;

    return true;
}

bool deserialize_bloomfilter(const uint8_t* buffer, size_t buffer_size, bloomfilter** bf,
                             bool decompress)
{
    if (!buffer || !bf) return false;

    uint8_t* temp_buffer = NULL;
    if (decompress)
    {
        size_t decompressed_size = ZSTD_getFrameContentSize(buffer, buffer_size);
        if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
            decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
            return false;

        temp_buffer = (uint8_t*)malloc(decompressed_size);
        if (!temp_buffer) return false;

        decompressed_size = ZSTD_decompress(temp_buffer, decompressed_size, buffer, buffer_size);
        if (ZSTD_isError(decompressed_size))
        {
            free(temp_buffer);
            return false;
        }

        buffer = temp_buffer;
        buffer_size = decompressed_size;
    }

    *bf = (bloomfilter*)malloc(sizeof(bloomfilter));
    if (!*bf)
    {
        if (temp_buffer) free(temp_buffer);
        return false;
    }

    const uint8_t* ptr = buffer;
    memcpy(&(*bf)->size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(&(*bf)->count, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    (*bf)->set = (uint8_t*)malloc((*bf)->size);
    if (!(*bf)->set)
    {
        free(*bf);
        if (temp_buffer) free(temp_buffer);

        return false;
    }
    memcpy((*bf)->set, ptr, (*bf)->size);
    ptr += (*bf)->size;

    bool has_next;
    memcpy(&has_next, ptr, sizeof(bool));
    (*bf)->next = has_next ? (bloomfilter*)malloc(sizeof(bloomfilter)) : NULL;

    if (temp_buffer) free(temp_buffer);

    return true;
}