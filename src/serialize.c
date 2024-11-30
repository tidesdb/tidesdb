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

int serialize_key_value_pair(const key_value_pair_t* kvp, uint8_t** buffer, size_t* encoded_size,
                             bool compress)
{
    if (!kvp || !buffer || !encoded_size)
        return -1; /* if any of the arguments are NULL, return -1 */

    size_t total_size = sizeof(kvp->key_size) + kvp->key_size + sizeof(kvp->value_size) +
                        kvp->value_size +
                        sizeof(kvp->ttl); /* calculate the total size of the buffer */

    uint8_t* temp_buffer = (uint8_t*)malloc(total_size); /* allocate memory for the buffer */
    if (!temp_buffer) return -1;                         /* if the allocation fails, return -1 */

    uint8_t* ptr = temp_buffer; /* set the pointer to the beginning of the buffer */

    memcpy(ptr, &kvp->key_size, sizeof(kvp->key_size)); /* copy the key size to the buffer */
    ptr += sizeof(kvp->key_size);

    /* copy the key to the buffer */
    memcpy(ptr, kvp->key, kvp->key_size);
    ptr += kvp->key_size;

    /* if the value is not NULL, copy the value size and value to the buffer */
    if (kvp->value != NULL)
    {
        memcpy(ptr, &kvp->value_size, sizeof(kvp->value_size));
        ptr += sizeof(kvp->value_size);
        memcpy(ptr, kvp->value, kvp->value_size);
        ptr += kvp->value_size;
    }

    /* copy the time to live to the buffer */
    memcpy(ptr, &kvp->ttl, sizeof(kvp->ttl));

    /* if compress is true, compress the buffer, we use Zstandard for compression */
    if (compress)
    {
        size_t compressed_size =
            ZSTD_compressBound(total_size);          /* calculate the maximum compressed size */
        *buffer = (uint8_t*)malloc(compressed_size); /* allocate memory for the compressed buffer */
        if (!*buffer)
        {
            free(temp_buffer);
            return -1;
        }
        *encoded_size = ZSTD_compress(*buffer, compressed_size, temp_buffer, total_size,
                                      1); /* compress the buffer */
        free(temp_buffer);                /* free the temporary buffer */
        if (ZSTD_isError(*encoded_size))
        {
            free(*buffer);
            return -1;
        }
    }
    else
    {
        *buffer = temp_buffer;
        *encoded_size = total_size;
    }

    return 0;
}

int deserialize_key_value_pair(const uint8_t* buffer, size_t buffer_size, key_value_pair_t** kvp,
                               bool decompress)
{
    if (!buffer || !kvp) return -1; /* if any of the arguments are NULL, return -1 */

    uint8_t* temp_buffer = NULL;            /* temporary buffer for decompression */
    size_t decompressed_size = buffer_size; /* set the decompressed size to the buffer size */

    if (decompress)
    {
        decompressed_size =
            ZSTD_getFrameContentSize(buffer, buffer_size); /* get the decompressed size */
        if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
            decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
        {
            return -1;
        }
        temp_buffer =
            (uint8_t*)malloc(decompressed_size); /* allocate memory for the temporary buffer */
        if (!temp_buffer) return -1;
        size_t result = ZSTD_decompress(temp_buffer, decompressed_size, buffer,
                                        buffer_size); /* decompress the buffer */
        if (ZSTD_isError(result))
        {
            free(temp_buffer);
            return -1;
        }
    }
    else
    {
        temp_buffer = (uint8_t*)buffer;
    }

    /* set the pointer to the beginning of the buffer */
    uint8_t* ptr = temp_buffer;

    /* allocate memory for the key value pair */
    *kvp = (key_value_pair_t*)malloc(sizeof(key_value_pair_t));
    if (!*kvp) /* if the allocation fails, return -1 */
    {
        if (decompress) free(temp_buffer);
        return -1;
    }

    /* copy the key size to the key value pair */
    memcpy(&(*kvp)->key_size, ptr, sizeof((*kvp)->key_size));
    ptr += sizeof((*kvp)->key_size);                  /* move the pointer */
    (*kvp)->key = (uint8_t*)malloc((*kvp)->key_size); /* allocate memory for the key */
    if (!(*kvp)->key)                                 /* if the allocation fails, return -1 */
    {
        free(*kvp);                        /* free the key value pair */
        if (decompress) free(temp_buffer); /* free the temporary buffer */
        return -1;
    }

    /* copy the key to the key value pair */
    memcpy((*kvp)->key, ptr, (*kvp)->key_size);

    /* move the pointer */
    ptr += (*kvp)->key_size;

    /* copy the value size to the key value pair */
    memcpy(&(*kvp)->value_size, ptr, sizeof((*kvp)->value_size));

    /* move the pointer */
    ptr += sizeof((*kvp)->value_size);

    /* if the value size is not 0, allocate memory for the value and copy it to the key value pair
     */
    (*kvp)->value = (uint8_t*)malloc((*kvp)->value_size);
    if (!(*kvp)->value)
    {
        free((*kvp)->key);
        free(*kvp);
        if (decompress) free(temp_buffer);
        return -1;
    }

    /* copy the value to the key value pair */
    memcpy((*kvp)->value, ptr, (*kvp)->value_size);
    ptr += (*kvp)->value_size;

    /* copy the time to live to the key value pair */
    memcpy(&(*kvp)->ttl, ptr, sizeof((*kvp)->ttl));

    if (decompress) free(temp_buffer); /* free the temporary buffer */

    return 0;
}

int serialize_operation(const operation_t* op, uint8_t** buffer, size_t* encoded_size,
                        bool compress)
{
    if (!op || !buffer || !encoded_size) return -1;

    uint8_t* kvp_buffer = NULL;
    size_t kvp_encoded_size = 0;
    if (serialize_key_value_pair(op->kv, &kvp_buffer, &kvp_encoded_size, false) != 0) return -1;

    size_t column_family_size = strlen(op->column_family) + 1;
    size_t total_size = sizeof(op->op_code) + kvp_encoded_size + column_family_size;

    uint8_t* temp_buffer = (uint8_t*)malloc(total_size);
    if (!temp_buffer)
    {
        free(kvp_buffer);
        return -1;
    }

    uint8_t* ptr = temp_buffer;
    memcpy(ptr, &op->op_code, sizeof(op->op_code));
    ptr += sizeof(op->op_code);
    memcpy(ptr, kvp_buffer, kvp_encoded_size);
    ptr += kvp_encoded_size;
    memcpy(ptr, op->column_family, column_family_size);

    free(kvp_buffer);

    if (compress)
    {
        size_t compressed_size = ZSTD_compressBound(total_size);
        *buffer = (uint8_t*)malloc(compressed_size);
        if (!*buffer)
        {
            free(temp_buffer);
            return -1;
        }
        *encoded_size = ZSTD_compress(*buffer, compressed_size, temp_buffer, total_size, 1);
        free(temp_buffer);
        if (ZSTD_isError(*encoded_size))
        {
            free(*buffer);
            return -1;
        }
    }
    else
    {
        *buffer = temp_buffer;
        *encoded_size = total_size;
    }

    return 0;
}

int deserialize_operation(const uint8_t* buffer, size_t buffer_size, operation_t** op,
                          bool decompress)
{
    if (!buffer || !op) return -1;

    uint8_t* temp_buffer = NULL;
    size_t decompressed_size = buffer_size;

    if (decompress)
    {
        decompressed_size = ZSTD_getFrameContentSize(buffer, buffer_size);
        if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
            decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
        {
            return -1;
        }
        temp_buffer = (uint8_t*)malloc(decompressed_size);
        if (!temp_buffer) return -1;
        size_t result = ZSTD_decompress(temp_buffer, decompressed_size, buffer, buffer_size);
        if (ZSTD_isError(result))
        {
            free(temp_buffer);
            return -1;
        }
    }
    else
    {
        temp_buffer = (uint8_t*)buffer;
    }

    uint8_t* ptr = temp_buffer;
    *op = (operation_t*)malloc(sizeof(operation_t));
    if (!*op)
    {
        if (decompress) free(temp_buffer);
        return -1;
    }

    memcpy(&(*op)->op_code, ptr, sizeof((*op)->op_code));
    ptr += sizeof((*op)->op_code);

    if (deserialize_key_value_pair(ptr, decompressed_size - (ptr - temp_buffer), &(*op)->kv,
                                   false) != 0)
    {
        free(*op);
        if (decompress) free(temp_buffer);
        return -1;
    }
    ptr += sizeof((*op)->kv->key_size) + (*op)->kv->key_size + sizeof((*op)->kv->value_size) +
           (*op)->kv->value_size + sizeof((*op)->kv->ttl);

    size_t column_family_size = strlen((char*)ptr) + 1;
    (*op)->column_family = (char*)malloc(column_family_size);
    if (!(*op)->column_family)
    {
        free((*op)->kv->key);
        free((*op)->kv->value);
        free((*op)->kv);
        free(*op);
        if (decompress) free(temp_buffer);
        return -1;
    }
    memcpy((*op)->column_family, ptr, column_family_size);

    if (decompress) free(temp_buffer);

    return 0;
}

int serialize_column_family_config(const column_family_config_t* config, uint8_t** buffer,
                                   size_t* encoded_size)
{
    if (!config || !buffer || !encoded_size) return -1;

    size_t name_size = strlen(config->name) + 1;
    size_t total_size = name_size + sizeof(config->flush_threshold) + sizeof(config->max_level) +
                        sizeof(config->probability) + sizeof(config->compressed);

    uint8_t* temp_buffer = (uint8_t*)malloc(total_size);
    if (!temp_buffer) return -1;

    uint8_t* ptr = temp_buffer;
    memcpy(ptr, config->name, name_size);
    ptr += name_size;
    memcpy(ptr, &config->flush_threshold, sizeof(config->flush_threshold));
    ptr += sizeof(config->flush_threshold);
    memcpy(ptr, &config->max_level, sizeof(config->max_level));
    ptr += sizeof(config->max_level);
    memcpy(ptr, &config->probability, sizeof(config->probability));
    ptr += sizeof(config->probability);
    memcpy(ptr, &config->compressed, sizeof(config->compressed));

    *buffer = temp_buffer;
    *encoded_size = total_size;

    return 0;
}

int deserialize_column_family_config(const uint8_t* buffer, size_t buffer_size,
                                     column_family_config_t** config)
{
    if (!buffer || !config) return -1;

    const uint8_t* ptr = buffer;
    *config = (column_family_config_t*)malloc(sizeof(column_family_config_t));
    if (!*config) return -1;

    size_t name_size = strlen((char*)ptr) + 1;
    (*config)->name = (char*)malloc(name_size);
    if (!(*config)->name)
    {
        free(*config);
        return -1;
    }
    memcpy((*config)->name, ptr, name_size);
    ptr += name_size;
    memcpy(&(*config)->flush_threshold, ptr, sizeof((*config)->flush_threshold));
    ptr += sizeof((*config)->flush_threshold);
    memcpy(&(*config)->max_level, ptr, sizeof((*config)->max_level));
    ptr += sizeof((*config)->max_level);
    memcpy(&(*config)->probability, ptr, sizeof((*config)->probability));
    ptr += sizeof((*config)->probability);
    memcpy(&(*config)->compressed, ptr, sizeof((*config)->compressed));

    return 0;
}

int serialize_bloomfilter(const bloomfilter_t* bf, uint8_t** buffer, size_t* encoded_size,
                          bool compress)
{
    if (bf == NULL || buffer == NULL || encoded_size == NULL) return -1;

    size_t size = 0;
    const bloomfilter_t* current = bf;
    while (current != NULL)
    {
        size += sizeof(bloomfilter_t) + (current->size + 7) / 8;
        current = current->next;
    }

    uint8_t* temp_buffer = malloc(size);
    if (temp_buffer == NULL) return -1;

    uint8_t* ptr = temp_buffer;
    current = bf;
    while (current != NULL)
    {
        memcpy(ptr, current, sizeof(bloomfilter_t));
        ptr += sizeof(bloomfilter_t);
        memcpy(ptr, current->set, (current->size + 7) / 8);
        ptr += (current->size + 7) / 8;
        current = current->next;
    }

    if (compress)
    {
        size_t max_compressed_size = ZSTD_compressBound(size);
        *buffer = malloc(max_compressed_size);
        if (*buffer == NULL)
        {
            free(temp_buffer);
            return -1;
        }

        *encoded_size = ZSTD_compress(*buffer, max_compressed_size, temp_buffer, size, 1);
        free(temp_buffer);

        if (ZSTD_isError(*encoded_size))
        {
            free(*buffer);
            return -1;
        }
    }
    else
    {
        *buffer = temp_buffer;
        *encoded_size = size;
    }

    return 0;
}

int deserialize_bloomfilter(const uint8_t* buffer, size_t buffer_size, bloomfilter_t** bf,
                            bool decompress)
{
    if (buffer == NULL || bf == NULL) return -1;

    uint8_t* temp_buffer;
    size_t size;

    if (decompress)
    {
        size = ZSTD_getFrameContentSize(buffer, buffer_size);
        if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN) return -1;

        temp_buffer = malloc(size);
        if (temp_buffer == NULL) return -1;

        size_t decompressed_size = ZSTD_decompress(temp_buffer, size, buffer, buffer_size);
        if (ZSTD_isError(decompressed_size) || decompressed_size != size)
        {
            free(temp_buffer);
            return -1;
        }
    }
    else
    {
        temp_buffer = (uint8_t*)buffer;
        size = buffer_size;
    }

    uint8_t* ptr = temp_buffer;
    bloomfilter_t* head = NULL;
    bloomfilter_t* current = NULL;

    while (ptr < temp_buffer + size)
    {
        bloomfilter_t* new_bf = malloc(sizeof(bloomfilter_t));
        if (new_bf == NULL)
        {
            if (decompress) free(temp_buffer);
            bloomfilter_destroy(head);
            return -1;
        }

        memcpy(new_bf, ptr, sizeof(bloomfilter_t));
        ptr += sizeof(bloomfilter_t);
        new_bf->set = malloc((new_bf->size + 7) / 8);
        if (new_bf->set == NULL)
        {
            free(new_bf);
            if (decompress) free(temp_buffer);
            bloomfilter_destroy(head);
            return -1;
        }

        memcpy(new_bf->set, ptr, (new_bf->size + 7) / 8);
        ptr += (new_bf->size + 7) / 8;
        new_bf->next = NULL;

        if (head == NULL)
        {
            head = new_bf;
        }
        else
        {
            if (current == NULL)
            {
                bloomfilter_destroy(head);
                free(temp_buffer);
                return -1;
            }
            current->next = new_bf;
        }
        current = new_bf;
    }

    if (decompress) free(temp_buffer);
    *bf = head;
    return 0;
}