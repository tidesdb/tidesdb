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
#include "binary_hash_array.h"

int binary_hash_array_compare(const void *a, const void *b)
{
    binary_hash_array_entry_t *ae = (binary_hash_array_entry_t *)a;
    binary_hash_array_entry_t *be = (binary_hash_array_entry_t *)b;

    return memcmp(ae->key, be->key,
                  sizeof(ae->key)); /* we ensure that ae->key and be->key are of the same size */
}

void binary_hash_array_hash_key(const uint8_t *key, size_t key_len, uint8_t *hash)
{
    XXH128_hash_t hash_value = XXH3_128bits(key, key_len);
    memcpy(hash, &hash_value, sizeof(hash_value)); /* copy the hash value into the hash */
}

binary_hash_array_t *binary_hash_array_new(size_t initial_capacity)
{
    binary_hash_array_t *bha = malloc(sizeof(binary_hash_array_t));
    if (!bha)
    {
        return NULL;
    }
    bha->entries = calloc(initial_capacity, sizeof(binary_hash_array_entry_t));
    if (!bha->entries)
    {
        free(bha);
        return NULL;
    }
    bha->size = 0;
    bha->capacity = initial_capacity;
    return bha;
}

void binary_hash_array_resize(binary_hash_array_t *bha, size_t new_capacity)
{
    binary_hash_array_entry_t *new_entries =
        realloc(bha->entries, new_capacity * sizeof(binary_hash_array_entry_t));
    if (new_entries)
    {
        bha->entries = new_entries;
        bha->capacity = new_capacity;
    }
}

void binary_hash_array_add(binary_hash_array_t *bha, uint8_t *key, size_t key_len, int64_t value)
{
    if (bha->size == bha->capacity)
    {
        binary_hash_array_resize(bha, bha->capacity * 2);
    }

    uint8_t hash[16];
    binary_hash_array_hash_key(key, key_len, hash);
    memcpy(bha->entries[bha->size].key, hash, sizeof(hash));
    bha->entries[bha->size].value = value;
    bha->size++;
}

uint8_t *binary_hash_array_serialize(binary_hash_array_t *bha, size_t *out_size)
{
    /* we sort the entries */
    qsort(bha->entries, bha->size, sizeof(binary_hash_array_entry_t), binary_hash_array_compare);

    *out_size = sizeof(size_t) + bha->size * sizeof(binary_hash_array_entry_t);
    uint8_t *buffer = malloc(*out_size);
    if (!buffer)
    {
        return NULL; /* allocation failed */
    }
    uint8_t *ptr = buffer;

    memcpy(ptr, &bha->size, sizeof(size_t));
    ptr += sizeof(size_t);

    memcpy(ptr, bha->entries, bha->size * sizeof(binary_hash_array_entry_t));

    return buffer;
}

binary_hash_array_t *binary_hash_array_deserialize(const uint8_t *data)
{
    const uint8_t *ptr = data;

    size_t array_size;
    memcpy(&array_size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    binary_hash_array_t *bha = malloc(sizeof(binary_hash_array_t));
    if (!bha)
    {
        return NULL; /* allocation failed */
    }
    bha->entries = malloc(array_size * sizeof(binary_hash_array_entry_t));
    if (!bha->entries)
    {
        free(bha);
        return NULL; /* allocation failed */
    }
    bha->size = array_size;

    memcpy(bha->entries, ptr, array_size * sizeof(binary_hash_array_entry_t));

    return bha;
}

void binary_hash_array_free(binary_hash_array_t *bha)
{
    free(bha->entries);
    free(bha);
}

int64_t binary_hash_array_contains(binary_hash_array_t *bha, uint8_t *key, size_t key_len)
{
    int low = 0;
    int high = bha->size - 1;

    uint8_t hash[16];
    binary_hash_array_hash_key(key, key_len, hash);

    while (low <= high)
    {
        int mid = low + (high - low) / 2;

        /* compare the hash of the key with the hash of the entry */
        int cmp_result = memcmp(hash, bha->entries[mid].key, sizeof(hash));

        if (cmp_result == 0)
        {
            /* key found */
            return bha->entries[mid].value;
        }
        else if (cmp_result < 0)
        {
            /* target is smaller, search in the left half */
            high = mid - 1;
        }
        else
        {
            /* target is larger, search in the right half */
            low = mid + 1;
        }
    }

    /* not found... */
    return -1;
}