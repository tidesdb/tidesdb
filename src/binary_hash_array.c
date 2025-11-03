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
    /* check if either a or b are NULL */
    if (!a)
    {
        if (!b)
        {
            return 0; /* both are NULL */
        }
        return -1; /* a is NULL */
    }

    if (!b)
    {
        return 1; /* b is NULL */
    }

    binary_hash_array_entry_t *ae = (binary_hash_array_entry_t *)a;
    binary_hash_array_entry_t *be = (binary_hash_array_entry_t *)b;

    return memcmp(
        ae->key, be->key,
        sizeof(ae->key)); /* keys should be of same size as their hash is fixed at 16 bytes */
}

void binary_hash_array_hash_key(const uint8_t *key, size_t key_len, uint8_t *hash)
{
    XXH128_hash_t hash_value = XXH3_128bits(key, key_len);
    memcpy(hash, &hash_value, sizeof(hash_value)); /* copy the hash value into the hash */
}

/* stable merge sort implementation for binary hash array entries */
static void merge_entries(binary_hash_array_entry_t *arr, size_t left, size_t mid, size_t right,
                          binary_hash_array_entry_t *temp)
{
    size_t i = left;
    size_t j = mid + 1;
    size_t k = left;

    while (i <= mid && j <= right)
    {
        int cmp = memcmp(arr[i].key, arr[j].key, 16);
        if (cmp <= 0)
        {
            memcpy(&temp[k++], &arr[i++], sizeof(binary_hash_array_entry_t));
        }
        else
        {
            memcpy(&temp[k++], &arr[j++], sizeof(binary_hash_array_entry_t));
        }
    }

    while (i <= mid)
    {
        memcpy(&temp[k++], &arr[i++], sizeof(binary_hash_array_entry_t));
    }

    while (j <= right)
    {
        memcpy(&temp[k++], &arr[j++], sizeof(binary_hash_array_entry_t));
    }

    for (i = left; i <= right; i++)
    {
        memcpy(&arr[i], &temp[i], sizeof(binary_hash_array_entry_t));
    }
}

static void merge_sort_entries(binary_hash_array_entry_t *arr, size_t left, size_t right,
                               binary_hash_array_entry_t *temp)
{
    if (left < right)
    {
        size_t mid = left + (right - left) / 2;
        merge_sort_entries(arr, left, mid, temp);
        merge_sort_entries(arr, mid + 1, right, temp);
        merge_entries(arr, left, mid, right, temp);
    }
}

static void stable_sort_entries(binary_hash_array_entry_t *entries, size_t count)
{
    if (count <= 1) return;

    binary_hash_array_entry_t *temp = malloc(count * sizeof(binary_hash_array_entry_t));
    if (!temp) return; /* allocation failed, skip sorting */

    merge_sort_entries(entries, 0, count - 1, temp);
    free(temp);
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
    bha->size = 0; /* no entries yet */
    bha->capacity = initial_capacity;

    return bha;
}

int binary_hash_array_resize(binary_hash_array_t *bha, size_t new_capacity)
{
    binary_hash_array_entry_t *new_entries =
        realloc(bha->entries, new_capacity * sizeof(binary_hash_array_entry_t));
    if (new_entries)
    {
        bha->entries = new_entries;
        bha->capacity = new_capacity;

        return 0;
    }
    return -1; /* could not resize */
}

int binary_hash_array_add(binary_hash_array_t *bha, uint8_t *key, size_t key_len, int64_t value)
{
    if (bha->size == bha->capacity)
    {
        if (binary_hash_array_resize(bha, bha->capacity * 2) == -1)
        {
            return -1; /* could not resize */
        }
    }

    uint8_t hash[16];
    binary_hash_array_hash_key(key, key_len, hash);
    memcpy(bha->entries[bha->size].key, hash, sizeof(hash));
    bha->entries[bha->size].value = value;
    bha->size++;

    return 0;
}

uint8_t *binary_hash_array_serialize(binary_hash_array_t *bha, size_t *out_size)
{
    stable_sort_entries(bha->entries, bha->size);

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
    bha = NULL;
}

int64_t binary_hash_array_contains(binary_hash_array_t *bha, uint8_t *key, size_t key_len)
{
    if (!bha || !key || bha->size == 0)
    {
        return -1; /* invalid input */
    }

    size_t low = 0;
    size_t high = bha->size - 1;

    uint8_t hash[16];
    binary_hash_array_hash_key(key, key_len, hash);

    while (low <= high)
    {
        size_t mid = low + (high - low) / 2;

        if (mid >= bha->size)
        {
            break; /* prevent out of bounds access */
        }

        int cmp_result = memcmp(hash, bha->entries[mid].key, sizeof(hash));

        if (cmp_result == 0)
        {
            /* found the key */
            return bha->entries[mid].value;
        }

        if (cmp_result < 0)
        {
            /* target is smaller, search in the left half */
            if (mid == 0) break; /* must prevent underflow */
            high = mid - 1;
        }
        else
        {
            /* target is larger, search in the right half */
            low = mid + 1;
        }
    }

    return -1;
}