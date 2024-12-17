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
#include "bloom_filter.h"

int bloom_filter_new(bloom_filter_t **bf, double p, int n)
{
    /* alloc memory for the bloom filter structure */
    *bf = malloc(sizeof(bloom_filter_t));
    if (*bf == NULL)
    {
        return -1;
    }

    /* calculate the size of the bitset (m) using the formula
     * m = -n * ln(p) / (ln(2)^2)
     *
     */
    (*bf)->m = (int)ceil(-((double)n) * log(p) / (M_LN2 * M_LN2));

    /* calculate the number of hash functions (h) using the formula
     * h = (m / n) * ln(2)
     *
     */
    (*bf)->h = (int)ceil(((double)(*bf)->m) / n * M_LN2);

    /* alloc memory for the bitset and initialize it to 0 */
    (*bf)->bitset = calloc((*bf)->m, sizeof(int8_t));
    if ((*bf)->bitset == NULL)
    {
        return -1;
    }

    return 0;
}

void bloom_filter_add(bloom_filter_t *bf, const uint8_t *entry, size_t size)
{
    /* add a key to the bloom filter using H hash functions */
    for (int i = 0; i < bf->h; i++)
    {
        unsigned int hash = bloom_filter_hash(entry, size, i);
        bf->bitset[hash % bf->m] = 1;
    }
}

int bloom_filter_contains(bloom_filter_t *bf, const uint8_t *entry, size_t size)
{
    /* check if a key is in the bloom filter using H hash functions */
    for (int i = 0; i < bf->h; i++)
    {
        unsigned int hash = bloom_filter_hash(entry, size, i);
        if (bf->bitset[hash % bf->m] == 0)
        {
            return 0;
        }
    }
    return 1;
}

int bloom_filter_is_full(bloom_filter_t *bf)
{
    /* check if all the bits are set to 1 */
    for (int i = 0; i < bf->m; i++)
    {
        if (bf->bitset[i] == 0)
        {
            return 0;
        }
    }
    return 1;
}

unsigned int bloom_filter_hash(const uint8_t *entry, size_t size, int seed)
{
    /* local constants */
    const uint32_t m = 0xc6a4a793;       /*  large prime */
    const uint32_t r = 24;               /* right shift value */
    const uint8_t *limit = entry + size; /* pointer to the end of the entry */
    uint32_t h = seed ^ (size * m);      /* initial hash value based on seed and size */

    /* we process the entry 4 bytes at a time */
    while (entry + 4 <= limit)
    {
        /* we decode the 4 bytes into a 32-bit unsigned integer */
        uint32_t w = decode_fixed_32((const char *)entry);
        entry += 4;     /* move the pointer forward by 4 bytes */
        h += w;         /** add the decoded value to the hash */
        h *= m;         /* multiply the hash by the large prime number */
        h ^= (h >> 16); /* xor the hash with its right-shifted value */
    }

    /* process any remaining bytes (less than 4) */
    switch (limit - entry)
    {
        case 3:
            h += (uint8_t)entry[2] << 16; /* add the third byte shifted left by 16 bits */
        /* fall through */
        case 2:
            h += (uint8_t)entry[1] << 8; /* add the second byte shifted left by 8 bits */
        /* fall through */
        case 1:
            h += (uint8_t)entry[0]; /*add the first byte*/
            h *= m;                 /* multiply the hash by the large prime */
            h ^= (h >> r);          /* xor the hash with its right-shifted value */
            break;
    }

    return h;
}

uint8_t *bloom_filter_serialize(bloom_filter_t *bf, size_t *out_size)
{
    /* calculate the size of the serialized data */
    *out_size = sizeof(int32_t) * 2 + bf->m * sizeof(int8_t);
    uint8_t *buffer = malloc(*out_size);
    uint8_t *ptr = buffer;

    /* write the size of the bitset (m) */
    memcpy(ptr, &bf->m, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* write the number of hash functions (h) */
    memcpy(ptr, &bf->h, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* write the bitset */
    memcpy(ptr, bf->bitset, bf->m * sizeof(int8_t));

    return buffer;
}

bloom_filter_t *bloom_filter_deserialize(const uint8_t *data)
{
    const uint8_t *ptr = data;

    /* read the size of the bitset (m) */
    int32_t m;
    memcpy(&m, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* read the number of hash functions (h) */
    int32_t h;
    memcpy(&h, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);

    /* read the bitset */
    int8_t *bitset = malloc(m * sizeof(int8_t));
    memcpy(bitset, ptr, m * sizeof(int8_t));

    bloom_filter_t *bf = malloc(sizeof(bloom_filter_t));
    bf->m = m;
    bf->h = h;
    bf->bitset = bitset;

    return bf;
}

void bloom_filter_free(bloom_filter_t *bf)
{
    free(bf->bitset);
    free(bf);
    bf = NULL;
}

uint32_t decode_fixed_32(const char *data)
{
    return ((uint32_t)(uint8_t)data[0]) | ((uint32_t)(uint8_t)data[1] << 8) |
           ((uint32_t)(uint8_t)data[2] << 16) | ((uint32_t)(uint8_t)data[3] << 24);
}