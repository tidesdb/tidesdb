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

/* bit manipulation macros for packed bitset */
#define BF_BITS_PER_WORD        64
#define BF_WORD_INDEX(bit)      ((bit) / BF_BITS_PER_WORD)
#define BF_BIT_INDEX(bit)       ((bit) % BF_BITS_PER_WORD)
#define BF_SET_BIT(bitset, bit) ((bitset)[BF_WORD_INDEX(bit)] |= (1ULL << BF_BIT_INDEX(bit)))
#define BF_GET_BIT(bitset, bit) (((bitset)[BF_WORD_INDEX(bit)] >> BF_BIT_INDEX(bit)) & 1ULL)

int bloom_filter_new(bloom_filter_t **bf, double p, int n)
{
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

    /* calculate number of 64-bit words needed for packed bitset */
    (*bf)->size_in_words = ((*bf)->m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* alloc memory for the packed bitset and initialize it to 0 */
    (*bf)->bitset = calloc((size_t)(*bf)->size_in_words, sizeof(uint64_t));
    if ((*bf)->bitset == NULL)
    {
        free(*bf);
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
        int index = (int)(hash % (unsigned int)bf->m);
        BF_SET_BIT(bf->bitset, index);
    }
}

int bloom_filter_contains(bloom_filter_t *bf, const uint8_t *entry, size_t size)
{
    /* check if a key is in the bloom filter using H hash functions
     * early exit on first zero bit (likely case for negative lookups) */
    for (int i = 0; i < bf->h; i++)
    {
        unsigned int hash = bloom_filter_hash(entry, size, i);
        int index = (int)(hash % (unsigned int)bf->m);
        if (!BF_GET_BIT(bf->bitset, index))
        {
            return 0; /* definitely not in set */
        }
    }
    return 1; /* probably in set */
}

int bloom_filter_is_full(bloom_filter_t *bf)
{
    /* check if all words are fully set (optimized for packed bits) */
    for (int i = 0; i < bf->size_in_words - 1; i++)
    {
        if (bf->bitset[i] != UINT64_MAX)
        {
            return 0;
        }
    }

    /* check last word (may be partial) */
    int remaining_bits = bf->m % BF_BITS_PER_WORD;
    if (remaining_bits == 0)
    {
        return (bf->bitset[bf->size_in_words - 1] == UINT64_MAX);
    }
    else
    {
        uint64_t mask = (1ULL << remaining_bits) - 1;
        return ((bf->bitset[bf->size_in_words - 1] & mask) == mask);
    }
}

unsigned int bloom_filter_hash(const uint8_t *entry, size_t size, int seed)
{
    /* local constants */
    const uint32_t m = 0xc6a4a793;       /*  large prime */
    const uint32_t r = 24;               /* right shift value */
    const uint8_t *limit = entry + size; /* pointer to the end of the entry */
    uint32_t h =
        (uint32_t)seed ^ ((uint32_t)size * m); /* initial hash value based on seed and size */

    while (entry + 4 <= limit)
    {
        uint32_t w = decode_fixed_32((const char *)entry);
        entry += 4;
        h += w;
        h *= m;         /* multiply the hash by the large prime number */
        h ^= (h >> 16); /* xor the hash with its right-shifted value */
    }

    /* process any remaining bytes (less than 4) */
    switch (limit - entry)
    {
        case 3:
            h += (unsigned int)((uint8_t)entry[2])
                 << 16; /* add the third byte shifted left by 16 bits */
        /* fall through */
        case 2:
            h += (unsigned int)((uint8_t)entry[1])
                 << 8; /* add the second byte shifted left by 8 bits */
        /* fall through */
        case 1:
            h += (uint8_t)entry[0]; /*add the first byte*/
            h *= m;                 /* multiply the hash by the large prime */
            h ^= (h >> r);          /* xor the hash with its right-shifted value */
            break;
        default:
            /* no real action required here, break is just to avoid
             * compiler warnings */
            break;
    }

    return h;
}

uint8_t *bloom_filter_serialize(bloom_filter_t *bf, size_t *out_size)
{
    /* calculate the size of the serialized data (packed format) */
    *out_size = sizeof(int32_t) * 2 + (size_t)bf->size_in_words * sizeof(uint64_t);
    uint8_t *buffer = malloc(*out_size);
    if (buffer == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buffer;

    /* write the size of the bitset (m) - little-endian */
    ptr[0] = (uint8_t)(bf->m & 0xFF);
    ptr[1] = (uint8_t)((bf->m >> 8) & 0xFF);
    ptr[2] = (uint8_t)((bf->m >> 16) & 0xFF);
    ptr[3] = (uint8_t)((bf->m >> 24) & 0xFF);
    ptr += sizeof(int32_t);

    /* write the number of hash functions (h) - little-endian */
    ptr[0] = (uint8_t)(bf->h & 0xFF);
    ptr[1] = (uint8_t)((bf->h >> 8) & 0xFF);
    ptr[2] = (uint8_t)((bf->h >> 16) & 0xFF);
    ptr[3] = (uint8_t)((bf->h >> 24) & 0xFF);
    ptr += sizeof(int32_t);

    /* write the packed bitset - little-endian */
    for (int i = 0; i < bf->size_in_words; i++)
    {
        uint64_t word = bf->bitset[i];
        ptr[0] = (uint8_t)(word & 0xFF);
        ptr[1] = (uint8_t)((word >> 8) & 0xFF);
        ptr[2] = (uint8_t)((word >> 16) & 0xFF);
        ptr[3] = (uint8_t)((word >> 24) & 0xFF);
        ptr[4] = (uint8_t)((word >> 32) & 0xFF);
        ptr[5] = (uint8_t)((word >> 40) & 0xFF);
        ptr[6] = (uint8_t)((word >> 48) & 0xFF);
        ptr[7] = (uint8_t)((word >> 56) & 0xFF);
        ptr += sizeof(uint64_t);
    }

    return buffer;
}

bloom_filter_t *bloom_filter_deserialize(const uint8_t *data)
{
    const uint8_t *ptr = data;

    /* read the size of the bitset (m) - little-endian */
    int32_t m = ((int32_t)ptr[0]) | ((int32_t)ptr[1] << 8) | ((int32_t)ptr[2] << 16) |
                ((int32_t)ptr[3] << 24);
    ptr += sizeof(int32_t);

    /* read the number of hash functions (h) - little-endian */
    int32_t h = ((int32_t)ptr[0]) | ((int32_t)ptr[1] << 8) | ((int32_t)ptr[2] << 16) |
                ((int32_t)ptr[3] << 24);
    ptr += sizeof(int32_t);

    int size_in_words = (m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* read the packed bitset - little-endian */
    uint64_t *bitset = malloc((size_t)size_in_words * sizeof(uint64_t));
    if (bitset == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < size_in_words; i++)
    {
        bitset[i] = ((uint64_t)ptr[0]) | ((uint64_t)ptr[1] << 8) | ((uint64_t)ptr[2] << 16) |
                    ((uint64_t)ptr[3] << 24) | ((uint64_t)ptr[4] << 32) | ((uint64_t)ptr[5] << 40) |
                    ((uint64_t)ptr[6] << 48) | ((uint64_t)ptr[7] << 56);
        ptr += sizeof(uint64_t);
    }

    bloom_filter_t *bf = malloc(sizeof(bloom_filter_t));
    if (bf == NULL)
    {
        free(bitset);
        return NULL;
    }

    bf->m = m;
    bf->h = h;
    bf->bitset = bitset;
    bf->size_in_words = size_in_words;

    return bf;
}

void bloom_filter_free(bloom_filter_t *bf)
{
    if (bf == NULL)
    {
        return;
    }

    free(bf->bitset);
    free(bf);
    bf = NULL;
}

uint32_t decode_fixed_32(const char *data)
{
    return ((uint32_t)(uint8_t)data[0]) | ((uint32_t)(uint8_t)data[1] << 8) |
           ((uint32_t)(uint8_t)data[2] << 16) | ((uint32_t)(uint8_t)data[3] << 24);
}