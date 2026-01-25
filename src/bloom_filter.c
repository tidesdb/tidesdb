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

#ifdef TDB_USE_MIMALLOC
#include <mimalloc-override.h>
#endif

#include <string.h>
#include <tgmath.h>

#include "bloom_filter.h"

#define BLOOM_UNLIKELY(x) TDB_UNLIKELY(x)

/* bit manipulation macros for packed bitset */
#define BF_BITS_PER_WORD        64
#define BF_WORD_INDEX(bit)      ((bit) / BF_BITS_PER_WORD)
#define BF_BIT_INDEX(bit)       ((bit) % BF_BITS_PER_WORD)
#define BF_SET_BIT(bitset, bit) ((bitset)[BF_WORD_INDEX(bit)] |= (1ULL << BF_BIT_INDEX(bit)))
#define BF_GET_BIT(bitset, bit) (((bitset)[BF_WORD_INDEX(bit)] >> BF_BIT_INDEX(bit)) & 1ULL)

int bloom_filter_new(bloom_filter_t **bf, double p, const int n)
{
    if (p <= 0.0 || p >= 1.0 || n <= 0)
    {
        return -1;
    }

    *bf = malloc(sizeof(bloom_filter_t));
    if (*bf == NULL)
    {
        return -1;
    }

    /* we calculate the size of the bitset (m) using the formula
     * m = -n * ln(p) / (ln(2)^2)
     *
     */
    const double m_double = ceil(-((double)n) * log(p) / (M_LN2 * M_LN2));

    /* we validate m is within valid range */
    if (m_double <= 0.0 || m_double > (double)UINT32_MAX)
    {
        free(*bf);
        return -1;
    }

    (*bf)->m = (unsigned int)m_double;

    /* we calculate the number of hash functions (h) using the formula
     * h = (m / n) * ln(2)
     *
     */
    const double h_double = ceil(((double)(*bf)->m) / n * M_LN2);

    /* we validate h is reasonable (typically 1-20) */
    if (h_double <= 0.0 || h_double > 100.0)
    {
        free(*bf);
        return -1;
    }

    (*bf)->h = (unsigned int)h_double;

    /* we calculate number of 64-bit words needed for packed bitset */
    (*bf)->size_in_words = ((*bf)->m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* we validate size_in_words to prevent overflow */
    if ((*bf)->size_in_words == 0 || (*bf)->size_in_words > UINT32_MAX / sizeof(uint64_t))
    {
        free(*bf);
        return -1;
    }

    /* we alloc memory for the packed bitset and initialize it to 0 */
    (*bf)->bitset = calloc((size_t)(*bf)->size_in_words, sizeof(uint64_t));
    if ((*bf)->bitset == NULL)
    {
        free(*bf);
        return -1;
    }

    return 0;
}

void bloom_filter_add(const bloom_filter_t *bf, const uint8_t *entry, const size_t size)
{
    if (BLOOM_UNLIKELY(bf == NULL)) return;
    if (BLOOM_UNLIKELY(entry == NULL || size == 0)) return;

    /* we cache struct fields to avoid repeated memory access */
    const unsigned int h = bf->h;
    const unsigned int m = bf->m;
    uint64_t *const bitset = bf->bitset;

    /* we add a key to the bloom filter using H hash functions */
    for (unsigned int i = 0; i < h; i++)
    {
        const unsigned int hash = bloom_filter_hash(entry, size, (int)i);
        const size_t index = hash % m;
        BF_SET_BIT(bitset, index);
    }
}

int bloom_filter_contains(const bloom_filter_t *bf, const uint8_t *entry, const size_t size)
{
    if (BLOOM_UNLIKELY(bf == NULL)) return -1;
    if (BLOOM_UNLIKELY(entry == NULL || size == 0)) return -1;

    /* we cache struct fields to avoid repeated memory access */
    const unsigned int h = bf->h;
    const unsigned int m = bf->m;
    const uint64_t *const bitset = bf->bitset;

    /* we check if a key is in the bloom filter using H hash functions
     * early exit on first zero bit (likely case for negative lookups) */
    for (unsigned int i = 0; i < h; i++)
    {
        const unsigned int hash = bloom_filter_hash(entry, size, (int)i);
        const size_t index = hash % m;
        if (!BF_GET_BIT(bitset, index))
        {
            return 0; /* definitely not in set */
        }
    }
    return 1; /* probably in set */
}

int bloom_filter_is_full(const bloom_filter_t *bf)
{
    if (BLOOM_UNLIKELY(bf == NULL)) return -1;
    if (BLOOM_UNLIKELY(bf->bitset == NULL)) return -1;

    const uint64_t *const bitset = bf->bitset;
    const unsigned int size_in_words = bf->size_in_words;

    /* we check if all words are fully set */
    for (unsigned int i = 0; i < size_in_words - 1; i++)
    {
        if (bitset[i] != UINT64_MAX)
        {
            return 0;
        }
    }

    /* we check last word (may be partial) */
    const unsigned int remaining_bits = bf->m % BF_BITS_PER_WORD;
    if (remaining_bits == 0)
    {
        return (bitset[size_in_words - 1] == UINT64_MAX);
    }
    const uint64_t mask = (1ULL << remaining_bits) - 1;
    return ((bitset[size_in_words - 1] & mask) == mask);
}

unsigned int bloom_filter_hash(const uint8_t *entry, const size_t size, const int seed)
{
    if (BLOOM_UNLIKELY(entry == NULL || size == 0)) return 0;

    /* hash constants */
    const uint32_t prime = 0xc6a4a793;
    const uint32_t shift = 24;
    const uint8_t *limit = entry + size;
    uint32_t h = (uint32_t)seed ^ ((uint32_t)size * prime);

    /* we process 4 bytes at a time */
    while (entry + 4 <= limit)
    {
        uint32_t w;
        memcpy(&w, entry, sizeof(w));
        entry += 4;
        h += w;
        h *= prime;
        h ^= (h >> 16);
    }

    /* we process any remaining bytes (less than 4) */
    switch (limit - entry)
    {
        case 3:
            h += (uint32_t)entry[2] << 16;
            /* fall through */
        case 2:
            h += (uint32_t)entry[1] << 8;
            /* fall through */
        case 1:
            h += entry[0];
            h *= prime;
            h ^= (h >> shift);
            break;
        default:
            break;
    }

    return h;
}

uint8_t *bloom_filter_serialize(const bloom_filter_t *bf, size_t *out_size)
{
    if (bf == NULL)
    {
        return NULL;
    }

    /* count non-zero words for sparse encoding */
    unsigned int non_zero_count = 0;
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        if (bf->bitset[i] != 0) non_zero_count++;
    }

    /* we allocate worst-case size
     * -- header: 3 varint32s (m, h, non_zero_count) = 15 bytes max
     * -- sparse data: each non-zero word = 5 bytes (index) + 10 bytes (value) = 15 bytes max
     */
    const size_t max_size = 15 + non_zero_count * 15;
    uint8_t *buffer = malloc(max_size);
    if (buffer == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buffer;

    /* we write header with varint encoding */
    ptr = encode_varint32(ptr, (uint32_t)bf->m);
    ptr = encode_varint32(ptr, (uint32_t)bf->h);
    ptr = encode_varint32(ptr, (uint32_t)non_zero_count);

    /* we write sparse bitset -- only non-zero words with their indices */
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        if (bf->bitset[i] != 0)
        {
            ptr = encode_varint32(ptr, (uint32_t)i);   /* word index */
            ptr = encode_varint64(ptr, bf->bitset[i]); /* word value */
        }
    }

    /* return actual size used */
    *out_size = ptr - buffer;

    /* shrink buffer to actual size */
    uint8_t *final_buffer = realloc(buffer, *out_size);
    return final_buffer ? final_buffer : buffer;
}

bloom_filter_t *bloom_filter_deserialize(const uint8_t *data)
{
    if (data == NULL)
    {
        return NULL;
    }

    const uint8_t *ptr = data;

    /* we read header with varint decoding */
    uint32_t m_u32, h_u32, non_zero_count;
    ptr = decode_varint32(ptr, &m_u32);
    ptr = decode_varint32(ptr, &h_u32);
    ptr = decode_varint32(ptr, &non_zero_count);

    unsigned int m = m_u32;
    unsigned int h = h_u32;

    /* validate deserialized values */
    if (m == 0 || h == 0)
    {
        return NULL;
    }

    /* check for potential integer overflow in size calculation */
    if (m > UINT32_MAX - BF_BITS_PER_WORD)
    {
        return NULL;
    }

    const unsigned int size_in_words = (m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* sanity check result */
    if (size_in_words == 0)
    {
        return NULL;
    }

    /* we allocate and zero-initialize bitset */
    uint64_t *bitset = calloc((size_t)size_in_words, sizeof(uint64_t));
    if (bitset == NULL)
    {
        return NULL;
    }

    /* we read sparse bitset -- only non-zero words */
    for (uint32_t i = 0; i < non_zero_count; i++)
    {
        uint32_t index;
        uint64_t value;
        ptr = decode_varint32(ptr, &index);
        ptr = decode_varint64(ptr, &value);

        /* validate index is within bounds */
        if (index >= (uint32_t)size_in_words)
        {
            free(bitset);
            return NULL;
        }

        bitset[index] = value;
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
