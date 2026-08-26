/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable/bloom_filter.h"

#include <tgmath.h>

#include "base/encoding/serialization.h" /* be32/be64 for the serialized framing */
#include "xxhash.h"                      /* XXH3 index hash, shared with the rest of the engine */

/* packed bitset word geometry */
#define BF_BITS_PER_WORD        64
#define BF_WORD_BYTES           8
#define BF_WORD_INDEX(bit)      ((bit) / BF_BITS_PER_WORD)
#define BF_BIT_INDEX(bit)       ((bit) % BF_BITS_PER_WORD)
#define BF_SET_BIT(bitset, bit) ((bitset)[BF_WORD_INDEX(bit)] |= (1ULL << BF_BIT_INDEX(bit)))

/* upper bound on the probe count accepted, both from bloom_filter_new's derivation and from a
 * serialized header; the derived h grows only logarithmically with p, so even p = 1e-30 stays well
 * under this, and the cap rejects a pathological or corrupt value that would make every query loop
 * billions of times */
#define BF_MAX_HASH_FUNCTIONS 100

/* the serialized header is a big-endian m followed by a big-endian h, then the raw bitset words */
#define BF_HEADER_BYTES (2 * (int)sizeof(uint32_t))

/* lemire's fast range reduction maps a uniform 32-bit hash into [0, range) with a single multiply
 * and shift, no division; not a true modulo but uniform, which is all a bloom filter needs */
static inline uint32_t bf_fast_range(uint32_t hash, uint32_t range)
{
    return (uint32_t)(((uint64_t)hash * (uint64_t)range) >> 32);
}

/* split one xxhash of the key into the two 32-bit base hashes double hashing combines */
static inline void bf_derive_hashes(const uint8_t *entry, size_t size, uint32_t *h1, uint32_t *h2)
{
    const uint64_t hash = XXH3_64bits(entry, size);
    *h1 = (uint32_t)hash;
    *h2 = (uint32_t)(hash >> 32);
}

int bloom_filter_new(bloom_filter_t **bf, double p, const int n)
{
    if (!bf) return -1;
    /* reject non-finite p explicitly -- a NaN slips past the range comparisons (all false for NaN)
     * and would reach an undefined (unsigned)NaN cast below */
    if (!isfinite(p) || p <= 0.0 || p >= 1.0 || n <= 0) return -1;

    *bf = malloc(sizeof(bloom_filter_t));
    if (*bf == NULL) return -1;

    /* the optimal bit count for n elements at rate p is m = -n * ln(p) / (ln(2)^2) */
    const double m_double = ceil(-((double)n) * log(p) / (M_LN2 * M_LN2));
    if (m_double <= 0.0 || m_double > (double)UINT32_MAX)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }
    (*bf)->m = (unsigned int)m_double;

    /* the optimal probe count is h = (m / n) * ln(2); the cap rejects a pathological config from a
     * floating-point edge case */
    const double h_double = ceil(((double)(*bf)->m) / n * M_LN2);
    if (h_double > (double)BF_MAX_HASH_FUNCTIONS)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }
    (*bf)->h = (unsigned int)h_double;

    (*bf)->size_in_words = ((*bf)->m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;
    if ((*bf)->size_in_words == 0 || (*bf)->size_in_words > UINT32_MAX / sizeof(uint64_t))
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }

    (*bf)->bitset = calloc((size_t)(*bf)->size_in_words, sizeof(uint64_t));
    if ((*bf)->bitset == NULL)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }
    return 0;
}

void bloom_filter_add(const bloom_filter_t *bf, const uint8_t *entry, const size_t size)
{
    if (TDB_UNLIKELY(bf == NULL || entry == NULL || size == 0)) return;

    const unsigned int h = bf->h;
    const unsigned int m = bf->m;
    uint64_t *const bitset = bf->bitset;

    uint32_t h1, h2;
    bf_derive_hashes(entry, size, &h1, &h2);
    for (unsigned int i = 0; i < h; i++)
    {
        const uint32_t index = bf_fast_range(h1 + i * h2, m);
        BF_SET_BIT(bitset, index);
    }
}

uint8_t *bloom_filter_serialize(const bloom_filter_t *bf, size_t *out_size)
{
    if (bf == NULL || out_size == NULL) return NULL;

    const size_t total = (size_t)BF_HEADER_BYTES + (size_t)bf->size_in_words * BF_WORD_BYTES;
    uint8_t *buffer = malloc(total);
    if (buffer == NULL) return NULL;

    tdb_encode_be32(bf->m, buffer);
    tdb_encode_be32(bf->h, buffer + sizeof(uint32_t));

    uint8_t *ptr = buffer + BF_HEADER_BYTES;
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        tdb_encode_be64(bf->bitset[i], ptr);
        ptr += BF_WORD_BYTES;
    }

    *out_size = total;
    return buffer;
}

int bloom_filter_contains_serialized(const uint8_t *data, const size_t len, const uint8_t *entry,
                                     const size_t size)
{
    if (data == NULL || entry == NULL || size == 0) return -1;
    if (len < (size_t)BF_HEADER_BYTES) return -1;

    const unsigned int m = tdb_decode_be32(data);
    const unsigned int h = tdb_decode_be32(data + sizeof(uint32_t));
    /* reject a corrupt header before it drives the probe loop or the size calculation off the rails
     */
    if (m == 0 || h == 0 || h > BF_MAX_HASH_FUNCTIONS) return -1;
    if (m > UINT32_MAX - BF_BITS_PER_WORD) return -1;

    const unsigned int size_in_words = (m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;
    if (len - (size_t)BF_HEADER_BYTES < (size_t)size_in_words * BF_WORD_BYTES) return -1;

    const uint8_t *const body = data + BF_HEADER_BYTES;
    uint32_t h1, h2;
    bf_derive_hashes(entry, size, &h1, &h2);
    for (unsigned int i = 0; i < h; i++)
    {
        const uint32_t index = bf_fast_range(h1 + i * h2, m);
        const uint8_t *const w = body + (size_t)BF_WORD_INDEX(index) * BF_WORD_BYTES;
        const uint64_t word = tdb_decode_be64(w);
        if (TDB_LIKELY(!((word >> BF_BIT_INDEX(index)) & 1ULL))) return 0; /* definitely absent */
    }
    return 1; /* probably present */
}

void bloom_filter_free(bloom_filter_t *bf)
{
    if (bf == NULL) return;
    free(bf->bitset);
    free(bf);
}
