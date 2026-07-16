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

#include "bloom_filter.h"

#include <string.h>
#include <tgmath.h>

#define BF_UNLIKELY(x) TDB_UNLIKELY(x)
#define BF_LIKELY(x)   TDB_LIKELY(x)

/* bit manipulation macros for packed bitset */
#define BF_BITS_PER_WORD        64
#define BF_WORD_INDEX(bit)      ((bit) / BF_BITS_PER_WORD)
#define BF_BIT_INDEX(bit)       ((bit) % BF_BITS_PER_WORD)
#define BF_SET_BIT(bitset, bit) ((bitset)[BF_WORD_INDEX(bit)] |= (1ULL << BF_BIT_INDEX(bit)))
#define BF_GET_BIT(bitset, bit) (((bitset)[BF_WORD_INDEX(bit)] >> BF_BIT_INDEX(bit)) & 1ULL)

/* hash mixing prime (murmur-family). chosen for good avalanche behavior in
 * the multiplicative mix below. */
#define BF_HASH_PRIME 0xc6a4a793u

/* index-derivation hash versions. version 1 is the original hash. version 2
 * appends a murmur3 fmix32 finalizer so short keys fully avalanche, which
 * decorrelates h1/h2 and lowers the false-positive rate on small structured
 * keys. the version is stored per filter; a filter is always queried with the
 * same hash that built it, so existing on-disk (v1) filters stay correct. */
#define BF_HASH_VERSION_LEGACY  1u
#define BF_HASH_VERSION_CURRENT 2u
/* serialized v2+ filters carry a 0x00 sentinel + a format byte. a v1 filter can
 * never start with 0x00 because its first field is varint32(m) and m >= 1. */
#define BF_SERIALIZE_VERSION_SENTINEL 0x00u
#define BF_SERIALIZE_VERSION_BYTES    2

/* the post-sentinel format byte packs the bitset encoding in the high nibble and
 * the hash version in the low nibble. sparse (encoding 0) with hash version 2 is
 * exactly 0x02 -- byte-identical to the original v2 framing -- so under-filled
 * filters still serialize as before and even an older binary reads them. only a
 * dense filter sets the high nibble, which an older binary rejects (it sees an
 * unknown version and falls back to a full read). hash_version stays <= 0x0F. */
#define BF_FORMAT_HASH_VERSION(b)     ((unsigned int)((b)&0x0Fu))
#define BF_FORMAT_ENCODING(b)         ((unsigned int)((b) >> 4))
#define BF_MAKE_FORMAT_BYTE(enc, ver) ((uint8_t)(((enc) << 4) | ((ver)&0x0Fu)))

/* bitset encodings. sparse stores only non-zero words (varint idx + varint64 val);
 * dense stores every word as 8 little-endian bytes. a correctly sized filter is
 * ~50% full so almost every 64-bit word is non-zero, which makes sparse larger
 * than the raw bitset -- serialize picks whichever encoding is smaller. */
#define BF_ENCODING_SPARSE 0u
#define BF_ENCODING_DENSE  1u

/* upper bound on the number of hash functions accepted by bloom_filter_new.
 * derived h grows logarithmically with target false-positive rate; even at
 * p = 1e-30 the formula yields h ~ 100, so this is a generous sanity ceiling
 * to reject pathological configs (negative or absurdly large values from
 * floating-point edge cases). typical real-world h is 7-15. */
#define BF_MAX_HASH_FUNCTIONS 100

/* raw bytes per dense bitset word (uint64 little-endian) */
#define BF_DENSE_WORD_BYTES 8

/* lemire's fast range reduction maps a uniform uint32_t hash into [0, range)
 * without integer division. it uses a single 64-bit multiply + shift.
 * not a true modulo but produces a uniform distribution, which is all
 * a bloom filter needs. */
static inline uint32_t bf_fast_range(const uint32_t hash, const uint32_t range)
{
    return (uint32_t)(((uint64_t)hash * (uint64_t)range) >> 32);
}

/**
 * bf_hash_inline
 * static inline version of bloom_filter_hash for internal use
 * allows compiler to inline in hot paths (add/contains)
 */
static inline uint32_t bf_hash_inline(const uint8_t *entry, const size_t size, const uint32_t seed)
{
    const uint32_t prime = BF_HASH_PRIME;
    const uint8_t *limit = entry + size;
    uint32_t h = seed ^ ((uint32_t)size * prime);

    /* read each 4-byte chunk little-endian so a key hashes identically on every host, matching the
     * byte-wise tail below rather than depending on host byte order. on a little-endian host this
     * is the same value the old host-order read produced, so existing filters keep querying. */
#if UINTPTR_MAX == UINT64_MAX
    while (entry + 8 <= limit)
    {
        const uint32_t w1 = decode_uint32_le_compat(entry);
        const uint32_t w2 = decode_uint32_le_compat(entry + 4);
        entry += 8;
        h += w1;
        h *= prime;
        h ^= (h >> 16);
        h += w2;
        h *= prime;
        h ^= (h >> 16);
    }
    if (entry + 4 <= limit)
    {
        const uint32_t w = decode_uint32_le_compat(entry);
        entry += 4;
        h += w;
        h *= prime;
        h ^= (h >> 16);
    }
#else
    while (entry + 4 <= limit)
    {
        const uint32_t w = decode_uint32_le_compat(entry);
        entry += 4;
        h += w;
        h *= prime;
        h ^= (h >> 16);
    }
#endif

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
            h ^= (h >> 24);
            break;
        default:
            break;
    }
    return h;
}

/* murmur3 fmix32 -- full-avalanche finalizer. applied by the v2 hash so even a
 * short key whose base hash had weak mixing produces well-spread index bits. */
static inline uint32_t bf_fmix32(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

/* v2 index hash -- base hash plus the fmix32 finalizer */
static inline uint32_t bf_hash_v2_inline(const uint8_t *entry, const size_t size,
                                         const uint32_t seed)
{
    return bf_fmix32(bf_hash_inline(entry, size, seed));
}

/* derive the two base hashes for a filter using the hash version it was built with,
 * so a filter is always queried with the same scheme that set its bits */
static inline void bf_derive_hashes(const bloom_filter_t *bf, const uint8_t *entry,
                                    const size_t size, uint32_t *h1, uint32_t *h2)
{
    if (bf->hash_version >= BF_HASH_VERSION_CURRENT)
    {
        *h1 = bf_hash_v2_inline(entry, size, 0);
        *h2 = bf_hash_v2_inline(entry, size, 1);
    }
    else
    {
        *h1 = bf_hash_inline(entry, size, 0);
        *h2 = bf_hash_inline(entry, size, 1);
    }
}

int bloom_filter_new(bloom_filter_t **bf, double p, const int n)
{
    /* reject non-finite p explicitly -- a NaN slips past the range comparisons
     * (all false for NaN) and would reach an undefined (unsigned)NaN cast below */
    if (!isfinite(p) || p <= 0.0 || p >= 1.0 || n <= 0)
    {
        return -1;
    }

    *bf = malloc(sizeof(bloom_filter_t));
    if (*bf == NULL)
    {
        return -1;
    }

    /**** we calculate the size of the bitset (m) using the formula
     ***  m = -n * ln(p) / (ln(2)^2)
     **
     */
    const double m_double = ceil(-((double)n) * log(p) / (M_LN2 * M_LN2));

    /* we validate m is within valid range */
    if (m_double <= 0.0 || m_double > (double)UINT32_MAX)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }

    (*bf)->m = (unsigned int)m_double;

    /* we calculate the number of hash functions (h) using the formula
     * h = (m / n) * ln(2)
     *
     */
    const double h_double = ceil(((double)(*bf)->m) / n * M_LN2);

    /* we validate h is reasonable -- typical real-world values are 7-15;
     * BF_MAX_HASH_FUNCTIONS rejects pathological configs from FP edge cases.
     * h_double is ceil() of a strictly positive quantity (m >= 1, n >= 1) so it
     * is always >= 1; only the upper bound can actually trip */
    if (h_double > (double)BF_MAX_HASH_FUNCTIONS)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }

    (*bf)->h = (unsigned int)h_double;

    /* we calculate number of 64-bit words needed for packed bitset */
    (*bf)->size_in_words = ((*bf)->m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* we validate size_in_words to prevent overflow */
    if ((*bf)->size_in_words == 0 || (*bf)->size_in_words > UINT32_MAX / sizeof(uint64_t))
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }

    /* we alloc memory for the packed bitset and initialize it to 0 */
    (*bf)->bitset = calloc((size_t)(*bf)->size_in_words, sizeof(uint64_t));
    if ((*bf)->bitset == NULL)
    {
        free(*bf);
        *bf = NULL;
        return -1;
    }

    /* freshly built filters use the current (best) index hash */
    (*bf)->hash_version = BF_HASH_VERSION_CURRENT;

    return 0;
}

void bloom_filter_add(const bloom_filter_t *bf, const uint8_t *entry, const size_t size)
{
    if (BF_UNLIKELY(bf == NULL)) return;
    if (BF_UNLIKELY(entry == NULL || size == 0)) return;

    /* we cache struct fields to avoid repeated memory access */
    const unsigned int h = bf->h;
    const unsigned int m = bf->m;
    uint64_t *const bitset = bf->bitset;

    uint32_t h1, h2;
    bf_derive_hashes(bf, entry, size, &h1, &h2);

    for (unsigned int i = 0; i < h; i++)
    {
        const uint32_t hash = h1 + i * h2;
        const uint32_t index = bf_fast_range(hash, m);
        BF_SET_BIT(bitset, index);
    }
}

int bloom_filter_contains(const bloom_filter_t *bf, const uint8_t *entry, const size_t size)
{
    if (BF_UNLIKELY(bf == NULL)) return -1;
    if (BF_UNLIKELY(entry == NULL || size == 0)) return -1;

    /* we cache struct fields to avoid repeated memory access */
    const unsigned int h = bf->h;
    const unsigned int m = bf->m;
    const uint64_t *const bitset = bf->bitset;

    /* Kirsch-Mitzenmacher double hashing + fast range reduction
     * 2 hashes + h cheap probes instead of h full hashes + h divisions */
    uint32_t h1, h2;
    bf_derive_hashes(bf, entry, size, &h1, &h2);

    for (unsigned int i = 0; i < h; i++)
    {
        const uint32_t hash = h1 + i * h2;
        const uint32_t index = bf_fast_range(hash, m);
        if (BF_LIKELY(!BF_GET_BIT(bitset, index)))
        {
            return 0; /* definitely not in set */
        }
    }
    return 1; /* probably in set */
}

int bloom_filter_is_full(const bloom_filter_t *bf)
{
    if (BF_UNLIKELY(bf == NULL)) return -1;
    if (BF_UNLIKELY(bf->bitset == NULL)) return -1;

    const uint64_t *const bitset = bf->bitset;
    const unsigned int size_in_words = bf->size_in_words;

    /*** prevents `size_in_words - 1` from underflowing as unsigned.
     **  the constructor rejects size_in_words == 0, but a future refactor or a
     *   deserialized filter that bypasses the constructor could produce one. */
    if (BF_UNLIKELY(size_in_words == 0)) return -1;

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
    if (BF_UNLIKELY(entry == NULL || size == 0)) return 0;

    return bf_hash_inline(entry, size, (uint32_t)seed);
}

/* encoded byte length of a varint, so serialize can size its buffer exactly */
static inline size_t bf_varint32_len(uint32_t v)
{
    size_t n = 1;
    while (v >= 0x80u)
    {
        v >>= 7;
        n++;
    }
    return n;
}

static inline size_t bf_varint64_len(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80u)
    {
        v >>= 7;
        n++;
    }
    return n;
}

/* write a uint64 as 8 little-endian bytes (endian-canonical, like the varints) */
static inline uint8_t *bf_put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < BF_DENSE_WORD_BYTES; i++) p[i] = (uint8_t)(v >> (8 * i));
    return p + BF_DENSE_WORD_BYTES;
}

uint8_t *bloom_filter_serialize(const bloom_filter_t *bf, size_t *out_size)
{
    if (bf == NULL)
    {
        return NULL;
    }

    /* count non-zero words and measure the exact sparse body in one pass */
    unsigned int non_zero_count = 0;
    size_t sparse_body = 0;
    for (unsigned int i = 0; i < bf->size_in_words; i++)
    {
        if (bf->bitset[i] != 0)
        {
            non_zero_count++;
            sparse_body += bf_varint32_len(i) + bf_varint64_len(bf->bitset[i]);
        }
    }
    sparse_body += bf_varint32_len((uint32_t)non_zero_count); /* sparse carries the count */

    /* dense stores every word raw; at ~50% fill nearly all words are non-zero so
     * sparse bloats past raw -- take whichever encoding is smaller. ties favor
     * sparse (only it is byte-identical to the legacy v2 framing). */
    const size_t dense_body = (size_t)bf->size_in_words * BF_DENSE_WORD_BYTES;
    const unsigned int encoding =
        (dense_body < sparse_body) ? BF_ENCODING_DENSE : BF_ENCODING_SPARSE;

    /* a 0x00 sentinel + format byte leads any filter that is not a legacy-hash
     * sparse filter (which stays in the original sentinel-free v1 layout). the
     * sentinel is impossible for a v1 filter, whose first byte is varint32(m),
     * m >= 1, so deserialize can tell the formats apart with no ambiguity. */
    const int versioned =
        (bf->hash_version > BF_HASH_VERSION_LEGACY) || (encoding != BF_ENCODING_SPARSE);

    size_t total = bf_varint32_len((uint32_t)bf->m) + bf_varint32_len((uint32_t)bf->h);
    total += versioned ? BF_SERIALIZE_VERSION_BYTES : 0;
    total += (encoding == BF_ENCODING_DENSE) ? dense_body : sparse_body;

    uint8_t *buffer = malloc(total);
    if (buffer == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buffer;
    if (versioned)
    {
        *ptr++ = BF_SERIALIZE_VERSION_SENTINEL;
        *ptr++ = BF_MAKE_FORMAT_BYTE(encoding, bf->hash_version);
    }

    ptr = encode_varint32(ptr, (uint32_t)bf->m);
    ptr = encode_varint32(ptr, (uint32_t)bf->h);

    if (encoding == BF_ENCODING_DENSE)
    {
        /* raw bitset, one little-endian word at a time -- size_in_words is
         * re-derived from m on read so no length prefix is needed */
        for (unsigned int i = 0; i < bf->size_in_words; i++) ptr = bf_put_u64le(ptr, bf->bitset[i]);
    }
    else
    {
        ptr = encode_varint32(ptr, (uint32_t)non_zero_count);
        for (unsigned int i = 0; i < bf->size_in_words; i++)
        {
            if (bf->bitset[i] != 0)
            {
                ptr = encode_varint32(ptr, (uint32_t)i);   /* word index */
                ptr = encode_varint64(ptr, bf->bitset[i]); /* word value */
            }
        }
    }

    /* the buffer was sized exactly, so no shrink is needed */
    *out_size = (size_t)(ptr - buffer);
    return buffer;
}

/* thin adapters over the canonical bounded decoders in compat.h -- advance *pp and return 0 on
 * success, -1 on truncation or an overlong varint, keeping the caller's advance-and-status style.
 */
static int bf_get_varint32(const uint8_t **pp, const uint8_t *end, uint32_t *out)
{
    const uint8_t *next = decode_varint32_safe(*pp, end, out);
    if (!next) return -1;
    *pp = next;
    return 0;
}

static int bf_get_varint64(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    const uint8_t *next = decode_varint64_safe(*pp, end, out);
    if (!next) return -1;
    *pp = next;
    return 0;
}

/* parse a serialized filter's header (optional version sentinel + format byte, then m and h) and
 * point *out_body at the bitset body. shared by deserialize and contains_serialized so both read
 * the framing identically. returns 0 on success, -1 on a truncated or invalid header. */
static int bf_parse_header(const uint8_t *data, size_t len, unsigned int *out_encoding,
                           unsigned int *out_hash_version, unsigned int *out_m, unsigned int *out_h,
                           const uint8_t **out_body)
{
    if (data == NULL || len == 0) return -1;

    const uint8_t *ptr = data;
    const uint8_t *const end = data + len;

    /* a leading 0x00 marks the versioned format (v1 can never start with 0x00,
     * its first field is varint32(m) with m >= 1). absent it, this is a legacy
     * v1 sparse filter that must keep being queried with the v1 hash. the format
     * byte packs the bitset encoding (high nibble) and hash version (low nibble);
     * a legacy v2 filter's byte is 0x02 -> sparse + hash version 2. */
    unsigned int hash_version = BF_HASH_VERSION_LEGACY;
    unsigned int encoding = BF_ENCODING_SPARSE;
    if (ptr[0] == BF_SERIALIZE_VERSION_SENTINEL)
    {
        if (end - ptr < BF_SERIALIZE_VERSION_BYTES) return -1; /* sentinel + format byte */
        ptr++;                                                 /* skip sentinel */
        const uint8_t format = *ptr++;
        hash_version = BF_FORMAT_HASH_VERSION(format);
        encoding = BF_FORMAT_ENCODING(format);
        /* reject an unknown hash version (querying with an undefined scheme would
         * silently false-negative) or an unknown bitset encoding */
        if (hash_version < BF_HASH_VERSION_LEGACY || hash_version > BF_HASH_VERSION_CURRENT)
            return -1;
        if (encoding != BF_ENCODING_SPARSE && encoding != BF_ENCODING_DENSE) return -1;
    }

    /* we read header with bounded varint decoding */
    uint32_t m_u32, h_u32;
    if (bf_get_varint32(&ptr, end, &m_u32) != 0) return -1;
    if (bf_get_varint32(&ptr, end, &h_u32) != 0) return -1;

    /* h is the per-query probe count, so an out-of-range h from a corrupt filter would turn every
     * query into a multi-billion-iteration loop. reject it with the same cap the constructor
     * enforces, which a valid filter can never exceed. */
    if (m_u32 == 0 || h_u32 == 0 || h_u32 > BF_MAX_HASH_FUNCTIONS) return -1;
    if (m_u32 > UINT32_MAX - BF_BITS_PER_WORD) return -1; /* size calculation overflow */

    *out_encoding = encoding;
    *out_hash_version = hash_version;
    *out_m = m_u32;
    *out_h = h_u32;
    *out_body = ptr;
    return 0;
}

bloom_filter_t *bloom_filter_deserialize(const uint8_t *data, const size_t len)
{
    unsigned int encoding, hash_version, m, h;
    const uint8_t *ptr;
    if (bf_parse_header(data, len, &encoding, &hash_version, &m, &h, &ptr) != 0) return NULL;

    const uint8_t *const end = data + len;
    const unsigned int size_in_words = (m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;

    /* we allocate and zero-initialize bitset */
    uint64_t *bitset = calloc((size_t)size_in_words, sizeof(uint64_t));
    if (bitset == NULL)
    {
        return NULL;
    }

    if (encoding == BF_ENCODING_DENSE)
    {
        /* raw bitset-- exactly size_in_words little-endian words must remain */
        if ((size_t)(end - ptr) < (size_t)size_in_words * BF_DENSE_WORD_BYTES)
        {
            free(bitset);
            return NULL;
        }
        for (unsigned int i = 0; i < size_in_words; i++)
        {
            uint64_t value = 0;
            for (int j = 0; j < BF_DENSE_WORD_BYTES; j++) value |= (uint64_t)(*ptr++) << (8 * j);
            bitset[i] = value;
        }
    }
    else
    {
        uint32_t non_zero_count;
        if (bf_get_varint32(&ptr, end, &non_zero_count) != 0)
        {
            free(bitset);
            return NULL;
        }

        /* a valid filter never has more non-zero words than total words; reject a
         * corrupt count up front so the loop below can't be driven past the buffer */
        if (non_zero_count > size_in_words)
        {
            free(bitset);
            return NULL;
        }

        /* we read sparse bitset -- only non-zero words */
        for (uint32_t i = 0; i < non_zero_count; i++)
        {
            uint32_t index;
            uint64_t value;
            if (bf_get_varint32(&ptr, end, &index) != 0 || bf_get_varint64(&ptr, end, &value) != 0)
            {
                free(bitset);
                return NULL;
            }

            /* we validate index is within bounds */
            if (index >= (uint32_t)size_in_words)
            {
                free(bitset);
                return NULL;
            }

            bitset[index] = value;
        }
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
    bf->hash_version = hash_version;

    return bf;
}

int bloom_filter_contains_serialized(const uint8_t *data, const size_t len, const uint8_t *entry,
                                     const size_t size)
{
    if (data == NULL || entry == NULL || size == 0) return -1;

    unsigned int encoding, hash_version, m, h;
    const uint8_t *body;
    if (bf_parse_header(data, len, &encoding, &hash_version, &m, &h, &body) != 0) return -1;

    /* the sparse encoding is rare for a well-filled filter; fall back to a full deserialize rather
     * than re-scan its varint word list on every probe */
    if (encoding != BF_ENCODING_DENSE)
    {
        bloom_filter_t *bf = bloom_filter_deserialize(data, len);
        if (bf == NULL) return -1;
        const int r = bloom_filter_contains(bf, entry, size);
        bloom_filter_free(bf);
        return r;
    }

    const uint8_t *const end = data + len;
    const unsigned int size_in_words = (m + BF_BITS_PER_WORD - 1) / BF_BITS_PER_WORD;
    if ((size_t)(end - body) < (size_t)size_in_words * BF_DENSE_WORD_BYTES) return -1;

    /* a stack header carries only the fields the hash derivation reads; the raw bitset is probed in
     * place, one little-endian word at a time, so no filter is materialized */
    bloom_filter_t hdr;
    hdr.m = m;
    hdr.h = h;
    hdr.size_in_words = size_in_words;
    hdr.hash_version = hash_version;
    hdr.bitset = NULL;

    uint32_t h1, h2;
    bf_derive_hashes(&hdr, entry, size, &h1, &h2);

    for (unsigned int i = 0; i < h; i++)
    {
        const uint32_t index = bf_fast_range(h1 + i * h2, m);
        const uint8_t *const w = body + (size_t)(index / BF_BITS_PER_WORD) * BF_DENSE_WORD_BYTES;
        uint64_t word = 0;
        for (int j = 0; j < BF_DENSE_WORD_BYTES; j++) word |= (uint64_t)w[j] << (8 * j);
        if (BF_LIKELY(!((word >> (index % BF_BITS_PER_WORD)) & 1ULL)))
        {
            return 0; /* definitely not in set */
        }
    }
    return 1; /* probably in set */
}

void bloom_filter_free(bloom_filter_t *bf)
{
    if (bf == NULL)
    {
        return;
    }

    free(bf->bitset);
    free(bf);
}
