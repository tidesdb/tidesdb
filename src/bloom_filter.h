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
#ifndef __BLOOM_FILTER_H__
#define __BLOOM_FILTER_H__
#include "compat.h"

/**
 * bloom_filter_t
 * bloom filter struct (optimized with packed bits)
 * @param bitset the bloom filter bitset (packed in uint64_t words)
 * @param m the size of the bloom filter in bits
 * @param h the number of hash functions
 * @param size_in_words number of uint64_t words in bitset
 * @param hash_version index-derivation hash version 1 = legacy, 2 = fmix-finalized
 *                     (better avalanche / lower FPR on short keys). carried with the
 *                     filter and honored by add/contains so on-disk filters built with
 *                     an older hash keep querying with that same hash (no false negatives).
 *
 * a filter is single-writer during build (add) and immutable after.
 * once frozen it may be queried (contains) concurrently by any number of threads --
 * the query path is pure-read. add() concurrent with add()/contains() is a data race
 * (the bitset words are non-atomic read-modify-write) and is not supported.
 */
typedef struct
{
    uint64_t *bitset;
    unsigned int m;
    unsigned int h;
    unsigned int size_in_words;
    unsigned int hash_version;
} bloom_filter_t;

/**
 * bloom_filter_new
 * creates a new bloom filter sized for n elements at false-positive rate p.
 * @param bf out -- on success receives the new filter. set to NULL on an
 *           allocation or range failure; the initial invalid-argument check
 *           returns before writing *bf, so initialize it to NULL if you intend
 *           to ignore the return code
 * @param p the target false positive rate, in the open interval (0, 1)
 * @param n the expected number of elements, must be > 0
 * @return 0 on success, -1 on invalid arguments or allocation failure
 */
int bloom_filter_new(bloom_filter_t **bf, double p, int n);

/**
 * bloom_filter_add
 * adds an entry to the bloom filter. a no-op if bf is NULL, entry is NULL, or
 * size is 0.
 * @param bf the bloom filter to add to
 * @param entry the entry to add
 * @param size the size of the entry
 */
void bloom_filter_add(const bloom_filter_t *bf, const uint8_t *entry, size_t size);

/**
 * bloom_filter_contains
 * checks if an entry is in the bloom filter
 * @param bf the bloom filter to check
 * @param entry the entry to check
 * @param size the size of the entry
 * @return 1 if probably present, 0 if definitely absent, -1 if bf is NULL or the
 *         entry is empty (NULL entry or size 0)
 */
int bloom_filter_contains(const bloom_filter_t *bf, const uint8_t *entry, size_t size);

/**
 * bloom_filter_is_full
 * checks if every bit in the filter is set
 * @param bf the bloom filter to check
 * @return 1 if full, 0 if not, -1 if bf or its bitset is NULL
 */
int bloom_filter_is_full(const bloom_filter_t *bf);

/**
 * bloom_filter_hash
 * hashes an entry with the base (version-1) hash. the internal version-2 index
 * hash applies an additional finalizer on top of this.
 * @param entry the entry to hash
 * @param size the size of the entry
 * @param seed the seed for the hash
 * @return the 32-bit hash, or 0 if entry is NULL or size is 0
 */
unsigned int bloom_filter_hash(const uint8_t *entry, size_t size, int seed);

/**
 * bloom_filter_serialize
 * serializes a bloom filter to a compact binary buffer, sized exactly:
 * -- optional version prefix -- a filter that is not a legacy-hash sparse filter
 *    leads with a 0x00 sentinel byte (impossible for a v1 filter, whose first
 *    byte is varint32(m) with m >= 1) followed by a format byte whose high nibble
 *    is the bitset encoding and low nibble the hash version. a sparse hash-v2
 *    filter's format byte is 0x02 -- byte-identical to the original v2 framing --
 *    so older readers still accept it; legacy v1 sparse filters omit the prefix
 * -- header              -- varint32 m and h
 * -- bitset, whichever encoding is smaller for this filter:
 *      sparse  -- varint32 non_zero_count, then per non-zero word a varint32
 *                 index and a varint64 value. wins for under-filled filters
 *                 (70-90% savings below ~50% fill)
 *      dense   -- every word as 8 little-endian bytes, no index or count. wins
 *                 for a correctly sized (~50% full) filter, where almost every
 *                 word is non-zero and sparse would exceed the raw bitset
 * @param bf the bloom filter to serialize
 * @param out_size set to the number of bytes returned (untouched on NULL return)
 * @return the serialized buffer (caller frees), or NULL if bf is NULL or on
 *         allocation failure
 */
uint8_t *bloom_filter_serialize(const bloom_filter_t *bf, size_t *out_size);

/**
 * bloom_filter_deserialize
 * deserializes a bloom filter, accepting every format bloom_filter_serialize
 * produces -- legacy v1 sparse, v2 sparse, and dense. every field read is bounded
 * by len, so a truncated or corrupt buffer is rejected (NULL) rather than
 * over-read; an unknown hash version or bitset encoding is rejected too.
 * @param data the serialized bloom filter
 * @param len the length in bytes of the serialized buffer
 * @return the deserialized bloom filter, or NULL on malformed/truncated input
 */
bloom_filter_t *bloom_filter_deserialize(const uint8_t *data, size_t len);

/**
 * bloom_filter_free
 * frees a bloom filter
 * @param bf the bloom filter to free
 */
void bloom_filter_free(bloom_filter_t *bf);

#endif /* __BLOOM_FILTER_H__ */