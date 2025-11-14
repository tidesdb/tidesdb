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
#ifndef __BLOOM_FILTER_H__
#define __BLOOM_FILTER_H__
#include <tgmath.h>

#include "compat.h"

/**
 * bloom_filter_t
 * bloom filter struct (optimized with packed bits)
 * @param bitset the bloom filter bitset (packed in uint64_t words)
 * @param m the size of the bloom filter in bits
 * @param h the number of hash functions
 * @param size_in_words number of uint64_t words in bitset
 */
typedef struct
{
    uint64_t *bitset;
    int m;
    int h;
    int size_in_words;
} bloom_filter_t;

/**
 * bloom_filter_new
 * creates a new bloom filter
 * @param bf the bloom filter to create
 * @param p the false positive rate
 * @param n the number of elements
 * @return 0 if successful, -1 if not
 */
int bloom_filter_new(bloom_filter_t **bf, double p, int n);

/**
 * bloom_filter_add
 * adds an entry to the bloom filter
 * @param bf the bloom filter to add to
 * @param entry the entry to add
 * @param size the size of the entry
 */
void bloom_filter_add(bloom_filter_t *bf, const uint8_t *entry, size_t size);

/**
 * bloom_filter_contains
 * checks if an entry is in the bloom filter
 * @param bf the bloom filter to check
 * @param entry the entry to check
 * @param size the size of the entry
 * @return 1 if the entry is in the bloom filter, 0 if not
 */
int bloom_filter_contains(bloom_filter_t *bf, const uint8_t *entry, size_t size);

/**
 * bloom_filter_is_full
 * checks if the bloom filter is full
 * @param bf the bloom filter to check
 * @return 1 if the bloom filter is full, 0 if not
 */
int bloom_filter_is_full(bloom_filter_t *bf);

/**
 * bloom_filter_hash
 * hashes an entry
 * @param entry the entry to hash
 * @param size the size of the entry
 * @param seed the seed for the hash
 * @return the hash
 */
unsigned int bloom_filter_hash(const uint8_t *entry, size_t size, int seed);

/**
 * bloom_filter_serialize
 * serializes a bloom filter
 * @param bf the bloom filter to serialize
 * @param out_size the size of the serialized bloom filter
 * @return the serialized bloom filter
 */
uint8_t *bloom_filter_serialize(bloom_filter_t *bf, size_t *out_size);

/**
 * bloom_filter_deserialize
 * deserializes a bloom filter
 * @param data the serialized bloom filter
 * @return the deserialized bloom filter
 */
bloom_filter_t *bloom_filter_deserialize(const uint8_t *data);

/**
 * bloom_filter_free
 * frees a bloom filter
 * @param bf the bloom filter to free
 */
void bloom_filter_free(bloom_filter_t *bf);

#endif /* __BLOOM_FILTER_H__ */