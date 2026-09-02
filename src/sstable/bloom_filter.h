/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BLOOM_FILTER_H__
#define __BLOOM_FILTER_H__
#include "compat.h"

/**
 * bloom_filter_t
 * a packed-bit bloom filter; the index bits come from one xxhash split into two 32-bit halves and
 * combined by kirsch-mitzenmacher double hashing, so add and query derive the same bits
 * @param bitset the bitset packed in uint64_t words
 * @param m the size of the filter in bits
 * @param h the number of index probes per key
 * @param size_in_words number of uint64_t words in bitset
 *
 * a filter is single-writer during build (add) and immutable after; once frozen it is queried
 * through its serialized form (bloom_filter_contains_serialized) by any number of threads
 * concurrently. add concurrent with add is a data race and is not supported.
 */
typedef struct
{
    uint64_t *bitset;
    unsigned int m;
    unsigned int h;
    unsigned int size_in_words;
} bloom_filter_t;

/**
 * bloom_filter_new
 * create a filter sized for n elements at false-positive rate p
 * @param bf out -- the new filter on success, set to NULL on failure (initialize it to NULL first
 * if you intend to ignore the return code, as the argument check returns before writing *bf)
 * @param p target false-positive rate, in the open interval (0, 1)
 * @param n expected element count, must be > 0
 * @return 0 on success, -1 on invalid arguments or allocation failure
 */
int bloom_filter_new(bloom_filter_t **bf, double p, int n);

/**
 * bloom_filter_add
 * add an entry; a no-op if bf or entry is NULL or size is 0
 * @param bf the filter to add to
 * @param entry the entry bytes
 * @param size the entry length
 */
void bloom_filter_add(const bloom_filter_t *bf, const uint8_t *entry, size_t size);

/**
 * bloom_filter_serialize
 * serialize a filter to a compact buffer: a big-endian m and h header, then the raw bitset as
 * big-endian words, sized exactly. the format is probed in place by
 * bloom_filter_contains_serialized
 * @param bf the filter to serialize
 * @param out_size out -- the byte count returned (untouched on a NULL return)
 * @return the serialized buffer (caller frees), or NULL on a NULL argument or allocation failure
 */
uint8_t *bloom_filter_serialize(const bloom_filter_t *bf, size_t *out_size);

/**
 * bloom_filter_contains_serialized
 * query a serialized filter in place without materializing a bloom_filter_t; every field read is
 * bounded by len so a truncated or corrupt buffer is rejected rather than over-read
 * @param data serialized filter bytes as produced by bloom_filter_serialize
 * @param len length of data
 * @param entry the entry to check
 * @param size the entry length
 * @return 1 if probably present, 0 if definitely absent, -1 on a NULL/empty entry or a malformed or
 *         truncated buffer
 */
int bloom_filter_contains_serialized(const uint8_t *data, size_t len, const uint8_t *entry,
                                     size_t size);

/**
 * bloom_filter_free
 * free a filter
 * @param bf the filter to free, may be NULL
 */
void bloom_filter_free(bloom_filter_t *bf);

#endif /* __BLOOM_FILTER_H__ */
