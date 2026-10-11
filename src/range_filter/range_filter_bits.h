/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_BITS_H__
#define __RANGE_FILTER_BITS_H__
#include "compat.h"

/* the range filter works on keys as strings of bits rather than of bytes. an encoded key is a run
 * of variable-length codes, an infix is a window cut out of the middle of one, and both are
 * compared in the order of the keys they came from. a bit string here is stored most significant
 * bit first, so bit 0 is the top bit of the first word, and two strings compare as their words do
 * as unsigned integers. that is what lets the filter compare encoded keys without decoding them */

/**
 * range_filter_bits_t
 * a growable string of bits, written by appending and read by position
 * @param words the bits, most significant first within each word
 * @param nbits how many bits the string holds
 * @param cap_words how many words are allocated
 */
typedef struct
{
    uint64_t *words;
    size_t nbits;
    size_t cap_words;
} range_filter_bits_t;

/**
 * range_filter_bits_init
 * start an empty string that allocates on its first append
 * @param b the string to initialise
 */
void range_filter_bits_init(range_filter_bits_t *b);

/**
 * range_filter_bits_reset
 * empty the string while keeping its allocation for reuse
 * @param b the string to empty
 */
void range_filter_bits_reset(range_filter_bits_t *b);

/**
 * range_filter_bits_free
 * release the string's allocation and leave it empty
 * @param b the string to release
 */
void range_filter_bits_free(range_filter_bits_t *b);

/**
 * range_filter_bits_append
 * append the low n bits of value, its most significant of those first
 * @param b the string to append to
 * @param value the bits to append, right-aligned
 * @param n how many bits, at most 64
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int range_filter_bits_append(range_filter_bits_t *b, uint64_t value, unsigned n);

/**
 * range_filter_bits_truncate
 * cut the string back to its first n bits, clearing the bits after so later appends read true
 * @param b the string
 * @param n the length to keep, at most its current length
 */
void range_filter_bits_truncate(range_filter_bits_t *b, size_t n);

/**
 * range_filter_bits_append_range
 * append n bits of another string starting at its bit position off, reading past its end as zero
 * @param b the string to append to
 * @param src the string to copy from
 * @param off the first bit to copy
 * @param n how many bits
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int range_filter_bits_append_range(range_filter_bits_t *b, const range_filter_bits_t *src,
                                   size_t off, size_t n);

/**
 * range_filter_bits_get
 * read n bits starting at bit position off, right-aligned in the result. bits past the end of the
 * string read as 0, which is how a key shorter than a window is padded
 * @param b the string to read
 * @param off the position of the first bit
 * @param n how many bits, at most 64
 * @return the bits read
 */
uint64_t range_filter_bits_get(const range_filter_bits_t *b, size_t off, unsigned n);

/**
 * range_filter_bits_compare
 * compare two bit strings in lexicographic order, where a proper prefix sorts first
 * @param a the first string
 * @param b the second string
 * @return negative, zero or positive as a sorts before, equal to, or after b
 */
int range_filter_bits_compare(const range_filter_bits_t *a, const range_filter_bits_t *b);

/**
 * range_filter_bits_common_prefix
 * the number of leading bits two strings share
 * @param a the first string
 * @param b the second string
 * @return the length of their longest common prefix, in bits
 */
size_t range_filter_bits_common_prefix(const range_filter_bits_t *a, const range_filter_bits_t *b);

#endif /* __RANGE_FILTER_BITS_H__ */
