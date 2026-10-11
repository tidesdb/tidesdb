/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_DTRIE_H__
#define __RANGE_FILTER_DTRIE_H__
#include "compat.h"
#include "range_filter/range_filter_bits.h"

/* when several keys in a gap cut down to the same infix, a plain store keeps that infix once per
 * key, and the copies tell the keys apart no better than one would. a d-trie spends the space of
 * the copies on what does tell them apart. the keys of such a group agree on every bit up to the
 * end of the infix window, so the trie is built over what follows, the tails. it is a binary trie
 * holding only branches and leaves, one leaf per key, each leaf knowing its key's tail up to the
 * point where it parts from every other, and after the nodes come trailing strings, the next t bits
 * of each tail, with t as large as the space left allows.
 *
 * the trie is written in preorder. a branch is a 0, the length of the shared path below it, and
 * that path's bits. a leaf is a 1. a branch's children both start with the bit that chose them, 0
 * for the left and 1 for the right, and that bit is never written. the root alone has no such bit.
 * path lengths are written in unary or in elias-gamma, whichever makes the trie smaller, and the
 * leading bit of the trie says which. the trailing strings follow in key order.
 *
 * tails are compared with their ends padded by zeros, as the infix window reads keys, so two tails
 * equal once padded cannot be told apart by any number of bits and such a group gets no trie */

/* the most keys one d-trie holds, which bounds the explicit stack its walks keep */
#define RANGE_FILTER_DTRIE_MAX_KEYS 64

/**
 * range_filter_dtrie_t
 * the shape of a d-trie found by parsing it, enough to search it
 * @param at the bit where the trie starts, its format bit
 * @param keys how many leaves, one per key
 * @param trie_bits the bits the format bit and the nodes take
 * @param trail the length of each trailing string
 */
typedef struct
{
    size_t at;
    size_t keys;
    size_t trie_bits;
    size_t trail;
} range_filter_dtrie_t;

/**
 * range_filter_dtrie_probe_t
 * a query endpoint's tail, read the way the keys' tails were
 * @param key the endpoint, encoded, or NULL when that side is not tested
 * @param tail_off the first bit of the tail in the endpoint
 */
typedef struct
{
    const range_filter_bits_t *key;
    size_t tail_off;
} range_filter_dtrie_probe_t;

/**
 * range_filter_dtrie_encode
 * append a d-trie and its trailing strings over a group's tails, filling exactly budget_bits
 * @param keys the group's keys in increasing order
 * @param n how many, between 2 and RANGE_FILTER_DTRIE_MAX_KEYS
 * @param tail_off where the tails start in every key
 * @param budget_bits the bits the trie, its trailing strings and the zero fill after them take
 * @param out the string to append to
 * @param fitted set to 1 when the trie was appended, 0 when it does not fit or two tails are equal
 *        once padded, and then nothing was appended
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int range_filter_dtrie_encode(const range_filter_bits_t *keys, size_t n, size_t tail_off,
                              size_t budget_bits, range_filter_bits_t *out, int *fitted);

/**
 * range_filter_dtrie_parse
 * read the nodes of a d-trie, checking they form one whole trie inside the bits allowed
 * @param src the string holding it
 * @param at the bit where it starts
 * @param limit the bit it must not reach
 * @param out the shape, with trail left 0 until range_filter_dtrie_set_budget settles it
 * @return TDB_SUCCESS, or TDB_ERR_CORRUPTION when the bits do not hold a trie
 */
int range_filter_dtrie_parse(const range_filter_bits_t *src, size_t at, size_t limit,
                             range_filter_dtrie_t *out);

/**
 * range_filter_dtrie_set_budget
 * settle the trailing string length from the space the trie was given, as the encoder did
 * @param t the parsed shape
 * @param budget_bits the bits the trie and its trailing strings were given
 * @return TDB_SUCCESS, or TDB_ERR_CORRUPTION when the nodes alone overrun the budget
 */
int range_filter_dtrie_set_budget(range_filter_dtrie_t *t, size_t budget_bits);

/**
 * range_filter_dtrie_may_contain
 * whether some key of the trie may lie at or above lo and at or below hi
 * @param src the string holding it
 * @param t the shape, parsed and with its budget set
 * @param lo the low endpoint, or one with a NULL key when the low side holds for every key
 * @param hi the high endpoint, or one with a NULL key when the high side holds for every key
 * @return 1 when one may, 0 when none can, 1 as well when the trie is damaged
 */
int range_filter_dtrie_may_contain(const range_filter_bits_t *src, const range_filter_dtrie_t *t,
                                   const range_filter_dtrie_probe_t *lo,
                                   const range_filter_dtrie_probe_t *hi);

#endif /* __RANGE_FILTER_DTRIE_H__ */
