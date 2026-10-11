/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_INFIX_H__
#define __RANGE_FILTER_INFIX_H__
#include "compat.h"
#include "range_filter/range_filter_bits.h"
#include "range_filter/range_filter_dtrie.h"

/* an infix store holds the infixes of the keys between two adjacent samples. each infix is split by
 * quotienting into its high bits, the quotient, and its low bits, the remainder. a quotient is held
 * as one bit in the occupieds bitmap, set when some infix has that quotient. remainders are held in
 * slots, in increasing order, where the infixes sharing a quotient form a contiguous run and the
 * runends bitmap marks each run's last slot. the i-th set bit of occupieds and the i-th set bit of
 * runends belong to the same run, so a quotient's run is found by a rank over the one and a select
 * over the other.
 *
 * keys that cut down to the same infix are held as a group. a plain group repeats the remainder
 * once per key. a group given its keys may instead keep the remainder once and spend the slots
 * after it on a d-trie over what follows the infix in each key. remainders never fall along a run,
 * so a trie announces itself by making the slot after its remainder read smaller than it, which
 * zeros padded in ahead of the trie guarantee. that is why a remainder of 0 never takes a trie. the
 * trie says how many keys it holds, and so how many slots the group spans.
 *
 * over the infixes the store is exact. a range of infixes is reported non-empty when one of them
 * lies in it, and a trie can only take that back, for an infix at an end of the range whose keys
 * the trie shows all fall outside */

/**
 * range_filter_infix_store_t
 * the quotient bitmap, the run boundaries and the remainders of one gap's infixes
 * @param n how many infixes are held, one slot each
 * @param q_bits quotient width, so occupieds spans 2^q_bits bits
 * @param r_bits remainder width, the bits each slot holds
 * @param occupieds bit q set when an infix with quotient q is held, least significant bit first
 * @param runends bit j set when slot j is the last of its run, least significant bit first
 * @param rem the remainders in slot order, r_bits each
 */
typedef struct
{
    uint32_t n;
    uint8_t q_bits;
    uint8_t r_bits;
    uint64_t *occupieds;
    uint64_t *runends;
    range_filter_bits_t rem;
} range_filter_infix_store_t;

/* the widest quotient a store accepts, which bounds its occupieds bitmap */
#define RANGE_FILTER_INFIX_MAX_Q_BITS 24

/* the widest remainder a store accepts */
#define RANGE_FILTER_INFIX_MAX_R_BITS 32

/**
 * range_filter_infix_store_build
 * build a store from infixes given in non-decreasing order, as a scan of sorted keys yields them
 * @param infixes the infixes, each fitting q_bits + r_bits bits
 * @param keys the keys the infixes were cut from, in the same order, or NULL to give no group a
 * trie
 * @param tail_off where the bits after the infix window start in every key
 * @param n how many
 * @param q_bits the quotient width
 * @param r_bits the remainder width
 * @param out the store to fill, owned by the caller and released with the free below
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS when the infixes are out of order or too wide or the
 *         widths are out of range, or TDB_ERR_MEMORY
 */
int range_filter_infix_store_build(const uint64_t *infixes, const range_filter_bits_t *keys,
                                   size_t tail_off, uint32_t n, unsigned q_bits, unsigned r_bits,
                                   range_filter_infix_store_t *out);

/**
 * range_filter_infix_store_may_contain
 * whether any key held may lie in the range whose ends cut down to infixes lo and hi
 * @param store the store
 * @param lo the low infix, inclusive
 * @param hi the high infix, inclusive
 * @param lo_key the low end itself, letting a trie on infix lo be searched, or NULL
 * @param hi_key the high end itself, letting a trie on infix hi be searched, or NULL
 * @return 1 when one may, 0 when none can or the range is empty
 */
int range_filter_infix_store_may_contain(const range_filter_infix_store_t *store, uint64_t lo,
                                         uint64_t hi, const range_filter_dtrie_probe_t *lo_key,
                                         const range_filter_dtrie_probe_t *hi_key);

/**
 * range_filter_infix_store_free
 * release what a store holds and leave it empty
 * @param store the store
 */
void range_filter_infix_store_free(range_filter_infix_store_t *store);

#endif /* __RANGE_FILTER_INFIX_H__ */
