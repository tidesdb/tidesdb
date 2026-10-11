/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_GAP_H__
#define __RANGE_FILTER_GAP_H__
#include "compat.h"
#include "range_filter/range_filter_bits.h"
#include "range_filter/range_filter_infix.h"

/* a gap is the stretch of keys between two adjacent samples. everything about how its keys are cut
 * down to infixes follows from the two samples alone, so a filter built in memory and one read back
 * from disk answer through the same functions here, and the geometry is recomputed rather than
 * stored */

/**
 * range_filter_gap_t
 * where the keys between two adjacent samples start to tell apart
 * @param d the first bit at which the two samples differ, the lower holding 0 there, or a position
 * past both when they are equal once the shorter is padded with zeros
 * @param m_red the length of the run after d where the lower sample holds 1s and the upper 0s
 */
typedef struct
{
    size_t d;
    size_t m_red;
} range_filter_gap_t;

/**
 * range_filter_gap_geometry
 * the geometry of the gap between two samples
 * @param below the lower sample
 * @param above the upper sample, sorting strictly after the lower
 * @param out the geometry
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS when the samples are out of order
 */
int range_filter_gap_geometry(const range_filter_bits_t *below, const range_filter_bits_t *above,
                              range_filter_gap_t *out);

/**
 * range_filter_gap_infix
 * a key's infix within a gap, the bit where the samples part followed by the bits after the
 * redundant run
 * @param key the encoded key
 * @param g the gap
 * @param m the infix width, quotient and remainder together
 * @return the infix, m bits
 */
uint64_t range_filter_gap_infix(const range_filter_bits_t *key, const range_filter_gap_t *g,
                                unsigned m);

/**
 * range_filter_gap_tail_off
 * where a key's bits past its infix window start, the tail a d-trie tells keys apart by
 * @param g the gap
 * @param m the infix width
 * @return the bit position
 */
size_t range_filter_gap_tail_off(const range_filter_gap_t *g, unsigned m);

/**
 * range_filter_gap_locate
 * place an encoded range among the samples, answering it outright when the samples settle it
 * @param samples the samples, ascending
 * @param n how many
 * @param lo the low end, sorting at or before hi
 * @param hi the high end
 * @param gap out -- the gap to search when neither answer is settled, the one above sample *gap
 * @return 1 when a sample lies in the range, 0 when the range lies outside every key, -1 when the
 *         gap must be searched
 */
int range_filter_gap_locate(const range_filter_bits_t *samples, size_t n,
                            const range_filter_bits_t *lo, const range_filter_bits_t *hi,
                            size_t *gap);

/**
 * range_filter_gap_may_contain
 * search one gap's store for a range lying strictly between its two samples
 * @param below the sample under the gap
 * @param above the sample over it
 * @param store the gap's infix store
 * @param lo the low end, encoded
 * @param hi the high end, encoded
 * @return 1 when a key may lie in the range, 0 when none can
 */
int range_filter_gap_may_contain(const range_filter_bits_t *below, const range_filter_bits_t *above,
                                 const range_filter_infix_store_t *store,
                                 const range_filter_bits_t *lo, const range_filter_bits_t *hi);

#endif /* __RANGE_FILTER_GAP_H__ */
