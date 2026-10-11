/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_gap.h"

#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* bits read at a time when scanning two samples for where they differ */
#define RF_WINDOW_BITS 64

/* the first set bit at or after position from, or SIZE_MAX when there is none */
static size_t rf_first_one_from(const range_filter_bits_t *b, size_t from)
{
    for (size_t at = from; at < b->nbits; at += RF_WINDOW_BITS)
    {
        const uint64_t w = range_filter_bits_get(b, at, RF_WINDOW_BITS);
        if (w != 0)
        {
            const size_t pos = at + (size_t)TDB_CLZ64(w);
            return pos < b->nbits ? pos : SIZE_MAX;
        }
    }
    return SIZE_MAX;
}

int range_filter_gap_geometry(const range_filter_bits_t *below, const range_filter_bits_t *above,
                              range_filter_gap_t *out)
{
    if (!below || !above || !out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    const size_t shorter = below->nbits < above->nbits ? below->nbits : above->nbits;
    size_t d = range_filter_bits_common_prefix(below, above);
    if (d >= shorter)
    {
        /* one is a prefix of the other, and the shorter reads on as zeros, so they part at the
         * longer's next 1 -- or never, when it has none, and then nothing fits between them */
        const range_filter_bits_t *longer = below->nbits > above->nbits ? below : above;
        d = rf_first_one_from(longer, shorter);
        if (d == SIZE_MAX)
        {
            /* equal once padded, as "a" and "a\0\0" can be when a zero byte codes to zeros. a key
             * between them, "a\0", is then equal to both once padded too, since padding can tie two
             * keys but never reverse them. so is any query endpoint in the gap. placing d past both
             * gives every one of them infix 0 -- the keys collide, which costs false positives, and
             * a query in the gap lands on 0, so none is missed */
            out->d = longer->nbits;
            out->m_red = 0;
            return TDB_SUCCESS;
        }
    }
    /* the lower sample sorts first, so where they part it holds the 0 */
    if (range_filter_bits_get(below, d, 1) != 0 || range_filter_bits_get(above, d, 1) != 1)
        return TDB_ERR_INVALID_ARGS;

    /* the run of positions after d where the lower holds 1 and the upper 0. past the lower's end
     * it reads 0, which ends the run, so the scan is bounded by the lower's length */
    size_t run = 0;
    for (size_t at = d + 1; at <= below->nbits + RF_WINDOW_BITS; at += RF_WINDOW_BITS)
    {
        const uint64_t ones = range_filter_bits_get(below, at, RF_WINDOW_BITS) &
                              ~range_filter_bits_get(above, at, RF_WINDOW_BITS);
        const unsigned lead = (unsigned)TDB_CLZ64(~ones);
        run += lead;
        if (lead < RF_WINDOW_BITS) break;
    }
    out->d = d;
    out->m_red = run;
    return TDB_SUCCESS;
}

uint64_t range_filter_gap_infix(const range_filter_bits_t *key, const range_filter_gap_t *g,
                                unsigned m)
{
    const uint64_t first = range_filter_bits_get(key, g->d, 1);
    const uint64_t rest = m > 1 ? range_filter_bits_get(key, g->d + 1 + g->m_red, m - 1) : 0;
    return (first << (m - 1)) | rest;
}

size_t range_filter_gap_tail_off(const range_filter_gap_t *g, unsigned m)
{
    return g->d + g->m_red + m;
}

int range_filter_gap_locate(const range_filter_bits_t *samples, size_t n,
                            const range_filter_bits_t *lo, const range_filter_bits_t *hi,
                            size_t *gap)
{
    /* the first sample that sorts at or after lo */
    size_t a = 0, b = n;
    while (a < b)
    {
        const size_t mid = a + (b - a) / 2;
        if (range_filter_bits_compare(&samples[mid], lo) < 0)
            a = mid + 1;
        else
            b = mid;
    }
    /* a sample is a key, so one inside the range answers it */
    if (a < n && range_filter_bits_compare(&samples[a], hi) <= 0) return 1;
    /* wholly below the first key or above the last */
    if (a == 0 || a == n) return 0;
    *gap = a - 1;
    return -1;
}

int range_filter_gap_may_contain(const range_filter_bits_t *below, const range_filter_bits_t *above,
                                 const range_filter_infix_store_t *store,
                                 const range_filter_bits_t *lo, const range_filter_bits_t *hi)
{
    range_filter_gap_t g;
    /* samples that do not order are not the ones the store was cut against, so it says nothing */
    if (range_filter_gap_geometry(below, above, &g) != TDB_SUCCESS) return 1;
    const unsigned m = (unsigned)store->q_bits + store->r_bits;
    const range_filter_dtrie_probe_t lo_key = {lo, range_filter_gap_tail_off(&g, m)};
    const range_filter_dtrie_probe_t hi_key = {hi, range_filter_gap_tail_off(&g, m)};
    return range_filter_infix_store_may_contain(store, range_filter_gap_infix(lo, &g, m),
                                                range_filter_gap_infix(hi, &g, m), &lo_key,
                                                &hi_key);
}
