/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_infix.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* bits held by one bitmap word */
#define RF_WORD_BITS 64

/* the bitmap words needed for n bits */
#define RF_WORDS_FOR(n) (((size_t)(n) + RF_WORD_BITS - 1) / RF_WORD_BITS)

static void rf_bit_set(uint64_t *map, size_t i)
{
    map[i / RF_WORD_BITS] |= UINT64_C(1) << (i % RF_WORD_BITS);
}

static int rf_bit_test(const uint64_t *map, size_t i)
{
    return (int)((map[i / RF_WORD_BITS] >> (i % RF_WORD_BITS)) & 1u);
}

/* how many bits are set before position i */
static size_t rf_rank(const uint64_t *map, size_t i)
{
    size_t ones = 0;
    const size_t whole = i / RF_WORD_BITS;
    for (size_t w = 0; w < whole; w++) ones += (size_t)TDB_POPCOUNT64(map[w]);
    const unsigned part = (unsigned)(i % RF_WORD_BITS);
    if (part > 0) ones += (size_t)TDB_POPCOUNT64(map[whole] & ((UINT64_C(1) << part) - 1));
    return ones;
}

/* the position of the set bit with index j counting from 0, in a map of n_words words, or SIZE_MAX
 * when the map holds fewer */
static size_t rf_select(const uint64_t *map, size_t n_words, size_t j)
{
    for (size_t w = 0; w < n_words; w++)
    {
        const size_t here = (size_t)TDB_POPCOUNT64(map[w]);
        if (j >= here)
        {
            j -= here;
            continue;
        }
        uint64_t word = map[w];
        /* clear the j lowest set bits, and the lowest one left is the one asked for */
        for (size_t k = 0; k < j; k++) word &= word - 1;
        return w * RF_WORD_BITS + (size_t)TDB_CTZ64(word);
    }
    return SIZE_MAX;
}

/* whether any bit is set strictly between positions a and b */
static int rf_any_between(const uint64_t *map, size_t a, size_t b)
{
    if (b <= a + 1) return 0;
    const size_t from = a + 1, to = b; /* the half-open span [from, to) */
    for (size_t w = from / RF_WORD_BITS; w * RF_WORD_BITS < to; w++)
    {
        uint64_t word = map[w];
        const size_t base = w * RF_WORD_BITS;
        if (base < from) word &= ~UINT64_C(0) << (from - base);
        if (to - base < RF_WORD_BITS) word &= (UINT64_C(1) << (to - base)) - 1;
        if (word != 0) return 1;
    }
    return 0;
}

/* the zeros put ahead of a trie so the slot after the remainder reads smaller than it, one more
 * than the zeros the remainder leads with */
static unsigned rf_trie_pad(uint64_t rem, unsigned r_bits)
{
    return (unsigned)TDB_CLZ64(rem) - (RF_WORD_BITS - r_bits) + 1;
}

/* write the remainders of the k keys from slot j on, as one remainder and a trie when they fit,
 * otherwise once per key */
static int rf_put_group(range_filter_infix_store_t *out, uint64_t rem,
                        const range_filter_bits_t *keys, size_t tail_off, uint32_t k)
{
    const unsigned r = out->r_bits;
    const size_t start = out->rem.nbits;
    if (keys && k >= 2 && k <= RANGE_FILTER_DTRIE_MAX_KEYS && rem != 0)
    {
        const unsigned pad = rf_trie_pad(rem, r);
        const size_t budget = (size_t)(k - 1) * r - pad;
        int fitted = 0;
        if (range_filter_bits_append(&out->rem, rem, r) != 0 ||
            range_filter_bits_append(&out->rem, 0, pad) != 0)
            return TDB_ERR_MEMORY;
        const int rc = range_filter_dtrie_encode(keys, k, tail_off, budget, &out->rem, &fitted);
        if (rc != TDB_SUCCESS) return rc;
        if (fitted) return TDB_SUCCESS;
        range_filter_bits_truncate(&out->rem, start);
    }
    for (uint32_t i = 0; i < k; i++)
        if (range_filter_bits_append(&out->rem, rem, r) != 0) return TDB_ERR_MEMORY;
    return TDB_SUCCESS;
}

int range_filter_infix_store_build(const uint64_t *infixes, const range_filter_bits_t *keys,
                                   size_t tail_off, uint32_t n, unsigned q_bits, unsigned r_bits,
                                   range_filter_infix_store_t *out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    range_filter_bits_init(&out->rem);
    if ((n > 0 && !infixes) || q_bits > RANGE_FILTER_INFIX_MAX_Q_BITS || r_bits == 0 ||
        r_bits > RANGE_FILTER_INFIX_MAX_R_BITS)
        return TDB_ERR_INVALID_ARGS;
    const unsigned width = q_bits + r_bits;
    const uint64_t limit = UINT64_C(1) << width;
    for (uint32_t j = 0; j < n; j++)
        if (infixes[j] >= limit || (j > 0 && infixes[j] < infixes[j - 1]))
            return TDB_ERR_INVALID_ARGS;

    out->n = n;
    out->q_bits = (uint8_t)q_bits;
    out->r_bits = (uint8_t)r_bits;
    out->occupieds = calloc(RF_WORDS_FOR(UINT64_C(1) << q_bits), sizeof(*out->occupieds));
    out->runends = calloc(RF_WORDS_FOR(n > 0 ? n : 1), sizeof(*out->runends));
    if (!out->occupieds || !out->runends)
    {
        range_filter_infix_store_free(out);
        return TDB_ERR_MEMORY;
    }
    const uint64_t r_mask = (UINT64_C(1) << r_bits) - 1;
    for (uint32_t j = 0; j < n; j++)
    {
        const uint64_t q = infixes[j] >> r_bits;
        rf_bit_set(out->occupieds, (size_t)q);
        /* a run ends at the last slot, or where the next infix has a different quotient */
        if (j + 1 == n || (infixes[j + 1] >> r_bits) != q) rf_bit_set(out->runends, j);
    }
    for (uint32_t j = 0; j < n;)
    {
        uint32_t k = 1;
        while (j + k < n && infixes[j + k] == infixes[j]) k++;
        const int rc = rf_put_group(out, infixes[j] & r_mask, keys ? keys + j : NULL, tail_off, k);
        if (rc != TDB_SUCCESS)
        {
            range_filter_infix_store_free(out);
            return rc;
        }
        j += k;
    }
    return TDB_SUCCESS;
}

/* the first and last slot of quotient q's run, which must be occupied */
static void rf_run_of(const range_filter_infix_store_t *s, uint64_t q, size_t *first, size_t *last)
{
    const size_t run = rf_rank(s->occupieds, (size_t)q);
    const size_t words = RF_WORDS_FOR(s->n);
    *last = rf_select(s->runends, words, run);
    *first = run == 0 ? 0 : rf_select(s->runends, words, run - 1) + 1;
}

/* the remainder in slot j */
static uint64_t rf_slot(const range_filter_infix_store_t *s, size_t j)
{
    return range_filter_bits_get(&s->rem, j * s->r_bits, s->r_bits);
}

/* the trie of the group whose remainder sits in slot j, ending by slot last, or an error when the
 * slots do not hold one */
static int rf_group_trie(const range_filter_infix_store_t *s, size_t j, size_t last,
                         range_filter_dtrie_t *t)
{
    const unsigned r = s->r_bits;
    const unsigned pad = rf_trie_pad(rf_slot(s, j), r);
    const size_t at = (j + 1) * r + pad;
    if (range_filter_dtrie_parse(&s->rem, at, (last + 1) * r, t) != TDB_SUCCESS ||
        t->keys > last - j + 1)
        return TDB_ERR_CORRUPTION;
    return range_filter_dtrie_set_budget(t, (t->keys - 1) * r - pad);
}

/* whether quotient q's run holds a key in the range, its remainders bounded by lo and hi, and a
 * trie on remainder lo or hi searched against the probe for that end when one is given */
static int rf_run_holds(const range_filter_infix_store_t *s, uint64_t q, uint64_t lo, uint64_t hi,
                        const range_filter_dtrie_probe_t *lo_key,
                        const range_filter_dtrie_probe_t *hi_key)
{
    static const range_filter_dtrie_probe_t untested = {NULL, 0};
    if (!rf_bit_test(s->occupieds, (size_t)q)) return 0;
    size_t first = 0, last = 0;
    rf_run_of(s, q, &first, &last);
    if (last == SIZE_MAX || last >= s->n) return 0;
    for (size_t j = first; j <= last;)
    {
        const uint64_t v = rf_slot(s, j);
        /* remainders rise along a run, so once one passes hi none after it can match */
        if (v > hi) return 0;
        const int trie = j < last && rf_slot(s, j + 1) < v;
        range_filter_dtrie_t t;
        size_t span = 1;
        if (trie)
        {
            /* a damaged trie cannot say where its group ends, so the run answers yes */
            if (rf_group_trie(s, j, last, &t) != TDB_SUCCESS) return 1;
            span = t.keys;
        }
        if (v >= lo)
        {
            if (!trie) return 1;
            const range_filter_dtrie_probe_t *a = v == lo && lo_key ? lo_key : &untested;
            const range_filter_dtrie_probe_t *b = v == hi && hi_key ? hi_key : &untested;
            /* an infix strictly inside the range needs no search, every key on it lies inside */
            if ((!a->key && !b->key) || range_filter_dtrie_may_contain(&s->rem, &t, a, b)) return 1;
        }
        j += span;
    }
    return 0;
}

int range_filter_infix_store_may_contain(const range_filter_infix_store_t *store, uint64_t lo,
                                         uint64_t hi, const range_filter_dtrie_probe_t *lo_key,
                                         const range_filter_dtrie_probe_t *hi_key)
{
    if (!store || store->n == 0 || lo > hi) return 0;
    const unsigned r = store->r_bits;
    const uint64_t r_mask = (UINT64_C(1) << r) - 1;
    const uint64_t q_max = (UINT64_C(1) << store->q_bits) - 1;
    uint64_t lq = lo >> r, hq = hi >> r;
    if (lq > q_max) return 0;
    uint64_t hr = hi & r_mask;
    if (hq > q_max)
    {
        /* a range reaching past the widest infix is cut back to it, and its high end no longer
         * names an infix a trie could be searched against */
        hq = q_max;
        hr = r_mask;
        hi_key = NULL;
    }
    const uint64_t lr = lo & r_mask;

    if (lq == hq) return rf_run_holds(store, lq, lr, hr, lo_key, hi_key);
    /* a quotient strictly between the two ends holds only infixes inside the range */
    if (rf_any_between(store->occupieds, (size_t)lq, (size_t)hq)) return 1;
    return rf_run_holds(store, lq, lr, r_mask, lo_key, NULL) ||
           rf_run_holds(store, hq, 0, hr, NULL, hi_key);
}

void range_filter_infix_store_free(range_filter_infix_store_t *store)
{
    if (!store) return;
    free(store->occupieds);
    free(store->runends);
    range_filter_bits_free(&store->rem);
    store->occupieds = NULL;
    store->runends = NULL;
    store->n = 0;
}
