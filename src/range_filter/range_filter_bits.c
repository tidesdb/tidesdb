/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_bits.h"

#include <stdlib.h>
#include <string.h>

/* bits held by one word of the string */
#define RF_BITS_PER_WORD 64

/* the most bits one append or one read handles, a whole word */
#define RF_BITS_MAX_FIELD 64

/* words a string grows by at least, so a run of short appends does not reallocate on each */
#define RF_BITS_MIN_GROW 4

void range_filter_bits_init(range_filter_bits_t *b)
{
    if (!b) return;
    b->words = NULL;
    b->nbits = 0;
    b->cap_words = 0;
}

void range_filter_bits_reset(range_filter_bits_t *b)
{
    if (!b) return;
    /* only the words in use are cleared, since an append ors its bits in and relies on the bits
     * past the end reading as zero */
    const size_t used = (b->nbits + RF_BITS_PER_WORD - 1) / RF_BITS_PER_WORD;
    if (used > 0) memset(b->words, 0, used * sizeof(*b->words));
    b->nbits = 0;
}

void range_filter_bits_free(range_filter_bits_t *b)
{
    if (!b) return;
    free(b->words);
    range_filter_bits_init(b);
}

/* make room for at least need_bits bits, keeping every new word zeroed */
static int rf_bits_reserve(range_filter_bits_t *b, size_t need_bits)
{
    const size_t need_words = (need_bits + RF_BITS_PER_WORD - 1) / RF_BITS_PER_WORD;
    if (need_words <= b->cap_words) return 0;
    size_t cap = b->cap_words * 2;
    if (cap < need_words) cap = need_words;
    if (cap < RF_BITS_MIN_GROW) cap = RF_BITS_MIN_GROW;
    uint64_t *grown = realloc(b->words, cap * sizeof(*grown));
    if (!grown) return -1;
    memset(grown + b->cap_words, 0, (cap - b->cap_words) * sizeof(*grown));
    b->words = grown;
    b->cap_words = cap;
    return 0;
}

int range_filter_bits_append(range_filter_bits_t *b, uint64_t value, unsigned n)
{
    if (!b || n > RF_BITS_MAX_FIELD) return -1;
    if (n == 0) return 0;
    if (rf_bits_reserve(b, b->nbits + n) != 0) return -1;
    if (n < RF_BITS_MAX_FIELD) value &= (UINT64_C(1) << n) - 1;

    const size_t word = b->nbits / RF_BITS_PER_WORD;
    const unsigned used = (unsigned)(b->nbits % RF_BITS_PER_WORD);
    const unsigned room = RF_BITS_PER_WORD - used;
    if (n <= room)
    {
        /* the field fits the current word, landing just below the bits already in it */
        b->words[word] |= value << (room - n);
    }
    else
    {
        /* the field straddles two words, its high part finishing this one and the rest opening
         * the next */
        const unsigned spill = n - room;
        b->words[word] |= value >> spill;
        b->words[word + 1] |= value << (RF_BITS_PER_WORD - spill);
    }
    b->nbits += n;
    return 0;
}

void range_filter_bits_truncate(range_filter_bits_t *b, size_t n)
{
    if (!b || n >= b->nbits) return;
    const size_t used = (b->nbits + RF_BITS_PER_WORD - 1) / RF_BITS_PER_WORD;
    const size_t keep = n / RF_BITS_PER_WORD;
    const unsigned part = (unsigned)(n % RF_BITS_PER_WORD);
    size_t clear_from = keep;
    if (part > 0)
    {
        /* keep the top part bits of the word holding the cut and clear the rest of it */
        b->words[keep] &= ~UINT64_C(0) << (RF_BITS_PER_WORD - part);
        clear_from = keep + 1;
    }
    if (used > clear_from)
        memset(b->words + clear_from, 0, (used - clear_from) * sizeof(*b->words));
    b->nbits = n;
}

int range_filter_bits_append_range(range_filter_bits_t *b, const range_filter_bits_t *src,
                                   size_t off, size_t n)
{
    if (!b || !src) return -1;
    while (n > 0)
    {
        const unsigned take = n < RF_BITS_MAX_FIELD ? (unsigned)n : RF_BITS_MAX_FIELD;
        if (range_filter_bits_append(b, range_filter_bits_get(src, off, take), take) != 0)
            return -1;
        off += take;
        n -= take;
    }
    return 0;
}

/* the word at index i, reading past the end of the string as zero */
static uint64_t rf_bits_word(const range_filter_bits_t *b, size_t i)
{
    const size_t used = (b->nbits + RF_BITS_PER_WORD - 1) / RF_BITS_PER_WORD;
    return i < used ? b->words[i] : 0;
}

uint64_t range_filter_bits_get(const range_filter_bits_t *b, size_t off, unsigned n)
{
    if (!b || n == 0 || n > RF_BITS_MAX_FIELD) return 0;
    const size_t word = off / RF_BITS_PER_WORD;
    const unsigned shift = (unsigned)(off % RF_BITS_PER_WORD);

    /* the 64 bits starting at off, assembled from the word holding off and the one after */
    uint64_t window = rf_bits_word(b, word) << shift;
    if (shift > 0) window |= rf_bits_word(b, word + 1) >> (RF_BITS_PER_WORD - shift);

    /* bits past the end of the string read as zero, however the words beyond it were left */
    if (off >= b->nbits) return 0;
    const size_t avail = b->nbits - off;
    if (avail < RF_BITS_PER_WORD) window &= ~(UINT64_C(0)) << (RF_BITS_PER_WORD - avail);

    return n == RF_BITS_MAX_FIELD ? window : window >> (RF_BITS_PER_WORD - n);
}

size_t range_filter_bits_common_prefix(const range_filter_bits_t *a, const range_filter_bits_t *b)
{
    if (!a || !b) return 0;
    const size_t limit = a->nbits < b->nbits ? a->nbits : b->nbits;
    const size_t words = (limit + RF_BITS_PER_WORD - 1) / RF_BITS_PER_WORD;
    for (size_t i = 0; i < words; i++)
    {
        const uint64_t diff = rf_bits_word(a, i) ^ rf_bits_word(b, i);
        if (diff != 0)
        {
            const size_t at = i * RF_BITS_PER_WORD + (size_t)TDB_CLZ64(diff);
            return at < limit ? at : limit;
        }
    }
    return limit;
}

int range_filter_bits_compare(const range_filter_bits_t *a, const range_filter_bits_t *b)
{
    const size_t common = range_filter_bits_common_prefix(a, b);
    const size_t limit = a->nbits < b->nbits ? a->nbits : b->nbits;
    if (common < limit)
    {
        /* the first bit that differs decides, and the string holding a 0 there sorts first */
        return range_filter_bits_get(a, common, 1) ? 1 : -1;
    }
    /* one is a prefix of the other, or they are equal, and the shorter sorts first */
    if (a->nbits == b->nbits) return 0;
    return a->nbits < b->nbits ? -1 : 1;
}
