/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_format.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "range_filter/range_filter.h"

/* bits in one bitmap word */
#define RF_FMT_WORD_BITS 64

/* bytes in one bitmap word on disk */
#define RF_FMT_WORD_BYTES 8

/* bits in a byte, the unit samples are packed in */
#define RF_FMT_BYTE_BITS 8

/* the directory's fixed head, magic, version, flags, four width bytes and the key count */
#define RF_FMT_DIR_HEAD_BYTES (4 * sizeof(uint32_t) + sizeof(uint64_t))

/* the directory's flags word, no flag being defined in this version */
#define RF_FMT_NO_FLAGS 0u

/* one partition table entry, offset, size and first gap */
#define RF_FMT_PART_ENTRY_BYTES (sizeof(uint64_t) + 2 * sizeof(uint32_t))

/* the bitmap words needed for n bits */
#define RF_FMT_WORDS(n) (((uint64_t)(n) + RF_FMT_WORD_BITS - 1) / RF_FMT_WORD_BITS)

/* the bytes needed for n bits */
#define RF_FMT_BYTES(n) (((uint64_t)(n) + RF_FMT_BYTE_BITS - 1) / RF_FMT_BYTE_BITS)

/* little-endian fixed-width integers, the convention of every on-disk format but the footer */
static void rf_le32_put(uint32_t v, uint8_t *p)
{
    for (size_t i = 0; i < sizeof(v); i++) p[i] = (uint8_t)(v >> (RF_FMT_BYTE_BITS * i));
}

static void rf_le64_put(uint64_t v, uint8_t *p)
{
    for (size_t i = 0; i < sizeof(v); i++) p[i] = (uint8_t)(v >> (RF_FMT_BYTE_BITS * i));
}

static uint32_t rf_le32_get(const uint8_t *p)
{
    uint32_t v = 0;
    for (size_t i = 0; i < sizeof(v); i++) v |= (uint32_t)p[i] << (RF_FMT_BYTE_BITS * i);
    return v;
}

static uint64_t rf_le64_get(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(v); i++) v |= (uint64_t)p[i] << (RF_FMT_BYTE_BITS * i);
    return v;
}

/**
 * rf_cursor_t
 * a bounds-checked read position over a buffer
 * @param p the next byte
 * @param rem the bytes left
 */
typedef struct
{
    const uint8_t *p;
    size_t rem;
} rf_cursor_t;

static int rf_take_u32(rf_cursor_t *c, uint32_t *v)
{
    if (c->rem < sizeof(uint32_t)) return -1;
    *v = rf_le32_get(c->p);
    c->p += sizeof(uint32_t);
    c->rem -= sizeof(uint32_t);
    return 0;
}

static int rf_take_u64(rf_cursor_t *c, uint64_t *v)
{
    if (c->rem < sizeof(uint64_t)) return -1;
    *v = rf_le64_get(c->p);
    c->p += sizeof(uint64_t);
    c->rem -= sizeof(uint64_t);
    return 0;
}

static void rf_put_u32(uint8_t **p, uint32_t v)
{
    rf_le32_put(v, *p);
    *p += sizeof(uint32_t);
}

static void rf_put_u64(uint8_t **p, uint64_t v)
{
    rf_le64_put(v, *p);
    *p += sizeof(uint64_t);
}

/* the word counts of a store's three bitmaps */
static void rf_store_words(uint32_t n, unsigned q_bits, unsigned r_bits, uint64_t *occ,
                           uint64_t *run, uint64_t *rem)
{
    *occ = RF_FMT_WORDS(UINT64_C(1) << q_bits);
    *run = RF_FMT_WORDS(n);
    *rem = RF_FMT_WORDS((uint64_t)n * r_bits);
}

size_t range_filter_store_encoded_size(const range_filter_infix_store_t *s)
{
    if (s->n == 0) return sizeof(uint32_t);
    uint64_t occ, run, rem;
    rf_store_words(s->n, s->q_bits, s->r_bits, &occ, &run, &rem);
    return sizeof(uint32_t) + (size_t)(occ + run + rem) * RF_FMT_WORD_BYTES;
}

static uint8_t *rf_put_words(uint8_t *p, const uint64_t *words, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++, p += RF_FMT_WORD_BYTES) rf_le64_put(words[i], p);
    return p;
}

void range_filter_store_encode(const range_filter_infix_store_t *s, uint8_t *out)
{
    rf_le32_put(s->n, out);
    if (s->n == 0) return;
    uint64_t occ, run, rem;
    rf_store_words(s->n, s->q_bits, s->r_bits, &occ, &run, &rem);
    uint8_t *p = out + sizeof(uint32_t);
    p = rf_put_words(p, s->occupieds, occ);
    p = rf_put_words(p, s->runends, run);
    (void)rf_put_words(p, s->rem.words, rem);
}

static size_t rf_popcount(const uint64_t *words, uint64_t n)
{
    size_t ones = 0;
    for (uint64_t i = 0; i < n; i++) ones += (size_t)TDB_POPCOUNT64(words[i]);
    return ones;
}

/* whether any bit at or past position from is set in a word array of n words */
static int rf_bits_past(const uint64_t *words, uint64_t n, uint64_t from)
{
    if (from >= n * RF_FMT_WORD_BITS) return 0;
    const uint64_t w = from / RF_FMT_WORD_BITS;
    const unsigned bit = (unsigned)(from % RF_FMT_WORD_BITS);
    if (bit > 0 && (words[w] >> bit) != 0) return 1;
    for (uint64_t i = bit > 0 ? w + 1 : w; i < n; i++)
        if (words[i] != 0) return 1;
    return 0;
}

/* read n words into a fresh array */
static uint64_t *rf_take_words(rf_cursor_t *c, uint64_t n)
{
    uint64_t *w = calloc(n > 0 ? (size_t)n : 1, sizeof(*w));
    if (!w) return NULL;
    for (uint64_t i = 0; i < n; i++)
    {
        w[i] = rf_le64_get(c->p);
        c->p += RF_FMT_WORD_BYTES;
    }
    c->rem -= (size_t)n * RF_FMT_WORD_BYTES;
    return w;
}

/* the checks that make a decoded store safe to search, its bitmaps agreeing with its slot count
 * and with each other, every run having an end and nothing set where nothing can be */
static int rf_store_consistent(const range_filter_infix_store_t *s, uint64_t occ, uint64_t run,
                               uint64_t rem)
{
    if (rf_bits_past(s->occupieds, occ, UINT64_C(1) << s->q_bits)) return 0;
    if (rf_bits_past(s->runends, run, s->n)) return 0;
    if (((s->runends[(s->n - 1) / RF_FMT_WORD_BITS] >> ((s->n - 1) % RF_FMT_WORD_BITS)) & 1u) == 0)
        return 0;
    if (rf_popcount(s->occupieds, occ) != rf_popcount(s->runends, run)) return 0;
    /* the remainders are read most significant bit first, so the bits past the last slot are the
     * low bits of the last word */
    const unsigned used = (unsigned)(((uint64_t)s->n * s->r_bits) % RF_FMT_WORD_BITS);
    if (used > 0 && (s->rem.words[rem - 1] << used) != 0) return 0;
    return 1;
}

int range_filter_store_decode(const uint8_t *data, size_t size, unsigned q_bits, unsigned r_bits,
                              uint32_t max_n, range_filter_infix_store_t *out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    range_filter_bits_init(&out->rem);
    out->q_bits = (uint8_t)q_bits;
    out->r_bits = (uint8_t)r_bits;
    rf_cursor_t c = {data, size};
    uint32_t n = 0;
    if (!data || rf_take_u32(&c, &n) != 0 || n > max_n) return TDB_ERR_CORRUPTION;
    if (n == 0) return c.rem == 0 ? TDB_SUCCESS : TDB_ERR_CORRUPTION;
    uint64_t occ, run, rem;
    rf_store_words(n, q_bits, r_bits, &occ, &run, &rem);
    if ((uint64_t)c.rem != (occ + run + rem) * RF_FMT_WORD_BYTES) return TDB_ERR_CORRUPTION;

    out->n = n;
    out->occupieds = rf_take_words(&c, occ);
    out->runends = rf_take_words(&c, run);
    out->rem.words = rf_take_words(&c, rem);
    out->rem.nbits = (size_t)n * r_bits;
    out->rem.cap_words = (size_t)rem;
    if (!out->occupieds || !out->runends || !out->rem.words)
    {
        range_filter_infix_store_free(out);
        return TDB_ERR_MEMORY;
    }
    if (!rf_store_consistent(out, occ, run, rem))
    {
        range_filter_infix_store_free(out);
        return TDB_ERR_CORRUPTION;
    }
    return TDB_SUCCESS;
}

int range_filter_part_encode(const uint8_t *stores, const uint32_t *offsets, uint32_t n_gaps,
                             uint8_t **out, size_t *out_size)
{
    if (!out || !out_size || !offsets || (n_gaps > 0 && !stores)) return TDB_ERR_INVALID_ARGS;
    const uint64_t head = sizeof(uint32_t) * ((uint64_t)n_gaps + 2);
    const uint64_t total = head + offsets[n_gaps];
    if (total > UINT32_MAX) return TDB_ERR_TOO_LARGE;
    uint8_t *buf = malloc((size_t)total);
    if (!buf) return TDB_ERR_MEMORY;
    rf_le32_put(n_gaps, buf);
    for (uint32_t i = 0; i <= n_gaps; i++)
        rf_le32_put(offsets[i], buf + sizeof(uint32_t) * ((size_t)i + 1));
    if (offsets[n_gaps] > 0) memcpy(buf + head, stores, offsets[n_gaps]);
    *out = buf;
    *out_size = (size_t)total;
    return TDB_SUCCESS;
}

int range_filter_part_gap(const uint8_t *data, size_t size, uint32_t index, const uint8_t **store,
                          size_t *store_size)
{
    if (!data || size < sizeof(uint32_t)) return TDB_ERR_CORRUPTION;
    const uint32_t n = rf_le32_get(data);
    const uint64_t head = sizeof(uint32_t) * ((uint64_t)n + 2);
    if (index >= n || head > size) return TDB_ERR_CORRUPTION;
    const uint64_t body = size - head;
    const uint32_t start = rf_le32_get(data + sizeof(uint32_t) * ((size_t)index + 1));
    const uint32_t end = rf_le32_get(data + sizeof(uint32_t) * ((size_t)index + 2));
    const uint32_t total = rf_le32_get(data + sizeof(uint32_t) * ((size_t)n + 1));
    if (total != body || start > end || end > total) return TDB_ERR_CORRUPTION;
    *store = data + head + start;
    *store_size = end - start;
    return TDB_SUCCESS;
}

/* the samples a filter of n keys at interval T holds, every T-th key from the first and the last */
static uint64_t rf_expected_samples(uint64_t n_keys, unsigned sample_bits)
{
    if (n_keys == 0) return 0;
    const uint64_t t = UINT64_C(1) << sample_bits;
    return (n_keys - 1) / t + 1 + ((n_keys - 1) % t != 0 ? 1 : 0);
}

int range_filter_dir_encode(const range_filter_dir_t *d, const uint8_t *model, size_t model_size,
                            uint8_t **out, size_t *out_size)
{
    if (!d || !model || !out || !out_size || (d->n_samples > 0 && !d->samples) ||
        (d->n_parts > 0 && !d->parts))
        return TDB_ERR_INVALID_ARGS;
    if (model_size > UINT32_MAX || d->n_samples > UINT32_MAX || d->n_parts > UINT32_MAX)
        return TDB_ERR_TOO_LARGE;
    uint64_t total = RF_FMT_DIR_HEAD_BYTES + 3 * sizeof(uint32_t) + model_size +
                     (uint64_t)d->n_parts * RF_FMT_PART_ENTRY_BYTES;
    for (size_t i = 0; i < d->n_samples; i++)
    {
        if (d->samples[i].nbits > UINT32_MAX) return TDB_ERR_TOO_LARGE;
        total += sizeof(uint32_t) + RF_FMT_BYTES(d->samples[i].nbits);
    }
    if (total > UINT32_MAX) return TDB_ERR_TOO_LARGE;
    uint8_t *buf = malloc((size_t)total);
    if (!buf) return TDB_ERR_MEMORY;

    uint8_t *p = buf;
    rf_put_u32(&p, RANGE_FILTER_DIR_MAGIC);
    rf_put_u32(&p, RANGE_FILTER_FORMAT_VERSION);
    rf_put_u32(&p, RF_FMT_NO_FLAGS);
    *p++ = (uint8_t)d->sample_bits;
    *p++ = (uint8_t)d->q_bits;
    *p++ = (uint8_t)d->r_bits;
    *p++ = 0; /* reserved */
    rf_put_u64(&p, d->n_keys);
    rf_put_u32(&p, (uint32_t)model_size);
    memcpy(p, model, model_size);
    p += model_size;
    rf_put_u32(&p, (uint32_t)d->n_samples);
    for (size_t i = 0; i < d->n_samples; i++)
    {
        const range_filter_bits_t *s = &d->samples[i];
        rf_put_u32(&p, (uint32_t)s->nbits);
        for (uint64_t b = 0; b < RF_FMT_BYTES(s->nbits); b++)
            *p++ = (uint8_t)range_filter_bits_get(s, b * RF_FMT_BYTE_BITS, RF_FMT_BYTE_BITS);
    }
    rf_put_u32(&p, (uint32_t)d->n_parts);
    for (size_t i = 0; i < d->n_parts; i++)
    {
        rf_put_u64(&p, d->parts[i].offset);
        rf_put_u32(&p, d->parts[i].size);
        rf_put_u32(&p, d->parts[i].first_gap);
    }
    *out = buf;
    *out_size = (size_t)total;
    return TDB_SUCCESS;
}

/* read the fixed head and check it names a filter this build reads */
static int rf_dir_head(rf_cursor_t *c, range_filter_dir_t *d)
{
    uint32_t magic = 0, version = 0, flags = 0;
    if (rf_take_u32(c, &magic) != 0 || rf_take_u32(c, &version) != 0 ||
        rf_take_u32(c, &flags) != 0 || c->rem < sizeof(uint32_t))
        return -1;
    /* a flag this build does not know names a layout it cannot read */
    if (magic != RANGE_FILTER_DIR_MAGIC || version != RANGE_FILTER_FORMAT_VERSION ||
        flags != RF_FMT_NO_FLAGS)
        return -1;
    d->sample_bits = c->p[0];
    d->q_bits = c->p[1];
    d->r_bits = c->p[2];
    c->p += sizeof(uint32_t);
    c->rem -= sizeof(uint32_t);
    if (d->sample_bits < 1 || d->sample_bits > RANGE_FILTER_MAX_SAMPLE_BITS ||
        d->q_bits != d->sample_bits || d->r_bits < 1 || d->r_bits > RANGE_FILTER_INFIX_MAX_R_BITS)
        return -1;
    return rf_take_u64(c, &d->n_keys);
}

/* read the samples, each packed most significant bit first, and check that they rise */
static int rf_dir_samples(rf_cursor_t *c, range_filter_dir_t *d)
{
    uint32_t n = 0;
    if (rf_take_u32(c, &n) != 0 || n != rf_expected_samples(d->n_keys, d->sample_bits) ||
        n > c->rem / sizeof(uint32_t))
        return TDB_ERR_CORRUPTION;
    d->samples = calloc(n > 0 ? n : 1, sizeof(*d->samples));
    if (!d->samples) return TDB_ERR_MEMORY;
    for (uint32_t i = 0; i < n; i++)
    {
        uint32_t nbits = 0;
        if (rf_take_u32(c, &nbits) != 0 || RF_FMT_BYTES(nbits) > c->rem) return TDB_ERR_CORRUPTION;
        range_filter_bits_t *s = &d->samples[i];
        range_filter_bits_init(s);
        d->n_samples = (size_t)i + 1;
        const size_t bytes = (size_t)RF_FMT_BYTES(nbits);
        for (size_t b = 0; b < bytes; b++)
            if (range_filter_bits_append(s, c->p[b], RF_FMT_BYTE_BITS) != 0) return TDB_ERR_MEMORY;
        range_filter_bits_truncate(s, nbits);
        c->p += bytes;
        c->rem -= bytes;
        if (i > 0 && range_filter_bits_compare(&d->samples[i - 1], s) >= 0)
            return TDB_ERR_CORRUPTION;
    }
    return TDB_SUCCESS;
}

/* read the partition table, which must cover the gaps from the first in rising order and end the
 * directory exactly */
static int rf_dir_parts(rf_cursor_t *c, range_filter_dir_t *d)
{
    uint32_t n = 0;
    const uint64_t gaps = d->n_samples > 0 ? d->n_samples - 1 : 0;
    if (rf_take_u32(c, &n) != 0 || (uint64_t)c->rem != (uint64_t)n * RF_FMT_PART_ENTRY_BYTES ||
        (n == 0) != (gaps == 0) || n > gaps)
        return TDB_ERR_CORRUPTION;
    d->parts = calloc(n > 0 ? n : 1, sizeof(*d->parts));
    if (!d->parts) return TDB_ERR_MEMORY;
    d->n_parts = n;
    for (uint32_t i = 0; i < n; i++)
    {
        range_filter_part_t *pt = &d->parts[i];
        (void)rf_take_u64(c, &pt->offset);
        (void)rf_take_u32(c, &pt->size);
        (void)rf_take_u32(c, &pt->first_gap);
        const uint32_t want_min = i == 0 ? 0 : d->parts[i - 1].first_gap + 1;
        if ((i == 0 && pt->first_gap != 0) || pt->first_gap < want_min || pt->first_gap >= gaps ||
            pt->size == 0)
            return TDB_ERR_CORRUPTION;
    }
    return TDB_SUCCESS;
}

int range_filter_dir_decode(const uint8_t *data, size_t size, range_filter_dir_t *out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    memset(out, 0, sizeof(*out));
    if (!data) return TDB_ERR_CORRUPTION;
    rf_cursor_t c = {data, size};
    uint32_t model_size = 0;
    if (rf_dir_head(&c, out) != 0 || rf_take_u32(&c, &model_size) != 0 || model_size > c.rem)
        return TDB_ERR_CORRUPTION;
    int rc = range_filter_codec_deserialize(c.p, model_size, &out->codec);
    if (rc == TDB_ERR_INVALID_ARGS) rc = TDB_ERR_CORRUPTION;
    c.p += model_size;
    c.rem -= model_size;
    if (rc == TDB_SUCCESS) rc = rf_dir_samples(&c, out);
    if (rc == TDB_SUCCESS) rc = rf_dir_parts(&c, out);
    if (rc != TDB_SUCCESS) range_filter_dir_release(out);
    return rc;
}

void range_filter_dir_release(range_filter_dir_t *d)
{
    if (!d) return;
    range_filter_codec_free(d->codec);
    if (d->samples)
        for (size_t i = 0; i < d->n_samples; i++) range_filter_bits_free(&d->samples[i]);
    free(d->samples);
    free(d->parts);
    memset(d, 0, sizeof(*d));
}
