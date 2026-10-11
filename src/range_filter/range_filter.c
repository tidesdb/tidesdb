/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "range_filter/range_filter_format.h"
#include "range_filter/range_filter_gap.h"
#include "range_filter/range_filter_infix.h"

/* samples a filter's array grows by at least */
#define RF_SAMPLES_MIN_GROW 16

/* entries a streaming builder's partition table grows by at least */
#define RF_PARTS_MIN_GROW 8

/* bits the remainder adds to each key's cost beyond its own width, the quotient and run-end bits */
#define RF_BITS_PER_KEY_OVERHEAD 2

/* bits in a byte */
#define RF_BYTE_BITS 8

/* a filter's false-positive rate is about this over 2^r */
#define RF_RATE_NUMERATOR 2.0

struct range_filter
{
    const range_filter_codec_t *codec;
    unsigned q_bits;
    unsigned r_bits;
    range_filter_bits_t *samples;
    size_t n_samples;
    size_t cap_samples;
    range_filter_infix_store_t
        *stores; /* n_samples - 1 when built in memory, gap i above sample i */
    uint64_t n_keys;
};

/**
 * rf_stream_t
 * where a streaming builder sends its partitions, the finished ones held until the build ends and
 * the one it is filling
 * @param write_fn the sink
 * @param write_ctx its context
 * @param partition_bytes the store bytes a partition is closed at
 * @param buf the open partition's stores laid end to end
 * @param len the bytes in buf
 * @param cap the bytes buf holds
 * @param offsets each open store's start in buf, and one entry past the last
 * @param cap_offsets the entries offsets holds
 * @param n_gaps the stores in the open partition
 * @param first_gap the gap the open partition starts at
 * @param parts the partitions finished so far, their offsets known once they are written
 * @param blobs each finished partition's bytes, parallel to parts, until it is written
 * @param n_parts how many
 * @param cap_parts the entries parts and blobs hold
 */
typedef struct
{
    range_filter_write_fn write_fn;
    void *write_ctx;
    size_t partition_bytes;
    uint8_t *buf;
    size_t len;
    size_t cap;
    uint32_t *offsets;
    size_t cap_offsets;
    uint32_t n_gaps;
    uint32_t first_gap;
    range_filter_part_t *parts;
    uint8_t **blobs;
    size_t n_parts;
    size_t cap_parts;
} rf_stream_t;

struct range_filter_builder
{
    range_filter_t *f;
    /* the keys since the last sample, at most T - 1. a slot keeps its words from one gap to the
     * next and is reset rather than freed, so the keys between samples cost no allocation */
    range_filter_bits_t *pending;
    size_t n_pending;
    uint64_t *infixes;   /* scratch for one gap's infixes */
    size_t interval;     /* T */
    rf_stream_t *stream; /* NULL when the filter is built in memory */
};

int range_filter_builder_new(const range_filter_codec_t *codec, unsigned sample_bits,
                             unsigned r_bits, range_filter_builder_t **out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    if (!codec || sample_bits < 1 || sample_bits > RANGE_FILTER_MAX_SAMPLE_BITS || r_bits < 1 ||
        r_bits > RANGE_FILTER_INFIX_MAX_R_BITS)
        return TDB_ERR_INVALID_ARGS;
    range_filter_builder_t *b = calloc(1, sizeof(*b));
    if (!b) return TDB_ERR_MEMORY;
    b->interval = (size_t)1 << sample_bits;
    b->f = calloc(1, sizeof(*b->f));
    b->pending = calloc(b->interval, sizeof(*b->pending));
    b->infixes = malloc(b->interval * sizeof(*b->infixes));
    if (!b->f || !b->pending || !b->infixes)
    {
        range_filter_builder_free(b);
        return TDB_ERR_MEMORY;
    }
    b->f->codec = codec;
    /* the infix is the quotient and the remainder together. a gap's infixes take between T/2 and
     * T distinct quotient values, so a quotient of log2 T bits covers them */
    b->f->q_bits = sample_bits;
    b->f->r_bits = r_bits;
    *out = b;
    return TDB_SUCCESS;
}

/* grow the samples and the stores together so a new sample and the gap below it fit */
static int rf_grow_samples(range_filter_t *f)
{
    if (f->n_samples < f->cap_samples) return TDB_SUCCESS;
    const size_t cap =
        f->cap_samples < RF_SAMPLES_MIN_GROW ? RF_SAMPLES_MIN_GROW : f->cap_samples * 2;
    range_filter_bits_t *s = realloc(f->samples, cap * sizeof(*s));
    if (s) f->samples = s;
    range_filter_infix_store_t *st = realloc(f->stores, cap * sizeof(*st));
    if (st) f->stores = st;
    if (!s || !st) return TDB_ERR_MEMORY;
    f->cap_samples = cap;
    return TDB_SUCCESS;
}

/* close the open partition and keep its bytes for the end of the build */
static int rf_stream_flush(rf_stream_t *st)
{
    if (st->n_gaps == 0) return TDB_SUCCESS;
    if (st->n_parts == st->cap_parts)
    {
        const size_t cap =
            st->cap_parts < RF_PARTS_MIN_GROW ? RF_PARTS_MIN_GROW : st->cap_parts * 2;
        range_filter_part_t *grown = realloc(st->parts, cap * sizeof(*grown));
        if (grown) st->parts = grown;
        uint8_t **grown_blobs = realloc(st->blobs, cap * sizeof(*grown_blobs));
        if (grown_blobs) st->blobs = grown_blobs;
        if (!grown || !grown_blobs) return TDB_ERR_MEMORY;
        st->cap_parts = cap;
    }
    uint8_t *blob = NULL;
    size_t size = 0;
    const int rc = range_filter_part_encode(st->buf, st->offsets, st->n_gaps, &blob, &size);
    if (rc != TDB_SUCCESS) return rc;
    st->blobs[st->n_parts] = blob;
    st->parts[st->n_parts++] = (range_filter_part_t){0, (uint32_t)size, st->first_gap};
    st->first_gap += st->n_gaps;
    st->n_gaps = 0;
    st->len = 0;
    return TDB_SUCCESS;
}

/* append a gap's store to the open partition, closing the partition once it is full */
static int rf_stream_add(rf_stream_t *st, const range_filter_infix_store_t *store)
{
    const size_t size = range_filter_store_encoded_size(store);
    if (st->len + size > UINT32_MAX) return TDB_ERR_TOO_LARGE;
    if (st->len + size > st->cap)
    {
        const size_t cap = st->len + size > st->cap * 2 ? st->len + size : st->cap * 2;
        uint8_t *grown = realloc(st->buf, cap);
        if (!grown) return TDB_ERR_MEMORY;
        st->buf = grown;
        st->cap = cap;
    }
    if ((size_t)st->n_gaps + 2 > st->cap_offsets)
    {
        const size_t cap =
            st->cap_offsets < RF_PARTS_MIN_GROW ? RF_PARTS_MIN_GROW : st->cap_offsets * 2;
        uint32_t *grown = realloc(st->offsets, cap * sizeof(*grown));
        if (!grown) return TDB_ERR_MEMORY;
        st->offsets = grown;
        st->cap_offsets = cap;
    }
    range_filter_store_encode(store, st->buf + st->len);
    st->offsets[st->n_gaps] = (uint32_t)st->len;
    st->len += size;
    st->n_gaps++;
    st->offsets[st->n_gaps] = (uint32_t)st->len;
    return st->len >= st->partition_bytes ? rf_stream_flush(st) : TDB_SUCCESS;
}

/* cut the first n pending keys down to infixes against the last sample and the next, build the
 * gap's store, keep it or stream it out, and append the next sample, which the filter then owns */
static int rf_close_gap(range_filter_builder_t *b, size_t n, range_filter_bits_t *next)
{
    range_filter_t *f = b->f;
    int rc = rf_grow_samples(f);
    if (rc != TDB_SUCCESS) return rc;
    if (f->n_samples > 0)
    {
        const size_t gi = f->n_samples - 1;
        /* the gap's store starts owning nothing, so freeing the filter after a failure here never
         * reads one that was not built */
        range_filter_infix_store_t *store = &f->stores[gi];
        memset(store, 0, sizeof(*store));
        range_filter_bits_init(&store->rem);
        range_filter_gap_t g;
        rc = range_filter_gap_geometry(&f->samples[gi], next, &g);
        if (rc != TDB_SUCCESS) return rc;
        const unsigned m = f->q_bits + f->r_bits;
        for (size_t i = 0; i < n; i++)
            b->infixes[i] = range_filter_gap_infix(&b->pending[i], &g, m);
        rc =
            range_filter_infix_store_build(b->infixes, b->pending, range_filter_gap_tail_off(&g, m),
                                           (uint32_t)n, f->q_bits, f->r_bits, store);
        if (rc != TDB_SUCCESS) return rc;
        if (b->stream)
        {
            /* a streamed store is on its way to disk, so the builder holds only the open
             * partition's bytes and never the whole filter */
            rc = rf_stream_add(b->stream, store);
            range_filter_infix_store_free(store);
            if (rc != TDB_SUCCESS) return rc;
        }
    }
    f->samples[f->n_samples++] = *next;
    range_filter_bits_init(next);
    return TDB_SUCCESS;
}

/* the key added last, which a new key must sort after */
static const range_filter_bits_t *rf_last_key(const range_filter_builder_t *b)
{
    if (b->n_pending > 0) return &b->pending[b->n_pending - 1];
    return b->f->n_samples > 0 ? &b->f->samples[b->f->n_samples - 1] : NULL;
}

int range_filter_builder_add(range_filter_builder_t *b, const uint8_t *key, size_t key_size)
{
    if (!b || (!key && key_size > 0)) return TDB_ERR_INVALID_ARGS;
    const range_filter_bits_t *last = rf_last_key(b);
    int rc = TDB_SUCCESS;
    if (b->f->n_keys % b->interval == 0)
    {
        /* a sample is kept for the life of the filter, so it gets words of its own */
        range_filter_bits_t cur;
        range_filter_bits_init(&cur);
        rc = range_filter_codec_encode(b->f->codec, key, key_size, &cur);
        if (rc == TDB_SUCCESS && last && range_filter_bits_compare(last, &cur) >= 0)
            rc = TDB_ERR_INVALID_ARGS;
        if (rc == TDB_SUCCESS) rc = rf_close_gap(b, b->n_pending, &cur);
        if (rc == TDB_SUCCESS) b->n_pending = 0;
        range_filter_bits_free(&cur);
    }
    else
    {
        range_filter_bits_t *slot = &b->pending[b->n_pending];
        range_filter_bits_reset(slot);
        rc = range_filter_codec_encode(b->f->codec, key, key_size, slot);
        if (rc == TDB_SUCCESS && last && range_filter_bits_compare(last, slot) >= 0)
            rc = TDB_ERR_INVALID_ARGS;
        if (rc == TDB_SUCCESS) b->n_pending++;
    }
    if (rc == TDB_SUCCESS) b->f->n_keys++;
    return rc;
}

/* the last key becomes the closing sample, so every key lies between two samples */
static int rf_close_last(range_filter_builder_t *b)
{
    if (b->n_pending == 0) return TDB_SUCCESS;
    range_filter_bits_t last = b->pending[b->n_pending - 1];
    range_filter_bits_init(&b->pending[b->n_pending - 1]);
    b->n_pending--;
    const int rc = rf_close_gap(b, b->n_pending, &last);
    range_filter_bits_free(&last);
    if (rc == TDB_SUCCESS) b->n_pending = 0;
    return rc;
}

int range_filter_builder_stream(range_filter_builder_t *b, range_filter_write_fn write_fn,
                                void *write_ctx, size_t partition_bytes)
{
    if (!b || !write_fn || b->stream || b->f->n_keys > 0) return TDB_ERR_INVALID_ARGS;
    b->stream = calloc(1, sizeof(*b->stream));
    if (!b->stream) return TDB_ERR_MEMORY;
    b->stream->write_fn = write_fn;
    b->stream->write_ctx = write_ctx;
    b->stream->partition_bytes =
        partition_bytes > 0 ? partition_bytes : RANGE_FILTER_DEFAULT_PARTITION_BYTES;
    return TDB_SUCCESS;
}

/* write every partition together, at the end of the build, so a sink that is also taking a table's
 * data blocks keeps those contiguous. the directory goes after, since it names where each landed */
static int rf_stream_write_parts(rf_stream_t *st)
{
    for (size_t i = 0; i < st->n_parts; i++)
    {
        if (st->write_fn(st->write_ctx, st->blobs[i], st->parts[i].size, &st->parts[i].offset) != 0)
            return TDB_ERR_IO;
        free(st->blobs[i]);
        st->blobs[i] = NULL;
    }
    return TDB_SUCCESS;
}

/* write the directory once every partition is out */
static int rf_stream_directory(range_filter_builder_t *b, uint64_t *dir_offset, uint32_t *dir_size)
{
    const range_filter_t *f = b->f;
    uint8_t *model = NULL, *dir = NULL;
    size_t model_size = 0, size = 0;
    int rc = range_filter_codec_serialize(f->codec, &model, &model_size);
    if (rc != TDB_SUCCESS) return rc;
    const range_filter_dir_t d = {.sample_bits = f->q_bits,
                                  .q_bits = f->q_bits,
                                  .r_bits = f->r_bits,
                                  .n_keys = f->n_keys,
                                  .samples = f->samples,
                                  .n_samples = f->n_samples,
                                  .parts = b->stream->parts,
                                  .n_parts = b->stream->n_parts};
    rc = range_filter_dir_encode(&d, model, model_size, &dir, &size);
    free(model);
    if (rc != TDB_SUCCESS) return rc;
    if (b->stream->write_fn(b->stream->write_ctx, dir, size, dir_offset) != 0) rc = TDB_ERR_IO;
    free(dir);
    if (rc == TDB_SUCCESS) *dir_size = (uint32_t)size;
    return rc;
}

int range_filter_builder_finish_stream(range_filter_builder_t *b, uint64_t *dir_offset,
                                       uint32_t *dir_size)
{
    int rc = TDB_ERR_INVALID_ARGS;
    if (b && b->stream && dir_offset && dir_size)
    {
        rc = rf_close_last(b);
        if (rc == TDB_SUCCESS) rc = rf_stream_flush(b->stream);
        if (rc == TDB_SUCCESS) rc = rf_stream_write_parts(b->stream);
        if (rc == TDB_SUCCESS) rc = rf_stream_directory(b, dir_offset, dir_size);
    }
    range_filter_builder_free(b);
    return rc;
}

int range_filter_builder_finish(range_filter_builder_t *b, range_filter_t **out)
{
    if (!out)
    {
        range_filter_builder_free(b);
        return TDB_ERR_INVALID_ARGS;
    }
    *out = NULL;
    if (!b || b->stream)
    {
        range_filter_builder_free(b);
        return TDB_ERR_INVALID_ARGS;
    }
    const int rc = rf_close_last(b);
    if (rc == TDB_SUCCESS)
    {
        *out = b->f;
        b->f = NULL;
    }
    range_filter_builder_free(b);
    return rc;
}

void range_filter_builder_free(range_filter_builder_t *b)
{
    if (!b) return;
    if (b->pending)
        for (size_t i = 0; i < b->interval; i++) range_filter_bits_free(&b->pending[i]);
    free(b->pending);
    free(b->infixes);
    if (b->stream)
    {
        free(b->stream->buf);
        free(b->stream->offsets);
        for (size_t i = 0; i < b->stream->n_parts; i++) free(b->stream->blobs[i]);
        free(b->stream->blobs);
        free(b->stream->parts);
        free(b->stream);
    }
    range_filter_free(b->f);
    free(b);
}

/* the answer for encoded endpoints, lo sorting at or before hi */
static int rf_may_contain_encoded(const range_filter_t *f, const range_filter_bits_t *lo,
                                  const range_filter_bits_t *hi)
{
    size_t gi = 0;
    const int settled = range_filter_gap_locate(f->samples, f->n_samples, lo, hi, &gi);
    if (settled >= 0) return settled;
    return range_filter_gap_may_contain(&f->samples[gi], &f->samples[gi + 1], &f->stores[gi], lo,
                                        hi);
}

int range_filter_may_contain(const range_filter_t *f, const uint8_t *lo, size_t lo_size,
                             const uint8_t *hi, size_t hi_size)
{
    if (!f) return 1;
    if (f->n_samples == 0) return 0;
    if ((!lo && lo_size > 0) || (!hi && hi_size > 0)) return 1;
    range_filter_bits_t a, b;
    range_filter_bits_init(&a);
    range_filter_bits_init(&b);
    int answer = 1;
    if (range_filter_codec_encode(f->codec, lo, lo_size, &a) == TDB_SUCCESS &&
        range_filter_codec_encode(f->codec, hi, hi_size, &b) == TDB_SUCCESS)
    {
        /* an inverted range holds nothing */
        answer = range_filter_bits_compare(&a, &b) > 0 ? 0 : rf_may_contain_encoded(f, &a, &b);
    }
    range_filter_bits_free(&a);
    range_filter_bits_free(&b);
    return answer;
}

uint64_t range_filter_size_bits(const range_filter_t *f)
{
    if (!f) return 0;
    uint64_t bits = 0;
    for (size_t i = 0; i < f->n_samples; i++) bits += f->samples[i].nbits;
    for (size_t i = 0; i + 1 < f->n_samples; i++)
    {
        const range_filter_infix_store_t *s = &f->stores[i];
        if (s->n == 0) continue;
        bits += (UINT64_C(1) << s->q_bits) + s->n + (uint64_t)s->n * s->r_bits;
    }
    return bits;
}

unsigned range_filter_remainder_bits(double fpr)
{
    /* the narrowest width whose rate reaches the target, found by doubling rather than a logarithm
     * so no floating library is needed */
    unsigned r = 1;
    double rate = RF_RATE_NUMERATOR / 2.0;
    while (rate > fpr && r < RANGE_FILTER_INFIX_MAX_R_BITS)
    {
        r++;
        rate /= 2.0;
    }
    return r;
}

int range_filter_context_budget(uint64_t n_keys, unsigned r_bits)
{
    /* the filter's own bytes, about r + 2 bits a key, and the model kept to a share of them */
    const uint64_t filter_bytes = n_keys * (r_bits + RF_BITS_PER_KEY_OVERHEAD) / RF_BYTE_BITS;
    const uint64_t contexts =
        filter_bytes / RANGE_FILTER_MODEL_SHARE / range_filter_codec_context_bytes();
    return contexts > (uint64_t)RANGE_FILTER_MAX_CONTEXTS ? RANGE_FILTER_MAX_CONTEXTS
                                                          : (int)contexts;
}

uint64_t range_filter_key_count(const range_filter_t *f)
{
    return f ? f->n_keys : 0;
}

void range_filter_free(range_filter_t *f)
{
    if (!f) return;
    for (size_t i = 0; i < f->n_samples; i++)
    {
        range_filter_bits_free(&f->samples[i]);
        if (i + 1 < f->n_samples) range_filter_infix_store_free(&f->stores[i]);
    }
    free(f->samples);
    free(f->stores);
    free(f);
}
