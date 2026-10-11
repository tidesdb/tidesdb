/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_reader.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "range_filter/range_filter_format.h"
#include "range_filter/range_filter_gap.h"

struct range_filter_reader
{
    range_filter_dir_t dir;
    range_filter_fetch_fn fetch_fn;
    range_filter_release_fn release_fn;
    void *ctx;
    size_t resident;
};

int range_filter_reader_open(range_filter_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                             range_filter_fetch_fn fetch_fn, range_filter_release_fn release_fn,
                             void *ctx)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    if (!fetch_fn || !release_fn || dir_size == 0) return TDB_ERR_INVALID_ARGS;
    range_filter_reader_t *r = calloc(1, sizeof(*r));
    if (!r) return TDB_ERR_MEMORY;
    r->fetch_fn = fetch_fn;
    r->release_fn = release_fn;
    r->ctx = ctx;

    const uint8_t *data = NULL;
    void *pin = NULL;
    if (fetch_fn(ctx, dir_offset, dir_size, &data, &pin) != 0)
    {
        free(r);
        return TDB_ERR_IO;
    }
    /* the directory is decoded into memory the reader owns, so its blob is released at once */
    const int rc = range_filter_dir_decode(data, dir_size, &r->dir);
    if (pin) release_fn(ctx, pin);
    if (rc != TDB_SUCCESS)
    {
        free(r);
        return rc;
    }
    r->resident = sizeof(*r) + range_filter_codec_resident_bytes(r->dir.codec) +
                  r->dir.n_samples * sizeof(*r->dir.samples) +
                  r->dir.n_parts * sizeof(*r->dir.parts);
    for (size_t i = 0; i < r->dir.n_samples; i++)
        r->resident += r->dir.samples[i].cap_words * sizeof(uint64_t);
    *out = r;
    return TDB_SUCCESS;
}

/* the partition holding a gap, the last whose first gap is at or before it */
static size_t rf_part_for(const range_filter_dir_t *d, size_t gap)
{
    size_t lo = 0, hi = d->n_parts;
    while (hi - lo > 1)
    {
        const size_t mid = lo + (hi - lo) / 2;
        if (d->parts[mid].first_gap <= gap)
            lo = mid;
        else
            hi = mid;
    }
    return lo;
}

/* fetch a gap's store and search it, answering 1 for anything that goes wrong on the way. a gap
 * holds the keys strictly between two samples, at most T - 1 */
static int rf_reader_gap(const range_filter_reader_t *r, size_t gap, const range_filter_bits_t *lo,
                         const range_filter_bits_t *hi)
{
    const range_filter_dir_t *d = &r->dir;
    const range_filter_part_t *pt = &d->parts[rf_part_for(d, gap)];
    const uint8_t *data = NULL, *bytes = NULL;
    size_t size = 0;
    void *pin = NULL;
    if (r->fetch_fn(r->ctx, pt->offset, pt->size, &data, &pin) != 0) return 1;
    int answer = 1;
    range_filter_infix_store_t store;
    if (range_filter_part_gap(data, pt->size, (uint32_t)(gap - pt->first_gap), &bytes, &size) ==
            TDB_SUCCESS &&
        range_filter_store_decode(bytes, size, d->q_bits, d->r_bits,
                                  (uint32_t)((UINT32_C(1) << d->sample_bits) - 1),
                                  &store) == TDB_SUCCESS)
    {
        answer =
            range_filter_gap_may_contain(&d->samples[gap], &d->samples[gap + 1], &store, lo, hi);
        range_filter_infix_store_free(&store);
    }
    if (pin) r->release_fn(r->ctx, pin);
    return answer;
}

int range_filter_reader_may_contain(const range_filter_reader_t *r, const uint8_t *lo,
                                    size_t lo_size, const uint8_t *hi, size_t hi_size)
{
    if (!r) return 1;
    if (r->dir.n_samples == 0) return 0;
    if ((!lo && lo_size > 0) || (!hi && hi_size > 0)) return 1;
    range_filter_bits_t a, b;
    range_filter_bits_init(&a);
    range_filter_bits_init(&b);
    int answer = 1;
    if (range_filter_codec_encode(r->dir.codec, lo, lo_size, &a) == TDB_SUCCESS &&
        range_filter_codec_encode(r->dir.codec, hi, hi_size, &b) == TDB_SUCCESS)
    {
        size_t gap = 0;
        /* an inverted range holds nothing */
        const int settled =
            range_filter_bits_compare(&a, &b) > 0
                ? 0
                : range_filter_gap_locate(r->dir.samples, r->dir.n_samples, &a, &b, &gap);
        answer = settled >= 0 ? settled : rf_reader_gap(r, gap, &a, &b);
    }
    range_filter_bits_free(&a);
    range_filter_bits_free(&b);
    return answer;
}

uint64_t range_filter_reader_key_count(const range_filter_reader_t *r)
{
    return r ? r->dir.n_keys : 0;
}

size_t range_filter_reader_resident_bytes(const range_filter_reader_t *r)
{
    return r ? r->resident : 0;
}

void range_filter_reader_free(range_filter_reader_t *r)
{
    if (!r) return;
    range_filter_dir_release(&r->dir);
    free(r);
}
