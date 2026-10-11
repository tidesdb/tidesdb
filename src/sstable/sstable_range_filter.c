/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "range_filter/range_filter.h"
#include "range_filter/range_filter_reader.h"
#include "sstable.h"
#include "sstable_internal.h"

/* keys held back to count before a table's model is built. a model drawn from this many of a run's
 * first keys measured as good as one drawn from the whole run on uniform, index, url and address
 * shaped keys */
#define SSTABLE_RF_WARMUP_KEYS 4096

/* the most key bytes held back, so a table of very long keys builds its model sooner rather than
 * buffering megabytes of them */
#define SSTABLE_RF_WARMUP_BYTES (1024 * 1024)

/**
 * sstable_rf_build
 * a table's range filter while the table is being written
 * @param r_bits the remainder width
 * @param expected_keys the distinct keys the table is expected to hold, 0 when unknown
 * @param bm the klog the filter lands in
 * @param counts the byte counts the model is built from, until it is built
 * @param warm the keys held back until the model exists
 * @param warm_sizes their lengths
 * @param n_warm how many
 * @param warm_bytes their total length
 * @param codec the model, once built
 * @param builder the filter's builder, once the model exists
 */
struct sstable_rf_build
{
    unsigned r_bits;
    uint64_t expected_keys;
    block_manager_t *bm;
    range_filter_codec_counts_t *counts;
    uint8_t **warm;
    size_t *warm_sizes;
    size_t n_warm;
    size_t warm_bytes;
    range_filter_codec_t *codec;
    range_filter_builder_t *builder;
};

int sstable_rf_build_new(unsigned r_bits, uint64_t expected_keys, block_manager_t *bm,
                         sstable_rf_build_t **out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    if (!bm || r_bits == 0) return TDB_ERR_INVALID_ARGS;
    sstable_rf_build_t *rb = calloc(1, sizeof(*rb));
    if (!rb) return TDB_ERR_MEMORY;
    rb->r_bits = r_bits;
    rb->expected_keys = expected_keys;
    rb->bm = bm;
    rb->warm = calloc(SSTABLE_RF_WARMUP_KEYS, sizeof(*rb->warm));
    rb->warm_sizes = calloc(SSTABLE_RF_WARMUP_KEYS, sizeof(*rb->warm_sizes));
    if (!rb->warm || !rb->warm_sizes || range_filter_codec_counts_new(&rb->counts) != TDB_SUCCESS)
    {
        sstable_rf_build_free(rb);
        return TDB_ERR_MEMORY;
    }
    *out = rb;
    return TDB_SUCCESS;
}

/* release the held-back keys */
static void sstable_rf_drop_warm(sstable_rf_build_t *rb)
{
    if (rb->warm)
        for (size_t i = 0; i < rb->n_warm; i++) free(rb->warm[i]);
    free(rb->warm);
    free(rb->warm_sizes);
    rb->warm = NULL;
    rb->warm_sizes = NULL;
    rb->n_warm = 0;
}

/* build the model for a table of about n keys, start the filter on it, and feed it the keys held
 * back so far */
static int sstable_rf_start(sstable_rf_build_t *rb, uint64_t n)
{
    int rc = range_filter_codec_build(rb->counts, RANGE_FILTER_CODEC_MAX_ORDER,
                                      range_filter_context_budget(n, rb->r_bits), &rb->codec);
    range_filter_codec_counts_free(rb->counts);
    rb->counts = NULL;
    if (rc == TDB_SUCCESS)
        rc = range_filter_builder_new(rb->codec, RANGE_FILTER_DEFAULT_SAMPLE_BITS, rb->r_bits,
                                      &rb->builder);
    if (rc == TDB_SUCCESS)
        rc = range_filter_builder_stream(rb->builder, sstable_blob_write, rb->bm, 0);
    for (size_t i = 0; i < rb->n_warm && rc == TDB_SUCCESS; i++)
        rc = range_filter_builder_add(rb->builder, rb->warm[i], rb->warm_sizes[i]);
    sstable_rf_drop_warm(rb);
    return rc;
}

int sstable_rf_build_add(sstable_rf_build_t *rb, const uint8_t *key, size_t key_size)
{
    if (!rb || !key) return TDB_ERR_INVALID_ARGS;
    if (rb->builder) return range_filter_builder_add(rb->builder, key, key_size);
    if (!rb->counts) return TDB_ERR_INVALID_ARGS;
    uint8_t *copy = malloc(key_size > 0 ? key_size : 1);
    if (!copy) return TDB_ERR_MEMORY;
    memcpy(copy, key, key_size);
    range_filter_codec_counts_add(rb->counts, key, key_size);
    rb->warm[rb->n_warm] = copy;
    rb->warm_sizes[rb->n_warm] = key_size;
    rb->n_warm++;
    rb->warm_bytes += key_size;
    if (rb->n_warm < SSTABLE_RF_WARMUP_KEYS && rb->warm_bytes < SSTABLE_RF_WARMUP_BYTES)
        return TDB_SUCCESS;
    /* the table holds at least what is held back, and the caller's estimate may say more */
    const uint64_t seen = rb->n_warm;
    return sstable_rf_start(rb, rb->expected_keys > seen ? rb->expected_keys : seen);
}

int sstable_rf_build_finish(sstable_rf_build_t *rb, uint64_t *out_offset, uint32_t *out_size)
{
    if (!rb || !out_offset || !out_size) return TDB_ERR_INVALID_ARGS;
    *out_offset = 0;
    *out_size = 0;
    int rc = TDB_SUCCESS;
    if (!rb->builder)
    {
        /* a table with no key carries no filter, and a scan reads it in full as before */
        if (rb->n_warm == 0) return TDB_SUCCESS;
        /* the whole table was held back, so its size is known exactly */
        rc = sstable_rf_start(rb, rb->n_warm);
    }
    if (rc == TDB_SUCCESS)
        rc = range_filter_builder_finish_stream(rb->builder, out_offset, out_size);
    else
        range_filter_builder_free(rb->builder);
    rb->builder = NULL;
    return rc;
}

void sstable_rf_build_free(sstable_rf_build_t *rb)
{
    if (!rb) return;
    sstable_rf_drop_warm(rb);
    range_filter_codec_counts_free(rb->counts);
    range_filter_builder_free(rb->builder);
    range_filter_codec_free(rb->codec);
    free(rb);
}

/* open the range filter on first use and publish it with a cas, a loser freeing its own. a table
 * without one, or whose directory failed its checks, has none to open */
static range_filter_reader_t *sstable_ensure_range_filter(sstable_t *sst)
{
    range_filter_reader_t *rf = atomic_load_explicit(&sst->range_filter, memory_order_acquire);
    if (rf) return rf;
    if (sst->range_filter_dir_size == 0 ||
        atomic_load_explicit(&sst->range_filter_refused, memory_order_relaxed))
        return NULL;

    range_filter_reader_t *opened = NULL;
    const int rc =
        range_filter_reader_open(&opened, sst->range_filter_dir_offset, sst->range_filter_dir_size,
                                 sstable_blob_fetch, sstable_blob_release, sst);
    if (rc != TDB_SUCCESS)
    {
        /* a fetch that failed may succeed later, after a reopen, but a directory that failed its
         * checks will fail them every time */
        if (rc == TDB_ERR_CORRUPTION)
            atomic_store_explicit(&sst->range_filter_refused, 1, memory_order_relaxed);
        return NULL;
    }
    range_filter_reader_t *expected = NULL;
    if (atomic_compare_exchange_strong(&sst->range_filter, &expected, opened)) return opened;
    range_filter_reader_free(opened);
    return expected;
}

int sstable_range_may_contain(sstable_t *sst, const uint8_t *lo, size_t lo_size, const uint8_t *hi,
                              size_t hi_size)
{
    if (!sst) return 1;
    const range_filter_reader_t *rf = sstable_ensure_range_filter(sst);
    if (!rf) return 1;
    return range_filter_reader_may_contain(rf, lo, lo_size, hi, hi_size);
}

int sstable_has_range_filter(const sstable_t *sst)
{
    return sst && sst->range_filter_dir_size > 0;
}
