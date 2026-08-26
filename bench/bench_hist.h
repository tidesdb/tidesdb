/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BENCH_HIST_H__
#define __BENCH_HIST_H__
#include <stdint.h>
#include <string.h>

/* a small fixed-size latency histogram. values are bucketed by their most significant bit
 * (a power of two) subdivided into 2^HIST_SUB_BITS linear sub-buckets, giving a bounded relative
 * error of about 1/2^HIST_SUB_BITS across the whole range at a fixed, tiny memory cost. it records
 * in nanoseconds, is merge-able so per-thread histograms combine without locking on the hot path,
 * and answers value-at-percentile for the p50/p99/p99.9/max report. */

/* sub-buckets per power of two; 6 bits gives 64 sub-buckets, about 1.5% relative error */
#define HIST_SUB_BITS  6
#define HIST_SUB_COUNT (1u << HIST_SUB_BITS)
/* highest power-of-two bucket, 2^47 ns is about 39 hours, far past any real op latency */
#define HIST_MAX_POW 47
#define HIST_BUCKETS ((HIST_MAX_POW + 1) * HIST_SUB_COUNT)

/**
 * bench_hist_t
 * a fixed-size latency histogram in nanoseconds
 * @param count the number of recorded samples
 * @param total the sum of all recorded values, for the mean
 * @param max the largest recorded value
 * @param buckets the per-sub-bucket sample counts
 */
typedef struct
{
    uint64_t count;
    uint64_t total;
    uint64_t max;
    uint64_t buckets[HIST_BUCKETS];
} bench_hist_t;

/* the most significant bit position of v (0 for v in [1,1]), a portable loop since a benchmark does
 * not need the intrinsic */
static inline int bench_hist_msb(uint64_t v)
{
    int b = 0;
    while (v >>= 1) b++;
    return b;
}

/* the bucket index a value falls in, from its power-of-two bucket and linear sub-bucket */
static inline int bench_hist_index(uint64_t v)
{
    if (v < HIST_SUB_COUNT) return (int)v; /* small values map one-to-one */
    const int m = bench_hist_msb(v);
    const int sub = (int)((v >> (m - HIST_SUB_BITS)) & (HIST_SUB_COUNT - 1));
    const int idx = (m - HIST_SUB_BITS + 1) * (int)HIST_SUB_COUNT + sub;
    return idx < (int)HIST_BUCKETS ? idx : (int)HIST_BUCKETS - 1;
}

/* the representative (lower-bound) value of a bucket index, for reporting a percentile */
static inline uint64_t bench_hist_value(int idx)
{
    if (idx < (int)HIST_SUB_COUNT) return (uint64_t)idx;
    const int m = idx / (int)HIST_SUB_COUNT;
    const int sub = idx % (int)HIST_SUB_COUNT;
    return ((uint64_t)sub | HIST_SUB_COUNT) << (m - 1 + HIST_SUB_BITS - HIST_SUB_BITS);
}

/* clear a histogram to empty */
static inline void bench_hist_reset(bench_hist_t *h)
{
    memset(h, 0, sizeof(*h));
}

/* record one latency sample in nanoseconds */
static inline void bench_hist_record(bench_hist_t *h, uint64_t ns)
{
    h->count++;
    h->total += ns;
    if (ns > h->max) h->max = ns;
    h->buckets[bench_hist_index(ns)]++;
}

/* fold src into dst, so per-thread histograms combine into one for the report */
static inline void bench_hist_merge(bench_hist_t *dst, const bench_hist_t *src)
{
    dst->count += src->count;
    dst->total += src->total;
    if (src->max > dst->max) dst->max = src->max;
    for (int i = 0; i < (int)HIST_BUCKETS; i++) dst->buckets[i] += src->buckets[i];
}

/* the value in nanoseconds at the given percentile in [0, 100] */
static inline uint64_t bench_hist_percentile(const bench_hist_t *h, double pct)
{
    if (h->count == 0) return 0;
    uint64_t rank = (uint64_t)((pct / 100.0) * (double)h->count + 0.5);
    if (rank == 0) rank = 1;
    uint64_t seen = 0;
    for (int i = 0; i < (int)HIST_BUCKETS; i++)
    {
        seen += h->buckets[i];
        if (seen >= rank) return bench_hist_value(i);
    }
    return h->max;
}

#endif /* __BENCH_HIST_H__ */
