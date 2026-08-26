/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BENCH_SAMPLE_H__
#define __BENCH_SAMPLE_H__
#include <stdio.h>

#include "compat.h" /* pthreads, clock_gettime, tdb_process_rss/cpu -- all portable via compat */
#include "db.h"

/* the sampler framework -- one background thread ticks a list of registered samplers every
 * interval, each writing one tab-separated row to its own stream so the series plots directly.
 * samplers cover the throughput and latency of the run, the process resource use, and the engine's
 * own db, per column family, and cache statistics. adding a sampler is one struct plus one
 * registration, and it is all portable because the threading, timing, and resource reads go through
 * compat. */

/* the shared state every sampler reads from */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t **cfs; /* the benchmark's column families */
    const char **cf_names;
    int n_cfs;
    _Atomic(uint64_t) *ops_done; /* live cumulative operation count the workers advance */
    double t0;                   /* the run's monotonic start, in seconds */
} bench_sample_ctx_t;

struct bench_sampler; /* forward */

/**
 * bench_sampler_t
 * one time-series source, emitting tab-separated rows to its own stream
 * @param name the sampler's short name, also its output file's stem
 * @param header writes the column header row once at start
 * @param row writes one sample row at elapsed time t seconds
 * @param out the stream this sampler writes to, or NULL to disable it
 * @param state opaque per-sampler state, e.g. the previous reading for a delta
 */
typedef struct bench_sampler
{
    const char *name;
    void (*header)(FILE *out, const bench_sample_ctx_t *c);
    void (*row)(FILE *out, double t, const bench_sample_ctx_t *c, struct bench_sampler *self);
    FILE *out;
    void *state;
} bench_sampler_t;

/* the monotonic clock in seconds, portable via compat's clock_gettime */
static inline double bench_now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/**
 * bench_samplers_open
 * populate samplers with the built-in set, opening a <dir>/<name>.tsv stream for each when dir is
 * non-NULL (otherwise every sampler is left disabled). returns the number of samplers filled in
 * @param samplers out array, must hold at least BENCH_SAMPLER_MAX entries
 * @param dir the output directory for the tsv streams, or NULL to disable file sampling
 * @param c the shared sampler context
 * @return the number of samplers populated
 */
#define BENCH_SAMPLER_MAX 8
int bench_samplers_open(bench_sampler_t *samplers, const char *dir, const bench_sample_ctx_t *c);

/**
 * bench_samplers_close
 * flush and close every sampler's stream and free its state
 * @param samplers the sampler array
 * @param n the number of samplers
 */
void bench_samplers_close(bench_sampler_t *samplers, int n);

/**
 * bench_sampler_thread_t
 * the running sampler thread handle
 * @param tid the pthread running the sample loop
 * @param stop set to end the loop
 * @param samplers the samplers this thread ticks
 * @param n_samplers the number of samplers
 * @param interval_ms the tick period in milliseconds
 * @param ctx the shared sampler context
 */
typedef struct
{
    pthread_t tid;
    _Atomic(int) stop;
    bench_sampler_t *samplers;
    int n_samplers;
    int interval_ms;
    const bench_sample_ctx_t *ctx;
} bench_sampler_thread_t;

/**
 * bench_sampler_thread_start
 * write every sampler's header and start the background tick loop
 * @param t the thread handle to initialize and start
 * @param samplers the samplers to tick
 * @param n_samplers the number of samplers
 * @param interval_ms the tick period in milliseconds
 * @param ctx the shared sampler context
 * @return 0 on success, -1 if the thread could not be created
 */
int bench_sampler_thread_start(bench_sampler_thread_t *t, bench_sampler_t *samplers, int n_samplers,
                               int interval_ms, const bench_sample_ctx_t *ctx);

/**
 * bench_sampler_thread_stop
 * signal the loop, join the thread, and take one final sample
 * @param t the running thread handle
 */
void bench_sampler_thread_stop(bench_sampler_thread_t *t);

#endif /* __BENCH_SAMPLE_H__ */
