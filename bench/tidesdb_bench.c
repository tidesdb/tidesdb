/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* tidesdb_bench -- a benchmark driver for TidesDB. a --benchmarks list of named
 * workloads runs in order over a shared database, each spread across --threads worker threads that
 * hammer their key slice while a background sampler plots throughput, resource use, and engine
 * statistics to tab-separated files. workloads read and write through real transactions across one
 * or more column families, keys are drawn uniform, zipfian, or sequential, and every workload
 * prints a throughput line plus a latency histogram. built release for profiling; portable via
 * compat. */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the stall tracer needs glibc's backtrace and posix signals, so it is the one part of the driver
 * that is linux-and-glibc only. everything else here builds anywhere the library does */
#if defined(__linux__) && defined(__GLIBC__)
#include <execinfo.h> /* backtrace, for the stall tracer */
#include <signal.h>

#define BENCH_HAVE_STALL_TRACE 1
#endif

/* unit conversions for the reported figures. these are plain formatting constants used by the
 * summary printers, which are not conditional -- defining them inside the tracer's guard left every
 * platform without glibc unable to compile the file at all */
/* bytes in a mebibyte, for the reported sizes */
#define BENCH_MB (1024.0 * 1024.0)
/* microseconds in a second, for the achieved-throughput column */
#define BENCH_US_PER_SEC 1000000.0

#include "base/log.h" /* tidesdb_log_set_sink, so a run can capture engine traces to a file */
#include "bench_hist.h"
#include "bench_internal.h"
#include "bench_sample.h"
#include "compat.h"
#include "db.h"

#define BENCH_MAX_THREADS         256
#define BENCH_MAX_CFS             64
#define BENCH_CF_BASENAME         "cf"
#define BENCH_DEFAULT_INTERVAL_MS 250

/* microseconds per millisecond, for reporting the engine's admission stall in milliseconds */
#define BENCH_US_PER_MS 1000.0

/* the stall tracer. a worker publishes when it enters a commit; a watchdog notices one that has not
 * returned in time and signals that exact thread, whose handler records its own stack while it is
 * still blocked. that is the stalled commit's stack rather than a sample of a busy one, which is
 * the distinction that matters for a stall nobody is on-CPU for */
#define BENCH_STALL_MAX_FRAMES 48
#define BENCH_STALL_POLL_US    5000
#define BENCH_DEADLINE_POLL_US 20000 /* how often a timed run checks its deadline */

/* rows sharing one indexed value. three is the TPC-C customer-by-last-name shape, where 3000
 * customers per district are spread over the 1000 last names the spec's syllable rule generates,
 * so a lookup by name returns about three rows */
#define BENCH_DEFAULT_INDEX_FANOUT 3
#define BENCH_STALL_MAX_REPORT     12

/* ===== zipfian generator ===== */

static double bench_zeta(uint64_t n, double theta)
{
    double sum = 0.0;
    for (uint64_t i = 1; i <= n; i++) sum += 1.0 / pow((double)i, theta);
    return sum;
}

static void bench_zipf_init(bench_zipf_t *z, uint64_t n, double theta)
{
    z->n = n;
    z->theta = theta;
    z->zetan = bench_zeta(n, theta);
    const double zeta2 = bench_zeta(2, theta);
    z->alpha = 1.0 / (1.0 - theta);
    z->eta = (1.0 - pow(2.0 / (double)n, 1.0 - theta)) / (1.0 - zeta2 / z->zetan);
}

/* draw a zipfian index in [0, n) from a uniform u in [0, 1) */
uint64_t bench_zipf_next(const bench_zipf_t *z, double u)
{
    const double uz = u * z->zetan;
    if (uz < 1.0) return 0;
    if (uz < 1.0 + pow(0.5, z->theta)) return 1;
    uint64_t idx = (uint64_t)((double)z->n * pow(z->eta * u - z->eta + 1.0, z->alpha));
    return idx < z->n ? idx : z->n - 1;
}

#ifdef BENCH_HAVE_STALL_TRACE
/**
 * bench_stall_slot_t
 * one worker's stall-tracer state, published to the watchdog
 * @field start_ns when the worker entered its current commit, 0 when it is not in one
 * @field signalled set once the watchdog has asked this thread for a stack, so it asks once
 * @field captured set by the handler when frames hold a stack the watchdog may print
 * @field thread the worker, for pthread_kill
 * @field frames the captured return addresses
 * @field n_frames how many of frames are valid
 * @field observed_us how long the commit had been running when the watchdog noticed
 */
typedef struct
{
    _Atomic(uint64_t) start_ns;
    _Atomic(int) signalled;
    _Atomic(int) captured;
    pthread_t thread;
    void *frames[BENCH_STALL_MAX_FRAMES];
    int n_frames;
    uint64_t observed_us;
} bench_stall_slot_t;

static uint64_t bench_now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static bench_stall_slot_t bench_stall_slots[BENCH_MAX_THREADS];
static _Thread_local bench_stall_slot_t *bench_stall_self;
static _Atomic(int) bench_stall_reports;

/* record this thread's own stack; runs in the stalled thread while it is still blocked */
static void bench_stall_handler(int sig)
{
    (void)sig;
    if (!bench_stall_self) return;
    bench_stall_self->n_frames = backtrace(bench_stall_self->frames, BENCH_STALL_MAX_FRAMES);
    atomic_store_explicit(&bench_stall_self->captured, 1, memory_order_release);
}

/**
 * bench_stall_watchdog_ctx_t
 * what the watchdog needs to police the workers
 * @field threads how many slots are live
 * @field threshold_ns a commit still running after this is reported
 * @field stop set to end the watchdog
 */
typedef struct
{
    int threads;
    uint64_t threshold_ns;
    _Atomic(int) stop;
} bench_stall_watchdog_ctx_t;

/* print one captured stack; runs on the watchdog, so it may allocate */
static void bench_stall_report(int slot_index)
{
    bench_stall_slot_t *slot = &bench_stall_slots[slot_index];
    char **names = backtrace_symbols(slot->frames, slot->n_frames);
    printf("\n=== stalled commit: worker %d blocked %llu us ===\n", slot_index,
           (unsigned long long)slot->observed_us);
    for (int i = 0; i < slot->n_frames; i++) printf("  %s\n", names ? names[i] : "?");
    free(names);
    fflush(stdout);
    atomic_store_explicit(&slot->captured, 0, memory_order_release);
}

/* watch every worker's published commit start, and ask one that has overrun for its stack */
static void *bench_stall_watchdog(void *arg)
{
    bench_stall_watchdog_ctx_t *ctx = (bench_stall_watchdog_ctx_t *)arg;
    while (!atomic_load_explicit(&ctx->stop, memory_order_acquire))
    {
        for (int i = 0; i < ctx->threads; i++)
        {
            bench_stall_slot_t *slot = &bench_stall_slots[i];
            if (atomic_load_explicit(&slot->captured, memory_order_acquire))
            {
                if (atomic_fetch_add_explicit(&bench_stall_reports, 1, memory_order_relaxed) <
                    BENCH_STALL_MAX_REPORT)
                    bench_stall_report(i);
                else
                    atomic_store_explicit(&slot->captured, 0, memory_order_release);
                continue;
            }
            const uint64_t start = atomic_load_explicit(&slot->start_ns, memory_order_acquire);
            if (start == 0) continue;

            /* sample the clock after the start, never before: a worker entering a batch between the
             * two reads would otherwise give a negative age, wrap, and look like the longest stall
             * ever recorded */
            const uint64_t now = bench_now_ns();
            if (now <= start || now - start < ctx->threshold_ns) continue;
            if (atomic_load_explicit(&slot->signalled, memory_order_acquire)) continue;
            slot->observed_us = (now - start) / 1000;
            atomic_store_explicit(&slot->signalled, 1, memory_order_release);
            pthread_kill(slot->thread, SIGPROF);
        }
        usleep(BENCH_STALL_POLL_US);
    }
    return NULL;
}
#endif

void bench_stall_enter(void)
{
#ifdef BENCH_HAVE_STALL_TRACE
    if (bench_stall_self)
        atomic_store_explicit(&bench_stall_self->start_ns, bench_now_ns(), memory_order_release);
#endif
}

void bench_stall_leave(void)
{
#ifdef BENCH_HAVE_STALL_TRACE
    if (bench_stall_self)
    {
        atomic_store_explicit(&bench_stall_self->start_ns, 0, memory_order_release);
        atomic_store_explicit(&bench_stall_self->signalled, 0, memory_order_release);
    }
#endif
}

/* print one latency line for a merged histogram, or nothing when the workload never recorded that
 * kind of operation, so a read-only or write-only workload still reports a single line */
static void bench_report_hist(const char *name, const char *kind, const bench_hist_t *h)
{
    if (h->count == 0) return;
    printf("%-16s %-5s  p50=%.1f p99=%.1f p99.9=%.1f max=%.1f us  (%llu ops)\n", name, kind,
           bench_hist_percentile(h, 50) / 1000.0, bench_hist_percentile(h, 99) / 1000.0,
           bench_hist_percentile(h, 99.9) / 1000.0, (double)h->max / 1000.0,
           (unsigned long long)h->count);
}

/* ===== runner ===== */

static void *bench_worker_entry(void *arg)
{
#ifdef BENCH_HAVE_STALL_TRACE
    {
        bench_thread_t *self = (bench_thread_t *)arg;
        if (self->cfg->stall_trace_ms > 0)
        {
            bench_stall_self = &bench_stall_slots[self->id];
            bench_stall_self->thread = pthread_self();
            /* warm the unwinder here, where allocation is safe -- the handler must not be the
             * first caller, since backtrace allocates on its first use per process */
            void *warm[2];
            (void)backtrace(warm, 2);
        }
    }
#endif
    bench_thread_t *t = (bench_thread_t *)arg;
    /* spin on the start gate so every worker begins together without pthread_barrier, which the
     * Windows threading shim does not provide */
    while (!atomic_load_explicit(t->go, memory_order_acquire)) cpu_pause();
    t->start_s = bench_now_seconds();
    t->run(t);
    atomic_fetch_add_explicit(t->finished, 1, memory_order_release);
    return NULL;
}

/* run one named benchmark across cfg->threads workers, sampling throughout, and print its result */
/**
 * bench_report_run
 * merge every worker's counters and histograms and print the workload's result lines
 * @param w the workload that ran, for the name each line is labelled with
 * @param cfg the run configuration, for the thread count and the key and value sizes
 * @param threads the joined workers, each holding its own totals and histograms
 * @param elapsed wall-clock seconds the workload took, the divisor for the rates
 */
static void bench_report_run(const bench_workload_t *w, const bench_config_t *cfg,
                             const bench_thread_t *threads, double elapsed)
{
    bench_hist_t reads, writes;
    bench_hist_reset(&reads);
    bench_hist_reset(&writes);
    uint64_t total = 0, conflicts = 0, write_errors = 0;
    uint64_t err_tally[BENCH_ERR_TALLY_LEN];
    memset(err_tally, 0, sizeof(err_tally));
    for (int i = 0; i < cfg->threads; i++)
    {
        bench_hist_merge(&reads, &threads[i].read_hist);
        bench_hist_merge(&writes, &threads[i].write_hist);
        total += threads[i].my_ops;
        conflicts += threads[i].my_conflicts;
        write_errors += threads[i].my_write_errors;
        for (int e = 0; e < BENCH_ERR_TALLY_LEN; e++) err_tally[e] += threads[i].my_err_tally[e];
    }
    const double ops_sec = elapsed > 0 ? (double)total / elapsed : 0;
    const double mb_sec = ops_sec * (double)(cfg->key_size + cfg->value_size) / BENCH_MB;
    printf("%-16s %10.0f ops/sec  %8.1f MB/s   (%llu ops, %.1fs)\n", w->name, ops_sec, mb_sec,
           (unsigned long long)total, elapsed);
    /* a conflicted batch is skipped rather than retried, so it never reaches the write histogram.
     * left unreported it silently shrinks the sample the write figures are drawn from -- by thirty
     * times between two runs of the same workload -- and a maximum over a thirtieth of the commits
     * is not comparable to one over all of them */
    if (conflicts > 0 || write_errors > 0)
        printf("%-16s %-5s  %llu conflicts, %llu other failures (%.1f%% of attempts skipped)\n",
               w->name, "skip", (unsigned long long)conflicts, (unsigned long long)write_errors,
               100.0 * (double)(conflicts + write_errors) /
                   (double)(conflicts + write_errors + total));
    for (int e = 0; e < BENCH_ERR_TALLY_LEN; e++)
        if (err_tally[e] > 0)
            printf("%-16s %-5s  error %d x %llu\n", w->name, "err", -e,
                   (unsigned long long)err_tally[e]);
    /* reads and commits are reported apart because they are different distributions -- a mixed
     * workload's reads sit in microseconds and its commits in tens of them, so one merged histogram
     * reports the majority operation and hides the other's tail entirely */
    bench_report_hist(w->name, "read", &reads);
    bench_report_hist(w->name, "write", &writes);
}

static void bench_run_one(const bench_workload_t *w, const bench_config_t *cfg, tidesdb_t *db,
                          tidesdb_column_family_t **cfs, const char **cf_names,
                          const bench_zipf_t *zipf)
{
    _Atomic(uint64_t) ops_done;
    atomic_init(&ops_done, 0);
    _Atomic(uint64_t) seq;
    atomic_init(&seq, 0);
    _Atomic(int) go;
    atomic_init(&go, 0);
    _Atomic(int) stop;
    atomic_init(&stop, 0);
    _Atomic(int) finished;
    atomic_init(&finished, 0);

    /* on the heap because each worker carries two latency histograms of about 24 KB, so the full
     * array is megabytes -- far past the default thread stack on musl and on Windows */
    bench_thread_t *threads = calloc((size_t)cfg->threads, sizeof(*threads));
    pthread_t tids[BENCH_MAX_THREADS];
    if (!threads)
    {
        printf("%-16s out of memory for %d worker(s)\n", w->name, cfg->threads);
        return;
    }
#ifdef BENCH_HAVE_STALL_TRACE
    bench_stall_watchdog_ctx_t stall_ctx;
    pthread_t stall_tid;
    int stall_on = cfg->stall_trace_ms > 0;
    if (stall_on)
    {
        memset(bench_stall_slots, 0, sizeof(bench_stall_slots));
        atomic_store(&bench_stall_reports, 0);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = bench_stall_handler;
        /* restart the interrupted syscall, so asking a blocked thread for its stack does not change
         * what it was doing */
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGPROF, &sa, NULL) != 0) stall_on = 0;
    }
#endif
    for (int i = 0; i < cfg->threads; i++)
    {
        memset(&threads[i], 0, sizeof(threads[i]));
        threads[i].id = i;
        threads[i].rng = cfg->seed ^ (0x9e3779b97f4a7c15ULL * (uint64_t)(i + 1));
        threads[i].cfg = cfg;
        threads[i].zipf = zipf;
        threads[i].db = db;
        threads[i].cfs = cfs;
        threads[i].ops_done = &ops_done;
        threads[i].seq = &seq;
        threads[i].go = &go;
        threads[i].stop = &stop;
        threads[i].finished = &finished;
        threads[i].per_op_s = cfg->rate > 0 ? (double)cfg->threads / (double)cfg->rate : 0.0;
        threads[i].run = w->run;
        pthread_create(&tids[i], NULL, bench_worker_entry, &threads[i]);
    }
#ifdef BENCH_HAVE_STALL_TRACE
    if (stall_on)
    {
        stall_ctx.threads = cfg->threads;
        stall_ctx.threshold_ns = (uint64_t)cfg->stall_trace_ms * 1000000ULL;
        atomic_init(&stall_ctx.stop, 0);
        pthread_create(&stall_tid, NULL, bench_stall_watchdog, &stall_ctx);
    }
#endif

    bench_sample_ctx_t sctx = {db, cfs, cf_names, cfg->n_cfs, &ops_done, 0};
    bench_sampler_t samplers[BENCH_SAMPLER_MAX];
    const char *sdir = cfg->sample_interval_ms > 0 ? cfg->dir : NULL;
    const int n_samplers = bench_samplers_open(samplers, sdir, &sctx);
    bench_sampler_thread_t sampler;

    const double t0 = bench_now_seconds();
    sctx.t0 = t0;
    atomic_store_explicit(&go, 1,
                          memory_order_release); /* release the workers, timing starts now */
    if (cfg->sample_interval_ms > 0)
        bench_sampler_thread_start(&sampler, samplers, n_samplers, cfg->sample_interval_ms, &sctx);

    if (cfg->seconds > 0)
    {
        /* polled rather than slept through, so a workload that runs itself out before the deadline
         * -- a fill that exhausts its keyspace -- ends the run then instead of being held open and
         * reported against an elapsed time it spent idle */
        const double deadline = t0 + (double)cfg->seconds;
        while (bench_now_seconds() < deadline &&
               atomic_load_explicit(&finished, memory_order_acquire) < cfg->threads)
        {
            usleep(BENCH_DEADLINE_POLL_US);
        }
        atomic_store_explicit(&stop, 1, memory_order_relaxed);
    }
    for (int i = 0; i < cfg->threads; i++) pthread_join(tids[i], NULL);
#ifdef BENCH_HAVE_STALL_TRACE
    if (stall_on)
    {
        atomic_store(&stall_ctx.stop, 1);
        pthread_join(stall_tid, NULL);
    }
#endif
    const double elapsed = bench_now_seconds() - t0;
    if (cfg->sample_interval_ms > 0) bench_sampler_thread_stop(&sampler);
    bench_samplers_close(samplers, n_samplers);

    bench_report_run(w, cfg, threads, elapsed);
    free(threads);
}

/* ===== config, cli, main ===== */

/**
 * bench_compression_id
 * map a compression name to the encoding id a column family's pipeline carries
 * @param name the name given to --compression
 * @return the encoding id, or 0 (none) for an unrecognised name
 */
static int bench_compression_id(const char *name)
{
    if (!strcmp(name, "snappy")) return TDB_COMPRESS_SNAPPY;
    if (!strcmp(name, "lz4")) return TDB_COMPRESS_LZ4;
    if (!strcmp(name, "zstd")) return TDB_COMPRESS_ZSTD;
    if (!strcmp(name, "lz4fast")) return TDB_COMPRESS_LZ4_FAST;
    return TDB_COMPRESS_NONE;
}

static void bench_config_defaults(bench_config_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->benchmarks, sizeof(c->benchmarks), "fillrandom,readrandom,readwrite");
    snprintf(c->dir, sizeof(c->dir), "tidesdb_bench_data");
    c->threads = 4;
    c->num = 1000000;
    c->key_size = 16;
    c->value_size = 100;
    c->dist = BENCH_DIST_UNIFORM;
    c->zipf_theta = 0.99;
    c->n_cfs = 1;
    c->txn_ops = 1;
    c->read_ratio = 50;
    c->scan_length = 100;
    c->seed = 0x243f6a8885a308d3ULL;
    c->sample_interval_ms = BENCH_DEFAULT_INTERVAL_MS;
    c->index_fanout = BENCH_DEFAULT_INDEX_FANOUT;
    c->sync_mode = TDB_SYNC_NONE;
    c->level_size_ratio = 0;
    c->min_levels = 0;
    c->dividing_level_offset = -1; /* -1 leaves it alone; 0 is a meaningful setting */
    c->l1_file_count_trigger = 0;
    c->tombstone_density_trigger = -1.0;
    c->tombstone_density_min_entries = 0;
    c->value_separation_threshold = 0;
    c->btree_block_size = 0;
    c->bloom_fpr = -1.0;
    c->large_value_size = 8192;
    c->large_ratio = 25;
    c->idle_flush_seconds = -1;
    c->skip_list_max_level = 0;
    c->skip_list_probability = -1.0;
    c->memtable_size = 64 * 1024 * 1024;
    c->cache_size = 256 * 1024 * 1024;
    c->bloom = 1;
    c->isolation = TDB_ISOLATION_SNAPSHOT;
    c->log_level = TDB_LOG_INFO;
}

/* apply one --key=value flag to the config, returning 0 when recognized */
static int bench_apply_flag(bench_config_t *c, const char *key, const char *val)
{
    if (!strcmp(key, "benchmarks"))
        snprintf(c->benchmarks, sizeof(c->benchmarks), "%s", val);
    else if (!strcmp(key, "dir"))
        snprintf(c->dir, sizeof(c->dir), "%s", val);
    else if (!strcmp(key, "fresh"))
        c->fresh = atoi(val);
    else if (!strcmp(key, "cleanup"))
        c->cleanup = atoi(val);
    else if (!strcmp(key, "threads"))
        c->threads = atoi(val);
    else if (!strcmp(key, "num"))
        c->num = strtoull(val, NULL, 10);
    else if (!strcmp(key, "key_size"))
        c->key_size = atoi(val);
    else if (!strcmp(key, "value_size"))
        c->value_size = atoi(val);
    else if (!strcmp(key, "zipf_theta"))
        c->zipf_theta = atof(val);
    else if (!strcmp(key, "cfs"))
        c->n_cfs = atoi(val);
    else if (!strcmp(key, "txn_ops"))
        c->txn_ops = atoi(val);
    else if (!strcmp(key, "read_ratio"))
        c->read_ratio = atoi(val);
    else if (!strcmp(key, "scan_length"))
        c->scan_length = atoi(val);
    else if (!strcmp(key, "seed"))
        c->seed = strtoull(val, NULL, 10);
    else if (!strcmp(key, "seconds"))
        c->seconds = atoi(val);
    else if (!strcmp(key, "rate"))
        c->rate = atoi(val);
    else if (!strcmp(key, "compression"))
        c->compression = bench_compression_id(val);
    else if (!strcmp(key, "index_fanout"))
        c->index_fanout = atoi(val);
    else if (!strcmp(key, "sample_interval_ms"))
        c->sample_interval_ms = atoi(val);
    else if (!strcmp(key, "sync"))
        c->sync_mode = atoi(val);
    else if (!strcmp(key, "memtable_size"))
        c->memtable_size = strtoull(val, NULL, 10);
    else if (!strcmp(key, "cache_size"))
        c->cache_size = strtoull(val, NULL, 10);
    else if (!strcmp(key, "l0_stall"))
        c->l0_stall = atoi(val);
    else if (!strcmp(key, "max_open_sstables"))
        c->max_open_sstables = atoi(val);
    else if (!strcmp(key, "vlog_segment_mb"))
        c->vlog_segment_mb = atoi(val);
    else if (!strcmp(key, "stall_trace_ms"))
        c->stall_trace_ms = atoi(val);
    else if (!strcmp(key, "flush_threads"))
        c->flush_threads = atoi(val);
    else if (!strcmp(key, "compaction_threads"))
        c->compaction_threads = atoi(val);
    else if (!strcmp(key, "level_size_ratio"))
        c->level_size_ratio = atoi(val);
    else if (!strcmp(key, "min_levels"))
        c->min_levels = atoi(val);
    else if (!strcmp(key, "dividing_level_offset"))
        c->dividing_level_offset = atoi(val);
    else if (!strcmp(key, "l1_trigger"))
        c->l1_file_count_trigger = atoi(val);
    else if (!strcmp(key, "tombstone_density"))
        c->tombstone_density_trigger = atof(val);
    else if (!strcmp(key, "tombstone_min_entries"))
        c->tombstone_density_min_entries = strtoull(val, NULL, 10);
    else if (!strcmp(key, "value_separation_threshold"))
        c->value_separation_threshold = strtoull(val, NULL, 10);
    else if (!strcmp(key, "btree_block_size"))
        c->btree_block_size = strtoull(val, NULL, 10);
    else if (!strcmp(key, "bloom_fpr"))
        c->bloom_fpr = atof(val);
    else if (!strcmp(key, "large_value_size"))
        c->large_value_size = atoi(val);
    else if (!strcmp(key, "large_ratio"))
        c->large_ratio = atoi(val);
    else if (!strcmp(key, "idle_flush_seconds"))
        c->idle_flush_seconds = atoi(val);
    else if (!strcmp(key, "skip_list_max_level"))
        c->skip_list_max_level = atoi(val);
    else if (!strcmp(key, "skip_list_probability"))
        c->skip_list_probability = atof(val);
    else if (!strcmp(key, "bloom"))
        c->bloom = atoi(val);
    else if (!strcmp(key, "log_level"))
        c->log_level = atoi(val);
    else if (!strcmp(key, "log_file"))
        snprintf(c->log_file, sizeof(c->log_file), "%s", val);
    else if (!strcmp(key, "isolation"))
        c->isolation = (tidesdb_isolation_level_t)atoi(val);
    else if (!strcmp(key, "dist"))
        c->dist = !strcmp(val, "zipfian")      ? BENCH_DIST_ZIPFIAN
                  : !strcmp(val, "sequential") ? BENCH_DIST_SEQUENTIAL
                                               : BENCH_DIST_UNIFORM;
    else
        return -1;
    return 0;
}

static int bench_parse_args(bench_config_t *c, int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
    {
        const char *a = argv[i];
        if (strncmp(a, "--", 2) != 0) return -1;
        a += 2;
        const char *eq = strchr(a, '=');
        if (!eq) return -1;
        char key[64];
        const size_t klen = (size_t)(eq - a) < sizeof(key) - 1 ? (size_t)(eq - a) : sizeof(key) - 1;
        memcpy(key, a, klen);
        key[klen] = '\0';
        if (bench_apply_flag(c, key, eq + 1) != 0)
        {
            fprintf(stderr, "unknown flag --%s\n", key);
            return -1;
        }
    }
    if (c->threads < 1 || c->threads > BENCH_MAX_THREADS) return -1;
    if (c->n_cfs < 1 || c->n_cfs > BENCH_MAX_CFS) return -1;
    if (c->key_size < 1 || c->key_size > BENCH_MAX_KEY) return -1;
    if (c->value_size < 1 || c->value_size > BENCH_MAX_VALUE) return -1;
    if (c->txn_ops < 1) return -1;
    if (c->num < 1) return -1;
    return 0;
}

/* open the database and create the benchmark's column families */
static int bench_open_db(const bench_config_t *c, tidesdb_t **db, tidesdb_column_family_t **cfs,
                         const char **cf_names, char names[][TDB_MAX_CF_NAME_LEN])
{
    /* point the engine log at a file before opening, so an open-time trace is captured too */
    if (c->log_file[0] != '\0')
    {
        FILE *log = fopen(c->log_file, "w");
        if (!log)
        {
            fprintf(stderr, "could not open log file %s\n", c->log_file);
            return -1;
        }
        tidesdb_log_set_sink(log, 0, NULL);
    }

    tidesdb_config_t dc = tidesdb_default_config();
    dc.db_path = (char *)c->dir;
    dc.log_level = (tidesdb_log_level_t)c->log_level;
    dc.memtable_write_buffer_size = c->memtable_size;
    dc.block_cache_size = c->cache_size;
    dc.memtable_sync_mode = c->sync_mode;
    if (c->l0_stall > 0) dc.memtable_l0_queue_stall_threshold = c->l0_stall;
    if (c->max_open_sstables > 0) dc.max_open_sstables = (size_t)c->max_open_sstables;
    if (c->value_separation_threshold > 0)
        dc.value_separation_threshold = (size_t)c->value_separation_threshold;
    if (c->vlog_segment_mb > 0) dc.vlog_segment_size = (size_t)c->vlog_segment_mb * 1024 * 1024;
    if (c->flush_threads > 0) dc.num_flush_threads = c->flush_threads;
    if (c->compaction_threads > 0) dc.num_compaction_threads = c->compaction_threads;
    if (c->idle_flush_seconds >= 0) dc.memtable_idle_flush_seconds = c->idle_flush_seconds;
    if (c->skip_list_max_level > 0) dc.memtable_skip_list_max_level = c->skip_list_max_level;
    if (c->skip_list_probability > 0.0)
        dc.memtable_skip_list_probability = (float)c->skip_list_probability;
    if (tidesdb_open(&dc, db) != TDB_SUCCESS) return -1;

    for (int i = 0; i < c->n_cfs; i++)
    {
        snprintf(names[i], TDB_MAX_CF_NAME_LEN, "%s%d", BENCH_CF_BASENAME, i);
        tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
        cc.enable_bloom_filter = c->bloom;
        cc.default_isolation_level = c->isolation;
        if (c->level_size_ratio > 0) cc.level_size_ratio = (size_t)c->level_size_ratio;
        if (c->min_levels > 0) cc.min_levels = c->min_levels;
        if (c->dividing_level_offset >= 0) cc.dividing_level_offset = c->dividing_level_offset;
        if (c->l1_file_count_trigger > 0) cc.l1_file_count_trigger = c->l1_file_count_trigger;
        if (c->tombstone_density_trigger >= 0.0)
            cc.tombstone_density_trigger = c->tombstone_density_trigger;
        if (c->tombstone_density_min_entries > 0)
            cc.tombstone_density_min_entries = c->tombstone_density_min_entries;
        if (c->btree_block_size > 0) cc.btree_klog_block_size = (size_t)c->btree_block_size;
        if (c->bloom_fpr > 0.0) cc.bloom_fpr = c->bloom_fpr;
        /* a builtin encoding's id is its compression enum value, so the pipeline is that one id.
         * this matters because a deployment that compresses is measuring a different engine than
         * one that does not -- every klog node is encoded on the way out and decoded on every read
         * that misses the cache */
        if (c->compression > 0)
        {
            cc.encoding_pipeline[0] = (uint8_t)c->compression;
            cc.encoding_count = 1;
        }
        (void)tidesdb_create_column_family(*db, names[i], &cc); /* ignore exists on reopen */
        cfs[i] = tidesdb_get_column_family(*db, names[i]);
        cf_names[i] = names[i];
        if (!cfs[i]) return -1;
    }
    return 0;
}

/* print one line per column family: the shape reads pay for, the amplification it carries, and the
 * level distribution behind both. the db-level line below folds these together, which hides a
 * single family whose L1 is backing up while the average looks healthy */
static void bench_print_cf_summary(tidesdb_column_family_t **cfs, const char **cf_names,
                                   const int n_cfs)
{
    printf("\n%-10s %6s %8s %9s %10s %10s %8s  %s\n", "cf", "sst", "read_amp", "data_mb",
           "comp_w_mb", "flush_mb", "comps", "levels (files/mb)");
    for (int i = 0; i < n_cfs; i++)
    {
        tidesdb_cf_stats_t s;
        if (!cfs[i] || tidesdb_get_cf_stats(cfs[i], &s) != 0) continue;

        int sst = 0;
        for (int lvl = 0; lvl < s.num_levels; lvl++) sst += s.level_num_sstables[lvl];

        printf("%-10s %6d %8.2f %9.1f %10.1f %10.1f %8llu  ", cf_names[i], sst, s.read_amp,
               (double)s.total_data_size / BENCH_MB, (double)s.compaction_bytes_written / BENCH_MB,
               (double)s.flush_bytes_written / BENCH_MB, (unsigned long long)s.compaction_count);
        for (int lvl = 0; lvl < s.num_levels; lvl++)
            printf("L%d=%d/%.0f ", lvl + 1, s.level_num_sstables[lvl],
                   (double)s.level_sizes[lvl] / BENCH_MB);
        printf("\n");
    }
}

/* print the final engine amplification and cache summary once every benchmark has run */
/* print one encoding chain's realised ratio, or say the store holds none */
static void bench_print_chains(const char *what, const tidesdb_encoding_stats_t *chains, size_t n)
{
    if (n == 0)
    {
        printf("  %-5s (nothing stored)\n", what);
        return;
    }
    for (size_t i = 0; i < n; i++)
    {
        char ids[64] = "verbatim";
        if (chains[i].id_count > 0)
        {
            int off = 0;
            for (int j = 0; j < chains[i].id_count && off < (int)sizeof(ids) - 8; j++)
                off += snprintf(ids + off, sizeof(ids) - (size_t)off, j ? ",%u" : "%u",
                                (unsigned)chains[i].ids[j]);
        }
        /* the ratio is against the bytes this chain wrote, so a store part way through a codec
         * change shows a row for each rather than one figure describing neither */
        printf("  %-5s codec=%-12s logical=%8.1fMB stored=%8.1fMB ratio=%.2fx items=%llu\n", what,
               ids, (double)chains[i].logical_bytes / BENCH_MB,
               (double)chains[i].stored_bytes / BENCH_MB,
               chains[i].stored_bytes
                   ? (double)chains[i].logical_bytes / (double)chains[i].stored_bytes
                   : 0.0,
               (unsigned long long)chains[i].item_count);
    }
}

static void bench_print_engine_summary(tidesdb_t *db)
{
    tidesdb_db_stats_t d;
    tidesdb_cache_stats_t ca;
    if (tidesdb_get_db_stats(db, &d) == 0)
    {
        const double user = d.user_bytes_written ? (double)d.user_bytes_written : 1.0;
        /* the value log counts. it is where a separated value physically lives, so a store holding
         * gigabytes of unreclaimed values while its key logs stay small was reporting a space
         * amplification near zero -- the figure read best exactly when the space was worst */
        const double physical = (double)(d.total_data_size_bytes + d.vlog_file_size);
        /* against what is still live, not against everything ever written. dividing by cumulative
         * writes makes a delete-heavy store look better the more it deletes, which is backwards --
         * space amplification is what the device holds over what the user can still read.
         *
         * live value bytes are what the sstables report holding, restated by each reclaim pass, so
         * a store that has not run one yet has nothing to divide by and says so rather than
         * printing a ratio it cannot support.
         *
         * a store that never spilled is not that case, though: with nothing indexed in the log
         * there are no live value bytes to be unsure of, and the key logs alone give the whole
         * answer. testing only the file size got this wrong, because the log carries a header from
         * the moment it is created -- so every store below the spill threshold, which is most of
         * them, reported an amplification of zero */
        const double live = (double)(d.total_data_size_bytes + d.vlog_live_bytes);
        const int live_known =
            d.vlog_value_count == 0 || d.vlog_live_bytes > 0 || d.vlog_file_size == 0;
        /* every place the device was asked to write, not only the ones that end up in the level
         * set. a store that separates its values writes most of its bytes to the log and the value
         * log, so counting the key logs alone reported a write amplification below one while
         * gigabytes went to the value log */
        const double written = (double)(d.flush_bytes_written + d.compaction_bytes_written +
                                        d.wal_bytes_written + d.vlog_bytes_written);
        printf(
            "\nengine: write_amp=%.2f  space_amp=%.2f  flushes=%llu  compactions=%llu  "
            "sstables=%d  data=%.1fMB  vlog=%.1fMB\n",
            written / user, live_known && live > 0 ? physical / live : 0.0,
            (unsigned long long)d.flush_count, (unsigned long long)d.compaction_count,
            d.total_sstable_count, (double)d.total_data_size_bytes / BENCH_MB,
            (double)d.vlog_file_size / BENCH_MB);

        /* where the bytes went, since one ratio cannot say whether a store is paying for its log,
         * its values, or its merges, and the three have entirely different remedies */
        printf(
            "bytes written: user=%.1fMB  wal=%.1fMB  vlog=%.1fMB  flush=%.1fMB  "
            "compaction=%.1fMB\n",
            user / BENCH_MB, (double)d.wal_bytes_written / BENCH_MB,
            (double)d.vlog_bytes_written / BENCH_MB, (double)d.flush_bytes_written / BENCH_MB,
            (double)d.compaction_bytes_written / BENCH_MB);
        tidesdb_encoding_stats_t chains[TDB_MAX_ENCODING_CHAINS];
        size_t n = 0;
        printf("\nencoding:\n");
        if (tidesdb_get_klog_encoding_stats(db, chains, TDB_MAX_ENCODING_CHAINS, &n) == 0)
            bench_print_chains("klog", chains, n);
        if (tidesdb_get_vlog_encoding_stats(db, chains, TDB_MAX_ENCODING_CHAINS, &n) == 0)
            bench_print_chains("vlog", chains, n);

        printf("admit:  throttled=%llu  blocked=%llu  stall=%.1fms  ceiling_hits=%llu\n",
               (unsigned long long)d.writes_throttled, (unsigned long long)d.writes_blocked,
               (double)d.write_stall_us / BENCH_US_PER_MS,
               (unsigned long long)d.write_stall_ceiling_hits);
    }
    tidesdb_stall_stats_t st;
    if (tidesdb_get_stall_stats(db, &st) == 0)
    {
        printf("\n%-14s %10s %12s %12s\n", "stall reason", "count", "total_ms", "max_ms");
        for (int i = 0; i < TDB_STALL_COUNT; i++)
            printf("%-14s %10llu %12.1f %12.1f\n",
                   tidesdb_stall_reason_name((tidesdb_stall_reason_t)i),
                   (unsigned long long)st.reasons[i].count,
                   (double)st.reasons[i].total_us / BENCH_US_PER_MS,
                   (double)st.reasons[i].max_us / BENCH_US_PER_MS);
    }

    tidesdb_io_stats_t io;
    if (tidesdb_get_io_stats(db, &io) == 0)
    {
        printf("\n%-10s %10s %10s %12s %12s %12s\n", "io class", "ops", "MB", "total_ms", "max_ms",
               "MB/s");
        for (int i = 0; i < TDB_IO_COUNT; i++)
        {
            const double secs = (double)io.classes[i].total_us / BENCH_US_PER_SEC;
            const double mb = (double)io.classes[i].bytes / BENCH_MB;
            printf("%-10s %10llu %10.1f %12.1f %12.1f %12.1f\n",
                   tidesdb_io_class_name((tidesdb_io_class_t)i),
                   (unsigned long long)io.classes[i].ops, mb,
                   (double)io.classes[i].total_us / BENCH_US_PER_MS,
                   (double)io.classes[i].max_us / BENCH_US_PER_MS, secs > 0 ? mb / secs : 0.0);
        }
    }

    if (tidesdb_get_cache_stats(db, &ca) == 0)
        printf("cache:  hit_rate=%.3f  hits=%llu  misses=%llu  entries=%zu\n", ca.hit_rate,
               (unsigned long long)ca.hits, (unsigned long long)ca.misses, ca.total_entries);
}

int main(int argc, char **argv)
{
    bench_config_t cfg;
    bench_config_defaults(&cfg);
    if (bench_parse_args(&cfg, argc, argv) != 0)
    {
        fprintf(
            stderr,
            "usage: %s [--benchmarks=list] [--threads=N] [--num=N] [--key_size=N]\n"
            "  [--value_size=N] [--dist=uniform|zipfian|sequential] [--zipf_theta=F]\n"
            "  [--cfs=N] [--txn_ops=N] [--read_ratio=PCT] [--scan_length=N] [--seed=N]\n"
            "  [--seconds=N] run each workload for N seconds instead of to its op count\n"
            "  [--rate=N] hold total throughput to N ops/sec, so two runs can be compared at\n"
            "             matched ingest rather than at whatever each can reach\n"
            "  [--compression=none|snappy|lz4|lz4fast|zstd] klog encoding pipeline\n"
            "  [--index_fanout=N] rows sharing one indexed value, for fillindex and indexscan\n"
            "  [--sample_interval_ms=N] [--sync=0|1|2] [--memtable_size=B] [--cache_size=B]\n"
            "  [--l0_stall=N] [--max_open_sstables=N] [--vlog_segment_mb=N] [--stall_trace_ms=N]\n"
            "  [--flush_threads=N] [--compaction_threads=N]\n"
            "  [--bloom=0|1] [--bloom_fpr=F] [--isolation=0..4] [--dir=PATH]\n"
            "  [--fresh=0|1] [--cleanup=0|1]  remove the store dir before / after the run\n"
            "  compaction shape (each unset leaves the engine default):\n"
            "  [--level_size_ratio=N] [--min_levels=N] [--dividing_level_offset=N]\n"
            "  [--l1_trigger=N] [--tombstone_density=F] [--tombstone_min_entries=N]\n"
            "  [--value_separation_threshold=N] [--btree_block_size=N]\n"
            "  memtable and pacing:\n"
            "  [--idle_flush_seconds=N] [--skip_list_max_level=N] [--skip_list_probability=F]\n"
            "  [--log_level=0..4] [--log_file=PATH]\n"
            "workloads: fillseq fillrandom readrandom readmissing readwrite deleterandom\n"
            "           deletewhileread scan scanrange scanempty indexscan mixedlarge\n"
            "           deletewhilereadlarge\n"
            "  value-log workloads: [--large_value_size=N] [--large_ratio=PCT]\n",
            argv[0]);
        return 2;
    }

    bench_zipf_t zipf;
    if (cfg.dist == BENCH_DIST_ZIPFIAN) bench_zipf_init(&zipf, cfg.num, cfg.zipf_theta);

    /* asked for explicitly, never assumed. the path may be one the caller wants kept */
    if (cfg.fresh && remove_directory(cfg.dir) != 0)
    {
        fprintf(stderr, "failed to remove %s\n", cfg.dir);
        return 1;
    }

    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cfs[BENCH_MAX_CFS];
    const char *cf_names[BENCH_MAX_CFS];
    static char names[BENCH_MAX_CFS][TDB_MAX_CF_NAME_LEN];
    if (bench_open_db(&cfg, &db, cfs, cf_names, names) != 0)
    {
        fprintf(stderr, "failed to open database at %s\n", cfg.dir);
        return 1;
    }

    printf("tidesdb_bench: threads=%d keys=%llu key=%dB value=%dB dist=%d cfs=%d sync=%d\n\n",
           cfg.threads, (unsigned long long)cfg.num, cfg.key_size, cfg.value_size, cfg.dist,
           cfg.n_cfs, cfg.sync_mode);

    char list[512];
    snprintf(list, sizeof(list), "%s", cfg.benchmarks);
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ","))
    {
        const bench_workload_t *w = bench_find_workload(tok);
        if (!w)
        {
            fprintf(stderr, "unknown benchmark '%s'\n", tok);
            continue;
        }
        /* the index workloads address a table family and an index family separately, so refuse the
         * run rather than read past a single-family array */
        if ((!strcmp(tok, "fillindex") || !strcmp(tok, "indexscan") ||
             !strcmp(tok, "indexmixed")) &&
            cfg.n_cfs < 2)
        {
            fprintf(stderr, "%s needs --cfs=2 or more (a table family and an index family)\n", tok);
            continue;
        }
        bench_run_one(w, &cfg, db, cfs, cf_names, &zipf);
    }

    bench_print_cf_summary(cfs, cf_names, cfg.n_cfs);
    bench_print_engine_summary(db);
    tidesdb_close(db);
    if (cfg.log_file[0] != '\0') tidesdb_log_close_sink();

    /* after the summaries, so a sweep that discards each configuration's data still reports what it
     * measured before the store goes */
    if (cfg.cleanup && remove_directory(cfg.dir) != 0)
    {
        fprintf(stderr, "failed to remove %s\n", cfg.dir);
        return 1;
    }
    return 0;
}
