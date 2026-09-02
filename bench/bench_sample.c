/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "bench_sample.h"

#include <stdlib.h>

#ifdef __GLIBC__
#include <malloc.h> /* mallinfo2, to separate live heap from resident pages */
#endif

#define BENCH_BYTES_PER_MB (1024.0 * 1024.0)

/* the shallowest levels are where a compaction backlog shows up, so the series carries them
 * per level rather than only as a total */
/* every level a family can hold, so a sweep that deepens the tree does not silently lose the levels
 * past the ones a shallower default happened to use */
#define BENCH_CF_LEVELS_SAMPLED TDB_MAX_LEVELS

/* a two-reading state used by the delta samplers (resource cpu, throughput ops) */
typedef struct
{
    double last_t;
    double last_cpu;
    uint64_t last_ops;
} bench_delta_state_t;

/* ===== resource sampler ===== */

/* live bytes the allocator says the process is holding, or 0 where the query is unavailable.
 *
 * this is the number that splits a memory question in three. the process's rss is what the kernel
 * has given it; live_mb is what the program actually asked for and has not returned; and the
 * engine's own statistics say what it believes it is holding. rss above live_mb is the allocator
 * sitting on freed memory -- fragmentation or per-thread arenas it has not released -- and live_mb
 * above what the engine accounts for is a structure the statistics do not name. without the middle
 * term the other two cannot be told apart */
static double bench_live_heap_mb(void)
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    const struct mallinfo2 mi = mallinfo2();
    return (double)mi.uordblks / BENCH_BYTES_PER_MB;
#else
    return 0.0;
#endif
}

/* the resource series: t_sec is the elapsed second, rss_mb what the kernel has given the process,
 * live_mb what the allocator says is still handed out, and cpu_pct the share of one core used since
 * the previous row. rss_mb above live_mb is the allocator holding memory it has not returned */
static void resource_header(FILE *out, const bench_sample_ctx_t *c)
{
    (void)c;
    fprintf(out, "t_sec\trss_mb\tlive_mb\tcpu_pct\n");
}

static void resource_row(FILE *out, double t, const bench_sample_ctx_t *c, bench_sampler_t *self)
{
    (void)c;
    bench_delta_state_t *st = (bench_delta_state_t *)self->state;
    const double cpu = tdb_process_cpu_seconds();
    const double dt = t - st->last_t;
    const double cpu_pct = dt > 0 ? (cpu - st->last_cpu) / dt * 100.0 : 0.0;
    st->last_t = t;
    st->last_cpu = cpu;
    fprintf(out, "%.3f\t%.1f\t%.1f\t%.1f\n", t, (double)tdb_process_rss() / BENCH_BYTES_PER_MB,
            bench_live_heap_mb(), cpu_pct);
}

/* ===== throughput sampler ===== */

static void throughput_header(FILE *out, const bench_sample_ctx_t *c)
{
    (void)c;
    fprintf(out, "t_sec\tops\tops_per_sec\n");
}

static void throughput_row(FILE *out, double t, const bench_sample_ctx_t *c, bench_sampler_t *self)
{
    bench_delta_state_t *st = (bench_delta_state_t *)self->state;
    const uint64_t ops = atomic_load_explicit(c->ops_done, memory_order_relaxed);
    const double dt = t - st->last_t;
    const double rate = dt > 0 ? (double)(ops - st->last_ops) / dt : 0.0;
    st->last_t = t;
    st->last_ops = ops;
    fprintf(out, "%.3f\t%llu\t%.0f\n", t, (unsigned long long)ops, rate);
}

/* ===== db-stats sampler ===== */

static void dbstats_header(FILE *out, const bench_sample_ctx_t *c)
{
    (void)c;
    fprintf(out,
            "t_sec\tcfs\tsstables\topen_sstables\tmemtable_mb\timmutables\tis_flushing\t"
            "flush_count\tcompaction_count\tcomp_pending\twal_gen\tdata_mb\t"
            "user_mb\tflush_mb\tcomp_write_mb\tcomp_read_mb\t"
            "vlog_file_mb\tvlog_live_mb\tvlog_values\tvlog_calls\tvlog_passes\tvlog_retired\t"
            "vlog_drainable\t"
            "global_seq\tmin_snapshot_seq\tactive_txns\ttxn_mb\t"
            "throttled\tblocked\tstall_us\tstall_ceiling\n");
}

static void dbstats_row(FILE *out, double t, const bench_sample_ctx_t *c, bench_sampler_t *self)
{
    (void)self;
    tidesdb_db_stats_t s;
    if (tidesdb_get_db_stats(c->db, &s) != 0) return;
    fprintf(
        out,
        "%.3f\t%d\t%d\t%d\t%.1f\t%d\t%d\t%llu\t%llu\t%d\t%llu\t%.1f\t"
        "%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%d\t"
        "%.1f\t%llu\t%llu\t%llu\t%llu\n",
        t, s.num_column_families, s.total_sstable_count, s.num_open_sstables,
        (double)s.memtable_bytes / BENCH_BYTES_PER_MB, s.immutable_memtable_count, s.is_flushing,
        (unsigned long long)s.flush_count, (unsigned long long)s.compaction_count,
        s.compaction_pending_count, (unsigned long long)s.wal_generation,
        (double)s.total_data_size_bytes / BENCH_BYTES_PER_MB,
        (double)s.user_bytes_written / BENCH_BYTES_PER_MB,
        (double)s.flush_bytes_written / BENCH_BYTES_PER_MB,
        (double)s.compaction_bytes_written / BENCH_BYTES_PER_MB,
        (double)s.compaction_bytes_read / BENCH_BYTES_PER_MB,
        (double)s.vlog_file_size / BENCH_BYTES_PER_MB,
        (double)s.vlog_live_bytes / BENCH_BYTES_PER_MB, (unsigned long long)s.vlog_value_count,
        (unsigned long long)s.vlog_reclaim_calls, (unsigned long long)s.vlog_reclaim_passes,
        (unsigned long long)s.vlog_segments_retired, (unsigned long long)s.vlog_segments_drainable,
        (unsigned long long)s.global_seq, (unsigned long long)s.min_snapshot_seq,
        s.active_txn_count, (double)s.txn_memory_bytes / BENCH_BYTES_PER_MB,
        (unsigned long long)s.writes_throttled, (unsigned long long)s.writes_blocked,
        (unsigned long long)s.write_stall_us, (unsigned long long)s.write_stall_ceiling_hits);
}

/* ===== per-column-family stats sampler (one row per cf per tick) ===== */

static void cfstats_header(FILE *out, const bench_sample_ctx_t *c)
{
    (void)c;
    fprintf(out,
            "t_sec\tcf\tlevels\ttotal_keys\tunflushed_keys\tsstables\tread_amp\t"
            "tombstones\ttombstone_ratio\tdata_mb\tavg_key\tavg_value\t"
            "btree_nodes\tbtree_max_h\tbtree_avg_h\tmax_density\tmax_density_lvl\t"
            "wal_mb\tflush_mb\tcomp_write_mb\tcomp_read_mb\tuser_mb\tcompactions");
    for (int lvl = 1; lvl <= BENCH_CF_LEVELS_SAMPLED; lvl++) fprintf(out, "\tl%d_files", lvl);
    for (int lvl = 1; lvl <= BENCH_CF_LEVELS_SAMPLED; lvl++) fprintf(out, "\tl%d_mb", lvl);
    fprintf(out, "\n");
}

static void cfstats_row(FILE *out, double t, const bench_sample_ctx_t *c, bench_sampler_t *self)
{
    (void)self;
    for (int i = 0; i < c->n_cfs; i++)
    {
        tidesdb_cf_stats_t s;
        if (tidesdb_get_cf_stats(c->cfs[i], &s) != 0) continue;
        int sstables = 0;
        for (int lvl = 0; lvl < s.num_levels; lvl++) sstables += s.level_num_sstables[lvl];
        /* every level, so a deepening tree stays visible rather than truncating at whatever
         * depth a shallower configuration happened to reach */
        int lf[BENCH_CF_LEVELS_SAMPLED] = {0};
        double lm[BENCH_CF_LEVELS_SAMPLED] = {0};
        for (int lvl = 0; lvl < s.num_levels && lvl < BENCH_CF_LEVELS_SAMPLED; lvl++)
        {
            lf[lvl] = s.level_num_sstables[lvl];
            lm[lvl] = (double)s.level_sizes[lvl] / BENCH_BYTES_PER_MB;
        }
        fprintf(out,
                "%.3f\t%s\t%d\t%llu\t%llu\t%d\t%.2f\t%llu\t%.4f\t%.1f\t%.1f\t%.1f\t"
                "%llu\t%u\t%.2f\t%.4f\t%d\t%.1f\t%.1f\t%.1f\t%.1f\t%.1f\t%llu",
                t, c->cf_names[i], s.num_levels, (unsigned long long)s.total_keys,
                (unsigned long long)s.unflushed_key_count, sstables, s.read_amp,
                (unsigned long long)s.total_tombstones, s.tombstone_ratio,
                (double)s.total_data_size / BENCH_BYTES_PER_MB, s.avg_key_size, s.avg_value_size,
                (unsigned long long)s.btree_total_nodes, s.btree_max_height, s.btree_avg_height,
                s.max_sst_density, s.max_sst_density_level,
                (double)s.wal_bytes_written / BENCH_BYTES_PER_MB,
                (double)s.flush_bytes_written / BENCH_BYTES_PER_MB,
                (double)s.compaction_bytes_written / BENCH_BYTES_PER_MB,
                (double)s.compaction_bytes_read / BENCH_BYTES_PER_MB,
                (double)s.user_bytes_written / BENCH_BYTES_PER_MB,
                (unsigned long long)s.compaction_count);
        for (int lvl = 0; lvl < BENCH_CF_LEVELS_SAMPLED; lvl++) fprintf(out, "\t%d", lf[lvl]);
        for (int lvl = 0; lvl < BENCH_CF_LEVELS_SAMPLED; lvl++) fprintf(out, "\t%.1f", lm[lvl]);
        fprintf(out, "\n");
    }
}

/* ===== cache stats sampler ===== */

static void cachestats_header(FILE *out, const bench_sample_ctx_t *c)
{
    (void)c;
    fprintf(out, "t_sec\tenabled\tentries\tbytes_mb\tpartitions\thits\tmisses\thit_rate\n");
}

static void cachestats_row(FILE *out, double t, const bench_sample_ctx_t *c, bench_sampler_t *self)
{
    (void)self;
    tidesdb_cache_stats_t s;
    if (tidesdb_get_cache_stats(c->db, &s) != 0) return;
    fprintf(out, "%.3f\t%d\t%zu\t%.1f\t%zu\t%llu\t%llu\t%.4f\n", t, s.enabled, s.total_entries,
            (double)s.total_bytes / BENCH_BYTES_PER_MB, s.num_partitions,
            (unsigned long long)s.hits, (unsigned long long)s.misses, s.hit_rate);
}

/* the built-in sampler table; a delta sampler carries a bench_delta_state_t, the rest carry none */
typedef struct
{
    const char *name;
    void (*header)(FILE *, const bench_sample_ctx_t *);
    void (*row)(FILE *, double, const bench_sample_ctx_t *, bench_sampler_t *);
    int needs_state;
} bench_sampler_def_t;

static const bench_sampler_def_t BENCH_SAMPLER_DEFS[] = {
    {"resource", resource_header, resource_row, 1},
    {"throughput", throughput_header, throughput_row, 1},
    {"dbstats", dbstats_header, dbstats_row, 0},
    {"cfstats", cfstats_header, cfstats_row, 0},
    {"cachestats", cachestats_header, cachestats_row, 0},
};

int bench_samplers_open(bench_sampler_t *samplers, const char *dir, const bench_sample_ctx_t *c)
{
    (void)c;
    const int n = (int)(sizeof(BENCH_SAMPLER_DEFS) / sizeof(BENCH_SAMPLER_DEFS[0]));
    for (int i = 0; i < n; i++)
    {
        const bench_sampler_def_t *d = &BENCH_SAMPLER_DEFS[i];
        samplers[i].name = d->name;
        samplers[i].header = d->header;
        samplers[i].row = d->row;
        samplers[i].state = NULL;
        samplers[i].out = NULL;
        if (d->needs_state)
        {
            samplers[i].state = calloc(1, sizeof(bench_delta_state_t));
            if (!samplers[i].state) return -1;
        }
        if (dir)
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s.tsv", dir, d->name);
            samplers[i].out = fopen(path, "w");
        }
    }
    return n;
}

void bench_samplers_close(bench_sampler_t *samplers, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (samplers[i].out) fclose(samplers[i].out);
        free(samplers[i].state);
    }
}

/* write one row from every enabled sampler at elapsed time t */
static void bench_samplers_tick(bench_sampler_t *samplers, int n, double t,
                                const bench_sample_ctx_t *ctx)
{
    for (int i = 0; i < n; i++)
    {
        if (!samplers[i].out) continue;
        samplers[i].row(samplers[i].out, t, ctx, &samplers[i]);
        /* flushed every tick rather than left to the stream's buffer. a run that is killed -- by
         * the OOM killer, by a watchdog, by an operator who has seen enough -- is exactly the run
         * whose series matters, and a buffered stream loses the last several KB of it, which on a
         * few-hundred-byte row is the whole file for a short run */
        fflush(samplers[i].out);
    }
}

static void *bench_sampler_loop(void *arg)
{
    bench_sampler_thread_t *t = (bench_sampler_thread_t *)arg;
    while (!atomic_load_explicit(&t->stop, memory_order_acquire))
    {
        usleep((unsigned int)(t->interval_ms * 1000));
        bench_samplers_tick(t->samplers, t->n_samplers, bench_now_seconds() - t->ctx->t0, t->ctx);
    }
    return NULL;
}

int bench_sampler_thread_start(bench_sampler_thread_t *t, bench_sampler_t *samplers, int n_samplers,
                               int interval_ms, const bench_sample_ctx_t *ctx)
{
    t->samplers = samplers;
    t->n_samplers = n_samplers;
    t->interval_ms = interval_ms;
    t->ctx = ctx;
    atomic_init(&t->stop, 0);
    for (int i = 0; i < n_samplers; i++)
        if (samplers[i].out) samplers[i].header(samplers[i].out, ctx);
    return pthread_create(&t->tid, NULL, bench_sampler_loop, t) == 0 ? 0 : -1;
}

void bench_sampler_thread_stop(bench_sampler_thread_t *t)
{
    atomic_store_explicit(&t->stop, 1, memory_order_release);
    pthread_join(t->tid, NULL);
    bench_samplers_tick(t->samplers, t->n_samplers, bench_now_seconds() - t->ctx->t0, t->ctx);
}
