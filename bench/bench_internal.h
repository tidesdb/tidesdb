/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BENCH_INTERNAL_H__
#define __TIDESDB_BENCH_INTERNAL_H__

#include <stdint.h>

#include "bench_hist.h"
#include "compat.h" /* usleep and clock_gettime for the rate limiter, portable via compat */
#include "db.h"

/* the surface the driver and the workloads share. the driver owns the database, the threads and
 * the reporting; the workloads own what a worker actually does with a transaction. splitting them
 * keeps each file to one job, and this header is the only thing that crosses between */

/* the widest key and value a workload frames on the stack; both are validated against these at
 * parse time so a workload can size a buffer without checking again */
#define BENCH_MAX_KEY   512
#define BENCH_MAX_VALUE 65536

/* the leading big-endian index bytes that order keys */
#define BENCH_KEY_PREFIX_BYTES 8

/* per-thread failure counts are tallied by negated error code, so the array spans the codes */
#define BENCH_ERR_TALLY_LEN 24

/* key selection distribution */
typedef enum
{
    BENCH_DIST_UNIFORM,
    BENCH_DIST_ZIPFIAN,
    BENCH_DIST_SEQUENTIAL
} bench_dist_t;

/**
 * bench_config_t
 * every knob the driver and the engine take, filled from defaults then argv
 * @param benchmarks the comma-separated workload list to run in order
 * @param dir the database and tsv-output directory
 * @param threads the number of worker threads per benchmark
 * @param num the number of distinct keys in the keyspace
 * @param key_size the key length in bytes
 * @param value_size the value length in bytes
 * @param dist the key selection distribution
 * @param zipf_theta the zipfian skew, higher is more skewed
 * @param n_cfs the number of column families keys are spread across
 * @param txn_ops the number of write ops batched into one committed transaction
 * @param read_ratio the percent of mixed-workload ops that are reads
 * @param scan_length the number of entries a scan op iterates
 * @param seed the base RNG seed
 * @param sample_interval_ms the sampler tick period, 0 disables sampling
 * @param seconds run each workload for this many seconds instead of to its op count
 * @param rate hold total throughput to this many ops a second, 0 leaves a run unpaced
 * @param compression the klog encoding pipeline
 * @param index_fanout rows sharing one indexed value, for fillindex and indexscan
 * @param bloom_fpr the bloom filter false positive rate, negative leaves the family default
 * @param level_size_ratio the level size ratio, 0 leaves the family default
 * @param min_levels the minimum level count, 0 leaves the family default
 * @param dividing_level_offset how far above the largest level partitioned merges begin, negative
 * leaves the family default since zero is itself a setting
 * @param l1_file_count_trigger the L1 file count a merge is due at, 0 leaves the family default
 * @param tombstone_density_trigger the tombstone fraction a merge is due at, negative leaves the
 * family default since zero is itself a setting
 * @param tombstone_density_min_entries the entry count that trigger applies above, 0 leaves the
 * family default
 * @param btree_block_size the target btree node size, 0 leaves the family default
 * @param value_separation_threshold the size at or above which a value is separated, 0 leaves the
 * database default
 * @param large_value_size the value size the large-value workloads write
 * @param large_ratio the percent of mixed-large ops that write a large value
 * @param idle_flush_seconds the idle rotation period, negative leaves the database default
 * @param skip_list_max_level the memtable skip list height, 0 leaves the database default
 * @param skip_list_probability the memtable skip list probability, negative leaves the database
 * default
 * @param sync_mode the engine sync mode
 * @param memtable_size the memtable write-buffer size in bytes
 * @param cache_size the block-cache size in bytes
 * @param l0_stall the immutable-queue depth at which writes stall, 0 leaves the engine default
 * @param max_open_sstables the sstable descriptor ceiling, 0 leaves the engine default
 * @param vlog_segment_mb value-log segment size in megabytes, 0 leaves the engine default
 * @param stall_trace_ms report the stack of any commit still running after this many
 * milliseconds, 0 disables the tracer
 * @param flush_threads the number of flush worker threads, 0 leaves the engine default
 * @param compaction_threads the number of compaction worker threads, 0 leaves the engine default
 * @param bloom whether column families enable a bloom filter
 * @param isolation the transaction isolation level
 * @param log_level the engine log level, so a run can capture engine traces
 * @param log_file path the engine log is written to, empty to leave it on stderr
 * @param fresh remove the store directory before opening, so a run starts from nothing. off by
 * default -- a benchmark that deleted a directory it was merely pointed at would be a poor thing to
 * hand a path to
 * @param cleanup remove the store directory after the run, for a sweep that would otherwise leave
 * every configuration's data behind. also off by default
 */
typedef struct
{
    char benchmarks[512];
    char dir[512];
    int fresh;
    int cleanup;
    char log_file[512];
    int threads;
    uint64_t num;
    int key_size;
    int value_size;
    bench_dist_t dist;
    double zipf_theta;
    int n_cfs;
    int txn_ops;
    int read_ratio;
    int scan_length;
    uint64_t seed;
    int sample_interval_ms;
    int seconds;
    int rate;
    int compression;
    int index_fanout;
    int sync_mode;
    size_t memtable_size;
    size_t cache_size;
    int l0_stall;
    int max_open_sstables;
    int vlog_segment_mb;
    int stall_trace_ms;
    int flush_threads;
    int compaction_threads;
    int bloom;
    double bloom_fpr;
    tidesdb_isolation_level_t isolation;
    int log_level;

    /* the compaction shape, so a sweep can vary the tree rather than only the load. 0 leaves the
     * engine's own default in place, which is what makes an unswept run comparable to a swept one
     */
    int level_size_ratio;
    int min_levels;
    int dividing_level_offset;
    int l1_file_count_trigger;
    double tombstone_density_trigger;
    uint64_t tombstone_density_min_entries;
    uint64_t btree_block_size;

    /* db-level pacing and memtable shape */
    uint64_t value_separation_threshold;
    /* values at or above value_separation_threshold spill to the shared value log, so a
     * workload that writes some of these exercises the value log and its reclaim alongside ordinary
     * compaction rather than instead of it */
    int large_value_size;
    int large_ratio;

    int idle_flush_seconds;
    int skip_list_max_level;
    double skip_list_probability;
} bench_config_t;

/**
 * bench_zipf_t
 * the precomputed constants a thread uses to draw a zipfian-skewed index in [0, n)
 * @param n the keyspace size
 * @param theta the skew
 * @param zetan the zeta sum over n, precomputed once
 * @param eta the derived interpolation constant
 * @param alpha the derived exponent
 */
typedef struct
{
    uint64_t n;
    double theta;
    double zetan;
    double eta;
    double alpha;
} bench_zipf_t;

/**
 * bench_thread_t
 * one worker's private state; the database, column families, and shared counters are pointers into
 * driver-owned state, everything else is thread-local so workers never contend outside the engine
 */
typedef struct bench_thread
{
    int id;
    uint64_t rng;
    const bench_config_t *cfg;
    const bench_zipf_t *zipf;
    tidesdb_t *db;
    tidesdb_column_family_t **cfs;
    _Atomic(uint64_t) *ops_done; /* shared live op counter for the throughput sampler */
    _Atomic(uint64_t) *seq;      /* shared sequential-key allocator for fill workloads */
    _Atomic(int) *go;            /* start gate the workers spin on so timing starts coherently */
    _Atomic(int) *stop;          /* set when --seconds expires, ending every workload's loop */
    _Atomic(int) *finished;      /* workers that have returned, so a deadline can end early */
    double start_s;              /* this worker's monotonic start, the pacing clock's origin */
    double per_op_s;             /* seconds one op must take to hold --rate, or 0 for unpaced */
    uint64_t my_ops;             /* this thread's completed logical ops */
    uint64_t my_conflicts;       /* batches abandoned to a write-write conflict */
    uint64_t my_write_errors;    /* batches abandoned for any other reason */
    uint64_t my_err_tally[BENCH_ERR_TALLY_LEN]; /* those failures by negated error code */
    bench_hist_t read_hist;  /* this thread's read latency histogram in nanoseconds */
    bench_hist_t write_hist; /* this thread's commit latency histogram in nanoseconds */
    void (*run)(struct bench_thread *);
} bench_thread_t;

/**
 * bench_pace
 * hold the worker to its share of --rate by sleeping until this op's slot comes due.
 *
 * a rate is what makes two configurations comparable on anything the store's *shape* decides. read
 * amplification is an equilibrium between how fast data enters the flush tier and how fast
 * compaction drains it, so a run that simply goes faster ingests more and can settle at the same
 * depth having bought throughput instead of shallowness. pinning the input rate leaves drain as the
 * only variable
 * @param t the worker, whose completed op count is the position in its schedule */
static inline void bench_pace(const bench_thread_t *t)
{
    if (t->per_op_s <= 0.0) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const double now = (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
    const double due = t->start_s + (double)t->my_ops * t->per_op_s;
    if (due > now) usleep((unsigned int)((due - now) * 1e6));
}

/**
 * bench_more
 * the loop bound every workload shares. under --seconds the run is governed by a deadline and the
 * per-thread op budget is ignored, so a workload sustains pressure for as long as it is given
 * rather than finishing early at high thread counts -- which is what lets a store reach the depth
 * and the compaction backlog a short counted run never builds
 * @param t the worker
 * @param done how many of this thread's iterations have completed
 * @param budget this thread's share of --num, used only when no deadline was set
 * @return 1 while the workload should keep going
 */
static inline int bench_more(const bench_thread_t *t, uint64_t done, uint64_t budget)
{
    bench_pace(t);
    if (t->cfg->seconds > 0) return !atomic_load_explicit(t->stop, memory_order_relaxed);
    return done < budget;
}

/**
 * bench_workload_t
 * one named workload the driver can run
 * @param name the name a caller selects the workload by
 * @param run the per-thread body, run once on each worker
 */
typedef struct
{
    const char *name;
    void (*run)(struct bench_thread *);
} bench_workload_t;

/**
 * bench_zipf_next
 * draw a zipfian-skewed index from a uniform deviate
 * @param z the initialized generator
 * @param u a uniform deviate in [0, 1)
 * @return an index in [0, n)
 */
uint64_t bench_zipf_next(const bench_zipf_t *z, double u);

/**
 * bench_find_workload
 * look a workload up by the name a caller selected it with
 * @param name the workload name
 * @return the workload, or NULL when no workload carries that name
 */
const bench_workload_t *bench_find_workload(const char *name);

/**
 * bench_stall_enter
 * publish that this worker has entered a commit, so the stall watchdog can notice one that does
 * not return and ask this thread for its stack while it is still blocked. a no-op on platforms
 * without the tracer, and on a thread the driver never registered
 */
void bench_stall_enter(void);

/**
 * bench_stall_leave
 * clear what bench_stall_enter published, so a worker between commits is never reported
 */
void bench_stall_leave(void);

#endif /* __TIDESDB_BENCH_INTERNAL_H__ */
