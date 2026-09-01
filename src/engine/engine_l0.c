/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>

#include "base/errors.h"
#include "base/log.h"
#include "engine_internal.h"
#include "flush/flush.h"
#include "io/block_manager.h"
#include "txn/wal_record.h"

/* the engine's L0 half -- sealing the active memtable into the immutable queue and driving the
 * queued immutables through the flush pool into L1. kept apart from the composition root because
 * this is the one part of the engine with a concurrency protocol of its own: rotation runs on a
 * committing thread under rotate_lock, builds run in parallel off it, and installs are resequenced
 * by ticket so no sstable ever lands newer than what is still in L0. */

/* monotonic clock conversions for the engine's own latency accounting */
#define ENGINE_US_PER_SEC 1000000ull
#define ENGINE_NS_PER_US  1000ull

/* a rotation slower than this is logged; it runs on a committing thread, so it is write latency the
 * caller paid for and cannot see the cause of otherwise */
#define ENGINE_SLOW_ROTATE_WARN_US 20000ull

/* fired after a flush installs a cf's L1 segment; wake the compaction scheduler to reconsider the
 * cf */
static void engine_on_flush(void *ctx, uint64_t cf_id)
{
    (void)cf_id;
    engine_compaction_wake((tidesdb_t *)ctx);
}

/* build the cf-by-index array the flush demux addresses families through. the borrow on the
 * published view is held until engine_cf_index_array_release, and the families are valid only until
 * then. returns the array length, or -1 on an allocation failure */
static int engine_cf_index_array(tidesdb_t *db, cf_t ***out, cf_registry_view_t **out_view)
{
    *out = NULL;
    *out_view = NULL;

    /* borrowed from the published view rather than read under the registry lock. this runs on every
     * flush build and every install, which is continuously under load, and holding the read lock
     * for it is what left a create waiting behind a stream of readers that never broke. the borrow
     * is left by engine_cf_index_array_release once the caller has finished with the families */
    cf_t **live = NULL;
    int n_live = 0;
    cf_registry_view_t *view = cf_registry_view_enter(db->cfs, &live, &n_live);
    *out_view = view;

    uint64_t max_id = 0;
    for (int i = 0; i < n_live; i++)
        if (live[i]->cf_id > max_id) max_id = live[i]->cf_id;

    /* the borrow is handed back through out_view on every path, including these two, so the caller
     * releases it exactly once. leaving it here as well would drop one borrow twice and free the
     * view while another reader still held it */
    const int size = n_live ? (int)max_id + 1 : 0;
    if (size == 0) return 0;

    cf_t **cfs = calloc((size_t)size, sizeof(*cfs));
    if (!cfs) return -1;
    for (int i = 0; i < n_live; i++) cfs[live[i]->cf_id] = live[i];
    *out = cfs;
    return size;
}

/* give back the borrow engine_cf_index_array took, once the families it handed out are done with */
static void engine_cf_index_array_release(tidesdb_t *db, cf_t **cfs, cf_registry_view_t *view)
{
    cf_registry_view_leave(db->cfs, view);
    free(cfs);
}

/* the flush context over a cf-by-index array; the array and the families it names must outlive the
 * call the context is passed to */
static flush_ctx_t engine_flush_ctx(tidesdb_t *db, cf_t *const *cfs, int n_cfs)
{
    return (flush_ctx_t){.l0 = db->l0,
                         .cfs = cfs,
                         .wal_generation_pinned = engine_wal_generation_pinned,
                         .on_wal_retained = engine_note_retained_wal,
                         .on_wal_retained_ctx = db,
                         .n_cfs = n_cfs,
                         .manifest = db->manifest,
                         .manifest_path = db->manifest->path,
                         .next_sstable_id = &db->next_sstable_id,
                         .fdm = &db->fdm,
                         .sync_mode = engine_durable_sync_mode(db->config.memtable_sync_mode),
                         .value_threshold = db->config.value_separation_threshold,
                         /* the same floor a merge retains against. a memtable holds a version chain
                          * per key, so this is what decides how much of it reaches L1 -- read once
                          * per flush, and only ever too low, which keeps a version a reader might
                          * still want rather than dropping one it needs */
                         .gc_floor = engine_take_gc_floor(db),
                         .on_flush = engine_on_flush,
                         .on_flush_ctx = db};
}

/* install a built job when its flush ticket comes up, so concurrently built immutables still land
 * oldest-first; the sequence advances and the next ticket is woken whether or not this one
 * installed, so a build failure never stalls the order.
 *
 * the view is borrowed only once the ticket has come up, and given back before returning. the
 * families the build resolved may have been dropped in the meantime, so the job is rebound to what
 * the registry holds now. returns TDB_SUCCESS only when the job installed, which is also the only
 * case
 * where the immutable was retired */
static int engine_flush_install_ordered(tidesdb_t *db, flush_job_t *job, int build_rc,
                                        uint64_t ticket)
{
    int rc = build_rc;
    pthread_mutex_lock(&db->install_lock);
    while (db->flush_install_seq != ticket) pthread_cond_wait(&db->install_cv, &db->install_lock);
    if (build_rc == TDB_SUCCESS)
    {
        cf_t **cfs = NULL;
        cf_registry_view_t *view = NULL;
        const int n_cfs = engine_cf_index_array(db, &cfs, &view);
        if (n_cfs < 0)
        {
            /* the install never ran, so the built sstables are still this call's to close */
            rc = TDB_ERR_MEMORY;
            flush_job_free(job);
        }
        else
        {
            const flush_ctx_t fx = engine_flush_ctx(db, cfs, n_cfs);
            (void)flush_job_rebind(job, cfs, n_cfs);
            rc = flush_install(&fx, job); /* consumes the job either way */
        }
        engine_cf_index_array_release(db, cfs, view);
        if (rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "flush install failed rc=%d, data stays durable in the WAL", rc);
    }
    else if (job)
        flush_job_free(job);
    db->flush_install_seq++;
    pthread_cond_broadcast(&db->install_cv);
    pthread_mutex_unlock(&db->install_lock);

    /* a resolved prepare's batch is durable in L1 once this install commits, so the logs kept for
     * it are finally unnecessary. sweeping here rather than at the decision keeps a PREPARE on disk
     * for exactly as long as replay might still need it */
    engine_sweep_retained_wals(db);
    return rc;
}

/* build the immutable's sstables against a borrowed view of the families, then install them in the
 * claim ticket's order. the borrow is what stops a concurrent drop freeing a family whose run is
 * being written -- a drop publishes a view without it and then waits for the borrows to drain */
static void engine_flush_one(tidesdb_t *db, tidesdb_memtable_t *imm, uint64_t ticket)
{
    flush_job_t *job = NULL;
    const int build_token = vlog_build_enter(db->vlog);
    cf_t **cfs = NULL;
    cf_registry_view_t *view = NULL;
    const int n_cfs = engine_cf_index_array(db, &cfs, &view);
    int build_rc = TDB_SUCCESS;
    if (n_cfs < 0)
    {
        build_rc = TDB_ERR_MEMORY;
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "flush could not allocate the cf index array");
    }
    else
    {
        const flush_ctx_t fx = engine_flush_ctx(db, cfs, n_cfs);
        build_rc = flush_build(&fx, imm, &job);
        if (build_rc != TDB_SUCCESS)
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "flush build failed rc=%d, data stays durable in the WAL",
                          build_rc);
    }
    engine_cf_index_array_release(db, cfs, view);

    /* read before the install, which retires the immutable and frees it on the way through. the
     * value is settled by then -- a reference is only ever added to the active memtable, and this
     * one was sealed and its writers drained before the build started */
    const int held = atomic_load_explicit(&imm->vlog_token, memory_order_acquire);

    /* a flush that did not install leaves the immutable queued and unflushed, so drop the claim
     * that won it -- otherwise no worker can ever take it again and its data reaches L1 only via a
     * WAL replay on the next open. the next rotation's wake retries it */
    const int install_rc = engine_flush_install_ordered(db, job, build_rc, ticket);

    /* left only after the install, since until then the sstable naming this build's values does not
     * exist and a reclaim scanning now would find them referenced by nothing */
    vlog_build_leave(db->vlog, build_token);

    /* and the immutable's own floor, which covered the values a commit separated into it while it
     * was the active memtable. only an install ends that -- until one lands, this memtable is still
     * the only thing naming them, and a failed build leaves it queued to be flushed again */
    if (install_rc == TDB_SUCCESS && held != VLOG_BUILD_TOKEN_NONE)
        vlog_build_leave(db->vlog, held);

    if (install_rc != TDB_SUCCESS) tidesdb_l0_release_immutable(db->l0, imm);
}

void engine_flush_worker(void *item, void *ctx)
{
    (void)item; /* a wake signal; the immutable comes from the shared L0 queue */
    tidesdb_t *db = (tidesdb_t *)ctx;
    pthread_mutex_lock(&db->flush_lock);
    tidesdb_memtable_t *imm = tidesdb_l0_claim_immutable(db->l0);
    const uint64_t ticket =
        imm ? atomic_fetch_add_explicit(&db->flush_claim_seq, 1, memory_order_relaxed) : 0;
    pthread_mutex_unlock(&db->flush_lock);
    if (imm) engine_flush_one(db, imm, ticket);
}

/* open a log for the given generation; the naming and path work a rotation would otherwise do */
/**
 * engine_monotonic_us
 * read the monotonic clock in microseconds, for measuring how long a committing thread spent in
 * work it does on behalf of the engine rather than the transaction
 * @return microseconds since an unspecified epoch
 */
static uint64_t engine_monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * ENGINE_US_PER_SEC + (uint64_t)ts.tv_nsec / ENGINE_NS_PER_US;
}

/**
 * engine_rotate_cost_t
 * what each phase of a rotation cost, filled while the rotation lock is held and reported after it
 * is dropped. logging takes a process-wide mutex and writes to a stream that can block, so a
 * rotation that logged its own timings would hold the lock across exactly the wait these figures
 * exist to find
 * @param open_us microseconds spent opening the next log, 0 when a prepared one was taken
 * @param create_us microseconds spent allocating the incoming memtable
 * @param publish_us microseconds spent installing it
 * @param enqueue_us microseconds spent handing the sealed memtable to a flush worker
 * @param gen the generation the rotation installed
 */
typedef struct
{
    uint64_t open_us;
    uint64_t create_us;
    uint64_t publish_us;
    uint64_t enqueue_us;
    uint64_t gen;
} engine_rotate_cost_t;

static int engine_open_wal_for_gen(tidesdb_t *db, uint64_t gen, block_manager_t **out,
                                   uint64_t *out_us)
{
    char wal_name[ENGINE_WAL_NAME_MAX], wal_path[ENGINE_PATH_BUF_SIZE];
    if (tidesdb_wal_filename(gen, wal_name, sizeof(wal_name)) != TDB_SUCCESS) return TDB_ERR_IO;
    if (engine_build_path(db->db_path, wal_name, wal_path, sizeof(wal_path)) != TDB_SUCCESS)
        return TDB_ERR_IO;

    /* timed on its own because it is the one piece of work a rotation and a spare-log prepare both
     * do, and the rotation's own figure covers the memtable allocation and the publish as well. a
     * stall reported against the rotation alone cannot say which of the three held it, which has
     * left a slow open looking like a lock this path does not take */
    const uint64_t opened_from = engine_monotonic_us();
    const int rc = engine_open_wal(db, wal_path, out);
    if (out_us) *out_us = engine_monotonic_us() - opened_from;
    return rc == 0 ? TDB_SUCCESS : TDB_ERR_IO;
}

void engine_prepare_spare_wal(tidesdb_t *db)
{
    if (!db || atomic_load_explicit(&db->spare_wal, memory_order_acquire)) return;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;

    /* every committer that rotated arrives here at once and the check above is only a hint, so
     * without claiming the work each would create a log for a slot that holds one. the file, its
     * generation and the device work behind them are all spent before the loser finds out */
    if (atomic_exchange_explicit(&db->spare_wal_preparing, 1, memory_order_acquire)) return;

    const uint64_t gen =
        atomic_fetch_add_explicit(&db->wal_generation, 1, memory_order_relaxed) + 1;
    block_manager_t *wal = NULL;
    if (engine_open_wal_for_gen(db, gen, &wal, NULL) != TDB_SUCCESS)
    {
        atomic_store_explicit(&db->spare_wal_preparing, 0, memory_order_release);
        return;
    }

    /* the generation is written before the pointer is published, so a rotation that takes the log
     * also sees the generation it was named for */
    db->spare_wal_gen = gen;
    block_manager_t *expected = NULL;
    if (!atomic_compare_exchange_strong_explicit(&db->spare_wal, &expected, wal,
                                                 memory_order_release, memory_order_relaxed))
    {
        /* the file is unlinked as well as closed. a log nothing will ever take is not waiting to be
         * used, it is stranded, and on the next open it would still be scanned, replayed and given
         * a memtable of its own */
        engine_unlink_wal(db, wal);
    }
    atomic_store_explicit(&db->spare_wal_preparing, 0, memory_order_release);
}

/* seal the active memtable into the immutable queue and install a fresh active on the next WAL
 * generation, then wake a flush worker; the caller holds rotate_lock. returns TDB_SUCCESS, or an
 * error with the active left in place */
static int engine_rotate_locked(tidesdb_t *db, engine_rotate_cost_t *cost)
{
    /* take the prepared log when one is waiting, which is the whole point of preparing it -- the
     * rotation then costs a memtable allocation and two pointer swaps rather than a file creation.
     *
     * the generation is taken under the same claim the preparer writes it under, not read beside
     * the pointer afterwards. emptying the slot is exactly what lets the next preparer start, and
     * it writes its own generation into the field straight away -- so a rotation that read the
     * field after its exchange could name a memtable for a log it does not hold. the id would then
     * point at another generation's file, and the flush that asks whether that generation is pinned
     * would ask about the wrong log and could unlink one still holding an undecided prepare */
    block_manager_t *new_wal = NULL;
    uint64_t gen = 0;
    if (!atomic_exchange_explicit(&db->spare_wal_preparing, 1, memory_order_acquire))
    {
        new_wal = atomic_exchange_explicit(&db->spare_wal, NULL, memory_order_acquire);
        if (new_wal) gen = db->spare_wal_gen;
        atomic_store_explicit(&db->spare_wal_preparing, 0, memory_order_release);
    }

    /* a preparer holding the claim leaves this rotation to open its own log rather than wait on it,
     * which costs the creation this exists to avoid but only for the rotation that collides */
    if (!new_wal)
    {
        gen = atomic_fetch_add_explicit(&db->wal_generation, 1, memory_order_relaxed) + 1;
        if (engine_open_wal_for_gen(db, gen, &new_wal, &cost->open_us) != TDB_SUCCESS)
            new_wal = NULL;
    }

    cost->gen = gen;
    const uint64_t mt_from = engine_monotonic_us();
    tidesdb_memtable_t *new_mt =
        new_wal == NULL
            ? NULL
            : tidesdb_memtable_create(new_wal, gen, gen, db->config.memtable_skip_list_max_level,
                                      db->config.memtable_skip_list_probability, &db->now_seconds,
                                      db->arena);
    cost->create_us = engine_monotonic_us() - mt_from;

    const uint64_t pub_from = engine_monotonic_us();
    const int published = new_mt != NULL && tidesdb_l0_rotate(db->l0, new_mt) == TDB_SUCCESS;
    cost->publish_us = engine_monotonic_us() - pub_from;

    if (published)
    {
        db->wal_bm = new_wal; /* the old active's WAL now belongs to the sealed immutable */

        const uint64_t enq_from = engine_monotonic_us();
        (void)queue_enqueue(db->flush_queue, db); /* wake a worker to flush the sealed immutable */
        cost->enqueue_us = engine_monotonic_us() - enq_from;
        return TDB_SUCCESS;
    }

    if (new_mt) tidesdb_memtable_free(new_mt);
    engine_close_wal(db, new_wal);
    TDB_DEBUG_LOG(TDB_LOG_ERROR, "wal rotation failed at generation %llu", (unsigned long long)gen);
    return TDB_ERR_IO;
}

void engine_maybe_rotate(tidesdb_t *db)
{
    if (!tidesdb_l0_active_full(db->l0)) return;

    /* a rotation runs on whichever committing thread found the memtable full. the others do not
     * queue behind it -- a rotation is work that has to happen rather than work this caller must
     * personally do, and the thread holding the lock is doing it right now. queueing is what a
     * mutex that hands off by barging turns into starvation, one waiter losing every race for
     * minutes while the rest stream through, and a waiter here gains nothing by waiting that it
     * does not get from the holder finishing.
     *
     * the caller's write has already landed by this point, so declining costs it nothing. the
     * memtable stays full until the holder seals it, which is what admission paces against */
    /* taken before the lock, and compared after it, so the re-check below costs one relaxed load.
     * measuring the memtable again would take its range tombstone lock, whose read side holds off
     * while any writer waits -- an unbounded wait, performed while holding the lock every other
     * committer needs. that is how a rotation came to hold this lock for minutes: not doing slow
     * work, but blocking on another lock in the middle of it, with every other committer declining
     * and writing on into a memtable that could no longer seal */
    const uint64_t mark_before = tidesdb_l0_rotation_mark(db->l0);

    const uint64_t started_us = engine_monotonic_us();
    if (pthread_mutex_trylock(&db->rotate_lock) != 0) return;
    const uint64_t acquired_us = engine_monotonic_us();
    /* nobody rotated while this thread waited for the lock, so the fullness established above still
     * holds and this rotation is the one to do it */
    engine_rotate_cost_t cost;
    memset(&cost, 0, sizeof(cost));
    if (tidesdb_l0_rotation_mark(db->l0) == mark_before) (void)engine_rotate_locked(db, &cost);
    pthread_mutex_unlock(&db->rotate_lock);

    /* measured before the prepare below, so the figure stays what it claims to be: the time this
     * rotation cost while holding a lock every other committer needs */
    const uint64_t done_us = engine_monotonic_us();

    /* retained rather than only logged: a slow rotation shows up in a caller's write latency, and
     * the totals are what say whether the tail it measured came from here or from the log. the
     * lock figure is the cost of taking an uncontended mutex now that a contended one is declined
     * rather than waited on, so a tail that used to appear there appears as rotation work instead
     */
    tdb_wait_note(&db->rotate_lock_wait, acquired_us - started_us);
    tdb_wait_note(&db->rotate_work_wait, done_us - acquired_us);

    /* reported here rather than inside the rotation, because writing a line takes a process-wide
     * mutex and a stream that can block -- logging under the rotation lock would hold it across
     * exactly the wait these figures are meant to find */
    if (done_us - started_us >= ENGINE_SLOW_ROTATE_WARN_US)
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "slow memtable rotation %llu us, %llu of it taking the lock, generation %llu "
                      "-- open %llu us, create %llu us, publish %llu us, enqueue %llu us",
                      (unsigned long long)(done_us - started_us),
                      (unsigned long long)(acquired_us - started_us), (unsigned long long)cost.gen,
                      (unsigned long long)cost.open_us, (unsigned long long)cost.create_us,
                      (unsigned long long)cost.publish_us, (unsigned long long)cost.enqueue_us);

    /* prepared outside the lock on purpose: this is the file creation, ring allocation and flush
     * thread the next rotation would otherwise do while every committer waits behind it. it is
     * still this caller's latency, so it is worth its own line -- but it is one thread's cost now
     * rather than every committer's */
    const uint64_t prepare_from = engine_monotonic_us();
    engine_prepare_spare_wal(db);
    const uint64_t prepared_us = engine_monotonic_us();
    if (prepared_us - prepare_from >= ENGINE_SLOW_ROTATE_WARN_US)
        TDB_DEBUG_LOG(TDB_LOG_WARN, "slow next-wal prepare %llu us, off the rotation lock",
                      (unsigned long long)(prepared_us - prepare_from));
}

int engine_force_rotate(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* nothing to seal when the active memtable is empty, so a forced flush of an idle db is a no-op
     */
    if (tidesdb_l0_active_bytes(db->l0) == 0) return TDB_SUCCESS;

    pthread_mutex_lock(&db->rotate_lock);
    engine_rotate_cost_t forced_cost;
    memset(&forced_cost, 0, sizeof(forced_cost));
    const int rc =
        tidesdb_l0_active_bytes(db->l0) > 0 ? engine_rotate_locked(db, &forced_cost) : TDB_SUCCESS;
    pthread_mutex_unlock(&db->rotate_lock);
    return rc;
}

void engine_drain_immutables(tidesdb_t *db, int do_flush)
{
    if (!db->l0) return;
    tidesdb_memtable_t *imm;
    while ((imm = tidesdb_l0_dequeue_immutable(db->l0)) != NULL)
    {
        if (do_flush)
            /* the pool is stopped, so pass the current install sequence as the ticket and this
             * flush installs immediately with nothing to order against */
            engine_flush_one(db, imm, db->flush_install_seq);
        else
        {
            /* reclaim does not close the WAL, so close it here without unlinking -- the data must
             * survive to be recovered on the next open */
            block_manager_t *wal = atomic_load_explicit(&imm->wal, memory_order_acquire);
            tidesdb_l0_reclaim(db->l0, imm);
            engine_close_wal(db, wal);
        }
    }
}
