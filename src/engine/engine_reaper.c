/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <limits.h> /* INT_MAX, the unlimited descriptor budget */
#include <stdlib.h>
#include <time.h>

#include "base/errors.h"
#include "base/log.h" /* TDB_DEBUG_LOG for the idle-rotation notice */
#include "column_family/level/level_set.h"
#include "engine/engine_internal.h"
#include "fdmanager/reaper.h"
#include "io/block_manager.h"
#include "sstable/sstable.h"

/* the reaper family runs as bg_tickers on the threadmanager. the fd-eviction reaper is the first
 * and the one that matters for liveness: it closes idle, unreferenced sstable klog descriptors so a
 * read held at the fd budget can reopen the klog it needs. that read wakes this reaper and rechecks
 * rather than reporting the shortage, so how promptly this reclaims is what decides whether the
 * wait clears or the read finally gives up as busy. the compaction backstop reaper is the
 * compaction scheduler (engine_compaction.c). */

/* the threadmanager labels and intervals for the ticker family */
#define ENGINE_FD_REAPER_LABEL       "reaper.fd_evict"
#define ENGINE_FD_REAPER_INTERVAL_US 1000000 /* sweep idle klog descriptors every second */

#define ENGINE_DEFERRED_FREE_LABEL "reaper.deferred_free"
/* reclaim drained retired layouts every second */
#define ENGINE_DEFERRED_FREE_INTERVAL_US 1000000

#define ENGINE_TXN_CLOCK_LABEL       "txn_clock"
#define ENGINE_TXN_CLOCK_INTERVAL_US 1000000 /* refresh the transaction clock every second */

#define ENGINE_WAL_SYNC_LABEL      "wal_sync"
#define ENGINE_WAL_SYNC_DEFAULT_US 1000000 /* fallback interval when the config leaves it zero */

#define ENGINE_IDLE_FLUSH_LABEL         "idle_flush"
#define ENGINE_IDLE_FLUSH_US_PER_SECOND 1000000ull

/* qsort comparator ordering sstables oldest-access-first, the eviction order fd_reaper_run expects
 */
static int engine_sstable_lru_cmp(const void *a, const void *b)
{
    const sstable_t *sa = *(sstable_t *const *)a;
    const sstable_t *sb = *(sstable_t *const *)b;
    const time_t ta = atomic_load_explicit(&sa->last_access_time, memory_order_relaxed);
    const time_t tb = atomic_load_explicit(&sb->last_access_time, memory_order_relaxed);
    if (ta < tb) return -1;
    return ta > tb ? 1 : 0;
}

/* the fd-eviction tick: gather every sstable, order it least-recently-accessed first, and hand it
 * to the fd reaper, which closes idle klog descriptors down to the budget. the whole tick holds the
 * registry read lock so a concurrent cf-levels reload cannot free a level set or truncate a klog
 * underneath the collected, still-referenced sstables */
static void engine_fd_reaper_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;

    /* the sweep below references every sstable in the database, orders them, and releases them all
     * again. it is worth doing only when there is something to reclaim, and the condition for that
     * is the one the reclaim loop itself tests -- so it is asked first, before any of the work. an
     * unlimited budget never reclaims at all, and a database inside its budget has nothing to give
     * back */
    const int budget = fd_manager_open_budget(&db->fdm);
    if (budget >= INT_MAX || fd_manager_open_total(&db->fdm) <= budget) return;

    cf_registry_rdlock(db->cfs);
    sstable_t **cands = NULL;
    const int n = engine_collect_sstables(db, &cands);
    if (n <= 0)
    {
        cf_registry_rdunlock(db->cfs);
        free(cands);
        return;
    }
    /* only a table holding a descriptor has anything to give back, and a database keeps far more
     * sstables than it keeps open -- every one merged away or never read since an eviction is dead
     * weight here. dropping them before the ordering spares both the sort and the sweep the whole
     * cold tail, and hands their references back at once rather than at the end of the tick */
    int resident = 0;
    for (int i = 0; i < n; i++)
    {
        if (sstable_klog_resident(cands[i]))
            cands[resident++] = cands[i];
        else if (sstable_unref(cands[i]))
            sstable_close(cands[i]);
    }
    /* still handed on with none of its own, since the sweep gives back value-log segments before it
     * looks at any candidate and that phase is owed a tick whatever the klogs are doing */
    qsort(cands, (size_t)resident, sizeof(*cands), engine_sstable_lru_cmp);
    (void)fd_reaper_run(&db->fdm, cands, resident, db->vlog);
    for (int i = 0; i < resident; i++)
        if (sstable_unref(cands[i])) sstable_close(cands[i]);
    cf_registry_rdunlock(db->cfs);
    free(cands);
}

/* the deferred-free tick: reclaim each cf's superseded level-set layouts whose readers have
 * drained, so retired sstables and layout memory do not pile up under steady reads with little
 * mutation */
static void engine_deferred_free_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;

    cf_registry_rdlock(db->cfs);
    const int n = cf_registry_count_locked(db->cfs);
    for (int i = 0; i < n; i++)
        level_set_reclaim_deferred(cf_registry_at_locked(db->cfs, i)->levels);
    cf_registry_rdunlock(db->cfs);

    /* immutables a flush could not free inline, because readers still held them when it finished.
     * swept here rather than waited on there, so a flush never holds the registry lock waiting for
     * a reader to leave */
    tidesdb_l0_reclaim_pending(db->l0);
}

/* the interval wal-sync tick: fsync the active WAL so interval-mode commits become durable within
 * one interval. the log is held open by a pin rather than by the rotation lock -- that lock is what
 * every committer takes to rotate a full memtable, so fsyncing under it stalled the whole database
 * once per interval, which is the one thing a background ticker must never do */
static void engine_wal_sync_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;
    (void)tidesdb_l0_sync_active_wal(db->l0);
}

/* the transaction-clock tick: publish the current second for transactions to age against. it runs
 * whatever the configuration says, because a timeout can be set on a single transaction at runtime
 * and a clock that only ticked when a database-wide default was configured would leave that one
 * unable to expire. one relaxed store a second */
static void engine_txn_clock_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    atomic_store_explicit(&db->now_seconds, (int64_t)time(NULL), memory_order_relaxed);
}

/* the idle-flush tick: rotate the active memtable when a whole interval has passed without a write
 * landing in it, so a database that has gone quiet still drains to L1.
 *
 * the idle signal is the active memtable's size sampled across two ticks. an unchanged non-zero
 * size means nothing was written in between, which costs nothing on the write path -- no timestamp
 * to stamp per commit, no counter to contend on. two different writes could in principle leave the
 * size identical, and the cost of that is a rotation one interval early, which is legal at any time
 */
static void engine_idle_flush_tick(void *ctx)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return;

    const size_t bytes = tidesdb_l0_active_bytes(db->l0);
    const size_t previous = db->idle_flush_bytes;
    db->idle_flush_bytes = bytes;

    if (bytes == 0 || bytes != previous) return;

    /* force_rotate seals only a non-empty active memtable and wakes a flush worker, so a rotation
     * that raced a write in is still correct */
    if (engine_force_rotate(db) == TDB_SUCCESS)
    {
        db->idle_flush_bytes = 0;
        TDB_DEBUG_LOG(TDB_LOG_INFO, "rotated %zu idle bytes to l1", bytes);
    }
}

/* start one ticker and register it, stopping it if registration fails. out_ticker receives the
 * started ticker for a caller that has to reach it again, borrowed -- the threadmanager owns it */
static int engine_start_ticker(tidesdb_t *db, uint64_t interval_us, bg_ticker_fn fn,
                               const char *label, bg_ticker_t **out_ticker)
{
    bg_ticker_t *ticker = bg_ticker_start(interval_us, fn, db);
    if (!ticker) return TDB_ERR_MEMORY;
    if (threadmanager_add_ticker(db->threads, label, ticker) != 0)
    {
        bg_ticker_stop(ticker);
        return TDB_ERR_MEMORY;
    }
    if (out_ticker) *out_ticker = ticker;
    return TDB_SUCCESS;
}

/* run the fd reaper's sweep now. the descriptor manager calls this when a caller is waiting on a
 * descriptor it cannot have, and without it that caller would sit out the rest of the tick -- which
 * is an order of magnitude longer than it is willing to wait, so it would give up every time */
static void engine_wake_fd_reaper(void *ctx)
{
    bg_ticker_wake((bg_ticker_t *)ctx);
}

int engine_reaper_init(tidesdb_t *db)
{
    /* seeded before the ticker starts so a transaction opened in the first second ages against a
     * real clock rather than against zero */
    atomic_store_explicit(&db->now_seconds, (int64_t)time(NULL), memory_order_relaxed);
    int rc = engine_start_ticker(db, ENGINE_TXN_CLOCK_INTERVAL_US, engine_txn_clock_tick,
                                 ENGINE_TXN_CLOCK_LABEL, NULL);
    if (rc != TDB_SUCCESS) return rc;
    rc = engine_start_ticker(db, ENGINE_FD_REAPER_INTERVAL_US, engine_fd_reaper_tick,
                             ENGINE_FD_REAPER_LABEL, &db->fd_reaper);
    if (rc != TDB_SUCCESS) return rc;
    /* now that there is a reaper to reach, a caller held at the descriptor budget can make it sweep
     * instead of waiting out its tick */
    fd_manager_set_reaper_wake(&db->fdm, engine_wake_fd_reaper, db->fd_reaper);
    rc = engine_start_ticker(db, ENGINE_DEFERRED_FREE_INTERVAL_US, engine_deferred_free_tick,
                             ENGINE_DEFERRED_FREE_LABEL, NULL);
    if (rc != TDB_SUCCESS) return rc;

    /* the idle-flush ticker is opt-out rather than opt-in, since a database that never drains is
     * the surprising behaviour; a zero interval turns it off */
    if (db->config.memtable_idle_flush_seconds > 0)
    {
        rc = engine_start_ticker(
            db, (uint64_t)db->config.memtable_idle_flush_seconds * ENGINE_IDLE_FLUSH_US_PER_SECOND,
            engine_idle_flush_tick, ENGINE_IDLE_FLUSH_LABEL, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }

    /* the wal-sync ticker exists only in interval mode: full fsyncs each commit, none never fsyncs
     */
    if (db->config.memtable_sync_mode == TDB_SYNC_INTERVAL)
    {
        const uint64_t interval = db->config.memtable_sync_interval_us
                                      ? db->config.memtable_sync_interval_us
                                      : ENGINE_WAL_SYNC_DEFAULT_US;
        rc = engine_start_ticker(db, interval, engine_wal_sync_tick, ENGINE_WAL_SYNC_LABEL, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }
    return TDB_SUCCESS;
}
