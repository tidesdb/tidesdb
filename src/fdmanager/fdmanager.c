/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "fdmanager.h"

#include <errno.h>
#include <limits.h>

#include "base/log.h"

/* the reader gate and the open path answer the same shortage from opposite ends -- the gate waits
 * for the reaper to give descriptors back, the open path retries the EMFILE the ceiling reports.
 * a gate that gives up sooner than the open path retries fails a read on a shortage the open was
 * about to clear, so the two bounds are one decision and drift between them is caught here rather
 * than by the read that starts failing */
_Static_assert(TDB_FD_BUDGET_MAX_RECHECKS == TDB_BM_OPEN_EMFILE_MAX_RETRIES,
               "the reader gate and the EMFILE retry must wait the same shortage out equally long");

const char *fd_manager_label_name(fd_manager_label_t label)
{
    switch (label)
    {
        case FD_LABEL_SSTABLE_KLOG:
            return "sstable_klog";
        case FD_LABEL_VLOG_SEGMENT:
            return "vlog_segment";
        case FD_LABEL_WAL_LOG:
            return "wal_log";
        case FD_LABEL_COUNT:
        default:
            return "unknown";
    }
}

/* the resident total is the sum of every label's open count, read with relaxed ordering since the
 * budget check tolerates a transiently stale total */
static int fdmanager_total(const fd_manager_t *fdm)
{
    int total = 0;
    for (int i = 0; i < FD_LABEL_COUNT; i++)
        total += atomic_load_explicit(&fdm->num_open[i], memory_order_relaxed);
    return total;
}

int fd_manager_budget_for_process(const int configured, const long process_limit)
{
    if (configured <= 0) return configured;    /* unlimited, the caller's own arrangement */
    if (process_limit <= 0) return configured; /* no real ceiling to fit */

    const long room = process_limit - TDB_FD_RESERVE_UNTRACKED;
    if (room >= configured) return configured;

    /* the cut stops at the floor rather than reaching zero, which would read as unlimited, or
     * going negative. the floor never raises a budget though -- a caller who asked for less than it
     * gets what they asked for, since handing back more than was requested is not a cut at all */
    const int floor = TDB_FD_BUDGET_MIN < configured ? TDB_FD_BUDGET_MIN : configured;
    return room > floor ? (int)room : floor;
}

int fd_manager_init(fd_manager_t *fdm, int max_open)
{
    if (!fdm) return -1;
    fdm->max_open = max_open;
    for (int i = 0; i < FD_LABEL_COUNT; i++)
    {
        atomic_init(&fdm->num_open[i], 0);
        tdb_io_init(&fdm->io[i]);
    }
    atomic_init(&fdm->wake_fn, NULL);
    fdm->wake_ctx = NULL;
    return 0;
}

void fd_manager_destroy(fd_manager_t *fdm)
{
    if (!fdm) return;
    atomic_store_explicit(&fdm->wake_fn, NULL, memory_order_release);
}

void fd_manager_note_open(fd_manager_t *fdm, fd_manager_label_t label)
{
    if (!fdm || label >= FD_LABEL_COUNT) return;
    atomic_fetch_add_explicit(&fdm->num_open[label], 1, memory_order_relaxed);
}

void fd_manager_note_close(fd_manager_t *fdm, fd_manager_label_t label)
{
    if (!fdm || label >= FD_LABEL_COUNT) return;
    atomic_fetch_sub_explicit(&fdm->num_open[label], 1, memory_order_relaxed);
}

void fd_manager_set_reaper_wake(fd_manager_t *fdm, const fd_manager_wake_fn fn, void *ctx)
{
    if (!fdm) return;
    /* the context is published before the function that reads it, and the function is cleared
     * before the context is dropped, so a concurrent wake sees either both or neither */
    if (fn)
    {
        fdm->wake_ctx = ctx;
        atomic_store_explicit(&fdm->wake_fn, fn, memory_order_release);
        return;
    }
    atomic_store_explicit(&fdm->wake_fn, NULL, memory_order_release);
    fdm->wake_ctx = NULL;
}

void fd_manager_wake_reaper(fd_manager_t *fdm)
{
    if (!fdm) return;
    const fd_manager_wake_fn fn = atomic_load_explicit(&fdm->wake_fn, memory_order_acquire);
    if (fn) fn(fdm->wake_ctx);
}

int fd_manager_bm_open(fd_manager_t *fdm, block_manager_t **bm, const char *path, int sync_mode,
                       const fd_manager_label_t label)
{
    for (int attempt = 0;; attempt++)
    {
        if (block_manager_open(bm, path, sync_mode) == 0)
        {
            block_manager_set_io_stat(*bm, &fdm->io[label]);
            return 0;
        }
        if ((errno != EMFILE && errno != ENFILE) || attempt >= TDB_BM_OPEN_EMFILE_MAX_RETRIES)
        {
            /* giving up after the reaper had its chances is worth saying, since it separates a
             * descriptor ceiling the engine could not clear from any other reason an open failed */
            if (errno == EMFILE || errno == ENFILE)
                TDB_DEBUG_LOG(TDB_LOG_ERROR, "descriptors exhausted opening %s after %d attempts",
                              path, attempt + 1);
            return -1;
        }
        /* fd table is full but idle sstables can usually be closed -- wake the reaper and give it a
         * moment to reclaim descriptors before retrying. */
        fd_manager_wake_reaper(fdm);
        usleep(TDB_BM_OPEN_EMFILE_BACKOFF_US);
    }
}

int fd_manager_bm_open_pre(fd_manager_t *fdm, block_manager_t **bm, const char *path, int sync_mode,
                           uint64_t prealloc_chunk, const fd_manager_label_t label)
{
    for (int attempt = 0;; attempt++)
    {
        if (block_manager_open_pre(bm, path, sync_mode, prealloc_chunk) == 0)
        {
            block_manager_set_io_stat(*bm, &fdm->io[label]);
            return 0;
        }
        if ((errno != EMFILE && errno != ENFILE) || attempt >= TDB_BM_OPEN_EMFILE_MAX_RETRIES)
            return -1;
        fd_manager_wake_reaper(fdm);
        usleep(TDB_BM_OPEN_EMFILE_BACKOFF_US);
    }
}

int fd_manager_bm_open_buffered(fd_manager_t *fdm, block_manager_t **bm, const char *path,
                                int sync_mode, uint64_t ring_size, const fd_manager_label_t label)
{
    for (int attempt = 0;; attempt++)
    {
        if (block_manager_open_buffered(bm, path, sync_mode, ring_size) == 0)
        {
            block_manager_set_io_stat(*bm, &fdm->io[label]);
            return 0;
        }
        if ((errno != EMFILE && errno != ENFILE) || attempt >= TDB_BM_OPEN_EMFILE_MAX_RETRIES)
            return -1;
        fd_manager_wake_reaper(fdm);
        usleep(TDB_BM_OPEN_EMFILE_BACKOFF_US);
    }
}

int fd_manager_open_count(const fd_manager_t *fdm, fd_manager_label_t label)
{
    if (!fdm || label >= FD_LABEL_COUNT) return 0;
    return atomic_load_explicit(&fdm->num_open[label], memory_order_relaxed);
}

int fd_manager_open_total(const fd_manager_t *fdm)
{
    if (!fdm) return 0;
    return fdmanager_total(fdm);
}

int fd_manager_open_budget(const fd_manager_t *fdm)
{
    const int max_open = fdm->max_open;
    /* 0 = unlimited -- no soft cap, so the reaper never evicts for budget and readers never back
     * off; resident files are bounded only by the OS open-file limit */
    if (max_open == 0) return INT_MAX;
    int reserve = max_open / TDB_FD_READER_RESERVE_DIVISOR;
    if (reserve < TDB_FD_READER_RESERVE_MIN) reserve = TDB_FD_READER_RESERVE_MIN;
    /* cap the reserve so it never starves reads when max_open is below the floor */
    const int reserve_cap = max_open / TDB_FD_READER_RESERVE_MAX_DIVISOR;
    if (reserve > reserve_cap) reserve = reserve_cap;
    int budget = max_open - reserve;
    if (budget < 1) budget = 1;
    return budget;
}

int fd_manager_reader_budget_ok(fd_manager_t *fdm, int already_open)
{
    /* already counted -- an open file needs no new tracked descriptor and is never blocked */
    if (already_open) return 1;

    const int max_open = fdm->max_open;
    if (max_open == 0) return 1; /* unlimited -- never gate a reader open */

    /* the resident total is the whole question, because the budget it is measured against was
     * already cut to fit the process at open -- so descriptor pressure from the manifest and
     * temporaries is answered by the reserve that cut held back, not by a second count here */
    if (fdmanager_total(fdm) < max_open) return 1;

    /* over budget for a new open -- give the reaper repeated chances to reclaim idle files. this
     * waits the pressure out here rather than reporting it, because the caller's only remedy is to
     * sleep and ask again, and the engine is the one that knows what it is waiting for */
    for (int attempt = 0; attempt < TDB_FD_BUDGET_MAX_RECHECKS; attempt++)
    {
        fd_manager_wake_reaper(fdm);
        usleep(TDB_FD_BUDGET_RECHECK_STALL_US);
        if (fdmanager_total(fdm) < max_open) return 1;
    }
    return 0;
}

void fd_manager_io_stats(const fd_manager_t *fdm, const fd_manager_label_t label, uint64_t *out_ops,
                         uint64_t *out_bytes, uint64_t *out_total_us, uint64_t *out_max_us)
{
    if (!fdm || label >= FD_LABEL_COUNT)
    {
        *out_ops = 0;
        *out_bytes = 0;
        *out_total_us = 0;
        *out_max_us = 0;
        return;
    }
    tdb_io_read(&fdm->io[label], out_ops, out_bytes, out_total_us, out_max_us);
}
