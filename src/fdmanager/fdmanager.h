/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FDMANAGER_H__
#define __TIDESDB_FDMANAGER_H__

#include "../compat.h"
#include "base/waitstat.h" /* tdb_io_stat_t for per-label write accounting */
#include "io/block_manager.h"

/* the fd manager is a standalone descriptor-budget service; it owns no engine and reaches into no
 * global handle. a caller constructs one, opens block managers through it, and gates reader opens
 * against a soft budget. both paths wait descriptor pressure out to the same bound -- waking the
 * reaper and rechecking -- and only report it when it does not clear, so a caller is not handed a
 * shortage the engine was about to resolve on its own. every tracked descriptor carries a label
 * naming its file kind (an sstable klog, an L0 write-ahead log), so counts are kept per label and
 * the right reaper reclaims the right kind, while one shared budget bounds the total. it is
 * unit-testable with a stack fd_manager_t and no database. */

/* opening a block manager can momentarily hit the process open-fd ceiling under heavy flush and
 * compaction. the bm-open wrappers treat EMFILE/ENFILE as transient backpressure -- wake the reaper
 * to close idle files and retry a bounded number of times before failing. */
#define TDB_BM_OPEN_EMFILE_MAX_RETRIES 5
#define TDB_BM_OPEN_EMFILE_BACKOFF_US  20000 /* 20ms between retries */

/* each labeled resident file holds one descriptor. value-log segments and write-ahead logs are
 * labeled alongside sstable klogs, while the manifest and stdio are not, so those plus headroom are
 * covered by FD_RESERVE_UNTRACKED -- subtracted from the process open-file limit to leave room for
 * the files the budget does not count. the engine spends it that way at open, cutting a configured
 * budget that would not leave it through fd_manager_budget_for_process. */
#define TDB_FD_RESERVE_UNTRACKED 64

/* the smallest budget a cut will leave. a process ceiling low enough to reach this cannot run the
 * engine well whatever the budget says, but a budget of zero means unlimited and a negative one is
 * nonsense, so the cut stops here and lets the EMFILE retry carry what is left */
#define TDB_FD_BUDGET_MIN 16

/* the reserve held back from the reapers, so that descriptors stay free for a reader to open into
 * rather than being held by whatever was resident when the sweep ran. the reserve is max_open /
 * DIVISOR, raised to MIN and then capped at max_open / MAX_DIVISOR, and the budget the reapers
 * evict down to is max_open minus it. the cap is what keeps the reserve from taking more than half,
 * so the reapers are always left at least half the descriptors to work with. */
#define TDB_FD_READER_RESERVE_DIVISOR     8
#define TDB_FD_READER_RESERVE_MIN         16
#define TDB_FD_READER_RESERVE_MAX_DIVISOR 2

/* after waking the reaper at the hard cap, a reader waits this long before rechecking the count.
 * it rechecks several times rather than once because descriptor pressure under a heavy flush and
 * compaction load lasts longer than one stall, and a read that gives up early turns transient
 * pressure into a failure the caller has to understand and retry -- which is engine work, not the
 * caller's. the bound matches the open path, which absorbs the same pressure the same way. */
#define TDB_FD_BUDGET_RECHECK_STALL_US 10000
#define TDB_FD_BUDGET_MAX_RECHECKS     5

/**
 * fd_manager_label_t
 * the kind of file a tracked descriptor belongs to; the manager keeps one open count per label and
 * a kind-specific reaper reclaims that label's descriptors
 * @param FD_LABEL_SSTABLE_KLOG an immutable sstable klog file
 * @param FD_LABEL_WAL_LOG an L0 write-ahead log file
 * @param FD_LABEL_VLOG_SEGMENT a value-log segment file
 * @param FD_LABEL_COUNT the number of labels, not itself a label
 */
typedef enum
{
    FD_LABEL_SSTABLE_KLOG = 0,
    FD_LABEL_WAL_LOG,
    FD_LABEL_VLOG_SEGMENT,
    FD_LABEL_COUNT
} fd_manager_label_t;

/**
 * fd_manager_label_name
 * a stable human-readable name for a label, for logging and introspection
 * @param label the label
 * @return the name, or "unknown" for an out-of-range label
 */
const char *fd_manager_label_name(fd_manager_label_t label);

/**
 * fd_manager_wake_fn
 * makes the reaper run its sweep now rather than at its next tick. the manager holds no engine and
 * knows nothing of how the reaper is scheduled, so what to call is installed from outside
 * @param ctx the context given alongside the function
 */
typedef void (*fd_manager_wake_fn)(void *ctx);

/**
 * fd_manager_t
 * a descriptor-budget context -- the shared resident-file cap, a live open count per label, and the
 * condition a reader signals to wake the reaper. fd_manager_init puts every field at its starting
 * value, so one on the stack needs nothing done to it first.
 * @param max_open shared soft cap on total resident labeled files, 0 for unlimited
 * @param num_open live open count per label, indexed by fd_manager_label_t
 * @param wake_fn what to run to make the reaper sweep now, or NULL while none is installed. cleared
 *          before the reaper is stopped, so a wake raced against shutdown finds nothing to call
 * @param wake_ctx passed to wake_fn, set once alongside it
 * @param io per-label write accounting, so bytes and time are attributed to the kind of file rather
 *     than pooled. a handle opened outside this manager is not accounted
 */
typedef struct
{
    int max_open;
    _Atomic(int) num_open[FD_LABEL_COUNT];
    _Atomic(fd_manager_wake_fn) wake_fn;
    void *wake_ctx;
    tdb_io_stat_t io[FD_LABEL_COUNT];
} fd_manager_t;

/**
 * fd_manager_budget_for_process
 * the resident-file cap to actually run with, given what the caller asked for and what the process
 * may hold open at once. a cap that would not leave TDB_FD_RESERVE_UNTRACKED descriptors for the
 * manifest, stdio and temporaries is cut until it does, because the alternative is a budget the
 * engine spends into EMFILE and then retries its way back out of, one open at a time. the ceiling
 * is only ever read -- raising it belongs to the operator, through tidesdb_raise_open_file_limit
 * @param configured the cap asked for; 0 means unlimited and is returned untouched, since that is
 *                   a caller saying they have sized the process themselves
 * @param process_limit the process open-file ceiling, or 0 when there is no real one to fit, in
 *                      which case there is nothing to cut against and configured stands
 * @return the cap to run with -- never above configured, and not cut below TDB_FD_BUDGET_MIN
 *         unless configured was already under it, since a cut may not hand back more than was asked
 */
int fd_manager_budget_for_process(int configured, long process_limit);

/**
 * fd_manager_init
 * initialize an fd manager with a shared resident-file cap, taken as given. fitting that cap to the
 * process is the caller's, through fd_manager_budget_for_process -- keeping it out of here leaves
 * this a primitive that does what it is told, and its budget arithmetic answerable without a
 * process ceiling in the question
 * @param fdm the fd manager
 * @param max_open shared soft cap on total resident labeled files, 0 for unlimited
 * @return 0 on success, -1 on a lock/condition init failure
 */
int fd_manager_init(fd_manager_t *fdm, int max_open);

/**
 * fd_manager_destroy
 * destroy an fd manager's lock and condition; the caller has already quiesced its users
 * @param fdm the fd manager, may be NULL
 */
void fd_manager_destroy(fd_manager_t *fdm);

/**
 * fd_manager_note_open / fd_manager_note_close
 * adjust the resident open count for a label when one of its descriptors is opened or closed
 * @param fdm the fd manager
 * @param label the file kind whose count to adjust
 */
void fd_manager_note_open(fd_manager_t *fdm, fd_manager_label_t label);
void fd_manager_note_close(fd_manager_t *fdm, fd_manager_label_t label);

/**
 * fd_manager_wake_reaper
 * nudge the reaper to run its eviction pass now, closing idle unreferenced block managers, rather
 * than leaving the waiting caller to sit out the rest of its tick. a no-op when no wake was
 * installed, which is every unit test that drives a manager without a reaper behind it
 * @param fdm the fd manager
 */
void fd_manager_wake_reaper(fd_manager_t *fdm);

/**
 * fd_manager_set_reaper_wake
 * install what fd_manager_wake_reaper calls, or clear it by passing NULL. the caller clears it
 * before the reaper it names is torn down, since a wake arriving after that would reach a stopped
 * one
 * @param fdm the fd manager
 * @param fn what to run to make the reaper sweep now, or NULL to install nothing
 * @param ctx passed back to fn
 */
void fd_manager_set_reaper_wake(fd_manager_t *fdm, fd_manager_wake_fn fn, void *ctx);

/**
 * fd_manager_bm_open
 * open a block manager, treating descriptor exhaustion as transient backpressure -- wake the reaper
 * and retry a bounded number of times, returning immediately on any other error or on success
 * @param fdm the fd manager, for waking the reaper on EMFILE
 * @param bm receives the opened block manager
 * @param path file path
 * @param sync_mode block-manager sync mode
 * @param label the file kind this handle's writes are accounted against
 * @return 0 on success, -1 on failure with errno set
 */
int fd_manager_bm_open(fd_manager_t *fdm, block_manager_t **bm, const char *path, int sync_mode,
                       fd_manager_label_t label);

/**
 * fd_manager_bm_open_pre
 * like fd_manager_bm_open but with a caller-chosen preallocation chunk, so a file known to stay
 * small does not reserve the full default extent; pass 0 to disable preallocation
 * @param fdm the fd manager, for waking the reaper on EMFILE
 * @param bm receives the opened block manager
 * @param path file path
 * @param sync_mode block-manager sync mode
 * @param prealloc_chunk the on-disk extent to grow by at a time, in bytes, or 0 to disable
 * @param label the file kind this handle's writes are accounted against
 * @return 0 on success, -1 on failure with errno set
 */
int fd_manager_bm_open_pre(fd_manager_t *fdm, block_manager_t **bm, const char *path, int sync_mode,
                           uint64_t prealloc_chunk, fd_manager_label_t label);

/**
 * fd_manager_bm_open_buffered
 * the buffered-append counterpart of fd_manager_bm_open, used for an active WAL, with the same
 * fd-exhaustion backpressure and retry policy
 * @param fdm the fd manager, for waking the reaper on EMFILE
 * @param bm receives the opened buffered block manager
 * @param path file path
 * @param sync_mode block-manager sync mode
 * @param ring_size staging ring size in bytes, 0 for the block manager's default
 * @param label the file kind this handle's writes are accounted against
 * @return 0 on success, -1 on failure with errno set
 */
int fd_manager_bm_open_buffered(fd_manager_t *fdm, block_manager_t **bm, const char *path,
                                int sync_mode, uint64_t ring_size, fd_manager_label_t label);

/**
 * fd_manager_io_stats
 * read one label's write accounting
 * @param fdm the fd manager, may be NULL
 * @param label the file kind to query
 * @param out_ops out -- writes issued
 * @param out_bytes out -- bytes written
 * @param out_total_us out -- summed write time
 * @param out_max_us out -- slowest single write
 */
void fd_manager_io_stats(const fd_manager_t *fdm, fd_manager_label_t label, uint64_t *out_ops,
                         uint64_t *out_bytes, uint64_t *out_total_us, uint64_t *out_max_us);

/**
 * fd_manager_open_count
 * the current resident open count for one label
 * @param fdm the fd manager, may be NULL
 * @param label the file kind to query
 * @return the label's resident open count, or 0 when fdm is NULL
 */
int fd_manager_open_count(const fd_manager_t *fdm, fd_manager_label_t label);

/**
 * fd_manager_open_total
 * the current resident open count summed across every label; the reaper compares it to the shared
 * budget to decide how many idle descriptors of its kind to reclaim
 * @param fdm the fd manager, may be NULL
 * @return the total resident open count, or 0 when fdm is NULL
 */
int fd_manager_open_total(const fd_manager_t *fdm);

/**
 * fd_manager_open_budget
 * the shared descriptor budget, max_open minus the reader reserve. it is what every reaper evicts
 * down to; a reader is admitted against max_open itself, and the gap between the two is the reserve
 * that leaves it something to open into
 * @param fdm the fd manager
 * @return the open budget, or INT_MAX when max_open is 0 (unlimited)
 */
int fd_manager_open_budget(const fd_manager_t *fdm);

/**
 * fd_manager_reader_budget_ok
 * gate a reader about to open a not-yet-open file against the fd budget -- both the shared resident
 * total and the comprehensive all-fds ceiling. an already-open file needs no new descriptor and is
 * never blocked. when over budget, wake the reaper and recheck a bounded number of times, so a read
 * waits out descriptor pressure instead of handing it back as a failure to retry
 * @param fdm the fd manager
 * @param already_open non-zero if the file already holds its descriptor (never gated)
 * @return 1 if ok to open (or already open), 0 if still over the budget after every recheck
 */
int fd_manager_reader_budget_ok(fd_manager_t *fdm, int already_open);

#endif /* __TIDESDB_FDMANAGER_H__ */
