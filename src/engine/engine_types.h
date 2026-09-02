/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_ENGINE_TYPES_H__
#define __TIDESDB_ENGINE_TYPES_H__

#include "base/arena.h"
#include "base/bg_ticker.h"
#include "base/encoding/encoding.h"
#include "base/waitstat.h" /* tdb_wait_stat_t for the rotation waits */
#include "cache/cache.h"
#include "column_family/cf_iter.h"
#include "column_family/cf_registry.h"
#include "datastructures/queue.h"
#include "db.h"
#include "fdmanager/fdmanager.h"
#include "flush/flush.h"
#include "io/block_manager.h" /* the sync-mode enum the sstable helper returns */
#include "manifest/manifest.h"
#include "memtable/memtable.h"
#include "sstable/vlog.h"
#include "threadmanager/threadmanager.h"
#include "txn/l0_adapter.h"
#include "txn/mvcc.h"
#include "txn/registry.h"
#include "txn/source.h"
#include "txn/txn.h"

/* the db-level read source stack every transaction reads and commit-validates against: the shared
 * L0 then the per-cf sstable levels, dispatched by cf-index. its size is fixed */
#define ENGINE_NUM_SOURCES 2

/* the engine is the internal global state of one open database -- the object the public tidesdb_t
 * handle names. it owns every db-level singleton, the column-family registry, the mvcc clock and
 * the worker registry, and composes them into the open, recover and close lifecycle. src/db.c is
 * the thin public facade over it, and nothing below the engine sees these types, which is what
 * leaves every module testable without a database.
 *
 * this header holds that state; the api operating on it is engine.h, which includes this one */

/**
 * engine_retained_wal_t
 * a flushed write-ahead log kept on disk because its generation may still hold an undecided prepare
 * @param path the log file to unlink once the generation is no longer needed
 * @param generation the log's generation, compared against the prepare floor to decide when that is
 */
typedef struct
{
    char *path;
    uint64_t generation;
} engine_retained_wal_t;

/**
 * tidesdb_t
 * the engine, the internal type behind the public opaque handle
 * @param config the resolved database configuration, with db_path pointing at the owned copy below
 * @param db_path an owned copy of the database directory path
 * @param cache the db-level block cache serving every cf's sstable block reads
 * @param encodings the db-level encoding registry every column family resolves its pipeline ids
 * against; built once at open with the compression backends this build carries, and extended by a
 * caller that registers its own
 * @param fdm the process fd budget for sstable klog handles
 * @param fdm_inited whether fdm was initialized, so close only destroys an initialized fd manager
 * @param arena the db-level arena pool the unified memtable draws from
 * @param node_arena the pool a decoded btree node carves its arena from, chunked for one node
 * rather than for a memtable so a cached node does not park a chunk it barely uses
 * @param manifest the db-level manifest, the catalog of every cf's sstables and the durable
 * sequence
 * @param vlog the db-level value log shared by every column family
 * @param clock the global mvcc sequence, seeded from the manifest sequence on recovery
 * @param cfs the column-family registry, empty until the cf lifecycle phase populates it
 * @param threads the worker registry owning every bg_pool and bg_ticker the engine starts
 * @param l0 the shared unified memtable (one skip_list + one WAL, cf-index namespaced)
 * @param wal_bm the block manager backing the active memtable's write-ahead log
 * @param l0_ctx the l0 adapter context binding the txn core to the shared L0
 * @param l0_ctx_inited whether l0_ctx was initialized, so close only tears down an initialized
 * adapter
 * @param backend the commit backend the txn core drives to append the WAL and apply to L0
 * @param sources the db-level read source stack (L0 then the sstable-dispatch source), newest-first
 * @param txn_registry the live-transaction registry feeding the compaction gc floor and ssi checks
 * @param prepared the two-phase records recovery staged from the WAL. what is still in-doubt once
 * the log is exhausted stays here for the coordinator to list and resolve
 * @param retained_wals the logs a flush kept because a prepare was outstanding, unlinked once
 * nothing is in doubt. without the sweep one would outlive the log holding its decision and the
 *                transaction would come back as falsely in doubt
 * @param n_retained_wals how many entries retained_wals holds
 * @param prepare_gens the write-ahead log generation each undecided prepare's record lives in, one
 *               entry per undecided prepare
 * @param n_prepare_gens how many entries prepare_gens holds
 * @param prepare_vlog_token the value log floor every undecided prepare's separated values sit
 * above, or VLOG_BUILD_TOKEN_NONE when nothing is in doubt. a prepared batch's entries never enter
 * a memtable and no sstable names them until phase two decides it, so without this the segments
 * holding its values read as empty to a reclaim
 * @param prepare_gen_floor the lowest generation that may hold an undecided prepare, UINT64_MAX
 * when none do. a flushed generation at or above it is kept; below it the log is unlinked, since
 * its data is in L1 and it holds nothing still in doubt
 * @param retained_wals_lock guards retained_wals against concurrent flushes and resolutions
 * @param flush_queue the flush pool's work queue; a rotation enqueues one wake signal per sealed
 * immutable
 * @param wal_generation the current active memtable's WAL generation, bumped on every rotation
 * @param spare_wal a log opened ahead of the rotation that will need it, or NULL. opening one costs
 * a file creation, a staging ring and a flush thread, and on a loaded device that is long enough to
 * matter -- paid under rotate_lock it would stop every committer in the database for the whole of
 * it, so it is paid outside the lock instead and the rotation itself becomes a swap
 * @param spare_wal_gen the generation spare_wal was named for. written and read under
 * spare_wal_preparing rather than beside the pointer, because taking the spare empties the slot and
 * lets the next preparer overwrite this field before the taker has read it
 * @param spare_wal_preparing whether a thread is already opening a spare, so a rotation burst
 * prepares one log rather than one per committer. without it every committer that rotated created a
 * file and all but one abandoned it
 * @param rotate_lock serializes rotation so only one thread seals the active memtable at a time
 * @param rotate_lock_inited whether rotate_lock was initialized, so close only destroys an
 * initialized lock
 * @param flush_lock guards only the immutable claim and its flush ticket, a cheap critical section
 * so the costly build runs off it and many immutables build at once
 * @param flush_lock_inited whether flush_lock was initialized, so close only destroys an
 * initialized lock
 * @param install_lock orders the install phase by flush ticket so immutables install oldest-first
 * even though they build concurrently, preserving the invariant that no sstable is newer than what
 * remains in L0
 * @param install_cv paired with install_lock to wake the ticket whose turn to install has come
 * @param install_lock_inited whether install_lock and install_cv were initialized, for a clean
 * close
 * @param flush_claim_seq the next flush ticket handed out when a worker claims an immutable
 * @param flush_install_seq the next ticket allowed to install, advanced under install_lock
 * @param compaction_queue the compaction pool's work queue, carrying planned {cf, plan} jobs
 * @param compaction_scheduler the backstop ticker that snapshots and plans each cf, woken on every
 * flush
 * @param fd_reaper the descriptor-eviction ticker, borrowed from the threadmanager that owns it, so
 * a caller held at the descriptor budget can make it sweep rather than wait out its tick
 * @param next_sstable_id the db-level monotonic sstable id sequence flush and compaction draw from
 * @param gc_floor_high_water the highest reclamation floor any collection has ever taken.
 * everything at or above it has never been eligible for collection, so a read there resolves to
 * exactly what was true; below it a merge has already kept one version per key and dropped the
 * rest, which is what makes an older point in time unanswerable rather than merely stale. raised
 * where a floor is taken rather than where the work finishes, so a job already collecting is
 * accounted for before a reader can conclude its sequence is safe
 * @param commit_hook_count the number of column families with a live commit hook, so the commit
 * path skips the post-commit hook pass entirely when it is zero
 * @param vlog_gc_active set while a value-log reclaim job is queued or running, so at most one runs
 * at a time
 * @param opened set once open fully succeeds, so close persists the clock only for a built engine
 * @param owns_log_sink whether this handle installed the process-wide log sink, so only it closes
 * it
 * @param rotate_lock_wait time committers spent waiting to take the rotation lock, so another
 * thread was rotating
 * @param rotate_work_wait time a committer spent performing a rotation, which it pays on every
 * other committer's behalf
 * @param idle_flush_bytes the active memtable's size at the previous idle-flush tick; an unchanged
 *                   non-zero sample means no write landed in between. only that ticker touches it
 * @param now_seconds the wall clock in seconds, refreshed by a ticker, that a transaction ages
 * against. it is cached rather than read per check so a transaction with no timeout pays nothing
 * and one with a timeout pays a relaxed load
 * @param closing set once close begins so new writes are refused
 */
struct tidesdb_t
{
    tidesdb_config_t config;
    char *db_path;

    cache_t *cache;
    tidesdb_encoding_registry_t encodings;
    fd_manager_t fdm;
    int fdm_inited;
    arena_pool_t *arena;
    arena_pool_t *node_arena;

    tidesdb_manifest_t *manifest;
    vlog_t *vlog;

    tidesdb_mvcc_t *clock;
    cf_registry_t *cfs;
    threadmanager_t *threads;

    tidesdb_l0_t *l0;
    block_manager_t *wal_bm;
    tidesdb_l0_txn_ctx_t l0_ctx;
    int l0_ctx_inited;
    tdb_txn_backend_t backend;
    tidesdb_source_t sources[ENGINE_NUM_SOURCES];
    tidesdb_txn_registry_t *txn_registry;
    tdb_prepare_stage_t *prepared;
    engine_retained_wal_t *retained_wals;
    int n_retained_wals;
    int prepare_vlog_token;
    uint64_t *prepare_gens;
    int n_prepare_gens;
    _Atomic(uint64_t) prepare_gen_floor;
    pthread_mutex_t retained_wals_lock;

    queue_t *flush_queue;
    _Atomic(uint64_t) wal_generation;
    _Atomic(block_manager_t *) spare_wal;
    uint64_t spare_wal_gen;
    _Atomic(int) spare_wal_preparing;
    pthread_mutex_t rotate_lock;
    int rotate_lock_inited;
    pthread_mutex_t flush_lock;
    int flush_lock_inited;
    pthread_mutex_t install_lock;
    pthread_cond_t install_cv;
    int install_lock_inited;
    _Atomic(uint64_t) flush_claim_seq;
    uint64_t flush_install_seq;

    queue_t *compaction_queue;
    bg_ticker_t *compaction_scheduler;
    bg_ticker_t *fd_reaper;

    _Atomic(uint64_t) next_sstable_id;
    _Atomic(uint64_t) gc_floor_high_water;
    _Atomic(int) commit_hook_count;
    _Atomic(int) vlog_gc_active;
    int lock_fd;
    int opened;
    int owns_log_sink;
    size_t idle_flush_bytes;
    tdb_wait_stat_t rotate_lock_wait;
    tdb_wait_stat_t rotate_work_wait;
    _Atomic(int64_t) now_seconds;
    _Atomic(int) closing;
};

/**
 * tidesdb_txn_t
 * the public transaction handle -- the internal transaction plus a back-reference to the engine, so
 * the facade's cf-scoped operations can reach the db-level source stack, commit backend, and mvcc
 * clock
 * @param inner the decoupled transaction core
 * @param db the owning engine, borrowed
 * @param prepare_generation the write-ahead log generation current before this transaction's
 * PREPARE record was appended, the low end of the range its decision releases. read only while the
 * transaction is prepared
 * @param prepare_generation_last the generation current after that append. which log the record
 * actually landed in is not knowable from one read, since a rotation may race the append, so both
 * ends are pinned and the inclusive range is released together -- keeping a log that turns out
 * unnecessary costs disk, where dropping the one holding an undecided batch loses it
 */
struct tidesdb_txn_t
{
    tdb_txn_t *inner;
    tidesdb_t *db;
    uint64_t prepare_generation;
    uint64_t prepare_generation_last;
};

/**
 * tidesdb_snapshot_t
 * a named point in the database's history, and the thing that keeps it readable
 * @param holder a registered transaction that never writes and is never decided. the reclamation
 * floor is the minimum frozen snapshot across the registry, so holding one registered is what stops
 *         compaction collecting the versions this snapshot resolves to -- without it the sequence
 *         would still be readable and would answer from whatever survived, which is worse than
 *         refusing
 * @param seq the sequence reads through this snapshot resolve at
 */
struct tidesdb_snapshot_t
{
    tidesdb_txn_t *holder;
    uint64_t seq;
};

/**
 * tidesdb_iter_t
 * the public range-iterator handle over one column family at a transaction's snapshot -- a per-cf
 * merge iterator plus the cf (for resolving a spilled value through its vlog) and the engine
 * @param inner the per-cf merge iterator over L0 and the cf's sstable levels
 * @param cf the iterated column family, borrowed
 * @param db the owning engine, borrowed
 */
struct tidesdb_iter_t
{
    cf_iter_t *inner;
    cf_t *cf;
    tidesdb_t *db;
};

/**
 * engine_durable_writes
 * whether the engine's own durable writes -- the manifest commits behind a ddl, a config publish
 * and a rebuild's catalogue -- should be fsynced. every sync mode but none asks for it, since
 * interval mode batches only the WAL and never the structures naming the data
 * @param db the database whose configuration decides
 * @return 1 when the write must be made durable, 0 under sync none
 */
static inline int engine_durable_writes(const tidesdb_t *db)
{
    return db->config.memtable_sync_mode != TDB_SYNC_NONE ? 1 : 0;
}

/**
 * engine_sstable_bm_sync
 * the block-manager sync mode the engine opens and writes sstables with, so a reload, a compaction
 * and the recovery path all reach the device on the same terms
 * @param db the database whose configuration decides
 * @return BLOCK_MANAGER_SYNC_NONE under sync none, BLOCK_MANAGER_SYNC_FULL otherwise
 */
static inline int engine_sstable_bm_sync(const tidesdb_t *db)
{
    return db->config.memtable_sync_mode == TDB_SYNC_NONE ? BLOCK_MANAGER_SYNC_NONE
                                                          : BLOCK_MANAGER_SYNC_FULL;
}

#endif /* __TIDESDB_ENGINE_TYPES_H__ */
