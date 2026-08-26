/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_ENGINE_INTERNAL_H__
#define __TIDESDB_ENGINE_INTERNAL_H__

#include "engine.h"
#include "txn/prepare_stage.h"

/* the engine's own cross-file surface, separate from engine.h so the module's API header keeps
 * describing what the layers above the engine call and nothing else. included only by the engine's
 * own translation units. */

/* buffer for a path built from db_path plus one component name */
#define ENGINE_PATH_BUF_SIZE 512

/* a fresh database's first ids; recovery advances these past the persisted maximums */
#define ENGINE_FIRST_CF_ID      0
#define ENGINE_FIRST_SSTABLE_ID 1

/* the active memtable's WAL starts at generation zero; rotation mints higher generations. buffer
 * for a NNNNNNN.log name */
#define ENGINE_FIRST_WAL_GENERATION 0
#define ENGINE_WAL_NAME_MAX         32

/* initial capacity of the recovered WAL generation list */
#define ENGINE_WAL_GEN_LIST_INIT 8

/**
 * engine_build_path
 * join a directory and a component name with the platform separator
 * @param dir the directory the name sits under
 * @param name the component to append
 * @param out the buffer receiving the NUL-terminated path
 * @param out_size the buffer capacity
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS when the result would not fit
 */
int engine_build_path(const char *dir, const char *name, char *out, size_t out_size);

/**
 * engine_durable_sync_mode
 * the block-manager sync mode for the durable base -- the value log, the flush and compaction
 * sstables, and the manifest. both full and interval keep the base fsynced, since interval only
 * batches the WAL, so a crash under interval risks at most the last interval of WAL commits
 * @param sync_mode the database's configured sync mode
 * @return the block-manager sync mode the durable base opens with
 */
int engine_durable_sync_mode(int sync_mode);

/**
 * engine_open_wal
 * open a WAL for a memtable generation in buffered append mode
 * @param db the database, for the sync mode, the ring sizing and the descriptor accounting
 * @param wal_path the file to open
 * @param out_bm receives the opened block manager
 * @return 0 on success, non-zero on failure
 */
int engine_open_wal(tidesdb_t *db, const char *wal_path, block_manager_t **out_bm);

/**
 * engine_open_wal_sealed
 * open a recovered generation's WAL for replay only, without the buffered-append machinery
 * nothing appends to a sealed generation, so its staging ring and flush thread would never be used
 * @param db the database, for the sync mode and the descriptor accounting
 * @param wal_path the file to open
 * @param out_bm receives the opened block manager
 * @return 0 on success, non-zero on failure
 */
int engine_open_wal_sealed(tidesdb_t *db, const char *wal_path, block_manager_t **out_bm);

/**
 * engine_close_wal
 * close a log opened by engine_open_wal and release its descriptor accounting
 * every close of an engine-opened log goes through here, so the labelled count stays balanced
 * @param db the database, for the descriptor accounting
 * @param wal the log to close, ignored when null
 */
void engine_close_wal(tidesdb_t *db, block_manager_t *wal);

/**
 * engine_unlink_wal
 * close a log and take its file with it, for one that will never be written to. an unused log left
 * on disk is not inert -- the next open scans it, replays it and gives it a memtable in the L0
 * queue, so it costs work on every open thereafter for records it never held
 * @param db the database, for the descriptor accounting
 * @param wal the log to close and unlink, ignored when null
 */
void engine_unlink_wal(tidesdb_t *db, block_manager_t *wal);

/**
 * engine_flush_worker
 * the flush pool worker: each wake signal claims the oldest immutable and takes a flush ticket
 * under the claim lock, then builds off the lock so many immutables build at once; the install runs
 * in ticket order so no sstable lands newer than what remains in L0. claiming leaves the immutable
 * in the queue and reader-visible until the install retires it, so no read misses its data
 * mid-flush
 * @param item the queued wake signal, unused -- the immutable comes from the shared L0 queue
 * @param ctx the database
 */
void engine_flush_worker(void *item, void *ctx);

/**
 * engine_drain_immutables
 * drain every queued immutable at close. the flush pool is already stopped, so no worker races this
 * @param db the database
 * @param do_flush nonzero to flush each immutable to L1, as a cleanly opened database wants; zero
 *                 to only reclaim them, for a failed open where their data stays durable in their
 *                 still-present WALs
 */
void engine_drain_immutables(tidesdb_t *db, int do_flush);

/**
 * engine_collect_sstables
 * reference every sstable across every column family into a freshly allocated array. the caller
 * holds the registry read lock across this call, and may release it once this returns -- an
 * sstable's file is closed and truncated only when its last reference drops, so a held reference
 * keeps it readable through a concurrent level-set reload
 * @param db the database
 * @param out receives the allocated array, NULL when the count is zero
 * @return the number of referenced sstables, 0 when there are none, or -1 on allocation failure
 */
int engine_collect_sstables(tidesdb_t *db, sstable_t ***out);

/**
 * engine_sweep_orphan_sstables
 * remove key logs in the database directory that the manifest does not name, and any leaf
 * staging file left beside them. a crash between an sstable finishing and the manifest commit that
 * names it, and any run predating the compaction unlink, leave files nothing will ever read but the
 * filesystem still charges for. call at open, before any worker can create a file the manifest does
 * not yet name; skipped entirely when the manifest was self-healed, since a rebuild takes the
 * sstables as its source
 * @param db the engine, with its families already recovered
 * @return TDB_SUCCESS; a file that cannot be unlinked is logged and left
 */
int engine_sweep_orphan_sstables(tidesdb_t *db);

/**
 * engine_recover_cfs
 * rebuild the column family registry from the manifest and seed the id sequences past every
 * recovered family; a fresh database recovers an empty registry
 * @param db the database, with its manifest open
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_CORRUPTION on an undecodable family config
 */
int engine_recover_cfs(tidesdb_t *db);

/**
 * engine_replay_superseded
 * whether an sstable already holds a version of this key newer than seq; the probe the WAL replay
 * filter calls, matching tidesdb_replay_superseded_fn
 * @param ctx the database handle
 * @param cf_index the column family the entry belongs to
 * @param key the entry's key
 * @param key_size length of key
 * @param seq the entry's own sequence
 * @return non-zero only on a definite newer durable version
 */
int engine_replay_superseded(void *ctx, uint32_t cf_index, const uint8_t *key, size_t key_size,
                             uint64_t seq);

/**
 * engine_recovered_max_sstable_seq
 * the highest sequence any recovered sstable holds, so the clock reseeds past data whose WAL a
 * flush already unlinked
 * @param db the database, with its column families recovered
 * @return the highest recovered sequence, or 0 when nothing was recovered
 */
uint64_t engine_recovered_max_sstable_seq(tidesdb_t *db);

/**
 * engine_recover_wal
 * replay every surviving WAL generation into L0 as an immutable and install a fresh active memtable
 * above them, staging any transaction left in doubt
 * @param db the database, with L0 created
 * @param out_recovered receives the number of generations recovered and awaiting flush
 * @param out_max_seq receives the highest sequence replay applied
 * @param stage the staging map two-phase records fold into
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO on a WAL open or replay failure
 */
int engine_recover_wal(tidesdb_t *db, int *out_recovered, uint64_t *out_max_seq,
                       tdb_prepare_stage_t *stage);

#endif /* __TIDESDB_ENGINE_INTERNAL_H__ */
