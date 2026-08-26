/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_L0_ADAPTER_H__
#define __TIDESDB_TXN_L0_ADAPTER_H__

#include "memtable/memtable.h"
#include "prepare_stage.h"
#include "sstable/vlog.h" /* vlog_t, for resolving a separated value on the read path */
#include "txn.h"

/* the l0 adapter is the concrete binding between the transaction core and the shared L0 subsystem.
 * it turns an l0 into the read source the txn snapshot reads consult and the commit backend the txn
 * durably writes through, so neither the txn core nor this adapter takes an engine. the composition
 * root builds one ctx and hands the source and backend to the txn manager; a test builds the same
 * over a stack l0. commit WAL appends coalesce in the WAL's own append ring, so concurrent commits
 * neither serialize nor do each other's writes. keys are byte-ordered throughout. */

/**
 * tidesdb_l0_txn_ctx_t
 * the context both the source and the backend share; the caller owns it, initializes it with
 * tidesdb_l0_adapter_init and keeps it alive while the source or backend is in use. it borrows
 * everything it holds, so there is nothing to release
 * @param l0 the shared L0 subsystem to read and commit through
 * @param vlog the shared value log, for resolving a memtable entry whose value was separated at
 * commit; may be NULL only where the caller has established L0 holds no references
 */
typedef struct
{
    tidesdb_l0_t *l0;
    vlog_t *vlog;
} tidesdb_l0_txn_ctx_t;

/**
 * tidesdb_l0_adapter_init
 * initialize an adapter context over an L0
 * @param ctx the context to initialize
 * @param l0 the shared L0 subsystem, borrowed
 * @param vlog the shared value log, borrowed, for resolving separated values; may be NULL only
 * where the caller has established L0 holds no references
 * @return 0 on success, -1 on a bad argument
 */
int tidesdb_l0_adapter_init(tidesdb_l0_txn_ctx_t *ctx, tidesdb_l0_t *l0, vlog_t *vlog);

/**
 * tidesdb_l0_source
 * fill a read source that resolves a key against L0 at the reader's snapshot -- the newest version
 * at or below the snapshot across the active memtable and the immutables
 * @param ctx the shared adapter context, borrowed by the source
 * @param out the source to fill
 */
void tidesdb_l0_source(tidesdb_l0_txn_ctx_t *ctx, tidesdb_source_t *out);

/**
 * tidesdb_l0_backend
 * fill a commit backend that durably appends each commit's WAL batch and then applies its entries
 * to L0 at the commit sequence. the backpressure hook is left unset until the flush path can pace
 * writers on the unflushed backlog
 * @param ctx the shared adapter context, borrowed by the backend
 * @param out the backend to fill
 */
void tidesdb_l0_backend(tidesdb_l0_txn_ctx_t *ctx, tdb_txn_backend_t *out);

/**
 * tidesdb_l0_apply_entries
 * make a decoded WAL batch visible in the active memtable at each entry's own commit sequence,
 * without touching the WAL. this is the apply half of a commit, shared by the live commit backend
 * and by recovery settling a prepared batch the log went on to commit
 * @param l0 the shared L0 subsystem
 * @param entries the decoded entries to apply
 * @param count number of entries, 0 applying nothing
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY if the active slot could not be pinned,
 *         or a memory error
 */
int tidesdb_l0_apply_entries(tidesdb_l0_t *l0, const tidesdb_wal_entry_t *entries, int count);

/**
 * tidesdb_l0_aborted_set_t
 * the commit sequences an abort record named, gathered before any generation is applied
 * an abort can land in a later generation than the batch it cancels, since the failing commit
 * appends it to whatever log is active by then, so the set has to be complete before replay starts
 * applying anything
 * @field seqs the aborted sequences, unordered
 * @field count how many are held
 * @field capacity allocated length of seqs
 */
typedef struct
{
    uint64_t *seqs;
    int count;
    int capacity;
} tidesdb_l0_aborted_set_t;

/**
 * tidesdb_l0_scan_aborts
 * collect every aborted commit sequence a log names, without applying anything
 * @param wal the log to scan
 * @param out the set to add to, carried across every generation
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int tidesdb_l0_scan_aborts(block_manager_t *wal, tidesdb_l0_aborted_set_t *out);

/**
 * tidesdb_l0_aborted_set_free
 * release a set's storage
 * @param set the set, may be NULL
 */
void tidesdb_l0_aborted_set_free(tidesdb_l0_aborted_set_t *set);

/**
 * tidesdb_replay_superseded_fn
 * answer whether the sstables already hold a version of this key newer than seq. consulted during
 * replay so an entry a durable later write has already retired is not put back into a memtable,
 * where every reader would take it as newer than anything on disk. it must read the sstables alone
 * -- asking the ordinary read stack would consult the half-replayed memtables and answer in circles
 * @param ctx the caller's context
 * @param cf_index the column family the entry belongs to
 * @param key the entry's key
 * @param key_size length of key
 * @param seq the entry's own sequence
 * @return non-zero only when a strictly newer version of this key is durable in an sstable; any
 * doubt answers zero, since applying an entry that was already superseded is harmless and dropping
 * one that was not is data loss
 */
typedef int (*tidesdb_replay_superseded_fn)(void *ctx, uint32_t cf_index, const uint8_t *key,
                                            size_t key_size, uint64_t seq);

/**
 * tidesdb_replay_filter_t
 * what replay needs to leave out an entry a durable later write has already retired
 * @param superseded the probe above, or NULL to apply every entry the log holds
 * @param ctx passed to superseded
 * @param durable_seq the highest sequence any sstable holds. an entry above it cannot be on disk,
 * so it skips the probe entirely -- which is every entry of an ordinary recovery, where the only
 * surviving log is the one the active memtable was never flushed from
 */
typedef struct
{
    tidesdb_replay_superseded_fn superseded;
    void *ctx;
    uint64_t durable_seq;
} tidesdb_replay_filter_t;

/**
 * tidesdb_l0_replay_wal
 * replay a persisted WAL into L0 on open, applying every single-phase commit batch it holds to the
 * active memtable at the entries' own commit sequences, in file order. two-phase records are folded
 * into the staging map instead of applied, since only the whole log decides them. the caller has
 * made the target memtable active first
 * @param l0 the shared L0 subsystem, its active memtable receiving the replayed writes
 * @param wal the open WAL block manager to read from
 * @param generation the generation this log is, recorded against any prepare it stages so the
 *                   engine can keep exactly this log while that batch stays in doubt
 * @param aborted sequences an abort record names, gathered from this log by a prior scan, or NULL
 *                to apply every batch. a batch whose sequence is in the set reached the log but
 *                failed to apply, so replaying it would resurrect a transaction its caller was
 *                told had failed
 * @param out_max_seq out -- the highest commit sequence replayed, 0 when nothing replayed, or NULL
 * to ignore. the engine reseeds the mvcc clock past it so a crash cannot reissue a seq
 * @param stage the cross-generation two-phase staging map, carried across every generation the
 *              caller replays, or NULL to discard two-phase records
 * @param filter leaves out an entry the sstables have already superseded, or NULL to apply every
 *               entry the log holds
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a read failure, TDB_ERR_CORRUPTION on a
 *         malformed record, or TDB_ERR_BUSY/TDB_ERR_MEMORY from the apply
 */
int tidesdb_l0_replay_wal(tidesdb_l0_t *l0, block_manager_t *wal, uint64_t generation,
                          const tidesdb_l0_aborted_set_t *aborted, uint64_t *out_max_seq,
                          tdb_prepare_stage_t *stage, const tidesdb_replay_filter_t *filter);

#endif /* __TIDESDB_TXN_L0_ADAPTER_H__ */
