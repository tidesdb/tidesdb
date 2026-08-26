/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/errors.h"
#include "column_family/level/level_set.h"
#include "compat.h" /* usleep */
#include "engine_internal.h"
#include "io/block_manager.h"
#include "manifest/manifest.h"
#include "memtable/memtable.h"
#include "sstable/sstable.h"
#include "txn/mvcc.h"

/* how long a synchronous flush waits for the immutable queue to drain, and how often it looks; the
 * bound caps the wait so a stuck flush pool surfaces as busy rather than hanging the caller */
#define ENGINE_FLUSH_WAIT_TIMEOUT_US (60ull * 1000 * 1000)
#define ENGINE_FLUSH_WAIT_POLL_US    1000

int engine_is_flushing(tidesdb_t *db)
{
    if (!db) return 0;
    return tidesdb_l0_queue_depth(db->l0) > 0 ? 1 : 0;
}

int engine_sync_wal(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* pinned rather than locked: the rotation lock is on the commit path, and holding it across a
     * device barrier stalls every committer for the length of the fsync */
    return tidesdb_l0_sync_active_wal(db->l0);
}

int engine_flush_memtable(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    const int rc = engine_force_rotate(db);
    if (rc != TDB_SUCCESS) return rc;

    /* wait for the immutable queue to drain, not merely for the generation this call sealed.
     *
     * waiting on the sealed generation alone is wrong for the callers that matter here. backup and
     * clone copy files, so everything they should capture has to be in a file before they start --
     * and a rotation seals nothing at all when the active memtable is empty, which is ordinary.
     * this call would then return at once while generations from earlier rotations were still
     * queued and still only in memory, and the copy would quietly miss their data.
     *
     * the cost is that a database under sustained writes may never show an empty queue, so this can
     * report contention when the caller's own data has in fact landed. that is the safe direction
     * to be wrong in, and it is the behaviour every caller here was written against */
    for (uint64_t tick = 0; tick < ENGINE_FLUSH_WAIT_TIMEOUT_US / ENGINE_FLUSH_WAIT_POLL_US; tick++)
    {
        if (tidesdb_l0_queue_depth(db->l0) == 0) return TDB_SUCCESS;
        usleep(ENGINE_FLUSH_WAIT_POLL_US);
    }
    return tidesdb_l0_queue_depth(db->l0) == 0 ? TDB_SUCCESS : TDB_ERR_LOCKED;
}

/* fsync every resident klog across all families, so a checkpoint lands the just-flushed L1 data
 * even under sync none where the flush itself skips the barrier; returns the first io or allocation
 * error */
static int engine_sync_all_klogs(tidesdb_t *db)
{
    /* the registry lock is held only long enough to reference the files, not across the barriers.
     * this sweep costs one device barrier per sstable in the database, and the write lock it would
     * otherwise block belongs to the level-set swap inside rename and clone -- so holding it across
     * the whole sweep stalls those for as long as a full-database fsync takes. a held reference is
     * what keeps each file open and untruncated meanwhile, since an sstable closes only when its
     * last reference drops */
    cf_registry_rdlock(db->cfs);
    sstable_t **all = NULL;
    const int n = engine_collect_sstables(db, &all);
    cf_registry_rdunlock(db->cfs);

    if (n < 0) return TDB_ERR_MEMORY;

    int rc = TDB_SUCCESS;
    for (int i = 0; i < n; i++)
        if (all[i] && sstable_sync_klog(all[i]) != TDB_SUCCESS) rc = TDB_ERR_IO;
    for (int i = 0; i < n; i++)
        if (all[i] && sstable_unref(all[i])) sstable_close(all[i]);
    free(all);
    return rc;
}

int engine_checkpoint(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    int rc = engine_flush_memtable(db); /* land the memtable in L1 sstables */
    if (rc != TDB_SUCCESS) return rc;

    rc = engine_sync_all_klogs(db);
    if (rc != TDB_SUCCESS) return rc;

    /* force the log, the value log and the manifest to disk regardless of the configured sync mode,
     * so the checkpoint is a real recovery point. the log is pinned rather than locked, so a
     * checkpoint does not stall every committer for the length of its barrier */
    if (tidesdb_l0_sync_active_wal(db->l0) != TDB_SUCCESS) return TDB_ERR_IO;

    if (db->vlog && vlog_sync(db->vlog) != VLOG_OK) return TDB_ERR_IO;

    /* record the clock high-water alongside the flushed data, so a crash right after the checkpoint
     * recovers a sequence past every committed key rather than below it */
    tidesdb_manifest_update_sequence(db->manifest, tidesdb_mvcc_current_seq(db->clock));
    if (tidesdb_manifest_commit(db->manifest, db->manifest->path, 1) != 0) return TDB_ERR_IO;
    return TDB_SUCCESS;
}
