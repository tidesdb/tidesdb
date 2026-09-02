/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"
#include "base/log.h"
#include "compat.h" /* remove */
#include "engine.h"

/* two-phase commit recovery -- the write-ahead log a batch still in doubt is durable in is held
 * back from reaping until its coordinator decides it. a decided batch needs nothing here, because
 * phase two writes its write set into the COMMIT record and replay applies that inline. */

/* whether any undecided prepare's record lives in this generation; the caller holds
 * retained_wals_lock. the set holds one entry per undecided prepare, so it is as long as the
 * coordinator's in-flight window and a scan of it costs nothing at flush frequency */
static int engine_generation_pinned_locked(const tidesdb_t *db, const uint64_t generation)
{
    for (int i = 0; i < db->n_prepare_gens; i++)
        if (db->prepare_gens[i] == generation) return 1;
    return 0;
}

/* unlink every retained log no undecided prepare lives in any more; caller holds the lock */
static void engine_sweep_unpinned_locked(tidesdb_t *db)
{
    int kept = 0;
    for (int i = 0; i < db->n_retained_wals; i++)
    {
        if (engine_generation_pinned_locked(db, db->retained_wals[i].generation))
        {
            db->retained_wals[kept++] = db->retained_wals[i];
            continue;
        }
        (void)remove(db->retained_wals[i].path);
        free(db->retained_wals[i].path);
    }
    db->n_retained_wals = kept;
}

int engine_wal_generation_pinned(void *ctx, const uint64_t generation)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (!db) return 0;

    pthread_mutex_lock(&db->retained_wals_lock);
    const int pinned = engine_generation_pinned_locked(db, generation);
    pthread_mutex_unlock(&db->retained_wals_lock);
    return pinned;
}

/* hold a value log floor over the segments every undecided prepare's values live in; the caller
 * holds retained_wals_lock.
 *
 * a prepared batch is the one holder of separated values that nothing else accounts for. its
 * entries never enter a memtable -- that is what a prepare is -- and no sstable names them until
 * phase two decides it, so the segments holding them read as empty to a reclaim and are dropped
 * while the batch still needs them. the write-ahead log generation is pinned for the same reason,
 * and this is the value log's half of it.
 *
 * the floor is taken at the segment active now, which is at or above where the values already
 * landed, so it is then lowered onto each of them. the whole stage is walked rather than one
 * record, since a reopen re-stages every in-doubt prepare at once */
static void engine_lower_prepared_floor_locked(tidesdb_t *db, const tidesdb_wal_entry_t *entries,
                                               const int count)
{
    for (int e = 0; e < count; e++)
    {
        if (!(entries[e].flags & TDB_WAL_ENTRY_VLOG_REF)) continue;
        uint64_t segment = 0;
        if (vlog_id_segment(db->vlog, entries[e].vlog_id, &segment) == VLOG_OK)
            vlog_build_lower(db->vlog, db->prepare_vlog_token, segment);
    }
}

static void engine_hold_prepared_vlog_floor_locked(tidesdb_t *db, const tidesdb_wal_entry_t *live,
                                                   const int live_count)
{
    if (!db->vlog) return;

    if (db->prepare_vlog_token == VLOG_BUILD_TOKEN_NONE)
        db->prepare_vlog_token = vlog_build_enter(db->vlog);

    /* a live prepare keeps its batch inside the transaction; only a replay fills the staging map,
     * so both have to be reached or a prepare made in this process protects nothing */
    if (live) engine_lower_prepared_floor_locked(db, live, live_count);
    if (!db->prepared) return;

    const int n = tdb_prepare_stage_count(db->prepared);
    for (int i = 0; i < n; i++)
    {
        const tdb_prepared_record_t *rec = tdb_prepare_stage_at(db->prepared, i);
        if (!rec) continue;
        engine_lower_prepared_floor_locked(db, rec->entries, rec->count);
    }
}

/* give the floor back once nothing is in doubt; the caller holds retained_wals_lock */
static void engine_release_prepared_vlog_floor_locked(tidesdb_t *db)
{
    if (db->n_prepare_gens > 0 || db->prepare_vlog_token == VLOG_BUILD_TOKEN_NONE) return;
    if (db->vlog) vlog_build_leave(db->vlog, db->prepare_vlog_token);
    db->prepare_vlog_token = VLOG_BUILD_TOKEN_NONE;
}

int engine_note_prepare_generation(tidesdb_t *db, const uint64_t first, const uint64_t last,
                                   const tidesdb_wal_entry_t *live, const int live_count)
{
    if (!db || last < first) return TDB_ERR_INVALID_ARGS;

    const int span = (int)(last - first) + 1;
    pthread_mutex_lock(&db->retained_wals_lock);
    uint64_t *grown =
        realloc(db->prepare_gens, (size_t)(db->n_prepare_gens + span) * sizeof(*grown));
    int rc = TDB_ERR_MEMORY;
    if (grown)
    {
        db->prepare_gens = grown;
        for (uint64_t g = first; g <= last; g++) db->prepare_gens[db->n_prepare_gens++] = g;
        rc = TDB_SUCCESS;
    }
    if (rc == TDB_SUCCESS) engine_hold_prepared_vlog_floor_locked(db, live, live_count);
    pthread_mutex_unlock(&db->retained_wals_lock);
    return rc;
}

void engine_release_prepare_generation(tidesdb_t *db, const uint64_t first, const uint64_t last)
{
    if (!db || last < first) return;

    pthread_mutex_lock(&db->retained_wals_lock);
    for (uint64_t g = first; g <= last; g++)
        for (int i = 0; i < db->n_prepare_gens; i++)
            if (db->prepare_gens[i] == g)
            {
                db->prepare_gens[i] = db->prepare_gens[--db->n_prepare_gens];
                break;
            }

    /* the decision is durable in its own generation -- a COMMIT record carries the write set and a
     * ROLLBACK leaves nothing to undo -- so a log no longer holding an undecided prepare is free */
    engine_sweep_unpinned_locked(db);
    engine_release_prepared_vlog_floor_locked(db);
    pthread_mutex_unlock(&db->retained_wals_lock);
}

void engine_note_retained_wal(void *ctx, const char *path, const uint64_t generation)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (!db || !path) return;

    pthread_mutex_lock(&db->retained_wals_lock);
    int retained = 0;
    engine_retained_wal_t *grown =
        realloc(db->retained_wals, (size_t)(db->n_retained_wals + 1) * sizeof(*grown));
    if (grown)
    {
        db->retained_wals = grown;
        db->retained_wals[db->n_retained_wals].path = strdup(path);
        db->retained_wals[db->n_retained_wals].generation = generation;
        if (db->retained_wals[db->n_retained_wals].path)
        {
            db->n_retained_wals++;
            retained = 1;
        }
    }
    pthread_mutex_unlock(&db->retained_wals_lock);

    /* the hook cannot refuse, so a failure here leaves the log of a batch still in doubt eligible
     * for reaping and its decision unrecoverable. say so rather than lose it quietly */
    if (!retained)
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "could not retain wal %s holding an in-doubt batch", path);
}

void engine_sweep_retained_wals(tidesdb_t *db)
{
    if (!db) return;

    pthread_mutex_lock(&db->retained_wals_lock);
    /* re-checked under the lock, since a prepare taken while the sweep was waiting can pin a
     * generation again */
    engine_sweep_unpinned_locked(db);
    pthread_mutex_unlock(&db->retained_wals_lock);
}

/* count what the log left undecided and pin their generations. a batch the log went on to commit
 * needs nothing here -- its COMMIT record carries the write set and replay already applied it in
 * sequence order -- and a rolled back one applied nothing and needs no undo. only a batch still in
 * doubt has a coordinator to wait for, and its PREPARE record is the only copy of it, so its
 * generation stays alive until that coordinator answers */
int engine_note_prepared_in_doubt(tidesdb_t *db)
{
    const int n = tdb_prepare_stage_count(db->prepared);
    int in_doubt = 0;
    for (int i = 0; i < n; i++)
    {
        const tdb_prepared_record_t *rec = tdb_prepare_stage_at(db->prepared, i);
        if (!rec || rec->resolution != TDB_PREPARE_IN_DOUBT) continue;
        in_doubt++;

        /* pinned here rather than where a caller adopts the transaction, because a database that
         * never asks for its in-doubt list still must not unlink the log holding the only copy of
         * one. the pin is released when the batch is finally decided */
        (void)engine_note_prepare_generation(db, rec->generation, rec->generation, NULL, 0);
    }
    if (in_doubt > 0)
        TDB_DEBUG_LOG(TDB_LOG_TRACE, "recovered %d prepared transactions still in doubt", in_doubt);
    return TDB_SUCCESS;
}
