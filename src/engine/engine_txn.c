/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* the transaction facade -- thin engine-side wrappers that bind the txn core to this db's clock,
 * read-source stack, and commit backend, plus the per-commit stats accounting and commit-hook
 * dispatch. every entry point here is public engine api declared in engine.h and called from the
 * db.c facade */
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"
#include "base/log.h"
#include "engine.h"
#include "txn/wal_record.h"
#include "txn/writeset.h"

int engine_txn_begin(tidesdb_t *db, tidesdb_isolation_level_t isolation, tidesdb_txn_t **out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return TDB_ERR_INVALID_DB;

    tidesdb_txn_t *h = malloc(sizeof(*h));
    if (!h) return TDB_ERR_MEMORY;
    h->db = db;
    /* the configured timeout applies to every transaction; a caller bounds a single one through
     * tidesdb_txn_set_timeout. the registry is joined only at repeatable-read and stronger */
    h->inner = tdb_txn_begin(db->clock, isolation, &db->now_seconds, db->config.txn_timeout_seconds,
                             db->txn_registry);
    if (!h->inner)
    {
        free(h);
        return TDB_ERR_MEMORY;
    }
    *out = h;
    return TDB_SUCCESS;
}

int engine_txn_put(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                   const uint8_t *value, size_t value_size, int64_t ttl)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    /* the family id is the key prefix, narrowed to the width the prefix is. engine_create_cf will
     * not hand out an id past TDB_CF_INDEX_MAX, which is what makes this lossless */
    return tdb_txn_put(txn->inner, (uint32_t)cf->cf_id, key, key_size, value, value_size, ttl);
}

int engine_txn_delete(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_delete(txn->inner, (uint32_t)cf->cf_id, key, key_size);
}

int engine_txn_delete_range(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *lo, size_t lo_size,
                            const uint8_t *hi, size_t hi_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_delete_range(txn->inner, (uint32_t)cf->cf_id, lo, lo_size, hi, hi_size);
}

int engine_txn_delete_prefix(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *prefix,
                             size_t prefix_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_delete_prefix(txn->inner, (uint32_t)cf->cf_id, prefix, prefix_size);
}

int engine_txn_get(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                   uint8_t **value, size_t *value_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_get(txn->inner, (uint32_t)cf->cf_id, key, key_size, txn->db->sources,
                       ENGINE_NUM_SOURCES, value, value_size);
}

/* attribute a committed write set's logical and wal bytes to the families it touched, for stats. an
 * op's wal cost is its marginal contribution to the encoded batch, so the shared per-commit header
 * is left unattributed. a one-slot cache collapses the usual single-family commit to one registry
 * lookup */
static void engine_account_commit(tidesdb_t *db, tdb_txn_t *inner)
{
    tidesdb_writeset_t *ws = tdb_txn_writeset(inner);
    const int n = tidesdb_writeset_count(ws);
    if (n <= 0) return;

    const size_t header_bytes = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, NULL, 0);
    uint32_t cached_index = 0;
    cf_t *cached_cf = NULL;
    int have_cache = 0;

    for (int i = 0; i < n; i++)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(ws, i, &op)) continue;

        cf_t *cf;
        if (have_cache && op.cf_index == cached_index)
            cf = cached_cf;
        else
        {
            cf = cf_registry_get_by_id(db->cfs, op.cf_index);
            cached_index = op.cf_index;
            cached_cf = cf;
            have_cache = 1;
        }
        if (!cf) continue;

        tidesdb_wal_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.cf_index = op.cf_index;
        entry.ttl = op.ttl;
        entry.flags = op.flags;
        if (op.ttl != -1) entry.flags |= TDB_WAL_ENTRY_HAS_TTL;
        entry.key = op.key;
        entry.key_size = op.key_size;
        entry.value = op.value;
        entry.value_size = op.value_size;
        const size_t entry_bytes =
            tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &entry, 1) - header_bytes;

        atomic_fetch_add_explicit(&cf->user_bytes_written, (uint64_t)(op.key_size + op.value_size),
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&cf->wal_bytes_written, (uint64_t)entry_bytes,
                                  memory_order_relaxed);
    }
}

/* fire each touched family's commit hook once with its own ops, after the commit is durable and
 * visible. a hook failure is logged, never rolled back. the outer gate skips this entirely when no
 * cf has a hook, so an unhooked db pays nothing */
static void engine_invoke_commit_hooks(tidesdb_t *db, tdb_txn_t *inner, uint64_t commit_seq)
{
    tidesdb_writeset_t *ws = tdb_txn_writeset(inner);
    const int n = tidesdb_writeset_count(ws);
    if (n <= 0) return;

    for (int i = 0; i < n; i++)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(ws, i, &op)) continue;

        /* process each cf once, at the first op that names it */
        int seen_earlier = 0;
        for (int k = 0; k < i && !seen_earlier; k++)
        {
            tidesdb_writeset_op_t prev;
            if (tidesdb_writeset_op_at(ws, k, &prev) && prev.cf_index == op.cf_index)
                seen_earlier = 1;
        }
        if (seen_earlier) continue;

        cf_t *cf = cf_registry_get_by_id(db->cfs, op.cf_index);
        if (!cf) continue;
        const tidesdb_commit_hook_fn fn =
            atomic_load_explicit(&cf->commit_hook_fn, memory_order_acquire);
        if (!fn) continue;
        void *ctx = atomic_load_explicit(&cf->commit_hook_ctx, memory_order_acquire);

        tidesdb_commit_op_t *ops = malloc((size_t)n * sizeof(*ops));
        if (!ops) return;
        int m = 0;
        for (int j = i; j < n; j++)
        {
            tidesdb_writeset_op_t o;
            if (!tidesdb_writeset_op_at(ws, j, &o) || o.cf_index != op.cf_index) continue;
            ops[m].key = o.key;
            ops[m].key_size = o.key_size;
            ops[m].value = o.value;
            ops[m].value_size = o.value_size;
            ops[m].ttl = (time_t)o.ttl;
            ops[m].is_delete = (o.flags & TDB_WAL_ENTRY_TOMBSTONE) != 0;
            m++;
        }
        if (m > 0 && fn(ops, m, commit_seq, ctx) != 0)
            TDB_DEBUG_LOG(TDB_LOG_WARN, "commit hook for cf %s returned nonzero", cf->name);
        free(ops);
    }
}

int engine_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    tidesdb_t *db = txn->db;
    const int rc = tdb_txn_commit(txn->inner, &db->backend, db->sources, ENGINE_NUM_SOURCES);
    if (rc == TDB_SUCCESS)
    {
        engine_account_commit(db, txn->inner);
        if (atomic_load_explicit(&db->commit_hook_count, memory_order_acquire) > 0)
            engine_invoke_commit_hooks(db, txn->inner, tdb_txn_commit_seq(txn->inner));
        /* a successful commit may have filled the active memtable; rotate and hand it to the flush
         * pool */
        engine_maybe_rotate(db);
    }
    return rc;
}

int engine_txn_prepare(tidesdb_txn_t *txn, const uint8_t *xid, size_t xid_size)
{
    if (!txn || !xid || xid_size == 0) return TDB_ERR_INVALID_ARGS;
    tidesdb_t *db = txn->db;

    /* the record's generation is not knowable from here with one read: a rotation may land it in a
     * later log than the one current before the append. so both ends are taken and both pinned --
     * they are the same generation unless a rotation raced, and keeping one log that turns out
     * unnecessary costs disk where dropping the one holding an undecided batch loses it */
    const uint64_t first = atomic_load_explicit(&db->wal_generation, memory_order_acquire);

    const int rc =
        tdb_txn_prepare(txn->inner, &db->backend, db->sources, ENGINE_NUM_SOURCES, xid, xid_size);
    const uint64_t last = atomic_load_explicit(&db->wal_generation, memory_order_acquire);
    /* only a write transaction leaves anything durable to protect; a read-only prepare finishes
     * outright and needs no phase two, so it must not pin the log */
    if (rc == TDB_SUCCESS && tdb_txn_state(txn->inner) == TDB_TXN_PREPARED)
    {
        txn->prepare_generation = first;
        txn->prepare_generation_last = last;
        int live_count = 0;
        const tidesdb_wal_entry_t *live = tdb_txn_prepared_entries(txn->inner, &live_count);
        (void)engine_note_prepare_generation(db, first, last, live, live_count);
    }
    return rc;
}

/* release one prepared transaction's hold on its write-ahead log generation once phase two has
 * decided it. the decision is self-contained -- a COMMIT record carries the write set and replay
 * applies it inline, a ROLLBACK leaves nothing to undo -- so the prepared generation is free the
 * moment the decision is durable, and its log goes with the release */
static void engine_prepared_resolved(tidesdb_t *db, const uint64_t first, const uint64_t last)
{
    engine_release_prepare_generation(db, first, last);
}

int engine_txn_commit_prepared(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    tidesdb_t *db = txn->db;
    const int rc = tdb_txn_commit_prepared(txn->inner, &db->backend);
    if (rc == TDB_SUCCESS)
    {
        engine_prepared_resolved(db, txn->prepare_generation, txn->prepare_generation_last);
        /* the prepared batch is now applied and visible, so it accounts and fires hooks exactly
         * like a single-phase commit */
        engine_account_commit(db, txn->inner);
        if (atomic_load_explicit(&db->commit_hook_count, memory_order_acquire) > 0)
            engine_invoke_commit_hooks(db, txn->inner, tdb_txn_commit_seq(txn->inner));
        engine_maybe_rotate(db);
    }
    return rc;
}

int engine_recover_prepared(tidesdb_t *db, tidesdb_prepared_txn_t *out, const int max,
                            int *out_count)
{
    if (!db || !out_count || max < 0 || (max > 0 && !out)) return TDB_ERR_INVALID_ARGS;

    const int staged = tdb_prepare_stage_count(db->prepared);
    int in_doubt = 0;
    for (int i = 0; i < staged; i++)
    {
        const tdb_prepared_record_t *rec = tdb_prepare_stage_at(db->prepared, i);
        if (rec && rec->resolution == TDB_PREPARE_IN_DOUBT) in_doubt++;
    }
    *out_count = in_doubt;

    /* a caller with no buffer is only asking how many there are */
    if (!out) return TDB_SUCCESS;

    /* otherwise report the shortfall rather than filling what fits, so a truncated listing can
     * never be mistaken for the whole set of outstanding transactions */
    if (in_doubt > max) return TDB_ERR_TOO_LARGE;

    int n = 0;
    for (int i = 0; i < staged && n < in_doubt; i++)
    {
        const tdb_prepared_record_t *rec = tdb_prepare_stage_at(db->prepared, i);
        if (!rec || rec->resolution != TDB_PREPARE_IN_DOUBT) continue;

        tidesdb_txn_t *handle = calloc(1, sizeof(*handle));
        if (handle)
        {
            handle->db = db;
            handle->inner = tdb_txn_adopt_prepared(db->clock, rec->xid, rec->xid_size, rec->entries,
                                                   rec->count, rec->commit_seq);
        }
        if (!handle || !handle->inner)
        {
            free(handle);
            for (int j = 0; j < n; j++) engine_txn_free(out[j].txn);
            *out_count = 0;
            return TDB_ERR_MEMORY;
        }
        /* recovery already pinned this generation for every in-doubt batch, so the handle only
         * needs to remember which one to release when its coordinator finally decides */
        handle->prepare_generation = rec->generation;
        handle->prepare_generation_last = rec->generation;

        out[n].txn = handle;
        out[n].xid = rec->xid;
        out[n].xid_size = rec->xid_size;
        n++;
    }
    return TDB_SUCCESS;
}

int engine_txn_rollback_prepared(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    const int rc = tdb_txn_rollback_prepared(txn->inner, &txn->db->backend);
    if (rc == TDB_SUCCESS)
        engine_prepared_resolved(txn->db, txn->prepare_generation, txn->prepare_generation_last);
    return rc;
}

int engine_txn_state(const tidesdb_txn_t *txn, tidesdb_txn_state_t *out_state)
{
    if (!txn || !out_state) return TDB_ERR_INVALID_ARGS;
    *out_state = (tidesdb_txn_state_t)tdb_txn_state(txn->inner);
    return TDB_SUCCESS;
}

int engine_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_rollback(txn->inner);
}

void engine_txn_request_abort(tidesdb_txn_t *txn)
{
    if (txn) tdb_txn_request_abort(txn->inner);
}

int engine_txn_set_timeout(tidesdb_txn_t *txn, int64_t seconds)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    /* the core reports a missing clock separately, but the engine always supplies one, so the only
     * way this fails for a caller is a transaction that is no longer active */
    const int rc = tdb_txn_set_timeout(txn->inner, seconds);
    return rc == TDB_ERR_INVALID_DB ? TDB_ERR_INVALID_ARGS : rc;
}

void engine_txn_free(tidesdb_txn_t *txn)
{
    if (!txn) return;
    tdb_txn_free(txn->inner);
    free(txn);
}

uint64_t engine_take_gc_floor(tidesdb_t *db)
{
    const uint64_t floor = tidesdb_txn_registry_min_snapshot(db->txn_registry);

    /* raised to the highest floor ever taken, never lowered. a reader asking whether a sequence is
     * still reconstructable compares against this, and it has to account for a collection that has
     * already read a floor and not yet finished -- recording it here rather than at completion is
     * what closes that window */
    uint64_t seen = atomic_load_explicit(&db->gc_floor_high_water, memory_order_relaxed);
    while (floor > seen &&
           !atomic_compare_exchange_weak_explicit(&db->gc_floor_high_water, &seen, floor,
                                                  memory_order_relaxed, memory_order_relaxed))
        ;
    return floor;
}

uint64_t engine_oldest_readable_seq(const tidesdb_t *db)
{
    return db ? atomic_load_explicit(&db->gc_floor_high_water, memory_order_acquire) : 0;
}

int engine_txn_begin_at_seq(tidesdb_t *db, uint64_t seq, tidesdb_txn_t **out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;

    /* registered before the check, not after. joining at this sequence caps the floor every later
     * collection takes, so once the watermark is read past this point it can no longer move above
     * seq -- checking first would leave a window where a collection began between the two */
    const int rc = engine_txn_begin(db, TDB_ISOLATION_REPEATABLE_READ, out);
    if (rc != TDB_SUCCESS) return rc;
    const int pinned = tdb_txn_pin_snapshot((*out)->inner, seq);
    if (pinned != TDB_SUCCESS)
    {
        engine_txn_free(*out);
        *out = NULL;
        return pinned;
    }

    /* the floor only ever rises, so a watermark at or below seq means nothing at seq has ever been
     * eligible for collection and the point in time is exact. above it a merge has already kept one
     * version per key and dropped the rest, and answering from what survived would report a key
     * that existed as absent */
    if (atomic_load_explicit(&db->gc_floor_high_water, memory_order_acquire) > seq)
    {
        engine_txn_free(*out);
        *out = NULL;
        return TDB_ERR_TOO_OLD;
    }
    return TDB_SUCCESS;
}

int engine_snapshot_create(tidesdb_t *db, tidesdb_snapshot_t **out)
{
    if (!db || !out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;

    tidesdb_snapshot_t *snap = malloc(sizeof(*snap));
    if (!snap) return TDB_ERR_MEMORY;

    /* repeatable-read is the weakest level that both freezes a snapshot and joins the registry, and
     * joining is the point -- the floor is the minimum frozen snapshot the registry holds, so this
     * transaction existing is what keeps the versions readable */
    const int rc = engine_txn_begin(db, TDB_ISOLATION_REPEATABLE_READ, &snap->holder);
    if (rc != TDB_SUCCESS)
    {
        free(snap);
        return rc;
    }

    snap->seq = tdb_txn_read_snapshot(snap->holder->inner);
    *out = snap;
    return TDB_SUCCESS;
}

void engine_snapshot_release(tidesdb_snapshot_t *snap)
{
    if (!snap) return;
    /* the holder leaves the registry here, which is what lets the floor rise again */
    engine_txn_free(snap->holder);
    free(snap);
}

uint64_t engine_snapshot_seq(const tidesdb_snapshot_t *snap)
{
    return snap ? snap->seq : 0;
}

int engine_txn_begin_at_snapshot(tidesdb_t *db, tidesdb_snapshot_t *snap, tidesdb_txn_t **out)
{
    if (!db || !snap || !out) return TDB_ERR_INVALID_ARGS;

    const int rc = engine_txn_begin(db, TDB_ISOLATION_REPEATABLE_READ, out);
    if (rc != TDB_SUCCESS) return rc;

    /* the snapshot's own registration already holds the floor at or below this sequence, so moving
     * this transaction's ceiling back only narrows what it sees -- it does not expose versions the
     * floor was not already protecting */
    const int pinned = tdb_txn_pin_snapshot((*out)->inner, snap->seq);
    if (pinned != TDB_SUCCESS)
    {
        engine_txn_free(*out);
        *out = NULL;
        return pinned;
    }
    return TDB_SUCCESS;
}

int engine_txn_contains(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_contains(txn->inner, (uint32_t)cf->cf_id, key, key_size, txn->db->sources,
                            ENGINE_NUM_SOURCES);
}

int engine_txn_get_notrack(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                           uint8_t **value, size_t *value_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_get_notrack(txn->inner, (uint32_t)cf->cf_id, key, key_size, txn->db->sources,
                               ENGINE_NUM_SOURCES, value, value_size);
}

uint64_t engine_txn_read_snapshot(const tidesdb_txn_t *txn)
{
    return txn ? tdb_txn_read_snapshot(txn->inner) : 0;
}

int engine_txn_single_delete(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_single_delete(txn->inner, (uint32_t)cf->cf_id, key, key_size);
}

int engine_txn_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_savepoint(txn->inner, name);
}

int engine_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_rollback_to_savepoint(txn->inner, name);
}

int engine_txn_release_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_txn_release_savepoint(txn->inner, name);
}

int engine_txn_reset(tidesdb_txn_t *txn, tidesdb_isolation_level_t isolation)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    /* the txn core has no in-place reset, so discard it and begin a fresh one at a new snapshot */
    tdb_txn_free(txn->inner);
    txn->inner = tdb_txn_begin(txn->db->clock, isolation, &txn->db->now_seconds,
                               txn->db->config.txn_timeout_seconds, txn->db->txn_registry);
    return txn->inner ? TDB_SUCCESS : TDB_ERR_MEMORY;
}
