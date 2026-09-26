/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "txn_internal.h"

/* two-phase commit -- prepare stages a batch durably without applying it, and phase two decides it.
 * a batch takes its sequence when it prepares, so writes that commit while it is in doubt are newer
 * than it; ordering it against them is what separates this path from an ordinary commit and why it
 * lives in its own file. */

int tdb_txn_prepare(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                    const tidesdb_source_t *sources, int num_sources, const uint8_t *xid,
                    size_t xid_size)
{
    if (!backend || !xid || xid_size == 0) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    /* a read-only transaction votes read-only, nothing durable and no phase two */
    if (tidesdb_writeset_count(txn->writeset) == 0)
    {
        txn->state = TDB_TXN_COMMITTED;
        txn_leave_registry(txn);
        return TDB_SUCCESS;
    }

    uint8_t *xid_copy = malloc(xid_size);
    if (!xid_copy)
    {
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        return TDB_ERR_MEMORY;
    }
    memcpy(xid_copy, xid, xid_size);

    tidesdb_wal_entry_t *entries = NULL;
    int count = 0;
    uint64_t seq = 0;
    const int rc = txn_write_phase(txn, backend, sources, num_sources, TDB_WAL_KIND_PREPARE, xid,
                                   xid_size, &entries, &count, &seq);
    if (rc != TDB_SUCCESS)
    {
        free(xid_copy);
        return rc; /* already aborted and left the registry */
    }

    /* stage for phase two -- durable but not applied. the txn keeps its registry membership and its
     * claims until resolved, so its snapshot still pins the gc floor and its keys stay held. the
     * sequence it drew never carries a version, since phase two commits at a fresh one, so for the
     * watermark it is spent here and now, and the claims are marked as a prepared batch's, which
     * every later commit reads as coming above its own */
    txn->prepared_entries = entries;
    txn->prepared_count = count;
    txn->commit_seq = seq;
    txn->xid = xid_copy;
    txn->xid_size = xid_size;
    txn->state = TDB_TXN_PREPARED;
    tidesdb_mvcc_commit_prepared(&txn->commit);
    tidesdb_mvcc_mark_aborted(txn->clock, seq);
    return TDB_SUCCESS;
}

/* append the framed record of the given kind, freeing the buffer either way
 * @param backend the injected commit backend
 * @param kind the WAL record kind
 * @param xid the two-phase transaction id, or NULL for a plain write batch
 * @param xid_size length of xid
 * @param entries the batch entries, or NULL for a decision record
 * @param count number of entries
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
static int txn_append_record(const tdb_txn_backend_t *backend, uint8_t kind, const uint8_t *xid,
                             size_t xid_size, const tidesdb_wal_entry_t *entries, int count)
{
    const size_t size = tidesdb_wal_batch_size(kind, xid, xid_size, entries, (size_t)count);
    uint8_t *buf = malloc(size);
    if (!buf) return TDB_ERR_MEMORY;
    /* nothing is written when the encode declines, and the buffer is uninitialised -- see
     * txn_append_batch. the size came from the same arguments, so a short write means they disagree
     */
    if (tidesdb_wal_batch_encode(kind, xid, xid_size, entries, (size_t)count, buf, size) != size)
    {
        free(buf);
        return TDB_ERR_INVALID_ARGS;
    }
    const int wr = backend->wal_append(backend->ctx, buf, size);
    free(buf);
    return wr == 0 ? TDB_SUCCESS : TDB_ERR_IO;
}

int tdb_txn_commit_prepared(tdb_txn_t *txn, const tdb_txn_backend_t *backend)
{
    if (!backend || !txn || txn->state != TDB_TXN_PREPARED) return TDB_ERR_INVALID_ARGS;

    /* the batch takes its sequence here, when it is decided, rather than keeping the one it drew at
     * prepare. a sequence from the past would place the batch below writes that committed while it
     * was in doubt, yet it materializes above them -- and the read path resolves a key by source
     * order rather than by sequence, so the older batch would shadow the newer writes. deciding the
     * sequence now keeps a batch's position and its age in agreement, the invariant the read path,
     * tombstone collection, and the generation layout all rest on */
    const uint64_t seq = tidesdb_mvcc_draw(txn->clock, NULL);
    for (int i = 0; i < txn->prepared_count; i++) txn->prepared_entries[i].seq = seq;

    /* the COMMIT record carries the write set, so it is both the decision and the only durable copy
     * the batch needs. recovery replays it inline like an ordinary write batch, at this sequence
     * and in this generation, which makes a second replay land exactly where the first one did */
    const int wr = txn_append_record(backend, TDB_WAL_KIND_COMMIT, txn->xid, txn->xid_size,
                                     txn->prepared_entries, txn->prepared_count);
    if (wr != TDB_SUCCESS)
    {
        /* stays prepared -- the coordinator retries, and the retry draws another sequence, so the
         * one drawn here is spent for the watermark */
        tidesdb_mvcc_mark_aborted(txn->clock, seq);
        return wr;
    }

    /* durable now, so apply and mark visible. a failed in-memory apply is recovered from the COMMIT
     * record on the next open */
    (void)backend->apply(backend->ctx, txn->prepared_entries, txn->prepared_count);

    txn->commit_seq = seq;
    tidesdb_mvcc_mark(txn->clock, seq, 1);
    tidesdb_mvcc_wait_visible(txn->clock, seq);

    /* the claims and the intervals go once the batch is visible, and not before: from here the
     * store holds the versions a later writer's validation finds */
    txn_release_claims(txn);

    txn->state = TDB_TXN_COMMITTED;
    txn_leave_registry(txn);

    free(txn->prepared_entries);
    txn->prepared_entries = NULL;
    free(txn->xid);
    txn->xid = NULL;
    return TDB_SUCCESS;
}

/**
 * txn_adopt_claims
 * hold a recovered in-doubt batch's keys, intervals and reads exactly as a live prepare holds them,
 * so a writer of one of them is refused for as long as the coordinator leaves the batch in doubt.
 * every batch here prepared before the crash, so the keys are registered rather than contested
 * @param txn the adopted transaction, its prepared entries and sequence in place
 * @param reads the keys the batch read, from the record written ahead of its PREPARE, or NULL
 * @param read_count how many
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_CONFLICT when an interval could not be held
 */
static int txn_adopt_claims(tdb_txn_t *txn, const tidesdb_wal_entry_t *reads, const int read_count)
{
    tidesdb_mvcc_claim_t *claims =
        malloc((size_t)(txn->prepared_count + read_count) * sizeof(*claims));
    if (!claims) return TDB_ERR_MEMORY;
    int n = 0;
    for (int i = 0; i < txn->prepared_count; i++)
    {
        const tidesdb_wal_entry_t *e = &txn->prepared_entries[i];
        if (e->flags & TDB_WAL_ENTRY_RANGE_DELETE) continue;
        tidesdb_mvcc_claim_init(&claims[n++], e->cf_index, e->key, (uint32_t)e->key_size,
                                TDB_MVCC_CLAIM_WRITE,
                                txn_key_hash(e->cf_index, e->key, e->key_size));
    }
    for (int i = 0; i < read_count; i++)
    {
        const tidesdb_wal_entry_t *r = &reads[i];
        tidesdb_mvcc_claim_init(&claims[n++], r->cf_index, r->key, (uint32_t)r->key_size,
                                TDB_MVCC_CLAIM_READ,
                                txn_key_hash(r->cf_index, r->key, r->key_size));
    }
    tidesdb_mvcc_commit_init(&txn->commit, claims, n);
    txn->claims = claims;
    int held = tidesdb_mvcc_claim(txn->clock, &txn->commit, 0);
    for (int i = 0; held && i < txn->prepared_count; i++)
    {
        const tidesdb_wal_entry_t *e = &txn->prepared_entries[i];
        if (e->flags & TDB_WAL_ENTRY_RANGE_DELETE)
            held = tidesdb_mvcc_claim_range(txn->clock, &txn->commit, e->cf_index, e->key,
                                            e->key_size, e->value, e->value_size, 0);
    }
    if (!held)
    {
        txn_release_claims(txn);
        tidesdb_mvcc_commit_init(&txn->commit, NULL, 0);
        return TDB_ERR_CONFLICT;
    }
    tidesdb_mvcc_commit_prepared(&txn->commit);
    return TDB_SUCCESS;
}

tdb_txn_t *tdb_txn_adopt_prepared(tidesdb_mvcc_t *clock, const uint8_t *xid, const size_t xid_size,
                                  const tidesdb_wal_entry_t *entries, const int count,
                                  const uint64_t commit_seq, const tidesdb_wal_entry_t *reads,
                                  const int read_count)
{
    if (!clock || !xid || xid_size == 0 || (count > 0 && !entries) || read_count < 0 ||
        (read_count > 0 && !reads))
        return NULL;

    tdb_txn_t *txn = calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    txn->clock = clock;
    txn->commit_seq = commit_seq;
    /* with no registry to leave; the claims below are what it holds in this process */
    txn->isolation = TDB_ISOLATION_READ_COMMITTED;
    atomic_store_explicit(&txn->snapshot_seq, commit_seq, memory_order_release);
    txn->state = TDB_TXN_PREPARED;
    tidesdb_mvcc_commit_init(&txn->commit, NULL, 0);

    txn->xid = malloc(xid_size);
    if (!txn->xid)
    {
        tdb_txn_free(txn);
        return NULL;
    }
    memcpy(txn->xid, xid, xid_size);
    txn->xid_size = xid_size;

    if (count > 0)
    {
        /* the entry array is this transaction's, matching what phase two frees, while the key and
         * value bytes stay owned by the staging map that outlives it */
        txn->prepared_entries = malloc((size_t)count * sizeof(*txn->prepared_entries));
        if (!txn->prepared_entries)
        {
            tdb_txn_free(txn);
            return NULL;
        }
        memcpy(txn->prepared_entries, entries, (size_t)count * sizeof(*entries));
        txn->prepared_count = count;
        if (txn_adopt_claims(txn, reads, read_count) != TDB_SUCCESS)
        {
            tdb_txn_free(txn);
            return NULL;
        }
    }
    return txn;
}

int tdb_txn_rollback_prepared(tdb_txn_t *txn, const tdb_txn_backend_t *backend)
{
    if (!backend || !txn || txn->state != TDB_TXN_PREPARED) return TDB_ERR_INVALID_ARGS;

    /* a durable ROLLBACK record so recovery discards the prepared batch */
    const size_t size =
        tidesdb_wal_batch_size(TDB_WAL_KIND_ROLLBACK, txn->xid, txn->xid_size, NULL, 0);
    uint8_t *buf = malloc(size);
    if (!buf) return TDB_ERR_MEMORY;
    if (tidesdb_wal_batch_encode(TDB_WAL_KIND_ROLLBACK, txn->xid, txn->xid_size, NULL, 0, buf,
                                 size) != size)
    {
        free(buf);
        return TDB_ERR_INVALID_ARGS;
    }
    const int wr = backend->wal_append(backend->ctx, buf, size);
    free(buf);
    if (wr != 0) return TDB_ERR_IO; /* stays prepared -- retry */

    /* nothing was applied, so nothing to undo; drop the claims and finish */
    txn_release_claims(txn);
    txn->state = TDB_TXN_ABORTED;
    txn_leave_registry(txn);

    free(txn->prepared_entries);
    txn->prepared_entries = NULL;
    free(txn->xid);
    txn->xid = NULL;
    return TDB_SUCCESS;
}

const tidesdb_wal_entry_t *tdb_txn_prepared_entries(const tdb_txn_t *txn, int *out_count)
{
    if (out_count) *out_count = 0;
    if (!txn || !txn->prepared_entries) return NULL;
    if (out_count) *out_count = txn->prepared_count;
    return txn->prepared_entries;
}
