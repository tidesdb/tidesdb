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

    /* the gate is held only for the prepare, not for the in-doubt window that follows -- that
     * window has no bound, and holding it would stop every other committer for as long as the
     * transaction stays undecided. what covers the window instead is the interval reservation the
     * prepare takes and keeps until phase two resolves it */
    const int gated = txn->isolation >= TDB_ISOLATION_SNAPSHOT;
    if (gated) tidesdb_mvcc_commit_gate_lock(txn->clock, txn_writes_an_interval(txn->writeset));

    tidesdb_wal_entry_t *entries = NULL;
    int count = 0;
    uint64_t seq = 0;
    const int rc = txn_write_phase(txn, backend, sources, num_sources, TDB_WAL_KIND_PREPARE, xid,
                                   xid_size, &entries, &count, &seq);
    if (gated) tidesdb_mvcc_commit_gate_unlock(txn->clock);
    if (rc != TDB_SUCCESS)
    {
        free(xid_copy);
        return rc; /* already aborted and left the registry */
    }

    /* stage for phase two -- durable but not applied and not marked committed, so the seq stays
     * in-progress and invisible. the txn keeps its registry membership and reservation until
     * resolved, so its snapshot still pins the gc floor */
    txn->prepared_entries = entries;
    txn->prepared_count = count;
    txn->commit_seq = seq;
    txn->xid = xid_copy;
    txn->xid_size = xid_size;
    txn->state = TDB_TXN_PREPARED;
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
    const uint64_t prepared_seq = txn->commit_seq; /* what the prepare drew, and reserved with */
    const uint64_t seq = tidesdb_mvcc_next_seq(txn->clock);
    tidesdb_mvcc_mark(txn->clock, seq, 0);
    for (int i = 0; i < txn->prepared_count; i++) txn->prepared_entries[i].seq = seq;

    /* the COMMIT record carries the write set, so it is both the decision and the only durable copy
     * the batch needs. recovery replays it inline like an ordinary write batch, at this sequence
     * and in this generation, which makes a second replay land exactly where the first one did */
    const int wr = txn_append_record(backend, TDB_WAL_KIND_COMMIT, txn->xid, txn->xid_size,
                                     txn->prepared_entries, txn->prepared_count);
    if (wr != TDB_SUCCESS) return wr; /* stays prepared -- the coordinator retries */

    /* durable now, so apply and mark visible. a failed in-memory apply is recovered from the COMMIT
     * record on the next open */
    (void)backend->apply(backend->ctx, txn->prepared_entries, txn->prepared_count);

    /* hand each reservation from the prepare's sequence to the one that just committed. the prepare
     * claimed these slots with a sequence phase two then replaced, and that sequence is never
     * marked committed -- so a slot left naming it reads to every later writer of the key as a
     * committer still in flight, and they abort against a transaction that finished long ago. it
     * happens here, once the batch is durable and applied, because until then the commit is not
     * certain: an append that failed leaves the transaction prepared for a retry that draws a
     * different sequence, and the slots have to still name the prepare's for that retry to find
     * them. the hold is never dropped, only renamed, so no concurrent writer of the key slips
     * between the two states */
    if (txn->isolation >= TDB_ISOLATION_SNAPSHOT)
        for (int i = 0; i < txn->prepared_count; i++)
            tidesdb_mvcc_reassign(
                txn->clock,
                txn_key_hash(txn->prepared_entries[i].cf_index, txn->prepared_entries[i].key,
                             txn->prepared_entries[i].key_size),
                prepared_seq, seq);

    /* the sequence the prepare held is spent -- every slot naming it has been handed to the one
     * that just committed, which the ring governs like any other */
    tidesdb_mvcc_prepared_release(txn->clock, prepared_seq);

    txn->commit_seq = seq;
    tidesdb_mvcc_mark(txn->clock, seq, 1);

    /* the intervals go once the batch is visible, and not before. a key reservation is renamed
     * rather than dropped because the slot is what a later writer of that key reads; an interval
     * has no slot of its own to read, so what replaces it here is the committed delete itself,
     * which a later writer's conflict scan finds. releasing earlier would leave the window between
     * the two with nothing covering it. it is keyed by the sequence the prepare took, which phase
     * two replaced, so the release names that one rather than the sequence just committed */
    tidesdb_mvcc_release_range(txn->clock, prepared_seq);

    txn->state = TDB_TXN_COMMITTED;
    txn_leave_registry(txn);

    free(txn->prepared_entries);
    txn->prepared_entries = NULL;
    free(txn->xid);
    txn->xid = NULL;
    return TDB_SUCCESS;
}

tdb_txn_t *tdb_txn_adopt_prepared(tidesdb_mvcc_t *clock, const uint8_t *xid, const size_t xid_size,
                                  const tidesdb_wal_entry_t *entries, const int count,
                                  const uint64_t commit_seq)
{
    if (!clock || !xid || xid_size == 0 || (count > 0 && !entries)) return NULL;

    tdb_txn_t *txn = calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    txn->clock = clock;
    txn->commit_seq = commit_seq;
    /* below snapshot isolation, so resolving it does not try to release reservations that died with
     * the process that took them, and with no registry to leave */
    txn->isolation = TDB_ISOLATION_READ_COMMITTED;
    atomic_store_explicit(&txn->snapshot_seq, commit_seq, memory_order_release);
    txn->state = TDB_TXN_PREPARED;

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

    /* nothing was applied, so nothing to undo; release the reservation and finish */
    if (txn->isolation >= TDB_ISOLATION_SNAPSHOT)
        txn_release_reservations(txn, txn->prepared_entries, txn->prepared_count, txn->commit_seq);
    tidesdb_mvcc_prepared_release(txn->clock, txn->commit_seq);
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
