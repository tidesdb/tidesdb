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

#include "base/encoding/serialization.h" /* tdb_encode_be64 for the abort record */
#include "base/log.h"
#include "txn_internal.h"

/* the commit half of a transaction -- everything between a caller saying commit and the batch
 * becoming visible. it decides whether the commit may proceed at all (the conflict scan, the
 * reservations, the serializable structure check), turns the buffered write set into WAL entries,
 * gets those durable, and draws and marks the sequence that makes them visible. the buffering, the
 * reads, the savepoints and the lifecycle it works on top of live in txn.c. */

uint64_t txn_key_hash(uint32_t cf_index, const uint8_t *key, size_t key_size)
{
    uint64_t h = 1469598103934665603ULL;     /* fnv offset basis */
    const uint64_t prime = 1099511628211ULL; /* fnv prime */
    for (int s = 0; s < 32; s += 8)
    {
        h ^= (uint8_t)(cf_index >> s);
        h *= prime;
    }
    for (size_t i = 0; i < key_size; i++)
    {
        h ^= key[i];
        h *= prime;
    }
    return h;
}

/* byte-wise order over keys, the order every source is sorted in */
static int txn_key_cmp(const uint8_t *a, const size_t a_size, const uint8_t *b, const size_t b_size)
{
    const size_t min_size = a_size < b_size ? a_size : b_size;
    const int c = min_size > 0 ? memcmp(a, b, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (a_size < b_size) return -1;
    if (a_size > b_size) return 1;
    return 0;
}

/* order two exclusive upper bounds, either of which may be open. an open bound is above every
 * spellable one, which is what a zero length means for an interval delete */
static int txn_hi_cmp_hi(const uint8_t *a, const size_t a_size, const uint8_t *b,
                         const size_t b_size)
{
    if (a_size == 0 && b_size == 0) return 0;
    if (a_size == 0) return 1;
    if (b_size == 0) return -1;
    return txn_key_cmp(a, a_size, b, b_size);
}

/* whether an interval delete covers a key -- its lower bound is the op's key and its upper bound
 * the op's value, open when that value is empty */
static int txn_range_covers(const tidesdb_writeset_op_t *op, const uint8_t *key,
                            const size_t key_size)
{
    if (txn_key_cmp(op->key, op->key_size, key, key_size) > 0) return 0;
    if (op->value_size == 0) return 1; /* open above */
    return txn_key_cmp(key, key_size, op->value, op->value_size) < 0;
}

/* whether a later op in the same batch already writes everything this one does, so only the later
 * one needs to reach the log. a range delete covers an interval, so it retires a point write that
 * falls inside it and a narrower interval within it, while nothing narrower ever retires it --
 * a point write speaks for one key and cannot cancel an interval, however exactly its key matches
 * the bound
 * @param op the earlier op
 * @param later the op after it in the same write set
 * @return non-zero when later covers everything op writes
 */
static int txn_op_superseded_by(const tidesdb_writeset_op_t *op, const tidesdb_writeset_op_t *later)
{
    if (later->cf_index != op->cf_index) return 0;

    if (later->flags & TDB_WAL_ENTRY_RANGE_DELETE)
    {
        /* an interval retires a point write it contains, and another interval it contains whole */
        if (!(op->flags & TDB_WAL_ENTRY_RANGE_DELETE))
            return txn_range_covers(later, op->key, op->key_size);
        return txn_key_cmp(later->key, later->key_size, op->key, op->key_size) <= 0 &&
               txn_hi_cmp_hi(op->value, op->value_size, later->value, later->value_size) <= 0;
    }

    if (op->flags & TDB_WAL_ENTRY_RANGE_DELETE) return 0;

    return later->key_size == op->key_size && memcmp(later->key, op->key, op->key_size) == 0;
}

/* materialize the write set as deduplicated WAL entries at commit_seq. only the last write covering
 * each cf-namespaced key survives, so last-write-wins holds on apply and replay. entries of one
 * batch share a sequence, and a point write beats a range delete at the same one -- which is what
 * makes a delete of a prefix followed by a write under it leave that one key alive. returns a
 * malloc'd array the caller frees with its length in out_count, or NULL (out_count 0) for an empty
 * set or on failure */
static tidesdb_wal_entry_t *txn_build_entries(tidesdb_writeset_t *ws, uint64_t commit_seq,
                                              int *out_count)
{
    *out_count = 0;
    const int n = tidesdb_writeset_count(ws);
    if (n == 0) return NULL;
    tidesdb_wal_entry_t *entries = malloc((size_t)n * sizeof(*entries));
    if (!entries) return NULL;

    int k = 0;
    for (int i = 0; i < n; i++)
    {
        tidesdb_writeset_op_t op;
        /* the accessor leaves out untouched when it declines, so the guard is what keeps an
         * out-of-range index from being compared as though it were an operation */
        if (!tidesdb_writeset_op_at(ws, i, &op)) continue;

        /* skip if a later op already writes everything this one does -- that later op is the
         * surviving version */
        int superseded = 0;
        for (int j = i + 1; j < n && !superseded; j++)
        {
            tidesdb_writeset_op_t later;
            if (!tidesdb_writeset_op_at(ws, j, &later)) continue;
            superseded = txn_op_superseded_by(&op, &later);
        }
        if (superseded) continue;

        tidesdb_wal_entry_t *e = &entries[k++];
        e->cf_index = op.cf_index;
        e->seq = commit_seq;
        e->ttl = op.ttl;
        e->flags = op.flags;
        if (op.ttl != -1) e->flags |= TDB_WAL_ENTRY_HAS_TTL;
        e->key = op.key;
        e->key_size = op.key_size;
        e->value = op.value;
        e->value_size = op.value_size;
        e->vlog_id = 0; /* the commit path holds its own bytes; nothing separates them yet */
    }
    *out_count = k;
    return entries;
}

/* move the values the database separates out of the batch and into the shared value log, leaving
 * each entry holding the id and the value's logical length. run after the reservation and the
 * pacing have both let this commit through, so a conflict leaves nothing behind in the log, and
 * before the record naming them is appended, so the bytes are on the device before anything points
 * at them. a commit that fails after this leaves its values as garbage, which the value log's own
 * reclamation is what clears */
static int txn_separate_values(const tdb_txn_backend_t *backend, tidesdb_wal_entry_t *entries,
                               const int count)
{
    if (!backend->separator.separate) return TDB_SUCCESS;

    for (int i = 0; i < count; i++)
    {
        tidesdb_wal_entry_t *e = &entries[i];
        /* a tombstone names no bytes, and an empty value has none worth moving */
        if ((e->flags & TDB_WAL_ENTRY_TOMBSTONE) || e->value == NULL || e->value_size == 0)
            continue;

        uint64_t id = 0;
        const int sep = backend->separator.separate(backend->separator.ctx, e->cf_index, e->value,
                                                    e->value_size, &id);
        if (sep < 0) return TDB_ERR_IO;
        if (sep == 0) continue;

        e->flags |= TDB_WAL_ENTRY_VLOG_REF;
        e->vlog_id = id;
        /* value_size stays the logical length; only the bytes go */
        e->value = NULL;
    }
    return TDB_SUCCESS;
}

/* release every reservation this commit may have claimed; a slot now owned by a newer committer is
 * left alone by tidesdb_mvcc_release */
void txn_release_reservations(tdb_txn_t *txn, const tidesdb_wal_entry_t *entries, int count,
                              uint64_t seq)
{
    for (int i = 0; i < count; i++)
        tidesdb_mvcc_release(txn->clock,
                             txn_key_hash(entries[i].cf_index, entries[i].key, entries[i].key_size),
                             seq);
    /* and the intervals, which are keyed by the holder rather than by anything in the entries */
    tidesdb_mvcc_release_range(txn->clock, seq);
}

/* ask the sources whether a version of a key exists above seq_floor, retrying a transient busy
 * internally. a source able to answer from its metadata skips the lookup entirely, which is what
 * keeps a commit's conflict scan off the read path. returns TDB_SUCCESS, or TDB_ERR_IO if busy
 * never cleared */
static int txn_probe_newer(const tidesdb_source_t *sources, int num_sources, uint32_t cf_index,
                           const uint8_t *key, size_t key_size, uint64_t seq_floor, int *newer)
{
    *newer = 0;
    for (int attempt = 0; attempt < TDB_TXN_BUSY_RETRY_MAX; attempt++)
    {
        const tidesdb_source_result_t r = tidesdb_source_stack_has_newer(
            sources, num_sources, cf_index, key, key_size, seq_floor, newer);
        if (r != TDB_SOURCE_BUSY) return TDB_SUCCESS;
        if (attempt < TDB_TXN_BUSY_SPIN_THRESHOLD)
            cpu_pause();
        else
            cpu_yield();
    }
    return TDB_ERR_IO;
}

/* ask the sources whether any key in [lo, hi) sits above seq_floor, retrying a transient busy
 * internally. this is what a range delete is checked with -- it writes an interval, so there is no
 * one key to probe, and a source that cannot answer leaves the commit unresolved rather than clear
 * @param sources the source stack
 * @param num_sources how many
 * @param cf_index the family the delete targets
 * @param lo inclusive lower bound
 * @param lo_size length of lo
 * @param hi exclusive upper bound, or NULL with hi_size 0 to run to the end of the family
 * @param hi_size length of hi
 * @param seq_floor the sequence a version must exceed to conflict
 * @param newer out, set non-zero when one exists
 * @return TDB_SUCCESS, or TDB_ERR_IO if busy never cleared
 */
static int txn_probe_range_newer(const tidesdb_source_t *sources, int num_sources,
                                 uint32_t cf_index, const uint8_t *lo, size_t lo_size,
                                 const uint8_t *hi, size_t hi_size, uint64_t seq_floor, int *newer)
{
    *newer = 0;
    for (int attempt = 0; attempt < TDB_TXN_BUSY_RETRY_MAX; attempt++)
    {
        const tidesdb_source_result_t r = tidesdb_source_stack_range_has_newer(
            sources, num_sources, cf_index, lo, lo_size, hi, hi_size, seq_floor, newer);
        if (r != TDB_SOURCE_BUSY) return TDB_SUCCESS;
        if (attempt < TDB_TXN_BUSY_SPIN_THRESHOLD)
            cpu_pause();
        else
            cpu_yield();
    }
    return TDB_ERR_IO;
}

/* serializable-snapshot-isolation dangerous-structure check. this txn is the pivot of a dangerous
 * read-write dependency structure when it has both an outgoing rw-edge (it read a key an active
 * serializable peer writes) and an incoming rw-edge (an active serializable peer read a key it
 * writes). a pivot is aborted -- the conservative Cahill rule, always safe. the edges are computed
 * locally against currently-active peers without mutating them, so exactly one of a write-skew pair
 * aborts and the other makes progress. returns TDB_ERR_CONFLICT if a pivot, else TDB_SUCCESS */
/* what the peer walk accumulates; the pivot test needs both edges, so the walk stops as soon as it
 * has them */
typedef struct
{
    tdb_txn_t *txn;
    int nreads;
    int nwrites;
    int rw_out;
    int rw_in;
} txn_ssi_scan_t;

/* examine one live peer for the two edges; returns non-zero once both are found so the registry
 * walk stops early, exactly as the original loop condition did */
static int txn_ssi_visit(tdb_txn_t *peer, void *ctx)
{
    txn_ssi_scan_t *scan = (txn_ssi_scan_t *)ctx;
    if (peer == scan->txn || peer->isolation != TDB_ISOLATION_SERIALIZABLE) return 0;

    /* outgoing edge, a key this txn read that the peer writes */
    for (int r = 0; r < scan->nreads && !scan->rw_out; r++)
    {
        tidesdb_readset_entry_t rd;
        if (!tidesdb_readset_at(scan->txn->readset, r, &rd)) continue;
        if (tidesdb_writeset_contains(peer->writeset, rd.cf_index, rd.key, rd.key_size))
            scan->rw_out = 1;
    }
    /* incoming edge, a key this txn writes that the peer read */
    for (int w = 0; w < scan->nwrites && !scan->rw_in; w++)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(scan->txn->writeset, w, &op)) continue;
        if (peer->readset &&
            tidesdb_readset_contains(peer->readset, op.cf_index, op.key, op.key_size))
            scan->rw_in = 1;
    }
    return scan->rw_in && scan->rw_out;
}

static int txn_check_ssi(tdb_txn_t *txn)
{
    if (txn->isolation != TDB_ISOLATION_SERIALIZABLE || !txn->registry) return TDB_SUCCESS;

    txn_ssi_scan_t scan = {.txn = txn,
                           .nreads = txn->readset ? tidesdb_readset_count(txn->readset) : 0,
                           .nwrites = tidesdb_writeset_count(txn->writeset),
                           .rw_out = 0,
                           .rw_in = 0};

    /* the walk holds the whole registry, so the peer set cannot shift between shards mid-decision
     */
    (void)tidesdb_txn_registry_for_each(txn->registry, txn_ssi_visit, &scan);

    return (scan.rw_in && scan.rw_out) ? TDB_ERR_CONFLICT : TDB_SUCCESS;
}

/* commit-time conflict detection against current data. repeatable-read and serializable validate
 * that no key they read has a newer committed version (non-repeatable/phantom prevention); snapshot
 * and serializable scan their write keys for a version newer than the snapshot -- an
 * already-applied writer the reservation cannot see; serializable also runs the dangerous-structure
 * check for write skew. returns TDB_SUCCESS, TDB_ERR_CONFLICT, or a probe error */
static int txn_check_conflicts(tdb_txn_t *txn, const tidesdb_source_t *sources, int num_sources)
{
    /* read-set validation runs for repeatable-read and serializable, but not snapshot (which uses
     * the first-committer-wins reservation instead) */
    const int validate_reads = txn->isolation == TDB_ISOLATION_REPEATABLE_READ ||
                               txn->isolation == TDB_ISOLATION_SERIALIZABLE;
    if (validate_reads && txn->readset)
    {
        const int n = tidesdb_readset_count(txn->readset);
        for (int i = 0; i < n; i++)
        {
            tidesdb_readset_entry_t rd;
            if (!tidesdb_readset_at(txn->readset, i, &rd)) continue;
            int newer = 0;
            const int rc = txn_probe_newer(sources, num_sources, rd.cf_index, rd.key, rd.key_size,
                                           rd.seq, &newer);
            if (rc != TDB_SUCCESS) return rc;
            if (newer) return TDB_ERR_CONFLICT;
        }
    }

    /* write-conflict scan for snapshot and serializable */
    if (txn->isolation >= TDB_ISOLATION_SNAPSHOT)
    {
        const int n = tidesdb_writeset_count(txn->writeset);
        for (int i = 0; i < n; i++)
        {
            tidesdb_writeset_op_t op;
            if (!tidesdb_writeset_op_at(txn->writeset, i, &op)) continue;
            int newer = 0;
            int rc;
            if (op.flags & TDB_WAL_ENTRY_RANGE_DELETE)
            {
                /* an interval delete conflicts with a write to any key inside it, not with a write
                 * to the one key whose bytes spell its lower bound. probing it as a key would clear
                 * a commit that is about to delete somebody else's just-written data */
                rc = txn_probe_range_newer(
                    sources, num_sources, op.cf_index, op.key, op.key_size, op.value, op.value_size,
                    atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire), &newer);
            }
            else
                rc = txn_probe_newer(sources, num_sources, op.cf_index, op.key, op.key_size,
                                     atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire),
                                     &newer);
            if (rc != TDB_SUCCESS) return rc;
            if (newer) return TDB_ERR_CONFLICT;
        }
    }

    /* serializable dangerous-structure detection (write-skew prevention) */
    return txn_check_ssi(txn);
}

/**
 * txn_reserve_writes
 * take the first-committer-wins reservation on every key this transaction writes. each key is
 * validated against the version this transaction actually read for it, falling back to the snapshot
 * for a blind write, so a writer that landed after the read is caught
 * @param txn the committing transaction
 * @param entries the encoded write set
 * @param count the number of entries
 * @param seq the commit sequence being reserved at
 * @return 1 when every key was reserved, 0 when another committer holds one
 */
static int txn_reserve_writes(tdb_txn_t *txn, const tidesdb_wal_entry_t *entries, int count,
                              uint64_t seq)
{
    /* read once for the whole write set rather than per key. this is the bound below which a
     * committed occupant of a slot cannot still be depended on, and it is what lets the slot's
     * fingerprint tell a real same-key writer from a hash collision; without it every collision
     * aborts a commit that had no real conflict. the published value is a scan the compaction
     * scheduler already runs, read here as one relaxed load -- running the scan on this path would
     * mean every registry shard, once per written key. it is only ever stale low, and low is the
     * conservative direction */
    const uint64_t min_snapshot = tidesdb_txn_registry_published_min_snapshot(txn->registry);

    /* the intervals this batch writes are claimed first, so a point write that arrives afterwards
     * meets them. an interval cannot be claimed as a key hash -- there is no one key to hash -- so
     * this is the only thing standing between a range delete and a concurrent write inside it once
     * the commit gate is gone, which for a two-phase transaction is the whole in-doubt window */
    for (int i = 0; i < count; i++)
    {
        if (!(entries[i].flags & TDB_WAL_ENTRY_RANGE_DELETE)) continue;
        if (!tidesdb_mvcc_reserve_range(txn->clock, entries[i].cf_index, entries[i].key,
                                        entries[i].key_size, entries[i].value,
                                        entries[i].value_size, seq))
            return 0;
    }

    for (int i = 0; i < count; i++)
    {
        if (entries[i].flags & TDB_WAL_ENTRY_RANGE_DELETE) continue; /* claimed above */

        /* an interval another transaction is committing, or holds in doubt, covers this key */
        if (tidesdb_mvcc_range_blocks(txn->clock, entries[i].cf_index, entries[i].key,
                                      entries[i].key_size, seq))
            return 0;

        const uint64_t h = txn_key_hash(entries[i].cf_index, entries[i].key, entries[i].key_size);
        uint64_t read_base = atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire);
        uint64_t rseq = 0;
        if (txn->readset && tidesdb_readset_seq(txn->readset, entries[i].cf_index, entries[i].key,
                                                entries[i].key_size, &rseq))
            read_base = rseq;
        if (!tidesdb_mvcc_reserve(txn->clock, h, seq, read_base, min_snapshot)) return 0;
    }
    return 1;
}

/**
 * txn_pace_families
 * let the backend pace this commit once per distinct column family it writes, before the durable
 * write. the write set is small enough that scanning back over it beats keeping a set of the
 * families already paced
 * @param backend the commit backend, whose backpressure hook may be absent
 * @param entries the encoded write set
 * @param count the number of entries
 * @return TDB_SUCCESS, or TDB_ERR_IO when the backend refused to admit the write
 */
static int txn_pace_families(const tdb_txn_backend_t *backend, const tidesdb_wal_entry_t *entries,
                             int count)
{
    if (!backend->backpressure) return TDB_SUCCESS;

    for (int i = 0; i < count; i++)
    {
        int seen = 0;
        for (int j = 0; j < i; j++)
            if (entries[j].cf_index == entries[i].cf_index)
            {
                seen = 1;
                break;
            }
        if (!seen && backend->backpressure(backend->ctx, entries[i].cf_index) != 0)
            return TDB_ERR_IO;
    }
    return TDB_SUCCESS;
}

/**
 * txn_append_batch
 * encode the write set as one WAL record and hand it to the backend to make durable
 * @param backend the commit backend
 * @param kind the record kind, which decides whether an xid is carried
 * @param xid the transaction id for a two-phase record, NULL otherwise
 * @param xid_size length of xid
 * @param entries the encoded write set
 * @param count the number of entries
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO when the append failed
 */
static int txn_append_batch(const tdb_txn_backend_t *backend, uint8_t kind, const uint8_t *xid,
                            size_t xid_size, const tidesdb_wal_entry_t *entries, int count)
{
    const size_t size = tidesdb_wal_batch_size(kind, xid, xid_size, entries, (size_t)count);
    uint8_t *buf = malloc(size);
    if (!buf) return TDB_ERR_MEMORY;

    /* the encode writes nothing at all when it declines, and the buffer is uninitialised, so an
     * unchecked call would hand the log a record's worth of whatever the allocator returned. the
     * size above is derived from the same arguments, so a short write means the two disagree */
    if (tidesdb_wal_batch_encode(kind, xid, xid_size, entries, (size_t)count, buf, size) != size)
    {
        free(buf);
        return TDB_ERR_INVALID_ARGS;
    }
    const int rc = backend->wal_append(backend->ctx, buf, size) != 0 ? TDB_ERR_IO : TDB_SUCCESS;
    free(buf);
    return rc;
}

/* record that a durable batch must not be replayed. best effort by construction -- if this append
 * fails there is nothing further to try, and the transaction is already being reported as failed --
 * so the failure is logged rather than returned, and the batch would come back on the next open */
static void txn_append_abort(const tdb_txn_backend_t *backend, uint64_t seq)
{
    uint8_t enc[TDB_WAL_ABORT_SEQ_SIZE];
    tdb_encode_be64(seq, enc);
    if (txn_append_batch(backend, TDB_WAL_KIND_ABORT_SEQ, enc, sizeof(enc), NULL, 0) != TDB_SUCCESS)
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "could not record the abort of durable batch seq %llu, it will replay",
                      (unsigned long long)seq);
}

/* the shared first phase of committing -- conflict-check, draw and mark-in-progress a commit seq,
 * build the deduplicated entries, reserve the write set, pace on backpressure, and durably append
 * the WAL record of the given kind (with an optional xid). on success returns TDB_SUCCESS with the
 * entries, count, and seq for the caller to apply and mark committed; on failure it releases the
 * reservation, aborts the txn, leaves the registry, frees the entries, and returns the error. the
 * caller must have handled the empty write set and the require-active check first */
int txn_write_phase(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                    const tidesdb_source_t *sources, int num_sources, uint8_t kind,
                    const uint8_t *xid, size_t xid_size, tidesdb_wal_entry_t **out_entries,
                    int *out_count, uint64_t *out_seq)
{
    *out_entries = NULL;
    *out_count = 0;
    *out_seq = 0;

    /* conflict detection against current data for everything above read-committed */
    if (txn->isolation > TDB_ISOLATION_READ_COMMITTED)
    {
        const int cc = txn_check_conflicts(txn, sources, num_sources);
        if (cc != TDB_SUCCESS)
        {
            txn->state = TDB_TXN_ABORTED;
            txn_leave_registry(txn);
            return cc;
        }
    }

    /* draw the commit sequence and mark it in-progress -- invisible until marked committed */
    const uint64_t seq = tidesdb_mvcc_next_seq(txn->clock);
    tidesdb_mvcc_mark(txn->clock, seq, 0);

    int count = 0;
    tidesdb_wal_entry_t *entries = txn_build_entries(txn->writeset, seq, &count);
    if (!entries)
    {
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        return TDB_ERR_MEMORY;
    }

    int rc = TDB_SUCCESS;

    /* first-committer-wins reservation for snapshot and serializable, before the WAL write */
    const int reserve = txn->isolation >= TDB_ISOLATION_SNAPSHOT;
    if (reserve && !txn_reserve_writes(txn, entries, count, seq)) rc = TDB_ERR_CONFLICT;

    /* pace each distinct column family before the durable write */
    if (rc == TDB_SUCCESS) rc = txn_pace_families(backend, entries, count);

    /* the values the database separates go to the value log here, before the record that names
     * them */
    if (rc == TDB_SUCCESS) rc = txn_separate_values(backend, entries, count);

    /* encode and durably append the WAL record */
    if (rc == TDB_SUCCESS) rc = txn_append_batch(backend, kind, xid, xid_size, entries, count);

    if (rc != TDB_SUCCESS)
    {
        /* release the reservation and abort. the wasted in-progress seq is never made visible and
         * ages out of the ring */
        if (reserve) txn_release_reservations(txn, entries, count, seq);
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        free(entries);
        return rc;
    }

    *out_entries = entries;
    *out_count = count;
    *out_seq = seq;
    return TDB_SUCCESS;
}

int txn_writes_an_interval(const tidesdb_writeset_t *ws)
{
    const int n = tidesdb_writeset_count(ws);
    for (int i = 0; i < n; i++)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(ws, i, &op)) continue;
        if (op.flags & TDB_WAL_ENTRY_RANGE_DELETE) return 1;
    }
    return 0;
}

int tdb_txn_commit(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                   const tidesdb_source_t *sources, int num_sources)
{
    if (!backend) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    /* a read-only transaction has nothing durable to do */
    if (tidesdb_writeset_count(txn->writeset) == 0)
    {
        txn->state = TDB_TXN_COMMITTED;
        txn_leave_registry(txn);
        return TDB_SUCCESS;
    }

    /* the gate spans the whole commit, not just the reservation, because what a range delete has
     * to be sure of is that no write it did not see becomes visible behind it. a batch that has
     * reserved but not yet marked its sequence visible is exactly such a write */
    const int gated = txn->isolation >= TDB_ISOLATION_SNAPSHOT;
    if (gated) tidesdb_mvcc_commit_gate_lock(txn->clock, txn_writes_an_interval(txn->writeset));

    tidesdb_wal_entry_t *entries = NULL;
    int count = 0;
    uint64_t seq = 0;
    const int rc = txn_write_phase(txn, backend, sources, num_sources, TDB_WAL_KIND_WRITE_BATCH,
                                   NULL, 0, &entries, &count, &seq);
    if (rc != TDB_SUCCESS)
    {
        if (gated) tidesdb_mvcc_commit_gate_unlock(txn->clock);
        return rc; /* already aborted and left the registry */
    }

    /* apply to L0 at the commit sequence, then mark committed and visible */
    if (backend->apply(backend->ctx, entries, count) != 0)
    {
        /* the batch is already durable, and replay treats a write batch's presence as its
         * commitment -- so without a record saying otherwise this transaction would come back whole
         * on the next open, after its caller was told it failed. the abort record is what replay
         * consults to leave it out */
        txn_append_abort(backend, seq);
        /* the durable record keeps the batch out on the next open; this keeps the entries the
         * failed apply already landed out of reads and out of the flush before then */
        if (backend->abandon) backend->abandon(backend->ctx, seq);

        if (txn->isolation >= TDB_ISOLATION_SNAPSHOT)
            txn_release_reservations(txn, entries, count, seq);
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        free(entries);
        if (gated) tidesdb_mvcc_commit_gate_unlock(txn->clock);
        return TDB_ERR_IO;
    }

    tidesdb_mvcc_mark(txn->clock, seq, 1);
    txn->commit_seq = seq;

    /* the intervals go once the batch is visible, and not before. a key reservation is renamed
     * rather than dropped because the slot is what a later writer of that key reads; an interval
     * has no slot of its own to read, so what replaces it here is the committed delete itself,
     * which a later writer's conflict scan finds. holding it past this point would leave the
     * table's slots to the first few range deletes a database commits, and refuse the rest */
    if (txn->isolation >= TDB_ISOLATION_SNAPSHOT) tidesdb_mvcc_release_range(txn->clock, seq);

    txn->state = TDB_TXN_COMMITTED;
    txn_leave_registry(txn);
    free(entries);
    /* released only here -- the batch is visible now, so a range delete waiting on the gate will
     * see it in the scan it runs once it has the gate */
    if (gated) tidesdb_mvcc_commit_gate_unlock(txn->clock);
    return TDB_SUCCESS;
}
