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
#include "base/keycmp.h"                 /* tdb_key_cmp, the one byte-wise key order */
#include "base/log.h"
#include "txn_internal.h"
#include "xxhash.h" /* XXH3 for the key hash the claims and the dedup are bucketed by */

/* the commit half of a transaction -- everything between a caller saying commit and the batch
 * becoming visible. it turns the buffered write set into WAL entries, claims the keys, draws the
 * sequence, decides whether the commit may proceed at all (the validation against the store and the
 * claims in flight), gets the entries durable, and marks the sequence that makes them visible. the
 * buffering, the reads, the savepoints and the lifecycle it works on top of live in txn.c. */

uint64_t txn_key_hash(uint32_t cf_index, const uint8_t *key, size_t key_size)
{
    /* the family namespaces the key through the seed rather than by prefixing it into a staging
     * buffer, which would cost a copy per call on a path that runs several times per written key */
    return XXH3_64bits_withSeed(key, key_size, cf_index);
}

/* order two exclusive upper bounds, either of which may be open. an open bound is above every
 * spellable one, which is what a zero length means for an interval delete */
static int txn_hi_cmp_hi(const uint8_t *a, const size_t a_size, const uint8_t *b,
                         const size_t b_size)
{
    if (a_size == 0 && b_size == 0) return 0;
    if (a_size == 0) return 1;
    if (b_size == 0) return -1;
    return tdb_key_cmp(a, a_size, b, b_size);
}

/* whether an interval delete covers a key -- its lower bound is the op's key and its upper bound
 * the op's value, open when that value is empty */
static int txn_range_covers(const tidesdb_writeset_op_t *op, const uint8_t *key,
                            const size_t key_size)
{
    if (tdb_key_cmp(op->key, op->key_size, key, key_size) > 0) return 0;
    if (op->value_size == 0) return 1; /* open above */
    return tdb_key_cmp(key, key_size, op->value, op->value_size) < 0;
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
        return tdb_key_cmp(later->key, later->key_size, op->key, op->key_size) <= 0 &&
               txn_hi_cmp_hi(op->value, op->value_size, later->value, later->value_size) <= 0;
    }

    if (op->flags & TDB_WAL_ENTRY_RANGE_DELETE) return 0;

    return later->key_size == op->key_size && memcmp(later->key, op->key, op->key_size) == 0;
}

/* the dedup set's floor, so a small batch does not pay a resize walk to reach a useful width */
#define TDB_DEDUP_MIN_SLOTS 64

/* the dedup asks, for every op, whether a later one already writes everything it does. asked
 * pairwise that is quadratic, and a bulk-loading transaction is exactly the case with the most ops
 * -- so the walk runs backward instead, testing each op against a summary of what follows it. point
 * writes are retired by the newest write of the same key, which an open-addressed set answers in
 * constant time; interval deletes cannot be summarized that way, but a batch holds few of them, so
 * they stay a list every op is checked against.
 * @param slot op index plus one, 0 for an empty slot; the index is kept so a collision can compare
 *             the key rather than trust the hash
 * @param mask one less than the power-of-two slot count
 */
typedef struct
{
    int *slot;
    uint64_t mask;
} txn_dedup_set_t;

/* whether the set already holds a point write of this op's key, meaning a later one supersedes it
 */
static int txn_dedup_seen(const txn_dedup_set_t *set, tidesdb_writeset_t *ws,
                          const tidesdb_writeset_op_t *op)
{
    uint64_t at = txn_key_hash(op->cf_index, op->key, op->key_size) & set->mask;
    while (set->slot[at] != 0)
    {
        tidesdb_writeset_op_t other;
        if (tidesdb_writeset_op_at(ws, set->slot[at] - 1, &other) &&
            other.cf_index == op->cf_index && other.key_size == op->key_size &&
            memcmp(other.key, op->key, op->key_size) == 0)
            return 1;
        at = (at + 1) & set->mask;
    }
    return 0;
}

/* record this op as the newest point write of its key seen so far */
static void txn_dedup_insert(const txn_dedup_set_t *set, tidesdb_writeset_t *ws, const int index,
                             const tidesdb_writeset_op_t *op)
{
    uint64_t at = txn_key_hash(op->cf_index, op->key, op->key_size) & set->mask;
    while (set->slot[at] != 0)
    {
        tidesdb_writeset_op_t other;
        if (tidesdb_writeset_op_at(ws, set->slot[at] - 1, &other) &&
            other.cf_index == op->cf_index && other.key_size == op->key_size &&
            memcmp(other.key, op->key, op->key_size) == 0)
            return; /* a newer write of this key is already the one that speaks for it */
        at = (at + 1) & set->mask;
    }
    set->slot[at] = index + 1;
}

/* mark every op a later one supersedes, walking backward so each is tested against what follows
 * @param ws the write set
 * @param n the op count
 * @param superseded out, one byte per op, set non-zero for an op a later one covers
 * @return 0 on success, -1 when the scratch could not be allocated and the caller must fall back
 */
static int txn_mark_superseded(tidesdb_writeset_t *ws, const int n, unsigned char *superseded)
{
    /* held at least twice the op count so a probe walks a short run */
    uint64_t cap = TDB_DEDUP_MIN_SLOTS;
    while (cap < (uint64_t)n * 2) cap <<= 1;

    txn_dedup_set_t set = {.slot = calloc((size_t)cap, sizeof(*set.slot)), .mask = cap - 1};
    int *ranges = malloc((size_t)n * sizeof(*ranges));
    if (!set.slot || !ranges)
    {
        free(set.slot);
        free(ranges);
        return -1;
    }

    int nranges = 0;
    for (int i = n - 1; i >= 0; i--)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(ws, i, &op)) continue;

        /* the interval deletes are asked pairwise, which is the same answer the quadratic walk gave
         * and cheap while a batch holds few of them */
        int sup = 0;
        for (int r = 0; r < nranges && !sup; r++)
        {
            tidesdb_writeset_op_t later;
            if (!tidesdb_writeset_op_at(ws, ranges[r], &later)) continue;
            sup = txn_op_superseded_by(&op, &later);
        }

        if (op.flags & TDB_WAL_ENTRY_RANGE_DELETE)
            ranges[nranges++] = i;
        else
        {
            if (!sup) sup = txn_dedup_seen(&set, ws, &op);
            /* recorded whether or not it survives -- an op it lost to speaks for the key from here
             * back, exactly as the pairwise walk had every later op to compare against */
            txn_dedup_insert(&set, ws, i, &op);
        }
        superseded[i] = (unsigned char)sup;
    }

    free(set.slot);
    free(ranges);
    return 0;
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

    /* one byte per op saying whether a later one covers it. the scan that fills this is linear in
     * the point writes; a failed allocation drops back to asking every pair, which is slow on a
     * large batch but still correct */
    unsigned char *superseded_of = calloc((size_t)n, 1);
    const int marked = superseded_of && txn_mark_superseded(ws, n, superseded_of) == 0;

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
        if (marked)
            superseded = superseded_of[i];
        else
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
    free(superseded_of);
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

void txn_release_claims(tdb_txn_t *txn)
{
    tidesdb_mvcc_unclaim(txn->clock, &txn->commit);
    free(txn->claims);
    txn->claims = NULL;
}

/* ask the sources whether a version of a key exists above seq_floor and at or below seq_ceiling,
 * retrying a transient busy internally. a source able to answer from its metadata skips the lookup
 * entirely, which is what keeps a commit's conflict scan off the read path. returns TDB_SUCCESS, or
 * TDB_ERR_IO if busy never cleared */
static int txn_probe_newer(const tidesdb_source_t *sources, int num_sources, uint32_t cf_index,
                           const uint8_t *key, size_t key_size, uint64_t seq_floor,
                           uint64_t seq_ceiling, int *newer)
{
    *newer = 0;
    for (int attempt = 0; attempt < TDB_TXN_BUSY_RETRY_MAX; attempt++)
    {
        const tidesdb_source_result_t r = tidesdb_source_stack_has_newer(
            sources, num_sources, cf_index, key, key_size, seq_floor, seq_ceiling, newer);
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
 * @param seq_ceiling the sequence a version must not exceed to count at all
 * @param newer out, set non-zero when one exists
 * @return TDB_SUCCESS, or TDB_ERR_IO if busy never cleared
 */
static int txn_probe_range_newer(const tidesdb_source_t *sources, int num_sources,
                                 uint32_t cf_index, const uint8_t *lo, size_t lo_size,
                                 const uint8_t *hi, size_t hi_size, uint64_t seq_floor,
                                 uint64_t seq_ceiling, int *newer)
{
    *newer = 0;
    for (int attempt = 0; attempt < TDB_TXN_BUSY_RETRY_MAX; attempt++)
    {
        const tidesdb_source_result_t r =
            tidesdb_source_stack_range_has_newer(sources, num_sources, cf_index, lo, lo_size, hi,
                                                 hi_size, seq_floor, seq_ceiling, newer);
        if (r != TDB_SOURCE_BUSY) return TDB_SUCCESS;
        if (attempt < TDB_TXN_BUSY_SPIN_THRESHOLD)
            cpu_pause();
        else
            cpu_yield();
    }
    return TDB_ERR_IO;
}

/* whether the level validates what it read at commit -- repeatable read and serializable. snapshot
 * keeps a read set for the version its writes are validated against, and validates no read */
static int txn_validates_reads(const tdb_txn_t *txn)
{
    return txn->isolation == TDB_ISOLATION_REPEATABLE_READ ||
           txn->isolation == TDB_ISOLATION_SERIALIZABLE;
}

/**
 * txn_validate_reads
 * refuse the commit if any key it read has a newer version -- committed into the store above the
 * version read, or held by a commit in flight whose sequence is below this one's, the writer whose
 * version this commit read before it existed -- or if any interval it scanned holds one, a phantom.
 * runs after the draw, so every writer that drew before this commit is either in the store or in
 * the claim set. the store is asked only about versions below this commit's own sequence: a writer
 * drawn after it that applied first is ordered after it, and its version stales nothing this
 * commit read
 * @param txn the committing transaction, its sequence drawn
 * @param sources the source stack
 * @param num_sources how many
 * @param below the highest sequence a store version may carry to count, the commit's own less one
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, or a probe error
 */
static int txn_validate_reads(tdb_txn_t *txn, const tidesdb_source_t *sources, int num_sources,
                              const uint64_t below)
{
    if (!txn->readset) return TDB_SUCCESS;
    const int n = tidesdb_readset_count(txn->readset);
    for (int i = 0; i < n; i++)
    {
        tidesdb_readset_entry_t rd;
        if (!tidesdb_readset_at(txn->readset, i, &rd)) continue;
        int newer = 0;
        const int rc = txn_probe_newer(sources, num_sources, rd.cf_index, rd.key, rd.key_size,
                                       rd.seq, below, &newer);
        if (rc != TDB_SUCCESS) return rc;
        if (newer) return TDB_ERR_CONFLICT;
        if (tidesdb_mvcc_read_stale(txn->clock, &txn->commit, rd.cf_index, rd.key,
                                    (uint32_t)rd.key_size,
                                    txn_key_hash(rd.cf_index, rd.key, rd.key_size)))
            return TDB_ERR_CONFLICT;
    }
    const int ranges = tidesdb_readset_range_count(txn->readset);
    for (int i = 0; i < ranges; i++)
    {
        tidesdb_readset_range_t sc;
        if (!tidesdb_readset_range_at(txn->readset, i, &sc)) continue;
        int newer = 0;
        const int rc = txn_probe_range_newer(sources, num_sources, sc.cf_index, sc.lo, sc.lo_size,
                                             sc.hi, sc.hi_size, sc.seq, below, &newer);
        if (rc != TDB_SUCCESS) return rc;
        if (newer) return TDB_ERR_CONFLICT;
        if (tidesdb_mvcc_range_stale(txn->clock, &txn->commit, sc.cf_index, sc.lo, sc.lo_size,
                                     sc.hi, sc.hi_size, 0))
            return TDB_ERR_CONFLICT;
    }
    return TDB_SUCCESS;
}

/**
 * txn_validate_writes
 * refuse the commit if any key it writes is read by a prepared batch that cannot yield, and, where
 * the level promises first-committer-wins, if the key has a version above the snapshot -- a
 * committer that finished between the snapshot and now -- or a commit in flight sequenced below
 * this one holds an interval covering it. an interval this commit deletes is probed over its bounds
 * rather than as a key, since a write to the one key spelling its lower bound is not a write inside
 * it, and against the claims in flight below this commit inside it
 * @param txn the committing transaction, its sequence drawn
 * @param sources the source stack
 * @param num_sources how many
 * @param below the highest sequence a store version may carry to count, the commit's own less one
 * @param first_committer_wins non-zero at snapshot and above
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, or a probe error
 */
static int txn_validate_writes(tdb_txn_t *txn, const tidesdb_source_t *sources, int num_sources,
                               const uint64_t below, int first_committer_wins)
{
    const uint64_t snapshot = atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire);
    const int n = tidesdb_writeset_count(txn->writeset);
    for (int i = 0; i < n; i++)
    {
        tidesdb_writeset_op_t op;
        if (!tidesdb_writeset_op_at(txn->writeset, i, &op)) continue;
        int newer = 0;
        int rc = TDB_SUCCESS;
        if (op.flags & TDB_WAL_ENTRY_RANGE_DELETE)
        {
            if (first_committer_wins)
                rc = txn_probe_range_newer(sources, num_sources, op.cf_index, op.key, op.key_size,
                                           op.value, op.value_size, snapshot, below, &newer);
            if (rc == TDB_SUCCESS && !newer && first_committer_wins &&
                tidesdb_mvcc_range_stale(txn->clock, &txn->commit, op.cf_index, op.key, op.key_size,
                                         op.value, op.value_size, 1))
                newer = 1;
        }
        else
        {
            if (first_committer_wins)
                rc = txn_probe_newer(sources, num_sources, op.cf_index, op.key, op.key_size,
                                     snapshot, below, &newer);
            if (rc == TDB_SUCCESS && !newer &&
                tidesdb_mvcc_write_blocked(
                    txn->clock, &txn->commit, op.cf_index, op.key, (uint32_t)op.key_size,
                    txn_key_hash(op.cf_index, op.key, op.key_size), first_committer_wins))
                newer = 1;
        }
        if (rc != TDB_SUCCESS) return rc;
        if (newer) return TDB_ERR_CONFLICT;
    }
    return TDB_SUCCESS;
}

/**
 * txn_validate
 * commit-time validation against the store and the claims in flight, after the sequence is drawn.
 * repeatable read and serializable validate what they read; snapshot and serializable validate what
 * they write on a first-committer-wins basis; every level here refuses to write a key a prepared
 * batch read. snapshot deliberately does not validate reads, since first-committer-wins is how it
 * prevents lost updates and validating reads on top would refuse what the level is defined to allow
 * @param txn the committing transaction, its sequence drawn
 * @param sources the source stack
 * @param num_sources how many
 * @param seq the sequence this commit drew; only store versions below it are its concern
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, or a probe error
 */
static int txn_validate(tdb_txn_t *txn, const tidesdb_source_t *sources, int num_sources,
                        const uint64_t seq)
{
    const uint64_t below = seq - 1;
    int rc = TDB_SUCCESS;
    if (txn_validates_reads(txn)) rc = txn_validate_reads(txn, sources, num_sources, below);
    if (rc == TDB_SUCCESS)
        rc = txn_validate_writes(txn, sources, num_sources, below,
                                 txn->isolation >= TDB_ISOLATION_SNAPSHOT);
    return rc;
}

/**
 * txn_claim_intervals
 * hold every interval this commit deletes, once its keys are claimed and before its sequence is
 * drawn -- refusing what it meets under first-committer-wins, recorded beside it at repeatable read
 * as the key claims are. an interval cannot be claimed as a key, there being no one key to hash, so
 * the clock's interval table is what stands between a range delete and a concurrent write inside
 * it, which for a two-phase transaction is the whole in-doubt window
 * @param txn the committing transaction, its keys claimed
 * @param entries the encoded write set
 * @param count the number of entries
 * @return TDB_SUCCESS, or TDB_ERR_CONFLICT when an interval meets a claim or interval in flight
 */
static int txn_claim_intervals(tdb_txn_t *txn, const tidesdb_wal_entry_t *entries, int count)
{
    const int first_committer_wins = txn->isolation >= TDB_ISOLATION_SNAPSHOT;
    for (int i = 0; i < count; i++)
    {
        if (!(entries[i].flags & TDB_WAL_ENTRY_RANGE_DELETE)) continue;
        if (!tidesdb_mvcc_claim_range(txn->clock, &txn->commit, entries[i].cf_index, entries[i].key,
                                      entries[i].key_size, entries[i].value, entries[i].value_size,
                                      first_committer_wins))
            return TDB_ERR_CONFLICT;
    }
    return TDB_SUCCESS;
}

/**
 * txn_claim_writes
 * claim every key this commit writes and, for a prepare at repeatable read or above, every key it
 * read, then hold every interval it deletes, all before the sequence is drawn. the claims borrow
 * the entries' and the read set's key bytes, both of which outlive them
 * @param txn the committing transaction
 * @param entries the encoded write set
 * @param count the number of entries
 * @param prepare non-zero for a prepare, whose reads are claimed too at the levels that validate
 *                them
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT when another commit in flight holds a key or an interval
 *         this one meets, or TDB_ERR_MEMORY
 */
static int txn_claim_writes(tdb_txn_t *txn, const tidesdb_wal_entry_t *entries, int count,
                            int prepare)
{
    const int reads = prepare && txn_validates_reads(txn) ? tidesdb_readset_count(txn->readset) : 0;
    const int cap = count + reads;
    tidesdb_mvcc_claim_t *claims = cap > 0 ? malloc((size_t)cap * sizeof(*claims)) : NULL;
    if (cap > 0 && !claims) return TDB_ERR_MEMORY;

    int n = 0;
    for (int i = 0; i < count; i++)
    {
        if (entries[i].flags & TDB_WAL_ENTRY_RANGE_DELETE) continue;
        tidesdb_mvcc_claim_init(
            &claims[n++], entries[i].cf_index, entries[i].key, (uint32_t)entries[i].key_size,
            TDB_MVCC_CLAIM_WRITE,
            txn_key_hash(entries[i].cf_index, entries[i].key, entries[i].key_size));
    }
    for (int i = 0; i < reads; i++)
    {
        tidesdb_readset_entry_t rd;
        if (!tidesdb_readset_at(txn->readset, i, &rd)) continue;
        tidesdb_mvcc_claim_init(&claims[n++], rd.cf_index, rd.key, (uint32_t)rd.key_size,
                                TDB_MVCC_CLAIM_READ,
                                txn_key_hash(rd.cf_index, rd.key, rd.key_size));
    }

    tidesdb_mvcc_commit_init(&txn->commit, claims, n);
    txn->claims = claims;
    if (tidesdb_mvcc_claim(txn->clock, &txn->commit, txn->isolation >= TDB_ISOLATION_SNAPSHOT) &&
        txn_claim_intervals(txn, entries, count) == TDB_SUCCESS)
        return TDB_SUCCESS;
    txn_release_claims(txn);
    tidesdb_mvcc_commit_init(&txn->commit, NULL, 0);
    return TDB_ERR_CONFLICT;
}

/* preserve the allocation-free path for a single entry and when the family set cannot be allocated
 */
static int txn_pace_families_scan(const tdb_txn_backend_t *backend,
                                  const tidesdb_wal_entry_t *entries, int count)
{
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
 * txn_pace_families
 * let the backend pace this commit once per distinct column family it writes, before the durable
 * write. remember families in a set so a large batch does not repeatedly scan preceding entries.
 * walk the entries in their original order, preserving the order of the backpressure callbacks
 * @param backend the commit backend, whose backpressure hook may be absent
 * @param entries the encoded write set
 * @param count the number of entries
 * @return TDB_SUCCESS, or TDB_ERR_IO when the backend refused to admit the write
 */
static int txn_pace_families(const tdb_txn_backend_t *backend, const tidesdb_wal_entry_t *entries,
                             int count)
{
    if (!backend->backpressure) return TDB_SUCCESS;
    if (count <= 1) return txn_pace_families_scan(backend, entries, count);

    size_t slots = 64;
    const size_t need = (size_t)count > SIZE_MAX / 2 ? SIZE_MAX : (size_t)count * 2;
    while (slots < need && slots <= SIZE_MAX / 2) slots <<= 1;
    if (slots < need || slots > SIZE_MAX / sizeof(uint32_t))
        return txn_pace_families_scan(backend, entries, count);

    /* a separate occupancy array leaves every column family id usable, including zero */
    uint32_t *families = malloc(slots * sizeof(*families));
    uint8_t *occupied = calloc(slots, sizeof(*occupied));
    if (!families || !occupied)
    {
        free(families);
        free(occupied);
        return txn_pace_families_scan(backend, entries, count);
    }
    for (int i = 0; i < count; i++)
    {
        const uint32_t family = entries[i].cf_index;
        size_t slot = ((uint64_t)family * UINT64_C(11400714819323198485)) & (slots - 1);
        while (occupied[slot] && families[slot] != family) slot = (slot + 1) & (slots - 1);
        if (occupied[slot]) continue;
        occupied[slot] = 1;
        families[slot] = family;
        if (backend->backpressure(backend->ctx, family) != 0)
        {
            free(occupied);
            free(families);
            return TDB_ERR_IO;
        }
    }
    free(occupied);
    free(families);
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

/**
 * txn_append_reads
 * make the keys a prepare read durable ahead of its PREPARE record, as a record of their own under
 * the same xid, so a batch adopted in doubt after a restart holds its read claims again. written
 * first, so a durable PREPARE always has its reads; a record no PREPARE followed is dropped by
 * recovery
 * @param backend the commit backend
 * @param txn the preparing transaction, whose read set is the source
 * @param xid the transaction id
 * @param xid_size length of xid
 * @param seq the prepare's sequence, carried so the record is shaped like every other
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO when the append failed
 */
static int txn_append_reads(const tdb_txn_backend_t *backend, const tdb_txn_t *txn,
                            const uint8_t *xid, size_t xid_size, uint64_t seq)
{
    const int n = tidesdb_readset_count(txn->readset);
    if (n == 0) return TDB_SUCCESS;
    tidesdb_wal_entry_t *keys = calloc((size_t)n, sizeof(*keys));
    if (!keys) return TDB_ERR_MEMORY;
    int count = 0;
    for (int i = 0; i < n; i++)
    {
        tidesdb_readset_entry_t rd;
        if (!tidesdb_readset_at(txn->readset, i, &rd)) continue;
        keys[count].cf_index = rd.cf_index;
        keys[count].seq = seq;
        keys[count].ttl = -1;
        keys[count].key = rd.key;
        keys[count].key_size = rd.key_size;
        count++;
    }
    const int rc =
        txn_append_batch(backend, TDB_WAL_KIND_PREPARE_READS, xid, xid_size, keys, count);
    free(keys);
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

/* the shared first phase of committing -- build the deduplicated entries, pace on backpressure,
 * claim the write set and hold its intervals, draw and mark-in-progress a commit seq, validate
 * against the store and the claims in flight, and durably append the WAL record of the given kind
 * (with an optional xid). on success returns TDB_SUCCESS with the entries, count, and seq for the
 * caller to apply and mark committed; on failure it drops the claims, marks a drawn seq aborted,
 * aborts the txn, leaves the registry, frees the entries, and returns the error. the caller must
 * have handled the empty write set and the require-active check first */
int txn_write_phase(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                    const tidesdb_source_t *sources, int num_sources, uint8_t kind,
                    const uint8_t *xid, size_t xid_size, tidesdb_wal_entry_t **out_entries,
                    int *out_count, uint64_t *out_seq)
{
    *out_entries = NULL;
    *out_count = 0;
    *out_seq = 0;

    int count = 0;
    tidesdb_wal_entry_t *entries = txn_build_entries(txn->writeset, 0, &count);
    if (!entries)
    {
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        return TDB_ERR_MEMORY;
    }

    /* admission comes first, while nothing is held and no sequence is drawn, so a park here neither
     * keeps a claim from other committers nor holds the watermark down for every reader */
    int rc = txn_pace_families(backend, entries, count);

    /* the claims come next, ahead of the sequence, so that any committer drawing after this one
     * finds them when it validates; a refused claim leaves nothing held and no sequence spent */
    const int claims = txn->isolation >= TDB_ISOLATION_REPEATABLE_READ;
    if (rc == TDB_SUCCESS && claims)
        rc = txn_claim_writes(txn, entries, count, kind == TDB_WAL_KIND_PREPARE);
    if (rc != TDB_SUCCESS)
    {
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        free(entries);
        return rc;
    }

    /* draw the commit sequence and mark it in progress -- invisible until marked committed. the
     * validation follows, since it orders this commit against the claims it meets by that sequence
     */
    const uint64_t seq = tidesdb_mvcc_draw(txn->clock, claims ? &txn->commit : NULL);
    for (int i = 0; i < count; i++) entries[i].seq = seq;
    if (txn->isolation > TDB_ISOLATION_READ_COMMITTED)
        rc = txn_validate(txn, sources, num_sources, seq);

    /* the values the database separates go to the value log here, before the record that names
     * them */
    if (rc == TDB_SUCCESS) rc = txn_separate_values(backend, entries, count);

    /* a prepare's read keys go ahead of its record, so a PREPARE that is durable always has them */
    if (rc == TDB_SUCCESS && kind == TDB_WAL_KIND_PREPARE && txn_validates_reads(txn))
        rc = txn_append_reads(backend, txn, xid, xid_size, seq);

    /* encode and durably append the WAL record */
    if (rc == TDB_SUCCESS) rc = txn_append_batch(backend, kind, xid, xid_size, entries, count);

    if (rc != TDB_SUCCESS)
    {
        /* drop the claims and abort. the drawn sequence is never made visible, and marking it
         * aborted is what lets the watermark pass it */
        txn_release_claims(txn);
        tidesdb_mvcc_mark_aborted(txn->clock, seq);
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

    tidesdb_wal_entry_t *entries = NULL;
    int count = 0;
    uint64_t seq = 0;
    const int rc = txn_write_phase(txn, backend, sources, num_sources, TDB_WAL_KIND_WRITE_BATCH,
                                   NULL, 0, &entries, &count, &seq);
    if (rc != TDB_SUCCESS) return rc; /* already aborted and left the registry */

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

        txn_release_claims(txn);
        tidesdb_mvcc_mark_aborted(txn->clock, seq);
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        free(entries);
        return TDB_ERR_IO;
    }

    tidesdb_mvcc_mark(txn->clock, seq, 1);
    tidesdb_mvcc_wait_visible(txn->clock, seq);
    txn->commit_seq = seq;

    /* the claims and the intervals go once the batch is visible, and not before: from here the
     * store holds the versions a later writer's validation finds, and until the mark it did not */
    txn_release_claims(txn);

    txn->state = TDB_TXN_COMMITTED;
    txn_leave_registry(txn);
    free(entries);
    return TDB_SUCCESS;
}
