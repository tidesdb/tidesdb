/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "txn.h"

#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* tdb_encode_be64 for the abort record */
#include "base/log.h"
#include "range_tombstone/range_tombstone.h" /* the successor the prefix form of a range delete is expressed with */
#include "txn_internal.h"

/* initial savepoint-array capacity, grown by doubling */
#define TDB_TXN_INITIAL_SAVEPOINT_CAP 4

/* copy a nul-terminated name into a fresh allocation */
static char *dup_name(const char *s)
{
    const size_t n = strlen(s) + 1;
    char *c = malloc(n);
    if (c) memcpy(c, s, n);
    return c;
}

tdb_txn_t *tdb_txn_begin(tidesdb_mvcc_t *clock, tidesdb_isolation_level_t isolation,
                         const _Atomic(int64_t) *now, int64_t timeout_seconds,
                         tidesdb_txn_registry_t *registry)
{
    if (!clock || isolation < TDB_ISOLATION_READ_UNCOMMITTED ||
        isolation > TDB_ISOLATION_SERIALIZABLE)
        return NULL;

    tdb_txn_t *txn = calloc(1, sizeof(*txn));
    if (!txn) return NULL;
    txn->writeset = tidesdb_writeset_create();
    if (!txn->writeset)
    {
        free(txn);
        return NULL;
    }

    txn->clock = clock;
    txn->isolation = isolation;
    txn->state = TDB_TXN_ACTIVE;
    txn->registry_shard = -1;
    txn->registry_index = -1;

    /* repeatable-read and stronger record their reads so commit can validate them; lower levels
     * never conflict on reads, so they carry no read set */
    if (isolation >= TDB_ISOLATION_REPEATABLE_READ)
    {
        txn->readset = tidesdb_readset_create();
        if (!txn->readset)
        {
            tidesdb_writeset_free(txn->writeset);
            free(txn);
            return NULL;
        }
    }

    /* set the expiry deadline from the current cached time plus the timeout; 0 means unbounded */
    txn->now = now;
    if (now && timeout_seconds > 0)
        txn->deadline = atomic_load_explicit(now, memory_order_relaxed) + timeout_seconds;

    /* draw the snapshot. read-uncommitted sees everything, read-committed refreshes per read (0
     * here), and repeatable-read and stronger freeze the highest already-assigned seq at begin */
    if (isolation == TDB_ISOLATION_READ_UNCOMMITTED)
    {
        atomic_store_explicit(&txn->snapshot_seq, UINT64_MAX, memory_order_relaxed);
    }
    else if (isolation == TDB_ISOLATION_READ_COMMITTED)
    {
        atomic_store_explicit(&txn->snapshot_seq, 0, memory_order_relaxed);
    }
    else
    {
        const uint64_t cur = tidesdb_mvcc_current_seq(clock);
        atomic_store_explicit(&txn->snapshot_seq, cur > 0 ? cur - 1 : 0, memory_order_relaxed);
    }

    /* join the live-transaction registry, done last so the snapshot is already set before a peer's
     * gc-floor scan can observe this txn. only repeatable-read and stronger join. a failed join is
     * not fatal -- the txn still runs correctly, only the gc floor and serializable checks lose it
     */
    if (registry && isolation >= TDB_ISOLATION_REPEATABLE_READ &&
        tidesdb_txn_registry_add(registry, txn) == TDB_SUCCESS)
        txn->registry = registry;

    return txn;
}

void tdb_txn_set_registry_slot(tdb_txn_t *txn, int shard, int index)
{
    if (!txn) return;
    txn->registry_shard = shard;
    txn->registry_index = index;
}

int tdb_txn_registry_shard(const tdb_txn_t *txn)
{
    return txn ? txn->registry_shard : -1;
}

int tdb_txn_registry_index(const tdb_txn_t *txn)
{
    return txn ? txn->registry_index : -1;
}

/* leave the live-transaction registry once, when the txn reaches a terminal state or is freed, so
 * the registry never holds a pointer to a finished or freed transaction */
void txn_leave_registry(tdb_txn_t *txn)
{
    if (txn->registry)
    {
        tidesdb_txn_registry_remove(txn->registry, txn);
        txn->registry = NULL;
    }
}

void tdb_txn_free(tdb_txn_t *txn)
{
    if (!txn) return;
    txn_leave_registry(txn); /* never leave a freed pointer in the registry */

    /* an in-doubt transaction freed without a decision is abandoned -- nothing in this process can
     * resolve it any more, and its key reservations are left to age out of the ring the way any
     * unresolved claim is. the sequence hold has to go with them, or it would keep a sequence no
     * one can decide in flight for the life of the database, holding those keys against every
     * later writer and taking a slot from a prepare that could still be decided */
    if (txn->state == TDB_TXN_PREPARED && txn->isolation >= TDB_ISOLATION_SNAPSHOT)
        tidesdb_mvcc_prepared_release(txn->clock, txn->commit_seq);

    free(txn->prepared_entries); /* an abandoned in-doubt txn still owns these */
    free(txn->xid);
    tidesdb_writeset_free(txn->writeset);
    tidesdb_readset_free(txn->readset);
    for (int i = 0; i < txn->num_sp; i++) free(txn->sp_names[i]);
    free(txn->sp_names);
    free(txn->sp_counts);
    free(txn);
}

int tdb_txn_set_timeout(tdb_txn_t *txn, int64_t seconds)
{
    if (!txn || txn->state != TDB_TXN_ACTIVE) return TDB_ERR_INVALID_ARGS;
    /* the deadline is an absolute second on the clock the transaction was given, so without one
     * there is nothing to age against and a timeout would silently never fire */
    if (!txn->now) return TDB_ERR_INVALID_DB;

    txn->deadline =
        seconds > 0 ? atomic_load_explicit(txn->now, memory_order_relaxed) + seconds : 0;
    return TDB_SUCCESS;
}

int tdb_txn_expired(const tdb_txn_t *txn)
{
    if (!txn || !txn->now || txn->deadline == 0) return 0;
    return atomic_load_explicit(txn->now, memory_order_relaxed) > txn->deadline;
}

void tdb_txn_request_abort(tdb_txn_t *txn)
{
    if (!txn) return;
    atomic_store_explicit(&txn->abort_requested, 1, memory_order_release);
}

/* require an active txn for a mutating operation, and resolve lazily on the way through what other
 * parties have decided about it -- an abort another thread asked for, or a deadline that has since
 * passed -- so an abandoned or overruled txn settles the moment it is next touched. returns
 * TDB_SUCCESS, TDB_ERR_TXN_ABORTED once another thread has asked for one, TDB_ERR_TXN_EXPIRED past
 * a deadline, or TDB_ERR_INVALID_ARGS for a txn that is simply finished */
int txn_require_active(tdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;

    /* an abort asked for by another thread, taken effect here rather than where it was asked for.
     * the requester only stores a flag, so this thread is still the only one that moves the state
     * and the transaction stays owned by one thread throughout. a request landing just after this
     * read lets the current operation finish and stops the next one, which is the same window the
     * deadline below has and is for the caller above to sequence if it needs more.
     *
     * it is answered ahead of the resolved-transaction check, and goes on being answered, because
     * the caller that asked for it has to hear the same thing from every operation afterwards. the
     * first one aborts the transaction, and a plain resolved-transaction reply from the ones after
     * would lose exactly the fact the caller needs -- a victim whose last read happened to notice
     * first would then have its commit report nothing more than a finished transaction, and the
     * ruling that ended it would be invisible at the point it most needs reporting */
    if (atomic_load_explicit(&txn->abort_requested, memory_order_acquire) &&
        txn->state != TDB_TXN_COMMITTED)
    {
        if (txn->state == TDB_TXN_ACTIVE)
        {
            txn->state = TDB_TXN_ABORTED;
            txn_leave_registry(txn);
        }
        return TDB_ERR_TXN_ABORTED;
    }

    if (txn->state != TDB_TXN_ACTIVE) return TDB_ERR_INVALID_ARGS;

    if (tdb_txn_expired(txn))
    {
        txn->state = TDB_TXN_ABORTED;
        txn_leave_registry(txn);
        return TDB_ERR_TXN_EXPIRED;
    }
    return TDB_SUCCESS;
}

/* buffer one write op after confirming the txn may still take writes */
static int txn_buffer(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                      const uint8_t *value, size_t value_size, int64_t ttl, uint8_t flags)
{
    const int rc = txn_require_active(txn);
    if (rc != TDB_SUCCESS) return rc;
    return tidesdb_writeset_put(txn->writeset, cf_index, key, key_size, value, value_size, ttl,
                                flags);
}

int tdb_txn_put(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                const uint8_t *value, size_t value_size, int64_t ttl)
{
    return txn_buffer(txn, cf_index, key, key_size, value, value_size, ttl, 0);
}

int tdb_txn_delete(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size)
{
    return txn_buffer(txn, cf_index, key, key_size, NULL, 0, -1, TDB_WAL_ENTRY_TOMBSTONE);
}

int tdb_txn_single_delete(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size)
{
    return txn_buffer(txn, cf_index, key, key_size, NULL, 0, -1,
                      TDB_WAL_ENTRY_TOMBSTONE | TDB_WAL_ENTRY_SINGLE_DELETE);
}

int tdb_txn_delete_range(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *lo, size_t lo_size,
                         const uint8_t *hi, size_t hi_size)
{
    if (hi_size > 0 && !hi) return TDB_ERR_INVALID_ARGS;
    /* keys are never empty, so an empty lower bound names no key the caller could have meant; a
     * bound below every key there can be is spelled as a single zero byte */
    if (!lo || lo_size == 0) return TDB_ERR_INVALID_ARGS;
    /* the interval reservation table holds a bound in a fixed slot, and it is what stands between
     * this delete and a concurrent write inside it. refused here rather than at the commit, where
     * a slot too small to hold the bound has nothing to report but a conflict that would never
     * clear however many times the caller retried */
    if (lo_size > TDB_MVCC_MAX_RANGE_BYTES || hi_size > TDB_MVCC_MAX_RANGE_BYTES)
        return TDB_ERR_INVALID_ARGS;

    /* an interval ending at or before it starts covers no key and fragments into nothing, which the
     * tombstone set refuses. it is caught here for the same reason an oversized bound is: the apply
     * that would meet it runs after the batch is durable, where every failure is taken for a
     * transient one and retried, so a bound the caller can still fix would instead burn the retries
     * and cancel the whole batch with an error naming the disk */
    if (!range_tombstone_interval_valid(lo, lo_size, hi, hi_size)) return TDB_ERR_INVALID_ARGS;

    /* the upper bound rides in the value. an interval delete names no value of its own, so the
     * field is free, and using it keeps the record exactly the shape a delete already had */
    return txn_buffer(txn, cf_index, lo, lo_size, hi, hi_size, -1,
                      TDB_WAL_ENTRY_TOMBSTONE | TDB_WAL_ENTRY_RANGE_DELETE);
}

int tdb_txn_delete_prefix(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *prefix,
                          size_t prefix_size)
{
    if (!prefix || prefix_size == 0) return TDB_ERR_INVALID_ARGS;

    /* a prefix is the interval from it to its successor, so this is the general call with the one
     * bound a prefix implies. a prefix of nothing but max bytes has no successor to name and runs
     * to the end of the family instead */
    uint8_t *hi = NULL;
    size_t hi_size = 0;
    const int rc = range_tombstone_prefix_successor(prefix, prefix_size, &hi, &hi_size);
    if (rc != TDB_SUCCESS) return rc;

    const int buffered = tdb_txn_delete_range(txn, cf_index, prefix, prefix_size, hi, hi_size);
    free(hi);
    return buffered;
}

/* the snapshot a read filters at -- read-uncommitted sees everything, read-committed draws a fresh
 * current-seq per read, and repeatable-read and stronger use the snapshot frozen at begin */
static uint64_t txn_read_snapshot(const tdb_txn_t *txn)
{
    if (txn->isolation == TDB_ISOLATION_READ_UNCOMMITTED) return UINT64_MAX;
    if (txn->isolation == TDB_ISOLATION_READ_COMMITTED) return tidesdb_mvcc_current_seq(txn->clock);
    return atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire);
}

static int txn_get_impl(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                        const tidesdb_source_t *sources, int num_sources, uint8_t **value,
                        size_t *value_size, int record_read)
{
    if (!key || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    /* read-your-own-writes, so the txn's own buffered write wins and a buffered delete reads as
     * not-found */
    tidesdb_writeset_op_t own;
    if (tidesdb_writeset_lookup(txn->writeset, cf_index, key, key_size, &own))
    {
        if (own.flags & TDB_WAL_ENTRY_TOMBSTONE) return TDB_ERR_NOT_FOUND;
        uint8_t *copy = NULL;
        if (own.value_size)
        {
            copy = malloc(own.value_size);
            if (!copy) return TDB_ERR_MEMORY;
            memcpy(copy, own.value, own.value_size);
        }
        *value = copy;
        *value_size = own.value_size;
        return TDB_SUCCESS;
    }

    /* the external source stack at the read's snapshot, absorbing a transient busy internally */
    const uint64_t snapshot = txn_read_snapshot(txn);
    for (int attempt = 0; attempt < TDB_TXN_BUSY_RETRY_MAX; attempt++)
    {
        tidesdb_source_version_t v;
        const tidesdb_source_result_t r =
            tidesdb_source_stack_get(sources, num_sources, cf_index, key, key_size, snapshot, &v);

        /* record the read for conflict validation. an absent read is recorded at the snapshot so a
         * later insert is caught; a hit is recorded at the version's seq. only when tracking and
         * only for the levels that keep a read set. a failed record cannot guarantee isolation */
        const int track = record_read && txn->readset;

        if (r == TDB_SOURCE_NOT_FOUND)
        {
            if (track && tidesdb_readset_record(txn->readset, cf_index, key, key_size, snapshot) !=
                             TDB_SUCCESS)
                return TDB_ERR_MEMORY;
            return TDB_ERR_NOT_FOUND;
        }
        if (r == TDB_SOURCE_FOUND)
        {
            if (track &&
                tidesdb_readset_record(txn->readset, cf_index, key, key_size, v.seq) != TDB_SUCCESS)
            {
                free(v.value);
                return TDB_ERR_MEMORY;
            }
            if (v.deleted)
            {
                free(v.value);
                return TDB_ERR_NOT_FOUND; /* a visible tombstone reads as not-found */
            }
            *value = v.value; /* ownership transfers to the caller */
            *value_size = v.value_size;
            return TDB_SUCCESS;
        }
        /* TDB_SOURCE_BUSY -- back off and retry; never surface it */
        if (attempt < TDB_TXN_BUSY_SPIN_THRESHOLD)
            cpu_pause();
        else
            cpu_yield();
    }
    return TDB_ERR_IO; /* transient contention never cleared -- internal failure, not a public busy
                        */
}

int tdb_txn_get(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                const tidesdb_source_t *sources, int num_sources, uint8_t **value,
                size_t *value_size)
{
    return txn_get_impl(txn, cf_index, key, key_size, sources, num_sources, value, value_size, 1);
}

int tdb_txn_get_notrack(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                        const tidesdb_source_t *sources, int num_sources, uint8_t **value,
                        size_t *value_size)
{
    return txn_get_impl(txn, cf_index, key, key_size, sources, num_sources, value, value_size, 0);
}

int tdb_txn_contains(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                     const tidesdb_source_t *sources, int num_sources)
{
    uint8_t *value = NULL;
    size_t value_size = 0;
    const int rc =
        txn_get_impl(txn, cf_index, key, key_size, sources, num_sources, &value, &value_size, 0);
    if (rc == TDB_SUCCESS) free(value);
    return rc;
}

uint64_t tdb_txn_commit_seq(const tdb_txn_t *txn)
{
    return txn ? txn->commit_seq : 0;
}

int tdb_txn_rollback(tdb_txn_t *txn)
{
    /* a prepared txn is durable and must be resolved through rollback-prepared, not discarded here
     */
    if (!txn || txn->state == TDB_TXN_COMMITTED || txn->state == TDB_TXN_PREPARED)
        return TDB_ERR_INVALID_ARGS;
    txn->state = TDB_TXN_ABORTED;
    txn_leave_registry(txn);
    return TDB_SUCCESS;
}

/* index of a savepoint by name, or -1 */
static int txn_savepoint_index(const tdb_txn_t *txn, const char *name)
{
    for (int i = 0; i < txn->num_sp; i++)
        if (strcmp(txn->sp_names[i], name) == 0) return i;
    return -1;
}

int tdb_txn_savepoint(tdb_txn_t *txn, const char *name)
{
    if (!name) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    const int count = tidesdb_writeset_count(txn->writeset);

    /* an existing name re-marks its position at the current write-set count */
    const int existing = txn_savepoint_index(txn, name);
    if (existing >= 0)
    {
        txn->sp_counts[existing] = count;
        return TDB_SUCCESS;
    }

    if (txn->num_sp == txn->sp_cap)
    {
        const int new_cap = txn->sp_cap ? txn->sp_cap * 2 : TDB_TXN_INITIAL_SAVEPOINT_CAP;
        char **grown_names = realloc(txn->sp_names, (size_t)new_cap * sizeof(*grown_names));
        if (!grown_names) return TDB_ERR_MEMORY;
        txn->sp_names = grown_names;
        int *grown_counts = realloc(txn->sp_counts, (size_t)new_cap * sizeof(*grown_counts));
        if (!grown_counts) return TDB_ERR_MEMORY;
        txn->sp_counts = grown_counts;
        txn->sp_cap = new_cap;
    }

    char *copy = dup_name(name);
    if (!copy) return TDB_ERR_MEMORY;
    txn->sp_names[txn->num_sp] = copy;
    txn->sp_counts[txn->num_sp] = count;
    txn->num_sp++;
    return TDB_SUCCESS;
}

int tdb_txn_rollback_to_savepoint(tdb_txn_t *txn, const char *name)
{
    if (!name) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    const int idx = txn_savepoint_index(txn, name);
    if (idx < 0) return TDB_ERR_NOT_FOUND;

    tidesdb_writeset_truncate(txn->writeset, txn->sp_counts[idx]);

    /* keep the target savepoint so it can be rolled back to again (standard sql), dropping only the
     * savepoints taken after it */
    for (int i = idx + 1; i < txn->num_sp; i++) free(txn->sp_names[i]);
    txn->num_sp = idx + 1;
    return TDB_SUCCESS;
}

int tdb_txn_release_savepoint(tdb_txn_t *txn, const char *name)
{
    if (!name) return TDB_ERR_INVALID_ARGS;
    const int active = txn_require_active(txn);
    if (active != TDB_SUCCESS) return active;

    const int idx = txn_savepoint_index(txn, name);
    if (idx < 0) return TDB_ERR_NOT_FOUND;

    free(txn->sp_names[idx]);
    for (int i = idx; i < txn->num_sp - 1; i++)
    {
        txn->sp_names[i] = txn->sp_names[i + 1];
        txn->sp_counts[i] = txn->sp_counts[i + 1];
    }
    txn->num_sp--;
    return TDB_SUCCESS;
}

uint64_t tdb_txn_snapshot(const tdb_txn_t *txn)
{
    return txn ? atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire) : 0;
}

uint64_t tdb_txn_read_snapshot(const tdb_txn_t *txn)
{
    return txn ? txn_read_snapshot(txn) : 0;
}

int tdb_txn_pin_snapshot(tdb_txn_t *txn, const uint64_t seq)
{
    if (!txn || txn->isolation < TDB_ISOLATION_REPEATABLE_READ) return TDB_ERR_INVALID_ARGS;

    if (seq < atomic_load_explicit(&txn->snapshot_seq, memory_order_acquire))
        atomic_store_explicit(&txn->snapshot_seq, seq, memory_order_release);
    return TDB_SUCCESS;
}

tidesdb_isolation_level_t tdb_txn_isolation(const tdb_txn_t *txn)
{
    return txn ? txn->isolation : TDB_ISOLATION_READ_COMMITTED;
}

tdb_txn_state_t tdb_txn_state(const tdb_txn_t *txn)
{
    return txn ? txn->state : TDB_TXN_ABORTED;
}

tidesdb_writeset_t *tdb_txn_writeset(tdb_txn_t *txn)
{
    return txn ? txn->writeset : NULL;
}

int64_t tdb_txn_mem_bytes(const tdb_txn_t *txn)
{
    if (!txn) return 0;
    return tidesdb_writeset_mem_bytes(txn->writeset) + tidesdb_readset_mem_bytes(txn->readset);
}
