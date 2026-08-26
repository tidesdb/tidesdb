/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_TXN_H__
#define __TIDESDB_TXN_TXN_H__

#include "db.h" /* tidesdb_isolation_level_t and the TDB_* result codes */
#include "mvcc.h"
#include "source.h"
#include "writeset.h"

/* the transaction handle, the core that composes the txn sub-modules. it holds the isolation level,
 * the snapshot sequence a read filters by, the buffered write set (buffer-at-commit -- nothing is
 * durable until commit), and the savepoint markers. it borrows the MVCC clock for both its snapshot
 * and its commit sequence. reads and commit consume injected sources and a commit backend so this
 * module depends only on the txn sub-modules, not the whole db -- the engine supplies the concrete
 * L0 and sstable sources. */

typedef struct tdb_txn tdb_txn_t;
typedef struct tidesdb_txn_registry tidesdb_txn_registry_t; /* full type in registry.h */

/**
 * tdb_txn_state_t
 * the lifecycle state of a transaction
 * @param TDB_TXN_ACTIVE buffering writes, not yet resolved
 * @param TDB_TXN_PREPARED durably prepared under an xid (2pc phase 1), awaiting commit or rollback
 * @param TDB_TXN_COMMITTED committed and applied
 * @param TDB_TXN_ABORTED rolled back or expired
 */
typedef enum
{
    TDB_TXN_ACTIVE = 0,
    TDB_TXN_PREPARED = 1,
    TDB_TXN_COMMITTED = 2,
    TDB_TXN_ABORTED = 3
} tdb_txn_state_t;

/**
 * tdb_txn_begin
 * begin a transaction at an isolation level, drawing its snapshot from the clock: read-uncommitted
 * sees everything, read-committed refreshes per read, and repeatable-read and stronger freeze the
 * snapshot at begin. an optional timeout bounds how long the transaction may stay active, so an
 * abandoned or long-idle transaction cannot pin the compaction gc floor and its reservations
 * forever
 * @param clock the borrowed MVCC clock
 * @param isolation the isolation level (TDB_ISOLATION_*)
 * @param now a borrowed seconds-resolution clock the caller keeps current, or NULL to disable the
 *            timeout. the engine passes NULL, so timeouts are inert in the database and this exists
 *            for a caller that maintains its own clock
 * @param timeout_seconds seconds the transaction may stay active before it expires, or <= 0 for no
 *                        timeout; ignored when now is NULL
 * @param registry the live-transaction registry to join for the gc floor and serializable conflict
 *                 detection; joined only at repeatable-read and stronger, and NULL disables it
 * @return the transaction, or NULL on bad args or allocation failure
 */
tdb_txn_t *tdb_txn_begin(tidesdb_mvcc_t *clock, tidesdb_isolation_level_t isolation,
                         const _Atomic(int64_t) *now, int64_t timeout_seconds,
                         tidesdb_txn_registry_t *registry);

/**
 * tdb_txn_free
 * free a transaction and its write set and savepoints
 * @param txn the transaction, may be NULL
 */
void tdb_txn_free(tdb_txn_t *txn);

/**
 * tdb_txn_put
 * buffer a put; the write is applied only at commit
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key (must be > 0)
 * @param value the value bytes
 * @param value_size length of value
 * @param ttl absolute expiry time, or -1 for none
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS (bad args or the txn is finished) / TDB_ERR_MEMORY
 */
int tdb_txn_put(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                const uint8_t *value, size_t value_size, int64_t ttl);

/**
 * tdb_txn_delete
 * buffer a tombstone delete
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn,
 * TDB_ERR_TXN_EXPIRED once a timeout has passed, or TDB_ERR_MEMORY
 */
int tdb_txn_delete(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size);

/**
 * tdb_txn_delete_prefix
 * buffer a delete of every key beginning with prefix, as one op however many keys it covers. it
 * shadows keys already written as well as keys written after it, so it is not the same as deleting
 * the keys that happen to be there when it is buffered. this is tdb_txn_delete_range with the one
 * bound a prefix implies -- its successor, or the end of the family when the prefix has none
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param prefix the prefix bytes, which must not be empty -- a whole family is dropped rather than
 * deleted a prefix at a time
 * @param prefix_size length of prefix, which must be greater than zero
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn or an empty prefix,
 * TDB_ERR_TXN_EXPIRED once a timeout has passed, or TDB_ERR_MEMORY
 */
int tdb_txn_delete_prefix(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *prefix,
                          size_t prefix_size);

/**
 * tdb_txn_delete_range
 * buffer a delete of every key in [lo, hi), as one op however many keys it covers. it shadows keys
 * already written as well as keys written after it. the upper bound is carried in the op's value,
 * since an interval delete names no value of its own
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param lo the inclusive lower bound, which must not be empty
 * @param lo_size length of lo, which must be greater than zero
 * @param hi the exclusive upper bound, or NULL with hi_size 0 to run to the end of the family
 * @param hi_size length of hi, 0 for the end of the family
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn or an empty lower
 * bound, TDB_ERR_TXN_EXPIRED once a timeout has passed, or TDB_ERR_MEMORY
 */
int tdb_txn_delete_range(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *lo, size_t lo_size,
                         const uint8_t *hi, size_t hi_size);

/**
 * tdb_txn_single_delete
 * buffer a single-delete tombstone, which pairs with exactly one put during compaction
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn,
 * TDB_ERR_TXN_EXPIRED once a timeout has passed, or TDB_ERR_MEMORY
 */
int tdb_txn_single_delete(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size);

/**
 * tdb_txn_get
 * read a key at the transaction's isolation. the transaction's own uncommitted writes win first
 * (read-your-own-writes: a buffered delete reads as not-found); otherwise the caller-supplied
 * source stack is consulted at the transaction's snapshot, and a transient source BUSY is retried
 * internally so it never surfaces
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param sources the caller's newest-first external source stack (L0 then this cf's sstables)
 * @param num_sources number of external sources
 * @param value out, receives a malloc'd value on a live hit (caller frees)
 * @param value_size out, receives the value length on a hit
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND, TDB_ERR_INVALID_ARGS/TDB_ERR_TXN_EXPIRED for an unusable
 * txn, or TDB_ERR_MEMORY
 */
int tdb_txn_get(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                const tidesdb_source_t *sources, int num_sources, uint8_t **value,
                size_t *value_size);

/**
 * tdb_txn_get_notrack
 * like tdb_txn_get but does not record the read into the conflict footprint; for uniqueness probes
 * that must not add read-write antidependencies
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param sources the caller's external source stack
 * @param num_sources number of external sources
 * @param value out, receives a malloc'd value on a live hit (caller frees)
 * @param value_size out, receives the value length on a hit
 * @return the same codes as tdb_txn_get
 */
int tdb_txn_get_notrack(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                        const tidesdb_source_t *sources, int num_sources, uint8_t **value,
                        size_t *value_size);

/**
 * tdb_txn_contains
 * whether a key is present (a non-tracking existence probe that frees any value internally)
 * @param txn the transaction
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param sources the caller's external source stack
 * @param num_sources number of external sources
 * @return TDB_SUCCESS if present, TDB_ERR_NOT_FOUND if absent, TDB_ERR_INVALID_ARGS on a NULL txn,
 * TDB_ERR_TXN_EXPIRED once a timeout has passed, TDB_ERR_BUSY when a source could not be read, or
 * TDB_ERR_MEMORY
 */
int tdb_txn_contains(tdb_txn_t *txn, uint32_t cf_index, const uint8_t *key, size_t key_size,
                     const tidesdb_source_t *sources, int num_sources);

/**
 * tdb_txn_backend_t
 * the durable side of commit, injected so the txn core stays decoupled from the L0 subsystem and
 * WAL. the engine supplies the concrete backend; tests supply a mock
 * @param backpressure admit a write to a column family, blocking or pacing as L0 fills; may be NULL
 * @param wal_append append the framed WAL batch and make it durable per the sync mode
 * @param apply apply the committed entries to L0 at their commit sequence
 * @param abandon record that a sequence's batch was applied in part and then given up on, so the
 * entries it left behind are hidden from reads and dropped by the flush rather than reaching L1;
 * may be NULL for a backend with no such state
 * @param separator moves a large value out of the record and into the shared value log, so the
 * bytes reach the device once instead of once in the log and again in the flush; its own context,
 * since the policy is the database's and the durable side is the log's
 * @param ctx opaque context passed to every backend call
 */
typedef struct
{
    /* separate one value, returning 1 with out_id set when the bytes went to the value log, 0 when
     * the policy keeps them in the record, and negative when the append failed */
    int (*separate)(void *ctx, uint32_t cf_index, const uint8_t *value, size_t value_size,
                    uint64_t *out_id);
    void *ctx;
} tdb_value_separator_t;

typedef struct
{
    int (*backpressure)(void *ctx, uint32_t cf_index);
    int (*wal_append)(void *ctx, const uint8_t *batch, size_t size);
    int (*apply)(void *ctx, const tidesdb_wal_entry_t *entries, int count);
    void (*abandon)(void *ctx, uint64_t seq);
    tdb_value_separator_t separator;
    void *ctx;
} tdb_txn_backend_t;

/**
 * tdb_txn_prepared_entries
 * the batch a prepare staged inside the transaction, so a caller holding it in doubt can protect
 * whatever it references. a live prepare keeps its entries here rather than in the engine's
 * cross-generation staging map, which only a replay fills
 * @param txn the transaction
 * @param out_count receives the entry count, 0 when the transaction is not prepared
 * @return the entries, borrowed and valid until the transaction is decided or freed, or NULL
 */
const tidesdb_wal_entry_t *tdb_txn_prepared_entries(const tdb_txn_t *txn, int *out_count);

/**
 * tdb_txn_commit
 * commit the buffered writes through the backend: draw a commit sequence, reserve the write set for
 * snapshot and serializable (first-committer-wins), pace on backpressure, append the WAL batch
 * durably, apply the deduplicated entries to L0 at the commit sequence, and mark the sequence
 * committed. a write-write conflict or any backend failure aborts the transaction and releases its
 * reservation; the wasted sequence stays in-progress and ages out harmlessly. a read-only
 * transaction commits with no durable work
 * @param txn the transaction
 * @param backend the injected commit backend
 * @param sources the source stack used for read-set validation and the write-conflict scan (may be
 *                empty for a level that needs no data-based conflict check)
 * @param num_sources number of sources
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT on a read-write or write-write conflict,
 * TDB_ERR_INVALID_ARGS / TDB_ERR_TXN_EXPIRED for an unusable txn, TDB_ERR_MEMORY, or TDB_ERR_IO
 * when the durable append failed or the apply did
 */
int tdb_txn_commit(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                   const tidesdb_source_t *sources, int num_sources);

/**
 * tdb_txn_prepare
 * two-phase-commit phase one: run the same conflict checks and reservation as commit, draw the
 * commit sequence, and durably append a PREPARE record carrying the xid and the write batch -- but
 * do not apply and do not mark committed, so the writes are crash-recoverable yet invisible. the
 * transaction moves to PREPARED and holds its reservation and snapshot until resolved by
 * commit-prepared or rollback-prepared. a read-only transaction votes read-only and finishes with
 * no phase two
 * @param txn the transaction
 * @param backend the injected commit backend
 * @param sources the source stack for conflict validation
 * @param num_sources number of sources
 * @param xid the transaction id to record, copied
 * @param xid_size length of xid (must be > 0)
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, TDB_ERR_INVALID_ARGS / TDB_ERR_TXN_EXPIRED,
 *         TDB_ERR_MEMORY, or TDB_ERR_IO when the durable append failed
 */
int tdb_txn_prepare(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                    const tidesdb_source_t *sources, int num_sources, const uint8_t *xid,
                    size_t xid_size);

/**
 * tdb_txn_commit_prepared
 * two-phase-commit phase two commit: durably append a COMMIT record for the prepared xid, then
 * apply the staged batch and mark the sequence committed. only valid on a PREPARED transaction; on
 * a transient io failure the transaction stays PREPARED so the coordinator can retry
 * @param txn the prepared transaction
 * @param backend the injected commit backend
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if not prepared, or TDB_ERR_MEMORY or TDB_ERR_IO,
 * either of which leaves the transaction prepared so the coordinator can retry the same decision
 */
int tdb_txn_commit_prepared(tdb_txn_t *txn, const tdb_txn_backend_t *backend);

/**
 * tdb_txn_rollback_prepared
 * two-phase-commit phase two rollback: durably append a ROLLBACK record for the prepared xid and
 * release the reservation. nothing was applied, so nothing is undone. only valid on a PREPARED
 * transaction; on a transient io failure it stays PREPARED so the coordinator can retry
 * @param txn the prepared transaction
 * @param backend the injected commit backend
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if not prepared, or TDB_ERR_MEMORY or TDB_ERR_IO,
 * either of which leaves the transaction prepared so the coordinator can retry the same decision
 */
int tdb_txn_rollback_prepared(tdb_txn_t *txn, const tdb_txn_backend_t *backend);

/**
 * tdb_txn_adopt_prepared
 * rebuild a transaction recovery found durably prepared but undecided, so the coordinator resolves
 * it through the same phase-two calls a live prepared transaction uses. it holds no snapshot and
 * joins no registry, since the process that took them is gone; only the batch and its sequence
 * survive
 * @param clock the borrowed MVCC clock, marked when phase two commits
 * @param xid the transaction id from the PREPARE record, copied here
 * @param xid_size length of xid, must be greater than zero
 * @param entries the prepared write set; the array is copied while its key and value bytes stay
 *                owned by the caller, which must outlive the returned transaction
 * @param count number of entries
 * @param commit_seq the sequence the batch commits at, taken when it originally prepared
 * @return the prepared transaction, or NULL on bad args or allocation failure
 */
tdb_txn_t *tdb_txn_adopt_prepared(tidesdb_mvcc_t *clock, const uint8_t *xid, size_t xid_size,
                                  const tidesdb_wal_entry_t *entries, int count,
                                  uint64_t commit_seq);

/**
 * tdb_txn_commit_seq
 * the commit sequence assigned to a committed transaction
 * @param txn the transaction
 * @return the commit sequence, or 0 if the transaction has not committed
 */
uint64_t tdb_txn_commit_seq(const tdb_txn_t *txn);

/**
 * tdb_txn_rollback
 * abort the transaction; nothing was applied, so nothing is undone
 * @param txn the transaction
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS if it was already committed
 */
int tdb_txn_rollback(tdb_txn_t *txn);

/**
 * tdb_txn_savepoint
 * mark a rollback point at the current write-set position under a name, updating it if the name
 * exists
 * @param txn the transaction
 * @param name the savepoint name
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL name or a finished txn, TDB_ERR_TXN_EXPIRED
 * once a timeout has passed, or TDB_ERR_MEMORY
 */
int tdb_txn_savepoint(tdb_txn_t *txn, const char *name);

/**
 * tdb_txn_rollback_to_savepoint
 * discard writes made after the named savepoint, keeping the transaction alive, and drop savepoints
 * taken after it
 * @param txn the transaction
 * @param name the savepoint name
 * @return TDB_SUCCESS, or TDB_ERR_NOT_FOUND if the name is unknown, or TDB_ERR_INVALID_ARGS
 */
int tdb_txn_rollback_to_savepoint(tdb_txn_t *txn, const char *name);

/**
 * tdb_txn_release_savepoint
 * drop a savepoint without rolling back to it
 * @param txn the transaction
 * @param name the savepoint name
 * @return TDB_SUCCESS, or TDB_ERR_NOT_FOUND if the name is unknown, or TDB_ERR_INVALID_ARGS
 */
int tdb_txn_release_savepoint(tdb_txn_t *txn, const char *name);

/**
 * tdb_txn_set_timeout
 * set or clear how long this transaction may stay active, measured from now. a transaction that is
 * abandoned rather than resolved holds its snapshot and its reservations, which keeps the
 * reclamation floor down and stops old versions being dropped, so a timeout is what bounds the cost
 * of a caller that never finishes
 * @param txn the transaction
 * @param seconds seconds from now at which it expires, or <= 0 to clear the timeout
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS for a NULL or finished transaction, or
 *         TDB_ERR_INVALID_DB when no clock was supplied to age it against
 */
int tdb_txn_set_timeout(tdb_txn_t *txn, int64_t seconds);

/**
 * tdb_txn_expired
 * whether the transaction has passed its timeout deadline; always false when no timeout was set
 * @param txn the transaction
 * @return 1 if past the deadline, 0 otherwise
 */
int tdb_txn_expired(const tdb_txn_t *txn);

/**
 * tdb_txn_request_abort
 * ask a transaction to fail, from a thread other than the one running it. the only cross-thread
 * operation on a transaction: it stores a flag and touches nothing else, and the owning thread
 * makes the state change itself the next time it enters an operation, so the transaction is still
 * owned by exactly one thread. safe to call more than once and on a transaction that has already
 * finished, where it has no effect
 * @param txn the transaction to abort, or NULL for a no-op
 */
void tdb_txn_request_abort(tdb_txn_t *txn);

/**
 * tdb_txn_state
 * the transaction's lifecycle state
 * @param txn the transaction
 * @return the state, or TDB_TXN_ABORTED if txn is NULL
 */
tdb_txn_state_t tdb_txn_state(const tdb_txn_t *txn);

/**
 * tdb_txn_snapshot
 * the snapshot sequence this transaction reads at
 * @param txn the transaction
 * @return the snapshot sequence, or 0 if txn is NULL
 */
uint64_t tdb_txn_snapshot(const tdb_txn_t *txn);

/**
 * tdb_txn_read_snapshot
 * the sequence a read filters at right now, honouring the isolation level -- read-uncommitted sees
 * everything, read-committed draws the current seq afresh on each call, and repeatable-read and
 * stronger return the snapshot frozen at begin. iterators must use this rather than
 * tdb_txn_snapshot so a read-committed scan sees data committed before it started instead of the
 * placeholder 0.
 * @param txn the transaction
 * @return the read snapshot sequence, or 0 if txn is NULL
 */
uint64_t tdb_txn_read_snapshot(const tdb_txn_t *txn);

/**
 * tdb_txn_pin_snapshot
 * lower a registered transaction's frozen snapshot to an earlier sequence, so its reads resolve as
 * of that point rather than as of its own begin. only meaningful at repeatable-read and stronger,
 * since the weaker levels do not read the frozen value at all
 * @param txn the transaction, which must already hold a frozen snapshot
 * @param seq the sequence to read at; ignored when above the transaction's own snapshot, so this
 *            only ever moves the ceiling backwards
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL txn or a level that does not freeze
 */
int tdb_txn_pin_snapshot(tdb_txn_t *txn, uint64_t seq);

/**
 * tdb_txn_set_registry_slot
 * record where the registry placed this transaction, so leaving is O(1)
 * @param txn the transaction
 * @param shard the shard it was added to, or -1 when it leaves
 * @param index its slot within that shard, or -1 when it leaves
 */
void tdb_txn_set_registry_slot(tdb_txn_t *txn, int shard, int index);

/**
 * tdb_txn_registry_shard
 * the registry shard this transaction sits in
 * @param txn the transaction
 * @return the shard index, or -1 if it is not registered
 */
int tdb_txn_registry_shard(const tdb_txn_t *txn);

/**
 * tdb_txn_registry_index
 * this transaction's slot within its registry shard
 * @param txn the transaction
 * @return the slot index, or -1 if it is not registered
 */
int tdb_txn_registry_index(const tdb_txn_t *txn);

/**
 * tdb_txn_isolation
 * the transaction's isolation level
 * @param txn the transaction
 * @return the isolation level, or TDB_ISOLATION_READ_COMMITTED if txn is NULL
 */
tidesdb_isolation_level_t tdb_txn_isolation(const tdb_txn_t *txn);

/**
 * tdb_txn_writeset
 * borrow the transaction's write set, for read-your-own-writes composition and commit-time
 * iteration
 * @param txn the transaction
 * @return the write set, or NULL if txn is NULL
 */
tidesdb_writeset_t *tdb_txn_writeset(tdb_txn_t *txn);

/**
 * tdb_txn_mem_bytes
 * the approximate heap this transaction holds, its write set plus read set, for db-level memory
 * stats
 * @param txn the transaction
 * @return the byte estimate, or 0 if txn is NULL
 */
int64_t tdb_txn_mem_bytes(const tdb_txn_t *txn);

#endif /* __TIDESDB_TXN_TXN_H__ */
