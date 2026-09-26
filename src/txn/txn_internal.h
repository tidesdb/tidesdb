/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_INTERNAL_H__
#define __TIDESDB_TXN_INTERNAL_H__

#include "readset.h"
#include "registry.h"
#include "txn.h"

/* the transaction handle and the commit-path helpers the one-phase and two-phase paths share.
 * private to the txn module -- the two files are split so neither carries the other's bulk, and
 * nothing outside src/txn includes this. */

/**
 * tdb_txn
 * the transaction handle
 * @param clock the borrowed MVCC clock
 * @param now a borrowed seconds-resolution clock the caller keeps current, or NULL when the
 *            timeout is disabled
 * @param deadline the wall-clock second at which the transaction expires, 0 for no timeout
 * @param isolation the isolation level
 * @param snapshot_seq the sequence reads filter at (per level). atomic because a peer's gc-floor
 * scan reads it from another thread while a time-travel begin is still lowering it -- the
 * transaction is registered before it pins, so that the floor is capped before the window opens
 * @param read_ceiling at read committed, the ceiling of the read or scan in flight, UINT64_MAX
 * between them. a read takes its ceiling from the watermark and then reads the store, and a
 * collection that took its floor meanwhile would keep one version per key and drop the ones the
 * read still resolves to; published here for the floor scan to see, and held only while a read or
 * an iterator is open. atomic because the scan reads it from another thread
 * @param read_holds how many reads and iterators of a read committed transaction are in flight;
 * the ceiling is published by the first and released by the last, so a scan's lower ceiling is not
 * lifted by a point read inside it
 * @param commit_seq the assigned commit sequence, 0 until commit or prepare
 * @param prepared_entries the entries staged by prepare, applied at phase-2 commit, NULL otherwise
 * @param prepared_count number of prepared entries
 * @param xid the two-phase-commit transaction id, owned, NULL unless prepared
 * @param xid_size length of xid
 * @param writeset the buffered write set
 * @param readset recorded reads for repeatable-read and stronger, NULL at lower levels
 * @param registry the live-transaction registry this txn joined, NULL if it did not join
 * @param registry_shard the registry shard this txn was added to, derived from its own address and
 * fixed for its life; -1 until it joins. stored rather than recomputed so a remove cannot disagree
 * with the add about which lock it needs
 * @param registry_index this txn's slot within that shard's array, for an O(1) remove; -1 until it
 * joins
 * @param sp_names savepoint names, parallel to sp_counts
 * @param sp_counts write-set op counts each savepoint was taken at
 * @param num_sp number of live savepoints
 * @param sp_cap allocated length of the savepoint arrays
 * @param state the lifecycle state
 * @param abort_requested set by another thread to make this transaction fail its next operation;
 *        the only field a thread other than the owner ever writes
 * @param commit this transaction's record in the clock's claim set while a commit or a prepare is
 *               in flight -- the keys it holds and the sequence they are ordered by
 * @param claims the claims that record chains, one per written key and, for a prepare at
 *               repeatable read or above, one per read key; NULL when nothing is held
 */
struct tdb_txn
{
    tidesdb_mvcc_t *clock;
    const _Atomic(int64_t) *now;
    int64_t deadline;
    tidesdb_isolation_level_t isolation;
    _Atomic(uint64_t) snapshot_seq;
    _Atomic(uint64_t) read_ceiling;
    int read_holds;
    uint64_t commit_seq;
    tidesdb_wal_entry_t *prepared_entries;
    int prepared_count;
    uint8_t *xid;
    size_t xid_size;
    tidesdb_writeset_t *writeset;
    tidesdb_readset_t *readset;
    tidesdb_txn_registry_t *registry;
    int registry_shard;
    int registry_index;
    char **sp_names;
    int *sp_counts;
    int num_sp;
    int sp_cap;
    tdb_txn_state_t state;
    /* written by whichever thread aborts this transaction, read by the owner. atomic because those
     * are different threads; everything else here stays plain because only the owner touches it */
    _Atomic(int) abort_requested;
    tidesdb_mvcc_commit_t commit;
    tidesdb_mvcc_claim_t *claims;
};

/* bounded internal retries for a transient source BUSY before giving up; the engine absorbs BUSY so
 * a caller never sees it. the window is far longer than any real layout-version race */
#define TDB_TXN_BUSY_RETRY_MAX      100000
#define TDB_TXN_BUSY_SPIN_THRESHOLD 1024

/**
 * txn_leave_registry
 * leave the live-transaction registry once, when the txn reaches a terminal state or is freed, so
 * the registry never holds a pointer to a finished or freed transaction
 * @param txn the transaction
 */
void txn_leave_registry(tdb_txn_t *txn);

/**
 * txn_require_active
 * require an active, unexpired txn for a mutating operation, expiring it lazily on the way through
 * so an abandoned txn resolves the moment it is next touched
 * @param txn the transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS for a finished txn, or TDB_ERR_TXN_EXPIRED for one past
 *         its deadline
 */
int txn_require_active(tdb_txn_t *txn);

/**
 * txn_key_hash
 * the 64-bit xxh3 hash of a cf-namespaced key, which picks the chain a claim on it hangs from.
 * shared so the two-phase path names the same chains the prepare claimed
 * @param cf_index the column family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @return the hash
 */
uint64_t txn_key_hash(uint32_t cf_index, const uint8_t *key, size_t key_size);

/**
 * txn_release_claims
 * drop every claim a commit or prepare holds and the intervals it holds, once its sequence is
 * decided or its batch is given up, so its keys stop refusing other writers; frees the claims array
 * @param txn the transaction
 */
void txn_release_claims(tdb_txn_t *txn);

/**
 * txn_write_phase
 * the shared first phase of committing -- build the deduplicated entries, pace on backpressure,
 * claim the write set and its intervals, draw and mark-in-progress a commit seq, validate, and
 * durably append the WAL record of the given kind. on failure it drops the claims, marks a drawn
 * seq aborted, aborts the transaction, leaves the registry, frees the entries, and returns the
 * error
 * @param txn the transaction
 * @param backend the injected commit backend
 * @param sources the source stack conflict detection reads
 * @param num_sources number of sources
 * @param kind the WAL record kind to append
 * @param xid the two-phase transaction id, or NULL for a plain write batch
 * @param xid_size length of xid
 * @param out_entries receives the built entries for the caller to apply and free
 * @param out_count receives the number of entries
 * @param out_seq receives the drawn commit sequence
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int txn_write_phase(tdb_txn_t *txn, const tdb_txn_backend_t *backend,
                    const tidesdb_source_t *sources, int num_sources, uint8_t kind,
                    const uint8_t *xid, size_t xid_size, tidesdb_wal_entry_t **out_entries,
                    int *out_count, uint64_t *out_seq);

#endif /* __TIDESDB_TXN_INTERNAL_H__ */
