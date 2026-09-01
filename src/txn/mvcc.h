/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_MVCC_H__
#define __TIDESDB_TXN_MVCC_H__

#include "../compat.h"
#include "db.h" /* TDB_MAX_RANGE_BOUND_SIZE, the public limit this table's slot width sets */

/* the MVCC clock -- the whole basis of which writes a read sees. it owns the monotonic sequence
 * counter, the commit-status ring that records whether each recent seq committed, and the
 * write-reservation table that gives snapshot/serializable commits their first-committer-wins
 * conflict check. it is pure: it knows sequence numbers and precomputed key hashes, not engine
 * structs, so it builds and unit-tests standalone. the transaction manager draws seqs and snapshots
 * from it, marks a commit's seq committed, filters reads through its visibility predicate, and
 * drives the reservation over a txn's write set. */

/* the commit-status ring records the last this-many sequence numbers; older seqs are treated as
 * committed by the eviction rule, which holds for every sequence a commit drew and not for one a
 * prepare is still sitting on -- those are held below and stay in flight however far they fall */
#define TDB_MVCC_COMMIT_RING_SIZE 65536

/* prepared batches whose sequence is exempt from the eviction rule at once. a two-phase batch keeps
 * its sequence in flight for as long as phase two leaves it undecided, which has no bound and so
 * outlasts the ring, and each undecided batch holds a slot until it is decided. a prepare that
 * cannot take one is refused rather than left holding keys nothing would defend */
#define TDB_MVCC_MAX_PREPARED_HOLDS 64

/* number of write-reservation slots and the mask to index one from a key hash */
#define TDB_MVCC_RESERVATION_SLOTS ((uint32_t)1 << 20)
#define TDB_MVCC_RESERVATION_MASK  (TDB_MVCC_RESERVATION_SLOTS - 1)

/* a reservation slot packs a 16-bit key fingerprint (high bits) and the claiming 48-bit commit_seq
 * (low bits); the fingerprint tells a real same-key conflict from a hash collision using the slot
 * alone, without ever reading another committer's applied version */
#define TDB_MVCC_RES_SEQ_BITS 48

typedef struct tidesdb_mvcc tidesdb_mvcc_t;

/**
 * tidesdb_mvcc_stats_t
 * a point-in-time snapshot of MVCC clock activity, for observability
 * @param seqs_assigned commit sequences drawn (roughly the number of commits started)
 * @param commits_marked sequences marked committed
 * @param reservations_won write reservations that claimed their slot
 * @param reservations_lost write reservations that lost to a concurrent writer (write-write
 * conflict)
 */
typedef struct
{
    uint64_t seqs_assigned;
    uint64_t commits_marked;
    uint64_t reservations_won;
    uint64_t reservations_lost;
} tidesdb_mvcc_stats_t;

/**
 * tidesdb_mvcc_create
 * create the MVCC clock with the sequence counter at 1, an all-in-progress commit ring, and an
 * empty reservation table
 * @return the clock, or NULL on allocation failure
 */
tidesdb_mvcc_t *tidesdb_mvcc_create(void);

/**
 * tidesdb_mvcc_destroy
 * free the MVCC clock and its ring and reservation table
 * @param m the clock, may be NULL
 */
void tidesdb_mvcc_destroy(tidesdb_mvcc_t *m);

/* interval reservations held at once. one belongs to a commit in flight or a two-phase transaction
 * in doubt, both of which are rare, so a table this size is not a bound a real workload meets --
 * and a commit that cannot take a slot reports a conflict rather than proceeding unchecked */
#define TDB_MVCC_MAX_RANGE_RESERVATIONS 32

/* the longest bound a reservation stores, which is the public limit on an interval delete's bounds
 * -- the two are the same number because this table is the reason for it. a bound past it is turned
 * away at the api, so a reservation refused here is one the table had no free slot for */
#define TDB_MVCC_MAX_RANGE_BYTES TDB_MAX_RANGE_BOUND_SIZE

/**
 * tidesdb_mvcc_reserve_range
 * hold an interval against concurrent point writes for as long as this transaction is unresolved.
 * the key-hash reservation a point write takes cannot express an interval, so this is what a range
 * delete claims instead -- and it is what carries a two-phase range delete through the window
 * between its prepare and its commit, where the commit gate cannot help because that window has no
 * bound
 * @param m the clock
 * @param cf_index the family the interval belongs to
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for open above
 * @param hi_size length of hi, 0 for open above
 * @param owner_seq the sequence this transaction reserved at, its identity here
 * @return 1 when the interval is held, 0 when another transaction already holds one meeting it, a
 *         bound is longer than the table stores, or the table is full
 */
int tidesdb_mvcc_reserve_range(tidesdb_mvcc_t *m, uint32_t cf_index, const uint8_t *lo,
                               size_t lo_size, const uint8_t *hi, size_t hi_size,
                               uint64_t owner_seq);

/**
 * tidesdb_mvcc_release_range
 * drop every interval a transaction holds, once it is resolved either way
 * @param m the clock
 * @param owner_seq the sequence the intervals were reserved at
 */
void tidesdb_mvcc_release_range(tidesdb_mvcc_t *m, uint64_t owner_seq);

/**
 * tidesdb_mvcc_range_blocks
 * whether another transaction holds an interval covering this key. a database with none held
 * answers from a single relaxed load, which is every database that never deletes a range
 * @param m the clock
 * @param cf_index the family the key belongs to
 * @param key the key a point write is about to reserve
 * @param key_size length of key
 * @param owner_seq the asking transaction's sequence, so its own intervals do not block it
 * @return non-zero when some other transaction's interval covers the key
 */
int tidesdb_mvcc_range_blocks(const tidesdb_mvcc_t *m, uint32_t cf_index, const uint8_t *key,
                              size_t key_size, uint64_t owner_seq);

/**
 * tidesdb_mvcc_commit_gate_lock
 * hold the database's commit gate for the length of one commit, from before its conflict scan until
 * its batch is marked visible. an ordinary commit holds it shared and so never waits on another;
 * one carrying a prefix delete holds it exclusively and runs alone
 *
 * this is what closes the window the reservation table cannot. a point write reserves the hash of
 * the key it writes, and a prefix delete has no key to hash -- it writes an interval -- so the two
 * can never collide there however they are ordered. running the interval alone is what makes the
 * conflict scan's answer still true by the time the delete commits
 * @param m the clock, or NULL for a no-op
 * @param exclusive non-zero for a batch containing a prefix delete, zero for any other
 */
void tidesdb_mvcc_commit_gate_lock(tidesdb_mvcc_t *m, int exclusive);

/**
 * tidesdb_mvcc_commit_gate_unlock
 * release the commit gate
 * @param m the clock, or NULL for a no-op
 */
void tidesdb_mvcc_commit_gate_unlock(tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_next_seq
 * draw and consume the next commit sequence number
 * @param m the clock
 * @return the assigned sequence number (monotonic, starting at 1)
 */
uint64_t tidesdb_mvcc_next_seq(tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_current_seq
 * the next sequence number that would be assigned; a snapshot taken at begin is this minus one, and
 * the highest seq already assigned is this minus one
 * @param m the clock
 * @return the current value of the sequence counter
 */
uint64_t tidesdb_mvcc_current_seq(const tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_mark
 * record whether a sequence has committed in the ring, advancing the ring high-water mark
 * @param m the clock
 * @param seq the sequence to mark (a zero seq is ignored)
 * @param committed non-zero to mark committed, zero to mark in-progress
 */
void tidesdb_mvcc_mark(tidesdb_mvcc_t *m, uint64_t seq, int committed);

/**
 * tidesdb_mvcc_committed
 * whether a sequence counts as committed -- its ring slot reads committed, or it has fallen more
 * than a ring capacity behind the high-water mark (evicted, so it already applied and must be
 * committed)
 * @param m the clock
 * @param seq the sequence to test
 * @return 1 if committed, 0 otherwise (including a zero seq)
 */
int tidesdb_mvcc_committed(const tidesdb_mvcc_t *m, uint64_t seq);

/**
 * tidesdb_mvcc_visible
 * the full read-visibility predicate: a nonzero seq at or below the reader's snapshot that has
 * committed
 * @param m the clock
 * @param seq the version's sequence number
 * @param snapshot the reader's snapshot sequence
 * @return 1 if the version is visible to the reader, 0 otherwise
 */
int tidesdb_mvcc_visible(const tidesdb_mvcc_t *m, uint64_t seq, uint64_t snapshot);

/**
 * tidesdb_mvcc_reseed
 * after recovery, advance the clock so the next seq follows the highest recovered seq and the ring
 * high-water covers it, so every recovered seq reads committed via the eviction rule
 * @param m the clock
 * @param max_recovered_seq the highest sequence seen during recovery
 */
void tidesdb_mvcc_reseed(tidesdb_mvcc_t *m, uint64_t max_recovered_seq);

/**
 * tidesdb_mvcc_get_stats
 * snapshot the clock's activity counters
 * @param m the clock
 * @param out receives the counters (zeroed if m is NULL)
 */
void tidesdb_mvcc_get_stats(const tidesdb_mvcc_t *m, tidesdb_mvcc_stats_t *out);

/**
 * tidesdb_mvcc_reserve
 * try to claim one write key's reservation slot for commit_seq (first-committer-wins). the caller
 * loops this over its write set and, on a conflict, releases the slots it already claimed and
 * aborts. conflict is decided from the slot alone: an in-flight occupant, or a committed seq past
 * the version this txn read whose fingerprint matches (a real same-key writer) or that is newer
 * than the oldest open snapshot (a possible concurrent writer of a colliding key)
 * @param m the clock
 * @param key_hash the 64-bit hash of the write key (slot index and fingerprint are derived from it)
 * @param commit_seq this committer's sequence number
 * @param read_base the seq this txn read for the key, or its snapshot seq for a blind write
 * @param min_snapshot the oldest open snapshot seq among active txns
 * @return 1 if the slot was claimed, 0 on conflict
 */
int tidesdb_mvcc_reserve(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t commit_seq,
                         uint64_t read_base, uint64_t min_snapshot);

/**
 * tidesdb_mvcc_prepared_hold
 * hold seq in flight past the ring's eviction rule until the batch that drew it is decided
 * @param m the clock
 * @param seq the sequence the prepare drew and reserves its keys with, which must not be zero
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_CONFLICT when every hold slot is taken
 */
int tidesdb_mvcc_prepared_hold(tidesdb_mvcc_t *m, uint64_t seq);

/**
 * tidesdb_mvcc_prepared_release
 * let go of seq once phase two has decided the batch, so the eviction rule governs it again
 * @param m the clock
 * @param seq the sequence handed to tidesdb_mvcc_prepared_hold; one never held is ignored
 */
void tidesdb_mvcc_prepared_release(tidesdb_mvcc_t *m, uint64_t seq);

/**
 * tidesdb_mvcc_release
 * release a write key's reservation slot if it still holds commit_seq; a slot now owned by a newer
 * committer is left alone
 * @param m the clock
 * @param key_hash the 64-bit hash of the write key
 * @param commit_seq the sequence this committer claimed the slot with
 */
void tidesdb_mvcc_release(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t commit_seq);

/**
 * tidesdb_mvcc_reassign
 * move a write key's reservation from the sequence that claimed it to the one that finally
 * committed it, keeping the hold unbroken across the change. two-phase commit needs this because a
 * prepare claims the slot with the sequence it drew then, while the batch commits at a fresh
 * sequence decided in phase two -- a slot left naming the prepare's sequence names one that is
 * never resolved, and every later writer of that key reads it as an in-flight committer and takes a
 * conflict that has no writer behind it
 * @param m the clock
 * @param key_hash the 64-bit hash of the write key
 * @param from_seq the sequence currently holding the slot
 * @param to_seq the sequence to hand it to
 */
void tidesdb_mvcc_reassign(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t from_seq,
                           uint64_t to_seq);

#endif /* __TIDESDB_TXN_MVCC_H__ */
