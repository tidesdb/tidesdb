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
 * counter, the commit-status ring that records whether each recent seq committed, the watermark
 * every reader's ceiling is taken from, and the claim set that gives commits their write-write and
 * read-write checks against one another, over keys and over intervals alike. it is pure: it knows
 * sequence numbers, key bytes and precomputed key hashes, not engine structs, so it builds and
 * unit-tests standalone. the transaction manager draws seqs and snapshots from it, claims and
 * validates a txn's keys and intervals through it, and marks a commit's seq committed. */

/* the commit-status ring records the last this-many sequence numbers, each as in progress,
 * committed or aborted. the ring is what the watermark reads, and it is read only above the
 * watermark; no sequence is drawn a ring's width above it, so a slot always describes the sequence
 * asked about */
#define TDB_MVCC_COMMIT_RING_SIZE 65536

/* the in-flight claim set. every commit at repeatable read and above claims the keys it writes
 * before it draws its sequence and validates after, and a prepare keeps its claims until phase two
 * decides it. a claim is a node the committer owns, chained from the bucket its key hashes to and
 * compared by bytes, so the set has no capacity of its own and never mistakes one key for another.
 * the chains are guarded by striped locks; a stripe is a set of buckets sharing one */
#define TDB_MVCC_CLAIM_BUCKETS ((uint32_t)1 << 18)
#define TDB_MVCC_CLAIM_STRIPES ((uint32_t)1 << 12)

/* a chain longer than this is refused rather than walked; nothing but a fault reaches it */
#define TDB_MVCC_CLAIM_WALK_MAX ((uint32_t)1 << 20)

/* the commits in flight an interval is checked against before the walk refuses rather than trusts;
 * the list holds the committers of the moment, so nothing but a fault reaches it */
#define TDB_MVCC_INFLIGHT_WALK_MAX ((uint32_t)1 << 16)

/* what a claim is for. a write claim is what first-committer-wins and read validation look for; a
 * read claim is taken only by a prepare at repeatable read or above, for the keys it read, so a
 * writer of one of them is refused while the prepare is undecided -- the batch cannot be the one to
 * yield once it has voted */
#define TDB_MVCC_CLAIM_WRITE 0
#define TDB_MVCC_CLAIM_READ  1

/* what an owner's sequence reads as while it is between drawing and publishing, and once its batch
 * is prepared and will commit above everything current */
#define TDB_MVCC_SEQ_DRAWING (UINT64_MAX - 1)
#define TDB_MVCC_SEQ_FUTURE  UINT64_MAX

/* intervals held at once, by commits in flight and two-phase transactions in doubt. both are rare,
 * so a table this size is not a bound a real workload meets -- and a commit that cannot take a slot
 * reports a conflict rather than proceeding unchecked */
#define TDB_MVCC_MAX_RANGE_RESERVATIONS 32

/* the longest bound the table stores, which is the public limit on an interval delete's bounds --
 * the two are the same number because this table is the reason for it. a bound past it is turned
 * away at the api, so an interval refused here is one the table had no free slot for */
#define TDB_MVCC_MAX_RANGE_BYTES TDB_MAX_RANGE_BOUND_SIZE

typedef struct tidesdb_mvcc tidesdb_mvcc_t;
typedef struct tidesdb_mvcc_claim tidesdb_mvcc_claim_t;
typedef struct tidesdb_mvcc_commit tidesdb_mvcc_commit_t;

/**
 * tidesdb_mvcc_commit
 * one commit's claims and the sequence they are ordered by, in flight from the claim to the release
 * @param seq 0 until the draw, TDB_MVCC_SEQ_DRAWING during it, the drawn sequence after, and
 *            TDB_MVCC_SEQ_FUTURE once the batch is prepared
 * @param claims the claims, an array the owner keeps in place until tidesdb_mvcc_unclaim returns;
 *               sorted by family and key by the claim call
 * @param n_claims how many
 * @param next_inflight the next commit in the clock's list of commits in flight, which is what an
 *                      interval is checked against
 * @param held non-zero while the commit is in flight -- from the claim call to the release --
 *             whether or not it holds any key, since it may hold intervals alone
 */
struct tidesdb_mvcc_commit
{
    _Atomic(uint64_t) seq;
    tidesdb_mvcc_claim_t *claims;
    int n_claims;
    tidesdb_mvcc_commit_t *next_inflight;
    int held;
};

/**
 * tidesdb_mvcc_claim
 * one key a commit holds, chained from the bucket its hash selects
 * @param hash the key's hash, which selects the bucket and screens a comparison
 * @param owner the commit holding it
 * @param key the key bytes, borrowed from the owner for the claim's life
 * @param key_size length of key
 * @param cf_index the family the key belongs to
 * @param kind TDB_MVCC_CLAIM_WRITE or TDB_MVCC_CLAIM_READ
 * @param next the next claim in the bucket's chain
 */
struct tidesdb_mvcc_claim
{
    uint64_t hash;
    tidesdb_mvcc_commit_t *owner;
    const uint8_t *key;
    uint32_t key_size;
    uint32_t cf_index;
    uint8_t kind;
    tidesdb_mvcc_claim_t *next;
};

/**
 * tidesdb_mvcc_create
 * create the MVCC clock with the sequence counter at 1, an empty commit ring, the watermark at
 * zero, and an empty claim set
 * @return the clock, or NULL on allocation failure
 */
tidesdb_mvcc_t *tidesdb_mvcc_create(void);

/**
 * tidesdb_mvcc_destroy
 * free the MVCC clock, its ring and its claim set; the claims themselves belong to their owners
 * @param m the clock, may be NULL
 */
void tidesdb_mvcc_destroy(tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_current_seq
 * the next sequence number that would be assigned; the highest seq already drawn is this minus one,
 * which may still be in flight, so a reader's ceiling comes from tidesdb_mvcc_visible_seq instead
 * @param m the clock
 * @return the current value of the sequence counter
 */
uint64_t tidesdb_mvcc_current_seq(const tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_visible_seq
 * the watermark, the highest sequence below which every drawn sequence has committed or aborted.
 * a ceiling taken from it never admits a sequence still in flight, so a snapshot holds still for
 * its whole life and no reader sees a batch half applied. a sequence that committed above it is
 * not yet in any new ceiling, which is the lag of an in-order publish, bounded by the slowest
 * commit in flight
 * @param m the clock, or NULL for zero
 * @return the watermark
 */
uint64_t tidesdb_mvcc_visible_seq(const tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_mark
 * record a drawn sequence in the ring as in progress, or as committed once its batch has been
 * applied in full, and on committed carry the watermark forward over every decided sequence
 * @param m the clock
 * @param seq the sequence to mark (a zero seq is ignored)
 * @param committed non-zero to mark committed, zero to mark in-progress
 */
void tidesdb_mvcc_mark(tidesdb_mvcc_t *m, uint64_t seq, int committed);

/**
 * tidesdb_mvcc_watermark_ref
 * the watermark itself, for a module that has to wait on it without knowing the clock -- the flush,
 * which builds only once every sequence in a memtable is decided
 * @param m the clock, which must outlive every use of the reference
 * @return the watermark, read with an acquire load, or NULL for a NULL clock
 */
const _Atomic(uint64_t) *tidesdb_mvcc_watermark_ref(const tidesdb_mvcc_t *m);

/**
 * tidesdb_mvcc_wait_visible
 * wait until the watermark has passed a committed sequence, so that a commit returns only once its
 * writes are inside every ceiling taken afterwards, the caller's own next transaction included. the
 * wait is on the commits in flight below seq, each of which decides its sequence within its own
 * commit window
 * @param m the clock
 * @param seq the sequence this caller marked committed
 */
void tidesdb_mvcc_wait_visible(const tidesdb_mvcc_t *m, uint64_t seq);

/**
 * tidesdb_mvcc_mark_aborted
 * record that a drawn sequence will never commit, and carry the watermark forward. every sequence
 * drawn must end here or in a committed mark, since the watermark waits on each one; a prepare's
 * sequence ends here as soon as its record is durable, because phase two commits at a fresh one
 * @param m the clock
 * @param seq the sequence to mark (a zero seq is ignored)
 */
void tidesdb_mvcc_mark_aborted(tidesdb_mvcc_t *m, uint64_t seq);

/**
 * tidesdb_mvcc_reseed
 * after recovery, advance the clock so the next seq follows the highest recovered seq and stand
 * the watermark at it so every recovered version is readable
 * @param m the clock
 * @param max_recovered_seq the highest sequence seen during recovery
 */
void tidesdb_mvcc_reseed(tidesdb_mvcc_t *m, uint64_t max_recovered_seq);

/**
 * tidesdb_mvcc_commit_init
 * arm a commit's claim record over an array of claims the owner keeps in place until unclaimed
 * @param commit the record, owned by the caller
 * @param claims the claims, filled with tidesdb_mvcc_claim_init; may be NULL when n_claims is 0
 * @param n_claims how many
 */
void tidesdb_mvcc_commit_init(tidesdb_mvcc_commit_t *commit, tidesdb_mvcc_claim_t *claims,
                              int n_claims);

/**
 * tidesdb_mvcc_claim_init
 * fill one claim; the key bytes are borrowed and must outlive the claim
 * @param claim the claim to fill
 * @param cf_index the family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @param kind TDB_MVCC_CLAIM_WRITE or TDB_MVCC_CLAIM_READ
 * @param hash the key's 64-bit hash over the family and the bytes
 */
void tidesdb_mvcc_claim_init(tidesdb_mvcc_claim_t *claim, uint32_t cf_index, const uint8_t *key,
                             uint32_t key_size, uint8_t kind, uint64_t hash);

/**
 * tidesdb_mvcc_claim
 * enter a commit into the set of commits in flight and take every claim of it, in one order shared
 * by every commit, or none of them. a write claim is refused by another owner's read claim on the
 * key, and, when this commit promises first-committer-wins, by another owner's write claim on it or
 * an interval another owner holds over it; a read claim is never refused. a refusal leaves nothing
 * behind. the claims are taken before the commit draws its sequence, which is what lets a validator
 * with a lower sequence be sure of seeing them. a commit with no claims still enters the set, so
 * the intervals it holds alone can be checked against
 * @param m the clock
 * @param commit the armed record, whose claims are sorted in place
 * @param first_committer_wins non-zero for snapshot and serializable, zero for repeatable read
 * @return 1 when every claim holds, 0 when one was refused
 */
int tidesdb_mvcc_claim(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit, int first_committer_wins);

/**
 * tidesdb_mvcc_claim_range
 * hold an interval a commit deletes against every other commit in flight, once its keys are claimed
 * and before its sequence is drawn. under first-committer-wins the interval is refused when another
 * owner holds an interval meeting it or a claim of any kind on a key inside it -- a writer in
 * flight it would overwrite, or a prepared reader it would invalidate; without that promise it is
 * entered and refuses nothing, as a repeatable-read write claim is, so the writers that meet it
 * decide. a bound longer than the table stores or a full table refuses it either way. the hold is
 * entered before the check, so a point writer claiming a key inside it in the same instant finds
 * it, and one of the two yields whichever way they interleave
 * @param m the clock
 * @param commit the record, already entered by tidesdb_mvcc_claim
 * @param cf_index the family the interval belongs to
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for open above
 * @param hi_size length of hi, 0 for open above
 * @param first_committer_wins non-zero for snapshot and serializable, zero for repeatable read and
 *                             for a batch adopted after a restart, which is registered rather than
 *                             contested
 * @return 1 when the interval is held, 0 when it was refused
 */
int tidesdb_mvcc_claim_range(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit, uint32_t cf_index,
                             const uint8_t *lo, size_t lo_size, const uint8_t *hi, size_t hi_size,
                             int first_committer_wins);

/**
 * tidesdb_mvcc_draw
 * draw and mark in progress the commit's sequence, publishing it on the record. the record reads as
 * drawing between the two, so a validator that meets it waits the few instructions out rather than
 * mistaking an undrawn sequence for a higher one
 * @param m the clock
 * @param commit the record, or NULL to draw a sequence that no claim is ordered by
 * @return the drawn sequence
 */
uint64_t tidesdb_mvcc_draw(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit);

/**
 * tidesdb_mvcc_commit_prepared
 * mark a commit's claims and intervals as belonging to a prepared batch, whose commit will come at
 * a sequence above everything current. a reader of one of its keys is serialized before it and its
 * read stands; a writer of one still meets its write claims, and a writer of a key it read meets
 * its read claims
 * @param commit the record of the prepared batch
 */
void tidesdb_mvcc_commit_prepared(tidesdb_mvcc_commit_t *commit);

/**
 * tidesdb_mvcc_read_stale
 * whether another commit in flight, under a sequence lower than this commit's, holds a write claim
 * on a key this commit read or an interval covering it -- the writer whose version this commit read
 * before it existed, or the delete that took what it read. asked after this commit's draw, for each
 * key of its read set, beside the store's own answer
 * @param m the clock
 * @param commit this commit, with its sequence drawn
 * @param cf_index the family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @param hash the key's hash, as given to the claims
 * @return 1 when such a commit holds the key, 0 otherwise
 */
int tidesdb_mvcc_read_stale(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                            uint32_t cf_index, const uint8_t *key, uint32_t key_size,
                            uint64_t hash);

/**
 * tidesdb_mvcc_range_stale
 * whether another commit in flight, under a sequence lower than this commit's, holds a write claim
 * on a key inside an interval this commit scanned or deletes, or an interval meeting it -- a
 * version that will exist inside the interval below this commit's position, which the store cannot
 * show yet. for an interval this commit deletes, another owner's read claim inside it refuses it at
 * any sequence, since a prepared reader cannot be the one to yield. asked after this commit's draw
 * @param m the clock
 * @param commit this commit, with its sequence drawn
 * @param cf_index the family the interval belongs to
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for open above
 * @param hi_size length of hi
 * @param writing non-zero for an interval this commit deletes, zero for one it scanned
 * @return 1 when such a commit holds something inside the interval, 0 otherwise
 */
int tidesdb_mvcc_range_stale(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                             uint32_t cf_index, const uint8_t *lo, size_t lo_size,
                             const uint8_t *hi, size_t hi_size, int writing);

/**
 * tidesdb_mvcc_write_blocked
 * whether a key this commit writes is held against it -- by another owner's read claim on it, a
 * prepared batch that read it and cannot yield, at any level; or, when this commit promises
 * first-committer-wins, by an interval another commit in flight holds over it under a sequence
 * lower than this commit's. asked after this commit's draw, for each key of its write set
 * @param m the clock
 * @param commit this commit, with its sequence drawn
 * @param cf_index the family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @param hash the key's hash, as given to the claims
 * @param first_committer_wins non-zero for snapshot and serializable, zero for repeatable read
 * @return 1 when the key is held against this commit, 0 otherwise
 */
int tidesdb_mvcc_write_blocked(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                               uint32_t cf_index, const uint8_t *key, uint32_t key_size,
                               uint64_t hash, int first_committer_wins);

/**
 * tidesdb_mvcc_unclaim
 * drop every claim and interval of a commit and take it out of the set in flight, once its sequence
 * is decided or its batch rolled back; the claims array is the caller's to free afterwards
 * @param m the clock
 * @param commit the record; one that never entered the set is a no-op
 */
void tidesdb_mvcc_unclaim(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit);

/**
 * tidesdb_mvcc_holds
 * whether a commit is in flight -- entered by tidesdb_mvcc_claim and not yet released -- and so has
 * something for tidesdb_mvcc_unclaim or tidesdb_mvcc_orphan_claims to do
 * @param commit the record, or NULL for zero
 * @return 1 when in flight, 0 otherwise
 */
int tidesdb_mvcc_holds(const tidesdb_mvcc_commit_t *commit);

/**
 * tidesdb_mvcc_orphan_claims
 * keep a prepared batch's claims and intervals held after the handle holding them is freed
 * undecided. the batch is durable and a later open may still commit it, so a write landing under
 * one of its keys now would be overwritten by a decision made afterwards; the clock takes copies of
 * the claims, keys included, re-owns the intervals, and holds them for its own life in the handle's
 * place. the caller's claims are unlinked and may be freed
 * @param m the clock
 * @param commit the prepared batch's record, whose claims are given up either way
 * @return 1 when the copies hold, 0 when they could not be made and the keys are left unheld
 */
int tidesdb_mvcc_orphan_claims(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit);

#endif /* __TIDESDB_TXN_MVCC_H__ */
