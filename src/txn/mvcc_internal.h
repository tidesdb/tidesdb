/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_MVCC_INTERNAL_H__
#define __TIDESDB_TXN_MVCC_INTERNAL_H__

/* the clock's state, shared by the files that implement it and by nothing else */
#include "mvcc.h"

/**
 * mvcc_range_hold_t
 * one interval held against concurrent point writes and other intervals while its commit is in
 * flight or its batch in doubt
 * @param lo the inclusive lower bound
 * @param hi the exclusive upper bound, meaningful only when hi_size is non-zero
 * @param lo_size length of lo
 * @param hi_size length of hi, zero when the interval is open above
 * @param cf_index the family the interval belongs to
 * @param owner the commit holding it, whose sequence orders it against a validator
 * @param in_use non-zero while the slot holds an interval, which is stated rather than inferred
 *        from a length so an open bound is not mistaken for a free slot
 */
typedef struct
{
    uint8_t lo[TDB_MVCC_MAX_RANGE_BYTES];
    uint8_t hi[TDB_MVCC_MAX_RANGE_BYTES];
    size_t lo_size;
    size_t hi_size;
    uint32_t cf_index;
    const tidesdb_mvcc_commit_t *owner;
    int in_use;
} mvcc_range_hold_t;

/**
 * mvcc_orphan_t
 * the claims of one prepared batch whose handle was freed undecided, copied so they outlive it
 * @param commit the record the copied claims chain under and the batch's intervals are owned by,
 *               a prepared batch's for good
 * @param claims the copied claims
 * @param keys the copied key bytes, one per claim
 * @param n how many
 * @param scans the copied scanned intervals
 * @param scan_bytes each interval's bounds, lower then upper in one allocation
 * @param n_scans how many
 * @param next the next orphan
 */
typedef struct mvcc_orphan
{
    tidesdb_mvcc_commit_t commit;
    tidesdb_mvcc_claim_t *claims;
    uint8_t **keys;
    int n;
    tidesdb_mvcc_range_t *scans;
    uint8_t **scan_bytes;
    int n_scans;
    struct mvcc_orphan *next;
} mvcc_orphan_t;

/* the count of commits writing without claims is split over this many counters, each on a line of
 * its own, since every such commit moves one twice and a single counter would be one line every
 * core fights for; a validating commit, which asks far less often, reads them all */
#define MVCC_UNCLAIMED_SHARDS 16
#define MVCC_LINE_BYTES       64

/**
 * mvcc_shard_t
 * one counter alone on its line
 * @param n the count
 * @param pad the rest of the line
 */
typedef struct
{
    _Atomic(int) n;
    char pad[MVCC_LINE_BYTES - sizeof(_Atomic(int))];
} mvcc_shard_t;

/**
 * tidesdb_mvcc
 * the MVCC clock state. the locks nest in one order wherever two are held -- a stripe, then the
 * interval table, then the in-flight list -- so no two committers can wait on each other
 * @param global_seq monotonic sequence counter; the next seq to assign
 * @param ring commit-status ring indexed by seq modulo capacity, each slot the packed sequence it
 *             describes and its state
 * @param ring_capacity length of ring, the most sequences that can be in flight above the watermark
 * @param visible_seq the watermark, the highest sequence below which every sequence is decided;
 *                    what every reader's ceiling is taken from
 * @param claim_heads the in-flight claim set, one chain head per bucket of a key's hash
 * @param claim_stripes the mutexes guarding the chains, one per stripe of buckets
 * @param inflight every commit between its claim and its release, which is what an interval is
 *                 checked against, since an interval has no one chain to look in
 * @param inflight_lock guards the in-flight list
 * @param range_holds the intervals held by commits in flight and prepares undecided
 * @param range_count how many slots are taken, so a database that never deletes a range reads one
 *                    counter
 * @param range_lock guards the interval table
 * @param orphans the claims of prepared batches whose handles were freed undecided, held for the
 *                clock's life in the handles' place
 * @param orphan_lock guards the orphan list
 * @param unclaimed how many commits are between drawing and deciding a sequence without claims,
 *                  which read committed and below write without, split over shards; a validating
 *                  commit cannot see one below it in the claims, only in the store once applied
 * @param read_holders how many commits in flight hold a read claim or a scanned interval, which
 * only a prepare at repeatable read or above does, so a writer finds none to check with one load
 */
struct tidesdb_mvcc
{
    _Atomic(uint64_t) global_seq;
    _Atomic(uint64_t) *ring;
    size_t ring_capacity;
    _Atomic(uint64_t) visible_seq;
    tidesdb_mvcc_claim_t **claim_heads;
    pthread_mutex_t *claim_stripes;
    tidesdb_mvcc_commit_t *inflight;
    pthread_mutex_t inflight_lock;
    mvcc_range_hold_t range_holds[TDB_MVCC_MAX_RANGE_RESERVATIONS];
    _Atomic(int) range_count;
    pthread_mutex_t range_lock;
    mvcc_orphan_t *orphans;
    pthread_mutex_t orphan_lock;
    _Atomic(int) read_holders;
    mvcc_shard_t unclaimed[MVCC_UNCLAIMED_SHARDS];
};

/**
 * mvcc_claim_bucket
 * the bucket a key's claims chain from
 * @param hash the key's hash
 * @return the bucket index
 */
uint32_t mvcc_claim_bucket(uint64_t hash);

/**
 * mvcc_claim_stripe
 * the lock guarding a bucket's chain
 * @param m the clock
 * @param bucket the bucket
 * @return the stripe mutex
 */
pthread_mutex_t *mvcc_claim_stripe(tidesdb_mvcc_t *m, uint32_t bucket);

/**
 * mvcc_claim_unlink
 * unlink one claim from its chain, under the stripe lock the caller holds
 * @param m the clock
 * @param bucket the claim's bucket
 * @param claim the claim
 */
void mvcc_claim_unlink(tidesdb_mvcc_t *m, uint32_t bucket, tidesdb_mvcc_claim_t *claim);

/**
 * mvcc_orphan_free
 * free one orphan's copies, its claims already off the chains or the chains going with it
 * @param o the orphan
 */
void mvcc_orphan_free(mvcc_orphan_t *o);

#endif /* __TIDESDB_TXN_MVCC_INTERNAL_H__ */
