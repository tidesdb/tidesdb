/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "mvcc.h"

#include <stdlib.h>
#include <string.h>

#include "base/keycmp.h"   /* tdb_key_cmp, the one byte-wise key order */
#include "base/lockfree.h" /* the writer-preferring rwlock the commit gate is */

/* commit-ring slot states */
#define TDB_MVCC_IN_PROGRESS 0
#define TDB_MVCC_COMMITTED   1

/* reservation slot pack/unpack -- 16-bit fingerprint in the high bits, 48-bit commit_seq in the low
 */
#define TDB_MVCC_RES_SEQ_MASK    ((1ULL << TDB_MVCC_RES_SEQ_BITS) - 1)
#define TDB_MVCC_RES_FP(packed)  ((uint16_t)((packed) >> TDB_MVCC_RES_SEQ_BITS))
#define TDB_MVCC_RES_SEQ(packed) ((packed)&TDB_MVCC_RES_SEQ_MASK)
#define TDB_MVCC_RES_PACK(fp, seq) \
    (((uint64_t)(fp) << TDB_MVCC_RES_SEQ_BITS) | ((seq)&TDB_MVCC_RES_SEQ_MASK))

/**
 * mvcc_range_reservation_t
 * one interval held against concurrent point writes while its transaction is unresolved
 * @param lo the inclusive lower bound
 * @param hi the exclusive upper bound, meaningful only when hi_size is non-zero
 * @param lo_size length of lo
 * @param hi_size length of hi, zero when the interval is open above
 * @param cf_index the family the interval belongs to
 * @param owner_seq the sequence the holding transaction reserved at
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
    uint64_t owner_seq;
    int in_use;
} mvcc_range_reservation_t;

/**
 * tidesdb_mvcc
 * the MVCC clock state
 * @param global_seq monotonic sequence counter; the next seq to assign
 * @param ring commit-status ring indexed by seq modulo capacity
 * @param ring_max_seq highest sequence recorded in the ring, the eviction high-water mark
 * @param ring_capacity length of ring, the eviction window width
 * @param reservation write-reservation table indexed by a key hash
 * @param stat_seqs count of commit sequences drawn
 * @param stat_marks count of sequences marked committed
 * @param stat_res_won count of write reservations that claimed their slot
 * @param stat_res_lost count of write reservations that lost to a concurrent writer
 * @param prepared_hold sequences of prepared batches phase two has not decided, which the ring's
 *                      eviction rule may not call committed; a zero slot is free
 * @param prepared_hold_count how many slots are taken, so the ordinary case of none reads one
 *                            counter rather than scanning the table
 */
struct tidesdb_mvcc
{
    _Atomic(uint64_t) global_seq;
    _Atomic(uint8_t) *ring;
    _Atomic(uint64_t) ring_max_seq;
    size_t ring_capacity;
    _Atomic(uint64_t) *reservation;
    _Atomic(uint64_t) stat_seqs;
    _Atomic(uint64_t) stat_marks;
    _Atomic(uint64_t) stat_res_won;
    _Atomic(uint64_t) stat_res_lost;
    tdb_wprwlock_t commit_gate;
    _Atomic(uint64_t) prepared_hold[TDB_MVCC_MAX_PREPARED_HOLDS];
    _Atomic(int) prepared_hold_count;
    mvcc_range_reservation_t range_res[TDB_MVCC_MAX_RANGE_RESERVATIONS];
    _Atomic(int) range_res_count;
    pthread_mutex_t range_lock;
};

tidesdb_mvcc_t *tidesdb_mvcc_create(void)
{
    tidesdb_mvcc_t *m = malloc(sizeof(*m));
    if (!m) return NULL;

    (void)tdb_wprwlock_init(&m->commit_gate);

    for (int i = 0; i < TDB_MVCC_MAX_PREPARED_HOLDS; i++) atomic_init(&m->prepared_hold[i], 0);
    atomic_init(&m->prepared_hold_count, 0);

    memset(m->range_res, 0, sizeof(m->range_res));
    atomic_init(&m->range_res_count, 0);
    pthread_mutex_init(&m->range_lock, NULL);

    m->ring = malloc(TDB_MVCC_COMMIT_RING_SIZE * sizeof(_Atomic(uint8_t)));
    if (!m->ring)
    {
        free(m);
        return NULL;
    }
    for (size_t i = 0; i < TDB_MVCC_COMMIT_RING_SIZE; i++)
        atomic_init(&m->ring[i], TDB_MVCC_IN_PROGRESS);

    m->reservation = calloc(TDB_MVCC_RESERVATION_SLOTS, sizeof(_Atomic(uint64_t)));
    if (!m->reservation)
    {
        free(m->ring);
        free(m);
        return NULL;
    }

    atomic_init(&m->global_seq, 1);
    atomic_init(&m->ring_max_seq, 0);
    m->ring_capacity = TDB_MVCC_COMMIT_RING_SIZE;
    atomic_init(&m->stat_seqs, 0);
    atomic_init(&m->stat_marks, 0);
    atomic_init(&m->stat_res_won, 0);
    atomic_init(&m->stat_res_lost, 0);
    return m;
}

/* whether a held interval covers a key */
static int mvcc_range_covers(const mvcc_range_reservation_t *r, const uint8_t *key,
                             const size_t key_size)
{
    if (tdb_key_cmp(r->lo, r->lo_size, key, key_size) > 0) return 0;
    if (r->hi_size == 0) return 1; /* open above */
    return tdb_key_cmp(key, key_size, r->hi, r->hi_size) < 0;
}

/* whether two half-open intervals intersect. an open upper bound is above every bound that can be
 * spelled, so it can never be the thing that separates them */
static int mvcc_ranges_overlap(const mvcc_range_reservation_t *r, const uint8_t *lo,
                               const size_t lo_size, const uint8_t *hi, const size_t hi_size)
{
    if (hi_size > 0 && tdb_key_cmp(hi, hi_size, r->lo, r->lo_size) <= 0) return 0;
    if (r->hi_size > 0 && tdb_key_cmp(r->hi, r->hi_size, lo, lo_size) <= 0) return 0;
    return 1;
}

int tidesdb_mvcc_reserve_range(tidesdb_mvcc_t *m, const uint32_t cf_index, const uint8_t *lo,
                               const size_t lo_size, const uint8_t *hi, const size_t hi_size,
                               const uint64_t owner_seq)
{
    if (!m || !lo || lo_size == 0) return 0;
    /* refused rather than truncated, because a truncated bound describes a wider interval than the
     * caller asked for and would block writes they never meant to block */
    if (lo_size > TDB_MVCC_MAX_RANGE_BYTES || hi_size > TDB_MVCC_MAX_RANGE_BYTES) return 0;

    pthread_mutex_lock(&m->range_lock);
    int slot = -1;
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS; i++)
    {
        if (!m->range_res[i].in_use)
        {
            if (slot < 0) slot = i;
            continue;
        }
        /* another transaction already holds an interval this one meets. a transaction may hold
         * several of its own, so its own slots are not in its way */
        if (m->range_res[i].owner_seq != owner_seq && m->range_res[i].cf_index == cf_index &&
            mvcc_ranges_overlap(&m->range_res[i], lo, lo_size, hi, hi_size))
        {
            pthread_mutex_unlock(&m->range_lock);
            return 0;
        }
    }
    if (slot < 0)
    {
        pthread_mutex_unlock(&m->range_lock);
        return 0; /* a full table conflicts rather than letting the commit past unchecked */
    }

    memcpy(m->range_res[slot].lo, lo, lo_size);
    m->range_res[slot].lo_size = lo_size;
    if (hi_size) memcpy(m->range_res[slot].hi, hi, hi_size);
    m->range_res[slot].hi_size = hi_size;
    m->range_res[slot].cf_index = cf_index;
    m->range_res[slot].owner_seq = owner_seq;
    /* published last, since it is what a reader takes as the slot being live */
    m->range_res[slot].in_use = 1;
    atomic_fetch_add_explicit(&m->range_res_count, 1, memory_order_release);
    pthread_mutex_unlock(&m->range_lock);
    return 1;
}

void tidesdb_mvcc_release_range(tidesdb_mvcc_t *m, const uint64_t owner_seq)
{
    if (!m) return;
    if (atomic_load_explicit(&m->range_res_count, memory_order_acquire) == 0) return;

    pthread_mutex_lock(&m->range_lock);
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS; i++)
    {
        if (!m->range_res[i].in_use || m->range_res[i].owner_seq != owner_seq) continue;
        m->range_res[i].in_use = 0;
        atomic_fetch_sub_explicit(&m->range_res_count, 1, memory_order_release);
    }
    pthread_mutex_unlock(&m->range_lock);
}

int tidesdb_mvcc_range_blocks(const tidesdb_mvcc_t *m, const uint32_t cf_index, const uint8_t *key,
                              const size_t key_size, const uint64_t owner_seq)
{
    if (!m || !key) return 0;
    if (atomic_load_explicit(&m->range_res_count, memory_order_acquire) == 0) return 0;

    pthread_mutex_t *lock = (pthread_mutex_t *)&m->range_lock;
    pthread_mutex_lock(lock);
    int blocked = 0;
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS && !blocked; i++)
    {
        if (!m->range_res[i].in_use) continue;
        if (m->range_res[i].owner_seq == owner_seq) continue;
        if (m->range_res[i].cf_index != cf_index) continue;
        blocked = mvcc_range_covers(&m->range_res[i], key, key_size);
    }
    pthread_mutex_unlock(lock);
    return blocked;
}

void tidesdb_mvcc_commit_gate_lock(tidesdb_mvcc_t *m, const int exclusive)
{
    if (!m) return;
    /* the exclusive side is the rare one and must not be starved -- a range delete waiting behind
     * an unbroken stream of point writes would never run */
    if (exclusive)
        tdb_wprwlock_wrlock(&m->commit_gate);
    else
        tdb_wprwlock_rdlock(&m->commit_gate);
}

void tidesdb_mvcc_commit_gate_unlock(tidesdb_mvcc_t *m)
{
    if (m) tdb_wprwlock_unlock(&m->commit_gate);
}

void tidesdb_mvcc_destroy(tidesdb_mvcc_t *m)
{
    if (!m) return;
    tdb_wprwlock_destroy(&m->commit_gate);
    pthread_mutex_destroy(&m->range_lock);
    free(m->ring);
    free(m->reservation);
    free(m);
}

uint64_t tidesdb_mvcc_next_seq(tidesdb_mvcc_t *m)
{
    atomic_fetch_add_explicit(&m->stat_seqs, 1, memory_order_relaxed);
    return atomic_fetch_add_explicit(&m->global_seq, 1, memory_order_acq_rel);
}

uint64_t tidesdb_mvcc_current_seq(const tidesdb_mvcc_t *m)
{
    return atomic_load_explicit(&m->global_seq, memory_order_acquire);
}

/* advance ring_max_seq to seq if seq is higher, with a cas loop so a concurrent higher mark wins */
static void mvcc_bump_max(tidesdb_mvcc_t *m, uint64_t seq)
{
    uint64_t cur = atomic_load_explicit(&m->ring_max_seq, memory_order_acquire);
    while (seq > cur)
    {
        if (atomic_compare_exchange_weak_explicit(&m->ring_max_seq, &cur, seq, memory_order_release,
                                                  memory_order_acquire))
            break;
    }
}

void tidesdb_mvcc_mark(tidesdb_mvcc_t *m, uint64_t seq, int committed)
{
    if (!m || seq == 0) return;
    mvcc_bump_max(m, seq);
    const uint8_t state = committed ? TDB_MVCC_COMMITTED : TDB_MVCC_IN_PROGRESS;
    atomic_store_explicit(&m->ring[seq % m->ring_capacity], state, memory_order_release);
    if (committed) atomic_fetch_add_explicit(&m->stat_marks, 1, memory_order_relaxed);
}

void tidesdb_mvcc_get_stats(const tidesdb_mvcc_t *m, tidesdb_mvcc_stats_t *out)
{
    if (!out) return;
    if (!m)
    {
        out->seqs_assigned = 0;
        out->commits_marked = 0;
        out->reservations_won = 0;
        out->reservations_lost = 0;
        return;
    }
    out->seqs_assigned = atomic_load_explicit(&m->stat_seqs, memory_order_relaxed);
    out->commits_marked = atomic_load_explicit(&m->stat_marks, memory_order_relaxed);
    out->reservations_won = atomic_load_explicit(&m->stat_res_won, memory_order_relaxed);
    out->reservations_lost = atomic_load_explicit(&m->stat_res_lost, memory_order_relaxed);
}

/* whether seq belongs to a prepared batch phase two has not decided, which is the one kind of
 * sequence that sits below the ring and is still in flight */
static int mvcc_prepared_held(const tidesdb_mvcc_t *m, uint64_t seq)
{
    if (atomic_load_explicit(&m->prepared_hold_count, memory_order_acquire) == 0) return 0;
    for (int i = 0; i < TDB_MVCC_MAX_PREPARED_HOLDS; i++)
        if (atomic_load_explicit(&m->prepared_hold[i], memory_order_acquire) == seq) return 1;
    return 0;
}

int tidesdb_mvcc_prepared_hold(tidesdb_mvcc_t *m, uint64_t seq)
{
    if (!m || seq == 0) return TDB_ERR_INVALID_ARGS;

    /* the count is raised before the slot is filled, so a concurrent reader that sees the count
     * never finds the table emptier than it is. a reader between the two reads one slot short and
     * calls the sequence committed, which is why the hold is taken before the reservation names it
     * -- until then no other thread has that sequence to ask about */
    atomic_fetch_add_explicit(&m->prepared_hold_count, 1, memory_order_release);
    for (int i = 0; i < TDB_MVCC_MAX_PREPARED_HOLDS; i++)
    {
        uint64_t empty = 0;
        if (atomic_compare_exchange_strong_explicit(&m->prepared_hold[i], &empty, seq,
                                                    memory_order_acq_rel, memory_order_relaxed))
            return TDB_SUCCESS;
    }
    atomic_fetch_sub_explicit(&m->prepared_hold_count, 1, memory_order_release);
    return TDB_ERR_CONFLICT;
}

void tidesdb_mvcc_prepared_release(tidesdb_mvcc_t *m, uint64_t seq)
{
    if (!m || seq == 0) return;
    for (int i = 0; i < TDB_MVCC_MAX_PREPARED_HOLDS; i++)
    {
        uint64_t held = seq;
        if (atomic_compare_exchange_strong_explicit(&m->prepared_hold[i], &held, 0,
                                                    memory_order_acq_rel, memory_order_relaxed))
        {
            atomic_fetch_sub_explicit(&m->prepared_hold_count, 1, memory_order_release);
            return;
        }
    }
}

int tidesdb_mvcc_committed(const tidesdb_mvcc_t *m, uint64_t seq)
{
    if (!m || seq == 0) return 0;

    /* a seq more than a ring capacity behind the high-water mark has had its slot recycled by a
     * newer seq, so the slot no longer describes it. such a seq already applied and cannot still be
     * in flight unless a prepare is holding it undecided, so it is committed -- the same assumption
     * recovery makes when it reseeds the
     * trailing window. without this an old committed version reads the newer seq's in-progress
     * status and is wrongly filtered out of a snapshot read */
    const uint64_t max_seq = atomic_load_explicit(&m->ring_max_seq, memory_order_acquire);
    if (max_seq >= m->ring_capacity && seq <= max_seq - m->ring_capacity)
        return !mvcc_prepared_held(m, seq);

    return atomic_load_explicit(&m->ring[seq % m->ring_capacity], memory_order_acquire) ==
           TDB_MVCC_COMMITTED;
}

int tidesdb_mvcc_visible(const tidesdb_mvcc_t *m, uint64_t seq, uint64_t snapshot)
{
    return seq != 0 && seq <= snapshot && tidesdb_mvcc_committed(m, seq);
}

void tidesdb_mvcc_reseed(tidesdb_mvcc_t *m, uint64_t max_recovered_seq)
{
    if (!m || max_recovered_seq == 0) return;
    atomic_store_explicit(&m->global_seq, max_recovered_seq + 1, memory_order_release);
    mvcc_bump_max(m, max_recovered_seq);

    /* backfill the ring's trailing window as committed. the ring only distinguishes the last
     * ring_capacity seqs, so older recovered seqs are already covered by the eviction rule; marking
     * from seq 1 would scale with the database's lifetime write count instead of the ring size */
    uint64_t start = 1;
    if (max_recovered_seq > (uint64_t)m->ring_capacity)
        start = max_recovered_seq - (uint64_t)m->ring_capacity + 1;
    for (uint64_t seq = start; seq <= max_recovered_seq; seq++)
        atomic_store_explicit(&m->ring[seq % m->ring_capacity], TDB_MVCC_COMMITTED,
                              memory_order_release);
}

int tidesdb_mvcc_reserve(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t commit_seq,
                         uint64_t read_base, uint64_t min_snapshot)
{
    if (!m) return 1;
    _Atomic(uint64_t) *res = m->reservation;
    const uint64_t myseq = commit_seq & TDB_MVCC_RES_SEQ_MASK;
    const uint32_t slot = (uint32_t)key_hash & TDB_MVCC_RESERVATION_MASK;
    const uint16_t myfp = (uint16_t)(key_hash >> TDB_MVCC_RES_SEQ_BITS);
    const uint64_t mine = TDB_MVCC_RES_PACK(myfp, myseq);

    for (;;)
    {
        const uint64_t cur = atomic_load_explicit(&res[slot], memory_order_acquire);
        const uint64_t cseq = TDB_MVCC_RES_SEQ(cur);
        if (cseq == myseq)
        {
            /* already held by this seq -- a duplicate key or a colliding sibling */
            atomic_fetch_add_explicit(&m->stat_res_won, 1, memory_order_relaxed);
            return 1;
        }

        /* an in-flight occupant could be a concurrent same-key committer this txn must lose to, and
         * it cannot be told from a colliding key without its applied version, so abort
         * conservatively. committed (and evicted) seqs pass tidesdb_mvcc_committed, so this fires
         * only for a genuine in-flight occupant */
        if (cseq != 0 && !tidesdb_mvcc_committed(m, cseq))
        {
            atomic_fetch_add_explicit(&m->stat_res_lost, 1, memory_order_relaxed);
            return 0;
        }

        /* a committed seq landed past the version this txn read. a matching fingerprint means a
         * real same-key writer and this txn loses; a differing fingerprint is a hash collision,
         * harmless unless it is newer than the oldest open snapshot, where a concurrent writer of
         * that colliding key could still depend on the slot and the reservation stays
         * conservative */
        if (cseq > read_base && (TDB_MVCC_RES_FP(cur) == myfp || cseq > min_snapshot))
        {
            atomic_fetch_add_explicit(&m->stat_res_lost, 1, memory_order_relaxed);
            return 0;
        }

        uint64_t expect = cur;
        if (atomic_compare_exchange_weak_explicit(&res[slot], &expect, mine, memory_order_acq_rel,
                                                  memory_order_acquire))
        {
            atomic_fetch_add_explicit(&m->stat_res_won, 1, memory_order_relaxed);
            return 1;
        }
        /* cas lost to a concurrent claimer -- re-read and re-evaluate this slot */
    }
}

void tidesdb_mvcc_reassign(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t from_seq, uint64_t to_seq)
{
    if (!m || from_seq == 0 || to_seq == 0) return;
    _Atomic(uint64_t) *res = m->reservation;
    const uint32_t slot = (uint32_t)key_hash & TDB_MVCC_RESERVATION_MASK;
    const uint16_t fp = (uint16_t)(key_hash >> TDB_MVCC_RES_SEQ_BITS);
    uint64_t expect = TDB_MVCC_RES_PACK(fp, from_seq & TDB_MVCC_RES_SEQ_MASK);
    const uint64_t want = TDB_MVCC_RES_PACK(fp, to_seq & TDB_MVCC_RES_SEQ_MASK);
    /* move the slot only if the old seq still owns it; a failed cas means a newer committer already
     * took it, and that newer claim is the one that should stand */
    atomic_compare_exchange_strong_explicit(&res[slot], &expect, want, memory_order_acq_rel,
                                            memory_order_acquire);
}

void tidesdb_mvcc_release(tidesdb_mvcc_t *m, uint64_t key_hash, uint64_t commit_seq)
{
    if (!m || commit_seq == 0) return;
    _Atomic(uint64_t) *res = m->reservation;
    const uint32_t slot = (uint32_t)key_hash & TDB_MVCC_RESERVATION_MASK;
    const uint16_t fp = (uint16_t)(key_hash >> TDB_MVCC_RES_SEQ_BITS);
    uint64_t expect = TDB_MVCC_RES_PACK(fp, commit_seq & TDB_MVCC_RES_SEQ_MASK);
    /* clear the slot only if this seq owns it; a failed cas means a newer committer took it */
    atomic_compare_exchange_strong_explicit(&res[slot], &expect, 0, memory_order_acq_rel,
                                            memory_order_acquire);
}
