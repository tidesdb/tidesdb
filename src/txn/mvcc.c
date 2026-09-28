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

#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "base/log.h"
#include "mvcc_internal.h"

/* commit-ring slot states, in the low bits of a slot; the sequence the slot describes sits above
 * them, so a slot recycled by a later sequence never reads as a decision about an earlier one */
#define TDB_MVCC_IN_PROGRESS           0
#define TDB_MVCC_COMMITTED             1
#define TDB_MVCC_ABORTED               2
#define TDB_MVCC_RING_STATE_BITS       2
#define TDB_MVCC_RING_STATE_MASK       ((1ULL << TDB_MVCC_RING_STATE_BITS) - 1)
#define TDB_MVCC_RING_PACK(seq, state) (((seq) << TDB_MVCC_RING_STATE_BITS) | (uint64_t)(state))
#define TDB_MVCC_RING_SEQ(slot)        ((slot) >> TDB_MVCC_RING_STATE_BITS)
#define TDB_MVCC_RING_STATE(slot)      ((slot)&TDB_MVCC_RING_STATE_MASK)

/* how a committer waits for the watermark to reach its sequence, and how a validator waits for an
 * owner between its draw and the publication of it: a short spin for the common case of a neighbour
 * a few instructions away, then yields. the bound is far beyond any commit window and exists so a
 * stall elsewhere is logged or refused rather than waited on forever */
#define TDB_MVCC_VISIBLE_WAIT_SPINS 1024
#define TDB_MVCC_VISIBLE_WAIT_MAX   100000000ULL

tidesdb_mvcc_t *tidesdb_mvcc_create(void)
{
    tidesdb_mvcc_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;

    m->ring = malloc(TDB_MVCC_COMMIT_RING_SIZE * sizeof(_Atomic(uint64_t)));
    m->claim_heads = calloc(TDB_MVCC_CLAIM_BUCKETS, sizeof(*m->claim_heads));
    m->claim_stripes = malloc(TDB_MVCC_CLAIM_STRIPES * sizeof(*m->claim_stripes));
    if (!m->ring || !m->claim_heads || !m->claim_stripes)
    {
        free((void *)m->ring);
        free(m->claim_heads);
        free(m->claim_stripes);
        free(m);
        return NULL;
    }
    for (size_t i = 0; i < TDB_MVCC_COMMIT_RING_SIZE; i++) atomic_init(&m->ring[i], 0);
    for (size_t i = 0; i < TDB_MVCC_CLAIM_STRIPES; i++)
        pthread_mutex_init(&m->claim_stripes[i], NULL);

    m->inflight = NULL;
    pthread_mutex_init(&m->inflight_lock, NULL);
    memset(m->range_holds, 0, sizeof(m->range_holds));
    atomic_init(&m->range_count, 0);
    atomic_init(&m->scan_holders, 0);
    pthread_mutex_init(&m->range_lock, NULL);
    m->orphans = NULL;
    pthread_mutex_init(&m->orphan_lock, NULL);

    atomic_init(&m->global_seq, 1);
    atomic_init(&m->visible_seq, 0);
    m->ring_capacity = TDB_MVCC_COMMIT_RING_SIZE;
    return m;
}

void tidesdb_mvcc_destroy(tidesdb_mvcc_t *m)
{
    if (!m) return;
    pthread_mutex_destroy(&m->range_lock);
    pthread_mutex_destroy(&m->inflight_lock);
    pthread_mutex_destroy(&m->orphan_lock);
    mvcc_orphan_t *o = m->orphans;
    while (o)
    {
        mvcc_orphan_t *next = o->next;
        mvcc_orphan_free(o);
        o = next;
    }
    for (size_t i = 0; i < TDB_MVCC_CLAIM_STRIPES; i++) pthread_mutex_destroy(&m->claim_stripes[i]);
    free(m->claim_stripes);
    free(m->claim_heads);
    free((void *)m->ring);
    free(m);
}

/* ===== the clock ===== */

/* wait for room to draw. the ring is what decides the watermark, so no sequence is drawn a ring's
 * width or more above it, where its slot would recycle one the watermark has yet to read; a draw
 * that far ahead waits for the commits below it to decide, which bounds the sequences in flight by
 * the ring rather than assuming it */
static void mvcc_wait_ring_room(tidesdb_mvcc_t *m)
{
    for (uint64_t spin = 0; spin < TDB_MVCC_VISIBLE_WAIT_MAX; spin++)
    {
        const uint64_t ahead = atomic_load_explicit(&m->global_seq, memory_order_acquire) -
                               atomic_load_explicit(&m->visible_seq, memory_order_acquire);
        if (ahead < (uint64_t)m->ring_capacity - 1) return;
        cpu_yield();
    }
}

/**
 * mvcc_take_seq
 * take the next sequence only while the ring has room for it, in one compare-and-swap with the
 * room check. a check apart from the take let every committer that saw the last free slot take a
 * sequence, and those past the ring recycled the slot of one the watermark had yet to read, losing
 * its decision and stopping the watermark for good
 * @param m the clock
 * @return the sequence taken, or 0 when the ring filled before this committer could take one
 */
static uint64_t mvcc_take_seq(tidesdb_mvcc_t *m)
{
    uint64_t seq = atomic_load_explicit(&m->global_seq, memory_order_acquire);
    for (uint64_t spin = 0; spin < TDB_MVCC_VISIBLE_WAIT_MAX; spin++)
    {
        if (seq - atomic_load_explicit(&m->visible_seq, memory_order_acquire) >=
            (uint64_t)m->ring_capacity - 1)
            return 0;
        if (atomic_compare_exchange_weak_explicit(&m->global_seq, &seq, seq + 1,
                                                  memory_order_acq_rel, memory_order_acquire))
            return seq;
    }
    return 0;
}

uint64_t tidesdb_mvcc_current_seq(const tidesdb_mvcc_t *m)
{
    return atomic_load_explicit(&m->global_seq, memory_order_acquire);
}

/**
 * mvcc_decided
 * whether a drawn sequence's outcome is settled, read from its own slot. the draw keeps every
 * sequence above the watermark within the ring, so the slot always describes the sequence asked
 * about and no eviction rule is needed here
 * @param m the clock
 * @param seq the sequence to test, which must have been drawn
 * @return 1 when the sequence is committed or aborted, 0 while it is still in flight
 */
static int mvcc_decided(const tidesdb_mvcc_t *m, const uint64_t seq)
{
    const uint64_t slot =
        atomic_load_explicit(&m->ring[seq % m->ring_capacity], memory_order_acquire);
    return TDB_MVCC_RING_SEQ(slot) == seq && TDB_MVCC_RING_STATE(slot) != TDB_MVCC_IN_PROGRESS;
}

/**
 * mvcc_advance_watermark
 * move the watermark up over every drawn sequence that has been decided, stopping at the first one
 * still in flight or not yet drawn. every committer calls this after deciding its own sequence,
 * and any of them may carry the watermark past the others', so one pass is bounded by the ring
 * rather than by how far behind the watermark is
 * @param m the clock
 */
static void mvcc_advance_watermark(tidesdb_mvcc_t *m)
{
    /* the caller has just stored its own slot, and the loads below read its neighbours'. two
     * committers deciding neighbouring sequences at once each store then load, and without a full
     * barrier between the two a store still in its buffer lets both loads miss both stores -- each
     * then stops at the other's slot, the watermark stands below both, and the higher committer
     * waits on a publication no one is left to make. the fence orders the store ahead of the loads
     * on both sides, so at least one of them sees the other's decision and carries it */
    atomic_thread_fence(memory_order_seq_cst);
    uint64_t visible = atomic_load_explicit(&m->visible_seq, memory_order_acquire);
    for (size_t step = 0; step < m->ring_capacity; step++)
    {
        const uint64_t next = visible + 1;
        if (next >= atomic_load_explicit(&m->global_seq, memory_order_acquire)) return;
        if (!mvcc_decided(m, next)) return;
        if (atomic_compare_exchange_weak_explicit(&m->visible_seq, &visible, next,
                                                  memory_order_acq_rel, memory_order_acquire))
            visible = next;
    }
}

void tidesdb_mvcc_mark(tidesdb_mvcc_t *m, uint64_t seq, int committed)
{
    if (!m || seq == 0) return;
    const uint64_t state = committed ? TDB_MVCC_COMMITTED : TDB_MVCC_IN_PROGRESS;
    atomic_store_explicit(&m->ring[seq % m->ring_capacity], TDB_MVCC_RING_PACK(seq, state),
                          memory_order_release);
    if (committed) mvcc_advance_watermark(m);
}

void tidesdb_mvcc_mark_aborted(tidesdb_mvcc_t *m, uint64_t seq)
{
    if (!m || seq == 0) return;
    atomic_store_explicit(&m->ring[seq % m->ring_capacity],
                          TDB_MVCC_RING_PACK(seq, TDB_MVCC_ABORTED), memory_order_release);
    mvcc_advance_watermark(m);
}

uint64_t tidesdb_mvcc_visible_seq(const tidesdb_mvcc_t *m)
{
    return m ? atomic_load_explicit(&m->visible_seq, memory_order_acquire) : 0;
}

const _Atomic(uint64_t) *tidesdb_mvcc_watermark_ref(const tidesdb_mvcc_t *m)
{
    return m ? &m->visible_seq : NULL;
}

void tidesdb_mvcc_wait_visible(const tidesdb_mvcc_t *m, uint64_t seq)
{
    if (!m) return;
    for (uint64_t spin = 0; spin < TDB_MVCC_VISIBLE_WAIT_MAX; spin++)
    {
        if (atomic_load_explicit(&m->visible_seq, memory_order_acquire) >= seq) return;
        if (spin < TDB_MVCC_VISIBLE_WAIT_SPINS)
            cpu_pause();
        else
            cpu_yield();
    }
    /* every drawn sequence is decided on every path, so this is a stall in a commit below seq, not
     * a lost decision; the batch is durable and applied, only its publication is late */
    TDB_DEBUG_LOG(TDB_LOG_WARN, "commit seq %llu returned before the watermark reached it",
                  (unsigned long long)seq);
}

void tidesdb_mvcc_reseed(tidesdb_mvcc_t *m, uint64_t max_recovered_seq)
{
    if (!m || max_recovered_seq == 0) return;
    atomic_store_explicit(&m->global_seq, max_recovered_seq + 1, memory_order_release);
    /* everything recovered is decided, so readers may see all of it from the first begin; the ring
     * is read only above the watermark, so nothing below it needs a slot */
    atomic_store_explicit(&m->visible_seq, max_recovered_seq, memory_order_release);
}

/* ===== the in-flight claim set ===== */

void tidesdb_mvcc_commit_init(tidesdb_mvcc_commit_t *commit, tidesdb_mvcc_claim_t *claims,
                              const int n_claims)
{
    if (!commit) return;
    atomic_init(&commit->seq, 0);
    commit->claims = claims;
    commit->n_claims = n_claims;
    commit->next_inflight = NULL;
    commit->held = 0;
    commit->scans = NULL;
    commit->n_scans = 0;
}

void tidesdb_mvcc_commit_scans(tidesdb_mvcc_commit_t *commit, const tidesdb_mvcc_range_t *scans,
                               const int n_scans)
{
    if (!commit || n_scans < 0 || (n_scans > 0 && !scans)) return;
    commit->scans = scans;
    commit->n_scans = n_scans;
}

void tidesdb_mvcc_claim_init(tidesdb_mvcc_claim_t *claim, const uint32_t cf_index,
                             const uint8_t *key, const uint32_t key_size, const uint8_t kind,
                             const uint64_t hash)
{
    if (!claim) return;
    claim->hash = hash;
    claim->owner = NULL;
    claim->key = key;
    claim->key_size = key_size;
    claim->cf_index = cf_index;
    claim->kind = kind;
    claim->next = NULL;
}

int tidesdb_mvcc_holds(const tidesdb_mvcc_commit_t *commit)
{
    return commit && commit->held;
}

/* the bucket a key's claims chain from, and the lock guarding that chain */
uint32_t mvcc_claim_bucket(const uint64_t hash)
{
    return (uint32_t)hash & (TDB_MVCC_CLAIM_BUCKETS - 1);
}

pthread_mutex_t *mvcc_claim_stripe(tidesdb_mvcc_t *m, const uint32_t bucket)
{
    return &m->claim_stripes[bucket & (TDB_MVCC_CLAIM_STRIPES - 1)];
}

/* whether two claims name the same key of the same family, by bytes and never by hash alone */
static int mvcc_claim_same_key(const tidesdb_mvcc_claim_t *a, const tidesdb_mvcc_claim_t *b)
{
    return a->hash == b->hash && a->cf_index == b->cf_index && a->key_size == b->key_size &&
           memcmp(a->key, b->key, a->key_size) == 0;
}

/* whether a key falls inside a half-open interval, an empty upper bound being open above */
static int mvcc_key_in_range(const uint8_t *key, const size_t key_size, const uint8_t *lo,
                             const size_t lo_size, const uint8_t *hi, const size_t hi_size)
{
    if (tdb_key_cmp(lo, lo_size, key, key_size) > 0) return 0;
    if (hi_size == 0) return 1;
    return tdb_key_cmp(key, key_size, hi, hi_size) < 0;
}

/* whether a held interval meets another half-open interval. an open upper bound is above every
 * bound that can be spelled, so it can never be the thing that separates them */
static int mvcc_hold_overlaps(const mvcc_range_hold_t *r, const uint8_t *lo, const size_t lo_size,
                              const uint8_t *hi, const size_t hi_size)
{
    if (hi_size > 0 && tdb_key_cmp(hi, hi_size, r->lo, r->lo_size) <= 0) return 0;
    if (r->hi_size > 0 && tdb_key_cmp(r->hi, r->hi_size, lo, lo_size) <= 0) return 0;
    return 1;
}

/* the one order every commit takes its claims in, so two commits sharing keys meet at the same
 * first key and exactly one of them yields rather than each holding half */
static int mvcc_claim_cmp(const void *pa, const void *pb)
{
    const tidesdb_mvcc_claim_t *a = pa;
    const tidesdb_mvcc_claim_t *b = pb;
    if (a->cf_index != b->cf_index) return a->cf_index < b->cf_index ? -1 : 1;
    return tdb_key_cmp(a->key, a->key_size, b->key, b->key_size);
}

/**
 * mvcc_owner_seq
 * the sequence an owner has published, waiting out one that is between its draw and the store of
 * it; a wait past the bound answers the lowest sequence, which refuses rather than trusts
 * @param owner the commit whose sequence is asked
 * @return the published sequence, TDB_MVCC_SEQ_FUTURE for a prepared owner, or 0 for one that has
 *         not drawn
 */
static uint64_t mvcc_owner_seq(const tidesdb_mvcc_commit_t *owner)
{
    for (uint64_t spin = 0; spin < TDB_MVCC_VISIBLE_WAIT_MAX; spin++)
    {
        const uint64_t seq = atomic_load_explicit(&owner->seq, memory_order_acquire);
        if (seq != TDB_MVCC_SEQ_DRAWING) return seq;
        if (spin < TDB_MVCC_VISIBLE_WAIT_SPINS)
            cpu_pause();
        else
            cpu_yield();
    }
    return 1;
}

/* whether an owner other than the asking commit is sequenced below it. an owner that has not drawn
 * will draw above this commit, and a prepared one commits above everything current; both leave
 * what this commit read the newest it could have seen */
static int mvcc_owner_below(const tidesdb_mvcc_commit_t *owner, const uint64_t mine)
{
    const uint64_t theirs = mvcc_owner_seq(owner);
    return theirs != 0 && theirs < mine;
}

/* the in-flight list, entered before a commit's first claim and left after its last release */
static void mvcc_inflight_push(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit)
{
    pthread_mutex_lock(&m->inflight_lock);
    commit->next_inflight = m->inflight;
    m->inflight = commit;
    commit->held = 1;
    if (commit->n_scans > 0) atomic_fetch_add_explicit(&m->scan_holders, 1, memory_order_release);
    pthread_mutex_unlock(&m->inflight_lock);
}

static void mvcc_inflight_pop(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit)
{
    pthread_mutex_lock(&m->inflight_lock);
    for (tidesdb_mvcc_commit_t **link = &m->inflight; *link; link = &(*link)->next_inflight)
        if (*link == commit)
        {
            *link = commit->next_inflight;
            if (commit->n_scans > 0)
                atomic_fetch_sub_explicit(&m->scan_holders, 1, memory_order_release);
            break;
        }
    commit->next_inflight = NULL;
    commit->held = 0;
    pthread_mutex_unlock(&m->inflight_lock);
}

/**
 * mvcc_interval_held_over
 * whether another owner's interval covers a key, under the interval table's lock
 * @param m the clock
 * @param commit the asking commit, whose own intervals are not in its way
 * @param cf_index the family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @param below_only non-zero to count only owners sequenced below the asking commit, zero to count
 *                   every other owner
 * @return 1 when such an interval covers the key, 0 otherwise
 */
static int mvcc_interval_held_over(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                                   const uint32_t cf_index, const uint8_t *key,
                                   const size_t key_size, const int below_only)
{
    if (atomic_load_explicit(&m->range_count, memory_order_acquire) == 0) return 0;
    const uint64_t mine = atomic_load_explicit(&commit->seq, memory_order_acquire);
    pthread_mutex_lock(&m->range_lock);
    int held = 0;
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS && !held; i++)
    {
        const mvcc_range_hold_t *r = &m->range_holds[i];
        if (!r->in_use || r->owner == commit || r->cf_index != cf_index) continue;
        if (!mvcc_key_in_range(key, key_size, r->lo, r->lo_size, r->hi, r->hi_size)) continue;
        held = !below_only || mvcc_owner_below(r->owner, mine);
    }
    pthread_mutex_unlock(&m->range_lock);
    return held;
}

/**
 * mvcc_claim_refused
 * whether a chain already holds a claim this one may not join. a write claim is refused by another
 * owner's read claim always, since a reader that has prepared cannot be the one to yield, and by
 * another owner's write claim when the claimant promises first-committer-wins. a read claim is
 * never refused; what it forbids is decided by the writers that meet it
 * @param head the chain
 * @param claim the claim about to join it
 * @param first_committer_wins non-zero when another writer of the key in flight is a conflict
 * @return 1 when the claim is refused, 0 when it may join
 */
static int mvcc_claim_refused(const tidesdb_mvcc_claim_t *head, const tidesdb_mvcc_claim_t *claim,
                              const int first_committer_wins)
{
    if (claim->kind == TDB_MVCC_CLAIM_READ) return 0;
    uint32_t walked = 0;
    for (const tidesdb_mvcc_claim_t *o = head; o && walked < TDB_MVCC_CLAIM_WALK_MAX;
         o = o->next, walked++)
    {
        if (o->owner == claim->owner || !mvcc_claim_same_key(o, claim)) continue;
        if (o->kind == TDB_MVCC_CLAIM_READ || first_committer_wins) return 1;
    }
    /* a chain past the bound is refused rather than trusted */
    return walked >= TDB_MVCC_CLAIM_WALK_MAX;
}

/* unlink one claim from its chain, under the stripe lock the caller holds */
void mvcc_claim_unlink(tidesdb_mvcc_t *m, const uint32_t bucket, tidesdb_mvcc_claim_t *claim)
{
    tidesdb_mvcc_claim_t **link = &m->claim_heads[bucket];
    for (uint32_t walked = 0; *link && walked < TDB_MVCC_CLAIM_WALK_MAX; walked++)
    {
        if (*link == claim)
        {
            *link = claim->next;
            claim->next = NULL;
            return;
        }
        link = &(*link)->next;
    }
}

/* drop the first n claims of a commit, the ones a refused claim leaves behind it */
static void mvcc_unclaim_first(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit, const int n)
{
    for (int i = 0; i < n; i++)
    {
        const uint32_t bucket = mvcc_claim_bucket(commit->claims[i].hash);
        pthread_mutex_t *lock = mvcc_claim_stripe(m, bucket);
        pthread_mutex_lock(lock);
        mvcc_claim_unlink(m, bucket, &commit->claims[i]);
        pthread_mutex_unlock(lock);
    }
}

/* give back every interval a commit holds, under the interval table's lock */
static void mvcc_release_ranges(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit)
{
    if (atomic_load_explicit(&m->range_count, memory_order_acquire) == 0) return;
    pthread_mutex_lock(&m->range_lock);
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS; i++)
    {
        if (!m->range_holds[i].in_use || m->range_holds[i].owner != commit) continue;
        m->range_holds[i].in_use = 0;
        atomic_fetch_sub_explicit(&m->range_count, 1, memory_order_release);
    }
    pthread_mutex_unlock(&m->range_lock);
}

int tidesdb_mvcc_claim(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit,
                       const int first_committer_wins)
{
    if (!m || !commit || (commit->n_claims > 0 && !commit->claims)) return 0;
    if (commit->n_claims > 1)
        qsort(commit->claims, (size_t)commit->n_claims, sizeof(*commit->claims), mvcc_claim_cmp);
    for (int i = 0; i < commit->n_claims; i++) commit->claims[i].owner = commit;

    /* in the list before the first claim, so an interval checked against the list in the same
     * instant finds these keys whether or not they are chained yet -- the array is complete */
    mvcc_inflight_push(m, commit);
    for (int i = 0; i < commit->n_claims; i++)
    {
        tidesdb_mvcc_claim_t *claim = &commit->claims[i];
        const uint32_t bucket = mvcc_claim_bucket(claim->hash);
        pthread_mutex_t *lock = mvcc_claim_stripe(m, bucket);
        pthread_mutex_lock(lock);
        const int refused =
            mvcc_claim_refused(m->claim_heads[bucket], claim, first_committer_wins) ||
            (first_committer_wins && claim->kind == TDB_MVCC_CLAIM_WRITE &&
             mvcc_interval_held_over(m, commit, claim->cf_index, claim->key, claim->key_size, 0));
        if (refused)
        {
            pthread_mutex_unlock(lock);
            mvcc_unclaim_first(m, commit, i);
            mvcc_inflight_pop(m, commit);
            return 0;
        }
        claim->next = m->claim_heads[bucket];
        m->claim_heads[bucket] = claim;
        pthread_mutex_unlock(lock);
    }
    return 1;
}

/**
 * mvcc_inflight_meets
 * whether a commit in flight other than the asking one holds a claim on a key inside an interval,
 * under the in-flight list's lock. a write claim counts when its owner is sequenced below the
 * asking commit, or at any sequence when below_only is zero; a read claim counts at any sequence
 * when reads_block is set, since a prepared reader cannot be the one to yield
 * @param m the clock
 * @param commit the asking commit
 * @param cf_index the family the interval belongs to
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for open above
 * @param hi_size length of hi
 * @param below_only non-zero to count only write claims of owners sequenced below the asking commit
 * @param reads_block non-zero when another owner's read claim inside the interval counts
 * @return 1 when such a claim exists, 0 otherwise
 */
static int mvcc_inflight_meets(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                               const uint32_t cf_index, const uint8_t *lo, const size_t lo_size,
                               const uint8_t *hi, const size_t hi_size, const int below_only,
                               const int reads_block)
{
    const uint64_t mine = atomic_load_explicit(&commit->seq, memory_order_acquire);
    pthread_mutex_lock(&m->inflight_lock);
    int met = 0;
    uint32_t walked = 0;
    for (const tidesdb_mvcc_commit_t *c = m->inflight;
         c && !met && walked < TDB_MVCC_INFLIGHT_WALK_MAX; c = c->next_inflight, walked++)
    {
        if (c == commit) continue;
        int inside = 0;
        for (int i = 0; i < c->n_claims && !inside; i++)
        {
            const tidesdb_mvcc_claim_t *k = &c->claims[i];
            if (k->cf_index != cf_index ||
                !mvcc_key_in_range(k->key, k->key_size, lo, lo_size, hi, hi_size))
                continue;
            if (k->kind == TDB_MVCC_CLAIM_READ)
                inside = reads_block;
            else
                inside = !below_only || mvcc_owner_below(c, mine);
        }
        met = inside;
    }
    pthread_mutex_unlock(&m->inflight_lock);
    /* a list past the bound is refused rather than trusted */
    return met || walked >= TDB_MVCC_INFLIGHT_WALK_MAX;
}

/**
 * mvcc_interval_meets_holds
 * whether another owner's interval meets this one, under the interval table's lock the caller holds
 * @param m the clock
 * @param commit the asking commit, whose own intervals are not in its way
 * @param cf_index the family
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for open above
 * @param hi_size length of hi
 * @param below_only non-zero to count only owners sequenced below the asking commit
 * @return 1 when such an interval exists, 0 otherwise
 */
static int mvcc_interval_meets_holds(const tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                                     const uint32_t cf_index, const uint8_t *lo,
                                     const size_t lo_size, const uint8_t *hi, const size_t hi_size,
                                     const int below_only)
{
    const uint64_t mine = atomic_load_explicit(&commit->seq, memory_order_acquire);
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS; i++)
    {
        const mvcc_range_hold_t *r = &m->range_holds[i];
        if (!r->in_use || r->owner == commit || r->cf_index != cf_index) continue;
        if (!mvcc_hold_overlaps(r, lo, lo_size, hi, hi_size)) continue;
        if (!below_only || mvcc_owner_below(r->owner, mine)) return 1;
    }
    return 0;
}

int tidesdb_mvcc_claim_range(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit,
                             const uint32_t cf_index, const uint8_t *lo, const size_t lo_size,
                             const uint8_t *hi, const size_t hi_size,
                             const int first_committer_wins)
{
    if (!m || !commit || !commit->held || !lo || lo_size == 0) return 0;
    /* refused rather than truncated, because a truncated bound describes a wider interval than the
     * caller asked for and would block writes they never meant to block */
    if (lo_size > TDB_MVCC_MAX_RANGE_BYTES || hi_size > TDB_MVCC_MAX_RANGE_BYTES) return 0;

    pthread_mutex_lock(&m->range_lock);
    int slot = -1;
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS && slot < 0; i++)
        if (!m->range_holds[i].in_use) slot = i;
    /* a full table conflicts rather than letting the commit past unchecked */
    int held =
        slot >= 0 && (!first_committer_wins ||
                      !mvcc_interval_meets_holds(m, commit, cf_index, lo, lo_size, hi, hi_size, 0));
    if (held)
    {
        mvcc_range_hold_t *r = &m->range_holds[slot];
        memcpy(r->lo, lo, lo_size);
        r->lo_size = lo_size;
        if (hi_size) memcpy(r->hi, hi, hi_size);
        r->hi_size = hi_size;
        r->cf_index = cf_index;
        r->owner = commit;
        r->in_use = 1;
        atomic_fetch_add_explicit(&m->range_count, 1, memory_order_release);
        /* held first, checked second: a point writer meeting the hold in the same instant is
         * refused, and one that claimed just before it is found here, so one of the two yields */
        if (first_committer_wins &&
            mvcc_inflight_meets(m, commit, cf_index, lo, lo_size, hi, hi_size, 0, 1))
        {
            r->in_use = 0;
            atomic_fetch_sub_explicit(&m->range_count, 1, memory_order_release);
            held = 0;
        }
    }
    pthread_mutex_unlock(&m->range_lock);
    return held;
}

uint64_t tidesdb_mvcc_draw(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit)
{
    if (!m) return 0;
    /* room in the ring is waited for before anything is announced. the committer holding the
     * lowest undecided sequence is the one whose decision makes the room, and it may be validating
     * against this commit's claims, spinning on the announcement to learn where this commit lands.
     * announced first, this commit would wait on that one while that one waited on this, for the
     * length of the spin budget.
     *
     * the draw is announced before the sequence is taken, so a validator that reads the
     * announcement knows a sequence that may be lower than its own is a few instructions from being
     * published, and one that reads nothing knows the draw has not happened and the sequence will
     * be higher than its own. the fence orders the claims taken before this against the draw
     * itself. a committer that lost the room between the wait and the take withdraws the
     * announcement, which is true to a validator, since it has taken nothing and will take a
     * sequence above the validator's own, and waits for room again */
    uint64_t seq = 0;
    for (uint64_t attempt = 0; seq == 0 && attempt < TDB_MVCC_VISIBLE_WAIT_MAX; attempt++)
    {
        mvcc_wait_ring_room(m);
        if (commit) atomic_store_explicit(&commit->seq, TDB_MVCC_SEQ_DRAWING, memory_order_release);
        atomic_thread_fence(memory_order_seq_cst);
        seq = mvcc_take_seq(m);
        if (seq == 0 && commit) atomic_store_explicit(&commit->seq, 0, memory_order_release);
    }
    /* a ring that never made room is a stall below every committer, not a lost decision; the draw
     * goes ahead rather than refuse a commit its caller cannot retry past */
    if (seq == 0)
    {
        if (commit) atomic_store_explicit(&commit->seq, TDB_MVCC_SEQ_DRAWING, memory_order_release);
        atomic_thread_fence(memory_order_seq_cst);
        seq = atomic_fetch_add_explicit(&m->global_seq, 1, memory_order_acq_rel);
    }
    tidesdb_mvcc_mark(m, seq, 0);
    if (commit) atomic_store_explicit(&commit->seq, seq, memory_order_release);
    return seq;
}

void tidesdb_mvcc_commit_prepared(tidesdb_mvcc_commit_t *commit)
{
    if (commit) atomic_store_explicit(&commit->seq, TDB_MVCC_SEQ_FUTURE, memory_order_release);
}

int tidesdb_mvcc_read_stale(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                            const uint32_t cf_index, const uint8_t *key, const uint32_t key_size,
                            const uint64_t hash)
{
    if (!m || !commit || !key) return 0;
    const uint64_t mine = atomic_load_explicit(&commit->seq, memory_order_acquire);
    tidesdb_mvcc_claim_t probe;
    tidesdb_mvcc_claim_init(&probe, cf_index, key, key_size, TDB_MVCC_CLAIM_READ, hash);

    const uint32_t bucket = mvcc_claim_bucket(hash);
    pthread_mutex_t *lock = mvcc_claim_stripe(m, bucket);
    pthread_mutex_lock(lock);
    int stale = 0;
    uint32_t walked = 0;
    for (const tidesdb_mvcc_claim_t *o = m->claim_heads[bucket];
         o && !stale && walked < TDB_MVCC_CLAIM_WALK_MAX; o = o->next, walked++)
    {
        if (o->owner == commit || o->kind != TDB_MVCC_CLAIM_WRITE ||
            !mvcc_claim_same_key(o, &probe))
            continue;
        /* one already drawn below this commit is the writer whose version it missed */
        stale = mvcc_owner_below(o->owner, mine);
    }
    if (!stale) stale = mvcc_interval_held_over(m, commit, cf_index, key, key_size, 1);
    pthread_mutex_unlock(lock);
    return stale || walked >= TDB_MVCC_CLAIM_WALK_MAX;
}

/* whether one of an in-flight commit's scanned intervals meets the interval given, or holds the key
 * given when point is set */
static int mvcc_scans_meet_one(const tidesdb_mvcc_commit_t *c, const uint32_t cf_index,
                               const uint8_t *lo, const size_t lo_size, const uint8_t *hi,
                               const size_t hi_size, const int point)
{
    for (int i = 0; i < c->n_scans; i++)
    {
        const tidesdb_mvcc_range_t *r = &c->scans[i];
        if (r->cf_index != cf_index) continue;
        if (point ? mvcc_key_in_range(lo, lo_size, r->lo, r->lo_size, r->hi, r->hi_size)
                  : (hi_size == 0 || tdb_key_cmp(hi, hi_size, r->lo, r->lo_size) > 0) &&
                        (r->hi_size == 0 || tdb_key_cmp(r->hi, r->hi_size, lo, lo_size) > 0))
            return 1;
    }
    return 0;
}

/* whether one of an in-flight commit's read claims falls inside the interval given */
static int mvcc_reads_inside(const tidesdb_mvcc_commit_t *c, const uint32_t cf_index,
                             const uint8_t *lo, const size_t lo_size, const uint8_t *hi,
                             const size_t hi_size)
{
    for (int i = 0; i < c->n_claims; i++)
    {
        const tidesdb_mvcc_claim_t *k = &c->claims[i];
        if (k->kind == TDB_MVCC_CLAIM_READ && k->cf_index == cf_index &&
            mvcc_key_in_range(k->key, k->key_size, lo, lo_size, hi, hi_size))
            return 1;
    }
    return 0;
}

/* whether a commit in flight other than this one read what a write would change -- scanned an
 * interval holding the key given, when point is set, or read a key or scanned an interval meeting
 * the interval given otherwise. only a prepare reads under a claim, and it is held against every
 * writer whatever its sequence, since it validated at prepare and is placed only when its phase two
 * draws. a point write has asked the chains for read claims already, so the walk is skipped when no
 * commit holds scans; an interval cannot ask the chains and always walks */
static int mvcc_reads_meet(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                           const uint32_t cf_index, const uint8_t *lo, const size_t lo_size,
                           const uint8_t *hi, const size_t hi_size, const int point)
{
    if (point && atomic_load_explicit(&m->scan_holders, memory_order_acquire) == 0) return 0;
    pthread_mutex_lock(&m->inflight_lock);
    int met = 0;
    uint32_t walked = 0;
    for (const tidesdb_mvcc_commit_t *c = m->inflight;
         c && !met && walked < TDB_MVCC_INFLIGHT_WALK_MAX; c = c->next_inflight, walked++)
    {
        if (c == commit) continue;
        met = mvcc_scans_meet_one(c, cf_index, lo, lo_size, hi, hi_size, point) ||
              (!point && mvcc_reads_inside(c, cf_index, lo, lo_size, hi, hi_size));
    }
    pthread_mutex_unlock(&m->inflight_lock);
    return met || walked >= TDB_MVCC_INFLIGHT_WALK_MAX;
}

int tidesdb_mvcc_range_read_held(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                                 const uint32_t cf_index, const uint8_t *lo, const size_t lo_size,
                                 const uint8_t *hi, const size_t hi_size)
{
    if (!m || !commit || !lo) return 0;
    return mvcc_reads_meet(m, commit, cf_index, lo, lo_size, hi, hi_size, 0);
}

int tidesdb_mvcc_range_stale(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                             const uint32_t cf_index, const uint8_t *lo, const size_t lo_size,
                             const uint8_t *hi, const size_t hi_size, const int writing)
{
    if (!m || !commit || !lo) return 0;
    pthread_mutex_lock(&m->range_lock);
    int stale = mvcc_interval_meets_holds(m, commit, cf_index, lo, lo_size, hi, hi_size, 1);
    if (!stale)
        stale = mvcc_inflight_meets(m, commit, cf_index, lo, lo_size, hi, hi_size, 1, writing);
    pthread_mutex_unlock(&m->range_lock);
    return stale;
}

int tidesdb_mvcc_write_blocked(tidesdb_mvcc_t *m, const tidesdb_mvcc_commit_t *commit,
                               const uint32_t cf_index, const uint8_t *key, const uint32_t key_size,
                               const uint64_t hash, const int first_committer_wins)
{
    if (!m || !commit || !key) return 0;
    tidesdb_mvcc_claim_t probe;
    tidesdb_mvcc_claim_init(&probe, cf_index, key, key_size, TDB_MVCC_CLAIM_WRITE, hash);

    const uint32_t bucket = mvcc_claim_bucket(hash);
    pthread_mutex_t *lock = mvcc_claim_stripe(m, bucket);
    pthread_mutex_lock(lock);
    int blocked = 0;
    uint32_t walked = 0;
    for (const tidesdb_mvcc_claim_t *o = m->claim_heads[bucket];
         o && !blocked && walked < TDB_MVCC_CLAIM_WALK_MAX; o = o->next, walked++)
        if (o->owner != commit && o->kind == TDB_MVCC_CLAIM_READ && mvcc_claim_same_key(o, &probe))
            blocked = 1;
    if (!blocked && first_committer_wins)
        blocked = mvcc_interval_held_over(m, commit, cf_index, key, key_size, 1);
    pthread_mutex_unlock(lock);
    if (!blocked) blocked = mvcc_reads_meet(m, commit, cf_index, key, key_size, NULL, 0, 1);
    return blocked || walked >= TDB_MVCC_CLAIM_WALK_MAX;
}

void tidesdb_mvcc_unclaim(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit)
{
    if (!m || !commit || !commit->held) return;
    mvcc_unclaim_first(m, commit, commit->n_claims);
    mvcc_release_ranges(m, commit);
    mvcc_inflight_pop(m, commit);
    commit->claims = NULL;
    commit->n_claims = 0;
    commit->scans = NULL;
    commit->n_scans = 0;
}
