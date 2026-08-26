/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "registry.h"

#include <stdlib.h>

#include "db.h"  /* TDB_SUCCESS / TDB_ERR_* */
#include "txn.h" /* tdb_txn_snapshot and the registry slot accessors */

/* initial capacity of one shard's array, grown by doubling; shards start small because the live set
 * is usually a handful of transactions spread across every shard */
#define TDB_TXN_REGISTRY_INITIAL_CAP 8

/* the registry is sharded because joining and leaving it is the hot path -- every transaction does
 * both exactly once, whatever else it does -- and a single lock made that a database-wide
 * serialization point. the cost is per transaction rather than per unit of work, so it grows with
 * concurrency rather than with load. a power of two so the shard index is a mask */
/* the count trades two costs against each other. more shards spread the join and leave that every
 * transaction pays, but tidesdb_txn_registry_for_each holds *every* shard for its walk, so a
 * serializable commit acquires this many locks at once -- and a thread holding 64 locks at once is
 * past what tooling will model (tsan's deadlock detector caps a thread there and aborts). 32 is
 * twice the spread of the original 16 while leaving that walk well inside the bound */
#define TDB_TXN_REGISTRY_SHARDS 32
#define TDB_TXN_REGISTRY_MASK   (TDB_TXN_REGISTRY_SHARDS - 1)

/**
 * tidesdb_txn_registry_shard_t
 * one shard's live-transaction array and the lock guarding it
 * @param txns borrowed transaction pointers
 * @param count number of live transactions in this shard
 * @param capacity allocated length of txns
 * @param lock guards this shard's array and lets a scanner hold it stable
 */
typedef struct
{
    tdb_txn_t **txns;
    int count;
    int capacity;
    pthread_rwlock_t lock;
} tidesdb_txn_registry_shard_t;

/**
 * tidesdb_txn_registry
 * the live-transaction set, split across independent shards selected by joining thread
 * @param shards the shard array
 * @param published_min the last minimum a scan published, for readers that cannot afford the scan
 *                      itself; starts at zero, which reads as "assume nothing"
 */
struct tidesdb_txn_registry
{
    tidesdb_txn_registry_shard_t shards[TDB_TXN_REGISTRY_SHARDS];
    _Atomic(uint64_t) published_min;
};

/* the shard a joining transaction takes, claimed once per thread from a global counter.
 *
 * derived from the joining thread rather than the transaction's address. a caller running one short
 * transaction at a time -- which is what a statement-scoped transaction looks like, and what the
 * mariadb plugin does under autocommit -- frees and reallocates at the same few addresses, so an
 * address-derived shard collapses onto a handful of slots and unrelated threads collide on one
 * lock. the thread is the thing that actually contends, so sharding on it is what spreads them.
 *
 * a transaction records the shard it landed in and remove reads that back rather than recomputing,
 * so one begun on a different thread than it is freed on still finds its own shard */
static THREAD_LOCAL int t_registry_slot = -1;
static _Atomic(int) g_registry_slot_counter = 0;

static int tidesdb_txn_registry_shard_of(void)
{
    if (t_registry_slot < 0)
    {
        const int s = atomic_fetch_add_explicit(&g_registry_slot_counter, 1, memory_order_relaxed);
        t_registry_slot = s & TDB_TXN_REGISTRY_MASK;
    }
    return t_registry_slot;
}

tidesdb_txn_registry_t *tidesdb_txn_registry_create(void)
{
    tidesdb_txn_registry_t *reg = calloc(1, sizeof(*reg));
    if (!reg) return NULL;

    for (int i = 0; i < TDB_TXN_REGISTRY_SHARDS; i++)
    {
        if (pthread_rwlock_init(&reg->shards[i].lock, NULL) != 0)
        {
            while (--i >= 0) pthread_rwlock_destroy(&reg->shards[i].lock);
            free(reg);
            return NULL;
        }
    }
    return reg;
}

void tidesdb_txn_registry_destroy(tidesdb_txn_registry_t *reg)
{
    if (!reg) return;
    for (int i = 0; i < TDB_TXN_REGISTRY_SHARDS; i++)
    {
        free(reg->shards[i].txns);
        pthread_rwlock_destroy(&reg->shards[i].lock);
    }
    free(reg);
}

int tidesdb_txn_registry_add(tidesdb_txn_registry_t *reg, tdb_txn_t *txn)
{
    if (!reg || !txn) return TDB_ERR_INVALID_ARGS;

    const int s = tidesdb_txn_registry_shard_of();
    tidesdb_txn_registry_shard_t *shard = &reg->shards[s];

    pthread_rwlock_wrlock(&shard->lock);
    if (shard->count == shard->capacity)
    {
        const int new_cap = shard->capacity ? shard->capacity * 2 : TDB_TXN_REGISTRY_INITIAL_CAP;
        tdb_txn_t **grown = realloc(shard->txns, (size_t)new_cap * sizeof(*grown));
        if (!grown)
        {
            pthread_rwlock_unlock(&shard->lock);
            return TDB_ERR_MEMORY;
        }
        shard->txns = grown;
        shard->capacity = new_cap;
    }
    /* the transaction records where it landed so leaving is O(1), and the shard is stored rather
     * than recomputed so a remove cannot disagree with the add about which lock it needs -- which
     * is also what lets a transaction be freed on a thread other than the one that began it */
    shard->txns[shard->count] = txn;
    tdb_txn_set_registry_slot(txn, s, shard->count);
    shard->count++;
    pthread_rwlock_unlock(&shard->lock);
    return TDB_SUCCESS;
}

void tidesdb_txn_registry_remove(tidesdb_txn_registry_t *reg, tdb_txn_t *txn)
{
    if (!reg || !txn) return;

    const int s = tdb_txn_registry_shard(txn);
    if (s < 0 || s >= TDB_TXN_REGISTRY_SHARDS) return; /* never added, or already removed */
    tidesdb_txn_registry_shard_t *shard = &reg->shards[s];

    pthread_rwlock_wrlock(&shard->lock);
    /* the txn carries its own slot, so leave is O(1): swap the last entry into it and fix that
     * entry's recorded slot, instead of scanning the array under the lock */
    const int i = tdb_txn_registry_index(txn);
    if (i >= 0 && i < shard->count && shard->txns[i] == txn)
    {
        tdb_txn_t *moved = shard->txns[shard->count - 1];
        shard->txns[i] = moved;
        tdb_txn_set_registry_slot(moved, s, i);
        shard->count--;
        tdb_txn_set_registry_slot(txn, -1, -1);
    }
    pthread_rwlock_unlock(&shard->lock);
}

uint64_t tidesdb_txn_registry_min_snapshot(tidesdb_txn_registry_t *reg)
{
    if (!reg) return UINT64_MAX;

    /* one shard at a time rather than the whole registry frozen. the answer can only come out too
     * low, never too high, and too low is the safe direction for a gc floor -- it keeps a version a
     * reader might still want. it cannot come out too high because both ways the set moves fail
     * safe: a transaction added after its shard was read draws its snapshot from a monotonic clock,
     * so it is above the minimum and could not have lowered it, and a transaction that leaves only
     * raises the true minimum above what was reported */
    uint64_t min = UINT64_MAX;
    for (int s = 0; s < TDB_TXN_REGISTRY_SHARDS; s++)
    {
        tidesdb_txn_registry_shard_t *shard = &reg->shards[s];
        pthread_rwlock_rdlock(&shard->lock);
        for (int i = 0; i < shard->count; i++)
        {
            const uint64_t snap = tdb_txn_snapshot(shard->txns[i]);
            if (snap < min) min = snap;
        }
        pthread_rwlock_unlock(&shard->lock);
    }
    return min;
}

void tidesdb_txn_registry_publish_min_snapshot(tidesdb_txn_registry_t *reg)
{
    if (!reg) return;

    /* an empty registry answers UINT64_MAX, which is a sentinel for "nothing constrains you"
     * rather than a real minimum -- publishing it would let a transaction that begins afterwards
     * hold a snapshot below the published value, which is the one direction a reader of this may
     * not tolerate. zero is the honest answer for an empty set: it constrains nothing wrongly */
    const uint64_t exact = tidesdb_txn_registry_min_snapshot(reg);
    atomic_store_explicit(&reg->published_min, exact == UINT64_MAX ? 0 : exact,
                          memory_order_relaxed);
}

uint64_t tidesdb_txn_registry_published_min_snapshot(const tidesdb_txn_registry_t *reg)
{
    return reg ? atomic_load_explicit(&reg->published_min, memory_order_relaxed) : 0;
}

int tidesdb_txn_registry_for_each(tidesdb_txn_registry_t *reg, tidesdb_txn_visit_fn visit,
                                  void *ctx)
{
    if (!reg || !visit) return 0;

    /* every shard is held for the whole walk, so the caller sees one instant of the live set rather
     * than a smear across shards. serializable commit validation needs exactly that: it decides
     * against the set of concurrent peers, and a peer that appeared between two shards could
     * otherwise be missed by this validation and by its own. the locks are taken in index order,
     * which is the only order anything takes them in, so they cannot deadlock against each other.
     * holding all of them is acceptable because this walk is rare -- a serializable commit or a
     * stats call, never the ordinary write path, which touches one shard */
    for (int s = 0; s < TDB_TXN_REGISTRY_SHARDS; s++) pthread_rwlock_rdlock(&reg->shards[s].lock);

    int stopped = 0;
    for (int s = 0; s < TDB_TXN_REGISTRY_SHARDS && !stopped; s++)
    {
        const tidesdb_txn_registry_shard_t *shard = &reg->shards[s];
        for (int i = 0; i < shard->count; i++)
            if (visit(shard->txns[i], ctx) != 0)
            {
                stopped = 1;
                break;
            }
    }

    for (int s = TDB_TXN_REGISTRY_SHARDS - 1; s >= 0; s--)
        pthread_rwlock_unlock(&reg->shards[s].lock);
    return stopped;
}
