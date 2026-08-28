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

#include "base/encoding/serialization.h" /* encode_varint, TDB_CF_PREFIX_SIZE */
#include "base/errors.h"                 /* TDB_ERR_BUSY */
#include "base/log.h"                    /* TDB_DEBUG_LOG for the admission trace */
#include "l0_internal.h"

/* a writer the policy blocks re-reads L0 pressure on this cadence, for at most this many reads. the
 * product is the ceiling a single write can be held for, after which it is admitted regardless --
 * flush that never drains the queue is a stuck engine, and hanging every writer on it forever turns
 * that into an unrecoverable database rather than a slow one */

/* one blocked writer in every this many traces its pressure, so a sustained stall is visible in the
 * log without a line per commit */

/* stack buffer for a small WAL record, so an append avoids a malloc */
#define TDB_L0_WAL_STACK_BUF 512

/* max bytes a base-128 varint of a uint64 occupies */
#define TDB_L0_WAL_MAX_VARINT 10

/* worst-case fixed head of a single-kv WAL record -- varint seq + varint ttl + u8 flags + varint
 * key_size + varint value_size */
#define TDB_L0_WAL_REC_MAX_HEADER (TDB_L0_WAL_MAX_VARINT * 4 + 1)

/* the refcount an idle memtable sits at -- its single structural reference (the active slot or the
 * queue). reclamation frees once every transient reader reference is dropped back to this. */
#define TDB_L0_MEMTABLE_BASELINE 1

/* a reclaimer waiting out a lingering reader reference pauses this long between rechecks */
#define TDB_L0_RECLAIM_DRAIN_STALL_US 50

/**
 * l0_pending_node_t
 * one immutable awaiting a quiet moment to be freed
 * @param mt the memtable, dequeued and unreachable by any new reader
 * @param next the next node in the pending list
 */
typedef struct l0_pending_node
{
    tidesdb_memtable_t *mt;
    struct l0_pending_node *next;
} l0_pending_node_t;

tidesdb_memtable_t *tidesdb_memtable_create(block_manager_t *wal, uint64_t id, uint64_t generation,
                                            int max_level, float probability, _Atomic(int64_t) *now,
                                            arena_pool_t *pool)
{
    tidesdb_memtable_t *mt = malloc(sizeof(*mt));
    if (!mt) return NULL;

    if (skip_list_new_with_arena(&mt->skip_list, max_level, probability, now, pool) != 0)
    {
        free(mt);
        return NULL;
    }

    /* the wal is borrowed -- the flush path owns closing and unlinking it once the immutable this
     * memtable becomes is durably recorded */
    atomic_init(&mt->wal, wal);
    mt->id = id;
    mt->generation = generation;
    atomic_init(&mt->refcount, 1);
    atomic_init(&mt->writers, 0);
    atomic_init(&mt->flushed, 0);
    atomic_init(&mt->claimed, 0);
    atomic_init(&mt->vlog_token, VLOG_BUILD_TOKEN_NONE);

    /* the set itself waits for the first range delete, so a database that never issues one carries
     * nothing but the empty count and the lock */
    mt->range_tombstones = NULL;
    atomic_init(&mt->range_tombstone_frags, 0);
    if (pthread_rwlock_init(&mt->range_tombstone_lock, NULL) != 0)
    {
        skip_list_free(mt->skip_list);
        free(mt);
        return NULL;
    }
    return mt;
}

void tidesdb_memtable_free(tidesdb_memtable_t *mt)
{
    if (!mt) return;
    if (mt->skip_list) skip_list_free(mt->skip_list);
    range_tombstone_set_free(mt->range_tombstones);
    (void)pthread_rwlock_destroy(&mt->range_tombstone_lock);
    free(mt);
}

int tidesdb_wal_filename(uint64_t generation, char *out, size_t out_size)
{
    if (!out || out_size == 0) return TDB_ERR_INVALID_ARGS;
    const int n = snprintf(out, out_size, "%0*llu%s", TDB_WAL_ID_DIGITS,
                           (unsigned long long)generation, TDB_WAL_EXT);
    if (n <= 0 || (size_t)n >= out_size) return TDB_ERR_INVALID_ARGS;
    return TDB_SUCCESS;
}

int tidesdb_wal_flushed_filename(uint64_t generation, char *out, size_t out_size)
{
    if (!out || out_size == 0) return TDB_ERR_INVALID_ARGS;
    const int n = snprintf(out, out_size, "%0*llu%s", TDB_WAL_ID_DIGITS,
                           (unsigned long long)generation, TDB_WAL_FLUSHED_EXT);
    if (n <= 0 || (size_t)n >= out_size) return TDB_ERR_INVALID_ARGS;
    return TDB_SUCCESS;
}

tidesdb_l0_t *tidesdb_l0_create(size_t write_buffer_size, int l0_queue_size, int max_level,
                                float probability, tidesdb_backpressure_policy_fn policy,
                                void *policy_ctx)
{
    tidesdb_l0_t *l0 = calloc(1, sizeof(*l0));
    if (!l0) return NULL;

    l0->queue = queue_new();
    if (!l0->queue)
    {
        free(l0);
        return NULL;
    }

    l0->backpressure = tidesdb_backpressure_new(policy, policy_ctx);
    if (!l0->backpressure)
    {
        queue_free(l0->queue);
        free(l0);
        return NULL;
    }

    l0->write_buffer_size = write_buffer_size;
    l0->vlog = NULL;
    l0->l0_queue_size = l0_queue_size;
    l0->max_level = max_level;
    l0->probability = probability;
    atomic_init(&l0->next_cf_index, 0);
    atomic_init(&l0->flushes_in_flight, 0);
    atomic_init(&l0->admits_throttled, 0);
    atomic_init(&l0->admits_blocked, 0);
    atomic_init(&l0->admit_stall_us, 0);
    atomic_init(&l0->admit_ceiling_hits, 0);
    atomic_init(&l0->aborted_count, 0);
    pthread_mutex_init(&l0->aborted_lock, NULL);
    pthread_mutex_init(&l0->admit_mtx, NULL);
    pthread_cond_init(&l0->admit_cv, NULL);
    return l0;
}

void tidesdb_l0_destroy(tidesdb_l0_t *l0)
{
    if (!l0) return;

    pthread_mutex_destroy(&l0->aborted_lock);
    pthread_mutex_destroy(&l0->admit_mtx);
    pthread_cond_destroy(&l0->admit_cv);

    /* every reader is gone by the time the subsystem is destroyed, so anything still deferred is
     * freed outright rather than checked */
    l0_pending_node_t *pending =
        atomic_exchange_explicit(&l0->pending_reclaim, NULL, memory_order_acq_rel);
    while (pending)
    {
        l0_pending_node_t *next = pending->next;
        tidesdb_memtable_free(pending->mt);
        free(pending);
        pending = next;
    }

    /* free the memtable structs the subsystem owns -- the active one and anything still queued.
     * their WALs are not closed here (the pairing borrows the WAL); the caller owns closing those.
     */
    tidesdb_memtable_t *active = atomic_load_explicit(&l0->active, memory_order_acquire);
    if (active) tidesdb_memtable_free(active);
    if (l0->queue)
    {
        tidesdb_memtable_t *queued;
        while ((queued = (tidesdb_memtable_t *)queue_dequeue(l0->queue)) != NULL)
            tidesdb_memtable_free(queued);
        queue_free(l0->queue);
    }
    tidesdb_backpressure_free(l0->backpressure);
    free(l0);
}

uint32_t tidesdb_l0_cf_index_alloc(tidesdb_l0_t *l0)
{
    if (!l0) return 0;
    return atomic_fetch_add_explicit(&l0->next_cf_index, 1, memory_order_acq_rel);
}

void tidesdb_l0_cf_index_observe(tidesdb_l0_t *l0, uint32_t seen)
{
    if (!l0) return;
    /* raise the allocator floor to seen + 1 with a cas loop so a concurrent alloc or observe never
     * lowers it; guard the wrap so a degenerate max index cannot force the floor back to zero */
    if (seen == UINT32_MAX) return;
    const uint32_t want = seen + 1;
    uint32_t cur = atomic_load_explicit(&l0->next_cf_index, memory_order_acquire);
    while (cur < want)
    {
        if (atomic_compare_exchange_weak_explicit(&l0->next_cf_index, &cur, want,
                                                  memory_order_acq_rel, memory_order_acquire))
            break;
    }
}

void tidesdb_l0_bind_cf_counter(tidesdb_l0_t *l0, uint32_t cf_index, _Atomic(int64_t) *counter)
{
    if (!l0 || cf_index >= TDB_L0_MAX_TRACKED_CFS) return;
    atomic_store_explicit(&l0->cf_unflushed[cf_index], counter, memory_order_release);
}

/* attribute a newly resident distinct key to its column family's unflushed counter, if one is bound
 * at this cf index and within the tracked table */
static void l0_count_new_key(tidesdb_l0_t *l0, uint32_t cf_index)
{
    if (cf_index >= TDB_L0_MAX_TRACKED_CFS) return;
    _Atomic(int64_t) *counter =
        atomic_load_explicit(&l0->cf_unflushed[cf_index], memory_order_acquire);
    if (counter) atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}

/* pin the active slot for reading -- bump the reader epoch, load the slot, and try_ref the loaded
 * memtable, dropping the epoch once the outcome is known. the epoch closes the window where a
 * rotation retires the loaded memtable between the load and the try_ref. returns the pinned
 * memtable, or NULL if the slot was empty or the memtable was already being reclaimed. */
tidesdb_memtable_t *l0_pin_active_read(tidesdb_l0_t *l0)
{
    tdb_epoch_enter(&l0->active_readers);
    tidesdb_memtable_t *mt = atomic_load_explicit(&l0->active, memory_order_acquire);
    const int ok = mt ? tdb_try_ref(&mt->refcount) : 0;
    tdb_epoch_exit(&l0->active_readers);
    return ok ? mt : NULL;
}

/* pin the active slot for writing -- read-pin it, then mark this writer in-flight on the memtable's
 * writers epoch (which a flush drains before reading the memtable) and revalidate the slot did not
 * rotate away. on a lost race it unwinds and retries. returns the pinned memtable, or NULL after
 * the retry budget, which the caller maps to BUSY. */
static tidesdb_memtable_t *l0_pin_active_write(tidesdb_l0_t *l0)
{
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS; attempt++)
    {
        tidesdb_memtable_t *mt = l0_pin_active_read(l0);
        if (!mt) continue;
        tdb_epoch_enter(&mt->writers);
        if (mt == atomic_load_explicit(&l0->active, memory_order_acquire)) return mt;
        /* rotation swapped the slot between the read-pin and the writer mark -- unwind and retry */
        tdb_epoch_exit(&mt->writers);
        if (tdb_unref(&mt->refcount)) tidesdb_memtable_free(mt);
    }
    return NULL;
}

/* drop a read pin; frees the memtable only if this was its last reference (never so while the
 * active slot or the L0 queue still holds its structural reference) */
void l0_unpin_read(tidesdb_memtable_t *mt)
{
    if (tdb_unref(&mt->refcount)) tidesdb_memtable_free(mt);
}

/* drop a write pin -- clear the in-flight writer mark, then drop the reference */
static void l0_unpin_write(tidesdb_memtable_t *mt)
{
    tdb_epoch_exit(&mt->writers);
    l0_unpin_read(mt);
}

/* append one kv as a single framed WAL record so it is durable before it is applied to the
 * skip_list. a NULL wal means an in-memory-only memtable and is a no-op. the numeric fields use the
 * serialization module's varint codec; layout is varint seq, varint ttl, u8 flags, varint key_size,
 * key, varint value_size, value. */
static int l0_wal_append_kv(block_manager_t *wal, const uint8_t *pkey, size_t pkey_size,
                            const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                            uint8_t flags)
{
    if (!wal) return TDB_SUCCESS;

    const size_t rec_max = TDB_L0_WAL_REC_MAX_HEADER + pkey_size + value_size;
    uint8_t stack_rec[TDB_L0_WAL_STACK_BUF];
    uint8_t *rec = rec_max <= sizeof(stack_rec) ? stack_rec : malloc(rec_max);
    if (!rec) return TDB_ERR_MEMORY;

    uint8_t *p = rec;
    p += encode_varint(p, seq);
    p += encode_varint(p, (uint64_t)ttl);
    *p++ = flags;
    p += encode_varint(p, (uint64_t)pkey_size);
    memcpy(p, pkey, pkey_size);
    p += pkey_size;
    p += encode_varint(p, (uint64_t)value_size);
    if (value_size) memcpy(p, value, value_size);
    p += value_size;

    const int64_t off = block_manager_write_raw(wal, rec, (uint32_t)(p - rec));
    if (rec != stack_rec) free(rec);
    return off < 0 ? TDB_ERR_IO : TDB_SUCCESS;
}

static void l0_hold_vlog_floor(tidesdb_l0_t *l0, tidesdb_memtable_t *mt);

tidesdb_memtable_t *tidesdb_l0_set_active(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0 || !mt) return NULL;
    l0_hold_vlog_floor(l0, mt);
    return atomic_exchange_explicit(&l0->active, mt, memory_order_acq_rel);
}

int tidesdb_l0_put(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                   const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                   uint8_t flags)
{
    if (!l0 || !key) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *mt = l0_pin_active_write(l0);
    if (!mt) return TDB_ERR_BUSY;

    const size_t pkey_size = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t stack_key[TDB_L0_KEY_STACK_BUF];
    uint8_t *pkey = pkey_size <= sizeof(stack_key) ? stack_key : malloc(pkey_size);
    if (!pkey)
    {
        l0_unpin_write(mt);
        return TDB_ERR_MEMORY;
    }
    tdb_build_prefixed_key(cf_index, key, key_size, pkey);

    /* wal append before apply so the record is durable before it becomes visible */
    int created = 0;
    int rc = l0_wal_append_kv(atomic_load_explicit(&mt->wal, memory_order_acquire), pkey, pkey_size,
                              value, value_size, ttl, seq, flags);
    if (rc == TDB_SUCCESS &&
        skip_list_put_with_seq_tracked(mt->skip_list, pkey, pkey_size, value, value_size, ttl, seq,
                                       flags, &created) != 0)
        rc = TDB_ERR_MEMORY;
    if (rc == TDB_SUCCESS && created) l0_count_new_key(l0, cf_index);

    if (pkey != stack_key) free(pkey);
    l0_unpin_write(mt);
    return rc;
}

/* take the value log floor a memtable holds while it may be the only thing naming a separated
 * value. taken as it becomes the active memtable rather than when it first receives a reference:
 * the value is written to the log before the commit that produced it reaches any memtable, so a
 * floor taken at the first reference arrives too late -- a reclaim in that window drains the
 * segment the value just went into, and the entry that follows names bytes that are already gone.
 * the floor covers the segment taking appends now, which is at or below wherever a value written
 * from here on lands */
static void l0_hold_vlog_floor(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0->vlog || !mt) return;

    const int fresh = vlog_build_enter(l0->vlog);
    int expected = VLOG_BUILD_TOKEN_NONE;
    if (!atomic_compare_exchange_strong_explicit(&mt->vlog_token, &expected, fresh,
                                                 memory_order_acq_rel, memory_order_acquire))
        vlog_build_leave(l0->vlog, fresh); /* already holds one, so give the extra back */
}

/* reach this memtable's floor back to the segment a reference's bytes actually live in. its own
 * floor covers everything written after it became active, but a value separated a moment before a
 * rotation is applied here while living in a segment below that point */
static void l0_protect_reference(tidesdb_l0_t *l0, tidesdb_memtable_t *mt, uint64_t vlog_id)
{
    if (!l0->vlog) return;

    const int token = atomic_load_explicit(&mt->vlog_token, memory_order_acquire);
    if (token == VLOG_BUILD_TOKEN_NONE) return;

    uint64_t segment = 0;
    if (vlog_id_segment(l0->vlog, vlog_id, &segment) == VLOG_OK)
        vlog_build_lower(l0->vlog, token, segment);
}

/* the shared body behind both applies -- pin the active memtable, prefix the key, put, and count a
 * newly distinct key. put_entry decides whether the version holds the bytes or an id */
static int l0_apply_entry(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                          const uint8_t *value, size_t value_size, uint64_t vlog_id, int64_t ttl,
                          uint64_t seq, uint8_t flags)
{
    if (!l0 || !key) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *mt = l0_pin_active_write(l0);
    if (!mt) return TDB_ERR_BUSY;

    const size_t pkey_size = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t stack_key[TDB_L0_KEY_STACK_BUF];
    uint8_t *pkey = pkey_size <= sizeof(stack_key) ? stack_key : malloc(pkey_size);
    if (!pkey)
    {
        l0_unpin_write(mt);
        return TDB_ERR_MEMORY;
    }
    tdb_build_prefixed_key(cf_index, key, key_size, pkey);

    /* the value's bytes are reachable only through this memtable until its flush installs, and the
     * segment holding them reads as dead until then. hold a floor over that segment, taken on the
     * first reference and reached back for every one after it -- a value separated a moment before
     * a rotation lands here while the segment it went into may already be below this memtable's
     * own starting point */
    if (vlog_id != 0) l0_protect_reference(l0, mt, vlog_id);

    /* the txn backend already wrote this entry to the WAL as part of the commit batch, so apply
     * only makes it visible in the skip_list */
    int created = 0;
    const int put = vlog_id != 0
                        ? skip_list_put_reference_with_seq(mt->skip_list, pkey, pkey_size, vlog_id,
                                                           value_size, ttl, seq, flags, &created)
                        : skip_list_put_with_seq_tracked(mt->skip_list, pkey, pkey_size, value,
                                                         value_size, ttl, seq, flags, &created);
    const int rc = put == 0 ? TDB_SUCCESS : TDB_ERR_MEMORY;
    if (rc == TDB_SUCCESS && created) l0_count_new_key(l0, cf_index);

    if (pkey != stack_key) free(pkey);
    l0_unpin_write(mt);
    return rc;
}

int tidesdb_l0_apply(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                     const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                     uint8_t flags)
{
    return l0_apply_entry(l0, cf_index, key, key_size, value, value_size, 0, ttl, seq, flags);
}

int tidesdb_l0_apply_reference(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key,
                               const size_t key_size, const uint64_t vlog_id,
                               const size_t value_size, const int64_t ttl, const uint64_t seq,
                               const uint8_t flags)
{
    if (vlog_id == 0 || (flags & SKIP_LIST_FLAG_DELETED)) return TDB_ERR_INVALID_ARGS;
    return l0_apply_entry(l0, cf_index, key, key_size, NULL, value_size, vlog_id, ttl, seq, flags);
}

/* what this memtable's range tombstones cost, read under the same lock a writer takes so the walk
 * cannot race a re-fragmentation. a memtable that has never taken one answers from a single load */
static size_t l0_range_tombstone_bytes(tidesdb_memtable_t *mt)
{
    if (atomic_load_explicit(&mt->range_tombstone_frags, memory_order_acquire) == 0) return 0;

    pthread_rwlock_rdlock(&mt->range_tombstone_lock);
    const size_t bytes = range_tombstone_set_bytes(mt->range_tombstones);
    pthread_rwlock_unlock(&mt->range_tombstone_lock);
    return bytes;
}

int tidesdb_l0_apply_range_tombstone(tidesdb_l0_t *l0, const uint32_t cf_index, const uint8_t *lo,
                                     const size_t lo_size, const uint8_t *hi, const size_t hi_size,
                                     const uint64_t seq)
{
    if (!l0 || !lo || lo_size == 0) return TDB_ERR_INVALID_ARGS;
    if (hi_size > 0 && !hi) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *mt = l0_pin_active_write(l0);
    if (!mt) return TDB_ERR_BUSY;

    /* the interval is stored over the prefixed keyspace the skip list is already sorted in, so one
     * set covers every family. an upper bound left open ends where the next family begins, which is
     * that family's prefix and nothing of it -- no key of the next family sorts at or below its own
     * bare prefix, since every key carries at least one byte beyond it */
    const size_t plo_size = TDB_CF_PREFIX_SIZE + lo_size;
    const size_t phi_size = hi_size > 0 ? TDB_CF_PREFIX_SIZE + hi_size : TDB_CF_PREFIX_SIZE;
    uint8_t stack_lo[TDB_L0_KEY_STACK_BUF];
    uint8_t stack_hi[TDB_L0_KEY_STACK_BUF];
    uint8_t *plo = plo_size <= sizeof(stack_lo) ? stack_lo : malloc(plo_size);
    uint8_t *phi = phi_size <= sizeof(stack_hi) ? stack_hi : malloc(phi_size);
    if (!plo || !phi)
    {
        if (plo && plo != stack_lo) free(plo);
        if (phi && phi != stack_hi) free(phi);
        l0_unpin_write(mt);
        return TDB_ERR_MEMORY;
    }
    tdb_build_prefixed_key(cf_index, lo, lo_size, plo);

    /* a family at the very top of the index space has no next one to stop at, so the interval runs
     * to the end of the order and is stored unbounded above */
    int unbounded = 0;
    if (hi_size > 0)
        tdb_build_prefixed_key(cf_index, hi, hi_size, phi);
    else if (cf_index == UINT32_MAX)
        unbounded = 1;
    else
        tdb_build_prefixed_key(cf_index + 1, NULL, 0, phi);

    pthread_rwlock_wrlock(&mt->range_tombstone_lock);
    int rc = TDB_SUCCESS;
    if (!mt->range_tombstones)
    {
        mt->range_tombstones = range_tombstone_set_new();
        if (!mt->range_tombstones) rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS)
        rc = range_tombstone_set_add(mt->range_tombstones, plo, plo_size, unbounded ? NULL : phi,
                                     unbounded ? RT_UNBOUNDED_ABOVE : phi_size, seq);
    if (rc == TDB_SUCCESS)
        atomic_store_explicit(&mt->range_tombstone_frags,
                              range_tombstone_set_count(mt->range_tombstones),
                              memory_order_release);
    pthread_rwlock_unlock(&mt->range_tombstone_lock);

    if (plo != stack_lo) free(plo);
    if (phi != stack_hi) free(phi);
    l0_unpin_write(mt);
    return rc;
}

void tidesdb_l0_set_vlog(tidesdb_l0_t *l0, vlog_t *vlog)
{
    if (l0) l0->vlog = vlog;
}

void tidesdb_l0_set_wal_ack_on_stage(tidesdb_l0_t *l0, const int ack_on_stage)
{
    if (l0) l0->wal_ack_on_stage = ack_on_stage;
}

/**
 * l0_pace_against_ring
 * dwell when the write-ahead log's staging ring is filling, so ingest meets the flush thread's rate
 * gradually instead of colliding with it. an appender whose ring slot still holds unwritten bytes
 * waits for the flush thread to reach it, which stops every committer at once for as long as a
 * whole ring takes to drain -- a wall the queue-driven admission path cannot see, because it reads
 * the immutable queue and the ring is a different resource. paced here rather than in admission
 * because this path already holds the log pinned, so the lag costs two atomic loads and no pin
 * @param l0 the subsystem, for its policy and counters
 * @param wal the pinned active log
 */
static void l0_pace_against_ring(tidesdb_l0_t *l0, block_manager_t *wal)
{
    if (!l0->backpressure) return;

    uint64_t lag = 0, capacity = 0;
    if (block_manager_buffered_lag(wal, &lag, &capacity) != 0 || capacity == 0) return;

    /* the queue fields are left zero on purpose: this decision is the ring's alone, and the queue
     * has its own admission point that weighs it properly */
    tidesdb_l0_pressure_t pressure;
    memset(&pressure, 0, sizeof(pressure));
    pressure.wal_ring_bytes = (size_t)capacity;
    pressure.wal_lag_bytes = (size_t)lag;

    const tidesdb_backpressure_decision_t decision =
        tidesdb_backpressure_decide(l0->backpressure, &pressure);
    if (decision.action != TDB_BACKPRESSURE_THROTTLE || decision.throttle_us == 0) return;

    /* measured rather than the figure asked for, because the other contributor to this counter is
     * measured and a total mixing the two describes neither. a sleep is not the length it was
     * asked for on any platform, and on the ones that round it up it is not close */
    const uint64_t paced_from = tdb_monotonic_us();
    usleep((unsigned int)decision.throttle_us);
    const uint64_t paced_us = tdb_monotonic_us() - paced_from;
    atomic_fetch_add_explicit(&l0->admits_throttled, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&l0->admit_stall_us, paced_us, memory_order_relaxed);
}

int tidesdb_l0_sync_active_wal(tidesdb_l0_t *l0)
{
    if (!l0) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *mt = l0_pin_active_write(l0);
    if (!mt) return TDB_ERR_BUSY;

    block_manager_t *wal = atomic_load_explicit(&mt->wal, memory_order_acquire);
    int rc = TDB_SUCCESS;
    if (wal && block_manager_escalate_fsync(wal) != 0) rc = TDB_ERR_IO;

    l0_unpin_write(mt);
    return rc;
}

int tidesdb_l0_wal_append_one(tidesdb_l0_t *l0, const uint8_t *batch, size_t size)
{
    if (!l0 || !batch || size == 0) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *mt = l0_pin_active_write(l0);
    if (!mt) return TDB_ERR_BUSY;

    /* the pin is what keeps this WAL alive across the wait below -- a rotation only seals the
     * memtable, it does not drain the ring, so the block manager the record was staged into has to
     * still be the one waited on */
    block_manager_t *wal = atomic_load_explicit(&mt->wal, memory_order_acquire);
    int rc = TDB_SUCCESS;
    if (wal)
    {
        l0_pace_against_ring(l0, wal);

        block_manager_block_t frame;
        frame.size = size;
        /* the block manager only reads the payload while framing it, so borrowing the submitter's
         * bytes is what keeps this append copy-free */
        frame.data = (void *)(uintptr_t)batch;
        frame.inline_data = 0;
        /* staging is the whole append when the mode acknowledges there; the sealed WAL is still
         * drained before its file is closed, so a record that outlives the ring reaches disk even
         * though no committer waited for it */
        /* the append is where a committer meets the log: it waits here for staging-ring space, and
         * under a syncing mode for its record to reach the file. that wait is what a write latency
         * tail is usually made of, so it is measured rather than inferred */
        const uint64_t started_us = tdb_monotonic_us();
        const int64_t offset = l0->wal_ack_on_stage
                                   ? block_manager_block_write(wal, &frame)
                                   : block_manager_block_write_durable(wal, &frame);
        const uint64_t waited_us = tdb_monotonic_us() - started_us;
        if (waited_us > 0) tdb_wait_note(&l0->wal_wait, waited_us);
        if (offset < 0)
            rc = TDB_ERR_IO;
        else
            atomic_fetch_add_explicit(
                &l0->wal_bytes_written,
                BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)size + BLOCK_MANAGER_FOOTER_SIZE,
                memory_order_relaxed);
    }

    l0_unpin_write(mt);
    return rc;
}

int tidesdb_l0_mark_aborted(tidesdb_l0_t *l0, const uint64_t seq)
{
    if (!l0 || seq == 0) return TDB_ERR_INVALID_ARGS;

    pthread_mutex_lock(&l0->aborted_lock);
    const int n = atomic_load_explicit(&l0->aborted_count, memory_order_relaxed);
    if (n >= TDB_L0_MAX_ABORTED_SEQS)
    {
        pthread_mutex_unlock(&l0->aborted_lock);
        return TDB_ERR_MEMORY_LIMIT;
    }
    l0->aborted_seqs[n] = seq;
    /* published after the slot is written, so a reader that sees the new count sees the sequence */
    atomic_store_explicit(&l0->aborted_count, n + 1, memory_order_release);
    pthread_mutex_unlock(&l0->aborted_lock);
    return TDB_SUCCESS;
}

int tidesdb_l0_seq_aborted(const tidesdb_l0_t *l0, const uint64_t seq)
{
    if (!l0) return 0;
    /* entries are only ever appended, so a reader needs no lock -- it takes the published count and
     * walks that many slots, every one of which was written before the count that admits it. the
     * table is empty in every database that has not had a commit fail, which is the common case and
     * costs one relaxed load */
    const int n = atomic_load_explicit(&l0->aborted_count, memory_order_acquire);
    for (int i = 0; i < n; i++)
        if (l0->aborted_seqs[i] == seq) return 1;
    return 0;
}

int tidesdb_l0_rotate(tidesdb_l0_t *l0, tidesdb_memtable_t *new_mt)
{
    if (!l0 || !new_mt) return TDB_ERR_INVALID_ARGS;

    /* before the swap, so the incoming memtable's floor is in place from the first commit that can
     * reach it */
    l0_hold_vlog_floor(l0, new_mt);

    /* the caller holds rotate_lock, so the active slot cannot change under us and this load names
     * the memtable the swap below will seal */
    tidesdb_memtable_t *sealed = atomic_load_explicit(&l0->active, memory_order_acquire);
    if (!sealed)
    {
        atomic_store_explicit(&l0->active, new_mt, memory_order_release); /* first install */
        return TDB_SUCCESS;
    }

    /* enqueue the sealed memtable before swapping the active, so a reader is never in the window
     * where the memtable is neither the active nor in the queue and a just-committed key reads back
     * stale. during the swap the sealed memtable is reachable both as the active and in the queue,
     * and the release-swap pairs with a reader's acquire-load of the active so a reader that sees
     * new_mt also sees the enqueue. the queue takes over the sealed memtable's structural
     * reference, so an enqueue OOM leaves it in the active slot untouched and the data stays
     * durable in its WAL for recovery. */
    if (queue_enqueue(l0->queue, sealed) != 0) return TDB_ERR_MEMORY;
    atomic_exchange_explicit(&l0->active, new_mt, memory_order_acq_rel);
    /* publish the boundary move so a reader that bracketed its active-then-queue read across this
     * rotation observes the change and retries rather than reporting a false miss */
    atomic_fetch_add_explicit(&l0->visible_changes, 1, memory_order_release);
    return TDB_SUCCESS;
}

int tidesdb_l0_active_full(tidesdb_l0_t *l0)
{
    if (!l0 || l0->write_buffer_size == 0) return 0;

    tidesdb_memtable_t *mt = NULL;
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS; attempt++)
    {
        mt = l0_pin_active_read(l0);
        if (mt) break;
    }
    if (!mt) return 0;

    const int full = skip_list_get_memory_bytes(mt->skip_list) + l0_range_tombstone_bytes(mt) >=
                     l0->write_buffer_size;
    l0_unpin_read(mt);
    return full;
}

size_t tidesdb_l0_active_bytes(tidesdb_l0_t *l0)
{
    if (!l0) return 0;

    tidesdb_memtable_t *mt = NULL;
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS; attempt++)
    {
        mt = l0_pin_active_read(l0);
        if (mt) break;
    }
    if (!mt) return 0;

    /* the range tombstones count toward the memtable's size too. without them a memtable holding
     * nothing but prefix deletes measures as empty, and neither the size trigger nor the idle flush
     * would ever seal it -- so the deletes would sit in memory with no flush to make them durable
     */
    const size_t bytes = skip_list_get_memory_bytes(mt->skip_list) + l0_range_tombstone_bytes(mt);
    l0_unpin_read(mt);
    return bytes;
}

void tidesdb_l0_admit_wake(tidesdb_l0_t *l0)
{
    if (!l0) return;
    /* taken so a waiter cannot be between its check and its wait and miss this. broadcast rather
     * than signal because every blocked writer is waiting on the same backlog and one slot may
     * admit several of them, and each re-decides for itself on waking */
    pthread_mutex_lock(&l0->admit_mtx);
    pthread_cond_broadcast(&l0->admit_cv);
    pthread_mutex_unlock(&l0->admit_mtx);
}

tidesdb_memtable_t *tidesdb_l0_dequeue_immutable(tidesdb_l0_t *l0)
{
    if (!l0) return NULL;
    tidesdb_memtable_t *mt = (tidesdb_memtable_t *)queue_dequeue(l0->queue);
    /* the queue just got shallower, which is the thing a blocked writer is waiting on */
    if (mt) tidesdb_l0_admit_wake(l0);
    return mt;
}

tidesdb_memtable_t *tidesdb_l0_claim_immutable(tidesdb_l0_t *l0)
{
    if (!l0) return NULL;

    /* run under the reader epoch, exactly as a read does, so a concurrent retire cannot free a
     * queued immutable between the snapshot and the claim compare-and-swap */
    tdb_epoch_enter(&l0->active_readers);
    const size_t depth = queue_size(l0->queue);
    if (depth == 0)
    {
        tdb_epoch_exit(&l0->active_readers);
        return NULL;
    }

    tidesdb_memtable_t *stack_snap[TDB_L0_IMMUTABLE_SNAP_STACK];
    void **snap =
        depth <= TDB_L0_IMMUTABLE_SNAP_STACK ? (void **)stack_snap : malloc(depth * sizeof(void *));
    if (!snap)
    {
        tdb_epoch_exit(&l0->active_readers);
        return NULL;
    }
    const size_t got = queue_snapshot(l0->queue, snap, depth);

    /* claim the oldest immutable no worker has taken yet, leaving it in the queue so readers still
     * see it until it is retired after its data reaches L1. a memtable already retired by another
     * worker is claimed, so the compare-and-swap skips it. a memtable still sitting in the active
     * slot is mid rotation -- it is in the queue for reader visibility but writers still target it,
     * so skip it until the swap makes it truly immutable, or a flush would race those writers and
     * lose their data */
    tidesdb_memtable_t *claimed = NULL;
    for (size_t i = 0; i < got && !claimed; i++)
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
        if (!mt || mt == atomic_load_explicit(&l0->active, memory_order_acquire)) continue;
        int expected = 0;
        if (atomic_compare_exchange_strong(&mt->claimed, &expected, 1)) claimed = mt;
    }
    if (snap != (void **)stack_snap) free(snap);
    tdb_epoch_exit(&l0->active_readers);
    if (claimed) atomic_fetch_add_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    return claimed;
}

/* queue_remove_if predicate matching the single memtable passed as context */
static int l0_match_memtable(void *data, void *context)
{
    return data == context;
}

void tidesdb_l0_retire_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0 || !mt) return;
    /* remove this immutable from the reader-visible queue now that its data is durable in L1, then
     * reclaim it once the readers that pinned it drain. this moves the reader-visible set exactly
     * as a rotation does, so it is published the same way -- a reader that missed the active and
     * then found this immutable already gone would otherwise report an absence it cannot stand
     * behind */
    (void)queue_remove_if(l0->queue, l0_match_memtable, mt, NULL);
    atomic_fetch_add_explicit(&l0->visible_changes, 1, memory_order_release);
    atomic_fetch_sub_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    tidesdb_l0_reclaim(l0, mt);
}

void tidesdb_l0_release_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!l0 || !mt) return;
    atomic_fetch_sub_explicit(&l0->flushes_in_flight, 1, memory_order_relaxed);
    atomic_store_explicit(&mt->claimed, 0, memory_order_release);
}

void tidesdb_l0_wal_wait_stats(const tidesdb_l0_t *l0, tidesdb_l0_wal_wait_t *out)
{
    if (!out) return;
    if (!l0)
    {
        memset(out, 0, sizeof(*out));
        return;
    }
    tdb_wait_read(&l0->wal_wait, &out->count, &out->total_us, &out->max_us);
}

uint64_t tidesdb_l0_wal_bytes_written(const tidesdb_l0_t *l0)
{
    return l0 ? atomic_load_explicit(&l0->wal_bytes_written, memory_order_relaxed) : 0;
}

size_t tidesdb_l0_queue_depth(const tidesdb_l0_t *l0)
{
    if (!l0) return 0;
    return queue_size(l0->queue);
}

void tidesdb_memtable_mark_flushed(tidesdb_memtable_t *mt)
{
    if (!mt) return;
    atomic_store_explicit(&mt->flushed, 1, memory_order_release);
}

int tidesdb_l0_pin_memtables(tidesdb_l0_t *l0, tidesdb_memtable_t **out, int max, int *n_out)
{
    if (!l0 || !out || !n_out) return TDB_ERR_INVALID_ARGS;
    *n_out = 0;

    /* pin the active memtable; a rotation that keeps swapping it out is transient */
    tidesdb_memtable_t *active = NULL;
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS && !active; attempt++)
        active = l0_pin_active_read(l0);

    /* snapshot and pin the immutable queue under the reader epoch, exactly as a read does */
    const size_t depth = queue_size(l0->queue);
    tidesdb_memtable_t *stack_snap[TDB_L0_IMMUTABLE_SNAP_STACK];
    void **snap =
        depth <= TDB_L0_IMMUTABLE_SNAP_STACK ? (void **)stack_snap : malloc(depth * sizeof(void *));
    if (depth > 0 && !snap)
    {
        if (active) l0_unpin_read(active);
        return TDB_ERR_MEMORY;
    }

    int n_imm = 0;
    if (depth > 0)
    {
        tdb_epoch_enter(&l0->active_readers);
        const size_t got = queue_snapshot(l0->queue, snap, depth);
        for (size_t i = 0; i < got; i++)
        {
            tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
            if (mt && tdb_try_ref(&mt->refcount)) snap[n_imm++] = mt; /* compact the pinned ones */
        }
        tdb_epoch_exit(&l0->active_readers);
    }

    const int total = (active ? 1 : 0) + n_imm;
    if (total > max)
    {
        /* the caller under-sized out; release every pin and report the needed count for a retry */
        if (active) l0_unpin_read(active);
        for (int i = 0; i < n_imm; i++) l0_unpin_read((tidesdb_memtable_t *)snap[i]);
        if (snap != (void **)stack_snap) free(snap);
        *n_out = total;
        return TDB_ERR_TOO_LARGE;
    }

    /* newest first -- the active, then the immutables from the queue tail (newest) to head */
    int k = 0;
    if (active) out[k++] = active;
    for (int i = n_imm - 1; i >= 0; i--) out[k++] = (tidesdb_memtable_t *)snap[i];
    if (snap != (void **)stack_snap) free(snap);
    *n_out = total;
    return TDB_SUCCESS;
}

void tidesdb_l0_unpin_memtables(tidesdb_memtable_t **mts, int n)
{
    if (!mts) return;
    for (int i = 0; i < n; i++)
        if (mts[i] && tdb_unref(&mts[i]->refcount)) tidesdb_memtable_free(mts[i]);
}

/* how many times reclaim rechecks inline before handing the immutable to the pending list. the
 * common case is that the readers holding it are point reads that finish in microseconds, so a
 * short recheck frees it here and the list stays empty */
#define TDB_L0_RECLAIM_INLINE_ATTEMPTS 20

/* push a node onto the lock-free pending list */
static void l0_pending_push(tidesdb_l0_t *l0, l0_pending_node_t *node)
{
    l0_pending_node_t *head = atomic_load_explicit(&l0->pending_reclaim, memory_order_acquire);
    do
    {
        node->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&l0->pending_reclaim, (void **)&head, node,
                                                    memory_order_release, memory_order_acquire));
}

/* whether an immutable can be freed now -- no reader is inside the pin window and none holds a
 * reference beyond the structural one the queue dropped */
static int l0_reclaim_ready(const tidesdb_l0_t *l0, const tidesdb_memtable_t *mt)
{
    if (l0 && tdb_epoch_active(&l0->active_readers) > 0) return 0;
    return atomic_load_explicit(&mt->refcount, memory_order_acquire) <= TDB_L0_MEMTABLE_BASELINE;
}

void tidesdb_l0_reclaim_pending(tidesdb_l0_t *l0)
{
    if (!l0) return;
    l0_pending_node_t *cur =
        atomic_exchange_explicit(&l0->pending_reclaim, NULL, memory_order_acq_rel);
    while (cur)
    {
        l0_pending_node_t *next = cur->next;
        if (l0_reclaim_ready(l0, cur->mt))
        {
            tidesdb_memtable_free(cur->mt);
            free(cur);
        }
        else
        {
            l0_pending_push(l0, cur);
        }
        cur = next;
    }
}

void tidesdb_l0_reclaim(tidesdb_l0_t *l0, tidesdb_memtable_t *mt)
{
    if (!mt) return;

    /* the caller dequeued mt, so no new reader can reach it and the only question is when the
     * readers already holding it leave. this runs inside a flush install, under locks a create or
     * drop needs, so it must not wait on that unboundedly -- the reader epoch is db-global and a
     * database under continuous reads may never present a quiet instant to the thread that happens
     * to be asking. recheck briefly, and hand anything still held to the pending list for the
     * reaper to free once the readers do leave */
    for (int attempt = 0; attempt < TDB_L0_RECLAIM_INLINE_ATTEMPTS; attempt++)
    {
        if (l0_reclaim_ready(l0, mt))
        {
            tidesdb_memtable_free(mt);
            return;
        }
        usleep(TDB_L0_RECLAIM_DRAIN_STALL_US);
    }

    if (!l0)
    {
        tidesdb_memtable_free(mt);
        return;
    }

    l0_pending_node_t *node = malloc(sizeof(*node));
    if (!node)
    {
        /* nowhere to defer it to, so the old inline wait is the only option left */
        tdb_epoch_wait_drained(&l0->active_readers);
        while (atomic_load_explicit(&mt->refcount, memory_order_acquire) > TDB_L0_MEMTABLE_BASELINE)
            usleep(TDB_L0_RECLAIM_DRAIN_STALL_US);
        tidesdb_memtable_free(mt);
        return;
    }
    node->mt = mt;
    l0_pending_push(l0, node);
}
