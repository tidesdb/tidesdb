/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_LOCKFREE_H__
#define __TIDESDB_BASE_LOCKFREE_H__

#include "../compat.h" /* atomics, cpu_pause, cpu_yield, usleep */

/* the engine's lock-free machinery reduces to two ideas -- a reader-drain epoch counter, and
 * deferred reclamation guarded by such a counter. these primitives are type-agnostic (they operate
 * on a raw atomic counter and an opaque item plus a reclaim callback), so a caller supplies what to
 * reclaim and which counter guards it while this module owns the tricky ordering and the
 * evicting-refcount window. */

/* ===== reader epoch ===== */

/* an in-flight-reader counter. a reader brackets its access to a shared structure with enter and
 * exit, and a writer that swaps the structure out waits for the count to drain before reclaiming
 * the old one. */
typedef _Atomic(int) tdb_epoch_t;

/* enter marks one reader in-flight. the fence is what makes the protocol safe rather than merely
 * ordered -- a reader stores its entry and then loads the shared pointer, while a writer stores the
 * new pointer and then loads this counter, and without a store-load barrier on both sides the two
 * can miss each other entirely: the writer reads zero readers while the reader is still walking the
 * structure it is about to free. a read-modify-write at acq_rel is not a store-load barrier on
 * architectures that allow that reordering, so the barrier is explicit and lives here rather than
 * at each call site */
static inline void tdb_epoch_enter(tdb_epoch_t *e)
{
    atomic_fetch_add_explicit(e, 1, memory_order_acq_rel);
    atomic_thread_fence(memory_order_seq_cst);
}

/* exit clears one reader; the release order keeps the preceding read from sinking past it */
static inline void tdb_epoch_exit(tdb_epoch_t *e)
{
    atomic_fetch_sub_explicit(e, 1, memory_order_release);
}

/* active reads the current in-flight reader count. this is the load half of the barrier described
 * on enter -- a caller reaches it having just published a replacement, and the fence keeps that
 * publication from sinking past this read and hiding a reader that has already entered */
static inline int tdb_epoch_active(const tdb_epoch_t *e)
{
    atomic_thread_fence(memory_order_seq_cst);
    return atomic_load_explicit(e, memory_order_acquire);
}

/**
 * tdb_epoch_wait_drained
 * spin, yielding as it goes, until the epoch has no in-flight readers
 * @param e epoch to wait on
 */
void tdb_epoch_wait_drained(tdb_epoch_t *e);

/* ===== refcount with a transient evicting window ===== */

/* a positive refcount is the number of live references; 0 means the object is being reclaimed and
 * must not be touched; TDB_REFCOUNT_EVICTING marks the brief window where a background thread is
 * closing the object's resources but will restore the count -- try_ref waits that window out rather
 * than treating it as dead, which is what keeps a reader from skipping a present object and
 * reporting a false miss. */
#define TDB_REFCOUNT_EVICTING (-1)

/* try_ref backoff -- pause up to SPIN, then yield up to YIELD, then sleep SLEEP_US each, giving up
 * after WAIT_MAX iterations (~70ms), far longer than any real resource close so a live evicting
 * object is always waited out */
#define TDB_REFCOUNT_DRAIN_SPIN_THRESHOLD  64
#define TDB_REFCOUNT_DRAIN_YIELD_THRESHOLD 1024
#define TDB_REFCOUNT_DRAIN_SLEEP_US        10
#define TDB_EVICT_WAIT_MAX                 8192

typedef _Atomic(int) tdb_refcount_t;

/* ref takes a reference; only safe when the caller already holds one or a lock keeps the object
 * live */
static inline void tdb_ref(tdb_refcount_t *rc)
{
    atomic_fetch_add(rc, 1);
}

/**
 * tdb_unref
 * drop a reference
 * @param rc refcount to drop
 * @return 1 when this call released the last reference and the caller must reclaim the object, else
 * 0
 */
static inline int tdb_unref(tdb_refcount_t *rc)
{
    return atomic_fetch_sub(rc, 1) == 1;
}

/**
 * tdb_try_ref
 * take a reference on an object that may be concurrently reclaimed, waiting out an evicting window
 * @param rc refcount to reference
 * @return 1 if a reference was acquired, 0 if the object is being freed
 */
int tdb_try_ref(tdb_refcount_t *rc);

/**
 * tdb_refcount_begin_evict
 * claim the evicting window by moving the refcount from baseline to TDB_REFCOUNT_EVICTING
 * @param rc refcount to transition
 * @param baseline the exact refcount a reclaimable-but-idle object must be at (its own ref plus the
 *                 evicting thread's work ref) for the claim to succeed
 * @return 1 if this thread won the evicting window, 0 if the object was busy or already gone
 */
int tdb_refcount_begin_evict(tdb_refcount_t *rc, int baseline);

/**
 * tdb_refcount_end_evict
 * end the evicting window, restoring the refcount so a waiting try_ref can proceed
 * @param rc refcount to restore
 * @param baseline the count begin_evict claimed from, the same value passed there
 * @return the refcount after the restore -- baseline, unless a reference was taken or dropped
 *         inside the window; 0 means the last reference went and the caller must reclaim the object
 */
static inline int tdb_refcount_end_evict(tdb_refcount_t *rc, const int baseline)
{
    /* added rather than stored, because the sentinel is a fixed offset below the baseline and a
     * plain store would discard whatever a concurrent thread did inside the window. losing an
     * acquire frees an object still in use; losing a release leaks one. adding the offset back
     * carries both through, and the caller learns from the result which it was */
    const int restore = baseline - TDB_REFCOUNT_EVICTING;
    return atomic_fetch_add(rc, restore) + restore;
}

/* ===== epoch-guarded deferred reclamation ===== */

/* reclaim an item once its guard epoch has drained; ctx carries whatever the callback needs */
typedef void (*tdb_reclaim_fn)(void *item, void *ctx);

/* select which retired items a drain should force-reclaim now; return nonzero to reclaim this item
 */
typedef int (*tdb_retire_match_fn)(void *item, const tdb_epoch_t *guard, void *ctx);

typedef struct tdb_retire_node tdb_retire_node_t;

/**
 * tdb_retire_list_t
 * a lock-free stack of retired items awaiting epoch-guarded reclamation; zero-initialize before use
 * @param head atomic head of the singly-linked retire stack
 */
typedef struct
{
    _Atomic(tdb_retire_node_t *) head;
} tdb_retire_list_t;

/* brief spin before allocating a deferral node, matching the common case of readers finishing
 * quickly */
#define TDB_RETIRE_SPIN_ATTEMPTS 64

/**
 * tdb_retire
 * reclaim item via reclaim(item, ctx) once guard has drained. reclaims inline after a brief spin
 * when the guard is already clear, otherwise defers onto the list for a later sweep or drain.
 * @param list retire list to defer onto
 * @param item opaque item to reclaim
 * @param guard epoch that must drain before item may be reclaimed
 * @param reclaim callback that reclaims item
 * @param ctx opaque context passed to reclaim
 */
void tdb_retire(tdb_retire_list_t *list, void *item, tdb_epoch_t *guard, tdb_reclaim_fn reclaim,
                void *ctx);

/**
 * tdb_retire_sweep
 * reclaim every retired item whose guard has drained and re-defer the rest; a periodic background
 * pass
 * @param list retire list to sweep
 */
void tdb_retire_sweep(tdb_retire_list_t *list);

/**
 * tdb_retire_drain
 * force-reclaim retired items selected by match, spinning until each one's guard drains, and
 * re-defer the rest. a NULL match selects every item, which is the shutdown drain.
 * @param list retire list to drain
 * @param match selector, or NULL to drain everything
 * @param ctx opaque context passed to match
 */
void tdb_retire_drain(tdb_retire_list_t *list, tdb_retire_match_fn match, void *ctx);

#endif /* __TIDESDB_BASE_LOCKFREE_H__ */
