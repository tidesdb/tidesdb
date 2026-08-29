/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>

#include "base/encoding/serialization.h" /* tdb_build_prefixed_key, TDB_CF_PREFIX_SIZE */
#include "base/errors.h"                 /* TDB_ERR_BUSY */
#include "l0_internal.h"

/* the L0 read path -- resolving one key against the active memtable and the sealed immutables at a
 * snapshot ceiling. it answers with the newest version at or below that ceiling, which is either a
 * version written against the key itself or a range tombstone written over an interval containing
 * it, whichever of the two is newer */

/* how many times a read re-snapshots the immutable queue when a concurrent rotation grows it past
 * the buffer; the buffer doubles each try, so this bound covers any queue depth a flush ever allows
 */
#define TDB_L0_IMMUTABLE_SNAP_TRIES 8

/* the visibility predicate the skip list consults per version, so an abandoned commit's entries are
 * skipped in favour of an older visible version rather than hiding the key outright */
static int l0_version_visible(void *ctx, uint64_t seq)
{
    return !tidesdb_l0_seq_aborted((const tidesdb_l0_t *)ctx, seq);
}

/* read one memtable's newest version of a prefixed key visible at the snapshot; UINT64_MAX ignores
 * the snapshot and reads the latest. the visibility predicate is passed even for that case, because
 * a commit whose apply failed can leave entries here at a sequence that never committed, and those
 * have to be stepped over at any snapshot rather than returned as the key's newest version */
int tidesdb_memtable_has_range_tombstones(const tidesdb_memtable_t *mt)
{
    return mt && atomic_load_explicit(&mt->range_tombstone_frags, memory_order_acquire) != 0;
}

/* the newest range tombstone covering a prefixed key at or below the snapshot, stepping over one an
 * abandoned commit left behind exactly as the per-version predicate does for a point write. a
 * memtable that has never taken a range delete answers from one load and never reaches the lock */
int tidesdb_memtable_range_tombstone_covering(const tidesdb_l0_t *l0, tidesdb_memtable_t *mt,
                                              const uint8_t *pkey, const size_t pkey_size,
                                              const uint64_t snapshot, uint64_t *out_seq)
{
    if (atomic_load_explicit(&mt->range_tombstone_frags, memory_order_acquire) == 0) return 0;

    int found = 0;
    const rt_fragment_t *frag = NULL;
    tdb_wprwlock_rdlock(&mt->range_tombstone_lock);
    if (range_tombstone_covering_fragment(mt->range_tombstones, pkey, pkey_size, &frag) == 1)
    {
        for (size_t i = 0; i < frag->seq_count && !found; i++)
        {
            if (frag->seqs[i] > snapshot || tidesdb_l0_seq_aborted(l0, frag->seqs[i])) continue;
            *out_seq = frag->seqs[i];
            found = 1;
        }
    }
    tdb_wprwlock_unlock(&mt->range_tombstone_lock);
    return found;
}

static int l0_read_mt(const tidesdb_l0_t *l0, tidesdb_memtable_t *mt, const uint8_t *pkey,
                      size_t pkey_size, uint64_t snapshot, uint8_t **value, size_t *value_size,
                      uint64_t *vlog_id, int64_t *ttl, uint8_t *deleted, uint64_t *out_seq)
{
    uint64_t seq = 0;
    const int rc =
        skip_list_get_with_seq(mt->skip_list, pkey, pkey_size, value, value_size, vlog_id, ttl,
                               deleted, &seq, snapshot, l0_version_visible, (void *)l0);

    /* a range tombstone deletes the key from its own sequence on, so it beats a version older than
     * itself and loses to a newer one. that is the ordinary contest between two versions of a key,
     * with one of them written as an interval rather than against the key itself */
    uint64_t tomb_seq = 0;
    if (tidesdb_memtable_range_tombstone_covering(l0, mt, pkey, pkey_size, snapshot, &tomb_seq) &&
        (rc != 0 || tomb_seq > seq))
    {
        if (rc == 0 && value) free(*value);
        if (value) *value = NULL;
        if (value_size) *value_size = 0;
        if (vlog_id) *vlog_id = 0;
        if (ttl) *ttl = TDB_TTL_NONE;
        if (deleted) *deleted = 1;
        if (out_seq) *out_seq = tomb_seq;
        return 0;
    }

    if (rc == 0 && out_seq) *out_seq = seq;
    return rc;
}

/* search the immutable queue for a prefixed key visible at the snapshot, newest to oldest,
 * returning the first hit. the snapshot and the pinning of each memtable happen inside a brief
 * reader epoch so a pointer cannot be freed by a concurrent reclaim before it is pinned; the epoch
 * is dropped before the skip_list reads so a reclaimer's drain is never held off by a slow read,
 * only by the pinning window. the pins (not the epoch) keep the memtables alive across the reads.
 */
/* pin every memtable in a queue snapshot, all or nothing -- a memtable already retiring cannot be
 * pinned, and rather than read a partial set the pins already taken are rolled back so the caller
 * retries against a fresh snapshot */
static int l0_pin_all(void **snap, size_t got)
{
    for (size_t i = 0; i < got; i++)
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
        if (!mt || !tdb_try_ref(&mt->refcount))
        {
            for (size_t j = 0; j < i; j++)
            {
                if (snap[j]) l0_unpin_read((tidesdb_memtable_t *)snap[j]);
            }
            return -1;
        }
    }
    return 0;
}

static int l0_get_from_immutables(tidesdb_l0_t *l0, const uint8_t *pkey, size_t pkey_size,
                                  uint64_t snapshot, uint8_t **value, size_t *value_size,
                                  uint64_t *vlog_id, int64_t *ttl, uint8_t *deleted,
                                  uint64_t *out_seq)
{
    if (queue_size(l0->queue) == 0) return TDB_ERR_NOT_FOUND;

    tidesdb_memtable_t *stack_snap[TDB_L0_IMMUTABLE_SNAP_STACK];
    void **snap = (void **)stack_snap;
    size_t cap = TDB_L0_IMMUTABLE_SNAP_STACK;
    size_t got = 0;
    int captured = 0;

    /* snapshot the whole queue, retrying with a larger buffer if a concurrent rotation grew it past
     * the buffer. queue_snapshot fills from the head, so a truncated snapshot would drop the newest
     * sealed memtable at the tail and miss a just-committed key, reading it back stale. the pinning
     * of each memtable happens inside a brief reader epoch so a pointer cannot be freed by a
     * concurrent reclaim before it is pinned; the pins then keep the memtables alive across the
     * reads below. */
    for (int tries = 0; tries < TDB_L0_IMMUTABLE_SNAP_TRIES && !captured; tries++)
    {
        tdb_epoch_enter(&l0->active_readers);
        got = queue_snapshot(l0->queue, snap, cap);
        if (got < cap)
        {
            const int pin_failed = l0_pin_all(snap, got) != 0;
            tdb_epoch_exit(&l0->active_readers);
            if (pin_failed)
            {
                if (snap != (void **)stack_snap) free(snap);
                return TDB_ERR_BUSY;
            }
            captured = 1;
            break;
        }
        tdb_epoch_exit(&l0->active_readers);

        cap *= 2;
        void **grown = malloc(cap * sizeof(void *));
        if (!grown)
        {
            if (snap != (void **)stack_snap) free(snap);
            return TDB_ERR_MEMORY;
        }
        if (snap != (void **)stack_snap) free(snap);
        snap = grown;
    }
    if (!captured)
    {
        if (snap != (void **)stack_snap) free(snap);
        return TDB_ERR_BUSY; /* the queue kept growing past the buffer, retryable by the caller */
    }

    /* read the pinned memtables newest (tail) to oldest (head), stopping at the first hit */
    int rc = TDB_ERR_NOT_FOUND;
    for (size_t i = got; i-- > 0;)
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
        if (mt && rc != TDB_SUCCESS &&
            l0_read_mt(l0, mt, pkey, pkey_size, snapshot, value, value_size, vlog_id, ttl, deleted,
                       out_seq) == 0)
            rc = TDB_SUCCESS;
    }
    for (size_t i = 0; i < got; i++)
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)snap[i];
        if (mt && tdb_unref(&mt->refcount)) tidesdb_memtable_free(mt);
    }

    if (snap != (void **)stack_snap) free(snap);
    return rc;
}

/* the shared read core reads the active memtable first, then the immutable queue, at a snapshot
 * ceiling (UINT64_MAX for the latest). out_seq, when non-NULL, receives the winning version's
 * sequence. */
static int l0_get_impl(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                       uint64_t snapshot, uint8_t **value, size_t *value_size, uint64_t *vlog_id,
                       int64_t *ttl, uint8_t *deleted, uint64_t *out_seq)
{
    if (!l0 || !key) return TDB_ERR_INVALID_ARGS;

    const size_t pkey_size = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t stack_key[TDB_L0_KEY_STACK_BUF];
    uint8_t *pkey = pkey_size <= sizeof(stack_key) ? stack_key : malloc(pkey_size);
    if (!pkey) return TDB_ERR_MEMORY;
    tdb_build_prefixed_key(cf_index, key, key_size, pkey);

    /* the active and the immutable queue are read in two steps with no lock between them, so a
     * rotation that moves a memtable from the active slot into the queue mid-read can leave a
     * just-committed version in neither snapshot. bracket the two-step read with the rotation
     * counter and, on a miss that raced a rotation, report a retryable busy rather than a
     * definitive absence the caller would trust and fall through to a stale older version for. */
    const uint64_t seen_before = atomic_load_explicit(&l0->visible_changes, memory_order_acquire);

    tidesdb_memtable_t *mt = NULL;
    for (int attempt = 0; attempt < TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS; attempt++)
    {
        mt = l0_pin_active_read(l0);
        if (mt) break;
    }
    if (!mt)
    {
        if (pkey != stack_key) free(pkey);
        return TDB_ERR_BUSY;
    }

    /* the active memtable holds the newest writes; only when it misses does the search fall through
     * the sealed immutables, newest first */
    const int found = l0_read_mt(l0, mt, pkey, pkey_size, snapshot, value, value_size, vlog_id, ttl,
                                 deleted, out_seq);
    l0_unpin_read(mt);

    int rc = found == 0 ? TDB_SUCCESS
                        : l0_get_from_immutables(l0, pkey, pkey_size, snapshot, value, value_size,
                                                 vlog_id, ttl, deleted, out_seq);
    if (rc == TDB_ERR_NOT_FOUND &&
        atomic_load_explicit(&l0->visible_changes, memory_order_acquire) != seen_before)
        rc = TDB_ERR_BUSY;
    if (pkey != stack_key) free(pkey);
    return rc;
}

int tidesdb_l0_get(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                   uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    uint64_t vlog_id = 0;
    const int rc = l0_get_impl(l0, cf_index, key, key_size, UINT64_MAX, value, value_size, &vlog_id,
                               ttl, deleted, NULL);
    /* this entry point has nowhere to report an id, so a referenced value would come back as an
     * empty one. a caller that may meet a reference reads through tidesdb_l0_get_at_seq */
    if (rc == TDB_SUCCESS && vlog_id != 0)
    {
        free(*value);
        *value = NULL;
        return TDB_ERR_INVALID_ARGS;
    }
    return rc;
}

int tidesdb_l0_get_at_seq(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                          uint64_t snapshot, uint8_t **value, size_t *value_size, uint64_t *vlog_id,
                          int64_t *ttl, uint8_t *deleted, uint64_t *seq)
{
    return l0_get_impl(l0, cf_index, key, key_size, snapshot, value, value_size, vlog_id, ttl,
                       deleted, seq);
}

/* memtables one range probe pins before it gives up; a deeper queue makes the probe report busy,
 * which a commit retries rather than reading as a clear run */
#define TDB_L0_RANGE_PROBE_MAX_MTS 64

/* the family prefix on its own, which is where a family's keyspace begins and, at the next index,
 * where it ends. an interval left unbounded inside a family stops at the next family's prefix */
#define TDB_L0_CF_PREFIX_ONLY TDB_CF_PREFIX_SIZE

/**
 * l0_mt_range_has_newer
 * walk one memtable over a prefixed interval looking for any version above the floor, stopping at
 * the first one -- a commit only needs to know that one exists
 * @param l0 the subsystem, for the abandoned-commit set
 * @param mt the memtable to walk
 * @param plo inclusive prefixed lower bound
 * @param plo_size length of plo
 * @param phi exclusive prefixed upper bound
 * @param phi_size length of phi
 * @param seq_floor the sequence a version must exceed
 * @param newer out, set non-zero as soon as one is found
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the cursor could not be built
 */
static int l0_mt_range_has_newer(const tidesdb_l0_t *l0, tidesdb_memtable_t *mt, const uint8_t *plo,
                                 const size_t plo_size, const uint8_t *phi, const size_t phi_size,
                                 const uint64_t seq_floor, int *newer)
{
    skip_list_cursor_t *cur = NULL;
    if (skip_list_cursor_init(&cur, mt->skip_list) != 0) return TDB_ERR_MEMORY;
    if (skip_list_cursor_seek_ge(cur, plo, plo_size) != 0)
    {
        skip_list_cursor_free(cur);
        return TDB_SUCCESS; /* nothing at or past the lower bound */
    }

    while (!*newer && skip_list_cursor_valid(cur))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t vlog_id = 0, seq = 0;
        int64_t ttl = 0;
        uint8_t flags = 0;
        if (skip_list_cursor_get_with_seq(cur, &key, &key_size, &value, &value_size, &vlog_id, &ttl,
                                          &flags, &seq) != 0)
            break;
        /* a NULL upper bound is unbounded above, which is what a family at the top of the index
         * space gets -- there is no next family's prefix to stop at */
        if (phi && skip_list_compare_keys(mt->skip_list, key, key_size, phi, phi_size) >= 0) break;

        /* every version of this key, since an older one can sit above the floor while the newest
         * belongs to this very transaction */
        for (;;)
        {
            if (seq > seq_floor && !tidesdb_l0_seq_aborted(l0, seq))
            {
                *newer = 1;
                break;
            }
            if (skip_list_cursor_advance_in_node(cur) != 0) break;
            if (skip_list_cursor_get_with_seq(cur, &key, &key_size, &value, &value_size, &vlog_id,
                                              &ttl, &flags, &seq) != 0)
                break;
        }
        if (*newer || skip_list_cursor_next(cur) != 0) break;
    }
    skip_list_cursor_free(cur);
    return TDB_SUCCESS;
}

int tidesdb_l0_range_has_newer(tidesdb_l0_t *l0, const uint32_t cf_index, const uint8_t *lo,
                               const size_t lo_size, const uint8_t *hi, const size_t hi_size,
                               const uint64_t seq_floor, int *newer)
{
    if (!l0 || !newer) return TDB_ERR_INVALID_ARGS;
    *newer = 0;

    /* the bounds go into the prefixed keyspace the shared skip list sorts on. an interval left
     * unbounded inside its family ends where the next family begins, and a family at the very top
     * of the index space has nothing above it, so the walk runs to the end of the list */
    const size_t plo_size = TDB_CF_PREFIX_SIZE + lo_size;
    const size_t phi_size = hi_size > 0 ? TDB_CF_PREFIX_SIZE + hi_size : TDB_L0_CF_PREFIX_ONLY;
    uint8_t stack_lo[TDB_L0_KEY_STACK_BUF];
    uint8_t stack_hi[TDB_L0_KEY_STACK_BUF];
    /* a bound past the stack buffer is one the caller is entitled to, not a transient condition,
     * so it is allocated rather than reported busy -- the apply path that stored the interval
     * allocated for the same bound, and a busy this scan can never clear reads as io at the commit
     */
    uint8_t *plo = plo_size <= sizeof(stack_lo) ? stack_lo : malloc(plo_size);
    uint8_t *phi_buf = phi_size <= sizeof(stack_hi) ? stack_hi : malloc(phi_size);
    if (!plo || !phi_buf)
    {
        if (plo && plo != stack_lo) free(plo);
        if (phi_buf && phi_buf != stack_hi) free(phi_buf);
        return TDB_ERR_MEMORY;
    }

    const uint8_t *phi = phi_buf;
    tdb_build_prefixed_key(cf_index, lo, lo_size, plo);
    if (hi_size > 0)
        tdb_build_prefixed_key(cf_index, hi, hi_size, phi_buf);
    else if (cf_index == UINT32_MAX)
        phi = NULL; /* the last family has no next one to stop at, so the walk runs to the end */
    else
        tdb_build_prefixed_key(cf_index + 1, NULL, 0, phi_buf);

    tidesdb_memtable_t *mts[TDB_L0_RANGE_PROBE_MAX_MTS];
    int n = 0;
    int rc = TDB_ERR_BUSY;
    if (tidesdb_l0_pin_memtables(l0, mts, TDB_L0_RANGE_PROBE_MAX_MTS, &n) == TDB_SUCCESS)
    {
        rc = TDB_SUCCESS;
        for (int i = 0; i < n && rc == TDB_SUCCESS && !*newer; i++)
            rc = l0_mt_range_has_newer(l0, mts[i], plo, plo_size, phi, phi_size, seq_floor, newer);
        tidesdb_l0_unpin_memtables(mts, n);
    }

    if (plo != stack_lo) free(plo);
    if (phi_buf != stack_hi) free(phi_buf);
    return rc;
}
