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

#include "base/errors.h"
#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order the footprint is kept in */
#include "base/log.h"
#include "engine/engine.h"
#include "iter/merge_sources.h" /* writeset_merge_source_new for read-your-own-writes scans */
#include "sstable/vlog.h"
#include "txn/txn.h" /* tdb_txn_writeset, tdb_txn_record_scan */

/* the public range iterator is a thin wrapper over the per-cf merge iterator (cf_iter), which
 * merges the shared L0 memtables and the cf's sstable levels at a snapshot and hides tombstones.
 * this file copies the borrowed key and value out for the caller, resolves a spilled value through
 * the vlog, and keeps the scan's footprint -- the interval of keys it has covered, absent ones
 * included -- so a transaction that validates its reads can refuse to commit over a key another
 * commit put inside it. */

/* the bound below every key there can be, since keys are never empty: one zero byte */
static const uint8_t ENGINE_ITER_KEY_FLOOR[1] = {0};

/* whether the transaction validates what it read at commit, which is when a scan's footprint is
 * worth keeping at all */
static int engine_iter_tracks(const tidesdb_txn_t *txn)
{
    const tidesdb_isolation_level_t iso = tdb_txn_isolation(txn->inner);
    return iso == TDB_ISOLATION_REPEATABLE_READ || iso == TDB_ISOLATION_SERIALIZABLE;
}

/* copy a bound into an owned buffer, the successor of the key when after is set -- the key with a
 * zero byte appended, the smallest key above it. a failed copy is recorded rather than returned, so
 * the footprint is widened to the whole family when it is recorded instead of narrowed */
static void engine_iter_take(tidesdb_iter_t *it, uint8_t **dst, size_t *dst_len, const uint8_t *src,
                             size_t len, int after)
{
    uint8_t *copy = malloc(len + (after ? 1 : 0));
    if (!copy)
    {
        it->footprint_lost = 1;
        return;
    }
    memcpy(copy, src, len);
    if (after) copy[len] = 0;
    free(*dst);
    *dst = copy;
    *dst_len = len + (after ? 1 : 0);
}

/* widen the footprint downward to a key */
static void engine_iter_cover_low(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (it->lo && tdb_key_cmp(it->lo, it->lo_size, key, key_size) <= 0) return;
    engine_iter_take(it, &it->lo, &it->lo_size, key, key_size, 0);
}

/* widen the footprint upward to include a key */
static void engine_iter_cover_high(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (it->hi_open) return;
    if (it->hi && tdb_key_cmp(it->hi, it->hi_size, key, key_size) > 0) return;
    engine_iter_take(it, &it->hi, &it->hi_size, key, key_size, 1);
}

/* the scan ran off the front: it covered from the range's lower bound, or from below every key */
static void engine_iter_cover_front(tidesdb_iter_t *it)
{
    if (it->bound_lo)
        engine_iter_cover_low(it, it->bound_lo, it->bound_lo_size);
    else
        engine_iter_cover_low(it, ENGINE_ITER_KEY_FLOOR, sizeof(ENGINE_ITER_KEY_FLOOR));
}

/* the scan ran off the end: it covered up to and including the range's upper bound, or everything
 * above */
static void engine_iter_cover_end(tidesdb_iter_t *it)
{
    if (it->bound_hi)
        engine_iter_cover_high(it, it->bound_hi, it->bound_hi_size);
    else
        it->hi_open = 1;
}

/* after a positioning call, take the key the iterator sits on into the footprint, or the end the
 * scan ran off when it sits on nothing */
static void engine_iter_cover_current(tidesdb_iter_t *it, int forward)
{
    if (!it->tracked) return;
    it->covered = 1;
    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    if (cf_iter_valid(it->inner) &&
        cf_iter_get(it->inner, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                    &deleted) == TDB_SUCCESS)
    {
        engine_iter_cover_low(it, key, key_size);
        engine_iter_cover_high(it, key, key_size);
    }
    else if (forward)
        engine_iter_cover_end(it);
    else
        engine_iter_cover_front(it);
}

int engine_iter_new(tidesdb_txn_t *txn, cf_t *cf, tidesdb_iter_t **out)
{
    return engine_iter_new_range(txn, cf, NULL, 0, NULL, 0, out);
}

int engine_iter_new_range(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *lower, size_t lower_size,
                          const uint8_t *upper, size_t upper_size, tidesdb_iter_t **out)
{
    if (!txn || !cf || !out) return TDB_ERR_INVALID_ARGS;

    tidesdb_iter_t *it = calloc(1, sizeof(*it));
    if (!it) return TDB_ERR_MEMORY;
    it->db = txn->db;
    it->cf = cf;
    it->txn = txn;
    it->tracked = engine_iter_tracks(txn);
    if (it->tracked && lower && lower_size > 0)
        engine_iter_take(it, &it->bound_lo, &it->bound_lo_size, lower, lower_size, 0);
    if (it->tracked && upper && upper_size > 0)
        engine_iter_take(it, &it->bound_hi, &it->bound_hi_size, upper, upper_size, 0);
    /* the isolation-aware read snapshot, not the frozen begin snapshot: a read-committed scan must
       draw the current seq at iterator creation so it sees data committed before it started,
       matching what point reads already do through txn_read_snapshot. tdb_txn_snapshot returns 0
       under read-committed and would filter every live row out. */
    const uint64_t snapshot = tdb_txn_read_snapshot(txn->inner);
    /* fold the transaction's own buffered writes over the committed snapshot so a scan inside the
     * transaction sees its uncommitted puts and its deletes hide the underlying rows, matching what
     * point reads already do through the write set. the overlay reports the read snapshot as its
     * sequence so it wins over every committed version the scan can see */
    writeset_merge_source_t *ws_src =
        writeset_merge_source_new(tdb_txn_writeset(txn->inner), (uint32_t)cf->cf_id, snapshot);
    const cf_iter_bounds_t bounds = {
        .lower = lower, .lower_size = lower_size, .upper = upper, .upper_size = upper_size};
    const int rc = cf_iter_new_bounded(cf, txn->db->l0, snapshot, ws_src, &bounds, &it->inner);
    if (rc != TDB_SUCCESS)
    {
        free(it->bound_lo);
        free(it->bound_hi);
        free(it);
        return rc;
    }
    *out = it;
    return TDB_SUCCESS;
}

/* hand the footprint to the transaction's read set, the whole family when a bound was lost. a read
 * set that cannot take it cannot guarantee the isolation the level promises, so the transaction is
 * made to fail rather than commit over a phantom it never checked for */
static void engine_iter_record(tidesdb_iter_t *it)
{
    if (!it->tracked || !it->covered) return;
    const uint8_t *lo = it->lo;
    size_t lo_size = it->lo_size;
    const uint8_t *hi = it->hi_open ? NULL : it->hi;
    size_t hi_size = it->hi_open ? 0 : it->hi_size;
    if (it->footprint_lost || !lo)
    {
        lo = ENGINE_ITER_KEY_FLOOR;
        lo_size = sizeof(ENGINE_ITER_KEY_FLOOR);
        hi = NULL;
        hi_size = 0;
    }
    if (tdb_txn_record_scan(it->txn->inner, (uint32_t)it->cf->cf_id, lo, lo_size, hi, hi_size) !=
        TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "a scan's footprint could not be recorded, failing its txn");
        tdb_txn_request_abort(it->txn->inner);
    }
}

void engine_iter_free(tidesdb_iter_t *it)
{
    if (!it) return;
    engine_iter_record(it);
    cf_iter_free(it->inner);
    free(it->lo);
    free(it->hi);
    free(it->bound_lo);
    free(it->bound_hi);
    free(it);
}

int engine_iter_seek_first(tidesdb_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_seek_first(it->inner);
    if (it->tracked) engine_iter_cover_front(it);
    engine_iter_cover_current(it, 1);
    return rc;
}

int engine_iter_seek_last(tidesdb_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_seek_last(it->inner);
    if (it->tracked) engine_iter_cover_end(it);
    engine_iter_cover_current(it, 0);
    return rc;
}

int engine_iter_seek(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_seek(it->inner, key, key_size);
    /* the target is covered whether or not a key sits there; an insert at it is a phantom too */
    if (it->tracked) engine_iter_cover_low(it, key, key_size);
    engine_iter_cover_current(it, 1);
    return rc;
}

int engine_iter_seek_for_prev(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_seek_for_prev(it->inner, key, key_size);
    if (it->tracked) engine_iter_cover_high(it, key, key_size);
    engine_iter_cover_current(it, 0);
    return rc;
}

int engine_iter_next(tidesdb_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_next(it->inner);
    engine_iter_cover_current(it, 1);
    return rc;
}

int engine_iter_prev(tidesdb_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    const int rc = cf_iter_prev(it->inner);
    engine_iter_cover_current(it, 0);
    return rc;
}

int engine_iter_valid(const tidesdb_iter_t *it)
{
    return it ? cf_iter_valid(it->inner) : 0;
}

/* read the iterator's current entry, borrowing its key and value pointers */
static int engine_iter_current(tidesdb_iter_t *it, const uint8_t **key, size_t *key_size,
                               const uint8_t **value, size_t *value_size, uint64_t *vlog_offset)
{
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    return cf_iter_get(it->inner, key, key_size, &seq, value, value_size, vlog_offset, &ttl,
                       &deleted);
}

/* copy a length of bytes into a freshly allocated buffer; a zero length yields a NULL buffer */
static int engine_iter_dup(const uint8_t *src, size_t len, uint8_t **out, size_t *out_len)
{
    if (len == 0)
    {
        *out = NULL;
        *out_len = 0;
        return TDB_SUCCESS;
    }
    uint8_t *copy = malloc(len);
    if (!copy) return TDB_ERR_MEMORY;
    memcpy(copy, src, len);
    *out = copy;
    *out_len = len;
    return TDB_SUCCESS;
}

/* copy the current value out, resolving a spilled value through the cf's vlog */
static int engine_iter_dup_value(tidesdb_iter_t *it, const uint8_t *value, size_t value_size,
                                 uint64_t vlog_offset, uint8_t **out, size_t *out_len)
{
    if (value == NULL && vlog_offset != 0)
    {
        uint8_t *resolved = NULL;
        size_t resolved_len = 0;
        if (vlog_read(it->cf->vlog, vlog_offset, &resolved, &resolved_len) != VLOG_OK)
            return TDB_ERR_IO;
        *out = resolved;
        *out_len = resolved_len;
        return TDB_SUCCESS;
    }
    return engine_iter_dup(value, value_size, out, out_len);
}

int engine_iter_key(tidesdb_iter_t *it, uint8_t **key, size_t *key_size)
{
    if (!it || !key || !key_size) return TDB_ERR_INVALID_ARGS;
    const uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    uint64_t voff = 0;
    if (engine_iter_current(it, &k, &ks, &v, &vs, &voff) != TDB_SUCCESS) return TDB_ERR_NOT_FOUND;
    return engine_iter_dup(k, ks, key, key_size);
}

int engine_iter_value(tidesdb_iter_t *it, uint8_t **value, size_t *value_size)
{
    if (!it || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    const uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    uint64_t voff = 0;
    if (engine_iter_current(it, &k, &ks, &v, &vs, &voff) != TDB_SUCCESS) return TDB_ERR_NOT_FOUND;
    return engine_iter_dup_value(it, v, vs, voff, value, value_size);
}

int engine_iter_key_value(tidesdb_iter_t *it, uint8_t **key, size_t *key_size, uint8_t **value,
                          size_t *value_size)
{
    if (!it || !key || !key_size || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    const uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    uint64_t voff = 0;
    if (engine_iter_current(it, &k, &ks, &v, &vs, &voff) != TDB_SUCCESS) return TDB_ERR_NOT_FOUND;

    if (engine_iter_dup(k, ks, key, key_size) != TDB_SUCCESS) return TDB_ERR_MEMORY;
    if (engine_iter_dup_value(it, v, vs, voff, value, value_size) != TDB_SUCCESS)
    {
        free(*key);
        *key = NULL;
        return TDB_ERR_IO;
    }
    return TDB_SUCCESS;
}
