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
#include "engine/engine.h"
#include "iter/merge_sources.h" /* writeset_merge_source_new for read-your-own-writes scans */
#include "sstable/vlog.h"
#include "txn/txn.h" /* tdb_txn_writeset */

/* the public range iterator is a thin wrapper over the per-cf merge iterator (cf_iter), which
 * merges the shared L0 memtables and the cf's sstable levels at a snapshot and hides tombstones.
 * this file copies the borrowed key and value out for the caller and resolves a spilled value
 * through the vlog. */

int engine_iter_new(tidesdb_txn_t *txn, cf_t *cf, tidesdb_iter_t **out)
{
    return engine_iter_new_range(txn, cf, NULL, 0, NULL, 0, out);
}

int engine_iter_new_range(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *lower, size_t lower_size,
                          const uint8_t *upper, size_t upper_size, tidesdb_iter_t **out)
{
    if (!txn || !cf || !out) return TDB_ERR_INVALID_ARGS;

    tidesdb_iter_t *it = malloc(sizeof(*it));
    if (!it) return TDB_ERR_MEMORY;
    it->db = txn->db;
    it->cf = cf;
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
        free(it);
        return rc;
    }
    *out = it;
    return TDB_SUCCESS;
}

void engine_iter_free(tidesdb_iter_t *it)
{
    if (!it) return;
    cf_iter_free(it->inner);
    free(it);
}

int engine_iter_seek_first(tidesdb_iter_t *it)
{
    return it ? cf_iter_seek_first(it->inner) : TDB_ERR_INVALID_ARGS;
}

int engine_iter_seek_last(tidesdb_iter_t *it)
{
    return it ? cf_iter_seek_last(it->inner) : TDB_ERR_INVALID_ARGS;
}

int engine_iter_seek(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    return it ? cf_iter_seek(it->inner, key, key_size) : TDB_ERR_INVALID_ARGS;
}

int engine_iter_seek_for_prev(tidesdb_iter_t *it, const uint8_t *key, size_t key_size)
{
    return it ? cf_iter_seek_for_prev(it->inner, key, key_size) : TDB_ERR_INVALID_ARGS;
}

int engine_iter_next(tidesdb_iter_t *it)
{
    return it ? cf_iter_next(it->inner) : TDB_ERR_INVALID_ARGS;
}

int engine_iter_prev(tidesdb_iter_t *it)
{
    return it ? cf_iter_prev(it->inner) : TDB_ERR_INVALID_ARGS;
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
