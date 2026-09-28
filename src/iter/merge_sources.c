/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "merge_sources.h"

#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* be32 codec, TDB_CF_PREFIX_SIZE */
#include "base/errors.h"                 /* TDB_SUCCESS */
#include "base/keycmp.h"                 /* tdb_key_cmp, the one byte-wise key order */
#include "memtable/memtable.h"           /* the interval predicate a memtable view asks first */
#include "txn/writeset.h"                /* writeset op access and TDB_WAL_ENTRY_TOMBSTONE */

/* stack buffer for the prefixed lookup key a memtable seek builds, covering the common small case
 */
#define MT_SEEK_STACK_BUF 256

/* ===== sstable source -- a thin pass-through over the bidirectional sstable cursor ===== */

static int ss_first(void *ctx)
{
    return sstable_iter_seek_first((sstable_iter_t *)ctx) == TDB_SUCCESS;
}
static int ss_last(void *ctx)
{
    return sstable_iter_seek_last((sstable_iter_t *)ctx) == TDB_SUCCESS;
}
static int ss_next(void *ctx)
{
    return sstable_iter_next((sstable_iter_t *)ctx) == TDB_SUCCESS;
}
static int ss_prev(void *ctx)
{
    return sstable_iter_prev((sstable_iter_t *)ctx) == TDB_SUCCESS;
}
static int ss_valid(void *ctx)
{
    return sstable_iter_valid((sstable_iter_t *)ctx);
}

static int ss_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    return sstable_iter_seek((sstable_iter_t *)ctx, key, key_size) == TDB_SUCCESS;
}

static int ss_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    return sstable_iter_seek_for_prev((sstable_iter_t *)ctx, key, key_size) == TDB_SUCCESS;
}

static void ss_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                   const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                   uint8_t *deleted)
{
    uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    (void)sstable_iter_get((sstable_iter_t *)ctx, &k, &ks, &v, &vs, vlog_offset, seq, ttl, deleted);
    *key = k;
    *key_size = ks;
    *value = v;
    *value_size = vs;
}

static int ss_read_failed(void *ctx)
{
    return sstable_iter_read_failed((sstable_iter_t *)ctx);
}

/* the newest interval this table carries that covers the key, at or below the snapshot. the block
 * is keyed by the family's own keys, the same form the merge walks in, so the key needs no shaping
 * @param ctx the sstable iterator, which names the table
 * @param key the key being resolved
 * @param key_size length of key
 * @param snapshot the reader's ceiling
 * @param out_seq receives the covering sequence on a hit
 * @return 1 when an interval covers the key, 0 when none does
 */
static int sstable_source_covers(void *ctx, const uint8_t *key, size_t key_size, uint64_t snapshot,
                                 uint64_t *out_seq)
{
    const range_tombstone_set_t *intervals = sstable_iter_intervals((sstable_iter_t *)ctx);
    if (!intervals) return 0;
    return range_tombstone_max_covering(intervals, key, key_size, snapshot, out_seq) == 1;
}

void sstable_merge_source(sstable_iter_t *it, merge_source_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->read_failed = ss_read_failed;
    out->first = ss_first;
    out->last = ss_last;
    out->next = ss_next;
    out->prev = ss_prev;
    out->valid = ss_valid;
    out->seek = ss_seek;
    out->seek_for_prev = ss_seek_for_prev;
    out->get = ss_get;
    out->ctx = it;
    out->covers = sstable_source_covers;
}

/* ===== memtable source -- one column family's snapshot view of the shared skip_list ===== */

/* resolve the current node to its newest version at or below the snapshot, caching the unprefixed
 * key and the version fields; returns 1 if a visible version exists, 0 if every version is above
 * the snapshot */
static int mt_resolve_version(memtable_merge_source_t *s)
{
    for (;;)
    {
        uint8_t *pkey = NULL, *value = NULL;
        size_t pkey_size = 0, value_size = 0;
        uint64_t vlog_id = 0;
        int64_t ttl = 0;
        uint8_t flags = 0;
        uint64_t seq = 0;
        if (skip_list_cursor_get_with_seq(s->cursor, &pkey, &pkey_size, &value, &value_size,
                                          &vlog_id, &ttl, &flags, &seq) != 0)
            return 0;
        if (seq <= s->snapshot)
        {
            const int tombstone = (flags & SKIP_LIST_FLAG_DELETED) != 0;
            s->key = pkey + TDB_CF_PREFIX_SIZE;
            s->key_size = pkey_size - TDB_CF_PREFIX_SIZE;
            s->value = tombstone ? NULL : value;
            s->value_size = tombstone ? 0 : value_size;
            s->vlog_id = tombstone ? 0 : vlog_id;
            s->seq = seq;
            s->ttl = ttl;
            s->deleted = (uint8_t)(tombstone ? 1 : 0);
            return 1;
        }
        if (skip_list_cursor_advance_in_node(s->cursor) != 0) return 0; /* no older version */
    }
}

/* walk nodes in the scan direction, stopping when a visible in-range version is found or the column
 * family's key range ends */
static int mt_position(memtable_merge_source_t *s, int forward)
{
    while (skip_list_cursor_valid(s->cursor))
    {
        uint8_t *pkey = NULL, *value = NULL;
        size_t pkey_size = 0, value_size = 0;
        int64_t ttl = 0;
        uint8_t flags = 0;
        uint64_t seq = 0;
        if (skip_list_cursor_get_with_seq(s->cursor, &pkey, &pkey_size, &value, &value_size, NULL,
                                          &ttl, &flags, &seq) != 0 ||
            pkey_size < TDB_CF_PREFIX_SIZE)
            break;

        const uint32_t cf = tdb_decode_be32(pkey);
        if (cf == s->cf_index)
        {
            if (mt_resolve_version(s))
            {
                s->positioned = 1;
                return 1;
            }
        }
        else if ((forward && cf > s->cf_index) || (!forward && cf < s->cf_index))
        {
            break; /* stepped out of the family's key range */
        }

        if ((forward ? skip_list_cursor_next(s->cursor) : skip_list_cursor_prev(s->cursor)) != 0)
            break;
    }
    s->positioned = 0;
    return 0;
}

/* move a cursor over a family-prefixed skip list to the start (forward) or the end (backward) of
 * one family's key range; the caller then resolves what it finds there */
static void ms_cursor_to_family_edge(skip_list_cursor_t *cursor, const uint32_t cf_index,
                                     const int forward)
{
    uint8_t prefix[TDB_CF_PREFIX_SIZE];
    if (forward)
    {
        tdb_encode_be32(cf_index, prefix);
        (void)skip_list_cursor_seek_ge(cursor, prefix, sizeof(prefix));
        return;
    }
    /* the largest key below the next family's prefix is this family's last key */
    if (cf_index == UINT32_MAX)
        (void)skip_list_cursor_goto_last(cursor);
    else
    {
        tdb_encode_be32(cf_index + 1, prefix);
        (void)skip_list_cursor_seek_for_prev(cursor, prefix, sizeof(prefix));
    }
}

/* build the prefixed lookup key for a user key seek */
static int ms_build_prefixed(const uint32_t cf_index, const uint8_t *key, size_t key_size,
                             uint8_t *stack, size_t stack_cap, uint8_t **out, size_t *out_size)
{
    const size_t total = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t *buf = total <= stack_cap ? stack : malloc(total);
    if (!buf) return -1;
    tdb_encode_be32(cf_index, buf);
    memcpy(buf + TDB_CF_PREFIX_SIZE, key, key_size);
    *out = buf;
    *out_size = total;
    return 0;
}

static int mt_first(void *ctx)
{
    memtable_merge_source_t *s = ctx;
    ms_cursor_to_family_edge(s->cursor, s->cf_index, 1);
    return mt_position(s, 1);
}
static int mt_last(void *ctx)
{
    memtable_merge_source_t *s = ctx;
    ms_cursor_to_family_edge(s->cursor, s->cf_index, 0);
    return mt_position(s, 0);
}

static int mt_next(void *ctx)
{
    memtable_merge_source_t *s = ctx;
    if (skip_list_cursor_next(s->cursor) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    return mt_position(s, 1);
}

static int mt_prev(void *ctx)
{
    memtable_merge_source_t *s = ctx;
    if (skip_list_cursor_prev(s->cursor) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    return mt_position(s, 0);
}

static int mt_valid(void *ctx)
{
    return ((memtable_merge_source_t *)ctx)->positioned;
}

static int mt_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    memtable_merge_source_t *s = ctx;
    uint8_t stack[MT_SEEK_STACK_BUF];
    uint8_t *prefixed = NULL;
    size_t prefixed_size = 0;
    if (ms_build_prefixed(s->cf_index, key, key_size, stack, sizeof(stack), &prefixed,
                          &prefixed_size) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    (void)skip_list_cursor_seek_ge(s->cursor, prefixed, prefixed_size);
    if (prefixed != stack) free(prefixed);
    return mt_position(s, 1);
}

static int mt_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    memtable_merge_source_t *s = ctx;
    uint8_t stack[MT_SEEK_STACK_BUF];
    uint8_t *prefixed = NULL;
    size_t prefixed_size = 0;
    if (ms_build_prefixed(s->cf_index, key, key_size, stack, sizeof(stack), &prefixed,
                          &prefixed_size) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    (void)skip_list_cursor_seek_for_prev(s->cursor, prefixed, prefixed_size);
    if (prefixed != stack) free(prefixed);
    return mt_position(s, 0);
}

static void mt_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                   const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                   uint8_t *deleted)
{
    memtable_merge_source_t *s = ctx;
    *key = s->key;
    *key_size = s->key_size;
    *seq = s->seq;
    *value = s->value;
    *value_size = s->value_size;
    /* a memtable holds either the bytes or the id of the value log entry holding them, the same
     * two shapes an sstable entry has, so the merge sees one kind of entry from either source */
    *vlog_offset = s->vlog_id;
    *ttl = s->ttl;
    *deleted = s->deleted;
}

void memtable_merge_source_init(memtable_merge_source_t *s, skip_list_cursor_t *cursor,
                                tidesdb_l0_t *l0, tidesdb_memtable_t *mt, uint32_t cf_index,
                                uint64_t snapshot)
{
    memset(s, 0, sizeof(*s));
    s->l0 = l0;
    s->mt = mt;
    s->cursor = cursor;
    s->cf_index = cf_index;
    s->snapshot = snapshot;
}

/* the newest interval this memtable holds that covers the key. the memtable's set is keyed by the
 * shared prefixed keyspace, so the family prefix goes back on before it is asked
 * @param ctx the memtable view, which names the memtable and the family
 * @param key the key being resolved, without a prefix
 * @param key_size length of key
 * @param snapshot the reader's ceiling
 * @param out_seq receives the covering sequence on a hit
 * @return 1 when an interval covers the key, 0 when none does
 */
static int memtable_source_covers(void *ctx, const uint8_t *key, size_t key_size, uint64_t snapshot,
                                  uint64_t *out_seq)
{
    memtable_merge_source_t *s = (memtable_merge_source_t *)ctx;
    if (!s->l0 || !s->mt) return 0;

    /* asked before the key is built rather than after. the answer needs the family prefix put back
     * on, which for a long key is an allocation, and a memtable that has never taken a range delete
     * answers no whatever key it is handed -- which is every memtable of every database that does
     * not delete ranges, on every key a scan resolves */
    if (!tidesdb_memtable_has_range_tombstones(s->mt)) return 0;

    uint8_t stack[MERGE_SOURCE_PREFIXED_KEY_STACK];
    const size_t pkey_size = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t *pkey = pkey_size <= sizeof(stack) ? stack : malloc(pkey_size);
    if (!pkey) return 0;
    tdb_build_prefixed_key(s->cf_index, key, key_size, pkey);

    const int covered =
        tidesdb_memtable_range_tombstone_covering(s->l0, s->mt, pkey, pkey_size, snapshot, out_seq);
    if (pkey != stack) free(pkey);
    return covered;
}

void memtable_merge_source(memtable_merge_source_t *s, merge_source_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->read_failed = NULL; /* reads from memory, so it never stops short of exhaustion */
    out->first = mt_first;
    out->last = mt_last;
    out->next = mt_next;
    out->prev = mt_prev;
    out->valid = mt_valid;
    out->seek = mt_seek;
    out->seek_for_prev = mt_seek_for_prev;
    out->get = mt_get;
    out->ctx = s;
    out->covers = memtable_source_covers;
}

/* ===== writeset overlay source -- a transaction's own buffered puts and deletes ===== */

struct writeset_merge_source
{
    const tidesdb_writeset_t *ws; /* the set the positions under the cursor are read back from */
    skip_list_cursor_t *cursor;   /* over the set's key list, family-prefixed like the memtable's */
    uint32_t cf_index;
    uint64_t
        seq; /* reported for every entry, the read snapshot, so the overlay wins over the store */
    int positioned;
    const uint8_t *key; /* the resolved entry, borrowed from the set until the next mutation */
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    int64_t ttl;
    uint8_t deleted;
};

/* resolve the node under the cursor to the write it names -- the head version's value is the
 * position of the key's newest write -- and decide how it reads: a tombstone, or a point write an
 * interval delete buffered after it covers, reads as deleted */
static int wss_resolve(writeset_merge_source_t *s)
{
    uint8_t *pkey = NULL, *value = NULL;
    size_t pkey_size = 0, value_size = 0;
    int64_t ttl = 0;
    uint8_t flags = 0;
    uint64_t seq = 0;
    if (skip_list_cursor_get_with_seq(s->cursor, &pkey, &pkey_size, &value, &value_size, NULL, &ttl,
                                      &flags, &seq) != 0 ||
        value_size != sizeof(uint64_t))
        return 0;
    uint64_t position = 0;
    memcpy(&position, value, sizeof(position));
    tidesdb_writeset_op_t op;
    if (!tidesdb_writeset_op_at(s->ws, (int)position, &op)) return 0;
    const int covered =
        tidesdb_writeset_covering(s->ws, s->cf_index, op.key, op.key_size, (int)position) >= 0;
    const int tombstone = covered || (op.flags & TDB_WAL_ENTRY_TOMBSTONE) != 0;
    s->key = op.key;
    s->key_size = op.key_size;
    s->value = tombstone ? NULL : op.value;
    s->value_size = tombstone ? 0 : op.value_size;
    s->ttl = op.ttl;
    s->deleted = (uint8_t)(tombstone ? 1 : 0);
    return 1;
}

/* walk nodes in the scan direction to the first that is this family's, resolving it, and stop where
 * the family's key range ends */
static int wss_position(writeset_merge_source_t *s, int forward)
{
    while (skip_list_cursor_valid(s->cursor))
    {
        uint8_t *pkey = NULL, *value = NULL;
        size_t pkey_size = 0, value_size = 0;
        if (skip_list_cursor_get_with_seq(s->cursor, &pkey, &pkey_size, &value, &value_size, NULL,
                                          NULL, NULL, NULL) != 0 ||
            pkey_size < TDB_CF_PREFIX_SIZE)
            break;
        const uint32_t cf = tdb_decode_be32(pkey);
        if (cf == s->cf_index)
        {
            s->positioned = wss_resolve(s);
            return s->positioned;
        }
        if ((forward && cf > s->cf_index) || (!forward && cf < s->cf_index)) break;
        if ((forward ? skip_list_cursor_next(s->cursor) : skip_list_cursor_prev(s->cursor)) != 0)
            break;
    }
    s->positioned = 0;
    return 0;
}

static int wss_first(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    ms_cursor_to_family_edge(s->cursor, s->cf_index, 1);
    return wss_position(s, 1);
}
static int wss_last(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    ms_cursor_to_family_edge(s->cursor, s->cf_index, 0);
    return wss_position(s, 0);
}
static int wss_next(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    if (skip_list_cursor_next(s->cursor) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    return wss_position(s, 1);
}
static int wss_prev(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    if (skip_list_cursor_prev(s->cursor) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    return wss_position(s, 0);
}
static int wss_valid(void *ctx)
{
    return ((writeset_merge_source_t *)ctx)->positioned;
}
static int wss_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    writeset_merge_source_t *s = ctx;
    uint8_t stack[MT_SEEK_STACK_BUF];
    uint8_t *prefixed = NULL;
    size_t prefixed_size = 0;
    if (ms_build_prefixed(s->cf_index, key, key_size, stack, sizeof(stack), &prefixed,
                          &prefixed_size) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    (void)skip_list_cursor_seek_ge(s->cursor, prefixed, prefixed_size);
    if (prefixed != stack) free(prefixed);
    return wss_position(s, 1);
}
static int wss_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    writeset_merge_source_t *s = ctx;
    uint8_t stack[MT_SEEK_STACK_BUF];
    uint8_t *prefixed = NULL;
    size_t prefixed_size = 0;
    if (ms_build_prefixed(s->cf_index, key, key_size, stack, sizeof(stack), &prefixed,
                          &prefixed_size) != 0)
    {
        s->positioned = 0;
        return 0;
    }
    (void)skip_list_cursor_seek_for_prev(s->cursor, prefixed, prefixed_size);
    if (prefixed != stack) free(prefixed);
    return wss_position(s, 0);
}
static void wss_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                    const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                    uint8_t *deleted)
{
    writeset_merge_source_t *s = ctx;
    *key = s->key;
    *key_size = s->key_size;
    *seq = s->seq;
    *value = s->value;
    *value_size = s->value_size;
    *vlog_offset = 0; /* a buffered value is always inline; the commit separates it later */
    *ttl = s->ttl;
    *deleted = s->deleted;
}

/* an interval the transaction buffered after its own newest write of the key covers it, one above
 * the overlay's own sequence. every committed version a scan can see sits at or below the snapshot,
 * which is the overlay's sequence, and the merge lets an interval delete only a strictly older
 * version, so a row committed at the snapshot itself would otherwise survive the delete. a key the
 * transaction wrote after its interval is not covered and stays live */
static int writeset_source_covers(void *ctx, const uint8_t *key, size_t key_size, uint64_t snapshot,
                                  uint64_t *out_seq)
{
    (void)snapshot;
    writeset_merge_source_t *s = (writeset_merge_source_t *)ctx;
    const int own = tidesdb_writeset_newest(s->ws, s->cf_index, key, key_size);
    if (tidesdb_writeset_covering(s->ws, s->cf_index, key, key_size, own) < 0) return 0;
    *out_seq = s->seq == UINT64_MAX ? UINT64_MAX : s->seq + 1;
    return 1;
}

writeset_merge_source_t *writeset_merge_source_new(const tidesdb_writeset_t *ws, uint32_t cf_index,
                                                   uint64_t seq)
{
    /* a family the set holds nothing of needs no source; the key list is the set's own, so nothing
     * is copied or sorted here however much the transaction has buffered */
    if (!ws || !tidesdb_writeset_touches(ws, cf_index)) return NULL;
    writeset_merge_source_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (skip_list_cursor_init(&s->cursor, tidesdb_writeset_keys(ws)) != 0)
    {
        free(s);
        return NULL;
    }
    s->ws = ws;
    s->cf_index = cf_index;
    s->seq = seq;
    return s;
}

void writeset_merge_source(writeset_merge_source_t *s, merge_source_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->read_failed = NULL; /* reads from the transaction's own buffer and cannot fail this way */
    out->first = wss_first;
    out->last = wss_last;
    out->next = wss_next;
    out->prev = wss_prev;
    out->valid = wss_valid;
    out->seek = wss_seek;
    out->seek_for_prev = wss_seek_for_prev;
    out->get = wss_get;
    out->ctx = s;
    out->covers = writeset_source_covers;
}

void writeset_merge_source_free(writeset_merge_source_t *s)
{
    if (!s) return;
    skip_list_cursor_free(s->cursor);
    free(s);
}
