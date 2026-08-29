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

/* seek to the start (dir forward) or end (dir backward) of the family's prefix range, then resolve
 */
static int mt_seek_family_edge(memtable_merge_source_t *s, int forward)
{
    uint8_t prefix[TDB_CF_PREFIX_SIZE];
    if (forward)
    {
        tdb_encode_be32(s->cf_index, prefix);
        (void)skip_list_cursor_seek_ge(s->cursor, prefix, sizeof(prefix));
        return mt_position(s, 1);
    }
    /* the largest key below the next family's prefix is this family's last key */
    if (s->cf_index == UINT32_MAX)
        (void)skip_list_cursor_goto_last(s->cursor);
    else
    {
        tdb_encode_be32(s->cf_index + 1, prefix);
        (void)skip_list_cursor_seek_for_prev(s->cursor, prefix, sizeof(prefix));
    }
    return mt_position(s, 0);
}

/* build the prefixed lookup key for a user key seek */
static int mt_build_prefixed(memtable_merge_source_t *s, const uint8_t *key, size_t key_size,
                             uint8_t *stack, size_t stack_cap, uint8_t **out, size_t *out_size)
{
    const size_t total = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t *buf = total <= stack_cap ? stack : malloc(total);
    if (!buf) return -1;
    tdb_encode_be32(s->cf_index, buf);
    memcpy(buf + TDB_CF_PREFIX_SIZE, key, key_size);
    *out = buf;
    *out_size = total;
    return 0;
}

static int mt_first(void *ctx)
{
    return mt_seek_family_edge((memtable_merge_source_t *)ctx, 1);
}
static int mt_last(void *ctx)
{
    return mt_seek_family_edge((memtable_merge_source_t *)ctx, 0);
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
    if (mt_build_prefixed(s, key, key_size, stack, sizeof(stack), &prefixed, &prefixed_size) != 0)
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
    if (mt_build_prefixed(s, key, key_size, stack, sizeof(stack), &prefixed, &prefixed_size) != 0)
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

/* one snapshotted buffered op, its key and value borrowed from the write set */
typedef struct
{
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    int64_t ttl;
    uint8_t deleted;
} ws_entry_t;

struct writeset_merge_source
{
    ws_entry_t *ents; /* sorted by key, one latest entry per key */
    int n;
    int pos; /* current cursor position, outside [0, n) when unpositioned */
    uint64_t seq;
};

/* byte-wise key order with a length tiebreak, matching the merge's ordering everywhere */
static int ws_key_cmp(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size)
{
    const size_t n = a_size < b_size ? a_size : b_size;
    const int c = n > 0 ? memcmp(a, b, n) : 0;
    if (c != 0) return c;
    return a_size < b_size ? -1 : (a_size > b_size ? 1 : 0);
}

/* one collected op paired with its insertion index, so a sort by key then index leaves the latest
 * write of each key last in its run */
typedef struct
{
    tidesdb_writeset_op_t op;
    int idx;
} ws_collect_t;

static int ws_collect_cmp(const void *a, const void *b)
{
    const ws_collect_t *x = a, *y = b;
    const int c = ws_key_cmp(x->op.key, x->op.key_size, y->op.key, y->op.key_size);
    if (c != 0) return c;
    return x->idx < y->idx ? -1 : (x->idx > y->idx ? 1 : 0);
}

writeset_merge_source_t *writeset_merge_source_new(const tidesdb_writeset_t *ws, uint32_t cf_index,
                                                   uint64_t seq)
{
    const int total = ws ? tidesdb_writeset_count(ws) : 0;
    if (total <= 0) return NULL;

    ws_collect_t *collected = malloc((size_t)total * sizeof(*collected));
    if (!collected) return NULL;
    int m = 0;
    for (int i = 0; i < total; i++)
    {
        tidesdb_writeset_op_t op;
        if (tidesdb_writeset_op_at(ws, i, &op) && op.cf_index == cf_index)
        {
            collected[m].op = op;
            collected[m].idx = i;
            m++;
        }
    }
    if (m == 0)
    {
        free(collected);
        return NULL;
    }
    qsort(collected, (size_t)m, sizeof(*collected), ws_collect_cmp);

    writeset_merge_source_t *s = calloc(1, sizeof(*s));
    ws_entry_t *ents = malloc((size_t)m * sizeof(*ents));
    if (!s || !ents)
    {
        free(s);
        free(ents);
        free(collected);
        return NULL;
    }
    /* keep the last op of each equal-key run, which the index tiebreak left as the latest write */
    int out = 0;
    for (int i = 0; i < m; i++)
    {
        if (i + 1 < m && ws_key_cmp(collected[i].op.key, collected[i].op.key_size,
                                    collected[i + 1].op.key, collected[i + 1].op.key_size) == 0)
            continue;
        const int deleted = (collected[i].op.flags & TDB_WAL_ENTRY_TOMBSTONE) != 0;
        ents[out].key = collected[i].op.key;
        ents[out].key_size = collected[i].op.key_size;
        ents[out].value = deleted ? NULL : collected[i].op.value;
        ents[out].value_size = deleted ? 0 : collected[i].op.value_size;
        ents[out].ttl = collected[i].op.ttl;
        ents[out].deleted = deleted ? 1 : 0;
        out++;
    }
    free(collected);
    s->ents = ents;
    s->n = out;
    s->pos = -1;
    s->seq = seq;
    return s;
}

static int wss_first(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    s->pos = 0;
    return s->n > 0;
}
static int wss_last(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    s->pos = s->n - 1;
    return s->n > 0;
}
static int wss_next(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    s->pos++;
    return s->pos >= 0 && s->pos < s->n;
}
static int wss_prev(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    s->pos--;
    return s->pos >= 0 && s->pos < s->n;
}
static int wss_valid(void *ctx)
{
    writeset_merge_source_t *s = ctx;
    return s->pos >= 0 && s->pos < s->n;
}

/* leftmost entry whose key is greater than or equal to the target */
static int wss_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    writeset_merge_source_t *s = ctx;
    int lo = 0, hi = s->n;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        if (ws_key_cmp(s->ents[mid].key, s->ents[mid].key_size, key, key_size) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    s->pos = lo;
    return s->pos < s->n;
}

/* rightmost entry whose key is less than or equal to the target */
static int wss_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    writeset_merge_source_t *s = ctx;
    int lo = 0, hi = s->n;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        if (ws_key_cmp(s->ents[mid].key, s->ents[mid].key_size, key, key_size) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    s->pos = lo - 1;
    return s->pos >= 0;
}

static void wss_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                    const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                    uint8_t *deleted)
{
    writeset_merge_source_t *s = ctx;
    const ws_entry_t *e = &s->ents[s->pos];
    *key = e->key;
    *key_size = e->key_size;
    *seq = s->seq;
    *value = e->value;
    *value_size = e->value_size;
    *vlog_offset = 0; /* buffered writes are inline, never spilled */
    *ttl = e->ttl;
    *deleted = e->deleted;
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
}

void writeset_merge_source_free(writeset_merge_source_t *s)
{
    if (!s) return;
    free(s->ents);
    free(s);
}
