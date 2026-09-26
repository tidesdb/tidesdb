/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "writeset.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* tdb_build_prefixed_key, TDB_CF_PREFIX_SIZE */
#include "base/keycmp.h"                 /* tdb_key_cmp, the one byte-wise key order */
#include "db.h"                          /* TDB_SUCCESS / TDB_ERR_* result codes */

/* initial op-array capacity, grown by doubling */
#define TDB_WRITESET_INITIAL_CAP 16

/* initial capacity of the list of interval deletes, grown by doubling; a batch holds few of them */
#define TDB_WRITESET_RANGES_INITIAL_CAP 4

/* the shape of the skip list over the ops, the memtable's own defaults */
#define TDB_WRITESET_SKIP_MAX_LEVEL   12
#define TDB_WRITESET_SKIP_PROBABILITY 0.25f

/* a family-prefixed key this long is built on the stack; a longer one is built on the heap */
#define TDB_WRITESET_KEY_STACK_BUF 256

/**
 * writeset_op
 * one buffered write; key and value share a single coalesced allocation with value following key
 * @param cf_index target column family prefix index
 * @param buf coalesced key+value allocation (only pointer freed for this op)
 * @param key_size length of the key portion at the head of buf
 * @param value_size length of the value portion after the key
 * @param ttl absolute expiry time, or -1 for none
 * @param flags op flag bits (tombstone / single-delete)
 */
typedef struct
{
    uint32_t cf_index;
    uint8_t *buf;
    size_t key_size;
    size_t value_size;
    int64_t ttl;
    uint8_t flags;
} writeset_op;

/**
 * tidesdb_writeset
 * the buffered write set with its publication lock and memory accounting
 * @param ops op array in insertion order
 * @param count number of live ops
 * @param capacity allocated length of ops
 * @param keys the ops by key -- a skip list over the family-prefixed keys, the order the memtable
 *             keeps, holding for each key one version per write of it with the write's position as
 *             the version's value and the position plus one as its sequence, so the newest write is
 *             the head. a lookup reads the head and a scan walks the list; before, a lookup walked
 *             the ops and a scan sorted a copy of them, so every operation of a transaction cost as
 *             much as it had already buffered and a load of a hundred thousand rows was quadratic
 * in the rows
 * @param ranges the positions of the interval deletes, in insertion order. an interval covers keys
 *               it was never written beside, so it has no place in a list keyed by key; there are
 *               few of them and a lookup walks them newest first
 * @param n_ranges how many interval deletes ranges holds
 * @param ranges_cap allocated length of ranges
 * @param lock guards ops-array mutation against a cross-txn peer scan
 * @param mem_bytes approximate heap held by the ops, their buffers and the key list. atomic
 *                  because the stats sweep sums it across live transactions owned by other
 *                  threads, while only the owner mutates it -- relaxed throughout, since the figure
 *                  is a gauge and the mutations are already ordered by the lock
 */
struct tidesdb_writeset
{
    writeset_op *ops;
    int count;
    int capacity;
    skip_list_t *keys;
    int *ranges;
    int n_ranges;
    int ranges_cap;
    pthread_rwlock_t lock;
    _Atomic(int64_t) mem_bytes;
};

tidesdb_writeset_t *tidesdb_writeset_create(void)
{
    tidesdb_writeset_t *ws = calloc(1, sizeof(*ws));
    if (!ws) return NULL;
    if (skip_list_new(&ws->keys, TDB_WRITESET_SKIP_MAX_LEVEL, TDB_WRITESET_SKIP_PROBABILITY) != 0)
    {
        free(ws);
        return NULL;
    }
    if (pthread_rwlock_init(&ws->lock, NULL) != 0)
    {
        skip_list_free(ws->keys);
        free(ws);
        return NULL;
    }
    return ws;
}

void tidesdb_writeset_free(tidesdb_writeset_t *ws)
{
    if (!ws) return;
    for (int i = 0; i < ws->count; i++) free(ws->ops[i].buf);
    free(ws->ops);
    skip_list_free(ws->keys);
    free(ws->ranges);
    pthread_rwlock_destroy(&ws->lock);
    free(ws);
}

/* the key list's key for a family and key, the family prefix and then the key; built on the stack
 * when it fits, or returned NULL when it had to be allocated and could not be */
static uint8_t *writeset_prefixed(const uint32_t cf_index, const uint8_t *key,
                                  const size_t key_size, uint8_t *stack, const size_t stack_cap,
                                  size_t *out_size)
{
    const size_t total = TDB_CF_PREFIX_SIZE + key_size;
    uint8_t *buf = total <= stack_cap ? stack : malloc(total);
    if (!buf) return NULL;
    tdb_build_prefixed_key(cf_index, key, key_size, buf);
    *out_size = total;
    return buf;
}

/* record the op at a position where it belongs -- in the key list as its key's newest write when it
 * is a point op, or on the interval list when it is an interval delete. the memory gauge follows
 * the key list */
static int writeset_note(tidesdb_writeset_t *ws, const int i)
{
    const writeset_op *op = &ws->ops[i];
    if (op->flags & TDB_WAL_ENTRY_RANGE_DELETE)
    {
        if (ws->n_ranges == ws->ranges_cap)
        {
            const int cap = ws->ranges_cap ? ws->ranges_cap * 2 : TDB_WRITESET_RANGES_INITIAL_CAP;
            int *grown = realloc(ws->ranges, (size_t)cap * sizeof(*grown));
            if (!grown) return TDB_ERR_MEMORY;
            atomic_fetch_add_explicit(&ws->mem_bytes,
                                      (int64_t)((size_t)(cap - ws->ranges_cap) * sizeof(*grown)),
                                      memory_order_relaxed);
            ws->ranges = grown;
            ws->ranges_cap = cap;
        }
        ws->ranges[ws->n_ranges++] = i;
        return TDB_SUCCESS;
    }

    uint8_t stack[TDB_WRITESET_KEY_STACK_BUF];
    size_t pkey_size = 0;
    uint8_t *pkey =
        writeset_prefixed(op->cf_index, op->buf, op->key_size, stack, sizeof(stack), &pkey_size);
    if (!pkey) return TDB_ERR_MEMORY;
    const uint64_t position = (uint64_t)i;
    const int64_t before = (int64_t)skip_list_get_memory_bytes(ws->keys);
    const int rc = skip_list_put_with_seq(ws->keys, pkey, pkey_size, (const uint8_t *)&position,
                                          sizeof(position), -1, position + 1, 0) == 0
                       ? TDB_SUCCESS
                       : TDB_ERR_MEMORY;
    atomic_fetch_add_explicit(&ws->mem_bytes,
                              (int64_t)skip_list_get_memory_bytes(ws->keys) - before,
                              memory_order_relaxed);
    if (pkey != stack) free(pkey);
    return rc;
}

int tidesdb_writeset_put(tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                         size_t key_size, const uint8_t *value, size_t value_size, int64_t ttl,
                         uint8_t flags)
{
    if (!ws || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    /* a tombstone carries no value, with one exception: an interval delete names no value of its
     * own, so its upper bound rides in that field. dropping it here would leave every interval
     * open above and delete far more than the caller asked for */
    if ((flags & TDB_WAL_ENTRY_TOMBSTONE) && !(flags & TDB_WAL_ENTRY_RANGE_DELETE)) value_size = 0;

    uint8_t *buf = malloc(key_size + value_size);
    if (!buf) return TDB_ERR_MEMORY;
    memcpy(buf, key, key_size);
    if (value_size) memcpy(buf + key_size, value, value_size);

    pthread_rwlock_wrlock(&ws->lock);
    if (ws->count == ws->capacity)
    {
        const int new_cap = ws->capacity ? ws->capacity * 2 : TDB_WRITESET_INITIAL_CAP;
        writeset_op *grown = realloc(ws->ops, (size_t)new_cap * sizeof(*grown));
        if (!grown)
        {
            pthread_rwlock_unlock(&ws->lock);
            free(buf);
            return TDB_ERR_MEMORY;
        }
        ws->ops = grown;
        ws->capacity = new_cap;
    }
    ws->ops[ws->count] = (writeset_op){cf_index, buf, key_size, value_size, ttl, flags};
    ws->count++;
    atomic_fetch_add_explicit(&ws->mem_bytes,
                              (int64_t)(sizeof(writeset_op) + key_size + value_size),
                              memory_order_relaxed);
    /* noted once it is in the array, so the key list never names an op the array does not hold. a
     * put that could not be noted is refused rather than left out of the list, since a lookup that
     * could miss a buffered write would read the store past the transaction's own delete */
    const int rc = writeset_note(ws, ws->count - 1);
    if (rc != TDB_SUCCESS)
    {
        ws->count--;
        atomic_fetch_sub_explicit(&ws->mem_bytes,
                                  (int64_t)(sizeof(writeset_op) + key_size + value_size),
                                  memory_order_relaxed);
        free(buf);
    }
    pthread_rwlock_unlock(&ws->lock);
    return rc;
}

int tidesdb_writeset_count(const tidesdb_writeset_t *ws)
{
    return ws ? ws->count : 0;
}

/* fill a public op view from an internal op */
static void writeset_view(const writeset_op *op, tidesdb_writeset_op_t *out)
{
    out->cf_index = op->cf_index;
    out->key = op->buf;
    out->key_size = op->key_size;
    out->value = op->value_size ? op->buf + op->key_size : NULL;
    out->value_size = op->value_size;
    out->ttl = op->ttl;
    out->flags = op->flags;
}

int tidesdb_writeset_op_at(const tidesdb_writeset_t *ws, int index, tidesdb_writeset_op_t *out)
{
    if (!ws || !out || index < 0 || index >= ws->count) return 0;
    writeset_view(&ws->ops[index], out);
    return 1;
}

/* whether a buffered interval delete covers a key. its lower bound is the op's key and its upper
 * bound the value stored beside it, open when that value is empty
 * @param op the buffered op, which the caller has already checked is an interval delete
 * @param key the key being looked up
 * @param key_size length of key
 * @return non-zero when the key falls inside the interval
 */
static int writeset_range_covers(const writeset_op *op, const uint8_t *key, const size_t key_size)
{
    if (tdb_key_cmp(op->buf, op->key_size, key, key_size) > 0) return 0;
    if (op->value_size == 0) return 1; /* open above */
    return tdb_key_cmp(key, key_size, op->buf + op->key_size, op->value_size) < 0;
}

skip_list_t *tidesdb_writeset_keys(const tidesdb_writeset_t *ws)
{
    return ws ? ws->keys : NULL;
}

int tidesdb_writeset_newest(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                            size_t key_size)
{
    if (!ws || !key || key_size == 0) return -1;
    uint8_t stack[TDB_WRITESET_KEY_STACK_BUF];
    size_t pkey_size = 0;
    uint8_t *pkey = writeset_prefixed(cf_index, key, key_size, stack, sizeof(stack), &pkey_size);
    if (!pkey) return -1;
    /* the head version is the newest write, and its value is that write's position */
    const uint8_t *value = NULL;
    size_t value_size = 0;
    const int found = skip_list_get_with_seq_ref(ws->keys, pkey, pkey_size, &value, &value_size,
                                                 NULL, NULL, NULL, UINT64_MAX, NULL, NULL);
    if (pkey != stack) free(pkey);
    if (found != 0 || value_size != sizeof(uint64_t)) return -1;
    uint64_t position = 0;
    memcpy(&position, value, sizeof(position));
    return (int)position;
}

int tidesdb_writeset_covering(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                              size_t key_size, int after)
{
    if (!ws || !key) return -1;
    /* newest first, stopping at the position the caller's own write holds -- an interval buffered
     * before that write does not shadow it */
    for (int r = ws->n_ranges - 1; r >= 0; r--)
    {
        const int i = ws->ranges[r];
        if (i <= after) break;
        const writeset_op *op = &ws->ops[i];
        if (op->cf_index == cf_index && writeset_range_covers(op, key, key_size)) return i;
    }
    return -1;
}

int tidesdb_writeset_touches(const tidesdb_writeset_t *ws, uint32_t cf_index)
{
    if (!ws) return 0;
    for (int r = 0; r < ws->n_ranges; r++)
        if (ws->ops[ws->ranges[r]].cf_index == cf_index) return 1;

    /* the first key at or past the family's prefix is the family's when it carries that prefix */
    skip_list_cursor_t *cursor = NULL;
    if (skip_list_cursor_init(&cursor, ws->keys) != 0) return 0;
    uint8_t prefix[TDB_CF_PREFIX_SIZE];
    tdb_encode_be32(cf_index, prefix);
    int touches = 0;
    if (skip_list_cursor_seek_ge(cursor, prefix, sizeof(prefix)) == 0 &&
        skip_list_cursor_valid(cursor))
    {
        uint8_t *pkey = NULL, *value = NULL;
        size_t pkey_size = 0, value_size = 0;
        touches = skip_list_cursor_get_with_seq(cursor, &pkey, &pkey_size, &value, &value_size,
                                                NULL, NULL, NULL, NULL) == 0 &&
                  pkey_size >= TDB_CF_PREFIX_SIZE && tdb_decode_be32(pkey) == cf_index;
    }
    skip_list_cursor_free(cursor);
    return touches;
}

int tidesdb_writeset_lookup(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                            size_t key_size, tidesdb_writeset_op_t *out)
{
    if (!ws || !key || !out) return 0;

    /* the newest point write of the key, then any interval delete buffered after it -- a buffered
     * interval delete shadows every key inside it, so it matches on its bounds rather than on
     * equality, and it is the newest write of this key from here on, exactly as a delete of the key
     * itself would be */
    const int point = tidesdb_writeset_newest(ws, cf_index, key, key_size);
    const int range = tidesdb_writeset_covering(ws, cf_index, key, key_size, point);
    if (range >= 0)
    {
        writeset_view(&ws->ops[range], out);
        return 1;
    }
    if (point < 0) return 0;
    writeset_view(&ws->ops[point], out);
    return 1;
}

int tidesdb_writeset_truncate(tidesdb_writeset_t *ws, int count)
{
    if (!ws) return TDB_ERR_INVALID_ARGS;
    if (count < 0) count = 0;
    int rc = TDB_SUCCESS;
    pthread_rwlock_wrlock(&ws->lock);
    if (count < ws->count)
    {
        for (int i = count; i < ws->count; i++)
        {
            atomic_fetch_sub_explicit(
                &ws->mem_bytes,
                (int64_t)(sizeof(writeset_op) + ws->ops[i].key_size + ws->ops[i].value_size),
                memory_order_relaxed);
            free(ws->ops[i].buf);
        }
        ws->count = count;

        /* the discarded tail may have held the newest write of a key an earlier op also wrote, so
         * the key list and the interval list are built again over what remains. a rollback to a
         * savepoint is rare enough that noting the surviving ops once more is the right price. a
         * list that could not be rebuilt whole is not left short of an op -- it is emptied and the
         * failure reported, for the caller to end the transaction rather than read past its own
         * writes */
        const int64_t before = (int64_t)skip_list_get_memory_bytes(ws->keys);
        (void)skip_list_clear(ws->keys);
        atomic_fetch_add_explicit(&ws->mem_bytes,
                                  (int64_t)skip_list_get_memory_bytes(ws->keys) - before,
                                  memory_order_relaxed);
        ws->n_ranges = 0;
        for (int i = 0; i < ws->count && rc == TDB_SUCCESS; i++) rc = writeset_note(ws, i);
        if (rc != TDB_SUCCESS)
        {
            (void)skip_list_clear(ws->keys);
            ws->n_ranges = 0;
        }
    }
    pthread_rwlock_unlock(&ws->lock);
    return rc;
}

int64_t tidesdb_writeset_mem_bytes(const tidesdb_writeset_t *ws)
{
    return ws ? atomic_load_explicit(&ws->mem_bytes, memory_order_relaxed) : 0;
}
