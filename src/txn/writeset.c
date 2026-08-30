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

#include "base/keycmp.h" /* tdb_key_cmp, the one byte-wise key order */
#include "db.h"          /* TDB_SUCCESS / TDB_ERR_* result codes */

/* initial op-array capacity, grown by doubling */
#define TDB_WRITESET_INITIAL_CAP 16

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
 * @param lock guards ops-array mutation against a cross-txn peer scan
 * @param mem_bytes approximate heap held by the ops and their buffers. atomic because the stats
 *                  sweep sums it across live transactions owned by other threads, while only the
 *                  owner mutates it -- relaxed throughout, since the figure is a gauge and the
 *                  mutations are already ordered by the lock
 */
struct tidesdb_writeset
{
    writeset_op *ops;
    int count;
    int capacity;
    pthread_rwlock_t lock;
    _Atomic(int64_t) mem_bytes;
};

tidesdb_writeset_t *tidesdb_writeset_create(void)
{
    tidesdb_writeset_t *ws = calloc(1, sizeof(*ws));
    if (!ws) return NULL;
    if (pthread_rwlock_init(&ws->lock, NULL) != 0)
    {
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
    pthread_rwlock_destroy(&ws->lock);
    free(ws);
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
    pthread_rwlock_unlock(&ws->lock);
    return TDB_SUCCESS;
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

int tidesdb_writeset_lookup(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                            size_t key_size, tidesdb_writeset_op_t *out)
{
    if (!ws || !key || !out) return 0;
    /* newest-first so the latest write of the key wins read-your-own-writes */
    for (int i = ws->count - 1; i >= 0; i--)
    {
        const writeset_op *op = &ws->ops[i];
        if (op->cf_index != cf_index) continue;

        /* a buffered interval delete shadows every key inside it, so its op matches on the bounds
         * rather than on equality. it is the newest write of this key from here on, exactly as a
         * delete of the key itself would be */
        const int hit = (op->flags & TDB_WAL_ENTRY_RANGE_DELETE)
                            ? writeset_range_covers(op, key, key_size)
                            : op->key_size == key_size && memcmp(op->buf, key, key_size) == 0;
        if (hit)
        {
            writeset_view(op, out);
            return 1;
        }
    }
    return 0;
}

void tidesdb_writeset_truncate(tidesdb_writeset_t *ws, int count)
{
    if (!ws) return;
    if (count < 0) count = 0;
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
    }
    pthread_rwlock_unlock(&ws->lock);
}

int tidesdb_writeset_contains(tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                              size_t key_size)
{
    if (!ws || !key) return 0;
    int found = 0;
    pthread_rwlock_rdlock(&ws->lock);
    for (int i = 0; i < ws->count; i++)
    {
        const writeset_op *op = &ws->ops[i];
        if (op->cf_index == cf_index && op->key_size == key_size &&
            memcmp(op->buf, key, key_size) == 0)
        {
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&ws->lock);
    return found;
}

int64_t tidesdb_writeset_mem_bytes(const tidesdb_writeset_t *ws)
{
    return ws ? atomic_load_explicit(&ws->mem_bytes, memory_order_relaxed) : 0;
}
