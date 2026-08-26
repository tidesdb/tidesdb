/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "wal_record.h"

#include <string.h>

/* byte length of value encoded as a base-128 varint */
static size_t varint_len(uint64_t value)
{
    size_t n = 1;
    while (value >= 0x80)
    {
        value >>= 7;
        n++;
    }
    return n;
}

/* encoded byte length of one entry's fields (not counting the batch header) */
static size_t entry_size(const tidesdb_wal_entry_t *e)
{
    size_t n = 1; /* flags */
    n += varint_len(e->cf_index);
    n += varint_len(e->seq);
    n += varint_len(e->key_size);
    n += varint_len(e->value_size);
    if (e->flags & TDB_WAL_ENTRY_HAS_TTL) n += varint_len((uint64_t)e->ttl);
    if (e->flags & TDB_WAL_ENTRY_VLOG_REF) n += varint_len(e->vlog_id);
    n += e->key_size;
    /* a referenced value keeps its logical length in value_size but lays down no bytes; the id
     * above is what stands in for them */
    if (!(e->flags & TDB_WAL_ENTRY_VLOG_REF)) n += e->value_size;
    return n;
}

size_t tidesdb_wal_batch_size(uint8_t kind, const uint8_t *xid, size_t xid_size,
                              const tidesdb_wal_entry_t *entries, size_t count)
{
    (void)kind;
    if (!xid) xid_size = 0;
    size_t n = 1 + 1; /* version byte + kind byte */
    n += varint_len((uint64_t)xid_size) + xid_size;
    n += varint_len((uint64_t)count);
    for (size_t i = 0; i < count; i++) n += entry_size(&entries[i]);
    return n;
}

size_t tidesdb_wal_batch_encode(uint8_t kind, const uint8_t *xid, size_t xid_size,
                                const tidesdb_wal_entry_t *entries, size_t count, uint8_t *out,
                                size_t cap)
{
    if (!out || (count > 0 && !entries)) return 0;
    if (!xid) xid_size = 0;
    const size_t need = tidesdb_wal_batch_size(kind, xid, xid_size, entries, count);
    if (cap < need) return 0;

    uint8_t *p = out;
    *p++ = TDB_WAL_FORMAT_VERSION;
    *p++ = kind;
    p += encode_varint(p, (uint64_t)xid_size);
    if (xid_size) memcpy(p, xid, xid_size);
    p += xid_size;
    p += encode_varint(p, (uint64_t)count);
    for (size_t i = 0; i < count; i++)
    {
        const tidesdb_wal_entry_t *e = &entries[i];
        *p++ = e->flags;
        p += encode_varint(p, e->cf_index);
        p += encode_varint(p, e->seq);
        p += encode_varint(p, (uint64_t)e->key_size);
        p += encode_varint(p, (uint64_t)e->value_size);
        if (e->flags & TDB_WAL_ENTRY_HAS_TTL) p += encode_varint(p, (uint64_t)e->ttl);
        if (e->flags & TDB_WAL_ENTRY_VLOG_REF) p += encode_varint(p, e->vlog_id);
        if (e->key_size) memcpy(p, e->key, e->key_size);
        p += e->key_size;
        if (!(e->flags & TDB_WAL_ENTRY_VLOG_REF))
        {
            if (e->value_size) memcpy(p, e->value, e->value_size);
            p += e->value_size;
        }
    }
    return (size_t)(p - out);
}

int tidesdb_wal_cursor_init(tidesdb_wal_cursor_t *c, const uint8_t *buf, size_t size)
{
    if (!c || !buf || size < 2) return -1;
    if (buf[0] != TDB_WAL_FORMAT_VERSION) return -1;

    c->buf = buf;
    c->size = size;
    c->kind = buf[1];
    c->pos = 2;

    /* xid blob */
    uint64_t xid_size = 0;
    int used = decode_varint(buf + c->pos, &xid_size, (int)(size - c->pos));
    if (used < 0) return -1;
    c->pos += (size_t)used;
    if (xid_size > size - c->pos) return -1;
    c->xid = xid_size ? buf + c->pos : NULL;
    c->xid_size = (size_t)xid_size;
    c->pos += (size_t)xid_size;

    /* entry count */
    uint64_t count = 0;
    used = decode_varint(buf + c->pos, &count, (int)(size - c->pos));
    if (used < 0) return -1;
    c->pos += (size_t)used;
    c->remaining = (size_t)count;
    return 0;
}

/* read a varint at the cursor position, advancing pos; returns 0 on success, -1 on truncation */
static int cursor_varint(tidesdb_wal_cursor_t *c, uint64_t *out)
{
    if (c->pos >= c->size) return -1;
    const int used = decode_varint(c->buf + c->pos, out, (int)(c->size - c->pos));
    if (used < 0) return -1;
    c->pos += (size_t)used;
    return 0;
}

int tidesdb_wal_cursor_next(tidesdb_wal_cursor_t *c, tidesdb_wal_entry_t *out)
{
    if (!c || !out) return -1;
    if (c->remaining == 0) return 0;

    if (c->pos >= c->size) return -1;
    const uint8_t flags = c->buf[c->pos++];

    uint64_t cf_index = 0, seq = 0, key_size = 0, value_size = 0;
    if (cursor_varint(c, &cf_index) != 0) return -1;
    if (cursor_varint(c, &seq) != 0) return -1;
    if (cursor_varint(c, &key_size) != 0) return -1;
    if (cursor_varint(c, &value_size) != 0) return -1;

    int64_t ttl = -1;
    if (flags & TDB_WAL_ENTRY_HAS_TTL)
    {
        uint64_t ttl_bits = 0;
        if (cursor_varint(c, &ttl_bits) != 0) return -1;
        ttl = (int64_t)ttl_bits;
    }

    uint64_t vlog_id = 0;
    if (flags & TDB_WAL_ENTRY_VLOG_REF)
    {
        if (cursor_varint(c, &vlog_id) != 0) return -1;
        /* an id of zero names nothing, so a record claiming a reference without one is malformed
         * rather than an entry with an empty value -- letting it through would apply a write whose
         * value could never be resolved */
        if (vlog_id == 0) return -1;
    }

    /* the key and value must both fit within the remaining buffer */
    if (key_size > c->size - c->pos) return -1;
    const uint8_t *key = c->buf + c->pos;
    c->pos += (size_t)key_size;

    /* a referenced value laid down no bytes, so its logical length says nothing about what remains
     * in the buffer and nothing is consumed for it */
    const uint8_t *value = NULL;
    if (!(flags & TDB_WAL_ENTRY_VLOG_REF))
    {
        if (value_size > c->size - c->pos) return -1;
        value = value_size ? c->buf + c->pos : NULL;
        c->pos += (size_t)value_size;
    }

    out->cf_index = (uint32_t)cf_index;
    out->seq = seq;
    out->ttl = ttl;
    out->flags = flags;
    out->key = key;
    out->key_size = (size_t)key_size;
    out->value = value;
    out->value_size = (size_t)value_size;
    out->vlog_id = vlog_id;
    c->remaining--;
    return 1;
}
