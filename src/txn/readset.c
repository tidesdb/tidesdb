/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "readset.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "db.h" /* TDB_SUCCESS / TDB_ERR_* result codes */

/* initial array capacity for the keys and for the intervals, grown by doubling */
#define TDB_READSET_INITIAL_CAP 16

/**
 * readset_entry
 * one recorded read; the key is its own allocation
 * @param cf_index target column family prefix index
 * @param key allocated key bytes
 * @param key_size length of key
 * @param seq highest sequence observed for the key
 */
typedef struct
{
    uint32_t cf_index;
    uint8_t *key;
    size_t key_size;
    uint64_t seq;
} readset_entry;

/**
 * readset_range
 * one interval a scan covered; the bounds are their own allocations
 * @param cf_index target column family prefix index
 * @param lo allocated inclusive lower bound
 * @param lo_size length of lo
 * @param hi allocated exclusive upper bound, NULL when the scan ran to the end of the family
 * @param hi_size length of hi, 0 when open above
 * @param seq the snapshot the scan read at
 */
typedef struct
{
    uint32_t cf_index;
    uint8_t *lo;
    size_t lo_size;
    uint8_t *hi;
    size_t hi_size;
    uint64_t seq;
} readset_range;

/**
 * tidesdb_readset
 * the read set with its lock and memory accounting
 * @param entries recorded reads, one per distinct key
 * @param count number of entries
 * @param capacity allocated length of entries
 * @param ranges the intervals scans covered, one per freed iterator
 * @param range_count number of ranges
 * @param range_capacity allocated length of ranges
 * @param lock guards array mutation
 * @param mem_bytes approximate heap held by the entries, the ranges and their bytes. atomic for the
 *                  same reason the write set's is -- the stats sweep reads it from another thread
 */
struct tidesdb_readset
{
    readset_entry *entries;
    int count;
    int capacity;
    readset_range *ranges;
    int range_count;
    int range_capacity;
    pthread_rwlock_t lock;
    _Atomic(int64_t) mem_bytes;
};

tidesdb_readset_t *tidesdb_readset_create(void)
{
    tidesdb_readset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    if (pthread_rwlock_init(&rs->lock, NULL) != 0)
    {
        free(rs);
        return NULL;
    }
    return rs;
}

/* free every entry's key and every range's bounds and reset the counts; the caller owns the set */
static void readset_drop_all(tidesdb_readset_t *rs)
{
    for (int i = 0; i < rs->count; i++) free(rs->entries[i].key);
    rs->count = 0;
    for (int i = 0; i < rs->range_count; i++)
    {
        free(rs->ranges[i].lo);
        free(rs->ranges[i].hi);
    }
    rs->range_count = 0;
    atomic_store_explicit(&rs->mem_bytes, 0, memory_order_relaxed);
}

void tidesdb_readset_free(tidesdb_readset_t *rs)
{
    if (!rs) return;
    readset_drop_all(rs);
    free(rs->entries);
    free(rs->ranges);
    pthread_rwlock_destroy(&rs->lock);
    free(rs);
}

/* index of a key in the entry array, or -1; caller holds a lock or owns the set */
static int readset_index(const tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                         size_t key_size)
{
    for (int i = 0; i < rs->count; i++)
    {
        const readset_entry *e = &rs->entries[i];
        if (e->cf_index == cf_index && e->key_size == key_size &&
            memcmp(e->key, key, key_size) == 0)
            return i;
    }
    return -1;
}

/* copy a bound, or NULL when it is empty or cannot be copied; *ok is cleared on a failed copy */
static uint8_t *readset_copy_bytes(const uint8_t *src, size_t size, int *ok)
{
    if (size == 0) return NULL;
    uint8_t *copy = malloc(size);
    if (!copy)
    {
        *ok = 0;
        return NULL;
    }
    memcpy(copy, src, size);
    return copy;
}

int tidesdb_readset_record(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                           size_t key_size, uint64_t seq)
{
    if (!rs || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    pthread_rwlock_wrlock(&rs->lock);

    /* keep the higher observed seq for a key already read */
    const int existing = readset_index(rs, cf_index, key, key_size);
    if (existing >= 0)
    {
        if (seq > rs->entries[existing].seq) rs->entries[existing].seq = seq;
        pthread_rwlock_unlock(&rs->lock);
        return TDB_SUCCESS;
    }

    uint8_t *key_copy = malloc(key_size);
    if (!key_copy)
    {
        pthread_rwlock_unlock(&rs->lock);
        return TDB_ERR_MEMORY;
    }
    memcpy(key_copy, key, key_size);

    if (rs->count == rs->capacity)
    {
        const int new_cap = rs->capacity ? rs->capacity * 2 : TDB_READSET_INITIAL_CAP;
        readset_entry *grown = realloc(rs->entries, (size_t)new_cap * sizeof(*grown));
        if (!grown)
        {
            free(key_copy);
            pthread_rwlock_unlock(&rs->lock);
            return TDB_ERR_MEMORY;
        }
        rs->entries = grown;
        rs->capacity = new_cap;
    }
    rs->entries[rs->count] = (readset_entry){cf_index, key_copy, key_size, seq};
    rs->count++;
    atomic_fetch_add_explicit(&rs->mem_bytes, (int64_t)(sizeof(readset_entry) + key_size),
                              memory_order_relaxed);
    pthread_rwlock_unlock(&rs->lock);
    return TDB_SUCCESS;
}

int tidesdb_readset_record_range(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *lo,
                                 size_t lo_size, const uint8_t *hi, size_t hi_size, uint64_t seq)
{
    if (!rs || !lo || lo_size == 0 || (hi_size > 0 && !hi)) return TDB_ERR_INVALID_ARGS;

    int ok = 1;
    uint8_t *lo_copy = readset_copy_bytes(lo, lo_size, &ok);
    uint8_t *hi_copy = readset_copy_bytes(hi, hi_size, &ok);
    if (!ok)
    {
        free(lo_copy);
        free(hi_copy);
        return TDB_ERR_MEMORY;
    }

    pthread_rwlock_wrlock(&rs->lock);
    if (rs->range_count == rs->range_capacity)
    {
        const int new_cap = rs->range_capacity ? rs->range_capacity * 2 : TDB_READSET_INITIAL_CAP;
        readset_range *grown = realloc(rs->ranges, (size_t)new_cap * sizeof(*grown));
        if (!grown)
        {
            pthread_rwlock_unlock(&rs->lock);
            free(lo_copy);
            free(hi_copy);
            return TDB_ERR_MEMORY;
        }
        rs->ranges = grown;
        rs->range_capacity = new_cap;
    }
    rs->ranges[rs->range_count] =
        (readset_range){cf_index, lo_copy, lo_size, hi_copy, hi_size, seq};
    rs->range_count++;
    atomic_fetch_add_explicit(&rs->mem_bytes, (int64_t)(sizeof(readset_range) + lo_size + hi_size),
                              memory_order_relaxed);
    pthread_rwlock_unlock(&rs->lock);
    return TDB_SUCCESS;
}

int tidesdb_readset_count(const tidesdb_readset_t *rs)
{
    return rs ? rs->count : 0;
}

int tidesdb_readset_at(const tidesdb_readset_t *rs, int index, tidesdb_readset_entry_t *out)
{
    if (!rs || !out || index < 0 || index >= rs->count) return 0;
    const readset_entry *e = &rs->entries[index];
    out->cf_index = e->cf_index;
    out->key = e->key;
    out->key_size = e->key_size;
    out->seq = e->seq;
    return 1;
}

int tidesdb_readset_range_count(const tidesdb_readset_t *rs)
{
    return rs ? rs->range_count : 0;
}

int tidesdb_readset_range_at(const tidesdb_readset_t *rs, int index, tidesdb_readset_range_t *out)
{
    if (!rs || !out || index < 0 || index >= rs->range_count) return 0;
    const readset_range *r = &rs->ranges[index];
    out->cf_index = r->cf_index;
    out->lo = r->lo;
    out->lo_size = r->lo_size;
    out->hi = r->hi;
    out->hi_size = r->hi_size;
    out->seq = r->seq;
    return 1;
}

int64_t tidesdb_readset_mem_bytes(const tidesdb_readset_t *rs)
{
    return rs ? atomic_load_explicit(&rs->mem_bytes, memory_order_relaxed) : 0;
}
