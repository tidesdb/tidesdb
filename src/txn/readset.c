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

/* initial entry-array capacity, grown by doubling */
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
 * tidesdb_readset
 * the read set with its scan lock and memory accounting
 * @param entries recorded reads, one per distinct key
 * @param count number of entries
 * @param capacity allocated length of entries
 * @param lock guards entry-array mutation against a cross-txn peer scan
 * @param mem_bytes approximate heap held by the entries and their keys. atomic for the same reason
 *                  the write set's is -- the stats sweep reads it from another thread
 */
struct tidesdb_readset
{
    readset_entry *entries;
    int count;
    int capacity;
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

/* free every entry's key and reset the count; the caller holds the write lock or owns the set */
static void readset_drop_all(tidesdb_readset_t *rs)
{
    for (int i = 0; i < rs->count; i++) free(rs->entries[i].key);
    rs->count = 0;
    atomic_store_explicit(&rs->mem_bytes, 0, memory_order_relaxed);
}

void tidesdb_readset_free(tidesdb_readset_t *rs)
{
    if (!rs) return;
    readset_drop_all(rs);
    free(rs->entries);
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

int tidesdb_readset_seq(const tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                        size_t key_size, uint64_t *out_seq)
{
    if (!rs || !key) return 0;
    const int idx = readset_index(rs, cf_index, key, key_size);
    if (idx < 0) return 0;
    if (out_seq) *out_seq = rs->entries[idx].seq;
    return 1;
}

int tidesdb_readset_contains(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                             size_t key_size)
{
    if (!rs || !key) return 0;
    pthread_rwlock_rdlock(&rs->lock);
    const int found = readset_index(rs, cf_index, key, key_size) >= 0;
    pthread_rwlock_unlock(&rs->lock);
    return found;
}

void tidesdb_readset_clear(tidesdb_readset_t *rs)
{
    if (!rs) return;
    pthread_rwlock_wrlock(&rs->lock);
    readset_drop_all(rs);
    pthread_rwlock_unlock(&rs->lock);
}

int64_t tidesdb_readset_mem_bytes(const tidesdb_readset_t *rs)
{
    return rs ? atomic_load_explicit(&rs->mem_bytes, memory_order_relaxed) : 0;
}
