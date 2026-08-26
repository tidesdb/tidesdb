/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_READSET_H__
#define __TIDESDB_TXN_READSET_H__

#include "../compat.h"

/* a transaction's read set -- the cf-namespaced keys it has read and the highest sequence it
 * observed for each. repeatable-read and serializable record their reads here so commit can
 * validate that none changed under them, and a serializable peer scans this set for read-write
 * antidependencies. like the write set, mutation goes through one guarded api: the owner records
 * behind a write lock and a peer scans behind the read lock. a repeated read of the same key keeps
 * the higher observed sequence rather than appending, so the set stays bounded by distinct keys. */

typedef struct tidesdb_readset tidesdb_readset_t;

/**
 * tidesdb_readset_entry_t
 * a read-only view of one recorded read, key pointing into the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param seq the highest sequence observed for this key
 */
typedef struct
{
    uint32_t cf_index;
    const uint8_t *key;
    size_t key_size;
    uint64_t seq;
} tidesdb_readset_entry_t;

/**
 * tidesdb_readset_create
 * create an empty read set
 * @return the read set, or NULL on allocation failure
 */
tidesdb_readset_t *tidesdb_readset_create(void);

/**
 * tidesdb_readset_free
 * free the read set and its recorded keys
 * @param rs the read set, may be NULL
 */
void tidesdb_readset_free(tidesdb_readset_t *rs);

/**
 * tidesdb_readset_record
 * record a read of a cf-namespaced key at the observed sequence, keeping the higher sequence if the
 * key was already read, under the write lock
 * @param rs the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key (must be > 0)
 * @param seq the sequence observed for this read
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS / TDB_ERR_MEMORY
 */
int tidesdb_readset_record(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                           size_t key_size, uint64_t seq);

/**
 * tidesdb_readset_count
 * the number of distinct recorded reads; an owner-side read
 * @param rs the read set
 * @return the count, or 0 if rs is NULL
 */
int tidesdb_readset_count(const tidesdb_readset_t *rs);

/**
 * tidesdb_readset_at
 * borrow the recorded read at an index for commit-time validation; an owner-side read
 * @param rs the read set
 * @param index 0-based index
 * @param out receives the entry view
 * @return 1 if the index was in range, 0 otherwise
 */
int tidesdb_readset_at(const tidesdb_readset_t *rs, int index, tidesdb_readset_entry_t *out);

/**
 * tidesdb_readset_seq
 * the highest sequence observed for a key, for the reservation read base; an owner-side read
 * @param rs the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param out_seq receives the observed sequence on a hit
 * @return 1 if the key was read, 0 otherwise
 */
int tidesdb_readset_seq(const tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                        size_t key_size, uint64_t *out_seq);

/**
 * tidesdb_readset_contains
 * whether a key was read, under the read lock so a serializable peer can scan a running txn's read
 * set safely for read-write antidependency detection
 * @param rs the read set
 * @param cf_index the column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @return 1 if the key was read, 0 otherwise
 */
int tidesdb_readset_contains(tidesdb_readset_t *rs, uint32_t cf_index, const uint8_t *key,
                             size_t key_size);

/**
 * tidesdb_readset_clear
 * drop every recorded read, freeing the keys, for reuse of the transaction
 * @param rs the read set
 */
void tidesdb_readset_clear(tidesdb_readset_t *rs);

/**
 * tidesdb_readset_mem_bytes
 * the approximate heap the read set holds, for per-txn memory accounting
 * @param rs the read set
 * @return the byte estimate, or 0 if rs is NULL
 */
int64_t tidesdb_readset_mem_bytes(const tidesdb_readset_t *rs);

#endif /* __TIDESDB_TXN_READSET_H__ */
