/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_KEY_INDEX_H__
#define __TIDESDB_TXN_KEY_INDEX_H__

#include "../compat.h"

/* an open-addressed index from a family and key to a position in an array its owner keeps. the
 * owner's array is the record and the index only says where in it to look, so the owner answers
 * every question about an entry and the index holds nothing but positions. the write set and the
 * read set both answered a lookup by walking their arrays and comparing keys, which made every
 * operation of a transaction cost as much as it had already buffered and a load of a hundred
 * thousand rows quadratic in the rows. both bucket by the one hash the claims and the commit's
 * dedup bucket by. single-threaded, like the sets that own one */

/**
 * tdb_key_index_t
 * the index, positions one-based so a zero slot is empty
 * @param slots the slot array, NULL until the first entry is indexed
 * @param mask one less than the slot count, a power of two
 * @param occupied how many slots hold a position, the load the width is kept against
 */
typedef struct
{
    int *slots;
    uint32_t mask;
    int occupied;
} tdb_key_index_t;

/**
 * tdb_key_index_entry_fn
 * the owner's view of the entry at a position, asked when a probe compares keys and when the index
 * is rebuilt
 * @param ctx the owner
 * @param position the entry's position in the owner's array
 * @param cf_index receives the entry's family
 * @param key receives the entry's key bytes, borrowed for the call
 * @param key_size receives the key length
 * @return 1 when the entry is one the index keys, 0 when it is not indexed by key at all
 */
typedef int (*tdb_key_index_entry_fn)(const void *ctx, int position, uint32_t *cf_index,
                                      const uint8_t **key, size_t *key_size);

/**
 * tdb_key_index_init
 * start an index empty
 * @param ix the index
 */
void tdb_key_index_init(tdb_key_index_t *ix);

/**
 * tdb_key_index_free
 * release an index's slots; the owner's entries are untouched
 * @param ix the index, may be NULL
 */
void tdb_key_index_free(tdb_key_index_t *ix);

/**
 * tdb_key_index_find
 * the position the index holds for a family and key
 * @param ix the index
 * @param ctx the owner, handed to entry
 * @param entry the owner's entry view
 * @param cf_index the family
 * @param key the key bytes
 * @param key_size length of key
 * @return the position, or -1 when the key is not indexed
 */
int tdb_key_index_find(const tdb_key_index_t *ix, const void *ctx, tdb_key_index_entry_fn entry,
                       uint32_t cf_index, const uint8_t *key, size_t key_size);

/**
 * tdb_key_index_put
 * index the entry the owner has just placed at a position, so it becomes the position its key maps
 * to -- an earlier position for the same key is superseded in place. widens the index by rebuilding
 * it over the owner's first count entries when it is full, which re-reads every entry once and
 * stays a constant per put by doubling
 * @param ix the index
 * @param ctx the owner, handed to entry
 * @param entry the owner's entry view
 * @param position the entry's position, below count
 * @param count how many entries the owner holds
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the index could not be widened, leaving it as it was
 *         without the entry
 */
int tdb_key_index_put(tdb_key_index_t *ix, const void *ctx, tdb_key_index_entry_fn entry,
                      int position, int count);

/**
 * tdb_key_index_rebuild
 * index the owner's first count entries afresh, at a width sized for them, reusing the slots when
 * they already suffice -- so an owner that discarded a tail can rebuild without an allocation that
 * could fail
 * @param ix the index
 * @param ctx the owner, handed to entry
 * @param entry the owner's entry view
 * @param count how many entries the owner holds
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when wider slots were needed and could not be allocated,
 *         leaving the index as it was
 */
int tdb_key_index_rebuild(tdb_key_index_t *ix, const void *ctx, tdb_key_index_entry_fn entry,
                          int count);

/**
 * tdb_key_index_clear
 * forget every position and release the slots, as an owner that dropped all its entries does
 * @param ix the index
 */
void tdb_key_index_clear(tdb_key_index_t *ix);

/**
 * tdb_key_index_bytes
 * the heap the slots occupy, for an owner's memory gauge
 * @param ix the index
 * @return bytes held
 */
size_t tdb_key_index_bytes(const tdb_key_index_t *ix);

#endif /* __TIDESDB_TXN_KEY_INDEX_H__ */
