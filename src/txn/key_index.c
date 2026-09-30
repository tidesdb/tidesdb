/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "key_index.h"

#include <stdlib.h>
#include <string.h>

#include "db.h"           /* TDB_SUCCESS / TDB_ERR_* result codes */
#include "txn_internal.h" /* txn_key_hash, the one hash the claims, the dedup and this share */

/* the fewest slots an index is built with, and the width it is held at relative to the positions
 * it holds -- at least twice as many slots as positions, so a probe walks a short run and always
 * finds an empty slot to stop at */
#define TDB_KEY_INDEX_MIN_SLOTS 64
#define TDB_KEY_INDEX_LOAD      2

void tdb_key_index_init(tdb_key_index_t *ix)
{
    if (!ix) return;
    ix->slots = NULL;
    ix->mask = 0;
    ix->occupied = 0;
}

void tdb_key_index_free(tdb_key_index_t *ix)
{
    if (!ix) return;
    free(ix->slots);
    tdb_key_index_init(ix);
}

void tdb_key_index_clear(tdb_key_index_t *ix)
{
    tdb_key_index_free(ix);
}

size_t tdb_key_index_bytes(const tdb_key_index_t *ix)
{
    return ix && ix->slots ? ((size_t)ix->mask + 1) * sizeof(*ix->slots) : 0;
}

/* whether the entry at a position is keyed by this family and key */
static int key_index_entry_is(const void *ctx, const tdb_key_index_entry_fn entry,
                              const int position, const uint32_t cf_index, const uint8_t *key,
                              const size_t key_size)
{
    uint32_t held_cf = 0;
    const uint8_t *held_key = NULL;
    size_t held_size = 0;
    return entry(ctx, position, &held_cf, &held_key, &held_size) && held_cf == cf_index &&
           held_size == key_size && memcmp(held_key, key, key_size) == 0;
}

/**
 * key_index_probe
 * walk a key's run to the slot that holds its position or to the empty slot the run ends in
 * @param ix the index, whose slots exist
 * @param ctx the owner, handed to entry
 * @param entry the owner's entry view
 * @param cf_index the family
 * @param key the key bytes
 * @param key_size length of key
 * @param at receives the slot the probe stopped at
 * @return 1 when the slot holds the key, 0 when it is empty, -1 when the run never ended, which
 *         the load factor rules out
 */
static int key_index_probe(const tdb_key_index_t *ix, const void *ctx,
                           const tdb_key_index_entry_fn entry, const uint32_t cf_index,
                           const uint8_t *key, const size_t key_size, uint32_t *at)
{
    uint32_t i = (uint32_t)txn_key_hash(cf_index, key, key_size) & ix->mask;
    for (uint32_t probes = 0; probes <= ix->mask; probes++)
    {
        const int held = ix->slots[i];
        *at = i;
        if (held == 0) return 0;
        if (key_index_entry_is(ctx, entry, held - 1, cf_index, key, key_size)) return 1;
        i = (i + 1) & ix->mask;
    }
    return -1;
}

int tdb_key_index_find(const tdb_key_index_t *ix, const void *ctx,
                       const tdb_key_index_entry_fn entry, const uint32_t cf_index,
                       const uint8_t *key, const size_t key_size)
{
    if (!ix || !ix->slots || !ctx || !entry || !key) return -1;
    uint32_t at = 0;
    if (key_index_probe(ix, ctx, entry, cf_index, key, key_size, &at) != 1) return -1;
    return ix->slots[at] - 1;
}

/* record one position in an index with room for it; a key already held takes the new position */
static int key_index_note(tdb_key_index_t *ix, const void *ctx, const tdb_key_index_entry_fn entry,
                          const int position)
{
    uint32_t cf_index = 0;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    if (!entry(ctx, position, &cf_index, &key, &key_size)) return TDB_SUCCESS;
    uint32_t at = 0;
    const int found = key_index_probe(ix, ctx, entry, cf_index, key, key_size, &at);
    if (found < 0) return TDB_ERR_MEMORY;
    if (found == 0) ix->occupied++;
    ix->slots[at] = position + 1;
    return TDB_SUCCESS;
}

/* the slot count an index over n positions is built with */
static uint32_t key_index_slots_for(const int n)
{
    uint32_t slots = TDB_KEY_INDEX_MIN_SLOTS;
    while (slots < (uint32_t)n * TDB_KEY_INDEX_LOAD) slots *= 2;
    return slots;
}

int tdb_key_index_rebuild(tdb_key_index_t *ix, const void *ctx, const tdb_key_index_entry_fn entry,
                          const int count)
{
    if (!ix || !ctx || !entry || count < 0) return TDB_ERR_INVALID_ARGS;
    const uint32_t needed = key_index_slots_for(count);
    if (!ix->slots || ix->mask + 1 < needed)
    {
        int *fresh = calloc(needed, sizeof(*fresh));
        if (!fresh) return TDB_ERR_MEMORY;
        free(ix->slots);
        ix->slots = fresh;
        ix->mask = needed - 1;
    }
    else
        memset(ix->slots, 0, ((size_t)ix->mask + 1) * sizeof(*ix->slots));
    ix->occupied = 0;
    for (int i = 0; i < count; i++)
        if (key_index_note(ix, ctx, entry, i) != TDB_SUCCESS) return TDB_ERR_MEMORY;
    return TDB_SUCCESS;
}

int tdb_key_index_put(tdb_key_index_t *ix, const void *ctx, const tdb_key_index_entry_fn entry,
                      const int position, const int count)
{
    if (!ix || !ctx || !entry || position < 0 || position >= count) return TDB_ERR_INVALID_ARGS;
    /* widened before the probe would run long, by a rebuild that indexes this position with the
     * rest */
    if (!ix->slots || (uint32_t)(ix->occupied + 1) * TDB_KEY_INDEX_LOAD > ix->mask + 1)
        return tdb_key_index_rebuild(ix, ctx, entry, count);
    return key_index_note(ix, ctx, entry, position);
}
