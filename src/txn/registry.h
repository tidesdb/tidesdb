/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_REGISTRY_H__
#define __TIDESDB_TXN_REGISTRY_H__

#include "../compat.h"

/* the set of live transactions at read committed and stronger. two consumers depend on it: the
 * reclamation floor (the smallest sequence any live transaction still reads at, below which a
 * superseded version may be dropped -- a frozen snapshot at repeatable read and stronger, the
 * ceiling of the read in flight at read committed) and the statistics, which enumerate the live
 * set. a transaction joins on begin and leaves when it commits, aborts, or frees. the registry
 * stores borrowed transaction pointers; it never owns or frees them. */

typedef struct tdb_txn tdb_txn_t; /* opaque; the full type is in txn.h */
typedef struct tidesdb_txn_registry tidesdb_txn_registry_t;

/**
 * tidesdb_txn_registry_create
 * create an empty registry
 * @return the registry, or NULL on allocation failure
 */
tidesdb_txn_registry_t *tidesdb_txn_registry_create(void);

/**
 * tidesdb_txn_registry_destroy
 * free the registry; it does not free the transactions it referenced
 * @param reg the registry, may be NULL
 */
void tidesdb_txn_registry_destroy(tidesdb_txn_registry_t *reg);

/**
 * tidesdb_txn_registry_add
 * register a live transaction
 * @param reg the registry
 * @param txn the transaction to add (borrowed)
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS / TDB_ERR_MEMORY
 */
int tidesdb_txn_registry_add(tidesdb_txn_registry_t *reg, tdb_txn_t *txn);

/**
 * tidesdb_txn_registry_remove
 * remove a transaction; a no-op if it was never added
 * @param reg the registry
 * @param txn the transaction to remove
 */
void tidesdb_txn_registry_remove(tidesdb_txn_registry_t *reg, tdb_txn_t *txn);

/**
 * tidesdb_txn_registry_min_snapshot
 * the smallest frozen snapshot among live transactions at repeatable read and stronger. the part of
 * the reclamation floor that stands still between ticks, which is what a plan can be memoized
 * against; a collection about to run takes tidesdb_txn_registry_take_floor instead
 * @param reg the registry
 * @return the minimum snapshot, or UINT64_MAX if none is frozen or reg is NULL
 */
uint64_t tidesdb_txn_registry_min_snapshot(tidesdb_txn_registry_t *reg);

/**
 * tidesdb_txn_registry_take_floor
 * the reclamation floor for a collection about to run: the smallest sequence any live transaction
 * still reads at, frozen snapshots and the ceilings of read committed reads in flight alike, and
 * never above the watermark, since nothing a collection reads is above it. the floor is published
 * as the high-water mark and the ceilings are scanned again behind a full barrier, so a read that
 * published its ceiling as the first scan ran is either seen by the second or sees the mark and
 * takes its ceiling again above it. raised where the floor is taken rather than where the work
 * finishes, so a job already collecting is accounted for before a reader concludes a sequence is
 * safe
 * @param reg the registry
 * @param watermark the clock's watermark, the highest sequence a collection can meet
 * @return the floor to retain against, at most watermark
 */
uint64_t tidesdb_txn_registry_take_floor(tidesdb_txn_registry_t *reg, uint64_t watermark);

/**
 * tidesdb_txn_registry_floor_high_water
 * the highest floor any collection has taken; nothing at or above it has ever been collectable, so
 * a read there resolves to exactly what was true, and below it a merge has already kept one version
 * per key
 * @param reg the registry
 * @return the high-water mark, or 0 when reg is NULL
 */
uint64_t tidesdb_txn_registry_floor_high_water(const tidesdb_txn_registry_t *reg);

/**
 * tidesdb_txn_registry_raise_floor_high_water
 * raise the high-water mark to a sequence, never lowering it; recovery raises it to the sequence it
 * resumed from, since nothing before an open is reconstructable
 * @param reg the registry
 * @param seq the sequence to raise it to
 */
void tidesdb_txn_registry_raise_floor_high_water(tidesdb_txn_registry_t *reg, uint64_t seq);

/**
 * tidesdb_txn_visit_fn
 * called for each live transaction during a walk
 * @param txn the live transaction (borrowed, valid only for the call)
 * @param ctx the caller's context
 * @return 0 to continue the walk, non-zero to stop it early
 */
typedef int (*tidesdb_txn_visit_fn)(tdb_txn_t *txn, void *ctx);

/**
 * tidesdb_txn_registry_for_each
 * walk every live transaction with the whole registry held, so the visitor sees one instant of the
 * live set rather than a view that shifts underneath it. that consistency is what serializable
 * commit validation depends on, since it decides against the set of concurrent peers. the visitor
 * runs with locks held, so it must not add to or remove from the registry, and must not block
 * @param reg the registry
 * @param visit called per transaction; returning non-zero stops the walk
 * @param ctx passed through to visit
 * @return non-zero if the walk was stopped early, 0 if it ran to completion
 */
int tidesdb_txn_registry_for_each(tidesdb_txn_registry_t *reg, tidesdb_txn_visit_fn visit,
                                  void *ctx);

#endif /* __TIDESDB_TXN_REGISTRY_H__ */
