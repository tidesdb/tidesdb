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

/* the set of live transactions at repeatable-read and stronger. two consumers depend on it: the
 * compaction gc floor (the smallest snapshot any live transaction still reads at, below which a
 * superseded version may be dropped) and serializable-snapshot-isolation, whose commit scans the
 * concurrent serializable peers for dangerous read-write dependency structures. a transaction joins
 * on begin and leaves when it commits, aborts, or frees. the registry stores borrowed transaction
 * pointers; it never owns or frees them. */

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
 * the smallest snapshot sequence among live transactions -- the compaction gc floor
 * @param reg the registry
 * @return the minimum snapshot, or UINT64_MAX if the registry is empty or NULL
 */
uint64_t tidesdb_txn_registry_min_snapshot(tidesdb_txn_registry_t *reg);

/**
 * tidesdb_txn_registry_publish_min_snapshot
 * run the scan once and publish its answer for readers that cannot afford to run it themselves.
 * an empty registry publishes zero rather than the UINT64_MAX sentinel the scan returns, so a
 * transaction beginning afterwards can never hold a snapshot below what was published
 * @param reg the registry
 */
void tidesdb_txn_registry_publish_min_snapshot(tidesdb_txn_registry_t *reg);

/**
 * tidesdb_txn_registry_published_min_snapshot
 * the last published minimum, as one relaxed load rather than a scan of every shard. the answer is
 * only ever stale low, never high -- a snapshot is drawn from a monotonic clock, so a transaction
 * beginning after a publish holds one at or above it, and one leaving only raises the true minimum
 * -- which is the direction a conservative reader needs
 * @param reg the registry
 * @return the last published minimum, or 0 when none has been published or reg is NULL
 */
uint64_t tidesdb_txn_registry_published_min_snapshot(const tidesdb_txn_registry_t *reg);

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
