/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_CF_REGISTRY_H__
#define __TIDESDB_CF_REGISTRY_H__

#include "column_family.h"

/* the engine's set of live column families, keyed by both name and cf id, guarded by an rwlock so
 * reads scale while the rare create/drop serializes. unlike the txn registry it OWNS the column
 * families it holds -- add takes ownership, destroy frees each with cf_free, and remove detaches
 * one for the caller to tear down. it also allocates cf ids from a monotonic counter seeded on
 * recovery. the sstable-id counter is a separate db-level sequence the engine owns, not a registry
 * concern. */

typedef struct cf_registry cf_registry_t;

/* one published, immutable snapshot of the registry's membership; borrowed by readers and handed
 * back by name so the borrow can be counted on the snapshot itself */
typedef struct cf_registry_view cf_registry_view_t;

/**
 * cf_registry_create
 * create an empty registry whose next allocated cf id is next_cf_id
 * @param next_cf_id the first id cf_registry_next_cf_id hands out, seeded on recovery to max(id)+1
 * @return the registry, or NULL on allocation failure
 */
cf_registry_t *cf_registry_create(uint64_t next_cf_id);

/**
 * cf_registry_destroy
 * free the registry and every column family it holds via cf_free; the caller must have already
 * stopped all workers and readers so no cf is still in use
 * @param reg the registry, may be NULL
 */
void cf_registry_destroy(cf_registry_t *reg);

/**
 * cf_registry_add
 * register a column family, taking ownership of it; rejects a name or cf id already present
 * @param reg the registry
 * @param cf the column family to add, owned by the registry on success
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_EXISTS on a duplicate name or id, or
 *         TDB_ERR_MEMORY
 */
int cf_registry_add(cf_registry_t *reg, cf_t *cf);

/**
 * cf_registry_get_by_name
 * look up a column family by name; the returned pointer is borrowed and valid until the cf is
 * dropped
 * @param reg the registry
 * @param name the cf name
 * @return the column family, or NULL when no cf has that name
 */
cf_t *cf_registry_get_by_name(cf_registry_t *reg, const char *name);

/**
 * cf_registry_get_by_id
 * look up a column family by cf id; the returned pointer is borrowed and valid until the cf is
 * dropped
 * @param reg the registry
 * @param cf_id the cf id
 * @return the column family, or NULL when no cf has that id
 */
cf_t *cf_registry_get_by_id(cf_registry_t *reg, uint64_t cf_id);

/**
 * cf_registry_remove
 * detach a column family by name; the caller takes ownership and must quiesce and cf_free it, or
 * when out is NULL the registry frees it directly
 * @param reg the registry
 * @param name the cf name
 * @param out out -- receives the detached cf when non-NULL (caller frees), else it is freed here
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_NOT_FOUND when no cf has that name
 */
int cf_registry_remove(cf_registry_t *reg, const char *name, cf_t **out);

/**
 * cf_registry_rename
 * give a family a new name, published so no reader can copy a torn one
 *
 * the caller must hold the family's compaction claim, which is what covers the readers that copy
 * the name outside a view borrow
 * @param reg the registry
 * @param cf the family
 * @param new_name the name to carry
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int cf_registry_rename(cf_registry_t *reg, cf_t *cf, const char *new_name);

/**
 * cf_registry_next_cf_id
 * allocate the next monotonic cf id
 * @param reg the registry
 * @return the id, or 0 when reg is NULL
 */
uint64_t cf_registry_next_cf_id(cf_registry_t *reg);

/**
 * cf_registry_lock
 * take the registry exclusively so a caller can change what it holds, or change a registered
 * family's structure
 *
 * only the membership changes take this -- create, drop, rename, clone. the readers are all on the
 * published view, so a caller holding this excludes the other writers and nothing else
 * @param reg the registry
 */
void cf_registry_lock(cf_registry_t *reg);

/**
 * cf_registry_unlock
 * release the registry
 * @param reg the registry
 */
void cf_registry_unlock(cf_registry_t *reg);

/**
 * cf_registry_view_enter
 * borrow the published family list without taking the read lock, guarded by the view epoch
 *
 * the background work that reads this list -- every flush build and install, every compaction
 * claim -- arrives continuously under load, and taking the read lock for it is what leaves a create
 * or a drop waiting on a stream that never breaks. a scheduler that does not hand the writer its
 * turn promptly turns that wait into a stall of minutes, so the readers stay off the lock entirely
 * and the writers contend only with each other.
 *
 * the returned array belongs to the view and stays valid until cf_registry_view_leave, which every
 * caller must reach on every path
 * @param reg the registry
 * @param out_cfs receives the borrowed family array, valid until the matching leave
 * @param out_count receives how many families it holds, zero when there are none
 * @return the borrowed view, to be handed back to cf_registry_view_leave; NULL when there is none
 */
cf_registry_view_t *cf_registry_view_enter(cf_registry_t *reg, cf_t ***out_cfs, int *out_count);

/**
 * cf_registry_view_leave
 * give back the borrow taken by cf_registry_view_enter
 * @param reg the registry
 * @param view the view that enter returned, may be NULL
 */
void cf_registry_view_leave(cf_registry_t *reg, cf_registry_view_t *view);

/**
 * cf_registry_wait_readers_drained
 * wait until no borrow of the published view is outstanding
 *
 * a family removed from the registry is still named by a view a reader borrowed before the removal
 * was published, so the handle cannot be freed until those readers have gone. the wait is on that
 * displaced view alone, whose borrows can only fall once a newer one is published -- waiting for no
 * reader at all would never come back under work that reads continuously
 * @param reg the registry
 * @param view the displaced view to wait out
 */
void cf_registry_wait_readers_drained(cf_registry_t *reg, cf_registry_view_t *view);

#endif /* __TIDESDB_CF_REGISTRY_H__ */
