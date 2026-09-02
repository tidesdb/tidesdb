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
 * cf_registry_retire_cf
 * free a removed family once no live view can still name it
 *
 * a family taken out of the published view is unreachable to anything arriving afterwards, but a
 * view published before the removal still names it, and a flush holds one of those by reference
 * count for as long as its I/O takes. freeing the handle under that is a use after free, and
 * waiting for those views to die is the stall this registry is built to avoid, so the free is
 * queued and taken by whichever view dies last -- or by cf_registry_sweep, if that view had already
 * died
 * @param reg the registry
 * @param cf the removed family, whose handle the caller is giving up
 * @param reclaim what frees it, invoked with cf once it is unreachable
 */
/**
 * cf_registry_retire_obj
 * free something a family owned once no live view can name that family
 *
 * the same rule cf_registry_retire_cf applies, for a part of a family rather than the whole handle.
 * a clone replaces its destination's level set, and the compaction scheduler reads every published
 * family's overlap depth off that set while holding only a view borrow -- so the set a swap
 * displaces has to outlive the borrows that could still reach it
 * @param reg the registry
 * @param item the displaced object, whose ownership the caller is giving up
 * @param reclaim what frees it, invoked with item once it is unreachable
 */
void cf_registry_retire_obj(cf_registry_t *reg, void *item, tdb_reclaim_fn reclaim);

void cf_registry_retire_cf(cf_registry_t *reg, cf_t *cf, tdb_reclaim_fn reclaim);

/**
 * cf_registry_sweep
 * reclaim whatever the registry deferred and can now free; a periodic background pass
 * @param reg the registry
 */
void cf_registry_sweep(cf_registry_t *reg);

#endif /* __TIDESDB_CF_REGISTRY_H__ */
