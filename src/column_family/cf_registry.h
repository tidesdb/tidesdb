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
 * cf_registry_rename_locked
 * change a registered column family's name, re-indexing it since the name is the lookup key, with
 * the registry write lock already held by the caller -- a rename has more to do under that lock
 * than change the name, so it takes it once around the whole operation
 * @param reg the registry
 * @param cf the column family to rename, already in the registry
 * @param new_name the new name, shorter than TDB_MAX_CF_NAME_LEN
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_EXISTS when new_name is taken
 */
int cf_registry_rename_locked(cf_registry_t *reg, cf_t *cf, const char *new_name);

/**
 * cf_registry_next_cf_id
 * allocate the next monotonic cf id
 * @param reg the registry
 * @return the id, or 0 when reg is NULL
 */
uint64_t cf_registry_next_cf_id(cf_registry_t *reg);

/**
 * cf_registry_rdlock
 * take the read lock so a caller can scan the registry consistently; no cf can be added or removed
 * while it is held
 * @param reg the registry
 */
void cf_registry_rdlock(cf_registry_t *reg);

/**
 * cf_registry_rdunlock
 * release the read lock
 * @param reg the registry
 */
void cf_registry_rdunlock(cf_registry_t *reg);

/**
 * cf_registry_wrlock
 * take the write lock so a caller can mutate a registered cf's structure -- the same lock the
 * reaper and query paths hold for read, so a structural change like reloading a cf's level set
 * excludes them
 * @param reg the registry
 */
void cf_registry_wrlock(cf_registry_t *reg);

/**
 * cf_registry_wrunlock
 * release the write lock
 * @param reg the registry
 */
void cf_registry_wrunlock(cf_registry_t *reg);

/**
 * cf_registry_count_locked
 * the number of registered column families; the caller must hold the read lock
 * @param reg the registry
 * @return the count, or 0 when reg is NULL
 */
int cf_registry_count_locked(const cf_registry_t *reg);

/**
 * cf_registry_at_locked
 * the column family at an index; the caller must hold the read lock
 * @param reg the registry
 * @param index 0-based index
 * @return the column family, or NULL when the index is out of range
 */
cf_t *cf_registry_at_locked(const cf_registry_t *reg, int index);

#endif /* __TIDESDB_CF_REGISTRY_H__ */
