/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_COLUMN_FAMILY_H__
#define __TIDESDB_COLUMN_FAMILY_H__

#include "base/lockfree.h"           /* epoch guard and retire list for the published config */
#include "cache/cache.h"             /* the db-global block cache, borrowed */
#include "column_family/cf_config.h" /* validate/serialize the persisted config */
#include "column_family/level/level_set.h"   /* the tiered sstable structure */
#include "fdmanager/fdmanager.h"             /* the db-global descriptor budget, borrowed */
#include "manifest/manifest.h"               /* db-level manifest, registry and entries */
#include "range_tombstone/range_tombstone.h" /* the family's range tombstones, below L0 */
#include "sstable/vlog.h"                    /* the db-global value log, borrowed */

/* column_family composes one runtime column family from the smaller modules -- a validated config
 * and the tiered level_set of its sstables. it owns the level_set and borrows the db-global
 * services it does not close, the manifest (identity and entry enumeration), the single value log
 * every family's sstables spill into, the block cache its sstables read through, and the descriptor
 * budget guarding klog reopens. it holds no engine handle, so it is unit-testable with a stack
 * config, a temp directory and the standalone services. keys are ordered byte-wise everywhere, so
 * no config field affects which sstables may merge. */

/* upper bound on the directory path a family's files are resolved against, which is the database
 * directory itself; sized for the longest name plus a generous db directory prefix */
#define CF_DIR_PATH_LEN (TDB_MAX_CF_NAME_LEN + 1024)

/* the shape of the name a family recovered from its key logs alone is given, when the manifest
 * record that carried its real name was lost. its immutable id is the only name left, so the id
 * becomes the name, zero-padded so a listing sorts in creation order. families have no directory of
 * their own -- every key log sits in the database directory and carries its family's id in its own
 * file name */
#define CF_DIR_PREFIX    "cf_"
#define CF_DIR_ID_DIGITS 10

/**
 * cf_t
 * a runtime column family, composing its config and tiered sstables over a borrowed db-global vlog
 * @param cf_id stable id from the manifest registry, the key every manifest entry references
 * @param name column family name, NUL-terminated
 * @param config the validated, persisted configuration, published as an immutable snapshot. a
 *               runtime reconfigure swaps a whole new one in rather than writing through this one,
 *               so a reader that took it sees one coherent configuration for as long as it holds it
 *               -- read it with cf_config_get rather than reaching through this pointer
 * @param name the family's name, published so a rename cannot tear one a reader is copying
 * @param config_epoch guards a published config against reclaim while a reader is copying it
 * @param config_retire configs displaced by a reconfigure, freed once no reader can hold them
 * @param dir the directory this family's klogs are resolved against, which is the database
 * directory itself -- families have no directory of their own, and a klog carries its family's id
 * in its file name instead
 * @param vlog the db-global value log, borrowed by this family's sstable builders and reads, not
 * owned
 * @param cache the db-global block cache this family's sstables read through, borrowed, not owned
 * @param now the db-wide clock the family's sstables read the current second from, borrowed
 * @param arena_pool the db-global chunk pool a decoded btree node's arena draws from, borrowed, not
 *                   owned, or NULL to allocate directly
 * @param fdm the db-global descriptor budget guarding this family's klog reopens, borrowed, not
 * owned
 * @param encodings the db-global encoding registry, borrowed; the family's pipeline ids mean
 *                  nothing without it, so every builder and reader it creates carries it through
 * @param levels the tiered set of sstables (L1 overlapping, L2+ sorted)
 * @param compacting set while a compaction for this family is planned or running, so the scheduler
 *                   runs at most one compaction per family at a time and a drop waits it out
 * @param planned_generation the level-set generation the backstop scheduler last planned this
 *                           family at, so a tick can skip a family whose shape has not moved. only
 *                           the holder of the compaction claim reads or writes it, which is what
 *                           makes a plain field safe here
 * @param planned_gc_floor the reclamation floor that plan was made against. a merge's value depends
 * on it as much as on the shape -- when transactions drain, the floor rises and versions the same
 * layout could not drop become droppable -- so a floor that has moved is reason to plan again even
 * though nothing was written
 * @param user_bytes_written logical key+value bytes committed to this family, for stats
 * @param wal_bytes_written write-ahead-log bytes this family's commits contributed, for stats
 * @param flush_bytes_written on-disk bytes this family's flushes wrote, for stats
 * @param flush_count sstables this family's flushes produced, for stats
 * @param compaction_bytes_written on-disk bytes this family's compactions wrote, for stats
 * @param compaction_bytes_read on-disk bytes this family's compactions read as input, for stats
 * @param compaction_count compactions this family has run, for stats
 * @param commit_hook_fn the live post-commit callback, set at runtime, NULL when none; read on the
 *                       commit path and swapped by the setter, so it is atomic
 * @param commit_hook_ctx the user context passed to commit_hook_fn, atomic for the same reason
 * @param unflushed_key_count distinct keys resident in the shared memtables for this family and not
 *                            yet in any sstable, raised by the l0 as new keys land and lowered by
 *                            flush as they drain to L1, for stats
 */
typedef struct cf
{
    uint64_t cf_id;
    /* published rather than written in place. a rename rewrites it while a flush may be reading it
     * to stamp onto an sstable, where it is the first component of a block cache key, so the name a
     * reader holds has to stay whole -- it is replaced by publishing another and freeing the old
     * once no reader can still be on it */
    _Atomic(char *) name;
    _Atomic(tidesdb_column_family_config_t *) config;
    tdb_epoch_t config_epoch;
    tdb_retire_list_t config_retire;
    char dir[CF_DIR_PATH_LEN];
    vlog_t *vlog;
    cache_t *cache;
    arena_pool_t *arena_pool;
    _Atomic(int64_t) *now;
    fd_manager_t *fdm;
    const tidesdb_encoding_registry_t *encodings;
    level_set_t *levels;
    _Atomic(int) compacting;
    uint64_t planned_generation;
    uint64_t planned_gc_floor;
    _Atomic(uint64_t) user_bytes_written;
    _Atomic(uint64_t) wal_bytes_written;
    _Atomic(uint64_t) flush_bytes_written;
    _Atomic(uint64_t) flush_count;
    _Atomic(uint64_t) compaction_bytes_written;
    _Atomic(uint64_t) compaction_bytes_read;
    _Atomic(uint64_t) compaction_count;
    _Atomic(tidesdb_commit_hook_fn) commit_hook_fn;
    _Atomic(void *) commit_hook_ctx;
    _Atomic(int64_t) unflushed_key_count;
} cf_t;

/**
 * cf_create
 * create a fresh column family -- validate the config, build an empty level set, and adopt the
 * borrowed db-global value log. no directory is created; the family's klogs live in the database
 * directory. the caller registers cf_id and the name in the manifest.
 * @param db_dir the database directory this family's klogs are resolved against
 * @param cf_id the stable id assigned to this family
 * @param config the configuration to validate and adopt
 * @param reg encoding registry to validate the pipeline against, or NULL to skip that check
 * @param vlog the db-global value log to borrow, or NULL if this family never spills values
 * @param cache the db-global block cache to borrow, or NULL to read uncached
 * @param fdm the db-global descriptor budget to borrow, or NULL to open klogs without a budget
 * @param arena_pool the db-global chunk pool to borrow for decoded nodes, or NULL to allocate
 *                   directly
 * @param now borrowed db-wide clock the ticker publishes the current second to, handed to every
 * sstable the family opens or builds so they age entries against the same second, or NULL
 * @param out out -- the new column family on success, owned by the caller (freed by cf_free)
 * @return 0 on success, -1 on a bad argument, an invalid config, an io or allocation failure
 */
/**
 * cf_name_publish
 * publish name as this family's, retiring whatever it carried before
 *
 * a rename cannot write the field in place -- a flush stamping the name onto an sstable would copy
 * it mid-write, and that name is the first component of a block cache key. the replacement is
 * published instead, and the old one retired behind the guard a config change already uses
 * @param cf the family
 * @param name the name to carry
 * @param out_old receives the displaced name to free, or NULL when there was none
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY
 */
int cf_name_publish(cf_t *cf, const char *name, char **out_old);

int cf_create(const char *db_dir, uint64_t cf_id, const tidesdb_column_family_config_t *config,
              const tidesdb_encoding_registry_t *reg, vlog_t *vlog, cache_t *cache,
              fd_manager_t *fdm, arena_pool_t *arena_pool, _Atomic(int64_t) *now, cf_t **out);

/**
 * cf_open
 * open an existing column family -- decode its persisted config blob, adopt the borrowed db-global
 * value log, and rebuild the level set by opening every manifest sstable entry for cf_id at its
 * level.
 * @param db_dir the database directory the family directory lives under
 * @param manifest the db-level manifest to enumerate this family's entries from
 * @param cf_id the family to open
 * @param name the family name
 * @param config_blob the serialized config produced by cf_config_serialize
 * @param blob_len length of config_blob in bytes
 * @param reg encoding registry the decoded pipeline is validated and resolved against, or NULL to
 *            skip that check
 * @param vlog the db-global value log to borrow, or NULL if this family never spills values
 * @param cache the db-global block cache to borrow, or NULL to read uncached
 * @param fdm the db-global descriptor budget to borrow, or NULL to open klogs without a budget
 * @param sync_mode block-manager sync mode for reopening klogs
 * @param arena_pool the db-global chunk pool to borrow for decoded nodes, or NULL to allocate
 *                   directly
 * @param now borrowed db-wide clock the ticker publishes the current second to, handed to every
 * sstable the family opens or builds so they age entries against the same second, or NULL
 * @param out out -- the opened column family on success, owned by the caller (freed by cf_free)
 * @return 0 on success, -1 on a bad argument, a bad blob, an io or allocation failure
 */
int cf_open(const char *db_dir, tidesdb_manifest_t *manifest, uint64_t cf_id, const char *name,
            const uint8_t *config_blob, size_t blob_len, const tidesdb_encoding_registry_t *reg,
            vlog_t *vlog, cache_t *cache, fd_manager_t *fdm, int sync_mode,
            arena_pool_t *arena_pool, _Atomic(int64_t) *now, cf_t **out);

/**
 * cf_reload_levels
 * rebuild the level set by reopening every manifest sstable entry for this family from its current
 * dir and name, replacing the old level set only when the rebuild succeeds. a clone uses this to
 * adopt the sstables copied into the destination family, whose manifest rows exist before any
 * handle for them does. requires the family quiesced against planners and the fd reaper
 * @param cf the column family, its dir and name already set to the target
 * @param manifest the db-level manifest to enumerate this family's entries from
 * @param sync_mode block-manager sync mode for reopening klogs
 * @return 0 on success (old level set freed), -1 on failure (old level set retained)
 */
int cf_reload_levels(cf_t *cf, tidesdb_manifest_t *manifest, int sync_mode);

/**
 * cf_range_tombstone_covering
 * the newest sequence at or below the snapshot whose tombstone covers the key -- what a read of the
 * family's sstables compares against the newest version it found there. a family that has never
 * taken a range delete answers from one load and never reaches the lock
 * @param cf the column family
 * @param key the key to test
 * @param key_size length of key in bytes
 * @param snapshot the reader's ceiling, inclusive
 * @param out_seq receives the covering sequence when the call returns 1
 * @return 1 when a tombstone at or below the snapshot covers the key, 0 otherwise
 */
int cf_range_tombstone_covering(cf_t *cf, const uint8_t *key, size_t key_size, uint64_t snapshot,
                                uint64_t *out_seq);

/**
 * cf_free
 * free a column family, freeing its level set; the borrowed manifest and db-global value log are
 * left untouched. safe on NULL.
 * @param cf the column family to free
 */
void cf_free(cf_t *cf);

/**
 * cf_config_get
 * copy the family's current configuration out. the published configuration is immutable once it is
 * visible, so the copy is one coherent configuration rather than a field-by-field read that a
 * concurrent reconfigure could split across two of them
 * the family is const to a caller reading its configuration; the epoch this brackets the read with
 * is bookkeeping rather than part of that state, which is why a const family can still be read
 * @param cf the column family
 * @param out out -- the configuration, copied
 */
void cf_config_get(const cf_t *cf, tidesdb_column_family_config_t *out);

/**
 * cf_config_publish
 * install a new configuration for the family, displacing the current one. the previous
 * configuration is retired rather than freed, since a reader may still be copying it
 * @param cf the column family
 * @param config the configuration to publish, copied
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the snapshot could not be allocated
 */
int cf_config_publish(cf_t *cf, const tidesdb_column_family_config_t *config);

/**
 * cf_config_default_isolation
 * the family's configured default isolation level. a transaction begin reads only this one field,
 * so it takes it directly rather than paying for a copy of the whole configuration
 * @param cf the column family
 * @return the configured default isolation level
 */
tidesdb_isolation_level_t cf_config_default_isolation(cf_t *cf);

#endif /* __TIDESDB_COLUMN_FAMILY_H__ */
