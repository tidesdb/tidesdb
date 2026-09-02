/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_ENGINE_H__
#define __TIDESDB_ENGINE_H__

/* the engine api. the state it operates on -- tidesdb_t and the public handle types --
 * lives in engine_types.h, which this header carries for every includer */
#include "engine/engine_types.h"

/**
 * engine_open
 * assemble a database from a fully resolved config: create the leaf singletons, open the manifest
 * and value log, seed the mvcc clock, and create the empty cf registry and worker registry. the
 * config is expected already validated and defaulted by the facade
 * @param config the resolved configuration, borrowed (db_path is copied)
 * @param out out -- the open engine on success, owned by the caller (freed by engine_close)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int engine_open(const tidesdb_config_t *config, tidesdb_t **out);

/**
 * engine_close
 * tear down an engine in dependency order -- stop the workers, free the cfs, the clock, the value
 * log, the manifest, and the leaf singletons -- and free the handle; safe on a partially built
 * engine and on NULL
 * @param db the engine, may be NULL
 */
void engine_close(tidesdb_t *db);

/**
 * engine_create_cf
 * create a column family, persist it in the manifest with its serialized config blob, and register
 * it; fails if a cf with the name already exists
 * @param db the engine
 * @param name the cf name, non-empty
 * @param config the cf configuration, borrowed
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_EXISTS, TDB_ERR_IO, or TDB_ERR_MEMORY
 */
int engine_create_cf(tidesdb_t *db, const char *name, const tidesdb_column_family_config_t *config);

/**
 * engine_drop_cf
 * drop a column family by name -- detach it from the registry, drop its manifest records, close it,
 * and delete its on-disk directory
 * @param db the engine
 * @param name the cf name
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, or TDB_ERR_IO
 */
int engine_drop_cf(tidesdb_t *db, const char *name);

/**
 * engine_get_cf
 * look up a live column family by name; the returned pointer is borrowed and valid until the cf is
 * dropped
 * @param db the engine
 * @param name the cf name
 * @return the column family, or NULL when no cf has that name
 */
cf_t *engine_get_cf(tidesdb_t *db, const char *name);

/**
 * engine_list_column_families
 * collect the names of every live column family into a freshly allocated array the caller frees
 * @param db the engine
 * @param out_names out -- a newly allocated array of newly allocated names, each freed by the
 * caller along with the array; NULL when there are none
 * @param out_count out -- the number of names
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_list_column_families(tidesdb_t *db, char ***out_names, int *out_count);

/**
 * engine_cf_update_runtime_config
 * replace a column family's configuration at runtime, preserving its name and id, and optionally
 * persist the new config to the manifest; the family is briefly claimed so the compaction scheduler
 * cannot read a half-replaced config
 * @param db the engine
 * @param cf the column family
 * @param new_config the configuration to validate and adopt, borrowed; its name field is ignored
 * @param persist 1 to record the new config in the manifest, 0 to change it in memory only
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED when a compaction is running, or an io
 * or allocation error
 */
int engine_cf_update_runtime_config(tidesdb_t *db, cf_t *cf,
                                    const tidesdb_column_family_config_t *new_config, int persist);

/**
 * engine_cf_set_commit_hook
 * set or clear a column family's post-commit hook at runtime, keeping the db-level gate counter
 * exact so the commit path can skip the hook pass when no family has one
 * @param db the engine
 * @param cf the column family
 * @param fn the hook to invoke after each commit to the cf, or NULL to clear it
 * @param ctx the user context passed to the hook
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_cf_set_commit_hook(tidesdb_t *db, cf_t *cf, tidesdb_commit_hook_fn fn, void *ctx);

/**
 * engine_rename_cf
 * rename a column family: re-index it in the registry and persist the new name to the manifest.
 * nothing on disk moves, since a key log is named for its family's immutable id rather than its
 * name, so there is no flush to drain and no level set to rebuild. the family is claimed for the
 * update so a concurrent ddl or planner pass cannot read the configuration while it is replaced
 * @param db the engine
 * @param old_name the current name
 * @param new_name the new name, shorter than TDB_MAX_CF_NAME_LEN
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, TDB_ERR_EXISTS, TDB_ERR_LOCKED when
 * a compaction holds the family for the whole quiesce wait, or an io or allocation error
 */
int engine_rename_cf(tidesdb_t *db, const char *old_name, const char *new_name);

/**
 * engine_get_cf_stats
 * fill a per-column-family statistics snapshot -- per-level aggregates folded from the live sstable
 * set, the derived averages and read amplification, and the family's cumulative byte counters
 * @param cf the column family
 * @param out out -- the statistics, zeroed then filled
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY under descriptor pressure, or
 * TDB_ERR_MEMORY
 */
int engine_get_cf_stats(cf_t *cf, tidesdb_cf_stats_t *out);

/**
 * engine_cf_estimate_cardinality
 * estimate a column family's distinct key count, the summed per-sstable distinct counts, an upper
 * bound since a key updated across levels is counted once per level it lives at
 * @param cf the column family
 * @param out_estimate out -- the estimated distinct key count
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY under descriptor pressure, or
 * TDB_ERR_MEMORY
 */
int engine_cf_estimate_cardinality(cf_t *cf, uint64_t *out_estimate);

/**
 * engine_get_db_stats
 * fill a database-level statistics snapshot -- the cross-family byte and count sums, the shared
 * memtable, value log, and mvcc clock figures, and the live transaction accounting
 * @param db the engine
 * @param out out -- the statistics, zeroed then filled
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_db_stats(tidesdb_t *db, tidesdb_db_stats_t *out);

/**
 * engine_get_klog_encoding_stats
 * what each encoding chain achieved on the key logs, grouped by the pipeline each table records
 * @param db the engine
 * @param out receives the entries
 * @param max capacity of out
 * @param out_count receives how many were written
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_klog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                   size_t *out_count);

/**
 * engine_get_vlog_encoding_stats
 * what each encoding chain achieved on the separated values
 * @param db the engine
 * @param out receives the entries
 * @param max capacity of out
 * @param out_count receives how many were written
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_vlog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                   size_t *out_count);

/**
 * engine_get_cache_stats
 * fill a block-cache statistics snapshot from the db-global cache, or mark it disabled when the db
 * runs without one
 * @param db the engine
 * @param out out -- the statistics, zeroed then filled
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *out);

/**
 * engine_txn_begin
 * begin a transaction at an isolation level over the db-level clock and source stack
 * @param db the engine
 * @param isolation the isolation level
 * @param out out -- the transaction handle on success, freed by engine_txn_free
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_INVALID_DB when closing, or TDB_ERR_MEMORY
 */
int engine_txn_begin(tidesdb_t *db, tidesdb_isolation_level_t isolation, tidesdb_txn_t **out);

/**
 * engine_snapshot_create
 * take a named snapshot of the database as it stands, and hold the reclamation floor at it. the
 * handle is a registered transaction that never writes and is never committed, which is what keeps
 * compaction from dropping the versions a later read at this sequence needs
 * @param db the engine
 * @param out out -- the snapshot handle on success, released by engine_snapshot_release
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_INVALID_DB when closing, or TDB_ERR_MEMORY
 */
int engine_snapshot_create(tidesdb_t *db, tidesdb_snapshot_t **out);

/**
 * engine_take_gc_floor
 * read the reclamation floor for a collection and record it as the oldest point any collection has
 * run against. raised here, where the floor is taken, rather than where the work completes -- a job
 * already collecting has to be visible to a reader deciding whether its sequence is still safe
 * @param db the engine
 * @return the floor to retain against
 */
uint64_t engine_take_gc_floor(tidesdb_t *db);

/**
 * engine_txn_begin_at_seq
 * begin a transaction reading as of an explicit sequence, refusing when that point in time can no
 * longer be reconstructed
 * @param db the engine
 * @param seq the sequence to read at
 * @param out out -- the transaction handle on success, freed by engine_txn_free
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_INVALID_DB when closing, TDB_ERR_MEMORY, or
 *         TDB_ERR_TOO_OLD when a collection has already run below seq
 */
int engine_txn_begin_at_seq(tidesdb_t *db, uint64_t seq, tidesdb_txn_t **out);

/**
 * engine_oldest_readable_seq
 * the highest reclamation floor any collection has taken, which is the oldest sequence still exact
 * @param db the engine
 * @return the oldest readable sequence, or 0 when db is NULL
 */
uint64_t engine_oldest_readable_seq(const tidesdb_t *db);

/**
 * engine_snapshot_release
 * release a snapshot and the floor it held, after which compaction may reclaim the versions it was
 * keeping alive
 * @param snap the snapshot, may be NULL
 */
void engine_snapshot_release(tidesdb_snapshot_t *snap);

/**
 * engine_snapshot_seq
 * the sequence a snapshot reads at
 * @param snap the snapshot
 * @return the sequence, or 0 when snap is NULL
 */
uint64_t engine_snapshot_seq(const tidesdb_snapshot_t *snap);

/**
 * engine_txn_begin_at_snapshot
 * begin a transaction whose reads resolve as of a snapshot rather than as of now. the snapshot must
 * outlive the transaction, since it is what holds the floor under the versions being read
 * @param db the engine
 * @param snap the snapshot to read at
 * @param out out -- the transaction handle on success, freed by engine_txn_free
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_INVALID_DB when closing, or TDB_ERR_MEMORY
 */
int engine_txn_begin_at_snapshot(tidesdb_t *db, tidesdb_snapshot_t *snap, tidesdb_txn_t **out);

/**
 * engine_txn_put
 * buffer a put into a transaction against a column family
 * @param txn the transaction
 * @param cf the target column family
 * @param key the key bytes
 * @param key_size length of key
 * @param value the value bytes
 * @param value_size length of value
 * @param ttl absolute expiry time, or -1 for none
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_txn_put(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                   const uint8_t *value, size_t value_size, int64_t ttl);

/**
 * engine_txn_delete
 * buffer a tombstone delete into a transaction against a column family
 * @param txn the transaction
 * @param cf the target column family
 * @param key the key bytes
 * @param key_size length of key
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_txn_delete(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size);

/**
 * engine_txn_delete_prefix
 * buffer a delete of every key beginning with prefix, resolving the family to its index
 * @param txn the transaction
 * @param cf the target column family
 * @param prefix the prefix bytes
 * @param prefix_size length of prefix
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_TXN_EXPIRED, or TDB_ERR_MEMORY
 */
int engine_txn_delete_prefix(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *prefix,
                             size_t prefix_size);

/**
 * engine_txn_delete_range
 * buffer a delete of every key in [lo, hi), resolving the family to its index
 * @param txn the transaction
 * @param cf the target column family
 * @param lo the inclusive lower bound
 * @param lo_size length of lo
 * @param hi the exclusive upper bound, or NULL with hi_size 0 for the end of the family
 * @param hi_size length of hi, 0 for the end of the family
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_TXN_EXPIRED, or TDB_ERR_MEMORY
 */
int engine_txn_delete_range(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *lo, size_t lo_size,
                            const uint8_t *hi, size_t hi_size);

/**
 * engine_txn_get
 * read a key at the transaction's snapshot through the db-level source stack
 * @param txn the transaction
 * @param cf the target column family
 * @param key the key bytes
 * @param key_size length of key
 * @param value out -- a malloc'd value on a live hit (caller frees)
 * @param value_size out -- the value length on a hit
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_txn_get(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                   uint8_t **value, size_t *value_size);

/**
 * engine_txn_commit
 * commit a transaction through the db-level commit backend and source stack
 * @param txn the transaction
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT when a conflicting write committed first,
 * TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn, TDB_ERR_TXN_EXPIRED, TDB_ERR_MEMORY, or
 * TDB_ERR_IO
 */
int engine_txn_commit(tidesdb_txn_t *txn);

/**
 * engine_txn_prepare
 * two-phase-commit phase one through the db-level backend and source stack, logging the batch under
 * the xid without applying it
 * @param txn the transaction
 * @param xid the transaction id to record durably
 * @param xid_size length of xid, must be greater than zero
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT when a conflicting write committed first,
 *         TDB_ERR_INVALID_ARGS, TDB_ERR_TXN_EXPIRED, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int engine_txn_prepare(tidesdb_txn_t *txn, const uint8_t *xid, size_t xid_size);

/**
 * engine_txn_commit_prepared
 * two-phase-commit phase two commit -- apply the prepared batch, then account its bytes, fire
 * commit hooks, and rotate the memtable if it filled, mirroring a single-phase commit
 * @param txn a prepared transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if not prepared, or TDB_ERR_MEMORY or TDB_ERR_IO,
 * either of which leaves the transaction prepared for the coordinator to retry
 */
int engine_txn_commit_prepared(tidesdb_txn_t *txn);

/**
 * engine_txn_set_timeout
 * bound how long a transaction may stay active, measured from now
 * @param txn the transaction handle
 * @param seconds seconds from now at which it expires, or <= 0 to clear the timeout
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS for a transaction that is no longer active
 */
int engine_txn_set_timeout(tidesdb_txn_t *txn, int64_t seconds);

/**
 * engine_txn_request_abort
 * flag a transaction running on another thread to fail its next operation; the one call here that
 * may cross threads, since it changes no state of its own
 * @param txn the transaction, or NULL for a no-op
 */
void engine_txn_request_abort(tidesdb_txn_t *txn);

/**
 * engine_txn_rollback_prepared
 * two-phase-commit phase two rollback -- durably discard the prepared batch
 * @param txn a prepared transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if not prepared, or TDB_ERR_MEMORY or TDB_ERR_IO,
 * either of which leaves the transaction prepared for the coordinator to retry
 */
int engine_txn_rollback_prepared(tidesdb_txn_t *txn);

/**
 * engine_recover_prepared
 * list the transactions recovery found durably prepared with no decision recorded after them, as
 * prepared handles the caller resolves with engine_txn_commit_prepared or
 * engine_txn_rollback_prepared. the set is fixed at open, so a caller may size its buffer from a
 * first call that passes max 0 and then fill it
 * @param db the engine
 * @param out out -- the in-doubt transactions, or NULL to only count them
 * @param max capacity of out in entries, ignored when out is NULL
 * @param out_count out -- how many in-doubt transactions there are, set even when out is too small
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_TOO_LARGE when out is given and max is below
 *         out_count, in which case nothing was written, or TDB_ERR_MEMORY
 */
int engine_recover_prepared(tidesdb_t *db, tidesdb_prepared_txn_t *out, int max, int *out_count);

/**
 * engine_note_retained_wal
 * record a write-ahead log a flush kept because a prepared transaction was outstanding, so it can
 * be unlinked once nothing is in doubt. shaped as a flush_ctx callback
 * @param ctx the engine, passed opaquely by the flush
 * @param path the log path that was kept
 * @param generation the write-ahead log generation path holds, so a decision can release exactly
 *                   the log its prepared transaction landed in
 */
void engine_note_retained_wal(void *ctx, const char *path, uint64_t generation);

/**
 * engine_sweep_retained_wals
 * unlink every log kept for a prepared transaction, once none are still awaiting a decision. a
 * no-op while any remain in doubt
 * @param db the engine
 */
void engine_sweep_retained_wals(tidesdb_t *db);

/**
 * engine_get_stall_stats
 * collect where writers have been made to wait, folding the l0's log and admission totals together
 * with the engine's rotation totals
 * @param db the engine
 * @param out out -- the totals, zeroed then filled
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_stall_stats(tidesdb_t *db, tidesdb_stall_stats_t *out);

/**
 * engine_get_io_stats
 * collect what each class of file asked of the device, from the descriptor manager's per-label
 * accounting
 * @param db the engine
 * @param out out -- the totals, zeroed then filled
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_get_io_stats(tidesdb_t *db, tidesdb_io_stats_t *out);

/**
 * engine_note_prepare_generation
 * @param live the batch a live prepare staged inside its transaction, or NULL for one a replay
 * re-staged into the cross-generation map; a value log floor is held over whatever either of them
 * references, since a prepared batch's values are named by no memtable and no sstable until phase
 * two decides it
 * @param live_count how many entries live holds
 * record that an undecided prepare's record lives in the given write-ahead log generation, lowering
 * the retention floor to it. the generation must be captured before the PREPARE is appended, so a
 * rotation racing the append makes this too low rather than too high -- keeping a log that is not
 * needed costs disk, dropping one that is loses the batch
 * @param db the engine
 * @param first the generation read before the append
 * @param last the generation read after it; the two differ only when a rotation raced the append,
 *             and both are pinned so the record's real generation is covered either way
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_note_prepare_generation(tidesdb_t *db, uint64_t first, uint64_t last,
                                   const tidesdb_wal_entry_t *live, int live_count);

/**
 * engine_wal_generation_pinned
 * whether an undecided prepare's record lives in the given write-ahead log generation, so a flush
 * knows to keep that generation's log rather than unlink it
 * @param ctx the engine, as an opaque flush-context pointer
 * @param generation the generation being retired
 * @return non-zero when the generation still holds an undecided prepare
 */
int engine_wal_generation_pinned(void *ctx, uint64_t generation);

/**
 * engine_release_prepare_generation
 * drop one undecided prepare's hold on its generation once phase two has decided it, then unlink
 * every retained log the floor has moved past. the decision is durable in its own generation, and a
 * COMMIT record carries the write set, so the prepared generation is free the moment it is decided
 * @param db the engine
 * @param first the first generation recorded when the prepare was taken
 * @param last the last generation recorded when the prepare was taken
 */
void engine_release_prepare_generation(tidesdb_t *db, uint64_t first, uint64_t last);

/**
 * engine_note_prepared_in_doubt
 * record how many recovered transactions are still awaiting a coordinator's decision, so their
 * write-ahead log generations stay pinned until they are resolved
 * @param db the engine, with the two-phase staging map populated by replay
 * @return TDB_SUCCESS
 */
int engine_note_prepared_in_doubt(tidesdb_t *db);

/**
 * engine_txn_state
 * report a transaction's lifecycle state
 * @param txn the transaction
 * @param out_state receives the state
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int engine_txn_state(const tidesdb_txn_t *txn, tidesdb_txn_state_t *out_state);

/**
 * engine_txn_read_snapshot
 * the sequence ceiling this transaction's reads filter at
 * @param txn the transaction
 * @return the read snapshot sequence, or 0 on a NULL transaction
 */
uint64_t engine_txn_read_snapshot(const tidesdb_txn_t *txn);

/**
 * engine_txn_rollback
 * abort a transaction, discarding its buffered writes
 * @param txn the transaction
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL or already-resolved txn
 */
int engine_txn_rollback(tidesdb_txn_t *txn);

/**
 * engine_txn_free
 * free a transaction handle and its core
 * @param txn the transaction, may be NULL
 */
void engine_txn_free(tidesdb_txn_t *txn);

/**
 * engine_txn_contains
 * whether a key is present at the transaction's snapshot, without tracking the read
 * @param txn the transaction
 * @param cf the column family to probe
 * @param key the key bytes
 * @param key_size length of key
 * @return TDB_SUCCESS if present, TDB_ERR_NOT_FOUND if absent, TDB_ERR_INVALID_ARGS on a NULL txn
 * or cf, TDB_ERR_BUSY under descriptor pressure, or TDB_ERR_MEMORY, TDB_ERR_IO or
 * TDB_ERR_CORRUPTION from a source read
 */
int engine_txn_contains(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size);

/**
 * engine_txn_get_notrack
 * read a key without recording it into the conflict footprint; for uniqueness probes
 * @param txn the transaction
 * @param cf the column family to read from
 * @param key the key bytes
 * @param key_size length of key
 * @param value out -- the value, allocated and owned by the caller
 * @param value_size out -- the value length
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when no visible version exists, TDB_ERR_INVALID_ARGS on a
 * NULL txn or cf, TDB_ERR_BUSY under descriptor pressure, or TDB_ERR_MEMORY, TDB_ERR_IO or
 * TDB_ERR_CORRUPTION from a source read
 */
int engine_txn_get_notrack(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size,
                           uint8_t **value, size_t *value_size);

/**
 * engine_txn_single_delete
 * buffer a single-delete tombstone that pairs with exactly one put
 * @param txn the transaction
 * @param cf the column family the key belongs to
 * @param key the key bytes
 * @param key_size length of key
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn or cf, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int engine_txn_single_delete(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *key, size_t key_size);

/**
 * engine_txn_savepoint / engine_txn_rollback_to_savepoint / engine_txn_release_savepoint
 * mark, roll back to, or discard a named savepoint within the transaction
 * @param txn the transaction
 * @param name the savepoint name
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND from the rollback and release forms when no savepoint
 * carries that name, TDB_ERR_INVALID_ARGS on a NULL txn or name, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int engine_txn_savepoint(tidesdb_txn_t *txn, const char *name);
int engine_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name);
int engine_txn_release_savepoint(tidesdb_txn_t *txn, const char *name);

/**
 * engine_txn_reset
 * discard the transaction's buffered work and restart it at a fresh snapshot and isolation level
 * @param txn the transaction
 * @param isolation the isolation level to restart at
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_txn_reset(tidesdb_txn_t *txn, tidesdb_isolation_level_t isolation);

/* ===== compaction scheduling (src/engine/engine_compaction.c) ===== */

/**
 * engine_compaction_init
 * create the compaction work queue, the worker pool, and the backstop scheduler ticker, registering
 * the pool and ticker on the threadmanager
 * @param db the engine
 * @return TDB_SUCCESS or TDB_ERR_MEMORY
 */
int engine_compaction_init(tidesdb_t *db);

/**
 * engine_compaction_wake
 * wake the scheduler to replan now, called after a flush installs new L1 segments
 * @param db the engine
 */
void engine_compaction_wake(tidesdb_t *db);

/**
 * engine_compaction_drain
 * free any planned jobs still queued at close; the workers must already be stopped
 * @param db the engine
 */
void engine_compaction_drain(tidesdb_t *db);

/**
 * engine_vlog_gc
 * reclaim dead space in the db-global value log: capture the write watermark, scan every live
 * sstable across all families for the vlog ids they still reference, and hand that live set to
 * vlog_reclaim, which drains whichever sealed segment holds the most dead bytes by copying its
 * live values forward into the active segment and unlinking the drained file. an incomplete scan
 * aborts without sweeping so a missed live id is never reclaimed. normally queued and run by the
 * compaction pool; exposed for a direct synchronous reclaim
 * @param db the engine
 */
void engine_vlog_gc(tidesdb_t *db);

/**
 * engine_is_compacting
 * whether a column family has a compaction claimed or running
 * @param cf the column family, may be NULL
 * @return 1 when a compaction is in progress, 0 otherwise
 */
int engine_is_compacting(cf_t *cf);

/**
 * engine_compact
 * synchronously run one forced compaction pass on a column family, planning a merge even when no
 * trigger is due and executing every job it produces in the caller's thread
 * @param db the engine
 * @param cf the column family
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED when a compaction is already running,
 * or an io or allocation error
 */
int engine_compact(tidesdb_t *db, cf_t *cf);

/**
 * engine_compact_range
 * synchronously merge every sstable overlapping [start, end) -- and, by overlap closure, every
 * sstable that overlaps their union span, so no run is left overlapping the output -- into the
 * largest level among them; a NULL endpoint is unbounded, both NULL is rejected
 * @param db the engine
 * @param cf the column family
 * @param start range start, or NULL for unbounded
 * @param start_size length of start in bytes
 * @param end range end, or NULL for unbounded
 * @param end_size length of end in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED, TDB_ERR_BUSY, or an io or allocation
 * error
 */
int engine_compact_range(tidesdb_t *db, cf_t *cf, const uint8_t *start, size_t start_size,
                         const uint8_t *end, size_t end_size);

/**
 * engine_range_stats
 * describe [key_a, key_b) for a planner, reporting the sorted runs a scan would merge and how many
 * live keys the range holds. one layout snapshot serves both, and the metadata pass gates the walk
 * so a wide range costs no more than the overlap count alone
 * @param db the database, for the shared memtable the count reads through
 * @param cf the column family
 * @param key_a range start, inclusive
 * @param key_a_size length of key_a in bytes
 * @param key_b range end, exclusive
 * @param key_b_size length of key_b in bytes
 * @param out out -- the statistics
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED, or TDB_ERR_MEMORY
 */
int engine_range_stats(tidesdb_t *db, cf_t *cf, const uint8_t *key_a, size_t key_a_size,
                       const uint8_t *key_b, size_t key_b_size, tidesdb_range_stats_t *out);

/* ===== maintenance operations (src/engine/engine_ops.c) ===== */

/**
 * engine_force_rotate
 * seal the active memtable into the immutable queue regardless of its fill level and install a
 * fresh active on the next WAL generation; a no-op when the active memtable is empty. defined in
 * engine.c
 * @param db the engine
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_IO on a rotation failure
 */
int engine_force_rotate(tidesdb_t *db);

/**
 * engine_prepare_spare_wal
 * open the log the next rotation will need, if one is not already waiting. called off the rotation
 * lock so the file creation, ring allocation and flush-thread start it costs are paid by one thread
 * rather than by every committer queued behind a rotation doing that work inline
 * @param db the database
 */
void engine_prepare_spare_wal(tidesdb_t *db);

/**
 * engine_maybe_rotate
 * rotate the active memtable only when it has filled -- seal it into the immutable queue and wake a
 * flush worker, serialized so only one thread rotates at a time. defined in engine.c
 * @param db the engine
 */
void engine_maybe_rotate(tidesdb_t *db);

/**
 * engine_is_flushing
 * whether the unified memtable has an immutable queued or flushing
 * @param db the engine, may be NULL
 * @return 1 when a flush is pending or in progress, 0 otherwise
 */
int engine_is_flushing(tidesdb_t *db);

/**
 * engine_sync_wal
 * force an fsync of the currently installed write-ahead log
 * @param db the engine
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_IO
 */
int engine_sync_wal(tidesdb_t *db);

/**
 * engine_flush_memtable
 * synchronously seal the active memtable and wait for the flush pool to drive every queued
 * immutable to L1; a no-op when the active memtable is empty
 * @param db the engine
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY when the flush does not drain in time, or
 * an io or allocation error
 */
int engine_flush_memtable(tidesdb_t *db);

/**
 * engine_checkpoint
 * establish a durability barrier: flush the memtable to L1, fsync every resident klog, then force
 * the write-ahead log, the value log, and the manifest to disk regardless of the configured sync
 * mode
 * @param db the engine
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or an io or allocation error
 */
int engine_checkpoint(tidesdb_t *db);

/**
 * engine_copy_file
 * stream at most limit bytes from src to dst, overwriting dst; a block-manager file is copied to
 * its logical size (not its preallocated on-disk size) so a reopen, which derives the size from
 * fstat, sees the same end-of-file. pass UINT64_MAX for a plain file. defined in engine_backup.c
 * @param src the source file path
 * @param dst the destination file path, created or overwritten
 * @param limit the maximum number of bytes to copy
 * @return TDB_SUCCESS, TDB_ERR_IO, or TDB_ERR_MEMORY
 */
int engine_copy_file(const char *src, const char *dst, uint64_t limit);

/**
 * engine_clone_cf
 * clone a column family to a new name: create the destination with the source's config, then copy
 * every source sstable into it under fresh ids while compaction and flushes are frozen. the copied
 * sstables share the source's value-log offsets, safe because the db-global value log's reclaim
 * keeps any block a live sstable references and the clone's are live. not safe against concurrent
 * operations on the source
 * @param db the engine
 * @param src_name the source family name
 * @param dst_name the destination family name, must not already exist
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, TDB_ERR_EXISTS, TDB_ERR_LOCKED when
 * a compaction holds either family for the whole quiesce wait, or an io or allocation error
 */
int engine_clone_cf(tidesdb_t *db, const char *src_name, const char *dst_name);

/**
 * engine_backup
 * write a consistent, directly-openable copy of the database into dir -- flush the memtable, then,
 * with compaction frozen and ddl held off, copy the manifest, value log, wals, and every cf's klogs
 * so no copied file can be deleted mid-copy. defined in engine_backup.c
 * @param db the engine
 * @param dir the destination directory, created if absent
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY when compaction cannot be quiesced, or an
 * io or allocation error
 */
int engine_backup(tidesdb_t *db, const char *dir);

/* ===== the reaper family (src/engine/engine_reaper.c) ===== */

/**
 * engine_reaper_init
 * start the reaper bg_tickers and register them on the threadmanager -- the fd-eviction reaper that
 * closes idle klog descriptors down to the fd budget
 * @param db the engine
 * @return TDB_SUCCESS or TDB_ERR_MEMORY
 */
int engine_reaper_init(tidesdb_t *db);

/* ===== range iteration (src/engine/engine_iter.c) ===== */

/**
 * engine_iter_new
 * open a range iterator over a column family at the transaction's snapshot, hiding tombstones
 * @param txn the transaction supplying the snapshot
 * @param cf the column family to iterate
 * @param out out -- the iterator on success, freed by engine_iter_free
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int engine_iter_new(tidesdb_txn_t *txn, cf_t *cf, tidesdb_iter_t **out);

/**
 * engine_iter_new_range
 * as engine_iter_new, but told the range the caller will read, so the scan's merge is built from
 * the sstables whose key range meets it rather than from every one the family holds
 * @param txn transaction providing the read snapshot
 * @param cf the column family to scan
 * @param lower range start, inclusive, or NULL for an unbounded scan
 * @param lower_size size of lower in bytes
 * @param upper range end, inclusive for source selection, or NULL for an unbounded scan
 * @param upper_size size of upper in bytes
 * @param out out -- the new iterator
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS when either end is missing, TDB_ERR_BUSY when the
 * descriptor budget or a moving level set left a source unopenable, or TDB_ERR_MEMORY
 */
int engine_iter_new_range(tidesdb_txn_t *txn, cf_t *cf, const uint8_t *lower, size_t lower_size,
                          const uint8_t *upper, size_t upper_size, tidesdb_iter_t **out);

/**
 * engine_iter_free
 * free an iterator and release its L0 pins and sstable references
 * @param it the iterator, may be NULL
 */
void engine_iter_free(tidesdb_iter_t *it);

/**
 * engine_iter_seek_first / engine_iter_seek_last / engine_iter_seek / engine_iter_seek_for_prev /
 * engine_iter_next / engine_iter_prev
 * position the iterator; seek lands on the first key >= key, seek_for_prev on the last key <= key
 * @param it the iterator
 * @return TDB_SUCCESS when positioned on an entry, TDB_ERR_NOT_FOUND when the merged stream has
 * none there, TDB_ERR_INVALID_ARGS on a NULL iterator, or TDB_ERR_MEMORY, TDB_ERR_IO or
 * TDB_ERR_CORRUPTION from a source read
 */
int engine_iter_seek_first(tidesdb_iter_t *it);
int engine_iter_seek_last(tidesdb_iter_t *it);
int engine_iter_seek(tidesdb_iter_t *it, const uint8_t *key, size_t key_size);
int engine_iter_seek_for_prev(tidesdb_iter_t *it, const uint8_t *key, size_t key_size);
int engine_iter_next(tidesdb_iter_t *it);
int engine_iter_prev(tidesdb_iter_t *it);

/**
 * engine_iter_valid
 * whether the iterator is positioned on a live entry
 * @param it the iterator
 * @return 1 when valid, 0 otherwise
 */
int engine_iter_valid(const tidesdb_iter_t *it);

/**
 * engine_iter_key / engine_iter_value / engine_iter_key_value
 * copy the current key and/or value out, resolving a spilled value through the cf's vlog; the
 * outputs are newly allocated and owned by the caller
 * @param it the iterator
 * @param key out -- the key, allocated; only in the key and key_value forms
 * @param key_size out -- the key length; only in the key and key_value forms
 * @param value out -- the value, allocated; only in the value and key_value forms
 * @param value_size out -- the value length; only in the value and key_value forms
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when not positioned, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int engine_iter_key(tidesdb_iter_t *it, uint8_t **key, size_t *key_size);
int engine_iter_value(tidesdb_iter_t *it, uint8_t **value, size_t *value_size);
int engine_iter_key_value(tidesdb_iter_t *it, uint8_t **key, size_t *key_size, uint8_t **value,
                          size_t *value_size);

#endif /* __TIDESDB_ENGINE_H__ */
