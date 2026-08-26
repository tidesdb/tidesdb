/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "db.h"

#include <string.h>
#include <time.h>

#include "base/errors.h"
#include "column_family/cf_config.h" /* TDB_DEFAULT_CF_BTREE_BLOCK_SIZE */
#include "compat.h"                  /* tdb_raise_max_open_files */
#include "engine/engine.h"
#include "internal/types.h" /* TDB_TTL_NONE, the deadline a never-expiring entry carries */

/* db.c is the thin public facade over the engine: it validates arguments, fills unset config fields
 * with their defaults, and delegates to the engine, holding no state of its own. */

/* configuration defaults; a config field left 0 by the caller resolves to these */
#define TDB_DEFAULT_FLUSH_THREADS      2
#define TDB_DEFAULT_COMPACTION_THREADS 2
#define TDB_DEFAULT_BLOCK_CACHE_SIZE   (64u << 20) /* 64 MiB */
#define TDB_DEFAULT_MAX_OPEN_SSTABLES  1024
#define TDB_DEFAULT_WRITE_BUFFER_SIZE  (64u << 20) /* 64 MiB */
/* how long an unwritten memtable waits before the engine rotates it, so an idle database still
 * drains to L1 rather than holding its last writes in memory until the process next takes one */
#define TDB_DEFAULT_IDLE_FLUSH_SECONDS    30
#define TDB_DEFAULT_SKIP_LIST_MAX_LEVEL   12
#define TDB_DEFAULT_SKIP_LIST_PROBABILITY 0.25f
#define TDB_DEFAULT_SYNC_INTERVAL_US      1000000 /* 1 second */
/* immutable-queue depth at which writes hard-block; the throttle band opens at three quarters of
 * it, so a wider limit gives writers more room to pace before the block and keeps the write tail
 * low at the default memtable size */
#define TDB_DEFAULT_L0_QUEUE_STALL 16

/* the value log's segment target; large enough that rolling is rare and descriptor pressure
 * stays low, small enough that draining one segment is a bounded amount of copying */
#define TDB_DEFAULT_VLOG_SEGMENT_SIZE (256ull * 1024 * 1024)

/* the size at or above which a value is stored in the value log instead of inline. a quarter of
 * the default klog node size, which is the pairing cf_config_warn_layout advises, so a node still
 * holds several entries at the largest size that stays inline */
#define TDB_DEFAULT_VALUE_SEPARATION_THRESHOLD 1024

/* column-family configuration defaults */
#define TDB_DEFAULT_CF_LEVEL_SIZE_RATIO 10
#define TDB_DEFAULT_CF_MIN_LEVELS       1
#define TDB_DEFAULT_CF_BLOOM_FPR        0.01
/* the dividing level sits this far above the largest, so X = L - 2. Spooky measures X = L - 1 as
 * running out of space at scale, since a dividing merge there rewrites a level holding a tenth of
 * the data at once, and X = L - 4 as exhausting the open-file budget; L - 2 is the balance it
 * settles on */
#define TDB_DEFAULT_CF_DIVIDING_LEVEL_OFFSET 1

#define TDB_DEFAULT_CF_L1_FILE_COUNT_TRIGGER 4
#define TDB_DEFAULT_CF_TOMBSTONE_DENSITY     0.5
#define TDB_DEFAULT_CF_TOMBSTONE_MIN_ENTRIES 4096

tidesdb_config_t tidesdb_default_config(void)
{
    tidesdb_config_t c;
    memset(&c, 0, sizeof(c));
    c.db_path = NULL; /* the caller must set the database directory */
    c.num_flush_threads = TDB_DEFAULT_FLUSH_THREADS;
    c.num_compaction_threads = TDB_DEFAULT_COMPACTION_THREADS;
    c.log_level = TDB_LOG_INFO;
    c.block_cache_size = TDB_DEFAULT_BLOCK_CACHE_SIZE;
    c.max_open_sstables = TDB_DEFAULT_MAX_OPEN_SSTABLES;
    c.log_to_file = 0;
    c.log_truncation_at = 0;
    c.memtable_write_buffer_size = TDB_DEFAULT_WRITE_BUFFER_SIZE;
    c.memtable_skip_list_max_level = TDB_DEFAULT_SKIP_LIST_MAX_LEVEL;
    c.memtable_skip_list_probability = TDB_DEFAULT_SKIP_LIST_PROBABILITY;
    c.memtable_sync_mode = TDB_SYNC_NONE;
    c.memtable_sync_interval_us = TDB_DEFAULT_SYNC_INTERVAL_US;
    c.value_separation_threshold = TDB_DEFAULT_VALUE_SEPARATION_THRESHOLD;
    c.vlog_segment_size = TDB_DEFAULT_VLOG_SEGMENT_SIZE;
    c.memtable_l0_queue_stall_threshold = TDB_DEFAULT_L0_QUEUE_STALL;
    c.memtable_idle_flush_seconds = TDB_DEFAULT_IDLE_FLUSH_SECONDS;
    return c;
}

/* the public spelling of internal contention. TDB_ERR_BUSY is an engine-internal code that db.h
 * does not define, and to a caller it means exactly what TDB_ERR_LOCKED means -- something else
 * held what the call needed, nothing was written, and asking again is the remedy. mapping it here
 * at the boundary is what keeps a code no header declares out of a caller's switch and out of
 * tidesdb_strerror, which would describe it as unknown */
static int tdb_public_rc(const int rc)
{
    return rc == TDB_ERR_BUSY ? TDB_ERR_LOCKED : rc;
}

int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db)
{
    if (!config || !db) return TDB_ERR_INVALID_ARGS;
    if (!config->db_path || config->db_path[0] == '\0') return TDB_ERR_INVALID_ARGS;

    /* fill the fields that treat 0 as auto with their defaults, leaving explicit choices untouched
     */
    tidesdb_config_t resolved = *config;
    const tidesdb_config_t d = tidesdb_default_config();
    if (resolved.num_flush_threads <= 0) resolved.num_flush_threads = d.num_flush_threads;
    if (resolved.num_compaction_threads <= 0)
        resolved.num_compaction_threads = d.num_compaction_threads;
    if (resolved.block_cache_size == 0) resolved.block_cache_size = d.block_cache_size;
    if (resolved.max_open_sstables == 0) resolved.max_open_sstables = d.max_open_sstables;
    if (resolved.value_separation_threshold == 0)
        resolved.value_separation_threshold = d.value_separation_threshold;
    if (resolved.vlog_segment_size == 0) resolved.vlog_segment_size = d.vlog_segment_size;
    if (resolved.memtable_write_buffer_size == 0)
        resolved.memtable_write_buffer_size = d.memtable_write_buffer_size;
    if (resolved.memtable_skip_list_max_level == 0)
        resolved.memtable_skip_list_max_level = d.memtable_skip_list_max_level;
    if (resolved.memtable_skip_list_probability <= 0.0f)
        resolved.memtable_skip_list_probability = d.memtable_skip_list_probability;

    return tdb_public_rc(engine_open(&resolved, db));
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    engine_close(db);
    return TDB_SUCCESS;
}

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    tidesdb_column_family_config_t c;
    memset(&c, 0, sizeof(c));
    c.level_size_ratio = TDB_DEFAULT_CF_LEVEL_SIZE_RATIO;
    c.min_levels = TDB_DEFAULT_CF_MIN_LEVELS;
    c.dividing_level_offset = TDB_DEFAULT_CF_DIVIDING_LEVEL_OFFSET;
    c.btree_klog_block_size = TDB_DEFAULT_CF_BTREE_BLOCK_SIZE;
    c.encoding_count = 0;
    c.enable_bloom_filter = 1;
    c.bloom_fpr = TDB_DEFAULT_CF_BLOOM_FPR;
    c.default_isolation_level = TDB_ISOLATION_READ_COMMITTED;
    c.l1_file_count_trigger = TDB_DEFAULT_CF_L1_FILE_COUNT_TRIGGER;
    c.tombstone_density_trigger = TDB_DEFAULT_CF_TOMBSTONE_DENSITY;
    c.tombstone_density_min_entries = TDB_DEFAULT_CF_TOMBSTONE_MIN_ENTRIES;
    c.commit_hook_fn = NULL;
    c.commit_hook_ctx = NULL;
    return c;
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name || !config) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_create_cf(db, name, config));
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_drop_cf(db, name));
}

/* the default isolation a plain begin uses when the caller names no level and no cf */
#define TDB_DEFAULT_TXN_ISOLATION TDB_ISOLATION_READ_COMMITTED

/* the public cf handle is the internal cf_t; the opaque type is never dereferenced as itself */
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;
    return (tidesdb_column_family_t *)engine_get_cf(db, name);
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_begin(db, TDB_DEFAULT_TXN_ISOLATION, txn));
}

int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_begin(db, isolation, txn));
}

int tidesdb_snapshot_create(tidesdb_t *db, tidesdb_snapshot_t **snapshot)
{
    if (!db || !snapshot) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_snapshot_create(db, snapshot));
}

void tidesdb_snapshot_release(tidesdb_snapshot_t *snapshot)
{
    engine_snapshot_release(snapshot);
}

uint64_t tidesdb_snapshot_seq(const tidesdb_snapshot_t *snapshot)
{
    return engine_snapshot_seq(snapshot);
}

int tidesdb_txn_begin_at_snapshot(tidesdb_t *db, tidesdb_snapshot_t *snapshot, tidesdb_txn_t **txn)
{
    if (!db || !snapshot || !txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_begin_at_snapshot(db, snapshot, txn));
}

int tidesdb_txn_begin_at_seq(tidesdb_t *db, uint64_t seq, tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_begin_at_seq(db, seq, txn));
}

uint64_t tidesdb_oldest_readable_seq(const tidesdb_t *db)
{
    return engine_oldest_readable_seq(db);
}

int tidesdb_txn_begin_cf(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn)
{
    if (!db || !cf || !txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_begin(db, cf_config_default_isolation((cf_t *)cf), txn));
}

/**
 * tidesdb_ttl_deadline
 * turn a caller's lifetime in seconds into the absolute deadline the engine stores. everything
 * below this boundary compares a stored deadline against the wall clock, which is one comparison
 * per version examined on the read path; converting once here is what keeps it that way, and it is
 * also what keeps replay correct, since a wal record must carry a deadline rather than a lifetime
 * that recovery would restart
 * @param ttl_seconds the caller's lifetime in seconds; zero or negative never expires
 * @return the absolute expiry, or TDB_TTL_NONE
 */
static int64_t tidesdb_ttl_deadline(time_t ttl_seconds)
{
    if (ttl_seconds <= 0) return TDB_TTL_NONE;

    const int64_t now = (int64_t)time(NULL);
    /* a lifetime long enough to overflow the deadline is one the caller means as forever */
    if (ttl_seconds > INT64_MAX - now) return TDB_TTL_NONE;
    return now + (int64_t)ttl_seconds;
}

int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_put(txn, (cf_t *)cf, key, key_size, value, value_size,
                                        tidesdb_ttl_deadline(ttl)));
}

int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_get(txn, (cf_t *)cf, key, key_size, value, value_size));
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_delete(txn, (cf_t *)cf, key, key_size));
}

int tidesdb_txn_delete_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lo,
                             size_t lo_size, const uint8_t *hi, size_t hi_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_delete_range(txn, (cf_t *)cf, lo, lo_size, hi, hi_size));
}

int tidesdb_txn_delete_prefix(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                              const uint8_t *prefix, size_t prefix_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_delete_prefix(txn, (cf_t *)cf, prefix, prefix_size));
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_commit(txn));
}

uint64_t tidesdb_txn_read_snapshot(const tidesdb_txn_t *txn)
{
    return engine_txn_read_snapshot(txn);
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_rollback(txn));
}

int tidesdb_txn_set_timeout(tidesdb_txn_t *txn, int64_t seconds)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_set_timeout(txn, seconds));
}

void tidesdb_txn_request_abort(tidesdb_txn_t *txn)
{
    engine_txn_request_abort(txn);
}

int tidesdb_txn_prepare(tidesdb_txn_t *txn, const uint8_t *xid, size_t xid_size)
{
    if (!txn || !xid || xid_size == 0) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_prepare(txn, xid, xid_size));
}

int tidesdb_txn_commit_prepared(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_commit_prepared(txn));
}

int tidesdb_txn_rollback_prepared(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_rollback_prepared(txn));
}

int tidesdb_recover_prepared(tidesdb_t *db, tidesdb_prepared_txn_t *out, const int max,
                             int *out_count)
{
    if (!db || !out_count) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_recover_prepared(db, out, max, out_count));
}

int tidesdb_txn_state(const tidesdb_txn_t *txn, tidesdb_txn_state_t *out_state)
{
    if (!txn || !out_state) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_state(txn, out_state));
}

void tidesdb_txn_free(tidesdb_txn_t *txn)
{
    engine_txn_free(txn);
}

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter)
{
    if (!txn || !cf || !iter) return TDB_ERR_INVALID_ARGS;
    /* opening a scan competes for the reader fd budget and for a source set a compaction may be
     * moving, and both report contention as the internal busy code */
    return tdb_public_rc(engine_iter_new(txn, (cf_t *)cf, iter));
}

int tidesdb_iter_new_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lower,
                           size_t lower_size, const uint8_t *upper, size_t upper_size,
                           tidesdb_iter_t **iter)
{
    if (!txn || !cf || !lower || !upper || !iter) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(
        engine_iter_new_range(txn, (cf_t *)cf, lower, lower_size, upper, upper_size, iter));
}

int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_seek(iter, key, key_size));
}

int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_seek_for_prev(iter, key, key_size));
}

int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_seek_first(iter));
}

int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_seek_last(iter));
}

int tidesdb_iter_next(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_next(iter));
}

int tidesdb_iter_prev(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_prev(iter));
}

int tidesdb_iter_valid(tidesdb_iter_t *iter)
{
    return engine_iter_valid(iter);
}

int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size)
{
    if (!iter || !key || !key_size) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_key(iter, key, key_size));
}

int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_value(iter, value, value_size));
}

int tidesdb_iter_key_value(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size, uint8_t **value,
                           size_t *value_size)
{
    if (!iter || !key || !key_size || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_iter_key_value(iter, key, key_size, value, value_size));
}

void tidesdb_iter_free(tidesdb_iter_t *iter)
{
    engine_iter_free(iter);
}

int tidesdb_txn_get_notrack(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                            size_t key_size, uint8_t **value, size_t *value_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_get_notrack(txn, (cf_t *)cf, key, key_size, value, value_size));
}

int tidesdb_txn_contains(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                         size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_contains(txn, (cf_t *)cf, key, key_size));
}

int tidesdb_txn_single_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                              size_t key_size)
{
    if (!txn || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_single_delete(txn, (cf_t *)cf, key, key_size));
}

int tidesdb_txn_reset(tidesdb_txn_t *txn, tidesdb_isolation_level_t isolation)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_reset(txn, isolation));
}

int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_savepoint(txn, name));
}

int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_rollback_to_savepoint(txn, name));
}

int tidesdb_txn_release_savepoint(tidesdb_txn_t *txn, const char *name)
{
    if (!txn || !name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_txn_release_savepoint(txn, name));
}

int tidesdb_get_cf_stats(tidesdb_column_family_t *cf, tidesdb_cf_stats_t *stats)
{
    if (!cf || !stats) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_get_cf_stats((cf_t *)cf, stats));
}

int tidesdb_cf_estimate_cardinality(tidesdb_column_family_t *cf, uint64_t *out_estimate)
{
    if (!cf || !out_estimate) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_cf_estimate_cardinality((cf_t *)cf, out_estimate));
}

int tidesdb_get_db_stats(tidesdb_t *db, tidesdb_db_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_get_db_stats(db, stats));
}

int tidesdb_get_klog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count)
{
    return tdb_public_rc(engine_get_klog_encoding_stats(db, out, max, out_count));
}

int tidesdb_get_vlog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count)
{
    return tdb_public_rc(engine_get_vlog_encoding_stats(db, out, max, out_count));
}

int tidesdb_get_stall_stats(tidesdb_t *db, tidesdb_stall_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_get_stall_stats(db, stats));
}

int tidesdb_get_io_stats(tidesdb_t *db, tidesdb_io_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_get_io_stats(db, stats));
}

int tidesdb_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *stats)
{
    if (!db || !stats) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_get_cache_stats(db, stats));
}

int tidesdb_compact(tidesdb_t *db, tidesdb_column_family_t *cf)
{
    if (!db || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_compact(db, (cf_t *)cf));
}

int tidesdb_compact_range(tidesdb_t *db, tidesdb_column_family_t *cf, const uint8_t *start_key,
                          size_t start_key_size, const uint8_t *end_key, size_t end_key_size)
{
    if (!db || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(
        engine_compact_range(db, (cf_t *)cf, start_key, start_key_size, end_key, end_key_size));
}

int tidesdb_flush_memtable(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_flush_memtable(db));
}

int tidesdb_is_flushing(tidesdb_t *db)
{
    return engine_is_flushing(db);
}

int tidesdb_is_compacting(tidesdb_column_family_t *cf)
{
    return engine_is_compacting((cf_t *)cf);
}

int tidesdb_sync_wal(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_sync_wal(db));
}

int tidesdb_range_stats(tidesdb_t *db, tidesdb_column_family_t *cf, const uint8_t *key_a,
                        size_t key_a_size, const uint8_t *key_b, size_t key_b_size,
                        tidesdb_range_stats_t *out)
{
    if (!db || !cf || !key_a || !key_b || !out) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(
        engine_range_stats(db, (cf_t *)cf, key_a, key_a_size, key_b, key_b_size, out));
}

int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count)
{
    if (!db || !names || !count) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_list_column_families(db, names, count));
}

int tidesdb_rename_column_family(tidesdb_t *db, const char *old_name, const char *new_name)
{
    if (!db || !old_name || !new_name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_rename_cf(db, old_name, new_name));
}

int tidesdb_clone_column_family(tidesdb_t *db, const char *src_name, const char *dst_name)
{
    if (!db || !src_name || !dst_name) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_clone_cf(db, src_name, dst_name));
}

int tidesdb_cf_update_runtime_config(tidesdb_t *db, tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk)
{
    if (!db || !cf || !new_config) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(
        engine_cf_update_runtime_config(db, (cf_t *)cf, new_config, persist_to_disk));
}

int tidesdb_cf_set_commit_hook(tidesdb_t *db, tidesdb_column_family_t *cf,
                               tidesdb_commit_hook_fn fn, void *ctx)
{
    if (!db || !cf) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_cf_set_commit_hook(db, (cf_t *)cf, fn, ctx));
}

int tidesdb_checkpoint(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_checkpoint(db));
}

int tidesdb_backup(tidesdb_t *db, const char *dir)
{
    if (!db || !dir) return TDB_ERR_INVALID_ARGS;
    return tdb_public_rc(engine_backup(db, dir));
}

long tidesdb_raise_open_file_limit(long desired)
{
    /* an explicit operator action; the engine never raises the limit itself. the multi-platform
     * raise lives in compat.h, and a partial or failed raise is non-fatal -- the prior ceiling
     * stands */
    return tdb_raise_max_open_files(desired);
}

void tidesdb_free(void *ptr)
{
    free(ptr);
}
