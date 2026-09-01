/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/bg_pool.h"
#include "base/encoding/serialization.h" /* TDB_WAL_EXT, TDB_CF_INDEX_MAX */
#include "base/errors.h"
#include "base/log.h"
#include "column_family/cf_config.h"
#include "compat.h" /* PATH_SEPARATOR, mkdir, remove_directory, opendir, readdir */
#include "engine_internal.h"
#include "flush/flush.h"
#include "io/block_manager.h"
#include "txn/cf_source.h"
#include "txn/wal_record.h"

/* the low-level modules mirror a few public constants rather than include db.h, which keeps them
 * independent but leaves nothing tying the copy to the original. the engine sees both sides, so it
 * is where the copies are held to their source -- a change to either half fails the build here
 * instead of quietly mapping a sync mode wrong or truncating a family name */
_Static_assert((int)TDB_SYNC_NONE == (int)BLOCK_MANAGER_SYNC_NONE,
               "block manager sync-none must match the public TDB_SYNC_NONE it is converted from");
_Static_assert((int)TDB_SYNC_FULL == (int)BLOCK_MANAGER_SYNC_FULL,
               "block manager sync-full must match the public TDB_SYNC_FULL it is converted from");
_Static_assert(MANIFEST_CF_NAME_MAX == TDB_MAX_CF_NAME_LEN,
               "manifest column family name bound must match the public one it mirrors");

/* the db-level arena pool sizing the unified memtable draws from */
#define ENGINE_ARENA_CHUNK_SIZE (1u << 20)  /* 1 MiB chunks */
#define ENGINE_ARENA_MAX_CACHED (16u << 20) /* retain up to 16 MiB of freed chunks */

/* the pool a decoded btree node carves its arena from. a node's decode needs about twice the node
 * size, and a cached node holds its chunk for as long as it stays cached -- so the chunk is sized
 * to one node's decode rather than to the memtable's much larger unit. drawing from the memtable
 * pool instead would park a megabyte per cached node to use a fraction of it, and the block cache
 * would keep charging itself only what the node measures, so its byte budget would stop describing
 * what the process actually holds.
 *
 * sized against the node size a family is actually created with, not against the builder's fallback
 * for a caller that asks for none -- those had drifted sixteen-fold apart, so every cached node
 * reserved a 128 KiB chunk to hold about 4 KiB, and a cache spent its whole budget holding a
 * thirty-second of it. a family configured with larger nodes is unaffected: an allocation above the
 * chunk size takes a block sized to itself rather than rounding up to a chunk */
#define ENGINE_NODE_ARENA_CHUNK_SIZE (TDB_DEFAULT_CF_BTREE_BLOCK_SIZE * 2)
#define ENGINE_NODE_ARENA_MAX_CACHED (64u << 20)

/* permissions for the database directory, rwxr-xr-x */
#define ENGINE_DB_DIR_MODE 0755

/* the file log_to_file routes output to, inside the database directory so it travels with the data
 * it describes rather than depending on the working directory a process happened to start in. named
 * like the LOCK and MANIFEST beside it, and deliberately without the .log the write-ahead logs
 * carry, so nothing scanning the directory for those has to tell it apart from one */
#define ENGINE_LOG_FILENAME "LOG"

/* poll interval while a drop waits out an in-flight compaction on the family being dropped */
#define ENGINE_DROP_QUIESCE_STALL_US 1000

/* the db-level file names under db_path */
#define ENGINE_MANIFEST_FILENAME "MANIFEST"

/* the file whose exclusive lock says which process owns this database directory */
#define ENGINE_LOCK_FILENAME "LOCK"

/* the threadmanager label for the flush worker pool */
#define ENGINE_FLUSH_POOL_LABEL "flush"

/* the WAL block-manager sync mode: only full durability fsyncs each WAL write here. none and
 * interval open the WAL without per-write fsync -- interval batches its durability through the
 * background wal-sync ticker instead */
static int engine_wal_sync_mode(int sync_mode)
{
    return sync_mode == TDB_SYNC_FULL ? BLOCK_MANAGER_SYNC_FULL : BLOCK_MANAGER_SYNC_NONE;
}

/* the WAL's staging ring is this fraction of the write buffer, as a right shift, then clamped. a
 * quarter leaves room for the records in flight while a rotation's worth of data is being written
 * without reserving memory the flush thread will never be that far behind on */
#define ENGINE_WAL_RING_SHIFT 2
#define ENGINE_WAL_RING_MIN   (1ull * 1024 * 1024)
#define ENGINE_WAL_RING_MAX   (16ull * 1024 * 1024)

/**
 * engine_wal_ring_size
 * the staging ring a WAL is opened with. the WAL runs in buffered append mode, where committing
 * threads copy their framed record into this ring and one flush thread does every pwrite, so the
 * ring is what decouples a commit from the write rather than an on-disk reservation. it only has to
 * hold the records in flight between a commit and the flush thread draining them, not the whole
 * memtable, and an appender whose slot is still unflushed waits -- so oversizing it buys nothing
 * and undersizing it turns into backpressure. sized against the write buffer and clamped to keep
 * both ends sane
 * @param db the database, for the configured memtable write buffer size
 * @return the ring capacity in bytes
 */
static uint64_t engine_wal_ring_size(const tidesdb_t *db)
{
    uint64_t ring = (uint64_t)db->config.memtable_write_buffer_size >> ENGINE_WAL_RING_SHIFT;
    if (ring < ENGINE_WAL_RING_MIN) ring = ENGINE_WAL_RING_MIN;
    if (ring > ENGINE_WAL_RING_MAX) ring = ENGINE_WAL_RING_MAX;
    return ring;
}

/**
 * engine_open_wal
 * open a WAL in buffered append mode, whatever the durability. committers reserve ring space with
 * one atomic and copy their own record in parallel, and a single flush thread writes whatever
 * completed as one contiguous run, so the appends coalesce without any of them doing the others'
 * I/O. every sync mode wants that. what the mode changes is where a committer stops waiting --
 * nowhere under none, at the page cache under interval, and at the device under full, which is what
 * each of them promises
 * @param db the database, for the sync mode, the ring sizing and the descriptor accounting
 * @param wal_path the file to open
 * @param out_bm receives the opened block manager
 * @return 0 on success, non-zero on failure
 */
int engine_open_wal(tidesdb_t *db, const char *wal_path, block_manager_t **out_bm)
{
    const int bm_sync = engine_wal_sync_mode(db->config.memtable_sync_mode);
    const int rc = fd_manager_bm_open_buffered(&db->fdm, out_bm, wal_path, bm_sync,
                                               engine_wal_ring_size(db), FD_LABEL_WAL_LOG);
    /* the labelled count is what the reaper and the open budget read, and it only balances if every
     * close pairs with this -- engine_close_wal and the flush path are the only two that may */
    if (rc == 0) fd_manager_note_open(&db->fdm, FD_LABEL_WAL_LOG);
    return rc;
}

int engine_open_wal_sealed(tidesdb_t *db, const char *wal_path, block_manager_t **out_bm)
{
    /* a generation recovered from disk is sealed: replay reads it back, a flush later lands its
     * data in L1, and nothing ever appends to it again -- only the active memtable's log takes
     * writes. opening it in buffered append mode would allocate a staging ring, at least a megabyte
     * of it, and start a flush thread, per recovered generation, and every one of those would sit
     * unused until the generation was flushed. so a sealed log is opened plainly and the buffering
     * is spent only on the active log that actually needs it */
    const int bm_sync = engine_wal_sync_mode(db->config.memtable_sync_mode);
    const int rc = fd_manager_bm_open(&db->fdm, out_bm, wal_path, bm_sync, FD_LABEL_WAL_LOG);
    if (rc == 0) fd_manager_note_open(&db->fdm, FD_LABEL_WAL_LOG);
    return rc;
}

void engine_close_wal(tidesdb_t *db, block_manager_t *wal)
{
    if (!wal) return;
    (void)block_manager_close(wal);
    fd_manager_note_close(&db->fdm, FD_LABEL_WAL_LOG);
}

/* close a log and take its file with it, for one that will never be written to. an unused log left
 * on disk is not inert: the next open scans it, replays it and gives it a memtable in the L0 queue,
 * so it costs work on every open thereafter for records it never held */
void engine_unlink_wal(tidesdb_t *db, block_manager_t *wal)
{
    if (!wal) return;
    char path[MAX_FILE_PATH_LENGTH];
    snprintf(path, sizeof(path), "%s", wal->file_path);
    engine_close_wal(db, wal);
    (void)remove(path);
}

/* the durable-base sync mode for the value log, flush and compaction sstables, and the manifest.
 * both full and interval keep the durable base fsynced -- interval only batches the WAL, never the
 * base -- so a crash in interval mode risks at most the last interval of WAL commits. only none
 * skips it */
int engine_durable_sync_mode(int sync_mode)
{
    return sync_mode == TDB_SYNC_NONE ? BLOCK_MANAGER_SYNC_NONE : BLOCK_MANAGER_SYNC_FULL;
}

/* join db_dir and name into out with the platform separator; fails when the result would not fit */
int engine_build_path(const char *dir, const char *name, char *out, size_t out_size)
{
    const int n = snprintf(out, out_size, "%s%s%s", dir, PATH_SEPARATOR, name);
    return (n > 0 && (size_t)n < out_size) ? TDB_SUCCESS : TDB_ERR_INVALID_ARGS;
}

/* a manifest commit fdatasyncs for both full and interval durability -- the catalog is part of the
 * durable base -- and only skips the fsync under none */
/* the db-level sstable read source: resolve the cf-index to its column family and read that cf's
 * sstable levels, so one source in the stack serves every cf a transaction touches */
static tidesdb_source_result_t engine_sstable_source_get(void *ctx, uint32_t cf_index,
                                                         const uint8_t *key, size_t key_size,
                                                         uint64_t snapshot,
                                                         tidesdb_source_version_t *out)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    cf_t *cf = cf_registry_get_by_id(db->cfs, cf_index);
    if (!cf) return TDB_SOURCE_NOT_FOUND;
    tidesdb_source_t s;
    cf_source(cf, &s);
    return s.get(s.ctx, cf_index, key, key_size, snapshot, out);
}

/* the db-level conflict probe, resolving the cf-index the same way the read source does so a commit
 * asking whether a key changed since its snapshot reaches the per-cf metadata skip */
static tidesdb_source_result_t engine_sstable_source_has_newer(void *ctx, uint32_t cf_index,
                                                               const uint8_t *key, size_t key_size,
                                                               uint64_t seq_floor, int *newer)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    cf_t *cf = cf_registry_get_by_id(db->cfs, cf_index);
    if (!cf) return TDB_SOURCE_NOT_FOUND;
    tidesdb_source_t s;
    cf_source(cf, &s);
    return s.has_newer(s.ctx, cf_index, key, key_size, seq_floor, newer);
}

/* the db-level interval probe, resolving the cf-index the same way the read source does so a commit
 * checking a prefix delete reaches the per-cf metadata skip */
static tidesdb_source_result_t engine_sstable_source_range_has_newer(
    void *ctx, uint32_t cf_index, const uint8_t *lo, size_t lo_size, const uint8_t *hi,
    size_t hi_size, uint64_t seq_floor, int *newer)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    cf_t *cf = cf_registry_get_by_id(db->cfs, cf_index);
    if (!cf) return TDB_SOURCE_NOT_FOUND;
    tidesdb_source_t s;
    cf_source(cf, &s);
    return s.range_has_newer(s.ctx, cf_index, lo, lo_size, hi, hi_size, seq_floor, newer);
}

/* move one value into the shared value log when the database's policy separates it, so its bytes
 * reach the device once rather than once in the log and again in the flush. the threshold is the
 * database's and the opt-out is the family's, which is what cf_config_value_threshold resolves.
 *
 * the family's codec chain travels with the value, the same chain the sstable builder would have
 * given it, so a separated value is compressed wherever it was written and decodes from the chain
 * recorded in its own block rather than from whatever the referencing table happens to carry now.
 * that moves the encode onto the committing thread, where it is latency rather than background work
 */
static int engine_separate_value(void *ctx, const uint32_t cf_index, const uint8_t *value,
                                 const size_t value_size, uint64_t *out_id)
{
    tidesdb_t *db = (tidesdb_t *)ctx;
    if (!db->vlog) return 0;

    /* a family the write names but the registry no longer holds is being dropped; its bytes are
     * going nowhere, so there is nothing to gain by moving them */
    cf_t *cf = cf_registry_get_by_id(db->cfs, cf_index);
    if (!cf) return 0;

    tidesdb_column_family_config_t cc;
    cf_config_get(cf, &cc);
    const size_t threshold = cf_config_value_threshold(&cc, db->config.value_separation_threshold);
    if (threshold == 0 || value_size < threshold) return 0;

    uint64_t id = 0, disk = 0;
    if (vlog_write(db->vlog, value, value_size, cc.encoding_pipeline, cc.encoding_count, &id,
                   &disk) != VLOG_OK)
        return -1;

    *out_id = id;
    return 1;
}

/* whether an sstable already holds a version of this key newer than seq, for the replay filter.
 * it asks the family's sstables directly rather than through the source stack, because during
 * recovery that stack reads the very memtables being rebuilt and would answer in circles. any
 * answer short of a definite yes is reported as no -- applying an entry that was already
 * superseded costs a redundant version, dropping one that was not is data loss */
int engine_replay_superseded(void *ctx, const uint32_t cf_index, const uint8_t *key,
                             const size_t key_size, const uint64_t seq)
{
    int newer = 0;
    if (engine_sstable_source_has_newer(ctx, cf_index, key, key_size, seq, &newer) !=
        TDB_SOURCE_FOUND)
        return 0;
    return newer;
}

/* create the shared L0 subsystem with no memtable yet -- the WAL recovery installs the active one
 */
static int engine_create_l0(tidesdb_t *db)
{
    db->l0 = tidesdb_l0_create(db->config.memtable_write_buffer_size,
                               db->config.memtable_l0_queue_stall_threshold,
                               db->config.memtable_skip_list_max_level,
                               db->config.memtable_skip_list_probability, NULL, NULL);
    if (!db->l0) return TDB_ERR_MEMORY;

    /* none is the mode that asks for nothing at commit, so its appends stop at the ring. interval
     * and full both promise an acknowledged commit has left this process, so they wait for it */
    tidesdb_l0_set_wal_ack_on_stage(db->l0, db->config.memtable_sync_mode == TDB_SYNC_NONE);
    return TDB_SUCCESS;
}

/* reference every sstable across all cfs into a freshly allocated array; the caller holds the
 * registry read lock, unrefs each, and frees the array. returns the count, or -1 on allocation
 * failure */
int engine_collect_sstables(tidesdb_t *db, sstable_t ***out)
{
    *out = NULL;
    const int ncf = cf_registry_count_locked(db->cfs);
    int total = 0;
    for (int i = 0; i < ncf; i++)
        total += level_set_collect_all(cf_registry_at_locked(db->cfs, i)->levels, NULL, 0);
    if (total == 0) return 0;
    sstable_t **arr = malloc((size_t)total * sizeof(*arr));
    if (!arr) return -1;
    int k = 0;
    for (int i = 0; i < ncf; i++)
    {
        cf_t *cf = cf_registry_at_locked(db->cfs, i);
        const int got = level_set_collect_all(cf->levels, arr + k, total - k);
        /* collect_all references only when the level's count fits the remaining room; a level that
         * grew since the first pass references nothing and is picked up on the next tick */
        if (got > 0 && got <= total - k) k += got;
    }
    *out = arr;
    return k;
}

/* route the engine's log into the database directory when the configuration asks for it. the sink
 * is process-wide rather than per-database, so the last database opened with log_to_file owns it
 * and every other handle in the process logs there too; the flag records which handle installed it
 * so only that one takes it away again. a file that cannot be opened leaves output on stderr, since
 * failing an open over a log destination would be worse than the missing file */
static void engine_open_log_sink(tidesdb_t *db)
{
    if (!db->config.log_to_file) return;

    char path[ENGINE_PATH_BUF_SIZE];
    if (engine_build_path(db->db_path, ENGINE_LOG_FILENAME, path, sizeof(path)) != TDB_SUCCESS)
        return;

    FILE *sink = fopen(path, "a");
    if (!sink)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "could not open %s, logging stays on stderr", path);
        return;
    }
    tidesdb_log_set_sink(sink, db->config.log_truncation_at, path);
    db->owns_log_sink = 1;
}

/**
 * engine_open_init
 * establish the database's identity before anything is opened under it -- the config copy the db
 * owns, the log gate the configured severity drives, the id sequences, and the directory itself
 * @param db the zeroed database
 * @param config the caller's configuration, copied
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO if the directory could not be created
 */
static int engine_open_init(tidesdb_t *db, const tidesdb_config_t *config)
{
    db->config = *config;

    /* the configured severity drives the log gate, which otherwise keeps its build-time default and
     * leaves an embedder no way to quiet the engine down or turn tracing up */
    atomic_store_explicit(&_tidesdb_log_level, (int)config->log_level, memory_order_relaxed);

    db->db_path = strdup(config->db_path);
    if (!db->db_path) return TDB_ERR_MEMORY;
    db->config.db_path = db->db_path;
    atomic_init(&db->next_sstable_id, ENGINE_FIRST_SSTABLE_ID);
    atomic_init(&db->wal_generation, ENGINE_FIRST_WAL_GENERATION);
    atomic_init(&db->closing, 0);
    atomic_init(&db->prepare_gen_floor, UINT64_MAX);

    /* the database directory must exist; an already-present directory is not an error */
    if (mkdir(db->db_path, ENGINE_DB_DIR_MODE) != 0 && errno != EEXIST) return TDB_ERR_IO;

    engine_open_log_sink(db);
    return TDB_SUCCESS;
}

/**
 * engine_open_stores
 * open the db-level stores every column family shares -- the block cache, the descriptor budget,
 * the arena pool, the manifest, and the value log
 * @param db the database, already through engine_open_init
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, TDB_ERR_IO, or TDB_ERR_INVALID_ARGS on an unformattable path
 */
static int engine_open_stores(tidesdb_t *db)
{
    const cache_config_t cc = {.capacity_bytes = db->config.block_cache_size};
    db->cache = cache_create(&cc);
    if (!db->cache) return TDB_ERR_MEMORY;

    /* the budget is cut to what this process can actually hold open. the default cap and the usual
     * POSIX default ceiling are both 1024, so a database left at its defaults would otherwise
     * budget every descriptor the process has and leave none for the manifest, stdio or a
     * temporary -- and meet the ceiling as an EMFILE it retries its way out of one open at a time,
     * rather than as a budget it never spent. said at warn because it is the configuration that is
     * wrong, and the operator who wants the larger budget raises the ceiling and opens again */
    const int configured = (int)db->config.max_open_sstables;
    const long ceiling = tdb_max_open_files_exact();
    const int budget = fd_manager_budget_for_process(configured, ceiling);
    if (budget != configured)
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "max open sstables %d does not fit this process's open-file ceiling of %ld, "
                      "running with %d",
                      configured, ceiling, budget);

    if (fd_manager_init(&db->fdm, budget) != 0) return TDB_ERR_MEMORY;
    db->fdm_inited = 1;

    /* seeded here rather than left to the ticker, because recovery opens sstables and builds
     * memtables long before the reaper starts and they all read this clock. a zero would tell every
     * one of them no entry has ever expired, and would stamp each sstable's last access at the
     * epoch -- which inverts the descriptor reaper, whose victim is the least recently used */
    atomic_store_explicit(&db->now_seconds, (int64_t)time(NULL), memory_order_relaxed);

    db->arena = arena_pool_create(ENGINE_ARENA_CHUNK_SIZE, ENGINE_ARENA_MAX_CACHED);
    db->node_arena = arena_pool_create(ENGINE_NODE_ARENA_CHUNK_SIZE, ENGINE_NODE_ARENA_MAX_CACHED);
    if (!db->arena) return TDB_ERR_MEMORY;

    /* the registry every family's encoding ids resolve against. it is built here rather than left
     * empty because an id names nothing without it, and a family configured with a pipeline would
     * otherwise fail to build an sstable at all */
    if (tidesdb_encoding_registry_init(&db->encodings) != TDB_SUCCESS) return TDB_ERR_MEMORY;

    char path[ENGINE_PATH_BUF_SIZE];

    /* taken before the manifest is touched, so a second process is refused rather than allowed to
     * begin recovering a database another one already owns */
    if (engine_build_path(db->db_path, ENGINE_LOCK_FILENAME, path, sizeof(path)) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;
    int lock_rc = TDB_LOCK_ERROR;
    db->lock_fd = tdb_open_lock_file(path, &lock_rc);
    /* the open is what refuses a second handle in this same process, on the platforms whose locks
     * belong to the process rather than to the descriptor and so would grant it one. it reports
     * that by failing, so the reason has to be read here rather than assumed to be the disk */
    if (db->lock_fd < 0) return lock_rc == TDB_LOCK_HELD ? TDB_ERR_LOCKED : TDB_ERR_IO;
    lock_rc = tdb_file_lock_exclusive(db->lock_fd, 0);
    if (lock_rc != TDB_LOCK_SUCCESS)
    {
        (void)tdb_file_close(db->lock_fd);
        db->lock_fd = -1;
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "database %s is open in another process", db->db_path);
        return lock_rc == TDB_LOCK_HELD ? TDB_ERR_LOCKED : TDB_ERR_IO;
    }

    if (engine_build_path(db->db_path, ENGINE_MANIFEST_FILENAME, path, sizeof(path)) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;
    db->manifest = tidesdb_manifest_open(path);
    if (!db->manifest) return TDB_ERR_IO;

    /* the store holds no codec of its own; each value records the one its family wrote it with */
    const vlog_config_t vc = {.encodings = &db->encodings,
                              .sync_mode = engine_durable_sync_mode(db->config.memtable_sync_mode),
                              .segment_target_bytes = db->config.vlog_segment_size,
                              .fdm = db->fdm_inited ? &db->fdm : NULL};
    if (vlog_open(db->db_path, &vc, &db->vlog) != VLOG_OK) return TDB_ERR_IO;
    return TDB_SUCCESS;
}

/**
 * engine_open_reseed
 * seed the sequence clock past the highest sequence any durable record holds -- the persisted
 * manifest sequence, the replayed WAL high-water, the newest sequence in any recovered sstable, and
 * any sequence a still-in-doubt transaction reserved -- so neither a clean close nor a crash can
 * reissue or filter out a committed sequence. a flush that retires an immutable and unlinks its WAL
 * leaves that sstable as the only record of its sequences, so a crash before a clean close relies
 * on the sstable high-water here, and an in-doubt sequence no record applied must be cleared too or
 * a new writer would be handed the sequence the coordinator may yet commit at
 * @param db the database, after cf and WAL recovery
 * @param wal_max_seq the highest sequence WAL replay applied
 */
static void engine_open_reseed(tidesdb_t *db, uint64_t wal_max_seq)
{
    const uint64_t manifest_seq =
        atomic_load_explicit(&db->manifest->sequence, memory_order_acquire);
    const uint64_t sstable_seq = engine_recovered_max_sstable_seq(db);
    const uint64_t prepared_seq = tdb_prepare_stage_max_seq(db->prepared);
    uint64_t reseed = wal_max_seq;
    if (manifest_seq > reseed) reseed = manifest_seq;
    if (sstable_seq > reseed) reseed = sstable_seq;
    if (prepared_seq > reseed) reseed = prepared_seq;
    TDB_DEBUG_LOG(TDB_LOG_TRACE,
                  "clock reseed to %llu (wal %llu manifest %llu sstable %llu prepared %llu)",
                  (unsigned long long)reseed, (unsigned long long)wal_max_seq,
                  (unsigned long long)manifest_seq, (unsigned long long)sstable_seq,
                  (unsigned long long)prepared_seq);
    tidesdb_mvcc_reseed(db->clock, reseed);

    /* nothing before this open is reconstructable. what an earlier run collected is not recorded
     * anywhere -- the sstables hold whatever survived it -- so the oldest readable point starts at
     * the sequence recovery resumed from rather than at zero, which would claim every sequence this
     * database ever issued can still be read exactly */
    atomic_store_explicit(&db->gc_floor_high_water, reseed, memory_order_release);
}

/**
 * engine_open_recover
 * bring the write side back -- the sequence clock, the shared L0, the cf registry rebuilt from the
 * manifest, and every surviving WAL generation replayed as an immutable behind a fresh active
 * @param db the database, already through engine_open_stores
 * @param out_recovered receives the number of recovered generations awaiting flush
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or a recovery failure code
 */
static int engine_open_recover(tidesdb_t *db, int *out_recovered)
{
    db->clock = tidesdb_mvcc_create();
    if (!db->clock) return TDB_ERR_MEMORY;

    /* the shared unified memtable subsystem, before recovery observes cf-indices into its allocator
     */
    int rc = engine_create_l0(db);
    if (rc != TDB_SUCCESS) return rc;

    /* every memtable this subsystem makes may receive a reference, and each holds a value log floor
     * over the segments only it names until its flush installs */
    tidesdb_l0_set_vlog(db->l0, db->vlog);

    /* rebuild the cf registry from the manifest (empty on a fresh db) and seed the id sequences */
    rc = engine_recover_cfs(db);
    if (rc != TDB_SUCCESS) return rc;

    db->prepared = tdb_prepare_stage_create();
    if (!db->prepared) return TDB_ERR_MEMORY;

    /* before the workers start, so no file being written right now can be mistaken for an orphan */
    (void)engine_sweep_orphan_sstables(db);

    uint64_t wal_max_seq = 0;
    rc = engine_recover_wal(db, out_recovered, &wal_max_seq, db->prepared);
    if (rc != TDB_SUCCESS) return rc;

    engine_open_reseed(db, wal_max_seq);
    return TDB_SUCCESS;
}

/**
 * engine_open_txn
 * wire the transaction side -- the commit backend and the db-level read source stack over L0 then
 * the per-cf sstable levels, the in-doubt transactions recovery adopted, and the txn registry
 * @param db the database, already through engine_open_recover
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or a settle failure code
 */
static int engine_open_txn(tidesdb_t *db)
{
    if (tidesdb_l0_adapter_init(&db->l0_ctx, db->l0, db->vlog) != 0) return TDB_ERR_MEMORY;
    db->l0_ctx_inited = 1;
    tidesdb_l0_backend(&db->l0_ctx, &db->backend);
    /* the separator is the engine's rather than the adapter's, since the policy needs the family
     * registry and the adapter is deliberately kept clear of it */
    db->backend.separator.separate = engine_separate_value;
    db->backend.separator.ctx = db;
    tidesdb_l0_source(&db->l0_ctx, &db->sources[0]);
    db->sources[1].name = "cf_sstable_dispatch";
    db->sources[1].get = engine_sstable_source_get;
    db->sources[1].has_newer = engine_sstable_source_has_newer;
    db->sources[1].range_has_newer = engine_sstable_source_range_has_newer;
    db->sources[1].ctx = db;

    const int settle_rc = engine_note_prepared_in_doubt(db);
    if (settle_rc != TDB_SUCCESS) return settle_rc;

    db->txn_registry = tidesdb_txn_registry_create();
    if (!db->txn_registry) return TDB_ERR_MEMORY;
    return TDB_SUCCESS;
}

/**
 * engine_open_threads
 * start the flush worker pool over its wake queue and take the locks the write path serializes on
 * -- rotation, the retained-WAL set, flush claiming, and ordered install
 * @param db the database, already through engine_open_txn
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY on a lock, queue, or pool failure
 */
static int engine_open_threads(tidesdb_t *db)
{
    db->threads = threadmanager_new();
    if (!db->threads) return TDB_ERR_MEMORY;

    if (pthread_mutex_init(&db->rotate_lock, NULL) != 0) return TDB_ERR_MEMORY;
    db->rotate_lock_inited = 1;
    pthread_mutex_init(&db->retained_wals_lock, NULL);
    db->prepare_vlog_token = VLOG_BUILD_TOKEN_NONE;
    if (pthread_mutex_init(&db->flush_lock, NULL) != 0) return TDB_ERR_MEMORY;
    db->flush_lock_inited = 1;
    if (pthread_mutex_init(&db->install_lock, NULL) != 0) return TDB_ERR_MEMORY;
    if (pthread_cond_init(&db->install_cv, NULL) != 0)
    {
        pthread_mutex_destroy(&db->install_lock);
        return TDB_ERR_MEMORY;
    }
    db->install_lock_inited = 1;
    atomic_init(&db->flush_claim_seq, 0);
    db->flush_install_seq = 0;

    db->flush_queue = queue_new();
    if (!db->flush_queue) return TDB_ERR_MEMORY;
    bg_pool_t *flush_pool = bg_pool_start_named(db->config.num_flush_threads, db->flush_queue,
                                                ENGINE_FLUSH_POOL_LABEL, engine_flush_worker, db);
    if (!flush_pool ||
        threadmanager_add_pool(db->threads, ENGINE_FLUSH_POOL_LABEL, flush_pool) != 0)
    {
        if (flush_pool) bg_pool_stop(flush_pool);
        return TDB_ERR_MEMORY;
    }
    return TDB_SUCCESS;
}

int engine_open(const tidesdb_config_t *config, tidesdb_t **out)
{
    if (!config || !config->db_path || config->db_path[0] == '\0' || !out)
        return TDB_ERR_INVALID_ARGS;

    tidesdb_t *db = calloc(1, sizeof(*db));
    if (!db) return TDB_ERR_MEMORY;
    /* zero is a descriptor a close would happily act on, so the unheld state is stated explicitly
     */
    db->lock_fd = -1;

    /* each stage leaves whatever it opened on db, so one engine_close unwinds however far this got
     */
    int recovered = 0;
    int rc = engine_open_init(db, config);
    if (rc == TDB_SUCCESS) rc = engine_open_stores(db);
    if (rc == TDB_SUCCESS) rc = engine_open_recover(db, &recovered);
    if (rc == TDB_SUCCESS) rc = engine_open_txn(db);
    if (rc == TDB_SUCCESS) rc = engine_open_threads(db);
    if (rc == TDB_SUCCESS) rc = engine_compaction_init(db);
    if (rc == TDB_SUCCESS) rc = engine_reaper_init(db);
    if (rc != TDB_SUCCESS)
    {
        engine_close(db);
        return rc;
    }

    /* wake the pool once per recovered immutable so the recovered generations flush to L1 */
    for (int i = 0; i < recovered; i++) (void)queue_enqueue(db->flush_queue, db);

    db->opened = 1;
    TDB_DEBUG_LOG(TDB_LOG_INFO, "opened %s with %d recovered generations to flush",
                  db->config.db_path, recovered);
    *out = db;
    return TDB_SUCCESS;
}

void engine_close(tidesdb_t *db)
{
    if (!db) return;
    const int owned_log_sink = db->owns_log_sink;
    atomic_store_explicit(&db->closing, 1, memory_order_release);

    /* the last line a clean shutdown leaves; a log that ends without it was a crash or a kill,
     * which is what an operator reading it back needs to be able to tell */
    if (db->opened) TDB_DEBUG_LOG(TDB_LOG_INFO, "closing %s", db->config.db_path);

    /* dependency order: stop the workers, tear down the txn/l0 write path, then the cfs (which
     * borrow the vlog), then the shared singletons, then the leaf resources */
    /* dropped before the reaper it names is stopped, so a descriptor wait raced against the close
     * finds nothing to call rather than a ticker that is going away */
    fd_manager_set_reaper_wake(&db->fdm, NULL, NULL);
    db->fd_reaper = NULL;
    if (db->threads)
        threadmanager_stop_all(db->threads); /* stops every process and frees the registry */

    /* persist the clock high-water so a clean reopen resumes the sequence past every committed
     * write */
    if (db->opened && db->clock && db->manifest)
    {
        const uint64_t seq = tidesdb_mvcc_current_seq(db->clock);
        tidesdb_manifest_update_sequence(db->manifest, seq);
        /* a failure here is not fatal to the close, but it is not free either -- the next open
         * reseeds the clock from the WAL, the manifest and the sstables, so it recovers a sequence
         * rather than resuming this one, and an operator should know the cheap path was missed */
        if (tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_durable_writes(db)) !=
            0)
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "could not persist the clock at %llu on close, the next open reseeds it",
                          (unsigned long long)seq);
    }

    if (db->l0_ctx_inited)
    {
        /* drain the immutable queue the l0 requires empty: flush each to L1 on a clean close, or
         * reclaim them on a failed open where the data stays durable in their WALs. done before
         * cf_registry_destroy since a flush reads the cfs, and after the workers are stopped, which
         * is what lets the drain hand out install tickets without synchronising */
        engine_drain_immutables(db, db->opened);
    }

    /* free any compaction jobs still queued (the workers are stopped); frees the queue */
    engine_compaction_drain(db);

    if (db->txn_registry) tidesdb_txn_registry_destroy(db->txn_registry);
    /* an unresolved prepared batch is durable in the log, so dropping the staged copy here loses
     * nothing -- the next open stages it again from the same records */
    tdb_prepare_stage_free(db->prepared);
    if (db->l0) tidesdb_l0_destroy(db->l0); /* frees the active memtable */
    engine_close_wal(db, db->wal_bm);
    if (db->flush_queue) queue_free(db->flush_queue);

    if (db->cfs) cf_registry_destroy(db->cfs);
    if (db->clock) tidesdb_mvcc_destroy(db->clock);
    /* a prepared log that was never rotated into holds nothing and never will, so it goes with the
     * database rather than waiting on disk for an open that would replay it for no records */
    block_manager_t *spare = atomic_exchange_explicit(&db->spare_wal, NULL, memory_order_acquire);
    engine_unlink_wal(db, spare);

    if (db->vlog) vlog_close(db->vlog);
    if (db->manifest) tidesdb_manifest_close(db->manifest);

    /* released last, so nothing this handle owns is still being written when another process is
     * allowed to take the directory */
    if (db->lock_fd >= 0)
    {
        (void)tdb_file_unlock(db->lock_fd);
        (void)tdb_file_close(db->lock_fd);
        db->lock_fd = -1;
    }
    if (db->arena) arena_pool_destroy(db->arena);
    if (db->fdm_inited) fd_manager_destroy(&db->fdm);
    if (db->cache) cache_destroy(db->cache);
    /* after the cache, never before it: every cached btree node holds an arena drawn from this
     * pool, and the cache returns those chunks as it reclaims each node on the way down */
    if (db->node_arena) arena_pool_destroy(db->node_arena);
    if (db->rotate_lock_inited)
    {
        pthread_mutex_destroy(&db->rotate_lock);
        pthread_mutex_destroy(&db->retained_wals_lock);
    }
    for (int i = 0; i < db->n_retained_wals; i++) free(db->retained_wals[i].path);
    free(db->retained_wals);
    free(db->prepare_gens);
    if (db->flush_lock_inited) pthread_mutex_destroy(&db->flush_lock);
    if (db->install_lock_inited)
    {
        pthread_mutex_destroy(&db->install_lock);
        pthread_cond_destroy(&db->install_cv);
    }
    free(db->db_path);
    free(db);

    /* last, so every line this teardown wrote still reached the file. only the handle that
     * installed the sink takes it away, since it is process-wide and another database may still be
     * logging through it */
    if (owned_log_sink) tidesdb_log_close_sink();
}

int engine_create_cf(tidesdb_t *db, const char *name, const tidesdb_column_family_config_t *config)
{
    if (!db || !name || name[0] == '\0' || !config) return TDB_ERR_INVALID_ARGS;
    if (atomic_load_explicit(&db->closing, memory_order_acquire)) return TDB_ERR_INVALID_DB;
    if (cf_registry_get_by_name(db->cfs, name)) return TDB_ERR_EXISTS;

    /* the name argument is authoritative, so stamp it onto the config the cf and its blob carry */
    tidesdb_column_family_config_t cfg = *config;
    snprintf(cfg.name, sizeof(cfg.name), "%s", name);

    cf_config_warn_layout(&cfg, db->config.value_separation_threshold);

    const uint64_t cf_id = cf_registry_next_cf_id(db->cfs);
    if (cf_id > TDB_CF_INDEX_MAX)
    {
        /* said at error because nothing an operator does clears it -- the counter never goes back,
         * so this database can hold the families it has and create no more */
        TDB_DEBUG_LOG(
            TDB_LOG_ERROR,
            "cannot create %s, this database has used every column family id the memtable "
            "key prefix can carry",
            name);
        return TDB_ERR_TOO_LARGE;
    }

    cf_t *cf = NULL;
    if (cf_create(db->db_path, cf_id, &cfg, &db->encodings, db->vlog, db->cache, &db->fdm,
                  db->node_arena, &db->now_seconds, &cf) != 0)
        return TDB_ERR_INVALID_ARGS;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (cf_config_serialize(&cfg, &blob, &blob_len) != 0)
    {
        cf_free(cf);
        return TDB_ERR_MEMORY;
    }

    /* persist durably before publishing in memory, so a crash cannot leave a live cf the manifest
     * does not know about */
    int rc = TDB_SUCCESS;
    if (tidesdb_manifest_add_cf(db->manifest, cf_id, name, blob, blob_len) != 0 ||
        tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_durable_writes(db)) != 0)
        rc = TDB_ERR_IO;
    free(blob);
    if (rc != TDB_SUCCESS)
    {
        cf_free(cf);
        return rc;
    }

    if (cf_registry_add(db->cfs, cf) != TDB_SUCCESS)
    {
        /* the cf is durable and will recover on reopen; drop the in-memory handle */
        cf_free(cf);
        return TDB_ERR_MEMORY;
    }
    tidesdb_l0_bind_cf_counter(db->l0, (uint32_t)cf->cf_id, &cf->unflushed_key_count);
    TDB_DEBUG_LOG(TDB_LOG_INFO, "cf %s created with id %llu", name, (unsigned long long)cf_id);

    /* honor a commit hook supplied in the create config, registering it on the gate counter */
    if (config->commit_hook_fn)
        (void)engine_cf_set_commit_hook(db, cf, config->commit_hook_fn, config->commit_hook_ctx);
    return TDB_SUCCESS;
}

int engine_drop_cf(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    cf_t *cf = NULL;
    const int rc = cf_registry_remove(db->cfs, name, &cf);
    if (rc != TDB_SUCCESS) return rc;

    /* the cf is out of the registry so the scheduler starts no new compaction for it; wait out any
     * compaction already in flight before freeing the handle it holds */
    while (atomic_load_explicit(&cf->compacting, memory_order_acquire))
        usleep(ENGINE_DROP_QUIESCE_STALL_US);

    /* clear any commit hook so the db-level gate counter stays exact once the handle is gone */
    if (atomic_load_explicit(&cf->commit_hook_fn, memory_order_acquire))
        (void)engine_cf_set_commit_hook(db, cf, NULL, NULL);

    /* stop the l0 attributing keys to this family's counter before its handle is freed */
    tidesdb_l0_bind_cf_counter(db->l0, (uint32_t)cf->cf_id, NULL);

    /* the handle is freed below, so capture what the teardown needs first */
    const uint64_t cf_id = cf->cf_id;

    /* where the family's files live, which is the database directory itself. it is emphatically not
     * something to delete: a family is a set of files the manifest names, not a place */
    char dir[CF_DIR_PATH_LEN];
    snprintf(dir, sizeof(dir), "%s", cf->dir);

    /* which files this family owns, taken while the manifest still names them. deleting by
     * directory instead would be shorter, and wrong the moment a family stops being a directory of
     * its own -- the sweep would take whatever else lived beside it */
    int n_files = tidesdb_manifest_copy_entries(db->manifest, cf_id, NULL, 0);
    tidesdb_manifest_entry_t *files = NULL;
    if (n_files > 0)
    {
        files = calloc((size_t)n_files, sizeof(*files));
        if (!files)
            n_files = 0;
        else
            n_files = tidesdb_manifest_copy_entries(db->manifest, cf_id, files, n_files);
    }

    int result = TDB_SUCCESS;
    if (tidesdb_manifest_drop_cf(db->manifest, cf_id) != 0 ||
        tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_durable_writes(db)) != 0)
        result = TDB_ERR_IO;

    TDB_DEBUG_LOG(TDB_LOG_INFO, "cf %s dropped, id %llu retired", name, (unsigned long long)cf_id);
    cf_free(cf); /* closes the cf's sstables */

    /* the manifest no longer names them, so a file left behind here is unreachable rather than
     * dangerous: the next open cannot adopt what nothing points at */
    for (int i = 0; i < n_files; i++)
    {
        char filename[ENGINE_PATH_BUF_SIZE], path[ENGINE_PATH_BUF_SIZE];
        if (sstable_klog_filename(&files[i], filename, sizeof(filename)) != TDB_SUCCESS) continue;
        if (snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, filename) >=
            (int)sizeof(path))
            continue;
        (void)remove(path);
    }
    free(files);

    return result;
}

cf_t *engine_get_cf(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;
    return cf_registry_get_by_name(db->cfs, name);
}
