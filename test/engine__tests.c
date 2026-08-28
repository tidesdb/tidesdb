/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "../src/column_family/column_family.h" /* cf_t, for level inspection */
#include "../src/column_family/level/level_set.h"
#include "../src/engine/engine.h"          /* engine_vlog_gc, for a direct value-log reclaim */
#include "../src/engine/engine_internal.h" /* ENGINE_FIRST_WAL_GENERATION */
#include "../src/engine/engine_types.h"    /* the inner txn a prefix delete is buffered on */
#include "../src/txn/txn.h"                /* tdb_txn_delete_prefix, not yet a public call */
#include "db.h"
#include "test_utils.h"

/* the E1 engine skeleton: open assembles the db-level singletons, the mvcc clock, an empty cf
 * registry, and the worker registry; close tears them down in order. these tests drive the public
 * open/close facade over a fresh and a reopened database, argument validation, and config defaults.
 */

static int tests_passed = 0;
static int tests_failed = 0;

#define ENGINE_TEST_DB_DIR "." PATH_SEPARATOR "test_engine_db"

/* a value-log segment small enough that a few dozen spilled values roll past it, and the number of
 * such values to write, so the store must open more than the one segment it starts with */
#define ENGINE_TEST_VLOG_SEGMENT_SIZE (64u * 1024)
#define ENGINE_TEST_VLOG_SEGMENT_KEYS 200

/* the transaction id an undecided prepare is left under, to pin the log generation holding it */
#define ENGINE_TEST_PIN_XID "pin-the-generation"
/* the transaction that prepares and then decides, so its batch is durable as a COMMIT record */
#define ENGINE_TEST_DECIDED_XID "decided-in-two-phases"

/* a value log entry planted straight into a memtable, standing in for a commit that separated its
 * value, since nothing on the commit path produces one yet */
#define ENGINE_TEST_PLANTED_VALUE_SIZE 4096
#define ENGINE_TEST_PLANTED_SEQ        1

/* a separation threshold and a value comfortably above it, for the family that opts out of
 * separation and the one that does not */
#define ENGINE_TEST_SEPARATION_THRESHOLD 512
#define ENGINE_TEST_SEPARATED_VALUE_SIZE 2048
#define ENGINE_TEST_SEPARATED_KEYS       64

/* an encoding id past every defined compression algorithm, for the rejection path */
#define ENGINE_TEST_UNKNOWN_ENCODING_ID 200

/* a call that claims a column family reports locked rather than waiting when a background
 * compaction holds it, so a test driving one retries the way a caller must */
/* the reclamation floor is read and used in two calls, and a flush between them raises it. it only
 * ever rises and this test writes nothing while retrying, so a couple of attempts always settle */
#define ENGINE_OLDEST_READABLE_RETRIES 16

#define ENGINE_TEST_LOCKED_RETRIES    100
#define ENGINE_TEST_LOCKED_BACKOFF_US 1000
#define ENGINE_TEST_COMPACT_KEYS      400
#define ENGINE_TEST_PATH_MAX          512
/* the first family's directory, named for its id, so a test can name its files by literal */
/* a family's key logs sit in the database directory, their names carrying which family they belong
 * to, so the first family's files are found by prefix rather than by a directory of its own */
#define ENGINE_TEST_CF0_DIR    ENGINE_TEST_DB_DIR
#define ENGINE_TEST_CF0_PREFIX "0000000000."
/* the block manager's preallocation chunk, the extent an untrimmed build would occupy */
#define ENGINE_TEST_PREALLOC_CHUNK (64u * 1024 * 1024)
/* room for per-file headers and footers over the data the stats report */
#define ENGINE_TEST_TRIM_SLACK         2
#define ENGINE_TEST_RECLAIM_TICKS      50
#define ENGINE_TEST_RECLAIM_STALL_US   100000
#define ENGINE_TEST_ORPHAN_KEYS        6000
#define ENGINE_TEST_ORPHAN_FLUSH_EVERY 500
#define ENGINE_TEST_LOG_TRUNCATE_AT    2048
#define ENGINE_TEST_LOG_ROUNDS         60
#define ENGINE_TEST_SCHED_TICKS        60
#define ENGINE_TEST_SCHED_STALL_US     100000
#define ENGINE_TEST_IDLE_KEYS          5
#define ENGINE_TEST_IDLE_TICKS         80
#define ENGINE_TEST_IDLE_STALL_US      100000
#define ENGINE_TEST_WAL_PIN_ROUNDS     6
/* the generation holding the prepare, the active one, and one for the rotation in flight */
#define ENGINE_TEST_WAL_PIN_ALLOWED 3

/* a config pointing at the test directory, otherwise defaulted */
static tidesdb_config_t engine_test_config(char *db_path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = db_path;
    return cfg;
}

/* opening a fresh directory assembles the engine and returns a handle, and close frees it cleanly
 */
void test_engine_open_close(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a database reopens over its existing manifest and value log */
void test_engine_reopen(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS); /* reads the existing MANIFEST and VLOG */
    ASSERT_TRUE(db != NULL);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* bad arguments are rejected without creating anything */
void test_engine_rejects_bad_args(void)
{
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(NULL, &db), TDB_ERR_INVALID_ARGS);

    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, NULL), TDB_ERR_INVALID_ARGS);

    tidesdb_config_t no_path = engine_test_config(NULL);
    ASSERT_EQ(tidesdb_open(&no_path, &db), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(NULL), TDB_ERR_INVALID_ARGS);
}

/* the default config carries sane, non-zero values for the auto-resolved fields */
void test_engine_default_config(void)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    ASSERT_TRUE(cfg.db_path == NULL); /* the caller must set the directory */
    ASSERT_TRUE(cfg.num_flush_threads > 0);
    ASSERT_TRUE(cfg.num_compaction_threads > 0);
    ASSERT_TRUE(cfg.block_cache_size > 0);
    ASSERT_TRUE(cfg.max_open_sstables > 0);
    ASSERT_TRUE(cfg.memtable_write_buffer_size > 0);
    ASSERT_TRUE(cfg.memtable_skip_list_max_level > 0);
    ASSERT_TRUE(cfg.memtable_skip_list_probability > 0.0f);
}

/* creating a column family succeeds once, and a duplicate name is rejected */
void test_engine_create_column_family(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cf = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "users", &cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "users", &cf), TDB_ERR_EXISTS);
    ASSERT_EQ(tidesdb_create_column_family(db, "orders", &cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* column families recover from the manifest on reopen -- proven by a recreate returning EXISTS */
void test_engine_cf_recovery(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cf = tidesdb_default_column_family_config();

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "users", &cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "orders", &cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "users", &cf), TDB_ERR_EXISTS);  /* recovered */
    ASSERT_EQ(tidesdb_create_column_family(db, "orders", &cf), TDB_ERR_EXISTS); /* recovered */
    ASSERT_EQ(tidesdb_create_column_family(db, "fresh", &cf), TDB_SUCCESS);     /* a new one */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* dropping a column family frees the name for reuse and persists across a reopen */
void test_engine_drop_column_family(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cf = tidesdb_default_column_family_config();

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "temp", &cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_drop_column_family(db, "temp"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_drop_column_family(db, "temp"), TDB_ERR_NOT_FOUND);  /* already gone */
    ASSERT_EQ(tidesdb_create_column_family(db, "temp", &cf), TDB_SUCCESS); /* name reusable */
    ASSERT_EQ(tidesdb_drop_column_family(db, "missing"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the drop and the recreate both persisted: only "temp" exists on reopen */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "temp", &cf), TDB_ERR_EXISTS);
    ASSERT_EQ(tidesdb_drop_column_family(db, "temp"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "temp", &cf), TDB_SUCCESS); /* drop persisted */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a column family id is never handed out twice, even when the family holding the largest id is
 * dropped and the database reopens. reissuing it would let that family's unreaped wal records
 * replay into whichever family later took the id, resurrecting its keys there */
void test_engine_cf_id_not_reused_after_drop_reopen(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cfc = tidesdb_default_column_family_config();

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "keep", &cfc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "doomed", &cfc), TDB_SUCCESS);
    const uint64_t doomed_id = engine_get_cf(db, "doomed")->cf_id;
    const uint64_t keep_id = engine_get_cf(db, "keep")->cf_id;
    ASSERT_TRUE(doomed_id > keep_id); /* the dropped family holds the largest id */
    ASSERT_EQ(tidesdb_drop_column_family(db, "doomed"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* on reopen the surviving family is the largest id on disk, so an allocator derived from the
     * survivors alone would hand the dropped id straight back out */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "fresh", &cfc), TDB_SUCCESS);
    ASSERT_TRUE(engine_get_cf(db, "fresh")->cf_id != doomed_id);
    ASSERT_TRUE(engine_get_cf(db, "fresh")->cf_id > doomed_id);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* open a db with one column family "kv" and hand back the db and the cf handle */
/* wait for the family's compaction claim to clear. a flush wakes the compaction scheduler by
 * design, and the backstop tick claims every idle family while it plans, so the flag reads set
 * transiently for reasons that have nothing to do with the merge under test -- sampling it once
 * races that */
static int engine_test_await_not_compacting(tidesdb_column_family_t *cf)
{
    for (int attempt = 0; attempt < ENGINE_TEST_LOCKED_RETRIES; attempt++)
    {
        if (tidesdb_is_compacting(cf) == 0) return 1;
        usleep(ENGINE_TEST_LOCKED_BACKOFF_US);
    }
    return 0;
}

/* force a compaction, retrying while the family is claimed. a synchronous compact reports locked
 * rather than waiting when the scheduler holds the claim, and a flush wakes that scheduler, so a
 * compact driven straight after a flush meets it routinely -- which is the contract a caller has to
 * honour rather than something the test may assume away */
static int engine_test_compact(tidesdb_t *db, tidesdb_column_family_t *cf)
{
    int rc = TDB_ERR_LOCKED;
    for (int attempt = 0; attempt < ENGINE_TEST_LOCKED_RETRIES && rc == TDB_ERR_LOCKED; attempt++)
    {
        rc = tidesdb_compact(db, cf);
        if (rc == TDB_ERR_LOCKED) usleep(ENGINE_TEST_LOCKED_BACKOFF_US);
    }
    return rc;
}

/* reconfigure a family, retrying while it is claimed. the update takes the family's claim so that
 * no two reconfigures or ddl operations run on it at once, and reports locked rather than waiting
 * when it cannot have it -- and the compaction scheduler's backstop tick claims every idle family
 * while it plans. so a reconfigure meets that claim for reasons that have nothing to do with what
 * it is changing, and on a busy runner it meets it often. the caller's contract is to retry */
static int engine_test_update_config(tidesdb_t *db, tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *cc, int persist)
{
    int rc = TDB_ERR_LOCKED;
    for (int attempt = 0; attempt < ENGINE_TEST_LOCKED_RETRIES && rc == TDB_ERR_LOCKED; attempt++)
    {
        rc = tidesdb_cf_update_runtime_config(db, cf, cc, persist);
        if (rc == TDB_ERR_LOCKED) usleep(ENGINE_TEST_LOCKED_BACKOFF_US);
    }
    return rc;
}

static void engine_open_with_cf(char *db_path, tidesdb_t **db, tidesdb_column_family_t **cf)
{
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(*db, "kv", &cc), TDB_SUCCESS);
    *cf = tidesdb_get_column_family(*db, "kv");
    ASSERT_TRUE(*cf != NULL);
}

/* commit a single put, then assert a fresh transaction reads it back */
static void engine_assert_committed(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key,
                                    const char *expect)
{
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    uint8_t *value = NULL;
    size_t value_size = 0;
    const int rc = tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &value, &value_size);
    if (expect == NULL)
        ASSERT_EQ(rc, TDB_ERR_NOT_FOUND);
    else
    {
        ASSERT_EQ(rc, TDB_SUCCESS);
        ASSERT_EQ((int)value_size, (int)strlen(expect));
        ASSERT_TRUE(value != NULL && memcmp(value, expect, value_size) == 0);
        free(value);
    }
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
}

/* a committed put reads back within its own transaction and from a later one */
void test_engine_txn_put_get(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"a", 1, (const uint8_t *)"one", 3, -1),
              TDB_SUCCESS);
    /* read-your-own-writes before commit */
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)"a", 1, &value, &value_size), TDB_SUCCESS);
    ASSERT_TRUE(value != NULL && value_size == 3 && memcmp(value, "one", 3) == 0);
    free(value);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    engine_assert_committed(db, cf, "a", "one"); /* visible to a later transaction */

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a committed delete hides a prior put */
void test_engine_txn_delete(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"x", 1, (const uint8_t *)"v", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, cf, "x", "v");

    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)"x", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, cf, "x", NULL); /* deleted */

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a rolled-back transaction leaves nothing behind */
void test_engine_txn_rollback(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"r", 1, (const uint8_t *)"1", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    engine_assert_committed(db, cf, "r", NULL); /* never committed */

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* committed writes recover from the WAL on reopen, before any flush */
void test_engine_write_recovery(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"durable", 7, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* reopen -- the write replays out of the WAL into the active memtable */
    tidesdb_config_t cfg = engine_test_config(db_path);
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "k", "durable");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a write made after recovery supersedes a recovered one, so the mvcc clock must have resumed past
 * every recovered sequence -- a reused sequence would let the stale value win */
void test_engine_overwrite_across_recovery(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"v1", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* reopen -- v1 recovers, then overwrite with v2, which must win */
    tidesdb_config_t cfg = engine_test_config(db_path);
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "k", "v1"); /* recovered */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"v2", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, cf, "k", "v2"); /* the newer write wins -> clock advanced past v1 */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* reopen once more -- v2 stays the newest recovered version */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "k", "v2");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the same key in two column families is namespaced independently through the dispatch source */
void test_engine_multi_cf_write(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cfa", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "cfb", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cfa = tidesdb_get_column_family(db, "cfa");
    tidesdb_column_family_t *cfb = tidesdb_get_column_family(db, "cfb");
    ASSERT_TRUE(cfa != NULL && cfb != NULL);

    /* one transaction writes the same key to both cfs with different values */
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cfa, (const uint8_t *)"k", 1, (const uint8_t *)"a", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cfb, (const uint8_t *)"k", 1, (const uint8_t *)"b", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    engine_assert_committed(db, cfa, "k", "a");
    engine_assert_committed(db, cfb, "k", "b");

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a small write buffer forces many rotations and background flushes; every key stays readable
 * during and after the flushes (no visibility gap), and survives a reopen through L1 and WAL
 * recovery */
void test_engine_flush_rotation(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 1024; /* tiny, so a handful of writes rotates */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 200;
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* every key is readable while flushes run concurrently -- the claim/retire path keeps each
     * immutable visible until its L1 segment is installed */
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* reopen -- the flushed segments come back from L1 and any unflushed generations from the WAL
     */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* enough flushes accumulate L1 files to trip the compaction trigger; the scheduler plans and a
 * worker merges them down, so data leaves L1 while every key stays readable throughout.
 *
 * which level it comes to rest in is the scheduler's business rather than this test's. a merge into
 * a level reads every level at and below it, and the planner targets the largest live one, so with
 * the minimum level count above two the tier goes straight past L2 and nothing ever rests there.
 * naming L2 turned this into a race on a level that may hold something for no time at all, which
 * one allocator's timing happened to lose every run and the others happened to win */
void test_engine_compaction(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 512; /* tiny, so many L1 flushes pile up fast */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 300;
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* wait for a compaction to land data anywhere below L1 (the grow merge of the L1 tier) */
    cf_t *icf = (cf_t *)cf;
    int compacted = 0;
    for (int t = 0; t < 500 && !compacted; t++)
    {
        for (int lvl = LEVEL_SET_L1 + 1; lvl <= LEVEL_SET_MAX_LEVELS && !compacted; lvl++)
            if (level_set_count(icf->levels, lvl) > 0) compacted = 1;
        if (!compacted) usleep(10000); /* 10ms */
    }
    ASSERT_TRUE(compacted); /* the scheduler planned and a worker merged the L1 tier down */

    /* every key is still readable across the flush + compaction churn */
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* under a small fd budget with many sstables, reads keep succeeding because the fd-eviction reaper
 * closes idle klog descriptors so a budget-blocked read can reopen the klog it needs */
void test_engine_fd_reaper(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 1024; /* many small L1 flushes -> many sstables */
    cfg.max_open_sstables = 16;            /* a tight klog fd budget */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 200;
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* read every key back over the tight budget -- each succeeds because idle klogs are evicted */
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* interval durability mode runs a background wal-sync ticker and fsyncs the durable base (flush and
 * compaction) fully; the db operates and recovers cleanly across a reopen */
void test_engine_interval_sync(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_sync_mode = TDB_SYNC_INTERVAL;
    cfg.memtable_sync_interval_us = 50000; /* 50ms, so the ticker fires within the test */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"v", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    usleep(120000); /* let the wal-sync ticker fire at least twice */
    engine_assert_committed(db, cf, "k", "v");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "k", "v");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a range iterator merges L0 and the sstable levels at a snapshot: forward and backward scans visit
 * every key in byte order, and a seek lands on the search key */
/* keys written for the bounded-scan test and the band it reads, wide enough that the range is a
 * small fraction of the family */
#define ENGINE_RANGE_KEYS  400
#define ENGINE_RANGE_FIRST 120
#define ENGINE_RANGE_LAST  139

/* a bounded scan returns exactly the rows in its range and nothing outside it. the bound is what
 * lets the scan leave out the sstables it cannot need, so the rows it does return have to be
 * complete -- a selection rule that dropped a source holding part of the band would show up here as
 * a short answer rather than as a wrong one */
void test_engine_bounded_iterator_returns_the_whole_range_and_nothing_else(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 512; /* force flushes so the band spans L0 and sstables */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < ENGINE_RANGE_KEYS; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    char lower[16], upper[16];
    snprintf(lower, sizeof(lower), "key%05d", ENGINE_RANGE_FIRST);
    snprintf(upper, sizeof(upper), "key%05d", ENGINE_RANGE_LAST);

    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new_range(rt, cf, (const uint8_t *)lower, strlen(lower),
                                     (const uint8_t *)upper, strlen(upper), &it),
              TDB_SUCCESS);

    ASSERT_EQ(tidesdb_iter_seek(it, (const uint8_t *)lower, strlen(lower)), TDB_SUCCESS);
    int seen = 0;
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t ks = 0, vs = 0;
        ASSERT_EQ(tidesdb_iter_key_value(it, &k, &ks, &v, &vs), TDB_SUCCESS);
        char expect_key[16], expect_val[16];
        snprintf(expect_key, sizeof(expect_key), "key%05d", ENGINE_RANGE_FIRST + seen);
        snprintf(expect_val, sizeof(expect_val), "val%05d", ENGINE_RANGE_FIRST + seen);
        ASSERT_EQ(ks, strlen(expect_key));
        ASSERT_TRUE(memcmp(k, expect_key, ks) == 0);
        ASSERT_TRUE(memcmp(v, expect_val, vs) == 0);
        free(k);
        free(v);
        seen++;
        /* the caller stops at its own upper bound; the iterator does not enforce one */
        if (seen > ENGINE_RANGE_LAST - ENGINE_RANGE_FIRST) break;
        if (tidesdb_iter_next(it) != TDB_SUCCESS) break;
    }
    ASSERT_EQ(seen, ENGINE_RANGE_LAST - ENGINE_RANGE_FIRST + 1);

    tidesdb_iter_free(it);

    /* both ends are required, since one end alone leaves nothing to test an sstable against */
    tidesdb_iter_t *bad = NULL;
    ASSERT_EQ(tidesdb_iter_new_range(rt, cf, (const uint8_t *)lower, strlen(lower), NULL, 0, &bad),
              TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_txn_rollback(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_iterator(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 512; /* force flushes so data spans L0 and sstables */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 200;
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(rt, cf, &it), TDB_SUCCESS);

    /* forward scan visits every key in order with its value */
    ASSERT_EQ(tidesdb_iter_seek_to_first(it), TDB_SUCCESS);
    int fwd = 0;
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t ks = 0, vs = 0;
        ASSERT_EQ(tidesdb_iter_key_value(it, &k, &ks, &v, &vs), TDB_SUCCESS);
        char ek[16], ev[16];
        snprintf(ek, sizeof(ek), "key%05d", fwd);
        snprintf(ev, sizeof(ev), "val%05d", fwd);
        ASSERT_TRUE(ks == strlen(ek) && memcmp(k, ek, ks) == 0);
        ASSERT_TRUE(vs == strlen(ev) && memcmp(v, ev, vs) == 0);
        free(k);
        free(v);
        fwd++;
        tidesdb_iter_next(it);
    }
    ASSERT_EQ(fwd, n);

    /* a seek lands on the exact key */
    ASSERT_EQ(tidesdb_iter_seek(it, (const uint8_t *)"key00100", 8), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_iter_valid(it));
    uint8_t *sk = NULL;
    size_t sks = 0;
    ASSERT_EQ(tidesdb_iter_key(it, &sk, &sks), TDB_SUCCESS);
    ASSERT_TRUE(sks == 8 && memcmp(sk, "key00100", 8) == 0);
    free(sk);

    /* backward scan visits every key */
    ASSERT_EQ(tidesdb_iter_seek_to_last(it), TDB_SUCCESS);
    int bwd = 0;
    while (tidesdb_iter_valid(it))
    {
        bwd++;
        tidesdb_iter_prev(it);
    }
    ASSERT_EQ(bwd, n);

    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* commit one key=value (val NULL deletes) in its own transaction */
static void ryow_commit(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key,
                        const char *val)
{
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    if (val)
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
    else
        ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
}

/* scan a cf inside a transaction in the given direction, folding visible key=value pairs into a
 * "key:value," string; hidden tombstones never appear */
static void ryow_scan(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, int forward, char *out,
                      size_t cap)
{
    out[0] = '\0';
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &it), TDB_SUCCESS);
    int rc = forward ? tidesdb_iter_seek_to_first(it) : tidesdb_iter_seek_to_last(it);
    while (rc == TDB_SUCCESS && tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t ks = 0, vs = 0;
        ASSERT_EQ(tidesdb_iter_key_value(it, &k, &ks, &v, &vs), TDB_SUCCESS);
        char item[64];
        snprintf(item, sizeof(item), "%.*s:%.*s,", (int)ks, (const char *)k, (int)vs,
                 v ? (const char *)v : "");
        strncat(out, item, cap - strlen(out) - 1);
        free(k);
        free(v);
        rc = forward ? tidesdb_iter_next(it) : tidesdb_iter_prev(it);
    }
    tidesdb_iter_free(it);
}

/* a scan inside a transaction reads the transaction's own buffered writes: new puts appear,
 * overwrites win over committed values, deletes hide the underlying rows, a put-then-delete
 * vanishes, and none of it leaks to a concurrent transaction until commit */
void test_engine_scan_reads_own_writes(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* committed baseline a=A c=C e=E */
    ryow_commit(db, cf, "a", "A");
    ryow_commit(db, cf, "c", "C");
    ryow_commit(db, cf, "e", "E");

    /* a concurrent reader opened before the writes must never see them */
    tidesdb_txn_t *other = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &other), TDB_SUCCESS);

    /* the writer buffers b (new), c=C2 (overwrite), delete a, and a put-then-delete of d */
    tidesdb_txn_t *w = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &w), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(w, cf, (const uint8_t *)"b", 1, (const uint8_t *)"B2", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(w, cf, (const uint8_t *)"c", 1, (const uint8_t *)"C2", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(w, cf, (const uint8_t *)"a", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(w, cf, (const uint8_t *)"d", 1, (const uint8_t *)"D2", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(w, cf, (const uint8_t *)"d", 1), TDB_SUCCESS);

    char buf[256];

    /* the writer's own scan sees b, the overwritten c, and e; a and d are hidden */
    ryow_scan(w, cf, 1, buf, sizeof(buf));
    ASSERT_TRUE(strcmp(buf, "b:B2,c:C2,e:E,") == 0);

    /* the reverse scan folds the overlay the same way */
    ryow_scan(w, cf, 0, buf, sizeof(buf));
    ASSERT_TRUE(strcmp(buf, "e:E,c:C2,b:B2,") == 0);

    /* a seek inside the writer lands on the buffered overwrite */
    tidesdb_iter_t *sit = NULL;
    ASSERT_EQ(tidesdb_iter_new(w, cf, &sit), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_seek(sit, (const uint8_t *)"c", 1), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_iter_valid(sit));
    uint8_t *sk = NULL, *sv = NULL;
    size_t sks = 0, svs = 0;
    ASSERT_EQ(tidesdb_iter_key_value(sit, &sk, &sks, &sv, &svs), TDB_SUCCESS);
    ASSERT_TRUE(sks == 1 && sk[0] == 'c' && svs == 2 && memcmp(sv, "C2", 2) == 0);
    free(sk);
    free(sv);
    tidesdb_iter_free(sit);

    /* the concurrent reader still sees only the committed baseline */
    ryow_scan(other, cf, 1, buf, sizeof(buf));
    ASSERT_TRUE(strcmp(buf, "a:A,c:C,e:E,") == 0);
    ASSERT_EQ(tidesdb_txn_rollback(other), TDB_SUCCESS);
    tidesdb_txn_free(other);

    /* after commit the durable state matches what the writer's scan showed */
    ASSERT_EQ(tidesdb_txn_commit(w), TDB_SUCCESS);
    tidesdb_txn_free(w);
    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ryow_scan(rt, cf, 1, buf, sizeof(buf));
    ASSERT_TRUE(strcmp(buf, "b:B2,c:C2,e:E,") == 0);
    ASSERT_EQ(tidesdb_txn_rollback(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* fixed-width keys and values make the average-size stats exactly predictable */
#define STATS_KEY_LEN 8
#define STATS_VAL_LEN 12

/* per-column-family stats fold the live sstables: fixed-width writes give exact averages, the byte
 * counters accumulate across the commit and flush paths, and a point-lookup read amplification and
 * btree structure figures come out of the flushed runs */
void test_engine_cf_stats(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 512; /* tiny, so writes flush to L1 sstables */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 300;
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);  /* exactly STATS_KEY_LEN bytes */
        snprintf(val, sizeof(val), "v%011d", i); /* exactly STATS_VAL_LEN bytes */
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, STATS_KEY_LEN, (const uint8_t *)val,
                                  STATS_VAL_LEN, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* wait for the first L1 sstables to land so the fold sees on-disk runs */
    cf_t *icf = (cf_t *)cf;
    int flushed = 0;
    for (int t = 0; t < 500 && !flushed; t++)
    {
        if (level_set_count(icf->levels, 1) > 0 || level_set_count(icf->levels, 2) > 0)
            flushed = 1;
        else
            usleep(10000);
    }
    ASSERT_TRUE(flushed);

    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);

    /* fixed-width writes make the per-distinct-key averages exact */
    ASSERT_TRUE(st.total_keys > 0);
    ASSERT_TRUE(st.avg_key_size > STATS_KEY_LEN - 1e-6 && st.avg_key_size < STATS_KEY_LEN + 1e-6);
    ASSERT_TRUE(st.avg_value_size > STATS_VAL_LEN - 1e-6 &&
                st.avg_value_size < STATS_VAL_LEN + 1e-6);
    ASSERT_TRUE(st.num_levels >= 1);
    ASSERT_TRUE(st.btree_total_nodes > 0);
    ASSERT_TRUE(st.btree_max_height >= 1);
    ASSERT_TRUE(st.read_amp >= 1.0);

    /* every committed op contributed its key+value to the user counter, regardless of flush
     * progress */
    ASSERT_EQ((int)st.user_bytes_written, n * (STATS_KEY_LEN + STATS_VAL_LEN));
    ASSERT_TRUE(st.wal_bytes_written > 0);
    ASSERT_TRUE(st.flush_bytes_written > 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the cardinality estimate is summed from the distinct key counts the sstables carry, so it reports
 * nothing while the writes are still in the memtable and reaches the true count once they land */
void test_engine_cf_estimate_cardinality(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 64 * 1024 * 1024; /* large, so nothing flushes on its own */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf0", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf0");
    ASSERT_TRUE(cf != NULL);

    uint64_t estimate = 1;
    ASSERT_EQ(tidesdb_cf_estimate_cardinality(cf, &estimate), TDB_SUCCESS);
    ASSERT_EQ(estimate, 0u); /* nothing written, so no sstable carries a count */

    const int n = 32;
    for (int i = 0; i < n; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%04d", i);
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)"v",
                                  1, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    /* still resident, so the estimate has nothing to read yet */
    ASSERT_EQ(tidesdb_cf_estimate_cardinality(cf, &estimate), TDB_SUCCESS);
    ASSERT_EQ(estimate, 0u);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_cf_estimate_cardinality(cf, &estimate), TDB_SUCCESS);
    ASSERT_EQ(estimate, (uint64_t)n);

    ASSERT_EQ(tidesdb_cf_estimate_cardinality(cf, NULL), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_cf_estimate_cardinality(NULL, &estimate), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the per-cf unflushed key count reflects distinct keys still in the shared memtables: it rises
 * with new keys, ignores repeat writes of a key already resident, drains as flushes move keys to
 * L1, and rebuilds from the wal on reopen */
void test_engine_cf_unflushed_keys(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size =
        64 * 1024 * 1024; /* large, so writes stay resident in memory */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 200;
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);
        snprintf(val, sizeof(val), "v%011d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, STATS_KEY_LEN, (const uint8_t *)val,
                                  STATS_VAL_LEN, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* nothing has flushed, so every distinct key sits unflushed and none are in an sstable yet */
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ((int)st.unflushed_key_count, n);
    ASSERT_EQ((int)st.total_keys, 0);

    /* rewriting keys already resident adds versions, not distinct keys, so the count holds */
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);
        snprintf(val, sizeof(val), "w%011d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, STATS_KEY_LEN, (const uint8_t *)val,
                                  STATS_VAL_LEN, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ((int)st.unflushed_key_count, n);

    /* the count survives a reopen -- the wal replay re-lands every resident key */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ((int)st.unflushed_key_count, n);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* put or delete key i in its own committed transaction; a NULL val lays down a tombstone */
static void engine_stats_write(tidesdb_t *db, tidesdb_column_family_t *cf, int i, int is_delete)
{
    char key[16], val[16];
    snprintf(key, sizeof(key), "key%05d", i);
    snprintf(val, sizeof(val), "val%05d", i);
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    if (is_delete)
        ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
    else
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
}

/* the remaining cf-stats fields carry real figures once data lands on disk: the per-level
 * breakdowns, the tombstone counts and ratio, the on-disk footprint, and the compaction counters a
 * forced merge advances */
/* a transaction bounded by the public setter expires once its deadline passes, and the next
 * operation on it reports that rather than silently continuing. the clock the engine ages against
 * ticks once a second, so a one-second bound is waited out rather than simulated */
/* a manifest destroyed while the database is closed is rebuilt from the sstables on disk, so the
 * data those files hold is reachable again rather than orphaned. what the files cannot carry --
 * the family's name and its configuration -- comes back as the directory name and defaults, which
 * is the documented limit of the rebuild */
void test_engine_rebuilds_catalogue_from_sstables(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* two flushes so the family owns real sstables rather than only memtable state */
    for (int i = 0; i < 40; i++) engine_stats_write(db, cf, i, 0);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    for (int i = 40; i < 80; i++) engine_stats_write(db, cf, i, 0);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* destroy the catalogue, leaving every klog untouched */
    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s%sMANIFEST", db_path, PATH_SEPARATOR);
    FILE *w = tdb_fopen(manifest_path, "wb");
    ASSERT_TRUE(w != NULL);
    const char garbage[] = "not a manifest \x01\x02\x03";
    ASSERT_EQ(fwrite(garbage, 1, sizeof(garbage), w), sizeof(garbage));
    fclose(w);

    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    /* the family is back under its directory name, since the manifest held the only real one */
    tidesdb_column_family_t *rebuilt = tidesdb_get_column_family(db, "cf_0000000000");
    ASSERT_TRUE(rebuilt != NULL);

    /* and its sstables were adopted, at L1 */
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(rebuilt, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.level_num_sstables[0] >= 2);
    ASSERT_TRUE(st.total_keys > 0);

    /* the data itself reads back -- the point of the rebuild */
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    int found = 0;
    for (int i = 0; i < 80; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%05d", i);
        uint8_t *val = NULL;
        size_t vlen = 0;
        if (tidesdb_txn_get(t, rebuilt, (const uint8_t *)key, strlen(key), &val, &vlen) ==
            TDB_SUCCESS)
        {
            found++;
            tidesdb_free(val);
        }
    }
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(found, 80);

    /* the rebuilt catalogue is durable -- a second open needs no rebuild and still sees the data */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    tidesdb_config_t cfg2 = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg2, &db), TDB_SUCCESS);
    tidesdb_column_family_t *again = tidesdb_get_column_family(db, "cf_0000000000");
    ASSERT_TRUE(again != NULL);
    ASSERT_EQ(tidesdb_get_cf_stats(again, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.total_keys > 0);

    /* a family created after a rebuild must not reuse an adopted id and inherit its files */
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "fresh", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *fresh = tidesdb_get_column_family(db, "fresh");
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(tidesdb_get_cf_stats(fresh, &st), TDB_SUCCESS);
    ASSERT_EQ(st.total_keys, 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_txn_timeout_expires(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_set_timeout(t, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"v", 1, 0),
              TDB_SUCCESS);

    /* wait past the deadline, giving the clock ticker room to publish a later second */
    int rc = TDB_SUCCESS;
    for (int i = 0; i < 60 && rc != TDB_ERR_TXN_EXPIRED; i++)
    {
        usleep(100000);
        rc = tidesdb_txn_put(t, cf, (const uint8_t *)"k2", 2, (const uint8_t *)"v", 1, 0);
    }
    ASSERT_EQ(rc, TDB_ERR_TXN_EXPIRED);
    /* expiry is reported once -- it aborts the transaction, so a later operation finds it resolved
     * rather than expiring it a second time */
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"k3", 2, (const uint8_t *)"v", 1, 0),
              TDB_ERR_INVALID_ARGS);
    tidesdb_txn_state_t st;
    ASSERT_EQ(tidesdb_txn_state(t, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_ABORTED);
    tidesdb_txn_free(t);

    /* the expired transaction committed nothing */
    tidesdb_txn_t *r = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &r), TDB_SUCCESS);
    uint8_t *val = NULL;
    size_t vlen = 0;
    ASSERT_EQ(tidesdb_txn_get(r, cf, (const uint8_t *)"k", 1, &val, &vlen), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_rollback(r), TDB_SUCCESS);
    tidesdb_txn_free(r);

    /* an unbounded transaction is unaffected, and clearing a bound restores that */
    tidesdb_txn_t *u = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &u), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_set_timeout(u, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_set_timeout(u, 0), TDB_SUCCESS);
    usleep(1500000);
    ASSERT_EQ(tidesdb_txn_put(u, cf, (const uint8_t *)"n", 1, (const uint8_t *)"v", 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(u), TDB_SUCCESS);
    tidesdb_txn_free(u);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the database-wide default bounds every transaction begun under it, without a per-txn call */
void test_engine_txn_timeout_config_default(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.txn_timeout_seconds = 1;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    int drc = TDB_SUCCESS;
    for (int i = 0; i < 60 && drc != TDB_ERR_TXN_EXPIRED; i++)
    {
        usleep(100000);
        drc = tidesdb_txn_put(t, cf, (const uint8_t *)"k", 1, (const uint8_t *)"v", 1, 0);
    }
    ASSERT_EQ(drc, TDB_ERR_TXN_EXPIRED);
    tidesdb_txn_free(t);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_cf_stats_levels_tombstones_compaction(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    /* one flush lays 60 keys into an L1 sstable, a second flush lays 20 tombstones over them */
    for (int i = 0; i < 60; i++) engine_stats_write(db, cf, i, 0);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    for (int i = 0; i < 20; i++) engine_stats_write(db, cf, i, 1);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_TRUE(level_set_count(icf->levels, 1) >= 2);

    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);

    /* the per-level breakdown agrees with the totals it sums to */
    ASSERT_TRUE(st.num_levels >= 1);
    uint64_t level_keys = 0, level_tombs = 0;
    int level_ssts = 0;
    uint64_t level_bytes = 0;
    for (int lvl = 0; lvl < st.num_levels; lvl++)
    {
        level_keys += st.level_key_counts[lvl];
        level_tombs += st.level_tombstone_counts[lvl];
        level_ssts += st.level_num_sstables[lvl];
        level_bytes += st.level_sizes[lvl];
    }
    ASSERT_EQ(level_keys, st.total_keys);
    ASSERT_EQ(level_tombs, st.total_tombstones);
    ASSERT_EQ(level_ssts, 2);
    ASSERT_TRUE(level_bytes > 0);

    /* the 20 deletes are on disk as tombstones, giving a ratio in the open unit interval */
    ASSERT_TRUE(st.total_tombstones >= 20);
    ASSERT_TRUE(st.tombstone_ratio > 0.0 && st.tombstone_ratio <= 1.0);
    ASSERT_TRUE(st.total_data_size > 0);
    ASSERT_TRUE(st.max_sst_density >= 0.0);

    /* no compaction has run, so its counters sit at zero */
    ASSERT_EQ((int)st.compaction_count, 0);
    ASSERT_EQ((int)st.compaction_bytes_read, 0);

    /* a forced merge of the L1 tier advances the compaction counters */
    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.compaction_count >= 1);
    ASSERT_TRUE(st.compaction_bytes_read > 0);
    ASSERT_TRUE(st.compaction_bytes_written > 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* database stats sum the families and expose the shared memtable, clock, value log, and live-txn
 * figures */
void test_engine_db_stats(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "a", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "b", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cfa = tidesdb_get_column_family(db, "a");
    ASSERT_TRUE(cfa != NULL);

    const int n = 40;
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);
        snprintf(val, sizeof(val), "v%011d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cfa, (const uint8_t *)key, STATS_KEY_LEN, (const uint8_t *)val,
                                  STATS_VAL_LEN, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* an open transaction is counted while it is live and its buffered write charged to memory.
     * begun at snapshot explicitly because only repeatable-read and stronger join the registry the
     * stat reads, and the default is read-committed */
    tidesdb_txn_t *live = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &live), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(live, cfa, (const uint8_t *)"k9999999", STATS_KEY_LEN,
                              (const uint8_t *)"v00000000000", STATS_VAL_LEN, -1),
              TDB_SUCCESS);

    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);

    ASSERT_EQ(st.num_column_families, 2);
    ASSERT_TRUE(st.global_seq > 0);
    ASSERT_TRUE(st.active_txn_count >= 1);
    ASSERT_TRUE(st.txn_memory_bytes > 0);
    ASSERT_EQ((int)st.user_bytes_written, n * (STATS_KEY_LEN + STATS_VAL_LEN));

    ASSERT_EQ(tidesdb_txn_rollback(live), TDB_SUCCESS);
    tidesdb_txn_free(live);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* block-cache stats report the shard partitioning and the hit or miss counters reads accumulate */
void test_engine_cache_stats(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 512; /* force flushes so reads hit the cached sstable path */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 200;
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);
        snprintf(val, sizeof(val), "v%011d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, STATS_KEY_LEN, (const uint8_t *)val,
                                  STATS_VAL_LEN, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    for (int i = 0; i < n; i++)
    {
        char key[STATS_KEY_LEN + 1], val[STATS_VAL_LEN + 1];
        snprintf(key, sizeof(key), "k%07d", i);
        snprintf(val, sizeof(val), "v%011d", i);
        engine_assert_committed(db, cf, key, val);
    }

    tidesdb_cache_stats_t st;
    ASSERT_EQ(tidesdb_get_cache_stats(db, &st), TDB_SUCCESS);
    ASSERT_EQ(st.enabled, 1);
    ASSERT_TRUE(st.num_partitions > 0);
    ASSERT_TRUE(st.hits + st.misses > 0);
    ASSERT_TRUE(st.hit_rate >= 0.0 && st.hit_rate <= 1.0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* commit one fixed-width key/value into a cf */
static void engine_put(tidesdb_t *db, tidesdb_column_family_t *cf, int i)
{
    char key[16], val[16];
    snprintf(key, sizeof(key), "key%05d", i);
    snprintf(val, sizeof(val), "val%05d", i);
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
}

/* read a key back and require it present with a value of exactly want_len bytes */
static void engine_assert_present_with_len(tidesdb_t *db, tidesdb_column_family_t *cf,
                                           const char *key, size_t want_len)
{
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    uint8_t *v = NULL;
    size_t vl = 1234; /* poisoned, so a path that returns success without setting it is caught */
    ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &v, &vl), TDB_SUCCESS);
    ASSERT_EQ(vl, want_len);
    if (v) tidesdb_free(v);
    (void)tidesdb_txn_rollback(t);
    tidesdb_txn_free(t);
}

/* an empty value is a value, and it stays one everywhere a version can live.
 *
 * the key is present and it is not a tombstone, so every layer that can answer a read has to say
 * present-with-nothing rather than absent: the memtable while the write is still there, the sstable
 * once a flush has written it out, and the replayed log after a reopen. a caller whose meaning is
 * carried entirely by the key -- a secondary index entry, a set member -- should not have to invent
 * a filler byte, and the layer that answers must not decide the key is gone because its value
 * happens to be zero bytes long */
void test_engine_an_empty_value_reads_back_as_present(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const char *empty_key = "empty";
    const char *gone_key = "gone";

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)empty_key, strlen(empty_key),
                              (const uint8_t *)"", 0, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)gone_key, strlen(gone_key),
                              (const uint8_t *)"x", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    /* out of the memtable */
    engine_assert_present_with_len(db, cf, empty_key, 0);

    /* an iterator sees it too -- a scan that skipped it would drop the key from a range */
    tidesdb_txn_t *it_txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &it_txn), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(it_txn, cf, &it), TDB_SUCCESS);
    int saw_empty = 0;
    for (tidesdb_iter_seek_to_first(it); tidesdb_iter_valid(it); tidesdb_iter_next(it))
    {
        uint8_t *k = NULL;
        size_t kl = 0;
        if (tidesdb_iter_key(it, &k, &kl) != TDB_SUCCESS) break;
        if (kl == strlen(empty_key) && memcmp(k, empty_key, kl) == 0) saw_empty = 1;
        tidesdb_free(k);
    }
    ASSERT_EQ(saw_empty, 1);
    tidesdb_iter_free(it);
    (void)tidesdb_txn_rollback(it_txn);
    tidesdb_txn_free(it_txn);

    /* and out of an sstable, once the flush has written it through the builder and the btree */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    engine_assert_present_with_len(db, cf, empty_key, 0);

    /* a real absence still reads as one, so present-with-nothing has not swallowed not-found */
    tidesdb_txn_t *d = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &d), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(d, cf, (const uint8_t *)gone_key, strlen(gone_key)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(d), TDB_SUCCESS);
    tidesdb_txn_free(d);
    tidesdb_txn_t *g = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &g), TDB_SUCCESS);
    uint8_t *gv = NULL;
    size_t gvl = 0;
    ASSERT_EQ(tidesdb_txn_get(g, cf, (const uint8_t *)gone_key, strlen(gone_key), &gv, &gvl),
              TDB_ERR_NOT_FOUND);
    (void)tidesdb_txn_rollback(g);
    tidesdb_txn_free(g);

    /* and it survives a reopen, which replays the log rather than reading the sstable */
    const char *fresh_key = "fresh";
    tidesdb_txn_t *f = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &f), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(f, cf, (const uint8_t *)fresh_key, strlen(fresh_key),
                              (const uint8_t *)"", 0, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(f), TDB_SUCCESS);
    tidesdb_txn_free(f);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_present_with_len(db, cf, empty_key, 0);
    engine_assert_present_with_len(db, cf, fresh_key, 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a synchronous flush seals the active memtable to L1 and a wal sync succeeds; is_flushing reads
 * clear once the flush has drained */
void test_engine_flush_and_sync(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    for (int i = 0; i < 20; i++) engine_put(db, cf, i);

    ASSERT_EQ(tidesdb_sync_wal(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_is_flushing(db), 0); /* the synchronous flush drained before returning */
    ASSERT_TRUE(level_set_count(icf->levels, 1) >= 1); /* the memtable landed as an L1 sstable */

    for (int i = 0; i < 20; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a forced compaction merges an L1 tier that no trigger would touch down into L2, and is_compacting
 * reads clear once it returns */
/* the backstop scheduler plans a family only when its shape has moved. the generation is what tells
 * it, so it has to advance on a real layout change and hold still otherwise -- if it never advanced
 * the scheduler would stop compacting entirely, and if it advanced on its own the skip would buy
 * nothing */
void test_engine_level_set_generation_tracks_layout_changes(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    /* an empty family has published no layout */
    ASSERT_EQ(level_set_generation(icf->levels), 0u);

    for (int i = 0; i < 30; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the flush installed an sstable, so the shape moved */
    const uint64_t after_flush = level_set_generation(icf->levels);
    ASSERT_TRUE(after_flush > 0u);

    /* reads and stats do not change the shape, so a scheduler tick over them finds nothing to do */
    for (int i = 0; i < 30; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ(level_set_generation(icf->levels), after_flush);

    /* a compaction rewrites the levels, which moves it again */
    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);
    ASSERT_TRUE(level_set_generation(icf->levels) > after_flush);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_compact(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db,
                        &cf); /* default config: a single L1 sstable trips no trigger */
    cf_t *icf = (cf_t *)cf;

    for (int i = 0; i < 30; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_TRUE(level_set_count(icf->levels, 1) >= 1);
    ASSERT_EQ(level_set_count(icf->levels, 2), 0); /* nothing has merged down yet */
    ASSERT_TRUE(engine_test_await_not_compacting(cf));

    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS); /* force plans a merge no trigger would */
    ASSERT_TRUE(engine_test_await_not_compacting(cf));
    ASSERT_TRUE(level_set_count(icf->levels, 2) >= 1); /* the L1 tier moved to L2 */

    for (int i = 0; i < 30; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* keys written across one wide sstable, and the narrow band the estimate is asked about. the total
 * is past the cap that decides estimate-versus-count, so the estimator has to answer without
 * walking -- which is the case a query planner actually hits */
#define ENGINE_ESTIMATE_KEYS       4000
#define ENGINE_ESTIMATE_BAND_FIRST 1000
#define ENGINE_ESTIMATE_BAND_LAST  1019

/* how far past the true count an estimate may land before it stops being useful to a planner. an
 * order of magnitude is generous; the failure this guards is three of them */
#define ENGINE_ESTIMATE_TOLERANCE 10

/* an estimate has to describe the range asked about, not the files it happens to touch. every
 * sstable an interleaved write pattern produces spans the whole key space, so a narrow range
 * overlaps all of them -- and counting each overlapping file's keys whole reports the entire store
 * for twenty rows. the number the optimizer costs its plan on is then wrong by orders of magnitude,
 * and the range is also pushed past the cap under which it would have been counted exactly */
void test_engine_range_stats_estimate_follows_the_range_not_the_file(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    for (int i = 0; i < ENGINE_ESTIMATE_KEYS; i++) engine_put(db, cf, i);

    /* one sstable spanning every key, the shape a shared memtable flushes */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    char lo[16], hi[16];
    snprintf(lo, sizeof(lo), "key%05d", ENGINE_ESTIMATE_BAND_FIRST);
    snprintf(hi, sizeof(hi), "key%05d", ENGINE_ESTIMATE_BAND_LAST);

    tidesdb_range_stats_t rs;
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)lo, strlen(lo), (const uint8_t *)hi,
                                  strlen(hi), &rs),
              TDB_SUCCESS);

    /* the band holds twenty keys; the file holds four thousand */
    const uint64_t truth = ENGINE_ESTIMATE_BAND_LAST - ENGINE_ESTIMATE_BAND_FIRST;
    ASSERT_TRUE(rs.estimated_keys <= truth * ENGINE_ESTIMATE_TOLERANCE);

    /* and the correction must not run the other way: a range covering the whole file still has to
     * report most of it, or the planner is misled just as badly in the opposite direction */
    char all_lo[16], all_hi[16];
    snprintf(all_lo, sizeof(all_lo), "key%05d", 0);
    snprintf(all_hi, sizeof(all_hi), "key%05d", ENGINE_ESTIMATE_KEYS);
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)all_lo, strlen(all_lo),
                                  (const uint8_t *)all_hi, strlen(all_hi), &rs),
              TDB_SUCCESS);
    ASSERT_TRUE(rs.estimated_keys >= ENGINE_ESTIMATE_KEYS / 2);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the interleaved shape a shared memtable produces under concurrent writers: each generation holds
 * keys from across the whole key space, so every flushed run spans it. bands are the key space's
 * divisions and rounds are the generations written across them */
#define ENGINE_CONVERGE_BANDS      32
#define ENGINE_CONVERGE_ROUNDS     16
#define ENGINE_CONVERGE_KEYS_TOTAL (ENGINE_CONVERGE_BANDS * ENGINE_CONVERGE_ROUNDS)

/* forced compaction passes after the writes, so convergence is measured rather than raced against
 * the background scheduler */
#define ENGINE_CONVERGE_PASSES 6

/* a narrow band must end up overlapping far fewer runs than the store took generations to build.
 * this is the count a scan of that band merges, so it is the read cost the whole layout exists to
 * bound */
#define ENGINE_CONVERGE_MAX_OVERLAP 8

/* compaction has to converge an interleaved store into levels a narrow range can be answered from.
 * every flush lands one run in the tier spanning the whole key space, so before the merges run a
 * narrow band overlaps every one of them -- which is the read-side collapse. what makes it converge
 * is the tree deepening as it fills and merges promoting out of the tier, so this asserts both the
 * depth and the overlap a range actually pays */
void test_engine_compaction_converges_an_interleaved_store(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = 4096; /* many generations, each spanning the key space */

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* one key per band per round, so each sealed memtable spans every band */
    for (int round = 0; round < ENGINE_CONVERGE_ROUNDS; round++)
        for (int band = 0; band < ENGINE_CONVERGE_BANDS; band++)
            engine_put(db, cf, band * ENGINE_CONVERGE_ROUNDS + round);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    for (int pass = 0; pass < ENGINE_CONVERGE_PASSES; pass++)
    {
        const int rc = tidesdb_compact(db, cf);
        ASSERT_TRUE(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED);
    }

    /* a narrow band, one thirty-second of the key space */
    char lo[16], hi[16];
    snprintf(lo, sizeof(lo), "key%05d", ENGINE_CONVERGE_ROUNDS * (ENGINE_CONVERGE_BANDS / 2));
    snprintf(hi, sizeof(hi), "key%05d", ENGINE_CONVERGE_ROUNDS * (ENGINE_CONVERGE_BANDS / 2 + 1));

    tidesdb_range_stats_t rs;
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)lo, strlen(lo), (const uint8_t *)hi,
                                  strlen(hi), &rs),
              TDB_SUCCESS);
    ASSERT_TRUE(rs.sstables_overlapping <= ENGINE_CONVERGE_MAX_OVERLAP);

    /* and every key is still readable, so convergence did not come at the cost of losing data */
    for (int i = 0; i < ENGINE_CONVERGE_KEYS_TOTAL; i += ENGINE_CONVERGE_ROUNDS)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        uint8_t *v = NULL;
        size_t vl = 0;
        ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &v, &vl), TDB_SUCCESS);
        free(v);
        (void)tidesdb_txn_rollback(t);
        tidesdb_txn_free(t);
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* delete key i, for the tombstone case below */
static void engine_range_delete(tidesdb_t *db, tidesdb_column_family_t *cf, int i)
{
    char key[16];
    snprintf(key, sizeof(key), "key%05d", i);
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
}

/* the key count reads the merged stream, so it sees data that has never been flushed, counts a key
 * living in both the memtable and an sstable once, and leaves deleted keys out */
void test_engine_range_stats_counts_merged_stream(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_range_stats_t rs;
    const uint8_t *lo = (const uint8_t *)"key00000";
    const uint8_t *hi = (const uint8_t *)"key00100";

    /* nothing flushed yet, so an sstable-only answer would be zero */
    for (int i = 0; i < 40; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_range_stats(db, cf, lo, 8, hi, 8, &rs), TDB_SUCCESS);
    ASSERT_EQ((int)rs.sstables_overlapping, 0);
    ASSERT_EQ((int)rs.estimated_keys, 40);
    ASSERT_TRUE(rs.keys_exact);

    /* flush, then rewrite half of those keys so they live in both the memtable and the sstable.
     * counting the two sources separately would report sixty; the merged stream reports forty */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    for (int i = 0; i < 20; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_range_stats(db, cf, lo, 8, hi, 8, &rs), TDB_SUCCESS);
    ASSERT_EQ((int)rs.estimated_keys, 40);
    ASSERT_TRUE(rs.keys_exact);

    /* a deleted key is not one the caller will see */
    for (int i = 0; i < 10; i++) engine_range_delete(db, cf, i);
    ASSERT_EQ(tidesdb_range_stats(db, cf, lo, 8, hi, 8, &rs), TDB_SUCCESS);
    ASSERT_EQ((int)rs.estimated_keys, 30);
    ASSERT_TRUE(rs.keys_exact);

    /* a range holding nothing is empty rather than unknown */
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)"key90000", 8,
                                  (const uint8_t *)"key99999", 8, &rs),
              TDB_SUCCESS);
    ASSERT_EQ((int)rs.estimated_keys, 0);
    ASSERT_TRUE(rs.keys_exact);

    /* bad arguments are rejected rather than answered */
    ASSERT_EQ(tidesdb_range_stats(NULL, cf, lo, 8, hi, 8, &rs), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_range_stats(db, cf, lo, 8, hi, 8, NULL), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a range too wide to walk is answered from sstable metadata instead, which keeps the call cheap at
 * the cost of an approximate count -- and says so, so a planner can tell the two apart */
void test_engine_range_stats_wide_range_is_estimated(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* more keys than the walk will step through, all flushed so the metadata ceiling is what
     * decides */
    for (int i = 0; i < 4000; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_range_stats_t rs;
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)"key00000", 8,
                                  (const uint8_t *)"key99999", 8, &rs),
              TDB_SUCCESS);
    ASSERT_TRUE(rs.sstables_overlapping > 0);
    ASSERT_TRUE(!rs.keys_exact);
    /* estimated rather than counted, but it must still be in the right neighbourhood */
    ASSERT_TRUE(rs.estimated_keys >= 3000 && rs.estimated_keys <= 5000);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* range cost counts the sstables a scan meets, and a range compaction consolidates the overlapping
 * L1 runs while every key stays readable */
void test_engine_compact_range(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    /* three flushes lay down three L1 sstables with disjoint key spans [000..099] [100..199]
     * [200..299] */
    for (int b = 0; b < 3; b++)
    {
        for (int i = b * 100; i < b * 100 + 100; i++) engine_put(db, cf, i);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }
    ASSERT_EQ(level_set_count(icf->levels, 1), 3);

    /* a range spanning the first two runs meets two sstables, a pinpoint range meets one */
    tidesdb_range_stats_t rs;
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)"key00050", 8,
                                  (const uint8_t *)"key00150", 8, &rs),
              TDB_SUCCESS);
    ASSERT_EQ((int)rs.sstables_overlapping, 2);
    ASSERT_EQ(tidesdb_range_stats(db, cf, (const uint8_t *)"key00050", 8,
                                  (const uint8_t *)"key00060", 8, &rs),
              TDB_SUCCESS);
    ASSERT_EQ((int)rs.sstables_overlapping, 1);
    /* and the key count for that pinpoint range is exact -- keys 50 through 59 */
    ASSERT_EQ((int)rs.estimated_keys, 10);
    ASSERT_TRUE(rs.keys_exact);

    /* compacting the whole span consolidates the three overlapping runs into fewer */
    ASSERT_EQ(tidesdb_compact_range(db, cf, (const uint8_t *)"key00000", 8,
                                    (const uint8_t *)"key00299", 8),
              TDB_SUCCESS);
    ASSERT_TRUE(level_set_count(icf->levels, 1) < 3);

    for (int i = 0; i < 300; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

#define ENGINE_TEST_BACKUP_DIR "." PATH_SEPARATOR "test_engine_backup"

/* a checkpoint flushes the memtable to L1 and returns cleanly, and every key survives a reopen */
void test_engine_checkpoint(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    for (int i = 0; i < 40; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_checkpoint(db), TDB_SUCCESS);
    ASSERT_TRUE(level_set_count(icf->levels, 1) >= 1); /* the memtable was flushed to L1 */
    ASSERT_EQ(tidesdb_is_flushing(db), 0);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < 40; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a backup is a consistent, directly-openable copy: every key written to the source reads back from
 * a database opened on the backup directory */
void test_engine_backup(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    (void)remove_directory(ENGINE_TEST_BACKUP_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* several flushes lay down multiple L1 klogs for the backup to copy */
    const int n = 250;
    for (int i = 0; i < n; i++)
    {
        engine_put(db, cf, i);
        if (i % 100 == 99) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }

    ASSERT_EQ(tidesdb_backup(db, ENGINE_TEST_BACKUP_DIR), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* open the backup as its own database and read every key back */
    char backup_path[] = ENGINE_TEST_BACKUP_DIR;
    tidesdb_config_t cfg = engine_test_config(backup_path);
    tidesdb_t *copy = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &copy), TDB_SUCCESS);
    tidesdb_column_family_t *ccf = tidesdb_get_column_family(copy, "kv");
    ASSERT_TRUE(ccf != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(copy, ccf, key, val);
    }
    ASSERT_EQ(tidesdb_close(copy), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
    (void)remove_directory(ENGINE_TEST_BACKUP_DIR);
}

/* listing returns every created column family's name exactly once */
void test_engine_list_column_families(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "alpha", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "beta", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "gamma", &cc), TDB_SUCCESS);

    char **names = NULL;
    int count = 0;
    ASSERT_EQ(tidesdb_list_column_families(db, &names, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 3);

    int seen_alpha = 0, seen_beta = 0, seen_gamma = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(names[i], "alpha") == 0) seen_alpha = 1;
        if (strcmp(names[i], "beta") == 0) seen_beta = 1;
        if (strcmp(names[i], "gamma") == 0) seen_gamma = 1;
        free(names[i]);
    }
    free(names);
    ASSERT_TRUE(seen_alpha && seen_beta && seen_gamma);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a runtime config update changes the family in place, keeps its name, and persists across a reopen
 */
void test_engine_cf_update_runtime_config(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    tidesdb_column_family_config_t updated = st.config;
    updated.l1_file_count_trigger = 99; /* a distinctive persisted planner knob */
    snprintf(updated.name, sizeof(updated.name), "ignored"); /* name change must be ignored */
    ASSERT_EQ(engine_test_update_config(db, cf, &updated, 1), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ(st.config.l1_file_count_trigger, 99);
    ASSERT_TRUE(strcmp(st.config.name, "kv") == 0); /* the name was preserved */

    /* an encoding id naming no algorithm is refused rather than persisted. this is the one public
     * entry point that writes the pipeline array straight into the on-disk config, and the engine
     * later casts each entry to a compression algorithm */
    tidesdb_column_family_config_t bogus = st.config;
    bogus.encoding_pipeline[0] = ENGINE_TEST_UNKNOWN_ENCODING_ID;
    bogus.encoding_count = 1;
    ASSERT_EQ(tidesdb_cf_update_runtime_config(db, cf, &bogus, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ(st.config.l1_file_count_trigger, 99); /* the rejected update changed nothing */

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_EQ(st.config.l1_file_count_trigger, 99); /* the change persisted */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* observation state for the commit hook test */
static int g_hook_calls = 0;
static int g_hook_ops = 0;
static uint64_t g_hook_last_seq = 0;
static int g_hook_last_is_delete = -1;
static void *g_hook_ctx = NULL;

static int engine_test_commit_hook(const tidesdb_commit_op_t *ops, int num_ops, uint64_t commit_seq,
                                   void *ctx)
{
    g_hook_calls++;
    g_hook_ops += num_ops;
    g_hook_last_seq = commit_seq;
    g_hook_ctx = ctx;
    if (num_ops > 0) g_hook_last_is_delete = ops[num_ops - 1].is_delete;
    return 0;
}

/* the commit hook fires once per commit with that cf's ops and sequence, sees deletes, and stops
 * firing once cleared */
void test_engine_commit_hook(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    int marker = 42;
    g_hook_calls = 0;
    g_hook_ops = 0;
    g_hook_last_seq = 0;
    ASSERT_EQ(tidesdb_cf_set_commit_hook(db, cf, engine_test_commit_hook, &marker), TDB_SUCCESS);

    for (int i = 0; i < 3; i++) engine_put(db, cf, i); /* three separate commits, one op each */
    ASSERT_EQ(g_hook_calls, 3);
    ASSERT_EQ(g_hook_ops, 3);
    ASSERT_TRUE(g_hook_last_seq > 0);
    ASSERT_TRUE(g_hook_ctx == &marker);
    ASSERT_EQ(g_hook_last_is_delete, 0);

    /* a delete reaches the hook flagged as such */
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)"key00000", 8), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(g_hook_last_is_delete, 1);

    /* clearing the hook stops further invocations */
    ASSERT_EQ(tidesdb_cf_set_commit_hook(db, cf, NULL, NULL), TDB_SUCCESS);
    const int before = g_hook_calls;
    engine_put(db, cf, 99);
    ASSERT_EQ(g_hook_calls, before);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* renaming moves the family and its data under the new name, rejects a taken name and a missing
 * one, and the rename persists across a reopen */
/* a write buffer small enough that a modest key run rotates the log many times, and the number of
 * keys to write against it */
#define ENGINE_TEST_WAL_ROTATE_BUFFER (32u * 1024)
#define ENGINE_TEST_WAL_ROTATE_KEYS   2000

/* keys written per pass of the separated-value compression test */
#define ENGINE_TEST_COMPRESSED_VALUE_KEYS 200

/* the concurrent-rename test seeds this many keys into the family being renamed, and waits for this
 * many background commits before renaming so the two genuinely overlap */
#define ENGINE_TEST_RENAME_SEED_KEYS   200
#define ENGINE_TEST_RENAME_MIN_COMMITS 50

/* the writer used to show a rename does not stall commits; it writes to a family the rename never
 * touches, which is the case that used to stop dead because the lock was database-wide */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    _Atomic(int) stop;
    _Atomic(int) commits;
} rename_writer_t;

static void *engine_test_commit_until_stopped(void *arg)
{
    rename_writer_t *w = (rename_writer_t *)arg;
    for (int i = 0; !atomic_load(&w->stop); i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "bg%08d", i);
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(w->db, &txn) != TDB_SUCCESS) continue;
        if (tidesdb_txn_put(txn, w->cf, (const uint8_t *)key, strlen(key), (const uint8_t *)"v", 1,
                            -1) == TDB_SUCCESS &&
            tidesdb_txn_commit(txn) == TDB_SUCCESS)
            atomic_fetch_add(&w->commits, 1);
        tidesdb_txn_free(txn);
    }
    return NULL;
}

/* a rename runs to completion, correctly, while another family commits and flushes throughout, and
 * those commits keep landing across it. a family's files live under its immutable id, so a rename
 * moves nothing and has no flush to drain and no level set to rebuild -- which is what takes it off
 * the write path entirely */
void test_engine_rename_completes_under_concurrent_writes(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    /* a write buffer this small rotates on nearly every commit, which is the only time a committer
     * takes the rotation lock at all -- without that the writer would never meet the lock a rename
     * used to hold and the measurement would prove nothing */
    cfg.memtable_write_buffer_size = ENGINE_TEST_WAL_ROTATE_BUFFER;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_create_column_family(db, "busy", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *busy = tidesdb_get_column_family(db, "busy");
    ASSERT_TRUE(busy != NULL);

    for (int i = 0; i < ENGINE_TEST_RENAME_SEED_KEYS; i++) engine_put(db, cf, i);

    rename_writer_t w;
    w.db = db;
    w.cf = busy;
    atomic_init(&w.stop, 0);
    atomic_init(&w.commits, 0);
    pthread_t writer;
    ASSERT_EQ(pthread_create(&writer, NULL, engine_test_commit_until_stopped, &w), 0);

    /* let the writer get going, so the rename genuinely overlaps live commits and live flushes */
    while (atomic_load(&w.commits) < ENGINE_TEST_RENAME_MIN_COMMITS)
        usleep(ENGINE_TEST_LOCKED_BACKOFF_US);

    /* commits keep landing through the rename now that it moves no files: a rename that had to
     * drain a flush and rebuild a level set drove this to zero for its whole duration.
     *
     * the progress is waited for rather than read the instant the call returns. a rename that moves
     * nothing can finish inside a microsecond, which says nothing about whether writers were held
     * -- what distinguishes a rename that blocks them is that they never resume */
    const int c0 = atomic_load(&w.commits);
    ASSERT_EQ(tidesdb_rename_column_family(db, "kv", "renamed"), TDB_SUCCESS);
    for (int tick = 0; tick < ENGINE_TEST_RECLAIM_TICKS && atomic_load(&w.commits) <= c0; tick++)
        usleep(ENGINE_TEST_LOCKED_BACKOFF_US);
    ASSERT_TRUE(atomic_load(&w.commits) > c0);

    atomic_store(&w.stop, 1);
    pthread_join(writer, NULL);

    ASSERT_TRUE(tidesdb_get_column_family(db, "renamed") != NULL);
    ASSERT_TRUE(tidesdb_get_column_family(db, "kv") == NULL);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the load held across the create, and how long the create is allowed to take. the writers keep the
 * flush pool busy so its installs occupy the registry read lock; the readers keep the shared reader
 * epoch occupied so those installs finish with the immutable still pinned. how reliably that
 * combination stalls a create depends on the machine, so the deterministic guard for the reclaim
 * itself is in the memtable suite -- this one holds the whole path together under real load */
#define ENGINE_TEST_CREATE_WRITERS       4
#define ENGINE_TEST_CREATE_READERS       8
#define ENGINE_TEST_CREATE_DEADLINE_SECS 10
#define ENGINE_TEST_CREATE_MIN_COMMITS   200

/* keep reading so the database-wide reader epoch is never empty. the epoch a flush waits on to
 * reclaim an immutable is shared by every family, so a steady read load holds it occupied
 * continuously -- which is the condition under which an unbounded reclaim never finishes */
static void *engine_test_read_until_stopped(void *arg)
{
    rename_writer_t *w = (rename_writer_t *)arg;
    for (uint64_t i = 0; !atomic_load(&w->stop); i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "bg%08d", (int)(i % ENGINE_TEST_CREATE_MIN_COMMITS));
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(w->db, &txn) != TDB_SUCCESS) continue;
        uint8_t *val = NULL;
        size_t val_size = 0;
        if (tidesdb_txn_get(txn, w->cf, (const uint8_t *)key, strlen(key), &val, &val_size) ==
            TDB_SUCCESS)
            free(val);
        tidesdb_txn_free(txn);
    }
    return NULL;
}

/* a create completes promptly while every flush worker is taking the registry read lock. the
 * install path holds that lock, so a create waits behind it for writing; with readers preferred and
 * flushes arriving continuously the create is admitted only in a gap that never comes, and it hangs
 * for as long as the load lasts rather than failing */
/* a runtime reconfigure is validated against the encoding registry, as a create is. an id inside
 * the enum but with no codec in this build resolves to nothing, and a family carrying one can never
 * build an sstable again -- so accepting it here would report success and then strand the family's
 * data in the write-ahead logs */
void test_engine_runtime_config_rejects_an_unbacked_encoding(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    /* find a compression id this build does not carry; if every one is linked in there is nothing
     * to prove here and the check is skipped */
    int unbacked = -1;
    const tidesdb_compression_algorithm_t all[] = {TDB_COMPRESS_SNAPPY, TDB_COMPRESS_LZ4,
                                                   TDB_COMPRESS_ZSTD, TDB_COMPRESS_LZ4_FAST};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (!tidesdb_compression_available(all[i])) unbacked = (int)all[i];

    if (unbacked >= 0)
    {
        cc.encoding_pipeline[0] = (uint8_t)unbacked;
        cc.encoding_count = 1;
        ASSERT_EQ(tidesdb_cf_update_runtime_config(db, cf, &cc, 0), TDB_ERR_INVALID_ARGS);
    }

    /* a backed id is accepted, so the check is discriminating rather than rejecting everything.
     * through the retry, since this one has to reach the claim to succeed where the rejection
     * above is refused by validation before the claim is ever attempted */
    cc.encoding_pipeline[0] = (uint8_t)TDB_COMPRESS_NONE;
    cc.encoding_count = 1;
    ASSERT_EQ(engine_test_update_config(db, cf, &cc, 0), TDB_SUCCESS);

    /* the family still flushes, which is the property the rejection protects */
    engine_put(db, cf, 1);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* count the write-ahead log files physically present in the database directory. every one of them
 * is opened twice and given a memtable in the L0 queue on the next recovery, so a log left behind
 * costs far more than the bytes it occupies */
static int engine_count_wal_logs_on_disk(const char *db_dir)
{
    DIR *d = opendir(db_dir);
    if (!d) return -1;
    int n = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        const size_t len = strlen(e->d_name);
        if (len > 4 && strcmp(e->d_name + len - 4, ".log") == 0) n++;
    }
    closedir(d);
    return n;
}

/* preparers released together, so they all find the spare slot empty and race to fill it, which is
 * the arrangement that leaks */
#define ENGINE_TEST_SPARE_PREPARERS 16

typedef struct
{
    tidesdb_t *db;
    _Atomic(int) *gate;
} engine_spare_prepare_arg_t;

static void *engine_test_prepare_spare_wal(void *arg)
{
    engine_spare_prepare_arg_t *a = (engine_spare_prepare_arg_t *)arg;
    while (!atomic_load_explicit(a->gate, memory_order_acquire)) cpu_pause();
    engine_prepare_spare_wal(a->db);
    return NULL;
}

/* only one log can become the spare, so preparing one concurrently must leave only one log behind.
 * a preparer that loses the race holds the only reference to the file it created, and closing the
 * descriptor without unlinking it strands the file for the life of the database -- one per losing
 * committer, per rotation, forever */
void test_engine_preparing_a_spare_log_strands_no_file(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    const int before = engine_count_wal_logs_on_disk(db_path);
    ASSERT_TRUE(before >= 0);

    _Atomic(int) gate = 0;
    pthread_t threads[ENGINE_TEST_SPARE_PREPARERS];
    engine_spare_prepare_arg_t args[ENGINE_TEST_SPARE_PREPARERS];
    for (int i = 0; i < ENGINE_TEST_SPARE_PREPARERS; i++)
    {
        args[i].db = db;
        args[i].gate = &gate;
        ASSERT_EQ(pthread_create(&threads[i], NULL, engine_test_prepare_spare_wal, &args[i]), 0);
    }
    atomic_store_explicit(&gate, 1, memory_order_release);
    for (int i = 0; i < ENGINE_TEST_SPARE_PREPARERS; i++) pthread_join(threads[i], NULL);

    /* one spare was installed, so at most one log joined the directory */
    const int after = engine_count_wal_logs_on_disk(db_path);
    ASSERT_TRUE(after >= 0);
    ASSERT_TRUE(after - before <= 1);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* count the klog files physically present under a column family's directory, which is what the
 * filesystem charges for -- distinct from the live sstable count the level set reports */
static int engine_count_klogs_on_disk(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        const size_t len = strlen(e->d_name);
        if (len > 5 && strcmp(e->d_name + len - 5, ".klog") == 0) n++;
    }
    closedir(d);
    return n;
}

/* a compaction that merges its inputs away must take their files with it. the manifest stops naming
 * them and the level set stops referencing them, so nothing reads them again -- but the bytes stay
 * charged to the filesystem until someone unlinks them, and a merge that leaves every input behind
 * grows the store without bound while reporting a live set that looks healthy */
/* log_to_file and log_truncation_at were documented configuration that nothing read: the sink
 * existed, the fields existed, and no code connected them, so an embedder asking for a log file got
 * stderr and no indication otherwise */
void test_engine_log_to_file_writes_into_the_database_directory(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.log_to_file = 1;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the engine logs the open, the family create and the close at info, so the file has content */
    FILE *f = fopen(ENGINE_TEST_DB_DIR PATH_SEPARATOR "tidesdb.log", "rb");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    const long size = ftell(f);
    fclose(f);
    ASSERT_TRUE(size > 0);

    /* the sink went back to stderr with the handle that installed it, so a later database that did
     * not ask for a file does not keep writing to this one */
    cfg.log_to_file = 0;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    f = fopen(ENGINE_TEST_DB_DIR PATH_SEPARATOR "tidesdb.log", "rb");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    ASSERT_EQ(ftell(f), size);
    fclose(f);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the truncation threshold bounds the sink rather than letting it grow for the life of the process
 */
void test_engine_log_truncation_bounds_the_file(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.log_to_file = 1;
    cfg.log_truncation_at = ENGINE_TEST_LOG_TRUNCATE_AT;
    cfg.memtable_write_buffer_size = ENGINE_TEST_WAL_ROTATE_BUFFER;

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* enough flushes that the info lines alone exceed the threshold several times over */
    for (int i = 0; i < ENGINE_TEST_LOG_ROUNDS; i++)
    {
        engine_put(db, cf, i);
        (void)tidesdb_flush_memtable(db);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    FILE *f = fopen(ENGINE_TEST_DB_DIR PATH_SEPARATOR "tidesdb.log", "rb");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    const long size = ftell(f);
    fclose(f);

    /* bounded by the threshold plus whatever one line adds past it, not by the whole run */
    ASSERT_TRUE(size > 0);
    ASSERT_TRUE(size < (long)ENGINE_TEST_LOG_TRUNCATE_AT * 2);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* read the scheduler's plan memo the way the scheduler itself does -- while holding the family's
 * compaction claim. the two fields are plain rather than atomic precisely because only the claim
 * holder touches them, so a test that peeked without the claim would be racing the scheduler thread
 * rather than observing it */
static void engine_test_read_plan_memo(cf_t *cf, uint64_t *out_generation, uint64_t *out_floor)
{
    for (int attempt = 0; attempt < ENGINE_TEST_SCHED_TICKS; attempt++)
    {
        int expected = 0;
        if (atomic_compare_exchange_strong(&cf->compacting, &expected, 1))
        {
            *out_generation = cf->planned_generation;
            *out_floor = cf->planned_gc_floor;
            atomic_store_explicit(&cf->compacting, 0, memory_order_release);
            return;
        }
        usleep(ENGINE_TEST_SCHED_STALL_US);
    }
}

/* the value of a merge depends on the reclamation floor as much as on the shape: when transactions
 * drain, versions the same layout could not drop become droppable. a memo keyed on shape alone
 * stops reconsidering exactly when the work becomes worth doing */
void test_engine_scheduler_replans_when_the_gc_floor_moves(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    cf_t *inner = (cf_t *)cf;

    /* let the scheduler settle on this shape, with no transaction holding the floor down */
    for (int tick = 0; tick < ENGINE_TEST_SCHED_TICKS; tick++)
    {
        uint64_t planned = 0, floor = 0;
        engine_test_read_plan_memo(inner, &planned, &floor);
        if (planned == level_set_generation(inner->levels)) break;
        usleep(ENGINE_TEST_SCHED_STALL_US);
    }
    uint64_t settled_generation = 0, settled_floor = 0;
    engine_test_read_plan_memo(inner, &settled_generation, &settled_floor);
    ASSERT_EQ(settled_generation, level_set_generation(inner->levels));

    /* a long-lived snapshot lowers the floor, which is a reason to plan again even though not one
     * byte was written */
    tidesdb_txn_t *holder = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &holder), TDB_SUCCESS);

    int replanned = 0;
    for (int tick = 0; tick < ENGINE_TEST_SCHED_TICKS; tick++)
    {
        uint64_t planned = 0, floor = 0;
        engine_test_read_plan_memo(inner, &planned, &floor);
        if (floor != settled_floor)
        {
            replanned = 1;
            break;
        }
        usleep(ENGINE_TEST_SCHED_STALL_US);
    }
    ASSERT_TRUE(replanned);

    ASSERT_EQ(tidesdb_txn_rollback(holder), TDB_SUCCESS);
    tidesdb_txn_free(holder);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* an idle database still drains: the active memtable is rotated once a whole interval passes with
 * no write landing in it, so its data reaches L1 and its log can be unlinked rather than being held
 * in memory until the process next takes a write */
void test_engine_idle_flush_rotates_an_unwritten_memtable(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_idle_flush_seconds = 1;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* well under the rotation threshold, so nothing but the idle ticker can seal this */
    for (int i = 0; i < ENGINE_TEST_IDLE_KEYS; i++) engine_put(db, cf, i);
    ASSERT_TRUE(tidesdb_l0_active_bytes(db->l0) > 0);

    int drained = 0;
    for (int tick = 0; tick < ENGINE_TEST_IDLE_TICKS; tick++)
    {
        tidesdb_cf_stats_t st;
        ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
        if (st.level_num_sstables[LEVEL_SET_L1 - 1] > 0)
        {
            drained = 1;
            break;
        }
        usleep(ENGINE_TEST_IDLE_STALL_US);
    }
    ASSERT_TRUE(drained);

    /* and the data is still readable through the rotation */
    engine_assert_committed(db, cf, "key00000", "val00000");

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* count the write-ahead log generations still on disk at the database root */
static int engine_count_wal_logs(const char *db_dir)
{
    DIR *d = opendir(db_dir);
    if (!d) return -1;
    int n = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        const size_t len = strlen(e->d_name);
        if (len > 4 && strcmp(e->d_name + len - 4, ".log") == 0) n++;
    }
    closedir(d);
    return n;
}

/* a log is kept past its flush only while it holds the durable copy of something still needed. one
 * undecided prepare must therefore pin its own generation and nothing else -- every other
 * generation has its data in L1 and nothing in doubt. holding them all turns a slow coordinator, or
 * a workload that always has a prepare in flight, into unbounded disk */
/* a batch recovered in doubt keeps its log across later flushes even when nothing ever asks for the
 * in-doubt list. the pin has to be taken by recovery itself rather than by whoever adopts the
 * transaction, or a database that simply reopens and carries on writing unlinks the only copy of a
 * batch its coordinator has not decided yet */
void test_engine_recovered_in_doubt_batch_survives_later_flushes(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    const uint8_t xid[] = "xid-orphan";
    const uint8_t key[] = "pending", val[] = "pv";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *hanging = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &hanging), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(hanging, cf, key, sizeof(key) - 1, val, sizeof(val) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(hanging, xid, sizeof(xid) - 1), TDB_SUCCESS);
    tidesdb_txn_free(hanging); /* the coordinator went away; the batch stays in doubt on disk */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* reopen and keep writing, never asking for the in-doubt list */
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    for (int round = 0; round < ENGINE_TEST_WAL_PIN_ROUNDS; round++)
    {
        for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, round * 1000 + i);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the batch is still in doubt and still decidable, so its log outlived every one of those
     * flushes */
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    int count = 0;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);

    tidesdb_prepared_txn_t found;
    ASSERT_EQ(tidesdb_recover_prepared(db, &found, 1, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(tidesdb_txn_commit_prepared(found.txn), TDB_SUCCESS);
    tidesdb_txn_free(found.txn);

    engine_assert_committed(db, cf, "pending", "pv");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_undecided_prepare_pins_only_its_own_generation(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* one prepare, deliberately left in doubt for the rest of the test */
    tidesdb_txn_t *indoubt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &indoubt), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(indoubt, cf, (const uint8_t *)"pending", 7, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(indoubt, (const uint8_t *)"xid-1", 5), TDB_SUCCESS);

    /* several further generations, each fully flushed to L1 and holding nothing in doubt */
    for (int round = 0; round < ENGINE_TEST_WAL_PIN_ROUNDS; round++)
    {
        for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, round * 1000 + i);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }

    /* the generation holding the prepare, plus the active one, is what the store needs. every other
     * flushed generation is durable in L1 and should be gone */
    const int logs = engine_count_wal_logs(ENGINE_TEST_DB_DIR);
    ASSERT_TRUE(logs > 0);
    ASSERT_TRUE(logs <= ENGINE_TEST_WAL_PIN_ALLOWED);

    ASSERT_EQ(tidesdb_txn_rollback_prepared(indoubt), TDB_SUCCESS);
    tidesdb_txn_free(indoubt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a finished sstable occupies its data, not its preallocated extent. preallocation advances the
 * file's logical end rather than only reserving blocks, and the only other trim runs at close --
 * which a live sstable never reaches -- so an untrimmed build is charged a whole 64 MiB chunk for
 * as long as it is installed. a store of any size is then mostly padding */
/* a family's reported size is its key logs and nothing else. adding the summed value length on top
 * counts every inline value twice -- once in the key log that holds it and once again as a value --
 * which for a workload whose values all stay under the spill threshold reports double the truth,
 * and makes every space question asked of the engine unanswerable */
void test_engine_cf_data_size_counts_key_logs_once(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* values well under the default spill threshold, so every one is inline and double counting
     * would show up as roughly twice the real size */
    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.total_data_size > 0);

    uint64_t levels_total = 0;
    for (int lvl = 0; lvl < TDB_MAX_LEVELS; lvl++) levels_total += st.level_sizes[lvl];

    /* the two are the same measurement, so they agree exactly */
    ASSERT_EQ((int)(st.total_data_size - levels_total), 0);

    /* and it is the real file size, not the file plus its contents again */
    DIR *d = opendir(ENGINE_TEST_CF0_DIR);
    ASSERT_TRUE(d != NULL);
    uint64_t on_disk = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        const size_t len = strlen(e->d_name);
        if (len <= 5 || strcmp(e->d_name + len - 5, ".klog") != 0) continue;
        if (strncmp(e->d_name, ENGINE_TEST_CF0_PREFIX, strlen(ENGINE_TEST_CF0_PREFIX)) != 0)
            continue;
        char path[ENGINE_TEST_PATH_MAX];
        snprintf(path, sizeof(path), "%s%s%s", ENGINE_TEST_CF0_DIR, PATH_SEPARATOR, e->d_name);
        FILE *f = fopen(path, "rb");
        ASSERT_TRUE(f != NULL);
        ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
        on_disk += (uint64_t)ftell(f);
        fclose(f);
    }
    closedir(d);
    ASSERT_EQ((int)(on_disk - st.total_data_size), 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a write latency tail has to be attributable from the engine's own numbers. every place a writer
 * can be made to wait reports a count, a total and a longest -- without which the only way to learn
 * why a commit took a second is to attach a debugger to one while it is happening */
/* the other half of attributing a stall: what each class of file asked of the device. knowing
 * writers waited on the log means nothing until you can also see whether the log's own writes were
 * slow, and how much traffic the sstables were putting beside them */
void test_engine_io_stats_attribute_device_work(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_io_stats_t before;
    ASSERT_EQ(tidesdb_get_io_stats(db, &before), TDB_SUCCESS);
    for (int i = 0; i < TDB_IO_COUNT; i++)
    {
        ASSERT_EQ((int)before.classes[i].ops, 0);
        ASSERT_EQ((int)before.classes[i].bytes, 0);
        ASSERT_TRUE(strcmp(tidesdb_io_class_name((tidesdb_io_class_t)i), "unknown") != 0);
    }
    ASSERT_TRUE(strcmp(tidesdb_io_class_name(TDB_IO_COUNT), "unknown") == 0);

    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);

    /* every commit writes its record to the log, so that class must have moved */
    tidesdb_io_stats_t after;
    ASSERT_EQ(tidesdb_get_io_stats(db, &after), TDB_SUCCESS);
    ASSERT_TRUE(after.classes[TDB_IO_WAL].ops > 0);
    ASSERT_TRUE(after.classes[TDB_IO_WAL].bytes > 0);

    /* a flush lands the data in a key log, so that class moves too */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_get_io_stats(db, &after), TDB_SUCCESS);
    ASSERT_TRUE(after.classes[TDB_IO_SSTABLE].ops > 0);
    ASSERT_TRUE(after.classes[TDB_IO_SSTABLE].bytes > 0);

    /* a class cannot have written fewer bytes than one write, nor a total below its slowest one */
    for (int i = 0; i < TDB_IO_COUNT; i++)
    {
        if (after.classes[i].ops == 0) continue;
        ASSERT_TRUE(after.classes[i].bytes >= after.classes[i].ops);
        ASSERT_TRUE(after.classes[i].total_us >= after.classes[i].max_us);
    }

    ASSERT_EQ(tidesdb_get_io_stats(NULL, &after), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_get_io_stats(db, NULL), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_stall_stats_attribute_writer_waits(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_stall_stats_t before;
    ASSERT_EQ(tidesdb_get_stall_stats(db, &before), TDB_SUCCESS);
    for (int i = 0; i < TDB_STALL_COUNT; i++)
    {
        ASSERT_EQ((int)before.reasons[i].count, 0);
        ASSERT_EQ((int)before.reasons[i].total_us, 0);
        ASSERT_EQ((int)before.reasons[i].max_us, 0);
        /* every reason names itself, so a stats table needs no parallel list of labels */
        ASSERT_TRUE(strcmp(tidesdb_stall_reason_name((tidesdb_stall_reason_t)i), "unknown") != 0);
    }
    ASSERT_TRUE(strcmp(tidesdb_stall_reason_name(TDB_STALL_COUNT), "unknown") == 0);

    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);

    /* the log is the one wait every commit passes through, so it is the one that must have counted
     * something; the others are load-dependent and may legitimately be zero */
    tidesdb_stall_stats_t after;
    ASSERT_EQ(tidesdb_get_stall_stats(db, &after), TDB_SUCCESS);
    ASSERT_TRUE(after.reasons[TDB_STALL_WAL_APPEND].count > 0);

    /* a total can never be less than the longest single wait inside it */
    for (int i = 0; i < TDB_STALL_COUNT; i++)
        ASSERT_TRUE(after.reasons[i].total_us >= after.reasons[i].max_us);

    ASSERT_EQ(tidesdb_get_stall_stats(NULL, &after), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_get_stall_stats(db, NULL), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_finished_sstable_is_trimmed_to_its_data(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* two flushes then a merge, because a flush sizes its own preallocation to the run it is about
     * to write while a compaction takes the block manager's default chunk -- so the output that
     * would be left holding a whole extent is the merged one */
    for (int round = 0; round < 2; round++)
    {
        for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, round * 1000 + i);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }
    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);

    /* measured while the database is still open, which is the whole point -- closing would trim it
     * either way and hide the defect */
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.total_data_size > 0);

    DIR *d = opendir(ENGINE_TEST_CF0_DIR);
    ASSERT_TRUE(d != NULL);
    uint64_t on_disk = 0;
    int klogs = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        const size_t len = strlen(e->d_name);
        if (len <= 5 || strcmp(e->d_name + len - 5, ".klog") != 0) continue;
        if (strncmp(e->d_name, ENGINE_TEST_CF0_PREFIX, strlen(ENGINE_TEST_CF0_PREFIX)) != 0)
            continue;
        char path[ENGINE_TEST_PATH_MAX];
        snprintf(path, sizeof(path), "%s%s%s", ENGINE_TEST_CF0_DIR, PATH_SEPARATOR, e->d_name);
        FILE *f = fopen(path, "rb");
        ASSERT_TRUE(f != NULL);
        ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
        on_disk += (uint64_t)ftell(f);
        fclose(f);
        klogs++;
    }
    closedir(d);
    ASSERT_TRUE(klogs > 0);

    /* the file holds its data, not a preallocation chunk. the bound is generous -- what it rules
     * out is a file rounded up to the extent, which for this little data is orders of magnitude
     * larger */
    ASSERT_TRUE(on_disk < (uint64_t)klogs * ENGINE_TEST_PREALLOC_CHUNK);
    ASSERT_TRUE(on_disk <= st.total_data_size * ENGINE_TEST_TRIM_SLACK);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_compaction_unlinks_merged_inputs(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    /* the compaction this asserts on is the forced one below, so the background scheduler is kept
     * away from the inputs. it was previously only losing the race by luck */
    cc.l1_file_count_trigger = 1000000;
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* two flushes, so L1 holds two sstables for the forced compaction to merge */
    for (int round = 0; round < 2; round++)
    {
        for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, round * 1000 + i);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }

    /* the family's key logs sit in the database directory, and this database holds one family, so
     * every key log there is its */
    const int before = engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR);
    ASSERT_TRUE(before >= 2);

    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);

    /* the merged inputs are gone from the live set */
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    int live = 0;
    for (int lvl = 0; lvl < TDB_MAX_LEVELS; lvl++) live += st.level_num_sstables[lvl];

    /* give the deferred reclaim a chance to run, since the unlink cannot happen while a reader
     * could still be inside the retired layout */
    for (int tick = 0; tick < ENGINE_TEST_RECLAIM_TICKS; tick++)
    {
        if (engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR) <= live) break;
        usleep(ENGINE_TEST_RECLAIM_STALL_US);
    }
    const int after = engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR);

    /* every file on disk must be one the live set still names; anything else is space the store can
     * never give back while it is open */
    ASSERT_EQ(after, live);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the same property under repeated flush and background compaction rather than one forced merge.
 * this is the shape the space leak was reported in: an insert-only load where compaction keeps
 * running, the live set stays modest, and the files left behind are what fills the disk */
void test_engine_compaction_leaves_no_orphans_under_load(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = ENGINE_TEST_WAL_ROTATE_BUFFER;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    for (int i = 0; i < ENGINE_TEST_ORPHAN_KEYS; i++)
    {
        engine_put(db, cf, i);
        if ((i % ENGINE_TEST_ORPHAN_FLUSH_EVERY) == 0) (void)tidesdb_flush_memtable(db);
    }
    (void)tidesdb_flush_memtable(db);
    (void)tidesdb_compact(db, cf);

    /* one family, and its key logs live in the database directory beside everything else */
    tidesdb_cf_stats_t st;
    int live = 0, on_disk = 0;
    for (int tick = 0; tick < ENGINE_TEST_RECLAIM_TICKS; tick++)
    {
        ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
        live = 0;
        for (int lvl = 0; lvl < TDB_MAX_LEVELS; lvl++) live += st.level_num_sstables[lvl];
        on_disk = engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR);
        if (on_disk <= live) break;
        usleep(ENGINE_TEST_RECLAIM_STALL_US);
    }

    /* every file the filesystem is charged for is one the engine can still read */
    ASSERT_EQ(on_disk, live);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a klog no manifest entry names is dead weight -- a crash between an sstable finishing and the
 * commit that names it leaves one, as does any store written before compaction learned to unlink
 * what it merged away. nothing reads them, so only the filesystem notices */
void test_engine_open_sweeps_orphaned_sstables(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    const int named = engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR);
    ASSERT_TRUE(named >= 1);

    /* stand in for what a crash leaves: a klog at an id the manifest never recorded, plus the leaf
     * staging file a build writes beside one */
    const char *orphan = ENGINE_TEST_CF0_DIR PATH_SEPARATOR "0000000000.9999998.klog";
    const char *stage = ENGINE_TEST_CF0_DIR PATH_SEPARATOR "0000000000.9999999.klog.lstmp";
    FILE *f = fopen(orphan, "wb");
    ASSERT_TRUE(f != NULL);
    fputs("orphan", f);
    fclose(f);
    f = fopen(stage, "wb");
    ASSERT_TRUE(f != NULL);
    fputs("stage", f);
    fclose(f);
    ASSERT_EQ(engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR), named + 1);

    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    /* the orphan and its staging file are gone, and every klog the manifest names survived */
    ASSERT_EQ(engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR), named);
    FILE *gone = fopen(stage, "rb");
    ASSERT_TRUE(gone == NULL);

    /* the data the manifest does name is still readable, so the sweep took only the dead files */
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "key00000", "val00000");

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the sweep must not run when the manifest was self-healed. a rebuild adopts whatever sstables are
 * on disk, so at that moment the files are the catalogue's source -- sweeping against a manifest
 * derived from them would delete exactly the ones the rebuild could not adopt, which is the only
 * copy of that data left */
void test_engine_open_keeps_sstables_when_manifest_self_healed(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the family's key logs sit in the database directory, and this database holds one family, so
     * every key log there is its */
    const int before = engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR);
    ASSERT_TRUE(before >= 1);

    /* a klog the rebuild will not be able to adopt, which is the case the guard exists for: the
     * rebuild skips it, so the manifest it produces does not name it, and a sweep keyed on that
     * manifest would delete the only copy of whatever it holds */
    const char *unreadable = ENGINE_TEST_CF0_DIR PATH_SEPARATOR "0000000000.9999998.klog";
    FILE *f = fopen(unreadable, "wb");
    ASSERT_TRUE(f != NULL);
    fputs("half a sstable", f);
    fclose(f);

    /* destroy the manifest header so the next open has to rebuild from the sstables */
    f = fopen(ENGINE_TEST_DB_DIR PATH_SEPARATOR "MANIFEST", "wb");
    ASSERT_TRUE(f != NULL);
    fputs("not a manifest", f);
    fclose(f);

    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    /* every sstable survived the rebuild open, the unadoptable one included */
    ASSERT_EQ(engine_count_klogs_on_disk(ENGINE_TEST_DB_DIR), before + 1);
    FILE *kept = fopen(unreadable, "rb");
    ASSERT_TRUE(kept != NULL);
    fclose(kept);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_create_completes_under_sustained_flush(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    /* rotate on nearly every commit so the flush pool is never idle and its installs keep the
     * registry read lock occupied for the whole test */
    cfg.memtable_write_buffer_size = ENGINE_TEST_WAL_ROTATE_BUFFER;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "busy", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *busy = tidesdb_get_column_family(db, "busy");
    ASSERT_TRUE(busy != NULL);

    rename_writer_t w;
    w.db = db;
    w.cf = busy;
    atomic_init(&w.stop, 0);
    atomic_init(&w.commits, 0);
    pthread_t writers[ENGINE_TEST_CREATE_WRITERS];
    for (int i = 0; i < ENGINE_TEST_CREATE_WRITERS; i++)
        ASSERT_EQ(pthread_create(&writers[i], NULL, engine_test_commit_until_stopped, &w), 0);

    /* the readers are what keep the shared reader epoch occupied, so a flush finishing an install
     * finds the immutable it just wrote still pinned */
    pthread_t readers[ENGINE_TEST_CREATE_READERS];
    for (int i = 0; i < ENGINE_TEST_CREATE_READERS; i++)
        ASSERT_EQ(pthread_create(&readers[i], NULL, engine_test_read_until_stopped, &w), 0);

    while (atomic_load(&w.commits) < ENGINE_TEST_CREATE_MIN_COMMITS)
        usleep(ENGINE_TEST_LOCKED_BACKOFF_US);

    const time_t started = time(NULL);
    const int rc = tidesdb_create_column_family(db, "late", &cc);
    const time_t elapsed = time(NULL) - started;

    atomic_store(&w.stop, 1);
    for (int i = 0; i < ENGINE_TEST_CREATE_WRITERS; i++) pthread_join(writers[i], NULL);
    for (int i = 0; i < ENGINE_TEST_CREATE_READERS; i++) pthread_join(readers[i], NULL);

    ASSERT_EQ(rc, TDB_SUCCESS);
    ASSERT_TRUE(elapsed < ENGINE_TEST_CREATE_DEADLINE_SECS);
    ASSERT_TRUE(tidesdb_get_column_family(db, "late") != NULL);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_rename_column_family(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const int n = 60;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);

    /* not-found and already-exists are rejected */
    ASSERT_EQ(tidesdb_rename_column_family(db, "missing", "whatever"), TDB_ERR_NOT_FOUND);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "other", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_rename_column_family(db, "kv", "other"), TDB_ERR_EXISTS);

    ASSERT_EQ(tidesdb_rename_column_family(db, "kv", "renamed"), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_get_column_family(db, "kv") == NULL);
    tidesdb_column_family_t *rcf = tidesdb_get_column_family(db, "renamed");
    ASSERT_TRUE(rcf != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, rcf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the rename survives a reopen: the new name has the data, the old is gone */
    db = NULL;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_get_column_family(db, "kv") == NULL);
    rcf = tidesdb_get_column_family(db, "renamed");
    ASSERT_TRUE(rcf != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, rcf, key, val);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* cloning produces an independent family holding the same data, which both sides keep across a
 * reopen, and a later write to one is invisible to the other */
/* a clone takes on the source's range tombstones along with its files. the sstables it copies still
 * hold every key those tombstones covered, so a clone that left them behind would hand back data
 * the source had deleted */
/* count the distinct keys the family's sstables actually hold, across every level. a read hiding a
 * key and a compaction having removed it look the same from outside, so this is what tells them
 * apart */
static uint64_t engine_sstable_key_count(cf_t *cf)
{
    sstable_t *out[128];
    const int n = level_set_collect_all(cf->levels, out, 128);
    uint64_t total = 0;
    for (int i = 0; i < n && i < 128; i++)
    {
        total += out[i]->distinct_key_count;
        if (sstable_unref(out[i])) sstable_close(out[i]);
    }
    return total;
}

/* compaction physically drops the versions a range tombstone covers once the tombstone sits at or
 * below the reclamation floor -- until it does, the keys are only hidden and every read pays for
 * them */
void test_engine_compaction_drops_versions_a_range_tombstone_covers(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const int n = 40;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    cf_t *icf = (cf_t *)cf;
    const uint64_t before = engine_sstable_key_count(icf);
    ASSERT_TRUE(before >= (uint64_t)n);

    /* every key written so far falls under this interval, and it sits at or below the reclamation
     * floor because no transaction is holding a snapshot open.
     *
     * written through a transaction rather than pushed into the family's set directly. the set is
     * the union of what the family's tables carry, republished whenever the layout changes, so an
     * interval that reached no table would be dropped by the next rebuild -- which is the point of
     * deriving it, and means a delete has to arrive the way the engine delivers one */
    tidesdb_txn_t *deleter = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &deleter), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(deleter, cf, (const uint8_t *)"key", 3, (const uint8_t *)"kez", 3),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(deleter), TDB_SUCCESS);
    tidesdb_txn_free(deleter);

    /* hidden, but still on disk */
    engine_assert_committed(db, cf, "key00000", NULL);
    ASSERT_EQ(engine_sstable_key_count(icf), before);

    /* more data, written after the tombstone so its own sequences are above it and it cannot touch
     * them, then a compaction so the covered run is actually rewritten */
    for (int i = n; i < n * 2; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    const uint64_t both = engine_sstable_key_count(icf);
    ASSERT_TRUE(both >= (uint64_t)(n * 2));

    for (int pass = 0; pass < 4; pass++)
    {
        const int rc = engine_test_compact(db, cf);
        ASSERT_TRUE(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED);
    }

    /* the covered keys are gone from the files, not merely hidden by a read, and the ones written
     * above the tombstone are all that is left */
    const uint64_t after = engine_sstable_key_count(icf);
    ASSERT_TRUE(after < both);
    ASSERT_TRUE(after >= (uint64_t)n);

    /* and they still read as absent, while a key written after the tombstone survives */
    engine_assert_committed(db, cf, "key00000", NULL);
    engine_assert_committed(db, cf, "key00039", NULL);
    char late[16], late_val[16];
    snprintf(late, sizeof(late), "key%05d", n);
    snprintf(late_val, sizeof(late_val), "val%05d", n);
    engine_assert_committed(db, cf, late, late_val);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* an interval outlives everything that still needs it, and that is now a property of where it is
 * kept rather than of a sweep proving it spent. the family's set is the union of what its tables
 * carry, republished whenever the layout changes, so an interval is present exactly while a table
 * carries it and goes when the last one holding it is merged away.
 *
 * the assertion that matters is the one at the end -- once the interval is no longer published, the
 * keys it covered have to stay gone, because a merge rewrote them rather than the interval hiding
 * them. that is what fails if the union is ever republished without an interval something still
 * needed */
void test_engine_range_tombstone_lives_as_long_as_a_table_carries_it(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    cf_t *icf = (cf_t *)cf;

    /* a table built before any interval existed, carrying keys the interval will cover */
    const int n = 30;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the interval and a key that outlives it go in together, so the flush builds a table for the
     * family and that table is what carries the interval */
    tidesdb_txn_t *deleter = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &deleter), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(deleter, cf, (const uint8_t *)"key", 3, (const uint8_t *)"kez", 3),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(deleter, cf, (const uint8_t *)"zz", 2, (const uint8_t *)"v", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(deleter), TDB_SUCCESS);
    tidesdb_txn_free(deleter);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the flush put it in a table, and the covered keys read as gone through it */
    engine_assert_committed(db, cf, "key00000", NULL);

    /* and it is a table that carries it, since there is nowhere else for it to be */
    sstable_t *tabs[64];
    const int nt = level_set_collect_all(icf->levels, tabs, 64);
    int carried_by_a_table = 0;
    for (int i = 0; i < nt; i++)
    {
        if (tabs[i]->range_tombstones && range_tombstone_set_count(tabs[i]->range_tombstones) > 0)
            carried_by_a_table = 1;
        if (sstable_unref(tabs[i])) sstable_close(tabs[i]);
    }
    ASSERT_TRUE(carried_by_a_table);

    /* merge until the covered run has been rewritten out of every table */
    for (int pass = 0; pass < 6; pass++)
    {
        const int rc = engine_test_compact(db, cf);
        ASSERT_TRUE(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED);
    }

    /* whether the interval is still published or not, the keys it covered stay gone -- a merge
     * removed them rather than the interval hiding them */
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        engine_assert_committed(db, cf, key, NULL);
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* and across a reopen, where the set is derived from the tables that came back */
    tidesdb_config_t reopen = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        engine_assert_committed(db, cf, key, NULL);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* at snapshot isolation a prefix delete has to conflict with a write to any key under it, not just
 * with a write to the one key whose bytes spell the prefix. probing it as a key would clear a
 * commit that is about to delete data another transaction wrote after this one drew its snapshot */
/* the whole feature through the public surface only -- a prefix delete, its durability across a
 * reopen, what a scan sees, and the keys it must leave alone */
/* a two-phase prefix delete holds its interval from the prepare until phase two resolves it. the
 * commit gate cannot cover that window -- it has no bound, and holding it would stop every other
 * committer for as long as the transaction stays undecided -- so the interval reservation is what
 * stands between an in-doubt prefix delete and a write under it */
/* how long the reader thread hammers a key while compactions move it between levels. the window is
 * one mask read straddling one layout swap, so it takes many attempts rather than a long wait */
#define ENGINE_LAYOUT_RACE_READS   40000
#define ENGINE_LAYOUT_RACE_KEYS    64
#define ENGINE_LAYOUT_RACE_COMPACT 400
/* one reader, not several. more of them contend the family's compaction claim, so fewer swaps
 * actually happen and the window this is trying to hit opens less often, not more */
#define ENGINE_LAYOUT_RACE_READERS 1

typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    _Atomic(int) stop;
    _Atomic(int) missing;
} engine_layout_race_t;

/* read committed keys over and over. every one of them is present for the whole run, so a single
 * absence is the bug: the reader skipped the level a compaction had just moved the table into,
 * having read the occupancy mask before the move and scanned the level after it */
static void *engine_layout_race_reader(void *arg)
{
    engine_layout_race_t *st = (engine_layout_race_t *)arg;
    for (int i = 0; i < ENGINE_LAYOUT_RACE_READS && !atomic_load(&st->stop); i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i % ENGINE_LAYOUT_RACE_KEYS);

        tidesdb_txn_t *t = NULL;
        if (tidesdb_txn_begin(st->db, &t) != TDB_SUCCESS) continue;
        uint8_t *value = NULL;
        size_t value_size = 0;
        const int rc =
            tidesdb_txn_get(t, st->cf, (const uint8_t *)key, strlen(key), &value, &value_size);
        if (rc == TDB_ERR_NOT_FOUND) atomic_fetch_add(&st->missing, 1);
        free(value);
        (void)tidesdb_txn_rollback(t);
        tidesdb_txn_free(t);
    }
    return NULL;
}

/* a key that is on disk the whole time must never read as absent while compaction moves its table
 * between levels.
 *
 * this catches the bug it was written for about one run in twenty, because the window is a handful
 * of instructions between one mask read and one layout swap. it is a stress rather than a tight
 * guard, and it is worth knowing that a single clean run of it proves very little. the read
 * snapshots which levels are occupied and then scans each one against the live layout, so a table
 * moved into a level the snapshot called empty is skipped -- and unlike a flush, a compaction
 * leaves no copy in L0 to be found instead */
void test_engine_read_survives_a_compaction_moving_levels(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* written once, so each key lives in exactly one table that then migrates down the levels. a
     * key rewritten every round would sit in the shallowest level and be found before the walk ever
     * reached the level a compaction was moving, which is the whole thing under test */
    for (int i = 0; i < ENGINE_LAYOUT_RACE_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* every key is on disk and stays there; nothing below deletes or rewrites one */
    engine_assert_committed(db, cf, "key00000", "val00000");

    engine_layout_race_t st;
    st.db = db;
    st.cf = cf;
    atomic_init(&st.stop, 0);
    atomic_init(&st.missing, 0);

    pthread_t readers[ENGINE_LAYOUT_RACE_READERS];
    for (int i = 0; i < ENGINE_LAYOUT_RACE_READERS; i++)
        ASSERT_EQ(pthread_create(&readers[i], NULL, engine_layout_race_reader, &st), 0);

    /* drive the table down the levels under the reader. each pass can move it into a level that was
     * empty a moment earlier, which is the shape the mask snapshot gets wrong */
    for (int pass = 0; pass < ENGINE_LAYOUT_RACE_COMPACT && !atomic_load(&st.missing); pass++)
    {
        const int rc = engine_test_compact(db, cf);
        ASSERT_TRUE(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED);
    }
    atomic_store(&st.stop, 1);
    for (int i = 0; i < ENGINE_LAYOUT_RACE_READERS; i++) pthread_join(readers[i], NULL);

    ASSERT_EQ(atomic_load(&st.missing), 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_prepared_prefix_delete_blocks_a_write_under_it(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    const uint32_t cf_index = (uint32_t)((cf_t *)cf)->cf_id;

    /* prepare a prefix delete and leave it in doubt */
    tidesdb_txn_t *deleter = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &deleter), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_delete_prefix(deleter->inner, cf_index, (const uint8_t *)"user:", 5),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(deleter, (const uint8_t *)"xid-1", 5), TDB_SUCCESS);

    /* a write under the interval is refused while it is undecided */
    tidesdb_txn_t *writer = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &writer), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(writer, cf, (const uint8_t *)"user:7", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(writer), TDB_ERR_CONFLICT);
    tidesdb_txn_free(writer);

    /* a write outside it is not */
    tidesdb_txn_t *elsewhere = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &elsewhere),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(elsewhere, cf, (const uint8_t *)"acct:1", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(elsewhere), TDB_SUCCESS);
    tidesdb_txn_free(elsewhere);

    /* once phase two resolves it the interval is let go, and the write it was blocking goes through
     */
    ASSERT_EQ(tidesdb_txn_commit_prepared(deleter), TDB_SUCCESS);
    tidesdb_txn_free(deleter);

    tidesdb_txn_t *after = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &after), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(after, cf, (const uint8_t *)"user:7", 6, (const uint8_t *)"v", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(after), TDB_SUCCESS);
    tidesdb_txn_free(after);
    engine_assert_committed(db, cf, "user:7", "v");

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a range whose bounds fall where no prefix could put them. "key00012" through "key00027" shares no
 * prefix that covers it and nothing else, which is the case a prefix delete cannot express at all
 */
void test_engine_delete_range_covers_bounds_no_prefix_could(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const int n = 40;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, (const uint8_t *)"key00012", 8,
                                       (const uint8_t *)"key00027", 8),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    /* inside is gone, the bounds behave half-open, and outside is untouched */
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        if (i >= 12 && i < 27)
            engine_assert_committed(db, cf, key, NULL);
        else
            engine_assert_committed(db, cf, key, val);
    }

    /* the upper bound is exclusive, so the key that spells it survives -- the half-open boundary a
     * prefix delete never has to answer for */
    engine_assert_committed(db, cf, "key00027", "val00027");
    engine_assert_committed(db, cf, "key00011", "val00011");

    /* a scan agrees with the point reads across the hole */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(t, cf, &it), TDB_SUCCESS);
    int seen = 0, seen_inside = 0;
    for (int rc = tidesdb_iter_seek_to_first(it); rc == TDB_SUCCESS && tidesdb_iter_valid(it);
         rc = tidesdb_iter_next(it))
    {
        uint8_t *k = NULL;
        size_t ks = 0;
        ASSERT_EQ(tidesdb_iter_key(it, &k, &ks), TDB_SUCCESS);
        if (ks == 8 && memcmp(k, "key000", 6) == 0)
        {
            const int idx = (k[6] - '0') * 10 + (k[7] - '0');
            seen++;
            if (idx >= 12 && idx < 27) seen_inside = 1;
        }
        free(k);
    }
    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(seen_inside, 0);
    ASSERT_EQ(seen, n - 15); /* forty written, fifteen inside the range */

    /* an open upper bound runs to the end of the family */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, (const uint8_t *)"key00030", 8, NULL, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, cf, "key00035", NULL);
    engine_assert_committed(db, cf, "key00029", "val00029");

    /* and it all survives a reopen, from the manifest */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_t *reopened = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(reopened != NULL);
    engine_assert_committed(db, reopened, "key00015", NULL);
    engine_assert_committed(db, reopened, "key00027", "val00027");
    engine_assert_committed(db, reopened, "key00035", NULL);
    engine_assert_committed(db, reopened, "key00029", "val00029");

    /* an empty lower bound is refused */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, reopened, (const uint8_t *)"", 0, NULL, 0),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_public_prefix_delete_end_to_end(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"user:1", 6, (const uint8_t *)"a", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"user:2", 6, (const uint8_t *)"b", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"used", 4, (const uint8_t *)"keep", 4, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    /* one call, however many keys it covers */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(t, cf, (const uint8_t *)"user:", 5), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    engine_assert_committed(db, cf, "user:1", NULL);
    engine_assert_committed(db, cf, "user:2", NULL);
    engine_assert_committed(db, cf, "used", "keep");

    /* a key never written but under the prefix is absent, as it always was */
    engine_assert_committed(db, cf, "user:9", NULL);

    /* a write after the delete comes back */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"user:1", 6, (const uint8_t *)"back", 4, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, cf, "user:1", "back");

    /* a scan agrees with the point reads, which is the half a get cannot stand in for */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(t, cf, &it), TDB_SUCCESS);
    int seen_user1 = 0, seen_user2 = 0, seen_used = 0;
    for (int rc = tidesdb_iter_seek_to_first(it); rc == TDB_SUCCESS && tidesdb_iter_valid(it);
         rc = tidesdb_iter_next(it))
    {
        uint8_t *k = NULL;
        size_t ks = 0;
        ASSERT_EQ(tidesdb_iter_key(it, &k, &ks), TDB_SUCCESS);
        if (ks == 6 && memcmp(k, "user:1", 6) == 0) seen_user1 = 1;
        if (ks == 6 && memcmp(k, "user:2", 6) == 0) seen_user2 = 1;
        if (ks == 4 && memcmp(k, "used", 4) == 0) seen_used = 1;
        free(k); /* the key comes back owned */
    }
    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(seen_user1, 1); /* rewritten above the delete */
    ASSERT_EQ(seen_user2, 0); /* still covered */
    ASSERT_EQ(seen_used, 1);  /* never covered */

    /* and all of it survives a reopen, from the manifest rather than from any memtable */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_t *reopened = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(reopened != NULL);
    engine_assert_committed(db, reopened, "user:2", NULL);
    engine_assert_committed(db, reopened, "user:1", "back");
    engine_assert_committed(db, reopened, "used", "keep");

    /* an empty prefix is refused -- a whole family is dropped, not deleted a prefix at a time */
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(t, reopened, (const uint8_t *)"", 0), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(NULL, reopened, (const uint8_t *)"a", 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(t, NULL, (const uint8_t *)"a", 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_prefix_delete_conflicts_with_a_write_under_it(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);
    const uint32_t cf_index = (uint32_t)((cf_t *)cf)->cf_id;

    /* the deleter draws its snapshot first */
    tidesdb_txn_t *deleter = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &deleter), TDB_SUCCESS);

    /* then somebody else writes a key under the prefix and commits */
    tidesdb_txn_t *writer = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &writer), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(writer, cf, (const uint8_t *)"user:7", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(writer), TDB_SUCCESS);
    tidesdb_txn_free(writer);

    /* the delete would silently take that write with it, so the commit has to be refused */
    ASSERT_EQ(tdb_txn_delete_prefix(deleter->inner, cf_index, (const uint8_t *)"user:", 5),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(deleter), TDB_ERR_CONFLICT);
    tidesdb_txn_free(deleter);

    /* the write survived, since the delete never committed */
    engine_assert_committed(db, cf, "user:7", "v");

    /* and a delete of a prefix nobody touched still goes through */
    tidesdb_txn_t *other = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &other), TDB_SUCCESS);
    tidesdb_txn_t *elsewhere = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &elsewhere), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(elsewhere, cf, (const uint8_t *)"acct:1", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(elsewhere), TDB_SUCCESS);
    tidesdb_txn_free(elsewhere);

    ASSERT_EQ(tdb_txn_delete_prefix(other->inner, cf_index, (const uint8_t *)"org:", 4),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(other), TDB_SUCCESS);
    tidesdb_txn_free(other);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* comfortably more interval deletes than the reservation table has slots, so a run that leaked one
 * per commit would exhaust it partway through */
#define ENGINE_TEST_RANGE_DELETE_ROUNDS 128

/* a committed interval delete gives its reservation back. the reservation is what stops a point
 * write landing inside the range while the commit is undecided, and once the batch is visible the
 * committed delete itself does that job -- so holding the slot past the commit only spends the
 * table. it has a fixed number of slots, so a leak of one per commit ends with every later interval
 * delete in the database refused as a conflict that no retry could clear */
void test_engine_repeated_range_deletes_do_not_exhaust_the_reservations(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    /* the same interval every round, so a leaked slot is met head-on rather than only once the
     * table fills */
    for (int i = 0; i < ENGINE_TEST_RANGE_DELETE_ROUNDS; i++)
    {
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_delete_range(t, cf, (const uint8_t *)"a", 1, (const uint8_t *)"b", 1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    /* serializable takes the same slots, and a prefix delete is the same claim by another name */
    for (int i = 0; i < ENGINE_TEST_RANGE_DELETE_ROUNDS; i++)
    {
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &t),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_delete_prefix(t, cf, (const uint8_t *)"user:", 5), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* an interval bound the reservation table has no slot wide enough for is refused where the caller
 * can act on it, not at the commit. the commit had nothing to say but conflict, which reads as
 * retryable and never would have cleared */
void test_engine_range_delete_refuses_a_bound_past_the_limit(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    uint8_t at_limit[TDB_MAX_RANGE_BOUND_SIZE];
    uint8_t past_limit[TDB_MAX_RANGE_BOUND_SIZE + 1];
    memset(at_limit, 'a', sizeof(at_limit));
    memset(past_limit, 'a', sizeof(past_limit));

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, past_limit, sizeof(past_limit), NULL, 0),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(t, cf, at_limit, sizeof(at_limit), past_limit, sizeof(past_limit)),
        TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(t, cf, past_limit, sizeof(past_limit)),
              TDB_ERR_INVALID_ARGS);

    /* a bound exactly at the limit is accepted and commits */
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, at_limit, sizeof(at_limit), NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* an interval covering no key is refused where the caller can act on it. the apply that would have
 * met it runs after the batch is durable, where every failure is taken for a transient one, so it
 * burned the retries and cancelled the whole batch with an error naming the disk -- losing the
 * writes that shared the transaction and telling the caller their storage had failed */
void test_engine_range_delete_refuses_an_interval_covering_nothing(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const uint8_t lo[] = "kc";
    const uint8_t hi[] = "kd";
    const size_t n = sizeof(lo) - 1;

    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SERIALIZABLE, &t), TDB_SUCCESS);

    /* an interval ending where it starts, and one ending before it starts */
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, lo, n, lo, n), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, hi, n, lo, n), TDB_ERR_INVALID_ARGS);

    /* an empty lower bound names no key the caller could have meant */
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, NULL, 0, hi, n), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, lo, 0, hi, n), TDB_ERR_INVALID_ARGS);

    /* the refusals left the transaction usable, so what shares it still commits */
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"ka", 2, (const uint8_t *)"v", 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_range(t, cf, lo, n, hi, n), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);

    uint8_t *val = NULL;
    size_t val_size = 0;
    tidesdb_txn_t *r = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &r), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(r, cf, (const uint8_t *)"ka", 2, &val, &val_size), TDB_SUCCESS);
    free(val);
    ASSERT_EQ(tidesdb_txn_rollback(r), TDB_SUCCESS);
    tidesdb_txn_free(r);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_clone_carries_range_tombstones(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const int n = 20;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);

    /* into sstables, so the clone's copy of them is what a read of it resolves against */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* delivered through a transaction and flushed into a table of its own, since the family's set
     * is the union of what its tables carry -- an interval that reached no table is not the
     * family's to hand to a clone */
    tidesdb_txn_t *deleter = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &deleter), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(deleter, cf, (const uint8_t *)"key", 3, (const uint8_t *)"kez", 3),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(deleter), TDB_SUCCESS);
    tidesdb_txn_free(deleter);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    cf_t *src = (cf_t *)cf;
    uint64_t tomb_seq = 0;
    ASSERT_EQ(
        cf_range_tombstone_covering(src, (const uint8_t *)"key00000", 8, UINT64_MAX, &tomb_seq), 1);
    ASSERT_TRUE(tomb_seq > 0);
    engine_assert_committed(db, cf, "key00000", NULL); /* the source reads them deleted */

    ASSERT_EQ(tidesdb_clone_column_family(db, "kv", "copy"), TDB_SUCCESS);
    tidesdb_column_family_t *copy = tidesdb_get_column_family(db, "copy");
    ASSERT_TRUE(copy != NULL);

    /* the clone holds the same tombstone, and reads the copied keys as deleted through it */
    uint64_t seq = 0;
    ASSERT_EQ(
        cf_range_tombstone_covering((cf_t *)copy, (const uint8_t *)"key00000", 8, UINT64_MAX, &seq),
        1);
    ASSERT_EQ(seq, tomb_seq);
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        engine_assert_committed(db, copy, key, NULL);
    }

    /* a key outside the tombstone still comes across, so the clone copied data and not just a
     * delete
     */
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"other", 5, (const uint8_t *)"v", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_clone_column_family(db, "kv", "copy2"), TDB_SUCCESS);
    tidesdb_column_family_t *copy2 = tidesdb_get_column_family(db, "copy2");
    ASSERT_TRUE(copy2 != NULL);
    engine_assert_committed(db, copy2, "other", "v");
    engine_assert_committed(db, copy2, "key00000", NULL);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* and the clone's tombstones are in the manifest, so they survive a reopen */
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_t *reopened = tidesdb_get_column_family(db, "copy");
    ASSERT_TRUE(reopened != NULL);
    engine_assert_committed(db, reopened, "key00000", NULL);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_clone_column_family(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    engine_open_with_cf(db_path, &db, &cf);

    const int n = 80;
    for (int i = 0; i < n; i++) engine_put(db, cf, i);

    ASSERT_EQ(tidesdb_clone_column_family(db, "missing", "x"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_clone_column_family(db, "kv", "kv"), TDB_ERR_EXISTS);

    ASSERT_EQ(tidesdb_clone_column_family(db, "kv", "copy"), TDB_SUCCESS);
    tidesdb_column_family_t *copy = tidesdb_get_column_family(db, "copy");
    ASSERT_TRUE(copy != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, cf, key, val);   /* source intact */
        engine_assert_committed(db, copy, key, val); /* clone has the same data */
    }

    /* a write to the clone stays out of the source: the families are independent */
    tidesdb_txn_t *t = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(t, copy, (const uint8_t *)"only-copy", 9, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
    tidesdb_txn_free(t);
    engine_assert_committed(db, copy, "only-copy", "v");
    engine_assert_committed(db, cf, "only-copy", NULL); /* source never saw it */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* both families and their data survive a reopen */
    db = NULL;
    tidesdb_config_t cfg = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    copy = tidesdb_get_column_family(db, "copy");
    ASSERT_TRUE(cf != NULL && copy != NULL);
    for (int i = 0; i < n; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(val, sizeof(val), "val%05d", i);
        engine_assert_committed(db, copy, key, val);
    }
    engine_assert_committed(db, copy, "only-copy", "v");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a value-log reclaim drops the blocks of superseded spilled values a compaction left dead, keeps
 * the live ones, and every current value still reads back intact */
/* the configured segment size decides how many files the value log spreads itself across, so a
 * small one must produce more of them for the same data than the default does */
void test_engine_vlog_segment_size_is_honoured(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.vlog_segment_size = ENGINE_TEST_VLOG_SEGMENT_SIZE;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const size_t vlen = 2048; /* above the spill threshold, so every value reaches the value log */
    char *big = malloc(vlen + 1);
    ASSERT_TRUE(big != NULL);
    memset(big, 'V', vlen);
    big[vlen] = '\0';

    for (int i = 0; i < ENGINE_TEST_VLOG_SEGMENT_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "k%06d", i);
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)big,
                                  vlen, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }
    free(big);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);

    /* the data written is several times the configured segment size, so it cannot have fitted in
     * the one segment a fresh store opens */
    ASSERT_TRUE(st.vlog_segment_count > 1);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* write the same run of oversized values into one family and report what the value log grew by */
static uint64_t engine_test_write_oversized(tidesdb_t *db, const char *cf_name)
{
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, cf_name);
    ASSERT_TRUE(cf != NULL);

    char *big = malloc(ENGINE_TEST_SEPARATED_VALUE_SIZE);
    ASSERT_TRUE(big != NULL);
    memset(big, 'V', ENGINE_TEST_SEPARATED_VALUE_SIZE);

    tidesdb_db_stats_t before;
    ASSERT_EQ(tidesdb_get_db_stats(db, &before), TDB_SUCCESS);

    for (int i = 0; i < ENGINE_TEST_SEPARATED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "%s%06d", cf_name, i);
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)big,
                                  ENGINE_TEST_SEPARATED_VALUE_SIZE, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_db_stats_t after;
    ASSERT_EQ(tidesdb_get_db_stats(db, &after), TDB_SUCCESS);
    free(big);

    /* every key must read back whichever side of the threshold its value was stored on */
    for (int i = 0; i < ENGINE_TEST_SEPARATED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "%s%06d", cf_name, i);
        uint8_t *got = NULL;
        size_t got_size = 0;
        tidesdb_txn_t *rt = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &got, &got_size),
                  TDB_SUCCESS);
        ASSERT_EQ((int)got_size, ENGINE_TEST_SEPARATED_VALUE_SIZE);
        ASSERT_EQ((int)got[0], 'V');
        free(got);
        ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
        tidesdb_txn_free(rt);
    }

    return after.vlog_bytes_written - before.vlog_bytes_written;
}

/* the separation threshold is the database's, and a family that asked to keep its values inline is
 * left out of it while every other family in the same database still separates */
void test_engine_value_separation_is_db_level_with_a_family_opt_out(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.value_separation_threshold = ENGINE_TEST_SEPARATION_THRESHOLD;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    tidesdb_column_family_config_t separating = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "split", &separating), TDB_SUCCESS);

    tidesdb_column_family_config_t inlined = tidesdb_default_column_family_config();
    inlined.keep_values_inline = 1;
    ASSERT_EQ(tidesdb_create_column_family(db, "whole", &inlined), TDB_SUCCESS);

    /* the same values, well above the threshold, written into each family in turn */
    const uint64_t split_vlog = engine_test_write_oversized(db, "split");
    const uint64_t whole_vlog = engine_test_write_oversized(db, "whole");

    /* the database threshold reached the family that did not opt out */
    ASSERT_TRUE(split_vlog >=
                (uint64_t)ENGINE_TEST_SEPARATED_KEYS * (uint64_t)ENGINE_TEST_SEPARATED_VALUE_SIZE);

    /* and the one that did wrote nothing to the value log at all */
    ASSERT_EQ((int)whole_vlog, 0);

    /* so the values are in that family's own key logs instead */
    tidesdb_cf_stats_t split_st, whole_st;
    ASSERT_EQ(tidesdb_get_cf_stats(tidesdb_get_column_family(db, "split"), &split_st), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_get_cf_stats(tidesdb_get_column_family(db, "whole"), &whole_st), TDB_SUCCESS);
    ASSERT_TRUE(whole_st.total_data_size > split_st.total_data_size);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the opt-out is persisted, so a reopened family is still left out of separation */
    tidesdb_config_t reopen = engine_test_config(db_path);
    reopen.value_separation_threshold = ENGINE_TEST_SEPARATION_THRESHOLD;
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    tidesdb_cf_stats_t reopened;
    ASSERT_EQ(tidesdb_get_cf_stats(tidesdb_get_column_family(db, "whole"), &reopened), TDB_SUCCESS);
    ASSERT_EQ(reopened.config.keep_values_inline, 1);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* read one key through a fresh transaction and check the bytes came back whole */
static void engine_test_assert_reads(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key)
{
    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &got, &got_size),
              TDB_SUCCESS);
    ASSERT_EQ((int)got_size, ENGINE_TEST_PLANTED_VALUE_SIZE);
    ASSERT_EQ((int)got[0], 'V');
    ASSERT_EQ((int)got[ENGINE_TEST_PLANTED_VALUE_SIZE - 1], 'V');
    free(got);

    /* and through a scan, which reaches the entry by a different path than the point get */
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new_range(rt, cf, (const uint8_t *)key, strlen(key),
                                     (const uint8_t *)key, strlen(key), &it),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_seek(it, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_iter_valid(it));
    uint8_t *k = NULL, *v = NULL;
    size_t ks = 0, vs = 0;
    ASSERT_EQ(tidesdb_iter_key_value(it, &k, &ks, &v, &vs), TDB_SUCCESS);
    ASSERT_EQ((int)vs, ENGINE_TEST_PLANTED_VALUE_SIZE);
    ASSERT_EQ((int)v[0], 'V');
    free(k);
    free(v);
    tidesdb_iter_free(it);

    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
}

/* a memtable entry may name a value log entry instead of holding the bytes. every read path has to
 * resolve it -- the point get through the L0 source, the scan through the memtable merge source --
 * and a flush has to carry the id into the sstable rather than write the value a second time.
 * nothing on the commit path produces one yet, so the entry is planted the way a commit will */
void test_engine_memtable_reference_resolves_on_every_path(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_create_column_family(db, "kv",
                                     &(tidesdb_column_family_config_t){
                                         .level_size_ratio = 10,
                                         .min_levels = 1,
                                         .btree_klog_block_size = 4096,
                                         .bloom_fpr = 0.01,
                                         .l1_file_count_trigger = 4,
                                         .default_isolation_level = TDB_ISOLATION_READ_COMMITTED}),
        TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* put the bytes in the value log the way a commit will, then plant the reference */
    uint8_t *big = malloc(ENGINE_TEST_PLANTED_VALUE_SIZE);
    ASSERT_TRUE(big != NULL);
    memset(big, 'V', ENGINE_TEST_PLANTED_VALUE_SIZE);
    uint64_t id = 0, disk = 0;
    ASSERT_EQ(vlog_write(db->vlog, big, ENGINE_TEST_PLANTED_VALUE_SIZE, NULL, 0, &id, &disk),
              VLOG_OK);
    free(big);
    ASSERT_TRUE(id != 0);

    vlog_stats_t before;
    vlog_get_stats(db->vlog, &before);

    ASSERT_EQ(tidesdb_l0_apply_reference(
                  db->l0, (uint32_t)((cf_t *)cf)->cf_id, (const uint8_t *)"planted", 7, id,
                  ENGINE_TEST_PLANTED_VALUE_SIZE, -1, ENGINE_TEST_PLANTED_SEQ, 0),
              TDB_SUCCESS);

    /* from the memtable */
    engine_test_assert_reads(db, cf, "planted");

    /* and from the sstable the flush built, which must have carried the id rather than re-spilled
     */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    engine_test_assert_reads(db, cf, "planted");

    vlog_stats_t after;
    vlog_get_stats(db->vlog, &after);
    ASSERT_TRUE(after.bytes_written == before.bytes_written);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* commit one write of the caller's choosing and settle it; a NULL value deletes */
static void engine_test_commit_one(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key,
                                   const char *value)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    if (value)
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key),
                                  (const uint8_t *)value, strlen(value), -1),
                  TDB_SUCCESS);
    else
        ASSERT_EQ(tidesdb_txn_delete(txn, cf, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

/* report whether a key reads back, so a resurrection shows up as a plain presence check */
static int engine_test_key_present(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key)
{
    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    uint8_t *got = NULL;
    size_t got_size = 0;
    const int rc = tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &got, &got_size);
    free(got);
    (void)tidesdb_txn_rollback(rt);
    tidesdb_txn_free(rt);
    return rc == TDB_SUCCESS;
}

/* a log can outlive the flush that installed its data, because an undecided prepare lives in it.
 * replaying such a log puts entries back into a memtable that the sstables have already superseded,
 * and every reader takes a memtable as newer than any sstable -- so a put restored from the old log
 * sits in front of the tombstone that retired it and the deleted key comes back.
 *
 * the put and the delete have to land in different generations, with only the older one kept, since
 * a log holding both replays both and the tombstone still wins */
void test_engine_replay_does_not_resurrect_over_its_sstables(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    engine_test_commit_one(db, cf, "doomed", "alive");
    ASSERT_TRUE(engine_test_key_present(db, cf, "doomed"));

    /* the undecided prepare is what keeps this generation's log once the flush installs its data */
    tidesdb_txn_t *pinned = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pinned), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(pinned, cf, (const uint8_t *)"pinned", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pinned, (const uint8_t *)ENGINE_TEST_PIN_XID,
                                  strlen(ENGINE_TEST_PIN_XID)),
              TDB_SUCCESS);
    tidesdb_txn_free(pinned); /* dropped undecided, on purpose */

    /* rotates, so the delete below lands in a generation of its own whose log is then unlinked */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    engine_test_commit_one(db, cf, "doomed", NULL);
    ASSERT_TRUE(!engine_test_key_present(db, cf, "doomed"));
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_TRUE(!engine_test_key_present(db, cf, "doomed"));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    ASSERT_TRUE(!engine_test_key_present(db, cf, "doomed"));

    /* the prepare the log was kept for is still in doubt, so the filter did not cost it */
    int in_doubt = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &in_doubt), TDB_SUCCESS);
    ASSERT_EQ(in_doubt, 1);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* read a key back and compare it, so an overwrite that came undone shows up as the older value
 * rather than as a mere presence */
static int engine_test_value_is(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key,
                                const char *expect)
{
    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    uint8_t *got = NULL;
    size_t got_size = 0;
    const int rc = tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &got, &got_size);
    const int match =
        rc == TDB_SUCCESS && got_size == strlen(expect) && memcmp(got, expect, got_size) == 0;
    free(got);
    (void)tidesdb_txn_rollback(rt);
    tidesdb_txn_free(rt);
    return match;
}

/* the sibling of the test above, on the two axes it does not cover -- an overwrite rather than a
 * delete, and more than one column family.
 *
 * one memtable serves every family, so one generation's log carries records for all of them and a
 * flush of it installs an sstable into each. when that log is kept for an undecided prepare, every
 * family's records in it are replayed together, and the filter has to answer per family: it
 * resolves the record's own cf index and asks that family's sstables. a filter that answered from
 * the wrong family, or from a db-wide view, would put one family's superseded writes back above its
 * sstables while looking correct for the other */
void test_engine_replay_does_not_undo_an_overwrite_in_any_family(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv2", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    tidesdb_column_family_t *cf2 = tidesdb_get_column_family(db, "kv2");
    ASSERT_TRUE(cf != NULL && cf2 != NULL);

    /* the older version, in both families, in the generation the prepare will pin */
    engine_test_commit_one(db, cf, "b", "v1");
    engine_test_commit_one(db, cf2, "b", "v1");

    tidesdb_txn_t *pinned = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pinned), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(pinned, cf, (const uint8_t *)"pinned", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pinned, (const uint8_t *)ENGINE_TEST_PIN_XID,
                                  strlen(ENGINE_TEST_PIN_XID)),
              TDB_SUCCESS);
    tidesdb_txn_free(pinned); /* dropped undecided, so its generation's log is kept */

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the newer version, in a generation of its own whose log is unlinked once it flushes */
    engine_test_commit_one(db, cf, "b", "v2");
    engine_test_commit_one(db, cf2, "b", "v2");
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_TRUE(engine_test_value_is(db, cf, "b", "v2"));
    ASSERT_TRUE(engine_test_value_is(db, cf2, "b", "v2"));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    cf2 = tidesdb_get_column_family(db, "kv2");
    ASSERT_TRUE(cf != NULL && cf2 != NULL);

    /* the retained log still holds v1 for both families; replaying it must not put either back */
    ASSERT_TRUE(engine_test_value_is(db, cf, "b", "v2"));
    ASSERT_TRUE(engine_test_value_is(db, cf2, "b", "v2"));

    int in_doubt = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &in_doubt), TDB_SUCCESS);
    ASSERT_EQ(in_doubt, 1);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a two-phase batch replays from the COMMIT record that decided it, not from a write batch, and
 * that record is filtered by nothing unless the replay applies the same superseded check the write
 * batch path applies.
 *
 * the log holding a COMMIT is kept for as long as any prepare in its generation is undecided, which
 * is unbounded, so every reopen replays that COMMIT again. once a later write has superseded one of
 * its keys and been flushed, re-applying it puts the older version in a memtable above the sstable
 * holding the newer one -- and a point get takes the first source holding the key, so it hands back
 * the superseded value. a scan resolves by sequence and would still be right, which is why this
 * reads the key rather than scanning for it */
void test_engine_two_phase_replay_does_not_resurrect_a_superseded_key(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* the older version arrives through two-phase commit, so it is durable as a COMMIT record */
    tidesdb_txn_t *decided = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &decided), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(decided, cf, (const uint8_t *)"k", 1, (const uint8_t *)"old", 3, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(decided, (const uint8_t *)ENGINE_TEST_DECIDED_XID,
                                  strlen(ENGINE_TEST_DECIDED_XID)),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit_prepared(decided), TDB_SUCCESS);
    tidesdb_txn_free(decided);
    ASSERT_TRUE(engine_test_value_is(db, cf, "k", "old"));

    /* and a second prepare left undecided in the same generation, which is what keeps that log --
     * and the COMMIT record in it -- alive across every reopen below */
    tidesdb_txn_t *pinned = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pinned), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(pinned, cf, (const uint8_t *)"pinned", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pinned, (const uint8_t *)ENGINE_TEST_PIN_XID,
                                  strlen(ENGINE_TEST_PIN_XID)),
              TDB_SUCCESS);
    tidesdb_txn_free(pinned); /* dropped undecided, on purpose */

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the newer version supersedes it and reaches an sstable of its own */
    engine_test_commit_one(db, cf, "k", "new");
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_TRUE(engine_test_value_is(db, cf, "k", "new"));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    ASSERT_TRUE(engine_test_value_is(db, cf, "k", "new"));

    /* and again, since the generation is kept for as long as the prepare stays in doubt and each
     * reopen replays that COMMIT record afresh */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    tidesdb_config_t again = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&again, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_TRUE(engine_test_value_is(db, cf, "k", "new"));

    int in_doubt = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &in_doubt), TDB_SUCCESS);
    ASSERT_EQ(in_doubt, 1);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the mirror of the test above. the filter drops an entry only when the sstables hold a strictly
 * newer version of that same key, and everything rests on that probe never saying yes when it
 * should not -- a wrong yes is a committed write dropped on recovery. so the probe is asked
 * directly, on a key disk holds and a key it has never seen */
void test_engine_replay_probe_says_yes_only_to_a_newer_durable_version(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    engine_test_commit_one(db, cf, "ondisk", "v");
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    const uint32_t idx = (uint32_t)((cf_t *)cf)->cf_id;

    /* something newer than the beginning of time is on disk for this key */
    ASSERT_EQ(engine_replay_superseded(db, idx, (const uint8_t *)"ondisk", 6, 0), 1);

    /* but nothing on disk is newer than the end of it, so an entry that late is never dropped */
    ASSERT_EQ(engine_replay_superseded(db, idx, (const uint8_t *)"ondisk", 6, UINT64_MAX), 0);

    /* a key disk has never seen is never superseded, at any sequence */
    ASSERT_EQ(engine_replay_superseded(db, idx, (const uint8_t *)"absent", 6, 0), 0);
    ASSERT_EQ(engine_replay_superseded(db, idx, (const uint8_t *)"absent", 6, UINT64_MAX), 0);

    /* nor is anything in a family that does not exist, which a dropped cf's entries replay as */
    ASSERT_EQ(engine_replay_superseded(db, idx + 100, (const uint8_t *)"ondisk", 6, 0), 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a write that no durable later write retired has to survive replay whatever its sequence, or the
 * fix would trade a resurrection for data loss */
void test_engine_replay_keeps_entries_disk_never_superseded(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* "survivor" is written once and never touched again, so nothing on disk ever supersedes it */
    engine_test_commit_one(db, cf, "survivor", "keep-me");

    tidesdb_txn_t *pinned = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pinned), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(pinned, cf, (const uint8_t *)"pinned", 6, (const uint8_t *)"v", 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pinned, (const uint8_t *)ENGINE_TEST_PIN_XID,
                                  strlen(ENGINE_TEST_PIN_XID)),
              TDB_SUCCESS);
    tidesdb_txn_free(pinned);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* later writes under other keys push the durable sequence well past the survivor's, so its
     * replay reaches the probe rather than being waved through by the sequence gate */
    for (int i = 0; i < ENGINE_TEST_COMPACT_KEYS; i++) engine_put(db, cf, i);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_TRUE(engine_test_key_present(db, cf, "survivor"));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a value the commit path separated is reachable only through the value log, so every step that
 * could lose track of which segment holds it has to keep it alive: the flush that turns the
 * memtable reference into an sstable reference, the reopen that rebuilds that sstable from its
 * footer, and the reclaim that decides which segments hold nothing worth keeping.
 *
 * this is the deterministic form of a fuzz case -- put a large value, flush it, reopen, reclaim,
 * read it back -- so the failure is a test rather than a seed */
void test_engine_separated_value_survives_reopen_and_reclaim(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    /* small enough that a handful of values seal segments, so a reclaim has candidates */
    cfg.vlog_segment_size = ENGINE_TEST_VLOG_SEGMENT_SIZE;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    uint8_t *big = malloc(ENGINE_TEST_SEPARATED_VALUE_SIZE);
    ASSERT_TRUE(big != NULL);
    memset(big, 'V', ENGINE_TEST_SEPARATED_VALUE_SIZE);

    /* enough of them to roll several segments, so the reclaim has sealed ones to judge */
    for (int i = 0; i < ENGINE_TEST_SEPARATED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "big%06d", i);
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), big,
                                  ENGINE_TEST_SEPARATED_VALUE_SIZE, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }
    free(big);

    /* the commit path put these in the value log, so the log carries them and the key logs do not
     */
    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.vlog_bytes_written >=
                (uint64_t)ENGINE_TEST_SEPARATED_KEYS * (uint64_t)ENGINE_TEST_SEPARATED_VALUE_SIZE);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    reopen.vlog_segment_size = ENGINE_TEST_VLOG_SEGMENT_SIZE;
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* the reclaim judges every segment by what the installed tables say they hold. a table rebuilt
     * from its footer has to report the same references the build recorded, or every segment reads
     * as holding nothing and the values go */
    engine_vlog_gc(db);

    for (int i = 0; i < ENGINE_TEST_SEPARATED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "big%06d", i);
        tidesdb_txn_t *rt = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
        uint8_t *got = NULL;
        size_t got_size = 0;
        ASSERT_EQ(tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &got, &got_size),
                  TDB_SUCCESS);
        ASSERT_EQ((int)got_size, ENGINE_TEST_SEPARATED_VALUE_SIZE);
        ASSERT_EQ((int)got[0], 'V');
        free(got);
        ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
        tidesdb_txn_free(rt);
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a prepared batch is a holder of separated values that nothing else accounts for. its entries
 * never enter a memtable -- that is the point of a prepare -- and no sstable names them until phase
 * two decides it, so the segments holding its values look empty to a reclaim. the value has to
 * survive until the batch is decided, whatever runs in between */
void test_engine_prepared_batch_keeps_its_separated_values(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.vlog_segment_size = ENGINE_TEST_VLOG_SEGMENT_SIZE;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* larger than a whole segment, so it lands in one of its own and that segment seals holding
     * nothing else. sharing a segment with committed values would hide the defect, since their
     * tables keep the segment alive on this one's behalf */
    const size_t lone = ENGINE_TEST_VLOG_SEGMENT_SIZE * 2;
    uint8_t *big = malloc(lone);
    ASSERT_TRUE(big != NULL);
    memset(big, 'P', lone);

    /* a large value inside a batch that is prepared and then left undecided */
    tidesdb_txn_t *pending = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pending), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(pending, cf, (const uint8_t *)"prepared", 8, big, lone, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pending, (const uint8_t *)ENGINE_TEST_PIN_XID,
                                  strlen(ENGINE_TEST_PIN_XID)),
              TDB_SUCCESS);

    /* unrelated traffic, enough to roll the value log past the segment the prepare's value is in */
    for (int i = 0; i < ENGINE_TEST_SEPARATED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "other%06d", i);
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), big,
                                  ENGINE_TEST_SEPARATED_VALUE_SIZE, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* the batch outlives the process. the handle goes without deciding it, and the reopen stages it
     * again from its log record -- which is where any protection it held in memory is lost */
    tidesdb_txn_free(pending);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t reopen = engine_test_config(db_path);
    reopen.vlog_segment_size = ENGINE_TEST_VLOG_SEGMENT_SIZE;
    ASSERT_EQ(tidesdb_open(&reopen, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_prepared_txn_t recovered[1];
    int in_doubt = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, recovered, 1, &in_doubt), TDB_SUCCESS);
    ASSERT_EQ(in_doubt, 1);

    /* nothing installed names the prepare's value, so this is where it would be dropped */
    engine_vlog_gc(db);

    /* phase two decides it, and the value it names has to still be there */
    ASSERT_EQ(tidesdb_txn_commit_prepared(recovered[0].txn), TDB_SUCCESS);
    tidesdb_txn_free(recovered[0].txn);

    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, (const uint8_t *)"prepared", 8, &got, &got_size),
              TDB_SUCCESS);
    ASSERT_EQ((int)got_size, (int)lone);
    ASSERT_EQ((int)got[0], 'P');
    free(got);
    free(big);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the logs a settled database holds open -- the active one, and the prepared spare when a rotation
 * has already minted it */
#define ENGINE_TEST_WAL_RESIDENT_MIN 1
#define ENGINE_TEST_WAL_RESIDENT_MAX 2

void test_engine_wal_descriptor_accounting_balances(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    cfg.memtable_write_buffer_size = ENGINE_TEST_WAL_ROTATE_BUFFER;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* a freshly opened database holds its active log and nothing else */
    ASSERT_EQ(fd_manager_open_count(&db->fdm, FD_LABEL_WAL_LOG), ENGINE_TEST_WAL_RESIDENT_MIN);

    for (int i = 0; i < ENGINE_TEST_WAL_ROTATE_KEYS; i++)
    {
        char key[32], val[64];
        snprintf(key, sizeof(key), "k%06d", i);
        memset(val, 'v', sizeof(val) - 1);
        val[sizeof(val) - 1] = '\0';
        tidesdb_txn_t *txn = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* every rotation opens a log and every flush retires one, so the count tracks what is actually
     * resident -- the active log, plus at most the prepared spare -- however many rotations ran.
     * an unpaired open or close instead drifts once per generation, and the total it feeds decides
     * whether the reaper evicts and whether a new file may open at all */
    const int wal_open = fd_manager_open_count(&db->fdm, FD_LABEL_WAL_LOG);
    ASSERT_TRUE(wal_open >= ENGINE_TEST_WAL_RESIDENT_MIN &&
                wal_open <= ENGINE_TEST_WAL_RESIDENT_MAX);
    ASSERT_TRUE(fd_manager_open_total(&db->fdm) >= 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a family's codec reaches the values it separates, not just the klog nodes it keeps inline. values
 * spill precisely because they are large, so leaving them verbatim compressed only what was small
 * enough to stay behind -- the opposite of what the size threshold selected for */
void test_engine_compression_reaches_separated_values(void)
{
    const size_t vlen = 8192; /* well above the spill threshold, so every value reaches the vlog */
    uint64_t sizes[2] = {0, 0};
    const int codecs[2] = {TDB_COMPRESS_NONE, TDB_COMPRESS_LZ4};

    for (int pass = 0; pass < 2; pass++)
    {
        (void)remove_directory(ENGINE_TEST_DB_DIR);
        char db_path[] = ENGINE_TEST_DB_DIR;
        tidesdb_config_t cfg = engine_test_config(db_path);
        tidesdb_t *db = NULL;
        ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

        tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
        cc.encoding_pipeline[0] = (uint8_t)codecs[pass];
        cc.encoding_count = 1;
        ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
        ASSERT_TRUE(cf != NULL);

        char *val = malloc(vlen);
        ASSERT_TRUE(val != NULL);
        memset(val, 'c', vlen); /* highly compressible, so the difference is unmistakable */

        for (int i = 0; i < ENGINE_TEST_COMPRESSED_VALUE_KEYS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "k%06d", i);
            tidesdb_txn_t *t = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)val, vlen, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
            tidesdb_txn_free(t);
        }
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

        tidesdb_db_stats_t st;
        ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
        sizes[pass] = st.vlog_file_size;

        /* every value still reads back as itself, through the codec its own block recorded */
        for (int i = 0; i < ENGINE_TEST_COMPRESSED_VALUE_KEYS; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "k%06d", i);
            tidesdb_txn_t *t = NULL;
            uint8_t *got = NULL;
            size_t got_len = 0;
            ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &got, &got_len),
                      TDB_SUCCESS);
            ASSERT_EQ(got_len, vlen);
            ASSERT_TRUE(memcmp(got, val, vlen) == 0);
            free(got);
            tidesdb_txn_free(t);
        }

        free(val);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }

    /* the compressed family's value log is dramatically smaller; without the codec reaching the
     * separated values the two would be the same size */
    ASSERT_TRUE(sizes[1] < sizes[0] / 2);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* keys written per pass of the stacked-pipeline test, and a value size that stays inline so the
 * klog nodes are what carries the whole chain */
#define ENGINE_TEST_STACKED_KEYS  300
#define ENGINE_TEST_STACKED_VALUE 64

/* above the 1024 spill threshold, so this value lands in the value log */
#define ENGINE_TEST_STACKED_SPILLED 4096

/* a pipeline of more than one encoding applies all of them, in order on write and in reverse on
 * read. every entry past the first was configured, validated, written into the footer and then
 * ignored until now, so this is the case that has never run */
void test_engine_stacked_encoding_round_trips(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    /* two distinct codecs, so a reader that applied only the first would not recover the bytes */
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    cc.encoding_pipeline[0] = TDB_COMPRESS_LZ4;
    cc.encoding_pipeline[1] = TDB_COMPRESS_ZSTD;
    cc.encoding_count = 2;
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    char val[ENGINE_TEST_STACKED_VALUE];
    memset(val, 's', sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';

    /* a value above the spill threshold, so the same chain has to survive the round trip through
     * the value log as well as through a klog node */
    char *big = malloc(ENGINE_TEST_STACKED_SPILLED + 1);
    ASSERT_TRUE(big != NULL);
    memset(big, 'p', ENGINE_TEST_STACKED_SPILLED);
    big[ENGINE_TEST_STACKED_SPILLED] = '\0';
    {
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)"spilled", 7, (const uint8_t *)big,
                                  ENGINE_TEST_STACKED_SPILLED, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    for (int i = 0; i < ENGINE_TEST_STACKED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "k%06d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    /* the flush is what encodes -- until then the values are inline in the memtable */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    engine_assert_committed(db, cf, "spilled", big);

    /* read back from the freshly built sstable, which is served from its in-memory handle */
    for (int i = 0; i < ENGINE_TEST_STACKED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "k%06d", i);
        engine_assert_committed(db, cf, key, val);
    }

    /* and again after a reopen, which resolves the chain from the ids the footer recorded rather
     * than from the builder that wrote it */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < ENGINE_TEST_STACKED_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "k%06d", i);
        engine_assert_committed(db, cf, key, val);
    }

    /* and the separated value, whose chain the value log recorded with it rather than taking from
     * whichever sstable happens to reference it */
    engine_assert_committed(db, cf, "spilled", big);

    free(big);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_vlog_gc(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    /* small enough that each pass below fills a segment and seals it. a segment still taking
     * appends is never reclaimed, so with the shipped target every value here would share the
     * active segment and nothing could be freed however dead it was */
    cfg.vlog_segment_size = 64 * 1024;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    cc.l1_file_count_trigger = 1000000; /* no background compaction races the manual one */
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 40;
    const size_t vlen = 2048; /* above the 1024 spill threshold, so values land in the value log */
    char *big = malloc(vlen + 1);
    ASSERT_TRUE(big != NULL);

    /* write large A-values and flush, then overwrite with large B-values and flush: two L1
     * sstables, each spilling n values */
    for (int pass = 0; pass < 2; pass++)
    {
        memset(big, pass == 0 ? 'A' : 'B', vlen);
        for (int i = 0; i < n; i++)
        {
            char key[16];
            snprintf(key, sizeof(key), "key%05d", i);
            tidesdb_txn_t *t = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)big, vlen, -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
            tidesdb_txn_free(t);
        }
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    }

    /* compacting drops the A-versions from the klogs, leaving their value-log blocks dead but
     * still indexed: the store is shared across families and a clone names values by the same ids,
     * so no single merge can conclude a value is dead. liveness is decided database-wide below,
     * from what the surviving sstables record about the segments they hold */
    ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);

    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
    const uint64_t before = st.vlog_value_count;
    ASSERT_TRUE(before >= (uint64_t)(2 * n)); /* dead A and live B are both still indexed */

    /* nothing has stated what it holds yet, so liveness reads as zero until the pass restates it */
    ASSERT_EQ((int)st.vlog_live_bytes, 0);

    /* the segment files are held against the same descriptor budget as klogs and write ahead logs,
     * so a store with many of them cannot exhaust the process on its own */
    ASSERT_TRUE(fd_manager_open_count(&db->fdm, FD_LABEL_VLOG_SEGMENT) > 0);
    const uint64_t files_before = st.vlog_file_size;

    engine_vlog_gc(db); /* drop the segments the surviving sstables no longer hold anything in */

    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);

    /* the segments holding nothing but dead A-blocks were unlinked, taking their index entries
     * with them, and the store is physically smaller for it */
    ASSERT_TRUE(st.vlog_segments_retired >= 1);
    ASSERT_TRUE(st.vlog_value_count < before);
    ASSERT_TRUE(st.vlog_file_size < files_before);

    /* what survives is the live B-values plus whatever dead ones share a segment with them. those
     * segments are not dropped, since dropping one would take the live values in it too -- emptying
     * them is compaction's work, not the store's */
    ASSERT_TRUE(st.vlog_live_bytes > 0);
    ASSERT_TRUE(st.vlog_value_count >= (uint64_t)n);

    const uint64_t settled = st.vlog_value_count;
    engine_vlog_gc(db); /* a second pass finds nothing further to drop */

    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
    ASSERT_EQ(st.vlog_value_count, settled);

    /* every key still reads back its current B-value */
    memset(big, 'B', vlen);
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        uint8_t *v = NULL;
        size_t vs = 0;
        ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &v, &vs), TDB_SUCCESS);
        ASSERT_EQ((int)vs, (int)vlen);
        ASSERT_TRUE(v != NULL && memcmp(v, big, vlen) == 0);
        free(v);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    free(big);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* what a codec achieved is attributed to the pipeline each table was written with, read from its
 * own footer, so a table older than a configuration change still reports what encoded it */
void test_engine_klog_encoding_stats_are_per_pipeline(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    char val[256];
    memset(val, 'C', sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';
    for (int i = 0; i < 200; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                                  strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_encoding_stats_t chains[TDB_MAX_ENCODING_CHAINS];
    size_t n = 0;
    ASSERT_EQ(tidesdb_get_klog_encoding_stats(db, chains, TDB_MAX_ENCODING_CHAINS, &n),
              TDB_SUCCESS);

    /* one family written under one pipeline, so one row, and it describes real bytes rather than
     * an average over the store */
    ASSERT_EQ((int)n, 1);
    ASSERT_TRUE(chains[0].item_count >= 1);
    ASSERT_TRUE(chains[0].logical_bytes > 0);
    ASSERT_TRUE(chains[0].stored_bytes > 0);

    /* the keys and inline values are the logical side, so it has to account for what was written
     * rather than reporting the file size back */
    ASSERT_TRUE(chains[0].logical_bytes >= 200 * strlen(val));

    tidesdb_encoding_stats_t vchains[TDB_MAX_ENCODING_CHAINS];
    size_t vn = 0;
    ASSERT_EQ(tidesdb_get_vlog_encoding_stats(db, vchains, TDB_MAX_ENCODING_CHAINS, &vn),
              TDB_SUCCESS);
    ASSERT_EQ((int)vn, 0); /* nothing spilled at this value size, so no chain wrote any value */

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a database directory belongs to one handle at a time. two opens would each recover the write
 * ahead log and each install sstables the other's manifest does not name, and the damage is done
 * before either could notice, so the second is refused rather than allowed to begin */
void test_engine_second_open_is_refused(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);

    tidesdb_config_t second_cfg = engine_test_config(db_path);
    tidesdb_t *second = NULL;
    ASSERT_EQ(tidesdb_open(&second_cfg, &second), TDB_ERR_LOCKED);
    ASSERT_TRUE(second == NULL);

    /* and the lock is released rather than leaked, so the directory reopens once it is closed --
     * a lock that outlived its handle would make a database unopenable until the process exited */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_open(&second_cfg, &second), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(second), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* ===== named snapshots ===== */

/* write a value, read it back through whichever transaction the caller supplies, and assert what
 * came out. returns nothing; a mismatch fails the test where it happened */
static void snap_assert_reads(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const char *key,
                              const char *expect)
{
    uint8_t *got = NULL;
    size_t got_size = 0;
    const int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key), &got, &got_size);
    if (!expect)
    {
        ASSERT_EQ(rc, TDB_ERR_NOT_FOUND);
        return;
    }
    ASSERT_EQ(rc, TDB_SUCCESS);
    ASSERT_EQ((int)got_size, (int)strlen(expect));
    ASSERT_TRUE(memcmp(got, expect, got_size) == 0);
    tidesdb_free(got);
}

/* commit one put in its own transaction */
static void snap_put(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key, const char *val)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

/* a frozen snapshot has to survive a flush, and this is the case that says whether it does. a
 * memtable holds a version chain per key while a flush writes to one sstable, so a flush that took
 * only the newest of each chain dropped every older version outright -- regardless of the
 * reclamation floor, which only a merge consulted. a repeatable-read reader whose snapshot sat
 * below an overwrite then watched its value turn into NOT_FOUND, which is worse than a stale read:
 * a live key reads as absent. the flush retains against the same floor a merge does, and with no
 * reader registered that floor is UINT64_MAX, so the newest version is still all that is written */
void test_engine_frozen_snapshot_survives_a_flush(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "over", "v1");
    snap_put(db, cf, "gone", "here");

    /* a reader that froze its snapshot above both writes */
    tidesdb_txn_t *reader = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_REPEATABLE_READ, &reader),
              TDB_SUCCESS);
    snap_assert_reads(reader, cf, "over", "v1");
    snap_assert_reads(reader, cf, "gone", "here");

    /* one key overwritten, one deleted, both after the snapshot and both into the same memtable */
    snap_put(db, cf, "over", "v2");
    tidesdb_txn_t *del = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &del), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(del, cf, (const uint8_t *)"gone", 4), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(del), TDB_SUCCESS);
    tidesdb_txn_free(del);

    /* the floor is the reader's snapshot, so the flush has to carry the versions under it */
    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
    ASSERT_TRUE(st.min_snapshot_seq <= tidesdb_txn_read_snapshot(reader));

    const int frc = tidesdb_flush_memtable(db);
    ASSERT_TRUE(frc == TDB_SUCCESS || frc == TDB_ERR_LOCKED);

    /* the reader's view is unchanged by the flush -- the whole point of freezing it */
    snap_assert_reads(reader, cf, "over", "v1");
    snap_assert_reads(reader, cf, "gone", "here");
    ASSERT_EQ(tidesdb_txn_rollback(reader), TDB_SUCCESS);
    tidesdb_txn_free(reader);

    /* and the retention did not hold the present back */
    tidesdb_txn_t *now = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &now), TDB_SUCCESS);
    snap_assert_reads(now, cf, "over", "v2");
    snap_assert_reads(now, cf, "gone", NULL);
    ASSERT_EQ(tidesdb_txn_rollback(now), TDB_SUCCESS);
    tidesdb_txn_free(now);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a snapshot answers as of the moment it was taken, while the live database moves on */
void test_engine_snapshot_reads_as_of_its_sequence(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "k", "v1");

    tidesdb_snapshot_t *snap = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &snap), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_snapshot_seq(snap) > 0);

    snap_put(db, cf, "k", "v2");

    /* the snapshot still sees v1 */
    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_snapshot(db, snap, &past), TDB_SUCCESS);
    snap_assert_reads(past, cf, "k", "v1");
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    /* and an ordinary transaction sees v2, so the snapshot narrowed one reader rather than the
     * database */
    tidesdb_txn_t *now = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &now), TDB_SUCCESS);
    snap_assert_reads(now, cf, "k", "v2");
    ASSERT_EQ(tidesdb_txn_rollback(now), TDB_SUCCESS);
    tidesdb_txn_free(now);

    tidesdb_snapshot_release(snap);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* the point of the handle is not that a ceiling can be set -- every read already takes one -- but
 * that the versions under it survive. compaction keeps only one version at or below the floor, so
 * a snapshot that did not hold the floor would read whatever that merge happened to leave, which
 * for an overwritten key is the newer value and for a deleted one is nothing at all */
void test_engine_snapshot_holds_versions_a_compaction_would_have_collected(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "kept", "v1");
    snap_put(db, cf, "gone", "here");

    tidesdb_snapshot_t *snap = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &snap), TDB_SUCCESS);

    /* move both keys on: one overwritten repeatedly, one deleted outright */
    for (int i = 0; i < 4; i++) snap_put(db, cf, "kept", "v2");
    tidesdb_txn_t *del = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &del), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(del, cf, (const uint8_t *)"gone", 4), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(del), TDB_SUCCESS);
    tidesdb_txn_free(del);

    /* flush and merge, which is where a version below the floor is dropped */
    const int frc = tidesdb_flush_memtable(db);
    ASSERT_TRUE(frc == TDB_SUCCESS || frc == TDB_ERR_LOCKED);
    const int crc = tidesdb_compact(db, cf);
    ASSERT_TRUE(crc == TDB_SUCCESS || crc == TDB_ERR_LOCKED);

    /* the snapshot's versions are still there to be read */
    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_snapshot(db, snap, &past), TDB_SUCCESS);
    snap_assert_reads(past, cf, "kept", "v1");
    snap_assert_reads(past, cf, "gone", "here");
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    /* while the present is what the merge left */
    tidesdb_txn_t *now = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &now), TDB_SUCCESS);
    snap_assert_reads(now, cf, "kept", "v2");
    snap_assert_reads(now, cf, "gone", NULL);
    ASSERT_EQ(tidesdb_txn_rollback(now), TDB_SUCCESS);
    tidesdb_txn_free(now);

    tidesdb_snapshot_release(snap);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* reading at a bare sequence, which is the general form of the same question. it is answerable only
 * while something holds the floor under that sequence -- here the reader's own snapshot does, which
 * is the ordinary way a caller has a sequence worth revisiting in the first place */
void test_engine_read_at_a_sequence_still_held(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "k", "v1");

    /* a snapshot holds the floor, and its sequence is the one to read back at */
    tidesdb_snapshot_t *held = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &held), TDB_SUCCESS);
    const uint64_t seq = tidesdb_snapshot_seq(held);

    snap_put(db, cf, "k", "v2");
    const int frc = tidesdb_flush_memtable(db);
    ASSERT_TRUE(frc == TDB_SUCCESS || frc == TDB_ERR_LOCKED);
    const int crc = tidesdb_compact(db, cf);
    ASSERT_TRUE(crc == TDB_SUCCESS || crc == TDB_ERR_LOCKED);

    /* the sequence is at or above the oldest readable point, so it answers exactly */
    ASSERT_TRUE(tidesdb_oldest_readable_seq(db) <= seq);
    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_seq(db, seq, &past), TDB_SUCCESS);
    snap_assert_reads(past, cf, "k", "v1");
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    tidesdb_snapshot_release(held);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* and the case the call exists to get right. with nothing holding the floor a merge collects below
 * it, so an older sequence no longer names a state the database can reconstruct. answering from
 * what happened to survive would report a key that existed as absent, so it refuses instead */
void test_engine_read_at_a_collected_sequence_is_refused(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "k", "v1");

    /* the sequence a reader would want, recorded while it was still current */
    tidesdb_txn_t *probe = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_REPEATABLE_READ, &probe),
              TDB_SUCCESS);
    const uint64_t seq = tidesdb_txn_read_snapshot(probe);
    ASSERT_EQ(tidesdb_txn_rollback(probe), TDB_SUCCESS);
    tidesdb_txn_free(probe); /* nothing holds the floor from here on */

    for (int i = 0; i < 4; i++) snap_put(db, cf, "k", "v2");
    const int frc = tidesdb_flush_memtable(db);
    ASSERT_TRUE(frc == TDB_SUCCESS || frc == TDB_ERR_LOCKED);
    const int crc = tidesdb_compact(db, cf);
    ASSERT_TRUE(crc == TDB_SUCCESS || crc == TDB_ERR_LOCKED);

    /* a collection has run past that sequence, and the call says so rather than guessing */
    ASSERT_TRUE(tidesdb_oldest_readable_seq(db) > seq);
    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_seq(db, seq, &past), TDB_ERR_TOO_OLD);
    ASSERT_TRUE(past == NULL);

    /* the present is unaffected */
    tidesdb_txn_t *now = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &now), TDB_SUCCESS);
    snap_assert_reads(now, cf, "k", "v2");
    ASSERT_EQ(tidesdb_txn_rollback(now), TDB_SUCCESS);
    tidesdb_txn_free(now);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a reopened database cannot speak for what an earlier run collected, so the oldest readable point
 * starts at the sequence recovery resumed from. reporting zero would claim every sequence the
 * database ever issued is still exact */
void test_engine_oldest_readable_seq_resets_on_open(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");
    for (int i = 0; i < 4; i++) snap_put(db, cf, "k", "v");
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    tidesdb_config_t again = engine_test_config(db_path);
    ASSERT_EQ(tidesdb_open(&again, &db), TDB_SUCCESS);
    /* the oldest readable point is the sequence recovery resumed from, not zero, so a sequence the
     * previous run issued is refused rather than answered from whatever its compactions left */
    ASSERT_TRUE(tidesdb_oldest_readable_seq(db) > 0);
    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_seq(db, 1, &past), TDB_ERR_TOO_OLD);
    ASSERT_TRUE(past == NULL);

    /* while the point the database resumed at is still exact, so a reopen does not refuse
     * everything. the floor is only a lower bound at the instant it is read -- a background flush
     * taking one raises it, and a sequence read before that stops being reconstructable, which is
     * exactly what the call documents. so this reads and retries rather than asserting the pair is
     * atomic; the floor only ever rises, and nothing here writes, so it converges at once */
    int begun = TDB_ERR_TOO_OLD;
    for (int attempt = 0; attempt < ENGINE_OLDEST_READABLE_RETRIES && begun != TDB_SUCCESS;
         attempt++)
        begun = tidesdb_txn_begin_at_seq(db, tidesdb_oldest_readable_seq(db), &past);
    ASSERT_EQ(begun, TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a snapshot pins the reclamation floor while it lives and lets it go when released. this is the
 * cost side of the feature, and it is the number an operator watches -- a snapshot left open is
 * indistinguishable from a leaked transaction */
void test_engine_snapshot_holds_and_releases_the_reclamation_floor(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "k", "v1");

    tidesdb_snapshot_t *snap = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &snap), TDB_SUCCESS);
    const uint64_t pinned = tidesdb_snapshot_seq(snap);

    for (int i = 0; i < 8; i++) snap_put(db, cf, "k", "v2");

    tidesdb_db_stats_t stats;
    ASSERT_EQ(tidesdb_get_db_stats(db, &stats), TDB_SUCCESS);
    /* the floor cannot have risen past the snapshot, however far the clock ran on */
    ASSERT_TRUE(stats.min_snapshot_seq <= pinned);
    ASSERT_TRUE(stats.global_seq > pinned);

    tidesdb_snapshot_release(snap);

    /* released, the floor is free to follow the clock again */
    ASSERT_EQ(tidesdb_get_db_stats(db, &stats), TDB_SUCCESS);
    ASSERT_TRUE(stats.min_snapshot_seq > pinned);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a scan through a snapshot sees the same past a point read does. iterators resolve at the
 * transaction's read snapshot, so this is the property that would break silently if a snapshot
 * were wired into point reads alone */
void test_engine_snapshot_scan_sees_the_same_past(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "cf", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "cf");

    snap_put(db, cf, "a", "1");
    snap_put(db, cf, "b", "1");

    tidesdb_snapshot_t *snap = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &snap), TDB_SUCCESS);

    snap_put(db, cf, "c", "1"); /* added after the snapshot */
    tidesdb_txn_t *del = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &del), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(del, cf, (const uint8_t *)"a", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(del), TDB_SUCCESS);
    tidesdb_txn_free(del);

    tidesdb_txn_t *past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_snapshot(db, snap, &past), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(past, cf, &it), TDB_SUCCESS);

    /* exactly the two keys that existed when the snapshot was taken, in order */
    const char *expect[] = {"a", "b"};
    int seen = 0;
    for (tidesdb_iter_seek_to_first(it); tidesdb_iter_valid(it); tidesdb_iter_next(it))
    {
        uint8_t *k = NULL;
        size_t klen = 0;
        ASSERT_EQ(tidesdb_iter_key(it, &k, &klen), TDB_SUCCESS);
        ASSERT_TRUE(seen < 2);
        ASSERT_EQ((int)klen, 1);
        ASSERT_TRUE(memcmp(k, expect[seen], 1) == 0);
        tidesdb_free(k);
        seen++;
    }
    ASSERT_EQ(seen, 2);

    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);
    tidesdb_snapshot_release(snap);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a family whose every key is deleted must give the space back -- both the key logs and the values
 * they referenced. this is the case the reclamation this replaced could never finish: the store had
 * to be scanned to learn what was dead, and a store large enough to have a lot of dead data was
 * large enough that the scan did not complete */
void test_engine_deleting_everything_reclaims_the_space(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    /* small enough that the values below fill several segments; the one taking appends is never
     * reclaimable, so with one big segment there would be nothing to observe */
    cfg.vlog_segment_size = 64 * 1024;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    cc.l1_file_count_trigger = 1000000; /* no background compaction races the manual ones */
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const int n = 400;
    const size_t vlen = 2048; /* above the spill threshold, so every value lands in the value log */
    char *big = malloc(vlen);
    ASSERT_TRUE(big != NULL);
    memset(big, 'K', vlen);

    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)big,
                                  vlen, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_db_stats_t st;
    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);
    const uint64_t peak_vlog = st.vlog_file_size;
    ASSERT_TRUE(peak_vlog >= n * vlen); /* the values really are in the value log */

    /* now delete every one of them */
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_delete(t, cf, (const uint8_t *)key, strlen(key)), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    /* compaction folds the tombstones over the data and reclamation drops what nothing references.
     * both are driven to a fixed point rather than assumed to finish in one pass, since a merge can
     * only drop a tombstone once no older sstable still holds the key underneath it */
    for (int round = 0; round < 8; round++)
    {
        ASSERT_EQ(engine_test_compact(db, cf), TDB_SUCCESS);
        engine_vlog_gc(db);
    }

    ASSERT_EQ(tidesdb_get_db_stats(db, &st), TDB_SUCCESS);

    /* nothing is referenced any more, so the value log is down to the segment still taking appends
     * and the space the deleted values held is back */
    ASSERT_EQ((int)st.vlog_live_bytes, 0);
    ASSERT_TRUE(st.vlog_segments_retired >= 1);
    ASSERT_TRUE(st.vlog_file_size < peak_vlog / 4);

    /* and the keys are genuinely gone rather than merely unreadable */
    for (int i = 0; i < n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%05d", i);
        tidesdb_txn_t *t = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
        uint8_t *v = NULL;
        size_t vs = 0;
        ASSERT_EQ(tidesdb_txn_get(t, cf, (const uint8_t *)key, strlen(key), &v, &vs),
                  TDB_ERR_NOT_FOUND);
        ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
        tidesdb_txn_free(t);
    }

    free(big);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* dropping a family removes that family's files and nothing else. the sweep is driven by what the
 * manifest says the family owns rather than by deleting a directory, because a family is only
 * incidentally a directory -- anything that deleted by location would take whatever else came to
 * live beside it */
void test_engine_drop_removes_only_that_familys_files(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "doomed", &cc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "keeper", &cc), TDB_SUCCESS);

    char val[512];
    memset(val, 'S', sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';
    const char *names[2] = {"doomed", "keeper"};
    for (int f = 0; f < 2; f++)
    {
        tidesdb_column_family_t *cf = tidesdb_get_column_family(db, names[f]);
        ASSERT_TRUE(cf != NULL);
        for (int i = 0; i < 100; i++)
        {
            char key[16];
            snprintf(key, sizeof(key), "k%05d", i);
            tidesdb_txn_t *t = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)val, strlen(val), -1),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
            tidesdb_txn_free(t);
        }
    }
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_drop_column_family(db, "doomed"), TDB_SUCCESS);

    /* the survivor still reads, in this handle and after a reopen -- a sweep that took too much
     * would show up as the manifest naming files that are no longer there */
    for (int pass = 0; pass < 2; pass++)
    {
        if (pass == 1)
        {
            ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
            ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
        }
        tidesdb_column_family_t *keeper = tidesdb_get_column_family(db, "keeper");
        ASSERT_TRUE(keeper != NULL);
        ASSERT_TRUE(tidesdb_get_column_family(db, "doomed") == NULL);

        for (int i = 0; i < 100; i++)
        {
            char key[16];
            snprintf(key, sizeof(key), "k%05d", i);
            tidesdb_txn_t *t = NULL;
            ASSERT_EQ(tidesdb_txn_begin(db, &t), TDB_SUCCESS);
            uint8_t *v = NULL;
            size_t vs = 0;
            ASSERT_EQ(tidesdb_txn_get(t, keeper, (const uint8_t *)key, strlen(key), &v, &vs),
                      TDB_SUCCESS);
            ASSERT_EQ(vs, strlen(val));
            ASSERT_TRUE(v != NULL && memcmp(v, val, vs) == 0);
            free(v);
            ASSERT_EQ(tidesdb_txn_commit(t), TDB_SUCCESS);
            tidesdb_txn_free(t);
        }
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* raising the open-file limit reports a positive ceiling, never lowers it, and the report reflects
 * the raise; the exact ceiling depends on the hard limit, so only the monotonic relation is
 * asserted */
void test_engine_raise_open_file_limit(void)
{
    const long current = tidesdb_raise_open_file_limit(0); /* report only */
    ASSERT_TRUE(current > 0);

    const long raised = tidesdb_raise_open_file_limit(current + 256);
    ASSERT_TRUE(raised >= current); /* never lowered; may be capped at the hard limit */

    ASSERT_EQ(tidesdb_raise_open_file_limit(0),
              raised); /* the report reflects the ceiling in effect */
}

/* two-phase commit -- a prepared write stays invisible until commit-prepared makes it visible, a
 * rollback-prepared discards it, the lifecycle state is reported, misuse is rejected, a read-only
 * prepare needs no phase two, and a committed-prepared write survives a flush and reopen */
/* a transaction prepared but never decided survives a restart as in-doubt, and the coordinator
 * resolves it after the fact. one the log already decided is settled during open and never listed,
 * so the coordinator is asked only about what it still owes an answer on */
void test_engine_recover_prepared(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    const uint8_t undecided[] = "xid-in-doubt";
    const uint8_t decided[] = "xid-decided";
    const uint8_t k1[] = "pk1", v1[] = "pv1";
    const uint8_t k2[] = "pk2", v2[] = "pv2";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* one transaction prepares and is left hanging, another prepares and is committed */
    tidesdb_txn_t *hanging = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &hanging), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(hanging, cf, k1, sizeof(k1) - 1, v1, sizeof(v1) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(hanging, undecided, sizeof(undecided) - 1), TDB_SUCCESS);

    tidesdb_txn_t *settled = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &settled), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(settled, cf, k2, sizeof(k2) - 1, v2, sizeof(v2) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(settled, decided, sizeof(decided) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit_prepared(settled), TDB_SUCCESS);
    tidesdb_txn_free(settled);

    /* close without ever deciding the first one, then reopen over the same log */
    tidesdb_txn_free(hanging);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* exactly the undecided one is in doubt; the committed one was settled during open */
    int count = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);

    tidesdb_prepared_txn_t found[4];
    ASSERT_EQ(tidesdb_recover_prepared(db, found, 4, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);
    ASSERT_EQ((int)found[0].xid_size, (int)sizeof(undecided) - 1);
    ASSERT_TRUE(memcmp(found[0].xid, undecided, sizeof(undecided) - 1) == 0);

    tidesdb_txn_state_t state = TDB_TXN_STATE_ACTIVE;
    ASSERT_EQ(tidesdb_txn_state(found[0].txn, &state), TDB_SUCCESS);
    ASSERT_EQ((int)state, (int)TDB_TXN_STATE_PREPARED);

    /* the settled transaction's write came back with it; the in-doubt one is still invisible */
    tidesdb_txn_t *rt = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, k2, sizeof(k2) - 1, &got, &got_size), TDB_SUCCESS);
    free(got);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, k1, sizeof(k1) - 1, &got, &got_size), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);

    /* deciding it now makes its write visible, exactly as phase two would have before the restart
     */
    ASSERT_EQ(tidesdb_txn_commit_prepared(found[0].txn), TDB_SUCCESS);
    tidesdb_txn_free(found[0].txn);

    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, k1, sizeof(k1) - 1, &got, &got_size), TDB_SUCCESS);
    free(got);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* phase two on a handle recovered after a restart is durable on its own and lands where it is
 * decided. the batch's PREPARE record lives in a generation this decision unpins, so the COMMIT
 * record carries the write set rather than leaning on it, and the flushed delete below the memtable
 * the batch applies into is the layout that would expose a stale sequence */
void test_engine_recovered_phase_two_durable_and_ordered(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    const uint8_t xid[] = "xid-recovered-phase-two";
    const uint8_t gone[] = "superseded", gonev0[] = "v0", gonev1[] = "v1";
    const uint8_t kept[] = "survives", keptv[] = "kv";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *seed = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &seed), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(seed, cf, gone, sizeof(gone) - 1, gonev0, sizeof(gonev0) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(seed), TDB_SUCCESS);
    tidesdb_txn_free(seed);

    /* prepare below snapshot isolation, which takes no reservation, then abandon the handle */
    tidesdb_txn_t *p = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_UNCOMMITTED, &p),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p, cf, gone, sizeof(gone) - 1, gonev1, sizeof(gonev1) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p, cf, kept, sizeof(kept) - 1, keptv, sizeof(keptv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(p, xid, sizeof(xid) - 1), TDB_SUCCESS);
    tidesdb_txn_free(p);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    int count = -1;
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);
    tidesdb_prepared_txn_t found[4];
    ASSERT_EQ(tidesdb_recover_prepared(db, found, 4, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);

    /* a newer delete, flushed so it lands below the memtable phase two will apply into */
    tidesdb_txn_t *d = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &d), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(d, cf, gone, sizeof(gone) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(d), TDB_SUCCESS);
    tidesdb_txn_free(d);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_commit_prepared(found[0].txn), TDB_SUCCESS);
    tidesdb_txn_free(found[0].txn);

    tidesdb_txn_t *rt = NULL;
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, gone, sizeof(gone) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(gonev1) - 1);
    free(got);
    got = NULL;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, kept, sizeof(kept) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(keptv) - 1);
    free(got);
    got = NULL;
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the decided batch is durable without its PREPARE record, and replays to the same place */
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(tidesdb_recover_prepared(db, NULL, 0, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 0);
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, gone, sizeof(gone) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(gonev1) - 1);
    free(got);
    got = NULL;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, kept, sizeof(kept) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(keptv) - 1);
    free(got);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* phase two draws its own sequence, so a batch is ordered where it is decided rather than where it
 * prepared and lands above anything that committed while it was in doubt. that keeps a batch's
 * position and its age in agreement, which is what the read path, tombstone collection, and the
 * generation layout all rest on, and a reopen must reach the same answer. the prepare is taken
 * below snapshot isolation, which claims no write reservation and so lets the competing delete
 * commit at all */
/* a key written by a two-phase transaction has to stay writable once that transaction has finished.
 * the prepare claims the key's reservation with the sequence it drew then, and phase two commits at
 * a fresh one -- so unless the slot is handed over, it goes on naming a sequence that is never
 * marked committed, and the next writer of that key reads it as a committer still in flight and
 * loses to a transaction that ended. no concurrency is needed to see it: one connection, one key,
 * everything already committed. it heals itself only after the commit ring wraps past the
 * abandoned sequence, which is what makes it look intermittent on a busy database and permanent on
 * a quiet one */
void test_engine_key_stays_writable_after_a_two_phase_commit(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    const uint8_t xid[] = "xid-then-write-again";
    const uint8_t key[] = "row", first[] = "v0", second[] = "v1";
    const uint8_t other[] = "untouched-row", otherv[] = "ov";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    /* write the key through two-phase commit and resolve it */
    tidesdb_txn_t *p = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &p), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p, cf, key, sizeof(key) - 1, first, sizeof(first) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(p, xid, sizeof(xid) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit_prepared(p), TDB_SUCCESS);
    tidesdb_txn_free(p);

    /* the same key again, single phase, nothing else running. there is no writer to lose to */
    tidesdb_txn_t *again = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &again), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(again, cf, key, sizeof(key) - 1, second, sizeof(second) - 1, -1),
              TDB_SUCCESS);
    const int rc = tidesdb_txn_commit(again);
    if (rc != TDB_SUCCESS) fprintf(stderr, "rewrite of a two-phase key refused, rc=%d\n", rc);
    ASSERT_EQ(rc, TDB_SUCCESS);
    tidesdb_txn_free(again);

    /* a second two-phase transaction over the same key resolves the same way */
    tidesdb_txn_t *p2 = NULL;
    const uint8_t xid2[] = "xid-second-round";
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &p2), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p2, cf, key, sizeof(key) - 1, first, sizeof(first) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(p2, xid2, sizeof(xid2) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit_prepared(p2), TDB_SUCCESS);
    tidesdb_txn_free(p2);

    /* and a rolled-back prepare must leave the key writable too, which is the path that always
     * released its reservation */
    tidesdb_txn_t *p3 = NULL;
    const uint8_t xid3[] = "xid-rolled-back";
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &p3), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p3, cf, other, sizeof(other) - 1, otherv, sizeof(otherv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(p3, xid3, sizeof(xid3) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback_prepared(p3), TDB_SUCCESS);
    tidesdb_txn_free(p3);

    tidesdb_txn_t *after_rollback = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &after_rollback),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(after_rollback, cf, other, sizeof(other) - 1, otherv,
                              sizeof(otherv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(after_rollback), TDB_SUCCESS);
    tidesdb_txn_free(after_rollback);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_settled_prepare_lands_above_writes_it_was_in_doubt_through(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    const uint8_t xid[] = "xid-decided-late";
    const uint8_t gone[] = "deleted-then-decided", gonev0[] = "v0", gonev1[] = "v1";
    const uint8_t kept[] = "untouched", keptv[] = "kv";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *seed = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &seed), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(seed, cf, gone, sizeof(gone) - 1, gonev0, sizeof(gonev0) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(seed), TDB_SUCCESS);
    tidesdb_txn_free(seed);

    tidesdb_txn_t *p = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_UNCOMMITTED, &p),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p, cf, gone, sizeof(gone) - 1, gonev1, sizeof(gonev1) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(p, cf, kept, sizeof(kept) - 1, keptv, sizeof(keptv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(p, xid, sizeof(xid) - 1), TDB_SUCCESS);

    /* delete the key while the batch is in doubt, and flush so the tombstone leaves the memtable
     * the batch will apply into */
    tidesdb_txn_t *d = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &d), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(d, cf, gone, sizeof(gone) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(d), TDB_SUCCESS);
    tidesdb_txn_free(d);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_commit_prepared(p), TDB_SUCCESS);
    tidesdb_txn_free(p);

    tidesdb_txn_t *rt = NULL;
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, gone, sizeof(gone) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(gonev1) - 1);
    free(got);
    got = NULL;
    ASSERT_EQ(tidesdb_txn_get(rt, cf, kept, sizeof(kept) - 1, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, sizeof(keptv) - 1);
    free(got);
    got = NULL;
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* replay reads the batch back out of its COMMIT record, at the same sequence and in the same
     * generation, so a reopen lands it exactly where the live decision did */
    for (int pass = 0; pass < 2; pass++)
    {
        ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
        cf = tidesdb_get_column_family(db, "kv");
        ASSERT_TRUE(cf != NULL);
        ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_get(rt, cf, gone, sizeof(gone) - 1, &got, &got_size), TDB_SUCCESS);
        ASSERT_EQ(got_size, sizeof(gonev1) - 1);
        free(got);
        got = NULL;
        ASSERT_EQ(tidesdb_txn_get(rt, cf, kept, sizeof(kept) - 1, &got, &got_size), TDB_SUCCESS);
        ASSERT_EQ(got_size, sizeof(keptv) - 1);
        free(got);
        got = NULL;
        ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
        tidesdb_txn_free(rt);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

/* a prepared batch is durable only in the write-ahead log until phase two applies it, and it never
 * enters a memtable, so the generation holding it can look fully flushed. flushing while one is
 * outstanding must not unlink that log, or the transaction is gone before its coordinator decides
 */
void test_engine_prepared_survives_flush(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();

    const uint8_t xid[] = "xid-across-flush";
    const uint8_t pk[] = "flushed-prepare", pv[] = "value";
    const uint8_t other[] = "unrelated", otherv[] = "v";

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t *pending = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &pending), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(pending, cf, pk, sizeof(pk) - 1, pv, sizeof(pv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(pending, xid, sizeof(xid) - 1), TDB_SUCCESS);

    /* commit unrelated work and flush it to L1, which retires the generation the prepare landed in
     */
    tidesdb_txn_t *w = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &w), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(w, cf, other, sizeof(other) - 1, otherv, sizeof(otherv) - 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(w), TDB_SUCCESS);
    tidesdb_txn_free(w);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_txn_free(pending);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* the prepare outlived the flush, so it is still in doubt and still resolvable */
    db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    int count = -1;
    tidesdb_prepared_txn_t found[4];
    ASSERT_EQ(tidesdb_recover_prepared(db, found, 4, &count), TDB_SUCCESS);
    ASSERT_EQ(count, 1);
    ASSERT_TRUE(memcmp(found[0].xid, xid, sizeof(xid) - 1) == 0);

    ASSERT_EQ(tidesdb_txn_commit_prepared(found[0].txn), TDB_SUCCESS);
    tidesdb_txn_free(found[0].txn);

    tidesdb_txn_t *rt = NULL;
    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(rt, cf, pk, sizeof(pk) - 1, &got, &got_size), TDB_SUCCESS);
    free(got);
    ASSERT_EQ(tidesdb_txn_commit(rt), TDB_SUCCESS);
    tidesdb_txn_free(rt);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

void test_engine_txn_two_phase_commit(void)
{
    (void)remove_directory(ENGINE_TEST_DB_DIR);
    char db_path[] = ENGINE_TEST_DB_DIR;
    tidesdb_config_t cfg = engine_test_config(db_path);

    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, "kv", &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);

    const uint8_t xid1[] = "xid-commit-001";
    const uint8_t k1[] = "alpha";
    const uint8_t v1[] = "one";

    /* prepare a write, then confirm the state moved to prepared and the write is invisible to a
     * fresh reader because commit-prepared has not applied it yet */
    tidesdb_txn_t *t1 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t1, cf, k1, sizeof(k1) - 1, v1, sizeof(v1) - 1, -1), TDB_SUCCESS);
    tidesdb_txn_state_t st = TDB_TXN_STATE_ABORTED;
    ASSERT_EQ(tidesdb_txn_state(t1, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_ACTIVE);
    ASSERT_EQ(tidesdb_txn_prepare(t1, xid1, sizeof(xid1) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_state(t1, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_PREPARED);
    engine_assert_committed(db, cf, "alpha", NULL);

    /* commit-prepared applies the batch, makes it visible, and moves the txn to committed */
    ASSERT_EQ(tidesdb_txn_commit_prepared(t1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_state(t1, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_COMMITTED);
    tidesdb_txn_free(t1);
    engine_assert_committed(db, cf, "alpha", "one");

    /* a second xid prepared then rolled back leaves no trace and ends aborted */
    const uint8_t xid2[] = "xid-rollback-002";
    const uint8_t k2[] = "beta";
    const uint8_t v2[] = "two";
    tidesdb_txn_t *t2 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t2), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(t2, cf, k2, sizeof(k2) - 1, v2, sizeof(v2) - 1, -1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_prepare(t2, xid2, sizeof(xid2) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback_prepared(t2), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_state(t2, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_ABORTED);
    tidesdb_txn_free(t2);
    engine_assert_committed(db, cf, "beta", NULL);

    /* misuse -- phase two on a still-active txn and a bad xid on prepare are rejected */
    tidesdb_txn_t *t3 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t3), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit_prepared(t3), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback_prepared(t3), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_prepare(t3, NULL, 0), TDB_ERR_INVALID_ARGS);
    tidesdb_txn_free(t3);

    /* a read-only prepare needs no phase two and votes committed immediately */
    tidesdb_txn_t *t4 = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &t4), TDB_SUCCESS);
    uint8_t *rv = NULL;
    size_t rvs = 0;
    ASSERT_EQ(tidesdb_txn_get(t4, cf, k1, sizeof(k1) - 1, &rv, &rvs), TDB_SUCCESS);
    free(rv);
    const uint8_t xid4[] = "xid-readonly-004";
    ASSERT_EQ(tidesdb_txn_prepare(t4, xid4, sizeof(xid4) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_state(t4, &st), TDB_SUCCESS);
    ASSERT_EQ(st, TDB_TXN_STATE_COMMITTED);
    tidesdb_txn_free(t4);

    /* the committed-prepared write survives a flush to L1 and a reopen */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    cf = tidesdb_get_column_family(db, "kv");
    ASSERT_TRUE(cf != NULL);
    engine_assert_committed(db, cf, "alpha", "one");
    engine_assert_committed(db, cf, "beta", NULL);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    (void)remove_directory(ENGINE_TEST_DB_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_engine_open_close, tests_passed);
    RUN_TEST(test_engine_reopen, tests_passed);
    RUN_TEST(test_engine_rejects_bad_args, tests_passed);
    RUN_TEST(test_engine_default_config, tests_passed);
    RUN_TEST(test_engine_create_column_family, tests_passed);
    RUN_TEST(test_engine_cf_recovery, tests_passed);
    RUN_TEST(test_engine_drop_column_family, tests_passed);
    RUN_TEST(test_engine_txn_put_get, tests_passed);
    RUN_TEST(test_engine_txn_delete, tests_passed);
    RUN_TEST(test_engine_txn_rollback, tests_passed);
    RUN_TEST(test_engine_txn_two_phase_commit, tests_passed);
    RUN_TEST(test_engine_recover_prepared, tests_passed);
    RUN_TEST(test_engine_prepared_survives_flush, tests_passed);
    RUN_TEST(test_engine_key_stays_writable_after_a_two_phase_commit, tests_passed);
    RUN_TEST(test_engine_settled_prepare_lands_above_writes_it_was_in_doubt_through, tests_passed);
    RUN_TEST(test_engine_recovered_phase_two_durable_and_ordered, tests_passed);
    RUN_TEST(test_engine_write_recovery, tests_passed);
    RUN_TEST(test_engine_overwrite_across_recovery, tests_passed);
    RUN_TEST(test_engine_multi_cf_write, tests_passed);
    RUN_TEST(test_engine_flush_rotation, tests_passed);
    RUN_TEST(test_engine_compaction, tests_passed);
    RUN_TEST(test_engine_fd_reaper, tests_passed);
    RUN_TEST(test_engine_interval_sync, tests_passed);
    RUN_TEST(test_engine_iterator, tests_passed);
    RUN_TEST(test_engine_bounded_iterator_returns_the_whole_range_and_nothing_else, tests_passed);
    RUN_TEST(test_engine_compaction_converges_an_interleaved_store, tests_passed);
    RUN_TEST(test_engine_scan_reads_own_writes, tests_passed);
    RUN_TEST(test_engine_cf_stats, tests_passed);
    RUN_TEST(test_engine_cf_estimate_cardinality, tests_passed);
    RUN_TEST(test_engine_cf_unflushed_keys, tests_passed);
    RUN_TEST(test_engine_cf_stats_levels_tombstones_compaction, tests_passed);
    RUN_TEST(test_engine_db_stats, tests_passed);
    RUN_TEST(test_engine_cache_stats, tests_passed);
    RUN_TEST(test_engine_an_empty_value_reads_back_as_present, tests_passed);
    RUN_TEST(test_engine_flush_and_sync, tests_passed);
    RUN_TEST(test_engine_level_set_generation_tracks_layout_changes, tests_passed);
    RUN_TEST(test_engine_compact, tests_passed);
    RUN_TEST(test_engine_compact_range, tests_passed);
    RUN_TEST(test_engine_range_stats_counts_merged_stream, tests_passed);
    RUN_TEST(test_engine_range_stats_estimate_follows_the_range_not_the_file, tests_passed);
    RUN_TEST(test_engine_range_stats_wide_range_is_estimated, tests_passed);
    RUN_TEST(test_engine_checkpoint, tests_passed);
    RUN_TEST(test_engine_backup, tests_passed);
    RUN_TEST(test_engine_list_column_families, tests_passed);
    RUN_TEST(test_engine_cf_update_runtime_config, tests_passed);
    RUN_TEST(test_engine_commit_hook, tests_passed);
    RUN_TEST(test_engine_rename_column_family, tests_passed);
    RUN_TEST(test_engine_rename_completes_under_concurrent_writes, tests_passed);
    RUN_TEST(test_engine_create_completes_under_sustained_flush, tests_passed);
    RUN_TEST(test_engine_log_to_file_writes_into_the_database_directory, tests_passed);
    RUN_TEST(test_engine_log_truncation_bounds_the_file, tests_passed);
    RUN_TEST(test_engine_scheduler_replans_when_the_gc_floor_moves, tests_passed);
    RUN_TEST(test_engine_idle_flush_rotates_an_unwritten_memtable, tests_passed);
    RUN_TEST(test_engine_preparing_a_spare_log_strands_no_file, tests_passed);
    RUN_TEST(test_engine_recovered_in_doubt_batch_survives_later_flushes, tests_passed);
    RUN_TEST(test_engine_undecided_prepare_pins_only_its_own_generation, tests_passed);
    RUN_TEST(test_engine_cf_data_size_counts_key_logs_once, tests_passed);
    RUN_TEST(test_engine_stall_stats_attribute_writer_waits, tests_passed);
    RUN_TEST(test_engine_io_stats_attribute_device_work, tests_passed);
    RUN_TEST(test_engine_finished_sstable_is_trimmed_to_its_data, tests_passed);
    RUN_TEST(test_engine_compaction_unlinks_merged_inputs, tests_passed);
    RUN_TEST(test_engine_compaction_leaves_no_orphans_under_load, tests_passed);
    RUN_TEST(test_engine_open_sweeps_orphaned_sstables, tests_passed);
    RUN_TEST(test_engine_open_keeps_sstables_when_manifest_self_healed, tests_passed);
    RUN_TEST(test_engine_runtime_config_rejects_an_unbacked_encoding, tests_passed);
    RUN_TEST(test_engine_compaction_drops_versions_a_range_tombstone_covers, tests_passed);
    RUN_TEST(test_engine_range_tombstone_lives_as_long_as_a_table_carries_it, tests_passed);
    RUN_TEST(test_engine_read_survives_a_compaction_moving_levels, tests_passed);
    RUN_TEST(test_engine_prepared_prefix_delete_blocks_a_write_under_it, tests_passed);
    RUN_TEST(test_engine_delete_range_covers_bounds_no_prefix_could, tests_passed);
    RUN_TEST(test_engine_public_prefix_delete_end_to_end, tests_passed);
    RUN_TEST(test_engine_prefix_delete_conflicts_with_a_write_under_it, tests_passed);
    RUN_TEST(test_engine_repeated_range_deletes_do_not_exhaust_the_reservations, tests_passed);
    RUN_TEST(test_engine_range_delete_refuses_a_bound_past_the_limit, tests_passed);
    RUN_TEST(test_engine_range_delete_refuses_an_interval_covering_nothing, tests_passed);
    RUN_TEST(test_engine_clone_carries_range_tombstones, tests_passed);
    RUN_TEST(test_engine_clone_column_family, tests_passed);
    RUN_TEST(test_engine_vlog_segment_size_is_honoured, tests_passed);
    RUN_TEST(test_engine_value_separation_is_db_level_with_a_family_opt_out, tests_passed);
    RUN_TEST(test_engine_memtable_reference_resolves_on_every_path, tests_passed);
    RUN_TEST(test_engine_separated_value_survives_reopen_and_reclaim, tests_passed);
    RUN_TEST(test_engine_prepared_batch_keeps_its_separated_values, tests_passed);
    RUN_TEST(test_engine_replay_does_not_resurrect_over_its_sstables, tests_passed);
    RUN_TEST(test_engine_replay_does_not_undo_an_overwrite_in_any_family, tests_passed);
    RUN_TEST(test_engine_two_phase_replay_does_not_resurrect_a_superseded_key, tests_passed);
    RUN_TEST(test_engine_replay_probe_says_yes_only_to_a_newer_durable_version, tests_passed);
    RUN_TEST(test_engine_replay_keeps_entries_disk_never_superseded, tests_passed);
    RUN_TEST(test_engine_compression_reaches_separated_values, tests_passed);
    RUN_TEST(test_engine_stacked_encoding_round_trips, tests_passed);
    RUN_TEST(test_engine_second_open_is_refused, tests_passed);
    RUN_TEST(test_engine_frozen_snapshot_survives_a_flush, tests_passed);
    RUN_TEST(test_engine_snapshot_reads_as_of_its_sequence, tests_passed);
    RUN_TEST(test_engine_snapshot_holds_versions_a_compaction_would_have_collected, tests_passed);
    RUN_TEST(test_engine_snapshot_holds_and_releases_the_reclamation_floor, tests_passed);
    RUN_TEST(test_engine_snapshot_scan_sees_the_same_past, tests_passed);
    RUN_TEST(test_engine_read_at_a_sequence_still_held, tests_passed);
    RUN_TEST(test_engine_read_at_a_collected_sequence_is_refused, tests_passed);
    RUN_TEST(test_engine_oldest_readable_seq_resets_on_open, tests_passed);
    RUN_TEST(test_engine_drop_removes_only_that_familys_files, tests_passed);
    RUN_TEST(test_engine_vlog_gc, tests_passed);
    RUN_TEST(test_engine_deleting_everything_reclaims_the_space, tests_passed);
    RUN_TEST(test_engine_klog_encoding_stats_are_per_pipeline, tests_passed);
    RUN_TEST(test_engine_wal_descriptor_accounting_balances, tests_passed);
    RUN_TEST(test_engine_rebuilds_catalogue_from_sstables, tests_passed);
    RUN_TEST(test_engine_txn_timeout_expires, tests_passed);
    RUN_TEST(test_engine_txn_timeout_config_default, tests_passed);
    RUN_TEST(test_engine_cf_id_not_reused_after_drop_reopen, tests_passed);
    RUN_TEST(test_engine_raise_open_file_limit, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
