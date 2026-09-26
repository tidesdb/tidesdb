/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/thread.h" /* threads retired without a join */
#include "db.h"
#include "test_utils.h"

/* the transaction entry points the other suites never call -- the family-bound begin, the read that
 * stays out of the conflict footprint, and the single-delete. each is a variant of a well covered
 * call, so what needs holding in place is the way it differs from the one beside it.
 *
 * the savepoint calls, the reset and the existence check are here for a different reason: their
 * only other cover is the model fuzzer, which drives valid sequences and compares against a model
 * that mirrors whatever the engine does. that finds divergence, not a wrong contract, so what the
 * cases below pin is the contract itself -- which writes a rollback discards, which savepoints it
 * forgets, and what an unknown name answers. */

static int tests_passed = 0;
static int tests_failed = 0;

#define TXNAPI_DB_DIR "." PATH_SEPARATOR "test_txn_api_db"
#define TXNAPI_CF     "cf0"

static tidesdb_t *txnapi_open(char *db_path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = db_path;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);
    return db;
}

static tidesdb_column_family_t *txnapi_make_cf(tidesdb_t *db, const char *name,
                                               tidesdb_isolation_level_t isolation)
{
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    cc.default_isolation_level = isolation;
    ASSERT_EQ(tidesdb_create_column_family(db, name, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, name);
    ASSERT_TRUE(cf != NULL);
    return cf;
}

static void txnapi_put(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key, const char *val)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static int txnapi_get(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    uint8_t *value = NULL;
    size_t value_size = 0;
    const int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key), &value, &value_size);
    free(value);
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    return rc;
}

/* buffer a write inside an already open transaction, so a case can shape a buffer around savepoints
 * rather than committing between each write */
static void txnapi_buffer(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const char *key,
                          const char *val)
{
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), -1),
              TDB_SUCCESS);
}

/* read a key through an open transaction, which sees that transaction's own buffered writes */
static int txnapi_peek(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const char *key)
{
    uint8_t *value = NULL;
    size_t value_size = 0;
    const int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key), &value, &value_size);
    free(value);
    return rc;
}

/* open a database and one family, the scaffolding every savepoint case starts from */
static tidesdb_t *txnapi_fresh(char *db_path, tidesdb_column_family_t **cf)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    tidesdb_t *db = txnapi_open(db_path);
    *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_READ_COMMITTED);
    return db;
}

/* the untracked read answers exactly as the tracked one does. it differs only in leaving the read
 * out of the conflict footprint, which must not cost it read-your-own-writes */
void test_txn_get_notrack_answers_as_get_does(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(db_path);
    tidesdb_column_family_t *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);

    txnapi_put(db, cf, "k1", "v1");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    uint8_t *tracked = NULL, *untracked = NULL;
    size_t tracked_size = 0, untracked_size = 0;
    ASSERT_EQ(tidesdb_txn_get(txn, cf, (const uint8_t *)"k1", 2, &tracked, &tracked_size),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_get_notrack(txn, cf, (const uint8_t *)"k1", 2, &untracked, &untracked_size),
        TDB_SUCCESS);
    ASSERT_EQ(untracked_size, tracked_size);
    ASSERT_TRUE(memcmp(untracked, tracked, tracked_size) == 0);
    free(tracked);
    free(untracked);

    /* an absent key is absent either way */
    ASSERT_EQ(
        tidesdb_txn_get_notrack(txn, cf, (const uint8_t *)"nope", 4, &untracked, &untracked_size),
        TDB_ERR_NOT_FOUND);

    /* the transaction's own buffered write is still visible to it */
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)"k2", 2, (const uint8_t *)"v2", 2, -1),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_get_notrack(txn, cf, (const uint8_t *)"k2", 2, &untracked, &untracked_size),
        TDB_SUCCESS);
    ASSERT_EQ(untracked_size, 2u);
    ASSERT_TRUE(memcmp(untracked, "v2", 2) == 0);
    free(untracked);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the family-bound begin takes the family's configured level rather than the database default. that
 * is only observable through the level's own behaviour, so drive the difference: read committed
 * picks up a commit made after it began, snapshot keeps the state it started from */
void test_txn_begin_cf_adopts_the_family_isolation(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(db_path);
    tidesdb_column_family_t *rc_cf = txnapi_make_cf(db, "cf_rc", TDB_ISOLATION_READ_COMMITTED);
    tidesdb_column_family_t *si_cf = txnapi_make_cf(db, "cf_si", TDB_ISOLATION_SNAPSHOT);

    txnapi_put(db, rc_cf, "k", "before");
    txnapi_put(db, si_cf, "k", "before");

    tidesdb_txn_t *reader_rc = NULL, *reader_si = NULL;
    ASSERT_EQ(tidesdb_txn_begin_cf(db, rc_cf, &reader_rc), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_begin_cf(db, si_cf, &reader_si), TDB_SUCCESS);

    /* both take a first read before anything else commits */
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tidesdb_txn_get(reader_rc, rc_cf, (const uint8_t *)"k", 1, &v, &vs), TDB_SUCCESS);
    free(v);
    ASSERT_EQ(tidesdb_txn_get(reader_si, si_cf, (const uint8_t *)"k", 1, &v, &vs), TDB_SUCCESS);
    free(v);

    txnapi_put(db, rc_cf, "k", "after");
    txnapi_put(db, si_cf, "k", "after");

    ASSERT_EQ(tidesdb_txn_get(reader_rc, rc_cf, (const uint8_t *)"k", 1, &v, &vs), TDB_SUCCESS);
    ASSERT_EQ(vs, strlen("after"));
    ASSERT_TRUE(memcmp(v, "after", vs) == 0);
    free(v);

    ASSERT_EQ(tidesdb_txn_get(reader_si, si_cf, (const uint8_t *)"k", 1, &v, &vs), TDB_SUCCESS);
    ASSERT_EQ(vs, strlen("before"));
    ASSERT_TRUE(memcmp(v, "before", vs) == 0);
    free(v);

    (void)tidesdb_txn_rollback(reader_rc);
    tidesdb_txn_free(reader_rc);
    (void)tidesdb_txn_rollback(reader_si);
    tidesdb_txn_free(reader_si);

    ASSERT_EQ(tidesdb_txn_begin_cf(db, NULL, &reader_rc), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* a single-delete reads exactly as a delete does -- the promise it carries is only about how
 * compaction may reap it, so a reader must never see the key again, in the memtable, from an
 * sstable, or after the tombstone has been replayed from the log */
void test_txn_single_delete_hides_key_across_flush_and_reopen(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(db_path);
    tidesdb_column_family_t *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);

    txnapi_put(db, cf, "gone", "v");
    txnapi_put(db, cf, "kept", "v");
    ASSERT_EQ(txnapi_get(db, cf, "gone"), TDB_SUCCESS);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_single_delete(txn, cf, (const uint8_t *)"gone", 4), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(txnapi_get(db, cf, "gone"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(txnapi_get(db, cf, "kept"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(txnapi_get(db, cf, "gone"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(txnapi_get(db, cf, "kept"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = txnapi_open(db_path);
    cf = tidesdb_get_column_family(db, TXNAPI_CF);
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(txnapi_get(db, cf, "gone"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(txnapi_get(db, cf, "kept"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* a rollback discards the writes buffered after the mark and keeps the ones before it, and what
 * survives the rollback is what the commit then makes durable */
void test_savepoint_rollback_discards_only_the_writes_taken_after_the_mark(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "before", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "after", "v");
    ASSERT_EQ(txnapi_peek(txn, cf, "before"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "after"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "before"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "after"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(txnapi_get(db, cf, "before"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_get(db, cf, "after"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the savepoint a rollback used stays available to roll back to again, which is what sql specifies,
 * while the savepoints marked after it are forgotten along with the writes they covered */
void test_savepoint_survives_its_rollback_and_forgets_the_later_marks(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "kept", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "outer"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "mid", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "inner"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "last", "v");

    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "outer"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "kept"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "mid"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(txnapi_peek(txn, cf, "last"), TDB_ERR_NOT_FOUND);

    /* the inner mark went with the writes it covered, the outer one did not */
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "inner"), TDB_ERR_NOT_FOUND);
    txnapi_buffer(txn, cf, "again", "v");
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "outer"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "again"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(txnapi_peek(txn, cf, "kept"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* releasing a savepoint forgets the name without touching a single buffered write, which is the
 * whole difference between it and a rollback */
void test_savepoint_release_keeps_the_writes_and_forgets_the_name(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "before", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "after", "v");

    ASSERT_EQ(tidesdb_txn_release_savepoint(txn, "sp"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "before"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "after"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(txnapi_get(db, cf, "before"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_get(db, cf, "after"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* marking a name that already exists moves that one to the current position rather than stacking a
 * second savepoint under the same name, so a later rollback goes to the newer position */
void test_savepoint_marking_an_existing_name_moves_it_forward(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "first", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "second", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp"), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "third", "v");

    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "first"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "second"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "third"), TDB_ERR_NOT_FOUND);

    /* one name means one savepoint, so releasing it once leaves nothing behind to find */
    ASSERT_EQ(tidesdb_txn_release_savepoint(txn, "sp"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_release_savepoint(txn, "sp"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* a name that was never marked is not found, and a missing handle or name is a bad argument. the
 * two are different answers and a caller separates a typo from a programming error by them */
void test_savepoint_rejects_unknown_names_and_null_arguments(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "never"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_release_savepoint(txn, "never"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_txn_savepoint(txn, NULL), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, NULL), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_release_savepoint(txn, NULL), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_savepoint(NULL, "sp"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(NULL, "sp"), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_release_savepoint(NULL, "sp"), TDB_ERR_INVALID_ARGS);

    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* a reset hands back a transaction with nothing buffered and no savepoints, which is what makes it
 * safe to reuse the handle rather than free it and begin another */
void test_txn_reset_discards_the_buffered_writes_and_the_savepoints(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    txnapi_buffer(txn, cf, "dropped", "v");
    ASSERT_EQ(tidesdb_txn_savepoint(txn, "sp"), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "dropped"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_txn_reset(txn, TDB_ISOLATION_SNAPSHOT), TDB_SUCCESS);
    ASSERT_EQ(txnapi_peek(txn, cf, "dropped"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_rollback_to_savepoint(txn, "sp"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_reset(NULL, TDB_ISOLATION_SNAPSHOT), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(txnapi_get(db, cf, "dropped"), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the existence check answers where the read answers, buffered writes included, without ever
 * handing back the value -- which is the only reason to reach for it over a get */
void test_txn_contains_answers_where_the_read_answers(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);
    txnapi_put(db, cf, "committed", "v");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, (const uint8_t *)"committed", 9), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, (const uint8_t *)"absent", 6), TDB_ERR_NOT_FOUND);

    /* read-your-own-writes both ways -- a buffered put is present, a buffered delete is not */
    txnapi_buffer(txn, cf, "buffered", "v");
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, (const uint8_t *)"buffered", 8), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, (const uint8_t *)"committed", 9), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, (const uint8_t *)"committed", 9), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_txn_contains(NULL, cf, (const uint8_t *)"k", 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_contains(txn, NULL, (const uint8_t *)"k", 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, NULL, 1), TDB_ERR_INVALID_ARGS);

    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the read snapshot is the ceiling a transaction's reads filter at, so it reports what the level
 * promises: everything for read-uncommitted, a moving ceiling for read-committed, and one frozen at
 * begin for repeatable-read and stronger */
void test_read_snapshot_reflects_the_isolation_level(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);
    txnapi_put(db, cf, "seed", "v");

    ASSERT_EQ(tidesdb_txn_read_snapshot(NULL), 0u);

    tidesdb_txn_t *dirty = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_UNCOMMITTED, &dirty),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_read_snapshot(dirty), UINT64_MAX);

    tidesdb_txn_t *frozen = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_REPEATABLE_READ, &frozen),
              TDB_SUCCESS);
    const uint64_t frozen_at_begin = tidesdb_txn_read_snapshot(frozen);

    tidesdb_txn_t *moving = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, &moving),
              TDB_SUCCESS);
    const uint64_t moving_before = tidesdb_txn_read_snapshot(moving);

    /* a commit by someone else advances the clock the moving ceiling reads from */
    txnapi_put(db, cf, "later", "v");
    ASSERT_EQ(tidesdb_txn_read_snapshot(frozen), frozen_at_begin);
    ASSERT_TRUE(tidesdb_txn_read_snapshot(moving) > moving_before);

    (void)tidesdb_txn_rollback(dirty);
    (void)tidesdb_txn_rollback(frozen);
    (void)tidesdb_txn_rollback(moving);
    tidesdb_txn_free(dirty);
    tidesdb_txn_free(frozen);
    tidesdb_txn_free(moving);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the abort a second thread asks for, run from a second thread so the cross-thread path is the one
 * under test rather than a same-thread stand-in for it */
static void *txnapi_abort_thread(void *arg)
{
    tidesdb_txn_request_abort((tidesdb_txn_t *)arg);
    return NULL;
}

/* an outside authority can rule that a transaction loses, and the transaction then fails rather
 * than committing. this is the one call that may cross threads, and what it must produce is a code
 * of its own: a caller that certified against this transaction elsewhere has to be able to tell its
 * own ruling from the engine's first-committer-wins verdict, because the two mean different things
 * to whatever it reports upwards */
void test_txn_request_abort_makes_the_transaction_fail_with_its_own_code(void)
{
    char db_path[] = TXNAPI_DB_DIR;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_t *db = txnapi_fresh(db_path, &cf);

    /* nothing to abort is not an error, so a caller need not check first */
    tidesdb_txn_request_abort(NULL);

    tidesdb_txn_t *victim = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &victim), TDB_SUCCESS);
    txnapi_buffer(victim, cf, "row", "v");

    /* the ruling arrives from another thread, as it does when the server aborts a victim */
    pthread_t th;
    ASSERT_EQ(pthread_create(&th, NULL, txnapi_abort_thread, victim), 0);
    ASSERT_EQ(pthread_join(th, NULL), 0);

    /* the next operation fails, and says an outside authority ruled rather than reporting the
     * engine's own conflict */
    const int after = txnapi_peek(victim, cf, "row");
    ASSERT_EQ(after, TDB_ERR_TXN_ABORTED);
    ASSERT_NE(after, TDB_ERR_CONFLICT);

    /* and the commit does not go through, which is the whole point -- a victim that committed
     * anyway is the divergence this exists to stop */
    ASSERT_EQ(tidesdb_txn_commit(victim), TDB_ERR_TXN_ABORTED);
    tidesdb_txn_free(victim);

    /* nothing the aborted transaction buffered reached the database */
    ASSERT_EQ(txnapi_get(db, cf, "row"), TDB_ERR_NOT_FOUND);

    /* asking twice is harmless, and so is asking after the transaction has resolved */
    tidesdb_txn_t *done = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &done), TDB_SUCCESS);
    tidesdb_txn_request_abort(done);
    tidesdb_txn_request_abort(done);
    ASSERT_EQ(tidesdb_txn_commit(done), TDB_ERR_TXN_ABORTED);
    tidesdb_txn_request_abort(done);
    tidesdb_txn_free(done);

    /* the key is untouched by any of it, so a later writer is not left contending with a ghost */
    tidesdb_txn_t *next = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &next), TDB_SUCCESS);
    txnapi_buffer(next, cf, "row", "w");
    ASSERT_EQ(tidesdb_txn_commit(next), TDB_SUCCESS);
    tidesdb_txn_free(next);
    ASSERT_EQ(txnapi_get(db, cf, "row"), TDB_SUCCESS);

    /* the code describes itself, since it reaches an operator through a log line */
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_ERR_TXN_ABORTED), "unknown error") != 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* concurrent committers whose write sets never share a key. a claim names the key itself, so
 * nothing two commits of different keys hold can collide, however many keys each carries and
 * however their commits overlap; a table of hashed slots refused most such pairs of a few hundred
 * keys */
#define TXNAPI_DISJOINT_WRITERS 2
#define TXNAPI_DISJOINT_ROUNDS  40
#define TXNAPI_DISJOINT_KEYS    500
#define TXNAPI_WIDE_KEYS        100000 /* the TPC-C item table, loaded in one transaction */

/**
 * txnapi_disjoint_t
 * one writer's share of the disjoint commit test and what it saw
 * @param db the open database
 * @param cf the family every writer commits to
 * @param id this writer's number, the prefix that keeps its keys apart from the others'
 * @param rounds how many commits the writer makes
 * @param keys how many fresh keys each commit carries
 * @param conflicts commits refused with TDB_ERR_CONFLICT
 * @param failures commits refused with anything else
 */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int id;
    int rounds;
    int keys;
    _Atomic(int) conflicts;
    _Atomic(int) failures;
} txnapi_disjoint_t;

/**
 * txnapi_disjoint_writer
 * commit the writer's rounds of fresh keys at snapshot isolation
 * @param arg the txnapi_disjoint_t
 * @return NULL
 */
static void *txnapi_disjoint_writer(void *arg)
{
    txnapi_disjoint_t *w = arg;
    for (int round = 0; round < w->rounds; round++)
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin_with_isolation(w->db, TDB_ISOLATION_SNAPSHOT, &txn) != TDB_SUCCESS)
        {
            atomic_fetch_add(&w->failures, 1);
            continue;
        }
        for (int k = 0; k < w->keys; k++)
        {
            char key[32];
            const int n = snprintf(key, sizeof(key), "w%d-%04d-%06d", w->id, round, k);
            if (tidesdb_txn_put(txn, w->cf, (const uint8_t *)key, (size_t)n, (const uint8_t *)"v",
                                1, -1) != TDB_SUCCESS)
                atomic_fetch_add(&w->failures, 1);
        }
        const int rc = tidesdb_txn_commit(txn);
        if (rc == TDB_ERR_CONFLICT)
            atomic_fetch_add(&w->conflicts, 1);
        else if (rc != TDB_SUCCESS)
            atomic_fetch_add(&w->failures, 1);
        tidesdb_txn_free(txn);
    }
    return NULL;
}

/* committers that never write the same key never conflict, however their commits overlap */
static void txnapi_run_disjoint_writers(const int rounds, const int keys)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char dir[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(dir);
    tidesdb_column_family_t *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);

    txnapi_disjoint_t writers[TXNAPI_DISJOINT_WRITERS];
    tdb_thread_t threads[TXNAPI_DISJOINT_WRITERS];
    for (int i = 0; i < TXNAPI_DISJOINT_WRITERS; i++)
    {
        writers[i].db = db;
        writers[i].cf = cf;
        writers[i].id = i;
        writers[i].rounds = rounds;
        writers[i].keys = keys;
        atomic_init(&writers[i].conflicts, 0);
        atomic_init(&writers[i].failures, 0);
        ASSERT_EQ(tdb_thread_start(&threads[i], txnapi_disjoint_writer, &writers[i]), 0);
    }
    int conflicts = 0;
    int failures = 0;
    for (int i = 0; i < TXNAPI_DISJOINT_WRITERS; i++)
    {
        tdb_thread_finish(&threads[i]);
        conflicts += atomic_load(&writers[i].conflicts);
        failures += atomic_load(&writers[i].failures);
    }
    printf("  %d writers x %d commits of %d disjoint keys: %d conflicts, %d other failures\n",
           TXNAPI_DISJOINT_WRITERS, rounds, keys, conflicts, failures);
    fflush(stdout);
    ASSERT_EQ(failures, 0);
    ASSERT_EQ(conflicts, 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

void test_txn_api_disjoint_commits_never_conflict(void)
{
    txnapi_run_disjoint_writers(TXNAPI_DISJOINT_ROUNDS, TXNAPI_DISJOINT_KEYS);
}

/* two table loads of a hundred thousand keys each, committed at once with no key in common, both
 * succeed. the run of hashed slots let a single such commit through but refused the second of two,
 * since with that many keys in flight every run had a stranger in it */
void test_txn_api_concurrent_wide_commits_both_succeed(void)
{
    txnapi_run_disjoint_writers(1, TXNAPI_WIDE_KEYS);
}

#define TXNAPI_ATOMIC_ROUNDS  3000 /* commits of the two-key batch the readers race */
#define TXNAPI_ATOMIC_READERS 2

/**
 * txnapi_atomic_t
 * what the readers of the batch-atomicity test share and count
 * @param db the open database
 * @param cf the family the batch is written to
 * @param done set by the writer once its last batch has committed
 * @param pairs reads that found both keys
 * @param torn pairs whose two keys came from different batches
 */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    _Atomic(int) done;
    _Atomic(long) pairs;
    _Atomic(long) torn;
} txnapi_atomic_t;

/* the round a value was written in, which is what the two keys of one batch must agree on */
static long txnapi_round_of(const uint8_t *value, size_t size)
{
    char text[32] = {0};
    memcpy(text, value, size < sizeof(text) - 1 ? size : sizeof(text) - 1);
    return strtol(text, NULL, 10);
}

static void *txnapi_atomic_writer(void *arg)
{
    txnapi_atomic_t *a = arg;
    for (long round = 1; round <= TXNAPI_ATOMIC_ROUNDS; round++)
    {
        char value[32];
        const int n = snprintf(value, sizeof(value), "%ld", round);
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin(a->db, &txn) != TDB_SUCCESS) break;
        (void)tidesdb_txn_put(txn, a->cf, (const uint8_t *)"a", 1, (const uint8_t *)value,
                              (size_t)n, -1);
        (void)tidesdb_txn_put(txn, a->cf, (const uint8_t *)"b", 1, (const uint8_t *)value,
                              (size_t)n, -1);
        (void)tidesdb_txn_commit(txn);
        tidesdb_txn_free(txn);
    }
    atomic_store(&a->done, 1);
    return NULL;
}

static void *txnapi_atomic_reader(void *arg)
{
    txnapi_atomic_t *a = arg;
    while (!atomic_load(&a->done))
    {
        tidesdb_txn_t *txn = NULL;
        if (tidesdb_txn_begin_with_isolation(a->db, TDB_ISOLATION_SNAPSHOT, &txn) != TDB_SUCCESS)
            continue;
        uint8_t *va = NULL, *vb = NULL;
        size_t la = 0, lb = 0;
        const int ra = tidesdb_txn_get(txn, a->cf, (const uint8_t *)"a", 1, &va, &la);
        const int rb = tidesdb_txn_get(txn, a->cf, (const uint8_t *)"b", 1, &vb, &lb);
        if (ra == TDB_SUCCESS && rb == TDB_SUCCESS)
        {
            atomic_fetch_add(&a->pairs, 1);
            if (txnapi_round_of(va, la) != txnapi_round_of(vb, lb)) atomic_fetch_add(&a->torn, 1);
        }
        free(va);
        free(vb);
        (void)tidesdb_txn_rollback(txn);
        tidesdb_txn_free(txn);
    }
    return NULL;
}

/* a committed batch is atomic to every reader: a snapshot transaction reading the two keys a batch
 * writes together never sees one from an earlier batch than the other, however the reads race the
 * apply */
void test_txn_api_batch_is_atomic_to_readers(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char dir[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(dir);
    txnapi_atomic_t a;
    a.db = db;
    a.cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);
    atomic_init(&a.done, 0);
    atomic_init(&a.pairs, 0);
    atomic_init(&a.torn, 0);

    tdb_thread_t writer, readers[TXNAPI_ATOMIC_READERS];
    ASSERT_EQ(tdb_thread_start(&writer, txnapi_atomic_writer, &a), 0);
    for (int i = 0; i < TXNAPI_ATOMIC_READERS; i++)
        ASSERT_EQ(tdb_thread_start(&readers[i], txnapi_atomic_reader, &a), 0);
    tdb_thread_finish(&writer);
    for (int i = 0; i < TXNAPI_ATOMIC_READERS; i++) tdb_thread_finish(&readers[i]);

    printf("  %ld pair reads, %ld torn\n", atomic_load(&a.pairs), atomic_load(&a.torn));
    fflush(stdout);
    ASSERT_TRUE(atomic_load(&a.pairs) > 0);
    ASSERT_EQ(atomic_load(&a.torn), 0);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* the database counts the commits it made and the commits it refused, so a caller can read the
 * retry rate a level above read committed is paying without instrumenting every call site */
void test_txn_api_stats_count_commits_and_conflicts(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char dir[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(dir);
    tidesdb_column_family_t *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);

    tidesdb_db_stats_t before;
    ASSERT_EQ(tidesdb_get_db_stats(db, &before), TDB_SUCCESS);

    tidesdb_txn_t *first = NULL, *second = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &first), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &second), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(first, cf, (const uint8_t *)"k", 1, (const uint8_t *)"1", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(second, cf, (const uint8_t *)"k", 1, (const uint8_t *)"2", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(first), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(second), TDB_ERR_CONFLICT);
    tidesdb_txn_free(first);
    tidesdb_txn_free(second);

    tidesdb_db_stats_t after;
    ASSERT_EQ(tidesdb_get_db_stats(db, &after), TDB_SUCCESS);
    ASSERT_TRUE(after.txn_commits == before.txn_commits + 1);
    ASSERT_TRUE(after.txn_conflicts == before.txn_conflicts + 1);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

/* one commit of a hundred thousand keys, the size of a table load, never refuses itself: its claims
 * are its own, however many of them there are */
void test_txn_api_wide_commit_never_conflicts_with_itself(void)
{
    (void)remove_directory(TXNAPI_DB_DIR);
    char dir[] = TXNAPI_DB_DIR;
    tidesdb_t *db = txnapi_open(dir);
    tidesdb_column_family_t *cf = txnapi_make_cf(db, TXNAPI_CF, TDB_ISOLATION_SNAPSHOT);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn), TDB_SUCCESS);
    for (int k = 0; k < TXNAPI_WIDE_KEYS; k++)
    {
        char key[16];
        const int n = snprintf(key, sizeof(key), "i%06d", k);
        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (const uint8_t *)key, (size_t)n, (const uint8_t *)"v", 1, -1),
            TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TXNAPI_DB_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_txn_request_abort_makes_the_transaction_fail_with_its_own_code, tests_passed);
    RUN_TEST(test_txn_get_notrack_answers_as_get_does, tests_passed);
    RUN_TEST(test_txn_begin_cf_adopts_the_family_isolation, tests_passed);
    RUN_TEST(test_txn_single_delete_hides_key_across_flush_and_reopen, tests_passed);
    RUN_TEST(test_savepoint_rollback_discards_only_the_writes_taken_after_the_mark, tests_passed);
    RUN_TEST(test_savepoint_survives_its_rollback_and_forgets_the_later_marks, tests_passed);
    RUN_TEST(test_savepoint_release_keeps_the_writes_and_forgets_the_name, tests_passed);
    RUN_TEST(test_savepoint_marking_an_existing_name_moves_it_forward, tests_passed);
    RUN_TEST(test_savepoint_rejects_unknown_names_and_null_arguments, tests_passed);
    RUN_TEST(test_txn_reset_discards_the_buffered_writes_and_the_savepoints, tests_passed);
    RUN_TEST(test_txn_contains_answers_where_the_read_answers, tests_passed);
    RUN_TEST(test_read_snapshot_reflects_the_isolation_level, tests_passed);
    RUN_TEST(test_txn_api_disjoint_commits_never_conflict, tests_passed);
    RUN_TEST(test_txn_api_concurrent_wide_commits_both_succeed, tests_passed);
    RUN_TEST(test_txn_api_wide_commit_never_conflicts_with_itself, tests_passed);
    RUN_TEST(test_txn_api_batch_is_atomic_to_readers, tests_passed);
    RUN_TEST(test_txn_api_stats_count_commits_and_conflicts, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
