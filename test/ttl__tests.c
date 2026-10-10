/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <time.h>

#include "../src/engine/engine.h"
#include "db.h"
#include "test_utils.h"

/* time-to-live through the public facade. the skip list and the btree each cover expiry over their
 * own storage, but nothing followed a deadline set on tidesdb_txn_put along the path a real entry
 * takes -- memtable, then sstable, then a reopen -- which is where an expiry gets dropped or
 * re-read as live. */

static int tests_passed = 0;
static int tests_failed = 0;

#define TTL_DB_DIR "." PATH_SEPARATOR "test_ttl_db"
#define TTL_CF     "cf0"

/* lifetimes in seconds, which is what the api takes. short enough that the suite does not stall
 * waiting for it, long enough that the key is still live for the reads taken immediately after */
#define TTL_SHORT_SECS 1
/* a life no test run outlives, for the key that has to stay readable throughout */
#define TTL_LONG_SECS 3600
/* the api's never-expires value */
#define TTL_FOREVER 0
/* a life long enough to outlive a flush, so the entry reaches an sstable while it is still live and
 * only lapses once it is there */
#define TTL_ON_DISK_SECS 3
/* how long a wait for a deadline sleeps between checks */
#define TTL_POLL_US 50000
/* how long to let the engine's once-a-second clock catch up to a deadline the test's own
 * clock has passed; generous because it only bounds a failure, never a success */
#define TTL_ABSENT_MAX_POLLS 200
/* keys written alongside the expiring one, enough that a merge has real work and the family does
 * not consist of a single entry */
#define TTL_FILLER_KEYS 64

static tidesdb_t *ttl_open(char *db_path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = db_path;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);
    return db;
}

static void ttl_put(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key, time_t ttl)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)"v", 1, ttl),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

/* wait out the rest of the current second and return the one the caller's puts will be timed from.
 *
 * the deadline a put is given is built on a clock counting whole seconds, so one made late in a
 * second is given a deadline less than its lifetime away, and a liveness check before that deadline
 * races it rather than testing it. how much headroom there is depends on where in the second the
 * test happened to start, which is nothing the test controls -- waiting for the tick first hands it
 * the whole lifetime every time
 * @return the second to measure the lifetime from
 */
static time_t ttl_wait_for_tick(void)
{
    const time_t tick = time(NULL);
    while (time(NULL) == tick) usleep(TTL_POLL_US);
    return time(NULL);
}

/* read a key in its own transaction and report the engine's result code */
static int ttl_get(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key)
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

/* the engine decides expiry against a clock a background ticker republishes once a second, so a
 * deadline the test's own time(NULL) has already passed can still be in the future from the
 * engine's point of view. the wall-clock wait above is what says the entry must not lapse early;
 * this is what waits for the engine to agree that it has, rather than demanding it the instant the
 * test's clock says so and failing on the ticker's phase
 * @param db the database
 * @param cf the column family
 * @param key the key expected to lapse
 * @return the engine's result once the key reads as absent, or its last result at the timeout
 */
static int ttl_wait_until_absent(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key)
{
    int rc = TDB_SUCCESS;
    for (int i = 0; i < TTL_ABSENT_MAX_POLLS && rc == TDB_SUCCESS; i++)
    {
        rc = ttl_get(db, cf, key);
        if (rc != TDB_SUCCESS) break;
        usleep(TTL_POLL_US);
    }
    return rc;
}

/* assert the three keys read as expected, so each stage checks the same thing */
static void ttl_expect(tidesdb_t *db, tidesdb_column_family_t *cf, int soon_rc)
{
    ASSERT_EQ(ttl_get(db, cf, "soon"), soon_rc);
    ASSERT_EQ(ttl_get(db, cf, "later"), TDB_SUCCESS);
    ASSERT_EQ(ttl_get(db, cf, "forever"), TDB_SUCCESS);
}

/* a deadline set on a put is honoured while the entry is in the memtable, travels with it into the
 * sstable, and is still honoured after a reopen -- while a long life and no life at all survive all
 * three */
void test_ttl_expires_across_memtable_flush_and_reopen(void)
{
    (void)remove_directory(TTL_DB_DIR);
    char db_path[] = TTL_DB_DIR;
    tidesdb_t *db = ttl_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, TTL_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(cf != NULL);

    /* the deadline is computed from the lifetime at put time, so note when that was in order to
     * wait past it below.
     *
     * started at the top of a second, for the reason ttl_wait_for_tick gives */
    const time_t written_at = ttl_wait_for_tick();
    ttl_put(db, cf, "soon", TTL_SHORT_SECS);
    ttl_put(db, cf, "later", TTL_LONG_SECS);
    ttl_put(db, cf, "forever", TTL_FOREVER);

    /* every key is live before the short deadline passes */
    ttl_expect(db, cf, TDB_SUCCESS);

    /* once it passes, the lapsed key reads as absent straight from the memtable */
    while (time(NULL) <= written_at + TTL_SHORT_SECS) usleep(TTL_POLL_US);
    ASSERT_EQ(ttl_wait_until_absent(db, cf, "soon"), TDB_ERR_NOT_FOUND);
    ttl_expect(db, cf, TDB_ERR_NOT_FOUND);

    /* the deadline has to reach the sstable, not be lost in the flush */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ttl_expect(db, cf, TDB_ERR_NOT_FOUND);

    /* and be what the reader honours after the entry is read back from disk */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = ttl_open(db_path);
    cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(cf != NULL);
    ttl_expect(db, cf, TDB_ERR_NOT_FOUND);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TTL_DB_DIR);
}

/* an entry can outlive the memtable and lapse only once it is in an sstable, which is the ordinary
 * case for any lifetime longer than the interval between flushes. a deadline that has not passed by
 * flush time is written out as a live entry carrying its deadline, so honouring it falls to the
 * sstable read -- it compares the deadline and, when it has passed, hands back exactly what a
 * tombstone hands back, which is no value, nothing to resolve out of the value log, and the deleted
 * flag set. that is how a layer above reads a lapsed entry as absent while knowing nothing of
 * expiry */
void test_ttl_expires_after_reaching_an_sstable(void)
{
    (void)remove_directory(TTL_DB_DIR);
    char db_path[] = TTL_DB_DIR;
    tidesdb_t *db = ttl_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, TTL_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(cf != NULL);

    const time_t written_at = ttl_wait_for_tick();
    ttl_put(db, cf, "lapses_on_disk", TTL_ON_DISK_SECS);
    ttl_put(db, cf, "forever", TTL_FOREVER);

    /* flushed while the deadline is still ahead, so the sstable holds a live entry carrying a
     * deadline rather than the tombstone a lapsed version would have been written as. the read
     * proves it: whatever answers below is answering from disk */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(ttl_get(db, cf, "lapses_on_disk"), TDB_SUCCESS);

    while (time(NULL) <= written_at + TTL_ON_DISK_SECS) usleep(TTL_POLL_US);

    /* the deadline has passed and the only copy is the one on disk */
    ASSERT_EQ(ttl_wait_until_absent(db, cf, "lapses_on_disk"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(ttl_get(db, cf, "forever"), TDB_SUCCESS);

    /* a reopen reads that same sstable, so it must not bring the key back either */
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = ttl_open(db_path);
    cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ(ttl_get(db, cf, "lapses_on_disk"), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(ttl_get(db, cf, "forever"), TDB_SUCCESS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TTL_DB_DIR);
}

/* read the family's live key total, which is what says whether a lapsed entry was physically
 * collected rather than merely hidden from a reader */
static uint64_t ttl_total_keys(tidesdb_column_family_t *cf)
{
    tidesdb_cf_stats_t st;
    ASSERT_EQ(tidesdb_get_cf_stats(cf, &st), TDB_SUCCESS);
    return st.total_keys;
}

/* a lapsed entry is hidden by the read path, but the bytes only go when a merge collects it. it
 * reaches the merge as a tombstone, so it is collected on the same terms as any tombstone -- which
 * is the point of turning it into one rather than dropping it where it lapsed */
void test_ttl_expired_entry_is_collected_by_compaction(void)
{
    (void)remove_directory(TTL_DB_DIR);
    char db_path[] = TTL_DB_DIR;
    tidesdb_t *db = ttl_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, TTL_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(cf != NULL);

    const time_t written_at = ttl_wait_for_tick();
    ttl_put(db, cf, "lapses_on_disk", TTL_ON_DISK_SECS);
    for (int i = 0; i < TTL_FILLER_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "keep%04d", i);
        ttl_put(db, cf, key, TTL_FOREVER);
    }

    /* flushed live, so the entry is real data in an sstable and its collection has to be a merge's
     * doing rather than the flush's */
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    const uint64_t keys_before = ttl_total_keys(cf);
    ASSERT_TRUE(keys_before >= TTL_FILLER_KEYS + 1);

    while (time(NULL) <= written_at + TTL_ON_DISK_SECS) usleep(TTL_POLL_US);
    ASSERT_EQ(ttl_wait_until_absent(db, cf, "lapses_on_disk"), TDB_ERR_NOT_FOUND);

    /* every level merges into one run here, so the lapsed entry meets the largest level where a
     * tombstone with nothing beneath it is dropped for good */
    ASSERT_EQ(tidesdb_compact(db, cf), TDB_SUCCESS);

    ASSERT_TRUE(ttl_total_keys(cf) < keys_before);
    ASSERT_EQ(ttl_get(db, cf, "lapses_on_disk"), TDB_ERR_NOT_FOUND);
    /* the merge collected the lapsed entry and nothing else */
    for (int i = 0; i < TTL_FILLER_KEYS; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "keep%04d", i);
        ASSERT_EQ(ttl_get(db, cf, key), TDB_SUCCESS);
    }

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(TTL_DB_DIR);
}

static tidesdb_t* ttl_getter_fresh(char* db_path, tidesdb_column_family_t** cf)
{
    (void)remove_directory(db_path);
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = db_path;
    cfg.value_separation_threshold = 64;
    cfg.txn_timeout_seconds = 0;
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, TTL_CF, &cc), TDB_SUCCESS);
    *cf = tidesdb_get_column_family(db, TTL_CF);
    ASSERT_TRUE(*cf != NULL);
    return db;
}

static void ttl_assert_deadline(tidesdb_txn_t* txn, tidesdb_column_family_t* cf, const char* key,
                                int expected_rc, time_t expected)
{
    time_t actual = 123;
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, (const uint8_t*)key, strlen(key), &actual), expected_rc);
    ASSERT_EQ(actual, expected_rc == TDB_SUCCESS ? expected : (time_t)123);
}

/* capture the stored deadline, and check that a duration became an absolute timestamp */
static time_t ttl_buffer_deadline(tidesdb_txn_t* txn, tidesdb_column_family_t* cf, const char* key,
                                  const uint8_t* value, size_t value_size, time_t seconds)
{
    const time_t before = time(NULL);
    ASSERT_EQ(
        tidesdb_txn_put(txn, cf, (const uint8_t*)key, strlen(key), value, value_size, seconds),
        TDB_SUCCESS);
    const time_t after = time(NULL);
    time_t deadline = 123;
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, (const uint8_t*)key, strlen(key), &deadline),
              TDB_SUCCESS);
    if (seconds > 0)
    {
        ASSERT_TRUE(deadline >= before + seconds);
        ASSERT_TRUE(deadline <= after + seconds);
    }
    else
        ASSERT_EQ(deadline, (time_t)-1);
    return deadline;
}

static time_t ttl_commit_deadline(tidesdb_t* db, tidesdb_column_family_t* cf, const char* key,
                                  time_t seconds)
{
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    const time_t deadline = ttl_buffer_deadline(txn, cf, key, (const uint8_t*)"v", 1, seconds);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    return deadline;
}

void test_txn_get_ttl_pending_and_errors(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    ttl_put(db, cf, "range_old", TTL_FOREVER);
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);

    time_t out = 123;
    ASSERT_EQ(tidesdb_txn_get_ttl(NULL, cf, (const uint8_t*)"key", 3, &out), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, NULL, (const uint8_t*)"key", 3, &out), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, NULL, 3, &out), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, (const uint8_t*)"key", 0, &out), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, (const uint8_t*)"key", 3, NULL), TDB_ERR_INVALID_ARGS);
    ttl_assert_deadline(txn, cf, "missing", TDB_ERR_NOT_FOUND, 0);

    const uint8_t value[] = "value";
    time_t deadline = ttl_buffer_deadline(txn, cf, "key", value, sizeof(value), TTL_LONG_SECS);
    ttl_assert_deadline(txn, cf, "key", TDB_SUCCESS, deadline);
    (void)ttl_buffer_deadline(txn, cf, "key", value, sizeof(value), 0);
    (void)ttl_buffer_deadline(txn, cf, "key", value, sizeof(value), -42);
    deadline = ttl_buffer_deadline(txn, cf, "key", NULL, 0, TTL_LONG_SECS);

    /* the oldest buffered key must remain findable after the write set grows */
    for (int i = 0; i < 128; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "other%03d", i);
        ASSERT_EQ(
            tidesdb_txn_put(txn, cf, (const uint8_t*)key, strlen(key), value, sizeof(value), 0),
            TDB_SUCCESS);
    }
    ttl_assert_deadline(txn, cf, "key", TDB_SUCCESS, deadline);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, (const uint8_t*)"key", 3), TDB_SUCCESS);
    ttl_assert_deadline(txn, cf, "key", TDB_ERR_NOT_FOUND, 0);

    (void)ttl_buffer_deadline(txn, cf, "range_new", value, sizeof(value), TTL_LONG_SECS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(txn, cf, (const uint8_t*)"range_", 6, (const uint8_t*)"range`", 6),
        TDB_SUCCESS);
    ttl_assert_deadline(txn, cf, "range_old", TDB_ERR_NOT_FOUND, 0);
    ttl_assert_deadline(txn, cf, "range_new", TDB_ERR_NOT_FOUND, 0);
    deadline = ttl_buffer_deadline(txn, cf, "range_new", value, sizeof(value), TTL_LONG_SECS);
    ttl_assert_deadline(txn, cf, "range_new", TDB_SUCCESS, deadline);

    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    ttl_assert_deadline(txn, cf, "key", TDB_ERR_INVALID_ARGS, 0);
    tidesdb_txn_free(txn);

    ASSERT_EQ(threadmanager_stop(db->threads, "txn_clock"), 0);
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_set_timeout(txn, 1), TDB_SUCCESS);
    atomic_fetch_add(&db->now_seconds, 2);
    ttl_assert_deadline(txn, cf, "range_old", TDB_ERR_TXN_EXPIRED, 0);
    tidesdb_txn_free(txn);
    atomic_store(&db->now_seconds, (int64_t)time(NULL));
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

void test_txn_get_ttl_commit_flush_and_reopen(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    const char* keys[] = {"inline", "large", "forever", "negative", "empty"};
    const time_t durations[] = {TTL_LONG_SECS, TTL_LONG_SECS + 10, 0, -42, TTL_LONG_SECS + 20};
    const size_t sizes[] = {8, 4096, 8, 8, 0};
    time_t deadlines[5];
    uint8_t value[4096];
    memset(value, 'v', sizeof(value));
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    for (int i = 0; i < 5; i++)
        deadlines[i] = ttl_buffer_deadline(txn, cf, keys[i], value, sizes[i], durations[i]);
    (void)ttl_buffer_deadline(txn, cf, "deleted", value, 8, TTL_LONG_SECS);
    (void)ttl_buffer_deadline(txn, cf, "ranged", value, 8, TTL_LONG_SECS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    ttl_assert_deadline(txn, cf, "inline", TDB_ERR_INVALID_ARGS, 0);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, (const uint8_t*)"deleted", 7), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_delete_range(txn, cf, (const uint8_t*)"range", 5, (const uint8_t*)"rangf", 5),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    for (int stage = 0; stage < 3; stage++)
    {
        if (stage == 1) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        if (stage == 2)
        {
            ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
            db = ttl_open(path);
            cf = tidesdb_get_column_family(db, TTL_CF);
            ASSERT_TRUE(cf != NULL);
        }
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        for (int i = 0; i < 5; i++)
        {
            ttl_assert_deadline(txn, cf, keys[i], TDB_SUCCESS, deadlines[i]);
            uint8_t* actual = NULL;
            size_t size = 0;
            ASSERT_EQ(
                tidesdb_txn_get(txn, cf, (const uint8_t*)keys[i], strlen(keys[i]), &actual, &size),
                TDB_SUCCESS);
            ASSERT_EQ(size, sizes[i]);
            if (size) ASSERT_EQ(memcmp(actual, value, size), 0);
            free(actual);
        }
        ttl_assert_deadline(txn, cf, "deleted", TDB_ERR_NOT_FOUND, 0);
        ttl_assert_deadline(txn, cf, "ranged", TDB_ERR_NOT_FOUND, 0);
        ttl_assert_deadline(txn, cf, "missing", TDB_ERR_NOT_FOUND, 0);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

void test_txn_get_ttl_snapshot_and_read_committed(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    const time_t first = ttl_commit_deadline(db, cf, "key", TTL_LONG_SECS);
    tidesdb_txn_t *snapshot = NULL, *read_committed = NULL;
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &snapshot), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_READ_COMMITTED, &read_committed),
              TDB_SUCCESS);
    ttl_assert_deadline(snapshot, cf, "key", TDB_SUCCESS, first);
    ttl_assert_deadline(read_committed, cf, "key", TDB_SUCCESS, first);
    const time_t second = ttl_commit_deadline(db, cf, "key", 2 * TTL_LONG_SECS);
    ASSERT_TRUE(second > first);
    for (int stage = 0; stage < 2; stage++)
    {
        if (stage) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        ttl_assert_deadline(snapshot, cf, "key", TDB_SUCCESS, first);
        ttl_assert_deadline(read_committed, cf, "key", TDB_SUCCESS, second);
    }
    tidesdb_txn_free(snapshot);
    tidesdb_txn_free(read_committed);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

void test_txn_get_ttl_reads_participate_in_conflicts(void)
{
    const tidesdb_isolation_level_t levels[] = {TDB_ISOLATION_REPEATABLE_READ,
                                                TDB_ISOLATION_SERIALIZABLE};
    for (int level = 0; level < 2; level++)
    {
        for (int present = 0; present < 2; present++)
        {
            char path[] = TTL_DB_DIR;
            tidesdb_column_family_t* cf = NULL;
            tidesdb_t* db = ttl_getter_fresh(path, &cf);
            time_t initial = -1;
            if (present) initial = ttl_commit_deadline(db, cf, "watched", TTL_LONG_SECS);
            tidesdb_txn_t* reader = NULL;
            ASSERT_EQ(tidesdb_txn_begin_with_isolation(db, levels[level], &reader), TDB_SUCCESS);
            ttl_assert_deadline(reader, cf, "watched", present ? TDB_SUCCESS : TDB_ERR_NOT_FOUND,
                                initial);
            (void)ttl_commit_deadline(db, cf, "watched", 2 * TTL_LONG_SECS);
            ASSERT_EQ(tidesdb_txn_put(reader, cf, (const uint8_t*)"unrelated", 9,
                                      (const uint8_t*)"v", 1, 0),
                      TDB_SUCCESS);
            ASSERT_EQ(tidesdb_txn_commit(reader), TDB_ERR_CONFLICT);
            tidesdb_txn_free(reader);
            ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
            (void)remove_directory(path);
        }
    }
}

void test_txn_get_ttl_expired_masks_older(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    ASSERT_EQ(threadmanager_stop(db->threads, "txn_clock"), 0);
    ttl_put(db, cf, "key", TTL_FOREVER);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    const time_t deadline =
        ttl_buffer_deadline(txn, cf, "key", (const uint8_t*)"new", 3, TTL_LONG_SECS);
    atomic_store(&db->now_seconds, (int64_t)deadline);
    ttl_assert_deadline(txn, cf, "key", TDB_ERR_NOT_FOUND, 0);
    atomic_store(&db->now_seconds, (int64_t)time(NULL));
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    for (int stage = 0; stage < 3; stage++)
    {
        if (stage == 1) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        if (stage == 2)
        {
            ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
            db = ttl_open(path);
            cf = tidesdb_get_column_family(db, TTL_CF);
            ASSERT_TRUE(cf != NULL);
            ASSERT_EQ(threadmanager_stop(db->threads, "txn_clock"), 0);
        }
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        atomic_store(&db->now_seconds, (int64_t)deadline - 1);
        ttl_assert_deadline(txn, cf, "key", TDB_SUCCESS, deadline);
        atomic_store(&db->now_seconds, (int64_t)deadline);
        ttl_assert_deadline(txn, cf, "key", TDB_ERR_NOT_FOUND, 0);
        tidesdb_txn_free(txn);
        atomic_store(&db->now_seconds, (int64_t)time(NULL));
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

static void ttl_assert_iterator_at(tidesdb_iter_t* iter, const char* expected_key,
                                   time_t expected_ttl)
{
    uint8_t* key = NULL;
    size_t key_size = 0;
    ASSERT_TRUE(tidesdb_iter_valid(iter));
    ASSERT_EQ(tidesdb_iter_key(iter, &key, &key_size), TDB_SUCCESS);
    ASSERT_EQ(key_size, strlen(expected_key));
    ASSERT_EQ(memcmp(key, expected_key, key_size), 0);
    free(key);
    time_t actual = 123;
    ASSERT_EQ(tidesdb_iter_ttl(iter, &actual), TDB_SUCCESS);
    ASSERT_EQ(actual, expected_ttl);
}

static void ttl_assert_iterator_scan(tidesdb_txn_t* txn, tidesdb_column_family_t* cf,
                                     const time_t* deadlines)
{
    const char* keys[] = {"a_expiring", "b_forever", "c_negative", "d_empty", "e_large"};
    tidesdb_iter_t* iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), TDB_SUCCESS);
    time_t out = 123;
    ASSERT_EQ(tidesdb_iter_ttl(NULL, &out), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_iter_ttl(iter, NULL), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_iter_ttl(iter, &out), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);
    for (int i = 0; i < 5; i++)
    {
        ttl_assert_iterator_at(iter, keys[i], deadlines[i]);
        const int rc = tidesdb_iter_next(iter);
        ASSERT_EQ(rc, i == 4 ? TDB_ERR_NOT_FOUND : TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_iter_ttl(iter, &out), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(out, (time_t)123);
    ASSERT_EQ(tidesdb_iter_seek_for_prev(iter, (const uint8_t*)"z", 1), TDB_SUCCESS);
    for (int i = 4; i >= 0; i--)
    {
        ttl_assert_iterator_at(iter, keys[i], deadlines[i]);
        const int rc = tidesdb_iter_prev(iter);
        ASSERT_EQ(rc, i == 0 ? TDB_ERR_NOT_FOUND : TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_iter_ttl(iter, &out), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(out, (time_t)123);
    tidesdb_iter_free(iter);
}

void test_iterator_ttl_pending_commit_flush_and_reopen(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    tidesdb_iter_t* empty = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &empty), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_seek_to_first(empty), TDB_ERR_NOT_FOUND);
    time_t out = 123;
    ASSERT_EQ(tidesdb_iter_ttl(empty, &out), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(out, (time_t)123);
    tidesdb_iter_free(empty);

    const char* keys[] = {"a_expiring", "b_forever", "c_negative", "d_empty", "e_large"};
    const time_t durations[] = {TTL_LONG_SECS, 0, -42, TTL_LONG_SECS + 10, TTL_LONG_SECS + 20};
    const size_t sizes[] = {8, 8, 8, 0, 4096};
    time_t deadlines[5];
    uint8_t value[4096];
    memset(value, 'v', sizeof(value));
    for (int i = 0; i < 5; i++)
        deadlines[i] = ttl_buffer_deadline(txn, cf, keys[i], value, sizes[i], durations[i]);
    (void)ttl_buffer_deadline(txn, cf, "f_deleted", value, 8, TTL_LONG_SECS);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, (const uint8_t*)"f_deleted", 9), TDB_SUCCESS);
    ttl_assert_iterator_scan(txn, cf, deadlines);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    for (int stage = 0; stage < 3; stage++)
    {
        if (stage == 1) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        if (stage == 2)
        {
            ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
            db = ttl_open(path);
            cf = tidesdb_get_column_family(db, TTL_CF);
            ASSERT_TRUE(cf != NULL);
        }
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ttl_assert_iterator_scan(txn, cf, deadlines);
        tidesdb_txn_free(txn);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

void test_iterator_ttl_current_expiry_and_detached(void)
{
    for (int on_disk = 0; on_disk < 2; on_disk++)
    {
        char path[] = TTL_DB_DIR;
        tidesdb_column_family_t* cf = NULL;
        tidesdb_t* db = ttl_getter_fresh(path, &cf);
        ASSERT_EQ(threadmanager_stop(db->threads, "txn_clock"), 0);
        const time_t deadline = ttl_commit_deadline(db, cf, "a_expiring", TTL_LONG_SECS);
        ttl_put(db, cf, "b_forever", TTL_FOREVER);
        if (on_disk) ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        tidesdb_txn_t* txn = NULL;
        tidesdb_iter_t* iter = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);
        ttl_assert_iterator_at(iter, "a_expiring", deadline);

        /* expiry after positioning must not change the metadata of the current entry */
        atomic_store(&db->now_seconds, (int64_t)deadline);
        ttl_assert_deadline(txn, cf, "a_expiring", TDB_ERR_NOT_FOUND, 0);
        ttl_assert_iterator_at(iter, "a_expiring", deadline);
        ASSERT_EQ(tidesdb_iter_next(iter), TDB_SUCCESS);
        ttl_assert_iterator_at(iter, "b_forever", -1);
        ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);
        ttl_assert_iterator_at(iter, "b_forever", -1);
        ASSERT_EQ(tidesdb_iter_prev(iter), TDB_ERR_NOT_FOUND);
        ASSERT_EQ(tidesdb_iter_seek_to_last(iter), TDB_SUCCESS);
        ttl_assert_iterator_at(iter, "b_forever", -1);

        tidesdb_txn_free(txn);
        time_t out = 123;
        ASSERT_EQ(tidesdb_iter_ttl(iter, &out), TDB_ERR_INVALID_ARGS);
        ASSERT_EQ(out, (time_t)123);
        tidesdb_iter_free(iter);
        atomic_store(&db->now_seconds, (int64_t)time(NULL));
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
        (void)remove_directory(path);
    }
}

void test_ttl_getters_respect_time_t_range(void)
{
    char path[] = TTL_DB_DIR;
    tidesdb_column_family_t* cf = NULL;
    tidesdb_t* db = ttl_getter_fresh(path, &cf);
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    const int64_t before = (int64_t)time(NULL);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t*)"key", 3, (const uint8_t*)"v", 1,
                              (time_t)INT32_MAX),
              TDB_SUCCESS);
    const int64_t after = (int64_t)time(NULL);
    const int expected_rc = sizeof(time_t) == 4 ? TDB_ERR_TOO_LARGE : TDB_SUCCESS;
    time_t out = 123;
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, (const uint8_t*)"key", 3, &out), expected_rc);
    if (expected_rc == TDB_SUCCESS)
    {
        ASSERT_TRUE((int64_t)out >= before + INT32_MAX);
        ASSERT_TRUE((int64_t)out <= after + INT32_MAX);
    }
    else
        ASSERT_EQ(out, (time_t)123);

    tidesdb_iter_t* iter = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &iter), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_seek_to_first(iter), TDB_SUCCESS);
    const time_t expected = out;
    out = 123;
    ASSERT_EQ(tidesdb_iter_ttl(iter, &out), expected_rc);
    ASSERT_EQ(out, expected);
    tidesdb_iter_free(iter);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(path);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_ttl_expires_across_memtable_flush_and_reopen, tests_passed);
    RUN_TEST(test_ttl_expires_after_reaching_an_sstable, tests_passed);
    RUN_TEST(test_ttl_expired_entry_is_collected_by_compaction, tests_passed);
    RUN_TEST(test_txn_get_ttl_pending_and_errors, tests_passed);
    RUN_TEST(test_txn_get_ttl_commit_flush_and_reopen, tests_passed);
    RUN_TEST(test_txn_get_ttl_snapshot_and_read_committed, tests_passed);
    RUN_TEST(test_txn_get_ttl_reads_participate_in_conflicts, tests_passed);
    RUN_TEST(test_txn_get_ttl_expired_masks_older, tests_passed);
    RUN_TEST(test_iterator_ttl_pending_commit_flush_and_reopen, tests_passed);
    RUN_TEST(test_iterator_ttl_current_expiry_and_detached, tests_passed);
    RUN_TEST(test_ttl_getters_respect_time_t_range, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
