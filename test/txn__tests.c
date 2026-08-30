/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/txn/registry.h"
#include "../src/txn/txn.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static int put(tdb_txn_t *t, uint32_t cf, const char *k, const char *v)
{
    return tdb_txn_put(t, cf, (const uint8_t *)k, strlen(k), (const uint8_t *)v, strlen(v), -1);
}

/* a mock external source holding at most one key at a seq (NULL value = tombstone); busy_remaining
 * forces that many transient BUSY results before answering, and a version is visible only at or
 * below the reader's snapshot */
typedef struct
{
    int busy_remaining;
    int has;
    const char *key;
    uint64_t seq;
    const char *value;
} tsrc;

static tidesdb_source_result_t tsrc_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                        size_t key_size, uint64_t snapshot,
                                        tidesdb_source_version_t *out)
{
    (void)cf_index;
    tsrc *m = (tsrc *)ctx;
    if (m->busy_remaining > 0)
    {
        m->busy_remaining--;
        return TDB_SOURCE_BUSY;
    }
    if (!m->has || key_size != strlen(m->key) || memcmp(key, m->key, key_size) != 0)
        return TDB_SOURCE_NOT_FOUND;
    if (m->seq > snapshot) return TDB_SOURCE_NOT_FOUND;
    out->seq = m->seq;
    out->ttl = -1;
    out->deleted = m->value ? 0 : 1;
    if (m->value)
    {
        out->value_size = strlen(m->value);
        out->value = malloc(out->value_size);
        memcpy(out->value, m->value, out->value_size);
    }
    else
    {
        out->value = NULL;
        out->value_size = 0;
    }
    return TDB_SOURCE_FOUND;
}

static tidesdb_source_t tsource(tsrc *m)
{
    tidesdb_source_t s = {.name = "mock", .get = tsrc_get, .has_newer = NULL, .ctx = m};
    return s;
}

static int get_is(tdb_txn_t *t, uint32_t cf, const char *k, const tidesdb_source_t *srcs, int ns,
                  const char *expect)
{
    uint8_t *v = NULL;
    size_t vs = 0;
    if (tdb_txn_get(t, cf, (const uint8_t *)k, strlen(k), srcs, ns, &v, &vs) != TDB_SUCCESS)
        return 0;
    const int ok = vs == strlen(expect) && memcmp(v, expect, vs) == 0;
    free(v);
    return ok;
}

/* the snapshot is drawn per isolation level: read-uncommitted sees all, read-committed refreshes
 * per read (0 at begin), and repeatable-read and stronger freeze the highest assigned seq */
void test_txn_begin_snapshot(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(clock != NULL);
    (void)tidesdb_mvcc_next_seq(clock);
    (void)tidesdb_mvcc_next_seq(clock);
    (void)tidesdb_mvcc_next_seq(clock); /* current_seq now 4, highest assigned 3 */

    tdb_txn_t *ru = tdb_txn_begin(clock, TDB_ISOLATION_READ_UNCOMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(tdb_txn_snapshot(ru) == UINT64_MAX);
    tdb_txn_free(ru);

    tdb_txn_t *rc = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(tdb_txn_snapshot(rc) == 0);
    tdb_txn_free(rc);

    tdb_txn_t *rr = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL);
    ASSERT_TRUE(tdb_txn_snapshot(rr) == 3);
    ASSERT_EQ(tdb_txn_isolation(rr), TDB_ISOLATION_REPEATABLE_READ);
    tdb_txn_free(rr);

    tdb_txn_t *ser = tdb_txn_begin(clock, TDB_ISOLATION_SERIALIZABLE, NULL, 0, NULL);
    ASSERT_TRUE(tdb_txn_snapshot(ser) == 3);
    tdb_txn_free(ser);

    tidesdb_mvcc_destroy(clock);
}

/* put and delete buffer into the write set and are visible to read-your-own-writes */
void test_txn_buffer_writes(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);

    ASSERT_EQ(put(t, 0, "k", "v"), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_delete(t, 0, (const uint8_t *)"d", 1), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_single_delete(t, 0, (const uint8_t *)"s", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(tdb_txn_writeset(t)), 3);

    tidesdb_writeset_op_t o;
    ASSERT_TRUE(tidesdb_writeset_lookup(tdb_txn_writeset(t), 0, (const uint8_t *)"k", 1, &o));
    ASSERT_TRUE(o.value_size == 1 && o.value[0] == 'v');
    ASSERT_TRUE(tidesdb_writeset_lookup(tdb_txn_writeset(t), 0, (const uint8_t *)"s", 1, &o));
    ASSERT_TRUE((o.flags & TDB_WAL_ENTRY_TOMBSTONE) && (o.flags & TDB_WAL_ENTRY_SINGLE_DELETE));

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* rollback aborts the txn; a finished txn refuses further writes */
void test_txn_rollback(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);

    put(t, 0, "k", "v");
    ASSERT_EQ(tdb_txn_rollback(t), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    ASSERT_EQ(put(t, 0, "k2", "v2"), TDB_ERR_INVALID_ARGS); /* finished */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a timeout bounds an active txn: once the cached clock passes the deadline the next operation
 * expires it and it aborts; a txn with no timeout never expires */
void test_txn_expiry(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    _Atomic(int64_t) now;
    atomic_init(&now, 1000);

    /* 5-second timeout from now=1000 -> deadline 1005 */
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, &now, 5, NULL);
    ASSERT_TRUE(t != NULL);
    ASSERT_EQ(tdb_txn_expired(t), 0);
    ASSERT_EQ(put(t, 0, "a", "1"), TDB_SUCCESS); /* within the deadline */

    /* the background clock advances past the deadline */
    atomic_store(&now, 1006);
    ASSERT_EQ(tdb_txn_expired(t), 1);
    ASSERT_EQ(put(t, 0, "b", "2"), TDB_ERR_TXN_EXPIRED); /* next op expires it */
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    tdb_txn_free(t);

    /* no timeout -> never expires even far in the future */
    tdb_txn_t *u = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, &now, 0, NULL);
    atomic_store(&now, 999999999);
    ASSERT_EQ(tdb_txn_expired(u), 0);
    ASSERT_EQ(put(u, 0, "c", "3"), TDB_SUCCESS);
    tdb_txn_free(u);

    tidesdb_mvcc_destroy(clock);
}

/* the timeout can be set, extended and cleared on a live transaction, which is what the public
 * per-transaction setter is built on */
void test_txn_set_timeout(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    _Atomic(int64_t) now;
    atomic_init(&now, 1000);

    /* a transaction begun without a timeout takes one */
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, &now, 0, NULL);
    ASSERT_TRUE(t != NULL);
    atomic_store(&now, 5000);
    ASSERT_EQ(tdb_txn_expired(t), 0); /* no deadline yet */
    ASSERT_EQ(tdb_txn_set_timeout(t, 10), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_expired(t), 0); /* deadline 5010 */
    atomic_store(&now, 5011);
    ASSERT_EQ(tdb_txn_expired(t), 1);

    /* setting it again measures from the current clock, so it extends rather than accumulates */
    ASSERT_EQ(tdb_txn_set_timeout(t, 10), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_expired(t), 0); /* deadline 5021 */

    /* clearing removes the deadline entirely */
    ASSERT_EQ(tdb_txn_set_timeout(t, 0), TDB_SUCCESS);
    atomic_store(&now, 999999999);
    ASSERT_EQ(tdb_txn_expired(t), 0);
    ASSERT_EQ(put(t, 0, "a", "1"), TDB_SUCCESS);
    tdb_txn_free(t);

    /* a transaction with no clock cannot age, and says so rather than pretending to hold a timeout
     */
    tdb_txn_t *u = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(u != NULL);
    ASSERT_EQ(tdb_txn_set_timeout(u, 5), TDB_ERR_INVALID_DB);
    tdb_txn_free(u);

    /* a resolved transaction takes no timeout */
    tdb_txn_t *v = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, &now, 0, NULL);
    ASSERT_TRUE(v != NULL);
    ASSERT_EQ(tdb_txn_rollback(v), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_set_timeout(v, 5), TDB_ERR_INVALID_ARGS);
    tdb_txn_free(v);

    tidesdb_mvcc_destroy(clock);
}

/* savepoints mark write-set positions; rollback-to discards later writes and keeps the target so it
 * can be used again; release drops it */
void test_txn_savepoints(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);

    put(t, 0, "a", "1");
    ASSERT_EQ(tdb_txn_savepoint(t, "s1"), TDB_SUCCESS); /* at 1 op */
    put(t, 0, "b", "2");
    ASSERT_EQ(tdb_txn_savepoint(t, "s2"), TDB_SUCCESS); /* at 2 ops */
    put(t, 0, "c", "3");
    ASSERT_EQ(tidesdb_writeset_count(tdb_txn_writeset(t)), 3);

    /* roll back to s1: only "a" survives, and s2 (taken later) is dropped */
    ASSERT_EQ(tdb_txn_rollback_to_savepoint(t, "s1"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(tdb_txn_writeset(t)), 1);
    ASSERT_EQ(tdb_txn_rollback_to_savepoint(t, "s2"), TDB_ERR_NOT_FOUND);

    /* s1 still exists and can be rolled back to again */
    put(t, 0, "d", "4");
    ASSERT_EQ(tdb_txn_rollback_to_savepoint(t, "s1"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(tdb_txn_writeset(t)), 1);

    /* release s1, then it is gone */
    ASSERT_EQ(tdb_txn_release_savepoint(t, "s1"), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_rollback_to_savepoint(t, "s1"), TDB_ERR_NOT_FOUND);

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* re-marking an existing savepoint name moves it to the current position */
void test_txn_savepoint_remark(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);

    put(t, 0, "a", "1");
    ASSERT_EQ(tdb_txn_savepoint(t, "s"), TDB_SUCCESS); /* at 1 */
    put(t, 0, "b", "2");
    ASSERT_EQ(tdb_txn_savepoint(t, "s"), TDB_SUCCESS); /* re-mark at 2 */
    put(t, 0, "c", "3");

    ASSERT_EQ(tdb_txn_rollback_to_savepoint(t, "s"), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(tdb_txn_writeset(t)), 2); /* a and b kept */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* bad args are handled */
void test_txn_null_safe(void)
{
    ASSERT_TRUE(tdb_txn_begin(NULL, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL) == NULL);
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(tdb_txn_begin(clock, (tidesdb_isolation_level_t)99, NULL, 0, NULL) == NULL);

    ASSERT_EQ(put(NULL, 0, "k", "v"), TDB_ERR_INVALID_ARGS);
    ASSERT_TRUE(tdb_txn_snapshot(NULL) == 0);
    ASSERT_EQ(tdb_txn_isolation(NULL), TDB_ISOLATION_READ_COMMITTED);
    ASSERT_TRUE(tdb_txn_writeset(NULL) == NULL);
    tdb_txn_free(NULL);
    tidesdb_mvcc_destroy(clock);
}

/* read-your-own-writes wins over any source, and a buffered delete reads as not-found */
void test_txn_read_ryow(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);

    tsrc m = {0, 1, "k", 1, "from_source"};
    tidesdb_source_t src = tsource(&m);

    put(t, 0, "k", "mine");
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "mine")); /* own write beats the source */

    tdb_txn_delete(t, 0, (const uint8_t *)"k", 1);
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(t, 0, (const uint8_t *)"k", 1, &src, 1, &v, &vs), TDB_ERR_NOT_FOUND);

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* with no own write, the external source answers at the read snapshot */
void test_txn_read_external(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);

    tsrc m = {0, 1, "k", 1, "value"};
    tidesdb_source_t src = tsource(&m);
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "value"));

    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(t, 0, (const uint8_t *)"absent", 6, &src, 1, &v, &vs), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tdb_txn_get(t, 0, (const uint8_t *)"k", 1, NULL, 0, &v, &vs),
              TDB_ERR_NOT_FOUND); /* no sources */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a repeatable-read snapshot freezes visibility: a source version newer than the snapshot is not
 * seen, an older one is */
void test_txn_read_snapshot(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    (void)tidesdb_mvcc_next_seq(clock);
    (void)tidesdb_mvcc_next_seq(clock);
    (void)tidesdb_mvcc_next_seq(clock); /* current 4, so RR snapshot = 3 */
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL);
    ASSERT_TRUE(tdb_txn_snapshot(t) == 3);

    tsrc newer = {0, 1, "k", 10, "newer"}; /* seq 10 > snapshot 3 */
    tidesdb_source_t s_new = tsource(&newer);
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(t, 0, (const uint8_t *)"k", 1, &s_new, 1, &v, &vs), TDB_ERR_NOT_FOUND);

    tsrc older = {0, 1, "k", 2, "older"}; /* seq 2 <= 3 */
    tidesdb_source_t s_old = tsource(&older);
    ASSERT_TRUE(get_is(t, 0, "k", &s_old, 1, "older"));

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a transient source BUSY is retried internally and never surfaces to the caller */
void test_txn_read_busy_absorbed(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);

    tsrc m = {3, 1, "k", 1, "resolved"}; /* busy 3 times, then answers */
    tidesdb_source_t src = tsource(&m);
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "resolved"));
    ASSERT_EQ(m.busy_remaining, 0); /* the retries consumed the busy window */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* contains is a non-tracking existence probe */
void test_txn_contains(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "k", "v");
    ASSERT_EQ(tdb_txn_contains(t, 0, (const uint8_t *)"k", 1, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_contains(t, 0, (const uint8_t *)"x", 1, NULL, 0), TDB_ERR_NOT_FOUND);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a read on an expired txn fails like any other operation */
void test_txn_read_expired(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    _Atomic(int64_t) now;
    atomic_init(&now, 100);
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, &now, 5, NULL);
    atomic_store(&now, 200); /* past the deadline */
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(t, 0, (const uint8_t *)"k", 1, NULL, 0, &v, &vs), TDB_ERR_TXN_EXPIRED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a mock commit backend recording the calls it received and able to fail any stage */
typedef struct
{
    int bp_calls;
    int wal_calls;
    int apply_calls;
    int last_apply_count;
    int fail_bp;
    int fail_wal;
    int fail_apply;
    int last_wal_kind;
} mockbe;

static int mb_bp(void *ctx, uint32_t cf_index)
{
    (void)cf_index;
    mockbe *m = (mockbe *)ctx;
    m->bp_calls++;
    return m->fail_bp ? -1 : 0;
}
static int mb_wal(void *ctx, const uint8_t *batch, size_t size)
{
    mockbe *m = (mockbe *)ctx;
    m->wal_calls++;
    if (size >= 2) m->last_wal_kind = batch[1]; /* version byte then the record kind */
    return m->fail_wal ? -1 : 0;
}
static int mb_apply(void *ctx, const tidesdb_wal_entry_t *entries, int count)
{
    (void)entries;
    mockbe *m = (mockbe *)ctx;
    m->apply_calls++;
    m->last_apply_count = count;
    return m->fail_apply ? -1 : 0;
}
static tdb_txn_backend_t mkbackend(mockbe *m)
{
    /* named so a new backend field defaults to zero rather than silently taking a positional one */
    tdb_txn_backend_t b = {
        .backpressure = mb_bp, .wal_append = mb_wal, .apply = mb_apply, .ctx = m};
    return b;
}

/* a commit draws a seq, appends the WAL, applies the entries, and marks the seq committed; the txn
 * is then finished */
void test_txn_commit(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "a", "1");
    put(t, 0, "b", "2");
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);

    ASSERT_EQ(m.wal_calls, 1);
    ASSERT_EQ(m.apply_calls, 1);
    ASSERT_EQ(m.last_apply_count, 2);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_COMMITTED);
    ASSERT_TRUE(tdb_txn_commit_seq(t) > 0);
    ASSERT_EQ(tidesdb_mvcc_committed(clock, tdb_txn_commit_seq(t)), 1);
    ASSERT_EQ(put(t, 0, "c", "3"), TDB_ERR_INVALID_ARGS); /* finished */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a read-only commit does no durable work */
void test_txn_commit_readonly(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(m.wal_calls, 0);
    ASSERT_EQ(m.apply_calls, 0);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_COMMITTED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* only the last write of each key reaches the backend (deduplicated) */
void test_txn_commit_dedup(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "x", "1");
    put(t, 0, "x", "2"); /* supersedes the first x */
    put(t, 0, "y", "3");
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(m.last_apply_count, 2); /* x (last) and y */
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a backend WAL failure aborts the commit; the seq is never marked committed */
void test_txn_commit_wal_failure(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {.fail_wal = 1};
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "a", "1");
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_ERR_IO);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    ASSERT_EQ(m.apply_calls, 0);            /* never reached apply */
    ASSERT_EQ(tdb_txn_commit_seq(t), 0ULL); /* no commit seq recorded */
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* the dedup keeps only the last op covering each key, and it does so through a hash-backed backward
 * walk rather than by asking every pair. this checks that walk against an independent brute-force
 * oracle over randomized batches that mix repeated keys with interval deletes, since a disagreement
 * would silently drop or resurrect a write */
#define DEDUP_ORACLE_MAX_OPS 400

typedef struct
{
    uint32_t cf;
    char key[16];
    char hi[16]; /* upper bound for an interval delete, empty when open or when a point write */
    int is_range;
} oracle_op;

static int oracle_kcmp(const char *a, const char *b)
{
    const int c = strcmp(a, b);
    return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

/* the documented rule, written out independently of the implementation under test */
static int oracle_superseded_by(const oracle_op *op, const oracle_op *later)
{
    if (later->cf != op->cf) return 0;
    if (later->is_range)
    {
        if (!op->is_range)
        {
            if (oracle_kcmp(later->key, op->key) > 0) return 0;
            if (later->hi[0] == '\0') return 1;
            return oracle_kcmp(op->key, later->hi) < 0;
        }
        if (oracle_kcmp(later->key, op->key) > 0) return 0;
        if (later->hi[0] == '\0') return 1;
        if (op->hi[0] == '\0') return 0;
        return oracle_kcmp(op->hi, later->hi) <= 0;
    }
    if (op->is_range) return 0;
    return oracle_kcmp(later->key, op->key) == 0;
}

static uint32_t dedup_rng_state = 0x9E3779B9u;
static uint32_t dedup_rand(void)
{
    dedup_rng_state ^= dedup_rng_state << 13;
    dedup_rng_state ^= dedup_rng_state >> 17;
    dedup_rng_state ^= dedup_rng_state << 5;
    return dedup_rng_state;
}

void test_txn_commit_dedup_matches_brute_force(void)
{
    for (int round = 0; round < 40; round++)
    {
        tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
        mockbe m = {0};
        tdb_txn_backend_t be = mkbackend(&m);
        tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);

        const int attempts = 1 + (int)(dedup_rand() % DEDUP_ORACLE_MAX_OPS);
        oracle_op *ops = calloc((size_t)attempts, sizeof(*ops));
        ASSERT_TRUE(ops != NULL);

        /* only an op the api actually buffered belongs in the oracle -- an interval whose upper
         * bound is not above its lower is refused, and counting one would compare the dedup against
         * a write set that never held it */
        int n = 0;
        for (int i = 0; i < attempts; i++)
        {
            oracle_op cand = {0};
            /* a small key space so repeats and interval overlaps actually happen */
            cand.cf = dedup_rand() % 2;
            snprintf(cand.key, sizeof cand.key, "k%03u", dedup_rand() % 40);
            cand.is_range = (dedup_rand() % 8) == 0;

            int rc;
            if (cand.is_range)
            {
                if (dedup_rand() % 4) snprintf(cand.hi, sizeof cand.hi, "k%03u", dedup_rand() % 40);
                rc = tdb_txn_delete_range(t, cand.cf, (const uint8_t *)cand.key, strlen(cand.key),
                                          cand.hi[0] ? (const uint8_t *)cand.hi : NULL,
                                          strlen(cand.hi));
            }
            else
                rc = tdb_txn_put(t, cand.cf, (const uint8_t *)cand.key, strlen(cand.key),
                                 (const uint8_t *)"v", 1, -1);
            if (rc == TDB_SUCCESS) ops[n++] = cand;
        }

        int expected = 0;
        for (int i = 0; i < n; i++)
        {
            int sup = 0;
            for (int j = i + 1; j < n && !sup; j++) sup = oracle_superseded_by(&ops[i], &ops[j]);
            if (!sup) expected++;
        }

        ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
        ASSERT_EQ(m.last_apply_count, expected);

        free(ops);
        tdb_txn_free(t);
        tidesdb_mvcc_destroy(clock);
    }
}

/* two snapshot transactions racing the same key -- the second to commit loses first-committer-wins
 */
void test_txn_commit_write_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t1 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    tdb_txn_t *t2 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(t1, 0, "k", "one");
    put(t2, 0, "k", "two");
    ASSERT_EQ(tdb_txn_commit(t1, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t2, &be, NULL, 0), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t2), TDB_TXN_ABORTED);
    tdb_txn_free(t1);
    tdb_txn_free(t2);

    /* a snapshot begun after the first commit has read the newer version, so it does not conflict
     */
    tdb_txn_t *t3 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(t3, 0, "k", "three");
    ASSERT_EQ(tdb_txn_commit(t3, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(t3);

    tidesdb_mvcc_destroy(clock);
}

/* repeatable-read read-set validation: a key read then changed by a newer committed version aborts
 * the commit */
void test_txn_read_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    for (int i = 0; i < 6; i++) (void)tidesdb_mvcc_next_seq(clock); /* current 7 */
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    tsrc m = {0, 1, "k", 5, "vk"};
    tidesdb_source_t src = tsource(&m);

    tdb_txn_t *t =
        tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL); /* snapshot 6 */
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "vk")); /* records read of k at seq 5 */
    put(t, 0, "j", "vj");                          /* a write so commit is not read-only */

    m.seq = 10; /* a newer committed version of k appears under us */
    ASSERT_EQ(tdb_txn_commit(t, &be, &src, 1), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* the same shape but the read key does not change: the commit succeeds */
void test_txn_read_conflict_none(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    for (int i = 0; i < 6; i++) (void)tidesdb_mvcc_next_seq(clock);
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    tsrc m = {0, 1, "k", 5, "vk"};
    tidesdb_source_t src = tsource(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL);
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "vk"));
    put(t, 0, "j", "vj");
    ASSERT_EQ(tdb_txn_commit(t, &be, &src, 1), TDB_SUCCESS); /* k unchanged */
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* snapshot write-conflict scan: writing a key that already has a committed version newer than the
 * snapshot aborts, catching an already-applied writer the reservation cannot see */
void test_txn_write_scan_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    tsrc m = {0, 1, "k", 5, "existing"}; /* k already committed at seq 5 */
    tidesdb_source_t src = tsource(&m);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL); /* snapshot 0 */
    put(t, 0, "k", "new");
    ASSERT_EQ(tdb_txn_commit(t, &be, &src, 1), TDB_ERR_CONFLICT); /* seq 5 > snapshot 0 */
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* set up the doctors-on-call write-skew scenario: two txns each read d1 and d2 (both on call) and
 * each takes a different one off call. runs it at the given isolation with a shared registry and
 * reports how many of the two commits succeeded */
static int run_write_skew(tidesdb_isolation_level_t iso)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    (void)tidesdb_mvcc_next_seq(clock);
    (void)tidesdb_mvcc_next_seq(clock); /* current 3 -> snapshot 2, above the data seqs */

    tsrc md1 = {0, 1, "d1", 1, "oncall"};
    tsrc md2 = {0, 1, "d2", 1, "oncall"};
    tidesdb_source_t sources[2] = {tsource(&md1), tsource(&md2)};

    tdb_txn_t *t1 = tdb_txn_begin(clock, iso, NULL, 0, reg);
    tdb_txn_t *t2 = tdb_txn_begin(clock, iso, NULL, 0, reg);

    /* each reads both doctors, then takes a different one off call */
    get_is(t1, 0, "d1", sources, 2, "oncall");
    get_is(t1, 0, "d2", sources, 2, "oncall");
    put(t1, 0, "d1", "off");
    get_is(t2, 0, "d1", sources, 2, "oncall");
    get_is(t2, 0, "d2", sources, 2, "oncall");
    put(t2, 0, "d2", "off");

    const int rc1 = tdb_txn_commit(t1, &be, sources, 2);
    const int rc2 = tdb_txn_commit(t2, &be, sources, 2);
    const int committed = (rc1 == TDB_SUCCESS) + (rc2 == TDB_SUCCESS);

    tdb_txn_free(t1);
    tdb_txn_free(t2);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
    return committed;
}

/* serializable prevents write skew: exactly one of the pair commits */
void test_txn_ssi_write_skew(void)
{
    ASSERT_EQ(run_write_skew(TDB_ISOLATION_SERIALIZABLE), 1);
}

/* snapshot isolation permits write skew (the famous SI gap): both commit, since they write disjoint
 * keys and SI does not run the dangerous-structure check */
void test_txn_snapshot_allows_write_skew(void)
{
    ASSERT_EQ(run_write_skew(TDB_ISOLATION_SNAPSHOT), 2);
}

/* two-phase commit: prepare durably records a PREPARE without applying or committing; phase-two
 * commit records the batch inside its COMMIT, applies, and makes the seq visible */
void test_txn_2pc_commit(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint8_t xid[] = {1, 2, 3, 4};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "k", "v");
    ASSERT_EQ(tdb_txn_prepare(t, &be, NULL, 0, xid, sizeof(xid)), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_PREPARED);
    ASSERT_EQ(m.wal_calls, 1);
    ASSERT_EQ(m.last_wal_kind, TDB_WAL_KIND_PREPARE);
    ASSERT_EQ(m.apply_calls, 0); /* not applied yet */
    const uint64_t seq = tdb_txn_commit_seq(t);
    ASSERT_TRUE(seq > 0);
    ASSERT_EQ(tidesdb_mvcc_committed(clock, seq), 0); /* in-progress, invisible */

    /* phase two draws its own sequence and carries the write set in the COMMIT record, so the
     * decision and the batch are one durable record and the prepare-time sequence is left behind */
    ASSERT_EQ(tdb_txn_commit_prepared(t, &be), TDB_SUCCESS);
    ASSERT_EQ(m.wal_calls, 2);
    ASSERT_EQ(m.last_wal_kind, TDB_WAL_KIND_COMMIT);
    ASSERT_EQ(m.apply_calls, 1);
    const uint64_t decided = tdb_txn_commit_seq(t);
    ASSERT_TRUE(decided > seq);                           /* decided later than it prepared */
    ASSERT_EQ(tidesdb_mvcc_committed(clock, decided), 1); /* now committed */
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_COMMITTED);

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* phase-two rollback records ROLLBACK, applies nothing, and leaves the seq uncommitted */
void test_txn_2pc_rollback(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint8_t xid[] = {9, 8, 7};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "k", "v");
    ASSERT_EQ(tdb_txn_prepare(t, &be, NULL, 0, xid, sizeof(xid)), TDB_SUCCESS);
    const uint64_t seq = tdb_txn_commit_seq(t);

    ASSERT_EQ(tdb_txn_rollback_prepared(t, &be), TDB_SUCCESS);
    ASSERT_EQ(m.wal_calls, 2);
    ASSERT_EQ(m.last_wal_kind, TDB_WAL_KIND_ROLLBACK);
    ASSERT_EQ(m.apply_calls, 0);
    ASSERT_EQ(tidesdb_mvcc_committed(clock, seq), 0);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a read-only prepare votes read-only and finishes with no durable work or phase two */
void test_txn_2pc_readonly(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint8_t xid[] = {1};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_prepare(t, &be, NULL, 0, xid, sizeof(xid)), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_COMMITTED);
    ASSERT_EQ(m.wal_calls, 0);
    ASSERT_EQ(m.apply_calls, 0);

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a prepared txn refuses ordinary operations, plain rollback, and single-phase commit */
void test_txn_2pc_prepared_is_frozen(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint8_t xid[] = {5};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t, 0, "k", "v");
    ASSERT_EQ(tdb_txn_prepare(t, &be, NULL, 0, xid, sizeof(xid)), TDB_SUCCESS);

    ASSERT_EQ(put(t, 0, "k2", "v2"), TDB_ERR_INVALID_ARGS); /* no more writes */
    ASSERT_EQ(tdb_txn_rollback(t), TDB_ERR_INVALID_ARGS);   /* must use rollback-prepared */
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_ERR_INVALID_ARGS); /* not single-phase */

    ASSERT_EQ(tdb_txn_rollback_prepared(t, &be), TDB_SUCCESS); /* resolve it cleanly */
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a conflict is detected at prepare, before the PREPARE record is written */
void test_txn_2pc_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    tsrc src_m = {0, 1, "k", 5, "existing"};
    tidesdb_source_t src = tsource(&src_m);
    const uint8_t xid[] = {1, 1};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL); /* snapshot 0 */
    put(t, 0, "k", "new");
    ASSERT_EQ(tdb_txn_prepare(t, &be, &src, 1, xid, sizeof(xid)), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    ASSERT_EQ(m.wal_calls, 0); /* aborted before any durable record */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_txn_begin_snapshot, tests_passed);
    RUN_TEST(test_txn_2pc_commit, tests_passed);
    RUN_TEST(test_txn_2pc_rollback, tests_passed);
    RUN_TEST(test_txn_2pc_readonly, tests_passed);
    RUN_TEST(test_txn_2pc_prepared_is_frozen, tests_passed);
    RUN_TEST(test_txn_2pc_conflict, tests_passed);
    RUN_TEST(test_txn_ssi_write_skew, tests_passed);
    RUN_TEST(test_txn_snapshot_allows_write_skew, tests_passed);
    RUN_TEST(test_txn_read_conflict, tests_passed);
    RUN_TEST(test_txn_read_conflict_none, tests_passed);
    RUN_TEST(test_txn_write_scan_conflict, tests_passed);
    RUN_TEST(test_txn_commit, tests_passed);
    RUN_TEST(test_txn_commit_readonly, tests_passed);
    RUN_TEST(test_txn_commit_dedup, tests_passed);
    RUN_TEST(test_txn_commit_wal_failure, tests_passed);
    RUN_TEST(test_txn_commit_dedup_matches_brute_force, tests_passed);
    RUN_TEST(test_txn_commit_write_conflict, tests_passed);
    RUN_TEST(test_txn_read_ryow, tests_passed);
    RUN_TEST(test_txn_read_external, tests_passed);
    RUN_TEST(test_txn_read_snapshot, tests_passed);
    RUN_TEST(test_txn_read_busy_absorbed, tests_passed);
    RUN_TEST(test_txn_contains, tests_passed);
    RUN_TEST(test_txn_read_expired, tests_passed);
    RUN_TEST(test_txn_buffer_writes, tests_passed);
    RUN_TEST(test_txn_rollback, tests_passed);
    RUN_TEST(test_txn_expiry, tests_passed);
    RUN_TEST(test_txn_set_timeout, tests_passed);
    RUN_TEST(test_txn_savepoints, tests_passed);
    RUN_TEST(test_txn_savepoint_remark, tests_passed);
    RUN_TEST(test_txn_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
