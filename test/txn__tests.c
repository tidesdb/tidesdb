/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/base/keycmp.h"
#include "../src/txn/registry.h"
#include "../src/txn/txn.h"
#include "../src/txn/txn_internal.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static int put(tdb_txn_t *t, uint32_t cf, const char *k, const char *v)
{
    return tdb_txn_put(t, cf, (const uint8_t *)k, strlen(k), (const uint8_t *)v, strlen(v), -1);
}

/* draw and commit n sequences, so the watermark, and with it every snapshot taken afterwards,
 * stands at n */
static void advance_clock(tidesdb_mvcc_t *clock, int n)
{
    for (int i = 0; i < n; i++) tidesdb_mvcc_mark(clock, tidesdb_mvcc_draw(clock, NULL), 1);
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

/* whether the one key the source holds falls inside [lo, hi) above the floor, which is what a
 * commit asks about an interval it scanned or deletes */
static tidesdb_source_result_t tsrc_range_has_newer(void *ctx, uint32_t cf_index, const uint8_t *lo,
                                                    size_t lo_size, const uint8_t *hi,
                                                    size_t hi_size, uint64_t seq_floor,
                                                    uint64_t seq_ceiling, int *newer)
{
    (void)cf_index;
    tsrc *m = (tsrc *)ctx;
    *newer = 0;
    if (!m->has) return TDB_SOURCE_NOT_FOUND;
    const uint8_t *key = (const uint8_t *)m->key;
    const size_t key_size = strlen(m->key);
    if (tdb_key_cmp(lo, lo_size, key, key_size) > 0) return TDB_SOURCE_NOT_FOUND;
    if (hi_size > 0 && tdb_key_cmp(key, key_size, hi, hi_size) >= 0) return TDB_SOURCE_NOT_FOUND;
    *newer = m->seq > seq_floor && m->seq <= seq_ceiling;
    return TDB_SOURCE_FOUND;
}

static tidesdb_source_t tsource(tsrc *m)
{
    tidesdb_source_t s = {.name = "mock",
                          .get = tsrc_get,
                          .has_newer = NULL,
                          .range_has_newer = tsrc_range_has_newer,
                          .ctx = m};
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
 * per read (0 at begin), and repeatable-read and stronger freeze the watermark */
void test_txn_begin_snapshot(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(clock != NULL);
    advance_clock(clock, 3); /* current_seq now 4, watermark 3 */

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
    advance_clock(clock, 1); /* the version at sequence 1 is decided, so it is readable */
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
    advance_clock(clock, 3); /* watermark 3, so RR snapshot = 3 */
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
    advance_clock(clock, 1);
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

/* how many sources a mock backend's apply lands entries in */
#define MB_MAX_APPLIED 2

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
    uint32_t paced_families[8];
    int fail_bp_call;
    tsrc *applied[MB_MAX_APPLIED]; /* stand in for the memtable: an applied entry lands in the
                                    * source holding its key, at the entry's sequence */
    int n_applied;
    tidesdb_mvcc_t
        *peer_clock; /* when set, the apply begins a snapshot transaction on this clock */
    tdb_txn_t *peer; /* the transaction the apply began, for the test to read through */
} mockbe;

static int mb_bp(void *ctx, uint32_t cf_index)
{
    mockbe *m = (mockbe *)ctx;
    if (m->bp_calls < (int)(sizeof(m->paced_families) / sizeof(m->paced_families[0])))
        m->paced_families[m->bp_calls] = cf_index;
    m->bp_calls++;
    return m->fail_bp || m->bp_calls == m->fail_bp_call ? -1 : 0;
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
    mockbe *m = (mockbe *)ctx;
    m->apply_calls++;
    m->last_apply_count = count;
    /* the version becomes readable at its sequence the moment it is applied, as in the memtable,
     * and a peer begun now stands exactly where a reader racing the apply would */
    for (int i = 0; i < count; i++)
        for (int s = 0; s < m->n_applied; s++)
        {
            tsrc *src = m->applied[s];
            if (entries[i].key_size != strlen(src->key) ||
                memcmp(entries[i].key, src->key, entries[i].key_size) != 0)
                continue;
            src->has = 1;
            src->seq = entries[i].seq;
        }
    if (m->peer_clock && !m->peer)
        m->peer = tdb_txn_begin(m->peer_clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    return m->fail_apply ? -1 : 0;
}
static tdb_txn_backend_t mkbackend(mockbe *m)
{
    /* named so a new backend field defaults to zero rather than silently taking a positional one */
    tdb_txn_backend_t b = {
        .backpressure = mb_bp, .wal_append = mb_wal, .apply = mb_apply, .ctx = m};
    return b;
}

/* a transaction that begins while another commit is applying sees nothing of that commit. its
 * snapshot is the watermark, below the sequence in flight, so neither the entries already applied
 * nor the ones still to come are inside it, and the commit is visible whole once it has marked */
void test_txn_begun_during_an_apply_sees_nothing_of_it(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tsrc applied = {0, 0, "k", 0, "v"};
    tidesdb_source_t src = tsource(&applied);
    mockbe be_m = {0};
    be_m.applied[0] = &applied;
    be_m.n_applied = 1;
    be_m.peer_clock = clock;
    tdb_txn_backend_t be = mkbackend(&be_m);

    tdb_txn_t *c = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(c, 0, "k", "v");
    ASSERT_EQ(tdb_txn_commit(c, &be, &src, 1), TDB_SUCCESS);
    const uint64_t seq = tdb_txn_commit_seq(c);

    tdb_txn_t *peer = be_m.peer;
    ASSERT_TRUE(peer != NULL);
    ASSERT_TRUE(tdb_txn_snapshot(peer) < seq);
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(peer, 0, (const uint8_t *)"k", 1, &src, 1, &v, &vs), TDB_ERR_NOT_FOUND);

    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) == seq);
    tdb_txn_t *after = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    ASSERT_TRUE(get_is(after, 0, "k", &src, 1, "v"));

    tdb_txn_free(after);
    tdb_txn_free(peer);
    tdb_txn_free(c);
    tidesdb_mvcc_destroy(clock);
}

/* a commit that fails after drawing its sequence still decides it, so the watermark passes it and
 * the next commit is visible the moment it marks */
void test_txn_failed_commit_leaves_the_watermark_advancing(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe be_m = {0};
    be_m.fail_wal = 1;
    tdb_txn_backend_t be = mkbackend(&be_m);

    tdb_txn_t *failed = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(failed, 0, "k", "v");
    ASSERT_EQ(tdb_txn_commit(failed, &be, NULL, 0), TDB_ERR_IO);
    ASSERT_EQ(tdb_txn_state(failed), TDB_TXN_ABORTED);

    be_m.fail_wal = 0;
    tdb_txn_t *next = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(next, 0, "k", "v");
    ASSERT_EQ(tdb_txn_commit(next, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_TRUE(tdb_txn_commit_seq(next) == 2); /* the failed commit spent sequence 1 */
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) == 2);

    tdb_txn_free(failed);
    tdb_txn_free(next);
    tidesdb_mvcc_destroy(clock);
}

/* a prepare's sequence never carries a version, so it does not hold the watermark down for the
 * in-doubt window; the commits around it become visible as they mark, and phase two's own
 * sequence is what the batch finally appears at */
void test_txn_prepared_sequence_does_not_hold_the_watermark(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    const uint8_t xid[] = {9, 9};

    tdb_txn_t *p = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(p, 0, "k", "v");
    ASSERT_EQ(tdb_txn_prepare(p, &be, NULL, 0, xid, sizeof(xid)), TDB_SUCCESS);
    const uint64_t prepared = tdb_txn_commit_seq(p);

    tdb_txn_t *other = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(other, 0, "j", "w");
    ASSERT_EQ(tdb_txn_commit(other, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_TRUE(tdb_txn_commit_seq(other) > prepared);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) == tdb_txn_commit_seq(other));

    ASSERT_EQ(tdb_txn_commit_prepared(p, &be), TDB_SUCCESS);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) == tdb_txn_commit_seq(p));

    tdb_txn_free(other);
    tdb_txn_free(p);
    tidesdb_mvcc_destroy(clock);
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
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) >= tdb_txn_commit_seq(t)); /* published */
    ASSERT_EQ(put(t, 0, "c", "3"), TDB_ERR_INVALID_ARGS);                  /* finished */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* repeated families, colliding ids and the id boundaries are paced once, in first-seen order */
void test_txn_commit_paces_first_seen_families(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint32_t families[] = {0, UINT32_MAX, 0, 64, UINT32_MAX, 128, 64};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    for (int i = 0; i < (int)(sizeof(families) / sizeof(families[0])); i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%d", i);
        ASSERT_EQ(put(t, families[i], key, "v"), TDB_SUCCESS);
    }
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(m.bp_calls, 4);
    ASSERT_EQ(m.paced_families[0], 0U);
    ASSERT_EQ(m.paced_families[1], UINT32_MAX);
    ASSERT_EQ(m.paced_families[2], 64U);
    ASSERT_EQ(m.paced_families[3], 128U);
    ASSERT_EQ(m.wal_calls, 1);
    ASSERT_EQ(m.apply_calls, 1);
    ASSERT_EQ(m.last_apply_count, 7);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_COMMITTED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* grouped writes make the preceding-entry scan expensive even with only a few distinct families
 */
void test_txn_commit_paces_large_grouped_families(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint32_t families[] = {0, UINT32_MAX, 64, 128};

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    for (int i = 0; i < 512; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%d", i);
        ASSERT_EQ(put(t, families[i / 128], key, "v"), TDB_SUCCESS);
    }
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(m.bp_calls, 4);
    for (int i = 0; i < 4; i++) ASSERT_EQ(m.paced_families[i], families[i]);
    ASSERT_EQ(m.wal_calls, 1);
    ASSERT_EQ(m.apply_calls, 1);
    ASSERT_EQ(m.last_apply_count, 512);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a refused family stops pacing immediately, before either the wal append or the apply */
void test_txn_commit_backpressure_failure(void)
{
    for (int fail_call = 1; fail_call <= 2; fail_call++)
    {
        tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
        mockbe m = {.fail_bp_call = fail_call};
        tdb_txn_backend_t be = mkbackend(&m);
        tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
        ASSERT_EQ(put(t, 0, "a", "1"), TDB_SUCCESS);
        ASSERT_EQ(put(t, 0, "b", "2"), TDB_SUCCESS);
        ASSERT_EQ(put(t, UINT32_MAX, "c", "3"), TDB_SUCCESS);
        ASSERT_EQ(put(t, 64, "d", "4"), TDB_SUCCESS);
        ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_ERR_IO);
        ASSERT_EQ(m.bp_calls, fail_call);
        ASSERT_EQ(m.paced_families[0], 0U);
        if (fail_call == 2) ASSERT_EQ(m.paced_families[1], UINT32_MAX);
        ASSERT_EQ(m.wal_calls, 0);
        ASSERT_EQ(m.apply_calls, 0);
        ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
        ASSERT_EQ(tdb_txn_commit_seq(t), 0ULL);
        tdb_txn_free(t);
        tidesdb_mvcc_destroy(clock);
    }
}

/* an absent pacing hook still allows the same multi-family commit */
void test_txn_commit_without_backpressure(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    be.backpressure = NULL;
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(put(t, 0, "a", "1"), TDB_SUCCESS);
    ASSERT_EQ(put(t, UINT32_MAX, "b", "2"), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    ASSERT_EQ(m.bp_calls, 0);
    ASSERT_EQ(m.wal_calls, 1);
    ASSERT_EQ(m.apply_calls, 1);
    ASSERT_EQ(m.last_apply_count, 2);
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

/* two snapshot transactions racing the same key -- the second to commit loses first-committer-wins.
 * the first commit has left the claim set by the time the second validates, so what refuses the
 * second is the version the first landed in the store, above the second's snapshot */
void test_txn_commit_write_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tsrc applied = {0, 0, "k", 0, "v"};
    tidesdb_source_t src = tsource(&applied);
    mockbe m = {0};
    m.applied[0] = &applied;
    m.n_applied = 1;
    tdb_txn_backend_t be = mkbackend(&m);

    tdb_txn_t *t1 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    tdb_txn_t *t2 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(t1, 0, "k", "one");
    put(t2, 0, "k", "two");
    ASSERT_EQ(tdb_txn_commit(t1, &be, &src, 1), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t2, &be, &src, 1), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t2), TDB_TXN_ABORTED);
    tdb_txn_free(t1);
    tdb_txn_free(t2);

    /* a snapshot begun after the first commit has read the newer version, so it does not conflict
     */
    tdb_txn_t *t3 = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(t3, 0, "k", "three");
    ASSERT_EQ(tdb_txn_commit(t3, &be, &src, 1), TDB_SUCCESS);
    tdb_txn_free(t3);

    tidesdb_mvcc_destroy(clock);
}

/* repeatable-read read-set validation: a key read then changed by a newer committed version aborts
 * the commit */
void test_txn_read_conflict(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    advance_clock(clock, 6); /* watermark 6 */
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    tsrc m = {0, 1, "k", 5, "vk"};
    tidesdb_source_t src = tsource(&m);

    tdb_txn_t *t =
        tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL); /* snapshot 6 */
    ASSERT_TRUE(get_is(t, 0, "k", &src, 1, "vk")); /* records read of k at seq 5 */
    put(t, 0, "j", "vj");                          /* a write so commit is not read-only */

    advance_clock(clock, 4); /* a newer version of k commits under us, at 10, decided */
    m.seq = 10;
    ASSERT_EQ(tdb_txn_commit(t, &be, &src, 1), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* the same shape but the read key does not change: the commit succeeds */
void test_txn_read_conflict_none(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    advance_clock(clock, 6);
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
    advance_clock(clock, 5); /* the version at 5 committed after the snapshot, below the commit */
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
    advance_clock(clock, 2); /* watermark 2, above the data seqs */

    tsrc md1 = {0, 1, "d1", 1, "oncall"};
    tsrc md2 = {0, 1, "d2", 1, "oncall"};
    tidesdb_source_t sources[2] = {tsource(&md1), tsource(&md2)};
    /* the first commit's write lands in the store, where the second one's validation finds it */
    be_m.applied[0] = &md1;
    be_m.applied[1] = &md2;
    be_m.n_applied = 2;

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
void test_txn_serializable_prevents_write_skew(void)
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
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) >= seq); /* spent, so the watermark passes it */

    /* phase two draws its own sequence and carries the write set in the COMMIT record, so the
     * decision and the batch are one durable record and the prepare-time sequence is left behind */
    ASSERT_EQ(tdb_txn_commit_prepared(t, &be), TDB_SUCCESS);
    ASSERT_EQ(m.wal_calls, 2);
    ASSERT_EQ(m.last_wal_kind, TDB_WAL_KIND_COMMIT);
    ASSERT_EQ(m.apply_calls, 1);
    const uint64_t decided = tdb_txn_commit_seq(t);
    ASSERT_TRUE(decided > seq);                              /* decided later than it prepared */
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) >= decided); /* now committed and published */
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
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(clock) >= seq); /* spent, nothing carries it */
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
    advance_clock(clock, 5); /* the version at 5 committed after the snapshot, below the prepare */
    put(t, 0, "k", "new");
    ASSERT_EQ(tdb_txn_prepare(t, &be, &src, 1, xid, sizeof(xid)), TDB_ERR_CONFLICT);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    ASSERT_EQ(m.wal_calls, 0); /* aborted before any durable record */

    tdb_txn_free(t);
    tidesdb_mvcc_destroy(clock);
}

/* a scan's footprint is validated like a read. the transaction covered [a, z) and found nothing;
 * a commit then puts m inside it, above the snapshot, and the first transaction commits a write of
 * its own. reports what that commit returned */
static int run_phantom(tidesdb_isolation_level_t iso)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tsrc inserted = {0, 0, "m", 0, "v"};
    tidesdb_source_t src = tsource(&inserted);
    mockbe be_m = {0};
    be_m.applied[0] = &inserted;
    be_m.n_applied = 1;
    tdb_txn_backend_t be = mkbackend(&be_m);
    advance_clock(clock, 1);

    tdb_txn_t *t1 = tdb_txn_begin(clock, iso, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_record_scan(t1, 0, (const uint8_t *)"a", 1, (const uint8_t *)"z", 1),
              TDB_SUCCESS);
    put(t1, 0, "marker", "x");

    tdb_txn_t *t2 = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    put(t2, 0, "m", "v");
    ASSERT_EQ(tdb_txn_commit(t2, &be, &src, 1), TDB_SUCCESS);

    const int rc = tdb_txn_commit(t1, &be, &src, 1);
    tdb_txn_free(t1);
    tdb_txn_free(t2);
    tidesdb_mvcc_destroy(clock);
    return rc;
}

/* a key another commit put inside a scanned interval, above the snapshot, is a phantom: the levels
 * that validate their reads refuse the commit */
void test_txn_scan_footprint_refuses_a_phantom(void)
{
    ASSERT_EQ(run_phantom(TDB_ISOLATION_REPEATABLE_READ), TDB_ERR_CONFLICT);
    ASSERT_EQ(run_phantom(TDB_ISOLATION_SERIALIZABLE), TDB_ERR_CONFLICT);
}

/* snapshot isolation validates no read, so it keeps no footprint and commits over the phantom */
void test_txn_snapshot_commits_over_a_phantom(void)
{
    ASSERT_EQ(run_phantom(TDB_ISOLATION_SNAPSHOT), TDB_SUCCESS);
}

/* a batch adopted in doubt after a restart holds what it read as well as what it wrote, from the
 * read keys recovery staged beside its entries: a writer of a read key is refused until the
 * coordinator decides, a writer of an unrelated key is not, and the decision lets the refused one
 * through */
void test_txn_adopted_prepare_holds_its_reads(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe m = {0};
    tdb_txn_backend_t be = mkbackend(&m);
    const uint8_t xid[] = {4, 2};
    const uint64_t prepared_at = 7;
    tidesdb_mvcc_reseed(clock, prepared_at);
    const tidesdb_wal_entry_t wrote = {.cf_index = 0,
                                       .seq = prepared_at,
                                       .ttl = -1,
                                       .key = (const uint8_t *)"y",
                                       .key_size = 1,
                                       .value = (const uint8_t *)"p",
                                       .value_size = 1};
    const tidesdb_wal_entry_t read = {
        .cf_index = 0, .seq = prepared_at, .ttl = -1, .key = (const uint8_t *)"x", .key_size = 1};

    tdb_txn_t *p =
        tdb_txn_adopt_prepared(clock, xid, sizeof(xid), &wrote, 1, prepared_at, &read, 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(tdb_txn_state(p), TDB_TXN_PREPARED);

    tdb_txn_t *w = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(w, 0, "x", "w");
    ASSERT_EQ(tdb_txn_commit(w, &be, NULL, 0), TDB_ERR_CONFLICT);
    tdb_txn_free(w);

    tdb_txn_t *elsewhere = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(elsewhere, 0, "z", "w");
    ASSERT_EQ(tdb_txn_commit(elsewhere, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(elsewhere);

    ASSERT_EQ(tdb_txn_commit_prepared(p, &be), TDB_SUCCESS);
    tdb_txn_free(p);
    w = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(w, 0, "x", "w");
    ASSERT_EQ(tdb_txn_commit(w, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(w);
    tidesdb_mvcc_destroy(clock);
}

/**
 * skew_src_t
 * the source of key x for the interleaved write-skew test. the first time a validation asks it
 * about x it commits the peer transaction, which read y and writes x, on a thread of its own before
 * answering -- so the peer lands exactly between the asking commit's probe and its decision
 * @param base the version of x the source holds
 * @param peer the transaction to commit from inside the probe, or NULL
 * @param be the backend the peer commits through
 * @param sources the source stack the peer validates against
 * @param nsources how many
 * @param fired set once the peer has been committed
 * @param peer_rc what the peer's commit returned
 */
typedef struct
{
    tsrc base;
    tdb_txn_t *peer;
    const tdb_txn_backend_t *be;
    const tidesdb_source_t *sources;
    int nsources;
    int fired;
    int peer_rc;
} skew_src_t;

/* commit the peer on a thread of its own, as a rival committer would be; the asking commit holds
 * the gate shared while it validates, and so does this one, so neither waits on the other */
static void *skew_commit_peer(void *arg)
{
    skew_src_t *s = (skew_src_t *)arg;
    s->peer_rc = tdb_txn_commit(s->peer, s->be, s->sources, s->nsources);
    return NULL;
}

static tidesdb_source_result_t skew_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                        size_t key_size, uint64_t snapshot,
                                        tidesdb_source_version_t *out)
{
    skew_src_t *s = (skew_src_t *)ctx;
    if (!s->fired && s->peer && key_size == 1 && key[0] == 'x')
    {
        s->fired = 1;
        pthread_t peer;
        if (pthread_create(&peer, NULL, skew_commit_peer, s) == 0) pthread_join(peer, NULL);
    }
    return tsrc_get(&s->base, cf_index, key, key_size, snapshot, out);
}

/* the doctors-on-call pair with the peer's whole commit landing inside the other's validation of
 * the key it read. run at the given isolation, reporting how many of the two committed */
static int run_write_skew_inside_probe(tidesdb_isolation_level_t iso)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);
    advance_clock(clock, 2); /* watermark 2, above the data at 1 */

    skew_src_t sx = {.base = {0, 1, "x", 1, "oncall"}};
    tsrc sy = {0, 1, "y", 1, "oncall"};
    tidesdb_source_t sources[2] = {{.name = "skew", .get = skew_get, .has_newer = NULL, .ctx = &sx},
                                   tsource(&sy)};

    tdb_txn_t *t1 = tdb_txn_begin(clock, iso, NULL, 0, NULL);
    tdb_txn_t *t2 = tdb_txn_begin(clock, iso, NULL, 0, NULL);
    get_is(t1, 0, "x", sources, 2, "oncall");
    put(t1, 0, "y", "off");
    get_is(t2, 0, "y", sources, 2, "oncall");
    put(t2, 0, "x", "off");

    sx.peer = t2;
    sx.be = &be;
    sx.sources = sources;
    sx.nsources = 2;
    const int rc1 = tdb_txn_commit(t1, &be, sources, 2);
    /* a level that validates no reads never asks the source about x, so the peer commits after --
     * disarmed first, since its own write validation asks about x and must not commit it again
     * from inside itself */
    if (!sx.fired)
    {
        sx.peer = NULL;
        sx.peer_rc = tdb_txn_commit(t2, &be, sources, 2);
    }
    const int committed = (rc1 == TDB_SUCCESS) + (sx.peer_rc == TDB_SUCCESS);

    tdb_txn_free(t1);
    tdb_txn_free(t2);
    tidesdb_mvcc_destroy(clock);
    return committed;
}

/* a write-skew pair whose second commit lands inside the first's validation still yields exactly
 * one commit at serializable and at repeatable read: the second finds the first's write claim below
 * its own sequence on the key it read. the probe alone would have cleared both, since the second
 * had not committed when the first looked */
/* a writer that drew its sequence after this commit's and applied before this commit validated is
 * ordered after it, so neither the read this commit validates nor the key it writes under
 * first-committer-wins is stale against that writer. validating against every version there is,
 * rather than the ones sequenced below the commit, refused both */
void test_txn_validation_ignores_a_writer_sequenced_above_the_commit(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    advance_clock(clock, 3); /* k@2 is decided and visible */
    tsrc m = {0, 1, "k", 2, "old"};
    tidesdb_source_t src = tsource(&m);
    mockbe be_m = {0};
    tdb_txn_backend_t be = mkbackend(&be_m);

    /* repeatable read validates the version it read */
    tdb_txn_t *rr = tdb_txn_begin(clock, TDB_ISOLATION_REPEATABLE_READ, NULL, 0, NULL);
    ASSERT_TRUE(get_is(rr, 0, "k", &src, 1, "old"));
    put(rr, 0, "other", "x");
    /* the next sequence is the one this commit draws; a writer one above it has already applied */
    m.seq = tidesdb_mvcc_current_seq(clock) + 1;
    m.value = "later";
    ASSERT_EQ(tdb_txn_commit(rr, &be, &src, 1), TDB_SUCCESS);
    tdb_txn_free(rr);

    /* snapshot validates the key it writes, first committer wins */
    m.seq = 2;
    m.value = "old";
    tdb_txn_t *si = tdb_txn_begin(clock, TDB_ISOLATION_SNAPSHOT, NULL, 0, NULL);
    put(si, 0, "k", "mine");
    m.seq = tidesdb_mvcc_current_seq(clock) + 1;
    m.value = "later";
    ASSERT_EQ(tdb_txn_commit(si, &be, &src, 1), TDB_SUCCESS);
    tdb_txn_free(si);

    tidesdb_mvcc_destroy(clock);
}

/**
 * floor_probe
 * a source that takes the reclamation floor from inside a read, standing where a flush or a merge
 * beginning while the read is in flight would
 * @param reg the registry the floor is taken from
 * @param ceiling_seen the ceiling the read arrived with
 * @param floor_seen the floor taken during it
 */
typedef struct
{
    tidesdb_txn_registry_t *reg;
    tidesdb_mvcc_t *clock;
    uint64_t ceiling_seen;
    uint64_t floor_seen;
} floor_probe;

static tidesdb_source_result_t floor_probe_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                               size_t key_size, uint64_t snapshot,
                                               tidesdb_source_version_t *out)
{
    (void)cf_index;
    (void)key;
    (void)key_size;
    (void)out;
    floor_probe *p = (floor_probe *)ctx;
    p->ceiling_seen = snapshot;
    p->floor_seen = tidesdb_txn_registry_take_floor(p->reg, tidesdb_mvcc_visible_seq(p->clock));
    return TDB_SOURCE_NOT_FOUND;
}

/* a read committed read takes its ceiling from the watermark and then reads the store, and a flush
 * or a merge that takes the reclamation floor meanwhile must not rise above that ceiling -- it
 * would keep one version per key and drop the ones this read still resolves to. the ceiling is held
 * only for the read; between reads the transaction pins nothing */
void test_txn_read_committed_read_holds_the_floor(void)
{
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    tidesdb_txn_registry_t *reg = tidesdb_txn_registry_create();
    advance_clock(clock, 5); /* the watermark, and so the read's ceiling, stands at 5 */

    tdb_txn_t *rc = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, reg);
    floor_probe p = {reg, clock, 0, 0};
    tidesdb_source_t src = {.name = "probe",
                            .get = floor_probe_get,
                            .has_newer = NULL,
                            .range_has_newer = NULL,
                            .ctx = &p};
    uint8_t *v = NULL;
    size_t vs = 0;
    ASSERT_EQ(tdb_txn_get(rc, 0, (const uint8_t *)"k", 1, &src, 1, &v, &vs), TDB_ERR_NOT_FOUND);
    ASSERT_EQ((int)p.ceiling_seen, 5);
    ASSERT_TRUE(p.floor_seen <= p.ceiling_seen);
    ASSERT_EQ((int)tidesdb_txn_registry_floor_high_water(reg), 5);

    /* between reads the transaction pins nothing, so the floor is the watermark itself, and a
     * committed sequence moves it */
    advance_clock(clock, 2);
    ASSERT_EQ((int)tidesdb_txn_registry_take_floor(reg, tidesdb_mvcc_visible_seq(clock)), 7);
    ASSERT_TRUE(tidesdb_txn_registry_min_snapshot(reg) == UINT64_MAX); /* no frozen snapshot */

    /* a scan holds its ceiling until it is freed, and a point read inside it does not lift it */
    uint64_t scan = 0, point = 0;
    ASSERT_EQ(tdb_txn_read_hold(rc, &scan), 0);
    ASSERT_EQ((int)scan, 7);
    advance_clock(clock, 3);
    ASSERT_EQ(tdb_txn_read_hold(rc, &point), 0);
    ASSERT_EQ((int)point, 10);
    tdb_txn_read_release(rc);
    ASSERT_EQ((int)tidesdb_txn_registry_take_floor(reg, tidesdb_mvcc_visible_seq(clock)), 7);
    tdb_txn_read_release(rc);
    ASSERT_EQ((int)tidesdb_txn_registry_take_floor(reg, tidesdb_mvcc_visible_seq(clock)), 10);

    tdb_txn_free(rc);
    tidesdb_txn_registry_destroy(reg);
    tidesdb_mvcc_destroy(clock);
}

void test_txn_write_skew_inside_the_probe_yields_one(void)
{
    ASSERT_EQ(run_write_skew_inside_probe(TDB_ISOLATION_SERIALIZABLE), 1);
    ASSERT_EQ(run_write_skew_inside_probe(TDB_ISOLATION_REPEATABLE_READ), 1);
}

/* snapshot isolation validates no reads, so the same pair commits twice -- the write skew the level
 * is defined to allow */
void test_txn_snapshot_allows_write_skew_inside_the_probe(void)
{
    ASSERT_EQ(run_write_skew_inside_probe(TDB_ISOLATION_SNAPSHOT), 2);
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
    RUN_TEST(test_txn_adopted_prepare_holds_its_reads, tests_passed);
    RUN_TEST(test_txn_scan_footprint_refuses_a_phantom, tests_passed);
    RUN_TEST(test_txn_snapshot_commits_over_a_phantom, tests_passed);
    RUN_TEST(test_txn_serializable_prevents_write_skew, tests_passed);
    RUN_TEST(test_txn_snapshot_allows_write_skew, tests_passed);
    RUN_TEST(test_txn_read_conflict, tests_passed);
    RUN_TEST(test_txn_read_conflict_none, tests_passed);
    RUN_TEST(test_txn_write_scan_conflict, tests_passed);
    RUN_TEST(test_txn_commit, tests_passed);
    RUN_TEST(test_txn_begun_during_an_apply_sees_nothing_of_it, tests_passed);
    RUN_TEST(test_txn_failed_commit_leaves_the_watermark_advancing, tests_passed);
    RUN_TEST(test_txn_prepared_sequence_does_not_hold_the_watermark, tests_passed);
    RUN_TEST(test_txn_commit_paces_first_seen_families, tests_passed);
    RUN_TEST(test_txn_commit_paces_large_grouped_families, tests_passed);
    RUN_TEST(test_txn_commit_backpressure_failure, tests_passed);
    RUN_TEST(test_txn_commit_without_backpressure, tests_passed);
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
    RUN_TEST(test_txn_write_skew_inside_the_probe_yields_one, tests_passed);
    RUN_TEST(test_txn_snapshot_allows_write_skew_inside_the_probe, tests_passed);
    RUN_TEST(test_txn_validation_ignores_a_writer_sequenced_above_the_commit, tests_passed);
    RUN_TEST(test_txn_read_committed_read_holds_the_floor, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
