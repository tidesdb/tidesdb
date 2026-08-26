/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "../src/txn/wal_record.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static tidesdb_wal_entry_t mk(uint32_t cf, uint64_t seq, int64_t ttl, uint8_t flags,
                              const char *key, const char *value)
{
    tidesdb_wal_entry_t e;
    e.cf_index = cf;
    e.seq = seq;
    e.ttl = ttl;
    e.flags = flags;
    e.key = (const uint8_t *)key;
    e.key_size = strlen(key);
    e.value = value ? (const uint8_t *)value : NULL;
    e.value_size = value ? strlen(value) : 0;
    e.vlog_id = 0;
    return e;
}

static int entry_key_is(const tidesdb_wal_entry_t *e, const char *s)
{
    return e->key_size == strlen(s) && memcmp(e->key, s, e->key_size) == 0;
}
static int entry_val_is(const tidesdb_wal_entry_t *e, const char *s)
{
    return e->value_size == strlen(s) && memcmp(e->value, s, e->value_size) == 0;
}

/* a batch of mixed entries (a put, a ttl put in another cf, a single-delete tombstone) round-trips
 * exactly through encode then cursor decode, and the reported size matches the bytes written */
void test_wal_roundtrip(void)
{
    tidesdb_wal_entry_t in[3];
    in[0] = mk(0, 1, -1, 0, "alpha", "one");
    in[1] = mk(1, 2, 12345, TDB_WAL_ENTRY_HAS_TTL, "beta", "two");
    in[2] = mk(0, 3, -1, TDB_WAL_ENTRY_TOMBSTONE | TDB_WAL_ENTRY_SINGLE_DELETE, "gamma", NULL);

    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 3);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    const size_t wrote =
        tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 3, buf, need);
    ASSERT_TRUE(wrote == need);

    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, wrote), 0);

    tidesdb_wal_entry_t e;
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(e.cf_index == 0 && e.seq == 1 && e.flags == 0 && e.ttl == -1);
    ASSERT_TRUE(entry_key_is(&e, "alpha") && entry_val_is(&e, "one"));

    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(e.cf_index == 1 && e.seq == 2 && (e.flags & TDB_WAL_ENTRY_HAS_TTL) &&
                e.ttl == 12345);
    ASSERT_TRUE(entry_key_is(&e, "beta") && entry_val_is(&e, "two"));

    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(e.cf_index == 0 && e.seq == 3);
    ASSERT_TRUE((e.flags & TDB_WAL_ENTRY_TOMBSTONE) && (e.flags & TDB_WAL_ENTRY_SINGLE_DELETE));
    ASSERT_TRUE(entry_key_is(&e, "gamma") && e.value == NULL && e.value_size == 0);

    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 0); /* end of batch */
    free(buf);
}

/* an entry whose value the commit put in the value log carries the id and the value's logical
 * length, and lays down no value bytes. the length has to survive so a reader knows how large the
 * value is without probing the log, and the id has to survive because it is the only way back to
 * the bytes. it rides beside ordinary entries in one batch, since a commit separates some of its
 * values and not others */
void test_wal_roundtrip_carries_a_value_log_reference(void)
{
    const uint64_t id = 0x0123456789abcdefULL;
    const size_t logical = 4096;

    tidesdb_wal_entry_t in[3];
    in[0] = mk(0, 1, -1, 0, "inline", "small");
    in[1] = mk(0, 2, -1, TDB_WAL_ENTRY_VLOG_REF, "separated", NULL);
    in[1].value_size = logical; /* the logical length, with no bytes behind it */
    in[1].vlog_id = id;
    in[2] = mk(1, 3, 999, TDB_WAL_ENTRY_HAS_TTL | TDB_WAL_ENTRY_VLOG_REF, "both", NULL);
    in[2].value_size = logical;
    in[2].vlog_id = id + 1;

    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 3);

    /* the reference costs its id, not its value -- the record is far smaller than the value it
     * names, which is the whole point of putting the bytes in the log instead */
    ASSERT_TRUE(need < logical);

    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    const size_t wrote =
        tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 3, buf, need);
    ASSERT_TRUE(wrote == need);

    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, wrote), 0);

    tidesdb_wal_entry_t e;
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(e.flags == 0 && e.vlog_id == 0);
    ASSERT_TRUE(entry_key_is(&e, "inline") && entry_val_is(&e, "small"));

    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE((e.flags & TDB_WAL_ENTRY_VLOG_REF) != 0);
    ASSERT_TRUE(e.vlog_id == id);
    ASSERT_EQ((int)e.value_size, (int)logical);
    ASSERT_TRUE(e.value == NULL); /* the bytes are in the log, not here */
    ASSERT_TRUE(entry_key_is(&e, "separated"));

    /* a ttl and a reference sit side by side, each gated on its own bit */
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE((e.flags & TDB_WAL_ENTRY_HAS_TTL) && (e.flags & TDB_WAL_ENTRY_VLOG_REF));
    ASSERT_TRUE(e.ttl == 999 && e.vlog_id == id + 1);
    ASSERT_EQ((int)e.value_size, (int)logical);
    ASSERT_TRUE(entry_key_is(&e, "both"));

    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 0);
    free(buf);
}

/* an entry claiming a reference to nothing could never be resolved, so it is refused rather than
 * decoded as a write with an empty value */
void test_wal_reference_to_a_zero_id_is_refused(void)
{
    tidesdb_wal_entry_t in[1];
    in[0] = mk(0, 1, -1, TDB_WAL_ENTRY_VLOG_REF, "k", NULL);
    in[0].value_size = 16;
    in[0].vlog_id = 0;

    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 1);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    const size_t wrote =
        tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 1, buf, need);

    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, wrote), 0);
    tidesdb_wal_entry_t e;
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), -1);
    free(buf);
}

/* an empty batch encodes a valid header and decodes to zero entries */
void test_wal_empty_batch(void)
{
    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, NULL, 0);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    ASSERT_TRUE(tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, NULL, 0, buf, need) ==
                need);

    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, need), 0);
    tidesdb_wal_entry_t e;
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 0);
    free(buf);
}

/* encode refuses a buffer too small and rejects bad args */
void test_wal_encode_guards(void)
{
    tidesdb_wal_entry_t in = mk(0, 1, -1, 0, "k", "v");
    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &in, 1);
    uint8_t small[2];
    ASSERT_TRUE(need > sizeof(small));
    ASSERT_EQ(
        tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &in, 1, small, sizeof(small)),
        (size_t)0);
    ASSERT_EQ(tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &in, 1, NULL, need),
              (size_t)0);
    ASSERT_EQ(
        tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, NULL, 1, small, sizeof(small)),
        (size_t)0);
}

/* a wrong version byte and a null/empty buffer are rejected at cursor init */
void test_wal_bad_header(void)
{
    tidesdb_wal_cursor_t c;
    uint8_t bad[4] = {TDB_WAL_FORMAT_VERSION + 1, 0, 0, 0};
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, bad, sizeof(bad)), -1);
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, NULL, 0), -1);
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, bad, 0), -1);
}

/* a batch whose bytes are truncated below what its header claims yields -1, never a bogus entry */
void test_wal_truncated(void)
{
    tidesdb_wal_entry_t in[2];
    in[0] = mk(0, 1, -1, 0, "alpha", "one");
    in[1] = mk(0, 2, -1, 0, "beta", "two");
    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 2);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    ASSERT_TRUE(tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 2, buf, need) ==
                need);

    /* the header still says two entries, but the buffer stops partway through them */
    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, need - 4), 0);
    tidesdb_wal_entry_t e;
    int saw_error = 0;
    for (int i = 0; i < 3; i++)
    {
        const int rc = tidesdb_wal_cursor_next(&c, &e);
        if (rc == -1)
        {
            saw_error = 1;
            break;
        }
        if (rc == 0) break;
    }
    ASSERT_TRUE(saw_error);
    free(buf);
}

/* a PREPARE record carries an xid alongside its ops; the cursor exposes both. a COMMIT record
 * carries just the xid and no ops. this is the two-phase-commit framing */
void test_wal_2pc_framing(void)
{
    const uint8_t xid[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    tidesdb_wal_entry_t in[2];
    in[0] = mk(0, 7, -1, 0, "k1", "v1");
    in[1] = mk(2, 8, -1, TDB_WAL_ENTRY_TOMBSTONE, "k2", NULL);

    /* PREPARE: xid + ops */
    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_PREPARE, xid, sizeof(xid), in, 2);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    ASSERT_TRUE(
        tidesdb_wal_batch_encode(TDB_WAL_KIND_PREPARE, xid, sizeof(xid), in, 2, buf, need) == need);

    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, need), 0);
    ASSERT_EQ(c.kind, TDB_WAL_KIND_PREPARE);
    ASSERT_TRUE(c.xid_size == sizeof(xid) && memcmp(c.xid, xid, sizeof(xid)) == 0);
    tidesdb_wal_entry_t e;
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(entry_key_is(&e, "k1") && e.seq == 7);
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 1);
    ASSERT_TRUE(entry_key_is(&e, "k2") && (e.flags & TDB_WAL_ENTRY_TOMBSTONE));
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 0);
    free(buf);

    /* COMMIT: just the xid, no ops */
    const size_t cneed = tidesdb_wal_batch_size(TDB_WAL_KIND_COMMIT, xid, sizeof(xid), NULL, 0);
    uint8_t *cbuf = malloc(cneed);
    ASSERT_TRUE(cbuf != NULL);
    ASSERT_TRUE(tidesdb_wal_batch_encode(TDB_WAL_KIND_COMMIT, xid, sizeof(xid), NULL, 0, cbuf,
                                         cneed) == cneed);
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, cbuf, cneed), 0);
    ASSERT_EQ(c.kind, TDB_WAL_KIND_COMMIT);
    ASSERT_TRUE(c.xid_size == sizeof(xid) && memcmp(c.xid, xid, sizeof(xid)) == 0);
    ASSERT_EQ(tidesdb_wal_cursor_next(&c, &e), 0); /* no ops */
    free(cbuf);
}

/* a plain WRITE_BATCH has no xid */
void test_wal_write_batch_no_xid(void)
{
    tidesdb_wal_entry_t in = mk(0, 1, -1, 0, "k", "v");
    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &in, 1);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, &in, 1, buf, need);
    tidesdb_wal_cursor_t c;
    ASSERT_EQ(tidesdb_wal_cursor_init(&c, buf, need), 0);
    ASSERT_EQ(c.kind, TDB_WAL_KIND_WRITE_BATCH);
    ASSERT_TRUE(c.xid == NULL && c.xid_size == 0);
    free(buf);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_wal_roundtrip, tests_passed);
    RUN_TEST(test_wal_roundtrip_carries_a_value_log_reference, tests_passed);
    RUN_TEST(test_wal_reference_to_a_zero_id_is_refused, tests_passed);
    RUN_TEST(test_wal_2pc_framing, tests_passed);
    RUN_TEST(test_wal_write_batch_no_xid, tests_passed);
    RUN_TEST(test_wal_empty_batch, tests_passed);
    RUN_TEST(test_wal_encode_guards, tests_passed);
    RUN_TEST(test_wal_bad_header, tests_passed);
    RUN_TEST(test_wal_truncated, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
