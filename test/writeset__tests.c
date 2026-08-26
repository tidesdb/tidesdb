/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/txn/writeset.h"
#include "db.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static int put(tidesdb_writeset_t *ws, uint32_t cf, const char *k, const char *v, uint8_t flags)
{
    return tidesdb_writeset_put(ws, cf, (const uint8_t *)k, strlen(k),
                                v ? (const uint8_t *)v : NULL, v ? strlen(v) : 0, -1, flags);
}

static int op_val_is(const tidesdb_writeset_op_t *o, const char *s)
{
    return o->value_size == strlen(s) && memcmp(o->value, s, o->value_size) == 0;
}

/* ops append in order and are readable back by index */
void test_writeset_append(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    ASSERT_EQ(tidesdb_writeset_count(ws), 0);

    ASSERT_EQ(put(ws, 0, "a", "1", 0), TDB_SUCCESS);
    ASSERT_EQ(put(ws, 0, "b", "2", 0), TDB_SUCCESS);
    ASSERT_EQ(put(ws, 1, "c", "3", 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(ws), 3);

    tidesdb_writeset_op_t o;
    ASSERT_TRUE(tidesdb_writeset_op_at(ws, 0, &o) && o.cf_index == 0 && op_val_is(&o, "1"));
    ASSERT_TRUE(tidesdb_writeset_op_at(ws, 2, &o) && o.cf_index == 1 && op_val_is(&o, "3"));
    ASSERT_TRUE(tidesdb_writeset_op_at(ws, 3, &o) == 0); /* out of range */
    tidesdb_writeset_free(ws);
}

/* read-your-own-writes: the latest write of a key wins, a tombstone reads back deleted, a cf-index
 * namespaces the key */
void test_writeset_ryow(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    tidesdb_writeset_op_t o;

    put(ws, 0, "k", "first", 0);
    ASSERT_TRUE(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"k", 1, &o) &&
                op_val_is(&o, "first"));

    put(ws, 0, "k", "second", 0); /* overwrite */
    ASSERT_TRUE(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"k", 1, &o) &&
                op_val_is(&o, "second"));

    put(ws, 0, "k", NULL, TDB_WAL_ENTRY_TOMBSTONE); /* delete */
    ASSERT_TRUE(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"k", 1, &o));
    ASSERT_TRUE((o.flags & TDB_WAL_ENTRY_TOMBSTONE) && o.value == NULL && o.value_size == 0);

    /* the same key under a different cf-index is a different entry, and unknown keys miss */
    put(ws, 1, "k", "other_cf", 0);
    ASSERT_TRUE(tidesdb_writeset_lookup(ws, 1, (const uint8_t *)"k", 1, &o) &&
                op_val_is(&o, "other_cf"));
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"missing", 7, &o), 0);
    tidesdb_writeset_free(ws);
}

/* a tombstone put drops any value it is handed */
void test_writeset_tombstone_no_value(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    put(ws, 0, "k", "should_be_dropped", TDB_WAL_ENTRY_TOMBSTONE);
    tidesdb_writeset_op_t o;
    ASSERT_TRUE(tidesdb_writeset_op_at(ws, 0, &o));
    ASSERT_TRUE(o.value_size == 0 && o.value == NULL);
    tidesdb_writeset_free(ws);
}

/* truncate drops the tail (a savepoint rollback) and reclaims its memory */
void test_writeset_truncate(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    put(ws, 0, "a", "1", 0);
    put(ws, 0, "b", "2", 0);
    put(ws, 0, "c", "3", 0);
    const int64_t full = tidesdb_writeset_mem_bytes(ws);
    ASSERT_TRUE(full > 0);

    tidesdb_writeset_truncate(ws, 1);
    ASSERT_EQ(tidesdb_writeset_count(ws), 1);
    ASSERT_TRUE(tidesdb_writeset_mem_bytes(ws) < full);

    tidesdb_writeset_op_t o;
    ASSERT_TRUE(tidesdb_writeset_op_at(ws, 0, &o) && op_val_is(&o, "1"));
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"b", 1, &o), 0); /* gone */
    tidesdb_writeset_free(ws);
}

/* contains reports whether a key is written, scoped by cf-index */
void test_writeset_contains(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    put(ws, 0, "x", "v", 0);
    put(ws, 0, "y", NULL, TDB_WAL_ENTRY_TOMBSTONE); /* a tombstone still counts as written */

    ASSERT_EQ(tidesdb_writeset_contains(ws, 0, (const uint8_t *)"x", 1), 1);
    ASSERT_EQ(tidesdb_writeset_contains(ws, 0, (const uint8_t *)"y", 1), 1);
    ASSERT_EQ(tidesdb_writeset_contains(ws, 0, (const uint8_t *)"z", 1), 0);
    ASSERT_EQ(tidesdb_writeset_contains(ws, 1, (const uint8_t *)"x", 1), 0); /* other cf */
    tidesdb_writeset_free(ws);
}

/* growth past the initial capacity keeps every op intact */
void test_writeset_growth(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    enum
    {
        N = 100
    };
    for (int i = 0; i < N; i++)
    {
        char k[16];
        snprintf(k, sizeof(k), "k%d", i);
        ASSERT_EQ(put(ws, 0, k, "v", 0), TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_writeset_count(ws), N);
    tidesdb_writeset_op_t o;
    ASSERT_TRUE(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"k57", 3, &o));
    tidesdb_writeset_free(ws);
}

/* bad args are handled */
void test_writeset_null_safe(void)
{
    ASSERT_EQ(tidesdb_writeset_count(NULL), 0);
    ASSERT_TRUE(tidesdb_writeset_mem_bytes(NULL) == 0);
    ASSERT_EQ(put(NULL, 0, "k", "v", 0), TDB_ERR_INVALID_ARGS);
    tidesdb_writeset_op_t o;
    ASSERT_EQ(tidesdb_writeset_lookup(NULL, 0, (const uint8_t *)"k", 1, &o), 0);
    ASSERT_EQ(tidesdb_writeset_contains(NULL, 0, (const uint8_t *)"k", 1), 0);
    tidesdb_writeset_truncate(NULL, 0);
    tidesdb_writeset_free(NULL);

    /* an empty key is rejected */
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_EQ(tidesdb_writeset_put(ws, 0, (const uint8_t *)"", 0, NULL, 0, -1, 0),
              TDB_ERR_INVALID_ARGS);
    tidesdb_writeset_free(ws);
}

/* an empty value is a value. the key is present, it is not a tombstone, and a read must say so --
 * a caller storing a marker whose whole meaning is in the key should not have to invent a filler
 * byte. what stays rejected is a caller claiming bytes it did not supply */
void test_writeset_keeps_a_live_entry_with_an_empty_value(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    const uint8_t key[] = "k";

    ASSERT_EQ(tidesdb_writeset_put(ws, 0, key, 1, (const uint8_t *)"", 0, -1, 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_writeset_count(ws), 1);

    /* it reads back as present with nothing in it, and not as a tombstone */
    tidesdb_writeset_op_t op;
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, key, 1, &op), 1);
    ASSERT_EQ(op.value_size, 0u);
    ASSERT_EQ(op.flags & TDB_WAL_ENTRY_TOMBSTONE, 0);

    tidesdb_writeset_free(ws);
}

/* read-your-own-writes has to honour a buffered prefix delete over every key under it, not just the
 * one key whose bytes happen to equal the prefix */
void test_writeset_prefix_delete_shadows_the_keys_under_it(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);

    ASSERT_EQ(put(ws, 0, "user:1", "one", 0), TDB_SUCCESS);
    ASSERT_EQ(put(ws, 0, "used", "keep", 0), TDB_SUCCESS);
    ASSERT_EQ(put(ws, 0, "user:", NULL, TDB_WAL_ENTRY_TOMBSTONE | TDB_WAL_ENTRY_RANGE_DELETE),
              TDB_SUCCESS);

    tidesdb_writeset_op_t op;
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"user:1", 6, &op), 1);
    ASSERT_TRUE((op.flags & TDB_WAL_ENTRY_TOMBSTONE) != 0);

    /* a key the buffered delete never covered is untouched by it */
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"used", 4, &op), 1);
    ASSERT_TRUE((op.flags & TDB_WAL_ENTRY_TOMBSTONE) == 0);

    /* and it reaches no further than its own family */
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 1, (const uint8_t *)"user:1", 6, &op), 0);

    tidesdb_writeset_free(ws);
}

/* a write buffered after the prefix delete is the newer op, so it wins the key back */
void test_writeset_write_after_a_prefix_delete_wins(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);

    ASSERT_EQ(put(ws, 0, "user:", NULL, TDB_WAL_ENTRY_TOMBSTONE | TDB_WAL_ENTRY_RANGE_DELETE),
              TDB_SUCCESS);
    ASSERT_EQ(put(ws, 0, "user:1", "back", 0), TDB_SUCCESS);

    tidesdb_writeset_op_t op;
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"user:1", 6, &op), 1);
    ASSERT_TRUE((op.flags & TDB_WAL_ENTRY_TOMBSTONE) == 0);
    ASSERT_TRUE(op.value_size == 4 && memcmp(op.value, "back", 4) == 0);

    /* its siblings stay deleted */
    ASSERT_EQ(tidesdb_writeset_lookup(ws, 0, (const uint8_t *)"user:2", 6, &op), 1);
    ASSERT_TRUE((op.flags & TDB_WAL_ENTRY_TOMBSTONE) != 0);

    tidesdb_writeset_free(ws);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_writeset_prefix_delete_shadows_the_keys_under_it, tests_passed);
    RUN_TEST(test_writeset_write_after_a_prefix_delete_wins, tests_passed);
    RUN_TEST(test_writeset_append, tests_passed);
    RUN_TEST(test_writeset_ryow, tests_passed);
    RUN_TEST(test_writeset_tombstone_no_value, tests_passed);
    RUN_TEST(test_writeset_truncate, tests_passed);
    RUN_TEST(test_writeset_contains, tests_passed);
    RUN_TEST(test_writeset_growth, tests_passed);
    RUN_TEST(test_writeset_null_safe, tests_passed);
    RUN_TEST(test_writeset_keeps_a_live_entry_with_an_empty_value, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
