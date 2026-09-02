/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/txn/readset.h"
#include "db.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static int rec(tidesdb_readset_t *rs, uint32_t cf, const char *k, uint64_t seq)
{
    return tidesdb_readset_record(rs, cf, (const uint8_t *)k, strlen(k), seq);
}

/* distinct reads append and are readable back */
void test_readset_record(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);
    ASSERT_EQ(tidesdb_readset_count(rs), 0);

    ASSERT_EQ(rec(rs, 0, "a", 5), TDB_SUCCESS);
    ASSERT_EQ(rec(rs, 0, "b", 6), TDB_SUCCESS);
    ASSERT_EQ(rec(rs, 1, "c", 7), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_readset_count(rs), 3);

    tidesdb_readset_entry_t e;
    ASSERT_TRUE(tidesdb_readset_at(rs, 0, &e) && e.cf_index == 0 && e.seq == 5);
    ASSERT_TRUE(tidesdb_readset_at(rs, 2, &e) && e.cf_index == 1 && e.seq == 7);
    ASSERT_TRUE(tidesdb_readset_at(rs, 3, &e) == 0);
    tidesdb_readset_free(rs);
}

/* re-reading a key keeps the higher observed seq rather than appending */
void test_readset_dedup_max_seq(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);

    rec(rs, 0, "k", 5);
    rec(rs, 0, "k", 3); /* lower -> ignored */
    ASSERT_EQ(tidesdb_readset_count(rs), 1);
    uint64_t seq = 0;
    ASSERT_TRUE(tidesdb_readset_seq(rs, 0, (const uint8_t *)"k", 1, &seq) && seq == 5);

    rec(rs, 0, "k", 8); /* higher -> kept */
    ASSERT_EQ(tidesdb_readset_count(rs), 1);
    ASSERT_TRUE(tidesdb_readset_seq(rs, 0, (const uint8_t *)"k", 1, &seq) && seq == 8);

    /* the same key under a different cf is a separate read */
    rec(rs, 1, "k", 2);
    ASSERT_EQ(tidesdb_readset_count(rs), 2);
    ASSERT_TRUE(tidesdb_readset_seq(rs, 1, (const uint8_t *)"k", 1, &seq) && seq == 2);

    /* an unread key has no seq */
    ASSERT_EQ(tidesdb_readset_seq(rs, 0, (const uint8_t *)"missing", 7, &seq), 0);
    tidesdb_readset_free(rs);
}

/* contains reports whether a key was read, scoped by cf-index */
void test_readset_contains(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);
    rec(rs, 0, "x", 1);

    ASSERT_EQ(tidesdb_readset_contains(rs, 0, (const uint8_t *)"x", 1), 1);
    ASSERT_EQ(tidesdb_readset_contains(rs, 0, (const uint8_t *)"y", 1), 0);
    ASSERT_EQ(tidesdb_readset_contains(rs, 1, (const uint8_t *)"x", 1), 0);
    tidesdb_readset_free(rs);
}

/* clear drops every recorded read and reclaims memory */
void test_readset_clear(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);
    rec(rs, 0, "a", 1);
    rec(rs, 0, "b", 2);
    ASSERT_TRUE(tidesdb_readset_mem_bytes(rs) > 0);

    tidesdb_readset_clear(rs);
    ASSERT_EQ(tidesdb_readset_count(rs), 0);
    ASSERT_TRUE(tidesdb_readset_mem_bytes(rs) == 0);

    /* usable again after clear */
    ASSERT_EQ(rec(rs, 0, "c", 3), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_readset_count(rs), 1);
    tidesdb_readset_free(rs);
}

/* growth past the initial capacity keeps every read intact */
void test_readset_growth(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);
    enum
    {
        N = 100
    };
    for (int i = 0; i < N; i++)
    {
        char k[16];
        snprintf(k, sizeof(k), "k%d", i);
        ASSERT_EQ(rec(rs, 0, k, (uint64_t)(i + 1)), TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_readset_count(rs), N);
    uint64_t seq = 0;
    ASSERT_TRUE(tidesdb_readset_seq(rs, 0, (const uint8_t *)"k57", 3, &seq) && seq == 58);
    tidesdb_readset_free(rs);
}

/* bad args are handled */
void test_readset_null_safe(void)
{
    ASSERT_EQ(tidesdb_readset_count(NULL), 0);
    ASSERT_TRUE(tidesdb_readset_mem_bytes(NULL) == 0);
    ASSERT_EQ(rec(NULL, 0, "k", 1), TDB_ERR_INVALID_ARGS);
    uint64_t seq = 0;
    ASSERT_EQ(tidesdb_readset_seq(NULL, 0, (const uint8_t *)"k", 1, &seq), 0);
    ASSERT_EQ(tidesdb_readset_contains(NULL, 0, (const uint8_t *)"k", 1), 0);
    tidesdb_readset_clear(NULL);
    tidesdb_readset_free(NULL);

    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_EQ(tidesdb_readset_record(rs, 0, (const uint8_t *)"", 0, 1), TDB_ERR_INVALID_ARGS);
    tidesdb_readset_free(rs);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_readset_record, tests_passed);
    RUN_TEST(test_readset_dedup_max_seq, tests_passed);
    RUN_TEST(test_readset_contains, tests_passed);
    RUN_TEST(test_readset_clear, tests_passed);
    RUN_TEST(test_readset_growth, tests_passed);
    RUN_TEST(test_readset_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
