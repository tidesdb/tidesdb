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
    tidesdb_readset_entry_t e;
    ASSERT_TRUE(tidesdb_readset_at(rs, 0, &e) && e.seq == 5);

    rec(rs, 0, "k", 8); /* higher -> kept */
    ASSERT_EQ(tidesdb_readset_count(rs), 1);
    ASSERT_TRUE(tidesdb_readset_at(rs, 0, &e) && e.seq == 8);

    /* the same key under a different cf is a separate read */
    rec(rs, 1, "k", 2);
    ASSERT_EQ(tidesdb_readset_count(rs), 2);
    ASSERT_TRUE(tidesdb_readset_at(rs, 1, &e) && e.cf_index == 1 && e.seq == 2);
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
    tidesdb_readset_entry_t e;
    ASSERT_TRUE(tidesdb_readset_at(rs, 57, &e) && e.seq == 58 && e.key_size == 3 &&
                memcmp(e.key, "k57", 3) == 0);
    tidesdb_readset_free(rs);
}

/* a scanned interval is kept beside the keys, bounds copied, an open upper bound as none */
void test_readset_record_range(void)
{
    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_TRUE(rs != NULL);
    ASSERT_EQ(tidesdb_readset_range_count(rs), 0);
    const int64_t before = tidesdb_readset_mem_bytes(rs);

    uint8_t lo[] = "a", hi[] = "m";
    ASSERT_EQ(tidesdb_readset_record_range(rs, 0, lo, 1, hi, 1, 5), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_readset_record_range(rs, 1, lo, 1, NULL, 0, 6), TDB_SUCCESS);
    memset(lo, 'x', 1); /* the set keeps its own copy */
    ASSERT_EQ(tidesdb_readset_range_count(rs), 2);
    ASSERT_EQ(tidesdb_readset_count(rs), 0); /* an interval is not a key */
    ASSERT_TRUE(tidesdb_readset_mem_bytes(rs) > before);

    tidesdb_readset_range_t r;
    ASSERT_TRUE(tidesdb_readset_range_at(rs, 0, &r));
    ASSERT_TRUE(r.cf_index == 0 && r.lo_size == 1 && r.lo[0] == 'a' && r.hi_size == 1 &&
                r.hi[0] == 'm' && r.seq == 5);
    ASSERT_TRUE(tidesdb_readset_range_at(rs, 1, &r));
    ASSERT_TRUE(r.cf_index == 1 && r.hi == NULL && r.hi_size == 0 && r.seq == 6);
    ASSERT_EQ(tidesdb_readset_range_at(rs, 2, &r), 0);
    tidesdb_readset_free(rs);
}

/* bad args are handled */
void test_readset_null_safe(void)
{
    ASSERT_EQ(tidesdb_readset_count(NULL), 0);
    ASSERT_EQ(tidesdb_readset_range_count(NULL), 0);
    ASSERT_TRUE(tidesdb_readset_mem_bytes(NULL) == 0);
    ASSERT_EQ(rec(NULL, 0, "k", 1), TDB_ERR_INVALID_ARGS);
    tidesdb_readset_entry_t e;
    ASSERT_EQ(tidesdb_readset_at(NULL, 0, &e), 0);
    tidesdb_readset_range_t r;
    ASSERT_EQ(tidesdb_readset_range_at(NULL, 0, &r), 0);
    ASSERT_EQ(tidesdb_readset_record_range(NULL, 0, (const uint8_t *)"a", 1, NULL, 0, 1),
              TDB_ERR_INVALID_ARGS);
    tidesdb_readset_free(NULL);

    tidesdb_readset_t *rs = tidesdb_readset_create();
    ASSERT_EQ(tidesdb_readset_record(rs, 0, (const uint8_t *)"", 0, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_readset_record_range(rs, 0, (const uint8_t *)"", 0, NULL, 0, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_readset_record_range(rs, 0, (const uint8_t *)"a", 1, NULL, 1, 1),
              TDB_ERR_INVALID_ARGS);
    tidesdb_readset_free(rs);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_readset_record, tests_passed);
    RUN_TEST(test_readset_dedup_max_seq, tests_passed);
    RUN_TEST(test_readset_growth, tests_passed);
    RUN_TEST(test_readset_record_range, tests_passed);
    RUN_TEST(test_readset_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
