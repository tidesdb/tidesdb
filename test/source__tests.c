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

#include "../src/txn/source.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a mock read source: it holds at most one key, at a seq, with a value (NULL = tombstone). busy
 * forces a transient failure; ryow models the write buffer (always visible, ignores the snapshot);
 * otherwise a version is only visible when its seq is at or below the snapshot */
typedef struct
{
    int busy;
    int has;
    int ryow;
    const char *key;
    uint64_t seq;
    const char *value;
} mock_src;

static tidesdb_source_result_t mock_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                        size_t key_size, uint64_t snapshot,
                                        tidesdb_source_version_t *out)
{
    (void)cf_index;
    mock_src *m = (mock_src *)ctx;
    if (m->busy) return TDB_SOURCE_BUSY;
    if (!m->has) return TDB_SOURCE_NOT_FOUND;
    if (key_size != strlen(m->key) || memcmp(key, m->key, key_size) != 0)
        return TDB_SOURCE_NOT_FOUND;
    if (!m->ryow && m->seq > snapshot) return TDB_SOURCE_NOT_FOUND; /* not visible at snapshot */

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

static tidesdb_source_t src(const char *name, mock_src *m)
{
    tidesdb_source_t s = {.name = name, .get = mock_get, .has_newer = NULL, .ctx = m};
    return s;
}

static int val_is(const tidesdb_source_version_t *v, const char *s)
{
    return v->value_size == strlen(s) && memcmp(v->value, s, v->value_size) == 0;
}

/* the write buffer sits first and wins even when a later source holds a higher committed seq -- a
 * txn reads its own uncommitted write */
void test_source_ryow_wins(void)
{
    mock_src wb = {0, 1, 1, "k", 0, "mine"};
    mock_src l0 = {0, 1, 0, "k", 100, "committed"};
    tidesdb_source_t stack[2] = {src("wb", &wb), src("l0", &l0)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 2, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_FOUND);
    ASSERT_TRUE(val_is(&v, "mine"));
    free(v.value);
}

/* with the write buffer empty, the newest tier that has a visible version wins */
void test_source_newest_wins(void)
{
    mock_src wb = {0, 0, 1, "k", 0, NULL};
    mock_src l0 = {0, 1, 0, "k", 10, "from_l0"};
    mock_src sst = {0, 1, 0, "k", 5, "from_sst"};
    tidesdb_source_t stack[3] = {src("wb", &wb), src("l0", &l0), src("sst", &sst)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 3, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_FOUND);
    ASSERT_TRUE(v.seq == 10 && val_is(&v, "from_l0"));
    free(v.value);
}

/* a read falls through empty newer sources to an older one that has the key */
void test_source_fallthrough(void)
{
    mock_src wb = {0, 0, 1, "k", 0, NULL};
    mock_src l0 = {0, 0, 0, "k", 0, NULL};
    mock_src sst = {0, 1, 0, "k", 5, "from_sst"};
    tidesdb_source_t stack[3] = {src("wb", &wb), src("l0", &l0), src("sst", &sst)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 3, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_FOUND);
    ASSERT_TRUE(v.seq == 5 && val_is(&v, "from_sst"));
    free(v.value);
}

/* a newer source whose only version is beyond the snapshot is skipped for an older visible version
 * -- the composer honors the per-source snapshot filter */
void test_source_snapshot_fallthrough(void)
{
    mock_src l0 = {0, 1, 0, "k", 10, "newer"}; /* seq 10, invisible at snapshot 7 */
    mock_src sst = {0, 1, 0, "k", 5, "older"}; /* seq 5, visible */
    tidesdb_source_t stack[2] = {src("l0", &l0), src("sst", &sst)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 2, 0, (const uint8_t *)"k", 1, 7, &v),
              TDB_SOURCE_FOUND);
    ASSERT_TRUE(v.seq == 5 && val_is(&v, "older"));
    free(v.value);
}

/* no source has the key */
void test_source_not_found(void)
{
    mock_src wb = {0, 0, 1, "k", 0, NULL};
    mock_src l0 = {0, 0, 0, "k", 0, NULL};
    tidesdb_source_t stack[2] = {src("wb", &wb), src("l0", &l0)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 2, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_NOT_FOUND);
}

/* a busy source short-circuits to busy without consulting older sources -- it may hold a version
 * the reader must see, so falling through could return a stale read */
void test_source_busy_shortcircuits(void)
{
    mock_src l0 = {1, 0, 0, "k", 0, NULL};        /* busy */
    mock_src sst = {0, 1, 0, "k", 5, "from_sst"}; /* would answer, but must not be consulted */
    tidesdb_source_t stack[2] = {src("l0", &l0), src("sst", &sst)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 2, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_BUSY);
}

/* a tombstone is a hit -- the composer returns FOUND with the deleted flag set and no value */
void test_source_tombstone(void)
{
    mock_src l0 = {0, 1, 0, "k", 10, NULL}; /* tombstone */
    tidesdb_source_t stack[1] = {src("l0", &l0)};

    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(stack, 1, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_FOUND);
    ASSERT_TRUE(v.deleted == 1 && v.value == NULL && v.seq == 10);
}

/* bad args are handled */
void test_source_null_safe(void)
{
    tidesdb_source_version_t v;
    ASSERT_EQ(tidesdb_source_stack_get(NULL, 0, 0, (const uint8_t *)"k", 1, 50, &v),
              TDB_SOURCE_NOT_FOUND);
    mock_src l0 = {0, 1, 0, "k", 5, "x"};
    tidesdb_source_t stack[1] = {src("l0", &l0)};
    ASSERT_EQ(tidesdb_source_stack_get(stack, 1, 0, NULL, 1, 50, &v), TDB_SOURCE_NOT_FOUND);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_source_ryow_wins, tests_passed);
    RUN_TEST(test_source_newest_wins, tests_passed);
    RUN_TEST(test_source_fallthrough, tests_passed);
    RUN_TEST(test_source_snapshot_fallthrough, tests_passed);
    RUN_TEST(test_source_not_found, tests_passed);
    RUN_TEST(test_source_busy_shortcircuits, tests_passed);
    RUN_TEST(test_source_tombstone, tests_passed);
    RUN_TEST(test_source_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
