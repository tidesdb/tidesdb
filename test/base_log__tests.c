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

#include "../src/base/log.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_LOG_PATH "./test_base_log.txt"

/* read the whole sink file into buf, NUL-terminated, returning bytes read or -1 */
static long read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    const size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return (long)n;
}

/* a written line carries its level tag, source location, and formatted message */
void test_log_write_to_file(void)
{
    FILE *f = fopen(TEST_LOG_PATH, "w");
    ASSERT_TRUE(f != NULL);
    tidesdb_log_set_sink(f, 0, NULL);

    tidesdb_log_write(TDB_LOG_INFO, "unit.c", 7, "hello %d", 42);
    tidesdb_log_close_sink();

    /* the sink routes back to stderr once closed */
    ASSERT_TRUE(_tidesdb_log_file == NULL);

    char buf[4096];
    ASSERT_TRUE(read_file(TEST_LOG_PATH, buf, sizeof(buf)) > 0);
    ASSERT_TRUE(strstr(buf, "[INFO]") != NULL);
    ASSERT_TRUE(strstr(buf, "unit.c:7") != NULL);
    ASSERT_TRUE(strstr(buf, "hello 42") != NULL);

    remove(TEST_LOG_PATH);
}

/* TDB_DEBUG_LOG drops a line below the configured level and keeps one at or above it */
void test_log_level_gating(void)
{
    const int saved = _tidesdb_log_level;

    FILE *f = fopen(TEST_LOG_PATH, "w");
    ASSERT_TRUE(f != NULL);
    tidesdb_log_set_sink(f, 0, NULL);

    _tidesdb_log_level = TDB_LOG_WARN;
    TDB_DEBUG_LOG(TDB_LOG_TRACE, "suppressed-below-level");
    TDB_DEBUG_LOG(TDB_LOG_ERROR, "emitted-above-level");

    tidesdb_log_close_sink();
    _tidesdb_log_level = saved;

    char buf[4096];
    ASSERT_TRUE(read_file(TEST_LOG_PATH, buf, sizeof(buf)) >= 0);
    ASSERT_TRUE(strstr(buf, "suppressed-below-level") == NULL);
    ASSERT_TRUE(strstr(buf, "emitted-above-level") != NULL);

    remove(TEST_LOG_PATH);
}

/* TDB_LOG_NONE silences every level, even ERROR */
void test_log_level_none_silences_all(void)
{
    const int saved = _tidesdb_log_level;

    FILE *f = fopen(TEST_LOG_PATH, "w");
    ASSERT_TRUE(f != NULL);
    tidesdb_log_set_sink(f, 0, NULL);

    _tidesdb_log_level = TDB_LOG_NONE;
    TDB_DEBUG_LOG(TDB_LOG_ERROR, "must-not-appear");

    tidesdb_log_close_sink();
    _tidesdb_log_level = saved;

    char buf[4096];
    ASSERT_TRUE(read_file(TEST_LOG_PATH, buf, sizeof(buf)) >= 0);
    ASSERT_TRUE(strstr(buf, "must-not-appear") == NULL);

    remove(TEST_LOG_PATH);
}

/* the sink reopens and truncates once it grows past the configured threshold, bounding its size */
void test_log_truncation(void)
{
    const size_t threshold = 256;
    FILE *f = fopen(TEST_LOG_PATH, "w");
    ASSERT_TRUE(f != NULL);
    tidesdb_log_set_sink(f, threshold, TEST_LOG_PATH);

    for (int i = 0; i < 200; i++)
        tidesdb_log_write(TDB_LOG_INFO, "unit.c", i, "line %d padding padding padding", i);

    tidesdb_log_close_sink();

    char buf[65536];
    const long n = read_file(TEST_LOG_PATH, buf, sizeof(buf));
    ASSERT_TRUE(n >= 0);
    /* truncation kept the file bounded far below the total volume written */
    ASSERT_TRUE(n < 4096);
    ASSERT_TRUE(strstr(buf, "LOG TRUNCATED") != NULL);

    remove(TEST_LOG_PATH);
}

/* set_sink with a NULL file routes output back to stderr and clears the truncation state */
void test_log_set_sink_null_routes_stderr(void)
{
    FILE *f = fopen(TEST_LOG_PATH, "w");
    ASSERT_TRUE(f != NULL);
    tidesdb_log_set_sink(f, 128, TEST_LOG_PATH);
    ASSERT_TRUE(_tidesdb_log_file != NULL);
    ASSERT_TRUE(_tidesdb_log_truncate == 128);

    /* the caller owns f here, so close it after detaching the sink */
    tidesdb_log_set_sink(NULL, 0, NULL);
    ASSERT_TRUE(_tidesdb_log_file == NULL);
    ASSERT_TRUE(_tidesdb_log_truncate == 0);
    ASSERT_TRUE(_tidesdb_log_path[0] == '\0');
    fclose(f);

    remove(TEST_LOG_PATH);
}

/* closing an already-stderr sink is a harmless no-op */
void test_log_close_sink_idempotent(void)
{
    tidesdb_log_set_sink(NULL, 0, NULL);
    tidesdb_log_close_sink();
    tidesdb_log_close_sink();
    ASSERT_TRUE(_tidesdb_log_file == NULL);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_log_write_to_file, tests_passed);
    RUN_TEST(test_log_level_gating, tests_passed);
    RUN_TEST(test_log_level_none_silences_all, tests_passed);
    RUN_TEST(test_log_truncation, tests_passed);
    RUN_TEST(test_log_set_sink_null_routes_stderr, tests_passed);
    RUN_TEST(test_log_close_sink_idempotent, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
