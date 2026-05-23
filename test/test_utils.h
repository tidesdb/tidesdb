/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <assert.h>
#include <string.h>

#include "../src/compat.h"
#include "../src/tidesdb.h"
#include "test_macros.h"

/* global test filter -- set via argv[1] for running specific tests */
static UNUSED const char *test_filter = NULL;
static UNUSED int tests_skipped = 0;

/* call at the top of main(argc, argv) to enable --filter or positional arg */
#define INIT_TEST_FILTER(argc, argv)             \
    do                                           \
    {                                            \
        if ((argc) > 1) test_filter = (argv)[1]; \
    } while (0)

/* disable format-truncation warnings for test utilities. all path buffers use 1024 bytes */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#define TEST_DB_PATH "./test_tidesdb"

/* ensure assertions work in both Debug and Release builds */
#undef NDEBUG
#include <assert.h>

#define ASSERT_EQ(a, b) assert((a) == (b))
#define ASSERT_NE(a, b) assert((a) != (b))
#define ASSERT_TRUE(a)  assert(a)
#define ASSERT_FALSE(a) assert(!(a))

#define RUN_TEST(test_func, test_passed)                     \
    do                                                       \
    {                                                        \
        if (test_filter && !strstr(#test_func, test_filter)) \
        {                                                    \
            tests_skipped++;                                 \
            break;                                           \
        }                                                    \
        printf(YELLOW "Running: %s... " RESET, #test_func);  \
        fflush(stdout);                                      \
        test_func();                                         \
        printf(GREEN "PASSED\n" RESET);                      \
        tests_passed++;                                      \
    } while (0)

/* print test results summary */
#define PRINT_TEST_RESULTS(test_passed, test_failed)                                        \
    do                                                                                      \
    {                                                                                       \
        printf("\n");                                                                       \
        printf("*=======================================*\n");                              \
        printf("Test Results:\n");                                                          \
        printf("  " BOLDGREEN "PASSED: %d" RESET "\n", tests_passed);                       \
        printf("  " BOLDRED "FAILED: %d" RESET "\n", tests_failed);                         \
        if (tests_skipped > 0) printf("  " YELLOW "SKIPPED: %d" RESET "\n", tests_skipped); \
        if (test_filter) printf("  Filter: \"%s\"\n", test_filter);                         \
        printf("*=======================================*\n");                              \
    } while (0)

#define REMOVE_DIR_RETRY_COUNT 5

/*
 * cleanup_test_dir
 * @brief cleanup test directory with retry logic
 */
static inline void cleanup_test_dir(void)
{
    (void)remove_directory(TEST_DB_PATH);
}

/*
 * tdb_test_commit_with_retry
 * commit a txn, retrying on TDB_ERR_BUSY (backpressure stall timeout) so that
 * stress tests don't flake on slow CI boxes where the 10s no-progress budget
 * can be reached under sustained load. caller still observes any real error
 * (TDB_ERR_IO, TDB_ERR_NOT_FOUND, TDB_ERR_UNKNOWN, ...) as the final return.
 * @param txn         transaction to commit (caller still owns the txn handle)
 * @param max_retries upper bound on retry attempts. 0 disables retry
 * @return 0 on success, or the last commit error code
 */
static inline int tdb_test_commit_with_retry(tidesdb_txn_t *txn, int max_retries)
{
    int rc;
    for (int attempt = 0; attempt <= max_retries; attempt++)
    {
        rc = tidesdb_txn_commit(txn);
        if (rc != TDB_ERR_BUSY) return rc;
        usleep(50000); /* 50ms backoff between attempts */
    }
    return rc;
}

/*
 * generate_random_key_value
 * @brief generate random key-value pairs for testing
 */
static inline void generate_random_key_value(uint8_t *key, size_t key_size, uint8_t *value,
                                             size_t value_size)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_size = sizeof(charset) - 1;

    for (size_t i = 0; i < key_size; i++)
    {
        key[i] = (uint8_t)charset[rand() % (int)charset_size];
    }
    for (size_t i = 0; i < value_size; i++)
    {
        value[i] = (uint8_t)charset[rand() % (int)charset_size];
    }
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* __TEST_UTILS_H__ */