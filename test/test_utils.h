/*
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
#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_macros.h"

#define TEST_DB_PATH    "./test_tidesdb"
#define ASSERT_EQ(a, b) assert((a) == (b))
#define ASSERT_NE(a, b) assert((a) != (b))
#define ASSERT_TRUE(a)  assert(a)
#define ASSERT_FALSE(a) assert(!(a))

#define RUN_TEST(test_func, test_passed)                    \
    do                                                      \
    {                                                       \
        printf(YELLOW "Running: %s... " RESET, #test_func); \
        fflush(stdout);                                     \
        test_func();                                        \
        printf(GREEN "PASSED\n" RESET);                     \
        tests_passed++;                                     \
    } while (0)

/* print test results summary */
#define PRINT_TEST_RESULTS(test_passed, test_failed)                  \
    do                                                                \
    {                                                                 \
        printf("\n");                                                 \
        printf("=======================================\n");          \
        printf("Test Results:\n");                                    \
        printf("  " BOLDGREEN "PASSED: %d" RESET "\n", tests_passed); \
        printf("  " BOLDRED "FAILED: %d" RESET "\n", tests_failed);   \
        printf("=======================================\n");          \
    } while (0)

/* helper to clean test directory */
static inline void cleanup_test_dir(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DB_PATH);
    system(cmd);
}

/* generate random key-value pairs for testing */
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

#endif /* TEST_UTILS_H */