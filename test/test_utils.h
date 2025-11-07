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
#include <sys/stat.h>

#include "../src/compat.h" /* for PATH_SEPARATOR and platform compatibility */

#ifdef _WIN32
#include <direct.h> /* for _rmdir */
#include <windows.h>
#else
#include <unistd.h> /* for rmdir */
#endif

/* dirent.h - MinGW has it natively, MSVC uses compat.h implementation */
#if !defined(_MSC_VER)
#include <dirent.h>
#endif

#include "test_macros.h"

#define TEST_DB_PATH "./test_tidesdb"

/* ensure assertions work in both Debug and Release builds */
#undef NDEBUG
#include <assert.h>

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

/*
 * remove_directory
 * @param path path to directory to remove
 * @return 0 on success, -1 on failure
 */
static inline int remove_directory(const char *path)
{
    char *dir_stack[64];
    int stack_top = 0;
    int result = 0;

    /* push initial directory */
    dir_stack[stack_top] = strdup(path);
    if (!dir_stack[stack_top]) return -1;
    stack_top++;

    /* process directories in post-order (children before parents) */
    while (stack_top > 0)
    {
        /* peek at top directory */
        char *current_path = dir_stack[stack_top - 1];
        DIR *dir = opendir(current_path);

        if (!dir)
        {
            /* directory doesn't exist or can't be opened, pop and continue */
            free(dir_stack[--stack_top]);
            continue;
        }

        struct dirent *entry;
        int has_subdirs = 0;

        /* scan for subdirectories and files */
        while ((entry = readdir(dir)) != NULL)
        {
            /* skip . and .. */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s" PATH_SEPARATOR "%s", current_path,
                     entry->d_name);

            struct stat statbuf;
            if (stat(filepath, &statbuf) != 0)
            {
                continue;
            }

            if (S_ISDIR(statbuf.st_mode))
            {
                /* push subdirectory onto stack if space available */
                if (stack_top < 64)
                {
                    dir_stack[stack_top] = strdup(filepath);
                    if (dir_stack[stack_top])
                    {
                        stack_top++;
                        has_subdirs = 1;
                    }
                }
            }
            else
            {
                /* remove file immediately */
                if (remove(filepath) != 0)
                {
                    result = -1;
                }
            }
        }

        closedir(dir);

        /* if we found subdirectories, process them first */
        if (has_subdirs)
        {
            continue;
        }

        /* no subdirectories, remove this directory and pop from stack */
#ifdef _WIN32
        if (_rmdir(current_path) != 0)
#else
        if (rmdir(current_path) != 0)
#endif
        {
            result = -1;
        }

        free(dir_stack[--stack_top]);
    }

    return result;
}

/*
 * cleanup_test_dir
 * @brief cleanup test directory
 */
UNUSED static inline void cleanup_test_dir(void)
{
#ifdef _WIN32
    /* wait for file handles to be released */
    Sleep(200);
#endif

    /* try to remove directory, retry if it fails (windows file locking) */
    for (int attempt = 0; attempt < 3; attempt++)
    {
        if (remove_directory(TEST_DB_PATH) == 0)
        {
            break; /* success */
        }

#ifdef _WIN32
        Sleep(100); /* wait and retry on Windows */
#endif
    }
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

#endif /* TEST_UTILS_H */