/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

#include <assert.h>
#include <string.h>

#include "../src/compat.h"
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

/* a test that closes its database owns no sstables afterwards, so the live handle count has to come
 * back to what it stood at before the test ran. asserting that around every test is what turns a
 * dropped sstable reference into a named, deterministic failure rather than something only a long
 * concurrent run happens to notice thousands of operations after the fact */
int64_t sstable_live_handles(void);
int64_t level_live_layouts(void);

#define RUN_TEST_HANDLE_BALANCED(test_func, test_passed)                           \
    do                                                                             \
    {                                                                              \
        const int64_t handles_before = sstable_live_handles();                     \
        const int64_t layouts_before = level_live_layouts();                       \
        RUN_TEST(test_func, test_passed);                                          \
        if (sstable_live_handles() != handles_before)                              \
        {                                                                          \
            printf(BOLDRED "  %s leaked %lld sstable handles\n" RESET, #test_func, \
                   (long long)(sstable_live_handles() - handles_before));          \
            tests_failed++;                                                        \
        }                                                                          \
        if (level_live_layouts() != layouts_before)                                \
        {                                                                          \
            printf(BOLDRED "  %s leaked %lld level layouts\n" RESET, #test_func,   \
                   (long long)(level_live_layouts() - layouts_before));            \
            tests_failed++;                                                        \
        }                                                                          \
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
 * @param brief cleanup test directory with retry logic
 */
static inline void cleanup_test_dir(void)
{
    (void)remove_directory(TEST_DB_PATH);
}

/*
 * generate_random_key_value
 * @param brief generate random key-value pairs for testing
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

/* the two primitives a crash test needs that have no common spelling. unlike a guard that compiles
 * a test away, both arms here do the same thing, so nothing is hidden from either platform -- the
 * difference is only in which call spells it */
#ifdef _WIN32
#include <io.h>
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

/* re-run this test binary as a child process and wait for it to finish. a crash test needs a real
 * process to lose, and fork is not portable -- so the child re-enters main and dispatches on the
 * arguments it was given rather than inheriting the parent's address space. that is also the
 * sturdier shape where threads are involved, since a forked child of a threaded process inherits
 * only the forking thread
 * @param exe this binary's path, as main received it in argv[0]
 * @param flag the argument that puts the child into its child mode
 * @param phase which crash phase the child should run
 * @param nth the crash point within that phase, as a decimal string
 * @return 0 once the child has exited, or -1 if it could not be started
 */
/* the status a child reports when the exec itself failed, chosen as the shell's convention for a
 * command that could not be run so it cannot collide with a phase's own exit */
#define TEST_SPAWN_EXEC_FAILED 127

static UNUSED int test_spawn_self(const char *exe, const char *flag, const char *phase,
                                  const char *nth)
{
#ifdef _WIN32
    const char *const args[] = {exe, flag, phase, nth, NULL};
    return _spawnv(_P_WAIT, exe, args) == -1 ? -1 : 0;
#else
    const pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0)
    {
        char *const args[] = {(char *)exe, (char *)flag, (char *)phase, (char *)nth, NULL};
        execv(exe, args);
        _exit(TEST_SPAWN_EXEC_FAILED); /* only reached when the exec itself failed */
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);

    /* the child is meant to die abnormally, so its status says almost nothing -- except in the one
     * case where it never became the child at all. an exec that failed is reported rather than
     * swallowed, because a caller that cannot tell it apart from a crash goes on to read a database
     * nothing ever wrote and fails somewhere far away from the reason */
    if (WIFEXITED(status) && WEXITSTATUS(status) == TEST_SPAWN_EXEC_FAILED)
    {
        fprintf(stderr, "could not exec the child %s -- the crash phase never ran\n", exe);
        return -1;
    }
    return 0;
#endif
}

/* the identity of whatever file is at a path, so a test can tell one replaced by a rename from one
 * rewritten in place.
 *
 * st_ino carries this on posix. on windows it is always zero, whatever file is there, so a test
 * comparing it finds every file identical to every other -- which reads as "not replaced" and
 * passes an equality check for a reason that has nothing to do with the property under test. the
 * identity there is the volume file id, and it takes a handle to read
 * @param path the path to identify
 * @param out set to the identity on success
 * @return 0 on success, -1 when the path could not be opened or queried
 */
static UNUSED int test_file_identity(const char *path, unsigned long long *out)
{
#ifdef _WIN32
    /* every share mode, since the point is to identify a file another thread is committing to */
    HANDLE h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    BY_HANDLE_FILE_INFORMATION info;
    const BOOL ok = GetFileInformationByHandle(h, &info);
    CloseHandle(h);
    if (!ok) return -1;
    *out = ((unsigned long long)info.nFileIndexHigh << 32) | (unsigned long long)info.nFileIndexLow;
    return 0;
#else
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = (unsigned long long)st.st_ino;
    return 0;
#endif
}

/* push a stdio stream all the way to the device, so what it holds survives the process being lost
 * rather than sitting in a buffer that dies with it
 * @param f the stream to flush and sync
 */
static UNUSED void test_fsync_file(FILE *f)
{
    (void)fflush(f);
#ifdef _WIN32
    (void)_commit(_fileno(f));
#else
    (void)fsync(fileno(f));
#endif
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif /* __TEST_UTILS_H__ */