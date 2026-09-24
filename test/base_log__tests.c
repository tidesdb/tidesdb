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

#ifdef _WIN32
#include <fcntl.h>
#endif

/* capacity asked of the pipe where the platform takes one, and a message several times any pipe's
 * capacity so writing it blocks until the reader drains */
#define TEST_LOG_PIPE_BYTES     4096
#define TEST_LOG_BLOCKING_BYTES (1024 * 1024)

/* how much of the pipe one read takes */
#define TEST_LOG_READ_BYTES 65536

/* the blocking writer is polled for until it starts, and then given long enough to take the sink
 * and park in its write */
#define TEST_LOG_POLL_US     1000
#define TEST_LOG_START_POLLS 10000
#define TEST_LOG_SETTLE_US   200000

/* the source file every line in this test claims, the line that must be dropped, the line written
 * once the sink moves, and the marker that has to precede it */
#define TEST_LOG_SRC_FILE       "unit.c"
#define TEST_LOG_DROPPED_LINE   "dropped line"
#define TEST_LOG_AFTER_LINE     "after the sink moved"
#define TEST_LOG_DROPPED_MARKER "LOG DROPPED - 1 lines"

/**
 * test_log_blocker_t
 * a writer thread's message and the two points it reports passing
 * @param message the line to log, large enough that writing it blocks on an undrained pipe
 * @param started set before the writer calls into the log
 * @param finished set once its log call has returned
 */
typedef struct
{
    const char *message;
    _Atomic(int) started;
    _Atomic(int) finished;
} test_log_blocker_t;

/**
 * test_log_pipe_open
 * open an anonymous pipe on whichever call the platform names for it
 * @param fds receives the read end then the write end
 * @return 0 on success, -1 on failure
 */
static int test_log_pipe_open(int fds[2])
{
#ifdef _WIN32
    return _pipe(fds, TEST_LOG_PIPE_BYTES, _O_BINARY);
#else
    return pipe(fds);
#endif
}

/**
 * test_log_pipe_read
 * read what is available from the pipe's read end, waiting for at least one byte
 * @param fd the read end
 * @param buf destination buffer
 * @param cap bytes buf can take
 * @return bytes read, 0 at end of stream, -1 on failure
 */
static long test_log_pipe_read(const int fd, char *buf, const size_t cap)
{
#ifdef _WIN32
    return (long)_read(fd, buf, (unsigned int)cap);
#else
    return (long)read(fd, buf, cap);
#endif
}

/**
 * test_log_pipe_close
 * close one end of the pipe
 * @param fd the end to close
 * @return 0 on success, -1 on failure
 */
static int test_log_pipe_close(const int fd)
{
#ifdef _WIN32
    return _close(fd);
#else
    return close(fd);
#endif
}

/**
 * test_log_pipe_writer
 * wrap the pipe's write end in a stream the log sink can take
 * @param fd the write end, owned by the returned stream
 * @return the stream, or NULL on failure
 */
static FILE *test_log_pipe_writer(const int fd)
{
#ifdef _WIN32
    return _fdopen(fd, "wb");
#else
    return fdopen(fd, "wb");
#endif
}

/**
 * test_log_blocking_writer
 * log the blocker's message from its own thread, which parks in the write while nothing drains
 * @param arg the test_log_blocker_t
 * @return NULL
 */
static void *test_log_blocking_writer(void *arg)
{
    test_log_blocker_t *b = arg;
    atomic_store(&b->started, 1);
    tidesdb_log_write(TDB_LOG_INFO, TEST_LOG_SRC_FILE, __LINE__, "%s", b->message);
    atomic_store(&b->finished, 1);
    return NULL;
}

/* a writer parked on a sink nobody drains holds the sink, and another thread's line is dropped
 * after a bounded wait rather than parking behind it, then reported once the sink moves again */
void test_log_blocked_sink_does_not_park_other_writers(void)
{
    int fds[2];
    ASSERT_EQ(test_log_pipe_open(fds), 0);
    FILE *w = test_log_pipe_writer(fds[1]);
    ASSERT_TRUE(w != NULL);
    tidesdb_log_set_sink(w, 0, NULL);

    char *big = malloc(TEST_LOG_BLOCKING_BYTES + 1);
    ASSERT_TRUE(big != NULL);
    memset(big, 'x', TEST_LOG_BLOCKING_BYTES);
    big[TEST_LOG_BLOCKING_BYTES] = '\0';

    test_log_blocker_t blocker = {.message = big, .started = 0, .finished = 0};
    pthread_t t;
    ASSERT_EQ(pthread_create(&t, NULL, test_log_blocking_writer, &blocker), 0);
    for (int i = 0; i < TEST_LOG_START_POLLS && !atomic_load(&blocker.started); i++)
        usleep(TEST_LOG_POLL_US);
    ASSERT_TRUE(atomic_load(&blocker.started));
    usleep(TEST_LOG_SETTLE_US);
    ASSERT_TRUE(!atomic_load(&blocker.finished));

    /* the call under test, it must return while the blocker still holds the sink */
    tidesdb_log_write(TDB_LOG_INFO, TEST_LOG_SRC_FILE, __LINE__, TEST_LOG_DROPPED_LINE);
    ASSERT_TRUE(!atomic_load(&blocker.finished));

    /* drain the blocker's line so it finishes. every read takes at least a byte, so the drain is
     * bounded by the message length */
    char buf[TEST_LOG_READ_BYTES];
    size_t seen = 0;
    for (size_t i = 0; i <= TEST_LOG_BLOCKING_BYTES && seen <= TEST_LOG_BLOCKING_BYTES; i++)
    {
        const long n = test_log_pipe_read(fds[0], buf, sizeof(buf));
        ASSERT_TRUE(n > 0);
        seen += (size_t)n;
    }
    ASSERT_EQ(pthread_join(t, NULL), 0);

    /* one more line, read to its end, carries the marker for the line that was dropped */
    tidesdb_log_write(TDB_LOG_INFO, TEST_LOG_SRC_FILE, __LINE__, TEST_LOG_AFTER_LINE);
    size_t len = 0;
    buf[0] = '\0';
    while (strstr(buf, TEST_LOG_AFTER_LINE) == NULL && len < sizeof(buf) - 1)
    {
        const long n = test_log_pipe_read(fds[0], buf + len, sizeof(buf) - 1 - len);
        ASSERT_TRUE(n > 0);
        len += (size_t)n;
        buf[len] = '\0';
    }
    ASSERT_TRUE(strstr(buf, TEST_LOG_DROPPED_MARKER) != NULL);
    ASSERT_TRUE(strstr(buf, TEST_LOG_DROPPED_LINE) == NULL);

    tidesdb_log_close_sink();
    ASSERT_EQ(test_log_pipe_close(fds[0]), 0);
    free(big);
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
    RUN_TEST(test_log_blocked_sink_does_not_park_other_writers, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
