/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_LOG_H__
#define __TIDESDB_BASE_LOG_H__

#include <time.h>

#include "../compat.h"
#include "db.h" /* tidesdb_log_level_t and the public TDB_LOG_* severities, resolved from include/ */
#include "io/block_manager.h" /* MAX_FILE_PATH_LENGTH sizes the sink path buffer */

/* the TDB_LOG_* level enum is public and comes from db.h; the sink below is internal to the engine.
 * these globals back the sink -- tidesdb_open may rewrite them at startup, and the TDB_DEBUG_LOG
 * macro gates on the level lock-free so a disabled line costs a single atomic load. */
extern _Atomic(int) _tidesdb_log_level; /* minimum severity to emit, default TDB_LOG_TRACE */
extern FILE *_tidesdb_log_file;         /* sink file, NULL routes output to stderr */
extern size_t _tidesdb_log_truncate;    /* truncate the sink file past this many bytes, 0 off */
extern char _tidesdb_log_path[MAX_FILE_PATH_LENGTH]; /* sink file path, reopened on truncation */

/**
 * tidesdb_log_write
 * write one timestamped line to the configured sink, reopening and truncating the file when it
 * grows past the configured threshold
 * @param level severity, one of the TDB_LOG_* levels from db.h
 * @param file source file name, typically __FILE__
 * @param line source line number, typically __LINE__
 * @param fmt printf-style format string
 * @param ... format arguments
 */
void tidesdb_log_write(int level, const char *file, int line, const char *fmt, ...);

/**
 * tidesdb_log_set_sink
 * publish the log sink file and its truncation policy under the sink lock, so a concurrent writer
 * never observes a half-updated file and path pair; pass a NULL file to route output back to stderr
 * @param file sink file to log to, or NULL for stderr
 * @param truncate_at truncate the sink file past this many bytes, 0 to never truncate
 * @param path sink file path used to reopen on truncation, consulted only when truncate_at is
 * nonzero
 */
void tidesdb_log_set_sink(FILE *file, size_t truncate_at, const char *path);

/**
 * tidesdb_log_close_sink
 * flush and close the sink file under the sink lock and route output back to stderr, a no-op when
 * the sink is already stderr
 */
void tidesdb_log_close_sink(void);

/* gate a log call on the configured level before touching its arguments, so a suppressed line costs
 * one relaxed atomic load and never formats its message. the level is read once into a local rather
 * than twice in the condition -- a second load could also disagree with the first, which on a
 * concurrent change to the level would test the two halves of the gate against different values.
 * relaxed is the right ordering for a gate that publishes nothing */
#define TDB_DEBUG_LOG(level, fmt, ...)                                                            \
    do                                                                                            \
    {                                                                                             \
        const int tdb_log_gate = atomic_load_explicit(&_tidesdb_log_level, memory_order_relaxed); \
        if (tdb_log_gate != TDB_LOG_NONE && (level) >= tdb_log_gate)                              \
            tidesdb_log_write((level), __FILE__, __LINE__, fmt, ##__VA_ARGS__);                   \
    } while (0)

/* the shortest interval between two lines from a throttled site, in seconds. a per-flush or
 * per-merge line is one per unit of work, which under sustained load is thousands of writes through
 * one process-wide mutex to a stream that can block -- and a caller holding that mutex holds up
 * every other thread that logs. the record of what happened is kept, at a rate a reader can use */
#define TDB_LOG_THROTTLE_SECS 1

/* emit at most one line per TDB_LOG_THROTTLE_SECS from this site, counting what was suppressed and
 * reporting it on the next line that gets through. the state is per-call-site and static, so a site
 * throttles across every thread that reaches it, which is the point -- the cost being avoided is
 * the shared mutex, not this thread's turn at it. the count is relaxed throughout; a line lost to a
 * race on the timestamp is one line, and the suppressed total says so either way */
#define TDB_DEBUG_LOG_THROTTLED(level, fmt, ...)                                                 \
    do                                                                                           \
    {                                                                                            \
        static _Atomic(int64_t) tdb_log_last = 0;                                                \
        static _Atomic(uint64_t) tdb_log_skipped = 0;                                            \
        const int64_t tdb_log_now = (int64_t)time(NULL);                                         \
        int64_t tdb_log_seen = atomic_load_explicit(&tdb_log_last, memory_order_relaxed);        \
        if (tdb_log_now - tdb_log_seen >= TDB_LOG_THROTTLE_SECS &&                               \
            atomic_compare_exchange_strong_explicit(&tdb_log_last, &tdb_log_seen, tdb_log_now,   \
                                                    memory_order_relaxed, memory_order_relaxed)) \
        {                                                                                        \
            const unsigned long long tdb_log_missed =                                            \
                (unsigned long long)atomic_exchange_explicit(&tdb_log_skipped, 0,                \
                                                             memory_order_relaxed);              \
            if (tdb_log_missed == 0)                                                             \
                TDB_DEBUG_LOG(level, fmt, ##__VA_ARGS__);                                        \
            else                                                                                 \
                TDB_DEBUG_LOG(level, fmt " (%llu more since the last of these)", ##__VA_ARGS__,  \
                              tdb_log_missed);                                                   \
        }                                                                                        \
        else                                                                                     \
            atomic_fetch_add_explicit(&tdb_log_skipped, 1, memory_order_relaxed);                \
    } while (0)

#endif /* __TIDESDB_BASE_LOG_H__ */
