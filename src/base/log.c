/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "log.h"

#include <stdarg.h>

/* mode for opening and reopening the sink file, write-truncate so each fresh session starts clean
 */
#define TDB_LOG_FILE_MODE "w"

/* struct tm counts years from 1900 and months from zero, so a printed timestamp adds these back */
#define TDB_LOG_TM_YEAR_BASE  1900
#define TDB_LOG_TM_MONTH_BASE 1

/* the timestamp prints milliseconds, which is what a nanosecond clock reading divides down to */
#define TDB_LOG_NS_PER_MS 1000000

/* global log level, emits everything until tidesdb_open lowers it to the configured level */
_Atomic(int) _tidesdb_log_level = TDB_LOG_TRACE;

/* global sink file, NULL routes output to stderr */
FILE *_tidesdb_log_file = NULL;

/* global truncation threshold in bytes, 0 disables truncation */
size_t _tidesdb_log_truncate = 0;

/* global sink file path, used to reopen the file when truncation fires */
char _tidesdb_log_path[MAX_FILE_PATH_LENGTH] = {0};

/* serializes sink writes and the truncation reopen so a concurrent writer never touches a closed
 * file
 */
static pthread_mutex_t tidesdb_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void tidesdb_log_write(const int level, const char *file, const int line, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    const time_t sec = ts.tv_sec;
    struct tm tm_info;
    tdb_gmtime_r(&sec, &tm_info);

    const char *level_str = (level == TDB_LOG_TRACE)  ? "TRACE"
                            : (level == TDB_LOG_INFO) ? "INFO"
                            : (level == TDB_LOG_WARN) ? "WARN"
                                                      : "ERROR";

    pthread_mutex_lock(&tidesdb_log_mutex);

    FILE *log_out = _tidesdb_log_file ? _tidesdb_log_file : stderr;

    fprintf(log_out, "[%04d-%02d-%02dT%02d:%02d:%02d.%03dZ] [%s] %s:%d: ",
            tm_info.tm_year + TDB_LOG_TM_YEAR_BASE, tm_info.tm_mon + TDB_LOG_TM_MONTH_BASE,
            tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
            (int)(ts.tv_nsec / TDB_LOG_NS_PER_MS), level_str, file, line);

    va_list args;
    va_start(args, fmt);
    if (fmt) vfprintf(log_out, fmt, args);
    va_end(args);

    fprintf(log_out, "\n");

    if (_tidesdb_log_file)
    {
        fflush(_tidesdb_log_file);

        if (_tidesdb_log_truncate > 0 && _tidesdb_log_path[0] != '\0')
        {
            const long current_pos = ftell(_tidesdb_log_file);
            if (current_pos > 0 && (size_t)current_pos >= _tidesdb_log_truncate)
            {
                fclose(_tidesdb_log_file);
                _tidesdb_log_file = fopen(_tidesdb_log_path, TDB_LOG_FILE_MODE);
                if (_tidesdb_log_file)
                {
                    tdb_setlinebuf(_tidesdb_log_file);
                    fprintf(_tidesdb_log_file, "[LOG TRUNCATED - exceeded %zu bytes]\n",
                            _tidesdb_log_truncate);
                    fflush(_tidesdb_log_file);
                }
            }
        }
    }

    pthread_mutex_unlock(&tidesdb_log_mutex);
}

void tidesdb_log_set_sink(FILE *file, const size_t truncate_at, const char *path)
{
    pthread_mutex_lock(&tidesdb_log_mutex);
    _tidesdb_log_file = file;
    _tidesdb_log_truncate = truncate_at;
    if (truncate_at > 0 && path)
        snprintf(_tidesdb_log_path, sizeof(_tidesdb_log_path), "%s", path);
    else
        _tidesdb_log_path[0] = '\0';
    pthread_mutex_unlock(&tidesdb_log_mutex);
}

void tidesdb_log_close_sink(void)
{
    pthread_mutex_lock(&tidesdb_log_mutex);
    if (_tidesdb_log_file)
    {
        fflush(_tidesdb_log_file);
        fclose(_tidesdb_log_file);
    }
    _tidesdb_log_file = NULL;
    _tidesdb_log_truncate = 0;
    _tidesdb_log_path[0] = '\0';
    pthread_mutex_unlock(&tidesdb_log_mutex);
}
