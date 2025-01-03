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
#ifndef __LOG_H__
#define __LOG_H__
#include <stdarg.h>

#include "compat.h"

#define BUFFER_SIZE 1024 /* buffer size for log messages */

/* format [yyyy-mm-dd hh:mm:ss] message \n */

/*
 * log_t
 * the log struct
 * @param file the file to write to
 * @param truncate_at the size to truncate the log at or -1 to disable truncation
 * @param lock the lock for the log
 */
typedef struct
{
    FILE *file;
    int truncate_at; /* can be -1 to disable truncation */
    pthread_mutex_t lock;
} log_t;

/*
 * log_init
 * initialize the log
 * @param log the log to initialize
 * @param filename the filename of the log
 * @param truncate_at the size to truncate the log at or -1 to disable truncation
 */
int log_init(log_t **log, const char *filename, int truncate_at);

/*
 * log_write
 * write a message to the log
 * @param log the log to write to
 * @param format the format of the message
 * @return 0 on success, -1 on failure
 */
int log_write(log_t *log, const char *format, ...);

/*
 * log_count_lines
 * count the number of lines in the log
 * @param log the log to count lines in
 * @return the number of lines in the log
 */
int log_count_lines(log_t *log);

/*
 * log_close
 * close the log
 * @param log the log to close
 * @return 0 on success, -1 on failure
 */
int log_close(log_t *log);

#endif /* __LOG_H__ */