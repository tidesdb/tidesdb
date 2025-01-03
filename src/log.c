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
#include "log.h"

int log_init(log_t **log, const char *filename, int truncate_at)
{
    *log = malloc(sizeof(log_t));
    if (*log == NULL) return -1;

    /* open log in append mode */
    (*log)->file = fopen(filename, "a+");
    if (!(*log)->file)
    {
        free(*log);
        *log = NULL;
        return -1;
    }
    /* set truncate_at */
    (*log)->truncate_at = truncate_at;

    /* initialize the lock */
    if (pthread_mutex_init(&(*log)->lock, NULL) != 0)
    {
        fclose((*log)->file);
        free(*log);
        *log = NULL;
        return -1;
    }

    /* check if we need to truncate the log */
    if (truncate_at != -1)
    {
        /* lock the log */
        if (pthread_mutex_lock(&(*log)->lock) != 0)
        {
            pthread_mutex_destroy(&(*log)->lock);
            fclose((*log)->file);
            free(*log);
            *log = NULL;
            return -1;
        }

        /* get the number of lines in the log */
        int lines = log_count_lines(*log);
        if (lines > truncate_at)
        {
            /* we need to truncate the log */
            FILE *tmp = fopen("tmp.log", "w");
            if (!tmp)
            {
                pthread_mutex_unlock(&(*log)->lock);
                pthread_mutex_destroy(&(*log)->lock);
                fclose((*log)->file);
                free(*log);
                *log = NULL;
                return -1;
            }
            /* we read the log line by line */
            char line[BUFFER_SIZE];
            int i = 0;
            rewind((*log)->file);
            while (fgets(line, sizeof(line), (*log)->file))
            {
                /* we write the line to the tmp file */
                if (i >= lines - truncate_at) fprintf(tmp, "%s", line);
                i++;
            }
            /* we close the files */
            fclose((*log)->file);
            fclose(tmp);
            /* we remove the old log */
            remove(filename);
            /* we rename the tmp log */
            rename("tmp.log", filename);
            /* we open the log in read/append mode */
            (*log)->file = fopen(filename, "a+");
            if (!(*log)->file)
            {
                pthread_mutex_unlock(&(*log)->lock);
                pthread_mutex_destroy(&(*log)->lock);
                free(*log);
                *log = NULL;
                return -1;
            }
        }

        /* unlock the log */
        pthread_mutex_unlock(&(*log)->lock);
    }

    return 0;
}

int log_write(log_t *log, const char *format, ...)
{
    if (!log) return -1; /* we check if the log is set */

    /* we check if the log file is set */
    if (!log->file) return -1;

    /* we lock the log */
    (void)pthread_mutex_lock(&log->lock);

    /* we get the current time */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[20]; /* yyyy-mm-dd hh:mm:ss */
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    /* format the message */
    va_list args;
    char buffer[BUFFER_SIZE];
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    /* we write log message with timestamp and newline */
    fprintf(log->file, "[%s] %s\n", time_str, buffer);
    fflush(log->file);        /* flush the buffer */
    fsync(fileno(log->file)); /* fsync the file */

    /* unlock the log */
    (void)pthread_mutex_unlock(&log->lock);

    return 0;
}

int log_count_lines(log_t *log)
{
    if (!log->file) return -1;

    rewind(log->file);

    int lines = 0;
    char line[BUFFER_SIZE];

    while (fgets(line, sizeof(line), log->file) != NULL)
    {
        lines++;
    }

    return lines;
}

int log_close(log_t *log)
{
    /* we check if the log file is set */
    if (!log->file) return -1;

    /* we free the lock */
    (void)pthread_mutex_destroy(&log->lock);

    /* we close the log file */
    (void)fclose(log->file);
    free(log);

    return 0;
}