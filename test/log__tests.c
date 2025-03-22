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
#include <assert.h>
#include <stdio.h>

#include "../src/compat.h"
#include "../src/log.h"
#include "test_macros.h"

void test_log_init()
{
    log_t *log = NULL;
    int result = log_init(&log, "test.log", 10);
    assert(result == 0);
    assert(log->file != NULL);
    assert(log->truncate_at == 10);
    (void)log_close(log);
    (void)remove("test.log");
    printf(GREEN "test_log_init passed\n" RESET);
}

void test_log_write()
{
    log_t *log = NULL;
    (void)log_init(&log, "test.log", -1);
    int result = log_write(log, "This is a test message");
    assert(result == 0);
    (void)log_close(log);
    (void)remove("test.log");
    printf(GREEN "test_log_write passed\n" RESET);
}

void test_log_count_lines()
{
    log_t *log = NULL;
    assert(log_init(&log, "test.log", -1) == 0);
    assert(log_write(log, "Line 1") == 0);
    assert(log_write(log, "Line 2") == 0);
    assert(log_write(log, "Line 3") == 0);
    int lines = log_count_lines(log);
    assert(lines == 3);
    (void)log_close(log);
    (void)remove("test.log");
    printf(GREEN "test_log_count_lines passed\n" RESET);
}

void test_log_truncate_realtime()
{
    log_t *log = NULL;
    const char *log_filename = "truncate_test.log";
    const int max_lines = 5; /* we initially set a small number for easier testing **/

    /* we init the log with truncation enabled */
    assert(log_init(&log, log_filename, max_lines) == 0);
    assert(log->truncate_at == max_lines);
    assert(log->cached_lines == 0);

    printf("Writing %d lines to log...\n", max_lines);

    /* now we will write exactly max_lines entries */
    for (int i = 0; i < max_lines; i++)
    {
        assert(log_write(log, "Line %d", i + 1) == 0);
    }

    /* we should have an equal number of cached lines */
    assert(log->cached_lines == max_lines);

    /* verify actual lines in file */
    int lines = log_count_lines(log);
    assert(lines == max_lines);
    printf("After writing %d lines, file contains %d lines\n", max_lines, lines);

    /* now we will write one more line to trigger truncation */
    printf("Writing one more line to trigger truncation...\n");
    assert(log_write(log, "Line %d - should trigger truncation", max_lines + 1) == 0);

    /* we verify cached_lines is still at max_lines */
    assert(log->cached_lines == max_lines);

    /* we verify actual lines in file */
    lines = log_count_lines(log);
    assert(lines == max_lines);
    printf("After truncation, file contains %d lines\n", lines);

    /* check if the first line was truncated by reading the file content */
    char line[BUFFER_SIZE];
    rewind(log->file);

    /* the first line should now be "Line 2" (not "Line 1") */
    fgets(line, sizeof(line), log->file);
    printf("First line after truncation: %s", line);
    assert(strstr(line, "Line 2") != NULL);

    /* we will just add several more lines to test multiple truncations */
    printf("Writing more lines to test multiple truncations...\n");
    for (int i = 0; i < max_lines; i++)
    {
        assert(log_write(log, "Extra line %d", i + 1) == 0);
    }

    lines = log_count_lines(log);
    assert(lines == max_lines);

    /* we check the first line again - should now be an "Extra line" */
    rewind(log->file);
    fgets(line, sizeof(line), log->file);
    printf("First line after multiple truncations: %s", line);
    assert(strstr(line, "Extra line") != NULL);

    (void)log_close(log);
    (void)remove(log_filename);
    printf(GREEN "test_log_truncate_realtime passed\n" RESET);
}

int main(void)
{
    test_log_init();
    test_log_write();
    test_log_count_lines();
    test_log_truncate_realtime();
    return 0;
}