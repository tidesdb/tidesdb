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

int main(void)
{
    test_log_init();
    test_log_write();
    test_log_count_lines();
    return 0;
}