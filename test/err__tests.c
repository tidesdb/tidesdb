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

#include "../src/err.h"
#include "test_macros.h"

void test_tidesdb_err_new()
{
    tidesdb_err_t *e = tidesdb_err_new(1, "test");
    assert(e->code == 1);

    assert(strcmp(e->message, "test") == 0);

    (void)tidesdb_err_free(e);
    printf(GREEN "test_tidesdb_err_new passed\n" RESET);
}

void test_tidesdb_err_from_code()
{
    tidesdb_err_t *e = tidesdb_err_from_code(TIDESDB_ERR_INVALID_DB);
    assert(e->code == 0);

    assert(strcmp(e->message, tidesdb_err_messages[TIDESDB_ERR_INVALID_DB].message) == 0);

    (void)tidesdb_err_free(e);
    printf(GREEN "test_tidesdb_err_from_code passed\n" RESET);
}

int main(void)
{
    test_tidesdb_err_new();
    test_tidesdb_err_from_code();
    return 0;
}