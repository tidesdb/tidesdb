/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/base/errors.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* every defined code maps to a non-empty string and success reads as "success" */
void test_strerror_known_codes(void)
{
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_SUCCESS), "success") == 0);

    const int codes[] = {TDB_ERR_MEMORY,     TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND,
                         TDB_ERR_IO,         TDB_ERR_CORRUPTION,   TDB_ERR_EXISTS,
                         TDB_ERR_CONFLICT,   TDB_ERR_TOO_LARGE,    TDB_ERR_MEMORY_LIMIT,
                         TDB_ERR_INVALID_DB, TDB_ERR_LOCKED,       TDB_ERR_READONLY,
                         TDB_ERR_BUSY,       TDB_ERR_TXN_EXPIRED};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
    {
        const char *s = tidesdb_strerror(codes[i]);
        ASSERT_TRUE(s != NULL);
        ASSERT_TRUE(s[0] != '\0');
    }
}

/* the sentinel unknown code and any out-of-range code both read as "unknown error" */
void test_strerror_unknown_codes(void)
{
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_ERR_UNKNOWN), "unknown error") == 0);
    ASSERT_TRUE(strcmp(tidesdb_strerror(-9999), "unknown error") == 0);
    ASSERT_TRUE(strcmp(tidesdb_strerror(12345), "unknown error") == 0);
}

/* the mapper never returns NULL for any int, so a log site can always print it */
void test_strerror_never_null(void)
{
    for (int c = -64; c <= 64; c++) ASSERT_TRUE(tidesdb_strerror(c) != NULL);
}

/* distinct real codes carry distinct messages, so a reader can tell failures apart */
void test_strerror_distinct_messages(void)
{
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_ERR_NOT_FOUND), tidesdb_strerror(TDB_ERR_CONFLICT)) !=
                0);
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_ERR_BUSY), tidesdb_strerror(TDB_ERR_LOCKED)) != 0);
    ASSERT_TRUE(strcmp(tidesdb_strerror(TDB_SUCCESS), tidesdb_strerror(TDB_ERR_IO)) != 0);
}

/* every public code carries a real message. a code added to db.h without a matching arm in the
 * table would fall through to "unknown error" and describe nothing, which is invisible until
 * someone reads a log and finds an error that will not say what it is */
void test_strerror_covers_every_public_code(void)
{
    static const int codes[] = {TDB_SUCCESS,          TDB_ERR_MEMORY,      TDB_ERR_INVALID_ARGS,
                                TDB_ERR_NOT_FOUND,    TDB_ERR_IO,          TDB_ERR_CORRUPTION,
                                TDB_ERR_EXISTS,       TDB_ERR_CONFLICT,    TDB_ERR_TOO_LARGE,
                                TDB_ERR_MEMORY_LIMIT, TDB_ERR_INVALID_DB,  TDB_ERR_LOCKED,
                                TDB_ERR_READONLY,     TDB_ERR_TXN_EXPIRED, TDB_ERR_NO_SPACE};

    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
    {
        const char *msg = tidesdb_strerror(codes[i]);
        ASSERT_TRUE(msg != NULL);
        /* TDB_ERR_UNKNOWN is the one code whose message is legitimately "unknown error", and it is
         * deliberately not in the list above -- everything else describing itself that way means a
         * missing arm rather than an unknown code */
        ASSERT_TRUE(strcmp(msg, "unknown error") != 0);
    }
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_strerror_known_codes, tests_passed);
    RUN_TEST(test_strerror_unknown_codes, tests_passed);
    RUN_TEST(test_strerror_never_null, tests_passed);
    RUN_TEST(test_strerror_distinct_messages, tests_passed);
    RUN_TEST(test_strerror_covers_every_public_code, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
