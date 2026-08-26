/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <string.h>

#include "../src/base/encoding/serialization.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a value encoded then decoded within a sufficient bound reproduces itself and the byte counts
 * agree */
void test_varint_roundtrip(void)
{
    const uint64_t values[] = {0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 300, 1000000, UINT64_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        uint8_t buf[10];
        const int wrote = encode_varint(buf, values[i]);
        ASSERT_TRUE(wrote >= 1 && wrote <= 10);

        uint64_t out = 0;
        const int read = decode_varint(buf, &out, wrote);
        ASSERT_EQ(read, wrote);
        ASSERT_TRUE(out == values[i]);
    }
}

/* small values take one byte and the continuation bit rolls over at 0x80 */
void test_varint_byte_counts(void)
{
    uint8_t buf[10];
    ASSERT_EQ(encode_varint(buf, 0), 1);
    ASSERT_EQ(encode_varint(buf, 0x7F), 1);
    ASSERT_EQ(encode_varint(buf, 0x80), 2);
    ASSERT_EQ(encode_varint(buf, UINT64_MAX), 10);
}

/* a non-positive bound and a truncated buffer both fail and still leave *value defined at 0 */
void test_varint_decode_bounds(void)
{
    uint8_t buf[10];
    const int wrote = encode_varint(buf, UINT64_MAX); /* 10 bytes, all continuation but the last */

    uint64_t out = 12345;
    ASSERT_EQ(decode_varint(buf, &out, 0), -1);
    ASSERT_TRUE(out == 0);

    out = 12345;
    ASSERT_EQ(decode_varint(buf, &out, wrote - 1), -1); /* not enough bytes for the full varint */
    ASSERT_TRUE(out == 0);
}

/* be32 is big-endian and round-trips */
void test_be32(void)
{
    uint8_t buf[4];
    tdb_encode_be32(0x01020304u, buf);
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[1], 0x02);
    ASSERT_EQ(buf[2], 0x03);
    ASSERT_EQ(buf[3], 0x04);
    ASSERT_TRUE(tdb_decode_be32(buf) == 0x01020304u);
    ASSERT_TRUE(tdb_decode_be32((const uint8_t *)"\xff\xff\xff\xff") == 0xFFFFFFFFu);
}

/* a prefixed key carries the big-endian cf index then the verbatim key, and reports the total size
 */
void test_build_prefixed_key(void)
{
    const uint8_t key[] = {'a', 'b', 'c'};
    uint8_t out[TDB_CF_PREFIX_SIZE + sizeof(key)];

    const size_t total = tdb_build_prefixed_key(0x00000102u, key, sizeof(key), out);
    ASSERT_TRUE(total == TDB_CF_PREFIX_SIZE + sizeof(key));
    ASSERT_TRUE(tdb_decode_be32(out) == 0x00000102u);
    ASSERT_TRUE(memcmp(out + TDB_CF_PREFIX_SIZE, key, sizeof(key)) == 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_varint_roundtrip, tests_passed);
    RUN_TEST(test_varint_byte_counts, tests_passed);
    RUN_TEST(test_varint_decode_bounds, tests_passed);
    RUN_TEST(test_be32, tests_passed);
    RUN_TEST(test_build_prefixed_key, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
