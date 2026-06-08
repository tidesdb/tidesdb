/**
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

#include "../src/sha256.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* render raw bytes as a lowercase hex string */
static void to_hex(const uint8_t *d, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++)
    {
        out[i * 2] = h[d[i] >> 4];
        out[i * 2 + 1] = h[d[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* FIPS 180-4 / NIST known-answer vectors for the empty string and "abc" */
static void test_sha256_empty(void)
{
    char hex[SHA256_HEX_SIZE];
    sha256_hex("", 0, hex);
    ASSERT_EQ(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), 0);
}

static void test_sha256_abc(void)
{
    char hex[SHA256_HEX_SIZE];
    sha256_hex("abc", 3, hex);
    ASSERT_EQ(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), 0);
}

/* 448-bit message that spans two compression blocks */
static void test_sha256_two_block(void)
{
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[SHA256_HEX_SIZE];
    sha256_hex(msg, strlen(msg), hex);
    ASSERT_EQ(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), 0);
}

/* the classic one-million-'a' vector, fed in small chunks to exercise streaming + block carry */
static void test_sha256_million_a_streaming(void)
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    for (int i = 0; i < 1000; i++) sha256_update(&ctx, chunk, sizeof(chunk));
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, digest);
    char hex[SHA256_HEX_SIZE];
    to_hex(digest, SHA256_DIGEST_SIZE, hex);
    ASSERT_EQ(strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), 0);
}

/* byte-at-a-time streaming must equal the one-shot digest of the same input */
static void test_sha256_streaming_matches_oneshot(void)
{
    const char *msg = "the quick brown fox jumps over the lazy dog, then does it again 0123456789";
    const size_t n = strlen(msg);

    uint8_t one[SHA256_DIGEST_SIZE];
    sha256_hash(msg, n, one);

    sha256_ctx ctx;
    sha256_init(&ctx);
    for (size_t i = 0; i < n; i++) sha256_update(&ctx, (const uint8_t *)msg + i, 1);
    uint8_t streamed[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, streamed);

    ASSERT_EQ(memcmp(one, streamed, SHA256_DIGEST_SIZE), 0);
}

/* sha256_hex must match the hex rendering of sha256_hash for the same input */
static void test_sha256_hex_matches_hash(void)
{
    const char *msg = "tidesdb";
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_hash(msg, strlen(msg), digest);
    char from_hash[SHA256_HEX_SIZE];
    to_hex(digest, SHA256_DIGEST_SIZE, from_hash);

    char from_hex[SHA256_HEX_SIZE];
    sha256_hex(msg, strlen(msg), from_hex);

    ASSERT_EQ(strcmp(from_hash, from_hex), 0);
}

/* a full 64-byte (one exact block) input exercises the no-room-for-length padding branch */
static void test_sha256_exact_block(void)
{
    uint8_t buf[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) buf[i] = (uint8_t)i;
    char hex[SHA256_HEX_SIZE];
    sha256_hex(buf, sizeof(buf), hex);
    ASSERT_EQ(strcmp(hex, "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"), 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);

    RUN_TEST(test_sha256_empty, tests_passed);
    RUN_TEST(test_sha256_abc, tests_passed);
    RUN_TEST(test_sha256_two_block, tests_passed);
    RUN_TEST(test_sha256_million_a_streaming, tests_passed);
    RUN_TEST(test_sha256_streaming_matches_oneshot, tests_passed);
    RUN_TEST(test_sha256_hex_matches_hash, tests_passed);
    RUN_TEST(test_sha256_exact_block, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
