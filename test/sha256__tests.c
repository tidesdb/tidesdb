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

#define BENCH_SHA256_OPS 1000000

/* benchmark one-shot sha256_hash on 1M small messages */
static void benchmark_sha256_oneshot(void)
{
    const size_t msg_size = 64;
    uint8_t msg[64];
    uint8_t digest[SHA256_DIGEST_SIZE];

    for (size_t i = 0; i < msg_size; i++) msg[i] = (uint8_t)(i & 0xff);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_SHA256_OPS; i++)
    {
        msg[0] = (uint8_t)(i & 0xff);
        msg[1] = (uint8_t)((i >> 8) & 0xff);
        sha256_hash(msg, msg_size, digest);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = BENCH_SHA256_OPS / elapsed;
    double mb_per_sec = (BENCH_SHA256_OPS * (double)msg_size) / (elapsed * 1024 * 1024);

    printf(CYAN
           "\n  One-shot %d-byte messages: %.2f M hashes/sec (%.2f MB/s, %.3f seconds)\n" RESET,
           (int)msg_size, ops_per_sec / 1e6, mb_per_sec, elapsed);
}

/* benchmark streaming throughput on large contiguous data (256 MB) */
static void benchmark_sha256_throughput(void)
{
    const size_t chunk_size = 4096;
    const size_t total_size = 256 * 1024 * 1024; /* 256 MB */
    const size_t num_chunks = total_size / chunk_size;

    uint8_t *chunk = malloc(chunk_size);
    ASSERT_TRUE(chunk != NULL);
    for (size_t i = 0; i < chunk_size; i++) chunk[i] = (uint8_t)(i & 0xff);

    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    sha256_init(&ctx);
    for (size_t i = 0; i < num_chunks; i++)
    {
        sha256_update(&ctx, chunk, chunk_size);
    }
    sha256_final(&ctx, digest);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double mb_per_sec = (total_size / (1024.0 * 1024.0)) / elapsed;

    printf(CYAN "  Streaming %zu MB in %zu-byte chunks: %.2f MB/s (%.3f seconds)\n" RESET,
           total_size / (1024 * 1024), chunk_size, mb_per_sec, elapsed);

    free(chunk);
}

/* benchmark sha256_hash across a range of message sizes to show how throughput scales */
static void benchmark_sha256_multisize(void)
{
    static const size_t sizes[] = {16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576};
    static const int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

    printf(CYAN "\n  %-12s  %14s  %12s  %10s\n" RESET, "msg size", "hashes/sec", "MB/s", "seconds");
    printf("  %-12s  %14s  %12s  %10s\n", "--------", "----------", "----", "-------");

    for (int s = 0; s < num_sizes; s++)
    {
        const size_t msg_size = sizes[s];

        /* target ~1 second of work per size so short messages don't finish instantly
         * and large messages don't take forever */
        int ops = (int)(256 * 1024 * 1024 / (msg_size > 0 ? msg_size : 1));
        if (ops < 4) ops = 4;
        if (ops > 2000000) ops = 2000000;

        uint8_t *msg = malloc(msg_size);
        ASSERT_TRUE(msg != NULL);
        for (size_t i = 0; i < msg_size; i++) msg[i] = (uint8_t)(i & 0xff);

        uint8_t digest[SHA256_DIGEST_SIZE];

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < ops; i++)
        {
            /* vary first two bytes so the compiler can't cache the result */
            msg[0] = (uint8_t)(i & 0xff);
            if (msg_size > 1) msg[1] = (uint8_t)((i >> 8) & 0xff);
            sha256_hash(msg, msg_size, digest);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double hashes_per_sec = ops / elapsed;
        double mb_per_sec = (ops * (double)msg_size) / (elapsed * 1024.0 * 1024.0);

        /* format message size with unit */
        char size_label[32];
        if (msg_size >= 1048576)
            snprintf(size_label, sizeof(size_label), "%zu MB", msg_size / 1048576);
        else if (msg_size >= 1024)
            snprintf(size_label, sizeof(size_label), "%zu KB", msg_size / 1024);
        else
            snprintf(size_label, sizeof(size_label), "%zu B", msg_size);

        printf("  %-12s  %11.2f K  %9.2f  %10.3f\n", size_label, hashes_per_sec / 1e3, mb_per_sec,
               elapsed);

        free(msg);
    }
}

/* benchmark sha256_hex on 1M small messages */
static void benchmark_sha256_hex(void)
{
    const size_t msg_size = 64;
    uint8_t msg[64];
    char hex[SHA256_HEX_SIZE];

    for (size_t i = 0; i < msg_size; i++) msg[i] = (uint8_t)(i & 0xff);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < BENCH_SHA256_OPS; i++)
    {
        msg[0] = (uint8_t)(i & 0xff);
        msg[1] = (uint8_t)((i >> 8) & 0xff);
        sha256_hex(msg, msg_size, hex);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = BENCH_SHA256_OPS / elapsed;

    printf(CYAN "  Hex digest %d-byte messages: %.2f M hashes/sec (%.3f seconds)\n" RESET,
           (int)msg_size, ops_per_sec / 1e6, elapsed);
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
    RUN_TEST(benchmark_sha256_oneshot, tests_passed);
    RUN_TEST(benchmark_sha256_throughput, tests_passed);
    RUN_TEST(benchmark_sha256_multisize, tests_passed);
    RUN_TEST(benchmark_sha256_hex, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
