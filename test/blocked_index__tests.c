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

#include "../src/block_manager.h"
#include "../src/blocked_index.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* an append-only in-memory backing store standing in for the sstable's block-managed file */
typedef struct
{
    uint8_t *buf;
    size_t len;
    size_t cap;
} bi_store_t;

static int store_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset)
{
    bi_store_t *s = ctx;
    if (s->len + size > s->cap)
    {
        size_t ncap = s->cap ? s->cap * 2 : 4096;
        while (ncap < s->len + size) ncap *= 2;
        uint8_t *nb = realloc(s->buf, ncap);
        if (!nb) return -1;
        s->buf = nb;
        s->cap = ncap;
    }
    *out_offset = s->len;
    memcpy(s->buf + s->len, data, size);
    s->len += size;
    return 0;
}

static int store_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                       void **out_pin)
{
    bi_store_t *s = ctx;
    if (offset > s->len || (uint64_t)size > s->len - offset) return -1;
    *out_data = s->buf + offset;
    *out_pin = NULL;
    return 0;
}

static void store_free(bi_store_t *s)
{
    free(s->buf);
}

/* callbacks that drive a real block manager, the same way the sstable klog stores aux blobs */
static int bm_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset)
{
    block_manager_block_t *blk = block_manager_block_create(size, data);
    if (!blk) return -1;
    int64_t off = block_manager_block_write((block_manager_t *)ctx, blk);
    block_manager_block_release(blk);
    if (off < 0) return -1;
    *out_offset = (uint64_t)off;
    return 0;
}

static int bm_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                    void **out_pin)
{
    block_manager_cursor_t *cur = NULL;
    if (block_manager_cursor_init(&cur, (block_manager_t *)ctx) != 0) return -1;
    if (block_manager_cursor_goto(cur, offset) != 0)
    {
        block_manager_cursor_free(cur);
        return -1;
    }
    block_manager_block_t *blk = block_manager_cursor_read(cur);
    block_manager_cursor_free(cur);
    if (!blk) return -1;
    if (blk->size != size)
    {
        block_manager_block_release(blk);
        return -1;
    }
    *out_data = blk->data;
    *out_pin = blk;
    return 0;
}

static void bm_release(void *ctx, void *pin)
{
    (void)ctx;
    block_manager_block_release((block_manager_block_t *)pin);
}

/* lexicographic order over raw bytes, matching tidesdb_comparator_fn */
static int cmp_lex(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, void *ctx)
{
    (void)ctx;
    size_t n = alen < blen ? alen : blen;
    int c = memcmp(a, b, n);
    if (c != 0) return c;
    return (alen > blen) - (alen < blen);
}

/* fixed-width zero-padded key so lexicographic order equals numeric order */
static size_t make_bkey(uint64_t v, uint8_t *out)
{
    return (size_t)snprintf((char *)out, 24, "b%010llu", (unsigned long long)v);
}

void test_bi_builder_new_invalid_args()
{
    blocked_index_builder_t *b = NULL;
    ASSERT_NE(blocked_index_builder_new(NULL, 0, store_write, NULL), 0);
    ASSERT_NE(blocked_index_builder_new(&b, 0, NULL, NULL), 0);
}

/* find returns the covering block and its ordinal for keys inside, at, and between block starts */
void test_bi_find_covering_block()
{
    bi_store_t store = {0};
    blocked_index_builder_t *b = NULL;
    ASSERT_EQ(blocked_index_builder_new(&b, 4, store_write, &store),
              0); /* small leaf to roll over */

    const int nblocks = 1000;
    for (int i = 0; i < nblocks; i++)
    {
        uint8_t key[24];
        size_t klen = make_bkey((uint64_t)i * 10, key); /* block i covers [i*10, i*10+9] */
        ASSERT_EQ(blocked_index_builder_add(b, key, klen, (uint64_t)i * 4096), 0);
    }
    uint64_t dir_off = 0, total = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, (uint64_t)nblocks);
    blocked_index_builder_free(b);

    blocked_index_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);

    for (int i = 0; i < nblocks; i++)
    {
        uint8_t key[24];
        uint64_t off = 0, ord = 0;
        /* a key inside block i (first-key + 5) routes to block i */
        size_t klen = make_bkey((uint64_t)i * 10 + 5, key);
        ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 1);
        ASSERT_EQ(off, (uint64_t)i * 4096);
        ASSERT_EQ(ord, (uint64_t)i);
        /* the exact first-key routes to the same block */
        klen = make_bkey((uint64_t)i * 10, key);
        ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 1);
        ASSERT_EQ(off, (uint64_t)i * 4096);
    }
    blocked_index_reader_free(r);
    store_free(&store);
}

/* a key below the first block is a definite miss */
void test_bi_below_range_not_found()
{
    bi_store_t store = {0};
    blocked_index_builder_t *b = NULL;
    ASSERT_EQ(blocked_index_builder_new(&b, 0, store_write, &store), 0);
    for (int i = 10; i < 500; i++)
    {
        uint8_t key[24];
        size_t klen = make_bkey((uint64_t)i, key);
        ASSERT_EQ(blocked_index_builder_add(b, key, klen, (uint64_t)i * 100), 0);
    }
    uint64_t dir_off = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_index_builder_free(b);

    blocked_index_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    uint8_t key[24];
    uint64_t off = 12345, ord = 999;
    size_t klen = make_bkey(0, key); /* below the smallest block first-key (10) */
    ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 0);
    blocked_index_reader_free(r);
    store_free(&store);
}

void test_bi_empty_and_single()
{
    /* empty build -- find reports not-found so the caller full-scans */
    bi_store_t store = {0};
    blocked_index_builder_t *b = NULL;
    ASSERT_EQ(blocked_index_builder_new(&b, 0, store_write, &store), 0);
    uint64_t dir_off = 0, total = 1;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, 0u);
    blocked_index_builder_free(b);

    blocked_index_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    uint8_t key[24];
    uint64_t off = 0, ord = 0;
    size_t klen = make_bkey(5, key);
    ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 0);
    ASSERT_TRUE(blocked_index_reader_resident_bytes(r) > 0);
    blocked_index_reader_free(r);
    store_free(&store);

    /* single block */
    bi_store_t s2 = {0};
    ASSERT_EQ(blocked_index_builder_new(&b, 0, store_write, &s2), 0);
    ASSERT_EQ(blocked_index_builder_add(b, key, klen, 777), 0);
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_index_builder_free(b);
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &s2), 0);
    ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 1);
    ASSERT_EQ(off, 777u);
    ASSERT_EQ(ord, 0u);
    blocked_index_reader_free(r);
    store_free(&s2);
}

void test_bi_free_null_safe()
{
    blocked_index_builder_free(NULL);
    blocked_index_reader_free(NULL);
    ASSERT_EQ(blocked_index_reader_resident_bytes(NULL), 0u);
}

/* end to end over a real block manager file, reopened from disk so the directory round-trips */
void test_bi_block_manager_backed()
{
    const char *path = "./test_bi_klog.bm";
    remove(path);

    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    blocked_index_builder_t *b = NULL;
    ASSERT_EQ(blocked_index_builder_new(&b, 64, bm_write, bm), 0);
    const int nblocks = 5000;
    for (int i = 0; i < nblocks; i++)
    {
        uint8_t key[24];
        size_t klen = make_bkey((uint64_t)i * 3, key);
        ASSERT_EQ(blocked_index_builder_add(b, key, klen, (uint64_t)i * 8192), 0);
    }
    uint64_t dir_off = 0, total = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, (uint64_t)nblocks);
    blocked_index_builder_free(b);
    ASSERT_EQ(block_manager_close(bm), 0);

    block_manager_t *bm2 = NULL;
    ASSERT_EQ(block_manager_open(&bm2, path, BLOCK_MANAGER_SYNC_NONE), 0);
    blocked_index_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, bm_fetch, bm_release, bm2),
        0);
    for (int i = 0; i < nblocks; i++)
    {
        uint8_t key[24];
        uint64_t off = 0, ord = 0;
        size_t klen = make_bkey((uint64_t)i * 3 + 1, key); /* inside block i */
        ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 1);
        ASSERT_EQ(off, (uint64_t)i * 8192);
        ASSERT_EQ(ord, (uint64_t)i);
    }
    blocked_index_reader_free(r);
    ASSERT_EQ(block_manager_close(bm2), 0);
    remove(path);
}

/* deterministic xorshift so the stress run is reproducible */
static uint32_t bi_rand(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

/* rightmost i with vals[i] <= q, or -1 -- the brute-force oracle the reader must match */
static int64_t oracle(const uint64_t *vals, int n, uint64_t q)
{
    int64_t lo = 0, hi = n - 1, res = -1;
    while (lo <= hi)
    {
        int64_t mid = lo + (hi - lo) / 2;
        if (vals[mid] <= q)
        {
            res = mid;
            lo = mid + 1;
        }
        else
        {
            hi = mid - 1;
        }
    }
    return res;
}

/* large scale over strictly-increasing blocks. every lookup -- exact first-keys and a fuzz of
 * random query values -- must return the same covering block a linear scan would, with the matching
 * ordinal */
void test_bi_stress_correctness()
{
    uint32_t seed = 0x243f6a88u;
    const int n = 100000;
    uint64_t *vals = malloc((size_t)n * sizeof(*vals));
    ASSERT_TRUE(vals != NULL);

    uint64_t v = 0;
    for (int i = 0; i < n; i++)
    {
        v += 1 + (bi_rand(&seed) % 50); /* strictly increasing gaps */
        vals[i] = v;
    }

    bi_store_t store = {0};
    blocked_index_builder_t *b = NULL;
    ASSERT_EQ(blocked_index_builder_new(&b, 128, store_write, &store), 0);
    for (int i = 0; i < n; i++)
    {
        uint8_t key[24];
        size_t klen = make_bkey(vals[i], key);
        ASSERT_EQ(blocked_index_builder_add(b, key, klen, (uint64_t)i * 4096 + 17), 0);
    }
    uint64_t dir_off = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_index_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_index_builder_free(b);

    blocked_index_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_index_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);

    /* exact first-keys route to their own block */
    for (int i = 0; i < n; i++)
    {
        uint8_t key[24];
        uint64_t off = 0, ord = 0;
        size_t klen = make_bkey(vals[i], key);
        ASSERT_EQ(blocked_index_reader_find(r, key, klen, &off, &ord), 1);
        ASSERT_EQ(off, (uint64_t)i * 4096 + 17);
        ASSERT_EQ(ord, (uint64_t)i);
    }

    /* random query values agree with the linear-scan oracle */
    for (int t = 0; t < n; t++)
    {
        uint64_t q = ((uint64_t)bi_rand(&seed) << 4) % (vals[n - 1] + 100);
        int64_t expect = oracle(vals, n, q);
        uint8_t key[24];
        uint64_t off = 0, ord = 0;
        size_t klen = make_bkey(q, key);
        int rc = blocked_index_reader_find(r, key, klen, &off, &ord);
        if (expect < 0)
        {
            ASSERT_EQ(rc, 0);
        }
        else
        {
            ASSERT_EQ(rc, 1);
            ASSERT_EQ(off, (uint64_t)expect * 4096 + 17);
            ASSERT_EQ(ord, (uint64_t)expect);
        }
    }

    blocked_index_reader_free(r);
    free(vals);
    store_free(&store);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_bi_builder_new_invalid_args, tests_passed);
    RUN_TEST(test_bi_find_covering_block, tests_passed);
    RUN_TEST(test_bi_below_range_not_found, tests_passed);
    RUN_TEST(test_bi_empty_and_single, tests_passed);
    RUN_TEST(test_bi_free_null_safe, tests_passed);
    RUN_TEST(test_bi_block_manager_backed, tests_passed);
    RUN_TEST(test_bi_stress_correctness, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
