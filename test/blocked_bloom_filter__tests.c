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
#include "../src/blocked_bloom_filter.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* an append-only in-memory backing store standing in for the sstable's block-managed file. write
 * appends and hands back the offset; fetch returns a pointer into the buffer (no pin needed). the
 * write counter lets a test observe that partitions are flushed as they roll over, not buffered. */
typedef struct
{
    uint8_t *buf;
    size_t len;
    size_t cap;
    int writes;
} bbf_store_t;

static int store_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset)
{
    bbf_store_t *s = ctx;
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
    s->writes++;
    return 0;
}

static int store_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                       void **out_pin)
{
    bbf_store_t *s = ctx;
    if (offset > s->len || (uint64_t)size > s->len - offset) return -1;
    *out_data = s->buf + offset;
    *out_pin = NULL;
    return 0;
}

static void store_free(bbf_store_t *s)
{
    free(s->buf);
}

/* callbacks that drive a real block manager, the same way the sstable klog stores aux blobs. write
 * appends one block and returns its offset; fetch reads the block at that offset and hands the
 * block back as the pin so release can free it once the probe is done. */
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
static size_t make_key(int v, uint8_t *out)
{
    return (size_t)snprintf((char *)out, 16, "k%08d", v);
}

void test_bbf_builder_new_invalid_args()
{
    blocked_bloom_builder_t *b = NULL;
    ASSERT_NE(blocked_bloom_builder_new(NULL, 0.01, 0, store_write, NULL), 0);
    ASSERT_NE(blocked_bloom_builder_new(&b, 0.0, 0, store_write, NULL), 0);
    ASSERT_NE(blocked_bloom_builder_new(&b, 1.0, 0, store_write, NULL), 0);
    ASSERT_NE(blocked_bloom_builder_new(&b, 0.01, 0, NULL, NULL), 0);
}

/* every added key must report may-present -- a bloom may never report a false negative */
void test_bbf_no_false_negatives()
{
    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 512, store_write, &store), 0);

    const int n = 20000;
    for (int i = 0; i < n; i++)
    {
        uint8_t key[16];
        size_t klen = make_key(i, key);
        ASSERT_EQ(blocked_bloom_builder_add(b, key, klen), 0);
    }
    uint64_t dir_off = 0, total = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, (uint64_t)n);
    blocked_bloom_builder_free(b);

    /* rollover at 512 keys over 20000 keys means many partitions plus the directory were written */
    ASSERT_TRUE(store.writes > n / 512);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    for (int i = 0; i < n; i++)
    {
        uint8_t key[16];
        size_t klen = make_key(i, key);
        ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, key, klen), 1);
    }
    blocked_bloom_reader_free(r);
    store_free(&store);
}

/* a key sorting before the first partition is a definite miss, answered without a fetch */
void test_bbf_below_range_is_absent()
{
    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 256, store_write, &store), 0);
    for (int i = 100; i < 5000; i++)
    {
        uint8_t key[16];
        size_t klen = make_key(i, key);
        ASSERT_EQ(blocked_bloom_builder_add(b, key, klen), 0);
    }
    uint64_t dir_off = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_bloom_builder_free(b);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    uint8_t key[16];
    size_t klen = make_key(0, key); /* below the smallest inserted key (100) */
    ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, key, klen), 0);
    blocked_bloom_reader_free(r);
    store_free(&store);
}

/* absent keys spread across partitions should trip the filter at roughly the configured rate */
void test_bbf_false_positive_rate()
{
    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 4096, store_write, &store), 0);

    const int n = 50000;
    for (int i = 0; i < n; i++) /* even keys inserted, ascending */
    {
        uint8_t key[16];
        size_t klen = make_key(i * 2, key);
        ASSERT_EQ(blocked_bloom_builder_add(b, key, klen), 0);
    }
    uint64_t dir_off = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_bloom_builder_free(b);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    int fp = 0;
    for (int i = 0; i < n; i++) /* odd keys never inserted, interleaved across partitions */
    {
        uint8_t key[16];
        size_t klen = make_key(i * 2 + 1, key);
        if (blocked_bloom_reader_maybe_contains(r, key, klen) == 1) fp++;
    }
    /* generous ceiling at 3x the target so the fixed seed cannot flake */
    ASSERT_TRUE(fp < n * 3 / 100);
    blocked_bloom_reader_free(r);
    store_free(&store);
}

/* a build with no keys yields an empty directory, and its reader answers may-present, which is the
 * safe fallback when no filter exists */
void test_bbf_empty_build()
{
    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 256, store_write, &store), 0);
    uint64_t dir_off = 0, total = 1;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, 0u);
    blocked_bloom_builder_free(b);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    uint8_t key[16];
    size_t klen = make_key(42, key);
    ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, key, klen), 1);
    ASSERT_TRUE(blocked_bloom_reader_resident_bytes(r) > 0);
    blocked_bloom_reader_free(r);
    store_free(&store);
}

/* one key, one partition */
void test_bbf_single_key()
{
    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 0, store_write, &store), 0);
    uint8_t key[16];
    size_t klen = make_key(7, key);
    ASSERT_EQ(blocked_bloom_builder_add(b, key, klen), 0);
    uint64_t dir_off = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, NULL), 0);
    blocked_bloom_builder_free(b);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);
    ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, key, klen), 1);
    uint8_t other[16];
    size_t olen = make_key(999999, other); /* absent, above range -> routes to the sole partition */
    ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, other, olen), 0);
    blocked_bloom_reader_free(r);
    store_free(&store);
}

void test_bbf_free_null_safe()
{
    blocked_bloom_builder_free(NULL);
    blocked_bloom_reader_free(NULL);
    ASSERT_EQ(blocked_bloom_reader_resident_bytes(NULL), 0u);
}

/* end to end over a real block manager file, exercising the exact write and read path the sstable
 * klog will use, and reopening the reader from a fresh block manager to prove the on-disk directory
 * and partitions round-trip through storage */
void test_bbf_block_manager_backed()
{
    const char *path = "./test_bbf_klog.bm";
    remove(path);

    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 1024, bm_write, bm), 0);
    const int n = 30000;
    for (int i = 0; i < n; i++)
    {
        uint8_t key[16];
        size_t klen = make_key(i, key);
        ASSERT_EQ(blocked_bloom_builder_add(b, key, klen), 0);
    }
    uint64_t dir_off = 0, total = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, (uint64_t)n);
    blocked_bloom_builder_free(b);
    ASSERT_EQ(block_manager_close(bm), 0);

    /* reopen from disk so the reader loads its directory through the block manager, not from any
     * builder state left in memory */
    block_manager_t *bm2 = NULL;
    ASSERT_EQ(block_manager_open(&bm2, path, BLOCK_MANAGER_SYNC_NONE), 0);
    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, bm_fetch, bm_release, bm2),
        0);
    for (int i = 0; i < n; i++)
    {
        uint8_t key[16];
        size_t klen = make_key(i, key);
        ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, key, klen), 1);
    }
    uint8_t absent[16];
    size_t alen = make_key(-1, absent); /* "k-0000001" sorts before every inserted key */
    ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, absent, alen), 0);

    blocked_bloom_reader_free(r);
    ASSERT_EQ(block_manager_close(bm2), 0);
    remove(path);
}

/* a variable-length key owned by the stress test */
typedef struct
{
    uint8_t *k;
    uint32_t len;
} bbf_skey_t;

/* deterministic xorshift so the stress run is reproducible and never flakes */
static uint32_t bbf_rand(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

static int bbf_skey_cmp(const void *a, const void *b)
{
    const bbf_skey_t *x = a, *y = b;
    return cmp_lex(x->k, x->len, y->k, y->len, NULL);
}

/* large scale over random variable-length binary keys. sorted-unique keys are built in order, then
 * every inserted key must report may-present (the invariant a bloom must never break) and a
 * disjoint set of random keys must keep the false-positive rate near the target across all
 * partitions */
void test_bbf_stress_correctness()
{
    uint32_t seed = 0x9e3779b9u;
    const int n = 200000;

    bbf_skey_t *keys = malloc((size_t)n * sizeof(*keys));
    ASSERT_TRUE(keys != NULL);
    for (int i = 0; i < n; i++)
    {
        uint32_t len = 4 + (bbf_rand(&seed) % 21); /* 4..24 bytes */
        uint8_t *k = malloc(len);
        for (uint32_t j = 0; j < len; j++) k[j] = (uint8_t)bbf_rand(&seed);
        keys[i].k = k;
        keys[i].len = len;
    }
    qsort(keys, (size_t)n, sizeof(*keys), bbf_skey_cmp);

    /* drop adjacent duplicates so the disjoint-query check below is exact */
    int m = n ? 1 : 0;
    for (int i = 1; i < n; i++)
    {
        if (bbf_skey_cmp(&keys[m - 1], &keys[i]) == 0)
            free(keys[i].k);
        else
            keys[m++] = keys[i];
    }

    bbf_store_t store = {0};
    blocked_bloom_builder_t *b = NULL;
    ASSERT_EQ(blocked_bloom_builder_new(&b, 0.01, 2048, store_write, &store), 0);
    for (int i = 0; i < m; i++) ASSERT_EQ(blocked_bloom_builder_add(b, keys[i].k, keys[i].len), 0);
    uint64_t dir_off = 0, total = 0;
    uint32_t dir_size = 0;
    ASSERT_EQ(blocked_bloom_builder_finish(b, &dir_off, &dir_size, &total), 0);
    ASSERT_EQ(total, (uint64_t)m);
    blocked_bloom_builder_free(b);

    blocked_bloom_reader_t *r = NULL;
    ASSERT_EQ(
        blocked_bloom_reader_open(&r, dir_off, dir_size, cmp_lex, NULL, store_fetch, NULL, &store),
        0);

    for (int i = 0; i < m; i++)
        ASSERT_EQ(blocked_bloom_reader_maybe_contains(r, keys[i].k, keys[i].len), 1);

    int tested = 0, fp = 0;
    for (int t = 0; t < n; t++)
    {
        uint8_t q[24];
        uint32_t len = 4 + (bbf_rand(&seed) % 21);
        for (uint32_t j = 0; j < len; j++) q[j] = (uint8_t)bbf_rand(&seed);
        bbf_skey_t probe = {q, len};
        if (bsearch(&probe, keys, (size_t)m, sizeof(*keys), bbf_skey_cmp))
            continue; /* skip present */
        tested++;
        if (blocked_bloom_reader_maybe_contains(r, q, len) == 1) fp++;
    }
    ASSERT_TRUE(tested > 0);
    ASSERT_TRUE(fp < tested * 3 / 100); /* 3x the 0.01 target -- a wide margin against flaking */

    blocked_bloom_reader_free(r);
    for (int i = 0; i < m; i++) free(keys[i].k);
    free(keys);
    store_free(&store);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_bbf_builder_new_invalid_args, tests_passed);
    RUN_TEST(test_bbf_no_false_negatives, tests_passed);
    RUN_TEST(test_bbf_below_range_is_absent, tests_passed);
    RUN_TEST(test_bbf_false_positive_rate, tests_passed);
    RUN_TEST(test_bbf_empty_build, tests_passed);
    RUN_TEST(test_bbf_single_key, tests_passed);
    RUN_TEST(test_bbf_free_null_safe, tests_passed);
    RUN_TEST(test_bbf_block_manager_backed, tests_passed);
    RUN_TEST(test_bbf_stress_correctness, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
