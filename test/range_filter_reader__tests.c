/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base/errors.h"
#include "../src/base/keycmp.h"
#include "../src/range_filter/range_filter.h"
#include "../src/range_filter/range_filter_format.h"
#include "../src/range_filter/range_filter_reader.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the longest key any test makes */
#define RRT_MAX_KEY 40

/* the remainder width the tests build with */
#define RRT_R_BITS 10

/* contexts the tests' coders keep */
#define RRT_CONTEXTS 256

/* the most blobs one memory sink holds */
#define RRT_MAX_BLOBS 4096

/* probes compared between the two forms of each filter */
#define RRT_PROBES 3000

/* a partition size small enough that every gap closes one */
#define RRT_TINY_PARTITION 1

/* the sizes the equivalence test builds, around the sample interval and well past it */
#define RRT_BIG 20000

/* a gap holds at most T - 1 keys, and the T the damage tests use */
#define RRT_SAMPLE_BITS 4

typedef struct
{
    uint8_t b[RRT_MAX_KEY];
    size_t n;
} rrt_key_t;

/**
 * rrt_sink_t
 * blobs written by a streaming build, read back by offset, standing in for a klog
 * @param data each blob
 * @param size each blob's length
 * @param n how many
 * @param fetches how many fetches were made
 * @param fail_fetch when set, every fetch fails
 * @param largest the longest blob written
 */
typedef struct
{
    uint8_t *data[RRT_MAX_BLOBS];
    size_t size[RRT_MAX_BLOBS];
    size_t n;
    size_t fetches;
    int fail_fetch;
    size_t largest;
} rrt_sink_t;

static int rrt_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset)
{
    rrt_sink_t *s = ctx;
    if (s->n == RRT_MAX_BLOBS) return -1;
    s->data[s->n] = malloc(size > 0 ? size : 1);
    if (!s->data[s->n]) return -1;
    memcpy(s->data[s->n], data, size);
    s->size[s->n] = size;
    if (size > s->largest) s->largest = size;
    *out_offset = s->n++;
    return 0;
}

static int rrt_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                     void **out_pin)
{
    rrt_sink_t *s = ctx;
    s->fetches++;
    if (s->fail_fetch || offset >= s->n || s->size[offset] != size) return -1;
    *out_data = s->data[offset];
    *out_pin = NULL;
    return 0;
}

static void rrt_release(void *ctx, void *pin)
{
    (void)ctx;
    (void)pin;
}

static void rrt_sink_free(rrt_sink_t *s)
{
    for (size_t i = 0; i < s->n; i++) free(s->data[i]);
    memset(s, 0, sizeof(*s));
}

static uint64_t rrt_next(uint64_t *s)
{
    uint64_t z = (*s += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static int rrt_cmp(const void *pa, const void *pb)
{
    const rrt_key_t *a = pa, *b = pb;
    return tdb_key_cmp(a->b, a->n, b->b, b->n);
}

/* keys of three shapes, sorted and without repeats, returning how many are left */
static int rrt_keys(rrt_key_t *k, int n, int shape, uint64_t seed)
{
    for (int i = 0; i < n; i++)
    {
        if (shape == 0)
        {
            k[i].n = 12;
            for (size_t j = 0; j < k[i].n; j++) k[i].b[j] = (uint8_t)rrt_next(&seed);
        }
        else if (shape == 1)
        {
            k[i].n =
                (size_t)snprintf((char *)k[i].b, RRT_MAX_KEY, "idx:%06d:%08d",
                                 (int)(rrt_next(&seed) % 500), (int)(rrt_next(&seed) % 100000000));
        }
        else
        {
            k[i].n = (size_t)(rrt_next(&seed) % RRT_MAX_KEY);
            for (size_t j = 0; j < k[i].n; j++) k[i].b[j] = (uint8_t)(rrt_next(&seed) % 4);
        }
    }
    qsort(k, (size_t)n, sizeof(*k), rrt_cmp);
    int out = 0;
    for (int i = 0; i < n; i++)
        if (out == 0 || rrt_cmp(&k[out - 1], &k[i]) != 0) k[out++] = k[i];
    return out;
}

static range_filter_codec_t *rrt_codec_with(const rrt_key_t *k, int n, int contexts)
{
    range_filter_codec_counts_t *c = NULL;
    ASSERT_EQ(range_filter_codec_counts_new(&c), TDB_SUCCESS);
    for (int i = 0; i < n; i++) range_filter_codec_counts_add(c, k[i].b, k[i].n);
    range_filter_codec_t *codec = NULL;
    ASSERT_EQ(range_filter_codec_build(c, 2, contexts, &codec), TDB_SUCCESS);
    range_filter_codec_counts_free(c);
    return codec;
}

static range_filter_codec_t *rrt_codec(const rrt_key_t *k, int n)
{
    return rrt_codec_with(k, n, RRT_CONTEXTS);
}

/* build a filter through a sink and open a reader over what landed there */
static range_filter_reader_t *rrt_stream(const range_filter_codec_t *codec, const rrt_key_t *k,
                                         int n, unsigned sample_bits, size_t partition_bytes,
                                         rrt_sink_t *sink, uint64_t *dir_offset, uint32_t *dir_size)
{
    range_filter_builder_t *b = NULL;
    ASSERT_EQ(range_filter_builder_new(codec, sample_bits, RRT_R_BITS, &b), TDB_SUCCESS);
    ASSERT_EQ(range_filter_builder_stream(b, rrt_write, sink, partition_bytes), TDB_SUCCESS);
    for (int i = 0; i < n; i++) ASSERT_EQ(range_filter_builder_add(b, k[i].b, k[i].n), TDB_SUCCESS);
    ASSERT_EQ(range_filter_builder_finish_stream(b, dir_offset, dir_size), TDB_SUCCESS);
    range_filter_reader_t *r = NULL;
    ASSERT_EQ(range_filter_reader_open(&r, *dir_offset, *dir_size, rrt_fetch, rrt_release, sink),
              TDB_SUCCESS);
    ASSERT_EQ(range_filter_reader_key_count(r), (uint64_t)n);
    return r;
}

static range_filter_t *rrt_memory(const range_filter_codec_t *codec, const rrt_key_t *k, int n,
                                  unsigned sample_bits)
{
    range_filter_builder_t *b = NULL;
    ASSERT_EQ(range_filter_builder_new(codec, sample_bits, RRT_R_BITS, &b), TDB_SUCCESS);
    for (int i = 0; i < n; i++) ASSERT_EQ(range_filter_builder_add(b, k[i].b, k[i].n), TDB_SUCCESS);
    range_filter_t *f = NULL;
    ASSERT_EQ(range_filter_builder_finish(b, &f), TDB_SUCCESS);
    return f;
}

/* a probe end, a key itself, a key nudged, or a fresh key of the same shape */
static void rrt_probe_key(rrt_key_t *p, const rrt_key_t *k, int n, int shape, uint64_t *seed)
{
    const uint64_t kind = rrt_next(seed) % 3;
    if (kind == 0 || n == 0)
    {
        (void)rrt_keys(p, 1, shape, rrt_next(seed));
        return;
    }
    *p = k[rrt_next(seed) % (uint64_t)n];
    if (kind == 2 && p->n > 0) p->b[p->n - 1] = (uint8_t)(p->b[p->n - 1] + 1);
}

/* the streamed filter read back answers every probe exactly as the one kept in memory, across key
 * shapes, sizes, sample intervals and partitions of one gap each or many */
void test_range_filter_reader_answers_as_the_filter_in_memory(void)
{
    static const int sizes[] = {1, 2, 15, 16, 17, 1023, 1025, RRT_BIG};
    static const size_t parts[] = {RRT_TINY_PARTITION, 0};
    rrt_key_t *k = malloc(RRT_BIG * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    uint64_t seed = 11;
    for (int shape = 0; shape < 3; shape++)
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
        {
            const int n = rrt_keys(k, sizes[s], shape, 1000 + (uint64_t)shape * 17 + s);
            range_filter_codec_t *codec = rrt_codec(k, n);
            for (unsigned sb = RRT_SAMPLE_BITS; sb <= RANGE_FILTER_DEFAULT_SAMPLE_BITS; sb += 6)
                for (size_t pi = 0; pi < sizeof(parts) / sizeof(parts[0]); pi++)
                {
                    rrt_sink_t sink = {0};
                    uint64_t off = 0;
                    uint32_t size = 0;
                    range_filter_t *f = rrt_memory(codec, k, n, sb);
                    range_filter_reader_t *r =
                        rrt_stream(codec, k, n, sb, parts[pi], &sink, &off, &size);
                    for (int i = 0; i < n; i++)
                        ASSERT_EQ(
                            range_filter_reader_may_contain(r, k[i].b, k[i].n, k[i].b, k[i].n), 1);
                    for (int p = 0; p < RRT_PROBES; p++)
                    {
                        rrt_key_t lo, hi;
                        rrt_probe_key(&lo, k, n, shape, &seed);
                        rrt_probe_key(&hi, k, n, shape, &seed);
                        if (p % 2 == 0) hi = lo;
                        ASSERT_EQ(range_filter_reader_may_contain(r, lo.b, lo.n, hi.b, hi.n),
                                  range_filter_may_contain(f, lo.b, lo.n, hi.b, hi.n));
                    }
                    range_filter_reader_free(r);
                    range_filter_free(f);
                    rrt_sink_free(&sink);
                }
            range_filter_codec_free(codec);
        }
    free(k);
}

/* partitions close near their size, a reader keeps only the directory, which is a small share of
 * the filter, and a query fetches one partition */
void test_range_filter_reader_holds_the_directory_only(void)
{
    rrt_key_t *k = malloc(RRT_BIG * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    const int n = rrt_keys(k, RRT_BIG, 0, 3);
    /* the model at the run's budget, as a real build sizes it */
    range_filter_codec_t *codec =
        rrt_codec_with(k, n, range_filter_context_budget((uint64_t)n, RRT_R_BITS));
    rrt_sink_t sink = {0};
    uint64_t off = 0;
    uint32_t size = 0;
    const size_t part_bytes = 4096;
    range_filter_reader_t *r =
        rrt_stream(codec, k, n, RANGE_FILTER_DEFAULT_SAMPLE_BITS, part_bytes, &sink, &off, &size);
    size_t stored = 0;
    for (size_t i = 0; i + 1 < sink.n; i++)
    {
        stored += sink.size[i];
        /* a partition closes on the store that carries it past its size, so it ends within one
         * store of it */
        ASSERT_TRUE(sink.size[i] < 2 * part_bytes);
    }
    fprintf(stderr, "  %zu partitions, %zu bytes of stores, %u byte directory, %zu resident\n",
            sink.n - 1, stored, size, range_filter_reader_resident_bytes(r));
    ASSERT_TRUE(sink.n > 2);
    ASSERT_TRUE(range_filter_reader_resident_bytes(r) < stored);
    sink.fetches = 0;
    ASSERT_EQ(range_filter_reader_may_contain(r, k[1].b, k[1].n, k[1].b, k[1].n), 1);
    ASSERT_TRUE(sink.fetches <= 1);
    range_filter_reader_free(r);
    rrt_sink_free(&sink);
    range_filter_codec_free(codec);
    free(k);
}

/* no keys write a directory with no samples, which answers no, and a lone key answers for itself */
void test_range_filter_reader_empty_and_single(void)
{
    rrt_key_t k[1] = {{"m", 1}};
    range_filter_codec_t *codec = rrt_codec(k, 1);
    for (int n = 0; n <= 1; n++)
    {
        rrt_sink_t sink = {0};
        uint64_t off = 0;
        uint32_t size = 0;
        range_filter_reader_t *r = rrt_stream(codec, k, n, RRT_SAMPLE_BITS, 0, &sink, &off, &size);
        ASSERT_EQ(
            range_filter_reader_may_contain(r, (const uint8_t *)"m", 1, (const uint8_t *)"m", 1),
            n);
        ASSERT_EQ(
            range_filter_reader_may_contain(r, (const uint8_t *)"a", 1, (const uint8_t *)"b", 1),
            0);
        range_filter_reader_free(r);
        rrt_sink_free(&sink);
    }
    range_filter_codec_free(codec);
}

/* a directory that is cut short, or whose fields disagree, is refused, a fetch that fails reads as
 * may-contain, and a damaged partition answers yes rather than no */
void test_range_filter_reader_refuses_damage(void)
{
    rrt_key_t *k = malloc(2000 * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    const int n = rrt_keys(k, 2000, 1, 9);
    range_filter_codec_t *codec = rrt_codec(k, n);
    rrt_sink_t sink = {0};
    uint64_t off = 0;
    uint32_t size = 0;
    range_filter_reader_t *r = rrt_stream(codec, k, n, RRT_SAMPLE_BITS, 0, &sink, &off, &size);
    range_filter_reader_free(r);

    uint8_t *dir = sink.data[off];
    range_filter_dir_t d;
    for (uint32_t cut = 0; cut < size; cut++)
        ASSERT_TRUE(range_filter_dir_decode(dir, cut, &d) != TDB_SUCCESS);
    uint8_t *copy = malloc((size_t)size + 1);
    ASSERT_TRUE(copy != NULL);
    memcpy(copy, dir, size);
    copy[size] = 0;
    ASSERT_EQ(range_filter_dir_decode(copy, (size_t)size + 1, &d), TDB_ERR_CORRUPTION);
    /* the magic, the version, an unknown flag, and remainder bits out of range */
    static const size_t fields[] = {0, 4, 8, 14};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
    {
        memcpy(copy, dir, size);
        copy[fields[i]] ^= 0x40;
        ASSERT_EQ(range_filter_dir_decode(copy, size, &d), TDB_ERR_CORRUPTION);
    }
    /* a key count that disagrees with the samples */
    memcpy(copy, dir, size);
    const uint64_t wrong = (uint64_t)n + (UINT64_C(1) << RRT_SAMPLE_BITS);
    for (size_t i = 0; i < sizeof(wrong); i++) copy[16 + i] = (uint8_t)(wrong >> (8 * i));
    ASSERT_EQ(range_filter_dir_decode(copy, size, &d), TDB_ERR_CORRUPTION);
    /* any one byte flipped anywhere is either refused or opened, and never read past */
    for (uint32_t at = 0; at < size; at++)
    {
        memcpy(copy, dir, size);
        copy[at] ^= 0xFF;
        if (range_filter_dir_decode(copy, size, &d) == TDB_SUCCESS) range_filter_dir_release(&d);
    }
    free(copy);

    /* every partition cut short, so a query landing in one cannot find its store */
    for (size_t i = 0; i < sink.n; i++)
        if (i != off) sink.size[i] /= 2;
    for (size_t i = 0; i < sink.n; i++)
        if (i != off)
        {
            uint8_t *shrunk = realloc(sink.data[i], sink.size[i] > 0 ? sink.size[i] : 1);
            if (shrunk) sink.data[i] = shrunk;
        }
    ASSERT_EQ(range_filter_reader_open(&r, off, size, rrt_fetch, rrt_release, &sink), TDB_SUCCESS);
    /* the partition table still names the old sizes, so every fetch fails and every query that
     * needs a store answers yes */
    for (int i = 0; i < n; i += 7)
    {
        rrt_key_t miss = k[i];
        miss.b[miss.n - 1] = (uint8_t)(miss.b[miss.n - 1] ^ 0x01);
        if (range_filter_reader_may_contain(r, miss.b, miss.n, miss.b, miss.n) == 0)
        {
            /* a no is allowed only where the samples alone settle the range */
            ASSERT_TRUE(bsearch(&miss, k, (size_t)n, sizeof(*k), rrt_cmp) == NULL);
        }
        ASSERT_EQ(range_filter_reader_may_contain(r, k[i].b, k[i].n, k[i].b, k[i].n), 1);
    }
    sink.fail_fetch = 1;
    ASSERT_EQ(range_filter_reader_may_contain(r, k[3].b, k[3].n, k[3].b, k[3].n), 1);
    range_filter_reader_free(r);
    ASSERT_EQ(range_filter_reader_open(&r, off, size, rrt_fetch, rrt_release, &sink), TDB_ERR_IO);
    ASSERT_TRUE(r == NULL);
    rrt_sink_free(&sink);
    range_filter_codec_free(codec);
    free(k);
}

/* a store whose bitmaps disagree with each other or with its slot count is refused */
void test_range_filter_reader_refuses_a_damaged_store(void)
{
    const uint64_t infixes[] = {1, 5, 5, 9, 200, 201};
    range_filter_infix_store_t s, back;
    ASSERT_EQ(range_filter_infix_store_build(infixes, NULL, 0, 6, 4, 4, &s), TDB_SUCCESS);
    const size_t size = range_filter_store_encoded_size(&s);
    uint8_t *buf = malloc(size);
    ASSERT_TRUE(buf != NULL);
    range_filter_store_encode(&s, buf);
    ASSERT_EQ(range_filter_store_decode(buf, size, 4, 4, 15, &back), TDB_SUCCESS);
    for (uint64_t lo = 0; lo < 256; lo++)
        ASSERT_EQ(range_filter_infix_store_may_contain(&back, lo, lo + 3, NULL, NULL),
                  range_filter_infix_store_may_contain(&s, lo, lo + 3, NULL, NULL));
    range_filter_infix_store_free(&back);
    ASSERT_EQ(range_filter_store_decode(buf, size, 4, 4, 5, &back), TDB_ERR_CORRUPTION);
    ASSERT_EQ(range_filter_store_decode(buf, size - 1, 4, 4, 15, &back), TDB_ERR_CORRUPTION);
    /* the word after the slot count is the quotient bitmap, and clearing quotient 0 leaves its run
     * with no quotient */
    buf[sizeof(uint32_t)] ^= 0x01;
    ASSERT_EQ(range_filter_store_decode(buf, size, 4, 4, 15, &back), TDB_ERR_CORRUPTION);
    buf[sizeof(uint32_t)] ^= 0x01;
    /* the run-end word follows. quotient 0's run ends at slot 3, and moving that end past the last
     * slot keeps the counts equal, yet a search would find the run ending nowhere */
    const size_t run_low = sizeof(uint32_t) + 8; /* words are little-endian, low byte first */
    buf[run_low] ^= 0x08;
    buf[run_low + 1] ^= 0x01;
    ASSERT_EQ(range_filter_store_decode(buf, size, 4, 4, 15, &back), TDB_ERR_CORRUPTION);
    free(buf);
    range_filter_infix_store_free(&s);
}

/* a directory whose samples do not rise is refused, since a search over them would land in the
 * wrong gap */
void test_range_filter_reader_refuses_unordered_samples(void)
{
    rrt_key_t *k = malloc(200 * sizeof(*k));
    ASSERT_TRUE(k != NULL);
    const int n = rrt_keys(k, 200, 0, 21);
    range_filter_codec_t *codec = rrt_codec(k, n);
    rrt_sink_t sink = {0};
    uint64_t off = 0;
    uint32_t size = 0;
    range_filter_reader_t *r = rrt_stream(codec, k, n, RRT_SAMPLE_BITS, 0, &sink, &off, &size);
    range_filter_reader_free(r);
    range_filter_dir_t d;
    ASSERT_EQ(range_filter_dir_decode(sink.data[off], size, &d), TDB_SUCCESS);
    ASSERT_TRUE(d.n_samples > 2);
    const range_filter_bits_t t = d.samples[1];
    d.samples[1] = d.samples[2];
    d.samples[2] = t;
    uint8_t *model = NULL, *bad = NULL;
    size_t model_size = 0, bad_size = 0;
    ASSERT_EQ(range_filter_codec_serialize(codec, &model, &model_size), TDB_SUCCESS);
    ASSERT_EQ(range_filter_dir_encode(&d, model, model_size, &bad, &bad_size), TDB_SUCCESS);
    range_filter_dir_t back;
    ASSERT_EQ(range_filter_dir_decode(bad, bad_size, &back), TDB_ERR_CORRUPTION);
    /* swapped back, the same bytes read */
    d.samples[2] = d.samples[1];
    d.samples[1] = t;
    free(bad);
    ASSERT_EQ(range_filter_dir_encode(&d, model, model_size, &bad, &bad_size), TDB_SUCCESS);
    ASSERT_EQ(range_filter_dir_decode(bad, bad_size, &back), TDB_SUCCESS);
    range_filter_dir_release(&back);
    range_filter_dir_release(&d);
    free(bad);
    free(model);
    rrt_sink_free(&sink);
    range_filter_codec_free(codec);
    free(k);
}

/* a small run's model gets no contexts, a large run's grows with it, and none passes the cap */
void test_range_filter_context_budget(void)
{
    ASSERT_EQ(range_filter_context_budget(0, RRT_R_BITS), 0);
    ASSERT_EQ(range_filter_context_budget(1000, RRT_R_BITS), 0);
    int prev = 0;
    for (uint64_t n = 1000; n < UINT64_C(1) << 32; n *= 4)
    {
        const int b = range_filter_context_budget(n, RRT_R_BITS);
        ASSERT_TRUE(b >= prev && b <= RANGE_FILTER_MAX_CONTEXTS);
        prev = b;
    }
    ASSERT_EQ(prev, RANGE_FILTER_MAX_CONTEXTS);
    /* a model at its budget stays within its share of the filter */
    const uint64_t n = 1000000;
    const uint64_t model =
        (uint64_t)range_filter_context_budget(n, RRT_R_BITS) * range_filter_codec_context_bytes();
    ASSERT_TRUE(model * RANGE_FILTER_MODEL_SHARE <= n * (RRT_R_BITS + 2) / 8);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_range_filter_reader_answers_as_the_filter_in_memory, tests_passed);
    RUN_TEST(test_range_filter_reader_holds_the_directory_only, tests_passed);
    RUN_TEST(test_range_filter_reader_empty_and_single, tests_passed);
    RUN_TEST(test_range_filter_reader_refuses_damage, tests_passed);
    RUN_TEST(test_range_filter_reader_refuses_a_damaged_store, tests_passed);
    RUN_TEST(test_range_filter_reader_refuses_unordered_samples, tests_passed);
    RUN_TEST(test_range_filter_context_budget, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
