/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/iter/merge_iter.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* a stub source over a fixed array of versioned entries sorted by key (versions of one key
 * adjacent), so the merge can be exercised with neither a memtable nor an sstable */
typedef struct
{
    const char *key;
    uint64_t seq;
    const char *value; /* NULL for a tombstone */
} stub_entry_t;

typedef struct
{
    const stub_entry_t *entries;
    int n;
    int pos;
    /* the position from which this source can no longer read, standing in for an sstable leaf that
     * will not load. it reports itself invalid there, exactly as a real one does, so only
     * read_failed tells the two apart. zero leaves the source always readable */
    int fail_at;
} stub_src_t;

/* whether the source has reached the point it can no longer read from */
static int stub_failing(const stub_src_t *s)
{
    return s->fail_at > 0 && s->pos >= s->fail_at;
}

static int stub_cmp(const char *a, const char *b)
{
    return strcmp(a, b);
}

static int stub_first(void *ctx)
{
    stub_src_t *s = ctx;
    s->pos = 0;
    return s->n > 0;
}
static int stub_last(void *ctx)
{
    stub_src_t *s = ctx;
    s->pos = s->n - 1;
    return s->n > 0;
}
static int stub_next(void *ctx)
{
    stub_src_t *s = ctx;
    s->pos++;
    return s->pos < s->n;
}
static int stub_prev(void *ctx)
{
    stub_src_t *s = ctx;
    s->pos--;
    return s->pos >= 0;
}
static int stub_valid(void *ctx)
{
    stub_src_t *s = ctx;
    if (stub_failing(s)) return 0;
    return s->pos >= 0 && s->pos < s->n;
}
static int stub_read_failed(void *ctx)
{
    return stub_failing((stub_src_t *)ctx);
}
static int stub_seek(void *ctx, const uint8_t *key, size_t key_size)
{
    stub_src_t *s = ctx;
    char buf[64];
    memcpy(buf, key, key_size);
    buf[key_size] = '\0';
    for (s->pos = 0; s->pos < s->n; s->pos++)
        if (stub_cmp(s->entries[s->pos].key, buf) >= 0) return 1;
    return 0;
}
static int stub_seek_for_prev(void *ctx, const uint8_t *key, size_t key_size)
{
    stub_src_t *s = ctx;
    char buf[64];
    memcpy(buf, key, key_size);
    buf[key_size] = '\0';
    for (s->pos = s->n - 1; s->pos >= 0; s->pos--)
        if (stub_cmp(s->entries[s->pos].key, buf) <= 0) return 1;
    return 0;
}
static void stub_get(void *ctx, const uint8_t **key, size_t *key_size, uint64_t *seq,
                     const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                     uint8_t *deleted)
{
    stub_src_t *s = ctx;
    const stub_entry_t *e = &s->entries[s->pos];
    *key = (const uint8_t *)e->key;
    *key_size = strlen(e->key);
    *seq = e->seq;
    *value = e->value ? (const uint8_t *)e->value : NULL;
    *value_size = e->value ? strlen(e->value) : 0;
    *vlog_offset = 0;
    *ttl = -1;
    *deleted = e->value ? 0 : 1;
}

static merge_source_t stub_source(stub_src_t *s)
{
    /* zero first, so an optional hook the stub does not set reads as absent rather than as
     * whatever the stack held */
    merge_source_t src = {0};
    src.first = stub_first;
    src.last = stub_last;
    src.next = stub_next;
    src.prev = stub_prev;
    src.valid = stub_valid;
    src.seek = stub_seek;
    src.seek_for_prev = stub_seek_for_prev;
    src.get = stub_get;
    src.read_failed = stub_read_failed;
    src.ctx = s;
    return src;
}

/* collect the forward (dir>0) or backward (dir<0) key stream as a "k:v" comma list into out */
static void collect(merge_iter_t *it, int dir, char *out, size_t out_cap)
{
    out[0] = '\0';
    int rc = dir > 0 ? merge_iter_seek_first(it) : merge_iter_seek_last(it);
    while (rc == TDB_SUCCESS)
    {
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                                 &deleted),
                  TDB_SUCCESS);
        char item[64];
        snprintf(item, sizeof(item), "%.*s:%.*s,", (int)key_size, (const char *)key,
                 (int)value_size, value ? (const char *)value : "");
        strncat(out, item, out_cap - strlen(out) - 1);
        rc = dir > 0 ? merge_iter_next(it) : merge_iter_prev(it);
    }
}

/* the merge folds two sources in key order, resolving each key to its newest version across sources
 */
void test_merge_forward_newest_wins(void)
{
    /* "a" appears in both sources; the higher seq (a5) wins */
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"c", 3, "c3"}};
    static const stub_entry_t eb[] = {{"a", 5, "a5"}, {"b", 2, "b2"}};
    stub_src_t sa = {.entries = ea, .n = 2}, sb = {.entries = eb, .n = 2};
    merge_source_t sources[2] = {stub_source(&sa), stub_source(&sb)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 2, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);
    char got[128];
    collect(it, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:a5,b:b2,c:c3,") == 0);
    merge_iter_free(it);
}

/* a snapshot hides versions above it, so an older version of a key becomes the visible one */
void test_merge_snapshot_visibility(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"c", 3, "c3"}};
    static const stub_entry_t eb[] = {{"a", 5, "a5"}, {"b", 2, "b2"}};
    stub_src_t sa = {.entries = ea, .n = 2}, sb = {.entries = eb, .n = 2};
    merge_source_t sources[2] = {stub_source(&sa), stub_source(&sb)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 2, 3, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS); /* snapshot 3 */
    char got[128];
    collect(it, 1, got, sizeof(got));
    /* a5 is above the snapshot, so a resolves to a1; b2 and c3 are visible */
    ASSERT_TRUE(strcmp(got, "a:a1,b:b2,c:c3,") == 0);
    merge_iter_free(it);
}

/* a source that stops because it could not read looks exactly like one that ran out, so the merge
 * would end the scan and drop everything past the failure while reporting a clean finish. the merge
 * has to say the stream is incomplete instead of handing back a short scan as the whole answer */
void test_merge_source_read_failure_is_not_end_of_scan(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"b", 2, "b2"}, {"c", 3, "c3"}};
    /* readable through b, then unable to load what holds c */
    stub_src_t sa = {.entries = ea, .n = 3, .fail_at = 2};
    merge_source_t sources[1] = {stub_source(&sa)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 1, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_seek_first(it), TDB_SUCCESS);

    const uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), TDB_SUCCESS);
    ASSERT_TRUE(key_size == 1 && key[0] == 'a');

    /* c is still out there, so this must not read as a clean end of scan */
    const int rc = merge_iter_next(it);
    ASSERT_EQ(rc, TDB_ERR_IO);
    ASSERT_TRUE(rc != TDB_ERR_NOT_FOUND);
    ASSERT_EQ(merge_iter_valid(it), 0);

    merge_iter_free(it);
}

/* a tombstone hides its key on a read, and surfaces on the raw scan a compaction runs */
void test_merge_tombstone(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"b", 4, NULL}, {"c", 3, "c3"}};
    stub_src_t sa = {.entries = ea, .n = 3};
    merge_source_t sources[1] = {stub_source(&sa)};

    merge_iter_t *hide = NULL;
    ASSERT_EQ(merge_iter_new(sources, 1, UINT64_MAX, MERGE_ITER_RESOLVE, &hide), TDB_SUCCESS);
    char got[128];
    collect(hide, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:a1,c:c3,") == 0); /* b is hidden */
    merge_iter_free(hide);

    /* raw hides nothing, which is what lets a compaction carry the tombstone into its output and
     * keep shadowing older versions in levels the merge did not include */
    stub_src_t sa2 = {.entries = ea, .n = 3};
    merge_source_t sources2[1] = {stub_source(&sa2)};
    merge_iter_t *keep = NULL;
    ASSERT_EQ(merge_iter_new(sources2, 1, UINT64_MAX, MERGE_ITER_RAW, &keep), TDB_SUCCESS);
    collect(keep, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:a1,b:,c:c3,") == 0); /* b surfaces as an empty-value tombstone */
    merge_iter_free(keep);
}

/* the backward scan yields the same resolved keys in reverse */
void test_merge_backward(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"c", 3, "c3"}};
    static const stub_entry_t eb[] = {{"a", 5, "a5"}, {"b", 2, "b2"}};
    stub_src_t sa = {.entries = ea, .n = 2}, sb = {.entries = eb, .n = 2};
    merge_source_t sources[2] = {stub_source(&sa), stub_source(&sb)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 2, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);
    char got[128];
    collect(it, -1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "c:c3,b:b2,a:a5,") == 0);
    merge_iter_free(it);
}

/* a raw scan is every version in one direction, so a flip has no correct answer for it -- the
 * re-seek a resolving flip uses steps over the very versions raw exists to emit, and turning round
 * without one re-emits the version just delivered. it is refused rather than answered wrongly */
void test_merge_raw_refuses_a_direction_flip(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"b", 2, "b2"}, {"c", 3, "c3"}};
    stub_src_t sa = {.entries = ea, .n = 3};
    merge_source_t sources[1] = {stub_source(&sa)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 1, UINT64_MAX, MERGE_ITER_RAW, &it), TDB_SUCCESS);

    ASSERT_EQ(merge_iter_seek_first(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_prev(it), TDB_ERR_INVALID_ARGS);

    /* refusing the turn leaves the scan where it was, so going on forward still works */
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);
    const uint8_t *key = NULL;
    size_t key_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(key_size == 1 && memcmp(key, "c", 1) == 0);

    /* and a raw scan that only ever runs backward never turns, so it is not refused */
    ASSERT_EQ(merge_iter_seek_last(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_prev(it), TDB_SUCCESS);

    merge_iter_free(it);
}

/* a mid-stream direction flip resumes correctly, neither repeating nor skipping a key */
void test_merge_direction_flip(void)
{
    static const stub_entry_t ea[] = {
        {"a", 1, "a1"}, {"b", 2, "b2"}, {"c", 3, "c3"}, {"d", 4, "d4"}};
    stub_src_t sa = {.entries = ea, .n = 4};
    merge_source_t sources[1] = {stub_source(&sa)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 1, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);

    /* forward to c */
    ASSERT_EQ(merge_iter_seek_first(it), TDB_SUCCESS); /* a */
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);       /* b */
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);       /* c */
    const uint8_t *key = NULL;
    size_t key_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "c", 1) == 0);

    /* flip backward -- should land on b, then a */
    ASSERT_EQ(merge_iter_prev(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "b", 1) == 0);

    /* flip forward again -- should land on c, then d */
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "c", 1) == 0);
    ASSERT_EQ(merge_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "d", 1) == 0);
    ASSERT_EQ(merge_iter_next(it), TDB_ERR_NOT_FOUND); /* end */

    merge_iter_free(it);
}

/* a seek lands on the first key at or after the target, and seek_for_prev at or before */
void test_merge_seek(void)
{
    static const stub_entry_t ea[] = {{"a", 1, "a1"}, {"c", 3, "c3"}, {"e", 5, "e5"}};
    stub_src_t sa = {.entries = ea, .n = 3};
    merge_source_t sources[1] = {stub_source(&sa)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 1, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);

    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(merge_iter_seek(it, (const uint8_t *)"b", 1), TDB_SUCCESS); /* first >= b is c */
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "c", 1) == 0);

    ASSERT_EQ(merge_iter_seek_for_prev(it, (const uint8_t *)"d", 1),
              TDB_SUCCESS); /* last <= d is c */
    ASSERT_EQ(merge_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "c", 1) == 0);

    merge_iter_free(it);
}

/* raw mode yields every version of every key in key-then-seq-descending order, unresolved, for a
 * compaction merge to apply its own retention */
void test_merge_raw_all_versions(void)
{
    /* two sources, "a" has three versions across them, "b" one, "c" a tombstone */
    static const stub_entry_t ea[] = {{"a", 3, "a3"}, {"a", 1, "a1"}, {"c", 4, NULL}};
    static const stub_entry_t eb[] = {{"a", 5, "a5"}, {"b", 2, "b2"}};
    stub_src_t sa = {.entries = ea, .n = 3}, sb = {.entries = eb, .n = 2};
    merge_source_t sources[2] = {stub_source(&sa), stub_source(&sb)};

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(sources, 2, UINT64_MAX, MERGE_ITER_RAW, &it), TDB_SUCCESS);
    char got[256];
    collect(it, 1, got, sizeof(got));
    /* a's three versions newest first, then b, then c's tombstone (empty value) -- nothing dropped
     */
    ASSERT_TRUE(strcmp(got, "a:a5,a:a3,a:a1,b:b2,c:,") == 0);
    merge_iter_free(it);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_merge_forward_newest_wins, tests_passed);
    RUN_TEST(test_merge_raw_all_versions, tests_passed);
    RUN_TEST(test_merge_snapshot_visibility, tests_passed);
    RUN_TEST(test_merge_tombstone, tests_passed);
    RUN_TEST(test_merge_backward, tests_passed);
    RUN_TEST(test_merge_raw_refuses_a_direction_flip, tests_passed);
    RUN_TEST(test_merge_direction_flip, tests_passed);
    RUN_TEST(test_merge_seek, tests_passed);
    RUN_TEST(test_merge_source_read_failure_is_not_end_of_scan, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
