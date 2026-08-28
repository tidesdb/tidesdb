/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/encoding/serialization.h"
#include "../src/base/errors.h"
#include "../src/iter/merge_sources.h"
#include "../src/txn/writeset.h" /* build a write set to overlay */
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define MS_MAX_LEVEL 12
#define MS_PROB      0.25f
#define MS_DIR       "." PATH_SEPARATOR "test_merge_src"

/* write a prefixed key (BE32 cf-index + user key) into buf, returning its size */
static size_t pkey(uint32_t cf, const char *user, uint8_t *buf)
{
    tdb_encode_be32(cf, buf);
    memcpy(buf + TDB_CF_PREFIX_SIZE, user, strlen(user));
    return TDB_CF_PREFIX_SIZE + strlen(user);
}

static void mt_put(skip_list_t *list, uint32_t cf, const char *user, const char *val, uint64_t seq,
                   uint8_t flags)
{
    uint8_t buf[64];
    const size_t n = pkey(cf, user, buf);
    ASSERT_EQ(skip_list_put_with_seq(list, buf, n, (const uint8_t *)val, val ? strlen(val) : 0, -1,
                                     seq, flags),
              0);
}

/* build a cf0 sstable on disk holding unprefixed (user key) entries and open a cursor over it */
static sstable_t *build_sstable(const char *dir, uint64_t id, const char *const *keys,
                                const char *const *vals, const uint64_t *seqs, int n)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.id = id;
    entry.birth_level = 1;
    entry.level = 1;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[64], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, filename);

    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE), 0);
    sstable_builder_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.target_node_size = BTREE_DEFAULT_NODE_SIZE;
    cfg.value_threshold = 1u << 20;
    cfg.enable_bloom = 1;
    cfg.bloom_fpr = 0.01;
    cfg.sync_mode = BLOCK_MANAGER_SYNC_NONE;
    cfg.id = id;
    cfg.partition = MANIFEST_NO_PARTITION;
    cfg.cf_name = "cf0";
    cfg.klog_path = path;

    sstable_builder_t *b = NULL;
    ASSERT_EQ(sstable_builder_new(&b, bm, NULL, &cfg), TDB_SUCCESS);
    for (int i = 0; i < n; i++)
        ASSERT_EQ(sstable_builder_add(b, (const uint8_t *)keys[i], strlen(keys[i]),
                                      (const uint8_t *)vals[i], strlen(vals[i]), seqs[i], 0, 0),
                  TDB_SUCCESS);
    sstable_t *built = NULL;
    ASSERT_EQ(sstable_builder_finish(b, &built, NULL), TDB_SUCCESS);
    sstable_builder_free(b);
    sstable_close(built); /* the klog persists; reopen it as a read handle */

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, dir, "cf0", &entry, BLOCK_MANAGER_SYNC_NONE, NULL,
                                         NULL, NULL, NULL, NULL),
              TDB_SUCCESS);
    return sst;
}

/* collect the merged stream forward (dir>0) or backward (dir<0) as a "k:v," list */
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

/* the memtable view yields only its column family's keys, unprefixed, both directions */
void test_memtable_source_bounds_cf(void)
{
    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, MS_MAX_LEVEL, MS_PROB), 0);
    mt_put(list, 0, "m1", "v-m1", 1, 0);
    mt_put(list, 0, "shared", "v-sh", 2, 0);
    mt_put(list, 1, "z", "v-z", 3, 0); /* another family, must be excluded */

    skip_list_cursor_t *cursor = NULL;
    ASSERT_EQ(skip_list_cursor_init(&cursor, list), 0);
    memtable_merge_source_t mts;
    memtable_merge_source_init(&mts, cursor, NULL, NULL, 0, UINT64_MAX);
    merge_source_t src[1];
    memtable_merge_source(&mts, &src[0]);

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(src, 1, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);
    char got[128];
    collect(it, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "m1:v-m1,shared:v-sh,") == 0); /* z (cf1) excluded */
    collect(it, -1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "shared:v-sh,m1:v-m1,") == 0);
    merge_iter_free(it);

    skip_list_cursor_free(cursor);
    skip_list_free(list);
}

/* the merge folds a memtable and an sstable, newest version across sources winning per key */
void test_merge_memtable_and_sstable(void)
{
    (void)remove_directory(MS_DIR);
    ASSERT_EQ(mkdir(MS_DIR, 0755), 0);

    skip_list_t *list = NULL;
    ASSERT_EQ(skip_list_new(&list, MS_MAX_LEVEL, MS_PROB), 0);
    mt_put(list, 0, "m1", "m1-old", 5, 0);
    mt_put(list, 0, "m1", "m1-new", 10, 0); /* newer version chained over m1-old */
    mt_put(list, 0, "shared", "mem-shared", 20, 0);

    const char *keys[] = {"s1", "shared"};
    const char *vals[] = {"sst-s1", "sst-shared"};
    const uint64_t seqs[] = {3, 8};
    sstable_t *sst = build_sstable(MS_DIR, 1, keys, vals, seqs, 2);
    sstable_iter_t *ssit = NULL;
    ASSERT_EQ(sstable_iter_new(sst, 0, &ssit), TDB_SUCCESS);

    skip_list_cursor_t *cursor = NULL;
    ASSERT_EQ(skip_list_cursor_init(&cursor, list), 0);
    memtable_merge_source_t mts;
    memtable_merge_source_init(&mts, cursor, NULL, NULL, 0, UINT64_MAX);
    merge_source_t src[2];
    memtable_merge_source(&mts, &src[0]);
    sstable_merge_source(ssit, &src[1]);

    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(src, 2, UINT64_MAX, MERGE_ITER_RESOLVE, &it), TDB_SUCCESS);
    char got[256];
    collect(it, 1, got, sizeof(got));
    /* m1 from the memtable's newest, s1 from the sstable, shared from the memtable (seq 20 > 8) */
    ASSERT_TRUE(strcmp(got, "m1:m1-new,s1:sst-s1,shared:mem-shared,") == 0);
    collect(it, -1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "shared:mem-shared,s1:sst-s1,m1:m1-new,") == 0);
    merge_iter_free(it);

    merge_iter_t *snap = NULL;
    memtable_merge_source_init(&mts, cursor, NULL, NULL, 0, 7); /* snapshot 7 */
    memtable_merge_source(&mts, &src[0]);
    ASSERT_EQ(merge_iter_new(src, 2, 7, MERGE_ITER_RESOLVE, &snap), TDB_SUCCESS);
    collect(snap, 1, got, sizeof(got));
    /* m1 resolves to m1-old (10 > 7), s1 visible (3), shared hidden (mem 20 and sst 8 both > 7) */
    ASSERT_TRUE(strcmp(got, "m1:m1-old,s1:sst-s1,") == 0);
    merge_iter_free(snap);

    sstable_iter_free(ssit);
    sstable_close(sst);
    skip_list_cursor_free(cursor);
    skip_list_free(list);
    (void)remove_directory(MS_DIR);
}

/* buffer one put (val non-NULL) or delete (val NULL) into the write set */
static void ws_put(tidesdb_writeset_t *ws, uint32_t cf, const char *key, const char *val)
{
    const uint8_t flags = val ? 0 : TDB_WAL_ENTRY_TOMBSTONE;
    ASSERT_EQ(
        tidesdb_writeset_put(ws, cf, (const uint8_t *)key, strlen(key),
                             val ? (const uint8_t *)val : NULL, val ? strlen(val) : 0, -1, flags),
        TDB_SUCCESS);
}

/* the write-set overlay yields one column family's buffered writes sorted by key, keeps the latest
 * write of each key, filters other families, surfaces deletes as tombstones, and reads both
 * directions */
void test_writeset_source_overlay(void)
{
    tidesdb_writeset_t *ws = tidesdb_writeset_create();
    ASSERT_TRUE(ws != NULL);
    /* out of order, a duplicate that must dedup to the latest, two deletes, and another family */
    ws_put(ws, 0, "d", "d1");
    ws_put(ws, 0, "b", "b1");
    ws_put(ws, 1, "x", "x1"); /* cf1, must be excluded from a cf0 overlay */
    ws_put(ws, 0, "b", "b2"); /* overwrite -- latest wins */
    ws_put(ws, 0, "d", NULL); /* delete d */
    ws_put(ws, 0, "a", "a1");
    ws_put(ws, 0, "c", "c1");
    ws_put(ws, 0, "c", NULL); /* put-then-delete -- collapses to a tombstone */

    /* a family with no buffered ops yields no overlay */
    ASSERT_TRUE(writeset_merge_source_new(ws, 5, 100) == NULL);

    writeset_merge_source_t *wss = writeset_merge_source_new(ws, 0, 100);
    ASSERT_TRUE(wss != NULL);
    merge_source_t src[1];

    /* a raw scan hides nothing, so the deletes come back as empty-valued tombstones -- which is
     * what makes the overlay's sort, dedup and family filter all visible in one pass. raw is
     * forward-only, so the backward and seek checks run against the resolving scan below */
    writeset_merge_source(wss, &src[0]);
    merge_iter_t *it = NULL;
    ASSERT_EQ(merge_iter_new(src, 1, 100, MERGE_ITER_RAW, &it), TDB_SUCCESS);
    char got[128];
    collect(it, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:a1,b:b2,c:,d:,") == 0); /* b2 not b1; c,d tombstones; x excluded */
    merge_iter_free(it);

    /* a read scan hides the tombstones, leaving only the live buffered writes, and reads both
     * directions over them */
    writeset_merge_source(wss, &src[0]);
    merge_iter_t *rd = NULL;
    ASSERT_EQ(merge_iter_new(src, 1, 100, MERGE_ITER_RESOLVE, &rd), TDB_SUCCESS);
    collect(rd, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:a1,b:b2,") == 0);
    collect(rd, -1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "b:b2,a:a1,") == 0);
    /* a seek lands on the first key at or after the target */
    ASSERT_EQ(merge_iter_seek(rd, (const uint8_t *)"b", 1), TDB_SUCCESS);
    const uint8_t *sk = NULL, *sv = NULL;
    size_t sks = 0, svs = 0;
    uint64_t sseq = 0, svoff = 0;
    int64_t sttl = 0;
    uint8_t sdel = 0;
    ASSERT_EQ(merge_iter_get(rd, &sk, &sks, &sseq, &sv, &svs, &svoff, &sttl, &sdel), TDB_SUCCESS);
    ASSERT_TRUE(sks == 1 && sk[0] == 'b' && svs == 2 && memcmp(sv, "b2", 2) == 0);
    merge_iter_free(rd);

    writeset_merge_source_free(wss);
    tidesdb_writeset_free(ws);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_memtable_source_bounds_cf, tests_passed);
    RUN_TEST(test_merge_memtable_and_sstable, tests_passed);
    RUN_TEST(test_writeset_source_overlay, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
