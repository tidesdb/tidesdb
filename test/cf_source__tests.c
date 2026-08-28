/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/column_family/column_family.h"
#include "../src/compaction/compaction_exec.h"
#include "../src/flush/flush.h"
#include "../src/txn/cf_source.h"
#include "test_utils.h"

/* the cf sstable source reads one column family's on-disk levels as a transaction read source.
 * these tests build a real cf, flush sstables into it, and drive cf_source directly: snapshot
 * visibility, highest-seq-wins across overlapping L1 files, tombstones, spilled-value resolution
 * through the vlog, top-down level shadowing, and misses -- no engine, no txn. */

static int tests_passed = 0;
static int tests_failed = 0;

#define CS_DB_DIR          "." PATH_SEPARATOR "test_cf_source_db"
#define CS_MAX_LEVEL       12
#define CS_PROB            0.25f
#define CS_SPILL_THRESHOLD 8 /* values longer than this spill to the vlog */

typedef struct
{
    vlog_t *vlog;
    cache_t *cache;
    fd_manager_t fdm;
    tidesdb_manifest_t *manifest;
    char manifest_path[256];
    tidesdb_l0_t *l0;
    cf_t *cf;
    _Atomic(uint64_t) next_id;
} cs_db_t;

static void cs_db_open(cs_db_t *db)
{
    (void)remove_directory(CS_DB_DIR);
    ASSERT_EQ(mkdir(CS_DB_DIR, 0755), 0);
    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(CS_DB_DIR, &vc, &db->vlog), VLOG_OK);
    db->cache = cache_create(NULL);
    ASSERT_EQ(fd_manager_init(&db->fdm, 0), 0);
    snprintf(db->manifest_path, sizeof(db->manifest_path), "%s%sMANIFEST", CS_DB_DIR,
             PATH_SEPARATOR);
    db->manifest = tidesdb_manifest_open(db->manifest_path);
    ASSERT_TRUE(db->manifest != NULL);

    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", "cf0");
    cfg.level_size_ratio = 10;
    cfg.min_levels = 3;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    ASSERT_EQ(
        cf_create(CS_DB_DIR, 0, &cfg, NULL, db->vlog, db->cache, &db->fdm, NULL, NULL, &db->cf), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(db->manifest, 0, "cf0", NULL, 0), 0);

    db->l0 = tidesdb_l0_create(64 * 1024, 8, CS_MAX_LEVEL, CS_PROB, NULL, NULL);
    tidesdb_l0_set_active(db->l0,
                          tidesdb_memtable_create(NULL, 0, 0, CS_MAX_LEVEL, CS_PROB, NULL, NULL));
    atomic_init(&db->next_id, 100);
}

static void cs_db_close(cs_db_t *db)
{
    tidesdb_l0_destroy(db->l0);
    cf_free(db->cf);
    tidesdb_manifest_close(db->manifest);
    fd_manager_destroy(&db->fdm);
    cache_destroy(db->cache);
    vlog_close(db->vlog);
    (void)remove_directory(CS_DB_DIR);
}

typedef struct
{
    const char *key;
    const char *val;
    size_t val_size; /* 0 means strlen(val) */
    uint64_t seq;
    int deleted;
} cs_entry_t;

/* apply a batch to the active memtable, rotate, and flush it to one L1 sstable; returns the sstable
 * id */
static uint64_t cs_flush(cs_db_t *db, const cs_entry_t *entries, int n, uint64_t generation)
{
    for (int i = 0; i < n; i++)
    {
        const cs_entry_t *e = &entries[i];
        const size_t vsize = e->deleted ? 0 : (e->val_size ? e->val_size : strlen(e->val));
        const uint8_t flags = e->deleted ? SKIP_LIST_FLAG_DELETED : 0;
        ASSERT_EQ(
            tidesdb_l0_apply(db->l0, 0, (const uint8_t *)e->key, strlen(e->key),
                             e->deleted ? NULL : (const uint8_t *)e->val, vsize, -1, e->seq, flags),
            TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_l0_rotate(db->l0, tidesdb_memtable_create(NULL, generation, generation,
                                                                CS_MAX_LEVEL, CS_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(db->l0);
    const uint64_t id = atomic_load(&db->next_id);
    cf_t *cfs[1] = {db->cf};
    flush_ctx_t fx = {.l0 = db->l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db->manifest,
                      .manifest_path = db->manifest_path,
                      .next_sstable_id = &db->next_id,
                      .fdm = &db->fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = CS_SPILL_THRESHOLD};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    return id;
}

/* merge every L1 sstable down into one L2 sstable, so a later L1 flush shadows it from above */
static void cs_grow_to_l2(cs_db_t *db, const uint64_t *ids, int n)
{
    const compaction_job_t job = {.input_ids = ids,
                                  .n_inputs = n,
                                  .target_level = 2,
                                  .is_largest_level = 1,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {.cf = db->cf,
                                 .manifest = db->manifest,
                                 .manifest_path = db->manifest_path,
                                 .next_sstable_id = &db->next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = CS_SPILL_THRESHOLD};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);
}

/* read one key through cf_source at a snapshot, returning the result and filling out */
static tidesdb_source_result_t cs_get(cf_t *cf, const char *key, uint64_t snapshot,
                                      tidesdb_source_version_t *out)
{
    tidesdb_source_t src;
    cf_source(cf, &src);
    memset(out, 0, sizeof(*out));
    return src.get(src.ctx, 0, (const uint8_t *)key, strlen(key), snapshot, out);
}

/* assert a live hit with the expected value and seq */
static void cs_assert_live(cf_t *cf, const char *key, uint64_t snapshot, const char *expect_val,
                           uint64_t expect_seq)
{
    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(cf, key, snapshot, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ(out.deleted, 0);
    ASSERT_EQ((int)out.value_size, (int)strlen(expect_val));
    ASSERT_TRUE(out.value != NULL && memcmp(out.value, expect_val, out.value_size) == 0);
    ASSERT_EQ((int)out.seq, (int)expect_seq);
    free(out.value);
}

/* a basic point read finds a present key and misses an absent one */
void test_cf_source_basic(void)
{
    cs_db_t db;
    cs_db_open(&db);
    const cs_entry_t a[] = {{"a", "va", 0, 1, 0}, {"b", "vb", 0, 2, 0}};
    (void)cs_flush(&db, a, 2, 1);

    cs_assert_live(db.cf, "a", UINT64_MAX, "va", 1);
    cs_assert_live(db.cf, "b", UINT64_MAX, "vb", 2);

    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "absent", UINT64_MAX, &out), TDB_SOURCE_NOT_FOUND);

    cs_db_close(&db);
}

/* the snapshot ceiling picks the newest version at or below it across overlapping L1 files, and
 * misses below the oldest */
void test_cf_source_snapshot_visibility(void)
{
    cs_db_t db;
    cs_db_open(&db);
    const cs_entry_t f1[] = {{"k", "v3", 0, 3, 0}};
    const cs_entry_t f2[] = {{"k", "v7", 0, 7, 0}};
    (void)cs_flush(&db, f1, 1, 1);
    (void)cs_flush(&db, f2, 1, 2); /* two overlapping L1 sstables each holding one version of k */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 2);

    cs_assert_live(db.cf, "k", UINT64_MAX, "v7", 7); /* highest seq wins across the overlap */
    cs_assert_live(db.cf, "k", 7, "v7", 7);
    cs_assert_live(db.cf, "k", 5, "v3", 3); /* v7 is above the ceiling, v3 visible */
    cs_assert_live(db.cf, "k", 3, "v3", 3);

    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "k", 2, &out), TDB_SOURCE_NOT_FOUND); /* nothing at or below 2 */

    cs_db_close(&db);
}

/* a tombstone reads back as a found delete with no value, so the composer stops the walk */
void test_cf_source_tombstone(void)
{
    cs_db_t db;
    cs_db_open(&db);
    const cs_entry_t d[] = {{"gone", NULL, 0, 4, 1}};
    (void)cs_flush(&db, d, 1, 1);

    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "gone", UINT64_MAX, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ(out.deleted, 1);
    ASSERT_TRUE(out.value == NULL);
    ASSERT_EQ((int)out.seq, 4);

    cs_db_close(&db);
}

/* a value larger than the spill threshold comes back resolved through the vlog, not as a raw offset
 */
void test_cf_source_spilled_value(void)
{
    cs_db_t db;
    cs_db_open(&db);
    char big[64];
    for (int i = 0; i < (int)sizeof(big); i++) big[i] = (char)('A' + (i % 26));
    const cs_entry_t f[] = {{"big", big, sizeof(big), 1, 0}};
    (void)cs_flush(&db, f, 1, 1);

    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "big", UINT64_MAX, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ(out.deleted, 0);
    ASSERT_EQ((int)out.value_size, (int)sizeof(big));
    ASSERT_TRUE(out.value != NULL && memcmp(out.value, big, sizeof(big)) == 0);
    free(out.value);

    cs_db_close(&db);
}

/* a newer version flushed to L1 shadows an older one sitting at L2, and a snapshot below the L1
 * version still sees the L2 version -- top-down with per-level snapshot filtering */
void test_cf_source_top_down_levels(void)
{
    cs_db_t db;
    cs_db_open(&db);
    const cs_entry_t old[] = {{"k", "old", 0, 1, 0}};
    const uint64_t id0 = cs_flush(&db, old, 1, 1);
    const uint64_t l1[1] = {id0};
    cs_grow_to_l2(&db, l1, 1); /* k@old now lives at L2 */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 0);
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);

    const cs_entry_t fresh[] = {{"k", "new", 0, 5, 0}};
    (void)cs_flush(&db, fresh, 1, 2); /* k@new at L1, above the L2 version */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1);

    cs_assert_live(db.cf, "k", UINT64_MAX, "new", 5); /* L1 shadows L2 */
    cs_assert_live(db.cf, "k", 3, "old",
                   1); /* new@5 above the ceiling, fall through to L2's old@1 */

    cs_db_close(&db);
}

/* the level walk stops at the first level holding the key rather than comparing what each holds, so
 * an older version in L1 shadows a newer one in L2. compaction only ever moves keys downward, which
 * is what makes the walk right; this pins what it costs if anything ever moves one the other way */
void test_cf_source_l1_shadows_a_newer_l2(void)
{
    cs_db_t db;
    cs_db_open(&db);

    const cs_entry_t newer[] = {{"k", "newer", 0, 10, 0}};
    const uint64_t id0 = cs_flush(&db, newer, 1, 1);
    const uint64_t l1[1] = {id0};
    cs_grow_to_l2(&db, l1, 1); /* k@10 now lives at L2 */
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);

    const cs_entry_t stale[] = {{"k", "stale", 0, 5, 0}};
    (void)cs_flush(&db, stale, 1, 2); /* k@5 at L1, above the newer L2 version */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1);

    cs_assert_live(db.cf, "k", UINT64_MAX, "stale", 5);

    cs_db_close(&db);
}

/* a merge retires its inputs, so whatever intervals they carried have to reach the output or every
 * delete they held goes with their files. this is the other half of a tombstone living as long as a
 * table holds it, and the half a merge is responsible for. the table left outside the merge is what
 * makes the carry necessary here -- it holds a key the interval covers and the merge never reads
 * it, so an output that let the interval go would bring that key back */
void test_cf_source_compaction_carries_input_intervals(void)
{
    cs_db_t db;
    cs_db_open(&db);

    /* a flush that lays down a key and an interval covering a different one */
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(db.l0, 0, (const uint8_t *)"m", 1,
                                               (const uint8_t *)"q", 1, 7),
              TDB_SUCCESS);
    const cs_entry_t rows[] = {{"k", "v", 0, 3, 0}};
    const uint64_t id0 = cs_flush(&db, rows, 1, 1);

    sstable_t *l1[4];
    int n = level_set_overlapping(db.cf->levels, 1, (const uint8_t *)"k", 1, (const uint8_t *)"k",
                                  1, l1, 4);
    ASSERT_EQ(n, 1);
    ASSERT_TRUE(l1[0]->range_tombstones != NULL);
    if (sstable_unref(l1[0])) sstable_close(l1[0]);

    /* a second table, inside the interval's range and older than it, that the merge below will not
     * take as an input. flush order is not sequence order, which is how a table younger than an
     * interval still holds a key beneath it */
    const cs_entry_t covered[] = {{"n", "older", 0, 3, 0}};
    (void)cs_flush(&db, covered, 1, 2);

    /* merged down, the output carries what the input did */
    const uint64_t ids[1] = {id0};
    cs_grow_to_l2(&db, ids, 1);
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);

    sstable_t *l2[4];
    n = level_set_overlapping(db.cf->levels, 2, (const uint8_t *)"k", 1, (const uint8_t *)"k", 1,
                              l2, 4);
    ASSERT_EQ(n, 1);
    ASSERT_TRUE(l2[0]->range_tombstones != NULL);
    uint64_t seq = 0;
    ASSERT_EQ(range_tombstone_max_covering(l2[0]->range_tombstones, (const uint8_t *)"n", 1,
                                           UINT64_MAX, &seq),
              1);
    ASSERT_EQ((int)seq, 7);
    if (sstable_unref(l2[0])) sstable_close(l2[0]);

    /* and the key it covers is still deleted, which is what the carry was for */
    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "n", UINT64_MAX, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ((int)out.deleted, 1);
    free(out.value);

    cs_db_close(&db);
}

/* the other side of that rule. a merge writing the largest level, whose inputs are the only tables
 * the interval's range reaches and whose sequence is below the reclamation floor, has just deleted
 * everything the interval had left to delete. carrying it on would grow what every table after this
 * one writes for no reader that could tell */
void test_cf_source_compaction_drops_an_interval_it_has_finished(void)
{
    cs_db_t db;
    cs_db_open(&db);

    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(db.l0, 0, (const uint8_t *)"m", 1,
                                               (const uint8_t *)"q", 1, 7),
              TDB_SUCCESS);
    /* one key outside the interval so the merge still has an output, one inside for it to delete */
    const cs_entry_t rows[] = {{"k", "v", 0, 3, 0}, {"n", "gone", 0, 3, 0}};
    const uint64_t id0 = cs_flush(&db, rows, 2, 1);

    const uint64_t ids[1] = {id0};
    cs_grow_to_l2(&db, ids, 1);
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);

    sstable_t *l2[4];
    const int n = level_set_overlapping(db.cf->levels, 2, (const uint8_t *)"k", 1,
                                        (const uint8_t *)"k", 1, l2, 4);
    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)range_tombstone_set_count(l2[0]->range_tombstones), 0);
    if (sstable_unref(l2[0])) sstable_close(l2[0]);

    /* the covered key went with the merge, so letting the interval go resurrects nothing */
    cs_assert_live(db.cf, "k", UINT64_MAX, "v", 3);
    tidesdb_source_version_t out;
    ASSERT_EQ(cs_get(db.cf, "n", UINT64_MAX, &out), TDB_SOURCE_NOT_FOUND);

    cs_db_close(&db);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cf_source_basic, tests_passed);
    RUN_TEST(test_cf_source_snapshot_visibility, tests_passed);
    RUN_TEST(test_cf_source_tombstone, tests_passed);
    RUN_TEST(test_cf_source_spilled_value, tests_passed);
    RUN_TEST(test_cf_source_top_down_levels, tests_passed);
    RUN_TEST(test_cf_source_l1_shadows_a_newer_l2, tests_passed);
    RUN_TEST(test_cf_source_compaction_carries_input_intervals, tests_passed);
    RUN_TEST(test_cf_source_compaction_drops_an_interval_it_has_finished, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
