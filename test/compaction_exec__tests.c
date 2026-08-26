/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/compaction/compaction_exec.h"
#include "../src/flush/flush.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define CE_DB_DIR    "." PATH_SEPARATOR "test_compaction_db"
#define CE_MAX_LEVEL 12
#define CE_PROB      0.25f

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
    size_t value_threshold;
} ce_db_t;

static void ce_db_open_threshold(ce_db_t *db, size_t value_threshold)
{
    (void)remove_directory(CE_DB_DIR);
    ASSERT_EQ(mkdir(CE_DB_DIR, 0755), 0);
    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(CE_DB_DIR, &vc, &db->vlog), VLOG_OK);
    db->cache = cache_create(NULL);
    ASSERT_EQ(fd_manager_init(&db->fdm, 0), 0);
    snprintf(db->manifest_path, sizeof(db->manifest_path), "%s%sMANIFEST", CE_DB_DIR,
             PATH_SEPARATOR);
    db->manifest = tidesdb_manifest_open(db->manifest_path);
    ASSERT_TRUE(db->manifest != NULL);

    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", "cf0");
    cfg.level_size_ratio = 10;
    cfg.min_levels = 3;
    db->value_threshold = value_threshold;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    ASSERT_EQ(
        cf_create(CE_DB_DIR, 0, &cfg, NULL, db->vlog, db->cache, &db->fdm, NULL, NULL, &db->cf), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(db->manifest, 0, "cf0", NULL, 0), 0);

    db->l0 = tidesdb_l0_create(64 * 1024, 8, CE_MAX_LEVEL, CE_PROB, NULL, NULL);
    tidesdb_l0_set_active(db->l0,
                          tidesdb_memtable_create(NULL, 0, 0, CE_MAX_LEVEL, CE_PROB, NULL, NULL));
    atomic_init(&db->next_id, 100);
}

static void ce_db_close(ce_db_t *db)
{
    tidesdb_l0_destroy(db->l0);
    cf_free(db->cf);
    tidesdb_manifest_close(db->manifest);
    fd_manager_destroy(&db->fdm);
    cache_destroy(db->cache);
    vlog_close(db->vlog);
    (void)remove_directory(CE_DB_DIR);
}

/* apply a batch of {key,val,seq,deleted} to the active memtable, then rotate and flush it to an L1
 * sstable, returning the sstable's id */
typedef struct
{
    const char *key;
    const char *val;
    uint64_t seq;
    int deleted;
} ce_entry_t;

/* the default cf keeps every value inline so a test sees klog bytes and logical bytes agree */
static void ce_db_open(ce_db_t *db)
{
    ce_db_open_threshold(db, 1u << 20);
}

static uint64_t ce_flush(ce_db_t *db, const ce_entry_t *entries, int n, uint64_t generation)
{
    for (int i = 0; i < n; i++)
    {
        const ce_entry_t *e = &entries[i];
        const uint8_t flags = e->deleted ? SKIP_LIST_FLAG_DELETED : 0;
        ASSERT_EQ(tidesdb_l0_apply(db->l0, 0, (const uint8_t *)e->key, strlen(e->key),
                                   e->deleted ? NULL : (const uint8_t *)e->val,
                                   e->deleted ? 0 : strlen(e->val), -1, e->seq, flags),
                  TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_l0_rotate(db->l0, tidesdb_memtable_create(NULL, generation, generation,
                                                                CE_MAX_LEVEL, CE_PROB, NULL, NULL)),
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
                      .value_threshold = db->value_threshold};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    return id;
}

/* read one key out of a level, asserting the value and tombstone flag; -1 expects absence */
static void ce_assert_read(cf_t *cf, int level, const char *key, const char *expect_val)
{
    sstable_t *out[8];
    const int n = level_set_overlapping(cf->levels, level, (const uint8_t *)key, strlen(key),
                                        (const uint8_t *)key, strlen(key), out, 8);
    int found = 0;
    for (int i = 0; i < n; i++)
    {
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0, seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        if (!found &&
            sstable_get(out[i], (const uint8_t *)key, strlen(key), &value, &value_size,
                        &vlog_offset, &seq, &ttl, &deleted) == TDB_SUCCESS &&
            !deleted)
        {
            found = 1;
            ASSERT_EQ((int)value_size, (int)strlen(expect_val));
            /* a spilled value comes back as its reference, so follow it to compare the bytes --
             * which also proves the compaction carried the reference forward intact */
            if (!value && vlog_offset != 0)
            {
                size_t spilled_size = 0;
                ASSERT_EQ(vlog_read(cf->vlog, vlog_offset, &value, &spilled_size), VLOG_OK);
                ASSERT_EQ((int)spilled_size, (int)strlen(expect_val));
            }
            ASSERT_TRUE(value != NULL);
            ASSERT_TRUE(memcmp(value, expect_val, value_size) == 0);
            free(value);
        }
        else if (value)
            free(value);
    }
    for (int i = 0; i < n; i++)
        if (sstable_unref(out[i])) sstable_close(out[i]);
    ASSERT_TRUE(expect_val ? found : !found);
}

/* a compaction merges two overlapping L1 sstables into one L2 sstable, newest version winning */
void test_compaction_merges_l1_to_l2(void)
{
    ce_db_t db;
    ce_db_open(&db);

    const ce_entry_t a[] = {{"a", "v-a", 1, 0}, {"c", "c-old", 2, 0}};
    const ce_entry_t b[] = {{"b", "v-b", 3, 0}, {"c", "c-new", 4, 0}};
    const uint64_t id0 = ce_flush(&db, a, 2, 1);
    const uint64_t id1 = ce_flush(&db, b, 2, 2);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 2);

    const uint64_t inputs[2] = {id0, id1};
    const compaction_job_t job = {.input_ids = inputs,
                                  .n_inputs = 2,
                                  .target_level = 2,
                                  .is_largest_level = 1,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    ASSERT_EQ(level_set_count(db.cf->levels, 1), 0); /* L1 drained */
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1); /* one merged L2 sstable */
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0), 1);

    ce_assert_read(db.cf, 2, "a", "v-a");
    ce_assert_read(db.cf, 2, "b", "v-b");
    ce_assert_read(db.cf, 2, "c", "c-new"); /* seq 4 beat seq 2 */

    ce_db_close(&db);
}

/* a tombstone at the largest level below the GC floor is dropped; the live key survives */
void test_compaction_tombstone_gc(void)
{
    ce_db_t db;
    ce_db_open(&db);

    const ce_entry_t a[] = {{"keep", "v", 1, 0}, {"gone", NULL, 2, 1}};
    const uint64_t id0 = ce_flush(&db, a, 2, 1);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1);

    const uint64_t inputs[1] = {id0};
    const compaction_job_t job = {.input_ids = inputs,
                                  .n_inputs = 1,
                                  .target_level = 2,
                                  .is_largest_level = 1,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {
        .cf = db.cf,
        .manifest = db.manifest,
        .manifest_path = db.manifest_path,
        .next_sstable_id = &db.next_id,
        .gc_floor = UINT64_MAX, /* no active snapshot -> the tombstone GCs */
        .sync_mode = BLOCK_MANAGER_SYNC_NONE,
        .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);
    ce_assert_read(db.cf, 2, "keep", "v");
    ce_assert_read(db.cf, 2, "gone", NULL); /* tombstone reaped, key absent */

    ce_db_close(&db);
}

/* a job whose inputs were already compacted away is a no-op, not a failure */
void test_compaction_stale_job(void)
{
    ce_db_t db;
    ce_db_open(&db);
    const ce_entry_t a[] = {{"a", "v", 1, 0}};
    (void)ce_flush(&db, a, 1, 1);

    const uint64_t missing[1] = {999}; /* never existed */
    const compaction_job_t job = {.input_ids = missing,
                                  .n_inputs = 1,
                                  .target_level = 2,
                                  .is_largest_level = 1,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS); /* skipped cleanly */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1);    /* nothing changed */
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 0);

    ce_db_close(&db);
}

/* a boundary split writes one output per partition, each overlapping only its own key range */
void test_compaction_split_boundaries(void)
{
    ce_db_t db;
    ce_db_open(&db);
    const ce_entry_t a[] = {{"a", "va", 1, 0},
                            {"b", "vb", 2, 0},
                            {"c", "vc", 3, 0},
                            {"d", "vd", 4, 0},
                            {"e", "ve", 5, 0}};
    const uint64_t id0 = ce_flush(&db, a, 5, 1);

    static const uint8_t bkey[] = "c";
    const uint8_t *boundaries[1] = {bkey};
    const size_t boundary_sizes[1] = {1};
    const uint64_t inputs[1] = {id0};
    compaction_job_t job = {0};
    job.input_ids = inputs;
    job.n_inputs = 1;
    job.target_level = 2;
    job.is_largest_level = 1;
    job.split = COMPACTION_SPLIT_BOUNDARIES;
    job.boundaries = boundaries;
    job.boundary_sizes = boundary_sizes;
    job.n_boundaries = 1;
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    /* a,b in one output; c,d,e in the other -- two L2 files split at "c" */
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 2);
    /* "a" overlaps exactly one file, "d" exactly one, never both */
    sstable_t *out[8];
    ASSERT_EQ(level_set_overlapping(db.cf->levels, 2, (const uint8_t *)"a", 1, (const uint8_t *)"a",
                                    1, out, 8),
              1);
    if (sstable_unref(out[0])) sstable_close(out[0]);
    ASSERT_EQ(level_set_overlapping(db.cf->levels, 2, (const uint8_t *)"d", 1, (const uint8_t *)"d",
                                    1, out, 8),
              1);
    if (sstable_unref(out[0])) sstable_close(out[0]);
    ce_assert_read(db.cf, 2, "a", "va");
    ce_assert_read(db.cf, 2, "e", "ve");
    ce_db_close(&db);
}

/* a size split rolls to a new output once the running size crosses file_max, at key boundaries */
void test_compaction_split_size(void)
{
    ce_db_t db;
    ce_db_open(&db);
    ce_entry_t k[10];
    char keys[10][8], vals[10][16];
    for (int i = 0; i < 10; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "k%d", i);
        snprintf(vals[i], sizeof(vals[i]), "value-%d", i);
        k[i] = (ce_entry_t){keys[i], vals[i], (uint64_t)(i + 1), 0};
    }
    const uint64_t id0 = ce_flush(&db, k, 10, 1);

    const uint64_t inputs[1] = {id0};
    compaction_job_t job = {0};
    job.input_ids = inputs;
    job.n_inputs = 1;
    job.target_level = 2;
    job.is_largest_level = 1;
    job.split = COMPACTION_SPLIT_NONE;
    job.file_max = 24; /* a few keys' worth, so the run splits into several files */
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    ASSERT_TRUE(level_set_count(db.cf->levels, 2) > 1); /* rolled into multiple files */
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0),
              level_set_count(db.cf->levels, 2));
    ce_assert_read(db.cf, 2, "k0", "value-0");
    ce_assert_read(db.cf, 2, "k9", "value-9");
    ce_db_close(&db);
}

/* splitting a merge across threads changes who writes each file, not which files get written.
 *
 * the ranges a subdivided merge runs are the boundary partitions the sink would have rolled at
 * anyway, so the same partitions produce the same outputs and every key reads back the same. this
 * is the property the whole design rests on -- if it did not hold, a merge's result would depend on
 * how many threads happened to be available, which is not something a storage engine may do */
void test_compaction_subdivided_merge_matches_one_thread(void)
{
    static const uint8_t b10[] = "k10", b20[] = "k20", b30[] = "k30";
    const uint8_t *boundaries[3] = {b10, b20, b30};
    const size_t boundary_sizes[3] = {3, 3, 3};

    int undivided_files = 0;
    for (int pass = 0; pass < 2; pass++)
    {
        const int subdivide = pass == 1;
        ce_db_t db;
        ce_db_open(&db);

        ce_entry_t k[40];
        char keys[40][8], vals[40][16];
        for (int i = 0; i < 40; i++)
        {
            /* zero padded so byte order is numeric order and the boundaries fall where intended */
            snprintf(keys[i], sizeof(keys[i]), "k%02d", i);
            snprintf(vals[i], sizeof(vals[i]), "value-%02d", i);
            k[i] = (ce_entry_t){keys[i], vals[i], (uint64_t)(i + 1), 0};
        }
        const uint64_t id0 = ce_flush(&db, k, 40, 1);

        const uint64_t inputs[1] = {id0};
        compaction_job_t job = {0};
        job.input_ids = inputs;
        job.n_inputs = 1;
        job.target_level = 2;
        job.is_largest_level = 1;
        job.split = COMPACTION_SPLIT_BOUNDARIES;
        job.boundaries = boundaries;
        job.boundary_sizes = boundary_sizes;
        job.n_boundaries = 3;
        job.may_subdivide = subdivide;

        const compaction_ctx_t cx = {.cf = db.cf,
                                     .manifest = db.manifest,
                                     .manifest_path = db.manifest_path,
                                     .next_sstable_id = &db.next_id,
                                     .gc_floor = UINT64_MAX,
                                     .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                     .value_threshold = db.value_threshold,
                                     /* four ranges for four partitions on the second pass, and a
                                      * budget the first pass may not use because its job withholds
                                      * permission */
                                     .max_subdivisions = 4};
        ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

        const int files = level_set_count(db.cf->levels, 2);
        ASSERT_EQ(files, 4); /* one per boundary partition, however many threads wrote them */
        ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0), files);
        if (!subdivide)
            undivided_files = files;
        else
            ASSERT_EQ(files, undivided_files);

        /* every key survives, in its own partition, with the version the merge should have kept */
        for (int i = 0; i < 40; i++) ce_assert_read(db.cf, 2, keys[i], vals[i]);

        ce_db_close(&db);
    }
}

/* a cap and a boundary split apply together: each partition's output is capped, and every output
 * still overlaps at most one file above because a capped output is a subset of its partition */
void test_compaction_split_size_within_boundaries(void)
{
    ce_db_t db;
    ce_db_open(&db);
    ce_entry_t k[10];
    char keys[10][8], vals[10][16];
    for (int i = 0; i < 10; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "k%d", i);
        snprintf(vals[i], sizeof(vals[i]), "value-%d", i);
        k[i] = (ce_entry_t){keys[i], vals[i], (uint64_t)(i + 1), 0};
    }
    const uint64_t id0 = ce_flush(&db, k, 10, 1);

    static const uint8_t bkey[] = "k5";
    const uint8_t *boundaries[1] = {bkey};
    const size_t boundary_sizes[1] = {2};
    const uint64_t inputs[1] = {id0};
    compaction_job_t job = {0};
    job.input_ids = inputs;
    job.n_inputs = 1;
    job.target_level = 2;
    job.is_largest_level = 1;
    job.split = COMPACTION_SPLIT_BOUNDARIES;
    job.boundaries = boundaries;
    job.boundary_sizes = boundary_sizes;
    job.n_boundaries = 1;
    job.file_max = 24; /* well under a partition, so the cap rolls inside each one */
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    /* more outputs than the two the boundary alone would give */
    ASSERT_TRUE(level_set_count(db.cf->levels, 2) > 2);
    sstable_t *out[16];
    ASSERT_EQ(level_set_overlapping(db.cf->levels, 2, (const uint8_t *)"k0", 2,
                                    (const uint8_t *)"k0", 2, out, 16),
              1);
    if (sstable_unref(out[0])) sstable_close(out[0]);
    ce_assert_read(db.cf, 2, "k0", "value-0");
    ce_assert_read(db.cf, 2, "k9", "value-9");
    ce_db_close(&db);
}

/* the cap counts what the klog actually holds, so a spilled value contributes its reference and not
 * its bytes -- counting the logical value size would split this run into one file per key */
void test_compaction_split_size_excludes_spilled_values(void)
{
    ce_db_t db;
    ce_db_open_threshold(&db, 64); /* every value below spills to the vlog */
    ce_entry_t k[10];
    char keys[10][8];
    static char vals[10][512];
    for (int i = 0; i < 10; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "k%d", i);
        memset(vals[i], 'a' + i, sizeof(vals[i]) - 1);
        vals[i][sizeof(vals[i]) - 1] = '\0';
        k[i] = (ce_entry_t){keys[i], vals[i], (uint64_t)(i + 1), 0};
    }
    const uint64_t id0 = ce_flush(&db, k, 10, 1);

    const uint64_t inputs[1] = {id0};
    compaction_job_t job = {0};
    job.input_ids = inputs;
    job.n_inputs = 1;
    job.target_level = 2;
    job.is_largest_level = 1;
    job.split = COMPACTION_SPLIT_NONE;
    /* above the keys and their entry metadata, far below the 5120 bytes of values */
    job.file_max = 1024;
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);
    ce_assert_read(db.cf, 2, "k0", vals[0]);
    ce_assert_read(db.cf, 2, "k9", vals[9]);
    ce_db_close(&db);
}

/* whether the newest version of key across the cf's sstable levels is a live put */
static int ce_merged_present(cf_t *cf, const char *key)
{
    const size_t kl = strlen(key);
    uint64_t best_seq = 0;
    int best_del = 1, found = 0;
    for (int lvl = 1; lvl <= LEVEL_SET_MAX_LEVELS; lvl++)
    {
        sstable_t *out[8];
        const int n = level_set_overlapping(cf->levels, lvl, (const uint8_t *)key, kl,
                                            (const uint8_t *)key, kl, out, 8);
        for (int i = 0; i < n; i++)
        {
            uint8_t *v = NULL;
            size_t vs = 0;
            uint64_t vo = 0, sq = 0;
            int64_t tl = 0;
            uint8_t dl = 0;
            if (sstable_get(out[i], (const uint8_t *)key, kl, &v, &vs, &vo, &sq, &tl, &dl) ==
                TDB_SUCCESS)
            {
                if (!found || sq > best_seq)
                {
                    best_seq = sq;
                    best_del = dl;
                    found = 1;
                }
                free(v);
            }
        }
        for (int i = 0; i < n; i++)
            if (sstable_unref(out[i])) sstable_close(out[i]);
    }
    return found && !best_del;
}

/* a tombstone at the largest level is not GC-dropped while a sibling sstable outside the merge
 * still holds the key, since dropping it would resurrect the older version once its shadow is gone
 */
void test_compaction_keeps_tombstone_with_sibling(void)
{
    ce_db_t db;
    ce_db_open(&db);

    const ce_entry_t put[] = {{"k", "v", 1, 0}};  /* id0 at L1 holds k put @1 */
    const ce_entry_t del[] = {{"k", NULL, 2, 1}}; /* id1 at L1 holds the newer k tombstone @2 */
    (void)ce_flush(&db, put, 1, 1);
    const uint64_t id1 = ce_flush(&db, del, 1, 2);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 2);

    /* compact only the tombstone sstable into the largest level, leaving the put's sstable at L1 */
    const uint64_t inputs[1] = {id1};
    const compaction_job_t job = {.input_ids = inputs,
                                  .n_inputs = 1,
                                  .target_level = 2,
                                  .is_largest_level = 1,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {.cf = db.cf,
                                 .manifest = db.manifest,
                                 .manifest_path = db.manifest_path,
                                 .next_sstable_id = &db.next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = db.value_threshold};
    ASSERT_EQ(compaction_exec(&cx, &job), TDB_SUCCESS);

    /* the tombstone was kept, so k's newest version stays a delete and it does not resurrect */
    ASSERT_TRUE(!ce_merged_present(db.cf, "k"));

    ce_db_close(&db);
}

/* ===== two compactions of one family, running at once against overlapping inputs =====
 *
 * a family's compaction claim is taken for a whole plan rather than for a job, and the plan's jobs
 * are handed to separate workers, so two merges of one family do run at the same time and can
 * resolve the same input. each takes its own reference on the inputs it resolved and each swaps its
 * outputs in under the level set's write lock, so the second swap finds an input the first already
 * removed and removes nothing for it. every reference taken along the way has to still be given
 * back: the handle count after the family is torn down is the whole assertion, and driving the
 * interleaving here reaches it thousands of times a second where a full concurrent run reaches it
 * by accident */
#define CE_RACE_ROUNDS  64
#define CE_RACE_READERS 2

typedef struct
{
    ce_db_t *db;
    const uint64_t *inputs;
    int n_inputs;
    int target_level;
} ce_race_arg_t;

static void *ce_race_compact(void *arg)
{
    const ce_race_arg_t *a = (const ce_race_arg_t *)arg;
    const compaction_job_t job = {.input_ids = a->inputs,
                                  .n_inputs = a->n_inputs,
                                  .target_level = a->target_level,
                                  .is_largest_level = 0,
                                  .split = COMPACTION_SPLIT_NONE,
                                  .file_max = 0};
    const compaction_ctx_t cx = {.cf = a->db->cf,
                                 .manifest = a->db->manifest,
                                 .manifest_path = a->db->manifest_path,
                                 .next_sstable_id = &a->db->next_id,
                                 .gc_floor = UINT64_MAX,
                                 .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                 .value_threshold = a->db->value_threshold};
    /* a stale job is reported as success and a lost race as a failure; neither is an error here,
     * since what is under test is what happens to the references either way */
    (void)compaction_exec(&cx, &job);
    return NULL;
}

static _Atomic(int) ce_race_stop;

/* a reader takes a reference on every candidate it collects and gives it back; running one against
 * the swaps is what makes a snapshot land between a level set losing an input and gaining an
 * output */
static void *ce_race_reader(void *arg)
{
    ce_db_t *db = (ce_db_t *)arg;
    while (!atomic_load_explicit(&ce_race_stop, memory_order_acquire))
    {
        const int total = level_set_snapshot(db->cf->levels, NULL, 0);
        if (total <= 0) continue;
        level_set_snapshot_entry_t *all = calloc((size_t)total, sizeof(*all));
        if (!all) continue;
        const int got = level_set_snapshot(db->cf->levels, all, total);
        for (int i = 0; i < got && i < total; i++)
            if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
        free(all);
    }
    return NULL;
}

void test_compaction_concurrent_merges_return_every_reference(void)
{
    for (int round = 0; round < CE_RACE_ROUNDS; round++)
    {
        ce_db_t db;
        ce_db_open(&db);

        const ce_entry_t a[] = {{"a", "v-a", 1, 0}, {"c", "c-old", 2, 0}};
        const ce_entry_t b[] = {{"b", "v-b", 3, 0}, {"c", "c-new", 4, 0}};
        const ce_entry_t c[] = {{"d", "v-d", 5, 0}, {"e", "v-e", 6, 0}};
        const uint64_t id0 = ce_flush(&db, a, 2, 1);
        const uint64_t id1 = ce_flush(&db, b, 2, 2);
        const uint64_t id2 = ce_flush(&db, c, 2, 3);

        /* the two jobs share id1, so whichever swaps second is handed an input the level set no
         * longer holds -- the case a single-threaded run never produces */
        const uint64_t left[2] = {id0, id1};
        const uint64_t right[2] = {id1, id2};
        ce_race_arg_t la = {&db, left, 2, 2};
        ce_race_arg_t ra = {&db, right, 2, 2};

        atomic_store(&ce_race_stop, 0);
        pthread_t readers[CE_RACE_READERS];
        int n_readers = 0;
        for (int i = 0; i < CE_RACE_READERS; i++)
            if (pthread_create(&readers[i], NULL, ce_race_reader, &db) == 0) n_readers++;

        pthread_t t;
        const int spawned = pthread_create(&t, NULL, ce_race_compact, &la) == 0;
        ce_race_compact(&ra);
        if (spawned)
            pthread_join(t, NULL);
        else
            ce_race_compact(&la);

        atomic_store(&ce_race_stop, 1);
        for (int i = 0; i < n_readers; i++) pthread_join(readers[i], NULL);

        ce_db_close(&db);
    }
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST_HANDLE_BALANCED(test_compaction_merges_l1_to_l2, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_tombstone_gc, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_stale_job, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_split_boundaries, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_subdivided_merge_matches_one_thread, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_split_size, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_split_size_within_boundaries, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_split_size_excludes_spilled_values, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_keeps_tombstone_with_sibling, tests_passed);
    RUN_TEST_HANDLE_BALANCED(test_compaction_concurrent_merges_return_every_reference,
                             tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
