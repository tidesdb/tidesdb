/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/column_family/level/level_set.h"
#include "../src/compaction/compaction_exec.h"
#include "../src/compaction/compaction_planner.h"
#include "../src/flush/flush.h"
#include "test_utils.h"

/* the pipeline tests drive the whole compaction path over a live column family with no engine in
 * the loop: flush real sstables into L1, snapshot the level set, let the deterministic planner emit
 * the jobs the snapshot calls for, run each job through the executor, and assert the tree
 * structure, the read-back, and the tombstone gc all agree with what the planner decided. */

static int tests_passed = 0;
static int tests_failed = 0;

#define CP_DB_DIR     "." PATH_SEPARATOR "test_compaction_pipeline_db"
#define CP_MAX_LEVEL  12
#define CP_PROB       0.25f
#define CP_L1_TRIGGER 2
/* larger than any value these tests write, so nothing reaches the vlog */
#define CP_NO_SPILL (1u << 20)

#define CP_SIZE_RATIO 10
/* a base capacity large enough that only the l1 file-count trigger fires in these tests */
#define CP_BASE_CAPACITY (1u << 20)

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
} cp_db_t;

static void cp_db_open(cp_db_t *db)
{
    (void)remove_directory(CP_DB_DIR);
    ASSERT_EQ(mkdir(CP_DB_DIR, 0755), 0);
    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(CP_DB_DIR, &vc, &db->vlog), VLOG_OK);
    db->cache = cache_create(NULL);
    ASSERT_EQ(fd_manager_init(&db->fdm, 0), 0);
    snprintf(db->manifest_path, sizeof(db->manifest_path), "%s%sMANIFEST", CP_DB_DIR,
             PATH_SEPARATOR);
    db->manifest = tidesdb_manifest_open(db->manifest_path);
    ASSERT_TRUE(db->manifest != NULL);

    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", "cf0");
    cfg.level_size_ratio = CP_SIZE_RATIO;
    cfg.min_levels = 1;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    ASSERT_EQ(
        cf_create(CP_DB_DIR, 0, &cfg, NULL, db->vlog, db->cache, &db->fdm, NULL, NULL, &db->cf), 0);
    ASSERT_EQ(tidesdb_manifest_add_cf(db->manifest, 0, "cf0", NULL, 0), 0);

    db->l0 = tidesdb_l0_create(64 * 1024, 8, CP_MAX_LEVEL, CP_PROB, NULL, NULL);
    tidesdb_l0_set_active(db->l0,
                          tidesdb_memtable_create(NULL, 0, 0, CP_MAX_LEVEL, CP_PROB, NULL, NULL));
    atomic_init(&db->next_id, 100);
}

static void cp_db_close(cp_db_t *db)
{
    tidesdb_l0_destroy(db->l0);
    cf_free(db->cf);
    tidesdb_manifest_close(db->manifest);
    fd_manager_destroy(&db->fdm);
    cache_destroy(db->cache);
    vlog_close(db->vlog);
    (void)remove_directory(CP_DB_DIR);
}

/* one key of a flush batch */
typedef struct
{
    const char *key;
    const char *val;
    uint64_t seq;
    int deleted;
} cp_entry_t;

/* apply a batch to the active memtable, rotate, and flush it to one L1 sstable */
static void cp_flush(cp_db_t *db, const cp_entry_t *entries, int n, uint64_t generation)
{
    for (int i = 0; i < n; i++)
    {
        const cp_entry_t *e = &entries[i];
        const uint8_t flags = e->deleted ? SKIP_LIST_FLAG_DELETED : 0;
        ASSERT_EQ(tidesdb_l0_apply(db->l0, 0, (const uint8_t *)e->key, strlen(e->key),
                                   e->deleted ? NULL : (const uint8_t *)e->val,
                                   e->deleted ? 0 : strlen(e->val), -1, e->seq, flags),
                  TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_l0_rotate(db->l0, tidesdb_memtable_create(NULL, generation, generation,
                                                                CP_MAX_LEVEL, CP_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(db->l0);
    cf_t *cfs[1] = {db->cf};
    flush_ctx_t fx = {.l0 = db->l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db->manifest,
                      .manifest_path = db->manifest_path,
                      .next_sstable_id = &db->next_id,
                      .fdm = &db->fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = CP_NO_SPILL};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
}

/* the planner config the pipeline tests share */
static compaction_planner_config_t cp_config(void)
{
    compaction_planner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.size_ratio = CP_SIZE_RATIO;
    cfg.dividing_level_offset = 0;
    cfg.min_levels = 1;
    cfg.l1_file_count_trigger = CP_L1_TRIGGER;
    cfg.tombstone_density_trigger = 0.0;
    cfg.tombstone_density_min_entries = 0;
    cfg.base_capacity = CP_BASE_CAPACITY;
    return cfg;
}

/* a captured snapshot together with the plan it produced; refs keep the sstables live so the plan's
 * borrowed boundary keys stay valid, and the executor re-refs its own inputs from the live level
 * set */
typedef struct
{
    level_set_snapshot_entry_t *refs;
    int n_refs;
    compaction_sstable_info_t *info;
    compaction_snapshot_t snap;
    compaction_plan_t *plan;
} cp_planned_t;

/* fold the cf's level set into a planner snapshot and produce its plan */
static void cp_plan(cp_db_t *db, const compaction_planner_config_t *cfg, cp_planned_t *out)
{
    memset(out, 0, sizeof(*out));
    const int total = level_set_snapshot(db->cf->levels, NULL, 0);
    out->n_refs = total;
    out->refs = calloc(total ? (size_t)total : 1, sizeof(*out->refs));
    out->info = calloc(total ? (size_t)total : 1, sizeof(*out->info));
    ASSERT_TRUE(out->refs != NULL && out->info != NULL);
    if (total > 0) ASSERT_EQ(level_set_snapshot(db->cf->levels, out->refs, total), total);

    int num_levels = 0;
    for (int i = 0; i < total; i++)
    {
        const sstable_t *s = out->refs[i].sst;
        out->info[i].id = s->id;
        out->info[i].level = out->refs[i].level;
        out->info[i].size = out->refs[i].size_bytes;
        out->info[i].min_key = s->min_key;
        out->info[i].min_key_size = s->min_key_size;
        out->info[i].max_key = s->max_key;
        out->info[i].max_key_size = s->max_key_size;
        out->info[i].entry_count = s->distinct_key_count;
        out->info[i].tombstone_count = s->tombstone_count;
        if (out->refs[i].level > num_levels) num_levels = out->refs[i].level;
    }
    out->snap.sstables = out->info;
    out->snap.n_sstables = total;
    out->snap.num_levels = num_levels;
    ASSERT_EQ(compaction_planner_plan(&out->snap, cfg, &out->plan), TDB_SUCCESS);
}

/* run every job in a plan through the executor against the live cf */
static void cp_exec(cp_db_t *db, const cp_planned_t *pl, uint64_t gc_floor)
{
    const int n = compaction_plan_job_count(pl->plan);
    for (int i = 0; i < n; i++)
    {
        const compaction_job_t *job = compaction_plan_job(pl->plan, i);
        const compaction_ctx_t cx = {.cf = db->cf,
                                     .manifest = db->manifest,
                                     .manifest_path = db->manifest_path,
                                     .next_sstable_id = &db->next_id,
                                     .gc_floor = gc_floor,
                                     .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                                     .value_threshold = CP_NO_SPILL};
        ASSERT_EQ(compaction_exec(&cx, job), TDB_SUCCESS);
    }
}

static void cp_planned_free(cp_planned_t *pl)
{
    compaction_plan_free(pl->plan);
    for (int i = 0; i < pl->n_refs; i++)
        if (sstable_unref(pl->refs[i].sst)) sstable_close(pl->refs[i].sst);
    free(pl->refs);
    free(pl->info);
}

/* read one key out of a level, asserting the value and presence; a NULL expect means absence */
static void cp_assert_read(cf_t *cf, int level, const char *key, const char *expect_val)
{
    sstable_t *out[16];
    const int n = level_set_overlapping(cf->levels, level, (const uint8_t *)key, strlen(key),
                                        (const uint8_t *)key, strlen(key), out, 16);
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

/* a single-level tree with enough L1 files grows: the planner emits one full merge into a new L2,
 * the executor consolidates every L1 run there, newest versions win, and a below-floor tombstone is
 * gc'd */
void test_pipeline_grow_l1_to_l2(void)
{
    cp_db_t db;
    cp_db_open(&db);

    const cp_entry_t f1[] = {{"a", "A", 1, 0}, {"m", "m-old", 2, 0}};
    const cp_entry_t f2[] = {{"b", "B", 3, 0}, {"m", "m-new", 4, 0}};
    const cp_entry_t f3[] = {{"c", "C", 5, 0}, {"d", NULL, 6, 1}};
    cp_flush(&db, f1, 2, 1);
    cp_flush(&db, f2, 2, 2);
    cp_flush(&db, f3, 2, 3);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 3);

    const compaction_planner_config_t cfg = cp_config();
    cp_planned_t pl;
    cp_plan(&db, &cfg, &pl);

    /* the plan the snapshot calls for: one full merge of all three L1 runs into the new largest
     * level */
    ASSERT_EQ(compaction_plan_job_count(pl.plan), 1);
    const compaction_job_t *job = compaction_plan_job(pl.plan, 0);
    ASSERT_EQ(job->target_level, 2);
    ASSERT_EQ((int)job->split, (int)COMPACTION_SPLIT_NONE);
    ASSERT_EQ(job->is_largest_level, 1);
    ASSERT_EQ(job->n_inputs, 3);

    cp_exec(&db, &pl, UINT64_MAX); /* no snapshot floor, so the tombstone reaps */
    cp_planned_free(&pl);

    ASSERT_EQ(level_set_count(db.cf->levels, 1), 0);
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 1);
    cp_assert_read(db.cf, 2, "a", "A");
    cp_assert_read(db.cf, 2, "b", "B");
    cp_assert_read(db.cf, 2, "c", "C");
    cp_assert_read(db.cf, 2, "m", "m-new"); /* seq 4 beat seq 2 */
    cp_assert_read(db.cf, 2, "d", NULL);    /* tombstone reaped at the largest level */

    cp_db_close(&db);
}

/* the planner and executor iterate over an evolving cf: after a first grow into L2, a second round
 * of L1 flushes plans and runs again, draining L1 and consolidating every live key at the largest
 * level */
void test_pipeline_iterates_over_evolving_cf(void)
{
    cp_db_t db;
    cp_db_open(&db);
    const compaction_planner_config_t cfg = cp_config();

    const cp_entry_t r1a[] = {{"a", "A", 1, 0}, {"m", "m1", 2, 0}};
    const cp_entry_t r1b[] = {{"b", "B", 3, 0}};
    const cp_entry_t r1c[] = {{"c", "C", 4, 0}, {"d", NULL, 5, 1}};
    cp_flush(&db, r1a, 2, 1);
    cp_flush(&db, r1b, 1, 2);
    cp_flush(&db, r1c, 2, 3);

    cp_planned_t r1;
    cp_plan(&db, &cfg, &r1);
    ASSERT_EQ(compaction_plan_job_count(r1.plan), 1);
    cp_exec(&db, &r1, UINT64_MAX);
    cp_planned_free(&r1);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 0);
    ASSERT_TRUE(level_set_count(db.cf->levels, 2) >= 1);

    /* a second write round refills L1 with new keys and an update to a key already at L2 */
    const cp_entry_t r2a[] = {{"e", "E", 6, 0}, {"a", "A2", 7, 0}};
    const cp_entry_t r2b[] = {{"f", "F", 8, 0}};
    cp_flush(&db, r2a, 2, 4);
    cp_flush(&db, r2b, 1, 5);
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 2);

    cp_planned_t r2;
    cp_plan(&db, &cfg, &r2);
    ASSERT_TRUE(compaction_plan_job_count(r2.plan) >= 1);
    cp_exec(&db, &r2, UINT64_MAX);
    cp_planned_free(&r2);

    /* L1 has drained and every live key is readable at the largest level with its newest value */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 0);
    cp_assert_read(db.cf, 2, "a", "A2"); /* the round-two update won */
    cp_assert_read(db.cf, 2, "b", "B");
    cp_assert_read(db.cf, 2, "c", "C");
    cp_assert_read(db.cf, 2, "e", "E");
    cp_assert_read(db.cf, 2, "f", "F");
    cp_assert_read(db.cf, 2, "m", "m1");
    cp_assert_read(db.cf, 2, "d", NULL); /* stayed reaped across the second round */

    cp_db_close(&db);
}

/* a cf under every trigger yields an empty plan, so the pipeline runs no jobs and leaves the tree
 * be */
void test_pipeline_no_work_empty_plan(void)
{
    cp_db_t db;
    cp_db_open(&db);
    const compaction_planner_config_t cfg = cp_config();

    const cp_entry_t f1[] = {{"a", "A", 1, 0}};
    cp_flush(&db, f1, 1, 1); /* one L1 file, below the file-count trigger */
    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1);

    cp_planned_t pl;
    cp_plan(&db, &cfg, &pl);
    ASSERT_EQ(compaction_plan_job_count(pl.plan), 0);
    cp_exec(&db, &pl, UINT64_MAX);
    cp_planned_free(&pl);

    ASSERT_EQ(level_set_count(db.cf->levels, 1), 1); /* untouched */
    ASSERT_EQ(level_set_count(db.cf->levels, 2), 0);
    cp_assert_read(db.cf, 1, "a", "A");

    cp_db_close(&db);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_pipeline_grow_l1_to_l2, tests_passed);
    RUN_TEST(test_pipeline_iterates_over_evolving_cf, tests_passed);
    RUN_TEST(test_pipeline_no_work_empty_plan, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
