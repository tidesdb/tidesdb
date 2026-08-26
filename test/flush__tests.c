/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/flush/flush.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define FLUSH_DB_DIR    "." PATH_SEPARATOR "test_flush_db"
#define FLUSH_DIR_MODE  0755
#define FLUSH_MAX_LEVEL 12
#define FLUSH_PROB      0.25f
#define FLUSH_BUFFER    (64 * 1024)
#define FLUSH_QDEPTH    8
/* larger than any value these tests write, so nothing reaches the vlog and a flush's
 * output is entirely in the klog where the assertions look for it */
#define FLUSH_NO_SPILL (1u << 20)

#define FLUSH_FIRST_ID 100

/* the db-global services every column family borrows during a flush */
typedef struct
{
    vlog_t *vlog;
    cache_t *cache;
    fd_manager_t fdm;
    tidesdb_manifest_t *manifest;
    char manifest_path[256];
} flush_db_t;

static void flush_db_open(flush_db_t *db)
{
    (void)remove_directory(FLUSH_DB_DIR);
    ASSERT_EQ(mkdir(FLUSH_DB_DIR, FLUSH_DIR_MODE), 0);

    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(FLUSH_DB_DIR, &vc, &db->vlog), VLOG_OK);
    db->cache = cache_create(NULL);
    ASSERT_TRUE(db->cache != NULL);
    ASSERT_EQ(fd_manager_init(&db->fdm, 0), 0);
    snprintf(db->manifest_path, sizeof(db->manifest_path), "%s%sMANIFEST", FLUSH_DB_DIR,
             PATH_SEPARATOR);
    db->manifest = tidesdb_manifest_open(db->manifest_path);
    ASSERT_TRUE(db->manifest != NULL);
}

static void flush_db_close(flush_db_t *db)
{
    tidesdb_manifest_close(db->manifest);
    fd_manager_destroy(&db->fdm);
    cache_destroy(db->cache);
    vlog_close(db->vlog);
    (void)remove_directory(FLUSH_DB_DIR);
}

static cf_t *flush_make_cf(flush_db_t *db, uint64_t cf_id, const char *name)
{
    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", name);
    cfg.level_size_ratio = 10;
    cfg.min_levels = 3;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    cfg.l1_file_count_trigger = 4;

    cf_t *cf = NULL;
    ASSERT_EQ(
        cf_create(FLUSH_DB_DIR, cf_id, &cfg, NULL, db->vlog, db->cache, &db->fdm, NULL, NULL, &cf),
        0);
    ASSERT_EQ(tidesdb_manifest_add_cf(db->manifest, cf_id, name, NULL, 0), 0);
    return cf;
}

/* read one key out of a level set at L1, asserting the value and tombstone flag */
static void assert_l1_reads(cf_t *cf, const char *key, const char *expect_val, int expect_deleted)
{
    sstable_t *out[8];
    const int n = level_set_overlapping(cf->levels, LEVEL_SET_L1, (const uint8_t *)key, strlen(key),
                                        (const uint8_t *)key, strlen(key), out, 8);
    ASSERT_TRUE(n >= 1);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    const int rc = sstable_get(out[0], (const uint8_t *)key, strlen(key), &value, &value_size,
                               &vlog_offset, &seq, &ttl, &deleted);
    ASSERT_EQ(rc, TDB_SUCCESS);
    ASSERT_EQ((int)deleted, expect_deleted);
    if (!expect_deleted)
    {
        ASSERT_EQ((int)value_size, (int)strlen(expect_val));
        ASSERT_TRUE(memcmp(value, expect_val, value_size) == 0);
    }
    free(value);
    for (int i = 0; i < n; i++)
        if (sstable_unref(out[i])) sstable_close(out[i]);
}

/* a memtable entry whose value the commit already put in the value log is flushed as a reference.
 * the flush must carry the id rather than re-spill, both because writing those bytes a second time
 * is the cost the whole arrangement exists to avoid and because the version holds no bytes to
 * write */
void test_flush_carries_a_memtable_reference_without_rewriting_it(void)
{
    flush_db_t db;
    flush_db_open(&db);
    cf_t *cf0 = flush_make_cf(&db, 0, "cf0");

    /* put a value in the value log the way a commit would, and note what that cost */
    const size_t vlen = 4096;
    uint8_t *big = malloc(vlen);
    ASSERT_TRUE(big != NULL);
    memset(big, 'V', vlen);
    uint64_t id = 0, disk = 0;
    ASSERT_EQ(vlog_write(db.vlog, big, vlen, NULL, 0, &id, &disk), VLOG_OK);
    ASSERT_TRUE(id != 0);
    vlog_stats_t before;
    vlog_get_stats(db.vlog, &before);

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(FLUSH_BUFFER, FLUSH_QDEPTH, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(NULL, 0, 0, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL));

    ASSERT_EQ(tidesdb_l0_apply_reference(l0, 0, (const uint8_t *)"big", 3, id, vlen, -1, 1, 0),
              TDB_SUCCESS);

    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(immutable != NULL);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, FLUSH_FIRST_ID);
    cf_t *cfs[1] = {cf0};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      /* far below the value, so an inline flush would certainly have spilled it */
                      .value_threshold = 64};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf0->levels, LEVEL_SET_L1), 1);

    /* the value log wrote nothing more, so the bytes did not reach the device a second time */
    vlog_stats_t after;
    vlog_get_stats(db.vlog, &after);
    ASSERT_TRUE(after.bytes_written == before.bytes_written);

    /* and the sstable entry names the same value log entry, with the value's logical length */
    sstable_t *out[4];
    const int n = level_set_overlapping(cf0->levels, LEVEL_SET_L1, (const uint8_t *)"big", 3,
                                        (const uint8_t *)"big", 3, out, 4);
    ASSERT_EQ(n, 1);
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_get(out[0], (const uint8_t *)"big", 3, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(value == NULL);
    ASSERT_EQ((int)value_size, (int)vlen);
    ASSERT_TRUE(vlog_offset == id);
    free(value);

    /* and the bytes are still there to be read back through it */
    uint8_t *resolved = NULL;
    size_t resolved_len = 0;
    ASSERT_EQ(vlog_read(db.vlog, vlog_offset, &resolved, &resolved_len), VLOG_OK);
    ASSERT_EQ((int)resolved_len, (int)vlen);
    ASSERT_EQ((int)resolved[0], 'V');
    free(resolved);
    free(big);

    for (int i = 0; i < n; i++)
        if (sstable_unref(out[i])) sstable_close(out[i]);
    tidesdb_l0_destroy(l0);
    cf_free(cf0);
    flush_db_close(&db);
}

/* a flush demuxes one immutable's shared skip_list into one L1 sstable per column family, records
 * them in the manifest, installs them into the level sets, and reclaims the immutable */
void test_flush_demux_two_cfs(void)
{
    flush_db_t db;
    flush_db_open(&db);
    cf_t *cf0 = flush_make_cf(&db, 0, "cf0");
    cf_t *cf1 = flush_make_cf(&db, 1, "cf1");

    /* build the immutable by writing into an L0 active, then rotating and dequeuing it */
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(FLUSH_BUFFER, FLUSH_QDEPTH, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(NULL, 0, 0, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL));

    /* bound so the applies below attribute their keys, which is what makes the counter assertions
     * after the flush mean anything -- unbound the count never leaves zero and they pass vacuously
     */
    tidesdb_l0_bind_cf_counter(l0, 0, &cf0->unflushed_key_count);
    tidesdb_l0_bind_cf_counter(l0, 1, &cf1->unflushed_key_count);

    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"a", 1, (const uint8_t *)"va", 2, -1, 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"b", 1, (const uint8_t *)"vb", 2, -1, 2, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 1, (const uint8_t *)"x", 1, (const uint8_t *)"vx", 2, -1, 3, 0),
              TDB_SUCCESS);
    /* a tombstone in cf1 survives the flush as a deleted entry */
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 1, (const uint8_t *)"y", 1, NULL, 0, -1, 4, SKIP_LIST_FLAG_DELETED),
        TDB_SUCCESS);

    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(immutable != NULL);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, FLUSH_FIRST_ID);
    cf_t *cfs[2] = {cf0, cf1};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 2,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = FLUSH_NO_SPILL};

    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);

    /* each column family got exactly one L1 sstable */
    ASSERT_EQ(level_set_count(cf0->levels, LEVEL_SET_L1), 1);
    ASSERT_EQ(level_set_count(cf1->levels, LEVEL_SET_L1), 1);

    /* both are recorded in the manifest under their own cf id */
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0), 1);
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 1, NULL, 0), 1);

    /* the immutable was reclaimed, so the queue is empty */
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    /* every family's keys left the memtable for L1, so every family's count is settled -- not just
     * the first. the install drops these once the whole batch has landed rather than one family at
     * a time, and a pass that settled only what it had reached would leave the second family here
     * still counting keys that are on disk */
    ASSERT_EQ((int)atomic_load(&cf0->unflushed_key_count), 0);
    ASSERT_EQ((int)atomic_load(&cf1->unflushed_key_count), 0);

    /* the data reads back from L1, tombstone preserved */
    assert_l1_reads(cf0, "a", "va", 0);
    assert_l1_reads(cf0, "b", "vb", 0);
    assert_l1_reads(cf1, "x", "vx", 0);
    assert_l1_reads(cf1, "y", NULL, 1);

    cf_free(cf0);
    cf_free(cf1);
    tidesdb_l0_destroy(l0);
    flush_db_close(&db);
}

/* an empty immutable flushes cleanly -- no sstables, no manifest rows, and it is still reclaimed */
void test_flush_empty_immutable(void)
{
    flush_db_t db;
    flush_db_open(&db);
    cf_t *cf0 = flush_make_cf(&db, 0, "cf0");

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(FLUSH_BUFFER, FLUSH_QDEPTH, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(NULL, 0, 0, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL));
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(immutable != NULL);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, FLUSH_FIRST_ID);
    cf_t *cfs[1] = {cf0};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = FLUSH_NO_SPILL};

    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf0->levels, LEVEL_SET_L1), 0);
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0), 0);
    ASSERT_EQ((int)atomic_load(&next_id), FLUSH_FIRST_ID); /* no id was consumed */

    cf_free(cf0);
    tidesdb_l0_destroy(l0);
    flush_db_close(&db);
}

/* a prefix delete that wrote no keys of its own still has to survive its memtable. this is the case
 * that decides where range tombstones can live at all -- the family produces no sstable, so
 * anything that hung them off one would lose them here */
void test_flush_carries_a_prefix_delete_that_wrote_no_keys(void)
{
    flush_db_t db;
    flush_db_open(&db);
    cf_t *cf0 = flush_make_cf(&db, 0, "cf0");

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(FLUSH_BUFFER, FLUSH_QDEPTH, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(NULL, 0, 0, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL));

    /* the only thing this memtable ever holds */
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 42),
              TDB_SUCCESS);

    /* and it is not measured as empty, or neither the size trigger nor the idle flush would seal it
     */
    ASSERT_TRUE(tidesdb_l0_active_bytes(l0) > 0);

    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(immutable != NULL);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, FLUSH_FIRST_ID);
    cf_t *cfs[1] = {cf0};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .gc_floor = UINT64_MAX,
                      .value_threshold = FLUSH_NO_SPILL};

    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);

    /* no sstable was built, and none was needed */
    ASSERT_EQ(level_set_count(cf0->levels, LEVEL_SET_L1), 0);
    ASSERT_EQ((int)atomic_load(&next_id), FLUSH_FIRST_ID);

    /* the family holds it, over its own unprefixed keys */
    uint64_t seq = 0;
    ASSERT_EQ(cf_range_tombstone_covering(cf0, (const uint8_t *)"user:1", 6, UINT64_MAX, &seq), 1);
    ASSERT_EQ(seq, 42);
    ASSERT_EQ(cf_range_tombstone_covering(cf0, (const uint8_t *)"used", 4, UINT64_MAX, &seq), 0);

    /* and a reader below the delete still sees nothing of it */
    ASSERT_EQ(cf_range_tombstone_covering(cf0, (const uint8_t *)"user:1", 6, 41, &seq), 0);

    /* the manifest carries it, so a reopen would rebuild the same set */
    uint8_t *blob = NULL;
    uint32_t blob_len = 0;
    ASSERT_EQ(tidesdb_manifest_get_range_dels(db.manifest, 0, &blob, &blob_len), 0);
    ASSERT_TRUE(blob != NULL && blob_len > 0);

    range_tombstone_set_t *rebuilt = NULL;
    ASSERT_EQ(range_tombstone_set_deserialize(blob, blob_len, &rebuilt), TDB_SUCCESS);
    free(blob);
    uint64_t rebuilt_seq = 0;
    ASSERT_EQ(range_tombstone_max_covering(rebuilt, (const uint8_t *)"user:9", 6, UINT64_MAX,
                                           &rebuilt_seq),
              1);
    ASSERT_EQ(rebuilt_seq, 42);
    range_tombstone_set_free(rebuilt);

    cf_free(cf0);
    tidesdb_l0_destroy(l0);
    flush_db_close(&db);
}

typedef struct
{
    const flush_ctx_t *fx;
    tidesdb_memtable_t *immutable;
    int rc;
} flush_worker_t;

static void *flush_worker(void *arg)
{
    flush_worker_t *w = arg;
    w->rc = flush_immutable(w->fx, w->immutable);
    return NULL;
}

/* two immutables destined for the same column family flush at the same time; both land as separate
 * L1 sstables, both recorded and readable -- the intra-cf parallel flush path */
void test_flush_concurrent_same_cf(void)
{
    flush_db_t db;
    flush_db_open(&db);
    cf_t *cf0 = flush_make_cf(&db, 0, "cf0");

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(FLUSH_BUFFER, FLUSH_QDEPTH, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(NULL, 0, 0, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL));

    /* first immutable holds the a-keys, second holds the disjoint b-keys */
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"a1", 2, (const uint8_t *)"va1", 3, -1, 1, 0),
        TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"a2", 2, (const uint8_t *)"va2", 3, -1, 2, 0),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"b1", 2, (const uint8_t *)"vb1", 3, -1, 3, 0),
        TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"b2", 2, (const uint8_t *)"vb2", 3, -1, 4, 0),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 2, 2, FLUSH_MAX_LEVEL, FLUSH_PROB, NULL, NULL)),
              TDB_SUCCESS);

    tidesdb_memtable_t *imm_a = tidesdb_l0_dequeue_immutable(l0);
    tidesdb_memtable_t *imm_b = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(imm_a != NULL && imm_b != NULL);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, FLUSH_FIRST_ID);
    cf_t *cfs[1] = {cf0};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = FLUSH_NO_SPILL};

    flush_worker_t wa = {&fx, imm_a, -1}, wb = {&fx, imm_b, -1};
    pthread_t ta, tb;
    pthread_create(&ta, NULL, flush_worker, &wa);
    pthread_create(&tb, NULL, flush_worker, &wb);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    ASSERT_EQ(wa.rc, TDB_SUCCESS);
    ASSERT_EQ(wb.rc, TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf0->levels, LEVEL_SET_L1), 2); /* one sstable per immutable */
    ASSERT_EQ(tidesdb_manifest_copy_entries(db.manifest, 0, NULL, 0), 2);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    assert_l1_reads(cf0, "a1", "va1", 0);
    assert_l1_reads(cf0, "a2", "va2", 0);
    assert_l1_reads(cf0, "b1", "vb1", 0);
    assert_l1_reads(cf0, "b2", "vb2", 0);

    cf_free(cf0);
    tidesdb_l0_destroy(l0);
    flush_db_close(&db);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_flush_demux_two_cfs, tests_passed);
    RUN_TEST(test_flush_carries_a_memtable_reference_without_rewriting_it, tests_passed);
    RUN_TEST(test_flush_empty_immutable, tests_passed);
    RUN_TEST(test_flush_carries_a_prefix_delete_that_wrote_no_keys, tests_passed);
    RUN_TEST(test_flush_concurrent_same_cf, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
