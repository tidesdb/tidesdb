/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/column_family/cf_iter.h"
#include "../src/flush/flush.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define CFI_DB_DIR    "." PATH_SEPARATOR "test_cf_iter_db"
#define CFI_MAX_LEVEL 12
#define CFI_PROB      0.25f
#define CFI_BUFFER    (64 * 1024)
#define CFI_QDEPTH    8

typedef struct
{
    vlog_t *vlog;
    cache_t *cache;
    fd_manager_t fdm;
    tidesdb_manifest_t *manifest;
    char manifest_path[256];
    size_t value_threshold;
} cfi_db_t;

static void cfi_db_open(cfi_db_t *db)
{
    (void)remove_directory(CFI_DB_DIR);
    ASSERT_EQ(mkdir(CFI_DB_DIR, 0755), 0);
    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(CFI_DB_DIR, &vc, &db->vlog), VLOG_OK);
    db->cache = cache_create(NULL);
    ASSERT_EQ(fd_manager_init(&db->fdm, 0), 0);
    snprintf(db->manifest_path, sizeof(db->manifest_path), "%s%sMANIFEST", CFI_DB_DIR,
             PATH_SEPARATOR);
    db->manifest = tidesdb_manifest_open(db->manifest_path);
    ASSERT_TRUE(db->manifest != NULL);
}

static void cfi_db_close(cfi_db_t *db)
{
    tidesdb_manifest_close(db->manifest);
    fd_manager_destroy(&db->fdm);
    cache_destroy(db->cache);
    vlog_close(db->vlog);
    (void)remove_directory(CFI_DB_DIR);
}

static cf_t *cfi_make_cf_thresh(cfi_db_t *db, uint32_t value_threshold)
{
    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", "cf0");
    cfg.level_size_ratio = 10;
    cfg.min_levels = 3;
    db->value_threshold = value_threshold;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    cf_t *cf = NULL;
    ASSERT_EQ(cf_create(CFI_DB_DIR, 0, &cfg, NULL, db->vlog, db->cache, &db->fdm, NULL, NULL, &cf),
              0);
    ASSERT_EQ(tidesdb_manifest_add_cf(db->manifest, 0, "cf0", NULL, 0), 0);
    return cf;
}

/* a threshold no value in these tests reaches, so everything stays inline in the klog */
static cf_t *cfi_make_cf(cfi_db_t *db)
{
    return cfi_make_cf_thresh(db, 1u << 20);
}

static void collect(cf_iter_t *it, int dir, char *out, size_t out_cap)
{
    out[0] = '\0';
    int rc = dir > 0 ? cf_iter_seek_first(it) : cf_iter_seek_last(it);
    while (rc == TDB_SUCCESS)
    {
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                              &deleted),
                  TDB_SUCCESS);
        char item[64];
        snprintf(item, sizeof(item), "%.*s:%.*s,", (int)key_size, (const char *)key,
                 (int)value_size, value ? (const char *)value : "");
        strncat(out, item, out_cap - strlen(out) - 1);
        rc = dir > 0 ? cf_iter_next(it) : cf_iter_prev(it);
    }
}

/* disjoint sstables laid down for the scan-cost reproductions, and the keys each one holds. enough
 * that a scan touching all of them is unmistakable against a scan touching only the band it asked
 * for */
#define CFI_BANDS         32
#define CFI_KEYS_PER_BAND 4
#define CFI_BAND_KEY_LEN  16

/* the band a narrow scan reads, chosen away from both ends so a scan that ran off in either
 * direction would show up */
#define CFI_NARROW_BAND 16

/* write one band's keys into the active memtable, seal it, and flush it to its own L1 sstable, so
 * the family ends up with one sstable per band and no two of them share a key range
 * @param l0 the shared L0 the band is written through
 * @param fx the flush context bound to the family
 * @param band the band index, which orders the keys
 */
static void cfi_flush_band(tidesdb_l0_t *l0, const flush_ctx_t *fx, int band)
{
    for (int k = 0; k < CFI_KEYS_PER_BAND; k++)
    {
        char key[CFI_BAND_KEY_LEN];
        snprintf(key, sizeof(key), "b%03d_k%03d", band, k);
        const uint64_t seq = (uint64_t)(band * CFI_KEYS_PER_BAND + k + 1);
        ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)key, strlen(key), (const uint8_t *)"v",
                                   1, -1, seq, 0),
                  TDB_SUCCESS);
    }
    ASSERT_EQ(
        tidesdb_l0_rotate(l0, tidesdb_memtable_create(NULL, (uint64_t)band + 1, (uint64_t)band + 1,
                                                      CFI_MAX_LEVEL, CFI_PROB, NULL, NULL)),
        TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(immutable != NULL);
    ASSERT_EQ(flush_immutable(fx, immutable), TDB_SUCCESS);
}

/* lay down one sstable per band and hand back the L0 they were written through */
static tidesdb_l0_t *cfi_build_banded_cf(cfi_db_t *db, cf_t *cf, _Atomic(uint64_t) *next_id,
                                         flush_ctx_t *fx, cf_t **cfs)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(CFI_BUFFER, CFI_QDEPTH, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL);
    tidesdb_l0_set_active(l0,
                          tidesdb_memtable_create(NULL, 0, 0, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL));

    cfs[0] = cf;
    atomic_init(next_id, 100);
    fx->l0 = l0;
    fx->cfs = cfs;
    fx->n_cfs = 1;
    fx->manifest = db->manifest;
    fx->manifest_path = db->manifest_path;
    fx->next_sstable_id = next_id;
    fx->fdm = &db->fdm;
    fx->sync_mode = BLOCK_MANAGER_SYNC_NONE;
    fx->value_threshold = db->value_threshold;

    for (int band = 0; band < CFI_BANDS; band++) cfi_flush_band(l0, fx, band);
    ASSERT_EQ(level_set_count(cf->levels, LEVEL_SET_L1), CFI_BANDS);
    return l0;
}

/* every lookup the family serves goes through the block cache, so the count of entries it hands out
 * is a direct measure of how much of the store a scan touched */
static uint64_t cfi_cache_touches(cache_t *cache)
{
    cache_stats_t st;
    cache_get_stats(cache, &st);
    return st.hits + st.misses;
}

/* a scan bounded to one band must cost what that band costs, not what the family costs. the merge
 * is built from every sstable the family holds rather than from the ones whose key range meets the
 * scan, so a narrow read opens a cursor into all of them, descends all of them, and then advances
 * across all of them for every row it returns -- which is why concurrent range scans saturate the
 * cores and stop making progress while the data they each want is tiny */
void test_cf_iter_narrow_range_scan_does_not_open_every_sstable(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    cf_t *cf = cfi_make_cf(&db);

    _Atomic(uint64_t) next_id;
    flush_ctx_t fx;
    memset(&fx, 0, sizeof(fx));
    cf_t *cfs[1];
    tidesdb_l0_t *l0 = cfi_build_banded_cf(&db, cf, &next_id, &fx, cfs);

    char first[CFI_BAND_KEY_LEN];
    snprintf(first, sizeof(first), "b%03d_k%03d", CFI_NARROW_BAND, 0);

    const uint64_t before = cfi_cache_touches(db.cache);

    char last[CFI_BAND_KEY_LEN];
    snprintf(last, sizeof(last), "b%03d_k%03d", CFI_NARROW_BAND, CFI_KEYS_PER_BAND - 1);
    const cf_iter_bounds_t bounds = {.lower = (const uint8_t *)first,
                                     .lower_size = strlen(first),
                                     .upper = (const uint8_t *)last,
                                     .upper_size = strlen(last)};

    cf_iter_t *it = NULL;
    ASSERT_EQ(cf_iter_new_bounded(cf, l0, UINT64_MAX, NULL, &bounds, &it), TDB_SUCCESS);
    ASSERT_EQ(cf_iter_seek(it, (const uint8_t *)first, strlen(first)), TDB_SUCCESS);

    /* read the band the scan asked for and stop, the way a bounded query does */
    int read = 0;
    while (cf_iter_valid(it) && read < CFI_KEYS_PER_BAND)
    {
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                              &deleted),
                  TDB_SUCCESS);
        read++;
        if (cf_iter_next(it) != TDB_SUCCESS) break;
    }
    cf_iter_free(it);

    const uint64_t touched = cfi_cache_touches(db.cache) - before;
    ASSERT_EQ(read, CFI_KEYS_PER_BAND);

    /* one touch per sstable is the floor for opening them all, so anything under that says the scan
     * skipped the sstables whose range it never needed */
    ASSERT_TRUE(touched < (uint64_t)CFI_BANDS);

    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

/* the companion the pruning has to keep true: a scan with no bound still spans every sstable, so a
 * merge that drops sources by key range cannot drop one that holds keys the scan wants */
void test_cf_iter_full_scan_spans_every_sstable(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    cf_t *cf = cfi_make_cf(&db);

    _Atomic(uint64_t) next_id;
    flush_ctx_t fx;
    memset(&fx, 0, sizeof(fx));
    cf_t *cfs[1];
    tidesdb_l0_t *l0 = cfi_build_banded_cf(&db, cf, &next_id, &fx, cfs);

    cf_iter_t *it = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, UINT64_MAX, NULL, &it), TDB_SUCCESS);

    int seen = 0;
    int rc = cf_iter_seek_first(it);
    while (rc == TDB_SUCCESS)
    {
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                              &deleted),
                  TDB_SUCCESS);
        seen++;
        rc = cf_iter_next(it);
    }
    cf_iter_free(it);

    ASSERT_EQ(seen, CFI_BANDS * CFI_KEYS_PER_BAND);

    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

/* a cf iterator folds a flushed sstable and the live memtable into one snapshot stream, the newest
 * version across the two winning per key */
void test_cf_iter_memtable_over_sstable(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    cf_t *cf = cfi_make_cf(&db);

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(CFI_BUFFER, CFI_QDEPTH, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL);
    tidesdb_l0_set_active(l0,
                          tidesdb_memtable_create(NULL, 0, 0, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL));

    /* phase 1 -- a and c go to an immutable that flushes to an L1 sstable */
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"a", 1, (const uint8_t *)"va", 2, -1, 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"c", 1, (const uint8_t *)"c-old", 5, -1, 2, 0),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, 100);
    cf_t *cfs[1] = {cf};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = db.value_threshold};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf->levels, LEVEL_SET_L1), 1);

    /* phase 2 -- b and a newer c stay live in the active memtable */
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"b", 1, (const uint8_t *)"vb", 3, -1, 3, 0),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"c", 1, (const uint8_t *)"c-new", 5, -1, 4, 0),
        TDB_SUCCESS);

    /* latest snapshot -- c resolves to the memtable's newer version */
    cf_iter_t *it = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, UINT64_MAX, NULL, &it), TDB_SUCCESS);
    char got[256];
    collect(it, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:va,b:vb,c:c-new,") == 0);
    collect(it, -1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "c:c-new,b:vb,a:va,") == 0);
    cf_iter_free(it);

    /* snapshot 2 -- only a and the sstable's c are visible */
    cf_iter_t *snap = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, 2, NULL, &snap), TDB_SUCCESS);
    collect(snap, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "a:va,c:c-old,") == 0);
    cf_iter_free(snap);

    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

/* a seek positions the merged stream, and a deleted key is hidden from the scan and skipped over by
 * a seek that lands on it */
void test_cf_iter_seek_hides_tombstones(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    cf_t *cf = cfi_make_cf(&db);

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(CFI_BUFFER, CFI_QDEPTH, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL);
    tidesdb_l0_set_active(l0,
                          tidesdb_memtable_create(NULL, 0, 0, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL));
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"k1", 2, (const uint8_t *)"v1", 2, -1, 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"k2", 2, NULL, 0, -1, 2, SKIP_LIST_FLAG_DELETED),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"k3", 2, (const uint8_t *)"v3", 2, -1, 3, 0),
              TDB_SUCCESS);

    /* a read hides the tombstone and a seek lands at or after the target */
    cf_iter_t *rd = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, UINT64_MAX, NULL, &rd), TDB_SUCCESS);
    char got[128];
    collect(rd, 1, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "k1:v1,k3:v3,") == 0); /* k2 hidden */
    ASSERT_EQ(cf_iter_seek(rd, (const uint8_t *)"k2", 2), TDB_SUCCESS);
    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(
        cf_iter_get(rd, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted),
        TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "k3", 2) == 0); /* first key >= k2 (k2 hidden) is k3 */
    cf_iter_free(rd);

    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

/* read the key the iterator sits on into a nul-terminated buffer */
static void cfi_key_at(cf_iter_t *it, char *out, size_t out_cap)
{
    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(
        cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted),
        TDB_SUCCESS);
    ASSERT_TRUE(key_size < out_cap);
    memcpy(out, key, key_size);
    out[key_size] = '\0';
}

/* the scans above run one direction to exhaustion, which never makes the merge turn around
 * mid-stream. a flip has to re-seek every source around the current key, and the sstable and the
 * memtable re-seek through completely different code, so walk back and forth across a stream
 * interleaved between the two and check no key is dropped or repeated at the turns */
void test_cf_iter_direction_flip_across_sources(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    cf_t *cf = cfi_make_cf(&db);

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(CFI_BUFFER, CFI_QDEPTH, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL);
    tidesdb_l0_set_active(l0,
                          tidesdb_memtable_create(NULL, 0, 0, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL));

    /* a, c, e flush to an sstable */
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"a", 1, (const uint8_t *)"va", 2, -1, 1, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"c", 1, (const uint8_t *)"vc", 2, -1, 2, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"e", 1, (const uint8_t *)"ve", 2, -1, 3, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, 100);
    cf_t *cfs[1] = {cf};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = db.value_threshold};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf->levels, LEVEL_SET_L1), 1);

    /* b and d stay live, so the merged stream alternates between the two source kinds */
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"b", 1, (const uint8_t *)"vb", 2, -1, 4, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"d", 1, (const uint8_t *)"vd", 2, -1, 5, 0),
              TDB_SUCCESS);

    cf_iter_t *it = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, UINT64_MAX, NULL, &it), TDB_SUCCESS);

    char k[16];
    ASSERT_EQ(cf_iter_seek_first(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "a") == 0);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "c") == 0);

    /* turn around at c -- the step back must land on b, not repeat c or skip to a */
    ASSERT_EQ(cf_iter_prev(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "b") == 0);
    ASSERT_EQ(cf_iter_prev(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "a") == 0);

    /* turn around again at the front and walk the whole stream forward */
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "b") == 0);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "c") == 0);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "d") == 0);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "e") == 0);
    ASSERT_EQ(cf_iter_next(it), TDB_ERR_NOT_FOUND);

    /* stepping back from the far end reverses cleanly too */
    ASSERT_EQ(cf_iter_seek_last(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "e") == 0);
    ASSERT_EQ(cf_iter_prev(it), TDB_SUCCESS);
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "e") == 0);

    /* seek_for_prev lands on the largest key at or below the target, from either source */
    ASSERT_EQ(cf_iter_seek_for_prev(it, (const uint8_t *)"d", 1), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "d") == 0);
    ASSERT_EQ(cf_iter_seek_for_prev(it, (const uint8_t *)"dz", 2), TDB_SUCCESS);
    cfi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "d") == 0);

    cf_iter_free(it);
    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

/* a value past the klog threshold is stored in the value log, so the merge carries its offset and
 * length but no bytes. the merge only ever copies inline bytes into its buffer, which means the
 * bytes of the last inline key it passed are still sitting there when a spilled key resolves --
 * only the offset tells them apart. scan across an inline key into a spilled one and check the
 * spilled entry comes back as an offset rather than as the previous key's value */
void test_cf_iter_spilled_value_reports_offset_not_stale_bytes(void)
{
    cfi_db_t db;
    cfi_db_open(&db);
    /* small enough that the padded value below spills while the short one stays inline */
    cf_t *cf = cfi_make_cf_thresh(&db, 8);

    tidesdb_l0_t *l0 =
        tidesdb_l0_create(CFI_BUFFER, CFI_QDEPTH, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL);
    tidesdb_l0_set_active(l0,
                          tidesdb_memtable_create(NULL, 0, 0, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL));

    static const char big[] = "this value is well past the klog threshold so it spills to the vlog";
    ASSERT_EQ(
        tidesdb_l0_apply(l0, 0, (const uint8_t *)"a", 1, (const uint8_t *)"tiny", 4, -1, 1, 0),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"b", 1, (const uint8_t *)big,
                               sizeof(big) - 1, -1, 2, 0),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(
                  l0, tidesdb_memtable_create(NULL, 1, 1, CFI_MAX_LEVEL, CFI_PROB, NULL, NULL)),
              TDB_SUCCESS);
    tidesdb_memtable_t *immutable = tidesdb_l0_dequeue_immutable(l0);

    _Atomic(uint64_t) next_id;
    atomic_init(&next_id, 100);
    cf_t *cfs[1] = {cf};
    flush_ctx_t fx = {.l0 = l0,
                      .cfs = cfs,
                      .n_cfs = 1,
                      .manifest = db.manifest,
                      .manifest_path = db.manifest_path,
                      .next_sstable_id = &next_id,
                      .fdm = &db.fdm,
                      .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                      .value_threshold = db.value_threshold};
    ASSERT_EQ(flush_immutable(&fx, immutable), TDB_SUCCESS);
    ASSERT_EQ(level_set_count(cf->levels, LEVEL_SET_L1), 1);

    cf_iter_t *it = NULL;
    ASSERT_EQ(cf_iter_new(cf, l0, UINT64_MAX, NULL, &it), TDB_SUCCESS);

    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    /* a stays inline, so its bytes are the ones left in the merge's buffer */
    ASSERT_EQ(cf_iter_seek_first(it), TDB_SUCCESS);
    ASSERT_EQ(
        cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted),
        TDB_SUCCESS);
    ASSERT_TRUE(key_size == 1 && key[0] == 'a');
    ASSERT_EQ(vlog_offset, 0u);
    ASSERT_TRUE(value != NULL);
    ASSERT_EQ(value_size, 4u);
    ASSERT_TRUE(memcmp(value, "tiny", 4) == 0);

    /* b spilled, so it must arrive as an offset with its true length and no bytes */
    ASSERT_EQ(cf_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(
        cf_iter_get(it, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted),
        TDB_SUCCESS);
    ASSERT_TRUE(key_size == 1 && key[0] == 'b');
    ASSERT_TRUE(vlog_offset != 0);
    ASSERT_TRUE(value == NULL); /* never the "tiny" bytes still in the buffer */
    ASSERT_EQ(value_size, sizeof(big) - 1);

    /* and the value log really does hold it at that offset */
    uint8_t *resolved = NULL;
    size_t resolved_size = 0;
    ASSERT_EQ(vlog_read(db.vlog, vlog_offset, &resolved, &resolved_size), VLOG_OK);
    ASSERT_EQ(resolved_size, sizeof(big) - 1);
    ASSERT_TRUE(memcmp(resolved, big, resolved_size) == 0);
    free(resolved);

    ASSERT_EQ(cf_iter_next(it), TDB_ERR_NOT_FOUND);

    cf_iter_free(it);
    tidesdb_l0_destroy(l0);
    cf_free(cf);
    cfi_db_close(&db);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cf_iter_memtable_over_sstable, tests_passed);
    RUN_TEST(test_cf_iter_full_scan_spans_every_sstable, tests_passed);
    RUN_TEST(test_cf_iter_narrow_range_scan_does_not_open_every_sstable, tests_passed);
    RUN_TEST(test_cf_iter_seek_hides_tombstones, tests_passed);
    RUN_TEST(test_cf_iter_direction_flip_across_sources, tests_passed);
    RUN_TEST(test_cf_iter_spilled_value_reports_offset_not_stale_bytes, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
