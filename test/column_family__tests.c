/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/column_family/column_family.h"
#include "../src/sstable/sstable.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_CF_DB_DIR   "." PATH_SEPARATOR "test_cf_db"
#define TEST_CF_DIR_MODE 0755
#define TEST_CF_NAME     "metrics"
#define TEST_CF_ID       7u
#define TEST_SST_KEYS    8
#define TEST_SST_VALUE   "column-family-value"

/* the db-global services every column family borrows -- the single value log, the block cache, and
 * the descriptor budget -- plus the family directory, all under a freshly created db directory */
typedef struct
{
    vlog_t *vlog;
    cache_t *cache;
    fd_manager_t fdm;
} db_services_t;

/* create the db directory and open the db-global services inside it */
static void db_services_open(db_services_t *dv)
{
    (void)remove_directory(TEST_CF_DB_DIR);
    ASSERT_EQ(mkdir(TEST_CF_DB_DIR, TEST_CF_DIR_MODE), 0);

    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(TEST_CF_DB_DIR, &vc, &dv->vlog), VLOG_OK);

    dv->cache = cache_create(NULL);
    ASSERT_TRUE(dv->cache != NULL);
    ASSERT_EQ(fd_manager_init(&dv->fdm, 0), 0);
}

static void db_services_close(db_services_t *dv)
{
    fd_manager_destroy(&dv->fdm);
    cache_destroy(dv->cache);
    vlog_close(dv->vlog);
    (void)remove_directory(TEST_CF_DB_DIR);
}

/* a config with a distinct value in every persisted field, so a config that fails to round-trip
 * through the blob is caught */
static tidesdb_column_family_config_t make_config(void)
{
    tidesdb_column_family_config_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.name, sizeof(c.name), "%s", TEST_CF_NAME);
    c.level_size_ratio = 10;
    c.min_levels = 3;
    c.dividing_level_offset = 1;
    c.keep_values_inline = 1;
    c.btree_klog_block_size = 8192;
    c.enable_bloom_filter = 1;
    c.bloom_fpr = 0.01;
    c.default_isolation_level = TDB_ISOLATION_SNAPSHOT;
    c.l1_file_count_trigger = 4;
    c.tombstone_density_trigger = 0.25;
    c.tombstone_density_min_entries = 1000;
    c.encoding_pipeline[0] = TDB_COMPRESS_NONE;
    c.encoding_count = 1;
    return c;
}

/* write a real sstable klog into dir under the given id; the entry it would be named by matches
 * what a manifest add_sstable at that level records */
static void build_sstable_on_disk(const char *dir, uint64_t cf_id, uint64_t id)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.id = id;
    /* the family is part of the file's name now, so a table built for one family cannot be found
     * by another */
    entry.column_family_id = cf_id;
    entry.birth_level = 1;
    entry.partition = MANIFEST_NO_PARTITION;

    char filename[128], path[512];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    memset(&config, 0, sizeof(config));
    config.target_node_size = BTREE_DEFAULT_NODE_SIZE;
    config.value_threshold = 1u << 20;
    config.enable_bloom = 1;
    config.bloom_fpr = 0.01;
    config.sync_mode = BLOCK_MANAGER_SYNC_NONE;
    config.id = id;
    config.partition = MANIFEST_NO_PARTITION;
    config.cf_name = TEST_CF_NAME;
    config.klog_path = path;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    for (int i = 0; i < TEST_SST_KEYS; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)TEST_SST_VALUE, strlen(TEST_SST_VALUE),
                                      (uint64_t)(i + 1), 0, 0),
                  TDB_SUCCESS);
    }

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);
    sstable_close(sst); /* the klog stays on disk, the handle is released */
}

/* a fresh family validates, makes its directory and an empty level set, and borrows the db vlog */
void test_cf_create(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), 0);
    tidesdb_column_family_config_t config = make_config();

    cf_t *cf = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, &reg, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &cf),
              0);
    ASSERT_TRUE(cf != NULL);
    ASSERT_EQ((int)cf->cf_id, (int)TEST_CF_ID);
    ASSERT_TRUE(strcmp(cf->name, TEST_CF_NAME) == 0);
    tidesdb_column_family_config_t got;
    cf_config_get(cf, &got);
    ASSERT_EQ((int)got.level_size_ratio, 10);
    ASSERT_TRUE(cf->vlog == dv.vlog); /* borrowed, not a private copy */
    ASSERT_TRUE(cf->levels != NULL);
    ASSERT_EQ(level_set_count(cf->levels, 1), 0);

    cf_free(cf);
    db_services_close(&dv);
}

/* an invalid config is refused against the registry and no family is produced */
void test_cf_create_invalid(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), 0);
    tidesdb_column_family_config_t config = make_config();
    config.bloom_fpr = 2.0; /* out of (0, 1) with the filter enabled */

    cf_t *cf = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, &reg, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &cf),
              -1);
    ASSERT_TRUE(cf == NULL);

    db_services_close(&dv);
}

/* opening a family whose manifest has no entries yields the same config and empty levels */
void test_cf_open_empty(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_column_family_config_t config = make_config();
    cf_t *created = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, NULL, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &created),
              0);

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    tidesdb_column_family_config_t saved;
    cf_config_get(created, &saved);
    ASSERT_EQ(cf_config_serialize(&saved, &blob, &blob_len), 0);
    cf_free(created);

    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s%sMANIFEST", TEST_CF_DB_DIR, PATH_SEPARATOR);
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(manifest_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, TEST_CF_ID, TEST_CF_NAME, NULL, 0), 0);

    cf_t *opened = NULL;
    ASSERT_EQ(cf_open(TEST_CF_DB_DIR, manifest, TEST_CF_ID, TEST_CF_NAME, blob, blob_len, NULL,
                      dv.vlog, dv.cache, &dv.fdm, BLOCK_MANAGER_SYNC_NONE, NULL, NULL, &opened),
              0);
    ASSERT_TRUE(opened != NULL);
    tidesdb_column_family_config_t got;
    cf_config_get(opened, &got);
    ASSERT_EQ((int)got.level_size_ratio, 10);
    ASSERT_TRUE(strcmp(got.name, TEST_CF_NAME) == 0);
    ASSERT_EQ(level_set_count(opened->levels, 1), 0);

    cf_free(opened);
    free(blob);
    tidesdb_manifest_close(manifest);
    db_services_close(&dv);
}

/* opening a family rebuilds its level set from the manifest, one sstable per recorded entry */
void test_cf_open_rebuilds_levels(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_column_family_config_t config = make_config();
    cf_t *created = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, NULL, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &created),
              0);
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    tidesdb_column_family_config_t saved;
    cf_config_get(created, &saved);
    ASSERT_EQ(cf_config_serialize(&saved, &blob, &blob_len), 0);

    /* two sstables written into the family directory, one at each of two levels */
    build_sstable_on_disk(created->dir, TEST_CF_ID, 1);
    build_sstable_on_disk(created->dir, TEST_CF_ID, 2);
    cf_free(created);

    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s%sMANIFEST", TEST_CF_DB_DIR, PATH_SEPARATOR);
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(manifest_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, TEST_CF_ID, TEST_CF_NAME, NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, TEST_CF_ID, 1, 1, TEST_SST_KEYS, 100,
                                           MANIFEST_NO_PARTITION),
              0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, TEST_CF_ID, 2, 2, TEST_SST_KEYS, 200,
                                           MANIFEST_NO_PARTITION),
              0);

    cf_t *opened = NULL;
    ASSERT_EQ(cf_open(TEST_CF_DB_DIR, manifest, TEST_CF_ID, TEST_CF_NAME, blob, blob_len, NULL,
                      dv.vlog, dv.cache, &dv.fdm, BLOCK_MANAGER_SYNC_NONE, NULL, NULL, &opened),
              0);
    ASSERT_TRUE(opened != NULL);
    ASSERT_EQ(level_set_count(opened->levels, 1), 1);
    ASSERT_EQ(level_set_count(opened->levels, 2), 1);

    cf_free(opened);
    free(blob);
    tidesdb_manifest_close(manifest);
    db_services_close(&dv);
}

/* overwrite an on-disk klog's block-manager magic so it will not open, mimicking a torn sstable a
 * crash can leave behind */
static void corrupt_klog(const char *dir, uint64_t cf_id, uint64_t id)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.id = id;
    entry.column_family_id = cf_id;
    entry.birth_level = 1;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[512];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, filename);

    FILE *f = fopen(path, "r+b");
    ASSERT_TRUE(f != NULL);
    const unsigned char garbage[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT_EQ(fwrite(garbage, 1, sizeof(garbage), f), sizeof(garbage));
    ASSERT_EQ(fclose(f), 0);
}

/* crash recovery self-heals past an unreadable L1 segment rather than refusing the open, since a
 * torn flush output's data still replays from its WAL generation; a good sstable at a deeper level
 * loads */
void test_cf_open_self_heals_torn_l1(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_column_family_config_t config = make_config();
    cf_t *created = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, NULL, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &created),
              0);
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    tidesdb_column_family_config_t saved;
    cf_config_get(created, &saved);
    ASSERT_EQ(cf_config_serialize(&saved, &blob, &blob_len), 0);

    build_sstable_on_disk(created->dir, TEST_CF_ID, 1); /* an L1 flush output, about to be torn */
    build_sstable_on_disk(created->dir, TEST_CF_ID, 2); /* a good sstable at a deeper level */
    corrupt_klog(created->dir, TEST_CF_ID, 1);
    cf_free(created);

    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s%sMANIFEST", TEST_CF_DB_DIR, PATH_SEPARATOR);
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(manifest_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, TEST_CF_ID, TEST_CF_NAME, NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, TEST_CF_ID, 1, 1, TEST_SST_KEYS, 100,
                                           MANIFEST_NO_PARTITION),
              0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, TEST_CF_ID, 2, 2, TEST_SST_KEYS, 200,
                                           MANIFEST_NO_PARTITION),
              0);

    cf_t *opened = NULL;
    ASSERT_EQ(cf_open(TEST_CF_DB_DIR, manifest, TEST_CF_ID, TEST_CF_NAME, blob, blob_len, NULL,
                      dv.vlog, dv.cache, &dv.fdm, BLOCK_MANAGER_SYNC_NONE, NULL, NULL, &opened),
              0);
    ASSERT_TRUE(opened != NULL);
    ASSERT_EQ(level_set_count(opened->levels, 1), 0); /* the torn L1 was skipped */
    ASSERT_EQ(level_set_count(opened->levels, 2), 1); /* the good deeper sstable loaded */

    cf_free(opened);
    free(blob);
    tidesdb_manifest_close(manifest);
    db_services_close(&dv);
}

/* a torn sstable below L1 is a compaction output whose inputs are already gone, so there is no WAL
 * to recover it from; the open fails loudly rather than silently dropping committed data */
void test_cf_open_fails_on_torn_deep_level(void)
{
    db_services_t dv;
    db_services_open(&dv);

    tidesdb_column_family_config_t config = make_config();
    cf_t *created = NULL;
    ASSERT_EQ(cf_create(TEST_CF_DB_DIR, TEST_CF_ID, &config, NULL, dv.vlog, dv.cache, &dv.fdm, NULL,
                        NULL, &created),
              0);
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    tidesdb_column_family_config_t saved;
    cf_config_get(created, &saved);
    ASSERT_EQ(cf_config_serialize(&saved, &blob, &blob_len), 0);

    build_sstable_on_disk(created->dir, TEST_CF_ID, 1);
    corrupt_klog(created->dir, TEST_CF_ID, 1);
    cf_free(created);

    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s%sMANIFEST", TEST_CF_DB_DIR, PATH_SEPARATOR);
    tidesdb_manifest_t *manifest = tidesdb_manifest_open(manifest_path);
    ASSERT_TRUE(manifest != NULL);
    ASSERT_EQ(tidesdb_manifest_add_cf(manifest, TEST_CF_ID, TEST_CF_NAME, NULL, 0), 0);
    ASSERT_EQ(tidesdb_manifest_add_sstable(manifest, TEST_CF_ID, 3, 1, TEST_SST_KEYS, 100,
                                           MANIFEST_NO_PARTITION),
              0);

    cf_t *opened = NULL;
    ASSERT_TRUE(cf_open(TEST_CF_DB_DIR, manifest, TEST_CF_ID, TEST_CF_NAME, blob, blob_len, NULL,
                        dv.vlog, dv.cache, &dv.fdm, BLOCK_MANAGER_SYNC_NONE, NULL, NULL,
                        &opened) != 0);
    ASSERT_TRUE(opened == NULL);

    free(blob);
    tidesdb_manifest_close(manifest);
    db_services_close(&dv);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cf_create, tests_passed);
    RUN_TEST(test_cf_create_invalid, tests_passed);
    RUN_TEST(test_cf_open_empty, tests_passed);
    RUN_TEST(test_cf_open_rebuilds_levels, tests_passed);
    RUN_TEST(test_cf_open_self_heals_torn_l1, tests_passed);
    RUN_TEST(test_cf_open_fails_on_torn_deep_level, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
