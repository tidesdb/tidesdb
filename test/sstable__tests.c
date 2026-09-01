/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "../src/base/errors.h"
#include "../src/cache/cache.h"
#include "../src/fdmanager/fdmanager.h"
#include "../src/internal/types.h" /* TDB_KV_FLAG_TOMBSTONE */
#include "../src/sstable/btree/btree.h"
#include "../src/sstable/sstable.h"
#include "../src/sstable/vlog.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_SSTABLE_DIR "." PATH_SEPARATOR "test_sstable"

/* octal mode for the test scratch dir, ignored on windows */
#define TEST_SSTABLE_DIR_PERMISSIONS 0755

/* number of keys the build helper writes into a synthetic klog */
#define TEST_SSTABLE_KEY_COUNT 10

/* a value large enough to be real but well under any spill threshold the helper sets */
#define TEST_SSTABLE_VALUE "the-quick-brown-fox"

/* an absolute deadline far past any wall clock this test could see, so an entry judged expired can
 * only have been judged against the clock the test publishes */
#define TEST_SSTABLE_TTL_DEADLINE 4102444800

/* build a synthetic klog at path -- a real btree followed by a footer block -- and report the
 * offsets and bounds the footer recorded, so the open test can assert they round-trip */
static void build_klog(const char *path, int64_t *root, int64_t *first, int64_t *last,
                       uint64_t *max_seq, char *min_key_out, char *max_key_out)
{
    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    btree_config_t config = {0};
    config.target_node_size = BTREE_DEFAULT_NODE_SIZE;

    btree_builder_t *builder = NULL;
    ASSERT_EQ(btree_builder_new(&builder, bm, &config), 0);

    for (int i = 0; i < TEST_SSTABLE_KEY_COUNT; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(btree_builder_add(builder, (const uint8_t *)key, strlen(key),
                                    (const uint8_t *)TEST_SSTABLE_VALUE, strlen(TEST_SSTABLE_VALUE),
                                    0, (uint64_t)(i + 1), 0, 0),
                  0);
    }

    btree_t *tree = NULL;
    ASSERT_EQ(btree_builder_finish(builder, &tree), 0);
    btree_builder_free(builder);

    *root = tree->root_offset;
    *first = tree->first_leaf_offset;
    *last = tree->last_leaf_offset;
    *max_seq = tree->max_seq;
    memcpy(min_key_out, tree->min_key, tree->min_key_size);
    min_key_out[tree->min_key_size] = '\0';
    memcpy(max_key_out, tree->max_key, tree->max_key_size);
    max_key_out[tree->max_key_size] = '\0';

    sstable_footer_t footer = {0};
    footer.version = TDB_SSTABLE_FORMAT_VERSION;
    footer.root_offset = tree->root_offset;
    footer.first_leaf_offset = tree->first_leaf_offset;
    footer.last_leaf_offset = tree->last_leaf_offset;
    footer.bloom_dir_offset = 0;
    footer.bloom_dir_size = 0;
    footer.distinct_key_count = tree->entry_count;
    footer.tombstone_count = 0;
    footer.max_seq = tree->max_seq;
    footer.min_key = tree->min_key;
    footer.min_key_size = (uint32_t)tree->min_key_size;
    footer.max_key = tree->max_key;
    footer.max_key_size = (uint32_t)tree->max_key_size;
    footer.encoding_count = 0;
    footer.btree_node_size = (uint32_t)config.target_node_size;

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    ASSERT_EQ(sstable_footer_serialize(&footer, &buf, &buf_size), TDB_SUCCESS);

    block_manager_block_t *block = block_manager_block_create(buf_size, buf);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);
    free(buf);

    btree_free(tree);
    ASSERT_EQ(block_manager_close(bm), 0);
}

/* a footer with keys and an encoding pipeline round-trips every field through serialize and parse
 */
void test_footer_roundtrip(void)
{
    sstable_footer_t in = {0};
    in.version = TDB_SSTABLE_FORMAT_VERSION;
    in.root_offset = 4096;
    in.first_leaf_offset = 128;
    in.last_leaf_offset = 3000;
    in.bloom_dir_offset = 5000;
    in.bloom_dir_size = 256;
    in.distinct_key_count = 42;
    in.tombstone_count = 7;
    in.max_seq = 99;
    in.min_key = (uint8_t *)"alpha";
    in.min_key_size = 5;
    in.max_key = (uint8_t *)"omega";
    in.max_key_size = 5;
    in.encoding_pipeline[0] = 3; /* zstd */
    in.encoding_pipeline[1] = 16;
    in.encoding_count = 2;

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    ASSERT_EQ(sstable_footer_serialize(&in, &buf, &buf_size), TDB_SUCCESS);

    sstable_footer_t out = {0};
    ASSERT_EQ(sstable_footer_parse(buf, buf_size, &out), TDB_SUCCESS);

    ASSERT_EQ(out.version, in.version);
    ASSERT_EQ(out.root_offset, in.root_offset);
    ASSERT_EQ(out.first_leaf_offset, in.first_leaf_offset);
    ASSERT_EQ(out.last_leaf_offset, in.last_leaf_offset);
    ASSERT_EQ(out.bloom_dir_offset, in.bloom_dir_offset);
    ASSERT_EQ(out.bloom_dir_size, in.bloom_dir_size);
    ASSERT_EQ(out.distinct_key_count, in.distinct_key_count);
    ASSERT_EQ(out.tombstone_count, in.tombstone_count);
    ASSERT_EQ(out.max_seq, in.max_seq);
    ASSERT_EQ(out.min_key_size, in.min_key_size);
    ASSERT_TRUE(memcmp(out.min_key, in.min_key, in.min_key_size) == 0);
    ASSERT_EQ(out.max_key_size, in.max_key_size);
    ASSERT_TRUE(memcmp(out.max_key, in.max_key, in.max_key_size) == 0);
    ASSERT_EQ(out.encoding_count, in.encoding_count);
    ASSERT_EQ(out.encoding_pipeline[0], in.encoding_pipeline[0]);
    ASSERT_EQ(out.encoding_pipeline[1], in.encoding_pipeline[1]);

    free(buf);
    sstable_footer_free(&out);
}

/* an empty sstable (no keys, no bloom) round-trips with zero-length bounds */
void test_footer_roundtrip_empty(void)
{
    sstable_footer_t in = {0};
    in.version = TDB_SSTABLE_FORMAT_VERSION;
    in.root_offset = -1;
    in.first_leaf_offset = -1;
    in.last_leaf_offset = -1;

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    ASSERT_EQ(sstable_footer_serialize(&in, &buf, &buf_size), TDB_SUCCESS);

    sstable_footer_t out = {0};
    ASSERT_EQ(sstable_footer_parse(buf, buf_size, &out), TDB_SUCCESS);
    ASSERT_EQ(out.min_key_size, 0u);
    ASSERT_EQ(out.max_key_size, 0u);
    ASSERT_EQ(out.encoding_count, 0);
    ASSERT_EQ(out.root_offset, (int64_t)-1);
    ASSERT_TRUE(out.min_key == NULL);

    free(buf);
    sstable_footer_free(&out);
}

/* a bad magic, a wrong version, and a truncated buffer are each rejected as corruption */
void test_footer_rejects_bad_input(void)
{
    sstable_footer_t in = {0};
    in.version = TDB_SSTABLE_FORMAT_VERSION;
    in.min_key = (uint8_t *)"k";
    in.min_key_size = 1;
    in.max_key = (uint8_t *)"k";
    in.max_key_size = 1;

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    ASSERT_EQ(sstable_footer_serialize(&in, &buf, &buf_size), TDB_SUCCESS);

    sstable_footer_t out = {0};
    ASSERT_EQ(sstable_footer_parse(buf, buf_size - 1, &out),
              TDB_ERR_CORRUPTION); /* truncated tail */

    buf[0] ^= 0xFF; /* corrupt the magic */
    ASSERT_EQ(sstable_footer_parse(buf, buf_size, &out), TDB_ERR_CORRUPTION);

    uint8_t tiny[4] = {0};
    ASSERT_EQ(sstable_footer_parse(tiny, sizeof(tiny), &out), TDB_ERR_CORRUPTION);

    free(buf);
}

/* the .klog file name carries the owning family and the sstable id, both zero-padded. the family
 * is in the name because it is no longer in the path -- a family is a set of files the manifest
 * names rather than a directory. the table id gets the wider field because a database draws a
 * fresh one per flush and per compaction output and never reuses one, while its families are
 * counted in hundreds */
void test_klog_filename(void)
{
    char name[128];

    tidesdb_manifest_entry_t plain = {0};
    plain.id = 7;
    plain.column_family_id = 3;
    plain.birth_level = 2;
    plain.partition = MANIFEST_NO_PARTITION;
    ASSERT_EQ(sstable_klog_filename(&plain, name, sizeof(name)), TDB_SUCCESS);
    ASSERT_TRUE(strcmp(name, "000000000003.000000000007.klog") == 0);

    tidesdb_manifest_entry_t parted = {0};
    parted.id = 9;
    parted.column_family_id = 12;
    parted.birth_level = 3;
    parted.partition = 4;
    ASSERT_EQ(sstable_klog_filename(&parted, name, sizeof(name)), TDB_SUCCESS);
    ASSERT_TRUE(strcmp(name, "000000000012.000000000009.klog") == 0);

    /* two families can hold sstables of the same id without colliding, which is the whole point of
     * the family being part of the name now that they share a directory */
    char other[128];
    tidesdb_manifest_entry_t twin = {0};
    twin.id = 9;
    twin.column_family_id = 13;
    twin.partition = MANIFEST_NO_PARTITION;
    ASSERT_EQ(sstable_klog_filename(&twin, other, sizeof(other)), TDB_SUCCESS);
    ASSERT_TRUE(strcmp(other, name) != 0);

    char tiny[4];
    ASSERT_EQ(sstable_klog_filename(&plain, tiny, sizeof(tiny)), TDB_ERR_INVALID_ARGS);
}

/* opening from a manifest entry reads the footer and reconstructs the sstable identity and bounds,
 * and ensure_open lazily reopens the klog fd that open released */
void test_open_from_manifest(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.level = 1;
    entry.birth_level = 1;
    entry.id = 42;
    entry.partition = MANIFEST_NO_PARTITION;
    entry.num_entries = TEST_SSTABLE_KEY_COUNT;

    char filename[128];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    char path[256];
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    int64_t root = 0, first = 0, last = 0;
    uint64_t max_seq = 0;
    char min_key[32], max_key[32];
    build_klog(path, &root, &first, &last, &max_seq, min_key, max_key);

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "testcf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, NULL, NULL, NULL),
              TDB_SUCCESS);

    ASSERT_EQ(sst->id, 42u);
    ASSERT_EQ(sst->partition, MANIFEST_NO_PARTITION);
    ASSERT_EQ(sst->root_offset, root);
    ASSERT_EQ(sst->first_leaf_offset, first);
    ASSERT_EQ(sst->last_leaf_offset, last);
    ASSERT_EQ(sst->max_seq, max_seq);
    ASSERT_EQ(sst->distinct_key_count, (uint64_t)TEST_SSTABLE_KEY_COUNT);
    ASSERT_EQ(sst->tombstone_count, 0u);
    /* the node size has to survive the footer, since a read sizes its first pread from it */
    ASSERT_EQ(sst->btree_node_size, (uint32_t)BTREE_DEFAULT_NODE_SIZE);
    ASSERT_EQ(sst->min_key_size, strlen(min_key));
    ASSERT_TRUE(memcmp(sst->min_key, min_key, sst->min_key_size) == 0);
    ASSERT_EQ(sst->max_key_size, strlen(max_key));
    ASSERT_TRUE(memcmp(sst->max_key, max_key, sst->max_key_size) == 0);
    ASSERT_TRUE(strcmp(sst->cf_name, "testcf") == 0);

    /* open released the fd, so klog_bm starts NULL and ensure_open reopens it, idempotently */
    ASSERT_TRUE(atomic_load(&sst->klog_bm) == NULL);
    block_manager_t *bm1 = sstable_ensure_open(sst);
    ASSERT_TRUE(bm1 != NULL);
    block_manager_t *bm2 = sstable_ensure_open(sst);
    ASSERT_TRUE(bm2 == bm1);

    sstable_close(sst);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* ref, try_ref, and unref move the count and report the last release */
void test_refcount_basics(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 1;
    entry.partition = MANIFEST_NO_PARTITION;

    char filename[128];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    char path[256];
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    int64_t root = 0, first = 0, last = 0;
    uint64_t max_seq = 0;
    char min_key[32], max_key[32];
    build_klog(path, &root, &first, &last, &max_seq, min_key, max_key);

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, NULL, NULL, NULL),
              TDB_SUCCESS);

    /* opens at the owner reference; a taken ref must be balanced before the owner release frees */
    sstable_ref(sst);
    ASSERT_EQ(sstable_unref(sst), 0); /* dropped the reader, owner ref remains */
    ASSERT_EQ(sstable_unref(sst), 1); /* dropped the owner, this call is the last release */

    sstable_close(sst);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* fill a builder config with the common memcmp/bloom-on defaults, leaving spill and identity to
 * caller */
static void default_builder_config(sstable_builder_config_t *c, uint64_t id, const char *klog_path)
{
    memset(c, 0, sizeof(*c));
    c->target_node_size = BTREE_DEFAULT_NODE_SIZE;
    c->value_threshold = 1u << 20; /* no spill unless a test lowers it */
    c->enable_bloom = 1;
    c->bloom_fpr = 0.01;
    c->sync_mode = BLOCK_MANAGER_SYNC_NONE;
    c->id = id;
    c->partition = MANIFEST_NO_PARTITION;
    c->cf_name = "cf";
    c->klog_path = klog_path;
}

/* an entry's deadline is judged against the clock the sstable was given, not against the wall
 * clock. this is what lets the memtable and the sstables agree on a second: they read the same
 * published value, and a key answered first by one and then by the other does not flicker across a
 * deadline */
static int test_get_ages_entries_against_the_injected_clock(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.column_family_id = 0;
    entry.id = 700;
    entry.partition = MANIFEST_NO_PARTITION;

    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    /* a deadline far enough out that the wall clock cannot reach it during the test, so anything
     * this test observes expiring can only have come from the injected clock */
    _Atomic(int64_t) clock;
    atomic_init(&clock, TEST_SSTABLE_TTL_DEADLINE - 1);

    sstable_builder_config_t config;
    default_builder_config(&config, 700, path);
    config.now = &clock;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"k", 1, (const uint8_t *)TEST_SSTABLE_VALUE,
                            strlen(TEST_SSTABLE_VALUE), 1, TEST_SSTABLE_TTL_DEADLINE, 0),
        TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);
    ASSERT_TRUE(sst->now == &clock);

    uint8_t *val = NULL;
    size_t val_size = 0;
    uint64_t vid = 0, sq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;

    /* the clock sits one second short of the deadline, so the entry is still live */
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"k", 1, &val, &val_size, &vid, &sq, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ(deleted, 0);
    ASSERT_EQ(val_size, strlen(TEST_SSTABLE_VALUE));
    free(val);
    val = NULL;

    /* the read also stamps the access time from that same clock rather than from time(NULL) */
    ASSERT_EQ(atomic_load(&sst->last_access_time), TEST_SSTABLE_TTL_DEADLINE - 1);

    /* advancing only the published clock is enough to retire it, and it comes back as a tombstone
     * rather than as a miss, which is what stops a reader falling through to an older version */
    atomic_store(&clock, (int64_t)TEST_SSTABLE_TTL_DEADLINE);
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"k", 1, &val, &val_size, &vid, &sq, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ(deleted, 1);
    ASSERT_EQ(val, NULL);
    ASSERT_EQ(val_size, 0u);

    sstable_close(sst);
    (void)remove_directory(TEST_SSTABLE_DIR);
    return 0;
}

/* the builder writes a btree, a bloom, and a footer; the produced sstable exposes the right bounds
 * and counts, keeps its klog open, and the btree it wrote reads back every key inline */
void test_builder_roundtrip(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 100;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    default_builder_config(&config, 100, path);

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);

    for (int i = 0; i < TEST_SSTABLE_KEY_COUNT; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)TEST_SSTABLE_VALUE,
                                      strlen(TEST_SSTABLE_VALUE), (uint64_t)(i + 1), 0, 0),
                  TDB_SUCCESS);
    }

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 1; /* must be zeroed by finish, no spill happened */
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);

    ASSERT_EQ(vlog_bytes, 0u);
    ASSERT_EQ(sst->id, 100u);
    ASSERT_EQ(sst->distinct_key_count, (uint64_t)TEST_SSTABLE_KEY_COUNT);
    ASSERT_EQ(sst->tombstone_count, 0u);
    ASSERT_EQ(sst->max_seq, (uint64_t)TEST_SSTABLE_KEY_COUNT);
    ASSERT_EQ(sst->min_key_size, 5u);
    ASSERT_TRUE(memcmp(sst->min_key, "key00", 5) == 0);
    ASSERT_TRUE(memcmp(sst->max_key, "key09", 5) == 0);
    ASSERT_TRUE(sst->bloom_dir_offset != 0); /* a bloom was built */
    /* the build keeps the klog open and hot rather than releasing the fd */
    block_manager_t *hot = atomic_load(&sst->klog_bm);
    ASSERT_TRUE(hot != NULL);

    /* the btree the builder wrote reads back a key inline from the adopted offsets */
    btree_config_t bc = {0};
    btree_t *tree = NULL;
    ASSERT_EQ(btree_open(&tree, hot, &bc, sst->root_offset, sst->first_leaf_offset,
                         sst->last_leaf_offset),
              0);
    uint8_t *val = NULL;
    size_t val_size = 0;
    uint64_t vid = 1, sq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    ASSERT_EQ(
        btree_get(tree, (const uint8_t *)"key05", 5, &val, &val_size, &vid, &sq, &ttl, &deleted),
        0);
    ASSERT_EQ(val_size, strlen(TEST_SSTABLE_VALUE));
    ASSERT_TRUE(memcmp(val, TEST_SSTABLE_VALUE, val_size) == 0);
    ASSERT_EQ(vid, 0u); /* inline, not spilled */
    ASSERT_EQ(deleted, 0);
    free(val);
    btree_free(tree);

    sstable_close(sst);

    /* the footer persisted on disk, so a fresh open-from-manifest sees the same counts and bounds
     */
    sstable_t *reopened = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&reopened, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, NULL, NULL, NULL),
              TDB_SUCCESS);
    ASSERT_EQ(reopened->distinct_key_count, (uint64_t)TEST_SSTABLE_KEY_COUNT);
    ASSERT_TRUE(memcmp(reopened->max_key, "key09", 5) == 0);
    sstable_close(reopened);

    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* a table carries the range tombstones it was built with in a block of its own, so an interval
 * lives exactly as long as a table holding it rather than as long as a claim the family has to
 * verify. the block has to survive the footer and come back on a reopen, since a table reopened
 * from the manifest is the only copy of what it carried */
void test_builder_carries_its_range_tombstones(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 140;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    range_tombstone_set_t *set = range_tombstone_set_new();
    ASSERT_TRUE(set != NULL);
    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)"b", 1, (const uint8_t *)"f", 1, 45),
              TDB_SUCCESS);
    ASSERT_EQ(range_tombstone_set_add(set, (const uint8_t *)"m", 1, NULL, RT_UNBOUNDED_ABOVE, 61),
              TDB_SUCCESS);

    sstable_builder_config_t config;
    default_builder_config(&config, 140, path);
    config.range_tombstones = set;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"key", 3, (const uint8_t *)"v", 1, 70, 0, 0),
        TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);

    /* the build kept its own copy, and the set the caller passed is still the caller's to free */
    ASSERT_TRUE(sst->range_del_offset != 0 && sst->range_del_size != 0);
    const uint64_t sst_offset = sst->range_del_offset;
    const uint32_t sst_size = sst->range_del_size;
    ASSERT_TRUE(sst->range_tombstones != NULL);
    ASSERT_EQ((int)range_tombstone_set_count(sst->range_tombstones), 2);
    range_tombstone_set_free(set);
    sstable_close(sst);

    /* and it comes back off disk, covering the same keys at the same sequences */
    sstable_t *reopened = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&reopened, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, NULL, NULL, NULL),
              TDB_SUCCESS);
    /* the footer carried the block's whereabouts, before asking whether the block itself read */
    ASSERT_EQ(reopened->range_del_offset, sst_offset);
    ASSERT_EQ(reopened->range_del_size, sst_size);
    ASSERT_TRUE(reopened->range_tombstones != NULL);
    ASSERT_EQ((int)range_tombstone_set_count(reopened->range_tombstones), 2);

    uint64_t seq = 0;
    ASSERT_EQ(range_tombstone_max_covering(reopened->range_tombstones, (const uint8_t *)"cc", 2,
                                           UINT64_MAX, &seq),
              1);
    ASSERT_EQ((int)seq, 45);
    ASSERT_EQ(range_tombstone_max_covering(reopened->range_tombstones, (const uint8_t *)"zz", 2,
                                           UINT64_MAX, &seq),
              1);
    ASSERT_EQ((int)seq, 61);
    /* and a key outside every interval is covered by none */
    ASSERT_EQ(range_tombstone_max_covering(reopened->range_tombstones, (const uint8_t *)"a", 1,
                                           UINT64_MAX, &seq),
              0);
    sstable_close(reopened);

    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* a value at or above the threshold spills to the shared vlog; the btree stores its id and the
 * value round-trips through vlog_read, while a small value stays inline */
void test_builder_vlog_spill(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    vlog_config_t vcfg = {0};
    vlog_t *vlog = NULL;
    ASSERT_EQ(vlog_open(TEST_SSTABLE_DIR, &vcfg, &vlog), VLOG_OK);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 200;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    default_builder_config(&config, 200, path);
    config.value_threshold = 16; /* values >= 16 bytes spill */

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, vlog, &config), TDB_SUCCESS);

    uint8_t big[128];
    memset(big, 'B', sizeof(big));
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"big", 3, big, sizeof(big), 1, 0, 0),
              TDB_SUCCESS);
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"small", 5, (const uint8_t *)"ab", 2, 2,
                                  0, 0),
              TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);
    ASSERT_TRUE(vlog_bytes > 0);

    block_manager_t *hot = atomic_load(&sst->klog_bm);
    btree_config_t bc = {0};
    btree_t *tree = NULL;
    ASSERT_EQ(btree_open(&tree, hot, &bc, sst->root_offset, sst->first_leaf_offset,
                         sst->last_leaf_offset),
              0);

    /* the big value was spilled -- the btree hands back a vlog id, and vlog_read restores the bytes
     */
    uint8_t *val = NULL;
    size_t val_size = 0;
    uint64_t vid = 0, sq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(
        btree_get(tree, (const uint8_t *)"big", 3, &val, &val_size, &vid, &sq, &ttl, &deleted), 0);
    ASSERT_TRUE(vid != 0);
    free(val);
    uint8_t *spilled = NULL;
    size_t spilled_len = 0;
    ASSERT_EQ(vlog_read(vlog, vid, &spilled, &spilled_len), VLOG_OK);
    ASSERT_EQ(spilled_len, sizeof(big));
    ASSERT_TRUE(memcmp(spilled, big, sizeof(big)) == 0);
    free(spilled);

    /* the small value stayed inline */
    val = NULL;
    vid = 1;
    ASSERT_EQ(
        btree_get(tree, (const uint8_t *)"small", 5, &val, &val_size, &vid, &sq, &ttl, &deleted),
        0);
    ASSERT_EQ(vid, 0u);
    ASSERT_EQ(val_size, 2u);
    free(val);

    btree_free(tree);
    sstable_close(sst);
    vlog_close(vlog);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* every spilled value is attributed to the value-log segment holding it, and that attribution
 * survives the footer, since the store's segment liveness is summed from it rather than scanned */
void test_builder_records_vlog_segment_references(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    vlog_config_t vcfg = {0};
    vlog_t *vlog = NULL;
    ASSERT_EQ(vlog_open(TEST_SSTABLE_DIR, &vcfg, &vlog), VLOG_OK);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 260;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    default_builder_config(&config, 260, path);
    config.value_threshold = 16;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, vlog, &config), TDB_SUCCESS);

    /* three spill, one stays inline, so the histogram must count three values and not four */
    uint8_t big[128];
    memset(big, 'B', sizeof(big));
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"k1", 2, big, sizeof(big), 1, 0, 0),
              TDB_SUCCESS);
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"k2", 2, big, sizeof(big), 2, 0, 0),
              TDB_SUCCESS);
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"k3", 2, big, sizeof(big), 3, 0, 0),
              TDB_SUCCESS);
    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"k4", 2, (const uint8_t *)"ab", 2, 4, 0, 0),
        TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);

    /* one segment took every spill, so the three values merged into a single entry */
    ASSERT_EQ(sst->vlog_ref_count, 1u);
    ASSERT_EQ(sst->vlog_refs[0].count, 3u);
    ASSERT_TRUE(sst->vlog_refs[0].bytes >= 3 * sizeof(big));
    const uint64_t segment = sst->vlog_refs[0].segment;
    const uint64_t bytes = sst->vlog_refs[0].bytes;
    sstable_close(sst);

    sstable_t *reopened = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&reopened, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, NULL, NULL, NULL),
              TDB_SUCCESS);
    ASSERT_EQ(reopened->vlog_ref_count, 1u);
    ASSERT_EQ(reopened->vlog_refs[0].segment, segment);
    ASSERT_EQ(reopened->vlog_refs[0].bytes, bytes);
    ASSERT_EQ(reopened->vlog_refs[0].count, 3u);
    sstable_close(reopened);

    vlog_close(vlog);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* a compaction carrying a value forward normally keeps the reference, which is what makes the value
 * log cheap. when the segment holding it is being emptied that is exactly wrong -- the output table
 * would hold the old segment open and no compaction could ever drain it -- so the value is written
 * afresh instead and the output names a different segment */
void test_builder_respills_a_value_out_of_a_draining_segment(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    /* a small target so the values below fill a segment and seal it; only a sealed segment can be
     * drained, since the one taking appends is where the rewrite would land */
    vlog_config_t vcfg = {0};
    vcfg.segment_target_bytes = 8 * 1024;
    vlog_t *vlog = NULL;
    ASSERT_EQ(vlog_open(TEST_SSTABLE_DIR, &vcfg, &vlog), VLOG_OK);

    uint8_t big[1024];
    memset(big, 'V', sizeof(big));

    /* fill the first segment, then keep writing so it seals behind a later active one */
    const int fill = 24;
    uint64_t ids[24];
    for (int i = 0; i < fill; i++)
    {
        uint64_t disk = 0;
        ASSERT_EQ(vlog_write(vlog, big, sizeof(big), NULL, 0, &ids[i], &disk), VLOG_OK);
    }

    /* report just the first value as still referenced. its segment is then almost entirely dead,
     * which is what marks it for draining */
    uint64_t segment = 0, bytes = 0;
    ASSERT_EQ(vlog_segment_of(vlog, ids[0], &segment, &bytes), VLOG_OK);
    vlog_live_reset(vlog);
    vlog_live_add(vlog, segment, bytes, 1);
    ASSERT_TRUE(vlog_mark_drainable(vlog) >= 1);
    ASSERT_EQ(vlog_should_respill(vlog, ids[0]), 1);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 270;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    default_builder_config(&config, 270, path);
    config.value_threshold = 16;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, vlog, &config), TDB_SUCCESS);

    /* the shape of a merge carrying an already-spilled value forward */
    ASSERT_EQ(sstable_builder_add_reference(builder, (const uint8_t *)"k", 1, ids[0], sizeof(big),
                                            1, 0, 0),
              TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);

    /* the output holds a segment, and it is not the one being drained -- had the reference been
     * carried, this would name the draining segment and it could never reach zero */
    ASSERT_EQ(sst->vlog_ref_count, 1u);
    ASSERT_TRUE(sst->vlog_refs[0].segment != segment);

    /* and the value itself survived the rewrite */
    block_manager_t *hot = atomic_load(&sst->klog_bm);
    btree_config_t bc = {0};
    btree_t *tree = NULL;
    ASSERT_EQ(btree_open(&tree, hot, &bc, sst->root_offset, sst->first_leaf_offset,
                         sst->last_leaf_offset),
              0);
    uint8_t *val = NULL;
    size_t val_size = 0;
    uint64_t vid = 0, sq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(btree_get(tree, (const uint8_t *)"k", 1, &val, &val_size, &vid, &sq, &ttl, &deleted),
              0);
    ASSERT_TRUE(vid != 0);
    free(val);
    uint8_t *moved = NULL;
    size_t moved_len = 0;
    ASSERT_EQ(vlog_read(vlog, vid, &moved, &moved_len), VLOG_OK);
    ASSERT_EQ(moved_len, sizeof(big));
    ASSERT_TRUE(memcmp(moved, big, sizeof(big)) == 0);
    free(moved);

    btree_free(tree);
    sstable_close(sst);
    vlog_close(vlog);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* a value carries the encoding it was written under, not the one of whatever table happens to
 * reference it. that already mattered because compaction carries a value forward by id, and it
 * matters more now that a drained segment's values are re-spilled: the family doing the merge
 * writes them through its own pipeline, so a value crosses from one codec to another */
void test_respilled_value_crosses_codecs_intact(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), TDB_SUCCESS);

    vlog_config_t vcfg = {0};
    vcfg.segment_target_bytes = 8 * 1024;
    vcfg.encodings = &reg;
    vlog_t *vlog = NULL;
    ASSERT_EQ(vlog_open(TEST_SSTABLE_DIR, &vcfg, &vlog), VLOG_OK);

    /* pseudo-random rather than a repeated byte. a compressible value shrinks so far under the
     * codec that the segments never reach their target, nothing seals, and there is nothing to
     * drain -- the codec still has to round-trip these, which is what the test is about */
    uint8_t big[2048];
    uint32_t seed = 0x9E3779B9u;
    for (size_t i = 0; i < sizeof(big); i++)
    {
        seed = seed * 1664525u + 1013904223u;
        big[i] = (uint8_t)(seed >> 24);
    }

    /* the first family writes its values under one codec */
    const uint8_t first_pipeline[1] = {(uint8_t)TDB_COMPRESS_ZSTD};
    uint64_t ids[16];
    for (int i = 0; i < 16; i++)
    {
        uint64_t disk = 0;
        ASSERT_EQ(vlog_write(vlog, big, sizeof(big), first_pipeline, 1, &ids[i], &disk), VLOG_OK);
    }

    /* only the first value stays referenced, so its segment is mostly dead and gets marked */
    uint64_t segment = 0, bytes = 0;
    ASSERT_EQ(vlog_segment_of(vlog, ids[0], &segment, &bytes), VLOG_OK);
    vlog_live_reset(vlog);
    vlog_live_add(vlog, segment, bytes, 1);
    ASSERT_TRUE(vlog_mark_drainable(vlog) >= 1);
    ASSERT_EQ(vlog_should_respill(vlog, ids[0]), 1);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 280;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    /* the merging family encodes differently from the one that wrote the value */
    const uint8_t second_pipeline[1] = {(uint8_t)TDB_COMPRESS_LZ4};
    sstable_builder_config_t config;
    default_builder_config(&config, 280, path);
    config.value_threshold = 16;
    config.encoding_pipeline = second_pipeline;
    config.encoding_count = 1;
    config.encodings = &reg;

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, vlog, &config), TDB_SUCCESS);

    ASSERT_EQ(sstable_builder_add_reference(builder, (const uint8_t *)"k", 1, ids[0], sizeof(big),
                                            1, 0, 0),
              TDB_SUCCESS);

    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, &vlog_bytes), TDB_SUCCESS);
    sstable_builder_free(builder);

    /* it moved out of the drained segment */
    ASSERT_EQ(sst->vlog_ref_count, 1u);
    ASSERT_TRUE(sst->vlog_refs[0].segment != segment);

    /* read through the sstable rather than the raw btree, since this table's nodes are themselves
     * encoded and only the sstable holds the resolved pipeline to decode them */
    uint8_t *val = NULL;
    size_t val_size = 0;
    uint64_t vid = 0, sq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"k", 1, &val, &val_size, &vid, &sq, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(vid != 0 && vid != ids[0]); /* rewritten, so it carries a new id */
    free(val);

    /* and it decodes through the chain recorded with the value, which is the second family's, not
     * the first's and not whatever this sstable's footer happens to say */
    uint8_t *moved = NULL;
    size_t moved_len = 0;
    ASSERT_EQ(vlog_read(vlog, vid, &moved, &moved_len), VLOG_OK);
    ASSERT_EQ(moved_len, sizeof(big));
    ASSERT_TRUE(memcmp(moved, big, sizeof(big)) == 0);
    free(moved);

    /* the original, written under the first codec, still reads too -- one store, two pipelines */
    uint8_t *original = NULL;
    size_t original_len = 0;
    ASSERT_EQ(vlog_read(vlog, ids[1], &original, &original_len), VLOG_OK);
    ASSERT_EQ(original_len, sizeof(big));
    ASSERT_TRUE(memcmp(original, big, sizeof(big)) == 0);
    free(original);

    sstable_close(sst);
    vlog_close(vlog);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* tombstones count into tombstone_count and never spill */
void test_builder_tombstone_count(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 300;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);

    sstable_builder_config_t config;
    default_builder_config(&config, 300, path);

    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);

    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"aaa", 3, (const uint8_t *)"v", 1, 1, 0, 0),
        TDB_SUCCESS);
    ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"bbb", 3, NULL, 0, 2, 0,
                                  TDB_KV_FLAG_TOMBSTONE),
              TDB_SUCCESS);

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);

    ASSERT_EQ(sst->distinct_key_count, 2u);
    ASSERT_EQ(sst->tombstone_count, 1u);

    sstable_close(sst);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* build a synthetic sstable at the standard path holding keys key00..key(count-1) each mapping to
 * the shared value, leaving the .klog on disk under the given id for a reopen */
static void build_full_sstable(uint64_t id, int count)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = id;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);
    sstable_builder_config_t config;
    default_builder_config(&config, id, path);
    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    for (int i = 0; i < count; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)TEST_SSTABLE_VALUE,
                                      strlen(TEST_SSTABLE_VALUE), (uint64_t)(i + 1), 0, 0),
                  TDB_SUCCESS);
    }
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);
    sstable_close(sst); /* the klog persists on disk, ready for a reopen */
}

/* fill a manifest entry naming the sstable built above */
static void full_sstable_entry(tidesdb_manifest_entry_t *entry, uint64_t id)
{
    memset(entry, 0, sizeof(*entry));
    entry->birth_level = 1;
    entry->level = 1;
    entry->id = id;
    entry->partition = MANIFEST_NO_PARTITION;
}

/* a point get finds a present key, misses an absent one, and warms the node cache on the way */
void test_get_through_cache(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_full_sstable(400, TEST_SSTABLE_KEY_COUNT);

    cache_t *cache = cache_create(NULL);
    ASSERT_TRUE(cache != NULL);
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);

    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 400);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, cache, &fdm, NULL, NULL),
              TDB_SUCCESS);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 1, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"key05", 5, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ((int)value_size, (int)strlen(TEST_SSTABLE_VALUE));
    ASSERT_TRUE(memcmp(value, TEST_SSTABLE_VALUE, value_size) == 0);
    ASSERT_EQ((int)vlog_offset, 0); /* inline value, nothing spilled */
    ASSERT_EQ((int)deleted, 0);
    free(value);

    value = NULL;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"nope", 4, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted),
              TDB_ERR_NOT_FOUND);

    cache_stats_t stats;
    cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.entries > 0); /* the read faulted node blocks into the cache */

    sstable_close(sst);
    fd_manager_destroy(&fdm);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* keys enough to force the klog btree past a single node, so its root is an internal node and the
 * held-root path is exercised; zero padded so insertion order is also key order */
#define TEST_SSTABLE_DEEP_KEY_COUNT  20000
#define TEST_SSTABLE_DEEP_KEY_FORMAT "key%06d"

/* one shard with room for two nodes, so a tree of more than two nodes evicts on nearly every read
 * and the held root's own frame is certainly evicted while it is still pinned */
#define TEST_SSTABLE_TINY_CACHE_BYTES  (16u * 1024)
#define TEST_SSTABLE_TINY_CACHE_SHARDS 1
#define TEST_SSTABLE_TINY_CACHE_SLOTS  2

/* build a klog deep enough to have an internal root */
static void build_deep_sstable(uint64_t id)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = id;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);
    sstable_builder_config_t config;
    default_builder_config(&config, id, path);
    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    for (int i = 0; i < TEST_SSTABLE_DEEP_KEY_COUNT; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), TEST_SSTABLE_DEEP_KEY_FORMAT, i);
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)TEST_SSTABLE_VALUE,
                                      strlen(TEST_SSTABLE_VALUE), (uint64_t)(i + 1), 0, 0),
                  TDB_SUCCESS);
    }
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);
    sstable_close(sst);
}

/* a tree whose root is internal has that root read once and held for the sstable's life, and every
 * descent starts from it without a pin of its own. the held root must keep answering reads after
 * its own cache frame has been evicted, since the pin outlives the entry */
void test_get_borrows_a_root_held_across_reads(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_deep_sstable(401);

    cache_config_t cfg = {0};
    cfg.capacity_bytes = TEST_SSTABLE_TINY_CACHE_BYTES;
    cfg.shard_count = TEST_SSTABLE_TINY_CACHE_SHARDS;
    cfg.slots_per_shard = TEST_SSTABLE_TINY_CACHE_SLOTS;
    cache_t *cache = cache_create(&cfg);
    ASSERT_TRUE(cache != NULL);
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);

    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 401);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, cache, &fdm, NULL, NULL),
              TDB_SUCCESS);

    /* nothing is held until the first read opens a tree over the klog */
    ASSERT_TRUE(atomic_load(&sst->root_node) == NULL);

    for (int i = 0; i < TEST_SSTABLE_DEEP_KEY_COUNT; i += 97)
    {
        char key[16];
        snprintf(key, sizeof(key), TEST_SSTABLE_DEEP_KEY_FORMAT, i);
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 1, seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 1;
        ASSERT_EQ(sstable_get(sst, (const uint8_t *)key, strlen(key), &value, &value_size,
                              &vlog_offset, &seq, &ttl, &deleted),
                  TDB_SUCCESS);
        ASSERT_EQ((int)value_size, (int)strlen(TEST_SSTABLE_VALUE));
        ASSERT_TRUE(memcmp(value, TEST_SSTABLE_VALUE, value_size) == 0);
        ASSERT_EQ((int)deleted, 0);
        free(value);
    }

    /* the root was held, which is what took its per-descent pin off the read path */
    ASSERT_TRUE(atomic_load(&sst->root_node) != NULL);
    ASSERT_TRUE(sst->root_pin != NULL);

    /* the reads ran a cache far smaller than the tree, so the root's frame was evicted under them
     * and the pin is all that kept it readable */
    cache_stats_t stats;
    cache_get_stats(cache, &stats);
    ASSERT_TRUE(stats.evictions > 0);

    /* a key that is not there still misses, so the held root routes rather than short-circuits */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 1, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"zzzz", 4, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted),
              TDB_ERR_NOT_FOUND);

    sstable_close(sst);
    fd_manager_destroy(&fdm);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* the zero-filled tail an interrupted flush leaves on a klog it never trimmed to logical size */
#define TEST_SSTABLE_PREALLOC_TAIL (64 * 1024)

/* a crash leaves a klog at its preallocated size -- valid blocks then a zero tail, since the trim
 * to logical size only runs on a clean close. reopening from the manifest must locate the real
 * logical end and read the footer there, not seek into the trailing zeros and fail, which would
 * abort recovery */
void test_open_from_manifest_preallocation_tail(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_full_sstable(700, TEST_SSTABLE_KEY_COUNT);

    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 700);
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    /* re-grow the trimmed klog with a zero-filled tail so it looks as it would after a crash */
    FILE *f = fopen(path, "r+b");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    const long logical = ftell(f);
    ASSERT_TRUE(logical > 0);
    ASSERT_EQ(fseek(f, logical + TEST_SSTABLE_PREALLOC_TAIL - 1, SEEK_SET), 0);
    const unsigned char zero = 0;
    ASSERT_EQ(fwrite(&zero, 1, 1, f), (size_t)1);
    ASSERT_EQ(fclose(f), 0);

    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, NULL, &fdm, NULL, NULL),
              TDB_SUCCESS);
    ASSERT_EQ(sst->distinct_key_count, (uint64_t)TEST_SSTABLE_KEY_COUNT);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 1, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"key05", 5, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ((int)value_size, (int)strlen(TEST_SSTABLE_VALUE));
    ASSERT_TRUE(memcmp(value, TEST_SSTABLE_VALUE, value_size) == 0);
    free(value);

    sstable_close(sst);
    fd_manager_destroy(&fdm);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* build an sstable holding one key "vk" with a three-version chain (seq 5 -> "v5", seq 3 -> "v3",
 * seq 1
 * -> "v1", added newest-first as a raw merge would), plus a lone key so the tree is not degenerate
 */
static void build_versioned_sstable(uint64_t id)
{
    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = id;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);
    sstable_builder_config_t config;
    default_builder_config(&config, id, path);
    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);
    const uint64_t seqs[3] = {5, 3, 1};
    const char *vals[3] = {"v5", "v3", "v1"};
    for (int i = 0; i < 3; i++)
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)"vk", 2, (const uint8_t *)vals[i],
                                      strlen(vals[i]), seqs[i], 0, 0),
                  TDB_SUCCESS);
    ASSERT_EQ(
        sstable_builder_add(builder, (const uint8_t *)"zz", 2, (const uint8_t *)"z", 1, 9, 0, 0),
        TDB_SUCCESS);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);
    sstable_close(sst);
}

/* read one version of "vk" out of the versioned sstable at a ceiling, asserting the value it
 * resolves */
static void assert_vk_at(sstable_t *sst, uint64_t ceiling, const char *expect_val,
                         uint64_t expect_seq)
{
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 1, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    const int rc = sstable_get_at_seq(sst, (const uint8_t *)"vk", 2, ceiling, &value, &value_size,
                                      &vlog_offset, &seq, &ttl, &deleted);
    if (expect_val == NULL)
    {
        ASSERT_EQ(rc, TDB_ERR_NOT_FOUND);
        return;
    }
    ASSERT_EQ(rc, TDB_SUCCESS);
    ASSERT_EQ((int)value_size, (int)strlen(expect_val));
    ASSERT_TRUE(memcmp(value, expect_val, value_size) == 0);
    ASSERT_EQ((int)seq, (int)expect_seq);
    ASSERT_EQ((int)deleted, 0);
    free(value);
}

/* a snapshot-aware point get resolves the newest version at or below each ceiling, and misses below
 * the oldest; the newest-overall path (sstable_get) matches the UINT64_MAX ceiling */
void test_get_at_seq_version_chain(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_versioned_sstable(420);

    cache_t *cache = cache_create(NULL);
    ASSERT_TRUE(cache != NULL);
    fd_manager_t fdm;
    ASSERT_EQ(fd_manager_init(&fdm, 0), 0);

    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 420);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, cache, &fdm, NULL, NULL),
              TDB_SUCCESS);

    assert_vk_at(sst, UINT64_MAX, "v5", 5); /* newest overall */
    assert_vk_at(sst, 5, "v5", 5);
    assert_vk_at(sst, 4, "v3", 3); /* skips the seq-5 version above the ceiling */
    assert_vk_at(sst, 3, "v3", 3);
    assert_vk_at(sst, 2, "v1", 1);
    assert_vk_at(sst, 1, "v1", 1);
    assert_vk_at(sst, 0, NULL, 0); /* no version at or below the ceiling */

    /* sstable_get is the UINT64_MAX ceiling */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_get(sst, (const uint8_t *)"vk", 2, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ((int)seq, 5);
    free(value);

    sstable_close(sst);
    fd_manager_destroy(&fdm);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* the iterator walks every key forward then backward, and a seek lands on the search key */
void test_iter_forward_and_backward(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_full_sstable(410, TEST_SSTABLE_KEY_COUNT);

    cache_t *cache = cache_create(NULL);
    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 410);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, cache, NULL, NULL, NULL),
              TDB_SUCCESS);

    sstable_iter_t *it = NULL;
    ASSERT_EQ(sstable_iter_new(sst, 1, &it), TDB_SUCCESS);

    int forward = 0;
    ASSERT_EQ(sstable_iter_seek_first(it), TDB_SUCCESS);
    while (sstable_iter_valid(it))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t vlog_offset = 0, seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(sstable_iter_get(it, &key, &key_size, &value, &value_size, &vlog_offset, &seq,
                                   &ttl, &deleted),
                  TDB_SUCCESS);
        char expect[16];
        snprintf(expect, sizeof(expect), "key%02d", forward);
        ASSERT_EQ((int)key_size, (int)strlen(expect));
        ASSERT_TRUE(memcmp(key, expect, key_size) == 0);
        forward++;
        if (sstable_iter_next(it) != TDB_SUCCESS) break;
    }
    ASSERT_EQ(forward, TEST_SSTABLE_KEY_COUNT);

    int backward = 0;
    ASSERT_EQ(sstable_iter_seek_last(it), TDB_SUCCESS);
    while (sstable_iter_valid(it))
    {
        uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t vlog_offset = 0, seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        ASSERT_EQ(sstable_iter_get(it, &key, &key_size, &value, &value_size, &vlog_offset, &seq,
                                   &ttl, &deleted),
                  TDB_SUCCESS);
        char expect[16];
        snprintf(expect, sizeof(expect), "key%02d", TEST_SSTABLE_KEY_COUNT - 1 - backward);
        ASSERT_TRUE(memcmp(key, expect, key_size) == 0);
        backward++;
        if (sstable_iter_prev(it) != TDB_SUCCESS) break;
    }
    ASSERT_EQ(backward, TEST_SSTABLE_KEY_COUNT);

    /* a seek lands on the key itself */
    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"key07", 5), TDB_SUCCESS);
    uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_iter_get(it, &key, &key_size, &value, &value_size, &vlog_offset, &seq, &ttl,
                               &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(key, "key07", 5) == 0);

    sstable_iter_free(it);
    sstable_close(sst);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* the running size estimate is what a compaction splits its output on, so it has to grow as entries
 * are added and be readable mid-build rather than only once the file is sealed. a figure that
 * stayed flat would let a merge write one unbounded file however large the job asked for */
void test_builder_klog_bytes_grows_as_entries_are_added(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);

    tidesdb_manifest_entry_t entry = {0};
    entry.birth_level = 1;
    entry.id = 703;
    entry.partition = MANIFEST_NO_PARTITION;
    char filename[128], path[256];
    ASSERT_EQ(sstable_klog_filename(&entry, filename, sizeof(filename)), TDB_SUCCESS);
    snprintf(path, sizeof(path), "%s%s%s", TEST_SSTABLE_DIR, PATH_SEPARATOR, filename);

    block_manager_t *klog_bm = NULL;
    ASSERT_EQ(block_manager_open(&klog_bm, path, BLOCK_MANAGER_SYNC_NONE), 0);
    sstable_builder_config_t config;
    default_builder_config(&config, 703, path);
    sstable_builder_t *builder = NULL;
    ASSERT_EQ(sstable_builder_new(&builder, klog_bm, NULL, &config), TDB_SUCCESS);

    ASSERT_EQ(sstable_builder_klog_bytes(NULL), 0u); /* a missing builder costs nothing */
    uint64_t previous = sstable_builder_klog_bytes(builder);
    for (int i = 0; i < TEST_SSTABLE_KEY_COUNT; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(sstable_builder_add(builder, (const uint8_t *)key, strlen(key),
                                      (const uint8_t *)TEST_SSTABLE_VALUE,
                                      strlen(TEST_SSTABLE_VALUE), (uint64_t)(i + 1), 0, 0),
                  TDB_SUCCESS);
        const uint64_t now = sstable_builder_klog_bytes(builder);
        ASSERT_TRUE(now >= previous);
        previous = now;
    }
    /* by the end it has to have moved at all, which a flat estimate would not have */
    ASSERT_TRUE(previous > 0);

    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_builder_finish(builder, &sst, NULL), TDB_SUCCESS);
    sstable_builder_free(builder);

    /* the checkpoint barrier a backup takes before copying the file, which for a resident sstable
     * is a real fsync and for a NULL handle is a rejected argument rather than a crash */
    ASSERT_EQ(sstable_sync_klog(sst), TDB_SUCCESS);
    ASSERT_EQ(sstable_sync_klog(NULL), TDB_ERR_INVALID_ARGS);

    sstable_close(sst);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* assert the cursor is sitting on the named key. the entry is borrowed from the cursor's own node,
 * so nothing here is freed */
static void iter_key_is(sstable_iter_t *it, const char *want)
{
    uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_iter_get(it, &key, &key_size, &value, &value_size, &vlog_offset, &seq, &ttl,
                               &deleted),
              TDB_SUCCESS);
    ASSERT_EQ(key_size, strlen(want));
    ASSERT_TRUE(memcmp(key, want, key_size) == 0);
}

/* build the standard ten-key sstable and open a cursor over it, handing back the handles the caller
 * closes. the keys are key00 through key09, so a probe can be placed exactly on one, between two,
 * below every one, or above every one */
static sstable_iter_t *iter_over_fresh_sstable(uint64_t id, sstable_t **sst, cache_t **cache)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_full_sstable(id, TEST_SSTABLE_KEY_COUNT);

    *cache = cache_create(NULL);
    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, id);
    *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, *cache, NULL, NULL, NULL),
              TDB_SUCCESS);
    sstable_iter_t *it = NULL;
    ASSERT_EQ(sstable_iter_new(*sst, 1, &it), TDB_SUCCESS);
    return it;
}

static void iter_teardown(sstable_iter_t *it, sstable_t *sst, cache_t *cache)
{
    sstable_iter_free(it);
    sstable_close(sst);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

/* a forward seek lands on the first key at or above the target, which for a target that is not
 * itself present means the next one up, and for a target above every key means nowhere */
void test_iter_seek_lands_on_the_first_key_at_or_above_the_target(void)
{
    sstable_t *sst = NULL;
    cache_t *cache = NULL;
    sstable_iter_t *it = iter_over_fresh_sstable(700, &sst, &cache);

    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"key05", 5), TDB_SUCCESS);
    iter_key_is(it, "key05");

    /* between key05 and key06, so the one above it */
    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"key05z", 6), TDB_SUCCESS);
    iter_key_is(it, "key06");

    /* below every key, so the smallest */
    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"a", 1), TDB_SUCCESS);
    iter_key_is(it, "key00");

    /* above every key, so nothing qualifies and the cursor is left off a key */
    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"zzz", 3), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(sstable_iter_valid(it), 0);

    iter_teardown(it, sst, cache);
}

/* the backward seek is the mirror -- the last key at or below the target -- and is the direction
 * the merge iterator reaches for when it scans in reverse */
void test_iter_seek_for_prev_lands_on_the_last_key_at_or_below_the_target(void)
{
    sstable_t *sst = NULL;
    cache_t *cache = NULL;
    sstable_iter_t *it = iter_over_fresh_sstable(701, &sst, &cache);

    ASSERT_EQ(sstable_iter_seek_for_prev(it, (const uint8_t *)"key05", 5), TDB_SUCCESS);
    iter_key_is(it, "key05");

    /* between key05 and key06, so the one below it */
    ASSERT_EQ(sstable_iter_seek_for_prev(it, (const uint8_t *)"key05z", 6), TDB_SUCCESS);
    iter_key_is(it, "key05");

    /* above every key, so the largest */
    ASSERT_EQ(sstable_iter_seek_for_prev(it, (const uint8_t *)"zzz", 3), TDB_SUCCESS);
    iter_key_is(it, "key09");

    /* below every key, so nothing qualifies */
    ASSERT_EQ(sstable_iter_seek_for_prev(it, (const uint8_t *)"a", 1), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(sstable_iter_valid(it), 0);

    iter_teardown(it, sst, cache);
}

/* running off either end reports an end rather than an error, and reversing mid-scan lands on the
 * neighbour actually beside the cursor. the reversal is the part worth pinning: a cursor that keeps
 * per-direction state can carry a stale position across the turn and skip or repeat a key, which
 * reads as data appearing or vanishing rather than as anything obviously wrong with the cursor */
void test_iter_reports_each_end_and_reverses_without_losing_its_place(void)
{
    sstable_t *sst = NULL;
    cache_t *cache = NULL;
    sstable_iter_t *it = iter_over_fresh_sstable(702, &sst, &cache);

    /* forward off the top */
    ASSERT_EQ(sstable_iter_seek_last(it), TDB_SUCCESS);
    iter_key_is(it, "key09");
    ASSERT_EQ(sstable_iter_next(it), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(sstable_iter_valid(it), 0);

    /* backward off the bottom */
    ASSERT_EQ(sstable_iter_seek_first(it), TDB_SUCCESS);
    iter_key_is(it, "key00");
    ASSERT_EQ(sstable_iter_prev(it), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(sstable_iter_valid(it), 0);

    /* forward two, then back two, then forward again -- every landing named */
    ASSERT_EQ(sstable_iter_seek_first(it), TDB_SUCCESS);
    ASSERT_EQ(sstable_iter_next(it), TDB_SUCCESS);
    iter_key_is(it, "key01");
    ASSERT_EQ(sstable_iter_next(it), TDB_SUCCESS);
    iter_key_is(it, "key02");
    ASSERT_EQ(sstable_iter_prev(it), TDB_SUCCESS);
    iter_key_is(it, "key01");
    ASSERT_EQ(sstable_iter_prev(it), TDB_SUCCESS);
    iter_key_is(it, "key00");
    ASSERT_EQ(sstable_iter_next(it), TDB_SUCCESS);
    iter_key_is(it, "key01");

    /* a reversal straight after a seek, which is the turn with the least state behind it */
    ASSERT_EQ(sstable_iter_seek(it, (const uint8_t *)"key07", 5), TDB_SUCCESS);
    ASSERT_EQ(sstable_iter_prev(it), TDB_SUCCESS);
    iter_key_is(it, "key06");

    /* nothing above stopped on a failed node load, so the ends reported above were real ends */
    ASSERT_EQ(sstable_iter_read_failed(it), 0);

    iter_teardown(it, sst, cache);
}

/* a cache-bypassing iterator reads every key without faulting a single block into the cache */
void test_iter_bypasses_cache(void)
{
    (void)remove_directory(TEST_SSTABLE_DIR);
    ASSERT_EQ(mkdir(TEST_SSTABLE_DIR, TEST_SSTABLE_DIR_PERMISSIONS), 0);
    build_full_sstable(420, TEST_SSTABLE_KEY_COUNT);

    cache_t *cache = cache_create(NULL);
    tidesdb_manifest_entry_t entry;
    full_sstable_entry(&entry, 420);
    sstable_t *sst = NULL;
    ASSERT_EQ(sstable_open_from_manifest(&sst, TEST_SSTABLE_DIR, "cf", &entry,
                                         BLOCK_MANAGER_SYNC_NONE, NULL, cache, NULL, NULL, NULL),
              TDB_SUCCESS);

    sstable_iter_t *it = NULL;
    ASSERT_EQ(sstable_iter_new(sst, 0, &it), TDB_SUCCESS); /* compaction-style, cache bypassed */

    int count = 0;
    ASSERT_EQ(sstable_iter_seek_first(it), TDB_SUCCESS);
    while (sstable_iter_valid(it))
    {
        count++;
        if (sstable_iter_next(it) != TDB_SUCCESS) break;
    }
    ASSERT_EQ(count, TEST_SSTABLE_KEY_COUNT);

    cache_stats_t stats;
    cache_get_stats(cache, &stats);
    ASSERT_EQ((int)stats.entries, 0); /* the bypassing scan left the cache untouched */

    sstable_iter_free(it);
    sstable_close(sst);
    cache_destroy(cache);
    (void)remove_directory(TEST_SSTABLE_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_footer_roundtrip, tests_passed);
    RUN_TEST(test_footer_roundtrip_empty, tests_passed);
    RUN_TEST(test_footer_rejects_bad_input, tests_passed);
    RUN_TEST(test_klog_filename, tests_passed);
    RUN_TEST(test_open_from_manifest, tests_passed);
    RUN_TEST(test_refcount_basics, tests_passed);
    RUN_TEST(test_builder_roundtrip, tests_passed);
    RUN_TEST(test_builder_carries_its_range_tombstones, tests_passed);
    RUN_TEST(test_builder_vlog_spill, tests_passed);
    RUN_TEST(test_builder_records_vlog_segment_references, tests_passed);
    RUN_TEST(test_builder_respills_a_value_out_of_a_draining_segment, tests_passed);
    RUN_TEST(test_respilled_value_crosses_codecs_intact, tests_passed);
    RUN_TEST(test_builder_tombstone_count, tests_passed);
    RUN_TEST(test_get_through_cache, tests_passed);
    RUN_TEST(test_get_borrows_a_root_held_across_reads, tests_passed);
    RUN_TEST(test_open_from_manifest_preallocation_tail, tests_passed);
    RUN_TEST(test_get_at_seq_version_chain, tests_passed);
    RUN_TEST(test_iter_forward_and_backward, tests_passed);
    RUN_TEST(test_builder_klog_bytes_grows_as_entries_are_added, tests_passed);
    RUN_TEST(test_iter_seek_lands_on_the_first_key_at_or_above_the_target, tests_passed);
    RUN_TEST(test_iter_seek_for_prev_lands_on_the_last_key_at_or_below_the_target, tests_passed);
    RUN_TEST(test_iter_reports_each_end_and_reverses_without_losing_its_place, tests_passed);
    RUN_TEST(test_iter_bypasses_cache, tests_passed);
    RUN_TEST(test_get_ages_entries_against_the_injected_clock, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
