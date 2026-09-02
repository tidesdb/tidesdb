/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/log.h"
#include "../src/column_family/cf_config.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* compare two doubles by their bits rather than by value. a 32-bit x86 build evaluates a floating
 * expression in the x87's extended precision, so the literal can be held to more precision than the
 * double it is compared against and an exact round-trip still tests unequal. the blob stores the
 * ieee-754 bits verbatim, so the bits are what the round-trip actually promises */
static int cf_config_same_double(const double a, const double b)
{
    return memcmp(&a, &b, sizeof(a)) == 0;
}

/* a config with a distinct value in every persisted field, so a round-trip that drops one is caught
 */
static tidesdb_column_family_config_t make_config(void)
{
    tidesdb_column_family_config_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.name, sizeof(c.name), "%s", "metrics");
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
    c.encoding_pipeline[0] = TDB_COMPRESS_SNAPPY;
    c.encoding_pipeline[1] = TDB_COMPRESS_NONE;
    c.encoding_count = 2;
    return c;
}

void test_cf_config_roundtrip(void)
{
    tidesdb_column_family_config_t in = make_config();

    uint8_t *blob = NULL;
    size_t len = 0;
    ASSERT_EQ(cf_config_serialize(&in, &blob, &len), 0);
    ASSERT_TRUE(blob != NULL);
    ASSERT_EQ((int)len, CF_CONFIG_BLOB_FIXED_SIZE + in.encoding_count);
    ASSERT_EQ((int)blob[0], CF_CONFIG_BLOB_VERSION);

    tidesdb_column_family_config_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(cf_config_deserialize(blob, len, &out), 0);

    ASSERT_EQ((int)out.level_size_ratio, 10);
    ASSERT_EQ(out.min_levels, 3);
    ASSERT_EQ(out.dividing_level_offset, 1);
    ASSERT_EQ(out.keep_values_inline, 1);
    ASSERT_EQ((int)out.btree_klog_block_size, 8192);
    ASSERT_EQ(out.enable_bloom_filter, 1);
    ASSERT_TRUE(cf_config_same_double(out.bloom_fpr, 0.01));
    ASSERT_EQ((int)out.default_isolation_level, TDB_ISOLATION_SNAPSHOT);
    ASSERT_EQ(out.l1_file_count_trigger, 4);
    ASSERT_TRUE(cf_config_same_double(out.tombstone_density_trigger, 0.25));
    ASSERT_EQ((int)out.tombstone_density_min_entries, 1000);
    ASSERT_EQ(out.encoding_count, 2);
    ASSERT_EQ(out.encoding_pipeline[0], TDB_COMPRESS_SNAPPY);
    ASSERT_EQ(out.encoding_pipeline[1], TDB_COMPRESS_NONE);

    free(blob);
}

/* the threshold is the database's unless the family keeps its values inline, in which case no
 * value can reach it */
void test_cf_config_value_threshold(void)
{
    tidesdb_column_family_config_t c = make_config();

    c.keep_values_inline = 0;
    ASSERT_EQ((int)cf_config_value_threshold(&c, 1024), 1024);

    c.keep_values_inline = 1;
    ASSERT_TRUE(cf_config_value_threshold(&c, 1024) == SIZE_MAX);

    /* a family the caller does not name still answers with the database's threshold */
    ASSERT_EQ((int)cf_config_value_threshold(NULL, 1024), 1024);
}

/* the layout advisory fires only when an inlined value would crowd its klog node, and it stays an
 * advisory -- the same config must keep validating, or a database already carrying it could not be
 * reopened */
void test_cf_config_warn_layout(void)
{
    const char *log_path = "./cf_config_layout_warn.log";
    (void)remove(log_path);

    tidesdb_column_family_config_t c = make_config();
    c.btree_klog_block_size = 4096;
    c.keep_values_inline = 0;

    FILE *log = fopen(log_path, "w+");
    ASSERT_TRUE(log != NULL);
    tidesdb_log_set_sink(log, 0, NULL);
    atomic_store(&_tidesdb_log_level, TDB_LOG_TRACE);

    /* a quarter of the node size leaves room for several entries, so nothing is logged */
    cf_config_warn_layout(&c, 1024);
    ASSERT_EQ(cf_config_validate(&c, NULL), 0);
    ASSERT_EQ(ftell(log), 0);

    /* a threshold past that quarter would leave a node holding one value, so it is called out */
    cf_config_warn_layout(&c, 4096);
    ASSERT_TRUE(ftell(log) > 0);
    ASSERT_EQ(cf_config_validate(&c, NULL), 0); /* still valid, only advised against */
    rewind(log);
    ASSERT_EQ(ftruncate(fileno(log), 0), 0);

    /* a family holding every value inline is not judged by a threshold it does not use */
    c.keep_values_inline = 1;
    cf_config_warn_layout(&c, 4096);
    ASSERT_EQ(ftell(log), 0);
    c.keep_values_inline = 0;

    /* neither a NULL config, an unset node size, nor an unset threshold may trip it */
    cf_config_warn_layout(NULL, 4096);
    cf_config_warn_layout(&c, 0);
    c.btree_klog_block_size = 0;
    cf_config_warn_layout(&c, 4096);

    tidesdb_log_close_sink();
    (void)remove(log_path);
}

/* a codec that is never invoked; the registry only needs the entry to exist for a resolve to find
 * it, and these tests never encode anything through it */
static int cf_config_test_codec(void *ctx, const uint8_t *src, size_t src_size, uint8_t **dst,
                                size_t *dst_size)
{
    (void)ctx;
    (void)src;
    (void)src_size;
    (void)dst;
    (void)dst_size;
    return TDB_SUCCESS;
}

void test_cf_config_validate(void)
{
    tidesdb_encoding_registry_t reg;
    ASSERT_EQ(tidesdb_encoding_registry_init(&reg), 0);

    tidesdb_column_family_config_t c = make_config();
    /* every case below that validates against the real registry has to name a codec this build
     * actually registered, and the only one guaranteed to be there is the one that does nothing.
     * naming an optional backend here made this whole test a check of how the runner was built */
    c.encoding_pipeline[0] = TDB_COMPRESS_NONE;
    ASSERT_EQ(cf_config_validate(&c, &reg), 0);

    /* a pipeline id naming no algorithm is rejected whether or not a registry is supplied. the
     * engine casts this byte to a compression algorithm, and a runtime config update takes it
     * straight from a public argument and persists it, so the check cannot depend on a caller
     * choosing to pass a registry */
    c.encoding_pipeline[0] = 200;
    ASSERT_EQ(cf_config_validate(&c, &reg), -1);
    ASSERT_EQ(cf_config_validate(&c, NULL), -1);

    /* an id that names a real algorithm passes even where the build lacks that codec, so a database
     * written by a build that had it still opens here */
    c.encoding_pipeline[0] = CF_CONFIG_MAX_ENCODING_ID;
    ASSERT_EQ(cf_config_validate(&c, NULL), 0);
    c.encoding_pipeline[0] = TDB_COMPRESS_SNAPPY;

    /* the same id against a registry that does not carry it is rejected, which is what a build
     * missing that backend looks like. this is the create and reconfigure path -- both pass the
     * registry, so a family can never be configured with a codec that cannot encode it. a family
     * that got one anyway would fail in every later sstable build, leaving it unflushable while the
     * call that set it reported success */
    tidesdb_encoding_registry_t bare;
    memset(&bare, 0, sizeof(bare));
    ASSERT_EQ(tidesdb_encoding_register(&bare, "none", TDB_COMPRESS_NONE, cf_config_test_codec,
                                        cf_config_test_codec, NULL),
              TDB_SUCCESS);
    ASSERT_EQ(cf_config_validate(&c, &bare), -1);
    c.encoding_pipeline[0] = TDB_COMPRESS_NONE;
    ASSERT_EQ(cf_config_validate(&c, &bare), 0);

    /* an out-of-range bloom fpr is rejected only when the filter is enabled */
    c.bloom_fpr = 1.5;
    ASSERT_EQ(cf_config_validate(&c, &reg), -1);
    c.enable_bloom_filter = 0;
    ASSERT_EQ(cf_config_validate(&c, &reg), 0);
    c.enable_bloom_filter = 1;
    c.bloom_fpr = 0.01;

    /* a tombstone density ratio outside [0, 1] is rejected */
    c.tombstone_density_trigger = 2.0;
    ASSERT_EQ(cf_config_validate(&c, &reg), -1);
    c.tombstone_density_trigger = 0.25;

    /* too many encodings is rejected */
    c.encoding_count = TDB_ENCODING_PIPELINE_MAX + 1;
    ASSERT_EQ(cf_config_validate(&c, &reg), -1);
    c.encoding_count = 2;

    ASSERT_EQ(cf_config_validate(NULL, &reg), -1);
}

void test_cf_config_version_reject(void)
{
    tidesdb_column_family_config_t in = make_config();
    uint8_t *blob = NULL;
    size_t len = 0;
    ASSERT_EQ(cf_config_serialize(&in, &blob, &len), 0);

    blob[0] = CF_CONFIG_BLOB_VERSION - 1; /* an older version is refused, not misread */
    tidesdb_column_family_config_t out;
    ASSERT_EQ(cf_config_deserialize(blob, len, &out), -1);

    free(blob);
}

void test_cf_config_truncated(void)
{
    tidesdb_column_family_config_t in = make_config();
    uint8_t *blob = NULL;
    size_t len = 0;
    ASSERT_EQ(cf_config_serialize(&in, &blob, &len), 0);

    tidesdb_column_family_config_t out;
    /* short of the fixed header, and short of the declared encoding array, both fail */
    ASSERT_EQ(cf_config_deserialize(blob, 10, &out), -1);
    ASSERT_EQ(cf_config_deserialize(blob, CF_CONFIG_BLOB_FIXED_SIZE, &out), -1);

    free(blob);
}

/* a blob that is the right version and the right length can still carry field values the engine
 * would never have accepted from a caller. the isolation level is the sharpest of them -- the
 * commit path decides whether to take a write reservation by comparing it against snapshot
 * isolation, so a value outside the enum silently changes whether concurrent writers conflict. the
 * decoder holds a blob to the same rules the create path enforces */
void test_cf_config_rejects_out_of_range_fields(void)
{
    tidesdb_column_family_config_t in = make_config();
    uint8_t *blob = NULL;
    size_t len = 0;
    ASSERT_EQ(cf_config_serialize(&in, &blob, &len), 0);

    /* locate the isolation word by re-serializing a config that differs only there */
    tidesdb_column_family_config_t probe = make_config();
    probe.default_isolation_level = TDB_ISOLATION_READ_UNCOMMITTED;
    uint8_t *probe_blob = NULL;
    size_t probe_len = 0;
    ASSERT_EQ(cf_config_serialize(&probe, &probe_blob, &probe_len), 0);
    ASSERT_EQ(len, probe_len);

    /* the two configs differ only in the isolation level, and the encoder writes it big-endian, so
     * the single differing byte is the word's low-order byte and the field starts three before it
     */
    size_t iso_off = 0;
    int found = 0;
    for (size_t i = 0; i < len; i++)
        if (blob[i] != probe_blob[i])
        {
            ASSERT_TRUE(i >= 3);
            iso_off = i - 3;
            found = 1;
            break;
        }
    free(probe_blob);
    ASSERT_TRUE(found);

    /* a value past the last isolation level, written big-endian like the encoder does */
    blob[iso_off] = 0;
    blob[iso_off + 1] = 0;
    blob[iso_off + 2] = 0;
    blob[iso_off + 3] = 99;

    tidesdb_column_family_config_t out;
    ASSERT_EQ(cf_config_deserialize(blob, len, &out), -1);

    free(blob);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cf_config_roundtrip, tests_passed);
    RUN_TEST(test_cf_config_validate, tests_passed);
    RUN_TEST(test_cf_config_value_threshold, tests_passed);
    RUN_TEST(test_cf_config_warn_layout, tests_passed);
    RUN_TEST(test_cf_config_version_reject, tests_passed);
    RUN_TEST(test_cf_config_truncated, tests_passed);
    RUN_TEST(test_cf_config_rejects_out_of_range_fields, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
