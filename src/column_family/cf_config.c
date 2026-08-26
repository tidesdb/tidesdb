/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "column_family/cf_config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* tdb_encode_be32/be64, tdb_decode_be32/be64 */
#include "base/log.h"                    /* TDB_DEBUG_LOG for the layout advisory */

/* the fewest maximum-size inlined values a klog node is expected to hold. a value only stays in the
 * klog while it is under the database's separation threshold, so a threshold approaching
 * btree_klog_block_size lets one value fill a node and drives the tree toward one entry per node,
 * spending the fan-out that makes a lookup cheap. four keeps a node holding several entries even at
 * the largest inlined size */
#define CF_CONFIG_MIN_ENTRIES_PER_BLOCK 4

/* a double is serialized by its raw IEEE-754 bits (copied to a u64, not aliased) so the value
 * survives a round-trip byte for byte; the engine already assumes IEEE-754 doubles */
static uint64_t cf_config_double_to_bits(const double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    return bits;
}

static double cf_config_bits_to_double(const uint64_t bits)
{
    double v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

size_t cf_config_value_threshold(const tidesdb_column_family_config_t *cfg,
                                 const size_t db_threshold)
{
    /* the builder separates a value whose size reaches the threshold, so a threshold no value can
     * reach is how a family that keeps its values inline is expressed */
    if (cfg && cfg->keep_values_inline) return SIZE_MAX;
    return db_threshold;
}

void cf_config_warn_layout(const tidesdb_column_family_config_t *cfg, const size_t db_threshold)
{
    if (!cfg || cfg->btree_klog_block_size == 0 || db_threshold == 0) return;

    /* a family that keeps every value inline has already accepted large entries in its nodes, so
     * the advisory has nothing to tell it */
    if (cfg->keep_values_inline) return;

    /* divide rather than multiply so an absurd threshold cannot overflow the comparison */
    if (db_threshold <= cfg->btree_klog_block_size / CF_CONFIG_MIN_ENTRIES_PER_BLOCK) return;

    TDB_DEBUG_LOG(
        TDB_LOG_WARN,
        "cf %s inlines values up to %zu bytes into %zu byte klog nodes, fewer than %d per "
        "node, which spends btree fan-out; raise btree_klog_block_size or lower "
        "value_separation_threshold",
        cfg->name, db_threshold, cfg->btree_klog_block_size, CF_CONFIG_MIN_ENTRIES_PER_BLOCK);
}

int cf_config_validate(const tidesdb_column_family_config_t *cfg,
                       const tidesdb_encoding_registry_t *reg)
{
    if (!cfg) return -1;
    if (strnlen(cfg->name, TDB_MAX_CF_NAME_LEN) >= TDB_MAX_CF_NAME_LEN) return -1;
    if (cfg->encoding_count > TDB_ENCODING_PIPELINE_MAX) return -1;

    /* the engine applies a pipeline entry by casting it to a compression algorithm, so an entry
     * outside that enum reaches the codec dispatch as an unrecognised value. checked whatever the
     * caller supplies, because a runtime config update takes this array straight from a public
     * argument and persists it. availability is deliberately not checked here -- a database written
     * with a codec this build lacks must still open, and surfaces the gap when a node is read */
    for (uint8_t i = 0; i < cfg->encoding_count; i++)
        if (cfg->encoding_pipeline[i] > CF_CONFIG_MAX_ENCODING_ID) return -1;

    /* every pipeline id must resolve in the registry when one is supplied */
    if (reg != NULL)
    {
        for (uint8_t i = 0; i < cfg->encoding_count; i++)
            if (tidesdb_encoding_find_by_id(reg, cfg->encoding_pipeline[i]) == NULL) return -1;
    }

    /* a bloom filter needs a false-positive rate strictly inside (0, 1) */
    if (cfg->enable_bloom_filter && (cfg->bloom_fpr <= 0.0 || cfg->bloom_fpr >= 1.0)) return -1;

    /* the tombstone density trigger is a ratio in [0, 1]; 0 disables it */
    if (cfg->tombstone_density_trigger < 0.0 || cfg->tombstone_density_trigger > 1.0) return -1;

    /* the isolation level indexes behaviour rather than merely describing it -- the commit path
     * compares it against snapshot isolation to decide whether a write takes a reservation at all
     * -- so a value outside the enum would quietly change how concurrent writers conflict */
    if (cfg->default_isolation_level < TDB_ISOLATION_READ_UNCOMMITTED ||
        cfg->default_isolation_level > TDB_ISOLATION_SERIALIZABLE)
        return -1;

    /* a level fan-out below two never grows the tree, and a non-positive level count leaves the
     * planner with no level to compact into */
    if (cfg->level_size_ratio < 2) return -1;
    if (cfg->min_levels <= 0) return -1;

    return 0;
}

int cf_config_serialize(const tidesdb_column_family_config_t *cfg, uint8_t **out, size_t *out_len)
{
    if (!cfg || !out || !out_len) return -1;
    if (cfg->encoding_count > TDB_ENCODING_PIPELINE_MAX) return -1;

    const size_t len = CF_CONFIG_BLOB_FIXED_SIZE + cfg->encoding_count;
    uint8_t *buf = malloc(len);
    if (!buf) return -1;

    size_t off = 0;
    buf[off++] = CF_CONFIG_BLOB_VERSION;
    tdb_encode_be64((uint64_t)cfg->level_size_ratio, buf + off);
    off += 8;
    tdb_encode_be32((uint32_t)cfg->min_levels, buf + off);
    off += 4;
    tdb_encode_be32((uint32_t)cfg->dividing_level_offset, buf + off);
    off += 4;
    buf[off++] = (uint8_t)(cfg->keep_values_inline ? 1 : 0);
    tdb_encode_be64((uint64_t)cfg->btree_klog_block_size, buf + off);
    off += 8;
    buf[off++] = (uint8_t)(cfg->enable_bloom_filter ? 1 : 0);
    tdb_encode_be64(cf_config_double_to_bits(cfg->bloom_fpr), buf + off);
    off += 8;
    tdb_encode_be32((uint32_t)cfg->default_isolation_level, buf + off);
    off += 4;
    tdb_encode_be32((uint32_t)cfg->l1_file_count_trigger, buf + off);
    off += 4;
    tdb_encode_be64(cf_config_double_to_bits(cfg->tombstone_density_trigger), buf + off);
    off += 8;
    tdb_encode_be64(cfg->tombstone_density_min_entries, buf + off);
    off += 8;
    buf[off++] = cfg->encoding_count;
    memcpy(buf + off, cfg->encoding_pipeline, cfg->encoding_count);

    *out = buf;
    *out_len = len;
    return 0;
}

int cf_config_deserialize(const uint8_t *data, size_t len, tidesdb_column_family_config_t *out)
{
    if (!data || !out || len < CF_CONFIG_BLOB_FIXED_SIZE) return -1;
    if (data[0] != CF_CONFIG_BLOB_VERSION) return -1;

    size_t off = 1;
    out->level_size_ratio = (size_t)tdb_decode_be64(data + off);
    off += 8;
    out->min_levels = (int)tdb_decode_be32(data + off);
    off += 4;
    out->dividing_level_offset = (int)tdb_decode_be32(data + off);
    off += 4;
    out->keep_values_inline = data[off++];
    out->btree_klog_block_size = (size_t)tdb_decode_be64(data + off);
    off += 8;
    out->enable_bloom_filter = data[off++];
    out->bloom_fpr = cf_config_bits_to_double(tdb_decode_be64(data + off));
    off += 8;
    const uint32_t isolation_word = tdb_decode_be32(data + off);
    out->default_isolation_level = (tidesdb_isolation_level_t)isolation_word;
    off += 4;
    out->l1_file_count_trigger = (int)tdb_decode_be32(data + off);
    off += 4;
    out->tombstone_density_trigger = cf_config_bits_to_double(tdb_decode_be64(data + off));
    off += 8;
    out->tombstone_density_min_entries = tdb_decode_be64(data + off);
    off += 8;

    const uint8_t encoding_count = data[off++];
    if (encoding_count > TDB_ENCODING_PIPELINE_MAX) return -1;
    if (len < (size_t)CF_CONFIG_BLOB_FIXED_SIZE + encoding_count) return -1;
    out->encoding_count = encoding_count;
    memcpy(out->encoding_pipeline, data + off, encoding_count);

    /* every field above came off disk, where a torn write or a hostile blob can leave any bit
     * pattern that still passes the version and length checks. the decoded config then reaches the
     * engine unchallenged -- an out-of-range isolation level, for one, decides through
     * `isolation >= TDB_ISOLATION_SNAPSHOT` whether a commit takes a write reservation at all. the
     * same rules the create path enforces are applied here so a blob can only produce a config the
     * engine would have accepted from a caller */
    if (cf_config_validate(out, NULL) != 0) return -1;

    /* name and the runtime commit hook are not part of the blob; the caller sets them */
    return 0;
}
