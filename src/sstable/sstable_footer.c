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

#include "base/encoding/serialization.h" /* be32/be64 and the sstable filename format constants */
#include "base/errors.h"                 /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h"
#include "sstable.h"

/* fixed portion of the footer -- magic(4) + version(4) + three btree offsets(24) + bloom dir off(8)
 * and size(4) + distinct(8) + tombstone(8) + max_seq(8) + total_key_bytes(8) + total_value_bytes(8)
 * + klog_logical_bytes(8) + btree_node_count(8) + range del block off(8) and size(4)
 * + btree_height(4) + btree_node_size(4), before the variable min/max keys and the encoding list
 */
#define TDB_SSTABLE_FOOTER_FIXED_BYTES 120

/* one histogram entry on disk -- segment number, framed bytes, value count */
#define TDB_SSTABLE_VLOG_REF_BYTES 24

int sstable_footer_serialize(const sstable_footer_t *footer, uint8_t **out, size_t *out_size)
{
    if (!footer || !out || !out_size) return TDB_ERR_INVALID_ARGS;
    if (footer->encoding_count > TDB_ENCODING_PIPELINE_MAX) return TDB_ERR_INVALID_ARGS;

    if (footer->vlog_ref_count > SSTABLE_VLOG_REF_MAX) return TDB_ERR_INVALID_ARGS;

    const size_t total = TDB_SSTABLE_FOOTER_FIXED_BYTES + sizeof(uint32_t) + footer->min_key_size +
                         sizeof(uint32_t) + footer->max_key_size + sizeof(uint8_t) +
                         footer->encoding_count + sizeof(uint32_t) +
                         (size_t)footer->vlog_ref_count * TDB_SSTABLE_VLOG_REF_BYTES;

    uint8_t *buf = malloc(total);
    if (!buf) return TDB_ERR_MEMORY;

    uint8_t *p = buf;
    tdb_encode_be32(TDB_SSTABLE_FOOTER_MAGIC, p);
    p += sizeof(uint32_t);
    tdb_encode_be32(footer->version, p);
    p += sizeof(uint32_t);
    tdb_encode_be64((uint64_t)footer->root_offset, p);
    p += sizeof(uint64_t);
    tdb_encode_be64((uint64_t)footer->first_leaf_offset, p);
    p += sizeof(uint64_t);
    tdb_encode_be64((uint64_t)footer->last_leaf_offset, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->bloom_dir_offset, p);
    p += sizeof(uint64_t);
    tdb_encode_be32(footer->bloom_dir_size, p);
    p += sizeof(uint32_t);
    tdb_encode_be64(footer->distinct_key_count, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->tombstone_count, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->max_seq, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->total_key_bytes, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->total_value_bytes, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->klog_logical_bytes, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->btree_node_count, p);
    p += sizeof(uint64_t);
    tdb_encode_be64(footer->range_del_offset, p);
    p += sizeof(uint64_t);
    tdb_encode_be32(footer->range_del_size, p);
    p += sizeof(uint32_t);
    tdb_encode_be32(footer->btree_height, p);
    p += sizeof(uint32_t);
    tdb_encode_be32(footer->btree_node_size, p);
    p += sizeof(uint32_t);

    tdb_encode_be32(footer->min_key_size, p);
    p += sizeof(uint32_t);
    if (footer->min_key_size)
    {
        memcpy(p, footer->min_key, footer->min_key_size);
        p += footer->min_key_size;
    }
    tdb_encode_be32(footer->max_key_size, p);
    p += sizeof(uint32_t);
    if (footer->max_key_size)
    {
        memcpy(p, footer->max_key, footer->max_key_size);
        p += footer->max_key_size;
    }

    *p++ = footer->encoding_count;
    if (footer->encoding_count)
    {
        memcpy(p, footer->encoding_pipeline, footer->encoding_count);
        p += footer->encoding_count;
    }

    tdb_encode_be32(footer->vlog_ref_count, p);
    p += sizeof(uint32_t);
    for (uint32_t i = 0; i < footer->vlog_ref_count; i++)
    {
        tdb_encode_be64(footer->vlog_refs[i].segment, p);
        p += sizeof(uint64_t);
        tdb_encode_be64(footer->vlog_refs[i].bytes, p);
        p += sizeof(uint64_t);
        tdb_encode_be64(footer->vlog_refs[i].count, p);
        p += sizeof(uint64_t);
    }

    *out = buf;
    *out_size = total;
    return TDB_SUCCESS;
}

/**
 * sstable_footer_parse_fixed
 * read the fixed-width part of the footer, rejecting a block that is not one of ours or is a
 * format version this build does not speak
 * @param p the read cursor, advanced past the fixed fields
 * @param out the footer being filled
 * @return TDB_SUCCESS, or TDB_ERR_CORRUPTION on a bad magic or version
 */
static int sstable_footer_parse_fixed(const uint8_t **p, sstable_footer_t *out)
{
    const uint32_t magic = tdb_decode_be32(*p);
    if (magic != TDB_SSTABLE_FOOTER_MAGIC)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer magic %08x is not %08x", magic,
                      (unsigned)TDB_SSTABLE_FOOTER_MAGIC);
        return TDB_ERR_CORRUPTION;
    }
    *p += sizeof(uint32_t);

    out->version = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    if (out->version != TDB_SSTABLE_FORMAT_VERSION)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer version %u is not %u", out->version,
                      (unsigned)TDB_SSTABLE_FORMAT_VERSION);
        return TDB_ERR_CORRUPTION;
    }

    out->root_offset = (int64_t)tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->first_leaf_offset = (int64_t)tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->last_leaf_offset = (int64_t)tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->bloom_dir_offset = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->bloom_dir_size = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    out->distinct_key_count = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->tombstone_count = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->max_seq = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->total_key_bytes = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->total_value_bytes = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->klog_logical_bytes = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->btree_node_count = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->range_del_offset = tdb_decode_be64(*p);
    *p += sizeof(uint64_t);
    out->range_del_size = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    out->btree_height = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    out->btree_node_size = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    return TDB_SUCCESS;
}

/**
 * sstable_footer_take_key
 * read one length-prefixed key out of the footer trailer, bounds-checked against what is left so a
 * truncated or lying footer is rejected rather than read past
 * @param p the read cursor, advanced past the length and the key
 * @param rem bytes left in the trailer, decremented by what this read
 * @param out_key receives the copied key, left NULL for a zero-length one
 * @param out_size receives the key length
 * @param what which key this is, for the log line
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION, or TDB_ERR_MEMORY
 */
static int sstable_footer_take_key(const uint8_t **p, size_t *rem, uint8_t **out_key,
                                   uint32_t *out_size, const char *what)
{
    if (*rem < sizeof(uint32_t))
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer trailer ends before the %s key length", what);
        return TDB_ERR_CORRUPTION;
    }
    *out_size = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    *rem -= sizeof(uint32_t);

    if (*rem < *out_size)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer claims a %u byte %s key with %zu left",
                      *out_size, what, *rem);
        return TDB_ERR_CORRUPTION;
    }
    if (*out_size == 0) return TDB_SUCCESS;

    *out_key = malloc(*out_size);
    if (!*out_key) return TDB_ERR_MEMORY;
    memcpy(*out_key, *p, *out_size);
    *p += *out_size;
    *rem -= *out_size;
    return TDB_SUCCESS;
}

/**
 * sstable_footer_parse_encodings
 * read the encoding pipeline the table was written through, which a reader has to replay in order
 * to decode a block
 * @param p the read cursor, advanced past the list
 * @param rem bytes left in the trailer, decremented by what this read
 * @param out the footer being filled
 * @return TDB_SUCCESS, or TDB_ERR_CORRUPTION on a count the trailer cannot hold
 */
static int sstable_footer_parse_encodings(const uint8_t **p, size_t *rem, sstable_footer_t *out)
{
    if (*rem < sizeof(uint8_t)) return TDB_ERR_CORRUPTION;

    out->encoding_count = *(*p)++;
    *rem -= sizeof(uint8_t);
    if (out->encoding_count > TDB_ENCODING_PIPELINE_MAX || *rem < out->encoding_count)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer declares %u encodings, max %d, %zu bytes left",
                      out->encoding_count, (int)TDB_ENCODING_PIPELINE_MAX, *rem);
        return TDB_ERR_CORRUPTION;
    }
    if (out->encoding_count)
    {
        memcpy(out->encoding_pipeline, *p, out->encoding_count);
        *p += out->encoding_count;
        *rem -= out->encoding_count;
    }
    return TDB_SUCCESS;
}

/**
 * sstable_footer_parse_vlog_refs
 * read the value-log reference histogram, which the store's segment liveness is summed from. a
 * footer that does not carry one is rejected rather than read as holding no references, since that
 * would report the segments it actually holds as empty and offer them up for reclamation
 * @param p the read cursor, advanced past the histogram
 * @param rem bytes left in the trailer, decremented by what this read
 * @param out the footer being filled
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION, or TDB_ERR_MEMORY
 */
static int sstable_footer_parse_vlog_refs(const uint8_t **p, size_t *rem, sstable_footer_t *out)
{
    if (*rem < sizeof(uint32_t))
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer ends before its value-log histogram");
        return TDB_ERR_CORRUPTION;
    }
    out->vlog_ref_count = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    *rem -= sizeof(uint32_t);

    if (out->vlog_ref_count > SSTABLE_VLOG_REF_MAX ||
        *rem < (size_t)out->vlog_ref_count * TDB_SSTABLE_VLOG_REF_BYTES)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "sstable footer declares %u value-log refs with %zu bytes left",
                      out->vlog_ref_count, *rem);
        return TDB_ERR_CORRUPTION;
    }
    if (out->vlog_ref_count == 0) return TDB_SUCCESS;

    out->vlog_refs = calloc(out->vlog_ref_count, sizeof(*out->vlog_refs));
    if (!out->vlog_refs) return TDB_ERR_MEMORY;

    for (uint32_t i = 0; i < out->vlog_ref_count; i++)
    {
        out->vlog_refs[i].segment = tdb_decode_be64(*p);
        *p += sizeof(uint64_t);
        out->vlog_refs[i].bytes = tdb_decode_be64(*p);
        *p += sizeof(uint64_t);
        out->vlog_refs[i].count = tdb_decode_be64(*p);
        *p += sizeof(uint64_t);
    }
    *rem -= (size_t)out->vlog_ref_count * TDB_SSTABLE_VLOG_REF_BYTES;
    return TDB_SUCCESS;
}

int sstable_footer_parse(const uint8_t *data, size_t size, sstable_footer_t *out)
{
    if (!data || !out) return TDB_ERR_INVALID_ARGS;
    if (size < TDB_SSTABLE_FOOTER_FIXED_BYTES)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "sstable footer is %zu bytes, short of the fixed %d", size,
                      (int)TDB_SSTABLE_FOOTER_FIXED_BYTES);
        return TDB_ERR_CORRUPTION;
    }

    memset(out, 0, sizeof(*out));

    const uint8_t *p = data;
    int rc = sstable_footer_parse_fixed(&p, out);

    /* the bytes after the fixed header hold the two length-prefixed keys and the encoding list */
    size_t rem = size - TDB_SSTABLE_FOOTER_FIXED_BYTES;
    if (rc == TDB_SUCCESS)
        rc = sstable_footer_take_key(&p, &rem, &out->min_key, &out->min_key_size, "min");
    if (rc == TDB_SUCCESS)
        rc = sstable_footer_take_key(&p, &rem, &out->max_key, &out->max_key_size, "max");
    if (rc == TDB_SUCCESS) rc = sstable_footer_parse_encodings(&p, &rem, out);
    if (rc == TDB_SUCCESS) rc = sstable_footer_parse_vlog_refs(&p, &rem, out);

    if (rc != TDB_SUCCESS) sstable_footer_free(out);
    return rc;
}

void sstable_footer_free(sstable_footer_t *footer)
{
    if (!footer) return;
    free(footer->min_key);
    footer->min_key = NULL;
    footer->min_key_size = 0;
    free(footer->max_key);
    footer->max_key = NULL;
    footer->max_key_size = 0;
    free(footer->vlog_refs);
    footer->vlog_refs = NULL;
    footer->vlog_ref_count = 0;
}
