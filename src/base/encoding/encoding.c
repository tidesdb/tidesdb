/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "encoding.h"

#include <stdlib.h>
#include <string.h>

#include "base/log.h"
#include "compress.h" /* the built-in encodings wrap the compression backends */
#include "db.h"       /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* the passthrough transform copies its input verbatim into an owned buffer, so an empty pipeline
 * and a "none" pipeline both hand back a freshly allocated copy the caller frees like any other
 * output. a zero-length input still allocates one byte so the returned pointer is always freeable.
 */
static int encoding_passthrough(void *ctx, const uint8_t *src, size_t src_size, uint8_t **dst,
                                size_t *dst_size)
{
    (void)ctx;
    if (!dst || !dst_size) return TDB_ERR_INVALID_ARGS;

    uint8_t *out = malloc(src_size ? src_size : 1);
    if (!out) return TDB_ERR_MEMORY;
    if (src_size && src) memcpy(out, src, src_size);

    *dst = out;
    *dst_size = src_size;
    return TDB_SUCCESS;
}

/* shared body for the compression built-ins; compress_data returns NULL on any failure, which
 * surfaces here as an io error since a failed encode is a write-side problem the caller cannot
 * recover from */
static int encoding_compress(tidesdb_compression_algorithm_t algo, const uint8_t *src,
                             size_t src_size, uint8_t **dst, size_t *dst_size)
{
    if (!dst || !dst_size) return TDB_ERR_INVALID_ARGS;

    size_t out_size = 0;
    uint8_t *out = compress_data(src, src_size, &out_size, algo);
    if (!out)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "encode failed, algorithm %d, %zu bytes in", (int)algo,
                      src_size);
        return TDB_ERR_IO;
    }

    *dst = out;
    *dst_size = out_size;
    return TDB_SUCCESS;
}

/* shared body for the decompression built-ins; a NULL from decompress_data means the stored bytes
 * did not decode, which on the read path is corruption rather than a transient io fault */
static int encoding_decompress(tidesdb_compression_algorithm_t algo, const uint8_t *src,
                               size_t src_size, uint8_t **dst, size_t *dst_size)
{
    if (!dst || !dst_size) return TDB_ERR_INVALID_ARGS;

    size_t out_size = 0;
    uint8_t *out = decompress_data(src, src_size, &out_size, algo);
    if (!out)
    {
        /* the usual cause is bytes that were never written by this algorithm, so the algorithm the
         * chain reached for is the fact worth carrying out of here */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "decode failed, algorithm %d, %zu bytes stored", (int)algo,
                      src_size);
        return TDB_ERR_CORRUPTION;
    }

    *dst = out;
    *dst_size = out_size;
    return TDB_SUCCESS;
}

static int encoding_encode_snappy(void *ctx, const uint8_t *src, size_t n, uint8_t **dst,
                                  size_t *dn)
{
    (void)ctx;
    return encoding_compress(TDB_COMPRESS_SNAPPY, src, n, dst, dn);
}

static int encoding_decode_snappy(void *ctx, const uint8_t *src, size_t n, uint8_t **dst,
                                  size_t *dn)
{
    (void)ctx;
    return encoding_decompress(TDB_COMPRESS_SNAPPY, src, n, dst, dn);
}

static int encoding_encode_lz4(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    return encoding_compress(TDB_COMPRESS_LZ4, src, n, dst, dn);
}

static int encoding_decode_lz4(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    return encoding_decompress(TDB_COMPRESS_LZ4, src, n, dst, dn);
}

static int encoding_encode_lz4_fast(void *ctx, const uint8_t *src, size_t n, uint8_t **dst,
                                    size_t *dn)
{
    (void)ctx;
    return encoding_compress(TDB_COMPRESS_LZ4_FAST, src, n, dst, dn);
}

static int encoding_decode_lz4_fast(void *ctx, const uint8_t *src, size_t n, uint8_t **dst,
                                    size_t *dn)
{
    (void)ctx;
    /* lz4_fast produces standard lz4 frames, so it decodes through the lz4 backend */
    return encoding_decompress(TDB_COMPRESS_LZ4, src, n, dst, dn);
}

static int encoding_encode_zstd(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    return encoding_compress(TDB_COMPRESS_ZSTD, src, n, dst, dn);
}

static int encoding_decode_zstd(void *ctx, const uint8_t *src, size_t n, uint8_t **dst, size_t *dn)
{
    (void)ctx;
    return encoding_decompress(TDB_COMPRESS_ZSTD, src, n, dst, dn);
}

const tidesdb_encoding_t *tidesdb_encoding_find_by_name(const tidesdb_encoding_registry_t *reg,
                                                        const char *name)
{
    if (!reg || !name) return NULL;
    for (int i = 0; i < reg->count; i++)
    {
        if (strcmp(reg->entries[i].name, name) == 0) return &reg->entries[i];
    }
    return NULL;
}

const tidesdb_encoding_t *tidesdb_encoding_find_by_id(const tidesdb_encoding_registry_t *reg,
                                                      uint8_t id)
{
    if (!reg) return NULL;
    for (int i = 0; i < reg->count; i++)
    {
        if (reg->entries[i].id == id) return &reg->entries[i];
    }
    return NULL;
}

int tidesdb_encoding_register(tidesdb_encoding_registry_t *reg, const char *name, uint8_t id,
                              tidesdb_encode_fn encode, tidesdb_decode_fn decode, void *ctx)
{
    if (!reg || !name || !encode || !decode) return TDB_ERR_INVALID_ARGS;

    const size_t len = strlen(name);
    if (len == 0 || len >= TDB_ENCODING_NAME_MAX) return TDB_ERR_INVALID_ARGS;
    if (reg->count >= TDB_ENCODING_REGISTRY_MAX) return TDB_ERR_MEMORY_LIMIT;
    if (tidesdb_encoding_find_by_name(reg, name) || tidesdb_encoding_find_by_id(reg, id))
        return TDB_ERR_EXISTS;

    tidesdb_encoding_t *e = &reg->entries[reg->count];
    memset(e, 0, sizeof(*e));
    memcpy(e->name, name, len);
    e->id = id;
    e->encode = encode;
    e->decode = decode;
    e->ctx = ctx;
    reg->count++;
    return TDB_SUCCESS;
}

int tidesdb_encoding_registry_init(tidesdb_encoding_registry_t *reg)
{
    if (!reg) return TDB_ERR_INVALID_ARGS;
    memset(reg, 0, sizeof(*reg));

    /* "none" is always present; verbatim storage needs no backend */
    int rc = tidesdb_encoding_register(reg, TDB_ENCODING_NAME_NONE, TDB_COMPRESS_NONE,
                                       encoding_passthrough, encoding_passthrough, NULL);
    if (rc != TDB_SUCCESS) return rc;

    if (tidesdb_compression_available(TDB_COMPRESS_SNAPPY))
    {
        rc = tidesdb_encoding_register(reg, TDB_ENCODING_NAME_SNAPPY, TDB_COMPRESS_SNAPPY,
                                       encoding_encode_snappy, encoding_decode_snappy, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }
    if (tidesdb_compression_available(TDB_COMPRESS_LZ4))
    {
        rc = tidesdb_encoding_register(reg, TDB_ENCODING_NAME_LZ4, TDB_COMPRESS_LZ4,
                                       encoding_encode_lz4, encoding_decode_lz4, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }
    if (tidesdb_compression_available(TDB_COMPRESS_LZ4_FAST))
    {
        rc = tidesdb_encoding_register(reg, TDB_ENCODING_NAME_LZ4_FAST, TDB_COMPRESS_LZ4_FAST,
                                       encoding_encode_lz4_fast, encoding_decode_lz4_fast, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }
    if (tidesdb_compression_available(TDB_COMPRESS_ZSTD))
    {
        rc = tidesdb_encoding_register(reg, TDB_ENCODING_NAME_ZSTD, TDB_COMPRESS_ZSTD,
                                       encoding_encode_zstd, encoding_decode_zstd, NULL);
        if (rc != TDB_SUCCESS) return rc;
    }
    return TDB_SUCCESS;
}

int tidesdb_encoding_resolve(const tidesdb_encoding_registry_t *reg, const uint8_t *ids,
                             const int count, tidesdb_encoding_stage_t *out, const int max)
{
    if (!reg || count < 0 || (count > 0 && (!ids || !out)) || count > max) return -1;
    for (int i = 0; i < count; i++)
    {
        const tidesdb_encoding_t *e = tidesdb_encoding_find_by_id(reg, ids[i]);
        if (!e)
        {
            /* an id the registry does not carry means this build cannot read what wrote the bytes
             */
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "unknown encoding id %u at stage %d of %d", ids[i], i,
                          count);
            return -1;
        }
        out[i].encode = e->encode;
        out[i].decode = e->decode;
        out[i].ctx = e->ctx;
    }
    return count;
}

/* run a resolved chain of transforms over src, freeing each intermediate as the next consumes it;
 * the first stage reads the borrowed src and every later stage reads the previous owned buffer, so
 * exactly one owned buffer survives to become the caller's output. shared by encode and decode,
 * which differ only in walk direction and which half of each stage they pull. nothing is looked up
 * here -- the stages were resolved before whatever loop is calling this. */
static int encoding_run_stages(const tidesdb_encoding_stage_t *stages, int count, int forward,
                               const uint8_t *src, size_t src_size, uint8_t **dst, size_t *dst_size)
{
    if (!dst || !dst_size) return TDB_ERR_INVALID_ARGS;
    if (count < 0 || (count > 0 && !stages)) return TDB_ERR_INVALID_ARGS;
    if (count == 0) return encoding_passthrough(NULL, src, src_size, dst, dst_size);

    uint8_t *owned = NULL; /* the current owned buffer, NULL until the first stage produces one */
    const uint8_t *in = src;
    size_t in_size = src_size;

    for (int step = 0; step < count; step++)
    {
        const tidesdb_encoding_stage_t *stage = &stages[forward ? step : (count - 1 - step)];
        const tidesdb_encode_fn fn = forward ? stage->encode : stage->decode;
        uint8_t *out = NULL;
        size_t out_size = 0;
        const int rc = fn(stage->ctx, in, in_size, &out, &out_size);
        if (rc != TDB_SUCCESS)
        {
            /* naming the step locates the break inside a stacked chain, where only one of the
             * transforms disagrees with the bytes and the rest are innocent */
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "%s stage %d of %d failed rc %d on %zu bytes",
                          forward ? "encode" : "decode", step, count, rc, in_size);
            free(owned);
            return rc;
        }
        free(owned);
        owned = out;
        in = owned;
        in_size = out_size;
    }

    *dst = owned;
    *dst_size = in_size;
    return TDB_SUCCESS;
}

int tidesdb_encoding_stages_encode(const tidesdb_encoding_stage_t *stages, const int count,
                                   const uint8_t *src, const size_t src_size, uint8_t **dst,
                                   size_t *dst_size)
{
    return encoding_run_stages(stages, count, 1, src, src_size, dst, dst_size);
}

int tidesdb_encoding_stages_decode(const tidesdb_encoding_stage_t *stages, const int count,
                                   const uint8_t *src, const size_t src_size, uint8_t **dst,
                                   size_t *dst_size)
{
    return encoding_run_stages(stages, count, 0, src, src_size, dst, dst_size);
}

/* resolve the pipeline and run it; the by-id entry points exist for callers that hold ids rather
 * than resolved stages, and pay one registry walk per call to get there */
static int encoding_run(const tidesdb_encoding_registry_t *reg, const uint8_t *ids, int count,
                        int forward, const uint8_t *src, size_t src_size, uint8_t **dst,
                        size_t *dst_size, int unresolved_err)
{
    if (!reg || !dst || !dst_size) return TDB_ERR_INVALID_ARGS;
    if (count < 0 || count > TDB_ENCODING_PIPELINE_MAX) return TDB_ERR_INVALID_ARGS;
    if (count > 0 && !ids) return TDB_ERR_INVALID_ARGS;

    tidesdb_encoding_stage_t stages[TDB_ENCODING_PIPELINE_MAX];
    if (tidesdb_encoding_resolve(reg, ids, count, stages, TDB_ENCODING_PIPELINE_MAX) < 0)
        return unresolved_err;

    return encoding_run_stages(stages, count, forward, src, src_size, dst, dst_size);
}

int tidesdb_encoding_pipeline_encode(const tidesdb_encoding_registry_t *reg, const uint8_t *ids,
                                     int count, const uint8_t *src, size_t src_size, uint8_t **dst,
                                     size_t *dst_size)
{
    /* an unresolved id on encode is a config error -- the family named an encoding it never
     * registered */
    return encoding_run(reg, ids, count, 1, src, src_size, dst, dst_size, TDB_ERR_INVALID_ARGS);
}

int tidesdb_encoding_pipeline_decode(const tidesdb_encoding_registry_t *reg, const uint8_t *ids,
                                     int count, const uint8_t *src, size_t src_size, uint8_t **dst,
                                     size_t *dst_size)
{
    /* an unresolved id on decode means the stored bytes need an encoding this build lacks, which is
     * unreadable data rather than a bad argument, so it is reported as corruption */
    return encoding_run(reg, ids, count, 0, src, src_size, dst, dst_size, TDB_ERR_CORRUPTION);
}
