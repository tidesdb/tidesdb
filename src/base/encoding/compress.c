/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/encoding/compress.h"

/* third-party backend headers, included only when the backend is compiled in. the TIDESDB_HAVE_*
 * macros are PRIVATE compile definitions set by CMake from the -DTIDESDB_WITH_* options, so a build
 * can drop any subset (or all) of them and still produce a working library that supports the
 * remaining algorithms plus TDB_COMPRESS_NONE. */
#ifdef TIDESDB_HAVE_LZ4
#include <lz4.h>
#endif
#ifdef TIDESDB_HAVE_SNAPPY
#include <snappy-c.h>
#endif
#ifdef TIDESDB_HAVE_ZSTD
#include <zstd.h>
#endif

/* the compression_algorithm enum values are an on-disk + ABI contract, they are written into
 * sstable/vlog metadata, so they must never change, and the duplicate enum in db.h (the
 * standalone FFI header, which cannot include this header) must hold identical values. pin them
 * at compile time so any drift in compress.h fails the build; db.h carries the matching contract
 * comment. the asserts are unconditional -- the enumerators exist regardless of which backends are
 * compiled in. guarded on C11 so older/non-conforming C front-ends still compile. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(TDB_COMPRESS_NONE == 0, "compression_algorithm wire drift: NONE must be 0");
_Static_assert(TDB_COMPRESS_SNAPPY == 1, "compression_algorithm wire drift: SNAPPY must be 1");
_Static_assert(TDB_COMPRESS_LZ4 == 2, "compression_algorithm wire drift: LZ4 must be 2");
_Static_assert(TDB_COMPRESS_ZSTD == 3, "compression_algorithm wire drift: ZSTD must be 3");
_Static_assert(TDB_COMPRESS_LZ4_FAST == 4, "compression_algorithm wire drift: LZ4_FAST must be 4");
#endif

/* maximum plausible decompression expansion per backend. a valid compressed block cannot expand
 * beyond these ratios of its compressed bytes, so a size prefix claiming more is corrupt and is
 * rejected before the output buffer is allocated. LZ4's block format tops out near 255x (a long run
 * encoded as one extended match) and snappy's copy operations near 64/3, so 64 leaves ample margin.
 * these are over-estimates of the true maxima, so they reject impossible sizes without ever
 * rejecting a valid stream. zstd's RLE mode can expand arbitrarily, so it keeps the UINT32_MAX cap
 * rather than a ratio bound. */
#define COMPRESS_LZ4_MAX_EXPANSION    255
#define COMPRESS_SNAPPY_MAX_EXPANSION 64

/* LZ4 acceleration factors. 1 is the library's default, and the fast variant steps one level up,
 * trading compression ratio for throughput */
#define COMPRESS_LZ4_ACCEL_DEFAULT 1
#define COMPRESS_LZ4_ACCEL_FAST    2

/* zstd compression level, the fastest setting -- this sits under an lsm write path where throughput
 * matters more than the last few percent of ratio */
#define COMPRESS_ZSTD_LEVEL 1

/* passed where a backend has no derivable expansion ratio, leaving the UINT32_MAX cap as the only
 * plausibility bound on a decoded size prefix */
#define COMPRESS_NO_EXPANSION_BOUND 0

int tidesdb_compression_available(const tidesdb_compression_algorithm_t type)
{
    switch (type)
    {
        case TDB_COMPRESS_NONE:
            return 1;
#ifdef TIDESDB_HAVE_SNAPPY
        case TDB_COMPRESS_SNAPPY:
            return 1;
#endif
#ifdef TIDESDB_HAVE_LZ4
        case TDB_COMPRESS_LZ4:
        case TDB_COMPRESS_LZ4_FAST:
            return 1;
#endif
#ifdef TIDESDB_HAVE_ZSTD
        case TDB_COMPRESS_ZSTD:
            return 1;
#endif
        default:
            return 0;
    }
}

/* ===== per-backend compression, one helper each so the entry point stays a dispatch ===== */

#ifdef TIDESDB_HAVE_SNAPPY
static uint8_t *compress_snappy(const uint8_t *data, const size_t data_size,
                                size_t *compressed_size)
{
    *compressed_size = snappy_max_compressed_length(data_size);
    uint8_t *out = malloc(*compressed_size + sizeof(uint64_t));
    if (TDB_UNLIKELY(!out)) return NULL;

    encode_uint64_le_compat(out, data_size);

    size_t actual_size = *compressed_size;
    if (TDB_UNLIKELY(snappy_compress((const char *)data, data_size,
                                     (char *)(out + sizeof(uint64_t)), &actual_size) != SNAPPY_OK))
    {
        free(out);
        return NULL;
    }

    *compressed_size = actual_size + sizeof(uint64_t);
    return out;
}
#endif

#ifdef TIDESDB_HAVE_LZ4
static uint8_t *compress_lz4(const uint8_t *data, const size_t data_size, size_t *compressed_size,
                             const tidesdb_compression_algorithm_t type)
{
    /* LZ4's API takes int lengths. reject an input past LZ4_MAX_INPUT_SIZE before the cast so a
     * value larger than INT_MAX cannot wrap to a negative length -- LZ4_compressBound would then
     * return 0 and the compress call run with a bogus size. the decompress side already bounds the
     * prefix, this closes the matching gap on the compress side. */
    if (TDB_UNLIKELY(data_size > LZ4_MAX_INPUT_SIZE)) return NULL;

    *compressed_size = (size_t)LZ4_compressBound((int)data_size);
    uint8_t *out = malloc(*compressed_size + sizeof(uint64_t));
    if (TDB_UNLIKELY(!out)) return NULL;

    encode_uint64_le_compat(out, data_size);

    /* both LZ4 variants share this path and differ only in acceleration */
    const int acceleration =
        (type == TDB_COMPRESS_LZ4_FAST) ? COMPRESS_LZ4_ACCEL_FAST : COMPRESS_LZ4_ACCEL_DEFAULT;
    const int lz4_result = LZ4_compress_fast((const char *)data, (char *)(out + sizeof(uint64_t)),
                                             (int)data_size, (int)*compressed_size, acceleration);
    if (TDB_UNLIKELY(lz4_result <= 0))
    {
        free(out);
        return NULL;
    }

    *compressed_size = (size_t)lz4_result + sizeof(uint64_t);
    return out;
}
#endif

#ifdef TIDESDB_HAVE_ZSTD
static uint8_t *compress_zstd(const uint8_t *data, const size_t data_size, size_t *compressed_size)
{
    *compressed_size = ZSTD_compressBound(data_size);
    uint8_t *out = malloc(*compressed_size + sizeof(uint64_t));
    if (TDB_UNLIKELY(!out)) return NULL;

    encode_uint64_le_compat(out, data_size);

    const size_t actual_size = ZSTD_compress(out + sizeof(uint64_t), *compressed_size, data,
                                             data_size, COMPRESS_ZSTD_LEVEL);
    if (TDB_UNLIKELY(ZSTD_isError(actual_size)))
    {
        free(out);
        return NULL;
    }

    *compressed_size = actual_size + sizeof(uint64_t);
    return out;
}
#endif

uint8_t *compress_data(const uint8_t *data, const size_t data_size, size_t *compressed_size,
                       const tidesdb_compression_algorithm_t type)
{
    /* every backend writes *compressed_size, so a NULL out-param is a caller error rather than
     * something to dereference blindly */
    if (TDB_UNLIKELY(!data || !compressed_size)) return NULL;

    uint8_t *compressed_data = NULL;
    switch (type)
    {
#ifdef TIDESDB_HAVE_SNAPPY
        case TDB_COMPRESS_SNAPPY:
            compressed_data = compress_snappy(data, data_size, compressed_size);
            break;
#endif
#ifdef TIDESDB_HAVE_LZ4
        case TDB_COMPRESS_LZ4:
        case TDB_COMPRESS_LZ4_FAST:
            compressed_data = compress_lz4(data, data_size, compressed_size, type);
            break;
#endif
#ifdef TIDESDB_HAVE_ZSTD
        case TDB_COMPRESS_ZSTD:
            compressed_data = compress_zstd(data, data_size, compressed_size);
            break;
#endif
        default:
            return NULL;
    }
    if (TDB_UNLIKELY(!compressed_data)) return NULL;

    /* shrink to the bytes actually produced, since the bound each backend sized from is generous.
     * a failed shrink is harmless -- the oversized buffer is still correct -- so the original is
     * only reassigned on success, never read after realloc took it */
    uint8_t *shrunk = realloc(compressed_data, *compressed_size);
    if (TDB_LIKELY(shrunk != NULL)) compressed_data = shrunk;
    return compressed_data;
}

/* ===== per-backend decompression ===== */

/* the front half every backend shares -- validate the size prefix the block was written with and
 * allocate the output from it. max_expansion bounds how far a valid block of these compressed bytes
 * could legitimately expand, so an implausible claim is refused before the allocation; pass
 * COMPRESS_NO_EXPANSION_BOUND where no ratio applies and only the UINT32_MAX cap holds. */
static uint8_t *decompress_alloc_from_prefix(const uint8_t *data, const size_t data_size,
                                             const uint64_t max_expansion, size_t *out_size)
{
    if (TDB_UNLIKELY(data_size < sizeof(uint64_t))) return NULL;

    const uint64_t original_size = decode_uint64_le_compat(data);
    if (TDB_UNLIKELY(original_size > UINT32_MAX)) return NULL;
    if (max_expansion != COMPRESS_NO_EXPANSION_BOUND &&
        TDB_UNLIKELY(original_size > (uint64_t)(data_size - sizeof(uint64_t)) * max_expansion))
        return NULL;

    *out_size = (size_t)original_size;
    return malloc(*out_size);
}

#ifdef TIDESDB_HAVE_SNAPPY
static uint8_t *decompress_snappy(const uint8_t *data, const size_t data_size, size_t *out_size)
{
    uint8_t *out =
        decompress_alloc_from_prefix(data, data_size, COMPRESS_SNAPPY_MAX_EXPANSION, out_size);
    if (TDB_UNLIKELY(!out)) return NULL;

    const size_t claimed = *out_size;
    if (TDB_UNLIKELY(snappy_uncompress((const char *)(data + sizeof(uint64_t)),
                                       data_size - sizeof(uint64_t), (char *)out,
                                       out_size) != SNAPPY_OK))
    {
        free(out);
        return NULL;
    }

    /* snappy can succeed with a shorter output that still fits the buffer, so hold it to the size
     * prefix the way the LZ4 and ZSTD backends are held to theirs */
    if (TDB_UNLIKELY(*out_size != claimed))
    {
        free(out);
        return NULL;
    }
    return out;
}
#endif

#ifdef TIDESDB_HAVE_LZ4
static uint8_t *decompress_lz4(const uint8_t *data, const size_t data_size, size_t *out_size)
{
    uint8_t *out =
        decompress_alloc_from_prefix(data, data_size, COMPRESS_LZ4_MAX_EXPANSION, out_size);
    if (TDB_UNLIKELY(!out)) return NULL;

    const int lz4_result = LZ4_decompress_safe((const char *)(data + sizeof(uint64_t)), (char *)out,
                                               (int)(data_size - sizeof(uint64_t)), (int)*out_size);
    if (TDB_UNLIKELY(lz4_result < 0 || lz4_result != (int)*out_size))
    {
        free(out);
        return NULL;
    }
    return out;
}
#endif

#ifdef TIDESDB_HAVE_ZSTD
static uint8_t *decompress_zstd(const uint8_t *data, const size_t data_size, size_t *out_size)
{
    /* zstd's RLE mode can expand arbitrarily, so no ratio bound applies here -- the UINT32_MAX cap
     * is the plausibility bound, and upstream frame checksums are what actually protect this
     * prefix from corruption */
    uint8_t *out =
        decompress_alloc_from_prefix(data, data_size, COMPRESS_NO_EXPANSION_BOUND, out_size);
    if (TDB_UNLIKELY(!out)) return NULL;

    const size_t zstd_result =
        ZSTD_decompress(out, *out_size, data + sizeof(uint64_t), data_size - sizeof(uint64_t));
    if (TDB_UNLIKELY(ZSTD_isError(zstd_result) || zstd_result != *out_size))
    {
        free(out);
        return NULL;
    }
    return out;
}
#endif

uint8_t *decompress_data(const uint8_t *data, const size_t data_size, size_t *decompressed_size,
                         const tidesdb_compression_algorithm_t type)
{
    /* every backend writes *decompressed_size, so a NULL out-param is a caller error */
    if (TDB_UNLIKELY(!data || !decompressed_size)) return NULL;

    switch (type)
    {
#ifdef TIDESDB_HAVE_SNAPPY
        case TDB_COMPRESS_SNAPPY:
            return decompress_snappy(data, data_size, decompressed_size);
#endif
#ifdef TIDESDB_HAVE_LZ4
        case TDB_COMPRESS_LZ4:
        case TDB_COMPRESS_LZ4_FAST:
            return decompress_lz4(data, data_size, decompressed_size);
#endif
#ifdef TIDESDB_HAVE_ZSTD
        case TDB_COMPRESS_ZSTD:
            return decompress_zstd(data, data_size, decompressed_size);
#endif
        default:
            return NULL;
    }
}
