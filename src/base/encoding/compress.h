/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __COMPRESS_H__
#define __COMPRESS_H__

#include "compat.h"
#include "db.h" /* the public compression enum and tidesdb_compression_available */

/* snappy, lz4 and zstd are the supported compression backends. each is optional at build time --
 * the -DTIDESDB_WITH_{SNAPPY,LZ4,ZSTD} CMake options (default ON) select which are compiled in, and
 * a build with all three off has no compression dependencies at all (TDB_COMPRESS_NONE only). the
 * third-party headers are included only in compress.c, guarded by the TIDESDB_HAVE_* build macros,
 * so a consumer of the installed library does not need the compression dev headers just to include
 * this file.
 * ABI/on-disk contract -- these numeric values are persisted in sstable/vlog metadata and are
 * duplicated in db.h (the standalone FFI header). the two copies must stay identical; compress.c
 * pins them with _Static_assert to catch drift at build time. every enumerator is defined
 * regardless of which backends are compiled in, so an sstable's algorithm id is always
 * recognizable -- an unavailable backend yields a clean runtime error, not an unknown algorithm. */
#ifndef TDB_COMPRESSION_ALGORITHM_DEFINED
#define TDB_COMPRESSION_ALGORITHM_DEFINED
typedef enum
{
    TDB_COMPRESS_NONE = 0,
    TDB_COMPRESS_SNAPPY = 1,
    TDB_COMPRESS_LZ4 = 2,
    TDB_COMPRESS_ZSTD = 3,
    TDB_COMPRESS_LZ4_FAST = 4
} tidesdb_compression_algorithm_t;
#endif

/**
 * compress_data
 * compresses data using the specified compression algorithm. type must be a real codec, not
 * TDB_COMPRESS_NONE -- NONE means "store the bytes verbatim" and is the caller's job, so it is not
 * a valid argument here and returns NULL like any other unsupported type. a type whose backend was
 * not compiled into this build likewise returns NULL; a NULL return is always a failure, never a
 * "no compression" signal.
 * @param data the data to compress
 * @param data_size the size of the data
 * @param compressed_size out-param for the compressed size; must not be NULL
 * @param type the compression algorithm to use (must not be TDB_COMPRESS_NONE)
 * @return newly allocated compressed data (caller frees), or NULL on failure (bad args,
 *         allocation failure, unsupported/uncompiled type, or a codec error)
 */
uint8_t *compress_data(const uint8_t *data, size_t data_size, size_t *compressed_size,
                       tidesdb_compression_algorithm_t type);

/**
 * decompress_data
 * decompresses data using the specified compression algorithm. as with compress_data, type must be
 * a real codec, not TDB_COMPRESS_NONE -- the caller reads verbatim bytes itself and only calls this
 * for data it actually compressed. the type must match the one the data was compressed with.
 * @param data the data to decompress
 * @param data_size the size of the data
 * @param decompressed_size out-param for the decompressed size; must not be NULL
 * @param type the compression algorithm to use (must not be TDB_COMPRESS_NONE)
 * @return newly allocated decompressed data (caller frees), or NULL on failure (bad args,
 *         allocation failure, or a codec/corruption error)
 */
uint8_t *decompress_data(const uint8_t *data, size_t data_size, size_t *decompressed_size,
                         tidesdb_compression_algorithm_t type);

/* tidesdb_compression_available is part of the public surface and is declared in db.h, which this
 * header includes above -- a caller rejects an unsupported algorithm up front rather than failing
 * at compress or flush time. declaring it here as well is a redundant declaration the build treats
 * as a warning */

#endif /* __COMPRESS_H__ */
