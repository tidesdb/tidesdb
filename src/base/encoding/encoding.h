/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_ENCODING_H__
#define __TIDESDB_BASE_ENCODING_H__

#include "compat.h" /* fixed-width ints, size_t, allocation */

/* an encoding is a named reversible byte transform; compression and user-supplied encryption are
 * both just encodings. a column family names an ordered pipeline of them, applied left-to-right on
 * write and inverted right-to-left on read, so compress-then-encrypt is expressed rather than
 * hard-coded. the registry maps names and on-disk ids to their transform pair; the engine stays
 * key-agnostic, so no encryption ships built in -- the built-in encodings are the compression
 * algorithms only, and a user registers their own (with any key held in the encoding's ctx) before
 * opening a family that names it. an id that cannot be resolved on read is a hard error, never
 * silent corruption. */

/* longest encoding name including the terminator */
#define TDB_ENCODING_NAME_MAX 64

/* longest pipeline a single family or sstable may stack; compress plus an encryption layer needs
 * two, the rest is headroom, and the small bound keeps the on-disk footer and the codec loop fixed
 */
#define TDB_ENCODING_PIPELINE_MAX 8

/* registry capacity -- the handful of built-in compression encodings plus room for user encodings
 */
#define TDB_ENCODING_REGISTRY_MAX 32

/* ids below this are reserved for built-in encodings (the compression algorithm ids); a user
 * encoding must claim an id at or above it so it can never shadow or be shadowed by a built-in */
#define TDB_ENCODING_ID_USER_MIN 16

/* built-in encoding names -- the compression algorithms registered at init, kept as named constants
 * so family config and the built-in table agree on the spelling */
#define TDB_ENCODING_NAME_NONE     "none"
#define TDB_ENCODING_NAME_SNAPPY   "snappy"
#define TDB_ENCODING_NAME_LZ4      "lz4"
#define TDB_ENCODING_NAME_LZ4_FAST "lz4_fast"
#define TDB_ENCODING_NAME_ZSTD     "zstd"

/**
 * tidesdb_encode_fn
 * transform src into a freshly allocated dst that the caller frees; decode is its exact inverse
 * @param ctx opaque context the encoding needs (a compression level, an encryption key), or NULL
 * @param src input bytes, borrowed for the call
 * @param src_size length of src in bytes
 * @param dst out -- newly allocated output on success, owned by the caller
 * @param dst_size out -- length of the output in bytes
 * @return TDB_SUCCESS, or a TDB_ERR_* code on failure with *dst left untouched
 */
typedef int (*tidesdb_encode_fn)(void *ctx, const uint8_t *src, size_t src_size, uint8_t **dst,
                                 size_t *dst_size);

/**
 * tidesdb_decode_fn
 * the exact inverse of a tidesdb_encode_fn -- see tidesdb_encode_fn for the parameter contract
 */
typedef tidesdb_encode_fn tidesdb_decode_fn;

/**
 * tidesdb_encoding_t
 * one entry in the encoding registry
 * @param name unique name identifying the encoding, NUL-terminated
 * @param id stable on-disk id, persisted in the sstable footer; built-ins are below
 *           TDB_ENCODING_ID_USER_MIN, user encodings at or above it
 * @param encode the forward transform
 * @param decode the inverse transform
 * @param ctx runtime context passed to both transforms, not owned by the registry (NULL if unused)
 */
typedef struct
{
    char name[TDB_ENCODING_NAME_MAX];
    uint8_t id;
    tidesdb_encode_fn encode;
    tidesdb_decode_fn decode;
    void *ctx;
} tidesdb_encoding_t;

/**
 * tidesdb_encoding_registry_t
 * a fixed-capacity table of registered encodings, embeddable in the db so no allocation happens
 * after init; entries only ever grow, so a resolved pointer stays valid for the registry's lifetime
 * @param entries the registered encodings, the first count of which are live
 * @param count number of live entries
 */
typedef struct
{
    tidesdb_encoding_t entries[TDB_ENCODING_REGISTRY_MAX];
    int count;
} tidesdb_encoding_registry_t;

/**
 * tidesdb_encoding_registry_init
 * zero the registry and register the built-in compression encodings that this build supports; a
 * backend compiled out is simply not registered, so a family naming it fails to resolve up front
 * @param reg the registry to initialize, caller-owned storage
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL registry
 */
int tidesdb_encoding_registry_init(tidesdb_encoding_registry_t *reg);

/**
 * tidesdb_encoding_register
 * add an encoding to the registry; the name and id must both be unused
 * @param reg the registry
 * @param name unique name, 1..TDB_ENCODING_NAME_MAX-1 bytes
 * @param id unique on-disk id
 * @param encode the forward transform, must not be NULL
 * @param decode the inverse transform, must not be NULL
 * @param ctx runtime context for both transforms, not owned by the registry (may be NULL)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument, TDB_ERR_EXISTS on a duplicate name
 * or id, or TDB_ERR_MEMORY_LIMIT when the registry is full
 */
int tidesdb_encoding_register(tidesdb_encoding_registry_t *reg, const char *name, uint8_t id,
                              tidesdb_encode_fn encode, tidesdb_decode_fn decode, void *ctx);

/**
 * tidesdb_encoding_find_by_name
 * resolve an encoding by name
 * @param reg the registry
 * @param name the name to look up
 * @return the entry, or NULL if the registry or name is NULL or no entry matches
 */
const tidesdb_encoding_t *tidesdb_encoding_find_by_name(const tidesdb_encoding_registry_t *reg,
                                                        const char *name);

/**
 * tidesdb_encoding_find_by_id
 * resolve an encoding by its on-disk id
 * @param reg the registry
 * @param id the id to look up
 * @return the entry, or NULL if the registry is NULL or no entry matches
 */
const tidesdb_encoding_t *tidesdb_encoding_find_by_id(const tidesdb_encoding_registry_t *reg,
                                                      uint8_t id);

/**
 * tidesdb_encoding_stage_t
 * one resolved stage of a pipeline -- the transform pair and context an id resolves to
 * resolving ids to these once, at setup, keeps the registry lookup off the path that runs per
 * block; the registry is a linear scan, and a btree node read cannot afford one
 * @field encode the forward transform
 * @field decode its inverse
 * @field ctx the opaque context both were registered with
 */
typedef struct
{
    tidesdb_encode_fn encode;
    tidesdb_decode_fn decode;
    void *ctx;
} tidesdb_encoding_stage_t;

/**
 * tidesdb_encoding_resolve
 * resolve a pipeline of ids into the transforms they name, in write order
 * @param reg the registry to resolve against
 * @param ids the pipeline's encoding ids
 * @param count how many ids, 0 for an empty pipeline
 * @param out receives the resolved stages, must hold count of them
 * @param max capacity of out
 * @return the number of stages resolved, or -1 when an id is not registered or out is too small
 */
int tidesdb_encoding_resolve(const tidesdb_encoding_registry_t *reg, const uint8_t *ids, int count,
                             tidesdb_encoding_stage_t *out, int max);

/**
 * tidesdb_encoding_stages_encode
 * run resolved stages forward over src, freeing each intermediate as the next consumes it
 * @param stages the resolved stages, applied in order
 * @param count how many stages, 0 copies src verbatim
 * @param src input bytes
 * @param src_size length of src
 * @param dst receives an allocated buffer the caller frees
 * @param dst_size receives its length
 * @return TDB_SUCCESS, or the failing stage's result
 */
int tidesdb_encoding_stages_encode(const tidesdb_encoding_stage_t *stages, int count,
                                   const uint8_t *src, size_t src_size, uint8_t **dst,
                                   size_t *dst_size);

/**
 * tidesdb_encoding_stages_decode
 * run resolved stages in reverse, undoing tidesdb_encoding_stages_encode
 * @param stages the resolved stages, applied last to first
 * @param count how many stages, 0 copies src verbatim
 * @param src encoded bytes
 * @param src_size length of src
 * @param dst receives an allocated buffer the caller frees
 * @param dst_size receives its length
 * @return TDB_SUCCESS, or the failing stage's result
 */
int tidesdb_encoding_stages_decode(const tidesdb_encoding_stage_t *stages, int count,
                                   const uint8_t *src, size_t src_size, uint8_t **dst,
                                   size_t *dst_size);

/**
 * tidesdb_encoding_pipeline_encode
 * run src through the pipeline ids in encode order (left-to-right), producing a freshly allocated
 * dst; a count of zero is a passthrough that returns an owned copy of src
 * @param reg the registry used to resolve each id
 * @param ids the pipeline encoding ids in encode order, or NULL when count is zero
 * @param count number of ids, 0..TDB_ENCODING_PIPELINE_MAX
 * @param src input bytes, borrowed
 * @param src_size length of src in bytes
 * @param dst out -- newly allocated output owned by the caller
 * @param dst_size out -- length of the output in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument or an id that does not resolve,
 *         TDB_ERR_MEMORY on allocation failure, or a transform's own error code
 */
int tidesdb_encoding_pipeline_encode(const tidesdb_encoding_registry_t *reg, const uint8_t *ids,
                                     int count, const uint8_t *src, size_t src_size, uint8_t **dst,
                                     size_t *dst_size);

/**
 * tidesdb_encoding_pipeline_decode
 * invert the pipeline, applying the ids' decoders in reverse (right-to-left); a count of zero is a
 * passthrough that returns an owned copy of src
 * @param reg the registry used to resolve each id
 * @param ids the same pipeline ids in encode order, or NULL when count is zero
 * @param count number of ids, 0..TDB_ENCODING_PIPELINE_MAX
 * @param src input bytes, borrowed
 * @param src_size length of src in bytes
 * @param dst out -- newly allocated output owned by the caller
 * @param dst_size out -- length of the output in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument, TDB_ERR_CORRUPTION when an id does
 * not resolve (an encoding this build does not have), TDB_ERR_MEMORY on allocation failure, or a
 *         transform's own error code
 */
int tidesdb_encoding_pipeline_decode(const tidesdb_encoding_registry_t *reg, const uint8_t *ids,
                                     int count, const uint8_t *src, size_t src_size, uint8_t **dst,
                                     size_t *dst_size);

#endif /* __TIDESDB_BASE_ENCODING_H__ */
