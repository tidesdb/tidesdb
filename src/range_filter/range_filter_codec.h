/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_FILTER_CODEC_H__
#define __RANGE_FILTER_CODEC_H__
#include "compat.h"
#include "range_filter/range_filter_bits.h"

/* the order-preserving entropy coder the range filter encodes every key and every query endpoint
 * through. common byte sequences get short
 * codes, so the bits that tell two nearby keys apart move closer to the front, where a fixed-width
 * window of each key can still see them.
 *
 * each byte is coded by a tree chosen from the bytes before it, one per pair of preceding bytes
 * (order 2), one per preceding byte (order 1), and one for every byte (order 0). a tree is built by
 * Mehlhorn's bisection over all 256 byte values in byte order, so a smaller byte always gets a
 * smaller code and no code is a prefix of another. a byte never seen when the model was built still
 * has a code, a long one, since every value carries a weight of at least one. a context too rare to
 * be worth its own tree falls back to the next lower order.
 *
 * the encoded bits of two keys therefore compare exactly as the keys do. along a shared prefix the
 * contexts agree, so the first differing byte is coded by the same tree on both sides, and that
 * tree orders its codes as it orders the bytes. a key that is a proper prefix of another encodes to
 * a proper prefix of it. nothing is ever decoded, and a range filter built over encoded keys
 * answers a query over encoded endpoints with no false negatives.
 *
 * the model is stored as each context's quantized byte weights rather than as trees. the trees are
 * derived from the weights with integer arithmetic only, so every platform derives the same codes,
 * and a merge can sum the weights of its inputs' models. */

/* the deepest context a byte's code may depend on, the two bytes before it */
#define RANGE_FILTER_CODEC_MAX_ORDER 2

/* the longest code any byte can have. a context's weights total at most 2^20 and every byte weighs
 * at least one, which bounds the bisection's depth by the doubled interval's 21 bits */
#define RANGE_FILTER_CODEC_MAX_CODE_BITS 21

/* the frequency counts gathered from keys, before they become a model */
typedef struct range_filter_codec_counts range_filter_codec_counts_t;

/* a built model, immutable, safe to encode through from any number of threads */
typedef struct range_filter_codec range_filter_codec_t;

/**
 * range_filter_codec_counts_new
 * create an empty set of counts
 * @param out out -- the counts on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int range_filter_codec_counts_new(range_filter_codec_counts_t **out);

/**
 * range_filter_codec_counts_add
 * count every byte of a key under each context it occurs in
 * @param counts the counts to add to
 * @param key the key bytes
 * @param key_size the key length
 */
void range_filter_codec_counts_add(range_filter_codec_counts_t *counts, const uint8_t *key,
                                   size_t key_size);

/**
 * range_filter_codec_counts_free
 * release a set of counts
 * @param counts the counts, or NULL
 */
void range_filter_codec_counts_free(range_filter_codec_counts_t *counts);

/**
 * range_filter_codec_build
 * build a model from counts. a context gets its own tree only when it was seen often enough and its
 * bytes stray from those of the context it would fall back to by more than chance, so random bytes
 * get no contexts at all. no more than max_contexts order-1 and order-2 contexts are kept, those
 * that stray furthest first, which bounds the model's size against the filter it serves
 * @param counts the counts to build from
 * @param max_order the deepest context to model, 0 to RANGE_FILTER_CODEC_MAX_ORDER
 * @param max_contexts the most order-1 and order-2 contexts to keep together
 * @param out out -- the model on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int range_filter_codec_build(const range_filter_codec_counts_t *counts, int max_order,
                             int max_contexts, range_filter_codec_t **out);

/**
 * range_filter_codec_encode
 * append the encoding of a key to a bit string
 * @param codec the model
 * @param key the key bytes, which may hold any byte value, seen at build time or not
 * @param key_size the key length
 * @param out the string to append to
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int range_filter_codec_encode(const range_filter_codec_t *codec, const uint8_t *key,
                              size_t key_size, range_filter_bits_t *out);

/**
 * range_filter_codec_order
 * the deepest context the model actually holds a tree for
 * @param codec the model
 * @return 0, 1 or 2
 */
int range_filter_codec_order(const range_filter_codec_t *codec);

/**
 * range_filter_codec_context_count
 * how many order-1 and order-2 trees the model holds besides its order-0 tree
 * @param codec the model
 * @return the count
 */
int range_filter_codec_context_count(const range_filter_codec_t *codec);

/**
 * range_filter_codec_serialize
 * write the model as its weights, in a form range_filter_codec_deserialize reads back exactly
 * @param codec the model, one built here, since a loaded model keeps only its code tables
 * @param out out -- a heap buffer the caller frees, NULL on failure
 * @param out_size out -- the buffer's length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS for a loaded model, or TDB_ERR_MEMORY
 */
int range_filter_codec_serialize(const range_filter_codec_t *codec, uint8_t **out,
                                 size_t *out_size);

/**
 * range_filter_codec_deserialize
 * read a model back, validating every field, and rebuild its trees from the weights, keeping only
 * the code tables encoding needs
 * @param data the serialized model
 * @param size its length
 * @param out out -- the model on success, NULL on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_CORRUPTION or TDB_ERR_MEMORY
 */
int range_filter_codec_deserialize(const uint8_t *data, size_t size, range_filter_codec_t **out);

/**
 * range_filter_codec_resident_bytes
 * the memory a model holds, its code tables and any weights it kept
 * @param codec the model, or NULL
 * @return the bytes, 0 for NULL
 */
size_t range_filter_codec_resident_bytes(const range_filter_codec_t *codec);

/**
 * range_filter_codec_context_bytes
 * the memory one context's tree takes in a loaded model
 * @return the bytes
 */
size_t range_filter_codec_context_bytes(void);

/**
 * range_filter_codec_free
 * release a model
 * @param codec the model, or NULL
 */
void range_filter_codec_free(range_filter_codec_t *codec);

#endif /* __RANGE_FILTER_CODEC_H__ */
