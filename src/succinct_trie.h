/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SUCCINCT_TRIE_H__
#define __SUCCINCT_TRIE_H__

#include <stddef.h>
#include <stdint.h>

#include "block_manager.h"
#include "compat.h"

/*
 * succinct_trie_comparator_fn
 * comparator function type for custom key comparison
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @param ctx optional context pointer for the comparator
 * @return 0 if keys are equal, negative if key1 < key2, positive if key1 > key2
 */
typedef int (*succinct_trie_comparator_fn)(const uint8_t *key1, size_t key1_size,
                                           const uint8_t *key2, size_t key2_size, void *ctx);

/*
 * succinct_trie_entry_t
 * temporary entry during construction
 * @param key the key
 * @param key_len the key length
 * @param value the value associated with the key
 */
typedef struct
{
    const uint8_t *key;
    size_t key_len;
    int64_t value;
} succinct_trie_entry_t;

/*
 * succinct_trie_t
 * succinct trie using LOUDS encoding
 * 2 bits per node + labels + values
 * @param louds LOUDS bitvector
 * @param louds_bits number of bits in LOUDS bitvector
 * @param labels edge labels
 * @param edge_child edge index -> child node ID mapping
 * @param n_edges number of edges
 * @param term terminal nodes bitvector
 * @param n_nodes number of nodes
 * @param vals values array
 * @param n_vals number of values
 * @param comparator custom comparator function (NULL for default memcmp)
 * @param comparator_ctx context pointer passed to comparator
 */
typedef struct
{
    uint8_t *louds;
    uint32_t louds_bits;
    uint8_t *labels;
    uint32_t *edge_child;
    uint32_t n_edges;
    uint8_t *term;
    uint32_t n_nodes;
    int64_t *vals;
    uint32_t n_vals;
    succinct_trie_comparator_fn comparator;
    void *comparator_ctx;
} succinct_trie_t;

/*
 * succinct_trie_builder_t
 * disk-based streaming builder
 * O(max_key_length) during construction
 * O(1) after construction
 * @param labels_bm block manager for edge labels
 * @param parents_bm block manager for parent node IDs
 * @param child_ids_bm block manager for child node IDs
 * @param term_bm block manager for terminal flags
 * @param vals_bm block manager for values
 * @param prev_key previous key for LCP
 * @param prev_key_len length of previous key
 * @param prev_key_capacity capacity of previous key
 * @param path_stack node IDs at each depth
 * @param path_capacity capacity of path stack
 * @param next_node_id next node ID to assign
 * @param n_nodes total nodes created
 * @param n_edges total edges created
 * @param n_vals total values created
 * @param comparator custom comparator function (NULL for default memcmp)
 * @param comparator_ctx context pointer passed to comparator
 */
typedef struct
{
    void *labels_bm;
    void *parents_bm;
    void *child_ids_bm;
    void *term_bm;
    void *vals_bm;
    uint8_t *prev_key;
    size_t prev_key_len;
    size_t prev_key_capacity;
    uint32_t *path_stack;
    size_t path_capacity;
    uint32_t next_node_id;
    uint32_t n_nodes;
    uint32_t n_edges;
    uint32_t n_vals;
    succinct_trie_comparator_fn comparator;
    void *comparator_ctx;
} succinct_trie_builder_t;

/*
 * succinct_trie_comparator_memcmp
 * default memcmp-based comparator for byte comparison
 * @param key1 the first key
 * @param key1_size the first key size
 * @param key2 the second key
 * @param key2_size the second key size
 * @param ctx unused context
 * @return 0 if keys are equal, negative if key1 < key2, positive if key1 > key2
 */
int succinct_trie_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                    size_t key2_size, void *ctx);

/*
 * succinct_trie_comparator_string
 * string-based comparator using strcmp
 * @param key1 the first key
 * @param key1_size the first key size (unused)
 * @param key2 the second key
 * @param key2_size the second key size (unused)
 * @param ctx unused context
 * @return 0 if keys are equal, negative if key1 < key2, positive if key1 > key2
 */
int succinct_trie_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                    size_t key2_size, void *ctx);

/*
 * succinct_trie_builder_new
 * create a new disk-based streaming trie builder
 * keys MUST be added in sorted order
 * O(max_key_length) regardless of dataset size
 * @param temp_dir directory for temporary files (NULL for "/tmp")
 * @param comparator custom comparator function (NULL for default memcmp)
 * @param comparator_ctx context pointer passed to comparator
 * @return newly allocated streaming builder or NULL on failure
 */
succinct_trie_builder_t *succinct_trie_builder_new(const char *temp_dir,
                                                   succinct_trie_comparator_fn comparator,
                                                   void *comparator_ctx);

/*
 * succinct_trie_builder_add
 * add an entry to the builder
 * @param builder the builder to add to
 * @param key pointer to key
 * @param key_len length of key
 * @param value value associated with key
 * @return 0 on success, -1 on failure
 */
int succinct_trie_builder_add(succinct_trie_builder_t *builder, const uint8_t *key, size_t key_len,
                              int64_t value);

/*
 * succinct_trie_builder_build
 * finalize the builder and create an immutable succinct trie
 * this consumes the builder and frees it
 * @param builder the builder to finalize (will be freed)
 * @return newly allocated trie or NULL on failure
 */
succinct_trie_t *succinct_trie_builder_build(succinct_trie_builder_t *builder);

/*
 * succinct_trie_builder_free
 * free a builder without building the trie
 * @param builder the builder to free
 */
void succinct_trie_builder_free(succinct_trie_builder_t *builder);

/*
 * succinct_trie_prefix_get
 * get the first value matching a prefix
 * @param trie succinct trie
 * @param prefix prefix to query
 * @param prefix_len length of prefix
 * @param value pointer to value to write
 * @return 0 on success, -1 on not found or error
 */
int succinct_trie_prefix_get(const succinct_trie_t *trie, const uint8_t *prefix, size_t prefix_len,
                             int64_t *value);

/*
 * succinct_trie_free
 * @param trie trie to free
 */
void succinct_trie_free(succinct_trie_t *trie);

/*
 * succinct_trie_serialize
 * @param trie trie to serialize
 * @param out_size pointer to store size of serialized data
 * @return newly allocated buffer containing serialized data or NULL on failure
 */
uint8_t *succinct_trie_serialize(const succinct_trie_t *trie, size_t *out_size);

/*
 * succinct_trie_deserialize
 * @param data serialized data
 * @param data_size size of serialized data
 * @return newly allocated trie or NULL on failure
 */
succinct_trie_t *succinct_trie_deserialize(const uint8_t *data, size_t data_size);

/*
 * succinct_trie_get_size
 * @param trie succinct trie
 * @return size of trie in bytes
 */
size_t succinct_trie_get_size(const succinct_trie_t *trie);

#endif /* __SUCCINCT_TRIE_H__ */