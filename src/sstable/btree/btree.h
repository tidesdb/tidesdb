/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BTREE_H__
#define __BTREE_H__

#include "base/arena.h"             /* the db-global chunk pool a node is deserialized into */
#include "base/encoding/encoding.h" /* tidesdb_encoding_stage_t, the resolved codec chain */
#include "cache/cache.h"            /* the db-global node cache btree reads through */
#include "compat.h"
#include "io/block_manager.h"

/* branch prediction hints */
#if defined(__GNUC__) || defined(__clang__)
#define BTREE_LIKELY(x)   __builtin_expect(!!(x), 1)
#define BTREE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define BTREE_LIKELY(x)   (x)
#define BTREE_UNLIKELY(x) (x)
#endif

/* a read return distinct from -1 (genuine absence) for when a node could not be loaded, so the
 * caller can retry a transient failure instead of trusting it as a definitive miss */
#define BTREE_READ_TRANSIENT (-2)

/* node type flags */
#define BTREE_NODE_LEAF     0x01
#define BTREE_NODE_INTERNAL 0x02

/* the on-disk entry flag byte. the memtable's TDB_KV_FLAG_* set is a separate, in-memory spelling
 * that sstable_builder_emit translates into these one bit at a time, so the two need not agree */
#define BTREE_ENTRY_FLAG_TOMBSTONE 0x01
#define BTREE_ENTRY_FLAG_HAS_TTL   0x02
#define BTREE_ENTRY_FLAG_VLOG_REF  0x04 /* value is in vlog, not inline */
#define BTREE_ENTRY_FLAG_SINGLE_DELETE       \
    0x10 /* single-delete tombstone subtype, \
          * always set alongside             \
          * BTREE_ENTRY_FLAG_TOMBSTONE */

/* default configuration */
#define BTREE_DEFAULT_NODE_SIZE    (64 * 1024) /* 64KB target node size */
#define BTREE_DEFAULT_FANOUT       256         /* target keys per internal node */
#define BTREE_MIN_ENTRIES_PER_LEAF 2

/* forward declarations */
typedef struct btree_t btree_t;
typedef struct btree_builder_t btree_builder_t;
typedef struct btree_cursor_t btree_cursor_t;
typedef struct btree_node_t btree_node_t;
typedef struct btree_entry_t btree_entry_t;

/**
 * btree_entry_t
 * a single key-value entry in a leaf node
 * @param key_size size of key
 * @param value_size size of value (inline or in vlog)
 * @param vlog_offset offset in vlog if value is external (0 = inline)
 * @param seq sequence number
 * @param ttl time-to-live (0 = no expiry)
 * @param flags entry flags (tombstone, has_ttl, vlog_ref)
 */
struct btree_entry_t
{
    uint32_t key_size;
    uint32_t value_size;
    uint64_t vlog_offset;
    uint64_t seq;
    int64_t ttl;
    uint8_t flags;
};

/**
 * btree_node_t
 * in-memory representation of a B+tree node
 * @param type node type (leaf or internal)
 * @param num_entries number of entries/children
 * @param entries array of entries (leaf nodes only)
 * @param keys array of key pointers
 * @param key_sizes array of key sizes
 * @param values array of inline value pointers (leaf nodes only)
 * @param child_offsets array of child block offsets (internal nodes only)
 * @param prev_offset offset of previous sibling (leaf nodes, for backward scan)
 * @param next_offset offset of next sibling (leaf nodes, for forward scan)
 * @param block_offset this node's offset in the file
 * @param arena arena the node's storage was deserialized into, freed as a unit and returning its
 * chunks to the shared pool rather than to the OS
 */
struct btree_node_t
{
    uint8_t type;
    uint32_t num_entries;
    btree_entry_t *entries;
    uint8_t **keys;
    size_t *key_sizes;
    uint8_t **values;
    int64_t *child_offsets;
    int64_t prev_offset;
    int64_t next_offset;
    int64_t block_offset;
    arena_t *arena;
};

/**
 * btree_config_t
 * configuration for B+tree construction
 * @param target_node_size target size for nodes in bytes
 * @param codec the family's encoding pipeline, already resolved to transforms and applied to every
 * node in order on write and in reverse on read; the btree knows nothing about which algorithms
 * these are. NULL, or a count of zero, stores nodes verbatim
 * @param codec_count how many stages codec holds
 * @param arena_pool the db-global chunk pool a decoded node's arena draws from, borrowed, or NULL
 * to allocate directly
 */
typedef struct
{
    size_t target_node_size;
    const tidesdb_encoding_stage_t *codec;
    int codec_count;
    arena_pool_t *arena_pool;
} btree_config_t;

/**
 * btree_t
 * immutable B+tree structure (read-only after construction)
 * @param bm block manager for storage
 * @param root_offset offset of root node
 * @param first_leaf_offset offset of first leaf (for forward iteration)
 * @param last_leaf_offset offset of last leaf (for backward iteration)
 * @param entry_count total number of entries
 * @param node_count total number of nodes
 * @param height tree height
 * @param config configuration
 * @param min_key minimum key in tree
 * @param min_key_size size of minimum key
 * @param max_key maximum key in tree
 * @param max_key_size size of maximum key
 * @param max_seq maximum sequence number
 * @param node_cache node cache for fast lookups (optional, can be NULL)
 * @param cache_key_prefix precomputed cache key prefix for this btree's node cache entries
 * @param borrowed_root a root node held open elsewhere for longer than this tree lives, used
 * without a pin of its own, or NULL to read the root like any other node
 */
struct btree_t
{
    block_manager_t *bm;
    int64_t root_offset;
    int64_t first_leaf_offset;
    int64_t last_leaf_offset;
    uint64_t entry_count;
    uint64_t node_count;
    uint32_t height;
    btree_config_t config;
    uint8_t *min_key;
    size_t min_key_size;
    uint8_t *max_key;
    size_t max_key_size;
    uint64_t max_seq;
    cache_t *node_cache;
    uint64_t cache_key_prefix;
    btree_node_t *borrowed_root;
};

/**
 * btree_stats_t
 * statistics for a single B+tree (per-sstable)
 * @param entry_count total number of entries
 * @param node_count total number of nodes
 * @param height tree height (1 = single leaf, 2+ = has internal nodes)
 * @param serialized_size total bytes on disk
 */
typedef struct
{
    uint64_t entry_count;
    uint64_t node_count;
    uint32_t height;
    uint64_t serialized_size;
} btree_stats_t;

/**
 * btree_cursor_t
 * cursor for iterating through the B+tree
 * uses tree traversal for leaf-to-leaf navigation (memory efficient)
 * @param tree pointer to the B+tree
 * @param current_node current leaf node
 * @param current_index index within current node
 * @param current_leaf_offset offset of current leaf node
 * @param at_end flag indicating cursor is past end
 * @param at_begin flag indicating cursor is before begin
 * @param current_pin cache pin for current_node when it came from the node cache, else NULL
 * @param read_error set when a node load failed (vs a genuine end of tree) so callers can tell a
 *                   truncated traversal apart from a complete one and not treat lost entries as
 * gone
 */
struct btree_cursor_t
{
    btree_t *tree;
    btree_node_t *current_node;
    int32_t current_index;
    int64_t current_leaf_offset;
    int at_end;
    int at_begin;
    cache_entry_t *current_pin;
    int read_error;
};

/**
 * btree_builder_new
 * creates a new B+tree builder for sorted data insertion
 * @param builder output pointer to builder
 * @param bm block manager for storage
 * @param config configuration (node size, value threshold)
 * @return 0 on success, -1 on failure
 */
int btree_builder_new(btree_builder_t **builder, block_manager_t *bm, const btree_config_t *config);

/**
 * btree_builder_add
 * adds an entry to the B+tree (must be called in sorted key order)
 * @param builder the builder
 * @param key key data
 * @param key_size size of key
 * @param value value data (NULL for tombstones)
 * @param value_size size of value
 * @param vlog_offset vlog offset if value is external (0 = inline)
 * @param seq sequence number
 * @param ttl time-to-live (0 = no expiry)
 * @param entry_flags bitmask of BTREE_ENTRY_FLAG_* to persist on this entry
 *                    (TOMBSTONE, SINGLE_DELETE). HAS_TTL and VLOG_REF are
 *                    derived from ttl and vlog_offset. passing 1 (a bare
 *                    tombstone) stays valid because 1 == TOMBSTONE.
 * @return 0 on success, -1 on failure
 */
int btree_builder_add(btree_builder_t *builder, const uint8_t *key, size_t key_size,
                      const uint8_t *value, size_t value_size, uint64_t vlog_offset, uint64_t seq,
                      int64_t ttl, uint8_t entry_flags);

/**
 * btree_builder_finish
 * finalizes the B+tree construction
 * @param builder the builder
 * @param tree output pointer to completed tree
 * @return 0 on success, -1 on failure
 */
int btree_builder_finish(btree_builder_t *builder, btree_t **tree);

/**
 * btree_builder_free
 * frees builder resources (call after finish or on error)
 * @param builder the builder to free
 */
void btree_builder_free(btree_builder_t *builder);

/**
 * btree_open
 * opens an existing B+tree from storage
 * tidesdb core reads sstable metadata and passes offsets to btree
 * @param tree output pointer to tree
 * @param bm block manager containing the tree
 * @param config configuration (must match what was used to build)
 * @param root_offset offset of root node (from sstable metadata)
 * @param first_leaf_offset offset of first leaf for forward iteration
 * @param last_leaf_offset offset of last leaf for backward iteration
 * @return 0 on success, -1 on failure
 */
int btree_open(btree_t **tree, block_manager_t *bm, const btree_config_t *config,
               int64_t root_offset, int64_t first_leaf_offset, int64_t last_leaf_offset);

/**
 * btree_get_at_seq
 * retrieves the version of a key visible at a sequence ceiling. a key may have
 * several versions in one tree (a flush or compaction retains a version chain);
 * this returns the one with the highest seq that does not exceed seq_ceiling,
 * or -1 if the key has no version at or below it.
 * @param tree the B+tree
 * @param key key data
 * @param key_size size of key
 * @param seq_ceiling highest sequence number to consider (UINT64_MAX = newest)
 * @param value output pointer to value (caller must free)
 * @param value_size output value size
 * @param vlog_offset output vlog offset (0 if inline)
 * @param seq output sequence number
 * @param ttl output time-to-live
 * @param deleted output tombstone flag
 * @return 0 on success, -1 on genuine not-found, BTREE_READ_TRANSIENT when a node could not be
 *         loaded and the result is inconclusive
 */
int btree_get_at_seq(btree_t *tree, const uint8_t *key, size_t key_size, uint64_t seq_ceiling,
                     uint8_t **value, size_t *value_size, uint64_t *vlog_offset, uint64_t *seq,
                     int64_t *ttl, uint8_t *deleted);

/**
 * btree_get
 * retrieves the newest version of a key (equivalent to btree_get_at_seq with
 * seq_ceiling = UINT64_MAX)
 * @param tree the B+tree
 * @param key key data
 * @param key_size size of key
 * @param value output pointer to value (caller must free)
 * @param value_size output value size
 * @param vlog_offset output vlog offset (0 if inline)
 * @param seq output sequence number
 * @param ttl output time-to-live
 * @param deleted output tombstone flag
 * @return 0 on success, -1 on not found or error
 */
int btree_get(btree_t *tree, const uint8_t *key, size_t key_size, uint8_t **value,
              size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
              uint8_t *deleted);

/**
 * btree_get_entry_count
 * returns total number of entries
 * @param tree the B+tree
 * @return total number of entries in the tree
 */
uint64_t btree_get_entry_count(const btree_t *tree);

/**
 * btree_get_min_key
 * gets the minimum key
 * @param tree the B+tree
 * @param key output pointer to key (caller must free)
 * @param key_size output key size
 * @return 0 on success, -1 on failure
 */
int btree_get_min_key(btree_t *tree, uint8_t **key, size_t *key_size);

/**
 * btree_get_max_key
 * gets the maximum key
 * @param tree the B+tree
 * @param key output pointer to key (caller must free)
 * @param key_size output key size
 * @return 0 on success, -1 on failure
 */
int btree_get_max_key(btree_t *tree, uint8_t **key, size_t *key_size);

/**
 * btree_get_max_seq
 * returns maximum sequence number in tree
 * @param tree the B+tree
 * @return maximum sequence number across all entries in the tree
 */
uint64_t btree_get_max_seq(const btree_t *tree);

/**
 * btree_get_stats
 * populates statistics for the B+tree
 * @param tree the B+tree
 * @param stats output statistics structure
 * @return 0 on success, -1 on failure
 */
int btree_get_stats(const btree_t *tree, btree_stats_t *stats);

/**
 * btree_free
 * frees B+tree resources
 * @param tree the tree to free
 */
void btree_free(btree_t *tree);

/**
 * btree_set_node_cache
 * attach the db-global node cache the btree reads through and the namespace its entries are keyed
 * under; not owned by the btree, the caller manages its lifetime
 * @param tree the B+tree
 * @param cache the cache to use, or NULL to read nodes directly without caching
 * @param cache_key_prefix the per-file namespace (an sstable's cache_key_prefix) keying node
 * entries
 */
void btree_set_node_cache(btree_t *tree, cache_t *cache, uint64_t cache_key_prefix);

/**
 * btree_hold_root
 * read the root node through the node cache and hand it back with the pin that holds it, for an
 * owner outliving the tree to keep and lend back with btree_set_borrowed_root
 *
 * only a root that is an internal node and came from the cache is handed back. a leaf root is
 * returned straight to a caller that releases whatever it is given, and an uncached read carries no
 * pin to hold it with, so both are left to the ordinary per-descent path
 * @param tree tree whose root to hold
 * @param root receives the root node, owned by the pin
 * @param pin receives the cache pin, released by the owner when it is done
 * @return 0 when a root was handed back, -1 when there is none to hold
 */
int btree_hold_root(btree_t *tree, btree_node_t **root, cache_entry_t **pin);

/**
 * btree_set_borrowed_root
 * lend the tree a root node whose lifetime already exceeds the tree's, so a descent starts from it
 * without taking a pin
 *
 * every descent begins at the same root, so pinning it per descent puts every reader of this tree
 * on one refcount's cache line. an owner that outlives the tree can hold that pin once instead
 * @param tree tree to lend the root to
 * @param root the root node, or NULL to read the root per descent as usual
 */
void btree_set_borrowed_root(btree_t *tree, btree_node_t *root);

/**
 * btree_cursor_init
 * create a cursor over the tree, left unpositioned -- position it with a seek, or with
 * btree_cursor_goto_first / goto_last, before drawing anything from it.
 *
 * it does not place itself on the first leaf, because a cursor that did would read and pin a node
 * almost no caller wants: a merge source is seeked to the range it will read, and a full scan asks
 * for the first leaf explicitly. the unpositioned state is already modelled -- btree_cursor_valid
 * reports 0, next goes to the first entry and prev to the last
 * @param cursor output pointer to cursor
 * @param tree the B+tree
 * @return 0 on success, -1 on failure
 */
int btree_cursor_init(btree_cursor_t **cursor, btree_t *tree);

/**
 * btree_cursor_next
 * moves cursor to next entry
 * @param cursor the cursor
 * @return 0 on success, -1 on failure or end
 */
int btree_cursor_next(btree_cursor_t *cursor);

/**
 * btree_cursor_prev
 * moves cursor to previous entry
 * @param cursor the cursor
 * @return 0 on success, -1 on failure or start
 */
int btree_cursor_prev(btree_cursor_t *cursor);

/**
 * btree_cursor_seek
 * positions cursor at first key >= target
 * @param cursor the cursor
 * @param key target key
 * @param key_size size of target key
 * @return 0 on success, -1 on failure
 */
int btree_cursor_seek(btree_cursor_t *cursor, const uint8_t *key, size_t key_size);

/**
 * btree_cursor_seek_for_prev
 * positions cursor at last key <= target
 * @param cursor the cursor
 * @param key target key
 * @param key_size size of target key
 * @return 0 on success, -1 on failure
 */
int btree_cursor_seek_for_prev(btree_cursor_t *cursor, const uint8_t *key, size_t key_size);

/**
 * btree_cursor_goto_first
 * moves cursor to first entry
 * @param cursor the cursor
 * @return 0 on success, -1 on failure
 */
int btree_cursor_goto_first(btree_cursor_t *cursor);

/**
 * btree_cursor_goto_last
 * moves cursor to last entry
 * @param cursor the cursor
 * @return 0 on success, -1 on failure
 */
int btree_cursor_goto_last(btree_cursor_t *cursor);

/**
 * btree_cursor_valid
 * checks if cursor is at a valid position
 * @param cursor the cursor
 * @return 1 if valid, 0 if not, -1 on error
 */
int btree_cursor_valid(btree_cursor_t *cursor);

/**
 * btree_cursor_read_failed
 * reports whether the cursor stopped because a node load failed rather than because it reached a
 * genuine end of the tree. lets a caller (e.g. a compaction merge source) tell a transiently
 * truncated scan apart from a complete one and abort instead of dropping the unread entries.
 * @param cursor the cursor
 * @return 1 if the last advance stopped on a node-load failure, 0 otherwise
 */
int btree_cursor_read_failed(const btree_cursor_t *cursor);

/**
 * btree_cursor_get
 * gets entry at current cursor position
 * @param cursor the cursor
 * @param key output key pointer (do not free, valid until cursor moves)
 * @param key_size output key size
 * @param value output value pointer (do not free, valid until cursor moves)
 * @param value_size output value size
 * @param vlog_offset output vlog offset (0 if inline)
 * @param seq output sequence number
 * @param ttl output time-to-live
 * @param deleted output tombstone flag
 * @return 0 on success, -1 on failure
 */
int btree_cursor_get(btree_cursor_t *cursor, uint8_t **key, size_t *key_size, uint8_t **value,
                     size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                     uint8_t *deleted);

/**
 * btree_cursor_has_next
 * checks if cursor has next entry
 * @param cursor the cursor
 * @return 1 if has next, 0 if not, -1 on error
 */
int btree_cursor_has_next(btree_cursor_t *cursor);

/**
 * btree_cursor_has_prev
 * checks if cursor has previous entry
 * @param cursor the cursor
 * @return 1 if has prev, 0 if not, -1 on error
 */
int btree_cursor_has_prev(btree_cursor_t *cursor);

/**
 * btree_cursor_free
 * frees cursor resources
 * @param cursor the cursor to free
 */
void btree_cursor_free(btree_cursor_t *cursor);

/**
 * btree_node_free
 * frees a node and its contents
 * @param node the node to free
 */
void btree_node_free(btree_node_t *node);

/**
 * btree_node_read_with_codec
 * reads a node from storage with decompression support
 * @param bm block manager
 * @param offset node offset
 * @param node output pointer to node
 * @param codec resolved encoding stages to undo, in reverse; NULL or a zero count reads verbatim
 * @param codec_count how many stages codec holds
 * @param pool the db-global chunk pool a decoded node's arena draws from, or NULL to allocate
 * directly; pooling is what keeps a block-cache miss off the process allocator's growth path
 * @param node_size_hint the tree's target node size, so the whole node arrives in the first pread;
 * 0 leaves the block manager to its default guess and risks a second syscall on a node larger than
 * it
 * @return 0 on success, -1 on failure
 */
int btree_node_read_with_codec(block_manager_t *bm, int64_t offset, btree_node_t **node,
                               const tidesdb_encoding_stage_t *codec, int codec_count,
                               arena_pool_t *pool, uint32_t node_size_hint);

#endif /* __BTREE_H__ */
