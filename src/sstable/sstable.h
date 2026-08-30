/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_SSTABLE_H__
#define __TIDESDB_SSTABLE_H__

#include "base/arena.h"             /* the db-global chunk pool a decoded node draws from */
#include "base/encoding/encoding.h" /* TDB_ENCODING_PIPELINE_MAX */
#include "base/lockfree.h"          /* tdb_refcount_t and the evicting-refcount window */
#include "cache/cache.h"            /* the db-global block cache the btree reads through */
#include "compat.h"                 /* fixed-width ints, size_t, time_t */
#include "db.h"                     /* TDB_MAX_CF_NAME_LEN */
#include "fdmanager/fdmanager.h"    /* the descriptor budget guarding klog reopens */
#include "io/block_manager.h"
#include "manifest/manifest.h"               /* tidesdb_manifest_entry_t names the file to open */
#include "range_tombstone/range_tombstone.h" /* the tombstone block a table carries */
#include "sstable/btree/btree.h"             /* btree_t, btree_builder for the sstable klog */
#include "sstable/pr_filter.h"
#include "sstable/vlog.h" /* the shared db-global value log, borrowed by the builder */

/* an sstable is one immutable sorted run of a column family, a single .klog file holding a b+tree,
 * a pr_filter directory, and a trailing metadata footer. the btree is the sorted store and the
 * index; this module adds the footer, the bloom front, value-log resolution, and the lock-free
 * lifetime. the shared db-global value log is borrowed per call, so an sstable owns exactly the one
 * klog file. */

/* the refcount an idle installed sstable sits at -- the single reference its level set holds. a
 * caller adds whatever references it holds itself before handing the total to sstable_evict_klog,
 * which claims the evicting window only at that exact count, when no reader is in flight. */
#define SSTABLE_IDLE_BASELINE 1

/* footer magic, identifies the trailing block as an sstable footer and catches a wrong-offset read
 */
#define TDB_SSTABLE_FOOTER_MAGIC 0x53535442 /* "SSTB" */

/* on-disk footer format version, aligned with the v10 on-disk generation, so a future layout change
 * is detected rather than misread */
#define TDB_SSTABLE_FORMAT_VERSION 10

/* an sstable can name at most one segment per segment that exists, and the segment table is fixed
 * at open, so the histogram is bounded by construction and never has to refuse an entry -- which
 * matters because a refused entry would understate a segment's live bytes */
#define SSTABLE_VLOG_REF_MAX VLOG_MAX_SEGMENTS

/**
 * sstable_vlog_ref_t
 * how much of one value-log segment an sstable's separated values hold
 * @param segment the segment number, stable across the segment table's slot reuse
 * @param bytes framed bytes this sstable's values occupy in that segment
 * @param count how many values those bytes are
 */
typedef struct
{
    uint64_t segment;
    uint64_t bytes;
    uint64_t count;
} sstable_vlog_ref_t;

/**
 * sstable_footer_t
 * the parsed metadata footer, the one block that makes an sstable knowable from a single read
 * @param version on-disk format version
 * @param root_offset btree root node offset, passed to btree_open
 * @param first_leaf_offset first leaf offset, the forward-iteration entry
 * @param last_leaf_offset last leaf offset, the backward-iteration entry
 * @param bloom_dir_offset pr_filter directory offset, 0 when the sstable added no keys
 * @param bloom_dir_size pr_filter directory size in bytes
 * @param distinct_key_count number of unique keys, a bloom-sizing and cardinality input
 * @param tombstone_count number of tombstone entries, gates tombstone-gc decisions
 * @param max_seq the sstable's newest sequence number
 * @param total_key_bytes summed length of every key, the input to average-key-size stats
 * @param total_value_bytes summed length of every live value, the input to average-value-size stats
 * @param klog_logical_bytes what the key log's contents amount to before encoding -- keys, the
 * values that stayed inline, and the per-entry overhead. read against the klog file's size it is
 * what the pipeline in this footer achieved, on this table's data. it has to be recorded here
 * rather than derived, because total_value_bytes counts spilled values too and those bytes are in
 * the value log, not this file
 * @param range_del_offset where this table's own range tombstone block landed, 0 when it carries
 * none. a tombstone is written into the table its memtable flushed to and travels down with that
 * table, so its lifetime is the table's rather than a claim the family has to verify
 * @param range_del_size how large that block is, 0 when the table carries none
 * @param btree_node_count the klog btree's node count, recorded at build time for structure stats
 * @param btree_height the klog btree's height, recorded at build time for structure stats
 * @param btree_node_size the node size the klog btree was built to, recorded so a later read can
 * ask the block manager for a whole node in its first pread instead of discovering the size by
 * coming up short
 * @param min_key smallest key, owned by the footer (freed by sstable_footer_free)
 * @param min_key_size size of min_key in bytes
 * @param max_key largest key, owned by the footer (freed by sstable_footer_free)
 * @param max_key_size size of max_key in bytes
 * @param encoding_pipeline the encoding ids in encode order, applied to node blocks and vlog values
 * @param encoding_count number of encodings in the pipeline
 * @param vlog_refs which value-log segments this table's separated values live in and how much of
 *        each they hold, owned by the footer (freed by sstable_footer_free). summed over the live
 *        tables it is what the store's segment liveness is, so reclamation needs no scan
 * @param vlog_ref_count how many entries vlog_refs holds
 */
typedef struct
{
    uint32_t version;
    int64_t root_offset;
    int64_t first_leaf_offset;
    int64_t last_leaf_offset;
    uint64_t bloom_dir_offset;
    uint32_t bloom_dir_size;
    uint64_t distinct_key_count;
    uint64_t tombstone_count;
    uint64_t max_seq;
    uint64_t range_del_offset;
    uint32_t range_del_size;
    uint64_t total_key_bytes;
    uint64_t total_value_bytes;
    uint64_t klog_logical_bytes;
    uint64_t btree_node_count;
    uint32_t btree_height;
    uint32_t btree_node_size;
    uint8_t *min_key;
    uint32_t min_key_size;
    uint8_t *max_key;
    uint32_t max_key_size;
    uint8_t encoding_pipeline[TDB_ENCODING_PIPELINE_MAX];
    uint8_t encoding_count;
    sstable_vlog_ref_t *vlog_refs;
    uint32_t vlog_ref_count;
} sstable_footer_t;

/**
 * sstable_t
 * one open sstable, a lightweight handle whose btree is stacked per call and whose klog block
 * manager is reopened on demand so the reaper can reclaim its fd without freeing the handle
 * @param id sstable id, part of the .klog file name
 * @param partition partition shard for a partitioned merge output, or MANIFEST_NO_PARTITION
 * @param klog_path full path to the .klog file, used to reopen after a reaper eviction
 * @param klog_filename pointer past the last separator of klog_path, for block-cache keys
 * @param cf_name owning column family name, the first component of a block-cache key
 * @param cache_key_prefix xxHash64 of klog_path, the btree node-cache namespace for this sstable
 * @param klog_bm the one owned block manager, NULL while reaper-evicted, published by a cas on
 * reopen
 * @param bloom membership front, lazily opened on first read and published by a cas; stays NULL
 * when the sstable has no bloom (no keys)
 * @param root_offset cached footer field, lets a reopen btree_open without re-reading the footer
 * @param first_leaf_offset cached footer field
 * @param last_leaf_offset cached footer field
 * @param bloom_dir_offset cached footer field
 * @param bloom_dir_size cached footer field
 * @param distinct_key_count cached footer field
 * @param tombstone_count cached footer field
 * @param max_seq cached footer field
 * @param total_key_bytes cached footer field, summed length of every key
 * @param total_value_bytes cached footer field, summed length of every live value
 * @param klog_logical_bytes cached footer field, the key log's contents before encoding
 * @param btree_node_count cached footer field, the klog btree's node count
 * @param btree_height cached footer field, the klog btree's height
 * @param btree_node_size cached footer field, the node size the btree was built to
 * @param min_key smallest key, owned by the sstable
 * @param min_key_size size of min_key in bytes
 * @param max_key largest key, owned by the sstable
 * @param max_key_size size of max_key in bytes
 * @param encoding_pipeline cached footer field, the decode pipeline for node blocks and vlog values
 * @param encoding_count number of encodings in the pipeline
 * @param vlog_refs cached footer field, which value-log segments this table's separated values live
 * in and how much of each they hold, owned by the sstable
 * @param vlog_ref_count how many entries vlog_refs holds
 * @param range_del_offset cached footer field, where this table's interval-delete block sits in the
 *                         klog, 0 when it carries none
 * @param range_del_size cached footer field, the size of that block, 0 when it carries none
 * @param range_tombstones the intervals decoded from that block, read once at open and owned by the
 *                         sstable, or NULL when the table carries none
 * @param sync_mode block-manager sync mode used when reopening the klog
 * @param encodings borrowed encoding registry the footer's pipeline ids resolve against, or NULL
 * when the family stores nodes verbatim
 * @param codec those ids resolved once at open, so a read never walks the registry
 * @param codec_count how many stages codec holds
 * @param node_cache borrowed db-global block cache the btree reads through, or NULL to read
 * uncached
 * @param fdm borrowed descriptor-budget service, or NULL to open klogs without a budget
 * @param arena_pool borrowed db-global chunk pool a decoded node's arena draws from, or NULL to
 * allocate directly
 * @param now borrowed db-wide clock the ticker publishes the current second to, read instead
 * of calling time(NULL) on every entry, or NULL to read the clock directly
 * @param root_node the klog btree's root, read once and held for as long as the sstable is open so
 * a descent starts from it without pinning it, or NULL until the first cached read publishes it
 * @param root_pin the cache pin keeping root_node alive, released when the sstable closes
 * @param refcount lock-free refcount with the evicting window, guards use against reaper eviction
 * @param last_access_time lru key for reaper victim selection, in seconds from the same clock
 * @param marked_for_deletion set once a compaction has committed the merge that supersedes this
 * sstable, so whoever drops its last reference unlinks the key log rather than only closing it
 */
typedef struct
{
    uint64_t id;
    int partition;
    char *klog_path;
    const char *klog_filename;
    char cf_name[TDB_MAX_CF_NAME_LEN];
    uint64_t cache_key_prefix;

    cache_t *node_cache;
    arena_pool_t *arena_pool;
    _Atomic(int64_t) *now;
    fd_manager_t *fdm;
    const tidesdb_encoding_registry_t *encodings;
    tidesdb_encoding_stage_t codec[TDB_ENCODING_PIPELINE_MAX];
    int codec_count;

    _Atomic(block_manager_t *) klog_bm;
    _Atomic(pr_filter_reader_t *) bloom;
    _Atomic(btree_node_t *) root_node;
    cache_entry_t *root_pin;

    int64_t root_offset;
    int64_t first_leaf_offset;
    int64_t last_leaf_offset;
    uint64_t bloom_dir_offset;
    uint32_t bloom_dir_size;
    uint64_t distinct_key_count;
    uint64_t tombstone_count;
    uint64_t max_seq;
    uint64_t range_del_offset;
    uint32_t range_del_size;
    /* the tombstones this table carries, taken from the build or read back at open, owned here */
    range_tombstone_set_t *range_tombstones;
    uint64_t total_key_bytes;
    uint64_t total_value_bytes;
    uint64_t klog_logical_bytes;
    uint64_t btree_node_count;
    uint32_t btree_height;
    uint32_t btree_node_size;

    uint8_t *min_key;
    size_t min_key_size;
    uint8_t *max_key;
    size_t max_key_size;

    uint8_t encoding_pipeline[TDB_ENCODING_PIPELINE_MAX];
    uint8_t encoding_count;
    int sync_mode;

    sstable_vlog_ref_t *vlog_refs;
    uint32_t vlog_ref_count;

    tdb_refcount_t refcount;
    _Atomic(int64_t) last_access_time;
    _Atomic(int) marked_for_deletion;
} sstable_t;

/**
 * sstable_footer_serialize
 * encode a footer into a freshly allocated buffer the caller frees and writes as one klog block
 * @param footer the footer to encode
 * @param out out -- newly allocated bytes on success, owned by the caller
 * @param out_size out -- length of the encoded footer
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument, or TDB_ERR_MEMORY
 */
int sstable_footer_serialize(const sstable_footer_t *footer, uint8_t **out, size_t *out_size);

/**
 * sstable_footer_parse
 * decode a footer from the bytes of a klog footer block, allocating owned copies of min/max keys
 * @param data the footer block payload
 * @param size length of data in bytes
 * @param out out -- the parsed footer, its min_key/max_key owned and freed by sstable_footer_free
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument, TDB_ERR_CORRUPTION on a bad magic,
 *         version, or truncated field, or TDB_ERR_MEMORY
 */
int sstable_footer_parse(const uint8_t *data, size_t size, sstable_footer_t *out);

/**
 * sstable_footer_free
 * release the min/max key buffers a parse allocated onto a footer; safe on a zeroed footer
 * @param footer the footer whose owned buffers to free
 */
void sstable_footer_free(sstable_footer_t *footer);

/**
 * sstable_klog_filename
 * build the .klog file name for a manifest entry -- the owning family's id and the sstable's id,
 * each zero-padded, joined by a dot. the family id is in the name because families have no
 * directory of their own, so this is what lets a rebuild from the files alone tell which family a
 * key log belongs to
 * @param entry the manifest entry naming the sstable
 * @param out output buffer
 * @param out_size size of out in bytes
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS when out is too small or an argument is NULL
 */
int sstable_klog_filename(const tidesdb_manifest_entry_t *entry, char *out, size_t out_size);

/**
 * sstable_open_from_manifest
 * open an existing sstable named by a manifest entry, reading its footer and caching every field so
 * a later read reopens the klog without touching the footer again; the klog fd is released after
 * the footer read, so opening many sstables at startup does not hold an fd per table
 * @param out out -- the open sstable on success, owned by the caller (freed by sstable_close)
 * @param cf_dir the directory holding the .klog file, which is the database directory -- families
 *               have no directory of their own
 * @param cf_name the owning column family name
 * @param entry the manifest entry naming the sstable (id, partition, birth_level)
 * @param sync_mode block-manager sync mode for reopening the klog
 * @param encodings the db-global encoding registry the footer's pipeline ids are resolved against,
 *                  once, at open. a file naming an id this build does not carry is unreadable and
 *                  reports corruption rather than opening and failing later, per node
 * @param node_cache borrowed db-global block cache the btree reads through, or NULL to read
 * uncached
 * @param fdm borrowed descriptor-budget service, or NULL to open klogs without a budget
 * @param arena_pool borrowed db-global chunk pool a decoded btree node's arena draws from, or NULL
 *                   to allocate directly
 * @param now borrowed db-wide clock the ticker publishes the current second to, read instead
 * of calling time(NULL) on every entry, or NULL to read the clock directly
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on an open or read failure,
 *         TDB_ERR_CORRUPTION on a bad footer, or TDB_ERR_MEMORY
 */
int sstable_open_from_manifest(sstable_t **out, const char *cf_dir, const char *cf_name,
                               const tidesdb_manifest_entry_t *entry, int sync_mode,
                               const tidesdb_encoding_registry_t *encodings, cache_t *node_cache,
                               fd_manager_t *fdm, arena_pool_t *arena_pool, _Atomic(int64_t) *now);

/**
 * sstable_ensure_open
 * return the klog block manager, reopening it if the reaper closed it; the reopen races safely, a
 * loser closes its own handle and returns the winner's
 * @param sst the sstable
 * @return the open block manager, or NULL if the reopen failed (an fd budget or io error)
 */
block_manager_t *sstable_ensure_open(sstable_t *sst);

/**
 * sstable_get_at_seq
 * look up the newest version of a key visible at a sequence ceiling in this sstable -- the highest
 * seq that does not exceed seq_ceiling, walking the version chain a flush or compaction retained.
 * this is the snapshot-aware point get the read path uses; the newest version overall is
 * seq_ceiling UINT64_MAX. the caller must already hold a reference so the reaper cannot evict the
 * klog mid-read. the bloom front short-circuits a definite miss (membership is version-agnostic);
 * on a hit the btree reads through the borrowed node cache. a value large enough to have spilled
 * comes back as a vlog offset the caller resolves against the db-global value log.
 * @param sst the sstable
 * @param key key data
 * @param key_size size of key in bytes
 * @param seq_ceiling highest sequence number to consider, UINT64_MAX for the newest version
 * @param value out -- inline value on success, newly allocated and owned by the caller (NULL when
 * the value spilled to the vlog)
 * @param value_size out -- the value's logical length, whether it is inline or spilled
 * @param vlog_offset out -- the vlog offset to resolve, or 0 when the value is inline
 * @param seq out -- the resolved version's sequence number
 * @param ttl out -- the resolved version's expiry, or 0 for none
 * @param deleted out -- non-zero when the resolved version is a tombstone
 * @return TDB_SUCCESS on a hit, TDB_ERR_NOT_FOUND on a miss or no version at or below the ceiling,
 *         TDB_ERR_BUSY when over the reader fd budget, or TDB_ERR_IO on an open or read failure
 */
int sstable_get_at_seq(sstable_t *sst, const uint8_t *key, size_t key_size, uint64_t seq_ceiling,
                       uint8_t **value, size_t *value_size, uint64_t *vlog_offset, uint64_t *seq,
                       int64_t *ttl, uint8_t *deleted);

/**
 * sstable_get
 * look up the newest version of a key in this sstable, equivalent to sstable_get_at_seq with a
 * UINT64_MAX ceiling
 * @param sst the sstable
 * @param key key data
 * @param key_size size of key in bytes
 * @param value out -- inline value on success, newly allocated and owned by the caller (NULL when
 * the value spilled to the vlog)
 * @param value_size out -- the value's logical length, whether it is inline or spilled
 * @param vlog_offset out -- the vlog offset to resolve, or 0 when the value is inline
 * @param seq out -- the resolved version's sequence number
 * @param ttl out -- the resolved version's expiry, or 0 for none
 * @param deleted out -- non-zero when the resolved version is a tombstone
 * @return TDB_SUCCESS on a hit, TDB_ERR_NOT_FOUND on a miss, TDB_ERR_BUSY when over the reader fd
 *         budget, or TDB_ERR_IO on an open or read failure
 */
int sstable_get(sstable_t *sst, const uint8_t *key, size_t key_size, uint8_t **value,
                size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                uint8_t *deleted);

/**
 * sstable_sync_klog
 * force a resident sstable's klog to disk, for a checkpoint durability barrier; an evicted sstable
 * settled its durability when it was closed, so this is a no-op for it
 * @param sst the sstable
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL sstable, or TDB_ERR_IO on an fsync failure
 */
int sstable_sync_klog(sstable_t *sst);

/**
 * sstable_iter_t
 * a bidirectional cursor over one sstable, the building block the txn merge iterator and the
 * compaction iterators compose over the level set. opaque; created by sstable_iter_new.
 */
typedef struct sstable_iter sstable_iter_t;

/**
 * sstable_iter_intervals
 * the interval tombstones the table this cursor reads carries, borrowed for the cursor's life
 * @param it the cursor
 * @return the set, or NULL when the table carries none
 */
const range_tombstone_set_t *sstable_iter_intervals(const sstable_iter_t *it);

/**
 * sstable_iter_new
 * open a bidirectional cursor over the sstable. the caller must already hold a reference so the
 * reaper cannot evict the klog for the cursor's lifetime. use_cache reads node blocks through the
 * borrowed node cache; a compaction scan passes 0 so a bulk read neither pollutes nor trusts the
 * cache, which a txn iterator (passing 1) wants for locality. the cursor starts unpositioned; seek
 * it before reading.
 * @param sst the sstable
 * @param use_cache non-zero to read node blocks through the node cache, 0 to read straight from
 * disk
 * @param out out -- the cursor on success, owned by the caller (freed by sstable_iter_free)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY over the reader fd budget, TDB_ERR_IO, or
 *         TDB_ERR_MEMORY
 */
int sstable_iter_new(sstable_t *sst, int use_cache, sstable_iter_t **out);

/**
 * sstable_iter_seek
 * position the cursor at the first key greater than or equal to the search key
 * @param it the cursor
 * @param key key data
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS if positioned on a key, TDB_ERR_NOT_FOUND if none qualifies,
 * TDB_ERR_INVALID_ARGS
 */
int sstable_iter_seek(sstable_iter_t *it, const uint8_t *key, size_t key_size);

/**
 * sstable_iter_seek_for_prev
 * position the cursor at the last key less than or equal to the search key
 * @param it the cursor
 * @param key key data
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS if positioned on a key, TDB_ERR_NOT_FOUND if none qualifies,
 * TDB_ERR_INVALID_ARGS
 */
int sstable_iter_seek_for_prev(sstable_iter_t *it, const uint8_t *key, size_t key_size);

/**
 * sstable_iter_seek_first / sstable_iter_seek_last
 * position the cursor at the smallest or largest key in the sstable
 * @param it the cursor
 * @return TDB_SUCCESS if positioned, TDB_ERR_NOT_FOUND if the sstable is empty,
 * TDB_ERR_INVALID_ARGS
 */
int sstable_iter_seek_first(sstable_iter_t *it);
int sstable_iter_seek_last(sstable_iter_t *it);

/**
 * sstable_iter_next / sstable_iter_prev
 * advance the cursor forward to the next key or backward to the previous one
 * @param it the cursor
 * @return TDB_SUCCESS if it landed on a key, TDB_ERR_NOT_FOUND at an end, TDB_ERR_INVALID_ARGS
 */
int sstable_iter_next(sstable_iter_t *it);
int sstable_iter_prev(sstable_iter_t *it);

/**
 * sstable_iter_valid
 * report whether the cursor is positioned on a key
 * @param it the cursor
 * @return 1 when positioned on a key, 0 otherwise
 */
int sstable_iter_valid(sstable_iter_t *it);

/**
 * sstable_iter_read_failed
 * report whether the last advance stopped on a node-load failure rather than a genuine end, so a
 * compaction scan can abort on a truncated read instead of silently dropping the unread tail
 * @param it the cursor
 * @return 1 if the last advance stopped on a node-load failure, 0 otherwise
 */
int sstable_iter_read_failed(const sstable_iter_t *it);

/**
 * sstable_iter_get
 * read the entry at the current cursor position; a value large enough to have spilled comes back as
 * a vlog offset the caller resolves against the db-global value log
 * @param it the cursor
 * @param key out -- key pointer, do not free, valid until the cursor moves
 * @param key_size out -- key length
 * @param value out -- inline value pointer, do not free, valid until the cursor moves (NULL when
 * spilled)
 * @param value_size out -- the value's logical length, whether it is inline or spilled
 * @param vlog_offset out -- the vlog offset to resolve, or 0 when the value is inline
 * @param seq out -- the entry's sequence number
 * @param ttl out -- the entry's expiry, or 0 for none
 * @param deleted out -- non-zero when the entry is a tombstone
 * @return TDB_SUCCESS on success, TDB_ERR_NOT_FOUND when the cursor is not positioned,
 * TDB_ERR_INVALID_ARGS
 */
int sstable_iter_get(sstable_iter_t *it, uint8_t **key, size_t *key_size, uint8_t **value,
                     size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                     uint8_t *deleted);

/**
 * sstable_iter_free
 * free the cursor and the btree it opened; does not drop the sstable reference the caller holds.
 * safe on NULL.
 * @param it the cursor, may be NULL
 */
void sstable_iter_free(sstable_iter_t *it);

/**
 * sstable_evict_klog
 * close the klog block manager to reclaim its descriptor while keeping the sstable handle alive, so
 * a later read reopens it. the reaper calls this on idle sstables; it claims the evicting window
 * and bails when a reader holds a reference, so an in-flight read is never cut off.
 * @param sst the sstable
 * @param idle_baseline the exact refcount an idle sstable sits at (its level-set reference)
 * @return 1 if a descriptor was reclaimed, 0 if the sstable was busy or already closed
 */
int sstable_evict_klog(sstable_t *sst, int idle_baseline);

/**
 * sstable_live_handles
 * how many sstable handles exist right now, across every database in this process. raised where one
 * is allocated and lowered where one is freed, which are single places, so it is exact rather than
 * an estimate. a database that has closed owns none of its own, so a harness that opens and closes
 * one can assert this returns to what it was -- a handle dropped without being closed is otherwise
 * invisible until a leak checker reports it at exit, with no way back to the path that dropped it
 * @return the live handle count
 */
int64_t sstable_live_handles(void);

/**
 * sstable_close
 * free an sstable, closing its klog block manager if open; does not touch the shared vlog and does
 * not delete any file. use only when no other thread can reach the handle
 * @param sst the sstable, may be NULL
 */
void sstable_close(sstable_t *sst);

/**
 * sstable_builder_config_t
 * the inputs that shape a build, snapshotted at sstable_builder_new
 * @param target_node_size btree node target size in bytes, 0 selects the btree default
 * @param value_threshold values at or above this size spill to the shared vlog
 * @param range_tombstones the tombstones this table is to carry, borrowed and written into a block
 * of its own, or NULL to carry none. a flush passes what its memtable held and a merge passes what
 * its inputs carried, so an interval lives exactly as long as a table holding it
 * @param enable_bloom build a partition-range filter (pr_filter) for point-get pruning
 * @param bloom_fpr target bloom false-positive rate when enable_bloom is set
 * @param sync_mode block-manager sync mode, drives the durability barrier at finish
 * @param id sstable id for the produced sstable and its manifest row
 * @param partition partition shard, or MANIFEST_NO_PARTITION
 * @param cf_name owning column family name
 * @param klog_path path the klog block manager was opened at, names the file and enables lazy
 * reopen
 * @param encoding_pipeline encoding ids in encode order, applied to every node and to every value
 * that spills, and recorded in the footer so a reader can undo them (may be NULL)
 * @param encoding_count number of encodings in the pipeline
 * @param encodings borrowed registry the pipeline ids resolve against; required when the pipeline
 * is non-empty, since ids mean nothing without it
 * @param node_cache borrowed db-global block cache the produced sstable reads through, or NULL
 * @param arena_pool borrowed db-global chunk pool the produced sstable's decoded nodes draw their
 * arenas from, or NULL to allocate directly
 * @param now borrowed db-wide clock the ticker publishes the current second to, read instead
 * of calling time(NULL) on every entry, or NULL to read the clock directly
 * @param fdm borrowed descriptor budget the produced sstable's klog is accounted against, or NULL;
 * the finished sstable adopts the open klog, so finish counts it as one resident descriptor
 */
typedef struct
{
    size_t target_node_size;
    size_t value_threshold;
    const range_tombstone_set_t *range_tombstones;
    int enable_bloom;
    double bloom_fpr;
    int sync_mode;
    uint64_t id;
    int partition;
    const char *cf_name;
    const char *klog_path;
    const uint8_t *encoding_pipeline;
    uint8_t encoding_count;
    const tidesdb_encoding_registry_t *encodings;
    cache_t *node_cache;
    arena_pool_t *arena_pool;
    _Atomic(int64_t) *now;
    fd_manager_t *fdm;
} sstable_builder_config_t;

/* an in-progress sstable build; keys are added in non-decreasing key order and the build is
 * sealed by sstable_builder_finish */
typedef struct sstable_builder sstable_builder_t;

/**
 * sstable_builder_new
 * begin a build over a freshly opened klog block manager, borrowing the column family's shared vlog
 * @param out out -- the builder on success, freed by sstable_builder_free
 * @param klog_bm the klog block manager, borrowed until finish adopts it into the produced sstable
 * @param cf_vlog the column family's shared value log for spilled values (may be NULL to forbid
 * spill)
 * @param config the build inputs
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int sstable_builder_new(sstable_builder_t **out, block_manager_t *klog_bm, vlog_t *cf_vlog,
                        const sstable_builder_config_t *config);

/**
 * sstable_builder_add
 * append the next entry; keys must arrive in non-decreasing key order, and a key's versions
 * (same key, descending seq) arrive together
 * @param builder the builder
 * @param key key bytes
 * @param key_size key length in bytes
 * @param value value bytes, ignored for a tombstone (may be NULL)
 * @param value_size value length in bytes
 * @param seq sequence number
 * @param ttl absolute expiry, 0 for none
 * @param flags kv entry flags (TDB_KV_FLAG_TOMBSTONE, TDB_KV_FLAG_SINGLE_DELETE)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a vlog spill failure, or TDB_ERR_MEMORY
 */
int sstable_builder_add(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                        const uint8_t *value, size_t value_size, uint64_t seq, int64_t ttl,
                        uint8_t flags);

/**
 * sstable_builder_add_reference
 * append an entry whose value already lives in the shared vlog, carrying its logical id forward
 * without reading or re-spilling the value; a compaction uses this for a spilled entry so the value
 * is never rewritten. keys arrive in the same non-decreasing order as sstable_builder_add
 * @param builder the builder
 * @param key key bytes
 * @param key_size key length in bytes
 * @param vlog_id the existing logical vlog id the value lives at, must be non-zero
 * @param value_size the value's logical length as reported by the upstream cursor, kept so the size
 *                   stats stay exact across compactions
 * @param seq sequence number
 * @param ttl absolute expiry, 0 for none
 * @param flags kv entry flags (TDB_KV_FLAG_TOMBSTONE, TDB_KV_FLAG_SINGLE_DELETE)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int sstable_builder_add_reference(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                                  uint64_t vlog_id, size_t value_size, uint64_t seq, int64_t ttl,
                                  uint8_t flags);

/**
 * sstable_builder_klog_bytes
 * the running estimate of the klog's encoded size, for deciding when to roll to a new output; a
 * spilled value contributes its reference rather than its bytes, so this tracks what the klog costs
 * to rewrite rather than the logical data volume
 * @param builder the builder
 * @return the estimated klog bytes added so far, or 0 when builder is NULL
 */
uint64_t sstable_builder_klog_bytes(const sstable_builder_t *builder);

/**
 * sstable_builder_finish
 * seal the build -- finalize the btree and bloom, write the footer, run the durability barrier, and
 * produce an open sstable that adopts the klog block manager; the total vlog bytes this sstable
 * appended are reported so the caller can size the manifest row
 * @param builder the builder
 * @param out out -- the open sstable on success, owned by the caller (freed by sstable_close)
 * @param out_vlog_bytes out -- bytes this sstable appended to the shared vlog (may be NULL)
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO, or TDB_ERR_MEMORY; on failure the klog
 * block manager is left to the caller and the builder is still freed by sstable_builder_free
 */
int sstable_builder_finish(sstable_builder_t *builder, sstable_t **out, uint64_t *out_vlog_bytes);

/**
 * sstable_builder_free
 * release a builder; abandons an unfinished build without closing the borrowed klog block manager
 * and is a no-op on the parts a finish already consumed
 * @param builder the builder, may be NULL
 */
void sstable_builder_free(sstable_builder_t *builder);

/**
 * sstable_ref
 * take a reference; only safe when the caller already holds one or membership keeps the sstable
 * live
 * @param sst the sstable
 */
void sstable_ref(sstable_t *sst);

/**
 * sstable_klog_resident
 * whether this sstable is holding an open klog descriptor, so a reaper can pass over the ones with
 * nothing to give back before it spends an ordering on them
 * @param sst the sstable
 * @return 1 when a descriptor is resident, 0 when it is not or sst is NULL
 */
int sstable_klog_resident(const sstable_t *sst);

/**
 * sstable_mark_for_deletion
 * record that a committed compaction has superseded this sstable, so the last reference to be
 * dropped unlinks its key log instead of merely closing the handle. the file cannot be removed at
 * commit time because a reader may still be inside it, and it must not be removed before the
 * manifest edit that retires it, or a crash would leave the catalogue naming a file that is gone.
 * setting this after that commit is what turns the reference count into the deletion trigger
 * @param sst the superseded sstable, may be NULL
 */
void sstable_mark_for_deletion(sstable_t *sst);

/**
 * sstable_unref
 * drop a reference
 * @param sst the sstable
 * @return 1 when this call released the last reference and the caller must reclaim, else 0
 */
int sstable_unref(sstable_t *sst);

#endif /* __TIDESDB_SSTABLE_H__ */
