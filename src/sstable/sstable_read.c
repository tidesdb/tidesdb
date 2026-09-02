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

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h"
#include "sstable.h"

/* fraction of the recorded node size added as read slack, as a right shift; 2 adds a quarter. a
 * node is closed once it has passed the target, so the node on disk is the target plus at most one
 * entry */
#define SSTABLE_NODE_SIZE_SLACK_SHIFT 2

/**
 * sstable_bloom_cache_reclaim
 * the cache's per-entry reclaim for a cached pr_filter partition; frees the blob once the last
 * reference to it drops, on whichever thread drops it
 * @param payload the cached partition bytes
 * @param ctx unused
 */
static void sstable_bloom_cache_reclaim(void *payload, void *ctx)
{
    (void)ctx;
    free(payload);
}

/**
 * sstable_bloom_read_block
 * read one pr_filter blob's block out of the klog, resolving the live block manager so a reaper
 * reopen between probes is transparent
 * @param sst the sstable owning the klog
 * @param offset byte offset of the blob's block
 * @param size the size the directory records for the blob; a mismatch means the block is not it
 * @return the read block, owned by the caller, or NULL on a read failure or size mismatch
 */
static block_manager_block_t *sstable_bloom_read_block(sstable_t *sst, uint64_t offset,
                                                       uint32_t size)
{
    block_manager_t *bm = sstable_ensure_open(sst);
    if (!bm) return NULL;

    block_manager_cursor_t cursor;
    if (block_manager_cursor_init_stack(&cursor, bm) != 0) return NULL;
    if (block_manager_cursor_goto(&cursor, offset) != 0) return NULL;

    block_manager_block_t *block = block_manager_cursor_read(&cursor);
    if (!block) return NULL;
    if (block->size != size)
    {
        block_manager_block_free(block);
        return NULL;
    }
    return block;
}

/**
 * sstable_bloom_fetch_cached
 * fetch a pr_filter blob through the block cache, keyed in the sstable's namespace by the blob's
 * klog offset so it cannot collide with a btree node; a miss reads the blob once, hands it to the
 * cache, and re-gets to pin whichever copy won. keeping the blob cached is what stops a probe from
 * re-reading and re-checksumming a whole partition per key
 * @param sst the sstable owning the klog and the borrowed cache
 * @param offset byte offset of the blob's block
 * @param size the size the directory records for the blob
 * @param out_data out -- the pinned blob bytes
 * @param out_pin out -- the cache pin, released by sstable_bloom_release
 * @return 0 with the blob pinned, or -1 when it could not be read or could not be kept cached
 */
static int sstable_bloom_fetch_cached(sstable_t *sst, uint64_t offset, uint32_t size,
                                      const uint8_t **out_data, void **out_pin)
{
    void *payload = NULL;
    cache_entry_t *pin = NULL;
    if (cache_get(sst->node_cache, sst->cache_key_prefix, offset, &payload, NULL, &pin))
    {
        *out_data = (const uint8_t *)payload;
        *out_pin = pin;
        return 0;
    }

    block_manager_block_t *block = sstable_bloom_read_block(sst, offset, size);
    if (!block) return -1;

    uint8_t *blob = malloc(size);
    if (!blob)
    {
        block_manager_block_free(block);
        return -1;
    }
    memcpy(blob, block->data, size);
    block_manager_block_free(block);

    /* cache_put takes ownership of blob on every outcome, reclaiming it itself on a duplicate
     * insert or a full cache, so the blob is never freed here and the pin comes from the re-get */
    (void)cache_put(sst->node_cache, sst->cache_key_prefix, offset, blob, size, size,
                    sstable_bloom_cache_reclaim, NULL, NULL);

    if (cache_get(sst->node_cache, sst->cache_key_prefix, offset, &payload, NULL, &pin))
    {
        *out_data = (const uint8_t *)payload;
        *out_pin = pin;
        return 0;
    }

    /* evicted before the get, rare; a failed fetch probes as may-present so the klog still answers
     */
    return -1;
}

/* fetch a bloom blob for a probe; the context is the sstable, so the cache it borrows decides
 * whether the pin is a cache entry or a bare block and sstable_bloom_release reads the same field
 */
static int sstable_bloom_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                               void **out_pin)
{
    sstable_t *sst = (sstable_t *)ctx;
    if (sst->node_cache) return sstable_bloom_fetch_cached(sst, offset, size, out_data, out_pin);

    block_manager_block_t *block = sstable_bloom_read_block(sst, offset, size);
    if (!block) return -1;
    *out_data = block->data;
    *out_pin = block;
    return 0;
}

static void sstable_bloom_release(void *ctx, void *pin)
{
    const sstable_t *sst = (const sstable_t *)ctx;
    if (sst->node_cache)
        cache_release((cache_entry_t *)pin);
    else
        block_manager_block_free((block_manager_block_t *)pin);
}

/* open the bloom reader on first probe and publish it with a cas; a loser frees its own reader. an
 * sstable with no bloom directory has nothing to open and returns NULL, meaning probe-as-present.
 */
static pr_filter_reader_t *sstable_ensure_bloom(sstable_t *sst)
{
    pr_filter_reader_t *bloom = atomic_load_explicit(&sst->bloom, memory_order_acquire);
    if (bloom) return bloom;
    if (sst->bloom_dir_size == 0) return NULL;

    pr_filter_reader_t *opened = NULL;
    if (pr_filter_reader_open(&opened, sst->bloom_dir_offset, sst->bloom_dir_size,
                              sstable_bloom_fetch, sstable_bloom_release, sst) != 0)
        return NULL;

    pr_filter_reader_t *expected = NULL;
    if (atomic_compare_exchange_strong(&sst->bloom, &expected, opened)) return opened;

    pr_filter_reader_free(opened);
    return expected;
}

/* hold the klog btree's root for as long as the sstable is open and publish it with a cas; a loser
 * releases its own pin and takes the winner's. every read of this sstable descends the same root,
 * so pinning it per descent puts every reader on one refcount's cache line, and one pin held here
 * takes that traffic off the read path entirely */
static btree_node_t *sstable_ensure_root(sstable_t *sst, btree_t *tree)
{
    btree_node_t *root = atomic_load_explicit(&sst->root_node, memory_order_acquire);
    if (root) return root;

    cache_entry_t *pin = NULL;
    if (btree_hold_root(tree, &root, &pin) != 0) return NULL;

    btree_node_t *expected = NULL;
    if (atomic_compare_exchange_strong(&sst->root_node, &expected, root))
    {
        /* only ever read when the last reference has gone, so it needs no ordering against the
         * readers this publish releases the root to */
        sst->root_pin = pin;
        return root;
    }

    cache_release(pin);
    return expected;
}

/* open a btree over the klog for one read or scan, reading nodes through the cache only when asked;
 * compaction scans pass use_cache 0 so a bulk read neither pollutes nor trusts the shared cache */
static int sstable_open_tree(sstable_t *sst, const int use_cache, btree_t **out)
{
    block_manager_t *bm = sstable_ensure_open(sst);
    if (!bm) return TDB_ERR_IO;

    btree_config_t config = {0};
    config.codec = sst->codec_count ? sst->codec : NULL;
    config.codec_count = sst->codec_count;
    /* a node decoded on a cache miss carves its arena out of the db-global pool, so the miss path
     * recycles chunks instead of growing and trimming the process heap under every reader */
    config.arena_pool = sst->arena_pool;

    /* the node size the footer recorded lets a node read ask the block manager for the whole node
     * up front. the builder closes a node once it has passed the target rather than before, so a
     * node on disk runs a little over it -- carrying that slack here keeps the common node inside
     * the first pread, and a node past even the slack only costs the second read it would always
     * have paid */
    config.target_node_size =
        sst->btree_node_size + (sst->btree_node_size >> SSTABLE_NODE_SIZE_SLACK_SHIFT);

    btree_t *tree = NULL;
    if (btree_open(&tree, bm, &config, sst->root_offset, sst->first_leaf_offset,
                   sst->last_leaf_offset) != 0)
    {
        /* the root read runs through the recorded codec chain, so name the chain and the offsets
         * here rather than letting a decode that disagrees with the bytes surface as a bare io code
         */
        TDB_DEBUG_LOG(
            TDB_LOG_ERROR,
            "btree open failed on %s, codecs %d, root %llu, first leaf %llu, node size %u",
            sst->klog_path, sst->codec_count, (unsigned long long)sst->root_offset,
            (unsigned long long)sst->first_leaf_offset, sst->btree_node_size);
        return TDB_ERR_IO;
    }
    btree_set_node_cache(tree, use_cache ? sst->node_cache : NULL, sst->cache_key_prefix);
    if (use_cache) btree_set_borrowed_root(tree, sstable_ensure_root(sst, tree));

    *out = tree;
    return TDB_SUCCESS;
}

/* an entry whose deadline has passed reads as a tombstone rather than as a value, which is what the
 * skip list does over its own storage. reporting it as absent instead would let an older version of
 * the same key beneath it surface, so it has to shadow like a tombstone and be collected like one.
 * the deadline is judged against the wall clock and not against the reader's snapshot, so a
 * transaction older than the deadline still sees the key gone -- the same rule the memtable
 * applies, and the two must agree or a key would flicker with whichever source answered
 * @param ttl the entry's absolute deadline, or TDB_TTL_NONE when it never expires
 * @return 1 when the deadline has passed
 */
static int sstable_entry_expired(const int64_t ttl, const int64_t now)
{
    return ttl > 0 && ttl <= now;
}

/* the current second from a db-wide clock a ticker publishes, or the clock itself when none was
 * given. the memtable reads the same clock, which is what keeps the two agreeing about a deadline
 * -- a key answered by one and then the other must not flicker across it */
static int64_t sstable_clock_read(const _Atomic(int64_t) *now)
{
    if (now == NULL) return (int64_t)time(NULL);
    return atomic_load_explicit(now, memory_order_relaxed);
}

static int64_t sstable_now(const sstable_t *sst)
{
    return sstable_clock_read(sst->now);
}

int sstable_get_at_seq(sstable_t *sst, const uint8_t *key, size_t key_size, uint64_t seq_ceiling,
                       uint8_t **value, size_t *value_size, uint64_t *vlog_offset, uint64_t *seq,
                       int64_t *ttl, uint8_t *deleted)
{
    if (!sst || !key || key_size == 0 || !value || !value_size || !vlog_offset || !seq || !ttl ||
        !deleted)
        return TDB_ERR_INVALID_ARGS;

    /* a definite bloom miss avoids the klog entirely; membership is version-agnostic, so it holds
     * for any ceiling */
    pr_filter_reader_t *bloom = sstable_ensure_bloom(sst);
    if (bloom && pr_filter_reader_maybe_contains(bloom, key, key_size) == 0)
        return TDB_ERR_NOT_FOUND;

    const int already_open = atomic_load_explicit(&sst->klog_bm, memory_order_acquire) != NULL;
    if (sst->fdm && !fd_manager_reader_budget_ok(sst->fdm, already_open)) return TDB_ERR_BUSY;

    btree_t *tree = NULL;
    const int open_rc = sstable_open_tree(sst, 1, &tree);
    if (open_rc != TDB_SUCCESS) return open_rc;

    const int rc = btree_get_at_seq(tree, key, key_size, seq_ceiling, value, value_size,
                                    vlog_offset, seq, ttl, deleted);
    btree_free(tree);

    /* a lapsed entry hands back what a tombstone hands back: no value, nothing to resolve out of
     * the value log, and the deleted flag every layer above already acts on */
    const int64_t now = sstable_now(sst);
    if (rc == 0 && !*deleted && sstable_entry_expired(*ttl, now))
    {
        free(*value);
        *value = NULL;
        *value_size = 0;
        *vlog_offset = 0;
        *deleted = 1;
    }
    atomic_store_explicit(&sst->last_access_time, now, memory_order_relaxed);

    /* a node that could not be loaded is a retryable busy, never a definitive miss the source stack
     * would trust and fall through to an older version for */
    if (rc == BTREE_READ_TRANSIENT) return TDB_ERR_BUSY;
    return rc == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_get(sstable_t *sst, const uint8_t *key, size_t key_size, uint8_t **value,
                size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                uint8_t *deleted)
{
    return sstable_get_at_seq(sst, key, key_size, UINT64_MAX, value, value_size, vlog_offset, seq,
                              ttl, deleted);
}

int sstable_sync_klog(sstable_t *sst)
{
    if (!sst) return TDB_ERR_INVALID_ARGS;

    /* only a resident klog needs syncing; an evicted one was closed, settling its durability then,
     * so there is nothing to force here */
    block_manager_t *bm = atomic_load_explicit(&sst->klog_bm, memory_order_acquire);
    if (!bm) return TDB_SUCCESS;
    return block_manager_escalate_fsync(bm) == 0 ? TDB_SUCCESS : TDB_ERR_IO;
}

/* the bidirectional cursor over one sstable, opened once and reused; the borrowed btree reads the
 * klog either through the node cache or straight from the file */
struct sstable_iter
{
    btree_t *tree;
    btree_cursor_t *cursor;
    /* the sstable's clock rather than the sstable, so the cursor holds no second handle on a
     * refcounted object it does not own */
    _Atomic(int64_t) *now;
    /* and the intervals it carries, borrowed on the same terms -- the caller holds the table open
     * for as long as this cursor lives, so the set outlives it */
    const range_tombstone_set_t *intervals;
};

const range_tombstone_set_t *sstable_iter_intervals(const sstable_iter_t *it)
{
    return it ? it->intervals : NULL;
}
static int64_t sstable_iter_now(const sstable_iter_t *it)
{
    return sstable_clock_read(it->now);
}

int sstable_iter_new(sstable_t *sst, const int use_cache, sstable_iter_t **out)
{
    if (!sst || !out) return TDB_ERR_INVALID_ARGS;

    const int already_open = atomic_load_explicit(&sst->klog_bm, memory_order_acquire) != NULL;
    if (sst->fdm && !fd_manager_reader_budget_ok(sst->fdm, already_open)) return TDB_ERR_BUSY;

    sstable_iter_t *it = calloc(1, sizeof(*it));
    if (!it) return TDB_ERR_MEMORY;

    const int open_rc = sstable_open_tree(sst, use_cache, &it->tree);
    if (open_rc != TDB_SUCCESS)
    {
        free(it);
        return open_rc;
    }
    if (btree_cursor_init(&it->cursor, it->tree) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "btree cursor init failed on %s", sst->klog_path);
        btree_free(it->tree);
        free(it);
        return TDB_ERR_IO;
    }
    it->now = sst->now;
    it->intervals = sst->range_tombstones;
    atomic_store_explicit(&sst->last_access_time, sstable_now(sst), memory_order_relaxed);

    *out = it;
    return TDB_SUCCESS;
}

int sstable_iter_seek(sstable_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_seek(it->cursor, key, key_size) == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_iter_seek_for_prev(sstable_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_seek_for_prev(it->cursor, key, key_size) == 0 ? TDB_SUCCESS
                                                                      : TDB_ERR_NOT_FOUND;
}

int sstable_iter_seek_first(sstable_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_goto_first(it->cursor) == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_iter_seek_last(sstable_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_goto_last(it->cursor) == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_iter_next(sstable_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_next(it->cursor) == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_iter_prev(sstable_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    return btree_cursor_prev(it->cursor) == 0 ? TDB_SUCCESS : TDB_ERR_NOT_FOUND;
}

int sstable_iter_valid(sstable_iter_t *it)
{
    if (!it) return 0;
    return btree_cursor_valid(it->cursor) == 1;
}

int sstable_iter_read_failed(const sstable_iter_t *it)
{
    if (!it) return 0;
    return btree_cursor_read_failed(it->cursor);
}

int sstable_iter_get(sstable_iter_t *it, uint8_t **key, size_t *key_size, uint8_t **value,
                     size_t *value_size, uint64_t *vlog_offset, uint64_t *seq, int64_t *ttl,
                     uint8_t *deleted)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    if (btree_cursor_get(it->cursor, key, key_size, value, value_size, vlog_offset, seq, ttl,
                         deleted) != 0)
        return TDB_ERR_NOT_FOUND;

    /* scans and the compaction merge read through here, so a lapsed entry becomes a tombstone for
     * both -- hidden from an iterator, and carried into the merge as the tombstone whose collection
     * is what finally reclaims it. the value is the cursor's to own, so it is dropped from this
     * answer rather than freed */
    if (!*deleted && sstable_entry_expired(*ttl, sstable_iter_now(it)))
    {
        *value = NULL;
        *value_size = 0;
        *vlog_offset = 0;
        *deleted = 1;
    }
    return TDB_SUCCESS;
}

void sstable_iter_free(sstable_iter_t *it)
{
    if (!it) return;
    btree_cursor_free(it->cursor);
    btree_free(it->tree);
    free(it);
}
