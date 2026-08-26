/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_CACHE_H__
#define __TIDESDB_CACHE_H__

#include "compat.h" /* fixed-width ints, size_t */

/* the db-global block cache. one bounded memory pool behind the sstable read path -- a btree node,
 * a partition-range filter partition, any raw block the klog reader fetches. the value log does not
 * read through it: a value is read once and is large, so caching values evicts the btree nodes that
 * are read repeatedly, and the budget buys more as index than as data. it is keyed by (file_id,
 * offset): the 64-bit id of the owning file and the block's byte offset, which together name one
 * block unambiguously. entries live in fixed per-shard slot arrays and are never freed while a
 * reader holds them; only their payloads are reclaimed, each by its own reclaim function, so parsed
 * nodes and raw byte blocks share one cache.
 *
 * reads are lock-free (probe, pin with the shared lock-free refcount, recheck); writes take a
 * per-shard lock. a payload is reclaimed exactly once, on whichever thread drops its last
 * reference, whether that is an evictor or the last reader -- the same reclamation discipline the
 * whole engine uses via base/lockfree, no bespoke scheme. */

typedef struct cache cache_t;

/* an opaque pin returned by a hit; the payload it points at stays valid until the pin is released
 */
typedef struct cache_entry cache_entry_t;

/**
 * cache_reclaim_fn
 * free one entry's payload, run once on the last reference drop; parsed nodes and raw blocks each
 * supply their own, which is how a single cache holds mixed payload types
 * @param payload the payload to reclaim
 * @param ctx opaque context supplied at insert
 */
typedef void (*cache_reclaim_fn)(void *payload, void *ctx);

/**
 * cache_config_t
 * cache sizing, all fields optional (0 selects a derived default)
 * @param capacity_bytes total byte budget across all shards; entries are evicted to stay under it
 * @param shard_count number of independent shards, rounded to a power of two (0 derives from cpu
 * count)
 * @param slots_per_shard fixed slots per shard, rounded to a power of two (0 derives from capacity)
 */
typedef struct
{
    size_t capacity_bytes;
    int shard_count;
    int slots_per_shard;
} cache_config_t;

/**
 * cache_stats_t
 * a snapshot of cache counters
 * @param hits get calls that found a live entry
 * @param misses get calls that found nothing
 * @param evictions entries evicted to reclaim space
 * @param bytes_used current live payload bytes charged against the budget
 * @param entries current live entries
 * @param shard_count the number of independent shards the cache is partitioned into
 */
typedef struct
{
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t bytes_used;
    uint64_t entries;
    uint64_t shard_count;
} cache_stats_t;

/**
 * cache_create
 * create a cache with the given configuration
 * @param config sizing configuration, or NULL for all defaults
 * @return the cache, or NULL on allocation failure
 */
cache_t *cache_create(const cache_config_t *config);

/**
 * cache_destroy
 * free the cache and reclaim every live payload; the caller must ensure no other thread is still
 * using the cache -- it does not drain readers
 * @param cache the cache, may be NULL
 */
void cache_destroy(cache_t *cache);

/**
 * cache_get
 * look up a block and pin it; on a hit the caller must release the pin when done with the payload
 * @param cache the cache
 * @param file_id id of the owning file
 * @param offset byte offset of the block
 * @param payload out -- the pinned payload on a hit, untouched on a miss
 * @param payload_len out -- the payload length on a hit (may be NULL)
 * @param pin out -- the pin to release on a hit, untouched on a miss
 * @return 1 on a hit, 0 on a miss
 */
int cache_get(cache_t *cache, uint64_t file_id, uint64_t offset, void **payload,
              size_t *payload_len, cache_entry_t **pin);

/**
 * cache_put
 * insert a block under (file_id, offset), taking ownership of payload via reclaim; if the key
 * already exists the existing entry is kept and the caller's payload is reclaimed instead, so
 * concurrent puts of the same block are idempotent. on success the entry is pinned and returned so
 * the caller can use it immediately without a follow-up get
 * @param cache the cache
 * @param file_id id of the owning file
 * @param offset byte offset of the block
 * @param payload the payload to cache, reclaimed by reclaim when evicted (or now, if the key
 * existed)
 * @param payload_len the payload length
 * @param cost byte weight charged against the budget (typically payload_len plus overhead)
 * @param reclaim the payload's reclaim function
 * @param ctx opaque context passed to reclaim
 * @param pin out -- the pin to release when done (may be NULL to insert without pinning)
 * @return 1 if the payload is now cached (or the key already was) and pinned, 0 if it could not be
 *         cached (no slot could be freed). ownership of payload transfers on every outcome -- a
 *         duplicate insert and a failed insert both reclaim it here -- so the caller must never
 *         reclaim it itself
 */
int cache_put(cache_t *cache, uint64_t file_id, uint64_t offset, void *payload, size_t payload_len,
              size_t cost, cache_reclaim_fn reclaim, void *ctx, cache_entry_t **pin);

/**
 * cache_release
 * release a pin from cache_get or cache_put; when the last reference to an evicted entry drops, its
 * payload is reclaimed here
 * @param pin the pin to release, may be NULL
 */
void cache_release(cache_entry_t *pin);

/**
 * cache_get_stats
 * snapshot the cache counters
 * @param cache the cache
 * @param stats out -- the counters
 */
void cache_get_stats(cache_t *cache, cache_stats_t *stats);

#endif /* __TIDESDB_CACHE_H__ */
