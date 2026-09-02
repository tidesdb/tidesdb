/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "cache.h"

#include <stdlib.h>
#include <string.h>

#include "base/lockfree.h" /* tdb_refcount_t, the shared pin discipline, and cpu_pause via compat */
#include "base/log.h"
#include "xxhash.h" /* XXH3 for the (file_id, offset) key hash */

/* default byte budget when the caller supplies none */
#define CACHE_DEFAULT_CAPACITY_BYTES (64ull * 1024 * 1024)

/* shards per cpu when the caller names no shard count, and the range the result is clamped to. one
 * shard per cpu still collides often enough to serialize inserts, since a shard is picked by key
 * hash rather than by thread, so the default oversubscribes; the ceiling keeps a many-cpu machine
 * from allocating an unbounded shard array */
#define CACHE_SHARDS_PER_CPU 4
#define CACHE_MIN_SHARDS     16
#define CACHE_MAX_SHARDS     512

/* the entry size the frame count is derived against when the caller names no slot count. slots are
 * fixed per shard, so too few make the slot count bind before the byte budget does and the cache
 * plateaus well under its capacity, silently -- the budget still reads as configured while the
 * cache holds a fraction of it. sizing against a nominal block keeps the budget the binding limit
 * for typically sized entries.
 *
 * the floor keeps a tiny cache usable. the ceiling is a guard against absurd arithmetic, not a
 * policy: a frame's metadata is a fixed fraction of the entry it tracks, so the array cannot grow
 * out of proportion to the budget it serves on its own. how long an insert may hold the shard lock
 * hunting a victim is a different question, and it is bounded separately below -- conflating the
 * two is what capped the cache at a quarter of its configured size */
#define CACHE_NOMINAL_ENTRY_BYTES  4096
#define CACHE_MIN_FRAMES_PER_SHARD 1024
/* the largest power of two the bucket's index field can address without reaching its two reserved
 * values, which at the nominal entry size is sixteen gibibytes of payload in a single shard */
#define CACHE_MAX_FRAMES_PER_SHARD (1 << (CACHE_BUCKET_INDEX_BITS - 1))

/* the bucket table is this multiple of the frame count so the open-addressed lookup stays low-load
 */
#define CACHE_BUCKETS_PER_FRAME 2

/* the hash's low bits pick the shard; this higher slice picks the bucket probe start, so shard and
 * bucket selection draw on disjoint bits of the same hash */
#define CACHE_BUCKET_HASH_SHIFT 32

/* a bucket packs a frame index in its low bits and a hash tag above it, in one 32-bit word. the tag
 * is what keeps a probe off the frame array: a bucket whose tag differs cannot hold this key, so it
 * is rejected from the bucket word alone, and only a tag match pays the frame's cache miss. the
 * frame's full key is still compared afterwards, so a tag collision costs a wasted touch and never
 * a wrong answer */
#define CACHE_BUCKET_INDEX_BITS 23
#define CACHE_BUCKET_INDEX_MASK ((1u << CACHE_BUCKET_INDEX_BITS) - 1u)
#define CACHE_BUCKET_TAG_MASK   0xFFu

/* the index field's two reserved values; a read probe stops at EMPTY and skips a TOMBSTONE, so an
 * evicted key never truncates the probe chain of a key hashed past it. they live in the index field
 * rather than the whole word so no tag can spell one, which is why the frame cap is one below the
 * range the field can address */
#define CACHE_BUCKET_EMPTY     CACHE_BUCKET_INDEX_MASK
#define CACHE_BUCKET_TOMBSTONE (CACHE_BUCKET_INDEX_MASK - 1u)

/* the slice of the hash the tag is cut from, disjoint from the low bits that pick the shard and the
 * higher slice that picks the bucket probe start */
#define CACHE_BUCKET_TAG_SHIFT 24

/* frame lifecycle: FREE is reusable, LIVE is a gettable entry, DYING is evicted but still pinned by
 * a reader whose release will reclaim the payload and return the frame to FREE */
#define CACHE_FRAME_FREE  0
#define CACHE_FRAME_LIVE  1
#define CACHE_FRAME_DYING 2

/* the reference a live entry carries for the cache itself; a reader pin adds one more on top */
#define CACHE_REF_BASELINE 1

/* how many frames one insert may examine hunting a victim. an absolute bound rather than a multiple
 * of the frame count, because this limits how long the shard lock is held and that must not grow
 * with how much the shard can hold. the clock exits at the first evictable frame, so this is only
 * reached when nearly every frame is pinned or freshly referenced -- and the hand persists across
 * calls, so giving up here resumes rather than restarts */
#define CACHE_CLOCK_MAX_EXAMINATIONS 512

/* the spinlock's two states */
#define CACHE_LOCK_FREE 0
#define CACHE_LOCK_HELD 1

typedef struct cache_shard cache_shard_t;

/* a per-shard write lock built on the engine's atomics rather than a platform mutex, so the module
 * carries no unchecked lock return and stays on the shared primitive set */
typedef _Atomic(int) cache_spinlock_t;

/* attempts spent pausing before a waiter yields its core instead. an insert that has to evict walks
 * the shard clock while holding the lock, so the hold is bounded but not brief, and when there are
 * more runnable threads than cores the holder can be descheduled mid-sweep -- pausing forever then
 * burns every waiter's whole timeslice waiting for a thread that is not running. yielding hands the
 * core back so the holder can finish */
#define CACHE_LOCK_SPIN_ATTEMPTS 64

/* acquire the write lock, pausing between attempts and yielding once a holder looks descheduled */
static void cache_lock(cache_spinlock_t *lock)
{
    int expected = CACHE_LOCK_FREE;
    int attempts = 0;
    while (!atomic_compare_exchange_weak_explicit(lock, &expected, CACHE_LOCK_HELD,
                                                  memory_order_acquire, memory_order_relaxed))
    {
        expected = CACHE_LOCK_FREE;
        if (++attempts < CACHE_LOCK_SPIN_ATTEMPTS)
        {
            cpu_pause();
            continue;
        }
        cpu_yield();
        attempts = 0;
    }
}

/* release the write lock */
static void cache_unlock(cache_spinlock_t *lock)
{
    atomic_store_explicit(lock, CACHE_LOCK_FREE, memory_order_release);
}

/**
 * cache_entry
 * one frame, both a cache slot and the pin handle a get or put hands back; the mutable fields are
 * atomic because a lock-free reader reads them while a writer under the shard lock sets them
 * @param file_id owning file id of the cached block
 * @param offset byte offset of the cached block
 * @param payload the cached bytes or object, reclaimed by reclaim
 * @param payload_len length reported to a getter
 * @param cost byte weight charged against the shard budget
 * @param reclaim the payload's reclaim function, run once on the last reference drop
 * @param reclaim_ctx context passed to reclaim
 * @param rc reference count, 0 free/reclaimed, CACHE_REF_BASELINE live, plus one per reader pin
 * @param ref_bit clock second-chance bit, set on access and cleared by the sweep
 * @param state CACHE_FRAME_FREE, LIVE, or DYING
 * @param shard the owning shard, constant after init
 */
struct cache_entry
{
    _Atomic(uint64_t) file_id;
    _Atomic(uint64_t) offset;
    _Atomic(void *) payload;
    _Atomic(size_t) payload_len;
    _Atomic(size_t) cost;
    _Atomic(cache_reclaim_fn) reclaim;
    _Atomic(void *) reclaim_ctx;
    tdb_refcount_t rc;
    _Atomic(uint8_t) ref_bit;
    _Atomic(uint8_t) state;
    cache_shard_t *shard;
};

/**
 * cache_shard
 * one independent partition: a fixed frame array clock-swept for eviction, a bucket table mapping
 * keys to frame indices for lookup, and the byte accounting and stats for its slice of the budget
 * @param lock write lock for put and eviction; reads are lock-free
 * @param frames the frame array of num_frames entries
 * @param buckets the lookup table of num_buckets words, each a hash tag over a frame index
 * @param num_frames frame count, a power of two
 * @param num_buckets bucket count, a power of two
 * @param frame_mask num_frames - 1
 * @param bucket_mask num_buckets - 1
 * @param capacity_bytes this shard's slice of the byte budget
 * @param bytes_used current live payload bytes
 * @param clock_hand eviction sweep position, advanced under the lock
 * @param hits gets that found a live entry
 * @param misses gets that found nothing
 * @param evictions entries evicted
 * @param entries current live entries
 */
struct cache_shard
{
    cache_spinlock_t lock;
    cache_entry_t *frames;
    _Atomic(uint32_t) *buckets;
    int num_frames;
    int num_buckets;
    int frame_mask;
    int bucket_mask;
    size_t capacity_bytes;
    _Atomic(size_t) bytes_used;
    size_t clock_hand;
    _Atomic(uint64_t) hits;
    _Atomic(uint64_t) misses;
    _Atomic(uint64_t) evictions;
    _Atomic(uint64_t) entries;
};

/**
 * cache
 * the db-global cache, a fixed array of independent shards selected by the key hash
 * @param shards the shard array
 * @param shard_count number of shards, a power of two
 * @param shard_mask shard_count - 1
 */
struct cache
{
    cache_shard_t *shards;
    int shard_count;
    int shard_mask;
};

/* hash the two key words into a well-distributed 64-bit value; the low bits pick the shard and a
 * higher slice picks the bucket probe start */
static uint64_t cache_hash(const uint64_t file_id, const uint64_t offset)
{
    const uint64_t key[2] = {file_id, offset};
    return XXH3_64bits(key, sizeof(key));
}

/* round up to a power of two, minimum one */
static int cache_round_pow2(int v)
{
    int p = 1;
    while (p < v) p <<= 1;
    return p;
}

/* the bucket probe start for a hash within a shard */
static int cache_bucket_start(const cache_shard_t *shard, const uint64_t h)
{
    return (int)((h >> CACHE_BUCKET_HASH_SHIFT) & (uint64_t)shard->bucket_mask);
}

/* the tag a hash carries in its bucket word */
static uint32_t cache_bucket_tag(const uint64_t h)
{
    return (uint32_t)((h >> CACHE_BUCKET_TAG_SHIFT) & CACHE_BUCKET_TAG_MASK);
}

/* the frame index a bucket word points at, or one of the two reserved values */
static uint32_t cache_bucket_index(const uint32_t word)
{
    return word & CACHE_BUCKET_INDEX_MASK;
}

/* combine a tag and a frame index into the word a bucket stores */
static uint32_t cache_bucket_pack(const uint32_t tag, const int frame_idx)
{
    return (tag << CACHE_BUCKET_INDEX_BITS) | (uint32_t)frame_idx;
}

/* reclaim a frame's payload exactly once and return the frame to FREE; runs on the last reference
 * drop, on whichever thread observed it. safe without the shard lock -- every field it touches is
 * atomic and the FREE store publishes the completed reclaim to a locked reuse. */
static void cache_frame_reclaim(cache_entry_t *frame)
{
    cache_shard_t *shard = frame->shard;
    cache_reclaim_fn reclaim = atomic_load_explicit(&frame->reclaim, memory_order_acquire);
    void *payload = atomic_load_explicit(&frame->payload, memory_order_acquire);
    void *ctx = atomic_load_explicit(&frame->reclaim_ctx, memory_order_acquire);
    const size_t cost = atomic_load_explicit(&frame->cost, memory_order_relaxed);

    if (reclaim) reclaim(payload, ctx);
    atomic_store_explicit(&frame->payload, NULL, memory_order_relaxed);
    atomic_fetch_sub_explicit(&shard->bytes_used, cost, memory_order_relaxed);
    atomic_fetch_sub_explicit(&shard->entries, 1, memory_order_relaxed);
    atomic_store_explicit(&frame->state, CACHE_FRAME_FREE, memory_order_release);
}

int cache_get(cache_t *cache, uint64_t file_id, uint64_t offset, void **payload,
              size_t *payload_len, cache_entry_t **pin)
{
    if (!cache || !payload || !pin) return 0;

    const uint64_t h = cache_hash(file_id, offset);
    cache_shard_t *shard = &cache->shards[h & (uint64_t)cache->shard_mask];
    const int start = cache_bucket_start(shard, h);
    const uint32_t tag = cache_bucket_tag(h);

    for (int k = 0; k <= shard->bucket_mask; k++)
    {
        const int b = (start + k) & shard->bucket_mask;
        const uint32_t word = atomic_load_explicit(&shard->buckets[b], memory_order_acquire);
        const uint32_t fi = cache_bucket_index(word);
        if (fi == CACHE_BUCKET_EMPTY) break; /* probe chain ends -> miss */
        if (fi == CACHE_BUCKET_TOMBSTONE) continue;
        /* the tag settles it from this word alone, leaving the frame untouched on a mismatch */
        if ((word >> CACHE_BUCKET_INDEX_BITS) != tag) continue;

        cache_entry_t *frame = &shard->frames[fi];
        if (atomic_load_explicit(&frame->file_id, memory_order_relaxed) != file_id ||
            atomic_load_explicit(&frame->offset, memory_order_relaxed) != offset)
            continue;

        if (!tdb_try_ref(&frame->rc)) continue; /* being reclaimed */

        /* recheck under the pin -- the frame may have been evicted and recycled since the bucket
         * read */
        if (atomic_load_explicit(&frame->state, memory_order_acquire) == CACHE_FRAME_LIVE &&
            atomic_load_explicit(&frame->file_id, memory_order_relaxed) == file_id &&
            atomic_load_explicit(&frame->offset, memory_order_relaxed) == offset)
        {
            atomic_store_explicit(&frame->ref_bit, 1, memory_order_relaxed);
            /* outside the shard lock, like the frame's own bit -- both are hints the sweep reads,
             * and a lost update only costs an entry its second chance */
            *payload = atomic_load_explicit(&frame->payload, memory_order_acquire);
            if (payload_len)
                *payload_len = atomic_load_explicit(&frame->payload_len, memory_order_relaxed);
            *pin = frame;
            atomic_fetch_add_explicit(&shard->hits, 1, memory_order_relaxed);
            return 1;
        }
        if (tdb_unref(&frame->rc)) cache_frame_reclaim(frame);
    }

    atomic_fetch_add_explicit(&shard->misses, 1, memory_order_relaxed);
    return 0;
}

/* tombstone the bucket mapping that points at frame_idx for the given key; the shard lock is held
 */
static void cache_bucket_remove(cache_shard_t *shard, const uint64_t h, int frame_idx)
{
    const int start = cache_bucket_start(shard, h);
    for (int k = 0; k <= shard->bucket_mask; k++)
    {
        const int b = (start + k) & shard->bucket_mask;
        const uint32_t fi =
            cache_bucket_index(atomic_load_explicit(&shard->buckets[b], memory_order_relaxed));
        if (fi == CACHE_BUCKET_EMPTY) return;
        if (fi == (uint32_t)frame_idx)
        {
            atomic_store_explicit(&shard->buckets[b], CACHE_BUCKET_TOMBSTONE, memory_order_release);
            return;
        }
    }
}

/* map frame_idx into the first empty or tombstone bucket of the key's probe chain; the shard lock
 * is held */
static void cache_bucket_insert(cache_shard_t *shard, const uint64_t h, int frame_idx)
{
    const int start = cache_bucket_start(shard, h);
    for (int k = 0; k <= shard->bucket_mask; k++)
    {
        const int b = (start + k) & shard->bucket_mask;
        const uint32_t fi =
            cache_bucket_index(atomic_load_explicit(&shard->buckets[b], memory_order_relaxed));
        if (fi == CACHE_BUCKET_EMPTY || fi == CACHE_BUCKET_TOMBSTONE)
        {
            atomic_store_explicit(&shard->buckets[b],
                                  cache_bucket_pack(cache_bucket_tag(h), frame_idx),
                                  memory_order_release);
            return;
        }
    }
}

/* evict a LIVE frame: drop its bucket mapping and its baseline reference, reclaiming the payload
 * now if no reader holds it (returning the frame to FREE) or deferring to the last reader. the
 * shard lock is held. */
static void cache_evict_frame(cache_shard_t *shard, cache_entry_t *frame)
{
    const uint64_t h = cache_hash(atomic_load_explicit(&frame->file_id, memory_order_relaxed),
                                  atomic_load_explicit(&frame->offset, memory_order_relaxed));
    const int frame_idx = (int)(frame - shard->frames);

    cache_bucket_remove(shard, h, frame_idx);
    atomic_store_explicit(&frame->state, CACHE_FRAME_DYING, memory_order_release);
    atomic_fetch_add_explicit(&shard->evictions, 1, memory_order_relaxed);
    if (tdb_unref(&frame->rc)) cache_frame_reclaim(frame);
}

/* run the clock hand evicting LIVE victims whose ref bit is clear until the shard's live bytes
 * leave room for `needed`, or the examination bound is reached; the shard lock is held. stopping
 * short leaves the shard over its budget, which the next insert continues from -- the hand
 * persists, so the bound paces the work rather than abandoning it */
static void cache_evict_for_bytes(cache_shard_t *shard, size_t needed)
{
    const int limit = CACHE_CLOCK_MAX_EXAMINATIONS;
    for (int swept = 0;
         swept < limit && atomic_load_explicit(&shard->bytes_used, memory_order_relaxed) + needed >
                              shard->capacity_bytes;
         swept++)
    {
        const int idx = (int)(shard->clock_hand & (uint64_t)shard->frame_mask);
        shard->clock_hand++;
        /* the whole decision is this one byte, and consecutive frames share a cache line, so a pass
         * that finds nothing to evict costs a fraction of what walking the frames costs */
        cache_entry_t *frame = &shard->frames[idx];
        if (atomic_load_explicit(&frame->state, memory_order_acquire) != CACHE_FRAME_LIVE) continue;
        if (atomic_load_explicit(&frame->ref_bit, memory_order_relaxed))
        {
            atomic_store_explicit(&frame->ref_bit, 0, memory_order_relaxed);
            continue; /* second chance */
        }
        cache_evict_frame(shard, frame);
    }
}

/* find a FREE frame for a new entry, running the clock hand and evicting LIVE victims with a
 * cleared ref bit; returns a frame index, or -1 when no victim turned up within the examination
 * bound -- which a caller treats as "do not cache this entry" rather than as an error, since the
 * hand persists and the next insert resumes where this one stopped. the shard lock is held. */
static int cache_alloc_frame(cache_shard_t *shard)
{
    const int limit = CACHE_CLOCK_MAX_EXAMINATIONS;
    for (int i = 0; i < limit; i++)
    {
        const int idx = (int)(shard->clock_hand & (uint64_t)shard->frame_mask);
        shard->clock_hand++;
        /* the same one-byte read as the evict sweep, for the same reason -- this walk is the one a
         * miss pays, so it is the one that must not chase 72-byte frames through cold memory */
        const unsigned char st =
            atomic_load_explicit(&shard->frames[idx].state, memory_order_acquire);

        if (st == CACHE_FRAME_FREE) return idx;
        if (st != CACHE_FRAME_LIVE) continue; /* DYING -- a reader still holds it */

        if (atomic_load_explicit(&shard->frames[idx].ref_bit, memory_order_relaxed))
        {
            atomic_store_explicit(&shard->frames[idx].ref_bit, 0, memory_order_relaxed);
            continue; /* second chance */
        }
        cache_evict_frame(shard, &shard->frames[idx]);
        if (atomic_load_explicit(&shard->frames[idx].state, memory_order_acquire) ==
            CACHE_FRAME_FREE)
            return idx; /* reclaimed immediately, reuse it */
    }
    return -1;
}

/* return the live frame already holding this key, or NULL; the shard lock is held */
static cache_entry_t *cache_find_locked(cache_shard_t *shard, const uint64_t h, uint64_t file_id,
                                        uint64_t offset)
{
    const int start = cache_bucket_start(shard, h);
    const uint32_t tag = cache_bucket_tag(h);
    for (int k = 0; k <= shard->bucket_mask; k++)
    {
        const int b = (start + k) & shard->bucket_mask;
        const uint32_t word = atomic_load_explicit(&shard->buckets[b], memory_order_relaxed);
        const uint32_t fi = cache_bucket_index(word);
        if (fi == CACHE_BUCKET_EMPTY) return NULL;
        if (fi == CACHE_BUCKET_TOMBSTONE) continue;
        if ((word >> CACHE_BUCKET_INDEX_BITS) != tag) continue;
        cache_entry_t *e = &shard->frames[fi];
        if (atomic_load_explicit(&e->state, memory_order_relaxed) == CACHE_FRAME_LIVE &&
            atomic_load_explicit(&e->file_id, memory_order_relaxed) == file_id &&
            atomic_load_explicit(&e->offset, memory_order_relaxed) == offset)
            return e;
    }
    return NULL;
}

int cache_put(cache_t *cache, uint64_t file_id, uint64_t offset, void *payload, size_t payload_len,
              size_t cost, cache_reclaim_fn reclaim, void *ctx, cache_entry_t **pin)
{
    if (!cache || !payload || !reclaim)
    {
        if (reclaim) reclaim(payload, ctx);
        return 0;
    }

    const uint64_t h = cache_hash(file_id, offset);
    cache_shard_t *shard = &cache->shards[h & (uint64_t)cache->shard_mask];

    cache_lock(&shard->lock);

    /* if the key already lives here, keep it and reclaim the caller's duplicate payload */
    cache_entry_t *existing = cache_find_locked(shard, h, file_id, offset);
    if (existing)
    {
        tdb_ref(&existing->rc);
        atomic_store_explicit(&existing->ref_bit, 1, memory_order_relaxed);
        cache_unlock(&shard->lock);
        reclaim(payload, ctx);
        if (pin)
            *pin = existing;
        else if (tdb_unref(&existing->rc))
            cache_frame_reclaim(existing);
        return 1;
    }

    cache_evict_for_bytes(shard, cost);

    const int idx = cache_alloc_frame(shard);
    if (idx < 0)
    {
        cache_unlock(&shard->lock);
        reclaim(payload, ctx); /* could not cache; hand the payload back for reclamation */
        return 0;
    }

    cache_entry_t *frame = &shard->frames[idx];
    atomic_store_explicit(&frame->file_id, file_id, memory_order_relaxed);
    atomic_store_explicit(&frame->offset, offset, memory_order_relaxed);
    atomic_store_explicit(&frame->payload, payload, memory_order_relaxed);
    atomic_store_explicit(&frame->payload_len, payload_len, memory_order_relaxed);
    atomic_store_explicit(&frame->cost, cost, memory_order_relaxed);
    atomic_store_explicit(&frame->reclaim, reclaim, memory_order_relaxed);
    atomic_store_explicit(&frame->reclaim_ctx, ctx, memory_order_relaxed);
    atomic_store_explicit(&frame->ref_bit, 1, memory_order_relaxed);
    /* one baseline reference for the cache, plus a reader reference when the caller wants a pin */
    atomic_store_explicit(&frame->rc, pin ? CACHE_REF_BASELINE + 1 : CACHE_REF_BASELINE,
                          memory_order_relaxed);
    atomic_fetch_add_explicit(&shard->bytes_used, cost, memory_order_relaxed);
    atomic_fetch_add_explicit(&shard->entries, 1, memory_order_relaxed);
    /* publish LIVE last so a lock-free reader that pins the frame sees every field above */
    atomic_store_explicit(&frame->state, CACHE_FRAME_LIVE, memory_order_release);

    cache_bucket_insert(shard, h, idx);
    cache_unlock(&shard->lock);

    if (pin) *pin = frame;
    return 1;
}

void cache_release(cache_entry_t *pin)
{
    if (!pin) return;
    if (tdb_unref(&pin->rc)) cache_frame_reclaim(pin);
}

void cache_get_stats(cache_t *cache, cache_stats_t *stats)
{
    if (!cache || !stats) return;
    memset(stats, 0, sizeof(*stats));
    stats->shard_count = (uint64_t)cache->shard_count;
    for (int s = 0; s < cache->shard_count; s++)
    {
        cache_shard_t *shard = &cache->shards[s];
        stats->hits += atomic_load_explicit(&shard->hits, memory_order_relaxed);
        stats->misses += atomic_load_explicit(&shard->misses, memory_order_relaxed);
        stats->evictions += atomic_load_explicit(&shard->evictions, memory_order_relaxed);
        stats->bytes_used += atomic_load_explicit(&shard->bytes_used, memory_order_relaxed);
        stats->entries += atomic_load_explicit(&shard->entries, memory_order_relaxed);
    }
}

/* free a shard's arrays */
static void cache_shard_destroy(cache_shard_t *shard)
{
    free(shard->frames);
    free((void *)shard->buckets);
}

/**
 * cache_derive_shards
 * pick a shard count for the running machine when the caller names none, so inserts spread across
 * independent locks instead of serializing on a fixed few
 * @return the shard count, clamped to the supported range
 */
static int cache_derive_shards(void)
{
    const int cpus = tdb_get_cpu_count();
    const int derived = cpus > 0 ? cpus * CACHE_SHARDS_PER_CPU : CACHE_MIN_SHARDS;

    if (derived < CACHE_MIN_SHARDS) return CACHE_MIN_SHARDS;
    if (derived > CACHE_MAX_SHARDS) return CACHE_MAX_SHARDS;
    return derived;
}

/**
 * cache_derive_frames
 * pick a per-shard frame count for a byte budget, so a caller who sizes the cache in bytes gets
 * enough slots for that budget to actually be reachable
 * @param capacity the total byte budget across all shards
 * @param shard_count the number of shards the budget is split across
 * @return the per-shard frame count, clamped to the supported range
 */
static int cache_derive_frames(const size_t capacity, const int shard_count)
{
    const size_t per_shard = capacity / (size_t)shard_count;
    const size_t derived = per_shard / CACHE_NOMINAL_ENTRY_BYTES;

    if (derived < CACHE_MIN_FRAMES_PER_SHARD) return CACHE_MIN_FRAMES_PER_SHARD;
    if (derived > CACHE_MAX_FRAMES_PER_SHARD) return CACHE_MAX_FRAMES_PER_SHARD;
    return (int)derived;
}

/* initialize a shard's frames and buckets; returns 0 on success, -1 on allocation failure */
static int cache_shard_init(cache_shard_t *shard, const int num_frames, const size_t capacity)
{
    shard->num_frames = num_frames;
    shard->num_buckets = num_frames * CACHE_BUCKETS_PER_FRAME;
    shard->frame_mask = num_frames - 1;
    shard->bucket_mask = shard->num_buckets - 1;
    shard->capacity_bytes = capacity;
    shard->clock_hand = 0;
    atomic_init(&shard->lock, CACHE_LOCK_FREE);
    atomic_init(&shard->bytes_used, 0);
    atomic_init(&shard->hits, 0);
    atomic_init(&shard->misses, 0);
    atomic_init(&shard->evictions, 0);
    atomic_init(&shard->entries, 0);

    shard->frames = calloc((size_t)num_frames, sizeof(*shard->frames));
    shard->buckets = calloc((size_t)shard->num_buckets, sizeof(*shard->buckets));
    if (!shard->frames || !shard->buckets)
    {
        free(shard->frames);
        free((void *)shard->buckets);
        return -1;
    }

    for (int i = 0; i < num_frames; i++)
    {
        atomic_init(&shard->frames[i].rc, 0);
        atomic_init(&shard->frames[i].state, CACHE_FRAME_FREE);
        shard->frames[i].shard = shard;
    }
    for (int i = 0; i < shard->num_buckets; i++)
        atomic_init(&shard->buckets[i], CACHE_BUCKET_EMPTY);
    return 0;
}

cache_t *cache_create(const cache_config_t *config)
{
    const size_t capacity =
        (config && config->capacity_bytes) ? config->capacity_bytes : CACHE_DEFAULT_CAPACITY_BYTES;
    int shard_count = (config && config->shard_count) ? config->shard_count : cache_derive_shards();
    shard_count = cache_round_pow2(shard_count);
    if (shard_count > CACHE_MAX_SHARDS) shard_count = CACHE_MAX_SHARDS;

    int frames = (config && config->slots_per_shard) ? config->slots_per_shard
                                                     : cache_derive_frames(capacity, shard_count);
    frames = cache_round_pow2(frames);
    if (frames > CACHE_MAX_FRAMES_PER_SHARD) frames = CACHE_MAX_FRAMES_PER_SHARD;

    cache_t *cache = calloc(1, sizeof(*cache));
    if (!cache)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "block cache allocation failed");
        return NULL;
    }
    cache->shards = calloc((size_t)shard_count, sizeof(*cache->shards));
    if (!cache->shards)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "block cache could not allocate %d shards", shard_count);
        free(cache);
        return NULL;
    }
    cache->shard_count = shard_count;
    cache->shard_mask = shard_count - 1;

    const size_t raw = capacity / (size_t)shard_count;
    const size_t per_shard_capacity = raw ? raw : 1;
    for (int s = 0; s < shard_count; s++)
    {
        if (cache_shard_init(&cache->shards[s], frames, per_shard_capacity) != 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_ERROR, "block cache shard %d of %d failed to initialize", s,
                          shard_count);
            for (int j = 0; j < s; j++) cache_shard_destroy(&cache->shards[j]);
            free(cache->shards);
            free(cache);
            return NULL;
        }
    }

    /* the resolved geometry rather than the requested one -- shards and frames are both rounded to
     * a power of two and clamped, and a budget that reaches far fewer frames than the caller
     * intended is invisible from the configuration alone */
    TDB_DEBUG_LOG(TDB_LOG_INFO, "block cache %zu bytes over %d shards, %d frames each", capacity,
                  shard_count, frames);
    return cache;
}

void cache_destroy(cache_t *cache)
{
    if (!cache) return;
    for (int s = 0; s < cache->shard_count; s++)
    {
        cache_shard_t *shard = &cache->shards[s];
        for (int i = 0; i < shard->num_frames; i++)
        {
            cache_entry_t *frame = &shard->frames[i];
            const uint8_t st = atomic_load_explicit(&frame->state, memory_order_relaxed);
            if (st != CACHE_FRAME_LIVE && st != CACHE_FRAME_DYING) continue;
            cache_reclaim_fn reclaim = atomic_load_explicit(&frame->reclaim, memory_order_relaxed);
            void *payload = atomic_load_explicit(&frame->payload, memory_order_relaxed);
            void *ctx = atomic_load_explicit(&frame->reclaim_ctx, memory_order_relaxed);
            if (reclaim) reclaim(payload, ctx);
        }
        cache_shard_destroy(shard);
    }
    free(cache->shards);
    free(cache);
}
