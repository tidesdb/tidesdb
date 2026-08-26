/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "arena.h"

#include <stddef.h>
#include <stdlib.h>

/* default usable bytes per recycled chunk */
#define ARENA_DEFAULT_CHUNK_SIZE (64 * 1024)

/* default soft cap on idle chunk bytes the pool keeps across all shards */
#define ARENA_DEFAULT_MAX_CACHED (16 * 1024 * 1024)

/* independent free-list shards so arenas assigned to different shards never contend on recycle */
#define ARENA_POOL_SHARDS 16

/* the largest fundamental alignment; every chunk's usable region starts here and a smaller
 * requested alignment is satisfied within it without special handling */
#define ARENA_MAX_ALIGN _Alignof(max_align_t)

/* the pool free-list spinlock's two states */
#define ARENA_LOCK_FREE 0
#define ARENA_LOCK_HELD 1

/* per-thread slots in a concurrent arena; a thread claims a slot for its lifetime, and only threads
 * that collide onto the same slot (beyond this many live threads) serialize on that slot's lock */
#define ARENA_MAX_THREADS 256

typedef _Atomic(int) arena_spinlock_t;

/* acquire the recycle lock, pausing between attempts; contended only when two arenas share a shard
 */
static void arena_lock(arena_spinlock_t *lock)
{
    int expected = ARENA_LOCK_FREE;
    while (!atomic_compare_exchange_weak_explicit(lock, &expected, ARENA_LOCK_HELD,
                                                  memory_order_acquire, memory_order_relaxed))
    {
        expected = ARENA_LOCK_FREE;
        cpu_pause();
    }
}

static void arena_unlock(arena_spinlock_t *lock)
{
    atomic_store_explicit(lock, ARENA_LOCK_FREE, memory_order_release);
}

/* one chunk: a link for the arena's chunk list or the pool free list, its usable capacity, the bump
 * offset within it, and then `capacity` usable bytes following the header */
typedef struct arena_chunk
{
    struct arena_chunk *next;
    size_t capacity;
    size_t used;
} arena_chunk_t;

/* a slice of the pool's recycled chunks, its own lock so shards do not contend */
typedef struct
{
    arena_spinlock_t lock;
    arena_chunk_t *free_list;
    size_t cached_bytes;
    size_t max_cached_bytes;
} arena_pool_shard_t;

struct arena_pool
{
    size_t chunk_size;
    arena_pool_shard_t shards[ARENA_POOL_SHARDS];
};

/* one per-thread bump slot in a concurrent arena; its lock is held only across this thread's bump
 * and chunk pull, so distinct-slot threads never contend */
typedef struct
{
    arena_spinlock_t lock;
    arena_chunk_t *current;
} arena_slot_t;

/* the extra state a concurrent arena carries: per-thread slots, a shared push-only chunk list
 * walked once at reset/destroy, and an atomic byte total */
typedef struct
{
    arena_slot_t slots[ARENA_MAX_THREADS];
    _Atomic(arena_chunk_t *) all_chunks;
    _Atomic(size_t) total_used;
    _Atomic(size_t) total_reserved;
} arena_mt_t;

struct arena
{
    arena_pool_t *pool; /* NULL means allocate and free chunks directly, no recycling */
    unsigned shard;     /* the pool shard this arena's chunks recycle through */
    size_t chunk_size;  /* usable bytes in a standard chunk */
    arena_mt_t
        *mt; /* non-NULL for a concurrent arena, else the single-threaded state below is used */
    arena_chunk_t *current;
    arena_chunk_t
        *chunks; /* every chunk a single-threaded arena holds, freed on reset or destroy */
    size_t total_used;
    /* bytes the chunks occupy, which is what the process is actually holding. a bump allocator
     * rounds a request up to a whole chunk, so a consumer that must honour a memory budget -- the
     * block cache being the one that must -- has to charge this rather than total_used */
    size_t total_reserved;
};

/* a thread's stable slot index, claimed once from a global counter; arena-independent, so it never
 * caches an arena pointer and needs no aba generation guard */
static _Thread_local int t_arena_slot = -1;
static _Atomic(int) g_arena_slot_counter = 0;

static int arena_thread_slot(void)
{
    if (t_arena_slot < 0)
    {
        const int s = atomic_fetch_add_explicit(&g_arena_slot_counter, 1, memory_order_relaxed);
        t_arena_slot = s % ARENA_MAX_THREADS;
    }
    return t_arena_slot;
}

/* round v up to a power-of-two alignment a */
static size_t arena_align_up(void)
{
    const size_t v = sizeof(arena_chunk_t);
    const size_t a = ARENA_MAX_ALIGN;

    return (v + a - 1) & ~(a - 1);
}

/* aligned byte offset from the chunk start to its usable region */
static size_t arena_header_size(void)
{
    return arena_align_up();
}

/* allocate a chunk with the given usable capacity, freshly reset */
static arena_chunk_t *arena_chunk_alloc(const size_t capacity)
{
    arena_chunk_t *c = malloc(arena_header_size() + capacity);
    if (!c) return NULL;
    c->next = NULL;
    c->capacity = capacity;
    c->used = 0;
    return c;
}

/* bump aligned bytes out of a chunk, or NULL if it does not fit */
static void *arena_chunk_bump(arena_chunk_t *c, const size_t size, const size_t align)
{
    uint8_t *const base = (uint8_t *)c + arena_header_size();
    const uintptr_t cur = (uintptr_t)base + c->used;
    const uintptr_t aligned = (cur + (align - 1)) & ~((uintptr_t)align - 1);
    const size_t new_used = (size_t)(aligned - (uintptr_t)base) + size;
    if (new_used > c->capacity) return NULL;
    c->used = new_used;
    return (void *)aligned;
}

/* take a standard chunk from the arena's shard free list, or allocate one when the list is empty */
static arena_chunk_t *arena_pool_take(arena_pool_t *pool, const unsigned shard,
                                      const size_t chunk_size)
{
    if (pool)
    {
        arena_pool_shard_t *s = &pool->shards[shard];
        arena_lock(&s->lock);
        arena_chunk_t *c = s->free_list;
        if (c)
        {
            s->free_list = c->next;
            s->cached_bytes -= arena_header_size() + c->capacity;
        }
        arena_unlock(&s->lock);
        if (c)
        {
            c->used = 0;
            c->next = NULL;
            return c;
        }
    }
    return arena_chunk_alloc(chunk_size);
}

/* return a chunk to the pool if it is a standard chunk and the shard is under its cache cap,
 * otherwise free it to the OS (an oversized dedicated chunk always frees) */
static void arena_pool_give(arena_pool_t *pool, const unsigned shard, arena_chunk_t *c)
{
    if (pool && c->capacity == pool->chunk_size)
    {
        arena_pool_shard_t *s = &pool->shards[shard];
        const size_t chunk_bytes = arena_header_size() + c->capacity;
        arena_lock(&s->lock);
        if (s->cached_bytes + chunk_bytes <= s->max_cached_bytes)
        {
            c->next = s->free_list;
            s->free_list = c;
            s->cached_bytes += chunk_bytes;
            arena_unlock(&s->lock);
            return;
        }
        arena_unlock(&s->lock);
    }
    free(c);
}

/* return every chunk the arena holds and clear its list */
static void arena_release_chunks(arena_t *arena)
{
    arena_chunk_t *c = arena->chunks;
    while (c)
    {
        arena_chunk_t *const next = c->next;
        arena_pool_give(arena->pool, arena->shard, c);
        c = next;
    }
    arena->chunks = NULL;
    arena->current = NULL;
    arena->total_reserved = 0;
    arena->total_used = 0;
}

/* push a chunk onto the concurrent arena's shared list; push-only during allocation (the list is
 * only walked at reset/destroy, single-threaded), so a plain treiber push with no aba concern */
static void arena_mt_push(arena_mt_t *mt, arena_chunk_t *c)
{
    arena_chunk_t *head = atomic_load_explicit(&mt->all_chunks, memory_order_relaxed);
    do
    {
        c->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&mt->all_chunks, &head, c, memory_order_release,
                                                    memory_order_relaxed));
}

/* concurrent bump: an oversized request gets a dedicated chunk with no slot; otherwise the calling
 * thread's slot is bumped, pulling a new chunk under the slot lock when the current one is full */
static void *arena_alloc_concurrent(const arena_t *arena, size_t size, const size_t align)
{
    arena_mt_t *mt = arena->mt;

    if (size > arena->chunk_size)
    {
        arena_chunk_t *c = arena_chunk_alloc(size + align);
        if (!c) return NULL;
        void *const p = arena_chunk_bump(c, size, align);
        arena_mt_push(mt, c);
        atomic_fetch_add_explicit(&mt->total_used, size, memory_order_relaxed);
        atomic_fetch_add_explicit(&mt->total_reserved, arena_header_size() + c->capacity,
                                  memory_order_relaxed);
        return p;
    }

    arena_slot_t *slot = &mt->slots[arena_thread_slot()];
    arena_lock(&slot->lock);

    if (slot->current)
    {
        void *const p = arena_chunk_bump(slot->current, size, align);
        if (p)
        {
            arena_unlock(&slot->lock);
            atomic_fetch_add_explicit(&mt->total_used, size, memory_order_relaxed);
            return p;
        }
    }

    /* the pool take nests the shard lock inside the slot lock; this is the only place the two are
     * held together and always in this order, so no deadlock */
    arena_chunk_t *c = arena_pool_take(arena->pool, arena->shard, arena->chunk_size);
    if (!c)
    {
        arena_unlock(&slot->lock);
        return NULL;
    }
    arena_mt_push(mt, c);
    slot->current = c;
    atomic_fetch_add_explicit(&mt->total_reserved, arena_header_size() + c->capacity,
                              memory_order_relaxed);
    void *const p = arena_chunk_bump(c, size, align);
    arena_unlock(&slot->lock);
    if (p) atomic_fetch_add_explicit(&mt->total_used, size, memory_order_relaxed);
    return p;
}

/* return every chunk a concurrent arena holds and clear its slots; single-threaded, no allocation
 * may be in flight */
static void arena_mt_release(const arena_t *arena)
{
    arena_mt_t *mt = arena->mt;
    arena_chunk_t *c = atomic_exchange_explicit(&mt->all_chunks, NULL, memory_order_acquire);
    while (c)
    {
        arena_chunk_t *const next = c->next;
        arena_pool_give(arena->pool, arena->shard, c);
        c = next;
    }
    for (int i = 0; i < ARENA_MAX_THREADS; i++) mt->slots[i].current = NULL;
    atomic_store_explicit(&mt->total_used, 0, memory_order_relaxed);
    atomic_store_explicit(&mt->total_reserved, 0, memory_order_relaxed);
}

arena_pool_t *arena_pool_create(const size_t chunk_size, const size_t max_cached_bytes)
{
    arena_pool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    pool->chunk_size = chunk_size ? chunk_size : ARENA_DEFAULT_CHUNK_SIZE;
    const size_t cap = max_cached_bytes ? max_cached_bytes : ARENA_DEFAULT_MAX_CACHED;
    for (int i = 0; i < ARENA_POOL_SHARDS; i++)
    {
        arena_pool_shard_t *s = &pool->shards[i];
        atomic_init(&s->lock, ARENA_LOCK_FREE);
        s->free_list = NULL;
        s->cached_bytes = 0;
        s->max_cached_bytes = cap / ARENA_POOL_SHARDS;
    }
    return pool;
}

void arena_pool_destroy(arena_pool_t *pool)
{
    if (!pool) return;
    for (int i = 0; i < ARENA_POOL_SHARDS; i++)
    {
        arena_chunk_t *c = pool->shards[i].free_list;
        while (c)
        {
            arena_chunk_t *const next = c->next;
            free(c);
            c = next;
        }
    }
    free(pool);
}

arena_t *arena_create(arena_pool_t *pool)
{
    arena_t *arena = calloc(1, sizeof(*arena));
    if (!arena) return NULL;

    arena->pool = pool;
    arena->chunk_size = pool ? pool->chunk_size : ARENA_DEFAULT_CHUNK_SIZE;
    /* the shard follows the creating thread rather than a global counter. a consumer that opens an
     * arena per unit of work -- one per decoded btree node, millions of them -- would otherwise pay
     * a contended atomic on every create and land its chunks on a different shard each time, so a
     * chunk it just released is never the one it picks up next. keyed by thread, a shard becomes
     * that thread's own free list in the common case and only collides once there are more live
     * threads than shards */
    arena->shard = pool ? (unsigned)(arena_thread_slot() % ARENA_POOL_SHARDS) : 0;
    return arena;
}

arena_t *arena_create_concurrent(arena_pool_t *pool)
{
    arena_t *arena = arena_create(pool);
    if (!arena) return NULL;

    arena_mt_t *mt = calloc(1, sizeof(*mt));
    if (!mt)
    {
        free(arena);
        return NULL;
    }
    for (int i = 0; i < ARENA_MAX_THREADS; i++)
    {
        atomic_init(&mt->slots[i].lock, ARENA_LOCK_FREE);
        mt->slots[i].current = NULL;
    }
    atomic_init(&mt->all_chunks, NULL);
    atomic_init(&mt->total_used, 0);
    arena->mt = mt;
    return arena;
}

void *arena_alloc(arena_t *arena, const size_t size, size_t align)
{
    if (!arena || size == 0) return NULL;
    if (align == 0) align = ARENA_MAX_ALIGN;

    if (arena->mt) return arena_alloc_concurrent(arena, size, align);

    /* an allocation larger than a standard chunk gets a dedicated block, sized with alignment
     * slack; it joins the chunk list for release but never becomes the current bump chunk */
    if (size > arena->chunk_size)
    {
        arena_chunk_t *c = arena_chunk_alloc(size + align);
        if (!c) return NULL;
        void *const p = arena_chunk_bump(c, size, align);
        c->next = arena->chunks;
        arena->chunks = c;
        arena->total_used += size;
        arena->total_reserved += arena_header_size() + c->capacity;
        return p;
    }

    if (arena->current)
    {
        void *const p = arena_chunk_bump(arena->current, size, align);
        if (p)
        {
            arena->total_used += size;
            return p;
        }
    }

    arena_chunk_t *c = arena_pool_take(arena->pool, arena->shard, arena->chunk_size);
    if (!c) return NULL;
    c->next = arena->chunks;
    arena->chunks = c;
    arena->current = c;
    arena->total_reserved += arena_header_size() + c->capacity;

    void *const p = arena_chunk_bump(c, size, align);
    if (p) arena->total_used += size;
    return p;
}

void arena_reset(arena_t *arena)
{
    if (!arena) return;
    if (arena->mt)
        arena_mt_release(arena);
    else
        arena_release_chunks(arena);
}

void arena_destroy(arena_t *arena)
{
    if (!arena) return;
    if (arena->mt)
    {
        arena_mt_release(arena);
        free(arena->mt);
    }
    else
    {
        arena_release_chunks(arena);
    }
    free(arena);
}

size_t arena_bytes_allocated(const arena_t *arena)
{
    if (!arena) return 0;
    if (arena->mt)
    {
        const arena_mt_t *mt = arena->mt;
        return atomic_load_explicit(&mt->total_used, memory_order_relaxed);
    }
    return arena->total_used;
}

size_t arena_bytes_reserved(const arena_t *arena)
{
    if (!arena) return 0;
    if (arena->mt)
    {
        const arena_mt_t *mt = arena->mt;
        return atomic_load_explicit(&mt->total_reserved, memory_order_relaxed);
    }
    return arena->total_reserved;
}
