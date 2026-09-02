/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_ARENA_H__
#define __TIDESDB_BASE_ARENA_H__

#include "compat.h" /* size_t, fixed-width ints */

/* one db-global region allocator for the hot LSM allocation pattern -- many small, same-lifetime
 * allocations freed as a group. it is not a malloc replacement; it is a bump allocator (arena) over
 * fixed-size chunks recycled through a shared pool, so a consumer stops paying per-object
 * malloc/free on its hot path and stops carrying a private arena. a chunk pool is created once for
 * the db; each consumer opens an arena over it, bump-allocates, and resets or destroys the whole
 * arena at once, which returns its chunks to the pool for the next arena rather than to the OS.
 *
 * an arena is single-writer -- concurrent arena_alloc on one arena is a data race. distinct arenas
 * over one shared pool are safe to use concurrently; the pool's recycling is internally
 * synchronized, and its free chunks are sharded by the creating thread -- so a consumer that opens
 * an arena per unit of work reuses the chunk it last returned rather than contending with the other
 * threads for one, and only collides once more threads are live than there are shards. */

typedef struct arena_pool arena_pool_t;
typedef struct arena arena_t;

/**
 * arena_pool_create
 * create the shared chunk pool
 * @param chunk_size bytes of usable space per recycled chunk, 0 selects a default; an arena
 * allocation larger than this is served by a dedicated block instead of a pooled chunk
 * @param max_cached_bytes soft cap on idle chunk bytes the pool retains; chunks returned beyond it
 * are freed to the OS rather than cached, 0 selects a default
 * @return the pool, or NULL on allocation failure
 */
arena_pool_t *arena_pool_create(size_t chunk_size, size_t max_cached_bytes);

/**
 * arena_pool_destroy
 * free the pool and every chunk it still caches; all arenas over it must already be destroyed
 * @param pool the pool, may be NULL
 */
void arena_pool_destroy(arena_pool_t *pool);

/**
 * arena_create
 * open an arena drawing chunks from a pool
 * @param pool the shared chunk pool, or NULL to allocate and free chunks directly without recycling
 * @return the arena, or NULL on allocation failure
 */
arena_t *arena_create(arena_pool_t *pool);

/**
 * arena_create_concurrent
 * open an arena that many threads may allocate from at once, using a per-thread slot so distinct
 * threads bump without contending; reset and destroy remain single-threaded (the caller must ensure
 * no allocation is in flight, the same drain a memtable already performs before freeing its skip
 * list)
 * @param pool the shared chunk pool, or NULL to allocate and free chunks directly
 * @return the arena, or NULL on allocation failure
 */
arena_t *arena_create_concurrent(arena_pool_t *pool);

/**
 * arena_alloc
 * bump-allocate aligned bytes from the arena, pulling a new chunk when the current one is
 * exhausted; an allocation larger than the pool chunk size gets a dedicated block. safe to call
 * concurrently only on an arena from arena_create_concurrent
 * @param arena the arena
 * @param size bytes to allocate; 0 returns NULL
 * @param align required alignment, must be a power of two, 0 selects the default max alignment
 * @return the allocated region, valid until the arena is reset or destroyed, or NULL on failure
 */
void *arena_alloc(arena_t *arena, size_t size, size_t align);

/**
 * arena_reset
 * release every allocation and return the arena's chunks to the pool, keeping one for immediate
 * reuse; the arena is usable again afterward with no allocation
 * @param arena the arena
 */
void arena_reset(arena_t *arena);

/**
 * arena_destroy
 * return all of the arena's chunks to the pool and free the arena
 * @param arena the arena, may be NULL
 */
void arena_destroy(arena_t *arena);

/**
 * arena_bytes_allocated
 * total bytes handed out by arena_alloc since the last reset
 * @param arena the arena
 * @return the byte total, or 0 if arena is NULL
 */
size_t arena_bytes_allocated(const arena_t *arena);

/**
 * arena_bytes_reserved
 * bytes the arena's chunks occupy, which is what the process actually holds on its behalf.
 *
 * a bump allocator rounds a request up to a whole chunk, so this is at or above what
 * arena_bytes_allocated reports, and by a wide margin when the arena holds one small object. a
 * consumer enforcing a memory budget has to charge this figure -- charging the allocated one means
 * enforcing a limit against a number that is not what the memory costs
 * @param arena the arena
 * @return the byte total, or 0 if arena is NULL
 */
size_t arena_bytes_reserved(const arena_t *arena);

#endif /* __TIDESDB_BASE_ARENA_H__ */
