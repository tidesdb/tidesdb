/**
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
#include <stdlib.h>

/* we use thin wrappers instead of taking addresses of stdlib functions directly
 * on MSVC, malloc/calloc/realloc/free are __declspec(dllimport) and their
 * address is not guaranteed to be static (warning C4232) */
static void *real_malloc(size_t size)
{
    return malloc(size);
}
static void *real_calloc(size_t count, size_t size)
{
    return calloc(count, size);
}
static void *real_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
static void real_free(void *ptr)
{
    free(ptr);
}

#include "alloc.h"

/* global allocator instance initialized with system defaults
 * we initialize with real stdlib functions so malloc/free work before tidesdb_init is called */
tidesdb_allocator_t tidesdb_allocator = {
    .malloc_fn = real_malloc,
    .calloc_fn = real_calloc,
    .realloc_fn = real_realloc,
    .free_fn = real_free,
};

int tidesdb_initialized = 0;

int tidesdb_init(tidesdb_malloc_fn malloc_fn, tidesdb_calloc_fn calloc_fn,
                 tidesdb_realloc_fn realloc_fn, tidesdb_free_fn free_fn)
{
    if (tidesdb_initialized)
    {
        return -1;
    }

    tidesdb_allocator.malloc_fn = malloc_fn ? malloc_fn : real_malloc;
    tidesdb_allocator.calloc_fn = calloc_fn ? calloc_fn : real_calloc;
    tidesdb_allocator.realloc_fn = realloc_fn ? realloc_fn : real_realloc;
    tidesdb_allocator.free_fn = free_fn ? free_fn : real_free;
    tidesdb_initialized = 1;

    return 0;
}

void tidesdb_finalize(void)
{
    tidesdb_allocator.malloc_fn = real_malloc;
    tidesdb_allocator.calloc_fn = real_calloc;
    tidesdb_allocator.realloc_fn = real_realloc;
    tidesdb_allocator.free_fn = real_free;
    tidesdb_initialized = 0;
}

void tidesdb_ensure_initialized(void)
{
    if (!tidesdb_initialized)
    {
        tidesdb_init(NULL, NULL, NULL, NULL);
    }
}
