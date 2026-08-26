/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* a placeholder so this translation unit is never empty when the injector is compiled out */
typedef int alloc_fault_translation_unit;

#ifdef TDB_ALLOC_FAULT

#include "alloc_fault.h"

#include <stdatomic.h>
#include <stddef.h>

/* the allocation to refuse, 0 when disarmed */
static _Atomic(uint64_t) g_alloc_nth = 0;
/* allocations counted since the last arm, whether or not anything is armed */
static _Atomic(uint64_t) g_alloc_count = 0;
/* set once the armed allocation was refused */
static _Atomic(int) g_alloc_tripped = 0;

void alloc_fault_arm(const uint64_t nth)
{
    atomic_store_explicit(&g_alloc_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_alloc_tripped, 0, memory_order_relaxed);
    atomic_store_explicit(&g_alloc_nth, nth, memory_order_release);
}

int alloc_fault_tripped(void)
{
    return atomic_load_explicit(&g_alloc_tripped, memory_order_acquire);
}

uint64_t alloc_fault_count(void)
{
    return atomic_load_explicit(&g_alloc_count, memory_order_acquire);
}

/* whether this allocation is the armed one. the count advances on every call so a disarmed run
 * still measures the workload, and only the exact nth is refused so the unwind that follows runs
 * against an otherwise working allocator */
static int alloc_fault_should_fail(void)
{
    const uint64_t seen = atomic_fetch_add_explicit(&g_alloc_count, 1, memory_order_relaxed) + 1;
    if (seen != atomic_load_explicit(&g_alloc_nth, memory_order_acquire)) return 0;
    atomic_store_explicit(&g_alloc_tripped, 1, memory_order_release);
    return 1;
}

/* the linker redirects the library's allocation calls here and leaves the real ones reachable under
 * these names */
extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t count, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

void *__wrap_malloc(size_t size)
{
    return alloc_fault_should_fail() ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    return alloc_fault_should_fail() ? NULL : __real_calloc(count, size);
}

/* a refused realloc leaves the caller's original block alive and owned, which is the case a caller
 * most often gets wrong -- overwriting the pointer with the NULL and losing the block */
void *__wrap_realloc(void *ptr, size_t size)
{
    return alloc_fault_should_fail() ? NULL : __real_realloc(ptr, size);
}

#endif /* TDB_ALLOC_FAULT */
