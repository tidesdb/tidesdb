/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* a placeholder so this translation unit is never empty when fault injection is compiled out */
typedef int block_manager_fault_translation_unit;

#ifdef TDB_FAULT_INJECTION

#include "block_manager_fault.h"

#include <stdatomic.h>

#include "compat.h" /* usleep, which msvc has only as a shim and no unistd.h to declare */

/* the target write to tear, 0 when disarmed */
static _Atomic(uint64_t) g_fault_nth = 0;
/* writes counted since the last arm */
static _Atomic(uint64_t) g_fault_count = 0;
/* set once the torn write happened, so every later write fails outright */
static _Atomic(int) g_fault_tripped = 0;

void block_manager_fault_arm_torn(uint64_t nth)
{
    atomic_store_explicit(&g_fault_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_fault_tripped, 0, memory_order_relaxed);
    atomic_store_explicit(&g_fault_nth, nth, memory_order_release);
}

int block_manager_fault_tripped(void)
{
    return atomic_load_explicit(&g_fault_tripped, memory_order_acquire);
}

int block_manager_fault_intercept(size_t *nbyte)
{
    const uint64_t nth = atomic_load_explicit(&g_fault_nth, memory_order_acquire);
    if (nth == 0) return 0; /* disarmed, the common case */
    if (atomic_load_explicit(&g_fault_tripped, memory_order_relaxed))
        return 2; /* already crashed */

    const uint64_t seen = atomic_fetch_add_explicit(&g_fault_count, 1, memory_order_relaxed) + 1;
    if (seen < nth) return 0; /* not the target write yet */

    /* the target write tears -- write a fraction of its bytes, then this thread freezes, exactly
     * the on-disk state a crash mid-write leaves with no further writes and no error handling
     * running */
    atomic_store_explicit(&g_fault_tripped, 1, memory_order_release);
    *nbyte = *nbyte * BM_FAULT_TORN_NUM / BM_FAULT_TORN_DEN;
    return 1;
}

int block_manager_fault_intercept_barrier(void)
{
    const uint64_t nth = atomic_load_explicit(&g_fault_nth, memory_order_acquire);
    if (nth == 0) return 0; /* disarmed, the common case */
    if (atomic_load_explicit(&g_fault_tripped, memory_order_relaxed))
        return 1; /* already crashed */

    const uint64_t seen = atomic_fetch_add_explicit(&g_fault_count, 1, memory_order_relaxed) + 1;
    if (seen < nth) return 0; /* not the target write yet */

    /* a vectored write cannot be split into a clean torn prefix, so the target crashes right before
     * it lands -- a valid crash point that leaves the sstable build interrupted with no committed
     * manifest entry, so recovery must discard the partial sstable and re-flush from the WAL */
    atomic_store_explicit(&g_fault_tripped, 1, memory_order_release);
    return 1;
}

void block_manager_fault_freeze(void)
{
    /* stand in for a dead process -- park here so the caller does nothing after the tear; the
     * test's main thread observes the trip and exits the whole process */
    for (;;) usleep(BM_FAULT_FREEZE_SLEEP_US);
}

#endif /* TDB_FAULT_INJECTION */
