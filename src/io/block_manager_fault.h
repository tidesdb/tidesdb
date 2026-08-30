/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BLOCK_MANAGER_FAULT_H__
#define __TIDESDB_BLOCK_MANAGER_FAULT_H__

/* deterministic write-fault injection for crash-recovery tests. every durable block-manager write
 * funnels through pwrite_all, so arming a torn write at the nth call reproduces exactly the on-disk
 * state a crash mid-write would leave, without a real process crash or its scheduling
 * nondeterminism. the whole feature compiles out unless TDB_FAULT_INJECTION is defined, so a
 * production build pays nothing and the hot write path is unchanged. */

#ifdef TDB_FAULT_INJECTION

#include <stddef.h>
#include <stdint.h>

/* the intercept clamps a torn write to this fraction of its bytes, a partial write like a crash mid
 * pwrite; expressed as a numerator over a denominator so the split is a named quantity */
#define BM_FAULT_TORN_NUM 1
#define BM_FAULT_TORN_DEN 2

/* how long the frozen thread sleeps between checks -- it never wakes to do anything, so this only
 * decides how little cpu a parked thread burns while the test's main thread exits the process */
#define BM_FAULT_FREEZE_SLEEP_US 1000

/**
 * block_manager_fault_arm_torn
 * arm a torn-write fault so the nth block-manager write after this call writes only a fraction of
 * its bytes and then fails, and every write after it fails outright; resets the write counter
 * @param nth the 1-based write to tear, or 0 to leave disarmed
 */
void block_manager_fault_arm_torn(uint64_t nth);

/**
 * block_manager_fault_tripped
 * whether the armed torn write has fired, so a test can crash the moment the on-disk tear lands
 * instead of waiting on a flush that can no longer make progress
 * @return non-zero once the torn write happened
 */
int block_manager_fault_tripped(void);

/**
 * block_manager_fault_intercept
 * the pwrite_all hook, deciding this write's fate against the armed fault
 * @param nbyte in out -- the write length, clamped to the torn fraction when the return is 1
 * @return 0 to proceed with nbyte unchanged, 1 to write the clamped nbyte then freeze this thread,
 * or 2 to freeze immediately with no bytes written
 */
int block_manager_fault_intercept(size_t *nbyte);

/**
 * block_manager_fault_intercept_barrier
 * the vectored-write hook, counting the write against the armed fault the same as the byte-clamping
 * intercept but with no partial write, since a pwritev cannot be split cleanly; the target write
 * crashes right before it lands
 * @return 0 to proceed, or 1 to freeze this thread before writing any bytes
 */
int block_manager_fault_intercept_barrier(void);

/**
 * block_manager_fault_freeze
 * park the calling thread forever, standing in for a process killed mid-write so no code runs after
 * the crash point; the process exits from another thread
 */
void block_manager_fault_freeze(void);

#endif /* TDB_FAULT_INJECTION */
#endif /* __TIDESDB_BLOCK_MANAGER_FAULT_H__ */
