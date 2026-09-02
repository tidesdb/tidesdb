/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_ALLOC_FAULT_H__
#define __TIDESDB_ALLOC_FAULT_H__

/* deterministic allocation-failure injection, for the out-of-memory paths. an allocation failing is
 * the one condition a caller cannot provoke from outside, so the unwind after it -- the frees, the
 * half-built structures, the locks already taken -- is the part of the engine least likely to have
 * ever run. arming the nth allocation and sweeping n walks those paths one at a time.
 *
 * only the armed allocation fails, never the ones after it, so what a run exercises is a single
 * site's unwind rather than a cascade in which every cleanup path also fails. the counter runs
 * whether or not anything is armed, so a caller can measure how many allocations a workload makes
 * before deciding how far to sweep.
 *
 * the feature compiles out unless TDB_ALLOC_FAULT is defined, and it needs a linker able to
 * redirect a symbol -- GNU ld and lld through --wrap -- which is why it is a build option rather
 * than something always compiled in. */

#ifdef TDB_ALLOC_FAULT

#include <stddef.h>
#include <stdint.h>

/* the linker redirects the library's allocation calls to these. they are declared rather than left
 * to the definitions alone because a definition with no visible prototype is a warning, and this
 * tree is built with none allowed */
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t count, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

/**
 * alloc_fault_arm
 * arm a failure at the nth allocation after this call, resetting the counter and the tripped flag
 * @param nth the 1-based allocation to fail, or 0 to disarm while still counting
 */
void alloc_fault_arm(uint64_t nth);

/**
 * alloc_fault_count
 * how many allocations have been counted since the last arm, which is what a sweep measures a
 * workload with before choosing its range
 * @return the count
 */
uint64_t alloc_fault_count(void);

#endif /* TDB_ALLOC_FAULT */
#endif /* __TIDESDB_ALLOC_FAULT_H__ */
