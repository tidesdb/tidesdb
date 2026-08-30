/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_L0_INTERNAL_H__
#define __TIDESDB_L0_INTERNAL_H__
#include "memtable.h"

/* what the L0 subsystem shares across its own translation units and exposes to nothing above them
 * -- the active-slot pin the write path and the read path both take, and the sizing constants both
 * measure themselves against */

/* bounded retries when pinning the active slot before a write or read gives up as TDB_ERR_BUSY -- a
 * rotation that keeps swapping the slot out from under the pin is transient, and BUSY is retryable
 */
#define TDB_L0_ACTIVE_ACQUIRE_MAX_ATTEMPTS 1000

/* how many times a read re-snapshots the active slot and the queue when a rotation moved the
 * boundary between the two halves of its walk. a rotation is an enqueue and an exchange, so one
 * more look is almost always enough and a handful bounds the pathological case where rotations
 * arrive faster than a read completes -- past that the caller is told busy rather than spun on */
#define TDB_L0_ROTATION_RETRY_MAX 4

/* stack buffer for the prefixed key a put or a get builds, so the common small case avoids a
 * malloc; a larger key falls back to a heap allocation */
#define TDB_L0_KEY_STACK_BUF 256

/* stack slots for the immutable-queue snapshot a read walks; a deeper queue falls back to the heap
 */
#define TDB_L0_IMMUTABLE_SNAP_STACK 32

/**
 * l0_pin_active_read
 * take a reader reference on the active memtable, so a rotation cannot free it mid-read
 * @param l0 the subsystem
 * @return the pinned memtable, or NULL when the slot moved under the pin and the caller should
 * retry
 */
tidesdb_memtable_t *l0_pin_active_read(tidesdb_l0_t *l0);

/**
 * l0_unpin_read
 * drop a reader reference, freeing the memtable when it was the last one holding a retired one
 * @param mt the memtable to release
 */
void l0_unpin_read(tidesdb_memtable_t *mt);

#endif /* __TIDESDB_L0_INTERNAL_H__ */
