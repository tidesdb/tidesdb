/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FUZZ_HARNESS_H__
#define __TIDESDB_FUZZ_HARNESS_H__

#include <stddef.h>
#include <stdint.h>

/* fuzz_run decodes the input bytes into a stream of storage-engine operations, applies each to a
 * fresh tidesdb database and to the reference model in lockstep, and asserts (aborting on failure,
 * so the fuzzer captures the input) that every observable result -- point reads, range scans,
 * transaction visibility, and the full state after a reopen or backup -- matches the model.
 * structural operations (flush, compaction, value-log reclaim) are applied to the database only and
 * must leave results unchanged. the database lives in a unique scratch directory removed before and
 * after the run. */

/* the sync mode a run opens the database with; the logical harness uses none for speed (a clean
 * close is durable without a barrier), the crash harness uses full so a killed process's committed
 * data is recoverable */
#define FUZZ_SYNC_NONE 0
#define FUZZ_SYNC_FULL 1

/**
 * fuzz_run
 * drive one input's operation stream against a fresh database and the model, checking equivalence
 * @param data the fuzzer input bytes decoded into operations
 * @param size length of data
 * @param sync_mode FUZZ_SYNC_NONE or FUZZ_SYNC_FULL
 * @return 0 always (an oracle failure aborts rather than returns)
 */
int fuzz_run(const uint8_t *data, size_t size, int sync_mode);

#endif /* __TIDESDB_FUZZ_HARNESS_H__ */
