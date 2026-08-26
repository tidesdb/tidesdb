/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FD_REAPER_H__
#define __TIDESDB_FD_REAPER_H__

#include "fdmanager/fdmanager.h"
#include "sstable/sstable.h"

/* the fd reaper is the first of the reaper family. it closes idle, unreferenced value-log segments
 * and sstable klog block managers to reclaim descriptors down to the fd manager's open budget,
 * keeping the handles themselves alive so a later read reopens the file. it owns nothing -- the
 * engine collects the candidate sstables by walking the column family level sets and hands them
 * here, so the reaper is a leaf the engine drives on its background ticker. it takes no engine
 * handle and is unit-testable with stack sstables and a stack fd manager. */

/**
 * fd_reaper_run
 * reclaim idle descriptors until the resident open count is back under the fd manager's budget, or
 * the candidates are exhausted. value-log segments are given back first -- a klog is read on every
 * point lookup reaching its sstable, while a segment is touched only when a separated value is
 * dereferenced, so the segment's descriptor is the one more likely to sit idle. then one forward
 * pass over the candidates, which the caller orders least-recently-used first so the coldest
 * sstables are evicted before warmer ones. a candidate a reader currently holds is left open and
 * skipped; the next run retries it. an unlimited fd manager (no soft cap) reclaims nothing.
 * @param fdm the descriptor-budget service
 * @param candidates the sstables to consider, ordered oldest-access-first, NULL entries skipped;
 *                   the caller holds a reference on each for the length of the call, which is
 *                   counted into the resting count the evicting window is claimed at
 * @param n_candidates the number of candidates
 * @param vlog the db-global value log to evict idle segments from first, or NULL to skip that phase
 * @return the number of descriptors reclaimed, segments and klogs together
 */
int fd_reaper_run(fd_manager_t *fdm, sstable_t *const *candidates, int n_candidates, vlog_t *vlog);

#endif /* __TIDESDB_FD_REAPER_H__ */
