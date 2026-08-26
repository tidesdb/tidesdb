/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "fdmanager/reaper.h"

#include <limits.h>

/* the reference the caller holds on every candidate while the sweep runs. it sits on top of the
 * level set's own, and both have to be counted or the evicting window is claimed at a count no
 * live sstable is ever at and no klog is ever given back */
#define FD_REAPER_CANDIDATE_REF 1

int fd_reaper_run(fd_manager_t *fdm, sstable_t *const *candidates, const int n_candidates,
                  vlog_t *vlog)
{
    if (!fdm || !candidates) return 0;

    const int budget = fd_manager_open_budget(fdm);
    if (budget >= INT_MAX) return 0; /* unlimited, no soft cap to reclaim toward */

    /* value-log segments go first. a key log is read on every point lookup that reaches its
     * sstable, while a segment is touched only when a separated value is dereferenced, so of the
     * two the segment's descriptor is the one more likely to sit idle and the cheaper to give back.
     * neither is lost by evicting -- both reopen on the next read */
    int reclaimed = 0;
    if (vlog && fd_manager_open_total(fdm) > budget)
        reclaimed += vlog_evict_idle_segments(vlog, fd_manager_open_total(fdm) - budget);

    for (int i = 0; i < n_candidates && fd_manager_open_total(fdm) > budget; i++)
    {
        if (candidates[i] &&
            sstable_evict_klog(candidates[i], SSTABLE_IDLE_BASELINE + FD_REAPER_CANDIDATE_REF))
            reclaimed++;
    }
    return reclaimed;
}
