/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "source.h"

tidesdb_source_result_t tidesdb_source_stack_range_has_newer(
    const tidesdb_source_t *sources, const int count, const uint32_t cf_index, const uint8_t *lo,
    const size_t lo_size, const uint8_t *hi, const size_t hi_size, const uint64_t seq_floor,
    int *newer)
{
    if (!sources || count <= 0 || !newer) return TDB_SOURCE_BUSY;
    *newer = 0;

    int held = 0;
    for (int i = 0; i < count; i++)
    {
        const tidesdb_source_t *s = &sources[i];

        /* a source with no interval probe cannot be stood in for the way a point probe falls back
         * to a full get, so the answer is that nobody can answer -- which a commit reads as a
         * reason to retry rather than as a clear run */
        if (!s->range_has_newer) return TDB_SOURCE_BUSY;

        const tidesdb_source_result_t r =
            s->range_has_newer(s->ctx, cf_index, lo, lo_size, hi, hi_size, seq_floor, newer);
        if (r == TDB_SOURCE_BUSY) return TDB_SOURCE_BUSY;
        if (*newer) return TDB_SOURCE_FOUND; /* one is enough to decide the commit */
        if (r == TDB_SOURCE_FOUND) held = 1;
    }
    return held ? TDB_SOURCE_FOUND : TDB_SOURCE_NOT_FOUND;
}

tidesdb_source_result_t tidesdb_source_stack_get(const tidesdb_source_t *sources, int count,
                                                 uint32_t cf_index, const uint8_t *key,
                                                 size_t key_size, uint64_t snapshot,
                                                 tidesdb_source_version_t *out)
{
    if (!sources || !key || !out) return TDB_SOURCE_NOT_FOUND;

    for (int i = 0; i < count; i++)
    {
        const tidesdb_source_t *s = &sources[i];
        if (!s->get) continue;

        const tidesdb_source_result_t r = s->get(s->ctx, cf_index, key, key_size, snapshot, out);

        /* a hit wins immediately -- newest-first ordering makes it the newest visible version. a
         * busy source short-circuits rather than falling through to an older source and risking a
         * stale read, since the busy source might hold a newer version the reader must see */
        if (r == TDB_SOURCE_FOUND || r == TDB_SOURCE_BUSY) return r;
    }
    return TDB_SOURCE_NOT_FOUND;
}

tidesdb_source_result_t tidesdb_source_stack_has_newer(const tidesdb_source_t *sources,
                                                       const int count, const uint32_t cf_index,
                                                       const uint8_t *key, const size_t key_size,
                                                       const uint64_t seq_floor, int *newer)
{
    if (!sources || !key || !newer) return TDB_SOURCE_NOT_FOUND;
    *newer = 0;

    for (int i = 0; i < count; i++)
    {
        const tidesdb_source_t *s = &sources[i];

        if (s->has_newer)
        {
            const tidesdb_source_result_t r =
                s->has_newer(s->ctx, cf_index, key, key_size, seq_floor, newer);
            if (r == TDB_SOURCE_FOUND || r == TDB_SOURCE_BUSY) return r;
            continue;
        }

        /* a source with no cheap answer still has to be consulted, so fall back to the full lookup
         * and decide from the version it returns */
        if (!s->get) continue;
        tidesdb_source_version_t v;
        const tidesdb_source_result_t r = s->get(s->ctx, cf_index, key, key_size, UINT64_MAX, &v);
        if (r == TDB_SOURCE_BUSY) return r;
        if (r == TDB_SOURCE_FOUND)
        {
            *newer = v.seq > seq_floor;
            free(v.value);
            return TDB_SOURCE_FOUND;
        }
    }
    return TDB_SOURCE_NOT_FOUND;
}
