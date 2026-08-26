/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "merge_iter.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* the scan direction; a flip between the two re-seeks the sources around the current key */
typedef enum
{
    MERGE_FORWARD,
    MERGE_BACKWARD
} merge_dir_t;

/* the resolved current entry plus the borrowed sources it folds; the key and value are owned copies
 * so they stay valid after the sources advance past them */
struct merge_iter
{
    const merge_source_t *sources;
    int n_sources;
    uint64_t snapshot;
    int raw;
    merge_dir_t direction;

    uint8_t *key;
    size_t key_size;
    size_t key_cap;
    uint8_t *value;
    size_t value_size;
    size_t value_cap;
    uint64_t seq;
    uint64_t vlog_offset;
    int64_t ttl;
    uint8_t deleted;
    int positioned;

    /* the sources sitting on the key the last pick chose, and how many. the pick compares every
     * source's current key against the winner to find it, so it already knows which of them tie --
     * recording that costs an int and saves the resolve pass rediscovering it, which it otherwise
     * did by asking every source for its current entry a second time. on a family with many
     * overlapping runs the tie set is one or two sources out of dozens */
    int *match;
    int n_match;
};

/* byte-wise key order with a length tiebreak, matching the engine's memcmp ordering everywhere */
static int merge_key_cmp(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size)
{
    const size_t n = a_size < b_size ? a_size : b_size;
    const int c = memcmp(a, b, n);
    if (c != 0) return c;
    if (a_size < b_size) return -1;
    return a_size > b_size ? 1 : 0;
}

/* grow an owned buffer to at least need bytes; a zero need leaves it untouched */
static int merge_ensure_cap(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap) return 0;
    uint8_t *grown = realloc(*buf, need);
    if (!grown) return -1;
    *buf = grown;
    *cap = need;
    return 0;
}

/* read the key the source is positioned on into out pointers */
static void merge_source_key(const merge_source_t *s, const uint8_t **key, size_t *key_size)
{
    const uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    s->get(s->ctx, key, key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted);
}

/* copy the extreme current key (smallest going forward, largest going backward) into the iterator's
 * key buffer; returns 1 if any source is positioned, 0 if all are exhausted, -1 on allocation
 * failure */
static int merge_pick_extreme(merge_iter_t *it, merge_dir_t dir)
{
    const uint8_t *extreme = NULL;
    size_t extreme_size = 0;
    it->n_match = 0;
    for (int i = 0; i < it->n_sources; i++)
    {
        const merge_source_t *s = &it->sources[i];
        if (!s->valid(s->ctx)) continue;
        const uint8_t *key = NULL;
        size_t key_size = 0;
        merge_source_key(s, &key, &key_size);
        if (extreme == NULL)
        {
            extreme = key;
            extreme_size = key_size;
            it->match[0] = i;
            it->n_match = 1;
            continue;
        }
        const int c = merge_key_cmp(key, key_size, extreme, extreme_size);
        if ((dir == MERGE_FORWARD && c < 0) || (dir == MERGE_BACKWARD && c > 0))
        {
            /* a new winner replaces the tie set rather than joining it */
            extreme = key;
            extreme_size = key_size;
            it->match[0] = i;
            it->n_match = 1;
        }
        else if (c == 0)
        {
            it->match[it->n_match++] = i;
        }
    }
    if (extreme == NULL) return 0;
    if (merge_ensure_cap(&it->key, &it->key_cap, extreme_size) != 0) return -1;
    memcpy(it->key, extreme, extreme_size);
    it->key_size = extreme_size;
    return 1;
}

/* resolve the current key's newest version at or below the snapshot across every source, copying
 * the winner into the iterator and advancing all sources past this key in the scan direction;
 * returns 1 if a visible version was found, 0 if none, -1 on allocation failure */
static int merge_resolve(merge_iter_t *it, merge_dir_t dir)
{
    int have = 0;
    uint64_t best_seq = 0;
    /* only the sources the pick found on this key. every other source's current entry orders after
     * it, so the walk below would read one entry from each and break on the first comparison */
    for (int m = 0; m < it->n_match; m++)
    {
        const merge_source_t *s = &it->sources[it->match[m]];
        while (s->valid(s->ctx))
        {
            const uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            uint64_t seq = 0, vlog_offset = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            s->get(s->ctx, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                   &deleted);
            if (merge_key_cmp(key, key_size, it->key, it->key_size) != 0) break;

            if (seq <= it->snapshot && (!have || seq > best_seq))
            {
                have = 1;
                best_seq = seq;
                it->seq = seq;
                it->ttl = ttl;
                it->deleted = deleted;
                it->vlog_offset = vlog_offset;
                it->value_size = value_size;
                /* only an inline value carries bytes here; a spilled value is NULL with its logical
                 * size set and is resolved later through vlog_offset, so it is not copied */
                if (vlog_offset == 0 && value_size > 0)
                {
                    if (merge_ensure_cap(&it->value, &it->value_cap, value_size) != 0) return -1;
                    memcpy(it->value, value, value_size);
                }
            }
            if (dir == MERGE_FORWARD)
                (void)s->next(s->ctx);
            else
                (void)s->prev(s->ctx);
        }
    }
    return have;
}

/* yield one version -- the extreme key and, among equal keys, the extreme sequence (highest going
 * forward so versions come newest first), advancing only the source it came from. no resolution, no
 * hiding; the compaction consumer applies retention and GC */
static int merge_advance_raw(merge_iter_t *it, merge_dir_t dir)
{
    int best = -1;
    const uint8_t *best_key = NULL;
    size_t best_key_size = 0;
    uint64_t best_seq = 0;
    for (int i = 0; i < it->n_sources; i++)
    {
        const merge_source_t *s = &it->sources[i];
        if (!s->valid(s->ctx)) continue;
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        s->get(s->ctx, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted);
        const int c = best < 0 ? 0 : merge_key_cmp(key, key_size, best_key, best_key_size);
        const int better =
            best < 0 || (dir == MERGE_FORWARD ? (c < 0 || (c == 0 && seq > best_seq))
                                              : (c > 0 || (c == 0 && seq < best_seq)));
        if (better)
        {
            best = i;
            best_key = key;
            best_key_size = key_size;
            best_seq = seq;
        }
    }
    if (best < 0)
    {
        it->positioned = 0;
        return TDB_ERR_NOT_FOUND;
    }

    const merge_source_t *s = &it->sources[best];
    const uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    uint64_t seq = 0, vlog_offset = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    s->get(s->ctx, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl, &deleted);
    if (merge_ensure_cap(&it->key, &it->key_cap, key_size) != 0) return TDB_ERR_MEMORY;
    memcpy(it->key, key, key_size);
    it->key_size = key_size;
    it->seq = seq;
    it->ttl = ttl;
    it->deleted = deleted;
    it->vlog_offset = vlog_offset;
    it->value_size = value_size;
    /* a spilled value carries its logical size but no inline bytes -- the bytes live in the vlog
     * and are resolved through vlog_offset -- so only an inline value is copied here */
    if (vlog_offset == 0 && value_size > 0)
    {
        if (merge_ensure_cap(&it->value, &it->value_cap, value_size) != 0) return TDB_ERR_MEMORY;
        memcpy(it->value, value, value_size);
    }

    if (dir == MERGE_FORWARD)
        (void)s->next(s->ctx);
    else
        (void)s->prev(s->ctx);
    it->positioned = 1;
    it->direction = dir;
    return TDB_SUCCESS;
}

/* whether any source stopped on a read failure rather than on exhaustion */
static int merge_any_read_failed(const merge_iter_t *it)
{
    for (int i = 0; i < it->n_sources; i++)
    {
        const merge_source_t *s = &it->sources[i];
        if (s->read_failed && s->read_failed(s->ctx)) return 1;
    }
    return 0;
}

/* find the next visible key in the scan direction, skipping keys with no version at or below the
 * snapshot and, unless emitting tombstones, keys whose newest visible version is a tombstone */
static int merge_advance_inner(merge_iter_t *it, merge_dir_t dir)
{
    if (it->raw) return merge_advance_raw(it, dir);
    for (;;)
    {
        const int picked = merge_pick_extreme(it, dir);
        if (picked < 0) return TDB_ERR_MEMORY;
        if (picked == 0)
        {
            it->positioned = 0;
            return TDB_ERR_NOT_FOUND;
        }

        const int have = merge_resolve(it, dir);
        if (have < 0) return TDB_ERR_MEMORY;
        if (have == 0) continue;   /* no version visible at the snapshot */
        if (it->deleted) continue; /* a tombstone hides the key */

        it->positioned = 1;
        it->direction = dir;
        return TDB_SUCCESS;
    }
}

/* advance, then refuse to pass off a stream a source dropped out of. a source that could not read
 * reports itself invalid, so the merge would otherwise treat its remaining entries as absent and
 * return a short scan as if it were complete -- the same failure the point read resolves by
 * retrying, reported here as io so the caller knows the scan is not the whole answer */
static int merge_advance(merge_iter_t *it, merge_dir_t dir)
{
    const int rc = merge_advance_inner(it, dir);
    if (merge_any_read_failed(it))
    {
        it->positioned = 0;
        return TDB_ERR_IO;
    }
    return rc;
}

/* re-seek every source to just past the current key in the given direction, so a direction flip
 * resumes exactly one step beyond the current key without dropping or repeating an entry */
static void merge_reseek(merge_iter_t *it, merge_dir_t dir)
{
    for (int i = 0; i < it->n_sources; i++)
    {
        const merge_source_t *s = &it->sources[i];
        if (dir == MERGE_FORWARD)
            (void)s->seek(s->ctx, it->key, it->key_size);
        else
            (void)s->seek_for_prev(s->ctx, it->key, it->key_size);

        /* step over any lingering versions of the current key so the next resolve begins on a new
         * key */
        while (s->valid(s->ctx))
        {
            const uint8_t *key = NULL;
            size_t key_size = 0;
            merge_source_key(s, &key, &key_size);
            if (merge_key_cmp(key, key_size, it->key, it->key_size) != 0) break;
            if (dir == MERGE_FORWARD)
                (void)s->next(s->ctx);
            else
                (void)s->prev(s->ctx);
        }
    }
}

int merge_iter_new(const merge_source_t *sources, int n_sources, uint64_t snapshot, int flags,
                   merge_iter_t **out)
{
    if ((!sources && n_sources > 0) || n_sources < 0 || !out) return TDB_ERR_INVALID_ARGS;

    merge_iter_t *it = calloc(1, sizeof(*it));
    if (!it) return TDB_ERR_MEMORY;
    /* one slot per source, since in the worst case every source sits on the same key */
    if (n_sources > 0)
    {
        it->match = malloc((size_t)n_sources * sizeof(*it->match));
        if (!it->match)
        {
            free(it);
            return TDB_ERR_MEMORY;
        }
    }
    it->sources = sources;
    it->n_sources = n_sources;
    it->snapshot = snapshot;
    it->raw = (flags & MERGE_ITER_RAW) != 0;
    it->direction = MERGE_FORWARD;
    *out = it;
    return TDB_SUCCESS;
}

void merge_iter_free(merge_iter_t *it)
{
    if (!it) return;
    free(it->key);
    free(it->value);
    free(it->match);
    free(it);
}

int merge_iter_seek_first(merge_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    for (int i = 0; i < it->n_sources; i++) (void)it->sources[i].first(it->sources[i].ctx);
    return merge_advance(it, MERGE_FORWARD);
}

int merge_iter_seek_last(merge_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    for (int i = 0; i < it->n_sources; i++) (void)it->sources[i].last(it->sources[i].ctx);
    return merge_advance(it, MERGE_BACKWARD);
}

int merge_iter_seek(merge_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it || !key) return TDB_ERR_INVALID_ARGS;
    for (int i = 0; i < it->n_sources; i++)
        (void)it->sources[i].seek(it->sources[i].ctx, key, key_size);
    return merge_advance(it, MERGE_FORWARD);
}

int merge_iter_seek_for_prev(merge_iter_t *it, const uint8_t *key, size_t key_size)
{
    if (!it || !key) return TDB_ERR_INVALID_ARGS;
    for (int i = 0; i < it->n_sources; i++)
        (void)it->sources[i].seek_for_prev(it->sources[i].ctx, key, key_size);
    return merge_advance(it, MERGE_BACKWARD);
}

/* the re-seek a direction flip needs, or the refusal raw mode gets instead. the re-seek resumes one
 * step past the current key, stepping over the key's remaining versions -- which is what a
 * resolving scan wants and precisely wrong for a raw one, whose whole purpose is to see every
 * version. raw cannot simply skip the re-seek either: its sources sit one step past the version
 * just emitted, so turning round without one re-emits it. no raw caller flips today -- compaction
 * is the only raw user and it runs forward -- so this refuses rather than answering a repeat in
 * silence
 * @return TDB_SUCCESS when the flip is done or was not needed, TDB_ERR_INVALID_ARGS for a raw flip
 */
static int merge_turn(merge_iter_t *it, merge_dir_t dir)
{
    if (it->direction == dir) return TDB_SUCCESS;
    if (it->raw) return TDB_ERR_INVALID_ARGS;
    merge_reseek(it, dir);
    return TDB_SUCCESS;
}

int merge_iter_next(merge_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    if (!it->positioned) return TDB_ERR_NOT_FOUND;
    const int turned = merge_turn(it, MERGE_FORWARD);
    if (turned != TDB_SUCCESS) return turned;
    return merge_advance(it, MERGE_FORWARD);
}

int merge_iter_prev(merge_iter_t *it)
{
    if (!it) return TDB_ERR_INVALID_ARGS;
    if (!it->positioned) return TDB_ERR_NOT_FOUND;
    const int turned = merge_turn(it, MERGE_BACKWARD);
    if (turned != TDB_SUCCESS) return turned;
    return merge_advance(it, MERGE_BACKWARD);
}

int merge_iter_valid(const merge_iter_t *it)
{
    return it && it->positioned;
}

int merge_iter_get(merge_iter_t *it, const uint8_t **key, size_t *key_size, uint64_t *seq,
                   const uint8_t **value, size_t *value_size, uint64_t *vlog_offset, int64_t *ttl,
                   uint8_t *deleted)
{
    if (!it || !it->positioned) return TDB_ERR_NOT_FOUND;
    if (key) *key = it->key;
    if (key_size) *key_size = it->key_size;
    if (seq) *seq = it->seq;
    /* inline bytes only when not spilled; a spilled value is NULL here and resolved via vlog_offset
     */
    if (value) *value = (it->vlog_offset == 0 && it->value_size > 0) ? it->value : NULL;
    if (value_size) *value_size = it->value_size;
    if (vlog_offset) *vlog_offset = it->vlog_offset;
    if (ttl) *ttl = it->ttl;
    if (deleted) *deleted = it->deleted;
    return TDB_SUCCESS;
}
