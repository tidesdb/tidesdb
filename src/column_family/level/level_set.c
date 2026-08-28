/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "column_family/level/level_set.h"

#include <stdlib.h>
#include <string.h>

#include "base/lockfree.h"

/* a layout that is neither published nor on the retire list holds sstable references nothing will
 * ever give back, which surfaces only as a leaked handle long afterwards. counting the layouts
 * makes that its own checkable balance rather than something inferred from a refcount */
static _Atomic(int64_t) level_live_layouts_count;

int64_t level_live_layouts(void)
{
    return atomic_load_explicit(&level_live_layouts_count, memory_order_relaxed);
}

/**
 * level_entry_t
 * one sstable's slot within a level -- the open handle plus the on-disk size that feeds size
 * triggers
 * @sst the referenced open sstable
 * @size_bytes on-disk size of the sstable
 */
typedef struct
{
    sstable_t *sst;
    uint64_t size_bytes;
} level_entry_t;

/**
 * level_layout_t
 * an immutable snapshot of every level's sstables, published behind one atomic pointer and
 * reclaimed once the reader epoch that could still see it has drained. holds one reference per
 * listed sstable.
 * @levels per-level arrays of entries, index level-1; L1 unordered, L2+ sorted by min_key
 * @counts number of entries at each level
 */
typedef struct
{
    level_entry_t *levels[LEVEL_SET_MAX_LEVELS];
    int counts[LEVEL_SET_MAX_LEVELS];
} level_layout_t;

/**
 * level_set
 * the per-cf tier structure -- an atomically published immutable layout, a reader epoch guarding
 * it, a retire list reclaiming superseded layouts, and a write lock serializing the infrequent
 * mutations
 * @layout current immutable layout
 * @epoch in-flight-reader counter guarding the layout
 * @retire deferred reclamation of superseded layouts
 * @write_lock serializes install and swap; reads are lock-free
 * @generation bumped on every published layout, so a caller can tell whether the shape it last
 * looked at is still the current one without walking it
 * @interval_tables how many of the listed sstables carry range tombstones, republished with the
 * layout, so a family that has never deleted a range answers a covering query from one load
 * @occupancy bit i set when level i+1 holds at least one sstable, republished with the layout. a
 * reader asking which levels are worth visiting reads this one word, where asking each level costs
 * an epoch enter and exit apiece -- and those are contended atomics on a counter every reader
 * shares, so the empty levels were the expensive ones
 */
struct level_set
{
    _Atomic(level_layout_t *) layout;
    tdb_epoch_t epoch;
    tdb_retire_list_t retire;
    pthread_mutex_t write_lock;
    _Atomic(uint64_t) generation;
    _Atomic(uint32_t) occupancy;
    _Atomic(uint32_t) interval_tables;
};

/* keys are ordered byte-wise; the shared prefix decides, otherwise the shorter key sorts first */
static int level_key_cmp(const uint8_t *key1, const size_t key1_size, const uint8_t *key2,
                         const size_t key2_size)
{
    const size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    /* the bounds of an sstable carrying nothing but an interval tombstone are a null pointer of no
     * length, and memcmp declares both pointers non-null whatever the count */
    const int c = min_size > 0 ? memcmp(key1, key2, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

/**
 * level_min_key_cmp
 * order two sstables by their min_key, keeping L2+ runs sorted
 * @return negative, zero, or positive as a's min_key orders before, equal to, or after b's
 */
static int level_min_key_cmp(const sstable_t *a, const sstable_t *b)
{
    return level_key_cmp(a->min_key, a->min_key_size, b->min_key, b->min_key_size);
}

/**
 * level_has_range
 * whether an sstable records the key bounds the ordered window search needs
 * @param sst the sstable
 * @return 1 when both bounds are recorded and non-empty, 0 otherwise
 */
static int level_has_range(const sstable_t *sst)
{
    return sst->min_key && sst->max_key && sst->min_key_size != 0 && sst->max_key_size != 0;
}

/**
 * level_min_key_upper_bound
 * the first index in a level sorted by min_key whose min_key orders after the given key, so
 * index - 1 is the last sstable that begins at or before it
 * @param arr the level's entries, sorted by min_key
 * @param n how many entries arr holds
 * @param key the key to bound against
 * @param key_size length of key
 * @return the index, in [0, n]
 */
static int level_min_key_upper_bound(const level_entry_t *arr, const int n, const uint8_t *key,
                                     const size_t key_size)
{
    int lo = 0, hi = n;
    while (lo < hi)
    {
        const int mid = lo + (hi - lo) / 2;
        const sstable_t *s = arr[mid].sst;
        if (level_key_cmp(s->min_key, s->min_key_size, key, key_size) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/**
 * level_ranges_overlap
 * whether an sstable's [min,max] intersects the query range [min_key,max_key]; disjoint iff
 * the sstable ends before the range starts or starts after the range ends
 */
static int level_ranges_overlap(const sstable_t *sst, const uint8_t *min_key,
                                const size_t min_key_size, const uint8_t *max_key,
                                const size_t max_key_size)
{
    /* an sstable that carries no recorded range cannot be placed, and an empty key would compare
     * below every real one and exclude the file from every query. treat it as overlapping so the
     * lookup still reads it -- consulting a file needlessly costs time, skipping one that holds the
     * key loses data */
    if (!sst->min_key || !sst->max_key || sst->min_key_size == 0 || sst->max_key_size == 0)
        return 1;

    if (level_key_cmp(sst->max_key, sst->max_key_size, min_key, min_key_size) < 0) return 0;
    if (level_key_cmp(sst->min_key, sst->min_key_size, max_key, max_key_size) > 0) return 0;
    return 1;
}

/**
 * level_layout_reclaim
 * free a superseded layout, dropping its reference on every sstable it listed; the last reference
 * to a superseded sstable closes the handle
 */
static void level_layout_reclaim(void *item, void *ctx)
{
    (void)ctx;
    level_layout_t *lay = (level_layout_t *)item;
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
    {
        for (int j = 0; j < lay->counts[i]; j++)
        {
            /* drop this layout's reference on the sstable, closing the handle on the last
             * reference */
            if (sstable_unref(lay->levels[i][j].sst)) sstable_close(lay->levels[i][j].sst);
        }
        free(lay->levels[i]);
    }
    atomic_fetch_sub_explicit(&level_live_layouts_count, 1, memory_order_relaxed);
    free(lay);
}

/**
 * level_layout_alloc
 * allocate an empty layout with room for the given per-level counts, taking no references yet
 * @param want the target entry count for each level
 * @return the new layout, or NULL on allocation failure (any partial arrays are freed)
 */
static level_layout_t *level_layout_alloc(const int *want)
{
    level_layout_t *lay = calloc(1, sizeof(level_layout_t));
    if (!lay) return NULL;
    atomic_fetch_add_explicit(&level_live_layouts_count, 1, memory_order_relaxed);
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
    {
        if (want[i] == 0) continue;
        lay->levels[i] = malloc((size_t)want[i] * sizeof(level_entry_t));
        if (!lay->levels[i])
        {
            for (int k = 0; k < i; k++) free(lay->levels[k]);
            free(lay);
            return NULL;
        }
    }
    return lay;
}

/**
 * level_insert_entry
 * place one entry into a level array that is being built, sorted by min_key for L2+ and appended
 * for L1; takes the layout's reference on the sstable
 * @param lay
 * @param level_index 0-based level index
 * @param sst
 * @param size_bytes
 */
static void level_insert_entry(level_layout_t *lay, const int level_index, sstable_t *sst,
                               const uint64_t size_bytes)
{
    level_entry_t *arr = lay->levels[level_index];
    int n = lay->counts[level_index];
    int pos = n;
    if (level_index != LEVEL_SET_L1 - 1)
    {
        pos = 0;
        while (pos < n && level_min_key_cmp(arr[pos].sst, sst) < 0) pos++;
        memmove(&arr[pos + 1], &arr[pos], (size_t)(n - pos) * sizeof(level_entry_t));
    }
    sstable_ref(sst);
    arr[pos].sst = sst;
    arr[pos].size_bytes = size_bytes;
    lay->counts[level_index] = n + 1;
}

/**
 * level_sst_in_set
 * whether an sstable pointer is one of the swap inputs, matched by identity
 */
static int level_sst_in_set(const sstable_t *sst, sstable_t *const *set, const int n)
{
    for (int i = 0; i < n; i++)
        if (set[i] == sst) return 1;
    return 0;
}

/**
 * level_publish
 * install a freshly built layout as current and retire the old one for epoch-guarded reclamation
 */
static void level_publish(level_set_t *ls, level_layout_t *fresh)
{
    uint32_t occ = 0;
    uint32_t carrying = 0;
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
    {
        if (fresh->counts[i] > 0) occ |= 1u << i;
        for (int j = 0; j < fresh->counts[i]; j++)
            if (range_tombstone_set_count(fresh->levels[i][j].sst->range_tombstones) > 0)
                carrying++;
    }

    level_layout_t *old = atomic_exchange_explicit(&ls->layout, fresh, memory_order_acq_rel);
    /* published after the layout, so a reader that sees a level occupied and then reads the layout
     * sees at least that layout.
     *
     * the other direction is the one that needs an argument: a reader can load the mask just before
     * this store and skip a level that has this instant gained its first sstable. that is safe
     * because of where the data also is. a flush installs its sstables and only then retires the
     * immutable memtable they came from, so through that whole window the same keys are still in
     * L0 -- and L0 is the first source every read and every conflict probe consults, ahead of any
     * sstable level. so a skipped brand-new level cannot hide a version from either; it is found in
     * L0 instead. shortening that window, or retiring the immutable before the install, would break
     * this */
    atomic_store_explicit(&ls->occupancy, occ, memory_order_release);
    /* the interval count rests on that same argument. a reader can load it as zero just before a
     * flush publishes the first table carrying an interval, and skip a walk that would have found
     * it -- but the memtable that flush is installing for has not been retired yet and holds the
     * same intervals, and it is asked ahead of any sstable. the count only ever drops to zero when
     * the last interval is really gone, and a reader holding a stale non-zero simply walks and
     * finds nothing */
    atomic_store_explicit(&ls->interval_tables, carrying, memory_order_release);
    /* bumped after the swap so an observer that reads the generation and then the layout cannot see
     * a new generation against the old shape */
    atomic_fetch_add_explicit(&ls->generation, 1, memory_order_release);
    tdb_retire(&ls->retire, old, &ls->epoch, level_layout_reclaim, NULL);
}

uint32_t level_set_occupancy(const level_set_t *ls)
{
    return ls ? atomic_load_explicit(&ls->occupancy, memory_order_acquire) : 0;
}

uint32_t level_set_interval_tables(const level_set_t *ls)
{
    return ls ? atomic_load_explicit(&ls->interval_tables, memory_order_acquire) : 0;
}

uint64_t level_set_generation(const level_set_t *ls)
{
    return ls ? atomic_load_explicit(&ls->generation, memory_order_acquire) : 0;
}

int level_set_create(level_set_t **out)
{
    if (!out) return -1;
    level_set_t *ls = calloc(1, sizeof(level_set_t));
    if (!ls) return -1;

    int want[LEVEL_SET_MAX_LEVELS] = {0};
    level_layout_t *empty = level_layout_alloc(want);
    if (!empty)
    {
        free(ls);
        return -1;
    }
    if (pthread_mutex_init(&ls->write_lock, NULL) != 0)
    {
        free(empty);
        free(ls);
        return -1;
    }
    atomic_init(&ls->layout, empty);
    atomic_init(&ls->epoch, 0);
    atomic_init(&ls->generation, 0);
    atomic_init(&ls->occupancy, 0);
    atomic_init(&ls->interval_tables, 0);
    ls->retire.head = NULL;
    *out = ls;
    return 0;
}

void level_set_reclaim_deferred(level_set_t *ls)
{
    if (!ls) return;
    /* reclaim superseded layouts whose reader epoch has since drained; a swap could only reclaim
     * them inline when no reader was active, so under steady reads they pile up until a sweep like
     * this */
    tdb_retire_sweep(&ls->retire);
}

void level_set_free(level_set_t *ls)
{
    if (!ls) return;
    /* drain any deferred layouts, then reclaim the current one directly */
    tdb_retire_drain(&ls->retire, NULL, NULL);
    level_layout_t *cur = atomic_load_explicit(&ls->layout, memory_order_acquire);
    if (cur) level_layout_reclaim(cur, NULL);
    pthread_mutex_destroy(&ls->write_lock);
    free(ls);
}

int level_set_install(level_set_t *ls, sstable_t *sst, const int level, const uint64_t size_bytes)
{
    if (!ls || !sst || level < LEVEL_SET_L1 || level > LEVEL_SET_MAX_LEVELS) return -1;
    const int idx = level - 1;

    pthread_mutex_lock(&ls->write_lock);
    level_layout_t *cur = atomic_load_explicit(&ls->layout, memory_order_acquire);

    int want[LEVEL_SET_MAX_LEVELS];
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++) want[i] = cur->counts[i];
    want[idx] += 1;

    level_layout_t *fresh = level_layout_alloc(want);
    if (!fresh)
    {
        pthread_mutex_unlock(&ls->write_lock);
        return -1;
    }

    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
        for (int j = 0; j < cur->counts[i]; j++)
            level_insert_entry(fresh, i, cur->levels[i][j].sst, cur->levels[i][j].size_bytes);
    level_insert_entry(fresh, idx, sst, size_bytes);

    level_publish(ls, fresh);
    pthread_mutex_unlock(&ls->write_lock);
    return 0;
}

int level_set_swap(level_set_t *ls, sstable_t *const *inputs, int n_inputs,
                   sstable_t *const *outputs, const int *out_levels, const uint64_t *out_sizes,
                   const int n_outputs)
{
    if (!ls || n_inputs < 0 || n_outputs < 0) return -1;
    if (n_inputs > 0 && !inputs) return -1;
    if (n_outputs > 0 && (!outputs || !out_levels || !out_sizes)) return -1;
    for (int i = 0; i < n_outputs; i++)
        if (out_levels[i] < LEVEL_SET_L1 || out_levels[i] > LEVEL_SET_MAX_LEVELS) return -1;

    pthread_mutex_lock(&ls->write_lock);
    level_layout_t *cur = atomic_load_explicit(&ls->layout, memory_order_acquire);

    int want[LEVEL_SET_MAX_LEVELS];
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
    {
        want[i] = 0;
        for (int j = 0; j < cur->counts[i]; j++)
            if (!level_sst_in_set(cur->levels[i][j].sst, inputs, n_inputs)) want[i]++;
    }
    for (int i = 0; i < n_outputs; i++) want[out_levels[i] - 1]++;

    level_layout_t *fresh = level_layout_alloc(want);
    if (!fresh)
    {
        pthread_mutex_unlock(&ls->write_lock);
        return -1;
    }

    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
        for (int j = 0; j < cur->counts[i]; j++)
            if (!level_sst_in_set(cur->levels[i][j].sst, inputs, n_inputs))
                level_insert_entry(fresh, i, cur->levels[i][j].sst, cur->levels[i][j].size_bytes);
    for (int i = 0; i < n_outputs; i++)
        if (outputs) level_insert_entry(fresh, out_levels[i] - 1, outputs[i], out_sizes[i]);

    level_publish(ls, fresh);
    pthread_mutex_unlock(&ls->write_lock);
    return 0;
}

int level_set_count(level_set_t *ls, const int level)
{
    if (!ls || level < LEVEL_SET_L1 || level > LEVEL_SET_MAX_LEVELS) return 0;
    tdb_epoch_enter(&ls->epoch);
    const int n = atomic_load_explicit(&ls->layout, memory_order_acquire)->counts[level - 1];
    tdb_epoch_exit(&ls->epoch);
    return n;
}

uint64_t level_set_level_bytes(level_set_t *ls, const int level)
{
    if (!ls || level < LEVEL_SET_L1 || level > LEVEL_SET_MAX_LEVELS) return 0;
    tdb_epoch_enter(&ls->epoch);
    const level_layout_t *lay = atomic_load_explicit(&ls->layout, memory_order_acquire);
    const int idx = level - 1;
    uint64_t total = 0;
    for (int j = 0; j < lay->counts[idx]; j++) total += lay->levels[idx][j].size_bytes;
    tdb_epoch_exit(&ls->epoch);
    return total;
}

int level_set_l1_overlap_depth(level_set_t *ls)
{
    return level_set_count(ls, LEVEL_SET_L1);
}

int level_set_overlapping(level_set_t *ls, const int level, const uint8_t *min_key,
                          const size_t min_key_size, const uint8_t *max_key,
                          const size_t max_key_size, sstable_t **out, const int max_out)
{
    if (!ls || level < LEVEL_SET_L1 || level > LEVEL_SET_MAX_LEVELS || !min_key || !max_key || !out)
        return -1;
    const int idx = level - 1;

    tdb_epoch_enter(&ls->epoch);
    const level_layout_t *lay = atomic_load_explicit(&ls->layout, memory_order_acquire);
    const level_entry_t *arr = lay->levels[idx];
    const int n = lay->counts[idx];

    /* L1 is unordered and its files overlap, so every one of them is a candidate. every deeper
     * level is a non-overlapping run kept sorted by min_key, and on one of those the files meeting
     * a range are a contiguous window: nothing beginning after the range's end can meet it, and
     * because the files do not overlap, nothing before the last file beginning at or before the
     * range's start can reach into it either. two binary searches find that window, which is what
     * keeps a point lookup off a scan of the whole level.
     *
     * a file that records no key bounds must be consulted by every query, and an empty key sorts
     * below every real one so such a file lands first; seeing one at the front means the ordering
     * the window rests on does not hold here, and the level is scanned instead */
    int first = 0, last = n - 1;
    if (level != LEVEL_SET_L1 && n > 0 && level_has_range(arr[0].sst))
    {
        last = level_min_key_upper_bound(arr, n, max_key, max_key_size) - 1;
        first = level_min_key_upper_bound(arr, n, min_key, min_key_size) - 1;
        if (first < 0) first = 0;
    }

    int overlapping = 0;
    for (int j = first; j <= last; j++)
    {
        sstable_t *sst = arr[j].sst;
        if (!level_ranges_overlap(sst, min_key, min_key_size, max_key, max_key_size)) continue;
        /* counting past the capacity is what lets the caller tell a complete answer from a
         * truncated one -- a caller that sized out from an earlier, smaller count would otherwise
         * take the highest sequence it could see for the highest that exists */
        if (overlapping < max_out)
        {
            /* the layout keeps sst live for this epoch; ref it so it outlives the epoch for the
             * caller, who drops the reference with sstable_unref */
            sstable_ref(sst);
            out[overlapping] = sst;
        }
        overlapping++;
    }
    tdb_epoch_exit(&ls->epoch);
    return overlapping;
}

int level_set_collect_all(level_set_t *ls, sstable_t **out, const int max)
{
    if (!ls) return 0;

    tdb_epoch_enter(&ls->epoch);
    const level_layout_t *lay = atomic_load_explicit(&ls->layout, memory_order_acquire);

    int total = 0;
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++) total += lay->counts[i];

    /* reference all or nothing so a caller that under-sized out never has to unwind partial refs */
    if (out && total <= max)
    {
        int k = 0;
        for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
            for (int j = 0; j < lay->counts[i]; j++)
            {
                sstable_ref(lay->levels[i][j].sst);
                out[k++] = lay->levels[i][j].sst;
            }
    }
    tdb_epoch_exit(&ls->epoch);
    return total;
}

int level_set_snapshot(level_set_t *ls, level_set_snapshot_entry_t *out, const int max)
{
    if (!ls) return 0;

    tdb_epoch_enter(&ls->epoch);
    const level_layout_t *lay = atomic_load_explicit(&ls->layout, memory_order_acquire);

    int total = 0;
    for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++) total += lay->counts[i];

    /* reference all or nothing so a caller that under-sized out never has to unwind partial refs */
    if (out && total <= max)
    {
        int k = 0;
        for (int i = 0; i < LEVEL_SET_MAX_LEVELS; i++)
            for (int j = 0; j < lay->counts[i]; j++)
            {
                sstable_ref(lay->levels[i][j].sst);
                out[k].sst = lay->levels[i][j].sst;
                out[k].level = i + 1;
                out[k].size_bytes = lay->levels[i][j].size_bytes;
                k++;
            }
    }
    tdb_epoch_exit(&ls->epoch);
    return total;
}
