/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "compaction_exec.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* the key log name format */
#include "base/errors.h"                 /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/keycmp.h"                 /* tdb_key_cmp, the one byte-wise key order */
#include "base/log.h"
#include "column_family/level/level_set.h" /* level_set_collect_all, level_set_swap */
#include "compat.h"                        /* PATH_SEPARATOR */
#include "internal/types.h"                /* TDB_KV_FLAG_TOMBSTONE */
#include "iter/merge_iter.h"
#include "iter/merge_sources.h"

/* the full path a compaction output opens, a family directory and a key log name within it */
#define CE_KLOG_PATH_LEN (CF_DIR_PATH_LEN + TDB_SSTABLE_KLOG_NAME_MAX)

/* how many output slots to grow the sink's array by at a time */
#define CE_OUTPUTS_GROW 8

/* how many times a layout snapshot is retried when the level set grew past the array it was given
 */
#define CE_SNAPSHOT_RETRIES 8

/* how many sstables one level of the base-tombstone sibling scan inspects; a level that fills this
 * many leaves the rest of the level unread, so absence is unproven and the tombstone is kept */
#define CE_TOMB_SIBLING_MAX 64

/* reference the job's input sstables from the live level set, summing their on-disk sizes into
 * read_bytes and recording each one's size in out_sizes so a rollback can put its catalogue entry
 * back; returns 0 with the handles on success, 1 when an input was already compacted away by a
 * raced job (skip the job), or a negative error */
static int ce_resolve_inputs(const compaction_ctx_t *cx, const compaction_job_t *job,
                             sstable_t **out, uint64_t *out_sizes, int *n_out, uint64_t *read_bytes)
{
    *read_bytes = 0;
    int total = level_set_snapshot(cx->cf->levels, NULL, 0);
    level_set_snapshot_entry_t *all = NULL;
    /* how many entries the collect actually wrote, which is not the capacity it was given -- the
     * count and the collect are two loads of a live layout, and a compaction retiring inputs
     * between them leaves the tail of the array holding whatever the allocator did. reading it as
     * an sstable pointer is a garbage dereference, and unreferencing it below is worse */
    int filled = 0;
    if (total > 0)
    {
        for (int tries = 0; tries < CE_SNAPSHOT_RETRIES; tries++)
        {
            all = malloc((size_t)total * sizeof(*all));
            if (!all) return TDB_ERR_MEMORY;
            const int got = level_set_snapshot(cx->cf->levels, all, total);
            if (got <= total)
            {
                filled = got;
                break;
            }
            free(all);
            all = NULL;
            total = got;
        }
        if (!all) return TDB_ERR_BUSY;
    }

    int n = 0;
    int stale = 0;
    for (int j = 0; j < job->n_inputs && !stale; j++)
    {
        sstable_t *found = NULL;
        uint64_t found_size = 0;
        for (int i = 0; i < filled; i++)
            if (all[i].sst && all[i].sst->id == job->input_ids[j])
            {
                found = all[i].sst;
                found_size = all[i].size_bytes;
                *read_bytes += all[i].size_bytes;
                all[i].sst = NULL;
                break;
            }
        if (found)
        {
            out_sizes[n] = found_size;
            out[n++] = found;
        }
        else
            stale = 1;
    }

    for (int i = 0; i < filled; i++)
        if (all[i].sst && sstable_unref(all[i].sst)) sstable_close(all[i].sst);
    free(all);

    if (stale)
    {
        for (int i = 0; i < n; i++)
            if (sstable_unref(out[i])) sstable_close(out[i]);
        return 1;
    }
    *n_out = n;
    return 0;
}

/* the output-building sink: the current in-progress output plus the finished ones, so a merge can
 * roll to a new file at a boundary or a size cap without the write loop knowing the details */
typedef struct
{
    const compaction_ctx_t *cx;
    sstable_t **outputs;
    uint64_t *sizes;
    int n_outputs;
    int cap_outputs;

    block_manager_t *cur_bm;
    sstable_builder_t *cur_builder;
    int cur_open;
    int cur_partition; /* index of the boundary partition the current output holds */
    /* the intervals this merge's inputs carried, borrowed, written into every output it produces.
     * an interval lives as long as a table holding it, so a merge that retires its inputs has to
     * hand what they carried to what replaces them or the deletes go with the files */
    const range_tombstone_set_t *carried;
} ce_sink_t;

/* fill a builder config from the cf's persisted config and the compaction's shared services */
static void ce_builder_config(const compaction_ctx_t *cx, uint64_t id, const char *klog_path,
                              tidesdb_column_family_config_t *cc, sstable_builder_config_t *config)
{
    /* the caller owns the snapshot because the builder config points into its pipeline array, and
     * that pointer is followed after this returns */
    cf_config_get(cx->cf, cc);

    memset(config, 0, sizeof(*config));
    config->target_node_size = cc->btree_klog_block_size;
    config->value_threshold = cf_config_value_threshold(cc, cx->value_threshold);
    config->enable_bloom = cc->enable_bloom_filter;
    config->bloom_fpr = cc->bloom_fpr;
    config->sync_mode = cx->sync_mode;
    config->id = id;
    config->partition = MANIFEST_NO_PARTITION;
    config->cf_name = cx->cf->name;
    config->klog_path = klog_path;
    config->encoding_pipeline = cc->encoding_pipeline;
    config->encodings = cx->cf->encodings;
    config->encoding_count = cc->encoding_count;
    config->node_cache = cx->cf->cache;
    config->arena_pool = cx->cf->arena_pool;
    config->now = cx->cf->now;
    config->fdm = cx->cf->fdm;
}

/* open a fresh klog and builder as the sink's current output under a newly allocated id */
static int ce_sink_open(ce_sink_t *s)
{
    const uint64_t id = atomic_fetch_add(s->cx->next_sstable_id, 1);
    tidesdb_manifest_entry_t naming = {0};
    naming.column_family_id = s->cx->cf->cf_id;
    naming.id = id;
    naming.partition = MANIFEST_NO_PARTITION;
    char filename[TDB_SSTABLE_KLOG_NAME_MAX], klog_path[CE_KLOG_PATH_LEN];
    if (sstable_klog_filename(&naming, filename, sizeof(filename)) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;
    const int len =
        snprintf(klog_path, sizeof(klog_path), "%s%s%s", s->cx->cf->dir, PATH_SEPARATOR, filename);
    if (len < 0 || (size_t)len >= sizeof(klog_path)) return TDB_ERR_INVALID_ARGS;

    /* opened without per-write durability even under a syncing mode -- nothing reads a merge output
     * until it installs, and the builder's closing fsync covers the whole file, so a barrier per
     * block would only slow the merge down. the builder config below still carries the real sync
     * mode, which is what drives that closing barrier */
    if (s->cx->cf->fdm ? fd_manager_bm_open(s->cx->cf->fdm, &s->cur_bm, klog_path,
                                            BLOCK_MANAGER_SYNC_NONE, FD_LABEL_SSTABLE_KLOG)
                       : block_manager_open(&s->cur_bm, klog_path, BLOCK_MANAGER_SYNC_NONE))
        return TDB_ERR_IO;

    sstable_builder_config_t config;
    tidesdb_column_family_config_t cc;
    ce_builder_config(s->cx, id, klog_path, &cc, &config);
    config.range_tombstones = s->carried;
    if (sstable_builder_new(&s->cur_builder, s->cur_bm, s->cx->cf->vlog, &config) != TDB_SUCCESS)
    {
        /* the klog was never adopted, so it was not counted; close it without a note_close, and
         * unlink it -- no manifest entry will ever name this file */
        (void)block_manager_close(s->cur_bm);
        s->cur_bm = NULL;
        (void)remove(klog_path);
        return TDB_ERR_MEMORY;
    }
    s->cur_open = 1;
    return TDB_SUCCESS;
}

/* finish the current output and append it to the finished list */
static int ce_sink_seal(ce_sink_t *s)
{
    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    if (sstable_builder_finish(s->cur_builder, &sst, &vlog_bytes) != TDB_SUCCESS)
    {
        /* the path is taken from the handle before it closes, since the file has to go with it --
         * finish fsyncs the klog before building its handle, so a failure after that leaves a
         * complete, durable file that no manifest entry will ever name */
        /* sized to the block manager's own path field rather than to this module's shorter klog
         * path, so copying one into the other cannot truncate and unlink the wrong name */
        char orphan[MAX_FILE_PATH_LENGTH];
        snprintf(orphan, sizeof(orphan), "%s", s->cur_bm->file_path);
        sstable_builder_free(s->cur_builder);
        (void)block_manager_close(s->cur_bm);
        s->cur_bm = NULL;
        s->cur_open = 0;
        (void)remove(orphan);
        return TDB_ERR_IO;
    }
    sstable_builder_free(s->cur_builder);
    s->cur_open = 0;

    if (s->n_outputs == s->cap_outputs)
    {
        const int cap = s->cap_outputs + CE_OUTPUTS_GROW;
        sstable_t **o = realloc(s->outputs, (size_t)cap * sizeof(*o));
        uint64_t *z = realloc(s->sizes, (size_t)cap * sizeof(*z));
        if (o) s->outputs = o;
        if (z) s->sizes = z;
        if (!o || !z)
        {
            sstable_close(sst);
            return TDB_ERR_MEMORY;
        }
        s->cap_outputs = cap;
    }
    uint64_t size = 0;
    (void)block_manager_get_size(s->cur_bm, &size);
    s->outputs[s->n_outputs] = sst;
    s->sizes[s->n_outputs] = size;
    s->n_outputs++;
    return TDB_SUCCESS;
}

/* the boundary partition a key falls in -- the count of boundaries at or below it */
static int ce_partition_of(const compaction_job_t *job, const uint8_t *key, size_t key_size)
{
    int p = 0;
    while (p < job->n_boundaries &&
           tdb_key_cmp(key, key_size, job->boundaries[p], job->boundary_sizes[p]) >= 0)
        p++;
    return p;
}

/* roll to a new output before this key if the split policy calls for it */
static int ce_sink_maybe_roll(ce_sink_t *s, const compaction_job_t *job, const uint8_t *key,
                              size_t key_size)
{
    const int part = ce_partition_of(job, key, key_size);
    if (s->cur_open)
    {
        /* the two reasons are independent: a partitioned merge still caps each partition's output,
         * and a cap alone splits an unaligned merge. the caller rolls only on a new distinct key,
         * so neither ever divides a key's version chain */
        const int at_boundary =
            job->split == COMPACTION_SPLIT_BOUNDARIES && part > s->cur_partition;
        const int at_cap =
            job->file_max > 0 && sstable_builder_klog_bytes(s->cur_builder) >= job->file_max;
        if ((at_boundary || at_cap) && ce_sink_seal(s) != TDB_SUCCESS) return TDB_ERR_IO;
    }
    s->cur_partition = part;
    return TDB_SUCCESS;
}

/* write one retained version, opening the current output lazily so an all-GC'd run makes no file */
static int ce_sink_add(ce_sink_t *s, const uint8_t *key, size_t key_size, const uint8_t *value,
                       size_t value_size, uint64_t vlog_offset, uint64_t seq, int64_t ttl,
                       uint8_t flags)
{
    if (!s->cur_open)
    {
        const int rc = ce_sink_open(s);
        if (rc != TDB_SUCCESS) return rc;
    }
    const int wr = vlog_offset != 0
                       ? sstable_builder_add_reference(s->cur_builder, key, key_size, vlog_offset,
                                                       value_size, seq, ttl, flags)
                       : sstable_builder_add(s->cur_builder, key, key_size, value, value_size, seq,
                                             ttl, flags);
    if (wr != TDB_SUCCESS) return wr;
    return TDB_SUCCESS;
}

/* discard the sink on failure: close any open output and drop the finished ones */
static void ce_sink_discard(ce_sink_t *s)
{
    if (s->cur_open)
    {
        sstable_builder_free(s->cur_builder);
        (void)block_manager_close(s->cur_bm);
    }
    for (int i = 0; i < s->n_outputs; i++) sstable_close(s->outputs[i]);
    free(s->outputs);
    free(s->sizes);
}

/* decide whether the current merged version is retained under MVCC: keep every version above the GC
 * floor, keep the newest at or below it as the base, drop the rest; a base tombstone at the largest
 * level below the floor is dropped as GC */
static int ce_retain(const compaction_ctx_t *cx, int is_largest, uint64_t seq, int deleted,
                     int *kept_base)
{
    if (seq > cx->gc_floor) return 1;
    if (*kept_base) return 0;
    *kept_base = 1;
    if (deleted && is_largest) return 0;
    return 1;
}

/* whether it is safe to GC-drop a base tombstone for key: safe only when no sstable outside the
 * merge inputs holds the key, since the largest level (and L1) are tiered and an older version in a
 * sibling sstable the merge did not see would resurrect once the tombstone that shadows it is gone
 */
static int ce_safe_to_drop_tomb(cf_t *cf, const uint8_t *key, size_t klen, const uint64_t *inputs,
                                int n_inputs)
{
    int safe = 1;
    for (int lvl = 1; lvl <= LEVEL_SET_MAX_LEVELS && safe; lvl++)
    {
        sstable_t *out[CE_TOMB_SIBLING_MAX];
        const int nn =
            level_set_overlapping(cf->levels, lvl, key, klen, key, klen, out, CE_TOMB_SIBLING_MAX);
        if (nn < 0)
        {
            safe = 0; /* the level could not be read, so no sibling is ruled out */
            break;
        }
        /* the scan reports how many overlap, which may exceed what it could store; only the stored
         * prefix is referenced, and a level that overflowed leaves an unread sibling that could
         * still hold an older version */
        const int stored = nn < CE_TOMB_SIBLING_MAX ? nn : CE_TOMB_SIBLING_MAX;
        if (nn >= CE_TOMB_SIBLING_MAX) safe = 0;
        for (int i = 0; i < stored; i++)
        {
            int is_input = 0;
            for (int q = 0; q < n_inputs; q++)
                if (out[i]->id == inputs[q])
                {
                    is_input = 1;
                    break;
                }
            if (!is_input)
            {
                uint8_t *v = NULL;
                size_t vs = 0;
                uint64_t vo = 0, sq = 0;
                int64_t tl = 0;
                uint8_t dl = 0;
                const int grc = sstable_get(out[i], key, klen, &v, &vs, &vo, &sq, &tl, &dl);
                if (grc == TDB_SUCCESS) free(v);
                /* only a definitive miss proves this sibling holds no older version. a hit, or any
                 * transient read error that leaves absence unconfirmed, means the base tombstone
                 * must stay or an older version the sibling still holds would resurrect */
                if (grc != TDB_ERR_NOT_FOUND) safe = 0;
            }
        }
        for (int i = 0; i < stored; i++)
            if (sstable_unref(out[i])) sstable_close(out[i]);
    }
    return safe;
}

/* iterate the raw merge over [begin, end), applying retention and the split policy, into the sink.
 * a NULL begin starts at the first key and a NULL end runs to the last, which is the whole range
 * and what an undivided job passes */
static int ce_write_merged(const compaction_ctx_t *cx, const compaction_job_t *job,
                           merge_iter_t *merge, ce_sink_t *sink, const uint8_t *begin,
                           size_t begin_size, const uint8_t *end, size_t end_size)
{
    uint8_t *prev_key = NULL;
    size_t prev_key_size = 0, prev_key_cap = 0;
    int kept_base = 0;
    int rc = begin ? merge_iter_seek(merge, begin, begin_size) : merge_iter_seek_first(merge);
    while (rc == TDB_SUCCESS)
    {
        const uint8_t *key = NULL, *value = NULL;
        size_t key_size = 0, value_size = 0;
        uint64_t seq = 0, vlog_offset = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        (void)merge_iter_get(merge, &key, &key_size, &seq, &value, &value_size, &vlog_offset, &ttl,
                             &deleted);

        /* the bound is exclusive and lands on a boundary key, which is a real key from the level
         * above -- so every version of every key below it has already been seen, and the range that
         * starts here begins with that key's own versions rather than the tail of this one's */
        if (end && tdb_key_cmp(key, key_size, end, end_size) >= 0) break;

        if (!prev_key || tdb_key_cmp(key, key_size, prev_key, prev_key_size) != 0)
        {
            kept_base = 0;
            if (ce_sink_maybe_roll(sink, job, key, key_size) != TDB_SUCCESS)
            {
                free(prev_key);
                return TDB_ERR_IO;
            }
            if (key_size > prev_key_cap)
            {
                uint8_t *grown = realloc(prev_key, key_size);
                if (!grown)
                {
                    free(prev_key);
                    return TDB_ERR_MEMORY;
                }
                prev_key = grown;
                prev_key_cap = key_size;
            }
            memcpy(prev_key, key, key_size);
            prev_key_size = key_size;
        }

        const int was_base = kept_base;
        int keep = ce_retain(cx, job->is_largest_level, seq, deleted, &kept_base);

        /* a range tombstone at or below the reclamation floor deletes this version for every reader
         * there can still be, so the version goes -- the base ce_retain kept included, since
         * nothing can resolve to it any more. the tombstone itself stays until it is provably
         * spent, so the data it shadows in a sibling this merge did not touch is still covered */
        uint64_t range_tomb_seq = 0;
        if (keep &&
            cf_range_tombstone_covering(cx->cf, key, key_size, cx->gc_floor, &range_tomb_seq) &&
            range_tomb_seq > seq)
            keep = 0;
        /* a base tombstone is only GC'd when no sstable outside the merge still holds the key; a
         * sibling in the tiered largest level or L1 that the merge did not include would otherwise
         * resurrect the older version once the shadowing tombstone is dropped */
        if (!keep && deleted && job->is_largest_level && !was_base && kept_base)
        {
            if (ce_safe_to_drop_tomb(cx->cf, key, key_size, job->input_ids, job->n_inputs))
                /* the point of no return for a delete -- once this tombstone is gone any older
                 * version a sibling still holds becomes visible again */
                TDB_DEBUG_LOG(TDB_LOG_TRACE, "dropping base tombstone cf %s key %.*s seq %llu",
                              cx->cf->name, (int)key_size, (const char *)key,
                              (unsigned long long)seq);
            else
                keep = 1;
        }
        if (keep)
        {
            const uint8_t flags = deleted ? TDB_KV_FLAG_TOMBSTONE : 0;
            /* a tombstone carries no deadline of its own, including one that lapsed and became a
             * tombstone on the way in here, which is how the flush writes one too */
            const int64_t entry_ttl = deleted ? TDB_TTL_NONE : ttl;
            const int wr = ce_sink_add(sink, key, key_size, value, value_size, vlog_offset, seq,
                                       entry_ttl, flags);
            if (wr != TDB_SUCCESS)
            {
                free(prev_key);
                return wr;
            }
        }
        rc = merge_iter_next(merge);
    }
    free(prev_key);
    /* two ways out are both a finished range: the merge ran out (not found), or the loop stopped at
     * the upper bound while it still had entries (success). only a real error skips the seal */
    if (rc != TDB_SUCCESS && rc != TDB_ERR_NOT_FOUND) return rc;
    return sink->cur_open ? ce_sink_seal(sink) : TDB_SUCCESS;
}

/* build the raw merge over the input sstables and drive the write of one key range */
static int ce_merge_inputs(const compaction_ctx_t *cx, const compaction_job_t *job,
                           sstable_t *const *inputs, int n_inputs, ce_sink_t *sink,
                           const uint8_t *begin, size_t begin_size, const uint8_t *end,
                           size_t end_size)
{
    sstable_iter_t **iters = calloc((size_t)n_inputs, sizeof(*iters));
    merge_source_t *sources = calloc((size_t)n_inputs, sizeof(*sources));
    if (!iters || !sources)
    {
        free(iters);
        free(sources);
        return TDB_ERR_MEMORY;
    }

    int rc = TDB_SUCCESS;
    for (int i = 0; i < n_inputs && rc == TDB_SUCCESS; i++)
    {
        if (sstable_iter_new(inputs[i], 0, &iters[i]) != TDB_SUCCESS) /* bypass the cache */
            rc = TDB_ERR_IO;
        else
            sstable_merge_source(iters[i], &sources[i]);
    }

    merge_iter_t *merge = NULL;
    if (rc == TDB_SUCCESS &&
        merge_iter_new(sources, n_inputs, UINT64_MAX, MERGE_ITER_RAW, &merge) != TDB_SUCCESS)
        rc = TDB_ERR_MEMORY;
    if (rc == TDB_SUCCESS)
        rc = ce_write_merged(cx, job, merge, sink, begin, begin_size, end, end_size);

    merge_iter_free(merge);
    for (int i = 0; i < n_inputs; i++) sstable_iter_free(iters[i]);
    free(iters);
    free(sources);
    return rc;
}

/* one worker's share of a subdivided merge: a contiguous run of the job's boundary partitions, and
 * the sink the outputs for that run are built into */
typedef struct
{
    const compaction_ctx_t *cx;
    const compaction_job_t *job;
    sstable_t *const *inputs;
    int n_inputs;
    ce_sink_t sink;
    const uint8_t *begin;
    size_t begin_size;
    const uint8_t *end;
    size_t end_size;
    int rc;
} ce_range_task_t;

static void *ce_range_thread(void *arg)
{
    ce_range_task_t *t = (ce_range_task_t *)arg;
    t->rc = ce_merge_inputs(t->cx, t->job, t->inputs, t->n_inputs, &t->sink, t->begin,
                            t->begin_size, t->end, t->end_size);
    return NULL;
}

/* how many ways to split a job's range: one per boundary partition at most, and never more threads
 * than the context allows */
static int ce_subdivisions(const compaction_ctx_t *cx, const compaction_job_t *job)
{
    if (!job->may_subdivide || job->n_boundaries <= 0) return 1;
    const int parts = job->n_boundaries + 1;
    int k = cx->max_subdivisions;
    if (k < 1) k = 1;
    if (k > parts) k = parts;
    return k;
}

/* give task t the boundary partitions [lo, hi) as a half-open key range. partition 0 opens at the
 * first key and the last closes at the last, so those two ends carry no bound */
static void ce_range_bounds(ce_range_task_t *t, const compaction_job_t *job, int lo, int hi)
{
    t->begin = lo == 0 ? NULL : job->boundaries[lo - 1];
    t->begin_size = lo == 0 ? 0 : job->boundary_sizes[lo - 1];
    t->end = hi > job->n_boundaries ? NULL : job->boundaries[hi - 1];
    t->end_size = hi > job->n_boundaries ? 0 : job->boundary_sizes[hi - 1];
}

/* move every output a worker built into the combined sink the commit reads, leaving the worker's
 * own arrays empty so tearing it down frees nothing the commit still owns */
static int ce_sink_absorb(ce_sink_t *dst, ce_sink_t *src)
{
    /* grown once, before anything moves. growing inside the loop would let a failure return with
     * some of src's outputs already handed to dst and the rest still counted by src -- and the
     * caller discards src on the way out, which would close what dst now owns */
    if (dst->n_outputs + src->n_outputs > dst->cap_outputs)
    {
        const int cap = dst->n_outputs + src->n_outputs + CE_OUTPUTS_GROW;
        sstable_t **o = realloc(dst->outputs, (size_t)cap * sizeof(*o));
        if (o) dst->outputs = o;
        uint64_t *z = realloc(dst->sizes, (size_t)cap * sizeof(*z));
        if (z) dst->sizes = z;
        if (!o || !z) return TDB_ERR_MEMORY;
        dst->cap_outputs = cap;
    }

    for (int i = 0; i < src->n_outputs; i++)
    {
        dst->outputs[dst->n_outputs] = src->outputs[i];
        dst->sizes[dst->n_outputs] = src->sizes[i];
        dst->n_outputs++;
    }
    free(src->outputs);
    free(src->sizes);
    src->outputs = NULL;
    src->sizes = NULL;
    src->n_outputs = 0;
    src->cap_outputs = 0;
    return TDB_SUCCESS;
}

/* run a job's merge as k independent key ranges and gather their outputs into one sink.
 *
 * the ranges are the boundary partitions the job would have written one after another anyway, so
 * the files produced are the same files -- what changes is that several are built at once. the
 * ranges share the input sstables, which are immutable and already referenced, and each holds its
 * own cursors over them. every version of a key stays in one range because the split keys are real
 * keys and the bound is exclusive, so retention and tombstone collection see a whole version chain
 * just as they would in one pass
 * @param cx the compaction context
 * @param job the job, whose boundaries divide the range
 * @param inputs the resolved input sstables, shared by every range
 * @param n_inputs the number of inputs
 * @param k how many ranges to split into
 * @param sink out -- the combined outputs of every range
 * @return TDB_SUCCESS when every range completed, else the first failure
 */
static int ce_merge_subdivided(const compaction_ctx_t *cx, const compaction_job_t *job,
                               sstable_t *const *inputs, int n_inputs, int k, ce_sink_t *sink)
{
    ce_range_task_t *tasks = calloc((size_t)k, sizeof(*tasks));
    pthread_t *tids = calloc((size_t)k, sizeof(*tids));
    if (!tasks || !tids)
    {
        free(tasks);
        free(tids);
        return TDB_ERR_MEMORY;
    }

    const int parts = job->n_boundaries + 1;
    const int base = parts / k;
    const int extra = parts % k;

    int lo = 0;
    int started = 0;
    for (int i = 0; i < k; i++)
    {
        const int hi = lo + base + (i < extra ? 1 : 0);
        tasks[i].cx = cx;
        tasks[i].job = job;
        tasks[i].inputs = inputs;
        tasks[i].n_inputs = n_inputs;
        tasks[i].sink.cx = cx;
        tasks[i].rc = TDB_SUCCESS;
        ce_range_bounds(&tasks[i], job, lo, hi);
        lo = hi;
    }

    /* the last range runs here rather than on a thread of its own, so k ranges cost k-1 threads and
     * the caller is never idle waiting on work it could have done */
    for (int i = 0; i < k - 1; i++)
    {
        if (pthread_create(&tids[i], NULL, ce_range_thread, &tasks[i]) != 0) break;
        started++;
    }
    /* a range whose thread never started is run here too, so a failure to spawn costs parallelism
     * rather than correctness */
    for (int i = started; i < k; i++) ce_range_thread(&tasks[i]);
    for (int i = 0; i < started; i++) pthread_join(tids[i], NULL);

    int rc = TDB_SUCCESS;
    for (int i = 0; i < k; i++)
        if (tasks[i].rc != TDB_SUCCESS && rc == TDB_SUCCESS) rc = tasks[i].rc;

    for (int i = 0; i < k; i++)
    {
        if (rc == TDB_SUCCESS)
        {
            const int arc = ce_sink_absorb(sink, &tasks[i].sink);
            if (arc != TDB_SUCCESS) rc = arc;
        }
        /* absorb emptied the ones it took, so this only discards what a failure left behind */
        ce_sink_discard(&tasks[i].sink);
    }

    free(tasks);
    free(tids);
    return rc;
}

/**
 * ce_rollback_commit
 * put the catalogue back the way the merge found it after a swap that could not be published --
 * the inputs named again at the levels they were removed from, the outputs unnamed. without it the
 * catalogue keeps naming outputs no level set ever took, and the next compaction of the same inputs
 * names a second set of them, so a reopen adopts both
 * @param cx the compaction context
 * @param job the job, whose target level the outputs were catalogued at
 * @param inputs the resolved input sstables, still installed because the swap did not happen
 * @param in_levels the level each input was catalogued at, or 0 where it was already unnamed
 * @param in_sizes the on-disk size each input's entry recorded
 * @param n_inputs the number of inputs
 * @param sink the outputs, whose entries are withdrawn
 * @param n_catalogued how many of the outputs reached the catalogue, which is all of them once the
 *                     naming loop finished and a prefix of them when it did not
 * @return TDB_SUCCESS when the catalogue is back and the output files may go, else TDB_ERR_IO with
 *         the catalogue left naming the outputs -- which a reopen adopts, so the data is whole
 *         either way and the cost is a redundant set of files
 */
static int ce_rollback_commit(const compaction_ctx_t *cx, const compaction_job_t *job,
                              sstable_t *const *inputs, const int *in_levels,
                              const uint64_t *in_sizes, int n_inputs, ce_sink_t *sink,
                              int n_catalogued)
{
    int restored = 1;
    for (int i = 0; i < n_inputs; i++)
        if (in_levels[i] > 0 &&
            tidesdb_manifest_add_sstable(cx->manifest, cx->cf->cf_id, in_levels[i], inputs[i]->id,
                                         inputs[i]->distinct_key_count, in_sizes[i],
                                         MANIFEST_NO_PARTITION) != 0)
            restored = 0;

    for (int i = 0; i < n_catalogued; i++)
        if (tidesdb_manifest_remove_sstable(cx->manifest, cx->cf->cf_id, job->target_level,
                                            sink->outputs[i]->id) != 0)
            restored = 0;

    const int durable = cx->sync_mode != BLOCK_MANAGER_SYNC_NONE;
    if (!restored || tidesdb_manifest_commit(cx->manifest, cx->manifest_path, durable) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "could not roll the catalogue back after a failed swap on cf %s, it keeps "
                      "naming %d output(s) the next open adopts",
                      cx->cf->name, sink->n_outputs);
        return TDB_ERR_IO;
    }

    /* nothing names them now, so the discard that closes each handle takes its file with it */
    for (int i = 0; i < sink->n_outputs; i++) sstable_mark_for_deletion(sink->outputs[i]);
    return TDB_SUCCESS;
}

/* record the outputs and removed inputs in one manifest batch, then swap the level set */
static int ce_commit(const compaction_ctx_t *cx, const compaction_job_t *job,
                     sstable_t *const *inputs, const uint64_t *in_sizes, int n_inputs,
                     ce_sink_t *sink)
{
    /* kept so a swap that cannot be published can name them again at the levels they came from.
     * zeroed, because a naming loop that stops partway leaves the rest untouched and a rollback
     * reads a zero as an input it never took out of the catalogue */
    int in_stack[CE_OUTPUTS_GROW] = {0};
    int *in_levels = n_inputs <= CE_OUTPUTS_GROW ? in_stack : calloc((size_t)n_inputs, sizeof(int));
    if (!in_levels) return TDB_ERR_MEMORY;

    for (int i = 0; i < n_inputs; i++)
    {
        in_levels[i] =
            tidesdb_manifest_find_level_by_id(cx->manifest, cx->cf->cf_id, inputs[i]->id);
        if (in_levels[i] > 0 && tidesdb_manifest_remove_sstable(cx->manifest, cx->cf->cf_id,
                                                                in_levels[i], inputs[i]->id) != 0)
        {
            /* this one is still named, so it is not the rollback's to restate -- the ones before it
             * are. rolling back rather than simply returning matters because the records already
             * written sit in the manifest's pending batch, and the next commit from any path at all
             * would carry them: inputs durably disowned, with the replacement never named */
            in_levels[i] = 0;
            (void)ce_rollback_commit(cx, job, inputs, in_levels, in_sizes, n_inputs, sink, 0);
            if (in_levels != in_stack) free(in_levels);
            return TDB_ERR_IO;
        }
    }

    int catalogued = 0;
    for (int i = 0; i < sink->n_outputs; i++)
    {
        if (tidesdb_manifest_add_sstable(cx->manifest, cx->cf->cf_id, job->target_level,
                                         sink->outputs[i]->id, sink->outputs[i]->distinct_key_count,
                                         sink->sizes[i], MANIFEST_NO_PARTITION) != 0)
        {
            (void)ce_rollback_commit(cx, job, inputs, in_levels, in_sizes, n_inputs, sink,
                                     catalogued);
            if (in_levels != in_stack) free(in_levels);
            return TDB_ERR_IO;
        }
        catalogued++;
    }

    const int durable = cx->sync_mode != BLOCK_MANAGER_SYNC_NONE;
    if (tidesdb_manifest_commit(cx->manifest, cx->manifest_path, durable) != 0)
    {
        /* the commit dropped its records but kept the live set it already mutated, so the catalogue
         * would otherwise go on naming outputs nothing installed and disowning inputs the level set
         * still serves -- and a later rollover would write that out as the truth */
        (void)ce_rollback_commit(cx, job, inputs, in_levels, in_sizes, n_inputs, sink, catalogued);
        if (in_levels != in_stack) free(in_levels);
        return TDB_ERR_IO;
    }

    int levels[CE_OUTPUTS_GROW];
    int *out_levels =
        sink->n_outputs <= CE_OUTPUTS_GROW ? levels : malloc((size_t)sink->n_outputs * sizeof(int));
    if (!out_levels)
    {
        if (in_levels != in_stack) free(in_levels);
        return TDB_ERR_MEMORY;
    }
    for (int i = 0; i < sink->n_outputs; i++) out_levels[i] = job->target_level;
    const int rc = level_set_swap(cx->cf->levels, inputs, n_inputs, sink->outputs, out_levels,
                                  sink->sizes, sink->n_outputs);
    if (out_levels != levels) free(out_levels);

    if (rc != 0)
    {
        (void)ce_rollback_commit(cx, job, inputs, in_levels, in_sizes, n_inputs, sink, catalogued);
        if (in_levels != in_stack) free(in_levels);
        return TDB_ERR_MEMORY;
    }
    if (in_levels != in_stack) free(in_levels);

    /* the swap is published and the catalogue no longer names the inputs, so their files may go.
     * marking rather than unlinking is what makes it safe: a reader can still be inside one, and
     * the unlink happens when its last reference drops. it waits until here because a swap that
     * failed leaves the inputs as the live data, and a mark taken before that would send their
     * files with them the moment the level set let go */
    for (int i = 0; i < n_inputs; i++) sstable_mark_for_deletion(inputs[i]);

    return TDB_SUCCESS;
}

/**
 * ce_interval_contained
 * whether every sstable reaching into a fragment's range is one this merge is consuming, so no key
 * the interval covers survives outside what the merge has just read
 *
 * asked once per fragment rather than once per sequence, since the answer is a property of the
 * range and every sequence on the fragment shares it
 * @param cf the family being compacted
 * @param frag the fragment whose range is being asked about
 * @param inputs the ids of the tables this merge is consuming
 * @param n_inputs how many
 * @return 1 when nothing outside the merge reaches the range, 0 when something does or might
 */
static int ce_interval_contained(cf_t *cf, const rt_fragment_t *frag, const uint64_t *inputs,
                                 const int n_inputs)
{
    /* an unbounded end, or a lower bound of no bytes, names a range the overlap scan cannot be
     * asked about, and an interval that is only ever carried costs space rather than correctness */
    if (frag->lo_size == 0 || frag->hi_size == RT_UNBOUNDED_ABOVE) return 0;

    for (int lvl = 1; lvl <= LEVEL_SET_MAX_LEVELS; lvl++)
    {
        sstable_t *out[CE_TOMB_SIBLING_MAX];
        /* the scan's upper bound is inclusive where the interval's is not, so a table beginning
         * exactly at the interval's end is counted as reaching in when it does not. that keeps an
         * interval a merge could have dropped, which is the direction to be wrong in */
        const int nn = level_set_overlapping(cf->levels, lvl, frag->lo, frag->lo_size, frag->hi,
                                             frag->hi_size, out, CE_TOMB_SIBLING_MAX);
        if (nn < 0) return 0; /* the level could not be read, so nothing is ruled out */

        const int stored = nn < CE_TOMB_SIBLING_MAX ? nn : CE_TOMB_SIBLING_MAX;
        int reaches = nn >= CE_TOMB_SIBLING_MAX; /* a truncated level leaves a table unseen */
        for (int i = 0; i < stored; i++)
        {
            int is_input = 0;
            for (int q = 0; q < n_inputs; q++)
                if (out[i]->id == inputs[q])
                {
                    is_input = 1;
                    break;
                }
            /* a table carrying only intervals holds no key the merge could have missed, and it is
             * the one kind of table the overlap scan returns for every range it is asked about */
            if (!is_input && out[i]->min_key && out[i]->min_key_size != 0) reaches = 1;
        }
        for (int i = 0; i < stored; i++)
            if (sstable_unref(out[i])) sstable_close(out[i]);
        if (reaches) return 0;
    }
    return 1;
}

/**
 * ce_union_intervals
 * the union of the intervals this merge's inputs carry, for its outputs to carry in their place
 *
 * an interval lives as long as a table holding it. the inputs are retired by this merge, so what
 * they carried has to reach what replaces them or every delete they held is lost with their files.
 * one this merge has finished the work of is left behind instead, which is the only thing that
 * bounds what a table accumulates
 * @param cx the compaction context, for the family and the reclamation floor
 * @param job the job being run, for its input ids and whether it writes the largest level
 * carrying none and failing to carry them are reported apart. this merge deletes the files its
 * inputs live in, so an interval that does not reach the output is not delayed but gone, and the
 * keys it covered come back
 * @param inputs the tables being merged
 * @param n_inputs how many
 * @param out receives a set the caller frees, or NULL when no input carries any
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the union could not be built
 */
static int ce_union_intervals(const compaction_ctx_t *cx, const compaction_job_t *job,
                              sstable_t *const *inputs, int n_inputs, range_tombstone_set_t **out)
{
    *out = NULL;
    range_tombstone_set_t *set = NULL;
    for (int i = 0; i < n_inputs; i++)
    {
        if (!inputs[i] || !inputs[i]->range_tombstones) continue;
        const size_t n = range_tombstone_set_count(inputs[i]->range_tombstones);
        for (size_t f = 0; f < n; f++)
        {
            const rt_fragment_t *frag = NULL;
            if (range_tombstone_set_fragment_at(inputs[i]->range_tombstones, f, &frag) !=
                TDB_SUCCESS)
                continue;

            /* the merge has finished a sequence's work when it writes the largest level, nothing
             * below it holding an older version, when every table the range reaches is one it has
             * just read, and when the sequence is at or below the floor -- which is what says every
             * reader that can still exist already sees it applied, and is the same ceiling the
             * per-entry drop ran under, so the keys it covered really are gone rather than carried
             * past. what is finished is left behind, and that is the only thing bounding what a
             * table accumulates */
            const int finished = job->is_largest_level &&
                                 ce_interval_contained(cx->cf, frag, job->input_ids, job->n_inputs);

            for (size_t k = 0; k < frag->seq_count; k++)
            {
                if (finished && frag->seqs[k] <= cx->gc_floor) continue;
                if (!set && !(set = range_tombstone_set_new())) return TDB_ERR_MEMORY;
                const int added = range_tombstone_set_add(set, frag->lo, frag->lo_size,
                                                          frag->hi_size ? frag->hi : NULL,
                                                          frag->hi_size, frag->seqs[k]);
                if (added != TDB_SUCCESS)
                {
                    range_tombstone_set_free(set);
                    return added;
                }
            }
        }
    }
    *out = set;
    return TDB_SUCCESS;
}

int compaction_exec(const compaction_ctx_t *cx, const compaction_job_t *job)
{
    if (!cx || !cx->cf || !job || job->n_inputs <= 0 || !job->input_ids)
        return TDB_ERR_INVALID_ARGS;

    sstable_t **inputs = malloc((size_t)job->n_inputs * sizeof(*inputs));
    /* their catalogued sizes, kept beside them so a rollback can restate the entries a failed swap
     * has already had removed */
    uint64_t *in_sizes = malloc((size_t)job->n_inputs * sizeof(*in_sizes));
    if (!inputs || !in_sizes)
    {
        free(inputs);
        free(in_sizes);
        return TDB_ERR_MEMORY;
    }
    int n_inputs = 0;
    uint64_t read_bytes = 0;
    const int resolved = ce_resolve_inputs(cx, job, inputs, in_sizes, &n_inputs, &read_bytes);
    if (resolved != 0)
    {
        free(inputs);
        free(in_sizes);
        return resolved > 0 ? TDB_SUCCESS : resolved; /* a stale job is a no-op, not a failure */
    }

    ce_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    sink.cx = cx;
    /* borrowed by the sink for the length of the merge; every output clones what it is given */
    range_tombstone_set_t *carried = NULL;
    /* built before anything is written, so a failure to gather what the inputs carry stops the
     * merge while its inputs are still installed and the whole job can be run again */
    int rc = ce_union_intervals(cx, job, inputs, n_inputs, &carried);
    sink.carried = carried;
    const int k = ce_subdivisions(cx, job);
    if (rc == TDB_SUCCESS)
        rc = k > 1 ? ce_merge_subdivided(cx, job, inputs, n_inputs, k, &sink)
                   : ce_merge_inputs(cx, job, inputs, n_inputs, &sink, NULL, 0, NULL, 0);
    if (rc == TDB_SUCCESS) rc = ce_commit(cx, job, inputs, in_sizes, n_inputs, &sink);

    if (rc == TDB_SUCCESS)
    {
        uint64_t written = 0;
        for (int i = 0; i < sink.n_outputs; i++) written += sink.sizes[i];
        atomic_fetch_add_explicit(&cx->cf->compaction_bytes_read, read_bytes, memory_order_relaxed);
        atomic_fetch_add_explicit(&cx->cf->compaction_bytes_written, written, memory_order_relaxed);
        atomic_fetch_add_explicit(&cx->cf->compaction_count, 1, memory_order_relaxed);

        /* the file counts and the two byte totals are what a write-amplification question is asked
         * in, and a merge that keeps writing as much as it reads is the shape of a level that is
         * not converging */
        TDB_DEBUG_LOG(TDB_LOG_INFO,
                      "compacted cf %s to level %d, %d files in %d out over %d range%s, %llu bytes "
                      "read %llu written",
                      cx->cf->name, job->target_level, n_inputs, sink.n_outputs, k,
                      k == 1 ? "" : "s", (unsigned long long)read_bytes,
                      (unsigned long long)written);

        /* the level set took its own references and dropped the inputs' structural references */
        for (int i = 0; i < sink.n_outputs; i++)
            if (sstable_unref(sink.outputs[i])) sstable_close(sink.outputs[i]);
        free(sink.outputs);
        free(sink.sizes);
    }
    else
    {
        ce_sink_discard(&sink);
    }
    for (int i = 0; i < n_inputs; i++)
        if (sstable_unref(inputs[i])) sstable_close(inputs[i]);
    range_tombstone_set_free(carried);
    free(inputs);
    free(in_sizes);
    return rc;
}
