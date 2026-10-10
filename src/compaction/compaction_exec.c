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
#include "compaction_internal.h"
#include "compat.h"         /* PATH_SEPARATOR */
#include "internal/types.h" /* TDB_KV_FLAG_TOMBSTONE */
#include "iter/merge_iter.h"
#include "iter/merge_sources.h"

/* the full path a compaction output opens, a family directory and a key log name within it */
#define CE_KLOG_PATH_LEN (CF_DIR_PATH_LEN + TDB_SSTABLE_KLOG_NAME_MAX)

/* how many times a layout snapshot is retried when the level set grew past the array it was given
 */
#define CE_SNAPSHOT_RETRIES 8

/* reference the job's input sstables from the live level set, summing their on-disk sizes into
 * read_bytes, recording each one's size in out_sizes so a rollback can put its catalogue entry
 * back, and the shallowest level any of them sits at in shallowest; returns 0 with the handles on
 * success, 1 when an input was already compacted away by a raced job (skip the job), or a negative
 * error */
static int ce_resolve_inputs(const compaction_ctx_t *cx, const compaction_job_t *job,
                             sstable_t **out, uint64_t *out_sizes, int *n_out, uint64_t *read_bytes,
                             int *shallowest)
{
    *read_bytes = 0;
    *shallowest = 0;
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
                if (*shallowest == 0 || all[i].level < *shallowest) *shallowest = all[i].level;
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

/* a merge that dropped every version still hands on the intervals it has not finished, and an
 * interval lives only in a table, so where there would be no output one is written to carry them */
static int ce_sink_carry_alone(ce_sink_t *s)
{
    if (s->n_outputs > 0 || s->cur_open || !s->carried) return TDB_SUCCESS;
    const int rc = ce_sink_open(s);
    return rc == TDB_SUCCESS ? ce_sink_seal(s) : rc;
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
 * merge inputs holds an older version of the key, since one the merge did not see would resurrect
 * once the tombstone that shadows it is gone. levels above the shallowest input are not asked.
 * deeper is older for every key, so what a table up there holds is newer than anything the merge
 * reads and stays the key's answer whatever the merge drops -- and asking would refuse the drop for
 * a key written again after its delete, and for every key once the flush tier holds more tables
 * than the check can look at
 */
static int ce_safe_to_drop_tomb(cf_t *cf, const uint8_t *key, size_t klen, const uint64_t *inputs,
                                int n_inputs, int from_level)
{
    int safe = 1;
    for (int lvl = from_level > 1 ? from_level : 1; lvl <= LEVEL_SET_MAX_LEVELS && safe; lvl++)
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

/**
 * ce_key_state_t
 * what the write loop carries from one version of a key to the next
 * @param key the key being merged, copied since the merge moves under it
 * @param key_size the copy's length
 * @param key_cap the copy's allocated size
 * @param kept_base whether the key's base version has been seen
 * @param sd_held whether a single-delete base is held back until the version beneath it is seen
 * @param sd_seq the held single-delete's sequence number
 */
typedef struct
{
    uint8_t *key;
    size_t key_size;
    size_t key_cap;
    int kept_base;
    int sd_held;
    uint64_t sd_seq;
} ce_key_state_t;

/* write one retained version. a tombstone carries no deadline of its own, including one that lapsed
 * and became a tombstone on the way in here, which is how the flush writes one too, and a
 * single-delete keeps its subtype so a later merge that meets its put can still drop the pair */
static int ce_add_version(ce_sink_t *sink, const uint8_t *key, size_t key_size,
                          const uint8_t *value, size_t value_size, uint64_t vlog_offset,
                          uint64_t seq, int64_t ttl, uint8_t deleted)
{
    const uint8_t flags =
        deleted ? (uint8_t)(TDB_KV_FLAG_TOMBSTONE | (deleted & TDB_KV_FLAG_SINGLE_DELETE)) : 0;
    const int64_t entry_ttl = deleted ? TDB_TTL_NONE : ttl;
    return ce_sink_add(sink, key, key_size, value, value_size, vlog_offset, seq, entry_ttl, flags);
}

/* settle a held single-delete. it goes with the put beneath it at any level, or alone at the
 * largest level as any base tombstone does, and in both only when no sstable outside the merge
 * holds the key. the promise of a single put is the caller's, and a second put in a table the merge
 * did not see would come back if it were trusted. kept, it is written back still a single-delete */
static int ce_release_single_delete(const compaction_ctx_t *cx, const compaction_job_t *job,
                                    ce_sink_t *sink, ce_key_state_t *st, int met_put)
{
    if (!st->sd_held) return TDB_SUCCESS;
    st->sd_held = 0;
    if ((met_put || job->is_largest_level) &&
        ce_safe_to_drop_tomb(cx->cf, st->key, st->key_size, job->input_ids, job->n_inputs,
                             job->shallowest_input_level))
    {
        TDB_DEBUG_LOG(TDB_LOG_TRACE, "dropping single-delete cf %s key %.*s seq %llu", cx->cf->name,
                      (int)st->key_size, (const char *)st->key, (unsigned long long)st->sd_seq);
        return TDB_SUCCESS;
    }
    return ce_add_version(sink, st->key, st->key_size, NULL, 0, 0, st->sd_seq, TDB_TTL_NONE,
                          TDB_KV_FLAG_TOMBSTONE | TDB_KV_FLAG_SINGLE_DELETE);
}

/* on the first version of a new key, settle what the previous key left held, roll the output at a
 * boundary, and copy the key */
static int ce_enter_key(const compaction_ctx_t *cx, const compaction_job_t *job, ce_sink_t *sink,
                        ce_key_state_t *st, const uint8_t *key, size_t key_size)
{
    if (st->key && tdb_key_cmp(key, key_size, st->key, st->key_size) == 0) return TDB_SUCCESS;
    const int rc = ce_release_single_delete(cx, job, sink, st, 0);
    if (rc != TDB_SUCCESS) return rc;
    st->kept_base = 0;
    if (ce_sink_maybe_roll(sink, job, key, key_size) != TDB_SUCCESS) return TDB_ERR_IO;
    if (key_size > st->key_cap)
    {
        uint8_t *grown = realloc(st->key, key_size);
        if (!grown) return TDB_ERR_MEMORY;
        st->key = grown;
        st->key_cap = key_size;
    }
    memcpy(st->key, key, key_size);
    st->key_size = key_size;
    return TDB_SUCCESS;
}

/* apply retention to one version of the current key and write it when it stays */
static int ce_place_version(const compaction_ctx_t *cx, const compaction_job_t *job,
                            ce_sink_t *sink, ce_key_state_t *st, const uint8_t *value,
                            size_t value_size, uint64_t vlog_offset, uint64_t seq, int64_t ttl,
                            uint8_t deleted)
{
    const uint8_t *key = st->key;
    const size_t key_size = st->key_size;
    /* the version beneath a held single-delete settles it, a live put being the one it pairs with.
     * everything beneath the base is dropped below, so nothing of this key is written after it */
    if (st->sd_held)
    {
        const int rc = ce_release_single_delete(cx, job, sink, st, !deleted);
        if (rc != TDB_SUCCESS) return rc;
    }

    const int was_base = st->kept_base;
    int keep = ce_retain(cx, job->is_largest_level, seq, deleted, &st->kept_base);
    const int is_base = !was_base && st->kept_base;

    /* a range tombstone at or below the reclamation floor deletes this version for every reader
     * there can still be, so the version goes -- the base ce_retain kept included, since
     * nothing can resolve to it any more. the tombstone itself stays until it is provably
     * spent, so the data it shadows in a sibling this merge did not touch is still covered */
    uint64_t range_tomb_seq = 0;
    if (keep && cf_range_tombstone_covering(cx->cf, key, key_size, cx->gc_floor, &range_tomb_seq) &&
        range_tomb_seq > seq)
        keep = 0;

    /* a single-delete base waits for the version beneath it, which is where its put would be */
    if (is_base && (deleted & TDB_KV_FLAG_SINGLE_DELETE) && (keep || job->is_largest_level))
    {
        st->sd_held = 1;
        st->sd_seq = seq;
        return TDB_SUCCESS;
    }
    /* a base tombstone is only GC'd when no sstable outside the merge still holds the key; a
     * sibling in the tiered largest level or L1 that the merge did not include would otherwise
     * resurrect the older version once the shadowing tombstone is dropped */
    if (!keep && deleted && job->is_largest_level && is_base)
    {
        if (ce_safe_to_drop_tomb(cx->cf, key, key_size, job->input_ids, job->n_inputs,
                                 job->shallowest_input_level))
            /* the point of no return for a delete -- once this tombstone is gone any older
             * version a sibling still holds becomes visible again */
            TDB_DEBUG_LOG(TDB_LOG_TRACE, "dropping base tombstone cf %s key %.*s seq %llu",
                          cx->cf->name, (int)key_size, (const char *)key, (unsigned long long)seq);
        else
            keep = 1;
    }
    if (!keep) return TDB_SUCCESS;
    return ce_add_version(sink, key, key_size, value, value_size, vlog_offset, seq, ttl, deleted);
}

/* iterate the raw merge over [begin, end), applying retention and the split policy, into the sink.
 * a NULL begin starts at the first key and a NULL end runs to the last, which is the whole range
 * and what an undivided job passes */
static int ce_write_merged(const compaction_ctx_t *cx, const compaction_job_t *job,
                           merge_iter_t *merge, ce_sink_t *sink, const uint8_t *begin,
                           size_t begin_size, const uint8_t *end, size_t end_size)
{
    ce_key_state_t st;
    memset(&st, 0, sizeof(st));
    int wr = TDB_SUCCESS;
    int rc = begin ? merge_iter_seek(merge, begin, begin_size) : merge_iter_seek_first(merge);
    while (rc == TDB_SUCCESS && wr == TDB_SUCCESS)
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

        wr = ce_enter_key(cx, job, sink, &st, key, key_size);
        if (wr == TDB_SUCCESS)
            wr = ce_place_version(cx, job, sink, &st, value, value_size, vlog_offset, seq, ttl,
                                  deleted);
        if (wr == TDB_SUCCESS) rc = merge_iter_next(merge);
    }
    /* the last key's single-delete has no version beneath it in this range */
    if (wr == TDB_SUCCESS) wr = ce_release_single_delete(cx, job, sink, &st, 0);
    free(st.key);
    if (wr != TDB_SUCCESS) return wr;
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
    tdb_thread_t *tids = calloc((size_t)k, sizeof(*tids));
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
        if (tdb_thread_start(&tids[i], ce_range_thread, &tasks[i]) != 0) break;
        started++;
    }
    /* a range whose thread never started is run here too, so a failure to spawn costs parallelism
     * rather than correctness */
    for (int i = started; i < k; i++) ce_range_thread(&tasks[i]);
    for (int i = 0; i < started; i++) tdb_thread_finish(&tids[i]);

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
    int shallowest = 0;
    const int resolved =
        ce_resolve_inputs(cx, job, inputs, in_sizes, &n_inputs, &read_bytes, &shallowest);
    if (resolved != 0)
    {
        free(inputs);
        free(in_sizes);
        return resolved > 0 ? TDB_SUCCESS : resolved; /* a stale job is a no-op, not a failure */
    }
    /* the merge runs a copy that knows where its inputs sit, which the planner cannot promise */
    compaction_job_t run = *job;
    run.shallowest_input_level = shallowest;

    ce_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    sink.cx = cx;
    /* borrowed by the sink for the length of the merge; every output clones what it is given */
    range_tombstone_set_t *carried = NULL;
    /* built before anything is written, so a failure to gather what the inputs carry stops the
     * merge while its inputs are still installed and the whole job can be run again */
    int rc = ce_union_intervals(cx, &run, inputs, n_inputs, &carried);
    sink.carried = carried;
    const int k = ce_subdivisions(cx, &run);
    if (rc == TDB_SUCCESS)
        rc = k > 1 ? ce_merge_subdivided(cx, &run, inputs, n_inputs, k, &sink)
                   : ce_merge_inputs(cx, &run, inputs, n_inputs, &sink, NULL, 0, NULL, 0);
    if (rc == TDB_SUCCESS) rc = ce_sink_carry_alone(&sink);
    if (rc == TDB_SUCCESS) rc = ce_commit(cx, &run, inputs, in_sizes, n_inputs, &sink);

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
