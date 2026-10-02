/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h"
#include "column_family/level/level_set.h" /* level_set_overlapping, level_set_swap */
#include "compaction_internal.h"

/* the commit side of a compaction -- naming its outputs and disowning its inputs in one manifest
 * batch, swapping the level set, rolling the catalogue back when a step fails, and gathering the
 * intervals the inputs carried for the outputs to carry in their place */

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

int ce_commit(const compaction_ctx_t *cx, const compaction_job_t *job, sstable_t *const *inputs,
              const uint64_t *in_sizes, int n_inputs, ce_sink_t *sink)
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

int ce_union_intervals(const compaction_ctx_t *cx, const compaction_job_t *job,
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
