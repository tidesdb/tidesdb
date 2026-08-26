/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "flush.h"

#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* tdb_decode_be32, TDB_CF_PREFIX_SIZE */
#include "base/errors.h"                 /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h"
#include "internal/types.h"  /* TDB_KV_FLAG_* the builder consumes, and TDB_TTL_NONE */
#include "sstable/sstable.h" /* the sstable builder and level_set install */

/* buffer for a klog file name, room for the family and sstable ids, the extension and the nul */
#define FLUSH_KLOG_NAME_MAX 64

/* longest klog path a flush opens, the database directory plus a klog file name */
#define FLUSH_KLOG_PATH_LEN (CF_DIR_PATH_LEN + FLUSH_KLOG_NAME_MAX)

/* fraction of the flushed data added as klog preallocation slack for internal nodes and the footer,
 * as a right shift; 2 adds a quarter, so a klog rarely has to extend mid-build */
#define FLUSH_KLOG_PREALLOC_SLACK_SHIFT 2

/* one built L1 sstable awaiting its manifest commit and level-set install */
typedef struct
{
    cf_t *cf;
    uint64_t cf_id;
    sstable_t *sst;
    uint64_t id;
    uint64_t num_entries;
    uint64_t size_bytes;
} flush_output_t;

/* a built-but-not-installed flush: the immutable's per-cf sstables sit on disk with their build
 * references held, ready for an ordered install. built by flush_build off the flush lock so many
 * immutables build at once, then installed one at a time in generation order by flush_install */
struct flush_job
{
    tidesdb_memtable_t *immutable;
    flush_output_t *outputs;
    int n_out;
};

/* translate a skip_list version's flag bits into the builder's kv flags */
static uint8_t flush_kv_flags(uint8_t sl_flags)
{
    uint8_t flags = 0;
    if (sl_flags & SKIP_LIST_FLAG_DELETED) flags |= TDB_KV_FLAG_TOMBSTONE;
    if (sl_flags & SKIP_LIST_FLAG_SINGLE_DELETE) flags |= TDB_KV_FLAG_SINGLE_DELETE;
    return flags;
}

/* read the cf-index prefix of the key the cursor is positioned on */
static int flush_cursor_cf_index(skip_list_cursor_t *cur, uint32_t *out_index)
{
    uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    int64_t ttl = 0;
    uint8_t flags = 0;
    uint64_t seq = 0;
    if (skip_list_cursor_get_with_seq(cur, &key, &key_size, &value, &value_size, NULL, &ttl, &flags,
                                      &seq) != 0)
        return TDB_ERR_CORRUPTION;
    if (key_size < TDB_CF_PREFIX_SIZE) return TDB_ERR_CORRUPTION;
    *out_index = tdb_decode_be32(key);
    return TDB_SUCCESS;
}

/* fill a builder config from a column family's persisted config and the flush's shared services */
static void flush_builder_config(const flush_ctx_t *fx, cf_t *cf, uint64_t id,
                                 const char *klog_path, tidesdb_column_family_config_t *cc,
                                 sstable_builder_config_t *config)
{
    /* the caller owns the snapshot because the builder config points into its pipeline array, and
     * that pointer is followed after this returns */
    cf_config_get(cf, cc);

    memset(config, 0, sizeof(*config));
    config->target_node_size = cc->btree_klog_block_size;
    config->value_threshold = cf_config_value_threshold(cc, fx->value_threshold);
    /* the watermark is the newest tombstone this build could actually see, not the floor it ran at.
     * a floor of every sequence there is would have this table claim it applied tombstones written
     * long after it was built, and the family would retire them with covered data still here */
    config->range_del_applied_seq = cf_range_tombstones_applied_through(cf, fx->gc_floor);
    config->enable_bloom = cc->enable_bloom_filter;
    config->bloom_fpr = cc->bloom_fpr;
    config->sync_mode = fx->sync_mode;
    config->id = id;
    config->partition = MANIFEST_NO_PARTITION;
    config->cf_name = cf->name;
    config->klog_path = klog_path;
    config->encoding_pipeline = cc->encoding_pipeline;
    config->encodings = cf->encodings;
    config->encoding_count = cc->encoding_count;
    config->node_cache = cf->cache;
    config->arena_pool = cf->arena_pool;
    config->now = cf->now;
    config->fdm = cf->fdm;
}

/* open a fresh klog block manager for a column family output under a newly allocated id; prealloc
 * is the on-disk extent to reserve, sized to the flushed data so a small klog does not fallocate
 * the full default chunk */
static int flush_open_klog(cf_t *cf, uint64_t id, uint64_t prealloc, char *klog_path,
                           size_t path_cap, block_manager_t **out_bm)
{
    char filename[FLUSH_KLOG_NAME_MAX];
    tidesdb_manifest_entry_t naming = {0};
    naming.id = id;
    /* the family is part of the file's name, so a table written without it would be looked for
     * under family zero and be invisible to the family that wrote it */
    naming.column_family_id = cf->cf_id;
    naming.partition = MANIFEST_NO_PARTITION;
    if (sstable_klog_filename(&naming, filename, sizeof(filename)) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;

    const int n = snprintf(klog_path, path_cap, "%s%s%s", cf->dir, PATH_SEPARATOR, filename);
    if (n < 0 || (size_t)n >= path_cap) return TDB_ERR_INVALID_ARGS;

    /* a klog is opened without per-write durability even under a syncing mode. nothing references
     * the file until the manifest commit, and the builder fsyncs it once when it finishes, so
     * making every block durable on its own only buys a device barrier per btree node -- the single
     * barrier at the end covers exactly the same bytes. the builder still gets the real sync mode
     * in its config, which is what decides that closing barrier */
    const int rc =
        cf->fdm
            ? fd_manager_bm_open_pre(cf->fdm, out_bm, klog_path, BLOCK_MANAGER_SYNC_NONE, prealloc)
            : block_manager_open_pre(out_bm, klog_path, BLOCK_MANAGER_SYNC_NONE, prealloc);
    /* the open preserved the failing syscall's errno, so a create that could not find space on the
     * device reports that rather than a generic io failure */
    if (rc != 0) return tdb_errno_to_result(errno);

    return TDB_SUCCESS;
}

/**
 * flush_retain
 * whether one version of a key survives the flush, under the same rule a merge applies: keep every
 * version above the gc floor, and the newest at or below it as the base. a memtable holds the whole
 * chain, so without this the flush would write the newest version alone and a reader whose frozen
 * snapshot sits below it would find the key absent -- the floor protects versions from a merge and
 * has to protect them here too.
 *
 * unlike a merge this never drops a base tombstone. flush output lands in L1, never the largest
 * level, and dropping a tombstone there would unshadow an older version in a deeper level
 * @param seq the version's sequence
 * @param gc_floor the oldest sequence any live snapshot can still read
 * @param kept_base in/out -- whether the base has already been taken for this key
 * @return 1 to write the version, 0 to drop it
 */
static int flush_retain(uint64_t seq, uint64_t gc_floor, int *kept_base)
{
    if (seq > gc_floor) return 1;
    if (*kept_base) return 0;
    *kept_base = 1;
    return 1;
}

/* write one version to the builder, carrying a separated value by its id rather than its bytes */
static int flush_emit(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                      const uint8_t *value, size_t value_size, uint64_t vlog_id, uint64_t seq,
                      uint8_t flags, int64_t ttl)
{
    const int64_t entry_ttl = (flags & SKIP_LIST_FLAG_DELETED) ? TDB_TTL_NONE : ttl;
    /* a value the commit already put in the value log is carried by its id. writing the bytes
     * again is what this whole path exists to avoid, and the builder would have no bytes to
     * write in any case -- the version holds none */
    return vlog_id != 0 ? sstable_builder_add_reference(
                              builder, key + TDB_CF_PREFIX_SIZE, key_size - TDB_CF_PREFIX_SIZE,
                              vlog_id, value_size, seq, entry_ttl, flush_kv_flags(flags))
                        : sstable_builder_add(builder, key + TDB_CF_PREFIX_SIZE,
                                              key_size - TDB_CF_PREFIX_SIZE, value, value_size, seq,
                                              entry_ttl, flush_kv_flags(flags));
}

/* whether a range tombstone at or below the reclamation floor deletes this version. both sets have
 * to be asked -- the family's, holding what earlier generations flushed, and this memtable's own,
 * which has not reached the family yet. a flush that skips either would still record the floor as
 * applied, and the family would go on to retire a tombstone with covered data left behind it
 * @param fx the flush context, for the floor
 * @param cf the family the run belongs to
 * @param immutable the memtable being flushed
 * @param pkey the key with its family prefix, the form the memtable's own set is keyed by
 * @param pkey_size length of pkey in bytes
 * @param seq the version's sequence
 * @return non-zero when the version is deleted out from under every reader there can still be
 */
static int flush_covered(const flush_ctx_t *fx, cf_t *cf, tidesdb_memtable_t *immutable,
                         const uint8_t *pkey, const size_t pkey_size, const uint64_t seq)
{
    uint64_t tomb = 0;
    if (cf_range_tombstone_covering(cf, pkey + TDB_CF_PREFIX_SIZE, pkey_size - TDB_CF_PREFIX_SIZE,
                                    fx->gc_floor, &tomb) &&
        tomb > seq)
        return 1;
    return tidesdb_memtable_range_tombstone_covering(fx->l0, immutable, pkey, pkey_size,
                                                     fx->gc_floor, &tomb) &&
           tomb > seq;
}

/* add every surviving version of each key in one column family's contiguous run to the builder,
 * advancing the cursor to the first key of the next column family (or the end); the run is bounded
 * by the skip_list size and each key's chain by its own length */
static int flush_add_run(const flush_ctx_t *fx, cf_t *cf, uint32_t cf_index,
                         tidesdb_memtable_t *immutable, skip_list_cursor_t *cur,
                         sstable_builder_t *builder, uint64_t *out_entries)
{
    uint64_t entries = 0;
    while (skip_list_cursor_valid(cur))
    {
        /* the whole chain for this key, newest first. the node's key is the same for every version
         * in it, so the family check is answered once from the newest */
        int kept_base = 0;
        int at_boundary = 0;
        for (;;)
        {
            uint8_t *key = NULL, *value = NULL;
            size_t key_size = 0, value_size = 0;
            uint64_t vlog_id = 0;
            int64_t ttl = 0;
            uint8_t flags = 0;
            uint64_t seq = 0;
            if (skip_list_cursor_get_with_seq(cur, &key, &key_size, &value, &value_size, &vlog_id,
                                              &ttl, &flags, &seq) != 0)
                return TDB_ERR_CORRUPTION;
            if (key_size < TDB_CF_PREFIX_SIZE) return TDB_ERR_CORRUPTION;
            if (tdb_decode_be32(key) != cf_index)
            {
                at_boundary = 1; /* the next column family's run begins here */
                break;
            }

            /* a commit whose apply failed after its batch was durable left these behind at a
             * sequence that never committed. reads already hide them; writing them into an sstable
             * would make them permanent, and outlive the memtable that is the only reason they are
             * hidden. it does not consume the base either -- a version nothing may read cannot be
             * what a snapshot resolves to */
            /* a covered version does not consume the base either -- what no reader can resolve to
             * cannot be what a snapshot resolves to */
            if (!flush_covered(fx, cf, immutable, key, key_size, seq) &&
                !tidesdb_l0_seq_aborted(fx->l0, seq) && flush_retain(seq, fx->gc_floor, &kept_base))
            {
                if (flush_emit(builder, key, key_size, value, value_size, vlog_id, seq, flags,
                               ttl) != TDB_SUCCESS)
                    return TDB_ERR_MEMORY;
                entries++;
            }

            if (skip_list_cursor_advance_in_node(cur) != 0) break; /* no older version */
        }
        if (at_boundary) break;
        if (skip_list_cursor_next(cur) != 0) break;
    }
    *out_entries = entries;
    return TDB_SUCCESS;
}

/* build one column family's L1 sstable from its run, leaving the cursor on the next family */
static int flush_build_cf(const flush_ctx_t *fx, cf_t *cf, uint32_t cf_index,
                          tidesdb_memtable_t *immutable, uint64_t prealloc, skip_list_cursor_t *cur,
                          flush_output_t *out)
{
    const uint64_t id = atomic_fetch_add(fx->next_sstable_id, 1);
    char klog_path[FLUSH_KLOG_PATH_LEN];
    block_manager_t *klog_bm = NULL;
    int rc = flush_open_klog(cf, id, prealloc, klog_path, sizeof(klog_path), &klog_bm);
    if (rc != TDB_SUCCESS) return rc;

    sstable_builder_config_t config;
    tidesdb_column_family_config_t cc;
    flush_builder_config(fx, cf, id, klog_path, &cc, &config);
    sstable_builder_t *builder = NULL;
    if (sstable_builder_new(&builder, klog_bm, cf->vlog, &config) != TDB_SUCCESS)
    {
        /* the klog was opened but never adopted by a finished sstable, so it was not counted as a
         * resident descriptor; close it without a note_close, and unlink it. nothing references a
         * file no manifest entry names, so leaving it behind is disk that is never reclaimed and
         * never read */
        (void)block_manager_close(klog_bm);
        (void)remove(klog_path);
        return TDB_ERR_MEMORY;
    }

    uint64_t num_entries = 0;
    rc = flush_add_run(fx, cf, cf_index, immutable, cur, builder, &num_entries);
    sstable_t *sst = NULL;
    uint64_t vlog_bytes = 0;
    if (rc == TDB_SUCCESS)
    {
        /* the builder's own code rather than a flat io failure, so a full device keeps saying so
         * all the way to the caller */
        const int finish_rc = sstable_builder_finish(builder, &sst, &vlog_bytes);
        if (finish_rc != TDB_SUCCESS) rc = finish_rc;
    }
    sstable_builder_free(builder);
    if (rc != TDB_SUCCESS)
    {
        /* finish did not adopt the klog on failure, so its descriptor is still ours to release, and
         * it was never counted, so no note_close. the file goes with it -- finish fsyncs the klog
         * before it builds the handle, so a failure after that point leaves a complete, durable
         * file that no manifest entry will ever name */
        (void)block_manager_close(klog_bm);
        (void)remove(klog_path);
        return rc;
    }

    uint64_t size_bytes = 0;
    (void)block_manager_get_size(klog_bm, &size_bytes);
    *out = (flush_output_t){cf, cf->cf_id, sst, id, num_entries, size_bytes};
    return TDB_SUCCESS;
}

/* advance the cursor past a dropped column family's run without building anything */
static void flush_skip_run(uint32_t cf_index, skip_list_cursor_t *cur)
{
    while (skip_list_cursor_valid(cur))
    {
        uint32_t idx = 0;
        if (flush_cursor_cf_index(cur, &idx) != TDB_SUCCESS || idx != cf_index) break;
        if (skip_list_cursor_next(cur) != 0) break;
    }
}

/**
 * flush_retract_uninstalled
 * take back the manifest entries of outputs that never reached a level set, so the catalogue names
 * exactly what is installed and the retried immutable does not flush alongside files nothing will
 * ever read. the files go only once the removal is durable -- unlinking first would leave a
 * committed manifest naming a file that is already gone, which fails the next open outright
 * @param fx the flush context
 * @param outputs the built outputs, whose handles the caller still owns
 * @param from the first output that never installed
 * @param n_out the number of outputs
 * @return nothing; a retraction that cannot be made durable leaves the entries in place, which
 *         costs a redundant file the next open adopts rather than anything unsafe
 */
static void flush_retract_uninstalled(const flush_ctx_t *fx, flush_output_t *outputs,
                                      const int from, const int n_out)
{
    int retracted = 1;
    for (int i = from; i < n_out; i++)
        if (tidesdb_manifest_remove_sstable(fx->manifest, outputs[i].cf->cf_id, LEVEL_SET_L1,
                                            outputs[i].id) != 0)
            retracted = 0;

    const int durable = fx->sync_mode != BLOCK_MANAGER_SYNC_NONE;
    if (!retracted || tidesdb_manifest_commit(fx->manifest, fx->manifest_path, durable) != 0)
    {
        TDB_DEBUG_LOG(
            TDB_LOG_WARN,
            "could not retract %d uninstalled flush output(s), the catalogue keeps naming "
            "them and the next open adopts them",
            n_out - from);
        return;
    }

    /* nothing names them now, so each file goes when the caller closes the handle holding it */
    for (int i = from; i < n_out; i++)
        if (outputs[i].sst) sstable_mark_for_deletion(outputs[i].sst);
}

/* record every output in one atomic manifest commit, then install them into the level sets */
/**
 * flush_carry_one_fragment
 * lay one of the immutable's fragments onto the family it belongs to, stripping the family prefix
 * the memtable stores it under and keeping only the sequences a reader could still resolve to
 * @param fx the flush context, for the abort set and the reclamation floor
 * @param cf the family the fragment belongs to
 * @param cf_index that family's prefix index
 * @param frag the fragment, its bounds still prefixed
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY
 */
static int flush_carry_one_fragment(const flush_ctx_t *fx, cf_t *cf, const uint32_t cf_index,
                                    const rt_fragment_t *frag)
{
    /* the upper bound is the family's own key only while it stays inside the family. a bound that
     * reached the next family's prefix, or ran off the end of the order, is unbounded once the
     * family prefix is gone -- it covers this family's keys from the lower bound on */
    const uint8_t *hi = NULL;
    size_t hi_size = RT_UNBOUNDED_ABOVE;
    if (frag->hi_size > TDB_CF_PREFIX_SIZE && tdb_decode_be32(frag->hi) == cf_index)
    {
        hi = frag->hi + TDB_CF_PREFIX_SIZE;
        hi_size = frag->hi_size - TDB_CF_PREFIX_SIZE;
    }

    /* the same retention a version gets -- every sequence a live snapshot could still be reading at
     * survives, plus the newest one at or below the floor as the base every older reader resolves
     * to
     */
    int kept_base = 0;
    for (size_t i = 0; i < frag->seq_count; i++)
    {
        const uint64_t seq = frag->seqs[i];
        if (tidesdb_l0_seq_aborted(fx->l0, seq)) continue;
        if (!flush_retain(seq, fx->gc_floor, &kept_base)) break;

        const int rc = cf_range_tombstone_add(cf, frag->lo + TDB_CF_PREFIX_SIZE,
                                              frag->lo_size - TDB_CF_PREFIX_SIZE, hi, hi_size, seq);
        if (rc != TDB_SUCCESS) return rc;
    }
    return TDB_SUCCESS;
}

/**
 * flush_carry_range_tombstones
 * move the immutable's range tombstones into the families they belong to and record each touched
 * family's whole set in the manifest batch this flush is about to commit. a family reached only by
 * a tombstone is carried here whether or not it also had keys, which is what stops a delete of a
 * prefix that wrote nothing else from being lost when its memtable retires
 * @param fx the flush context
 * @param immutable the immutable being flushed
 * @param out_any set non-zero when any family's set was recorded, so a flush with no sstables still
 *                knows it has a batch to commit
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO when the manifest refused a set
 */
static int flush_carry_range_tombstones(const flush_ctx_t *fx, tidesdb_memtable_t *immutable,
                                        int *out_any)
{
    *out_any = 0;
    if (atomic_load_explicit(&immutable->range_tombstone_frags, memory_order_acquire) == 0)
        return TDB_SUCCESS;

    /* the immutable takes no more writes, but a reader may still be resolving against its set, so
     * the walk is under the same lock a read takes rather than over a set that could be replaced */
    /* which families this flush actually reached. only those are rewritten below -- a family whose
     * set nothing here changed already has the same bytes recorded, and rewriting them would grow
     * the log and pull the next rollover forward for no change at all */
    unsigned char *touched = calloc((size_t)(fx->n_cfs > 0 ? fx->n_cfs : 1), 1);
    if (!touched) return TDB_ERR_MEMORY;

    pthread_rwlock_rdlock(&immutable->range_tombstone_lock);
    int rc = TDB_SUCCESS;
    const size_t n = range_tombstone_set_count(immutable->range_tombstones);
    for (size_t i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        const rt_fragment_t *frag = NULL;
        if (range_tombstone_set_fragment_at(immutable->range_tombstones, i, &frag) != TDB_SUCCESS ||
            frag->lo_size < TDB_CF_PREFIX_SIZE)
        {
            rc = TDB_ERR_CORRUPTION;
            break;
        }
        const uint32_t cf_index = tdb_decode_be32(frag->lo);
        cf_t *cf = (cf_index < (uint32_t)fx->n_cfs) ? fx->cfs[cf_index] : NULL;
        if (!cf) continue; /* a dropped family's tombstones go with the rest of its data */

        rc = flush_carry_one_fragment(fx, cf, cf_index, frag);
        if (rc == TDB_SUCCESS)
        {
            touched[cf_index] = 1;
            *out_any = 1;
        }
    }
    pthread_rwlock_unlock(&immutable->range_tombstone_lock);
    if (rc != TDB_SUCCESS || !*out_any)
    {
        free(touched);
        return rc;
    }

    /* record each touched family's whole set once, after every fragment has landed in it, so a
     * family reached by several fragments is written out once rather than once per fragment */
    for (int i = 0; i < fx->n_cfs && rc == TDB_SUCCESS; i++)
    {
        if (!touched[i]) continue;
        cf_t *cf = fx->cfs[i];

        uint8_t *blob = NULL;
        size_t blob_len = 0;
        rc = cf_range_tombstones_serialize(cf, &blob, &blob_len);
        if (rc != TDB_SUCCESS) break;

        if (blob_len > MANIFEST_RANGE_DEL_BLOB_MAX)
        {
            /* named rather than folded into a bare io error, because the condition is a family
             * whose range deletes have outrun the compaction that retires them, and nothing about
             * an io failure would point at that */
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "cf %s range tombstone set is %zu bytes, past the %u the manifest holds",
                          cf->name, blob_len, (unsigned)MANIFEST_RANGE_DEL_BLOB_MAX);
            rc = TDB_ERR_IO;
        }
        else if (tidesdb_manifest_set_range_dels(fx->manifest, cf->cf_id, blob,
                                                 (uint32_t)blob_len) != 0)
            rc = TDB_ERR_IO;
        free(blob);
    }
    free(touched);
    return rc;
}

static int flush_commit_and_install(const flush_ctx_t *fx, flush_output_t *outputs, int n_out,
                                    tidesdb_memtable_t *immutable)
{
    /* the tombstones go into the batch first, so a flush that carries nothing but deletes still has
     * a batch to commit and the early return below does not swallow them */
    int carried = 0;
    const int carry = flush_carry_range_tombstones(fx, immutable, &carried);
    if (carry != TDB_SUCCESS) return carry;
    if (n_out == 0 && !carried) return TDB_SUCCESS;

    for (int i = 0; i < n_out; i++)
    {
        if (tidesdb_manifest_add_sstable(fx->manifest, outputs[i].cf->cf_id, LEVEL_SET_L1,
                                         outputs[i].id, outputs[i].num_entries,
                                         outputs[i].size_bytes, MANIFEST_NO_PARTITION) == 0)
            continue;

        /* the names already written are not discarded by giving up here -- they sit in the pending
         * batch and the next commit from any path carries them, leaving the catalogue naming
         * outputs no level set ever took. take them back for the same reason the commit failure
         * below does. the ones from here on were never named, so they are not the retraction's and
         * the next open sweeps their files as orphans */
        flush_retract_uninstalled(fx, outputs, 0, i);
        return TDB_ERR_IO;
    }

    const int durable = fx->sync_mode != BLOCK_MANAGER_SYNC_NONE;
    if (tidesdb_manifest_commit(fx->manifest, fx->manifest_path, durable) != 0)
    {
        /* a commit that fails drops the records it was carrying but keeps the live set it already
         * mutated, so without this the catalogue goes on naming outputs no reader can reach and a
         * later rollover writes them out as though they had always been there */
        flush_retract_uninstalled(fx, outputs, 0, n_out);
        return TDB_ERR_IO;
    }

    /* the commit is the durability point; install now makes the sstables readable */
    for (int i = 0; i < n_out; i++)
    {
        if (level_set_install(outputs[i].cf->levels, outputs[i].sst, LEVEL_SET_L1,
                              outputs[i].size_bytes) == 0)
            continue;

        /* the installs that already landed belong to their level sets now, so their build
         * references go here and the entries are cleared. the caller's failure path closes whatever
         * it still names, and closing an installed table would free it out from under the level set
         * holding a reference to it */
        for (int j = 0; j < i; j++)
        {
            if (sstable_unref(outputs[j].sst)) sstable_close(outputs[j].sst);
            outputs[j].sst = NULL;
        }
        /* the ones from here on are still this call's, and the catalogue already names them from
         * the commit above. retract those entries so the retry does not flush the same keys a
         * second time beside files that no level set will ever hold */
        flush_retract_uninstalled(fx, outputs, i, n_out);
        return TDB_ERR_MEMORY;
    }

    /* the installs have landed, so the family's tables now include this flush's outputs and their
     * floor. a tombstone every one of them has applied has nothing left to hide, and this is the
     * first moment that can be true of the tombstones this same flush just carried in */
    for (int i = 0; i < n_out; i++)
    {
        size_t dropped = 0;
        if (cf_range_tombstones_sweep(outputs[i].cf, &dropped) != TDB_SUCCESS || dropped == 0)
            continue;

        uint8_t *blob = NULL;
        size_t blob_len = 0;
        if (cf_range_tombstones_serialize(outputs[i].cf, &blob, &blob_len) != TDB_SUCCESS) continue;
        /* a failure here costs nothing but the retirement -- the set in memory is already smaller,
         * and the record it did not replace replays as the larger one it superseded */
        (void)tidesdb_manifest_set_range_dels(fx->manifest, outputs[i].cf->cf_id, blob,
                                              (uint32_t)blob_len);
        free(blob);
        (void)tidesdb_manifest_commit(fx->manifest, fx->manifest_path,
                                      fx->sync_mode != BLOCK_MANAGER_SYNC_NONE);
    }

    /* settled only once every install has landed. lowering each family's count as its own install
     * went would, on a failure part-way, leave the families already installed counted as drained
     * for keys the retried immutable flushes again, and the second pass lowers them a second time.
     * the drift only ever goes one way, so the count a caller reads back under-reports what the
     * memtables actually hold -- stats clamps the negative away rather than correcting it */
    for (int i = 0; i < n_out; i++)
    {
        /* these keys leave the memtables for L1, so lower the family's unflushed count by the
         * distinct keys the built sstable holds; read it before the reference is dropped */
        const int64_t drained = (int64_t)outputs[i].sst->distinct_key_count;
        if (sstable_unref(outputs[i].sst)) sstable_close(outputs[i].sst);
        outputs[i].sst = NULL; /* owned by the level set now */
        atomic_fetch_sub_explicit(&outputs[i].cf->unflushed_key_count, drained,
                                  memory_order_relaxed);
    }
    return TDB_SUCCESS;
}

int flush_build(const flush_ctx_t *fx, tidesdb_memtable_t *immutable, flush_job_t **out_job)
{
    if (!fx || !immutable || !immutable->skip_list || !out_job) return TDB_ERR_INVALID_ARGS;
    *out_job = NULL;

    /* a writer that passed the active-slot check before this memtable rotated is still committed to
     * inserting into its skip list, so drain the writers epoch before cursoring; otherwise the
     * cursor can pass a key's position before that late insert lands and the built sstable would
     * omit a committed key, losing it once the immutable is retired from L0 */
    tdb_epoch_wait_drained(&immutable->writers);

    skip_list_cursor_t *cur = NULL;
    if (skip_list_cursor_init(&cur, immutable->skip_list) != 0) return TDB_ERR_IO;

    /* size each output klog's preallocation to the flushed data rather than the full default chunk,
     * so a small immutable does not fallocate 64 MB per column family; the block manager still
     * extends if a run outgrows the estimate. the whole immutable size bounds any single family's
     * klog, and the cap keeps a large immutable at the default */
    const uint64_t data = skip_list_get_data_bytes(immutable->skip_list);
    uint64_t prealloc = data + (data >> FLUSH_KLOG_PREALLOC_SLACK_SHIFT);
    if (prealloc == 0 || prealloc > BLOCK_MANAGER_PREALLOC_CHUNK)
        prealloc = BLOCK_MANAGER_PREALLOC_CHUNK;

    const int cap = fx->n_cfs > 0 ? fx->n_cfs : 1;
    flush_output_t *outputs = malloc((size_t)cap * sizeof(*outputs));
    if (!outputs)
    {
        skip_list_cursor_free(cur);
        return TDB_ERR_MEMORY;
    }

    int n_out = 0;
    int rc = TDB_SUCCESS;
    if (skip_list_cursor_goto_first(cur) == 0)
    {
        while (rc == TDB_SUCCESS && skip_list_cursor_valid(cur))
        {
            uint32_t cf_index = 0;
            rc = flush_cursor_cf_index(cur, &cf_index);
            if (rc != TDB_SUCCESS) break;

            cf_t *cf = (cf_index < (uint32_t)fx->n_cfs) ? fx->cfs[cf_index] : NULL;
            if (!cf)
            {
                /* traced because a family id that came back into use would silently route this run
                 * into whichever family now holds the index instead of discarding it */
                TDB_DEBUG_LOG(TDB_LOG_TRACE, "flush discarding run for retired cf index %u",
                              cf_index);
                flush_skip_run(cf_index, cur); /* a dropped family's data is discarded */
                continue;
            }
            rc = flush_build_cf(fx, cf, cf_index, immutable, prealloc, cur, &outputs[n_out]);
            if (rc == TDB_SUCCESS) n_out++;
        }
    }
    skip_list_cursor_free(cur);

    if (rc != TDB_SUCCESS)
    {
        for (int i = 0; i < n_out; i++)
            if (outputs[i].sst) sstable_close(outputs[i].sst);
        free(outputs);
        return rc;
    }

    flush_job_t *job = malloc(sizeof(*job));
    if (!job)
    {
        for (int i = 0; i < n_out; i++)
            if (outputs[i].sst) sstable_close(outputs[i].sst);
        free(outputs);
        return TDB_ERR_MEMORY;
    }
    job->immutable = immutable;
    job->outputs = outputs;
    job->n_out = n_out;
    *out_job = job;
    return TDB_SUCCESS;
}

int flush_install(const flush_ctx_t *fx, flush_job_t *job)
{
    if (!fx || !job) return TDB_ERR_INVALID_ARGS;

    const int rc = flush_commit_and_install(fx, job->outputs, job->n_out, job->immutable);
    if (rc == TDB_SUCCESS)
    {
        tidesdb_memtable_mark_flushed(job->immutable);
        /* the immutable's data is durable in L1 now, so its WAL descriptor is released and the file
         * unlinked here; a crash between the install commit and this unlink only re-flushes the
         * generation on reopen, which is idempotent at the entries' own sequences */
        block_manager_t *wal = atomic_load_explicit(&job->immutable->wal, memory_order_acquire);
        if (wal)
        {
            char wal_path[MAX_FILE_PATH_LENGTH];
            snprintf(wal_path, sizeof(wal_path), "%s", wal->file_path);
            (void)block_manager_close(wal);
            if (fx->fdm) fd_manager_note_close(fx->fdm, FD_LABEL_WAL_LOG);
            /* a prepared batch is durable only in its log until phase two decides it, and it never
             * enters a memtable, so a generation can look fully flushed while still holding the
             * only copy of one. the descriptor is released either way, but this generation's file
             * stays if an undecided prepare may live in it. a generation below the floor holds
             * nothing in doubt and its data is in L1, so it goes now -- keeping it because some
             * unrelated transaction elsewhere is undecided would grow the store without bound under
             * a workload that always has one in flight */
            const uint64_t generation = job->immutable->generation;
            const int pinned = fx->wal_generation_pinned &&
                               fx->wal_generation_pinned(fx->on_wal_retained_ctx, generation);
            if (!pinned)
                (void)remove(wal_path);
            else if (fx->on_wal_retained)
                fx->on_wal_retained(fx->on_wal_retained_ctx, wal_path, generation);
        }
        /* the L1 segment is installed and visible, so drop the immutable from the reader-visible
         * queue and reclaim it -- a no-op on the queue for a dequeued immutable, a real removal for
         * a claimed one, which is how the flush visibility gap is closed */
        tidesdb_l0_retire_immutable(fx->l0, job->immutable);

        /* account the flush output bytes and let the engine consider each cf for compaction */
        for (int i = 0; i < job->n_out; i++)
        {
            atomic_fetch_add_explicit(&job->outputs[i].cf->flush_bytes_written,
                                      job->outputs[i].size_bytes, memory_order_relaxed);
            atomic_fetch_add_explicit(&job->outputs[i].cf->flush_count, 1, memory_order_relaxed);
            if (fx->on_flush) fx->on_flush(fx->on_flush_ctx, job->outputs[i].cf->cf_id);

            /* one line per output rather than per flush, so the record says which family grew and
             * by how much -- the two things a read-amplification question starts from */
            TDB_DEBUG_LOG(TDB_LOG_INFO, "flushed cf %s to l1 sstable %llu, %llu entries %llu bytes",
                          job->outputs[i].cf->name, (unsigned long long)job->outputs[i].id,
                          (unsigned long long)job->outputs[i].num_entries,
                          (unsigned long long)job->outputs[i].size_bytes);
        }
    }
    else
    {
        /* leave the immutable for a retry -- its data is still durable in its WAL -- and close any
         * built-but-not-installed sstables */
        for (int i = 0; i < job->n_out; i++)
            if (job->outputs[i].sst) sstable_close(job->outputs[i].sst);
    }
    free(job->outputs);
    free(job);
    return rc;
}

int flush_job_rebind(flush_job_t *job, cf_t *const *cfs, int n_cfs)
{
    if (!job) return TDB_ERR_INVALID_ARGS;

    int kept = 0;
    for (int i = 0; i < job->n_out; i++)
    {
        const uint64_t cf_id = job->outputs[i].cf_id;
        cf_t *cf = (cfs && cf_id < (uint64_t)n_cfs) ? cfs[cf_id] : NULL;
        if (!cf)
        {
            /* the family was dropped between the build and this install, and the drop deleted its
             * directory, so this output names a file that is gone or about to be. installing it
             * would put an entry in the manifest for a family the manifest no longer has */
            TDB_DEBUG_LOG(TDB_LOG_INFO,
                          "flush output for cf %llu discarded, the family was dropped",
                          (unsigned long long)cf_id);
            if (job->outputs[i].sst) sstable_close(job->outputs[i].sst);
            continue;
        }
        job->outputs[kept] = job->outputs[i];
        job->outputs[kept].cf = cf;
        kept++;
    }
    job->n_out = kept;
    return TDB_SUCCESS;
}

void flush_job_free(flush_job_t *job)
{
    if (!job) return;
    for (int i = 0; i < job->n_out; i++)
        if (job->outputs[i].sst) sstable_close(job->outputs[i].sst);
    free(job->outputs);
    free(job);
}

int flush_immutable(const flush_ctx_t *fx, tidesdb_memtable_t *immutable)
{
    flush_job_t *job = NULL;
    const int rc = flush_build(fx, immutable, &job);
    if (rc != TDB_SUCCESS) return rc;
    return flush_install(fx, job);
}
