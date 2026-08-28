/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* the sstable filename format constants */
#include "base/errors.h"                 /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/log.h" /* TDB_DEBUG_LOG for a failed unlink of a superseded file */
#include "sstable_internal.h"
#include "xxhash.h" /* XXH64 for the node-cache key prefix */

/* the reference count a freshly opened sstable starts at -- the one owning reference the caller
 * holds */
#define TDB_SSTABLE_REF_OWNER 1

/* upper bound on a .klog file name, generous against the zero-padded id and the extension */
#define TDB_SSTABLE_KLOG_NAME_MAX 96

/* sstable klog files are named by id alone (globally unique), zero-padded to this width; the
 * manifest still records level and partition for placement, they are not in the file name */
#define TDB_SSTABLE_ID_DIGITS 7

/* the owning family's id leads the name. every family's files share the one database directory, so
 * the name is the only thing that says which family a file belongs to */
#define TDB_SSTABLE_CF_DIGITS 10

int sstable_klog_filename(const tidesdb_manifest_entry_t *entry, char *out, size_t out_size)
{
    if (!entry || !out || out_size == 0) return TDB_ERR_INVALID_ARGS;

    const int n = snprintf(out, out_size, "%0*llu.%0*llu%s", TDB_SSTABLE_CF_DIGITS,
                           (unsigned long long)entry->column_family_id, TDB_SSTABLE_ID_DIGITS,
                           (unsigned long long)entry->id, TDB_SSTABLE_KLOG_EXT);
    if (n <= 0 || (size_t)n >= out_size) return TDB_ERR_INVALID_ARGS;
    return TDB_SUCCESS;
}

/* allocate an sstable handle and fill the identity fields both create paths share, adopting
 * klog_path (freed here on allocation failure); the handle starts at the owner reference with no
 * open klog */
/* handles alive right now, raised here and lowered in sstable_close, which are the only two places
 * one is created or destroyed. a closed database owns no sstables, so this returning to where it
 * started is a whole-store statement about the reference counting that no single test can make --
 * a handle dropped without being closed shows up here and nowhere else until a leak checker
 * notices it at process exit, by which point the path that dropped it is long gone */
static _Atomic(int64_t) sstable_live_handles_count;

int64_t sstable_live_handles(void)
{
    return atomic_load_explicit(&sstable_live_handles_count, memory_order_relaxed);
}

sstable_t *sstable_alloc_owning_path(uint64_t id, int partition, char *klog_path,
                                     const char *cf_name, int sync_mode)
{
    sstable_t *sst = calloc(1, sizeof(*sst));
    if (!sst)
    {
        free(klog_path);
        return NULL;
    }
    atomic_fetch_add_explicit(&sstable_live_handles_count, 1, memory_order_relaxed);

    sst->id = id;
    sst->partition = partition;
    sst->klog_path = klog_path;
    const char *sep = strrchr(klog_path, PATH_SEPARATOR[0]);
    sst->klog_filename = sep ? sep + 1 : klog_path;
    sst->cache_key_prefix = XXH64(klog_path, strlen(klog_path), 0);
    snprintf(sst->cf_name, sizeof(sst->cf_name), "%s", cf_name);
    sst->sync_mode = sync_mode;

    atomic_init(&sst->klog_bm, NULL);
    atomic_init(&sst->bloom, NULL);
    atomic_init(&sst->root_node, NULL);
    atomic_init(&sst->refcount, TDB_SSTABLE_REF_OWNER);
    atomic_init(&sst->last_access_time, (int64_t)time(NULL));
    atomic_init(&sst->marked_for_deletion, 0);
    return sst;
}

/* read and parse the footer, the last block of the klog, into out; the caller owns out's key
 * buffers */
static int sstable_read_footer(block_manager_t *bm, sstable_footer_t *out)
{
    block_manager_cursor_t cursor;
    if (block_manager_cursor_init_stack(&cursor, bm) != 0) return TDB_ERR_IO;
    if (block_manager_cursor_goto_last(&cursor) != 0) return TDB_ERR_CORRUPTION;

    block_manager_block_t *block = block_manager_cursor_read(&cursor);
    if (!block) return TDB_ERR_CORRUPTION;

    const int rc = sstable_footer_parse(block->data, block->size, out);
    block_manager_block_free(block);
    return rc;
}

/**
 * sstable_adopt_footer
 * copies the parsed footer onto the open sstable, taking ownership of its heap buffers so the parse
 * copy is not made a second time
 * @param sst the sstable being opened
 * @param footer the parsed footer, left owning nothing this took
 */
static void sstable_adopt_footer(sstable_t *sst, sstable_footer_t *footer)
{
    sst->root_offset = footer->root_offset;
    sst->first_leaf_offset = footer->first_leaf_offset;
    sst->last_leaf_offset = footer->last_leaf_offset;
    sst->bloom_dir_offset = footer->bloom_dir_offset;
    sst->bloom_dir_size = footer->bloom_dir_size;
    sst->distinct_key_count = footer->distinct_key_count;
    sst->tombstone_count = footer->tombstone_count;
    sst->max_seq = footer->max_seq;
    sst->range_del_offset = footer->range_del_offset;
    sst->range_del_size = footer->range_del_size;
    sst->total_key_bytes = footer->total_key_bytes;
    sst->total_value_bytes = footer->total_value_bytes;
    sst->klog_logical_bytes = footer->klog_logical_bytes;
    sst->btree_node_count = footer->btree_node_count;
    sst->btree_height = footer->btree_height;
    sst->btree_node_size = footer->btree_node_size;

    sst->min_key = footer->min_key;
    sst->min_key_size = footer->min_key_size;
    sst->max_key = footer->max_key;
    sst->max_key_size = footer->max_key_size;
    sst->vlog_refs = footer->vlog_refs;
    sst->vlog_ref_count = footer->vlog_ref_count;
    footer->min_key = NULL;
    footer->max_key = NULL;
    footer->vlog_refs = NULL;

    sst->encoding_count = footer->encoding_count;
    memcpy(sst->encoding_pipeline, footer->encoding_pipeline, footer->encoding_count);
}

/* read back the range tombstone block a build wrote, so a table reopened from the manifest carries
 * the intervals it was built with. read while the footer's descriptor is still open, since the
 * open closes it straight afterwards and everything past that point goes through a lazy reopen
 * @param bm the klog, still open from the footer read
 * @param offset where the block was written
 * @param size how large it is
 * @param id the table's id, for the notice when the block will not parse
 * @return the set, or NULL when the table carries none or the block would not read back. a block
 *         that will not parse is not fatal, since the intervals it held are still in the logs
 */
static range_tombstone_set_t *sstable_read_range_dels(block_manager_t *bm, uint64_t offset,
                                                      uint32_t size, uint64_t id)
{
    if (size == 0) return NULL;

    /* through a cursor rather than a raw read at the offset, since what a write_raw left there is a
     * framed block and the payload starts past its header */
    block_manager_cursor_t cursor;
    if (block_manager_cursor_init_stack(&cursor, bm) != 0) return NULL;
    if (block_manager_cursor_goto(&cursor, offset) != 0) return NULL;

    block_manager_block_t *block = block_manager_cursor_read(&cursor);
    if (!block) return NULL;

    range_tombstone_set_t *set = NULL;
    if (block->size != size ||
        range_tombstone_set_deserialize(block->data, block->size, &set) != TDB_SUCCESS)
    {
        TDB_DEBUG_LOG(TDB_LOG_WARN, "sstable %llu range tombstone block would not read back",
                      (unsigned long long)id);
        set = NULL;
    }
    block_manager_block_free(block);
    return set;
}

int sstable_open_from_manifest(sstable_t **out, const char *cf_dir, const char *cf_name,
                               const tidesdb_manifest_entry_t *entry, int sync_mode,
                               const tidesdb_encoding_registry_t *encodings, cache_t *node_cache,
                               fd_manager_t *fdm, arena_pool_t *arena_pool, _Atomic(int64_t) *now)
{
    if (!out || !cf_dir || !cf_name || !entry) return TDB_ERR_INVALID_ARGS;

    char filename[TDB_SSTABLE_KLOG_NAME_MAX];
    int rc = sstable_klog_filename(entry, filename, sizeof(filename));
    if (rc != TDB_SUCCESS) return rc;

    const size_t path_len = strlen(cf_dir) + strlen(PATH_SEPARATOR) + strlen(filename) + 1;
    char *klog_path = malloc(path_len);
    if (!klog_path) return TDB_ERR_MEMORY;
    snprintf(klog_path, path_len, "%s%s%s", cf_dir, PATH_SEPARATOR, filename);

    /* the footer read opens and closes the klog momentarily, so it is not counted as a resident
     * descriptor; it still routes through the fd manager for EMFILE backpressure when one is given
     */
    block_manager_t *bm = NULL;
    const int open_rc = fdm ? fd_manager_bm_open(fdm, &bm, klog_path, sync_mode)
                            : block_manager_open(&bm, klog_path, sync_mode);
    if (open_rc != 0)
    {
        free(klog_path);
        return TDB_ERR_IO;
    }

    /* a crash can leave the klog at its preallocated size, a run of valid blocks followed by a zero
     * tail, since the trim to logical size only happens on a clean close. locate the true logical
     * end (and trim the tail) so the footer read finds the last real block instead of the trailing
     * zeros */
    if (block_manager_validate_last_block(bm, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION) != 0)
    {
        (void)block_manager_close(bm);
        free(klog_path);
        return TDB_ERR_IO;
    }

    sstable_footer_t footer;
    rc = sstable_read_footer(bm, &footer);
    range_tombstone_set_t *range_tombstones =
        rc == TDB_SUCCESS
            ? sstable_read_range_dels(bm, footer.range_del_offset, footer.range_del_size, entry->id)
            : NULL;
    (void)block_manager_close(
        bm); /* the footer is cached from here on; the lazy reopen owns the resident fd */
    if (rc != TDB_SUCCESS)
    {
        free(klog_path);
        return rc;
    }

    sstable_t *sst =
        sstable_alloc_owning_path(entry->id, entry->partition, klog_path, cf_name, sync_mode);
    if (!sst)
    {
        range_tombstone_set_free(range_tombstones);
        sstable_footer_free(&footer); /* the helper already freed klog_path */
        return TDB_ERR_MEMORY;
    }
    sst->node_cache = node_cache;
    sst->arena_pool = arena_pool;
    sst->now = now;
    sst->fdm = fdm;
    sst->encodings = encodings;

    sstable_adopt_footer(sst, &footer);
    sst->range_tombstones = range_tombstones;

    /* resolve the footer's pipeline once, here. a node read cannot afford a registry walk, and a
     * file whose ids do not resolve is unreadable by this build -- reported as corruption, the same
     * as any other stored bytes it cannot decode */
    if (sst->encoding_count > 0)
    {
        if (!sst->encodings ||
            tidesdb_encoding_resolve(sst->encodings, sst->encoding_pipeline, sst->encoding_count,
                                     sst->codec, TDB_ENCODING_PIPELINE_MAX) < 0)
        {
            sstable_close(sst);
            return TDB_ERR_CORRUPTION;
        }
        sst->codec_count = sst->encoding_count;
    }

    *out = sst;
    return TDB_SUCCESS;
}

block_manager_t *sstable_ensure_open(sstable_t *sst)
{
    if (!sst) return NULL;

    block_manager_t *bm = atomic_load_explicit(&sst->klog_bm, memory_order_acquire);
    if (bm) return bm;

    block_manager_t *opened = NULL;
    const int open_rc = sst->fdm
                            ? fd_manager_bm_open(sst->fdm, &opened, sst->klog_path, sst->sync_mode)
                            : block_manager_open(&opened, sst->klog_path, sst->sync_mode);
    if (open_rc != 0) return NULL;

    block_manager_t *expected = NULL;
    if (atomic_compare_exchange_strong(&sst->klog_bm, &expected, opened))
    {
        /* this handle is now the resident descriptor for the sstable */
        if (sst->fdm) fd_manager_note_open(sst->fdm, FD_LABEL_SSTABLE_KLOG);
        return opened;
    }

    /* another thread reopened first; drop ours, uncounted, and use the published handle */
    (void)block_manager_close(opened);
    return expected;
}

int sstable_evict_klog(sstable_t *sst, const int idle_baseline)
{
    if (!sst) return 0;
    if (atomic_load_explicit(&sst->klog_bm, memory_order_acquire) == NULL) return 0;

    /* claim the evicting window; it fails when a reader holds a reference beyond the ones the
     * baseline accounts for, so a live read is safe */
    if (!tdb_refcount_begin_evict(&sst->refcount, idle_baseline)) return 0;
    block_manager_t *bm = atomic_exchange(&sst->klog_bm, NULL);
    /* the caller holds one of the references the baseline counts, so the handle cannot have been
     * reclaimed inside the window and the restored count is the caller's to drop as usual */
    const int remaining = tdb_refcount_end_evict(&sst->refcount, idle_baseline);
    if (remaining <= 0)
        TDB_DEBUG_LOG(TDB_LOG_ERROR,
                      "sstable %llu evicted at baseline %d and fell to %d, so the baseline counted "
                      "a reference the caller does not hold",
                      (unsigned long long)sst->id, idle_baseline, remaining);

    /* the descriptor came out of the handle above, so it is this call's to close on every path from
     * here -- returning without it would strand an open file the handle no longer names */
    if (!bm) return 0;
    (void)block_manager_close(bm);
    if (sst->fdm) fd_manager_note_close(sst->fdm, FD_LABEL_SSTABLE_KLOG);
    return 1;
}

void sstable_close(sstable_t *sst)
{
    if (!sst) return;

    block_manager_t *bm = atomic_load_explicit(&sst->klog_bm, memory_order_acquire);
    if (bm)
    {
        (void)block_manager_close(bm);
        if (sst->fdm) fd_manager_note_close(sst->fdm, FD_LABEL_SSTABLE_KLOG);
    }
    pr_filter_reader_free(atomic_load_explicit(&sst->bloom, memory_order_acquire));
    cache_release(sst->root_pin);

    /* a superseded sstable's bytes stay charged to the filesystem until the file is unlinked, and
     * this is the first moment it is safe -- the last reference has gone, so no reader is inside
     * it. without this the merged-away inputs accumulate for as long as the database stays open,
     * and the store grows without bound while the level set reports a healthy live set */
    if (atomic_load_explicit(&sst->marked_for_deletion, memory_order_acquire) && sst->klog_path)
    {
        if (remove(sst->klog_path) != 0)
            TDB_DEBUG_LOG(TDB_LOG_WARN, "could not unlink superseded sstable %s", sst->klog_path);
    }

    range_tombstone_set_free(sst->range_tombstones);
    free(sst->min_key);
    free(sst->max_key);
    free(sst->vlog_refs);
    free(sst->klog_path);
    atomic_fetch_sub_explicit(&sstable_live_handles_count, 1, memory_order_relaxed);
    free(sst);
}

int sstable_klog_resident(const sstable_t *sst)
{
    if (!sst) return 0;
    return atomic_load_explicit(&sst->klog_bm, memory_order_acquire) != NULL;
}

void sstable_mark_for_deletion(sstable_t *sst)
{
    if (!sst) return;
    atomic_store_explicit(&sst->marked_for_deletion, 1, memory_order_release);
}

void sstable_ref(sstable_t *sst)
{
    if (!sst) return;
    tdb_ref(&sst->refcount);
}

int sstable_unref(sstable_t *sst)
{
    if (!sst) return 0;
    return tdb_unref(&sst->refcount);
}
