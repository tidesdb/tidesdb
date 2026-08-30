/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"    /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "internal/types.h" /* TDB_KV_FLAG_* entry flags carried in from the memtable */
#include "sstable.h"
#include "sstable_internal.h"

/* the in-progress build state; opaque to callers */
struct sstable_builder
{
    block_manager_t *klog_bm; /* borrowed until finish adopts it into the produced sstable */
    vlog_t *vlog;             /* the cf's shared value log, borrowed; NULL forbids a spill */
    btree_builder_t *btree_builder;
    pr_filter_builder_t *bloom_builder; /* NULL when the bloom is disabled */

    size_t value_threshold;
    /* this build's own copy, since the caller's set may be rebuilt before finish writes the block
     */
    range_tombstone_set_t *range_tombstones;
    int sync_mode;
    /* the family's pipeline resolved once, here, rather than per node or per value. the btree reads
     * these on every node it writes, so a registry walk on that path would be paid per node */
    tidesdb_encoding_stage_t codec[TDB_ENCODING_PIPELINE_MAX];
    int codec_count;
    const tidesdb_encoding_registry_t *encodings; /* carried onto the produced sstable */
    /* the pipeline a spilled value is stored under, recorded with the value itself so a later read
     * undoes exactly what was applied -- compaction carries a value forward by id, so the sstable
     * referencing it may by then record a different pipeline than the one that wrote it */
    uint8_t value_ids[TDB_ENCODING_PIPELINE_MAX];
    int value_id_count;

    cache_t *node_cache;      /* the produced sstable's borrowed node cache */
    arena_pool_t *arena_pool; /* the produced sstable's borrowed chunk pool */
    _Atomic(int64_t) *now;    /* the produced sstable's borrowed clock */
    fd_manager_t *fdm;        /* the produced sstable's borrowed descriptor budget */

    uint64_t id;
    int partition;
    char *klog_path;
    char cf_name[TDB_MAX_CF_NAME_LEN];
    uint8_t encoding_pipeline[TDB_ENCODING_PIPELINE_MAX];
    uint8_t encoding_count;

    uint64_t num_entries;
    uint64_t tombstone_count;
    uint64_t distinct_key_count;
    uint64_t total_key_bytes; /* summed length of every distinct key, for average-key-size stats */
    uint64_t
        total_value_bytes; /* summed length of every distinct live value, for average-value stats */
    uint64_t vlog_bytes;
    uint64_t
        klog_bytes; /* running estimate of the klog's encoded size, for output split decisions */

    uint8_t *prev_key; /* the previous key, to count distinct keys apart from total versions */
    size_t prev_key_size;
    size_t prev_key_cap;
    int has_prev;

    /* which value-log segments this table's separated values landed in, kept sorted by segment
     * number so the running insert is a binary search rather than a walk. summed across the live
     * tables this is what tells the store how much of a segment is still referenced, which is the
     * whole reason reclamation no longer has to read every klog to find out */
    sstable_vlog_ref_t *vlog_refs;
    uint32_t vlog_ref_count;
    uint32_t vlog_ref_cap;
};

/**
 * sstable_builder_note_value
 * records that one separated value of this table lives in a value-log segment, merging into the
 * entry for that segment if it is already named
 * @param builder the builder
 * @param vlog_id the value's logical id
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the histogram could not grow
 */
static int sstable_builder_note_value(sstable_builder_t *builder, uint64_t vlog_id)
{
    uint64_t segment = 0;
    uint64_t bytes = 0;
    if (vlog_segment_of(builder->vlog, vlog_id, &segment, &bytes) != VLOG_OK)
    {
        /* the id resolves to nothing, so no segment is holding bytes on this table's behalf and
         * there is nothing to attribute. a read of it would fail the same way */
        return TDB_SUCCESS;
    }

    size_t lo = 0;
    size_t hi = builder->vlog_ref_count;
    while (lo < hi)
    {
        const size_t mid = lo + (hi - lo) / 2;
        if (builder->vlog_refs[mid].segment == segment)
        {
            builder->vlog_refs[mid].bytes += bytes;
            builder->vlog_refs[mid].count++;
            return TDB_SUCCESS;
        }
        if (builder->vlog_refs[mid].segment < segment)
            lo = mid + 1;
        else
            hi = mid;
    }

    if (builder->vlog_ref_count == builder->vlog_ref_cap)
    {
        const uint32_t grown = builder->vlog_ref_cap ? builder->vlog_ref_cap * 2 : 4;
        sstable_vlog_ref_t *bigger = realloc(builder->vlog_refs, grown * sizeof(*bigger));
        if (!bigger) return TDB_ERR_MEMORY;
        builder->vlog_refs = bigger;
        builder->vlog_ref_cap = grown;
    }

    memmove(&builder->vlog_refs[lo + 1], &builder->vlog_refs[lo],
            (builder->vlog_ref_count - lo) * sizeof(*builder->vlog_refs));
    builder->vlog_refs[lo].segment = segment;
    builder->vlog_refs[lo].bytes = bytes;
    builder->vlog_refs[lo].count = 1;
    builder->vlog_ref_count++;
    return TDB_SUCCESS;
}

/* write callback the pr_filter builder uses to land each partition and its directory as klog
 * blocks; the returned offset is the block frame the reader's fetch will read back */
static int sstable_bloom_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset)
{
    block_manager_t *bm = ctx;
    block_manager_block_t *block = block_manager_block_create(size, data);
    if (!block) return -1;
    const int64_t off = block_manager_block_write(bm, block);
    block_manager_block_free(block);
    if (off < 0) return -1;
    *out_offset = (uint64_t)off;
    return 0;
}

int sstable_builder_new(sstable_builder_t **out, block_manager_t *klog_bm, vlog_t *cf_vlog,
                        const sstable_builder_config_t *config)
{
    if (!out || !klog_bm || !config || !config->cf_name || !config->klog_path)
        return TDB_ERR_INVALID_ARGS;
    if (config->encoding_count > TDB_ENCODING_PIPELINE_MAX) return TDB_ERR_INVALID_ARGS;

    sstable_builder_t *b = calloc(1, sizeof(*b));
    if (!b) return TDB_ERR_MEMORY;

    /* take the caller's pipeline once and build everything else from that copy, so the chain
     * resolved into the codec and the chain recorded in the footer cannot be two different chains.
     * reading the caller's buffer twice would make that possible, and the result is an sstable
     * whose footer names encodings its nodes were not written with -- unreadable, permanently,
     * since the footer is the only record of how the bytes were produced */
    b->encoding_count = config->encoding_count;
    if (config->encoding_count > 0 && config->encoding_pipeline)
        memcpy(b->encoding_pipeline, config->encoding_pipeline, config->encoding_count);

    /* a pipeline with no registry to resolve against cannot be applied, and silently storing the
     * nodes verbatim would produce an sstable whose footer claims encodings its bytes do not have
     */
    if (b->encoding_count > 0)
    {
        if (!config->encodings ||
            tidesdb_encoding_resolve(config->encodings, b->encoding_pipeline, b->encoding_count,
                                     b->codec, TDB_ENCODING_PIPELINE_MAX) < 0)
        {
            free(b);
            return TDB_ERR_INVALID_ARGS;
        }
        b->codec_count = b->encoding_count;
        memcpy(b->value_ids, b->encoding_pipeline, b->encoding_count);
        b->value_id_count = b->encoding_count;
    }
    b->encodings = config->encodings;

    btree_config_t bt = {0};
    bt.target_node_size =
        config->target_node_size ? config->target_node_size : BTREE_DEFAULT_NODE_SIZE;
    bt.codec = b->codec_count ? b->codec : NULL;
    bt.codec_count = b->codec_count;

    const size_t path_len = strlen(config->klog_path) + 1;
    b->klog_path = malloc(path_len);
    if (!b->klog_path)
    {
        free(b);
        return TDB_ERR_MEMORY;
    }
    memcpy(b->klog_path, config->klog_path, path_len);

    if (btree_builder_new(&b->btree_builder, klog_bm, &bt) != 0)
    {
        free(b->klog_path);
        free(b);
        return TDB_ERR_MEMORY;
    }

    if (config->enable_bloom && pr_filter_builder_new(&b->bloom_builder, config->bloom_fpr, 0,
                                                      sstable_bloom_write, klog_bm) != 0)
    {
        btree_builder_free(b->btree_builder);
        free(b->klog_path);
        free(b);
        return TDB_ERR_MEMORY;
    }

    b->klog_bm = klog_bm;
    b->vlog = cf_vlog;
    b->value_threshold = config->value_threshold;
    /* cloned rather than borrowed, since the family's set may be rebuilt while this build runs */
    b->range_tombstones =
        config->range_tombstones ? range_tombstone_set_clone(config->range_tombstones) : NULL;
    b->sync_mode = config->sync_mode;
    b->node_cache = config->node_cache;
    b->arena_pool = config->arena_pool;
    b->now = config->now;
    b->fdm = config->fdm;
    b->id = config->id;
    b->partition = config->partition;
    snprintf(b->cf_name, sizeof(b->cf_name), "%s", config->cf_name);

    *out = b;
    return TDB_SUCCESS;
}

/* record a key with either an inline value or a vlog reference into the btree, the bloom, and the
 * counters; the spill decision is the caller's, so this is shared by a fresh add and a
 * carry-forward */
static int sstable_builder_emit(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                                const uint8_t *value, size_t value_size, uint64_t vlog_id,
                                uint64_t seq, int64_t ttl, uint8_t flags)
{
    uint8_t entry_flags = 0;
    if (flags & TDB_KV_FLAG_TOMBSTONE) entry_flags |= BTREE_ENTRY_FLAG_TOMBSTONE;
    if (flags & TDB_KV_FLAG_SINGLE_DELETE) entry_flags |= BTREE_ENTRY_FLAG_SINGLE_DELETE;

    if (btree_builder_add(builder->btree_builder, key, key_size, value, value_size, vlog_id, seq,
                          ttl, entry_flags) != 0)
        return TDB_ERR_MEMORY;

    if (builder->bloom_builder && pr_filter_builder_add(builder->bloom_builder, key, key_size) != 0)
        return TDB_ERR_MEMORY;

    /* count a distinct key only when this key differs from the previous one, so the footer
     * separates unique keys from the total version count. versions arrive newest first, so the
     * first occurrence of a key is its newest version, the one whose key and value bytes the size
     * stats attribute */
    int is_new_distinct = 1;
    if (builder->has_prev)
        is_new_distinct =
            !(builder->prev_key_size == key_size && memcmp(builder->prev_key, key, key_size) == 0);
    if (is_new_distinct)
    {
        builder->distinct_key_count++;
        builder->total_key_bytes += key_size;
        if (!(flags & TDB_KV_FLAG_TOMBSTONE)) builder->total_value_bytes += value_size;
    }

    if (key_size > builder->prev_key_cap)
    {
        uint8_t *grown = realloc(builder->prev_key, key_size);
        if (!grown) return TDB_ERR_MEMORY;
        builder->prev_key = grown;
        builder->prev_key_cap = key_size;
    }
    memcpy(builder->prev_key, key, key_size);
    builder->prev_key_size = key_size;
    builder->has_prev = 1;

    builder->num_entries++;
    if (flags & TDB_KV_FLAG_TOMBSTONE) builder->tombstone_count++;

    /* a spilled value leaves only its reference behind, so the klog grows by the key and the entry
     * metadata alone -- which is why this cannot be counted from the logical value size */
    builder->klog_bytes += key_size + (value ? value_size : 0) + SSTABLE_KLOG_ENTRY_OVERHEAD_BYTES;
    return TDB_SUCCESS;
}

int sstable_builder_add(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                        const uint8_t *value, size_t value_size, uint64_t seq, int64_t ttl,
                        uint8_t flags)
{
    if (!builder || !key || key_size == 0) return TDB_ERR_INVALID_ARGS;

    const int deleted = (flags & TDB_KV_FLAG_TOMBSTONE) != 0;

    /* spill a large live value to the shared vlog; the btree entry then stores the id in place of
     * the bytes, so a later compaction can carry the id forward without rewriting the value */
    uint64_t vlog_id = 0;
    if (builder->vlog && value && value_size > 0 && !deleted &&
        value_size >= builder->value_threshold)
    {
        uint64_t disk = 0;
        /* a separated value carries the family's codec too. these are the values above the spill
         * threshold, so they are the largest the database holds and the ones compression is worth
         * most on -- leaving them verbatim compressed only what stayed inline, which is the
         * opposite of what the size threshold selected for */
        if (vlog_write(builder->vlog, value, value_size, builder->value_ids,
                       builder->value_id_count, &vlog_id, &disk) != VLOG_OK)
            return TDB_ERR_IO;
        builder->vlog_bytes += disk;
        const int noted = sstable_builder_note_value(builder, vlog_id);
        if (noted != TDB_SUCCESS) return noted;
    }

    /* a spilled value keeps its logical length in the entry while its bytes move to the vlog, so
     * the size flows through reads, cursors, and a later compaction's reference carry without a
     * vlog probe */
    const uint8_t *value_to_store = (vlog_id > 0) ? NULL : value;
    return sstable_builder_emit(builder, key, key_size, value_to_store, value_size, vlog_id, seq,
                                ttl, flags);
}

uint64_t sstable_builder_klog_bytes(const sstable_builder_t *builder)
{
    return builder ? builder->klog_bytes : 0;
}

int sstable_builder_add_reference(sstable_builder_t *builder, const uint8_t *key, size_t key_size,
                                  uint64_t vlog_id, size_t value_size, uint64_t seq, int64_t ttl,
                                  uint8_t flags)
{
    if (!builder || !key || key_size == 0 || vlog_id == 0) return TDB_ERR_INVALID_ARGS;

    /* a value whose segment is being emptied is written afresh rather than carried, which is the
     * only way that segment ever reaches zero -- carrying the reference would leave the output
     * table holding the old segment and no amount of compaction could drain it. the read and the
     * write are the cost of reclaiming it, paid inside a merge that was already running */
    if (vlog_should_respill(builder->vlog, vlog_id))
    {
        uint8_t *value = NULL;
        size_t got = 0;
        if (vlog_read(builder->vlog, vlog_id, &value, &got) == VLOG_OK)
        {
            const int rc = sstable_builder_add(builder, key, key_size, value, got, seq, ttl, flags);
            free(value);
            return rc;
        }
        /* unreadable, so carry the reference on as before. a merge is the wrong place to decide a
         * value is gone, and dropping it here would turn a read failure into data loss */
    }

    /* carry an already-spilled value forward by its logical vlog id -- no read, no re-spill -- so
     * an LSM compaction rewrites keys without ever moving their values; value_size is the logical
     * length the upstream cursor reported, kept so the size stats stay exact across compactions.
     * the segment it lives in is still noted, because the output table now holds that reference and
     * the input table is about to stop existing */
    const int noted = sstable_builder_note_value(builder, vlog_id);
    if (noted != TDB_SUCCESS) return noted;

    return sstable_builder_emit(builder, key, key_size, NULL, value_size, vlog_id, seq, ttl, flags);
}

/* write this table's own range tombstone block, so the intervals it carries travel with it. a
 * table holding none writes nothing and records a zero offset, which is what every table produced
 * before a family ever took an interval delete looks like
 * @param builder the build being sealed
 * @param out_offset receives where the block landed, 0 when none was written
 * @param out_size receives how large it is, 0 when none was written
 * @return TDB_SUCCESS, TDB_ERR_IO, or TDB_ERR_MEMORY
 */
static int sstable_finish_range_dels(sstable_builder_t *builder, uint64_t *out_offset,
                                     uint32_t *out_size)
{
    *out_offset = 0;
    *out_size = 0;
    if (!builder->range_tombstones || range_tombstone_set_count(builder->range_tombstones) == 0)
        return TDB_SUCCESS;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    const int rc = range_tombstone_set_serialize(builder->range_tombstones, &blob, &blob_len);
    if (rc != TDB_SUCCESS) return rc;

    const int64_t off = block_manager_write_raw(builder->klog_bm, blob, (uint32_t)blob_len);
    free(blob);
    if (off < 0) return TDB_ERR_IO;

    *out_offset = (uint64_t)off;
    *out_size = (uint32_t)blob_len;
    return TDB_SUCCESS;
}

/**
 * sstable_finish_bloom
 * close out the partition range filter, when the build has one, and report where its directory
 * landed in the klog
 * @param builder the builder, whose filter builder is consumed
 * @param out_offset receives the filter directory offset, 0 when the build has no filter
 * @param out_size receives the filter directory size, 0 when the build has no filter
 * @return TDB_SUCCESS, or TDB_ERR_IO when the filter could not be written
 */
static int sstable_finish_bloom(sstable_builder_t *builder, uint64_t *out_offset,
                                uint32_t *out_size)
{
    *out_offset = 0;
    *out_size = 0;
    if (!builder->bloom_builder) return TDB_SUCCESS;

    uint64_t total = 0;
    if (pr_filter_builder_finish(builder->bloom_builder, out_offset, out_size, &total) != 0)
        return TDB_ERR_IO;

    pr_filter_builder_free(builder->bloom_builder);
    builder->bloom_builder = NULL;
    return TDB_SUCCESS;
}

/**
 * sstable_write_footer
 * describe the finished table in its self-describing footer and append it as the klog's last block,
 * which is what lets a reader open the table knowing only the file
 * @param builder the builder, for the counts it accumulated
 * @param tree the finished btree, for its shape and key bounds
 * @param bloom_dir_offset where the partition range filter directory landed
 * @param bloom_dir_size how large that directory is
 * @param range_del_offset where this table's interval-delete block landed, 0 when it carries none
 * @param range_del_size how large that block is, 0 when it carries none
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_IO on a serialize or write failure
 */
static int sstable_write_footer(sstable_builder_t *builder, const btree_t *tree,
                                uint64_t bloom_dir_offset, uint32_t bloom_dir_size,
                                uint64_t range_del_offset, uint32_t range_del_size)
{
    sstable_footer_t footer = {0};
    footer.version = TDB_SSTABLE_FORMAT_VERSION;
    footer.root_offset = tree->root_offset;
    footer.first_leaf_offset = tree->first_leaf_offset;
    footer.last_leaf_offset = tree->last_leaf_offset;
    footer.bloom_dir_offset = bloom_dir_offset;
    footer.bloom_dir_size = bloom_dir_size;
    footer.range_del_offset = range_del_offset;
    footer.range_del_size = range_del_size;
    footer.distinct_key_count = builder->distinct_key_count;
    footer.tombstone_count = builder->tombstone_count;
    footer.max_seq = tree->max_seq;
    footer.total_key_bytes = builder->total_key_bytes;
    footer.total_value_bytes = builder->total_value_bytes;
    footer.klog_logical_bytes = builder->klog_bytes;
    footer.btree_node_count = tree->node_count;
    footer.btree_height = tree->height;
    footer.btree_node_size = (uint32_t)tree->config.target_node_size;
    footer.min_key = tree->min_key;
    footer.min_key_size = (uint32_t)tree->min_key_size;
    footer.max_key = tree->max_key;
    footer.max_key_size = (uint32_t)tree->max_key_size;
    footer.encoding_count = builder->encoding_count;
    memcpy(footer.encoding_pipeline, builder->encoding_pipeline, builder->encoding_count);
    footer.vlog_refs = builder->vlog_refs;
    footer.vlog_ref_count = builder->vlog_ref_count;

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    const int rc = sstable_footer_serialize(&footer, &buf, &buf_size);
    if (rc != TDB_SUCCESS) return rc;

    block_manager_block_t *block = block_manager_block_create(buf_size, buf);
    free(buf);
    if (!block) return TDB_ERR_MEMORY;

    const int64_t footer_off = block_manager_block_write(builder->klog_bm, block);
    block_manager_block_free(block);
    /* the errno rather than a flat io failure, so a build that stopped because the device filled
     * says so -- a caller can free space and retry, where an io error promises nothing */
    return footer_off < 0 ? tdb_errno_to_result(block_manager_last_errno(builder->klog_bm))
                          : TDB_SUCCESS;
}

/**
 * sstable_copy_key_bounds
 * copy the tree's first and last keys onto the sstable, which outlives the tree they came from
 * @param sst the sstable being assembled
 * @param tree the finished btree
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY
 */
static int sstable_copy_key_bounds(sstable_t *sst, const btree_t *tree)
{
    if (tree->min_key_size)
    {
        sst->min_key = malloc(tree->min_key_size);
        if (!sst->min_key) return TDB_ERR_MEMORY;
        memcpy(sst->min_key, tree->min_key, tree->min_key_size);
        sst->min_key_size = tree->min_key_size;
    }
    if (tree->max_key_size)
    {
        sst->max_key = malloc(tree->max_key_size);
        if (!sst->max_key) return TDB_ERR_MEMORY;
        memcpy(sst->max_key, tree->max_key, tree->max_key_size);
        sst->max_key_size = tree->max_key_size;
    }
    return TDB_SUCCESS;
}

/**
 * sstable_build_handle
 * assemble the readable sstable from the finished tree and the builder's own counts, adopting the
 * builder's klog block manager so a fresh build stays hot rather than being reopened to be read
 * @param builder the builder, whose klog block manager is taken on success
 * @param tree the finished btree
 * @param bloom_dir_offset where the partition range filter directory landed
 * @param bloom_dir_size how large that directory is
 * @param range_del_offset where this table's interval-delete block landed, 0 when it carries none
 * @param range_del_size how large that block is, 0 when it carries none
 * @param out receives the sstable
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY
 */
static int sstable_build_handle(sstable_builder_t *builder, const btree_t *tree,
                                uint64_t bloom_dir_offset, uint32_t bloom_dir_size,
                                uint64_t range_del_offset, uint32_t range_del_size, sstable_t **out)
{
    const size_t path_len = strlen(builder->klog_path) + 1;
    char *path_copy = malloc(path_len);
    if (!path_copy) return TDB_ERR_MEMORY;
    memcpy(path_copy, builder->klog_path, path_len);

    sstable_t *sst = sstable_alloc_owning_path(builder->id, builder->partition, path_copy,
                                               builder->cf_name, builder->sync_mode);
    /* on failure the helper freed path_copy; klog_bm still belongs to the caller */
    if (!sst) return TDB_ERR_MEMORY;

    sst->root_offset = tree->root_offset;
    sst->first_leaf_offset = tree->first_leaf_offset;
    sst->last_leaf_offset = tree->last_leaf_offset;
    sst->bloom_dir_offset = bloom_dir_offset;
    sst->bloom_dir_size = bloom_dir_size;
    sst->range_del_offset = range_del_offset;
    sst->range_del_size = range_del_size;
    /* the handle takes the build's own set rather than reading the block back, since it is already
     * in memory and identical to what was just written */
    sst->range_tombstones = builder->range_tombstones;
    builder->range_tombstones = NULL;
    sst->distinct_key_count = builder->distinct_key_count;
    sst->tombstone_count = builder->tombstone_count;
    sst->max_seq = tree->max_seq;
    sst->total_key_bytes = builder->total_key_bytes;
    sst->total_value_bytes = builder->total_value_bytes;
    sst->btree_node_count = tree->node_count;
    sst->btree_height = tree->height;
    sst->btree_node_size = (uint32_t)tree->config.target_node_size;

    const int rc = sstable_copy_key_bounds(sst, tree);
    if (rc != TDB_SUCCESS)
    {
        sstable_close(sst);
        return rc;
    }

    sst->klog_logical_bytes = builder->klog_bytes;
    sst->encoding_count = builder->encoding_count;
    memcpy(sst->encoding_pipeline, builder->encoding_pipeline, builder->encoding_count);

    /* the handle carries its own copy of the histogram rather than the builder's, since the two are
     * freed independently. a table installed straight from a build has to report the same segment
     * references as the same table read back from its footer, or the store's liveness would depend
     * on whether a segment's tables happened to have been reopened */
    if (builder->vlog_ref_count > 0)
    {
        const size_t refs_bytes = builder->vlog_ref_count * sizeof(*sst->vlog_refs);
        sst->vlog_refs = malloc(refs_bytes);
        if (!sst->vlog_refs)
        {
            sstable_close(sst);
            return TDB_ERR_MEMORY;
        }
        memcpy(sst->vlog_refs, builder->vlog_refs, refs_bytes);
        sst->vlog_ref_count = builder->vlog_ref_count;
    }
    /* the produced sstable is read through directly, without being reopened from its footer, so it
     * needs the same resolved chain the build used -- otherwise its own compressed nodes would be
     * read back as if they were stored verbatim */
    memcpy(sst->codec, builder->codec, sizeof(sst->codec));
    sst->codec_count = builder->codec_count;
    sst->encodings = builder->encodings;

    /* the produced sstable reads through the borrowed cache and is accounted against the borrowed
     * fd budget once it is being read */
    sst->node_cache = builder->node_cache;
    sst->arena_pool = builder->arena_pool;
    sst->now = builder->now;
    sst->fdm = builder->fdm;

    /* the sstable adopts the builder's klog block manager, so the caller must not close it after a
     * successful finish. the adopted klog is a resident descriptor, so account it now to pair with
     * the note_close on sstable_close or a reaper eviction */
    atomic_store_explicit(&sst->klog_bm, builder->klog_bm, memory_order_release);
    builder->klog_bm = NULL;
    if (sst->fdm) fd_manager_note_open(sst->fdm, FD_LABEL_SSTABLE_KLOG);

    *out = sst;
    return TDB_SUCCESS;
}

int sstable_builder_finish(sstable_builder_t *builder, sstable_t **out, uint64_t *out_vlog_bytes)
{
    if (!builder || !out) return TDB_ERR_INVALID_ARGS;

    btree_t *tree = NULL;
    if (btree_builder_finish(builder->btree_builder, &tree) != 0) return TDB_ERR_MEMORY;
    btree_builder_free(builder->btree_builder);
    builder->btree_builder = NULL; /* finish consumed it */

    uint64_t bloom_dir_offset = 0;
    uint32_t bloom_dir_size = 0;
    uint64_t range_del_offset = 0;
    uint32_t range_del_size = 0;
    int rc = sstable_finish_bloom(builder, &bloom_dir_offset, &bloom_dir_size);
    if (rc == TDB_SUCCESS)
        rc = sstable_finish_range_dels(builder, &range_del_offset, &range_del_size);
    if (rc == TDB_SUCCESS)
        rc = sstable_write_footer(builder, tree, bloom_dir_offset, bloom_dir_size, range_del_offset,
                                  range_del_size);

    /* the file stops growing here, so give back the preallocated tail. preallocation advances the
     * logical end of the file, not just its block reservation -- that is deliberate, since
     * reserving without moving i_size leaves writes on the kernel's extending-write path and buys
     * nothing -- so an sstable left untrimmed is charged its whole extent rather than its data.
     * nothing trims it later either: the only other trim runs in block_manager_close, and a live
     * sstable holds its handle open for as long as it is installed. at 64 MiB a chunk that is most
     * of the store once a database holds more than a handful of tables
     *
     * before the barrier below rather than after, so the one fsync covers the truncation too */
    uint64_t klog_size = 0;
    if (rc == TDB_SUCCESS && block_manager_get_size(builder->klog_bm, &klog_size) == 0)
        (void)block_manager_truncate_to(builder->klog_bm, klog_size);

    /* the klog must be on disk before the caller commits the manifest add, and this is the only
     * barrier it gets -- the file is opened without per-write durability precisely so this one
     * covers it. the shared vlog is not fsynced here, and no flush or compaction driver fsyncs it
     * either: its durability comes from being opened O_DSYNC under a syncing mode, so every value
     * is already on the device by the time a klog can reference it. do not "optimise" that open
     * without first adding a vlog barrier ahead of the manifest commit, or a crash leaves a durable
     * klog pointing at value bytes that never landed */
    if (rc == TDB_SUCCESS && builder->sync_mode != BLOCK_MANAGER_SYNC_NONE &&
        block_manager_escalate_fsync(builder->klog_bm) != 0)
        rc = tdb_errno_to_result(block_manager_last_errno(builder->klog_bm));

    sstable_t *sst = NULL;
    if (rc == TDB_SUCCESS)
        rc = sstable_build_handle(builder, tree, bloom_dir_offset, bloom_dir_size, range_del_offset,
                                  range_del_size, &sst);

    btree_free(tree);
    if (rc != TDB_SUCCESS) return rc;

    if (out_vlog_bytes) *out_vlog_bytes = builder->vlog_bytes;
    *out = sst;
    return TDB_SUCCESS;
}

void sstable_builder_free(sstable_builder_t *builder)
{
    if (!builder) return;
    /* free the sub-builders only if a finish did not already consume them; klog_bm is borrowed and
     * left to the caller on an unfinished build, or already moved into the sstable on a finished
     * one */
    if (builder->btree_builder) btree_builder_free(builder->btree_builder);
    if (builder->bloom_builder) pr_filter_builder_free(builder->bloom_builder);
    /* NULL once a finish moved it onto the produced sstable */
    range_tombstone_set_free(builder->range_tombstones);
    free(builder->klog_path);
    free(builder->prev_key);
    free(builder->vlog_refs);
    free(builder);
}
