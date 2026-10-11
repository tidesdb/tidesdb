/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_SSTABLE_INTERNAL_H__
#define __TIDESDB_SSTABLE_INTERNAL_H__

#include "sstable.h"

/* private helpers shared between the sstable module's translation units; not part of the public
 * surface in sstable.h */

/* per-entry klog metadata charged to the running size estimate: the leaf's key offset slot plus the
 * varint prefix length, suffix length, value size, vlog offset, sequence delta, and ttl. the leaf
 * encoding uses varints and prefix compression, so this is an approximation sized for split
 * decisions rather than an exact encoded length */
#define SSTABLE_KLOG_ENTRY_OVERHEAD_BYTES 16

/**
 * sstable_alloc_owning_path
 * allocate an sstable handle and fill the identity fields both the open and build paths share; the
 * handle adopts klog_path and starts at the owner reference with no open klog
 * @param id sstable id
 * @param partition partition shard, or MANIFEST_NO_PARTITION
 * @param klog_path full .klog path, adopted by the handle and freed here on allocation failure
 * @param cf_name owning column family name
 * @param sync_mode block-manager sync mode used when reopening the klog
 * @return the handle on success, or NULL on allocation failure (klog_path is freed)
 */
sstable_t *sstable_alloc_owning_path(uint64_t id, int partition, char *klog_path,
                                     const char *cf_name, int sync_mode);

/**
 * sstable_blob_write
 * land a filter blob, a bloom or range filter partition or directory, as a klog block. the returned
 * offset is the block frame sstable_blob_fetch reads back
 * @param ctx the klog block manager
 * @param data the blob
 * @param size its length
 * @param out_offset receives where the block landed
 * @return 0 on success, -1 on a write failure
 */
int sstable_blob_write(void *ctx, const uint8_t *data, size_t size, uint64_t *out_offset);

/**
 * sstable_blob_fetch
 * fetch a filter blob for a probe, through the block cache when the sstable borrows one, so a hot
 * partition is not re-read and re-checksummed on every probe
 * @param ctx the sstable
 * @param offset where the blob's block sits
 * @param size the size its directory records, a mismatch meaning the block is not it
 * @param out_data receives the blob bytes
 * @param out_pin receives the cache pin or bare block, released by sstable_blob_release
 * @return 0 with the blob pinned, -1 when it could not be read
 */
int sstable_blob_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                       void **out_pin);

/**
 * sstable_blob_release
 * release what sstable_blob_fetch pinned
 * @param ctx the sstable
 * @param pin the pin
 */
void sstable_blob_release(void *ctx, void *pin);

typedef struct sstable_rf_build sstable_rf_build_t;

/**
 * sstable_rf_build_new
 * start a table's range filter. its model has to exist before the first key is encoded, so the
 * first keys are held back and counted, the model is built from them, and they are encoded then
 * with everything after. a model drawn from the first keys measured as good as one drawn from the
 * whole run, since any byte has a code and only compression depends on the counts
 * @param r_bits the remainder width
 * @param expected_keys the distinct keys the table is expected to hold, sizing the model, 0 when
 *        unknown
 * @param bm the klog the partitions and directory land in
 * @param out out -- the build
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS or TDB_ERR_MEMORY
 */
int sstable_rf_build_new(unsigned r_bits, uint64_t expected_keys, block_manager_t *bm,
                         sstable_rf_build_t **out);

/**
 * sstable_rf_build_add
 * add the next distinct key, tombstones included, since a scan that skipped a table holding only a
 * key's tombstone would bring back the older value it hides
 * @param rb the build
 * @param key the key
 * @param key_size its length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS for a key out of order, or TDB_ERR_MEMORY
 */
int sstable_rf_build_add(sstable_rf_build_t *rb, const uint8_t *key, size_t key_size);

/**
 * sstable_rf_build_finish
 * write the filter's partitions and directory into the klog
 * @param rb the build, left holding nothing
 * @param out_offset receives where the directory landed, 0 when the table holds no key
 * @param out_size receives its size, 0 when the table holds no key
 * @return TDB_SUCCESS, TDB_ERR_IO, TDB_ERR_TOO_LARGE or TDB_ERR_MEMORY
 */
int sstable_rf_build_finish(sstable_rf_build_t *rb, uint64_t *out_offset, uint32_t *out_size);

/**
 * sstable_rf_build_free
 * release a build, finished or not
 * @param rb the build, or NULL
 */
void sstable_rf_build_free(sstable_rf_build_t *rb);

#endif /* __TIDESDB_SSTABLE_INTERNAL_H__ */
