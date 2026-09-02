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

#endif /* __TIDESDB_SSTABLE_INTERNAL_H__ */
