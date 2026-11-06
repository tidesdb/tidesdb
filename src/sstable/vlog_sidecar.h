/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __VLOG_SIDECAR_H__
#define __VLOG_SIDECAR_H__

#include "sstable/vlog.h"

/* a segment's latest index is kept beside it, never in the manifest */
#define VLOG_SIDECAR_EXT      ".vix"
#define VLOG_SIDECAR_TMP_EXT  ".vix.tmp"
#define VLOG_SIDECAR_NAME_MAX 40

typedef enum
{
    VLOG_SIDECAR_SEALED,
    VLOG_SIDECAR_PREFIX
} vlog_sidecar_kind_t;

/**
 * vlog_sidecar_entry_t
 * the compact recovery information for one completed value
 * @param id nonzero logical value id
 * @param offset block-frame offset in the segment
 * @param value_len original uncompressed value length
 * @param disk_len complete framed block length
 * @param chain encoding ids packed least-significant byte first
 */
typedef struct
{
    uint64_t id;
    uint64_t offset;
    uint64_t value_len;
    uint64_t disk_len;
    uint64_t chain;
} vlog_sidecar_entry_t;

/**
 * vlog_sidecar_name
 * formats a segment's published or temporary sidecar name
 * @param number segment file number
 * @param temporary nonzero for the unpublished .vix.tmp name
 * @param out receives the basename
 * @param out_size capacity of out
 * @return VLOG_OK or VLOG_ERR_INVALID when arguments or capacity are invalid
 */
int vlog_sidecar_name(uint64_t number, int temporary, char *out, size_t out_size);

/**
 * vlog_sidecar_publish
 * syncs the segment and atomically publishes a sorted index through extent
 * @param v opened value log
 * @param slot segment pinned under exclusive writer admission or owned by single-threaded recovery
 * @param entries complete entries through extent, reordered by offset in place
 * @param count number of entries
 * @param extent first byte after the final complete frame
 * @param kind VLOG_SIDECAR_PREFIX preserves active preallocation and permits later appends
 * @return VLOG_OK, VLOG_ERR_INVALID, VLOG_ERR_MEMORY, VLOG_ERR_IO, or VLOG_ERR_CORRUPTION
 */
int vlog_sidecar_publish(vlog_t *v, uint32_t slot, vlog_sidecar_entry_t *entries, size_t count,
                         uint64_t extent, vlog_sidecar_kind_t kind);

/**
 * vlog_sidecar_load
 * validates a published sidecar against its segment without reading covered value bytes
 * @param v opened value log
 * @param slot segment table slot, exclusively owned during recovery
 * @param extent segment size at reopen, which may include a physical reservation
 * @param entries receives owned compact entries on success
 * @param count receives the entry count on success
 * @param indexed_extent receives the first byte after the validated frames on success
 * @return VLOG_OK when the sidecar is fully usable, otherwise a VLOG_ERR_* failure
 */
int vlog_sidecar_load(vlog_t *v, uint32_t slot, uint64_t extent, vlog_sidecar_entry_t **entries,
                      size_t *count, uint64_t *indexed_extent);

/**
 * vlog_sidecar_unlink
 * removes a retired segment's published and interrupted temporary sidecars
 * @param v opened value log
 * @param number retired segment number
 * @return VLOG_OK, VLOG_ERR_INVALID, or VLOG_ERR_IO
 */
int vlog_sidecar_unlink(vlog_t *v, uint64_t number);

#endif /* __VLOG_SIDECAR_H__ */
