/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __VLOG_GROUP_DISK_H__
#define __VLOG_GROUP_DISK_H__

#include <stdint.h>

#include "io/block_manager.h"

/* legacy parser sees this normal-looking segment number and refuses before adopting any segments */
#define VLOG_GROUP_GUARD_NUMBER UINT64_MAX
#define VLOG_GROUP_GUARD_NAME   "18446744073709551615.vlog"

/**
 * vlog_group_disk_preflight
 * reject retained grouped files which the selected group ceiling cannot serve before vlog recovery
 * can clean an empty file or create an active segment
 * @param dir database directory containing segment files
 * @param max_groups zero disables grouped files; otherwise valid ids are below this ceiling
 * @return VLOG_OK, VLOG_ERR_INVALID for an incompatible group configuration, or VLOG_ERR_IO
 */
int vlog_group_disk_preflight(const char* dir, uint32_t max_groups);

/**
 * vlog_group_disk_guard_create
 * durably install the legacy-refusal directory before the first grouped file becomes visible
 * @param dir database directory containing segment files
 * @return VLOG_OK, VLOG_ERR_INVALID, or VLOG_ERR_IO
 */
int vlog_group_disk_guard_create(const char* dir);

/**
 * vlog_group_disk_write_header
 * append the reserved first block identifying a newly created grouped segment and its owner
 * @param bm newly opened grouped segment with no records after its block-manager header
 * @param group group id assigned to the segment, never VLOG_GROUP_UNGROUPED
 * @return VLOG_OK or VLOG_ERR_IO
 */
int vlog_group_disk_write_header(block_manager_t* bm, uint32_t group);

/**
 * vlog_group_disk_read_owner
 * recover the owner from the fixed-size, checksummed first frame without modifying the file
 * @param fd open grouped segment, positioned reads only
 * @param out_group receives its shard-group id
 * @return VLOG_OK, VLOG_ERR_INVALID for bad arguments, or VLOG_ERR_CORRUPTION for an invalid header
 */
int vlog_group_disk_read_owner(int fd, uint32_t* out_group);

/**
 * vlog_group_disk_data_start
 * return the first value-frame offset for a segment owner
 * @param group VLOG_GROUP_UNGROUPED for an ordinary segment, otherwise its validated group id
 * @return BLOCK_MANAGER_HEADER_SIZE for ordinary segments or the grouped metadata frame's end
 */
uint64_t vlog_group_disk_data_start(uint32_t group);

#endif /* __VLOG_GROUP_DISK_H__ */
