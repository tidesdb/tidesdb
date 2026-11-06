/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable/vlog_group_disk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h"
#include "compat.h"
#include "sstable/vlog.h"
#include "sstable/vlog_internal.h"
#include "xxhash.h"

/* a first value-block whose impossible id makes the grouped ownership self-describing */
#define VLOG_GROUP_HEADER_MAGIC   UINT64_C(0x31505247564c4454)
#define VLOG_GROUP_HEADER_VERSION 1u
#define VLOG_GROUP_HEADER_SIZE    24u
#define VLOG_GROUP_GUARD_DIR_MODE 0755

static int vlog_group_disk_path(const char* dir, char* out, size_t out_size)
{
    const int n = snprintf(out, out_size, "%s%s%s", dir, PATH_SEPARATOR, VLOG_GROUP_GUARD_NAME);
    return n > 0 && (size_t)n < out_size ? VLOG_OK : VLOG_ERR_INVALID;
}

/* guard files retain db-global sequence numbers, so their names use the legacy numeric grammar
 * without a group suffix. the directory itself marks the file as grouped. */
static int vlog_group_disk_parse_number(const char* name)
{
    uint64_t number = 0;
    if (!vlog_segment_parse_number(name, &number) || number == VLOG_GROUP_GUARD_NUMBER) return 0;
    char canonical[VLOG_SEGMENT_NAME_MAX];
    return vlog_segment_name(number, canonical, sizeof(canonical)) == VLOG_OK &&
           strcmp(name, canonical) == 0;
}

/* creation writes this exact suffix beside the eventual grouped file. it is only an unpublished
 * scratch file: a crash can leave it behind, but it never describes an owned segment and preflight
 * must neither adopt nor delete it. */
static int vlog_group_disk_is_temporary(const char* name)
{
    static const char suffix[] = ".tmp";
    const size_t name_len = strlen(name);
    const size_t suffix_len = sizeof(suffix) - 1u;
    if (name_len <= suffix_len || strcmp(name + name_len - suffix_len, suffix) != 0) return 0;
    char base[VLOG_SEGMENT_NAME_MAX];
    const size_t base_len = name_len - suffix_len;
    if (base_len >= sizeof(base)) return 0;
    memcpy(base, name, base_len);
    base[base_len] = '\0';
    return vlog_group_disk_parse_number(base);
}

/* preflight cannot open a block manager: its recovery mode can turn a torn tail into an on-disk
 * cleanup. this bounded read-only validator checks exactly the block-manager file header and the
 * one fixed-size group metadata frame, including its checksum and footer. */
int vlog_group_disk_read_owner(int fd, uint32_t* out_group)
{
    if (fd < 0 || !out_group) return VLOG_ERR_INVALID;
    uint8_t bytes[BLOCK_MANAGER_HEADER_SIZE + BLOCK_MANAGER_BLOCK_HEADER_SIZE +
                  VLOG_GROUP_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE];
    const size_t want = sizeof(bytes);
    const ssize_t got = pread(fd, bytes, want, 0);
    if (got != (ssize_t)want) return VLOG_ERR_CORRUPTION;

    const uint32_t file_magic = decode_uint32_le_compat(bytes) & BLOCK_MANAGER_MAGIC_MASK;
    if (file_magic != BLOCK_MANAGER_MAGIC ||
        bytes[BLOCK_MANAGER_MAGIC_SIZE] != BLOCK_MANAGER_VERSION)
        return VLOG_ERR_CORRUPTION;
    const uint8_t* frame = bytes + BLOCK_MANAGER_HEADER_SIZE;
    const uint32_t payload_size = decode_uint32_le_compat(frame);
    const uint32_t checksum = decode_uint32_le_compat(frame + BLOCK_MANAGER_SIZE_FIELD_SIZE);
    const uint8_t* payload = frame + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    const uint8_t* footer = payload + VLOG_GROUP_HEADER_SIZE;
    if (payload_size != VLOG_GROUP_HEADER_SIZE ||
        decode_uint32_le_compat(footer) != VLOG_GROUP_HEADER_SIZE ||
        decode_uint32_le_compat(footer + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET) !=
            BLOCK_MANAGER_FOOTER_MAGIC ||
        (uint32_t)XXH3_64bits(payload, VLOG_GROUP_HEADER_SIZE) != checksum)
        return VLOG_ERR_CORRUPTION;
    if (decode_uint64_le_compat(payload) != VLOG_ID_INVALID ||
        decode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE) != VLOG_GROUP_HEADER_MAGIC ||
        decode_uint32_le_compat(payload + VLOG_BLK_HDR_SIZE) == VLOG_GROUP_UNGROUPED ||
        decode_uint32_le_compat(payload + VLOG_BLK_HDR_SIZE + sizeof(uint32_t)) !=
            VLOG_GROUP_HEADER_VERSION)
        return VLOG_ERR_CORRUPTION;
    *out_group = decode_uint32_le_compat(payload + VLOG_BLK_HDR_SIZE);
    return VLOG_OK;
}

int vlog_group_disk_preflight(const char* dir, uint32_t max_groups)
{
    if (!dir || dir[0] == '\0') return VLOG_ERR_INVALID;
    char guard[VLOG_PATH_MAX];
    struct STAT_STRUCT st;
    if (vlog_group_disk_path(dir, guard, sizeof(guard)) != VLOG_OK) return VLOG_ERR_INVALID;
    if (STAT_FUNC(guard, &st) != 0) return errno == ENOENT ? VLOG_OK : VLOG_ERR_IO;
    if (!S_ISDIR(st.st_mode)) return VLOG_ERR_CORRUPTION;

    DIR* d = opendir(guard);
    if (!d) return VLOG_ERR_IO;

    int rc = VLOG_OK;
    struct dirent* ent = NULL;
    for (;;)
    {
        errno = 0;
        ent = readdir(d);
        if (!ent)
        {
            if (errno != 0) rc = VLOG_ERR_IO;
            break;
        }
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (vlog_group_disk_is_temporary(ent->d_name)) continue;
        if (!vlog_group_disk_parse_number(ent->d_name))
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        char path[VLOG_PATH_MAX];
        const int path_size =
            snprintf(path, sizeof(path), "%s%s%s", guard, PATH_SEPARATOR, ent->d_name);
        if (path_size < 0 || (size_t)path_size >= sizeof(path))
        {
            rc = VLOG_ERR_INVALID;
            break;
        }
        uint32_t group = VLOG_GROUP_UNGROUPED;
        FILE* file = fopen(path, "rb");
        if (!file)
        {
            rc = VLOG_ERR_IO;
            break;
        }
        const int decoded = vlog_group_disk_read_owner(tdb_fileno(file), &group);
        if (fclose(file) != 0 || decoded != VLOG_OK)
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        if (max_groups == 0 || group >= max_groups)
        {
            rc = VLOG_ERR_INVALID;
            break;
        }
    }
    if (closedir(d) != 0 && rc == VLOG_OK) rc = VLOG_ERR_IO;
    return rc;
}

int vlog_group_disk_guard_create(const char* dir)
{
    if (!dir || dir[0] == '\0') return VLOG_ERR_INVALID;
    char path[VLOG_PATH_MAX];
    if (vlog_group_disk_path(dir, path, sizeof(path)) != VLOG_OK) return VLOG_ERR_INVALID;

    if (mkdir(path, VLOG_GROUP_GUARD_DIR_MODE) != 0 && errno != EEXIST) return VLOG_ERR_IO;
    /* an earlier mkdir may have succeeded while syncing its parent failed. every publisher
     * establishes this barrier before exposing a segment under the guard. */
    return tdb_fsync_parent_dir(path) == 0 ? VLOG_OK : VLOG_ERR_IO;
}

int vlog_group_disk_write_header(block_manager_t* bm, uint32_t group)
{
    if (!bm || group == VLOG_GROUP_UNGROUPED) return VLOG_ERR_INVALID;
    uint8_t payload[VLOG_GROUP_HEADER_SIZE] = {0};
    encode_uint64_le_compat(payload, VLOG_ID_INVALID);
    encode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE, VLOG_GROUP_HEADER_MAGIC);
    encode_uint32_le_compat(payload + VLOG_BLK_HDR_SIZE, group);
    encode_uint32_le_compat(payload + VLOG_BLK_HDR_SIZE + sizeof(uint32_t),
                            VLOG_GROUP_HEADER_VERSION);
    return block_manager_write_raw(bm, payload, sizeof(payload)) < 0 ? VLOG_ERR_IO : VLOG_OK;
}

uint64_t vlog_group_disk_data_start(uint32_t group)
{
    return group == VLOG_GROUP_UNGROUPED
               ? BLOCK_MANAGER_HEADER_SIZE
               : BLOCK_MANAGER_HEADER_SIZE + block_manager_framed_size(VLOG_GROUP_HEADER_SIZE);
}
