/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>

#define XXH_STATIC_LINKING_ONLY /* stack-allocated streaming checksum state */
#include "sstable/vlog_group_disk.h"
#include "sstable/vlog_internal.h"
#include "sstable/vlog_sidecar.h"
#include "xxhash.h"

#define VLOG_SIDECAR_VERSION       1u
#define VLOG_SIDECAR_HEADER_SIZE   72u
#define VLOG_SIDECAR_RECORD_SIZE   48u
#define VLOG_SIDECAR_TRAILER_SIZE  8u
#define VLOG_SIDECAR_FLAG_IDENTITY 1u
#define VLOG_SIDECAR_FLAG_PREFIX   2u
#define VLOG_SIDECAR_MIN_FRAME \
    (BLOCK_MANAGER_BLOCK_HEADER_SIZE + VLOG_BLK_HDR_SIZE + BLOCK_MANAGER_FOOTER_SIZE)

static const uint8_t vlog_sidecar_magic[8] = {'T', 'D', 'B', 'V', 'I', 'X', '0', '1'};

/* form dir/basename without ever accepting a filename from disk */
static int vlog_sidecar_path(const char* dir, uint64_t number, int temporary, char* out,
                             size_t out_size)
{
    char name[VLOG_SIDECAR_NAME_MAX];
    if (!dir || !out || vlog_sidecar_name(number, temporary, name, sizeof(name)) != VLOG_OK)
        return VLOG_ERR_INVALID;
    const int n = snprintf(out, out_size, "%s%s%s", dir, PATH_SEPARATOR, name);
    return n > 0 && (size_t)n < out_size ? VLOG_OK : VLOG_ERR_INVALID;
}

int vlog_sidecar_name(uint64_t number, int temporary, char *out, size_t out_size)
{
    if (!out || out_size == 0) return VLOG_ERR_INVALID;
    const char *const ext = temporary ? VLOG_SIDECAR_TMP_EXT : VLOG_SIDECAR_EXT;
    const int n =
        snprintf(out, out_size, "%0*llu%s", VLOG_SEGMENT_DIGITS, (unsigned long long)number, ext);
    return n > 0 && (size_t)n < out_size ? VLOG_OK : VLOG_ERR_INVALID;
}

/* fixed little-endian fields, followed by packed physical-order records and an XXH3-64 trailer */
enum
{
    VIX_VERSION = 8,
    VIX_HEADER_LEN = 12,
    VIX_NUMBER = 16,
    VIX_EXTENT = 24,
    VIX_DEV = 32,
    VIX_INO = 40,
    VIX_COUNT = 48,
    VIX_FLAGS = 56,
    VIX_BM_HEADER = 64,
    VIX_ID = 0,
    VIX_OFFSET = 8,
    VIX_VALUE_LEN = 16,
    VIX_DISK_LEN = 24,
    VIX_CHAIN = 32,
    VIX_BLOCK_CHECKSUM = 40,
    VIX_CODEC_COUNT = 44
};

static int vlog_sidecar_header(int fd, uint64_t number, uint64_t extent, uint64_t count, int prefix,
                               uint8_t* header)
{
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(fd, &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size < extent ||
        (!prefix && (uint64_t)st.st_size != extent))
        return VLOG_ERR_IO;
    memset(header, 0, VLOG_SIDECAR_HEADER_SIZE);
    memcpy(header, vlog_sidecar_magic, sizeof(vlog_sidecar_magic));
    encode_uint32_le_compat(header + VIX_VERSION, VLOG_SIDECAR_VERSION);
    encode_uint32_le_compat(header + VIX_HEADER_LEN, VLOG_SIDECAR_HEADER_SIZE);
    encode_uint64_le_compat(header + VIX_NUMBER, number);
    encode_uint64_le_compat(header + VIX_EXTENT, extent);
    encode_uint64_le_compat(header + VIX_COUNT, count);
    encode_uint32_le_compat(header + VIX_FLAGS,
                            VLOG_SIDECAR_FLAG_IDENTITY | (prefix ? VLOG_SIDECAR_FLAG_PREFIX : 0));
#ifdef _WIN32
    const intptr_t handle = _get_osfhandle(fd);
    BY_HANDLE_FILE_INFORMATION info;
    if (handle == -1 || !GetFileInformationByHandle((HANDLE)handle, &info)) return VLOG_ERR_IO;
    encode_uint64_le_compat(header + VIX_DEV, info.dwVolumeSerialNumber);
    encode_uint64_le_compat(header + VIX_INO,
                            ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow);
#else
    encode_uint64_le_compat(header + VIX_DEV, (uint64_t)st.st_dev);
    encode_uint64_le_compat(header + VIX_INO, (uint64_t)st.st_ino);
#endif
    return pread(fd, header + VIX_BM_HEADER, BLOCK_MANAGER_HEADER_SIZE, 0) ==
                   BLOCK_MANAGER_HEADER_SIZE
               ? VLOG_OK
               : VLOG_ERR_IO;
}

/* bind each record to the authoritative header, encoding ids, checksum and footer. a same-inode
 * overwrite can preserve both file number and byte length. point reads verify the payload itself.
 */
static int vlog_sidecar_record(int fd, uint64_t offset, uint64_t extent,
                               const vlog_sidecar_entry_t* entry, uint8_t* record)
{
    if (entry->id == VLOG_ID_INVALID || entry->offset != offset || offset > extent ||
        entry->disk_len < VLOG_SIDECAR_MIN_FRAME || entry->disk_len > extent - offset)
        return VLOG_ERR_CORRUPTION;

    uint8_t head[BLOCK_MANAGER_BLOCK_HEADER_SIZE + VLOG_BLK_HDR_SIZE];
    if (pread(fd, head, sizeof(head), (off_t)offset) != (ssize_t)sizeof(head)) return VLOG_ERR_IO;
    const uint32_t size = decode_uint32_le_compat(head);
    const uint8_t *value = head + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    const uint64_t word = decode_uint64_le_compat(value + VLOG_BLK_ID_SIZE);
    const uint8_t stages = (uint8_t)(word >> VLOG_BLK_CHAIN_SHIFT);
    if (block_manager_framed_size(size) != entry->disk_len ||
        decode_uint64_le_compat(value) != entry->id ||
        (word & VLOG_BLK_LEN_MASK) != entry->value_len || stages > TDB_ENCODING_PIPELINE_MAX ||
        size < VLOG_BLK_HDR_SIZE + stages)
        return VLOG_ERR_CORRUPTION;

    uint8_t ids[sizeof(entry->chain)] = {0};
    if (stages && pread(fd, ids, stages, (off_t)(offset + sizeof(head))) != stages)
        return VLOG_ERR_IO;
    if (decode_uint64_le_compat(ids) != entry->chain) return VLOG_ERR_CORRUPTION;
    uint8_t footer[BLOCK_MANAGER_FOOTER_SIZE];
    if (pread(fd, footer, sizeof(footer), (off_t)(offset + entry->disk_len - sizeof(footer))) !=
        (ssize_t)sizeof(footer))
        return VLOG_ERR_IO;
    if (decode_uint32_le_compat(footer) != size ||
        decode_uint32_le_compat(footer + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET) !=
            BLOCK_MANAGER_FOOTER_MAGIC)
        return VLOG_ERR_CORRUPTION;

    memset(record, 0, VLOG_SIDECAR_RECORD_SIZE);
    encode_uint64_le_compat(record + VIX_ID, entry->id);
    encode_uint64_le_compat(record + VIX_OFFSET, entry->offset);
    encode_uint64_le_compat(record + VIX_VALUE_LEN, entry->value_len);
    encode_uint64_le_compat(record + VIX_DISK_LEN, entry->disk_len);
    encode_uint64_le_compat(record + VIX_CHAIN, entry->chain);
    memcpy(record + VIX_BLOCK_CHECKSUM, head + BLOCK_MANAGER_SIZE_FIELD_SIZE,
           BLOCK_MANAGER_CHECKSUM_LENGTH);
    record[VIX_CODEC_COUNT] = stages;
    return VLOG_OK;
}

static int vlog_offset_compare(const void *left, const void *right)
{
    const vlog_sidecar_entry_t *a = left, *b = right;
    return (a->offset > b->offset) - (a->offset < b->offset);
}

/* the caller has drained writers. only a seal releases surplus preallocation; after a checkpoint
 * subsequent appends still own that reservation. force all covered data before writing the cache.
 */
static int vlog_sync_indexed_extent(block_manager_t *bm, uint64_t extent, vlog_sidecar_kind_t kind)
{
    uint64_t size = 0;
    if (block_manager_get_size(bm, &size) != 0 || size != extent) return VLOG_ERR_IO;
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(bm->fd, &st) != 0 || (uint64_t)st.st_size < extent) return VLOG_ERR_IO;
    if (kind == VLOG_SIDECAR_SEALED && (uint64_t)st.st_size > extent)
    {
        if (ftruncate(bm->fd, (off_t)extent) != 0) return VLOG_ERR_IO;
        atomic_store(&bm->preallocated_size, extent);
    }
    return block_manager_escalate_fsync(bm) == 0 ? VLOG_OK : VLOG_ERR_IO;
}

static int vlog_write_sidecar(FILE* file, int fd, FILE* expected_records, uint64_t number,
                              uint64_t extent, const vlog_sidecar_entry_t* entries, size_t count,
                              vlog_sidecar_kind_t kind, uint64_t data_start)
{
    uint8_t header[VLOG_SIDECAR_HEADER_SIZE];
    int rc = vlog_sidecar_header(fd, number, extent, count, kind == VLOG_SIDECAR_PREFIX, header);
    if (rc != VLOG_OK) return rc;
    XXH3_state_t hash;
    if (XXH3_64bits_reset(&hash) != XXH_OK ||
        XXH3_64bits_update(&hash, header, sizeof(header)) != XXH_OK ||
        fwrite(header, 1, sizeof(header), file) != sizeof(header))
        return VLOG_ERR_IO;

    uint64_t offset = data_start;
    for (size_t i = 0; i < count; ++i)
    {
        uint8_t record[VLOG_SIDECAR_RECORD_SIZE];
        rc = vlog_sidecar_record(fd, offset, extent, &entries[i], record);
        if (rc != VLOG_OK) return rc;
        if (expected_records)
        {
            uint8_t expected[VLOG_SIDECAR_RECORD_SIZE];
            if (fread(expected, 1, sizeof(expected), expected_records) != sizeof(expected) ||
                memcmp(expected, record, sizeof(record)) != 0)
                return VLOG_ERR_CORRUPTION;
        }
        if (XXH3_64bits_update(&hash, record, sizeof(record)) != XXH_OK ||
            fwrite(record, 1, sizeof(record), file) != sizeof(record))
            return VLOG_ERR_IO;
        offset += entries[i].disk_len;
    }
    if (offset != extent) return VLOG_ERR_CORRUPTION;
    uint8_t trailer[VLOG_SIDECAR_TRAILER_SIZE];
    encode_uint64_le_compat(trailer, XXH3_64bits_digest(&hash));
    if (fwrite(trailer, 1, sizeof(trailer), file) != sizeof(trailer) || fflush(file) != 0 ||
        tdb_fsync(tdb_fileno(file)) != 0)
        return VLOG_ERR_IO;
    return VLOG_OK;
}

int vlog_sidecar_publish(vlog_t *v, uint32_t slot, vlog_sidecar_entry_t *entries, size_t count,
                         uint64_t extent, vlog_sidecar_kind_t kind)
{
    if (!v || !entries || !count || slot >= v->max_segments) return VLOG_ERR_INVALID;
    const uint64_t data_start = vlog_group_disk_data_start(v->segments[slot].group);
    if (extent < data_start || count > (extent - data_start) / VLOG_SIDECAR_MIN_FRAME)
        return VLOG_ERR_INVALID;
    const uint64_t number = v->segments[slot].number;
    char tmp[VLOG_PATH_MAX], path[VLOG_PATH_MAX];
    if (vlog_sidecar_path(v->dir, number, 1, tmp, sizeof(tmp)) != VLOG_OK ||
        vlog_sidecar_path(v->dir, number, 0, path, sizeof(path)) != VLOG_OK)
        return VLOG_ERR_INVALID;

    block_manager_t *bm = vlog_segment_ensure_open(v, slot);
    if (!bm || vlog_sync_indexed_extent(bm, extent, kind) != VLOG_OK) return VLOG_ERR_IO;
    qsort(entries, count, sizeof(*entries), vlog_offset_compare);
    if (remove(tmp) != 0 && errno != ENOENT) return VLOG_ERR_IO;
    FILE *file = fopen(tmp, "wbx");
    if (!file) return VLOG_ERR_IO;
    int rc =
        vlog_write_sidecar(file, bm->fd, NULL, number, extent, entries, count, kind, data_start);
    if (fclose(file) != 0) rc = VLOG_ERR_IO;
#ifdef TDB_FAULT_INJECTION
    if (rc == VLOG_OK && v->publication_hook) v->publication_hook(0);
#endif
    if (rc == VLOG_OK && tdb_replace_file(tmp, path) != 0) rc = VLOG_ERR_IO;
    if (rc != VLOG_OK)
    {
        (void)remove(tmp); /* the next attempt discards any interrupted temporary */
        return rc;
    }
#ifdef TDB_FAULT_INJECTION
    if (v->publication_hook) v->publication_hook(1);
#endif
    return tdb_fsync_parent_dir(path) == 0 ? VLOG_OK : VLOG_ERR_IO;
}

static int vlog_read_sidecar(FILE* file, int fd, uint64_t number, uint64_t logical_extent,
                             uint64_t data_start, vlog_sidecar_entry_t** out, size_t* count,
                             uint64_t* out_extent)
{
    uint8_t header[VLOG_SIDECAR_HEADER_SIZE], bound[VLOG_SIDECAR_HEADER_SIZE];
    if (fread(header, 1, sizeof(header), file) != sizeof(header)) return VLOG_ERR_CORRUPTION;
    const uint64_t n = decode_uint64_le_compat(header + VIX_COUNT);
    const uint64_t extent = decode_uint64_le_compat(header + VIX_EXTENT);
    const uint32_t flags = decode_uint32_le_compat(header + VIX_FLAGS);
    const int prefix = (flags & VLOG_SIDECAR_FLAG_PREFIX) != 0;
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(tdb_fileno(file), &st) != 0) return VLOG_ERR_IO;
    const uint64_t fixed = sizeof(header) + VLOG_SIDECAR_TRAILER_SIZE;
    if (extent < data_start || extent > logical_extent || (!prefix && extent != logical_extent) ||
        !n || n > (extent - data_start) / VLOG_SIDECAR_MIN_FRAME || n > SIZE_MAX / sizeof(**out) ||
        n > (UINT64_MAX - fixed) / VLOG_SIDECAR_RECORD_SIZE || (uint64_t)st.st_size < fixed ||
        (uint64_t)st.st_size - fixed != n * VLOG_SIDECAR_RECORD_SIZE)
        return VLOG_ERR_CORRUPTION;
    if (vlog_sidecar_header(fd, number, extent, n, prefix, bound) != VLOG_OK ||
        memcmp(bound, header, sizeof(header)) != 0)
        return VLOG_ERR_CORRUPTION;

    XXH3_state_t hash;
    if (XXH3_64bits_reset(&hash) != XXH_OK ||
        XXH3_64bits_update(&hash, header, sizeof(header)) != XXH_OK)
        return VLOG_ERR_IO;
    vlog_sidecar_entry_t *entries = malloc((size_t)n * sizeof(*entries));
    if (!entries) return VLOG_ERR_MEMORY;
    int rc = VLOG_OK;
    uint64_t offset = data_start;
    for (size_t i = 0; i < n; ++i)
    {
        uint8_t record[VLOG_SIDECAR_RECORD_SIZE], checked[VLOG_SIDECAR_RECORD_SIZE];
        if (fread(record, 1, sizeof(record), file) != sizeof(record))
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        entries[i] =
            (vlog_sidecar_entry_t){.id = decode_uint64_le_compat(record + VIX_ID),
                                   .offset = decode_uint64_le_compat(record + VIX_OFFSET),
                                   .value_len = decode_uint64_le_compat(record + VIX_VALUE_LEN),
                                   .disk_len = decode_uint64_le_compat(record + VIX_DISK_LEN),
                                   .chain = decode_uint64_le_compat(record + VIX_CHAIN)};
        rc = vlog_sidecar_record(fd, offset, extent, &entries[i], checked);
        if (rc != VLOG_OK) break;
        if (memcmp(checked, record, sizeof(record)) != 0 ||
            XXH3_64bits_update(&hash, record, sizeof(record)) != XXH_OK)
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        offset += entries[i].disk_len;
    }
    uint8_t trailer[VLOG_SIDECAR_TRAILER_SIZE];
    if (rc == VLOG_OK &&
        (offset != extent || fread(trailer, 1, sizeof(trailer), file) != sizeof(trailer) ||
         XXH3_64bits_digest(&hash) != decode_uint64_le_compat(trailer)))
        rc = VLOG_ERR_CORRUPTION;
    if (rc == VLOG_OK)
    {
        *out = entries;
        *count = (size_t)n;
        *out_extent = extent;
    }
    else
        free(entries);
    return rc;
}

int vlog_sidecar_load(vlog_t *v, uint32_t slot, uint64_t logical_extent, vlog_sidecar_entry_t **out,
                      size_t *count, uint64_t *out_extent)
{
    if (!v || !out || !count || !out_extent || slot >= v->max_segments ||
        logical_extent < BLOCK_MANAGER_HEADER_SIZE)
        return VLOG_ERR_INVALID;
    *out = NULL;
    *count = 0;
    *out_extent = 0;
    char path[VLOG_PATH_MAX];
    if (vlog_sidecar_path(v->dir, v->segments[slot].number, 0, path, sizeof(path)) != VLOG_OK)
        return VLOG_ERR_INVALID;
    FILE *file = fopen(path, "rb");
    if (!file) return errno == ENOENT ? VLOG_ERR_NOT_FOUND : VLOG_ERR_IO;
    block_manager_t *bm = vlog_segment_ensure_open(v, slot);
    const int rc = bm ? vlog_read_sidecar(file, bm->fd, v->segments[slot].number, logical_extent,
                                          vlog_group_disk_data_start(v->segments[slot].group), out,
                                          count, out_extent)
                      : VLOG_ERR_IO;
    if (fclose(file) != 0 && rc == VLOG_OK)
    {
        free(*out);
        *out = NULL;
        *count = 0;
        *out_extent = 0;
        return VLOG_ERR_IO;
    }
    return rc;
}

/* keep the kernel identity check on the source index. compare the resulting frame records,
 * including each stored checksum, before binding them to the destination inode. */
static int vlog_rebind_index(FILE* index, int source_fd, int copy_fd,
                             const vlog_segment_info_t* info, const char* dir)
{
    const uint64_t start = vlog_group_disk_data_start(info->group);
    vlog_sidecar_entry_t* entries = NULL;
    size_t count = 0;
    uint64_t extent = 0;
    int rc = vlog_read_sidecar(index, source_fd, info->number, info->logical_size, start, &entries,
                               &count, &extent);
    if (rc == VLOG_ERR_CORRUPTION) return VLOG_OK; /* recovery rebuilds this optional index */
    if (rc != VLOG_OK) return rc;
    if (extent == info->logical_size)
    {
        char path[VLOG_PATH_MAX];
        rc = vlog_sidecar_path(dir, info->number, 0, path, sizeof(path));
        if (rc == VLOG_OK && fseek(index, VLOG_SIDECAR_HEADER_SIZE, SEEK_SET) != 0)
            rc = VLOG_ERR_IO;
        if (rc == VLOG_OK)
        {
            /* only the directory rename publishes these files. a failed rebind discards the stage.
             */
            FILE* out = fopen(path, "wbx");
            if (!out)
                rc = VLOG_ERR_IO;
            else
            {
                rc = vlog_write_sidecar(out, copy_fd, index, info->number, extent, entries, count,
                                        VLOG_SIDECAR_SEALED, start);
                if (fclose(out) != 0 || (rc == VLOG_OK && tdb_fsync_parent_dir(path) != 0))
                    rc = VLOG_ERR_IO;
            }
        }
    }
    free(entries);
    return rc;
}

int vlog_backup_index(vlog_t* v, const vlog_segment_info_t* info, const char* source_path,
                      const char* copy_path, const char* dir)
{
    if (!v || !info || !source_path || !copy_path || !dir) return VLOG_ERR_INVALID;
    FILE* copy = fopen(copy_path, "rb");
    if (!copy) return VLOG_ERR_IO;
    const int copy_fd = tdb_fileno(copy);
    struct STAT_STRUCT st;
    int rc = VLOG_OK;
    if (FSTAT_FUNC(copy_fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size != info->logical_size)
        rc = VLOG_ERR_CORRUPTION;
    if (rc == VLOG_OK && info->group != VLOG_GROUP_UNGROUPED)
    {
        uint32_t group = VLOG_GROUP_UNGROUPED;
        rc = vlog_group_disk_read_owner(copy_fd, &group);
        if (rc == VLOG_OK && group != info->group) rc = VLOG_ERR_CORRUPTION;
    }
    if (rc == VLOG_OK && v->enable_vlog_indexes)
    {
        char path[VLOG_PATH_MAX];
        rc = vlog_sidecar_path(v->dir, info->number, 0, path, sizeof(path));
        if (rc == VLOG_OK)
        {
            FILE* index = fopen(path, "rb");
            if (index)
            {
                FILE* source = fopen(source_path, "rb");
                rc = source ? vlog_rebind_index(index, tdb_fileno(source), copy_fd, info, dir)
                            : VLOG_ERR_IO;
                if (source && fclose(source) != 0) rc = VLOG_ERR_IO;
                if (fclose(index) != 0) rc = VLOG_ERR_IO;
            }
            else if (errno != ENOENT)
                rc = VLOG_ERR_IO;
        }
    }
    if (fclose(copy) != 0) rc = VLOG_ERR_IO;
    return rc;
}

int vlog_sidecar_unlink(vlog_t *v, uint64_t number)
{
    if (!v) return VLOG_ERR_INVALID;
    char published[VLOG_PATH_MAX], temporary[VLOG_PATH_MAX];
    if (vlog_sidecar_path(v->dir, number, 0, published, sizeof(published)) != VLOG_OK ||
        vlog_sidecar_path(v->dir, number, 1, temporary, sizeof(temporary)) != VLOG_OK)
        return VLOG_ERR_INVALID;
    int rc = VLOG_OK;
    int removed = 0;
    if (remove(published) == 0)
        removed = 1;
    else if (errno != ENOENT)
        rc = VLOG_ERR_IO;
    if (remove(temporary) == 0)
        removed = 1;
    else if (errno != ENOENT)
        rc = VLOG_ERR_IO;
    if (rc == VLOG_OK && removed && tdb_fsync_parent_dir(published) != 0) rc = VLOG_ERR_IO;
    return rc;
}
