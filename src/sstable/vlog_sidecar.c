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
#include "base/log.h"
#include "sstable/vlog_group_disk.h"
#include "sstable/vlog_internal.h"
#include "sstable/vlog_sidecar.h"
#include "xxhash.h"

#define VLOG_SIDECAR_VERSION        1u
#define VLOG_SIDECAR_PREFIX_VERSION 2u
#define VLOG_SIDECAR_HEADER_SIZE    72u
#define VLOG_SIDECAR_RECORD_SIZE    48u
#define VLOG_SIDECAR_TRAILER_SIZE   8u
#define VLOG_SIDECAR_FLAG_IDENTITY  1u
#define VLOG_SIDECAR_FLAG_PREFIX    2u
#define VLOG_SIDECAR_MIN_FRAME \
    (BLOCK_MANAGER_BLOCK_HEADER_SIZE + VLOG_BLK_HDR_SIZE + BLOCK_MANAGER_FOOTER_SIZE)

static const uint8_t vlog_sidecar_magic[8] = {'T', 'D', 'B', 'V', 'I', 'X', '0', '1'};
static const uint8_t vlog_sidecar_delta_magic[8] = {'T', 'D', 'B', 'V', 'I', 'X', 'D', '1'};

#define VLOG_SIDECAR_DELTA_HEADER_SIZE 24u

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

int vlog_sidecar_name(uint64_t number, int temporary, char* out, size_t out_size)
{
    if (!out || out_size == 0) return VLOG_ERR_INVALID;
    const char* const ext = temporary ? VLOG_SIDECAR_TMP_EXT : VLOG_SIDECAR_EXT;
    const int n =
        snprintf(out, out_size, "%0*llu%s", VLOG_SEGMENT_DIGITS, (unsigned long long)number, ext);
    return n > 0 && (size_t)n < out_size ? VLOG_OK : VLOG_ERR_INVALID;
}

/* fixed little-endian fields, followed by packed physical-order records and an XXH3-64 trailer */
enum
{
    VIX_DELTA_EXTENT = 8,
    VIX_DELTA_COUNT = 16,
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

static int vlog_sidecar_header(int fd, uint64_t number, uint64_t extent, uint64_t count,
                               uint32_t version, int prefix, uint8_t* header)
{
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(fd, &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size < extent ||
        (!prefix && (uint64_t)st.st_size != extent))
        return VLOG_ERR_IO;
    memset(header, 0, VLOG_SIDECAR_HEADER_SIZE);
    memcpy(header, vlog_sidecar_magic, sizeof(vlog_sidecar_magic));
    encode_uint32_le_compat(header + VIX_VERSION, version);
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
    const uint8_t* value = head + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    const uint64_t word = decode_uint64_le_compat(value + VLOG_BLK_ID_SIZE);
    const uint8_t stages = (uint8_t)(word >> VLOG_BLK_CHAIN_SHIFT);
    if (block_manager_framed_size(size) != entry->disk_len ||
        decode_uint64_le_compat(value) != entry->id ||
        (word & VLOG_BLK_LEN_MASK) != entry->value_len || stages > TDB_ENCODING_PIPELINE_MAX ||
        size < VLOG_BLK_HDR_SIZE + (uint32_t)stages)
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

static int vlog_offset_compare(const void* left, const void* right)
{
    const vlog_sidecar_entry_t *a = left, *b = right;
    return (a->offset > b->offset) - (a->offset < b->offset);
}

/* the caller has drained writers. only a seal releases surplus preallocation; after a checkpoint
 * subsequent appends still own that reservation. force all covered data before writing the cache.
 */
static int vlog_sync_indexed_extent(block_manager_t* bm, uint64_t extent, vlog_sidecar_kind_t kind)
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

/* a validated source index supplies the exact expected frame bytes when rebinding a backup.
 * v1 has one record run. v2 separates its runs with a digest and the next delta header. */
typedef struct
{
    FILE* file;
    uint64_t remaining;
} vlog_record_source_t;

static int vlog_match_record(vlog_record_source_t* source, const uint8_t* record)
{
    if (!source->remaining)
    {
        uint8_t delta[VLOG_SIDECAR_DELTA_HEADER_SIZE];
        if (fread(delta, 1, sizeof(delta), source->file) != sizeof(delta)) return VLOG_ERR_IO;
        source->remaining = decode_uint64_le_compat(delta + VIX_DELTA_COUNT);
        if (!source->remaining ||
            memcmp(delta, vlog_sidecar_delta_magic, sizeof(vlog_sidecar_delta_magic)) != 0)
            return VLOG_ERR_CORRUPTION;
    }
    uint8_t expected[VLOG_SIDECAR_RECORD_SIZE];
    if (fread(expected, 1, sizeof(expected), source->file) != sizeof(expected) ||
        memcmp(expected, record, sizeof(expected)) != 0)
        return VLOG_ERR_CORRUPTION;
    if (!--source->remaining && fseek(source->file, VLOG_SIDECAR_TRAILER_SIZE, SEEK_CUR) != 0)
        return VLOG_ERR_IO;
    return VLOG_OK;
}

static int vlog_write_records(FILE* file, int fd, vlog_record_source_t* source,
                              const uint8_t* header, size_t header_size, uint64_t offset,
                              uint64_t extent, const vlog_sidecar_entry_t* entries, size_t count)
{
    XXH3_state_t hash;
    if (XXH3_64bits_reset(&hash) != XXH_OK ||
        XXH3_64bits_update(&hash, header, header_size) != XXH_OK ||
        fwrite(header, 1, header_size, file) != header_size)
        return VLOG_ERR_IO;

    for (size_t i = 0; i < count; ++i)
    {
        uint8_t record[VLOG_SIDECAR_RECORD_SIZE];
        int rc = vlog_sidecar_record(fd, offset, extent, &entries[i], record);
        if (rc != VLOG_OK) return rc;
        if (source && (rc = vlog_match_record(source, record)) != VLOG_OK) return rc;
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

/* only append to an index that still covers the last successful publication. replace a
 * missing or truncated cache, and discard any tail left by a failed flush or sync. */
static int vlog_resume_prefix(const char* path, const uint8_t* header, uint64_t size, FILE** out)
{
    FILE* file = fopen(path, "r+b");
    if (!file) return errno == ENOENT ? VLOG_OK : VLOG_ERR_IO;
    struct STAT_STRUCT st;
    uint8_t saved[VLOG_SIDECAR_HEADER_SIZE];
    int rc = VLOG_OK;
    if (FSTAT_FUNC(tdb_fileno(file), &st) != 0)
        rc = VLOG_ERR_IO;
    else if (st.st_size >= 0 && (uint64_t)st.st_size >= size &&
             fread(saved, 1, sizeof(saved), file) == sizeof(saved) &&
             memcmp(saved, header, sizeof(saved)) == 0)
    {
        if (((uint64_t)st.st_size > size && ftruncate(tdb_fileno(file), (off_t)size) != 0) ||
            fseek(file, 0, SEEK_END) != 0)
            rc = VLOG_ERR_IO;
        else
        {
            *out = file;
            return VLOG_OK;
        }
    }
    return fclose(file) == 0 ? rc : VLOG_ERR_IO;
}

/* the caller drains writers. the first checkpoint and the seal replace the index atomically,
 * while later checkpoints append only their newly completed frames. */
static int vlog_sidecar_publish(vlog_t* v, uint32_t slot, vlog_pending_t* writer, uint64_t extent,
                                vlog_sidecar_kind_t kind)
{
    const int prefix = kind == VLOG_SIDECAR_PREFIX;
    const uint64_t start = vlog_group_disk_data_start(v->segments[slot].group);
    const uint64_t number = v->segments[slot].number;
    char tmp[VLOG_PATH_MAX], path[VLOG_PATH_MAX];
    if (vlog_sidecar_path(v->dir, number, 1, tmp, sizeof(tmp)) != VLOG_OK ||
        vlog_sidecar_path(v->dir, number, 0, path, sizeof(path)) != VLOG_OK)
        return VLOG_ERR_INVALID;

    block_manager_t* bm = vlog_segment_ensure_open(v, slot);
    if (!bm || vlog_sync_indexed_extent(bm, extent, kind) != VLOG_OK) return VLOG_ERR_IO;
    uint8_t header[VLOG_SIDECAR_HEADER_SIZE];
    int rc = vlog_sidecar_header(
        bm->fd, number, prefix ? start : extent, prefix ? 0 : writer->count,
        prefix ? VLOG_SIDECAR_PREFIX_VERSION : VLOG_SIDECAR_VERSION, prefix, header);
    if (rc != VLOG_OK) return rc;
    qsort(writer->entries + writer->published_count, writer->count - writer->published_count,
          sizeof(*writer->entries), vlog_offset_compare);

    FILE* file = NULL;
    if (prefix && writer->published_count)
    {
        rc = vlog_resume_prefix(path, header, writer->published_size, &file);
        if (rc != VLOG_OK) return rc;
    }
    const size_t first = file ? writer->published_count : 0;
    if (!file)
    {
        if (remove(tmp) != 0 && errno != ENOENT) return VLOG_ERR_IO;
        file = fopen(tmp, "wbx");
        if (!file) return VLOG_ERR_IO;
    }
    const size_t count = writer->count - first;
    if (prefix)
    {
        if (!first && fwrite(header, 1, sizeof(header), file) != sizeof(header)) rc = VLOG_ERR_IO;
#ifdef TDB_FAULT_INJECTION
        if (first && v->publication_hook) v->publication_hook(0);
#endif
        uint8_t delta[VLOG_SIDECAR_DELTA_HEADER_SIZE];
        memcpy(delta, vlog_sidecar_delta_magic, sizeof(vlog_sidecar_delta_magic));
        encode_uint64_le_compat(delta + VIX_DELTA_EXTENT, extent);
        encode_uint64_le_compat(delta + VIX_DELTA_COUNT, count);
        const uint64_t offset =
            first ? writer->entries[first - 1].offset + writer->entries[first - 1].disk_len : start;
        if (rc == VLOG_OK)
            rc = vlog_write_records(file, bm->fd, NULL, delta, sizeof(delta), offset, extent,
                                    writer->entries + first, count);
    }
    else
        rc = vlog_write_records(file, bm->fd, NULL, header, sizeof(header), start, extent,
                                writer->entries, count);
    if (fclose(file) != 0) rc = VLOG_ERR_IO;
    if (!first)
    {
#ifdef TDB_FAULT_INJECTION
        if (rc == VLOG_OK && v->publication_hook) v->publication_hook(0);
#endif
        if (rc == VLOG_OK && tdb_replace_file(tmp, path) != 0) rc = VLOG_ERR_IO;
        if (rc != VLOG_OK) (void)remove(tmp);
    }
#ifdef TDB_FAULT_INJECTION
    if (rc == VLOG_OK && v->publication_hook) v->publication_hook(1);
#endif
    if (rc == VLOG_OK && !first && tdb_fsync_parent_dir(path) != 0) rc = VLOG_ERR_IO;
    if (rc == VLOG_OK && prefix)
    {
        writer->published_count = writer->count;
        writer->published_size =
            (first ? writer->published_size : sizeof(header)) + VLOG_SIDECAR_DELTA_HEADER_SIZE +
            (uint64_t)count * VLOG_SIDECAR_RECORD_SIZE + VLOG_SIDECAR_TRAILER_SIZE;
    }
    return rc;
}

void vlog_publish_pending(vlog_t* v, uint32_t slot, vlog_pending_t* writer, uint64_t extent,
                          vlog_sidecar_kind_t kind)
{
    if (writer->count && !writer->incomplete &&
        (kind == VLOG_SIDECAR_SEALED || writer->count > writer->published_count) &&
        vlog_sidecar_publish(v, slot, writer, extent, kind) != VLOG_OK)
        TDB_DEBUG_LOG(TDB_LOG_WARN, "could not publish recovery index for vlog segment %llu",
                      (unsigned long long)v->segments[slot].number);
    if (kind == VLOG_SIDECAR_SEALED)
    {
        writer->count = 0;
        writer->published_count = 0;
        writer->published_size = 0;
        writer->incomplete = 0;
        writer->checkpoint_at = BLOCK_MANAGER_HEADER_SIZE + VLOG_CHECKPOINT_INTERVAL_BYTES;
    }
}

static int vlog_read_records(FILE* file, int fd, const uint8_t* header, size_t header_size,
                             uint64_t offset, uint64_t extent, vlog_sidecar_entry_t* entries,
                             size_t count)
{
    XXH3_state_t hash;
    if (XXH3_64bits_reset(&hash) != XXH_OK ||
        XXH3_64bits_update(&hash, header, header_size) != XXH_OK)
        return VLOG_ERR_IO;
    for (size_t i = 0; i < count; ++i)
    {
        uint8_t record[VLOG_SIDECAR_RECORD_SIZE], checked[VLOG_SIDECAR_RECORD_SIZE];
        if (fread(record, 1, sizeof(record), file) != sizeof(record)) return VLOG_ERR_CORRUPTION;
        entries[i] =
            (vlog_sidecar_entry_t){.id = decode_uint64_le_compat(record + VIX_ID),
                                   .offset = decode_uint64_le_compat(record + VIX_OFFSET),
                                   .value_len = decode_uint64_le_compat(record + VIX_VALUE_LEN),
                                   .disk_len = decode_uint64_le_compat(record + VIX_DISK_LEN),
                                   .chain = decode_uint64_le_compat(record + VIX_CHAIN)};
        int rc = vlog_sidecar_record(fd, offset, extent, &entries[i], checked);
        if (rc != VLOG_OK) return rc;
        if (memcmp(checked, record, sizeof(record)) != 0 ||
            XXH3_64bits_update(&hash, record, sizeof(record)) != XXH_OK)
            return VLOG_ERR_CORRUPTION;
        offset += entries[i].disk_len;
    }
    uint8_t trailer[VLOG_SIDECAR_TRAILER_SIZE];
    if (offset != extent || fread(trailer, 1, sizeof(trailer), file) != sizeof(trailer) ||
        XXH3_64bits_digest(&hash) != decode_uint64_le_compat(trailer))
        return VLOG_ERR_CORRUPTION;
    return VLOG_OK;
}

static int vlog_read_sidecar(FILE* file, int fd, uint64_t number, uint64_t logical_extent,
                             uint64_t start, vlog_sidecar_entry_t** out, size_t* count,
                             uint64_t* out_extent)
{
    uint8_t header[VLOG_SIDECAR_HEADER_SIZE], bound[VLOG_SIDECAR_HEADER_SIZE];
    if (fread(header, 1, sizeof(header), file) != sizeof(header)) return VLOG_ERR_CORRUPTION;
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(tdb_fileno(file), &st) != 0) return VLOG_ERR_IO;
    if (st.st_size < (off_t)sizeof(header) || logical_extent < start) return VLOG_ERR_CORRUPTION;
    const uint32_t version = decode_uint32_le_compat(header + VIX_VERSION);
    const int deltas = version == VLOG_SIDECAR_PREFIX_VERSION;
    const int prefix =
        (decode_uint32_le_compat(header + VIX_FLAGS) & VLOG_SIDECAR_FLAG_PREFIX) != 0;
    uint64_t extent = decode_uint64_le_compat(header + VIX_EXTENT);
    uint64_t n = decode_uint64_le_compat(header + VIX_COUNT);
    if ((!deltas && version != VLOG_SIDECAR_VERSION) ||
        (deltas && (!prefix || extent != start || n)) || extent < start ||
        extent > logical_extent || (!prefix && extent != logical_extent) ||
        vlog_sidecar_header(fd, number, extent, n, version, prefix, bound) != VLOG_OK ||
        memcmp(bound, header, sizeof(header)) != 0)
        return VLOG_ERR_CORRUPTION;

    vlog_sidecar_entry_t* entries = NULL;
    size_t used = 0, capacity = 0;
    uint64_t remaining = (uint64_t)st.st_size - sizeof(header);
    int rc = VLOG_OK;
    do
    {
        size_t header_size = sizeof(header);
        if (deltas)
        {
            header_size = VLOG_SIDECAR_DELTA_HEADER_SIZE;
            if (remaining < header_size)
                break; /* a short last append leaves earlier deltas valid */
            if (fread(header, 1, header_size, file) != header_size ||
                memcmp(header, vlog_sidecar_delta_magic, sizeof(vlog_sidecar_delta_magic)) != 0)
            {
                rc = VLOG_ERR_CORRUPTION;
                break;
            }
            remaining -= header_size;
            extent = decode_uint64_le_compat(header + VIX_DELTA_EXTENT);
            n = decode_uint64_le_compat(header + VIX_DELTA_COUNT);
        }
        if (!n || extent < start || extent > logical_extent ||
            n > (extent - start) / VLOG_SIDECAR_MIN_FRAME ||
            n > SIZE_MAX / sizeof(*entries) - used ||
            n > (UINT64_MAX - VLOG_SIDECAR_TRAILER_SIZE) / VLOG_SIDECAR_RECORD_SIZE)
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        const uint64_t bytes = n * VLOG_SIDECAR_RECORD_SIZE + VLOG_SIDECAR_TRAILER_SIZE;
        if (!deltas && bytes != remaining)
        {
            rc = VLOG_ERR_CORRUPTION;
            break;
        }
        if (bytes > remaining) break; /* torn records or trailer */
        const size_t needed = used + (size_t)n;
        if (needed > capacity)
        {
            capacity = capacity <= SIZE_MAX / sizeof(*entries) / 2 ? capacity * 2 : needed;
            if (capacity < needed) capacity = needed;
            vlog_sidecar_entry_t* more = realloc(entries, capacity * sizeof(*entries));
            if (!more)
            {
                rc = VLOG_ERR_MEMORY;
                break;
            }
            entries = more;
        }
        rc = vlog_read_records(file, fd, header, header_size, start, extent, entries + used,
                               (size_t)n);
        if (rc != VLOG_OK) break;
        remaining -= bytes;
        used = needed;
        start = extent;
    } while (deltas && remaining);
    if (rc != VLOG_OK || !used)
    {
        free(entries);
        return rc == VLOG_OK ? VLOG_ERR_CORRUPTION : rc;
    }
    *out = entries;
    *count = used;
    *out_extent = start;
    return VLOG_OK;
}

int vlog_sidecar_load(vlog_t* v, uint32_t slot, uint64_t logical_extent, vlog_sidecar_entry_t** out,
                      size_t* count, uint64_t* out_extent)
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
    FILE* file = fopen(path, "rb");
    if (!file) return errno == ENOENT ? VLOG_ERR_NOT_FOUND : VLOG_ERR_IO;
    block_manager_t* bm = vlog_segment_ensure_open(v, slot);
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
        if (rc == VLOG_OK)
        {
            /* only the directory rename publishes these files. a failed rebind discards the stage.
             */
            FILE* out = fopen(path, "wbx");
            if (!out)
                rc = VLOG_ERR_IO;
            else
            {
                uint8_t header[VLOG_SIDECAR_HEADER_SIZE];
                if (fseek(index, 0, SEEK_SET) != 0 ||
                    fread(header, 1, sizeof(header), index) != sizeof(header))
                    rc = VLOG_ERR_IO;
                else
                {
                    /* the v2 identity header starts with zero entries. Its first delta follows. */
                    vlog_record_source_t source = {index,
                                                   decode_uint64_le_compat(header + VIX_COUNT)};
                    rc = vlog_sidecar_header(copy_fd, info->number, extent, count,
                                             VLOG_SIDECAR_VERSION, 0, header);
                    if (rc == VLOG_OK)
                        rc = vlog_write_records(out, copy_fd, &source, header, sizeof(header),
                                                start, extent, entries, count);
                }
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

int vlog_sidecar_unlink(vlog_t* v, uint64_t number)
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
