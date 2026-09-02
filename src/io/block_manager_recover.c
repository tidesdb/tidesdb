/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/log.h"
#include "block_manager_internal.h"

/* discard a tail the validator could not vouch for. permissive recovery has already decided the
 * file is to be salvaged rather than refused, so the bytes go either way -- what matters is that
 * the loss is on the record, because a silent truncation is indistinguishable afterwards from data
 * that was never written. */
static int recover_truncate_to_header(block_manager_t *bm, const char *reason)
{
    TDB_DEBUG_LOG(TDB_LOG_WARN, "block manager discarding all blocks in %s, %s", bm->file_path,
                  reason);
    return truncate_to_header(bm);
}

/**
 * is_trailing_zero
 * check whether the file region [start, end) consists entirely of zero bytes.
 * used to distinguish preallocation tail (legitimate trailing zeros that should
 * be tolerated by validation) from mid-write corruption (non-zero garbage).
 * reads in chunks and stops early on the first non-zero byte.
 * @param fd the file descriptor
 * @param start start offset (inclusive)
 * @param end   end offset (exclusive)
 * @return 1 if all bytes in [start, end) are zero, 0 if any non-zero byte found, -1 on I/O error
 */
static int is_trailing_zero(const int fd, const uint64_t start, const uint64_t end)
{
    if (start >= end) return 1;

    /* small on-stack chunk -- the loop re-reads, so a big buffer buys nothing and
     * 64 KB on the stack is risky on platforms with small thread stacks */
    enum
    {
        SCAN_CHUNK = 8 * 1024
    };
    unsigned char buf[SCAN_CHUNK];

    uint64_t pos = start;
    while (pos < end)
    {
        size_t want = SCAN_CHUNK;
        if ((uint64_t)want > end - pos) want = (size_t)(end - pos);

        const ssize_t got = pread(fd, buf, want, (off_t)pos);
        if (got <= 0) return -1;

        for (ssize_t i = 0; i < got; i++)
        {
            if (buf[i] != 0) return 0;
        }
        pos += (uint64_t)got;
    }
    return 1;
}

int block_manager_count_blocks(block_manager_t *bm)
{
    if (!bm) return -1;

    const uint64_t file_size = atomic_load(&bm->current_file_size);
    if (file_size <= BLOCK_MANAGER_HEADER_SIZE) return 0;

    set_file_sequential_hint(bm->fd);

    /** buffered scan reading 64KB chunks so thousands of block headers are parsed per
     * syscall. only the first 4 bytes of each block (size field) are needed to compute the skip
     * distance. */
    enum
    {
        COUNT_BUF = 64 * 1024
    };
    uint8_t *buf = bm_get_read_buf(COUNT_BUF);
    if (!buf)
    {
        /* fallback to per-block pread via cursor */
        block_manager_cursor_t c;
        int n = 0;
        (void)block_manager_cursor_init_stack(&c, bm);
        while (block_manager_cursor_next(&c) == 0) n++;
        return n;
    }

    int count = 0;
    uint64_t pos = BLOCK_MANAGER_HEADER_SIZE;

    while (pos < file_size)
    {
        size_t want = COUNT_BUF;
        if (pos + want > file_size) want = (size_t)(file_size - pos);

        const ssize_t got = pread(bm->fd, buf, want, (off_t)pos);
        if (got < (ssize_t)BLOCK_MANAGER_SIZE_FIELD_SIZE) break;

        size_t off = 0;
        while (off + BLOCK_MANAGER_SIZE_FIELD_SIZE <= (size_t)got)
        {
            const uint32_t bsz = decode_uint32_le_compat(buf + off);
            if (bsz == 0) return count;

            const size_t total =
                BLOCK_MANAGER_BLOCK_HEADER_SIZE + (size_t)bsz + BLOCK_MANAGER_FOOTER_SIZE;

            if (off + total > (size_t)got)
            {
                /* block straddles buffer edge, break to re-read from this block's start */
                break;
            }

            off += total;
            count++;
        }

        /** advance file position by bytes consumed.
         *  if off == 0, one block is larger than the buffer, so read its size and skip. */
        if (off == 0)
        {
            const uint32_t bsz = decode_uint32_le_compat(buf);
            pos += BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)bsz + BLOCK_MANAGER_FOOTER_SIZE;
            count++;
        }
        else
        {
            pos += off;
        }
    }

    return count;
}

/**
 * validate_scan_extent
 * forward-scan from the header to the last well-formed block, returning the byte offset one past
 * the last valid block; sets *corrupt to 1 when non-zero garbage or a partial block is hit rather
 * than a clean end of data (a zero size field, the preallocation tail or a hole)
 * @param bm the block manager
 * @param file_size the on-disk file size the scan is bounded by
 * @param corrupt out set to 1 on garbage or a partial block, 0 on a clean end of data
 * @return the offset one past the last valid block
 */
static uint64_t validate_scan_extent(block_manager_t *bm, uint64_t file_size, int *corrupt)
{
    const uint64_t min_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;
    uint64_t valid_size = BLOCK_MANAGER_HEADER_SIZE;
    *corrupt = 0;

    while (scan_pos + min_block_size <= file_size)
    {
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
        {
            *corrupt = 1;
            break;
        }

        const uint32_t block_size = decode_uint32_le_compat(size_buf);
        if (block_size == 0) break; /* end of data; the tail is either prealloc or a hole */

        const uint64_t total_block_size =
            BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
        if (scan_pos + total_block_size > file_size)
        {
            *corrupt = 1; /* declared size overruns the file */
            break;
        }

        unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
        const off_t block_footer_offset =
            (off_t)(scan_pos + total_block_size - BLOCK_MANAGER_FOOTER_SIZE);
        if (pread(bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, block_footer_offset) !=
            BLOCK_MANAGER_FOOTER_SIZE)
        {
            *corrupt = 1;
            break;
        }

        const uint32_t block_footer_size = decode_uint32_le_compat(footer_buf);
        const uint32_t block_footer_magic =
            decode_uint32_le_compat(footer_buf + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET);
        if (block_footer_magic != BLOCK_MANAGER_FOOTER_MAGIC || block_footer_size != block_size)
        {
            *corrupt = 1;
            break;
        }

        valid_size = scan_pos + total_block_size;
        scan_pos += total_block_size;
    }

    return valid_size;
}

/**
 * validate_recover_no_magic
 * recover a file whose last footer magic is missing, by forward-scanning to the true data extent
 * and deciding whether the trailing region is a legitimate preallocation tail or corruption
 * @param bm the block manager
 * @param file_size the on-disk file size
 * @param validation strict rejects any non-zero tail, permissive truncates the tail away
 * @return 0 when the file is left self-describing, -1 on corruption or an io error
 */
static int validate_recover_no_magic(block_manager_t *bm, uint64_t file_size,
                                     tidesdb_block_validation_mode_t validation)
{
    int hit_corruption = 0;
    const uint64_t valid_size = validate_scan_extent(bm, file_size, &hit_corruption);

    if (validation == BLOCK_MANAGER_STRICT_BLOCK_VALIDATION)
    {
        /* the trailing region must be all zeros to confirm it is preallocation tail rather than a
         * partial write; permissive mode truncates either way and so never needs this scan */
        const int trailing_zero =
            hit_corruption ? 0 : is_trailing_zero(bm->fd, valid_size, file_size);
        if (hit_corruption || trailing_zero != 1) return -1;
        /* preallocation tail is legitimate, so record the true extent without truncating */
        atomic_store(&bm->current_file_size, valid_size);
        return 0;
    }

    /* permissive mode truncates trailing garbage or preallocation tail so the file is always
     * self-describing on next open */
    if (valid_size != file_size)
    {
        /* trailing garbage and an unused preallocation tail are indistinguishable to a permissive
         * recovery, so say which one the scan thought it saw -- a corrupt tail is a torn write and
         * lost data, a clean one is only the file being right-sized */
        TDB_DEBUG_LOG(TDB_LOG_WARN, "block manager trimming %s from %llu to %llu bytes, %s",
                      bm->file_path, (unsigned long long)file_size, (unsigned long long)valid_size,
                      hit_corruption ? "the tail is corrupt" : "the tail is unwritten");
        if (ftruncate(bm->fd, (off_t)valid_size) != 0) return -1;
        if (bm_sync_after_truncate(bm) != 0) return -1;
        if (reopen_fd(bm) != 0) return -1;
        atomic_store(&bm->current_file_size, valid_size);
        atomic_store(&bm->preallocated_size, valid_size);
    }
    return 0;
}

/**
 * validate_tail_block
 * verify the last block when its footer magic is intact, checking the block fits and its header
 * size field matches the footer size field
 * @param bm the block manager
 * @param file_size the on-disk file size
 * @param footer_size the size field decoded from the last footer
 * @param validation strict rejects an ill-positioned block, permissive truncates to the header
 * @return 0 when the last block is valid, -1 on corruption or an io error
 */
static int validate_tail_block(block_manager_t *bm, uint64_t file_size, uint32_t footer_size,
                               tidesdb_block_validation_mode_t validation)
{
    const uint64_t min_required =
        (uint64_t)BLOCK_MANAGER_FOOTER_SIZE + footer_size + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (file_size < min_required + BLOCK_MANAGER_HEADER_SIZE)
    {
        if (validation == BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) return -1;
        return recover_truncate_to_header(bm, "the last block runs past the end of the file");
    }

    const uint64_t block_start = file_size - min_required;
    unsigned char header_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, header_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)block_start) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1; /* cannot read the block header, an io error in both modes */

    const uint32_t header_size = decode_uint32_le_compat(header_size_buf);
    if (header_size != footer_size) return -1; /* size mismatch, unrecoverable in both modes */

    return 0; /* the last block is valid, no truncation needed */
}

int block_manager_validate_last_block(block_manager_t *bm,
                                      const tidesdb_block_validation_mode_t validation)
{
    if (!bm) return -1;

    uint64_t file_size;
    if (get_file_size(bm->fd, &file_size) != 0) return -1;

    atomic_store(&bm->current_file_size, file_size);
    atomic_store(&bm->preallocated_size, file_size);

    /* an empty file just needs a fresh header */
    if (file_size == 0)
    {
        if (write_header(bm->fd) != 0) return -1;
        if (bm_sync_after_write(bm) != 0) return -1;
        return 0;
    }

    if (file_size == BLOCK_MANAGER_HEADER_SIZE) return 0; /* a valid header-only file */

    /* the file must hold at least the header plus one minimum block */
    const uint64_t min_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
    if (file_size < BLOCK_MANAGER_HEADER_SIZE + min_block_size)
    {
        if (validation == BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) return -1;
        return recover_truncate_to_header(bm, "the file is too small to hold one block");
    }

    /* O(1) validation reads the footer of the last block */
    unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
    const off_t footer_offset = (off_t)(file_size - BLOCK_MANAGER_FOOTER_SIZE);
    if (pread(bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, footer_offset) !=
        BLOCK_MANAGER_FOOTER_SIZE)
    {
        if (validation == BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) return -1;
        return recover_truncate_to_header(bm, "the last block footer could not be read");
    }

    const uint32_t footer_size = decode_uint32_le_compat(footer_buf);
    const uint32_t footer_magic =
        decode_uint32_le_compat(footer_buf + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET);

    if (footer_magic != BLOCK_MANAGER_FOOTER_MAGIC)
        return validate_recover_no_magic(bm, file_size, validation);
    return validate_tail_block(bm, file_size, footer_size, validation);
}
