/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "block_manager_internal.h"

/**
 * bm_read_size_field
 * read the 4-byte block size field at pos into *out, decoding it on a full read; returns the pread
 * byte count (BLOCK_MANAGER_SIZE_FIELD_SIZE on success, 0 at EOF, a short count on a partial read)
 * or -1 on an io error, leaving each caller to decide how to treat EOF and a zero size field
 * @param fd the file descriptor
 * @param pos the file offset of the size field
 * @param out receives the decoded size on a full read
 * @return the number of bytes read, or -1 on error
 */
static ssize_t bm_read_size_field(int fd, uint64_t pos, uint32_t *out)
{
    unsigned char buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    const ssize_t n = pread(fd, buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)pos);
    if (n == BLOCK_MANAGER_SIZE_FIELD_SIZE) *out = decode_uint32_le_compat(buf);
    return n;
}

int block_manager_cursor_init_stack(block_manager_cursor_t *cursor, block_manager_t *bm)
{
    if (!cursor || !bm) return -1;

    cursor->bm = bm;

    /* start at the position before the first block */
    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_size_valid = 0;

    /* position at first block so cursor_read works immediately. an empty file has none to go to,
     * and the cursor is left where a read reports that rather than being an error to hand back */
    (void)block_manager_cursor_goto_first(cursor);

    return 0;
}

int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm)
{
    if (!bm) return -1;

    (*cursor) = malloc(sizeof(block_manager_cursor_t));
    if (!(*cursor)) return -1;

    const int rc = block_manager_cursor_init_stack(*cursor, bm);
    if (rc == 0)
    {
        /* heap-allocated cursors are used for sequential iteration
         * hint the OS for read-ahead optimization */
        set_file_sequential_hint(bm->fd);
    }
    return rc;
}

int block_manager_cursor_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    uint32_t block_size;

    /* use cached block size if valid, otherwise read from disk */
    if (cursor->block_size_valid && cursor->current_block_size > 0)
    {
        block_size = (uint32_t)cursor->current_block_size;
    }
    else
    {
        const ssize_t nread = bm_read_size_field(cursor->bm->fd, cursor->current_pos, &block_size);
        if (nread != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        {
            if (nread == 0) return 1; /* EOF */
            return -1;
        }
        if (block_size == 0) return -1; /* invalid block */
    }

    /* next block starts after, [size][checksum][data][footer_size][footer_magic] */
    cursor->current_pos +=
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size + BLOCK_MANAGER_FOOTER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_size_valid = 0; /* invalidate cache after moving */

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    const uint64_t file_size = atomic_load(&cursor->bm->current_file_size);
    if (cursor->current_pos >= file_size) return 0; /* at or past EOF */

    /** use cached block size if valid */
    if (cursor->block_size_valid && cursor->current_block_size > 0)
    {
        return 1;
    }

    /* read current block size to check if current block is valid */
    uint32_t block_size;
    const ssize_t nread = bm_read_size_field(cursor->bm->fd, cursor->current_pos, &block_size);
    if (nread != BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        if (nread == 0) return 0; /* EOF */
        return -1;
    }
    if (block_size == 0) return -1; /* invalid block */

    /* cache the block size for subsequent cursor_next call */
    cursor->current_block_size = block_size;
    cursor->block_size_valid = 1;

    /* has_next returns 1 if cursor_next would succeed (can read current block and move forward) */
    return 1;
}

int block_manager_cursor_has_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    return (cursor->current_pos > BLOCK_MANAGER_HEADER_SIZE) ? 1 : 0;
}

int block_manager_cursor_skip_corrupt(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* read the size field from the current position */
    uint32_t block_size;
    if (bm_read_size_field(cursor->bm->fd, cursor->current_pos, &block_size) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        return -1;
    }
    if (block_size == 0) return -1; /* zero-filled hole extent unknown, cannot advance */

    /* read footer magic to distinguish partial write from genuine corruption.
     * the magic sits one size field into the footer, which starts after the payload */
    const off_t footer_magic_offset = (off_t)cursor->current_pos + BLOCK_MANAGER_BLOCK_HEADER_SIZE +
                                      (off_t)block_size + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET;
    unsigned char magic_buf[BLOCK_MANAGER_FOOTER_MAGIC_SIZE];
    const ssize_t nread =
        pread(cursor->bm->fd, magic_buf, BLOCK_MANAGER_FOOTER_MAGIC_SIZE, footer_magic_offset);
    if (nread != BLOCK_MANAGER_FOOTER_MAGIC_SIZE)
    {
        /* footer not present so file truncated mid-block; treat as partial write */
        cursor->current_pos +=
            BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size + BLOCK_MANAGER_FOOTER_SIZE;
        cursor->current_block_size = 0;
        cursor->block_size_valid = 0;
        return 0;
    }

    const uint32_t footer_magic = decode_uint32_le_compat(magic_buf);
    if (footer_magic == BLOCK_MANAGER_FOOTER_MAGIC)
    {
        return -1;
    }

    cursor->current_pos +=
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size + BLOCK_MANAGER_FOOTER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_size_valid = 0;
    return 0;
}

/**
 * bm_read_block_tls
 * reads a full block (header + payload) at `offset` into the thread-local buffer.
 * the first pread grabs the header plus a payload guess in one syscall; a block larger than the
 * guess pays one more pread for the remainder, so the guess costs only bandwidth when it is too big
 * and a whole syscall when it is too small. the checksum is verified before returning.
 * @param fd the file descriptor
 * @param offset the file offset of the block (start of header)
 * @param extent_limit if non-zero, reject a block whose frame extends past this
 *                     byte offset (guards against garbage sizes); 0 skips the check
 * @param payload_hint bytes of payload to fetch alongside the header, for a caller that already
 * knows the size; 0 or anything under the default asks for BM_READ_HINT_BYTES
 * @param out_size set to the payload size on success
 * @return pointer to the verified payload inside the TLS buffer, or NULL on failure
 */
uint8_t *bm_read_block_tls(const int fd, const uint64_t offset, const uint64_t extent_limit,
                           const uint32_t payload_hint, uint32_t *out_size)
{
    /* first pread -- header + a hint of payload in one syscall */
    const uint32_t hint = payload_hint > BM_READ_HINT_BYTES ? payload_hint : BM_READ_HINT_BYTES;
    uint8_t *buf = bm_get_read_buf(BLOCK_MANAGER_BLOCK_HEADER_SIZE + hint);
    if (BM_UNLIKELY(!buf)) return NULL;

    const ssize_t got = pread(fd, buf, BLOCK_MANAGER_BLOCK_HEADER_SIZE + hint, (off_t)offset);
    if (BM_UNLIKELY(got < (ssize_t)BLOCK_MANAGER_BLOCK_HEADER_SIZE)) return NULL;

    const uint32_t size = decode_uint32_le_compat(buf);
    if (BM_UNLIKELY(size == 0)) return NULL;
    const uint32_t checksum = decode_uint32_le_compat(buf + BLOCK_MANAGER_SIZE_FIELD_SIZE);

    /* a block claiming to extend past the data extent is garbage (off-boundary
     * read, torn write, corruption) -- reject before reading/allocating trash */
    if (extent_limit)
    {
        const uint64_t frame_end =
            offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)size + BLOCK_MANAGER_FOOTER_SIZE;
        if (BM_UNLIKELY(frame_end > extent_limit)) return NULL;
    }

    /* payload bytes already in buf (the first read may also have pulled the footer
     * and into the next block -- clamp to the real payload length) */
    uint32_t have = (uint32_t)got - BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (have > size) have = size;

    if (size > have)
    {
        /* grow the TLS buffer if needed -- realloc preserves the bytes already read */
        buf = bm_get_read_buf(BLOCK_MANAGER_BLOCK_HEADER_SIZE + size);
        if (BM_UNLIKELY(!buf)) return NULL;

        const off_t rem_offset = (off_t)offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE + have;
        if (BM_UNLIKELY(pread(fd, buf + BLOCK_MANAGER_BLOCK_HEADER_SIZE + have, size - have,
                              rem_offset) != (ssize_t)(size - have)))
            return NULL;
    }

    uint8_t *payload = buf + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (BM_UNLIKELY(verify_checksum(payload, size, checksum) != 0)) return NULL;

    *out_size = size;
    return payload;
}

/**
 * block_manager_read_block_at_offset
 * reads a block at a specific offset
 * @param bm the block manager
 * @param offset the offset to read from
 * @return the block if successful, NULL otherwise
 */
static block_manager_block_t *block_manager_read_block_at_offset(block_manager_t *bm,
                                                                 const uint64_t offset)
{
    if (BM_UNLIKELY(!bm)) return NULL;

    /* enforce the data extent so a garbage size cannot drive a read or an allocation past EOF; a
     * file_size of 0 means the size is not known here, and the check is skipped rather than
     * rejecting every read */
    const uint64_t file_size = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);

    uint32_t block_size = 0;
    uint8_t *payload = bm_read_block_tls(bm->fd, offset, file_size, 0, &block_size);
    if (BM_UNLIKELY(!payload)) return NULL;

    block_manager_block_t *block = malloc(sizeof(block_manager_block_t) + block_size);
    if (!block) return NULL;

    block->size = block_size;
    block->data = (uint8_t *)(block + 1);
    block->inline_data = 1;

    memcpy(block->data, payload, block_size);
    return block;
}

int block_manager_cursor_resync_past_hole(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* a reservation hole reads back as a zero size field. a nonzero size is either a real block or
     * genuine corruption block_manager_cursor_skip_corrupt already stopped on, so leave it alone.
     */
    uint32_t hole_size;
    if (bm_read_size_field(cursor->bm->fd, cursor->current_pos, &hole_size) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    if (hole_size != 0) return -1;

    const uint64_t extent =
        atomic_load_explicit(&cursor->bm->current_file_size, memory_order_acquire);

    unsigned char magic[BLOCK_MANAGER_FOOTER_MAGIC_SIZE];
    encode_uint32_le_compat(magic, BLOCK_MANAGER_FOOTER_MAGIC);

    /* small on-stack scan window -- a big buffer is risky on platforms with small thread stacks and
     * the loop re-reads, so it buys nothing. windows overlap by the magic length minus one so a
     * magic straddling a window boundary is still found. */
    enum
    {
        BM_RESYNC_CHUNK = 8 * 1024
    };
    unsigned char buf[BM_RESYNC_CHUNK];

    /* a footer magic at absolute offset m ends the block whose footer_size sits at m minus the size
     * field and whose start is one header, its data, and one footer before the end of the magic.
     * every candidate is validated by re-reading the framed block, so a magic-shaped byte run in a
     * value cannot fool the resync, and a zero region holds no magic and resolves to end of data.
     */
    uint64_t pos = cursor->current_pos;
    while (pos + BLOCK_MANAGER_FOOTER_SIZE <= extent)
    {
        size_t want = BM_RESYNC_CHUNK;
        if ((uint64_t)want > extent - pos) want = (size_t)(extent - pos);

        const ssize_t got = pread(cursor->bm->fd, buf, want, (off_t)pos);
        if (got < (ssize_t)BLOCK_MANAGER_FOOTER_MAGIC_SIZE) break;

        for (ssize_t i = 0; i + (ssize_t)BLOCK_MANAGER_FOOTER_MAGIC_SIZE <= got; i++)
        {
            if (buf[i] != magic[0] || memcmp(buf + i, magic, BLOCK_MANAGER_FOOTER_MAGIC_SIZE) != 0)
                continue;

            const uint64_t abs_magic = pos + (uint64_t)i;
            if (abs_magic < BLOCK_MANAGER_SIZE_FIELD_SIZE) continue;

            uint32_t fsize;
            if (bm_read_size_field(cursor->bm->fd, abs_magic - BLOCK_MANAGER_SIZE_FIELD_SIZE,
                                   &fsize) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
                continue;
            if (fsize == 0) continue;

            const uint64_t frame =
                BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)fsize + BLOCK_MANAGER_FOOTER_SIZE;
            const uint64_t magic_end = abs_magic + BLOCK_MANAGER_FOOTER_MAGIC_SIZE;
            if (magic_end < frame) continue;
            const uint64_t block_start = magic_end - frame;
            if (block_start < cursor->current_pos) continue;

            /* validate the whole frame by re-reading it -- the checksum inside bm_read_block_tls is
             * the gate that rejects a false-positive magic */
            uint32_t validated_size = 0;
            if (bm_read_block_tls(cursor->bm->fd, block_start, extent, 0, &validated_size) &&
                validated_size == fsize)
            {
                cursor->current_pos = block_start;
                cursor->current_block_size = 0;
                cursor->block_size_valid = 0;
                return 0;
            }
        }

        if ((uint64_t)got < want) break; /* short read means end of file reached */
        pos += (uint64_t)got - (BLOCK_MANAGER_FOOTER_MAGIC_SIZE - 1);
    }

    return -1;
}

block_manager_block_t *block_manager_cursor_read(block_manager_cursor_t *cursor)
{
    if (!cursor) return NULL;

    block_manager_block_t *block =
        block_manager_read_block_at_offset(cursor->bm, cursor->current_pos);
    if (block)
    {
        /* cache block size so cursor_next skips the pread for size header */
        cursor->current_block_size = block->size;
        cursor->block_size_valid = 1;
    }
    return block;
}

block_manager_block_t *block_manager_cursor_read_and_advance(block_manager_cursor_t *cursor)
{
    if (!cursor) return NULL;

    block_manager_block_t *block =
        block_manager_read_block_at_offset(cursor->bm, cursor->current_pos);
    if (!block) return NULL;

    /* advance cursor using the block size just read, avoiding redundant pread */
    cursor->current_pos +=
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block->size + BLOCK_MANAGER_FOOTER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_size_valid = 0; /* invalidate cache -- moved to a new position */

    return block;
}

void block_manager_cursor_free(block_manager_cursor_t *cursor)
{
    if (cursor)
    {
        free(cursor);
    }
}

int block_manager_cursor_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* already at first block position, cannot go back */
    if (cursor->current_pos <= BLOCK_MANAGER_HEADER_SIZE) return -1;

    const uint64_t prev_footer_end = cursor->current_pos;
    if (prev_footer_end <
        BLOCK_MANAGER_HEADER_SIZE + BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE)
    {
        return -1; /* not enough space for a valid previous block */
    }

    unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
    const off_t footer_offset = (off_t)(prev_footer_end - BLOCK_MANAGER_FOOTER_SIZE);
    if (pread(cursor->bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, footer_offset) !=
        BLOCK_MANAGER_FOOTER_SIZE)
    {
        return -1;
    }

    const uint32_t prev_block_size = decode_uint32_le_compat(footer_buf);
    const uint32_t footer_magic =
        decode_uint32_le_compat(footer_buf + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET);

    /* validate footer magic */
    if (footer_magic != BLOCK_MANAGER_FOOTER_MAGIC || prev_block_size == 0)
    {
        return -1;
    }

    /* calculate start of previous block */
    const uint64_t prev_total_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + prev_block_size + BLOCK_MANAGER_FOOTER_SIZE;
    if (cursor->current_pos < prev_total_size)
    {
        return -1; /* invalid -- would underflow */
    }

    const uint64_t prev_block_start = cursor->current_pos - prev_total_size;
    if (prev_block_start < BLOCK_MANAGER_HEADER_SIZE)
    {
        return -1; /* invalid -- before file header */
    }

    cursor->current_pos = prev_block_start;
    cursor->current_block_size = prev_block_size;
    cursor->block_size_valid = 1; /* size known from footer */

    return 0;
}

int block_manager_cursor_goto_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_size_valid = 0;

    return 0;
}

int block_manager_cursor_goto_last_before(block_manager_cursor_t *cursor, const uint64_t end_offset)
{
    if (!cursor) return -1;

    if (end_offset <= BLOCK_MANAGER_HEADER_SIZE)
    {
        return -1;
    }

    /* read footer of last block to get its size */
    unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
    const off_t footer_offset = (off_t)(end_offset - BLOCK_MANAGER_FOOTER_SIZE);
    const ssize_t n = pread(cursor->bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, footer_offset);

    if (n != BLOCK_MANAGER_FOOTER_SIZE)
    {
        return -1;
    }

    const uint32_t block_size = decode_uint32_le_compat(footer_buf);
    const uint32_t footer_magic =
        decode_uint32_le_compat(footer_buf + BLOCK_MANAGER_FOOTER_MAGIC_OFFSET);

    /* verify footer magic */
    if (footer_magic != BLOCK_MANAGER_FOOTER_MAGIC || block_size == 0)
    {
        return -1;
    }

    /* calculate start position of last block */
    const uint64_t total_block_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
    if (end_offset < total_block_size)
    {
        return -1;
    }

    cursor->current_pos = end_offset - total_block_size;
    cursor->current_block_size = block_size;
    cursor->block_size_valid = 1; /* size known from footer */

    return 0;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* O(1) seek to end and work backwards using footer */
    const uint64_t file_size = atomic_load(&cursor->bm->current_file_size);
    return block_manager_cursor_goto_last_before(cursor, file_size);
}

int block_manager_cursor_at_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;
    return (cursor->current_pos == BLOCK_MANAGER_HEADER_SIZE) ? 1 : 0;
}

int block_manager_cursor_at_second(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if at first block, not at second */
    if (cursor->current_pos == BLOCK_MANAGER_HEADER_SIZE) return 0;

    /* read first block size */
    uint32_t first_block_size;
    if (bm_read_size_field(cursor->bm->fd, BLOCK_MANAGER_HEADER_SIZE, &first_block_size) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    if (first_block_size == 0) return -1;

    /* calculate second block position, first_block_pos + [size][checksum][data][footer] */
    const uint64_t first_total_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)first_block_size + BLOCK_MANAGER_FOOTER_SIZE;
    const uint64_t second_block_pos = BLOCK_MANAGER_HEADER_SIZE + first_total_size;

    return (cursor->current_pos == second_block_pos) ? 1 : 0;
}

int block_manager_cursor_at_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* use cached block size to avoid pread syscall when possible */
    uint32_t block_size;
    if (cursor->block_size_valid && cursor->current_block_size > 0)
    {
        block_size = (uint32_t)cursor->current_block_size;
    }
    else
    {
        if (bm_read_size_field(cursor->bm->fd, cursor->current_pos, &block_size) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        if (block_size == 0) return -1;
    }

    /* calculate position after current block, [size][checksum][data][footer] */
    const uint64_t total_block_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
    const uint64_t next_block_pos = cursor->current_pos + total_block_size;

    /* check against cached file size, no room after this block means at last */
    const uint64_t file_size = atomic_load(&cursor->bm->current_file_size);
    return (next_block_pos >= file_size) ? 1 : 0;
}

int block_manager_cursor_goto(block_manager_cursor_t *cursor, const uint64_t pos)
{
    if (!cursor) return -1;

    cursor->current_pos = pos;
    cursor->block_size_valid = 0; /* invalidate cache when jumping to arbitrary position */
    return 0;
}

int block_manager_get_block_size_at_offset(block_manager_t *bm, const uint64_t offset,
                                           uint32_t *size)
{
    if (!bm || !size) return -1;

    /* read the size field from block header */
    if (bm_read_size_field(bm->fd, offset, size) != BLOCK_MANAGER_SIZE_FIELD_SIZE) return -1;
    if (*size == 0) return -1; /* invalid block */

    return 0;
}

int block_manager_read_at_offset(block_manager_t *bm, const uint64_t offset, const size_t size,
                                 uint8_t *data)
{
    if (!bm || !data || size == 0) return -1;

    /* a simple pread at the specified offset */
    const ssize_t nread = pread(bm->fd, data, size, (off_t)offset);
    if (nread != (ssize_t)size)
    {
        return -1;
    }

    return 0;
}

int block_manager_read_block_data_at_offset(block_manager_t *bm, const uint64_t offset,
                                            uint8_t **data, uint32_t *data_size)
{
    if (!bm || !data || !data_size) return -1;

    /* the offset arrives from a value-log id the caller resolved out of klog bytes, so it is only
     * as trustworthy as the file it was read from. the checksum inside the helper rejects a corrupt
     * block, but it can only do so after the declared size has been believed once -- four garbage
     * bytes would otherwise buy a four gigabyte buffer before anything checks them. bounding the
     * frame by the file puts the guard ahead of the allocation, and the checksum then rejects what
     * survives it */
    const uint64_t extent = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);
    uint32_t block_size = 0;
    uint8_t *payload = bm_read_block_tls(bm->fd, offset, extent, 0, &block_size);
    if (BM_UNLIKELY(!payload)) return -1;

    uint8_t *block_data = malloc(block_size);
    if (BM_UNLIKELY(!block_data)) return -1;

    memcpy(block_data, payload, block_size);
    *data = block_data;
    *data_size = block_size;
    return 0;
}

const uint8_t *block_manager_borrow_block_data_at_offset(block_manager_t *bm, const uint64_t offset,
                                                         const uint32_t payload_hint,
                                                         uint32_t *data_size)
{
    if (!bm || !data_size) return NULL;

    /* the same untrusted-offset reasoning as the owning read above applies -- the frame is bounded
     * by the file before anything sizes a buffer from it */
    const uint64_t extent = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);
    return bm_read_block_tls(bm->fd, offset, extent, payload_hint, data_size);
}
