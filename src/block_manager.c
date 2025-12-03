/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "block_manager.h"

#include "lru.h"
#include "xxhash.h"

/**
 *
 * file format *
 *
 * HEADER *
 * magic (3 bytes) 0x544442 "TDB"
 * version (1 byte) 5
 * block_size (4 bytes) default block size
 * padding (4 bytes) reserved
 *
 * BLOCKS *
 * block_size (8 bytes)
 * checksum (8 bytes) xxHash64 of data
 * data (variable size)
 * overflow_offset (8 bytes) 0 if no overflow, otherwise offset to next overflow block
 *
 * CONCURRENCY MODEL *
 * single file descriptor shared by all operations
 * pread/pwrite for lock-free reads (readers don't block readers or writers)
 * atomic offset allocation for lock-free writes
 * writers don't block writers, concurrent writes to different offsets
 * readers never block, they can read while writes happen
 *
 * REFERENCE COUNTING *
 * blocks use atomic reference counting for safe concurrent access
 * blocks start with ref_count=1 when created
 * callers must call block_manager_block_release when done
 * blocks are freed when ref_count reaches 0
 * block_manager_block_acquire/release provide thread-safe ref management
 * global block cache in tidesdb.c uses these functions for safe sharing
 */

/**
 * compute_checksum
 * compute xxHash64 checksum
 * @param data the data to compute the checksum for
 * @param size the size of the data
 * @return the 64-bit checksum
 */
static inline uint64_t compute_checksum(const void *data, size_t size)
{
    return XXH64(data, size, 0);
}

/**
 * verify_checksum
 * verify xxHash64 checksum
 * @param data the data to verify the checksum for
 * @param size the size of the data
 * @param expected_checksum the expected checksum
 * @return 0 if the checksum matches, -1 otherwise
 */
static inline int verify_checksum(const void *data, size_t size, uint64_t expected_checksum)
{
    uint64_t computed = compute_checksum(data, size);
    return (computed == expected_checksum) ? 0 : -1;
}

/**
 * write_header
 * write file header using pwrite
 * @param fd the file descriptor to write to
 * @param block_size the block size to write
 * @return 0 if successful, -1 otherwise
 */
static int write_header(int fd, uint32_t block_size)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];
    uint32_t magic = BLOCK_MANAGER_MAGIC;
    uint8_t version = BLOCK_MANAGER_VERSION;
    uint32_t padding = 0;

    encode_uint32_le_compat(header, magic);
    header[BLOCK_MANAGER_MAGIC_SIZE] = version;
    encode_uint32_le_compat(header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE,
                            block_size);
    encode_uint32_le_compat(header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE +
                                BLOCK_MANAGER_BLOCK_SIZE_SIZE,
                            padding);

    ssize_t written = pwrite(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    return (written == BLOCK_MANAGER_HEADER_SIZE) ? 0 : -1;
}

/**
 * read_header
 * read and validate file header using pread
 * @param fd the file descriptor to read from
 * @param block_size the block size to read
 * @return 0 if successful, -1 otherwise
 */
static int read_header(int fd, uint32_t *block_size)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];

    ssize_t nread = pread(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    if (nread != BLOCK_MANAGER_HEADER_SIZE) return -1;

    uint32_t magic;
    memcpy(&magic, header, BLOCK_MANAGER_MAGIC_SIZE);
    magic &= BLOCK_MANAGER_MAGIC_MASK;

    if (magic != BLOCK_MANAGER_MAGIC) return -1;

    uint8_t version;
    memcpy(&version, header + BLOCK_MANAGER_MAGIC_SIZE, BLOCK_MANAGER_VERSION_SIZE);
    if (version != BLOCK_MANAGER_VERSION) return -1;

    memcpy(block_size, header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE,
           BLOCK_MANAGER_BLOCK_SIZE_SIZE);

    return 0;
}

/**
 * get_file_size
 * get file size using fstat
 * @param fd the file descriptor to get the size of
 * @param size the size to store the result in
 * @return 0 if successful, -1 otherwise
 */
static int get_file_size(int fd, uint64_t *size)
{
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(fd, &st) != 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

/**
 * block_manager_open_internal
 * opens a block manager (no cache)
 * @param bm the block manager to open
 * @param file_path the path of the file
 * @param sync_mode the sync mode (TDB_SYNC_NONE, TDB_SYNC_FULL)
 * @return 0 if successful, -1 if not
 */
static int block_manager_open_internal(block_manager_t **bm, const char *file_path,
                                       block_manager_sync_mode_t sync_mode)
{
    block_manager_t *new_bm = malloc(sizeof(block_manager_t));
    if (!new_bm)
    {
        *bm = NULL;
        return -1;
    }

    int file_exists = access(file_path, F_OK) == 0;

    int flags = O_RDWR | O_CREAT;
    mode_t mode = BLOCK_MANAGER_FILE_MODE;

    new_bm->fd = open(file_path, flags, mode);
    if (new_bm->fd == -1)
    {
        free(new_bm);
        *bm = NULL;
        return -1;
    }

    strncpy(new_bm->file_path, file_path, MAX_FILE_PATH_LENGTH - 1);
    new_bm->file_path[MAX_FILE_PATH_LENGTH - 1] = '\0';

    new_bm->sync_mode = sync_mode;

    if (file_exists)
    {
        if (read_header(new_bm->fd, &new_bm->block_size) != 0)
        {
            close(new_bm->fd);
            free(new_bm);
            *bm = NULL;
            return -1;
        }

        int validation_result = block_manager_validate_last_block(new_bm);
        if (validation_result != 0)
        {
            close(new_bm->fd);
            free(new_bm);
            *bm = NULL;
            return -1;
        }
    }
    else
    {
        new_bm->block_size = MAX_INLINE_BLOCK_SIZE;
        if (write_header(new_bm->fd, new_bm->block_size) != 0)
        {
            close(new_bm->fd);
            free(new_bm);
            *bm = NULL;
            return -1;
        }
        if (new_bm->sync_mode == BLOCK_MANAGER_SYNC_FULL)
        {
            if (fdatasync(new_bm->fd) != 0)
            {
                close(new_bm->fd);
                free(new_bm);
                *bm = NULL;
                return -1;
            }
        }
    }

    uint64_t file_size = 0;
    if (get_file_size(new_bm->fd, &file_size) == 0)
    {
        new_bm->current_file_size = file_size;
    }
    else
    {
        /* if we can't get size, use lseek to get current position (end of file) */
        off_t pos = lseek(new_bm->fd, 0, SEEK_END);
        new_bm->current_file_size = (pos >= 0) ? (uint64_t)pos : 0;
    }

    *bm = new_bm;
    return 0;
}

int block_manager_close(block_manager_t *bm)
{
    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL)
    {
        (void)fdatasync(bm->fd);
    }

    if (close(bm->fd) != 0) return -1;

    free(bm);
    bm = NULL;

    return 0;
}

block_manager_block_t *block_manager_block_create(uint64_t size, void *data)
{
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;
    atomic_init(&block->ref_count, 1);

    block->data = malloc(size);
    if (!block->data)
    {
        free(block);
        block = NULL;
        return NULL;
    }

    /* only copy if size > 0 and data is not NULL */
    if (size > 0 && data != NULL)
    {
        memcpy(block->data, data, size);
    }
    return block;
}

block_manager_block_t *block_manager_block_create_from_buffer(uint64_t size, void *data)
{
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;
    block->data = data;
    atomic_init(&block->ref_count, 1);
    return block;
}

int64_t block_manager_block_write(block_manager_t *bm, block_manager_block_t *block)
{
    uint64_t inline_size = block->size <= bm->block_size ? block->size : bm->block_size;
    uint64_t remaining = block->size > bm->block_size ? block->size - bm->block_size : 0;

    size_t main_block_total_size = BLOCK_MANAGER_SIZE_FIELD_SIZE + BLOCK_MANAGER_CHECKSUM_LENGTH +
                                   inline_size + BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE;

    uint64_t total_bytes_needed = main_block_total_size;
    uint64_t temp_remaining = remaining;
    while (temp_remaining > 0)
    {
        uint64_t chunk = temp_remaining <= bm->block_size ? temp_remaining : bm->block_size;
        total_bytes_needed += BLOCK_MANAGER_SIZE_FIELD_SIZE + BLOCK_MANAGER_CHECKSUM_LENGTH +
                              chunk + BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE;
        temp_remaining -= chunk;
    }

    int64_t offset = (int64_t)atomic_fetch_add(&bm->current_file_size, total_bytes_needed);

    uint64_t checksum = compute_checksum(block->data, block->size);

    unsigned char stack_buffer[MAX_INLINE_BLOCK_SIZE + BLOCK_MANAGER_STACK_BUFFER_OVERHEAD];
    unsigned char *main_block_buffer;
    int use_stack = (main_block_total_size <= sizeof(stack_buffer));

    if (use_stack)
    {
        main_block_buffer = stack_buffer;
    }
    else
    {
        main_block_buffer = malloc(main_block_total_size);
        if (!main_block_buffer)
        {
            return -1;
        }
    }

    size_t buf_offset = 0;

    encode_uint64_le_compat(main_block_buffer + buf_offset, block->size);
    buf_offset += BLOCK_MANAGER_SIZE_FIELD_SIZE;

    encode_uint64_le_compat(main_block_buffer + buf_offset, checksum);
    buf_offset += BLOCK_MANAGER_CHECKSUM_LENGTH;

    memcpy(main_block_buffer + buf_offset, block->data, inline_size);
    buf_offset += inline_size;

    uint64_t overflow_offset = 0;
    encode_uint64_le_compat(main_block_buffer + buf_offset, overflow_offset);

    ssize_t written = pwrite(bm->fd, main_block_buffer, main_block_total_size, offset);
    if (!use_stack) free(main_block_buffer);

    if (written != (ssize_t)main_block_total_size)
    {
        return -1;
    }

    if (remaining > 0)
    {
        uint64_t overflow_link_pos = (uint64_t)offset + BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                     BLOCK_MANAGER_CHECKSUM_LENGTH + inline_size;
        uint64_t data_offset = inline_size;
        uint64_t current_write_pos = (uint64_t)offset + main_block_total_size;

        while (remaining > 0)
        {
            uint64_t chunk_size = remaining <= bm->block_size ? remaining : bm->block_size;

            uint64_t chunk_checksum =
                compute_checksum((unsigned char *)block->data + data_offset, chunk_size);

            size_t overflow_block_size = BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                         BLOCK_MANAGER_CHECKSUM_LENGTH + chunk_size +
                                         BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE;

            unsigned char overflow_stack[MAX_INLINE_BLOCK_SIZE + 64];
            unsigned char *overflow_buffer;
            int use_overflow_stack = (overflow_block_size <= sizeof(overflow_stack));

            if (use_overflow_stack)
            {
                overflow_buffer = overflow_stack;
            }
            else
            {
                overflow_buffer = malloc(overflow_block_size);
                if (!overflow_buffer)
                {
                    return -1;
                }
            }

            size_t obuf_offset = 0;

            encode_uint64_le_compat(overflow_buffer + obuf_offset, chunk_size);
            obuf_offset += BLOCK_MANAGER_SIZE_FIELD_SIZE;

            encode_uint64_le_compat(overflow_buffer + obuf_offset, chunk_checksum);
            obuf_offset += BLOCK_MANAGER_CHECKSUM_LENGTH;

            memcpy(overflow_buffer + obuf_offset, (unsigned char *)block->data + data_offset,
                   chunk_size);
            obuf_offset += chunk_size;

            /* next overflow offset (0 if last) */
            uint64_t next_overflow =
                (remaining - chunk_size > 0) ? (current_write_pos + overflow_block_size) : 0;
            encode_uint64_le_compat(overflow_buffer + obuf_offset, next_overflow);

            /* write overflow link pointer */
            unsigned char link_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
            encode_uint64_le_compat(link_buf, current_write_pos);
            if (pwrite(bm->fd, link_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                       (off_t)overflow_link_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            {
                if (!use_overflow_stack) free(overflow_buffer);
                return -1;
            }

            if (pwrite(bm->fd, overflow_buffer, overflow_block_size, (off_t)current_write_pos) !=
                (ssize_t)overflow_block_size)
            {
                if (!use_overflow_stack) free(overflow_buffer);
                return -1;
            }

            if (!use_overflow_stack) free(overflow_buffer);

            /* update for next iteration */
            overflow_link_pos = current_write_pos + BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                BLOCK_MANAGER_CHECKSUM_LENGTH + chunk_size;
            data_offset += chunk_size;
            remaining -= chunk_size;
            current_write_pos += overflow_block_size;
        }
    }

    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL)
    {
        if (fdatasync(bm->fd) != 0)
        {
            return -1;
        }
    }

    return offset;
}

void block_manager_block_free(block_manager_block_t *block)
{
    if (!block) return;

    if (block->data) free(block->data);
    free(block);
}

int block_manager_block_acquire(block_manager_block_t *block)
{
    if (!block) return 0;

    uint32_t old_ref = atomic_load_explicit(&block->ref_count, memory_order_relaxed);
    do
    {
        if (old_ref == 0) return 0; /* block is being freed */
    } while (!atomic_compare_exchange_weak_explicit(&block->ref_count, &old_ref, old_ref + 1,
                                                    memory_order_acquire, memory_order_relaxed));
    return 1;
}

void block_manager_block_release(block_manager_block_t *block)
{
    if (!block) return;

    uint32_t old_ref = atomic_fetch_sub_explicit(&block->ref_count, 1, memory_order_release);
    if (old_ref == 1)
    {
        /* we were the last reference, free the block */
        atomic_thread_fence(memory_order_acquire);
        block_manager_block_free(block);
    }
}

int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm)
{
    if (!bm) return -1;

    (*cursor) = malloc(sizeof(block_manager_cursor_t));
    if (!(*cursor)) return -1;

    (*cursor)->bm = bm;

    /* initialize to position after header */
    (*cursor)->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    (*cursor)->current_block_size = 0;

    /* initialize position cache */
    (*cursor)->position_cache = NULL;
    (*cursor)->size_cache = NULL;
    (*cursor)->cache_capacity = 0;
    (*cursor)->cache_size = 0;
    (*cursor)->cache_index = -1; /* -1 means cache not built */

    /* hint to OS that we'll be reading sequentially */
    set_file_sequential_hint(bm->fd);

    return 0;
}

int block_manager_cursor_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    ssize_t nread =
        pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)cursor->current_pos);
    if (nread != BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        if (nread == 0) return 1; /* EOF */
        return -1;
    }
    uint64_t block_size = decode_uint64_le_compat(size_buf);

    uint64_t inline_size =
        block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

    off_t overflow_offset_pos = (off_t)cursor->current_pos + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)inline_size;

    unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
    if (pread(cursor->bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
              (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
        return -1;
    uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

    /* if no overflow, next block starts immediately after this one */
    if (overflow_offset == 0)
    {
        cursor->current_pos =
            (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
        cursor->current_block_size = block_size;
        return 0;
    }

    /* skip overflow chain to find end */
    uint64_t last_overflow_pos =
        (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
    while (overflow_offset != 0)
    {
        off_t chunk_offset = (off_t)overflow_offset;

        unsigned char chunk_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(cursor->bm->fd, chunk_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                  (off_t)chunk_offset) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        uint64_t chunk_size = decode_uint64_le_compat(chunk_size_buf);

        off_t next_overflow_pos = chunk_offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                  (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)chunk_size;

        unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(cursor->bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            return -1;
        overflow_offset = decode_uint64_le_compat(next_overflow_buf);

        last_overflow_pos =
            (uint64_t)(next_overflow_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
    }

    /* update cursor position to after last overflow block */
    cursor->current_pos = last_overflow_pos;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* save current state */
    uint64_t saved_cursor_pos = cursor->current_pos;
    uint64_t saved_block_size = cursor->current_block_size;

    int result = block_manager_cursor_next(cursor);

    /* restore cursor state */
    cursor->current_pos = saved_cursor_pos;
    cursor->current_block_size = saved_block_size;

    if (result == 0) return 1; /* has next */
    if (result == 1) return 0; /* EOF */
    return -1;                 /* error */
}

int block_manager_cursor_has_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;
    return (cursor->current_pos > BLOCK_MANAGER_HEADER_SIZE) ? 1 : 0;
}

/**
 * block_manager_read_block_at_offset
 * reads a block at a specific offset, checking cache first
 * @param bm the block manager
 * @param offset the offset to read from
 * @return the block if successful, NULL otherwise
 */
static block_manager_block_t *block_manager_read_block_at_offset(block_manager_t *bm,
                                                                 uint64_t offset)
{
    if (!bm) return NULL;

    block_manager_block_t *block = NULL;

    /* read block size with little-endian decoding */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)offset) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return NULL;
    uint64_t block_size = decode_uint64_le_compat(size_buf);

    if (block_size == 0) return NULL;

    /* read checksum with little-endian decoding */
    unsigned char checksum_buf[BLOCK_MANAGER_CHECKSUM_LENGTH];
    off_t checksum_pos = (off_t)offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE;
    if (pread(bm->fd, checksum_buf, BLOCK_MANAGER_CHECKSUM_LENGTH, (off_t)checksum_pos) !=
        BLOCK_MANAGER_CHECKSUM_LENGTH)
        return NULL;
    uint64_t checksum = decode_uint64_le_compat(checksum_buf);

    block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = block_size;
    atomic_init(&block->ref_count, 1); /* initial reference for caller */
    block->data = malloc(block_size);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    uint64_t inline_size = block_size <= bm->block_size ? block_size : bm->block_size;
    off_t data_pos =
        (off_t)offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE + (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH;

    if (pread(bm->fd, block->data, inline_size, (off_t)data_pos) != (ssize_t)inline_size)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    off_t overflow_offset_pos = data_pos + (off_t)inline_size;
    unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
    if (pread(bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
              (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
    {
        free(block->data);
        free(block);
        return NULL;
    }
    uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

    uint64_t data_offset = inline_size;
    while (overflow_offset != 0)
    {
        unsigned char chunk_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(bm->fd, chunk_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)overflow_offset) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
        {
            free(block->data);
            free(block);
            return NULL;
        }
        uint64_t chunk_size = decode_uint64_le_compat(chunk_size_buf);

        if (chunk_size == 0)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        unsigned char chunk_checksum_buf[BLOCK_MANAGER_CHECKSUM_LENGTH];
        off_t chunk_checksum_pos = (off_t)overflow_offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE;
        if (pread(bm->fd, chunk_checksum_buf, BLOCK_MANAGER_CHECKSUM_LENGTH,
                  (off_t)chunk_checksum_pos) != BLOCK_MANAGER_CHECKSUM_LENGTH)
        {
            free(block->data);
            free(block);
            return NULL;
        }
        uint64_t chunk_checksum = decode_uint64_le_compat(chunk_checksum_buf);

        off_t chunk_data_pos = chunk_checksum_pos + (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH;
        if (pread(bm->fd, (unsigned char *)block->data + data_offset, chunk_size,
                  (off_t)chunk_data_pos) != (ssize_t)chunk_size)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        if (verify_checksum((unsigned char *)block->data + data_offset, chunk_size,
                            chunk_checksum) != 0)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        off_t next_overflow_pos = chunk_data_pos + (off_t)chunk_size;
        unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
        {
            free(block->data);
            free(block);
            return NULL;
        }
        overflow_offset = decode_uint64_le_compat(next_overflow_buf);

        data_offset += chunk_size;
    }

    /* verify main block checksum */
    if (verify_checksum(block->data, block_size, checksum) != 0)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* return block to caller (caller has initial reference) */
    return block;
}

block_manager_block_t *block_manager_cursor_read(block_manager_cursor_t *cursor)
{
    if (!cursor) return NULL;

    return block_manager_read_block_at_offset(cursor->bm, cursor->current_pos);
}

block_manager_block_t *block_manager_cursor_read_partial(block_manager_cursor_t *cursor,
                                                         size_t max_bytes)
{
    if (!cursor) return NULL;
    if (max_bytes == 0) return block_manager_cursor_read(cursor);

    block_manager_t *bm = cursor->bm;
    uint64_t offset = cursor->current_pos;

    /* read block size */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)offset) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return NULL;
    uint64_t block_size = decode_uint64_le_compat(size_buf);

    if (block_size == 0) return NULL;

    /* if block is smaller than max_bytes, read full block */
    if (block_size <= max_bytes)
    {
        return block_manager_read_block_at_offset(bm, offset);
    }

    /* read checksum */
    unsigned char checksum_buf[BLOCK_MANAGER_CHECKSUM_LENGTH];
    off_t checksum_pos = (off_t)offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE;
    if (pread(bm->fd, checksum_buf, BLOCK_MANAGER_CHECKSUM_LENGTH, checksum_pos) !=
        BLOCK_MANAGER_CHECKSUM_LENGTH)
        return NULL;

    /* allocate partial block */
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = max_bytes;
    atomic_init(&block->ref_count, 1);
    block->data = malloc(max_bytes);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    /* read only first max_bytes of data */
    off_t data_pos = checksum_pos + (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH;
    size_t bytes_to_read = max_bytes <= bm->block_size ? max_bytes : bm->block_size;

    if (pread(bm->fd, block->data, bytes_to_read, data_pos) != (ssize_t)bytes_to_read)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* if we need more bytes and they're in overflow, read from overflow */
    if (max_bytes > bm->block_size)
    {
        off_t overflow_offset_pos = data_pos + (off_t)bm->block_size;
        unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE, overflow_offset_pos) !=
            BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
        {
            free(block->data);
            free(block);
            return NULL;
        }
        uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

        size_t data_offset = bm->block_size;
        while (overflow_offset != 0 && data_offset < max_bytes)
        {
            /* skip chunk size and checksum, read data */
            off_t chunk_data_pos = (off_t)overflow_offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                   (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH;
            size_t remaining = max_bytes - data_offset;
            size_t chunk_read = remaining <= bm->block_size ? remaining : bm->block_size;

            if (pread(bm->fd, (unsigned char *)block->data + data_offset, chunk_read,
                      chunk_data_pos) != (ssize_t)chunk_read)
            {
                free(block->data);
                free(block);
                return NULL;
            }

            data_offset += chunk_read;
            if (data_offset >= max_bytes) break;

            /* read next overflow offset */
            off_t next_overflow_pos = chunk_data_pos + (off_t)bm->block_size;
            unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
            if (pread(bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                      next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            {
                free(block->data);
                free(block);
                return NULL;
            }
            overflow_offset = decode_uint64_le_compat(next_overflow_buf);
        }
    }

    /* we don't verify checksum for partial reads since we don't have full data */
    return block;
}

void block_manager_cursor_free(block_manager_cursor_t *cursor)
{
    if (cursor)
    {
        if (cursor->position_cache) free(cursor->position_cache);
        if (cursor->size_cache) free(cursor->size_cache);
        free(cursor);
        cursor = NULL;
    }
}

int block_manager_cursor_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* can't go back from first block */
    if (cursor->current_pos <= BLOCK_MANAGER_HEADER_SIZE) return -1;

    /* if cache is built and we're using it, just decrement index */
    if (cursor->cache_index >= 0)
    {
        if (cursor->cache_index == 0) return -1; /* already at first */
        cursor->cache_index--;
        cursor->current_pos = cursor->position_cache[cursor->cache_index];
        cursor->current_block_size = cursor->size_cache[cursor->cache_index];
        return 0;
    }

    /* cache not built - use old O(n) method to find previous block */
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < cursor->current_pos)
    {
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        uint64_t block_size = decode_uint64_le_compat(size_buf);

        uint64_t inline_size =
            block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

        off_t overflow_offset_pos = (off_t)scan_pos + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                    (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)inline_size;
        unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(cursor->bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            return -1;
        uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

        uint64_t next_pos =
            (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);

        while (overflow_offset != 0)
        {
            unsigned char chunk_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
            if (pread(cursor->bm->fd, chunk_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                      (off_t)overflow_offset) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
                return -1;
            uint64_t chunk_size = decode_uint64_le_compat(chunk_size_buf);

            off_t next_overflow_pos = (off_t)overflow_offset +
                                      (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                      (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)chunk_size;
            unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
            if (pread(cursor->bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                      (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
                return -1;
            overflow_offset = decode_uint64_le_compat(next_overflow_buf);

            next_pos = (uint64_t)(next_overflow_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
        }

        /* check if next block is our current position */
        if (next_pos >= cursor->current_pos)
        {
            cursor->current_pos = scan_pos;
            cursor->current_block_size = block_size;
            return 0;
        }

        scan_pos = next_pos;
    }

    return -1;
}

int block_manager_cursor_goto_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;

    return 0;
}

int block_manager_cursor_build_cache(block_manager_cursor_t *cursor, uint64_t end_offset)
{
    if (!cursor) return -1;

    /* free existing cache if any */
    if (cursor->position_cache) free(cursor->position_cache);
    if (cursor->size_cache) free(cursor->size_cache);

    /* initial capacity estimate: assume ~160 bytes per block on average */
    int initial_capacity = (int)((end_offset - BLOCK_MANAGER_HEADER_SIZE) / 160) + 100;
    if (initial_capacity < 1000) initial_capacity = 1000;

    cursor->position_cache = malloc(initial_capacity * sizeof(uint64_t));
    cursor->size_cache = malloc(initial_capacity * sizeof(uint64_t));
    if (!cursor->position_cache || !cursor->size_cache)
    {
        if (cursor->position_cache) free(cursor->position_cache);
        if (cursor->size_cache) free(cursor->size_cache);
        cursor->position_cache = NULL;
        cursor->size_cache = NULL;
        return -1;
    }

    cursor->cache_capacity = initial_capacity;
    cursor->cache_size = 0;

    /* scan forward and cache all block positions */
    if (block_manager_cursor_goto_first(cursor) != 0) return -1;

    do
    {
        /* check if we've reached the end offset */
        if (end_offset > 0 && cursor->current_pos >= end_offset) break;

        /* grow cache if needed */
        if (cursor->cache_size >= cursor->cache_capacity)
        {
            int new_capacity = cursor->cache_capacity * 2;
            uint64_t *new_pos = realloc(cursor->position_cache, new_capacity * sizeof(uint64_t));
            uint64_t *new_size = realloc(cursor->size_cache, new_capacity * sizeof(uint64_t));
            if (!new_pos || !new_size)
            {
                if (new_pos) free(new_pos);
                if (new_size) free(new_size);
                return -1;
            }
            cursor->position_cache = new_pos;
            cursor->size_cache = new_size;
            cursor->cache_capacity = new_capacity;
        }

        /* cache this block's position and size */
        cursor->position_cache[cursor->cache_size] = cursor->current_pos;
        cursor->size_cache[cursor->cache_size] = cursor->current_block_size;
        cursor->cache_size++;

    } while (block_manager_cursor_next(cursor) == 0);

    /* position at last cached block and set index */
    if (cursor->cache_size > 0)
    {
        cursor->cache_index = cursor->cache_size - 1;
        cursor->current_pos = cursor->position_cache[cursor->cache_index];
        cursor->current_block_size = cursor->size_cache[cursor->cache_index];
        return 0;
    }

    return -1;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    if (block_manager_cursor_goto_first(cursor) != 0) return -1;

    /* move forward until we hit EOF (no more blocks to read) */
    while (block_manager_cursor_next(cursor) == 0)
    {
        /* keep advancing through blocks */
    }

    /* at this point, cursor is positioned after the last block.
     * move back one block to be AT the last block (readable). */
    return block_manager_cursor_prev(cursor);
}

int block_manager_truncate(block_manager_t *bm)
{
    if (!bm) return -1;

    if (ftruncate(bm->fd, 0) != 0)
    {
        return -1;
    }

    if (close(bm->fd) != 0)
    {
        return -1;
    }

    bm->fd = open(bm->file_path, O_RDWR | O_CREAT, 0644);
    if (bm->fd == -1)
    {
        return -1;
    }

    /* write new header */
    if (write_header(bm->fd, bm->block_size) != 0)
    {
        return -1;
    }

    if (fdatasync(bm->fd) != 0)
    {
        return -1;
    }

    /* reset cached file size to header size */
    atomic_store(&bm->current_file_size, BLOCK_MANAGER_HEADER_SIZE);

    return 0;
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

    uint64_t first_block_size;
    if (pread(cursor->bm->fd, &first_block_size, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)BLOCK_MANAGER_HEADER_SIZE) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;

    uint64_t inline_size =
        first_block_size <= cursor->bm->block_size ? first_block_size : cursor->bm->block_size;

    /* calculate overflow offset position */
    off_t overflow_offset_pos = (off_t)BLOCK_MANAGER_HEADER_SIZE +
                                (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)inline_size;

    uint64_t overflow_offset;
    if (pread(cursor->bm->fd, &overflow_offset, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
              (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
        return -1;

    /* calculate second block position */
    uint64_t second_block_pos =
        (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);

    while (overflow_offset != 0)
    {
        uint64_t chunk_size;
        if (pread(cursor->bm->fd, &chunk_size, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                  (off_t)overflow_offset) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;

        off_t next_overflow_pos = (off_t)overflow_offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                  (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)chunk_size;
        if (pread(cursor->bm->fd, &overflow_offset, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            return -1;

        second_block_pos =
            (uint64_t)(next_overflow_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
    }

    return (cursor->current_pos == second_block_pos) ? 1 : 0;
}

int block_manager_cursor_at_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)cursor->current_pos) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    uint64_t block_size = decode_uint64_le_compat(size_buf);

    uint64_t inline_size =
        block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

    off_t overflow_offset_pos = (off_t)cursor->current_pos + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)inline_size;

    unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
    if (pread(cursor->bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
              (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
        return -1;
    uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

    uint64_t after_current_pos =
        (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);

    while (overflow_offset != 0)
    {
        unsigned char chunk_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(cursor->bm->fd, chunk_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                  (off_t)overflow_offset) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        uint64_t chunk_size = decode_uint64_le_compat(chunk_size_buf);

        off_t next_overflow_pos = (off_t)overflow_offset + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                  (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)chunk_size;
        unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(cursor->bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            return -1;
        overflow_offset = decode_uint64_le_compat(next_overflow_buf);

        after_current_pos =
            (uint64_t)(next_overflow_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
    }

    unsigned char next_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    ssize_t read_result = pread(cursor->bm->fd, next_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                                (off_t)after_current_pos);

    return (read_result != BLOCK_MANAGER_SIZE_FIELD_SIZE) ? 1 : 0;
}

int block_manager_get_size(block_manager_t *bm, uint64_t *size)
{
    if (!bm || !size) return -1;
    *size = bm->current_file_size;
    return 0;
}

int block_manager_cursor_goto(block_manager_cursor_t *cursor, uint64_t pos)
{
    if (!cursor) return -1;

    cursor->current_pos = pos;
    return 0;
}

int block_manager_escalate_fsync(block_manager_t *bm)
{
    if (!bm) return -1;
    return fdatasync(bm->fd);
}

time_t block_manager_last_modified(block_manager_t *bm)
{
    if (!bm) return -1;

    struct stat st;
    if (stat(bm->file_path, &st) != 0) return -1;
    return st.st_mtime;
}

int block_manager_count_blocks(block_manager_t *bm)
{
    if (!bm) return -1;

    block_manager_cursor_t *cursor;
    int count = 0;

    if (block_manager_cursor_init(&cursor, bm) != 0) return -1;

    block_manager_cursor_goto_first(cursor);

    if (block_manager_cursor_has_next(cursor) > 0)
    {
        /* move to first block and count it */
        block_manager_cursor_next(cursor);
        count++;

        while (block_manager_cursor_next(cursor) == 0)
        {
            count++;
        }
    }

    block_manager_cursor_free(cursor);
    return count;
}

int block_manager_validate_last_block(block_manager_t *bm)
{
    if (!bm) return -1;

    uint64_t file_size;
    if (get_file_size(bm->fd, &file_size) != 0) return -1;

    /* if file is empty, write header */
    if (file_size == 0)
    {
        if (write_header(bm->fd, bm->block_size) != 0)
        {
            return -1;
        }
        fdatasync(bm->fd);
        return 0;
    }

    if (file_size == BLOCK_MANAGER_HEADER_SIZE)
    {
        return 0; /* valid empty file with header */
    }

    /* ensure we have at least header + one block header */
    if (file_size < BLOCK_MANAGER_HEADER_SIZE + BLOCK_MANAGER_SIZE_FIELD_SIZE +
                        BLOCK_MANAGER_CHECKSUM_LENGTH + BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
    {
        /* truncate to header only */
        if (ftruncate(bm->fd, BLOCK_MANAGER_HEADER_SIZE) == -1)
        {
            return -1;
        }
        lseek(bm->fd, 0, SEEK_SET);
        return (bm->fd != -1) ? 0 : -1;
    }

    uint64_t valid_size = BLOCK_MANAGER_HEADER_SIZE;
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < file_size)
    {
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
            break;
        uint64_t block_size = decode_uint64_le_compat(size_buf);

        uint64_t inline_size = block_size <= bm->block_size ? block_size : bm->block_size;

        if (scan_pos + BLOCK_MANAGER_SIZE_FIELD_SIZE + BLOCK_MANAGER_CHECKSUM_LENGTH + inline_size +
                BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE >
            file_size)
        {
            valid_size = scan_pos;
            break;
        }

        off_t overflow_offset_pos = (off_t)scan_pos + (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                    (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)inline_size;
        unsigned char overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
        if (pread(bm->fd, overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                  (off_t)overflow_offset_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            break;
        uint64_t overflow_offset = decode_uint64_le_compat(overflow_buf);

        uint64_t next_pos =
            (uint64_t)(overflow_offset_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);

        while (overflow_offset != 0)
        {
            if (overflow_offset >= file_size)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            unsigned char chunk_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
            if (pread(bm->fd, chunk_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
                      (off_t)overflow_offset) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }
            uint64_t chunk_size = decode_uint64_le_compat(chunk_size_buf);

            if (overflow_offset + BLOCK_MANAGER_SIZE_FIELD_SIZE + BLOCK_MANAGER_CHECKSUM_LENGTH +
                    chunk_size + BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE >
                file_size)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            off_t next_overflow_pos = (off_t)overflow_offset +
                                      (off_t)BLOCK_MANAGER_SIZE_FIELD_SIZE +
                                      (off_t)BLOCK_MANAGER_CHECKSUM_LENGTH + (off_t)chunk_size;
            unsigned char next_overflow_buf[BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE];
            if (pread(bm->fd, next_overflow_buf, BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE,
                      (off_t)next_overflow_pos) != BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }
            overflow_offset = decode_uint64_le_compat(next_overflow_buf);

            next_pos = (uint64_t)(next_overflow_pos + (off_t)BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE);
        }

        valid_size = next_pos;
        scan_pos = next_pos;
    }

done_scanning:
    if (valid_size != file_size)
    {
        if (ftruncate(bm->fd, (long)valid_size) != 0)
        {
            return -1;
        }

        close(bm->fd);
        bm->fd = open(bm->file_path, O_RDWR | O_CREAT, 0644);
        if (bm->fd == -1)
        {
            return -1;
        }
    }

    return 0;
}

/*
 * convert_sync_mode
 * converts tidesdb sync mode to block manager sync mode
 * @param tdb_sync_mode the tidesdb sync mode
 * @return the corresponding block manager sync mode
 */
block_manager_sync_mode_t convert_sync_mode(int tdb_sync_mode)
{
    switch (tdb_sync_mode)
    {
        case 0: /* TDB_SYNC_NONE */
            return BLOCK_MANAGER_SYNC_NONE;
        case 1: /* TDB_SYNC_FULL */
            return BLOCK_MANAGER_SYNC_FULL;
        default:
            return BLOCK_MANAGER_SYNC_NONE;
    }
}

int block_manager_open(block_manager_t **bm, const char *file_path, int sync_mode)
{
    return block_manager_open_internal(bm, file_path, convert_sync_mode(sync_mode));
}