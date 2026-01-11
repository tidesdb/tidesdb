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

#include "xxhash.h"

#define BLOCK_MANAGER_STACK_BUFFER_SIZE 65536

/**
 *
 * file format *
 *
 * HEADER *
 * magic (3 bytes) 0x544442 "TDB"
 * version (1 byte) 6
 * padding (4 bytes) reserved
 *
 * BLOCKS *
 * block_size (4 bytes) -- size of data (uint32_t, supports up to 4GB)
 * checksum (4 bytes) -- xxHash32 of data
 * data (variable size) -- actual block data
 * footer_size (4 bytes) -- duplicate of block_size for validation
 * footer_magic (4 bytes) -- 0x42445442 "BTDB" for fast validation
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
 * compute xxHash32 checksum
 * @param data the data to compute the checksum for
 * @param size the size of the data
 * @return the 32-bit checksum
 */
static inline uint32_t compute_checksum(const void *data, const size_t size)
{
    return XXH32(data, size, 0);
}

/**
 * verify_checksum
 * verify xxHash32 checksum
 * @param data the data to verify the checksum for
 * @param size the size of the data
 * @param expected_checksum the expected checksum
 * @return 0 if the checksum matches, -1 otherwise
 */
static inline int verify_checksum(const void *data, const size_t size,
                                  const uint32_t expected_checksum)
{
    return (compute_checksum(data, size) == expected_checksum) ? 0 : -1;
}

/**
 * write_header
 * write file header using pwrite
 * @param fd the file descriptor to write to
 * @return 0 if successful, -1 otherwise
 */
static int write_header(int fd)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];
    uint32_t magic = BLOCK_MANAGER_MAGIC;
    uint8_t version = BLOCK_MANAGER_VERSION;
    uint32_t padding = 0;

    /* header format, [3-byte magic][1-byte version][4-byte padding] = 8 bytes */
    encode_uint32_le_compat(header, magic);
    header[BLOCK_MANAGER_MAGIC_SIZE] = version;
    encode_uint32_le_compat(header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE,
                            padding);

    const ssize_t written = pwrite(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    return (written == BLOCK_MANAGER_HEADER_SIZE) ? 0 : -1;
}

/**
 * read_header
 * read and validate file header using pread
 * @param fd the file descriptor to read from
 * @return 0 if successful, -1 otherwise
 */
static int read_header(const int fd)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];

    const ssize_t nread = pread(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    if (nread != BLOCK_MANAGER_HEADER_SIZE) return -1;

    /* we decode magic using little-endian conversion for cross-platform compatibility */
    uint32_t magic = decode_uint32_le_compat(header);
    magic &= BLOCK_MANAGER_MAGIC_MASK;

    if (magic != BLOCK_MANAGER_MAGIC) return -1;

    uint8_t version;
    memcpy(&version, header + BLOCK_MANAGER_MAGIC_SIZE, BLOCK_MANAGER_VERSION_SIZE);
    if (version != BLOCK_MANAGER_VERSION) return -1;

    return 0;
}

/**
 * get_file_size
 * get file size using fstat
 * @param fd the file descriptor to get the size of
 * @param size the size to store the result in
 * @return 0 if successful, -1 otherwise
 */
static int get_file_size(const int fd, uint64_t *size)
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
                                       const block_manager_sync_mode_t sync_mode)
{
    block_manager_t *new_bm = malloc(sizeof(block_manager_t));
    if (!new_bm)
    {
        *bm = NULL;
        return -1;
    }

    /* initialize atomic variable to prevent reading uninitialized memory */
    atomic_init(&new_bm->current_file_size, 0);

    const int file_exists = access(file_path, F_OK) == 0;

    int flags = O_RDWR | O_CREAT;

    /* we use O_DSYNC for synchronous data writes in SYNC_FULL mode
     * this ensures each pwrite is durable before returning, eliminating
     * the need for per-write fdatasync() calls on platforms that support it.
     * this is also faster, less syscalls, for example
     */
    if (sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC != 0)
    {
        flags |= O_DSYNC;
    }

    const mode_t mode = BLOCK_MANAGER_FILE_MODE;

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
        if (read_header(new_bm->fd) != 0)
        {
            close(new_bm->fd);
            free(new_bm);
            *bm = NULL;
            return -1;
        }
    }
    else
    {
        if (write_header(new_bm->fd) != 0)
        {
            close(new_bm->fd);
            free(new_bm);
            *bm = NULL;
            return -1;
        }
        /* if O_DSYNC is available, pwrite already synced the header
         * otherwise fall back to explicit fdatasync */
        if (new_bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
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

    /* set current_file_size if not already set by validation */
    if (atomic_load(&new_bm->current_file_size) == 0)
    {
        uint64_t file_size = 0;
        if (get_file_size(new_bm->fd, &file_size) == 0)
        {
            atomic_store(&new_bm->current_file_size, file_size);
        }
        else
        {
            /* if we can't get size, use lseek to get current position (end of file) */
            const off_t pos = lseek(new_bm->fd, 0, SEEK_END);
            atomic_store(&new_bm->current_file_size, (pos >= 0) ? (uint64_t)pos : 0);
        }
    }

    *bm = new_bm;
    return 0;
}

int block_manager_close(block_manager_t *bm)
{
    if (!bm) return -1;

    /* final sync on close -- really only needed if O_DSYNC wasnt used
     * with O_DSYNC, all writes are already durable */
    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
    {
        (void)fdatasync(bm->fd);
    }

    if (close(bm->fd) != 0) return -1;

    free(bm);

    return 0;
}

block_manager_block_t *block_manager_block_create(const uint64_t size, const void *data)
{
    if (size > UINT32_MAX)
    {
        return NULL;
    }

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

block_manager_block_t *block_manager_block_create_from_buffer(const uint64_t size, void *data)
{
    if (size > UINT32_MAX)
    {
        return NULL;
    }

    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;
    block->data = data;
    atomic_init(&block->ref_count, 1);
    return block;
}

int64_t block_manager_block_write(block_manager_t *bm, block_manager_block_t *block)
{
    if (!bm || !block) return -1;

    /* block size is stored as uint32_t, so enforce 4GB limit */
    if (block->size > UINT32_MAX)
    {
        return -1;
    }

    /* block format, [size][checksum][data][size][magic] */
    /* check for overflow when computing total_size */
    if (block->size > SIZE_MAX - BLOCK_MANAGER_BLOCK_HEADER_SIZE - BLOCK_MANAGER_FOOTER_SIZE)
    {
        return -1;
    }
    const size_t total_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block->size + BLOCK_MANAGER_FOOTER_SIZE;

    /* we atomically allocate space in file */
    const int64_t offset = (int64_t)atomic_fetch_add(&bm->current_file_size, total_size);
    const uint32_t checksum = compute_checksum(block->data, block->size);

    /* we use stack buffer for small blocks to avoid malloc overhead */
    unsigned char stack_buffer[BLOCK_MANAGER_STACK_BUFFER_SIZE]; /* BLOCK_MANAGER_STACK_BUFFER_SIZE
                                                                    stack buffer */
    unsigned char *write_buffer;
    const int use_stack = (total_size <= sizeof(stack_buffer));

    if (use_stack)
    {
        write_buffer = stack_buffer;
    }
    else
    {
        write_buffer = malloc(total_size);
        if (!write_buffer) return -1;
    }

    /* serialize block, [size(4)][checksum(4)][data][size(4)][magic(4)] */
    size_t buf_offset = 0;

    encode_uint32_le_compat(write_buffer + buf_offset, (uint32_t)block->size);
    buf_offset += BLOCK_MANAGER_SIZE_FIELD_SIZE;

    encode_uint32_le_compat(write_buffer + buf_offset, checksum);
    buf_offset += BLOCK_MANAGER_CHECKSUM_LENGTH;

    memcpy(write_buffer + buf_offset, block->data, block->size);
    buf_offset += block->size;

    /* write footer, size + magic for fast validation */
    encode_uint32_le_compat(write_buffer + buf_offset, (uint32_t)block->size);
    buf_offset += 4;

    encode_uint32_le_compat(write_buffer + buf_offset, BLOCK_MANAGER_FOOTER_MAGIC);
    buf_offset += 4;

    /* single atomic write */
    const ssize_t written = pwrite(bm->fd, write_buffer, total_size, offset);

    if (!use_stack) free(write_buffer);

    if (written != (ssize_t)total_size)
    {
        return -1;
    }

    /* if O_DSYNC is available and was used at open time, pwrite already synced
     * otherwise fall back to explicit fdatasync for durability */
    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
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

    const uint32_t old_ref = atomic_fetch_sub_explicit(&block->ref_count, 1, memory_order_release);
    if (old_ref == 1)
    {
        /* we were the last reference, free the block */
        atomic_thread_fence(memory_order_acquire);
        block_manager_block_free(block);
    }
}

int block_manager_cursor_init_stack(block_manager_cursor_t *cursor, block_manager_t *bm)
{
    if (!cursor || !bm) return -1;

    cursor->bm = bm;

    /* initialize to position before first block */
    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_index = -1; /* -1 means before first block */

    set_file_sequential_hint(bm->fd);

    /* position at first block so cursor_read works immediately */
    block_manager_cursor_goto_first(cursor);

    return 0;
}

int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm)
{
    if (!bm) return -1;

    (*cursor) = malloc(sizeof(block_manager_cursor_t));
    if (!(*cursor)) return -1;

    return block_manager_cursor_init_stack(*cursor, bm);
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
    uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return -1; /* invalid block */

    /* next block starts after, [size][checksum][data][footer_size][footer_magic] */
    cursor->current_pos +=
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size + BLOCK_MANAGER_FOOTER_SIZE;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    const uint64_t saved_cursor_pos = cursor->current_pos;
    const uint64_t saved_block_size = cursor->current_block_size;
    const int saved_block_index = cursor->block_index;

    const int result = block_manager_cursor_next(cursor);

    /* restore cursor state */
    cursor->current_pos = saved_cursor_pos;
    cursor->current_block_size = saved_block_size;
    cursor->block_index = saved_block_index;

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
 * reads a block at a specific offset
 * @param bm the block manager
 * @param offset the offset to read from
 * @return the block if successful, NULL otherwise
 */
static block_manager_block_t *block_manager_read_block_at_offset(block_manager_t *bm,
                                                                 const uint64_t offset)
{
    if (!bm) return NULL;

/* we use stack buffer for small blocks to read header+data in one syscall
 * for blocks <= 64KB -- header size, we read everything in one pread
 * for larger blocks, we fall back to two-syscall approach */
#define READ_STACK_BUF_SIZE 65536
    unsigned char stack_buf[READ_STACK_BUF_SIZE];

    /* first pread -- try to get header + data in one syscall */
    const ssize_t initial_read = pread(bm->fd, stack_buf, READ_STACK_BUF_SIZE, (off_t)offset);
    if (initial_read < (ssize_t)BLOCK_MANAGER_BLOCK_HEADER_SIZE) return NULL;

    const uint32_t block_size = decode_uint32_le_compat(stack_buf);
    if (block_size == 0) return NULL;

    const uint32_t stored_checksum =
        decode_uint32_le_compat(stack_buf + BLOCK_MANAGER_SIZE_FIELD_SIZE);

    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = block_size;
    atomic_init(&block->ref_count, 1);
    block->data = malloc(block_size);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    /* we check if we already have all the data from initial read */
    const size_t total_needed = BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size;
    if ((size_t)initial_read >= total_needed)
    {
        /* single syscall path: copy data from stack buffer */
        memcpy(block->data, stack_buf + BLOCK_MANAGER_BLOCK_HEADER_SIZE, block_size);
    }
    else
    {
        /* large block -- need second read for remaining data */
        const size_t already_have = (size_t)initial_read - BLOCK_MANAGER_BLOCK_HEADER_SIZE;
        if (already_have > 0)
        {
            memcpy(block->data, stack_buf + BLOCK_MANAGER_BLOCK_HEADER_SIZE, already_have);
        }

        /* we read remaining data */
        const size_t remaining = block_size - already_have;
        const off_t remaining_offset = (off_t)offset + (off_t)initial_read;
        if (pread(bm->fd, (uint8_t *)block->data + already_have, remaining, remaining_offset) !=
            (ssize_t)remaining)
        {
            free(block->data);
            free(block);
            return NULL;
        }
    }

    if (verify_checksum(block->data, block_size, stored_checksum) != 0)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    return block;
#undef READ_STACK_BUF_SIZE
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
    const uint64_t offset = cursor->current_pos;

    /* read block size */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)offset) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return NULL;
    uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return NULL;

    /* if block is smaller than max_bytes, read full block */
    if (block_size <= max_bytes)
    {
        return block_manager_read_block_at_offset(bm, offset);
    }

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
    const off_t data_pos = (off_t)offset + (off_t)BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (pread(bm->fd, block->data, max_bytes, data_pos) != (ssize_t)max_bytes)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* we don't verify checksum for partial reads since we don't have full data */
    return block;
}

void block_manager_cursor_free(block_manager_cursor_t *cursor)
{
    if (cursor)
    {
        free(cursor);
        cursor = NULL;
    }
}

int block_manager_cursor_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < cursor->current_pos)
    {
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        const uint32_t block_size = decode_uint32_le_compat(size_buf);
        if (block_size == 0) return -1;

        /* we calculate next block position, [size][checksum][data][footer] */
        const uint64_t total_block_size =
            BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size + BLOCK_MANAGER_FOOTER_SIZE;
        const uint64_t next_pos = scan_pos + total_block_size;

        /* we check if next block is our current position */
        if (next_pos == cursor->current_pos)
        {
            /* scan_pos is the block immediately before current */
            cursor->current_pos = scan_pos;
            cursor->current_block_size = block_size;
            return 0;
        }

        /* move to next block */
        scan_pos = next_pos;
    }

    return -1;
}

int block_manager_cursor_goto_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_index = -1;

    return 0;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* O(1) seek to end and work backwards using footer */
    const uint64_t file_size = atomic_load(&cursor->bm->current_file_size);

    /* empty file or only header */
    if (file_size <= BLOCK_MANAGER_HEADER_SIZE)
    {
        return -1;
    }

    /* read footer of last block to get its size */
    unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
    const off_t footer_offset = (off_t)(file_size - BLOCK_MANAGER_FOOTER_SIZE);
    const ssize_t n = pread(cursor->bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, footer_offset);

    if (n != BLOCK_MANAGER_FOOTER_SIZE)
    {
        return -1;
    }

    const uint32_t block_size = decode_uint32_le_compat(footer_buf);
    const uint32_t footer_magic = decode_uint32_le_compat(footer_buf + 4);

    /* verify footer magic */
    if (footer_magic != BLOCK_MANAGER_FOOTER_MAGIC || block_size == 0)
    {
        return -1;
    }

    /* we calculate start position of last block */
    const uint64_t total_block_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
    if (file_size < total_block_size)
    {
        return -1;
    }

    cursor->current_pos = file_size - total_block_size;
    cursor->current_block_size = block_size;
    cursor->block_index = -1; /* unknown index */

    return 0;
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

    /* we reopen with same flags as original open, including O_DSYNC if in SYNC_FULL mode */
    int flags = O_RDWR | O_CREAT;
    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC != 0)
    {
        flags |= O_DSYNC;
    }

    bm->fd = open(bm->file_path, flags, 0644);
    if (bm->fd == -1)
    {
        return -1;
    }

    if (write_header(bm->fd) != 0)
    {
        return -1;
    }

    if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
    {
        if (fdatasync(bm->fd) != 0)
        {
            return -1;
        }
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

    /* we read first block size */
    unsigned char first_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(cursor->bm->fd, first_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)BLOCK_MANAGER_HEADER_SIZE) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    const uint32_t first_block_size = decode_uint32_le_compat(first_size_buf);
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

    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)cursor->current_pos) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    const uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return -1;

    /* we calculate position after current block, [size][checksum][data][footer] */
    const uint64_t total_block_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
    const uint64_t next_block_pos = cursor->current_pos + total_block_size;

    /* try to read next block size -- if we can't, we're at last block */
    unsigned char next_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    const ssize_t read_result =
        pread(cursor->bm->fd, next_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)next_block_pos);

    return (read_result != BLOCK_MANAGER_SIZE_FIELD_SIZE) ? 1 : 0;
}

int block_manager_get_size(block_manager_t *bm, uint64_t *size)
{
    if (!bm || !size) return -1;
    *size = atomic_load(&bm->current_file_size);
    return 0;
}

int block_manager_cursor_goto(block_manager_cursor_t *cursor, const uint64_t pos)
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

    struct STAT_STRUCT st;
    if (STAT_FUNC(bm->file_path, &st) != 0) return -1;
    return st.st_mtime;
}

int block_manager_count_blocks(block_manager_t *bm)
{
    if (!bm) return -1;

    block_manager_cursor_t *cursor;
    int count = 0;

    if (block_manager_cursor_init(&cursor, bm) != 0) return -1;

    if (block_manager_cursor_goto_first(cursor) != 0)
    {
        block_manager_cursor_free(cursor);
        return 0; /* empty file */
    }

    if (cursor->block_index >= 0)
    {
        count = 1;
        while (block_manager_cursor_next(cursor) == 0)
        {
            count++;
        }
    }
    else
    {
        while (block_manager_cursor_next(cursor) == 0)
        {
            count++;
        }
    }

    block_manager_cursor_free(cursor);
    return count;
}

int block_manager_validate_last_block(block_manager_t *bm, const int strict)
{
    if (!bm) return -1;

    uint64_t file_size;
    if (get_file_size(bm->fd, &file_size) != 0) return -1;

    /* cache file size for subsequent cursor operations */
    atomic_store(&bm->current_file_size, file_size);

    /* if file is empty, write header */
    if (file_size == 0)
    {
        if (write_header(bm->fd) != 0)
        {
            return -1;
        }
        if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
        {
            fdatasync(bm->fd);
        }
        return 0;
    }

    if (file_size == BLOCK_MANAGER_HEADER_SIZE)
    {
        return 0; /* valid empty file with header */
    }

    /* we must ensure we have at least header + minimum block */
    const uint64_t min_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
    if (file_size < BLOCK_MANAGER_HEADER_SIZE + min_block_size)
    {
        if (strict)
        {
            return -1;
        }
        if (ftruncate(bm->fd, (off_t)BLOCK_MANAGER_HEADER_SIZE) == -1)
        {
            return -1;
        }
        lseek(bm->fd, 0, SEEK_SET);
        atomic_store(&bm->current_file_size, BLOCK_MANAGER_HEADER_SIZE);
        return 0;
    }

    /* fast O(1) validation, read footer of last block */
    unsigned char footer_buf[BLOCK_MANAGER_FOOTER_SIZE];
    const off_t footer_offset = (off_t)(file_size - BLOCK_MANAGER_FOOTER_SIZE);
    const ssize_t n = pread(bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, footer_offset);

    if (n != BLOCK_MANAGER_FOOTER_SIZE)
    {
        if (strict)
        {
            /* strict mode -- can't read footer = corruption */
            return -1;
        }
        /* permissive mode -- truncate to header */
        if (ftruncate(bm->fd, (off_t)BLOCK_MANAGER_HEADER_SIZE) == -1) return -1;
        atomic_store(&bm->current_file_size, BLOCK_MANAGER_HEADER_SIZE);
        return 0;
    }

    const uint32_t footer_size = decode_uint32_le_compat(footer_buf);
    const uint32_t footer_magic = decode_uint32_le_compat(footer_buf + 4);

    /* we check if footer is valid */
    if (footer_magic != BLOCK_MANAGER_FOOTER_MAGIC)
    {
        fprintf(stderr,
                "[block_manager] File %s: invalid footer magic 0x%08x (expected 0x%08x), "
                "file_size=%" PRIu64 "\n",
                bm->file_path, footer_magic, BLOCK_MANAGER_FOOTER_MAGIC, file_size);
        if (strict)
        {
            return -1;
        }

        fprintf(stderr, "[block_manager] Permissive mode: scanning for last valid block\n");
        uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;
        uint64_t valid_size = BLOCK_MANAGER_HEADER_SIZE;

        while (scan_pos + min_block_size <= file_size)
        {
            unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
            if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
                BLOCK_MANAGER_SIZE_FIELD_SIZE)
                break;

            const uint32_t block_size = decode_uint32_le_compat(size_buf);
            if (block_size == 0) break;

            const uint64_t total_block_size =
                BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size + BLOCK_MANAGER_FOOTER_SIZE;
            if (scan_pos + total_block_size > file_size) break;

            /* we verify footer of this block */
            const off_t block_footer_offset =
                (off_t)(scan_pos + total_block_size - BLOCK_MANAGER_FOOTER_SIZE);
            if (pread(bm->fd, footer_buf, BLOCK_MANAGER_FOOTER_SIZE, block_footer_offset) !=
                BLOCK_MANAGER_FOOTER_SIZE)
                break;

            const uint32_t block_footer_size = decode_uint32_le_compat(footer_buf);
            const uint32_t block_footer_magic = decode_uint32_le_compat(footer_buf + 4);

            if (block_footer_magic != BLOCK_MANAGER_FOOTER_MAGIC || block_footer_size != block_size)
                break;

            valid_size = scan_pos + total_block_size;
            scan_pos += total_block_size;
        }

        if (valid_size != file_size)
        {
            fprintf(stderr, "[block_manager] Truncating %s from %" PRIu64 " to %" PRIu64 " bytes\n",
                    bm->file_path, file_size, valid_size);
            if (ftruncate(bm->fd, (off_t)valid_size) != 0) return -1;
            /* sync truncation - only needed if O_DSYNC not available */
            if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC == 0)
            {
                fdatasync(bm->fd);
            }
            close(bm->fd);
            /* reopen with same flags as original open */
            int flags = O_RDWR | O_CREAT;
            if (bm->sync_mode == BLOCK_MANAGER_SYNC_FULL && O_DSYNC != 0)
            {
                flags |= O_DSYNC;
            }
            bm->fd = open(bm->file_path, flags, 0644);
            if (bm->fd == -1) return -1;
            atomic_store(&bm->current_file_size, valid_size);
            fprintf(stderr, "[block_manager] Truncation complete, file reopened\n");
        }
        else
        {
            fprintf(stderr, "[block_manager] No truncation needed, valid_size matches file_size\n");
        }
        return 0;
    }

    /* footer magic is valid, verify size matches header */
    const uint64_t block_start =
        file_size - BLOCK_MANAGER_FOOTER_SIZE - footer_size - BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (block_start < BLOCK_MANAGER_HEADER_SIZE)
    {
        if (strict)
        {
            /*** strict mode -- invalid block position = corruption */
            return -1;
        }
        /*** permissive mode -- truncate to header */
        if (ftruncate(bm->fd, (off_t)BLOCK_MANAGER_HEADER_SIZE) == -1) return -1;
        atomic_store(&bm->current_file_size, BLOCK_MANAGER_HEADER_SIZE);
        return 0;
    }

    unsigned char header_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, header_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)block_start) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        /* cant read block header = I/O error (fail in both modes) */
        return -1;
    }

    const uint32_t header_size = decode_uint32_le_compat(header_size_buf);
    if (header_size != footer_size)
    {
        /* size mismatch = corruption (fail in both modes, this is unrecoverable) */
        return -1;
    }

    /* last block is valid, no truncation needed */
    return 0;
}

/*
 * convert_sync_mode
 * converts tidesdb sync mode to block manager sync mode
 * @param tdb_sync_mode the tidesdb sync mode
 * @return the corresponding block manager sync mode
 */
block_manager_sync_mode_t convert_sync_mode(const int tdb_sync_mode)
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

void block_manager_set_sync_mode(block_manager_t *bm, const int sync_mode)
{
    if (!bm) return;
    bm->sync_mode = convert_sync_mode(sync_mode);
}

int block_manager_get_block_size_at_offset(block_manager_t *bm, const uint64_t offset,
                                           uint32_t *size)
{
    if (!bm || !size) return -1;

    /* read the size field from block header (first 4 bytes of block) */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    const ssize_t nread = pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)offset);
    if (nread != BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        return -1;
    }

    *size = decode_uint32_le_compat(size_buf);
    if (*size == 0) return -1; /* invalid block */

    return 0;
}

int block_manager_read_at_offset(block_manager_t *bm, const uint64_t offset, const size_t size,
                                 uint8_t *data)
{
    if (!bm || !data || size == 0) return -1;

    /* we do a simple pread at the specified offset */
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

    /* we read block header (size + checksum) in one operation */
    unsigned char header[BLOCK_MANAGER_BLOCK_HEADER_SIZE];
    ssize_t nread = pread(bm->fd, header, BLOCK_MANAGER_BLOCK_HEADER_SIZE, (off_t)offset);
    if (nread != BLOCK_MANAGER_BLOCK_HEADER_SIZE)
    {
        return -1;
    }

    const uint32_t block_size = decode_uint32_le_compat(header);
    const uint32_t expected_checksum =
        decode_uint32_le_compat(header + BLOCK_MANAGER_SIZE_FIELD_SIZE);

    if (block_size == 0) return -1; /* invalid block */

    uint8_t *block_data = malloc(block_size);
    if (!block_data) return -1;

    /* we read block data immediately after header */
    const uint64_t data_offset = offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    nread = pread(bm->fd, block_data, block_size, (off_t)data_offset);
    if (nread != (ssize_t)block_size)
    {
        free(block_data);
        return -1;
    }

    if (verify_checksum(block_data, block_size, expected_checksum) != 0)
    {
        free(block_data);
        return -1; /* checksum mismatch */
    }

    *data = block_data;
    *data_size = block_size;
    return 0;
}

int block_manager_open(block_manager_t **bm, const char *file_path, const int sync_mode)
{
    if (!bm || !file_path) return -1;
    return block_manager_open_internal(bm, file_path, convert_sync_mode(sync_mode));
}