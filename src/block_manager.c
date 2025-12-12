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
 * block_size (4 bytes) - size of data (uint32_t, supports up to 4GB)
 * checksum (4 bytes) - xxHash32 of data
 * data (variable size) - actual block data
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
static inline uint32_t compute_checksum(const void *data, size_t size)
{
    return XXH32(data, size, 0);
}

/**
 * verify_checksum
 * verify xxHash64 checksum
 * @param data the data to verify the checksum for
 * @param size the size of the data
 * @param expected_checksum the expected checksum
 * @return 0 if the checksum matches, -1 otherwise
 */
static inline int verify_checksum(const void *data, size_t size, uint32_t expected_checksum)
{
    uint32_t computed = compute_checksum(data, size);
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

    /* decode magic using little-endian conversion for cross-platform compatibility */
    uint32_t magic = decode_uint32_le_compat(header);
    magic &= BLOCK_MANAGER_MAGIC_MASK;

    if (magic != BLOCK_MANAGER_MAGIC) return -1;

    uint8_t version;
    memcpy(&version, header + BLOCK_MANAGER_MAGIC_SIZE, BLOCK_MANAGER_VERSION_SIZE);
    if (version != BLOCK_MANAGER_VERSION) return -1;

    /* decode block_size using little-endian conversion for cross-platform compatibility */
    *block_size =
        decode_uint32_le_compat(header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE);

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

int block_manager_build_position_cache(block_manager_t *bm)
{
    if (!bm) return -1;

    /* set flag to prevent concurrent cache access during rebuild */
    atomic_store(&bm->cache_rebuilding, 1);

    /* free existing cache if present */
    if (bm->block_positions)
    {
        free(bm->block_positions);
        bm->block_positions = NULL;
    }
    if (bm->block_sizes)
    {
        free(bm->block_sizes);
        bm->block_sizes = NULL;
    }
    bm->block_count = 0;

    uint64_t file_size = atomic_load(&bm->current_file_size);

    uint64_t actual_file_size;
    if (get_file_size(bm->fd, &actual_file_size) == 0)
    {
        if (actual_file_size != file_size)
        {
            file_size = actual_file_size;
        }
    }

    /* empty file, no blocks to cache */
    if (file_size <= BLOCK_MANAGER_HEADER_SIZE)
    {
        atomic_store(&bm->cache_rebuilding, 0);
        return 0;
    }

    /* estimate initial capacity based on file size and average block size */
    int initial_capacity = (int)((file_size - BLOCK_MANAGER_HEADER_SIZE) / 160) + 100;
    if (initial_capacity < 1000) initial_capacity = 1000;

    bm->block_positions = malloc(initial_capacity * sizeof(uint64_t));
    bm->block_sizes = malloc(initial_capacity * sizeof(uint64_t));
    if (!bm->block_positions || !bm->block_sizes)
    {
        if (bm->block_positions) free(bm->block_positions);
        if (bm->block_sizes) free(bm->block_sizes);
        bm->block_positions = NULL;
        bm->block_sizes = NULL;
        return -1;
    }

    int capacity = initial_capacity;
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    /* scan all blocks and cache their positions */
    while (scan_pos < file_size)
    {
        /* read block size */
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        ssize_t nread = pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos);
        if (nread != BLOCK_MANAGER_SIZE_FIELD_SIZE) break;

        uint32_t block_size = decode_uint32_le_compat(size_buf);
        if (block_size == 0) break;

        /* verify complete block fits in file: [size][checksum][data] */
        uint64_t total_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size;
        if (scan_pos + total_block_size > file_size) break;

        /* grow cache if needed */
        if (bm->block_count >= capacity)
        {
            int new_capacity = capacity * 2;
            uint64_t *new_pos = realloc(bm->block_positions, new_capacity * sizeof(uint64_t));
            uint64_t *new_size = realloc(bm->block_sizes, new_capacity * sizeof(uint64_t));
            if (!new_pos || !new_size)
            {
                if (new_pos) free(new_pos);
                if (new_size) free(new_size);
                /* keep existing cache, just stop growing */
                break;
            }
            bm->block_positions = new_pos;
            bm->block_sizes = new_size;
            capacity = new_capacity;
        }

        /* cache this block */
        bm->block_positions[bm->block_count] = scan_pos;
        bm->block_sizes[bm->block_count] = block_size;
        bm->block_count++;

        /* move to next block */
        scan_pos += total_block_size;
    }

    /* clear flag to allow cache access again */
    atomic_store(&bm->cache_rebuilding, 0);
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

    /* initialize cache pointers to prevent use of uninitialized memory */
    new_bm->block_positions = NULL;
    new_bm->block_sizes = NULL;
    new_bm->block_count = 0;
    atomic_store(&new_bm->cache_rebuilding, 0);

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
        new_bm->block_size = 65536; /* 64KB default block size */
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

    /* build shared position cache for O(1) navigation and random access */
    if (block_manager_build_position_cache(new_bm) != 0)
    {
        /* cache build failed, but continue, though cursors will work without cache */
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

    if (bm->block_positions) free(bm->block_positions);
    if (bm->block_sizes) free(bm->block_sizes);

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
    /* simple variable-length block: [size][checksum][data] */
    size_t total_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + block->size;

    /* atomically allocate space in file */
    int64_t offset = (int64_t)atomic_fetch_add(&bm->current_file_size, total_size);

    /* compute checksum of data */
    uint32_t checksum = compute_checksum(block->data, block->size);

    /* use stack buffer for small blocks to avoid malloc overhead */
    unsigned char stack_buffer[65536]; /* 64KB stack buffer */
    unsigned char *write_buffer;
    int use_stack = (total_size <= sizeof(stack_buffer));

    if (use_stack)
    {
        write_buffer = stack_buffer;
    }
    else
    {
        write_buffer = malloc(total_size);
        if (!write_buffer) return -1;
    }

    /* serialize block: [size(4)][checksum(4)][data] */
    size_t buf_offset = 0;

    encode_uint32_le_compat(write_buffer + buf_offset, (uint32_t)block->size);
    buf_offset += BLOCK_MANAGER_SIZE_FIELD_SIZE;

    encode_uint32_le_compat(write_buffer + buf_offset, checksum);
    buf_offset += BLOCK_MANAGER_CHECKSUM_LENGTH;

    memcpy(write_buffer + buf_offset, block->data, block->size);

    /* single atomic write */
    ssize_t written = pwrite(bm->fd, write_buffer, total_size, offset);

    if (!use_stack) free(write_buffer);

    if (written != (ssize_t)total_size)
    {
        return -1;
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

    /* initialize to position before first block */
    (*cursor)->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    (*cursor)->current_block_size = 0;
    (*cursor)->block_index = -1; /* -1 means before first block */

    /* hint to OS that we'll be reading sequentially */
    set_file_sequential_hint(bm->fd);

    /* position at first block so cursor_read works immediately */
    block_manager_cursor_goto_first(*cursor);

    return 0;
}

int block_manager_cursor_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if cache is available and not being rebuilt, use O(1) lookup */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        int next_index = cursor->block_index + 1;
        if (next_index >= cursor->bm->block_count)
        {
            return 1; /* EOF */
        }

        cursor->block_index = next_index;
        cursor->current_pos = cursor->bm->block_positions[next_index];
        cursor->current_block_size = cursor->bm->block_sizes[next_index];
        return 0;
    }

    /* no cache, read block size and skip to next block */
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

    /* next block starts immediately after current block: [size][checksum][data] */
    cursor->current_pos += BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if cache is available and not being rebuilt, use O(1) check */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        return (cursor->block_index < cursor->bm->block_count - 1) ? 1 : 0;
    }

    /* no cache, save current state and try to advance */
    uint64_t saved_cursor_pos = cursor->current_pos;
    uint64_t saved_block_size = cursor->current_block_size;
    int saved_block_index = cursor->block_index;

    int result = block_manager_cursor_next(cursor);

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

    /* if cache is available and not being rebuilt, use block_index */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        return (cursor->block_index > 0) ? 1 : 0;
    }

    /* no cache, check position */
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

    /* read block header: [size(4)][checksum(4)] */
    unsigned char header_buf[BLOCK_MANAGER_BLOCK_HEADER_SIZE];
    if (pread(bm->fd, header_buf, sizeof(header_buf), (off_t)offset) != sizeof(header_buf))
        return NULL;

    uint32_t block_size = decode_uint32_le_compat(header_buf);
    if (block_size == 0) return NULL;

    uint32_t stored_checksum = decode_uint32_le_compat(header_buf + BLOCK_MANAGER_SIZE_FIELD_SIZE);

    /* allocate block structure */
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = block_size;
    atomic_init(&block->ref_count, 1); /* initial reference for caller */
    block->data = malloc(block_size);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    /* read block data */
    off_t data_pos = (off_t)offset + (off_t)BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (pread(bm->fd, block->data, block_size, data_pos) != (ssize_t)block_size)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* verify checksum */
    if (verify_checksum(block->data, block_size, stored_checksum) != 0)
    {
        free(block->data);
        free(block);
        return NULL;
    }

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
    uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return NULL;

    /* if block is smaller than max_bytes, read full block */
    if (block_size <= max_bytes)
    {
        return block_manager_read_block_at_offset(bm, offset);
    }

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
    off_t data_pos = (off_t)offset + (off_t)BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (pread(bm->fd, block->data, max_bytes, data_pos) != (ssize_t)max_bytes)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* note: we don't verify checksum for partial reads since we don't have full data */
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

    /* if cache is available and not being rebuilt, use O(1) lookup */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        if (cursor->block_index <= 0) return -1; /* already at or before first block */

        cursor->block_index--;
        cursor->current_pos = cursor->bm->block_positions[cursor->block_index];
        cursor->current_block_size = cursor->bm->block_sizes[cursor->block_index];
        return 0;
    }

    /* no cache, use O(n) scan method */
    if (cursor->current_pos <= BLOCK_MANAGER_HEADER_SIZE) return -1;

    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < cursor->current_pos)
    {
        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)scan_pos) !=
            BLOCK_MANAGER_SIZE_FIELD_SIZE)
            return -1;
        uint32_t block_size = decode_uint32_le_compat(size_buf);
        if (block_size == 0) return -1;

        /* calculate next block position: [size][checksum][data] */
        uint64_t total_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)block_size;
        uint64_t next_pos = scan_pos + total_block_size;

        /* check if next block is our current position */
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

    /* if cache available and not being rebuilt, position at first block */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        cursor->block_index = 0;
        cursor->current_pos = cursor->bm->block_positions[0];
        cursor->current_block_size = cursor->bm->block_sizes[0];
        return 0;
    }

    /* no cache! position at header (will need cursor_next to read first block) */
    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;
    cursor->block_index = -1;

    return 0;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if cache is available and not being rebuilt, use O(1) jump to last block */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        cursor->block_index = cursor->bm->block_count - 1;
        cursor->current_pos = cursor->bm->block_positions[cursor->block_index];
        cursor->current_block_size = cursor->bm->block_sizes[cursor->block_index];
        return 0;
    }

    /*  no cache, scan forward then back */
    (void)block_manager_cursor_goto_first(cursor);

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

    /* read first block size */
    unsigned char first_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(cursor->bm->fd, first_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)BLOCK_MANAGER_HEADER_SIZE) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    uint32_t first_block_size = decode_uint32_le_compat(first_size_buf);
    if (first_block_size == 0) return -1;

    /* calculate second block position: first_block_pos + [size][checksum][data] */
    uint64_t first_total_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)first_block_size;
    uint64_t second_block_pos = BLOCK_MANAGER_HEADER_SIZE + first_total_size;

    return (cursor->current_pos == second_block_pos) ? 1 : 0;
}

int block_manager_cursor_at_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if cache available and not being rebuilt, use O(1) check */
    if (cursor->bm->block_count > 0 && cursor->bm->block_positions &&
        !atomic_load(&cursor->bm->cache_rebuilding))
    {
        return (cursor->block_index == cursor->bm->block_count - 1) ? 1 : 0;
    }

    /* no cache, check if there's a next block */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(cursor->bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE,
              (off_t)cursor->current_pos) != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        return -1;
    uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return -1;

    /* calculate position after current block: [size][checksum][data] */
    uint64_t total_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size;
    uint64_t next_block_pos = cursor->current_pos + total_block_size;

    /* try to read next block size - if we can't, we're at last block */
    unsigned char next_size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    ssize_t read_result =
        pread(cursor->bm->fd, next_size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, (off_t)next_block_pos);

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

    if (block_manager_cursor_goto_first(cursor) != 0)
    {
        block_manager_cursor_free(cursor);
        return 0; /* empty file */
    }

    /* if cache exists, goto_first positioned us at first block
     * if no cache, goto_first positioned us before first block (at header)
     * check block_index to determine which case we're in */
    if (cursor->block_index >= 0)
    {
        /* cache? already at first block */
        count = 1;
        while (block_manager_cursor_next(cursor) == 0)
        {
            count++;
        }
    }
    else
    {
        /* no cache, positioned before first block, need to advance */
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
    if (file_size < BLOCK_MANAGER_HEADER_SIZE + BLOCK_MANAGER_BLOCK_HEADER_SIZE)
    {
        /* truncate to header only */
        if (ftruncate(bm->fd, (off_t)BLOCK_MANAGER_HEADER_SIZE) == -1)
        {
            return -1;
        }
        lseek(bm->fd, 0, SEEK_SET);
        return 0;
    }

    uint64_t valid_size = BLOCK_MANAGER_HEADER_SIZE;
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;
    int block_num = 0;

    while (scan_pos < file_size)
    {
        /* safe conversion of scan_pos to off_t */
        if (scan_pos > (uint64_t)LLONG_MAX) break;
        off_t off_scan = (off_t)(int64_t)scan_pos;

        unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
        ssize_t n = pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, off_scan);
        if (n != BLOCK_MANAGER_SIZE_FIELD_SIZE)
        {
            /* short read, we treat as corruption */
            break;
        }

        uint32_t block_size = decode_uint32_le_compat(size_buf);
        if (block_size == 0)
        {
            valid_size = scan_pos;
            break;
        }

        /* validate complete block fits in file: [size][checksum][data] */
        uint64_t total_block_size = BLOCK_MANAGER_BLOCK_HEADER_SIZE + block_size;
        if (scan_pos + total_block_size > file_size)
        {
            valid_size = scan_pos;
            break;
        }

        /* block is valid, move to next */
        valid_size = scan_pos + total_block_size;
        scan_pos = scan_pos + total_block_size;
        block_num++;
    }

    if (valid_size != file_size)
    {
        /* truncate to last valid block */
        if (valid_size > (uint64_t)LLONG_MAX)
        {
            return -1; /* file too large */
        }
        off_t truncate_off = (off_t)(int64_t)valid_size;

        if (ftruncate(bm->fd, truncate_off) != 0)
        {
            return -1;
        }

        fdatasync(bm->fd);

        close(bm->fd);
        bm->fd = open(bm->file_path, O_RDWR | O_CREAT, 0644);
        if (bm->fd == -1)
        {
            return -1;
        }

        /* update file size and rebuild cache after truncation */
        atomic_store(&bm->current_file_size, valid_size);

        /* free old cache */
        if (bm->block_positions) free(bm->block_positions);
        if (bm->block_sizes) free(bm->block_sizes);
        bm->block_positions = NULL;
        bm->block_sizes = NULL;
        bm->block_count = 0;

        block_manager_build_position_cache(bm);
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