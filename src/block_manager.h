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
#ifndef __BLOCK_MANAGER_H__
#define __BLOCK_MANAGER_H__
#include "compat.h"
#include "fifo.h"

/* more time equals more results, but remember to take breaks to refresh your mind. */

/* max file path length for block manager file(s) */
#define MAX_FILE_PATH_LENGTH 1024 * 4

/* TDB in hex */
#define BLOCK_MANAGER_MAGIC 0x544442
/* 3-byte mask for magic number validation */
#define BLOCK_MANAGER_MAGIC_MASK 0xFFFFFF

/* block manager version */
#define BLOCK_MANAGER_VERSION 5

/* header field sizes */
/* magic number size in bytes */
#define BLOCK_MANAGER_MAGIC_SIZE 3
/* version field size in bytes */
#define BLOCK_MANAGER_VERSION_SIZE 1
/* block_size field size in bytes */
#define BLOCK_MANAGER_BLOCK_SIZE_SIZE 4
/* padding field size in bytes */
#define BLOCK_MANAGER_PADDING_SIZE 4

#define BLOCK_MANAGER_HEADER_SIZE 12

/* block field sizes */
/* block size field (uint64_t) */
#define BLOCK_MANAGER_SIZE_FIELD_SIZE 8
/* xxHash64 = 8 bytes */
#define BLOCK_MANAGER_CHECKSUM_LENGTH 8

/* overflow offset field (uint64_t) */
#define BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE 8
#define BLOCK_MANAGER_BLOCK_HEADER_SIZE                              \
    (BLOCK_MANAGER_SIZE_FIELD_SIZE + BLOCK_MANAGER_CHECKSUM_LENGTH + \
     BLOCK_MANAGER_OVERFLOW_OFFSET_SIZE)
#define MAX_INLINE_BLOCK_SIZE (32 * 1024)
/* extra bytes for headers in stack buffers */
#define BLOCK_MANAGER_STACK_BUFFER_OVERHEAD 64
/* size of cache key buffer for offset-to-string conversion */
#define BLOCK_MANAGER_CACHE_KEY_SIZE 32

/* default file permissions (rw-r--r--) */
#define BLOCK_MANAGER_FILE_MODE 0644
#define MIN_CACHE_ENTRIES       10

typedef enum
{
    BLOCK_MANAGER_SYNC_NONE,
    BLOCK_MANAGER_SYNC_FULL,
} block_manager_sync_mode_t;

/**
 * block_manager_cache_t
 * block manager cache struct
 * used for block manager caching
 * @param max_size max size of cache in bytes
 * @param current_size current size of cache in bytes
 * @param fifo_cache utilized for hot block caching
 */
typedef struct
{
    uint32_t max_size;
    uint32_t current_size;
    fifo_cache_t *fifo_cache;
} block_manager_cache_t;

/**
 * block_manager_t
 * block manager struct
 * used for block managers in TidesDB
 * @param fd the file descriptor the block manager is managing
 * @param file_path the path of the file
 * @param sync_mode sync mode for this block manager
 * @param block_size the default block size for this block manager
 * @param cache_size size of lru cache of blocks in bytes
 * @param current_file_size track file size in memory to avoid syscalls
 * @param block_manager_cache the block manager cache
 */
typedef struct
{
    int fd;
    char file_path[MAX_FILE_PATH_LENGTH];
    block_manager_sync_mode_t sync_mode;
    uint32_t block_size;
    _Atomic uint64_t current_file_size;
    block_manager_cache_t *block_manager_cache;
} block_manager_t;

/**
 * block_t
 * block struct
 * used for blocks in TidesDB
 * @param size the size of the data in the block
 * @param data the data in the block
 * @param ref_count reference count for zero-copy caching (atomic)
 */
typedef struct
{
    uint64_t size;
    void *data;
    _Atomic(int) ref_count;
} block_manager_block_t;

/**
 * block_cursor_t
 * block cursor struct
 * used for block cursors in TidesDB
 * @param bm the block manager
 * @param current_pos the current position of the cursor
 * @param current_block_size the size of the current block
 */
typedef struct
{
    block_manager_t *bm;
    uint64_t current_pos;
    uint64_t current_block_size;

    /* position cache for O(1) backward navigation */
    uint64_t *position_cache; /* array of block positions */
    uint64_t *size_cache;     /* array of block sizes */
    int cache_capacity;       /* allocated capacity */
    int cache_size;           /* number of cached positions */
    int cache_index;          /* current index in cache (-1 if not using cache) */
} block_manager_cursor_t;

/**
 * block_manager_open
 * opens a block manager (no cache)
 * @param bm the block manager to open
 * @param file_path the path of the file
 * @param sync_mode the sync mode (TDB_SYNC_NONE, TDB_SYNC_FULL)
 * @return 0 if successful, -1 if not
 */
int block_manager_open(block_manager_t **bm, const char *file_path, int sync_mode);

/**
 * block_manager_open_with_cache
 * opens a block manager with LRU cache support for blocks, if you provide cache_size of 0, will
 * open with no caching.
 * @param bm the block manager to open
 * @param file_path the path of the file
 * @param sync_mode the sync mode
 * @param cache_size size of block manager lru block cache in bytes
 * @return 0 if successful, -1 if not
 */
int block_manager_open_with_cache(block_manager_t **bm, const char *file_path,
                                  block_manager_sync_mode_t sync_mode, uint32_t cache_size);

/**
 * block_manager_close
 * closes a block manager gracefully
 * @param bm the block manager to close
 * @return 0 if successful, -1 if not
 */
int block_manager_close(block_manager_t *bm);

/**
 * block_manager_block_create
 * creates a new block
 * @param size the size of the data in block
 * @param data the data to be placed in block
 * @return a new block
 */
block_manager_block_t *block_manager_block_create(uint64_t size, void *data);

/**
 * block_manager_block_create_from_buffer
 * creates a new block taking ownership of buffer (no copy)
 * @param size the size of the data in block
 * @param data the data buffer (will be freed with block)
 * @return a new block
 */
block_manager_block_t *block_manager_block_create_from_buffer(uint64_t size, void *data);

/**
 * block_manager_block_write
 * @param bm the block manager to write the block to
 * @param block the block to write
 * @return block offset if successful, -1 if not
 */
int64_t block_manager_block_write(block_manager_t *bm, block_manager_block_t *block);

/**
 * block_manager_block_free
 * frees a block (use this for non-cached blocks)
 * @param block the block to free
 */
void block_manager_block_free(block_manager_block_t *block);

/**
 * block_manager_block_acquire
 * increments reference count for a cached block
 * @param block the block to acquire
 * @return 1 if successful, 0 if block is being freed
 */
int block_manager_block_acquire(block_manager_block_t *block);

/**
 * block_manager_block_release
 * decrements reference count and frees block when count reaches 0
 * @param block the block to release
 */
void block_manager_block_release(block_manager_block_t *block);

/**
 * block_manager_cursor_init
 * initializes a block manager cursor
 * @param cursor the cursor to initialize
 * @param bm the block manager to initialize the cursor on
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm);

/**
 * cursor_next
 * moves the cursor to the next block
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_next(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_read
 * reads the block at the cursor current position
 * @param cursor the cursor to read from
 * @return the block read from the cursor
 */
block_manager_block_t *block_manager_cursor_read(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_read_partial
 * reads only the first max_bytes of a block at cursor position
 * useful for reading header+key without reading large values
 * @param cursor the cursor to read from
 * @param max_bytes maximum bytes to read (0 = read full block)
 * @return the partial block read from the cursor
 */
block_manager_block_t *block_manager_cursor_read_partial(block_manager_cursor_t *cursor,
                                                         size_t max_bytes);

/**
 * block_manager_cursor_free
 * frees a cursor
 * @param cursor the cursor to free
 */
void block_manager_cursor_free(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_prev
 * moves the cursor to the previous block
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_prev(block_manager_cursor_t *cursor);

/**
 * block_manager_fsync_thread
 * fsync thread for block manager
 * @param arg the block manager
 * @return NULL
 */
void *block_manager_fsync_thread(void *arg);

/**
 * block_manager_truncate
 * truncates a block manager to 0 removing all blocks
 * @param bm the block manager to truncate
 * @return 0 if successful, -1 if not
 */
int block_manager_truncate(block_manager_t *bm);

/**
 * block_manager_last_modified
 * gets the last modified time of a block manager file
 * @param bm the block manager to get the last modified time of
 * @return the last modified time of the block manager
 */
time_t block_manager_last_modified(block_manager_t *bm);

/**
 * block_manager_count_blocks
 * counts the number of blocks in a block managed file
 * @param bm the block manager to count the blocks of
 * @return the number of blocks in the block manager
 */
int block_manager_count_blocks(block_manager_t *bm);

/**
 * block_manager_cursor_has_next
 * checks if the cursor has a next block
 * @param cursor the cursor to check
 * @return 1 if the cursor has a next block, 0 if not.  Can return -1 if error
 */
int block_manager_cursor_has_next(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_has_prev
 * checks if the cursor has a previous block
 * @param cursor the cursor to check
 * @return 1 if the cursor has a previous block, 0 if not.  Can return -1 if error
 */
int block_manager_cursor_has_prev(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_goto_last
 * moves the cursor to the last block
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_goto_last(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_goto
 * moves the cursor to a specific block
 * @param cursor the cursor to move
 * @param pos the position to move the cursor to
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_goto(block_manager_cursor_t *cursor, uint64_t pos);

/**
 * block_manager_cursor_goto_first
 * moves the cursor to the first block
 * @param cursor the cursor to move
 * @return 0 if successful, -1 if not
 */
int block_manager_cursor_goto_first(block_manager_cursor_t *cursor);

/**
 * block_manager_get_size
 * gets the total size of a block manager file
 * @param bm the block manager to get the size of
 * @param size the size of the block manager
 * @return 0 if successful, -1 if not
 */
int block_manager_get_size(block_manager_t *bm, uint64_t *size);

/**
 * block_manager_escalate_fsync
 * escalates an fsync to the underlying block manager file
 */
int block_manager_escalate_fsync(block_manager_t *bm);

/**
 * block_manager_cursor_at_last
 * checks if the cursor is at the last block
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the last block, 0 if not.  can return -1 if error
 */
int block_manager_cursor_at_last(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_at_first
 * checks if the cursor is at the first block
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the first block, 0 if not.  can return -1 if error
 */
int block_manager_cursor_at_first(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_at_second
 * checks if the cursor is at the second block from start
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the second block, 0 if not.  can return -1 if error
 */
int block_manager_cursor_at_second(block_manager_cursor_t *cursor);

/**
 * block_manager_validate_last_block
 * validates the integrity of the last block in a block manager file
 * returns 0 if the last block is valid, -1 if validation fails
 *
 *** if the validation fails, the file is truncated to the last valid block.
 */
int block_manager_validate_last_block(block_manager_t *bm);

/**
 * convert_sync_mode
 * converts TidesDB sync mode enum values to block manager sync mode enum values
 * This function provides compatibility between the public TidesDB API (which uses
 * TDB_SYNC_NONE/TDB_SYNC_FULL) and the internal block manager API (which uses
 * BLOCK_MANAGER_SYNC_NONE/BLOCK_MANAGER_TDB_SYNC_FULL)
 * @param tdb_sync_mode the TidesDB sync mode (TDB_SYNC_NONE=0, TDB_SYNC_FULL=1)
 * @return the corresponding block manager sync mode enum value
 */
block_manager_sync_mode_t convert_sync_mode(int tdb_sync_mode);

#endif /* __BLOCK_MANAGER_H__ */