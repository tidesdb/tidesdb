/*
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

/* more time equals more results, but remember to take breaks to refresh your mind. */

#define MAX_FILE_PATH_LENGTH 1024 /* max file path length for block manager file(s) */

/**
 * block_manager_t
 * block manager struct
 * used for block managers in TidesDB
 * @param file the file the block manager is managing
 * @param file_path the path of the file
 * @param fsync_thread the fsync thread
 * @param fsync_interval the fsync interval in seconds
 * @param stop_fsync_thread flag to stop fsync thread
 * @param mutex mutex for safe concurrent access
 */
typedef struct
{
    FILE *file;
    char file_path[MAX_FILE_PATH_LENGTH];
    pthread_t fsync_thread;
    float fsync_interval;
    int stop_fsync_thread;
    pthread_mutex_t mutex;
} block_manager_t;

/**
 * block_t
 * block struct
 * used for blocks in TidesDB
 * @param size the size of the data in the block
 * @param data the data in the block
 */
typedef struct
{
    uint64_t size;
    void *data;
} block_manager_block_t;

/**
 * block_cursor_t
 * block cursor struct
 * used for block cursors in TidesDB
 * @param bm the block manager
 * @param file private file handle for cursor operations
 * @param current_pos the current position of the cursor
 * @param current_block_size the size of the current block
 */
typedef struct
{
    block_manager_t *bm;
    FILE *file;
    uint64_t current_pos;
    uint64_t current_block_size;
} block_manager_cursor_t;

/**
 * block_manager_open
 * opens a block manager
 * @param bm the block manager to open
 * @param file_path the path of the file
 * @param fsync_interval the fsync interval
 * @return 0 if successful, -1 if not
 */
int block_manager_open(block_manager_t **bm, const char *file_path, float fsync_interval);

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
 * block_manager_block_write
 * writes a block to a file
 * @param bm the block manager to write the block to
 * @param block the block to write
 * @param lock whether to lock the block manager or not
 * @return block offset if successful, -1 if not
 */
long block_manager_block_write(block_manager_t *bm, block_manager_block_t *block, uint8_t lock);

/**
 * block_manager_block_read
 * reads a block from a file at current file position
 * @param bm the block manager to read the block from
 * @return the block read from the file
 */
block_manager_block_t *block_manager_block_read(block_manager_t *bm);

/**
 * block_manager_block_free
 * frees a block
 * @param block the block to free
 */
void block_manager_block_free(block_manager_block_t *block);

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
 * block_manager_seek
 * seeks to a position in a block manager
 * @param bm the block manager to seek in
 * @param pos the position to seek to
 * @return 0 if successful, -1 if not
 */
int block_manager_seek(block_manager_t *bm, uint64_t pos);

/**
 * block_manager_escalate_fsync
 * escalates an fsync to the underlying block manager file
 */
int block_manager_escalate_fsync(block_manager_t *bm);

/**
 * block_manager_cursor_at_last
 * checks if the cursor is at the last block
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the last block, 0 if not.  Can return -1 if error
 */
int block_manager_cursor_at_last(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_at_first
 * checks if the cursor is at the first block
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the first block, 0 if not.  Can return -1 if error
 */
int block_manager_cursor_at_first(block_manager_cursor_t *cursor);

/**
 * block_manager_cursor_at_second
 * checks if the cursor is at the second block from start
 * @param cursor the cursor to check
 * @return 1 if the cursor is at the second block, 0 if not.  Can return -1 if error
 */
int block_manager_cursor_at_second(block_manager_cursor_t *cursor);

/**
 * block_manager_lock
 * locks the block manager mutex
 * @param bm the block manager to lock
 * @return 0 if successful, -1 if not
 */
int block_manager_lock(block_manager_t *bm);

/**
 * block_manager_unlock
 * unlocks the block manager mutex
 * @param bm the block manager to unlock
 * @return 0 if successful, -1 if not
 */
int block_manager_unlock(block_manager_t *bm);

#endif /* __BLOCK_MANAGER_H__ */