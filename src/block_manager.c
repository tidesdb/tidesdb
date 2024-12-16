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
#include "block_manager.h"

int block_manager_open(block_manager_t **bm, const char *file_path, float fsync_interval)
{
    /* we allocate memory for the new block manager */
    (*bm) = malloc(sizeof(block_manager_t));
    if (!(*bm)) return -1; /* if allocation fails, return -1 */

    (*bm)->file = fopen(file_path, "a+b"); /* we open the desired file in append-binary mode */
    if (!(*bm)->file) return -1;

    /* we copy the file path to the block manager */
    strcpy((*bm)->file_path, file_path);

    /* we set the fsync interval */
    (*bm)->fsync_interval = fsync_interval;

    /* we set the stop fsync thread flag to 0 */
    (*bm)->stop_fsync_thread = 0;

    /* we create and start the fsync thread */
    if (pthread_create(&(*bm)->fsync_thread, NULL, block_manager_fsync_thread, *bm) != 0) return -1;
    return 0;
}

int block_manager_close(block_manager_t *bm)
{
    /* we stop the fsync thread */
    bm->stop_fsync_thread = 1;

    /* we flush the file to disk */
    fsync(fileno(bm->file)); /* flush file to disk */

    /* we join the fsync thread */
    if (pthread_join(bm->fsync_thread, NULL) != 0) return -1;

    /* we close the file */
    if (fclose(bm->file) != 0) return -1;

    /* we free the block manager */
    free(bm);
    bm = NULL; /* we set the pointer to NULL */
    return 0;
}

block_manager_block_t *block_manager_block_create(uint64_t size, void *data)
{
    /* we allocate memory for the new block */
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL; /* if allocation fails, return NULL */

    /* we set the size of the block */
    block->size = size;

    /* we allocate memory for the data of the block */
    block->data = malloc(size);
    if (!block->data) /* if allocation fails, free the block and return NULL */
    {
        free(block);
        block = NULL;
        return NULL;
    }

    /* we copy the data to the block */
    memcpy(block->data, data, size);
    return block;
}

int block_manager_block_write(block_manager_t *bm, block_manager_block_t *block)
{
    /* seek to end of file */
    if (fseek(bm->file, 0, SEEK_END) != 0) return -1;

    /* write the size of the block */
    if (fwrite(&block->size, sizeof(uint64_t), 1, bm->file) != 1) return -1;

    /* write the data of the block */
    if (fwrite(block->data, block->size, 1, bm->file) != 1) return -1;
    return 0;
}

block_manager_block_t *block_manager_block_read(block_manager_t *bm)
{
    /* we allocate memory for the new block */
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL; /* if allocation fails, return NULL */

    /* we read the size of the block */
    if (fread(&block->size, sizeof(uint64_t), 1, bm->file) != 1)
    {
        free(block);
        block = NULL;
        return NULL;
    }

    /* we allocate memory for the data of the block */
    block->data = malloc(block->size);
    if (!block->data)
    {
        free(block);
        block = NULL;
        return NULL;
    }

    /* we read the data of the block */
    if (fread(block->data, block->size, 1, bm->file) != 1)
    {
        free(block->data);
        free(block);
        block = NULL;
        return NULL;
    }

    return block;
}

void block_manager_block_free(block_manager_block_t *block)
{
    /* we free the data and the block */
    if (block)
    {
        free(block->data);
        free(block);
        block = NULL;
    }
}

int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm)
{
    /* we allocate memory for the new cursor */
    (*cursor) = malloc(sizeof(block_manager_cursor_t));
    if (!(*cursor)) return -1; /* if allocation fails, return -1 */

    /* seek to beginning of file */
    if (fseek(bm->file, 0, SEEK_SET) != 0) return -1;

    /* we set the block manager of the cursor */
    (*cursor)->bm = bm;
    if (!(*cursor)->bm) return -1; /* if the block manager is NULL, return -1 */
    (*cursor)->current_pos = 0;    /* we set the current position to 0 */
    return 0;
}

int block_manager_cursor_next(block_manager_cursor_t *cursor)
{
    uint64_t block_size; /* we declare a variable to store the block size */
    if (fseek(cursor->bm->file, cursor->current_pos, SEEK_SET) != 0)
        return -1; /* we move the file pointer to the current position */

    /* we read the size of the next block */
    if (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) != 1)
    {
        if (feof(cursor->bm->file)) return 1; /* if we reached the end of the file, return 1 */
        return -1;
    }

    /* we set the current block size */
    cursor->current_block_size = block_size;

    /* we move the file pointer to the beginning of the next block */
    if (fseek(cursor->bm->file, cursor->current_pos + sizeof(uint64_t), SEEK_SET) != 0) return -1;

    /* we update the current position */
    cursor->current_pos += sizeof(uint64_t) + block_size;

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    /* save the current file pointer position */
    long original_pos = ftell(cursor->bm->file);
    if (original_pos == -1) return -1;

    /* move the file pointer to the current position */
    if (fseek(cursor->bm->file, cursor->current_pos, SEEK_SET) != 0) return -1;

    /* read the size of the next block */
    uint64_t block_size;
    if (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) != 1)
    {
        if (feof(cursor->bm->file)) return 0; /* if we reached the end of the file, return 0 */
        return -1;
    }

    /* restore the original file pointer position */
    if (fseek(cursor->bm->file, original_pos, SEEK_SET) != 0) return -1;

    return 1;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (cursor == NULL || cursor->bm == NULL)
        return -1; /* if the cursor or the block manager is NULL, return -1 */

    /* seek to the beginning of the file */
    if (fseek(cursor->bm->file, 0, SEEK_SET) != 0) return -1;

    uint64_t block_size;
    long last_pos = 0;
    long current_pos = 0;

    /* traverse through each block until the end of the file */
    while (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) == 1)
    {
        last_pos = current_pos;
        current_pos += sizeof(uint64_t) + block_size;

        /* move the file pointer to the next block */
        if (fseek(cursor->bm->file, block_size, SEEK_CUR) != 0) return -1;
    }

    /* update the cursor position and block size */
    cursor->current_pos = last_pos;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_goto_first(block_manager_cursor_t *cursor)
{
    if (cursor == NULL || cursor->bm == NULL) return -1;

    /* move to the beginning of the file */
    if (fseek(cursor->bm->file, 0, SEEK_SET) != 0) return -1;

    /* read the size of the first block */
    uint64_t block_size;
    if (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) != 1) return -1;

    /* update the cursor position */
    cursor->current_pos = 0;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_has_prev(block_manager_cursor_t *cursor)
{
    /* save the current file pointer position */
    long original_pos = ftell(cursor->bm->file);
    if (original_pos == -1) return -1;

    /* if we are at the beginning of the file, there is no previous block */
    if (cursor->current_pos == 0) return 0;

    /* move the file pointer to the position of the previous block size */
    if (fseek(cursor->bm->file, cursor->current_pos - sizeof(uint64_t), SEEK_SET) != 0) return -1;

    /* read the size of the previous block */
    uint64_t block_size;
    if (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) != 1) return -1;

    /* restore the original file pointer position */
    if (fseek(cursor->bm->file, original_pos, SEEK_SET) != 0) return -1;

    return 1;
}

int block_manager_cursor_prev(block_manager_cursor_t *cursor)
{
    /* we go back current block size + sizeof(uint64_t) */
    /* we get and set the current block size */
    if (cursor->current_pos == 0)
        return -1; /* we can't go back if we are at the beginning of the file */

    /* we move the file pointer to the start of the previous block */
    if (fseek(cursor->bm->file, sizeof(uint64_t) + cursor->current_block_size, SEEK_SET) != 0)
        return -1;

    uint64_t block_size;
    if (fread(&block_size, sizeof(uint64_t), 1, cursor->bm->file) != 1)
        return -1; /* we read the size of the previous block */

    /* we update the current position to the start of the previous block */
    cursor->current_pos -= (sizeof(uint64_t) + block_size);
    cursor->current_block_size = block_size;

    return 0;
}

block_manager_block_t *block_manager_cursor_read(block_manager_cursor_t *cursor)
{
    if (cursor == NULL) return NULL; /* if the cursor is NULL, return NULL */

    /* we move the file pointer to the current position */
    if (fseek(cursor->bm->file, cursor->current_pos, SEEK_SET) != 0) return NULL;
    return block_manager_block_read(cursor->bm); /* we read the block at the current position */
}

void block_manager_cursor_free(block_manager_cursor_t *cursor)
{
    /* we free the cursor */
    if (cursor)
    {
        if (cursor->bm) cursor->bm = NULL;

        free(cursor);
        cursor = NULL;
    }
}

void *block_manager_fsync_thread(void *arg)
{
    /* we cast the argument to a block manager */
    block_manager_t *bm = arg;
    /* we fsync the file every fsync interval */
    while (bm->stop_fsync_thread == 0)
    {
        sleep(bm->fsync_interval);
        fsync(fileno(bm->file));
    }
    return NULL;
}

int block_manager_truncate(block_manager_t *bm)
{
    /* we close the file */
    if (fclose(bm->file) != 0) return -1;

    /* we truncate the file */
    if (truncate(bm->file_path, 0) != 0) return -1;

    /* we open the file again */
    bm->file = fopen(bm->file_path, "a+b");
    if (!bm->file) return -1;
    return 0;
}

time_t block_manager_last_modified(block_manager_t *bm)
{
    struct stat st;
    if (stat(bm->file_path, &st) != 0) return -1;
    return st.st_mtime;
}

int block_manager_count_blocks(block_manager_t *bm)
{
    block_manager_cursor_t *cursor;
    int count = 0;

    if (block_manager_cursor_init(&cursor, bm) != 0) return -1;

    while (block_manager_cursor_next(cursor) == 0)
    {
        count++;
    }

    block_manager_cursor_free(cursor);
    return count;
}