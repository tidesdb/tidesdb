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
#include "../src/block_manager.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_block_manager_open()
{
    block_manager_t *bm;
    ASSERT_TRUE(block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) == 0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_NE(bm->fd, 0);
    ASSERT_EQ(strcmp(bm->file_path, "test.db"), 0);
    ASSERT_EQ(bm->sync_mode, TDB_SYNC_NONE);
    (void)block_manager_close(bm);

    remove("test.db"); /* remove created file */
    printf(GREEN "test_block_manager_open passed\n" RESET);
}

void test_block_manager_block_create()
{
    /* we setup a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block->size, size);

    /* we verify that the data is copied correctly */
    ASSERT_EQ(memcmp(block->data, data, size), 0);
    (void)block_manager_block_free(block);

    printf(GREEN "test_block_manager_block_create passed\n" RESET);
}

void test_block_manager_block_write()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_block_write passed\n" RESET);
}

void test_block_manager_block_write_close_reopen_read()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we use a cursor to read the block from the file */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);

    /* we verify that the block was read correctly */
    ASSERT_EQ(block->size, size);
    ASSERT_EQ(memcmp(block->data, data, size), 0);

    (void)block_manager_block_free(block);
    (void)block_manager_cursor_free(cursor);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we remove the file */
    remove("test.db");

    printf(GREEN "test_block_manager_block_write_close_reopen_read passed\n" RESET);
}

void test_block_manager_truncate()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    /* we truncate the file */
    ASSERT_TRUE(block_manager_truncate(bm) == 0);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we use a cursor to verify the file is empty */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL); /* we expect the block to be NULL */

    (void)block_manager_cursor_free(cursor);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_truncate passed\n" RESET);
}

void test_block_manager_cursor()
{
    /* we create a block manager, write a few blocks and verify forward and backward iteration */

    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        /* we set up a new block */
        uint64_t size = 10;
        char data[10];

        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL); /* we verify that the block was created successfully */

        /* now we write the block to the file */
        /* should not be -1 */
        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);

        (void)block_manager_block_free(block);
    }

    /* now we create a cursor */
    block_manager_cursor_t *cursor;

    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* we get first block from cursor should be the first block we wrote */
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }
    ASSERT_EQ(read_block->size, 10);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);

    (void)block_manager_block_free(read_block);

    /* we go next */
    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    ASSERT_EQ(read_block->size, 10);
    ASSERT_EQ(memcmp(read_block->data, "testdata1", 10), 0);

    (void)block_manager_block_free(read_block);

    /* we go next */
    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    ASSERT_EQ(read_block->size, 10);
    ASSERT_EQ(memcmp(read_block->data, "testdata2", 10), 0);

    (void)block_manager_block_free(read_block);

    /* we go back */
    ASSERT_TRUE(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    ASSERT_EQ(read_block->size, 10);
    ASSERT_EQ(memcmp(read_block->data, "testdata1", 10), 0);

    (void)block_manager_block_free(read_block);

    /* we go back */
    ASSERT_TRUE(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    ASSERT_EQ(read_block->size, 10);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);

    (void)block_manager_block_free(read_block);

    /* we free the cursor */
    (void)block_manager_cursor_free(cursor);

    /* we close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor passed\n" RESET);
}

void test_block_manager_count_blocks()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        printf("data: %s\n", data);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    ASSERT_TRUE(block_manager_count_blocks(bm) == 3);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_count_blocks passed\n" RESET);
}

void test_block_manager_cursor_goto_first()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return;
    }

    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);
    (void)block_manager_block_free(read_block);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_goto_first passed\n" RESET);
}

void test_block_manager_cursor_goto_last()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return;
    }

    ASSERT_TRUE(block_manager_cursor_goto_last(cursor) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);

    ASSERT_EQ(memcmp(read_block->data, "testdata2", 10), 0);
    (void)block_manager_block_free(read_block);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_goto_last passed\n" RESET);
}

void test_block_manager_cursor_has_next()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_next(cursor) == 1);

    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_next(cursor) == 1);

    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_next(cursor) == 1);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_has_next passed\n" RESET);
}

void test_block_manager_cursor_has_prev()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    ASSERT_TRUE(block_manager_cursor_goto_last(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_prev(cursor) == 1);

    ASSERT_TRUE(block_manager_cursor_prev(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_prev(cursor) == 1);

    ASSERT_TRUE(block_manager_cursor_prev(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_has_prev(cursor) == 0);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_has_prev passed\n" RESET);
}

void test_block_manager_cursor_position_checks()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we write 3 blocks */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* test at_first */
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_first(cursor) == 1);
    ASSERT_TRUE(block_manager_cursor_at_second(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_last(cursor) == 0);

    /* test at_second */
    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_first(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_second(cursor) == 1);
    ASSERT_TRUE(block_manager_cursor_at_last(cursor) == 0);

    /* test at_last */
    ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_first(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_second(cursor) == 0);
    ASSERT_TRUE(block_manager_cursor_at_last(cursor) == 1);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_position_checks passed\n" RESET);
}

void test_block_manager_get_size()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    uint64_t initial_size;
    ASSERT_TRUE(block_manager_get_size(bm, &initial_size) == 0);
    ASSERT_EQ(initial_size, BLOCK_MANAGER_HEADER_SIZE); /* file should be empty initially */

    /* we write some data and check size increases */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    uint64_t after_write_size;
    ASSERT_TRUE(block_manager_get_size(bm, &after_write_size) == 0);
    ASSERT_TRUE(after_write_size > 0);

    /* we trunc and verify size is 0 again */
    ASSERT_TRUE(block_manager_truncate(bm) == 0);

    uint64_t after_truncate_size;
    ASSERT_TRUE(block_manager_get_size(bm, &after_truncate_size) == 0);
    ASSERT_EQ(after_truncate_size, BLOCK_MANAGER_HEADER_SIZE);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_get_size passed\n" RESET);
}

void test_block_manager_seek_and_goto()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", TDB_SYNC_NONE, 0) != 0) return;

    /* we write 3 blocks */
    long block_offsets[3];
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        /* we save the offset for each block */
        block_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_TRUE(block_offsets[i] >= 0);
        (void)block_manager_block_free(block);
    }

    /* we test block_manager_cursor_goto with block_offsets */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* go to second block using its offset */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[1]) == 0);

    /* we read the block and verify */
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata1", 10), 0);
    (void)block_manager_block_free(read_block);

    /* go to third block using its offset */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[2]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata2", 10), 0);
    (void)block_manager_block_free(read_block);

    /* now go to first block */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[0]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);
    (void)block_manager_block_free(read_block);

    /* we free the cursor */
    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_seek_and_goto passed\n" RESET);
}

/** multithreaded tests */
/* shared block manager
 * for all threads **/
block_manager_t *bm;

/* mutex for thread-safe block manager operations */
pthread_mutex_t bm_mutex = PTHREAD_MUTEX_INITIALIZER;

/* number of blocks each writer will write */
#define BLOCKS_PER_WRITER 10

/* number of writer threads */
#define NUM_WRITERS 3

/* number of reader threads */
#define NUM_READERS 2

void *writer_thread(void *arg)
{
    int thread_id = *((int *)arg);

    for (int i = 0; i < BLOCKS_PER_WRITER; i++)
    {
        uint64_t size = 20;
        char data[20];
        snprintf(data, 20, "writer%d-block%d", thread_id, i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        (void)pthread_mutex_lock(&bm_mutex);

        long offset = block_manager_block_write(bm, block);
        ASSERT_NE(offset, -1);

        (void)pthread_mutex_unlock(&bm_mutex);

        printf("Writer %d wrote block %d: %s\n", thread_id, i, data);

        (void)block_manager_block_free(block);

        usleep((unsigned int)(rand() % 10000));  // NOLINT(cert-msc30-c,cert-msc50-cpp)
    }

    return NULL;
}

void *reader_thread(void *arg)
{
    int thread_id = *((int *)arg);

    /* we sleep a bit to let writers create some blocks first */
    usleep(50000);

    int read_count = 0;

    while (read_count < 10) /* each reader will read 10 blocks */
    {
        block_manager_cursor_t *cursor;

        /* acquire mutex
         * before initializing cursor and reading */
        (void)pthread_mutex_lock(&bm_mutex);

        if (block_manager_cursor_init(&cursor, bm) != 0)
        {
            (void)pthread_mutex_unlock(&bm_mutex);
            printf("Reader %d failed to initialize cursor\n", thread_id);
            break;
        }

        /* go to a random position (first, last, or specific position) */
        int pos_type = rand() % 3;

        if (pos_type == 0)
        {
            if (block_manager_cursor_goto_first(cursor) != 0)
            {
                (void)pthread_mutex_unlock(&bm_mutex);
                (void)block_manager_cursor_free(cursor);
                usleep(100000); /* we wait for more blocks */
                continue;
            }
        }
        else if (pos_type == 1)
        {
            if (block_manager_cursor_goto_last(cursor) != 0)
            {
                (void)pthread_mutex_unlock(&bm_mutex);
                (void)block_manager_cursor_free(cursor);
                usleep(100000); /* we wait for more blocks */
                continue;
            }
        }
        else
        {
            /* we count blocks to determine a valid position */
            int block_count = block_manager_count_blocks(bm);
            if (block_count <= 0)
            {
                pthread_mutex_unlock(&bm_mutex);
                block_manager_cursor_free(cursor);
                usleep(100000); /* we wait for more blocks */
                continue;
            }

            int random_block = rand() % block_count;

            (void)block_manager_cursor_goto_first(cursor);

            for (int i = 0; i < random_block; i++)
            {
                if (block_manager_cursor_next(cursor) != 0) break;
            }
        }

        block_manager_block_t *read_block = block_manager_cursor_read(cursor);

        if (read_block != NULL)
        {
            printf("Reader %d read: %.*s\n", thread_id, (int)read_block->size,
                   (char *)read_block->data);
            (void)block_manager_block_free(read_block);
            read_count++;
        }

        (void)block_manager_cursor_free(cursor);
        (void)pthread_mutex_unlock(&bm_mutex);

        /* we sleep a short random time to simulate
         * variable processing time */
        usleep((useconds_t)(rand() % 5000));  // NOLINT(cert-msc30-c,cert-msc50-cpp)
    }

    return NULL;
}

void test_block_manager_concurrent_rw()
{
    srand((unsigned int)time(NULL));  // NOLINT(cert-msc51-cpp) - acceptable for test code

    /* we initialize the block manager */
    ASSERT_TRUE(block_manager_open(&bm, "concurrent_test.db", TDB_SYNC_NONE, 0) == 0);

    /* we create thread IDs */
    pthread_t writer_threads[NUM_WRITERS];
    pthread_t reader_threads[NUM_READERS];

    int writer_ids[NUM_WRITERS];
    int reader_ids[NUM_READERS];

    /* we start writer threads */
    for (int i = 0; i < NUM_WRITERS; i++)
    {
        writer_ids[i] = i;
        ASSERT_TRUE(pthread_create(&writer_threads[i], NULL, writer_thread, &writer_ids[i]) == 0);
    }

    /*we start reader threads */
    for (int i = 0; i < NUM_READERS; i++)
    {
        reader_ids[i] = i;
        ASSERT_TRUE(pthread_create(&reader_threads[i], NULL, reader_thread, &reader_ids[i]) == 0);
    }

    /* we wait for all threads to complete */
    for (int i = 0; i < NUM_WRITERS; i++)
    {
        ASSERT_TRUE(pthread_join(writer_threads[i], NULL) == 0);
    }

    for (int i = 0; i < NUM_READERS; i++)
    {
        ASSERT_TRUE(pthread_join(reader_threads[i], NULL) == 0);
    }

    /* we verify final state */
    int final_block_count = block_manager_count_blocks(bm);
    printf("Final block count: %d (expected: %d)\n", final_block_count,
           NUM_WRITERS * BLOCKS_PER_WRITER);
    ASSERT_EQ(final_block_count, NUM_WRITERS * BLOCKS_PER_WRITER);

    printf("\nAll blocks in order:\n");
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    block_manager_block_t *block;
    int block_index = 0;
    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        printf("Block %d: %.*s\n", block_index++, (int)block->size, (char *)block->data);
        (void)block_manager_block_free(block);
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("concurrent_test.db");

    printf(GREEN "test_block_manager_concurrent_rw passed\n" RESET);
}

void test_block_manager_validate_last_block()
{
    printf("Testing block manager validation of last block...\n");

    /* first, create a block manager and write some valid blocks */
    block_manager_t *bm;
    ASSERT_TRUE(block_manager_open(&bm, "validate_test.db", TDB_SYNC_NONE, 0) == 0);

    /* we write 3 valid blocks */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        (void)block_manager_block_free(block);
    }

    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we now manually corrupt the file by appending just a size prefix without data */
    FILE *file = fopen("validate_test.db", "a+b");
    ASSERT_TRUE(file != NULL);

    /* we append just a size prefix (8 bytes) without the actual data */
    uint64_t corrupt_size = 100; /* size that's larger than what we'll actually write */
    ASSERT_TRUE(fwrite(&corrupt_size, sizeof(uint64_t), 1, file) == 1);

    /* we close the file */
    fclose(file);

    /* we get the file size after corruption */
    struct stat st;
    ASSERT_TRUE(stat("validate_test.db", &st) == 0);
    uint64_t corrupted_size = (uint64_t)st.st_size;
    printf("File size after corruption: %lu bytes\n", corrupted_size);

    /* now reopen the block manager, which should validate and fix the last block */
    ASSERT_TRUE(block_manager_open(&bm, "validate_test.db", TDB_SYNC_NONE, 0) == 0);

    /* we get the file size after validation/repair */
    ASSERT_TRUE(stat("validate_test.db", &st) == 0);
    uint64_t repaired_size = (uint64_t)st.st_size;
    printf("File size after repair: %lu bytes\n", repaired_size);

    /* the repaired size should be less than the corrupted size */
    ASSERT_TRUE(repaired_size < corrupted_size);

    /* we verify that exactly 3 blocks can be read */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* we go to the first block */
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    /* we read and verify all blocks */
    int block_count = 0;
    for (int i = 0; i < 3; i++)
    {
        /* read the current block */
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(block != NULL);

        /* verify the block data */
        char expected[10];
        snprintf(expected, 10, "testdata%d", i);
        ASSERT_EQ(block->size, 10);
        ASSERT_EQ(memcmp(block->data, expected, 10), 0);

        (void)block_manager_block_free(block);
        block_count++;

        /* we move to the next block if not the last one */
        if (i < 2)
        {
            ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
        }
    }

    ASSERT_EQ(block_count, 3);

    /* we verify there are no more blocks (the corrupted one was removed) */
    int at_last = block_manager_cursor_at_last(cursor);
    printf("Cursor at last block: %d\n", at_last);
    ASSERT_EQ(at_last, 1); /* should be at the last block */

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("validate_test.db");

    printf(GREEN "test_block_manager_validate_last_block passed\n" RESET);
}

void test_block_manager_validation_edge_cases()
{
    printf("Testing block manager validation edge cases...\n");

    block_manager_t *bm;

    /* 1 opening a fresh empty database */
    (void)remove("empty_test.db");
    ASSERT_TRUE(block_manager_open(&bm, "empty_test.db", TDB_SYNC_NONE, 0) == 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* 2 opening an existing empty database */
    ASSERT_TRUE(block_manager_open(&bm, "empty_test.db", TDB_SYNC_NONE, 0) == 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* 3 test with some data and validation */
    if (block_manager_open(&bm, "empty_test.db", TDB_SYNC_NONE, 0) == 0)
    {
        uint64_t size = 10;
        char data[10] = "testdata0";

        block_manager_block_t *block = block_manager_block_create(size, data);
        if (block != NULL)
        {
            block_manager_block_write(bm, block);
            (void)block_manager_block_free(block);
        }

        ASSERT_TRUE(block_manager_close(bm) == 0);
    }

    /* Cleanup */
    (void)remove("empty_test.db");

    printf(GREEN "test_block_manager_validation_edge_cases passed\n" RESET);
}

void test_block_manager_open_safety()
{
    printf("Testing block manager open with very long path...\n");

    block_manager_t *bm;

    /* we create a path name that would exceed the buffer */
    char long_path[1024] = "test_";
    for (int i = 0; i < 50; i++)
    {
        if (strlen(long_path) + strlen("very_long_directory_name_") < sizeof(long_path) - 1)
        {
            strcat(long_path, "very_long_directory_name_");
        }
        else
        {
            break;
        }
    }
    strcat(long_path, ".db");

    /* should not crash with buffer overflow, even with long path */
    int result = block_manager_open(&bm, long_path, TDB_SYNC_NONE, 0);

    /* might fail due to path length limits, but shouldn't crash */
    if (result == 0)
    {
        ASSERT_TRUE(block_manager_close(bm) == 0);
        remove(long_path); /* try to remove, might fail */
    }

    printf(GREEN "test_block_manager_open_safety passed\n" RESET);
}

/** benchmark tests */

/* number of blocks to use in benchmark */
#define NUM_BLOCKS 100000

/* block size for benchmark (bytes) */
#define BLOCK_SIZE 256

void benchmark_block_manager()
{
    printf(BOLDWHITE "Running block manager benchmark...\n" RESET);

    block_manager_t *bm;
    ASSERT_TRUE(block_manager_open(&bm, "benchmark.db", TDB_SYNC_NONE, 0) == 0);

    uint8_t **block_data = malloc(NUM_BLOCKS * sizeof(uint8_t *));
    ASSERT_TRUE(block_data != NULL);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_data[i] = malloc(BLOCK_SIZE);
        ASSERT_TRUE(block_data[i] != NULL);

        /* we fill with random data + sequential identifier */
        for (int j = 0; j < BLOCK_SIZE - 20; j++)
        {
            block_data[i][j] = (uint8_t)(rand() % 256);  // NOLINT(cert-msc30-c,cert-msc50-cpp)
        }

        /* we add identifier at the end of each block for verification */
        sprintf((char *)(block_data[i] + BLOCK_SIZE - 20), "block_%d", i);
    }

    printf(BOLDWHITE "Benchmark 1: Sequential Write Performance\n" RESET);

    long *block_offsets = malloc(NUM_BLOCKS * sizeof(long));
    ASSERT_TRUE(block_offsets != NULL);

    clock_t start_write = clock();

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_manager_block_t *block = block_manager_block_create(BLOCK_SIZE, block_data[i]);
        ASSERT_TRUE(block != NULL);

        block_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_NE(block_offsets[i], -1);

        (void)block_manager_block_free(block);
    }

    clock_t end_write = clock();
    double time_spent_write = (double)(end_write - start_write) / CLOCKS_PER_SEC;

    printf(CYAN "Writing %d blocks (%d bytes each) took %.3f seconds\n", NUM_BLOCKS, BLOCK_SIZE,
           time_spent_write);
    printf("Write throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_write);
    printf("Write throughput: %.2f MB/second\n" RESET,
           (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_write * 1024 * 1024));

    uint64_t file_size;
    ASSERT_TRUE(block_manager_get_size(bm, &file_size) == 0);
    printf(BOLDWHITE "Database file size: %.2f MB\n" RESET, (float)file_size / (1024 * 1024));

    printf(BOLDWHITE "Benchmark 2: Sequential Read Performance\n" RESET);

    /* we reopen the database to ensure data is read from disk */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "benchmark.db", TDB_SYNC_NONE, 0) == 0);

    clock_t start_read_seq = clock();

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    int blocks_read = 0;
    block_manager_block_t *block;

    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        /* we verify block identifier */
        char expected_id[20];
        sprintf(expected_id, "block_%d", blocks_read);

        ASSERT_TRUE(
            memcmp((char *)(block->data + BLOCK_SIZE - 20), expected_id, strlen(expected_id)) == 0);

        (void)block_manager_block_free(block);
        blocks_read++;

        if (block_manager_cursor_next(cursor) != 0 || blocks_read >= NUM_BLOCKS)
        {
            break;
        }
    }

    ASSERT_EQ(blocks_read, NUM_BLOCKS);
    (void)block_manager_cursor_free(cursor);

    clock_t end_read_seq = clock();
    double time_spent_read_seq = (double)(end_read_seq - start_read_seq) / CLOCKS_PER_SEC;

    printf(CYAN "Sequentially reading %d blocks took %.3f seconds\n", NUM_BLOCKS,
           time_spent_read_seq);
    printf("Sequential read throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_read_seq);
    printf("Sequential read throughput: %.2f MB/second\n" RESET,
           (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_seq * 1024 * 1024));

    printf(BOLDWHITE "Benchmark 3: Random Read Performance\n" RESET);

    clock_t start_read_random = clock();

    /* we shuffle the offsets array to randomize access */
    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        int j =
            rand() % NUM_BLOCKS;  // NOLINT(cert-msc30-c,cert-msc50-cpp) - acceptable for test code
        long temp = block_offsets[i];
        block_offsets[i] = block_offsets[j];
        block_offsets[j] = temp;
    }

    /* init a cursor for random access */
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        /* we seek to the random offset */
        ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[i]) == 0);

        block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(block != NULL);

        /* no need to verify the block content for this benchmark */
        (void)block_manager_block_free(block);
    }

    (void)block_manager_cursor_free(cursor);

    clock_t end_read_random = clock();
    double time_spent_read_random = (double)(end_read_random - start_read_random) / CLOCKS_PER_SEC;

    printf(CYAN "Randomly reading %d blocks took %.3f seconds\n", NUM_BLOCKS,
           time_spent_read_random);
    printf("Random read throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_read_random);
    printf("Random read throughput: %.2f MB/second\n" RESET,
           (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_random * 1024 * 1024));

    printf(BOLDWHITE "Benchmark 4: Block Count Performance\n" RESET);

    clock_t start_count = clock();
    int count = block_manager_count_blocks(bm);
    clock_t end_count = clock();

    double time_spent_count = (double)(end_count - start_count) / CLOCKS_PER_SEC;

    printf(CYAN "Counting %d blocks took %.3f seconds\n" RESET, count, time_spent_count);
    ASSERT_EQ(count, NUM_BLOCKS);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        free(block_data[i]);
    }
    free(block_data);
    free(block_offsets);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("benchmark.db");

    printf(GREEN "benchmark_block_manager completed successfully\n" RESET);
}

int main(void)
{
    RUN_TEST(test_block_manager_open, tests_passed);
    RUN_TEST(test_block_manager_block_create, tests_passed);
    RUN_TEST(test_block_manager_block_write, tests_passed);
    RUN_TEST(test_block_manager_block_write_close_reopen_read, tests_passed);
    RUN_TEST(test_block_manager_truncate, tests_passed);
    RUN_TEST(test_block_manager_count_blocks, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_first, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_next, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_prev, tests_passed);
    RUN_TEST(test_block_manager_cursor_position_checks, tests_passed);
    RUN_TEST(test_block_manager_open_safety, tests_passed);
    RUN_TEST(test_block_manager_validate_last_block, tests_passed);
    RUN_TEST(test_block_manager_get_size, tests_passed);
    RUN_TEST(test_block_manager_cursor, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_last, tests_passed);
    RUN_TEST(test_block_manager_seek_and_goto, tests_passed);
    RUN_TEST(test_block_manager_validation_edge_cases, tests_passed);
    RUN_TEST(test_block_manager_concurrent_rw, tests_passed);

    srand((unsigned int)time(NULL));  // NOLINT(cert-msc51-cpp) - acceptable for test code
    RUN_TEST(benchmark_block_manager, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}