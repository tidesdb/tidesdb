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

#include "../src/block_manager.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_block_manager_open()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_NE(bm->fd, 0);
    ASSERT_EQ(strcmp(bm->file_path, "test.db"), 0);
    ASSERT_EQ(bm->sync_mode, BLOCK_MANAGER_SYNC_NONE);
    (void)block_manager_close(bm);

    remove("test.db");
}

void test_block_manager_block_create()
{
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block->size, size);

    ASSERT_EQ(memcmp(block->data, data, size), 0);
    (void)block_manager_block_free(block);
}

void test_block_manager_block_write()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);

    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    (void)remove("test.db");
}

void test_block_manager_block_write_close_reopen_read()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);

    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);

    ASSERT_EQ(block->size, size);
    ASSERT_EQ(memcmp(block->data, data, size), 0);

    (void)block_manager_block_free(block);
    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    remove("test.db");
}

void test_block_manager_truncate()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);

    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);

    (void)block_manager_block_free(block);

    ASSERT_TRUE(block_manager_truncate(bm) == 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL); /* we expect the block to be NULL */

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    (void)remove("test.db");
}

void test_block_manager_cursor()
{
    /* we create a block manager, write a few blocks and verify forward and backward iteration */

    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    (void)remove("test.db");
}

void test_block_manager_count_blocks()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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

    ASSERT_TRUE(block_manager_count_blocks(bm) == 3);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");
}

void test_block_manager_cursor_goto_first()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_cursor_goto_last()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_cursor_has_next()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_cursor_has_prev()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_cursor_position_checks()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_get_size()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
}

void test_block_manager_seek_and_goto()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, "test.db", BLOCK_MANAGER_SYNC_NONE) != 0) return;

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

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test.db");
}

block_manager_t *bm = NULL;

pthread_mutex_t bm_mutex = PTHREAD_MUTEX_INITIALIZER;
#define BLOCKS_PER_WRITER 10
#define NUM_WRITERS       3
#define NUM_READERS       2

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

        (void)block_manager_block_free(block);

        usleep((unsigned int)(rand() % 10000)); /* NOLINT(cert-msc30-c,cert-msc50-cpp) */
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
            (void)block_manager_block_free(read_block);
            read_count++;
        }

        (void)block_manager_cursor_free(cursor);
        (void)pthread_mutex_unlock(&bm_mutex);

        /* we sleep a short random time to simulate variable processing time */
        usleep(rand() % 5000); /* 0-5ms */
    }

    return NULL;
}

void test_block_manager_concurrent_rw()
{
    srand((unsigned int)time(NULL)); /* NOLINT(cert-msc51-cpp) -- acceptable for test code */

    ASSERT_TRUE(block_manager_open(&bm, "concurrent_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    pthread_t writer_threads[NUM_WRITERS];
    pthread_t reader_threads[NUM_READERS];

    int writer_ids[NUM_WRITERS];
    int reader_ids[NUM_READERS];

    for (int i = 0; i < NUM_WRITERS; i++)
    {
        writer_ids[i] = i;
        ASSERT_TRUE(pthread_create(&writer_threads[i], NULL, writer_thread, &writer_ids[i]) == 0);
    }

    for (int i = 0; i < NUM_READERS; i++)
    {
        reader_ids[i] = i;
        ASSERT_TRUE(pthread_create(&reader_threads[i], NULL, reader_thread, &reader_ids[i]) == 0);
    }

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
    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        (void)block_manager_block_free(block);
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("concurrent_test.db");
}

void test_block_manager_validate_last_block()
{
    block_manager_t *bm = NULL;
    (void)remove("validate_test.db");
    ASSERT_TRUE(block_manager_open(&bm, "validate_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);

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

    /* ensure all writes are flushed to disk */
    block_manager_escalate_fsync(bm);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we now manually corrupt the file by appending just a size prefix without data */
    FILE *file = fopen("validate_test.db", "a+b");
    ASSERT_TRUE(file != NULL);

    /* we append just a size prefix (4 bytes) without the actual data */
    /* must use little-endian encoding to match block manager's format */
    uint32_t corrupt_size = 100; /* size that's larger than what we'll actually write */
    uint8_t size_buf[4];
    encode_uint32_le_compat(size_buf, corrupt_size);
    ASSERT_TRUE(fwrite(size_buf, sizeof(size_buf), 1, file) == 1);

    fclose(file);

    /* we get the file size after corruption */
    struct stat st;
    ASSERT_TRUE(stat("validate_test.db", &st) == 0);
    uint64_t corrupted_size = (uint64_t)st.st_size;
    printf("File size after corruption: %" PRIu64 " bytes\n", corrupted_size);

    /* now reopen the block manager and explicitly validate (permissive mode) */
    ASSERT_TRUE(block_manager_open(&bm, "validate_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_validate_last_block(bm, 0) ==
                0); /* permissive, truncate corruption */

    /* we get the file size after validation/repair */
    ASSERT_TRUE(stat("validate_test.db", &st) == 0);
    uint64_t repaired_size = (uint64_t)st.st_size;
    printf("File size after repair: %" PRIu64 " bytes\n", repaired_size);

    /* the repaired size should be less than the corrupted size */
    ASSERT_TRUE(repaired_size < corrupted_size);

    /* we verify that exactly 3 blocks can be read */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    /* we read and verify all blocks */
    int block_count = 0;
    for (int i = 0; i < 3; i++)
    {
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

    int at_last = block_manager_cursor_at_last(cursor);
    printf("Cursor at last block: %d\n", at_last);
    ASSERT_EQ(at_last, 1); /* should be at the last block */

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("validate_test.db");
}

void test_block_manager_validation_edge_cases()
{
    block_manager_t *bm = NULL;

    (void)remove("empty_test.db");
    ASSERT_TRUE(block_manager_open(&bm, "empty_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* opening an existing empty database */
    ASSERT_TRUE(block_manager_open(&bm, "empty_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* test with some data and validation */
    if (block_manager_open(&bm, "empty_test.db", BLOCK_MANAGER_SYNC_NONE) == 0)
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

    (void)remove("empty_test.db");
}

void test_block_manager_open_safety()
{
    block_manager_t *bm = NULL;

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
    int result = block_manager_open(&bm, long_path, BLOCK_MANAGER_SYNC_NONE);

    /* might fail due to path length limits, but shouldn't crash */
    if (result == 0)
    {
        ASSERT_TRUE(block_manager_close(bm) == 0);
        remove(long_path); /* try to remove, might fail */
    }
}

#define NUM_BLOCKS 100000
#define BLOCK_SIZE 256

void benchmark_block_manager()
{
    block_manager_t *bm = NULL;
    (void)remove("benchmark.db");
    ASSERT_TRUE(block_manager_open(&bm, "benchmark.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    uint8_t **block_data = malloc(NUM_BLOCKS * sizeof(uint8_t *));
    ASSERT_TRUE(block_data != NULL);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_data[i] = malloc(BLOCK_SIZE);
        ASSERT_TRUE(block_data[i] != NULL);

        /* we fill with random data + sequential identifier */
        for (int j = 0; j < BLOCK_SIZE - 20; j++)
        {
            block_data[i][j] = (uint8_t)(rand() % 256); /* NOLINT(cert-msc30-c,cert-msc50-cpp) */
        }

        /* we add identifier at the end of each block for verification */
        snprintf((char *)(block_data[i] + BLOCK_SIZE - 20), 20, "block_%d", i);
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
    if (time_spent_write > 0.0)
    {
        printf("Write throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_write);
        printf("Write throughput: %.2f MB/second\n" RESET,
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_write * 1024 * 1024));
    }
    else
    {
        printf("Write throughput: N/A (completed too fast to measure)\n" RESET);
    }

    uint64_t file_size;
    ASSERT_TRUE(block_manager_get_size(bm, &file_size) == 0);
    printf(BOLDWHITE "Database file size: %.2f MB\n" RESET, (float)file_size / (1024 * 1024));

    printf(BOLDWHITE "Benchmark 2: Sequential Read Performance\n" RESET);

    /* we reopen the database to ensure data is read from disk */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "benchmark.db", BLOCK_MANAGER_SYNC_NONE) == 0);

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
        snprintf(expected_id, sizeof(expected_id), "block_%d", blocks_read);

        ASSERT_TRUE(
            memcmp((char *)block->data + BLOCK_SIZE - 20, expected_id, strlen(expected_id)) == 0);

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
    if (time_spent_read_seq > 0.0)
    {
        printf("Sequential read throughput: %.2f blocks/second\n",
               NUM_BLOCKS / time_spent_read_seq);
        printf("Sequential read throughput: %.2f MB/second\n" RESET,
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_seq * 1024 * 1024));
    }
    else
    {
        printf("Sequential read throughput: N/A (completed too fast to measure)\n" RESET);
    }

    printf(BOLDWHITE "Benchmark 3: Random Read Performance\n" RESET);

    clock_t start_read_random = clock();

    /* we shuffle the offsets array to randomize access */
    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        int j = rand() % NUM_BLOCKS; /* NOLINT(cert-msc30-c,cert-msc50-cpp) */
        long temp = block_offsets[i];
        block_offsets[i] = block_offsets[j];
        block_offsets[j] = temp;
    }

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
    if (time_spent_read_random > 0.0)
    {
        printf("Random read throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_read_random);
        printf("Random read throughput: %.2f MB/second\n" RESET,
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_random * 1024 * 1024));
    }
    else
    {
        printf("Random read throughput: N/A (completed too fast to measure)\n" RESET);
    }

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
}

typedef struct
{
    block_manager_t *bm;
    int thread_id;
    int blocks_per_thread;
    double elapsed_time;
} parallel_write_context_t;

void *parallel_write_worker(void *arg)
{
    parallel_write_context_t *ctx = (parallel_write_context_t *)arg;
    struct timespec start, end;

    clock_gettime(0, &start);

    for (int i = 0; i < ctx->blocks_per_thread; i++)
    {
        char data[256];
        snprintf(data, sizeof(data), "thread%d-block%d", ctx->thread_id, i);

        block_manager_block_t *block =
            block_manager_block_create(strlen(data) + 1, (uint8_t *)data);
        if (block)
        {
            block_manager_block_write(ctx->bm, block);
            block_manager_block_free(block);
        }
    }

    clock_gettime(0, &end);
    ctx->elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return NULL;
}

void test_block_manager_sync_modes()
{
    /* test SYNC_NONE */
    block_manager_t *bm_none = NULL;
    ASSERT_EQ(block_manager_open(&bm_none, "test_sync_none.db", BLOCK_MANAGER_SYNC_NONE), 0);

    block_manager_block_t *block = block_manager_block_create(10, (uint8_t *)"test_data");
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm_none, block);
    ASSERT_TRUE(offset != -1);

    block_manager_block_free(block);
    block_manager_close(bm_none);
    remove("test_sync_none.db");

    /* test SYNC_FULL */
    block_manager_t *bm_full = NULL;
    ASSERT_EQ(block_manager_open(&bm_full, "test_sync_full.db", BLOCK_MANAGER_SYNC_FULL), 0);

    block = block_manager_block_create(10, (uint8_t *)"test_data");
    ASSERT_TRUE(block != NULL);
    offset = block_manager_block_write(bm_full, block);
    ASSERT_TRUE(offset != -1);

    block_manager_block_free(block);
    block_manager_close(bm_full);
    remove("test_sync_full.db");
}

void test_block_manager_empty_block()
{
    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, "test_empty.db", BLOCK_MANAGER_SYNC_NONE), 0);

    block_manager_block_t *block = block_manager_block_create(0, NULL);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);

    if (offset != -1)
    {
        block_manager_cursor_t *cursor;
        if (block_manager_cursor_init(&cursor, bm) == 0)
        {
            if (block_manager_cursor_goto(cursor, (uint64_t)offset) == 0)
            {
                block_manager_block_t *read_block = block_manager_cursor_read(cursor);
                if (read_block != NULL)
                {
                    ASSERT_EQ(read_block->size, 0);
                    block_manager_block_free(read_block);
                }
            }
            block_manager_cursor_free(cursor);
        }
    }

    block_manager_block_free(block);
    block_manager_close(bm);
    remove("test_empty.db");
}

void benchmark_block_manager_iteration(void)
{
    block_manager_t *bm = NULL;
    (void)remove("iteration_bench.db");
    ASSERT_TRUE(block_manager_open(&bm, "iteration_bench.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* we test with different block counts to show cache scaling */
    const int test_configs[][2] = {
        {1000, 1024},  /* 1K blocks (1KB each) */
        {5000, 1024},  /* 5K blocks (1KB each) */
        {10000, 1024}, /* 10K blocks (1KB each) */
        {20000, 1024}, /* 20K blocks (1KB each) */
    };

    for (size_t config = 0; config < sizeof(test_configs) / sizeof(test_configs[0]); config++)
    {
        int num_blocks = test_configs[config][0];
        int block_size = test_configs[config][1];

        block_manager_truncate(bm);

        printf("\n" BOLDWHITE "Config: %d blocks × %d bytes\n" RESET, num_blocks, block_size);

        uint8_t *data = malloc(block_size);
        memset(data, 'X', block_size);

        for (int i = 0; i < num_blocks; i++)
        {
            block_manager_block_t *block = block_manager_block_create(block_size, data);
            block_manager_block_write(bm, block);
            block_manager_block_free(block);
        }
        free(data);

        block_manager_close(bm);
        ASSERT_TRUE(block_manager_open(&bm, "iteration_bench.db", BLOCK_MANAGER_SYNC_NONE) == 0);

        block_manager_cursor_t *cursor;
        ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        int blocks_read = 0;
        ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);
        do
        {
            blocks_read++;
        } while (block_manager_cursor_next(cursor) == 0);

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed_no_cache = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        double throughput_no_cache = blocks_read / elapsed_no_cache;
        double mb_per_sec_no_cache = (throughput_no_cache * block_size) / (1024.0 * 1024.0);

        printf("    Blocks iterated: %d\n", blocks_read);
        printf("    Time: %.3f seconds\n", elapsed_no_cache);
        printf("    Throughput: %.2f blocks/sec\n", throughput_no_cache);
        printf("    Throughput: %.2f MB/sec\n", mb_per_sec_no_cache);
        printf("    Avg latency: %.2f μs/block\n", (elapsed_no_cache / blocks_read) * 1e6);

        block_manager_cursor_free(cursor);
    }

    block_manager_close(bm);
    remove("iteration_bench.db");
}

void benchmark_block_manager_parallel_write(void)
{
    block_manager_t *bm = NULL;
    (void)remove("test_parallel.db");
    ASSERT_TRUE(block_manager_open(&bm, "test_parallel.db", 0) == 0);

    const int num_threads[] = {1, 2, 4, 6, 8};
    const int total_blocks = 100000;

    for (size_t t = 0; t < sizeof(num_threads) / sizeof(num_threads[0]); t++)
    {
        int threads = num_threads[t];
        int blocks_per_thread = total_blocks / threads;

        block_manager_truncate(bm);

        pthread_t *thread_ids = malloc(threads * sizeof(pthread_t));
        parallel_write_context_t *contexts = malloc(threads * sizeof(parallel_write_context_t));

        struct timespec start, end;
        clock_gettime(0, &start);

        for (int i = 0; i < threads; i++)
        {
            contexts[i].bm = bm;
            contexts[i].thread_id = i;
            contexts[i].blocks_per_thread = blocks_per_thread;
            contexts[i].elapsed_time = 0;
            pthread_create(&thread_ids[i], NULL, parallel_write_worker, &contexts[i]);
        }

        for (int i = 0; i < threads; i++)
        {
            pthread_join(thread_ids[i], NULL);
        }

        clock_gettime(0, &end);
        double wall_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        double aggregate_throughput = (total_blocks) / wall_time;
        double aggregate_mb_per_sec = (aggregate_throughput * 256) / (1024.0 * 1024.0);

        double avg_thread_time = 0;
        for (int i = 0; i < threads; i++)
        {
            avg_thread_time += contexts[i].elapsed_time;
        }
        avg_thread_time /= threads;

        printf(CYAN "\n%d thread%s:\n" RESET, threads, threads > 1 ? "s" : "");
        printf(CYAN "  Wall time: %.3f seconds\n" RESET, wall_time);
        printf(CYAN "  Aggregate throughput: %.2f blocks/sec (%.2f MB/sec)\n" RESET,
               aggregate_throughput, aggregate_mb_per_sec);
        printf(CYAN "  Average per-thread time: %.3f seconds\n" RESET, avg_thread_time);

        if (t > 0)
        {
            printf(CYAN "  Speedup vs 1 thread: %.2fx\n" RESET,
                   (double)threads * wall_time / wall_time);
        }

        free(thread_ids);
        free(contexts);
    }

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test_parallel.db");
}

void test_block_manager_goto_last_after_reopen()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_reopen.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* write 5 blocks with different data */
    for (int i = 0; i < 5; i++)
    {
        char data[32];
        snprintf(data, sizeof(data), "block_%d_data", i);
        block_manager_block_t *block =
            block_manager_block_create(strlen(data) + 1, (uint8_t *)data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) != -1);
        block_manager_block_free(block);
    }
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_reopen.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* goto_last should work immediately after reopen */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_last(cursor) == 0);

    /* read last block and verify it's block 4 */
    block_manager_block_t *last_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(last_block != NULL);
    ASSERT_EQ(memcmp(last_block->data, "block_4_data", 13), 0);
    block_manager_block_free(last_block);

    /* verify we can navigate backwards */
    ASSERT_TRUE(block_manager_cursor_prev(cursor) == 0);
    block_manager_block_t *prev_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(prev_block != NULL);
    ASSERT_EQ(memcmp(prev_block->data, "block_3_data", 13), 0);
    block_manager_block_free(prev_block);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test_reopen.db");
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
    RUN_TEST(test_block_manager_cursor, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_last, tests_passed);
    RUN_TEST(test_block_manager_goto_last_after_reopen, tests_passed);
    RUN_TEST(test_block_manager_cursor_position_checks, tests_passed);
    RUN_TEST(test_block_manager_open_safety, tests_passed);
    RUN_TEST(test_block_manager_validate_last_block, tests_passed);
    RUN_TEST(test_block_manager_get_size, tests_passed);
    RUN_TEST(test_block_manager_seek_and_goto, tests_passed);
    RUN_TEST(test_block_manager_validation_edge_cases, tests_passed);
    RUN_TEST(test_block_manager_concurrent_rw, tests_passed);
    RUN_TEST(test_block_manager_sync_modes, tests_passed);
    RUN_TEST(test_block_manager_empty_block, tests_passed);

    srand((unsigned int)time(NULL)); /* NOLINT(cert-msc51-cpp) */
    RUN_TEST(benchmark_block_manager, tests_passed);
    RUN_TEST(benchmark_block_manager_iteration, tests_passed);
    RUN_TEST(benchmark_block_manager_parallel_write, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}